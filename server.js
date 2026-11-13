// QueueLess — Stage 1 server (Express + Postgres).
// Every tenant query runs inside a transaction that first sets
// app.current_org_id, so Postgres row-level security isolates organizations.
import express, { Router } from 'express';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import QRCode from 'qrcode';
import {
  createCipheriv, createDecipheriv, createHash, createHmac,
  randomBytes, randomInt, timingSafeEqual,
} from 'node:crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// =========================================================== crypto helpers

const MASTER = Buffer.from(process.env.PHONE_ENC_KEY || '', 'hex');
const SESSION_SECRET = process.env.SESSION_SECRET || '';
if (MASTER.length !== 32) throw new Error('PHONE_ENC_KEY must be 64 hex characters (32 bytes)');
if (SESSION_SECRET.length < 32) throw new Error('SESSION_SECRET must be at least 32 characters');

// Per-organization keys, so the same phone number cannot be linked across tenants.
const derive = (label, orgId) => createHmac('sha256', MASTER).update(`${label}:${orgId}`).digest();

function normalizePhone(raw) {
  if (typeof raw !== 'string') return null;
  let p = raw.replace(/[\s\-().]/g, '');
  if (p.startsWith('00')) p = `+${p.slice(2)}`;
  return /^\+[1-9][0-9]{7,14}$/.test(p) ? p : null;
}

const phoneHash = (orgId, phone) =>
  createHmac('sha256', derive('phone-hash', orgId)).update(phone).digest();
const otpHash = (orgId, phone, code) =>
  createHmac('sha256', derive('otp', orgId)).update(`${phone}:${code}`).digest();

function encryptField(orgId, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', derive('phone-enc', orgId), iv);
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]);
}

function decryptField(orgId, buf) {
  const decipher = createDecipheriv('aes-256-gcm', derive('phone-enc', orgId), buf.subarray(0, 12));
  decipher.setAuthTag(buf.subarray(12, 28));
  return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString('utf8');
}

const sha256 = (s) => createHash('sha256').update(s).digest();
const randomToken = () => randomBytes(32).toString('hex');
const safeEqual = (a, b) => a.length === b.length && timingSafeEqual(a, b);

// Signed, expiring tokens (phone-verification tokens and staff sessions).
function sign(payload, ttlMs) {
  const body = Buffer.from(JSON.stringify({ ...payload, exp: Date.now() + ttlMs })).toString('base64url');
  const sig = createHmac('sha256', SESSION_SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verify(token) {
  if (typeof token !== 'string') return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expected = createHmac('sha256', SESSION_SECRET).update(body).digest();
  if (!safeEqual(expected, Buffer.from(sig, 'base64url'))) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return p.exp > Date.now() ? p : null;
  } catch {
    return null;
  }
}

// ================================================================== database

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is not set');

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, max: 8 });
pool.on('error', (e) => console.error('pg pool error:', e.message));

// Runs fn in one transaction with the tenant set, so Postgres row-level
// security limits every query to that organization. set_config(..., true)
// is the parameterized form of SET LOCAL and resets at commit/rollback.
async function withTx(orgId, fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (orgId) await client.query("SELECT set_config('app.current_org_id', $1, true)", [orgId]);
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch { /* ignore */ }
    throw e;
  } finally {
    client.release();
  }
}

class HttpError extends Error {
  constructor(status, code, message) {
    super(message || code);
    this.status = status;
    this.code = code;
  }
}

const ok = (data) => ({ success: true, data });
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (v) => typeof v === 'string' && UUID_RE.test(v);
function needUuid(v, code = 'BAD_REQUEST') {
  if (!isUuid(v)) throw new HttpError(code === 'BAD_REQUEST' ? 400 : 404, code);
  return v;
}

// Tiny in-memory rate limiter (per process). Fine for one instance.
const hits = new Map();
function limit(key, max, windowMs) {
  const now = Date.now();
  const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (recent.length >= max) {
    hits.set(key, recent);
    return false;
  }
  recent.push(now);
  hits.set(key, recent);
  return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of hits) if (!v.some((t) => now - t < 3600e3)) hits.delete(k);
}, 600e3).unref();

// ======================================================================== SMS
// Twilio over plain HTTPS. Active only when the env vars are set; otherwise the
// app stays in demo mode (OTP shown on screen when DEV_SHOW_OTP=true).
const smsEnabled = () => !!(process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN
  && (process.env.TWILIO_FROM || process.env.TWILIO_MESSAGING_SERVICE_SID));

async function sendSms(to, body) {
  const sid = process.env.TWILIO_ACCOUNT_SID;
  const params = new URLSearchParams({ To: to, Body: body });
  if (process.env.TWILIO_MESSAGING_SERVICE_SID) params.set('MessagingServiceSid', process.env.TWILIO_MESSAGING_SERVICE_SID);
  else params.set('From', process.env.TWILIO_FROM);
  const res = await fetch(`https://api.twilio.com/2010-04-01/Accounts/${sid}/Messages.json`, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${Buffer.from(`${sid}:${process.env.TWILIO_AUTH_TOKEN}`).toString('base64')}`,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: params,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(`SMS provider error ${res.status}${json.code ? ` (code ${json.code})` : ''}`);
  return json.sid || null;
}

function smsBody(template, p) {
  if (template === 'your_turn') return `QueueLess: ${p.ticket}, it's your turn. Please go to ${p.counter}.`;
  if (template === 'almost_up') {
    const who = p.ahead === 0 ? "you're next" : `${p.ahead} ${p.ahead === 1 ? 'person' : 'people'} ahead of you`;
    return `QueueLess: ${p.ticket} at ${p.branch}: ${who}. Please head to the branch now.`;
  }
  return 'QueueLess notification';
}

// ============================================================ public routes
const publicRouter = Router();

const SLUG_RE = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const CHECK_IN_WINDOW_MS = 30 * 60e3;
// Demo mode shows the OTP on screen because no SMS provider is connected yet.
const devOtp = () => process.env.DEV_SHOW_OTP === 'true';

async function getOrg(slug) {
  if (typeof slug !== 'string' || !SLUG_RE.test(slug)) throw new HttpError(404, 'ORG_NOT_FOUND', 'Organization not found.');
  const r = await pool.query('SELECT * FROM resolve_organization_by_slug($1)', [slug]);
  if (!r.rowCount) throw new HttpError(404, 'ORG_NOT_FOUND', 'Organization not found.');
  return r.rows[0];
}

function phoneFromToken(token, org) {
  const p = verify(token);
  if (!p || p.t !== 'phone' || p.o !== org.id) {
    throw new HttpError(401, 'PHONE_NOT_VERIFIED', 'Please verify your phone number first.');
  }
  return p.p;
}

// Ticket and booking links carry a secret; only its SHA-256 is stored.
function checkSecret(k, storedHash, code) {
  if (typeof k !== 'string' || k.length !== 64 || !storedHash || !safeEqual(sha256(k), storedHash)) {
    throw new HttpError(404, code, 'Not found.');
  }
}

async function orgOf(fn, id, code) {
  const r = await pool.query(`SELECT ${fn}($1) AS org`, [id]);
  const org = r.rows[0]?.org;
  if (!org) throw new HttpError(404, code, 'Not found.');
  return org;
}

const baseUrl = (req) => `${req.protocol}://${req.get('host')}`;

// ---------------------------------------------------------------- config / org

publicRouter.get('/config', (req, res) => {
  res.json(ok({ defaultOrg: process.env.DEFAULT_ORG_SLUG || null, devOtp: devOtp(), smsEnabled: smsEnabled() }));
});

publicRouter.get('/orgs/:slug', wrap(async (req, res) => {
  const org = await getOrg(req.params.slug);
  const data = await withTx(org.id, async (c) => {
    const branches = await c.query('SELECT id, name, address, timezone FROM branches WHERE is_active ORDER BY name');
    const services = await c.query(`
      SELECT s.id, s.branch_id AS "branchId", s.name, s.description, s.mode,
             s.duration_minutes AS "durationMinutes", s.required_documents AS "requiredDocuments",
             (SELECT count(*)::int FROM queue_tickets t WHERE t.service_id = s.id AND t.status = 'waiting') AS waiting
      FROM services s WHERE s.is_active ORDER BY s.name`);
    return { branches: branches.rows, services: services.rows };
  });
  res.json(ok({
    org: { slug: req.params.slug, name: org.name, logoUrl: org.logo_url, primaryColor: org.primary_color },
    ...data,
  }));
}));

// ------------------------------------------------------------------------ OTP

publicRouter.post('/otp/request', wrap(async (req, res) => {
  const org = await getOrg(req.body?.slug);
  const phone = normalizePhone(req.body?.phone);
  if (!phone) throw new HttpError(400, 'PHONE_INVALID', 'Use international format, for example +2348012345678.');
  if (!limit(`otp-ip:${req.ip}`, 20, 600e3)) throw new HttpError(429, 'RATE_LIMITED', 'Too many requests. Try again later.');
  if (!smsEnabled() && !devOtp()) throw new HttpError(501, 'SMS_NOT_CONFIGURED', 'SMS delivery is not set up yet.');

  const hash = phoneHash(org.id, phone);
  const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
  await withTx(org.id, async (c) => {
    const r = await c.query(
      "SELECT count(*)::int AS n FROM otp_verifications WHERE phone_hash = $1 AND created_at > now() - interval '10 minutes'",
      [hash],
    );
    if (r.rows[0].n >= 3) throw new HttpError(429, 'RATE_LIMITED', 'Too many codes requested. Try again in a few minutes.');
    await c.query(
      `INSERT INTO otp_verifications (organization_id, phone_hash, purpose, code_hash, requested_ip, expires_at)
       VALUES ($1, $2, 'booking', $3, $4, now() + interval '10 minutes')`,
      [org.id, hash, otpHash(org.id, phone, code), req.ip || null],
    );
  });
  if (smsEnabled()) {
    try {
      await sendSms(phone, `Your QueueLess code is ${code}. It expires in 10 minutes.`);
    } catch (e) {
      console.error('OTP SMS failed:', e.message);
      if (!devOtp()) throw new HttpError(502, 'SMS_FAILED', 'We could not send the SMS. Please try again.');
    }
  }
  res.json(ok({ sent: true, devCode: devOtp() ? code : undefined }));
}));

publicRouter.post('/otp/verify', wrap(async (req, res) => {
  const org = await getOrg(req.body?.slug);
  const phone = normalizePhone(req.body?.phone);
  const code = String(req.body?.code ?? '').trim();
  if (!phone || !/^[0-9]{6}$/.test(code)) throw new HttpError(400, 'OTP_INVALID', 'Enter the 6-digit code.');
  if (!limit(`otpv-ip:${req.ip}`, 30, 600e3)) throw new HttpError(429, 'RATE_LIMITED', 'Too many attempts. Try again later.');

  const hash = phoneHash(org.id, phone);
  // Return a result instead of throwing so the attempt counter is committed.
  const result = await withTx(org.id, async (c) => {
    const r = await c.query(
      `SELECT id, code_hash, attempts, max_attempts FROM otp_verifications
       WHERE phone_hash = $1 AND purpose = 'booking' AND consumed_at IS NULL AND expires_at > now()
       ORDER BY created_at DESC LIMIT 1 FOR UPDATE`,
      [hash],
    );
    if (!r.rowCount) return 'invalid';
    const row = r.rows[0];
    if (row.attempts >= row.max_attempts) return 'locked';
    await c.query('UPDATE otp_verifications SET attempts = attempts + 1 WHERE id = $1', [row.id]);
    if (!safeEqual(row.code_hash, otpHash(org.id, phone, code))) return 'invalid';
    await c.query('UPDATE otp_verifications SET consumed_at = now() WHERE id = $1', [row.id]);
    return 'ok';
  });
  if (result === 'locked') throw new HttpError(429, 'OTP_LOCKED', 'Too many wrong codes. Request a new code.');
  if (result !== 'ok') throw new HttpError(400, 'OTP_INVALID', 'That code is not valid or has expired.');
  res.json(ok({ token: sign({ t: 'phone', o: org.id, p: phone }, 30 * 60e3) }));
}));

// --------------------------------------------------------------- virtual queue

publicRouter.post('/queue/join', wrap(async (req, res) => {
  const org = await getOrg(req.body?.slug);
  const phone = phoneFromToken(req.body?.token, org);
  const branchId = needUuid(req.body?.branchId);
  const serviceId = needUuid(req.body?.serviceId);
  const secret = randomToken();

  const ticket = await withTx(org.id, async (c) => {
    const s = await c.query(`
      SELECT s.mode, b.name AS branch_name,
        EXISTS (SELECT 1 FROM business_hours h
                WHERE h.branch_id = b.id AND NOT h.is_closed
                  AND h.weekday = EXTRACT(DOW FROM (now() AT TIME ZONE b.timezone))::int
                  AND (now() AT TIME ZONE b.timezone)::time BETWEEN h.opens_at AND h.closes_at) AS is_open
      FROM services s JOIN branches b ON b.id = s.branch_id
      WHERE s.id = $1 AND s.branch_id = $2 AND s.is_active AND b.is_active`, [serviceId, branchId]);
    if (!s.rowCount) throw new HttpError(404, 'SERVICE_NOT_FOUND', 'Service not found.');
    if (s.rows[0].mode === 'scheduled') throw new HttpError(409, 'SERVICE_NOT_WALKIN', 'This service is by appointment only.');
    if (!s.rows[0].is_open) throw new HttpError(409, 'BRANCH_CLOSED', 'This branch is closed right now.');

    const num = (await c.query('SELECT next_ticket_number($1) AS n', [branchId])).rows[0].n;
    try {
      const t = await c.query(
        `INSERT INTO queue_tickets (organization_id, branch_id, service_id, customer_phone_enc,
                                    customer_phone_hash, ticket_number, qr_token_hash)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, ticket_number`,
        [org.id, branchId, serviceId, encryptField(org.id, phone), phoneHash(org.id, phone), num, sha256(secret)],
      );
      return { ...t.rows[0], branchName: s.rows[0].branch_name };
    } catch (e) {
      if (e.code === '23505' && e.constraint === 'uq_tickets_one_active') {
        throw new HttpError(409, 'DUPLICATE_ACTIVE_TICKET', 'You already have an active ticket for this service.');
      }
      throw e;
    }
  });
  if (smsEnabled()) {
    sendSms(phone, `QueueLess: your ticket ${ticket.ticket_number} at ${ticket.branchName}. Track it here: ${baseUrl(req)}/t/${ticket.id}?k=${secret}`)
      .catch((e) => console.error('ticket SMS failed:', e.message));
  }
  res.status(201).json(ok({ ticketId: ticket.id, ticketNumber: ticket.ticket_number, url: `/t/${ticket.id}?k=${secret}` }));
}));

publicRouter.get('/tickets/:id', wrap(async (req, res) => {
  const id = needUuid(req.params.id, 'TICKET_NOT_FOUND');
  const k = req.query.k;
  const orgId = await orgOf('resolve_ticket_org', id, 'TICKET_NOT_FOUND');

  const data = await withTx(orgId, async (c) => {
    const r = await c.query(`
      SELECT t.status, t.ticket_number, t.qr_token_hash, t.service_id,
             s.name AS service_name, s.duration_minutes, b.name AS branch_name, b.address,
             ct.name AS counter_name
      FROM queue_tickets t
      JOIN services s ON s.id = t.service_id
      JOIN branches b ON b.id = t.branch_id
      LEFT JOIN counters ct ON ct.id = t.counter_id
      WHERE t.id = $1`, [id]);
    if (!r.rowCount) throw new HttpError(404, 'TICKET_NOT_FOUND', 'Not found.');
    const t = r.rows[0];
    checkSecret(k, t.qr_token_hash, 'TICKET_NOT_FOUND');

    const out = {
      ticketNumber: t.ticket_number, status: t.status, serviceName: t.service_name,
      branchName: t.branch_name, address: t.address, counterName: t.counter_name,
      ahead: null, position: null, etaMinutes: null, almostUp: false,
    };
    if (t.status === 'transferred') {
      const nx = await c.query('SELECT id FROM queue_tickets WHERE transferred_from_ticket_id = $1', [id]);
      out.nextTicketId = nx.rows[0] ? nx.rows[0].id : null;
    }
    if (t.status === 'waiting') {
      const a = await c.query(`
        SELECT count(*)::int AS n
        FROM queue_tickets me
        JOIN queue_tickets o ON o.branch_id = me.branch_id AND o.service_id = me.service_id AND o.status = 'waiting'
         AND (o.priority > me.priority
              OR (o.priority = me.priority AND (o.joined_at, o.id) < (me.joined_at, me.id)))
        WHERE me.id = $1`, [id]);
      const m = await c.query(`
        SELECT avg(service_seconds)::float AS avg
        FROM (SELECT service_seconds FROM service_metrics WHERE service_id = $1
              ORDER BY completed_at DESC LIMIT 30) x`, [t.service_id]);
      const cn = await c.query(`
        SELECT count(DISTINCT counter_id)::int AS n FROM queue_tickets
        WHERE service_id = $1 AND counter_id IS NOT NULL
          AND (status IN ('called', 'serving') OR called_at > now() - interval '15 minutes')`, [t.service_id]);
      const ahead = a.rows[0].n;
      const avgSeconds = m.rows[0].avg || t.duration_minutes * 60;
      const counters = Math.max(1, cn.rows[0].n);
      out.ahead = ahead;
      out.position = ahead + 1;
      // Rough estimate: people ahead (plus half the one in progress) x average service time / open counters.
      out.etaMinutes = Math.max(1, Math.ceil(((ahead + 0.5) * avgSeconds) / counters / 60));
      out.almostUp = ahead <= 2;
    }
    return out;
  });

  if (req.query.qr === '1') {
    data.qr = await QRCode.toDataURL(`${baseUrl(req)}/t/${id}?k=${k}`, { margin: 1, width: 260 });
  }
  res.json(ok(data));
}));

publicRouter.post('/tickets/:id/cancel', wrap(async (req, res) => {
  const id = needUuid(req.params.id, 'TICKET_NOT_FOUND');
  const orgId = await orgOf('resolve_ticket_org', id, 'TICKET_NOT_FOUND');
  await withTx(orgId, async (c) => {
    const r = await c.query('SELECT status, qr_token_hash, booking_id FROM queue_tickets WHERE id = $1 FOR UPDATE', [id]);
    if (!r.rowCount) throw new HttpError(404, 'TICKET_NOT_FOUND', 'Not found.');
    checkSecret(req.body?.k, r.rows[0].qr_token_hash, 'TICKET_NOT_FOUND');
    if (r.rows[0].status !== 'waiting') {
      throw new HttpError(409, 'TICKET_NOT_CANCELLABLE', 'This ticket can no longer be cancelled.');
    }
    await c.query("UPDATE queue_tickets SET status = 'cancelled', cancelled_at = now() WHERE id = $1", [id]);
    if (r.rows[0].booking_id) {
      await c.query("UPDATE bookings SET status = 'cancelled', cancelled_at = now() WHERE id = $1", [r.rows[0].booking_id]);
    }
  });
  res.json(ok({ cancelled: true }));
}));

// ---------------------------------------------------------------- appointments

const SLOTS_SQL = `
WITH svc AS (
  SELECT s.id, s.branch_id, s.duration_minutes AS dur, s.capacity, b.timezone AS tz
  FROM services s JOIN branches b ON b.id = s.branch_id
  WHERE s.id = $1 AND s.is_active AND b.is_active AND s.mode IN ('scheduled', 'both')
), slots AS (
  SELECT svc.id AS service_id, svc.capacity, svc.dur, gs.start_ts
  FROM svc
  JOIN business_hours h ON h.branch_id = svc.branch_id AND NOT h.is_closed
       AND h.weekday = EXTRACT(DOW FROM $2::date)::int
  CROSS JOIN LATERAL generate_series(
    (($2::date + h.opens_at) AT TIME ZONE svc.tz),
    (($2::date + h.closes_at) AT TIME ZONE svc.tz) - (svc.dur * interval '1 minute'),
    svc.dur * interval '1 minute'
  ) AS gs(start_ts)
)
SELECT s.start_ts, s.start_ts + s.dur * interval '1 minute' AS end_ts, s.capacity,
  (SELECT count(*)::int FROM bookings b
    WHERE b.service_id = s.service_id AND b.status IN ('confirmed', 'checked_in')
      AND tstzrange(b.scheduled_start, b.scheduled_end, '[)')
          && tstzrange(s.start_ts, s.start_ts + s.dur * interval '1 minute', '[)')) AS taken
FROM slots s
WHERE s.start_ts > now()
ORDER BY s.start_ts
LIMIT 200`;

publicRouter.get('/orgs/:slug/services/:serviceId/slots', wrap(async (req, res) => {
  const org = await getOrg(req.params.slug);
  const serviceId = needUuid(req.params.serviceId, 'SERVICE_NOT_FOUND');
  const date = String(req.query.date || '');
  const d = new Date(`${date}T00:00:00Z`);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== date) {
    throw new HttpError(400, 'BAD_REQUEST', 'Pick a valid date.');
  }
  const rows = await withTx(org.id, async (c) => (await c.query(SLOTS_SQL, [serviceId, date])).rows);
  res.json(ok({
    slots: rows.map((r) => ({
      start: r.start_ts.toISOString(),
      end: r.end_ts.toISOString(),
      available: r.taken < r.capacity,
    })),
  }));
}));

const SLOT_VALID_SQL = `
SELECT 1 FROM business_hours h
CROSS JOIN LATERAL generate_series(
  ((($2::timestamptz AT TIME ZONE $3)::date + h.opens_at) AT TIME ZONE $3),
  ((($2::timestamptz AT TIME ZONE $3)::date + h.closes_at) AT TIME ZONE $3) - ($4::int * interval '1 minute'),
  $4::int * interval '1 minute'
) AS gs(ts)
WHERE h.branch_id = $1 AND NOT h.is_closed
  AND h.weekday = EXTRACT(DOW FROM ($2::timestamptz AT TIME ZONE $3))::int
  AND gs.ts = $2::timestamptz AND gs.ts > now()
LIMIT 1`;

publicRouter.post('/bookings', wrap(async (req, res) => {
  const org = await getOrg(req.body?.slug);
  const phone = phoneFromToken(req.body?.token, org);
  const serviceId = needUuid(req.body?.serviceId);
  const start = new Date(req.body?.start);
  if (Number.isNaN(start.getTime())) throw new HttpError(400, 'BAD_REQUEST', 'Invalid start time.');
  const secret = randomToken();

  const booking = await withTx(org.id, async (c) => {
    const s = await c.query(`
      SELECT s.branch_id, s.duration_minutes, s.capacity, b.timezone, b.name AS branch_name
      FROM services s JOIN branches b ON b.id = s.branch_id
      WHERE s.id = $1 AND s.is_active AND b.is_active AND s.mode IN ('scheduled', 'both')`, [serviceId]);
    if (!s.rowCount) throw new HttpError(404, 'SERVICE_NOT_FOUND', 'Service not found.');
    const svc = s.rows[0];
    // Unattended past appointments must not block this phone number from booking again.
    await c.query("UPDATE bookings SET status = 'no_show' WHERE status = 'confirmed' AND scheduled_end < now()");

    const valid = await c.query(SLOT_VALID_SQL, [svc.branch_id, start.toISOString(), svc.timezone, svc.duration_minutes]);
    if (!valid.rowCount) throw new HttpError(400, 'INVALID_SLOT', 'That time is not available.');

    const num = (await c.query('SELECT next_ticket_number($1) AS n', [svc.branch_id])).rows[0].n;
    // Try each parallel "lane"; the database exclusion constraint guarantees no double-booking.
    for (let lane = 1; lane <= svc.capacity; lane += 1) {
      await c.query('SAVEPOINT lane_try');
      try {
        const r = await c.query(
          `INSERT INTO bookings (organization_id, branch_id, service_id, customer_phone_enc, customer_phone_hash,
                                 scheduled_start, scheduled_end, capacity_lane, ticket_number, qr_token_hash)
           VALUES ($1, $2, $3, $4, $5, $6::timestamptz, $6::timestamptz + ($7::int * interval '1 minute'), $8, $9, $10)
           RETURNING id, ticket_number`,
          [org.id, svc.branch_id, serviceId, encryptField(org.id, phone), phoneHash(org.id, phone),
            start.toISOString(), svc.duration_minutes, lane, num, sha256(secret)],
        );
        await c.query('RELEASE SAVEPOINT lane_try');
        return { ...r.rows[0], branchName: svc.branch_name, tz: svc.timezone };
      } catch (e) {
        await c.query('ROLLBACK TO SAVEPOINT lane_try');
        if (e.code === '23P01' && e.constraint === 'bookings_no_lane_overlap') continue;
        if (e.code === '23P01') throw new HttpError(409, 'CUSTOMER_OVERLAP', 'You already have an appointment at that time.');
        if (e.code === '23505' && e.constraint === 'uq_bookings_one_active') {
          throw new HttpError(409, 'DUPLICATE_ACTIVE_BOOKING', 'You already have an active appointment for this service.');
        }
        throw e;
      }
    }
    throw new HttpError(409, 'SLOT_FULL', 'That time was just taken. Please pick another.');
  });
  if (smsEnabled()) {
    const when = start.toLocaleString('en-GB', {
      timeZone: booking.tz, weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit',
    });
    sendSms(phone, `QueueLess: appointment ${booking.ticket_number} at ${booking.branchName}, ${when}. Manage it here: ${baseUrl(req)}/b/${booking.id}?k=${secret}`)
      .catch((e) => console.error('booking SMS failed:', e.message));
  }
  res.status(201).json(ok({ bookingId: booking.id, ticketNumber: booking.ticket_number, url: `/b/${booking.id}?k=${secret}` }));
}));

publicRouter.get('/bookings/:id', wrap(async (req, res) => {
  const id = needUuid(req.params.id, 'BOOKING_NOT_FOUND');
  const k = req.query.k;
  const orgId = await orgOf('resolve_booking_org', id, 'BOOKING_NOT_FOUND');

  const data = await withTx(orgId, async (c) => {
    const r = await c.query(`
      SELECT bk.status, bk.ticket_number, bk.scheduled_start, bk.scheduled_end, bk.qr_token_hash,
             s.name AS service_name, s.required_documents, s.cancellation_deadline_minutes,
             b.name AS branch_name, b.address, b.timezone,
             (SELECT q.id FROM queue_tickets q WHERE q.booking_id = bk.id) AS ticket_id
      FROM bookings bk
      JOIN services s ON s.id = bk.service_id
      JOIN branches b ON b.id = bk.branch_id
      WHERE bk.id = $1`, [id]);
    if (!r.rowCount) throw new HttpError(404, 'BOOKING_NOT_FOUND', 'Not found.');
    const b = r.rows[0];
    checkSecret(k, b.qr_token_hash, 'BOOKING_NOT_FOUND');
    const now = Date.now();
    const startMs = b.scheduled_start.getTime();
    const endMs = b.scheduled_end.getTime();
    return {
      ticketNumber: b.ticket_number, status: b.status === 'confirmed' && now >= endMs ? 'no_show' : b.status, serviceName: b.service_name,
      branchName: b.branch_name, address: b.address, timezone: b.timezone,
      start: b.scheduled_start.toISOString(), end: b.scheduled_end.toISOString(),
      requiredDocuments: b.required_documents, ticketId: b.ticket_id,
      canCancel: b.status === 'confirmed' && now < startMs - b.cancellation_deadline_minutes * 60e3,
      canCheckIn: b.status === 'confirmed' && now >= startMs - CHECK_IN_WINDOW_MS && now < endMs,
    };
  });

  if (req.query.qr === '1') {
    data.qr = await QRCode.toDataURL(`${baseUrl(req)}/b/${id}?k=${k}`, { margin: 1, width: 260 });
  }
  res.json(ok(data));
}));

publicRouter.post('/bookings/:id/cancel', wrap(async (req, res) => {
  const id = needUuid(req.params.id, 'BOOKING_NOT_FOUND');
  const orgId = await orgOf('resolve_booking_org', id, 'BOOKING_NOT_FOUND');
  await withTx(orgId, async (c) => {
    const r = await c.query(`
      SELECT bk.status, bk.scheduled_start, bk.qr_token_hash, s.cancellation_deadline_minutes AS deadline
      FROM bookings bk JOIN services s ON s.id = bk.service_id
      WHERE bk.id = $1 FOR UPDATE OF bk`, [id]);
    if (!r.rowCount) throw new HttpError(404, 'BOOKING_NOT_FOUND', 'Not found.');
    const b = r.rows[0];
    checkSecret(req.body?.k, b.qr_token_hash, 'BOOKING_NOT_FOUND');
    if (b.status !== 'confirmed') throw new HttpError(409, 'BOOKING_NOT_CANCELLABLE', 'This appointment can no longer be cancelled.');
    if (Date.now() >= b.scheduled_start.getTime() - b.deadline * 60e3) {
      throw new HttpError(409, 'CANCELLATION_CLOSED', 'It is too late to cancel this appointment online.');
    }
    await c.query("UPDATE bookings SET status = 'cancelled', cancelled_at = now() WHERE id = $1", [id]);
  });
  res.json(ok({ cancelled: true }));
}));

publicRouter.post('/bookings/:id/check-in', wrap(async (req, res) => {
  const id = needUuid(req.params.id, 'BOOKING_NOT_FOUND');
  const orgId = await orgOf('resolve_booking_org', id, 'BOOKING_NOT_FOUND');
  const ticketId = await withTx(orgId, async (c) => {
    const r = await c.query('SELECT * FROM bookings WHERE id = $1 FOR UPDATE', [id]);
    if (!r.rowCount) throw new HttpError(404, 'BOOKING_NOT_FOUND', 'Not found.');
    const b = r.rows[0];
    checkSecret(req.body?.k, b.qr_token_hash, 'BOOKING_NOT_FOUND');
    if (b.status !== 'confirmed') throw new HttpError(409, 'BOOKING_NOT_CHECKABLE', 'This appointment cannot be checked in.');
    const now = Date.now();
    if (now < b.scheduled_start.getTime() - CHECK_IN_WINDOW_MS || now >= b.scheduled_end.getTime()) {
      throw new HttpError(409, 'CHECK_IN_CLOSED', 'Check-in opens 30 minutes before your appointment.');
    }
    try {
      // The ticket reuses the booking's secret, so the same link works for both.
      const t = await c.query(
        `INSERT INTO queue_tickets (organization_id, branch_id, service_id, booking_id, customer_phone_enc,
                                    customer_phone_hash, ticket_number, qr_token_hash, checked_in_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now()) RETURNING id`,
        [b.organization_id, b.branch_id, b.service_id, b.id, b.customer_phone_enc, b.customer_phone_hash,
          b.ticket_number, b.qr_token_hash],
      );
      await c.query("UPDATE bookings SET status = 'checked_in', checked_in_at = now() WHERE id = $1", [id]);
      return t.rows[0].id;
    } catch (e) {
      if (e.code === '23505' && e.constraint === 'uq_tickets_one_active') {
        throw new HttpError(409, 'DUPLICATE_ACTIVE_TICKET', 'You are already in the queue for this service.');
      }
      throw e;
    }
  });
  res.json(ok({ ticketId }));
}));



// ---------------------------------------------------------- TV display + kiosk

publicRouter.get('/orgs/:slug/display', wrap(async (req, res) => {
  const org = await getOrg(req.params.slug);
  const branchId = req.query.branch ? needUuid(String(req.query.branch), 'BRANCH_NOT_FOUND') : null;
  const data = await withTx(org.id, async (c) => {
    const b = await c.query(
      'SELECT id, name FROM branches WHERE is_active AND ($1::uuid IS NULL OR id = $1::uuid) ORDER BY name LIMIT 1',
      [branchId],
    );
    if (!b.rowCount) throw new HttpError(404, 'BRANCH_NOT_FOUND', 'Branch not found.');
    const counters = await c.query(`
      SELECT ct.name, t.ticket_number AS "ticketNumber", t.status
      FROM counters ct
      LEFT JOIN queue_tickets t ON t.counter_id = ct.id AND t.status IN ('called', 'serving')
      WHERE ct.branch_id = $1 AND ct.is_active ORDER BY ct.name`, [b.rows[0].id]);
    const waiting = await c.query(`
      SELECT s.name, count(t.id)::int AS waiting
      FROM services s LEFT JOIN queue_tickets t ON t.service_id = s.id AND t.status = 'waiting'
      WHERE s.branch_id = $1 AND s.is_active GROUP BY s.id, s.name ORDER BY s.name`, [b.rows[0].id]);
    return { branch: b.rows[0].name, counters: counters.rows, waiting: waiting.rows };
  });
  res.json(ok(data));
}));

const kioskKeyOk = (key) => {
  const expected = process.env.KIOSK_KEY;
  return !!expected && typeof key === 'string' && safeEqual(sha256(key), sha256(expected));
};

// Walk-in tickets from an on-site tablet. Anonymous (no phone), so the kiosk
// itself is protected by a secret key in its URL.
publicRouter.post('/kiosk/ticket', wrap(async (req, res) => {
  if (!kioskKeyOk(req.body?.key)) throw new HttpError(401, 'KIOSK_UNAUTHORIZED', 'This kiosk is not authorized.');
  if (!limit(`kiosk:${req.ip}`, 120, 600e3)) throw new HttpError(429, 'RATE_LIMITED', 'Too many tickets. Please wait a moment.');
  const org = await getOrg(req.body?.slug);
  const branchId = needUuid(req.body?.branchId);
  const serviceId = needUuid(req.body?.serviceId);
  const secret = randomToken();

  const ticket = await withTx(org.id, async (c) => {
    const s = await c.query(`
      SELECT s.mode,
        EXISTS (SELECT 1 FROM business_hours h
                WHERE h.branch_id = b.id AND NOT h.is_closed
                  AND h.weekday = EXTRACT(DOW FROM (now() AT TIME ZONE b.timezone))::int
                  AND (now() AT TIME ZONE b.timezone)::time BETWEEN h.opens_at AND h.closes_at) AS is_open
      FROM services s JOIN branches b ON b.id = s.branch_id
      WHERE s.id = $1 AND s.branch_id = $2 AND s.is_active AND b.is_active`, [serviceId, branchId]);
    if (!s.rowCount) throw new HttpError(404, 'SERVICE_NOT_FOUND', 'Service not found.');
    if (s.rows[0].mode === 'scheduled') throw new HttpError(409, 'SERVICE_NOT_WALKIN', 'This service is by appointment only.');
    if (!s.rows[0].is_open) throw new HttpError(409, 'BRANCH_CLOSED', 'This branch is closed right now.');
    const num = (await c.query('SELECT next_ticket_number($1) AS n', [branchId])).rows[0].n;
    const t = await c.query(
      `INSERT INTO queue_tickets (organization_id, branch_id, service_id, customer_phone_enc,
                                  customer_phone_hash, ticket_number, qr_token_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id, ticket_number`,
      [org.id, branchId, serviceId, encryptField(org.id, 'kiosk'), randomBytes(32), num, sha256(secret)],
    );
    return t.rows[0];
  });
  const url = `${baseUrl(req)}/t/${ticket.id}?k=${secret}`;
  res.status(201).json(ok({ ticketNumber: ticket.ticket_number, url, qr: await QRCode.toDataURL(url, { margin: 1, width: 260 }) }));
}));

// ============================================================= staff routes
const staffRouter = Router();

const COOKIE = 'qs';
const SESSION_MS = 12 * 3600e3;
const cookieOpts = {
  httpOnly: true,
  sameSite: 'lax', // blocks cross-site POSTs, which covers CSRF for these JSON endpoints
  secure: process.env.NODE_ENV === 'production',
  maxAge: SESSION_MS,
  path: '/',
};

function readCookie(req, name) {
  const header = req.headers.cookie;
  if (!header) return null;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) {
      try { return decodeURIComponent(part.slice(i + 1).trim()); } catch { return null; }
    }
  }
  return null;
}

staffRouter.post('/login', wrap(async (req, res) => {
  if (!limit(`login:${req.ip}`, 10, 600e3)) throw new HttpError(429, 'RATE_LIMITED', 'Too many attempts. Try again later.');
  const email = String(req.body?.email || '').trim();
  const password = String(req.body?.password || '');
  if (!email || !password || password.length > 200) throw new HttpError(400, 'BAD_REQUEST', 'Enter your email and password.');

  const r = await pool.query('SELECT * FROM staff_login($1, $2)', [email, password]);
  if (!r.rowCount) throw new HttpError(401, 'INVALID_CREDENTIALS', 'Wrong email or password.');
  const m = r.rows[0];

  let branchId = m.branch_id;
  if (!branchId) {
    branchId = await withTx(m.organization_id, async (c) =>
      (await c.query('SELECT id FROM branches WHERE is_active ORDER BY created_at LIMIT 1')).rows[0]?.id);
  }
  if (!branchId) throw new HttpError(409, 'NO_BRANCH', 'No active branch for this account.');

  res.cookie(COOKIE, sign({ t: 'staff', u: m.user_id, o: m.organization_id, b: branchId, r: m.role }, SESSION_MS), cookieOpts);
  res.json(ok({ role: m.role }));
}));

staffRouter.post('/logout', (req, res) => {
  res.clearCookie(COOKIE, { path: '/' });
  res.json(ok({ loggedOut: true }));
});

const requireStaff = (req, res, next) => {
  const p = verify(readCookie(req, COOKIE));
  if (!p || p.t !== 'staff') return next(new HttpError(401, 'UNAUTHENTICATED', 'Please sign in.'));
  req.staff = { uid: p.u, org: p.o, branch: p.b, role: p.r };
  return next();
};
staffRouter.use(requireStaff);

const audit = (c, req, action, entityType, entityId) =>
  c.query(
    `INSERT INTO audit_logs (organization_id, actor_id, action, entity_type, entity_id, ip_address)
     VALUES ($1, $2, $3, $4, $5, $6)`,
    [req.staff.org, req.staff.uid, action, entityType, entityId, req.ip || null],
  );

staffRouter.post('/password', wrap(async (req, res) => {
  const current = String(req.body?.current || '');
  const next = String(req.body?.next || '');
  if (next.length < 10 || next.length > 200) throw new HttpError(400, 'WEAK_PASSWORD', 'Use at least 10 characters.');
  if (next === current) throw new HttpError(400, 'WEAK_PASSWORD', 'Choose a different password.');
  if (!limit(`pw:${req.staff.uid}`, 5, 600e3)) throw new HttpError(429, 'RATE_LIMITED', 'Too many attempts. Try again later.');
  const r = await pool.query(
    `UPDATE users SET password_hash = crypt($3, gen_salt('bf'))
     WHERE id = $1 AND is_active AND password_hash = crypt($2, password_hash) RETURNING id`,
    [req.staff.uid, current, next],
  );
  if (!r.rowCount) throw new HttpError(401, 'WRONG_PASSWORD', 'Current password is wrong.');
  res.json(ok({ changed: true }));
}));

staffRouter.get('/queue', wrap(async (req, res) => {
  const { org, branch } = req.staff;
  const data = await withTx(org, async (c) => {
    const b = await c.query('SELECT name FROM branches WHERE id = $1', [branch]);
    const counters = await c.query('SELECT id, name FROM counters WHERE branch_id = $1 AND is_active ORDER BY name', [branch]);
    const services = await c.query('SELECT id, name FROM services WHERE branch_id = $1 AND is_active ORDER BY name', [branch]);
    const waiting = await c.query(`
      SELECT id, ticket_number AS "ticketNumber", service_id AS "serviceId", priority
      FROM queue_tickets WHERE branch_id = $1 AND status = 'waiting'
      ORDER BY priority DESC, joined_at, id LIMIT 200`, [branch]);
    const active = await c.query(`
      SELECT t.id, t.ticket_number AS "ticketNumber", t.service_id AS "serviceId", t.status, t.counter_id AS "counterId"
      FROM queue_tickets t WHERE t.branch_id = $1 AND t.status IN ('called', 'serving')
      ORDER BY t.called_at`, [branch]);
    const rules = await c.query('SELECT id, code, name FROM priority_rules WHERE is_active ORDER BY priority_level DESC');
    return {
      branch: { name: b.rows[0]?.name || '' }, role: req.staff.role,
      counters: counters.rows, services: services.rows, waiting: waiting.rows, active: active.rows, rules: rules.rows,
    };
  });
  res.json(ok(data));
}));

staffRouter.post('/call-next', wrap(async (req, res) => {
  const { serviceId, counterId } = req.body || {};
  if (!isUuid(serviceId) || !isUuid(counterId)) throw new HttpError(400, 'BAD_REQUEST', 'Pick a counter and a service.');
  const { org, branch } = req.staff;

  const ticket = await withTx(org, async (c) => {
    const k = await c.query('SELECT name FROM counters WHERE id = $1 AND branch_id = $2 AND is_active', [counterId, branch]);
    if (!k.rowCount) throw new HttpError(400, 'COUNTER_INVALID', 'That counter is not available.');
    const busy = await c.query("SELECT 1 FROM queue_tickets WHERE counter_id = $1 AND status IN ('called', 'serving')", [counterId]);
    if (busy.rowCount) throw new HttpError(409, 'COUNTER_BUSY', 'Finish the current customer first.');

    // SKIP LOCKED: two staff pressing "call next" at once always get different tickets.
    const next = await c.query(`
      SELECT id FROM queue_tickets
      WHERE branch_id = $1 AND service_id = $2 AND status = 'waiting'
      ORDER BY priority DESC, joined_at, id LIMIT 1 FOR UPDATE SKIP LOCKED`, [branch, serviceId]);
    if (!next.rowCount) throw new HttpError(404, 'QUEUE_EMPTY', 'Nobody is waiting.');

    try {
      const u = await c.query(
        `UPDATE queue_tickets SET status = 'called', called_at = now(), counter_id = $2
         WHERE id = $1 RETURNING id, ticket_number`, [next.rows[0].id, counterId]);
      await audit(c, req, 'ticket.call', 'queue_ticket', u.rows[0].id);
      if (smsEnabled()) {
        await c.query(
          `INSERT INTO notifications (organization_id, ticket_id, channel, template, params, recipient_enc)
           SELECT organization_id, id, 'sms', 'your_turn',
                  jsonb_build_object('ticket', ticket_number, 'counter', $2::text), customer_phone_enc
           FROM queue_tickets WHERE id = $1 ON CONFLICT DO NOTHING`,
          [u.rows[0].id, k.rows[0].name],
        );
      }
      return u.rows[0];
    } catch (e) {
      if (e.code === '23505') throw new HttpError(409, 'COUNTER_BUSY', 'Finish the current customer first.');
      throw e;
    }
  });
  res.json(ok({ id: ticket.id, ticketNumber: ticket.ticket_number }));
}));

async function move(req, res, { action, from, set, after }) {
  if (!isUuid(req.params.id)) throw new HttpError(404, 'TICKET_NOT_FOUND', 'Not found.');
  const row = await withTx(req.staff.org, async (c) => {
    // `set` is a constant defined below, never user input.
    const u = await c.query(
      `UPDATE queue_tickets SET ${set} WHERE id = $1 AND branch_id = $2 AND status = ANY($3)
       RETURNING id, ticket_number, status, booking_id`,
      [req.params.id, req.staff.branch, from]);
    if (!u.rowCount) throw new HttpError(409, 'INVALID_STATE', 'That ticket cannot be changed right now.');
    await audit(c, req, action, 'queue_ticket', u.rows[0].id);
    if (after) await after(c, u.rows[0]);
    return u.rows[0];
  });
  res.json(ok({ id: row.id, ticketNumber: row.ticket_number, status: row.status }));
}

staffRouter.post('/tickets/:id/start', wrap((req, res) =>
  move(req, res, { action: 'ticket.start', from: ['called'], set: "status = 'serving', started_at = now()" })));

staffRouter.post('/tickets/:id/recall', wrap((req, res) =>
  move(req, res, { action: 'ticket.recall', from: ['called'], set: 'called_at = now()' })));

staffRouter.post('/tickets/:id/skip', wrap((req, res) =>
  move(req, res, {
    action: 'ticket.no_show', from: ['called'], set: "status = 'no_show'",
    after: async (c, t) => {
      if (t.booking_id) await c.query("UPDATE bookings SET status = 'no_show' WHERE id = $1", [t.booking_id]);
    },
  })));

staffRouter.post('/tickets/:id/complete', wrap((req, res) =>
  move(req, res, {
    action: 'ticket.complete', from: ['serving'], set: "status = 'completed', completed_at = now()",
    after: async (c, t) => {
      await c.query(`
        INSERT INTO service_metrics (organization_id, branch_id, service_id, counter_id, ticket_id,
                                     wait_seconds, service_seconds, completed_at)
        SELECT organization_id, branch_id, service_id, counter_id, id,
               GREATEST(0, EXTRACT(EPOCH FROM (started_at - joined_at))::int),
               GREATEST(0, EXTRACT(EPOCH FROM (completed_at - started_at))::int),
               completed_at
        FROM queue_tickets WHERE id = $1`, [t.id]);
      if (t.booking_id) await c.query("UPDATE bookings SET status = 'completed' WHERE id = $1", [t.booking_id]);
    },
  })));


// ============================================================ staff: priority, transfer
const adminAudit = (c, req, action, entityType, entityId, metadata = {}) =>
  c.query(
    `INSERT INTO audit_logs (organization_id, actor_id, action, entity_type, entity_id, ip_address, metadata)
     VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)`,
    [req.staff.org, req.staff.uid, action, entityType, entityId, req.ip || null, JSON.stringify(metadata)],
  );

// Staff approve priority (emergency, accessibility, elderly...). Customers cannot self-assign it.
staffRouter.post('/tickets/:id/priority', wrap(async (req, res) => {
  if (!isUuid(req.params.id)) throw new HttpError(404, 'TICKET_NOT_FOUND', 'Not found.');
  const ruleId = req.body?.ruleId ?? null;
  if (ruleId !== null && !isUuid(ruleId)) throw new HttpError(400, 'BAD_REQUEST', 'Pick a priority.');
  await withTx(req.staff.org, async (c) => {
    let level = 0;
    let code = null;
    if (ruleId) {
      const r = await c.query('SELECT code, priority_level FROM priority_rules WHERE id = $1 AND is_active', [ruleId]);
      if (!r.rowCount) throw new HttpError(404, 'RULE_NOT_FOUND', 'That priority is not available.');
      level = r.rows[0].priority_level;
      code = r.rows[0].code;
    }
    const u = await c.query(
      `UPDATE queue_tickets SET priority = $3, priority_rule_id = $4, priority_approved_by = $5
       WHERE id = $1 AND branch_id = $2 AND status = 'waiting' RETURNING id`,
      [req.params.id, req.staff.branch, level, ruleId, ruleId ? req.staff.uid : null],
    );
    if (!u.rowCount) throw new HttpError(409, 'INVALID_STATE', 'Only waiting tickets can change priority.');
    await adminAudit(c, req, ruleId ? 'ticket.priority_set' : 'ticket.priority_cleared', 'queue_ticket', req.params.id, { rule: code });
  });
  res.json(ok({ updated: true }));
}));

// Moves a customer to another service queue. The old ticket closes as "transferred" and a new
// ticket (new number, same secret link, same priority) opens in the target queue.
staffRouter.post('/tickets/:id/transfer', wrap(async (req, res) => {
  const target = req.body?.serviceId;
  if (!isUuid(req.params.id) || !isUuid(target)) throw new HttpError(400, 'BAD_REQUEST', 'Pick a service.');
  const created = await withTx(req.staff.org, async (c) => {
    const o = await c.query(
      "SELECT * FROM queue_tickets WHERE id = $1 AND branch_id = $2 AND status IN ('waiting', 'called', 'serving') FOR UPDATE",
      [req.params.id, req.staff.branch],
    );
    if (!o.rowCount) throw new HttpError(409, 'INVALID_STATE', 'That ticket cannot be moved right now.');
    const old = o.rows[0];
    if (old.service_id === target) throw new HttpError(400, 'BAD_REQUEST', 'The ticket is already in that service.');
    const s = await c.query('SELECT 1 FROM services WHERE id = $1 AND branch_id = $2 AND is_active', [target, req.staff.branch]);
    if (!s.rowCount) throw new HttpError(404, 'SERVICE_NOT_FOUND', 'Service not found.');

    const num = (await c.query('SELECT next_ticket_number($1) AS n', [req.staff.branch])).rows[0].n;
    await c.query("UPDATE queue_tickets SET status = 'transferred' WHERE id = $1", [old.id]);
    try {
      const n = await c.query(
        `INSERT INTO queue_tickets (organization_id, branch_id, service_id, transferred_from_ticket_id,
                                    customer_phone_enc, customer_phone_hash, ticket_number, qr_token_hash,
                                    priority, priority_rule_id, priority_approved_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING id, ticket_number`,
        [old.organization_id, old.branch_id, target, old.id, old.customer_phone_enc, old.customer_phone_hash,
          num, old.qr_token_hash, old.priority, old.priority_rule_id, old.priority_approved_by],
      );
      if (old.booking_id) await c.query("UPDATE bookings SET status = 'completed' WHERE id = $1", [old.booking_id]);
      await adminAudit(c, req, 'ticket.transfer', 'queue_ticket', old.id, { toService: target, newTicket: n.rows[0].ticket_number });
      return n.rows[0];
    } catch (e) {
      if (e.code === '23505' && e.constraint === 'uq_tickets_one_active') {
        throw new HttpError(409, 'DUPLICATE_ACTIVE_TICKET', 'That customer already has a ticket for that service.');
      }
      throw e;
    }
  });
  res.json(ok({ id: created.id, ticketNumber: created.ticket_number }));
}));

// ================================================================ admin routes
const adminRouter = Router();
adminRouter.use(requireStaff, (req, res, next) =>
  (['org_admin', 'branch_manager'].includes(req.staff.role)
    ? next()
    : next(new HttpError(403, 'FORBIDDEN', 'Admin access is required.'))));

const MODES = ['scheduled', 'virtual', 'both'];
const HHMM = /^([01]\d|2[0-3]):[0-5]\d$/;

function intIn(v, min, max, name) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw new HttpError(400, 'BAD_REQUEST', `${name} must be a whole number from ${min} to ${max}.`);
  return n;
}
const optInt = (v, min, max, name) => (v == null ? null : intIn(v, min, max, name));

// Org admins may pick any branch of their organization; branch managers are fixed to theirs.
async function scopeBranch(c, req) {
  const wanted = req.staff.role === 'org_admin' ? (req.query.branch || req.body?.branchId) : null;
  const id = wanted && isUuid(String(wanted)) ? String(wanted) : req.staff.branch;
  const b = await c.query('SELECT id, name, timezone FROM branches WHERE id = $1 AND is_active', [id]);
  if (!b.rowCount) throw new HttpError(404, 'BRANCH_NOT_FOUND', 'Branch not found.');
  return b.rows[0];
}

const SINCE = "now() - ($2::int * interval '1 day')";
const ANALYTICS = {
  summary: `
    SELECT
      (SELECT count(*)::int FROM service_metrics m WHERE m.branch_id = $1 AND m.completed_at >= ${SINCE}) AS served,
      (SELECT avg(m.wait_seconds)::float FROM service_metrics m WHERE m.branch_id = $1 AND m.completed_at >= ${SINCE}) AS "avgWait",
      (SELECT avg(m.service_seconds)::float FROM service_metrics m WHERE m.branch_id = $1 AND m.completed_at >= ${SINCE}) AS "avgService",
      (SELECT count(*)::int FROM queue_tickets t WHERE t.branch_id = $1 AND t.status = 'no_show' AND t.joined_at >= ${SINCE}) AS "noShows",
      (SELECT count(*)::int FROM queue_tickets t WHERE t.branch_id = $1 AND t.status = 'cancelled' AND t.joined_at >= ${SINCE}) AS cancelled,
      (SELECT count(*)::int FROM queue_tickets t WHERE t.branch_id = $1 AND t.joined_at >= ${SINCE}) AS joined`,
  services: `
    SELECT s.id, s.name, count(m.id)::int AS served, avg(m.wait_seconds)::float AS "avgWait",
           avg(m.service_seconds)::float AS "avgService",
           (SELECT count(*)::int FROM queue_tickets t
             WHERE t.service_id = s.id AND t.status = 'no_show' AND t.joined_at >= ${SINCE}) AS "noShows"
    FROM services s
    LEFT JOIN service_metrics m ON m.service_id = s.id AND m.completed_at >= ${SINCE}
    WHERE s.branch_id = $1 GROUP BY s.id, s.name ORDER BY s.name`,
  counters: `
    SELECT c.id, c.name, count(m.id)::int AS served, avg(m.service_seconds)::float AS "avgService",
           COALESCE(sum(m.service_seconds), 0)::int AS "busySeconds"
    FROM counters c
    LEFT JOIN service_metrics m ON m.counter_id = c.id AND m.completed_at >= ${SINCE}
    WHERE c.branch_id = $1 GROUP BY c.id, c.name ORDER BY c.name`,
  hours: `
    SELECT EXTRACT(HOUR FROM t.joined_at AT TIME ZONE b.timezone)::int AS hour, count(*)::int AS n
    FROM queue_tickets t JOIN branches b ON b.id = t.branch_id
    WHERE t.branch_id = $1 AND t.joined_at >= ${SINCE} GROUP BY 1 ORDER BY 1`,
  daily: `
    SELECT to_char((t.joined_at AT TIME ZONE b.timezone)::date, 'YYYY-MM-DD') AS day,
           count(*)::int AS joined, count(*) FILTER (WHERE t.status = 'completed')::int AS served
    FROM queue_tickets t JOIN branches b ON b.id = t.branch_id
    WHERE t.branch_id = $1 AND t.joined_at >= ${SINCE} GROUP BY 1 ORDER BY 1`,
  appointments: `
    SELECT count(*)::int AS total,
           count(*) FILTER (WHERE status IN ('checked_in', 'completed'))::int AS attended,
           count(*) FILTER (WHERE status = 'no_show')::int AS "noShows",
           count(*) FILTER (WHERE status = 'cancelled')::int AS cancelled
    FROM bookings WHERE branch_id = $1 AND scheduled_start >= ${SINCE} AND scheduled_start < now()`,
};

adminRouter.get('/analytics', wrap(async (req, res) => {
  const days = intIn(req.query.days || 7, 1, 90, 'Days');
  const data = await withTx(req.staff.org, async (c) => {
    const branch = await scopeBranch(c, req);
    const run = async (sql) => (await c.query(sql, [branch.id, days])).rows;
    const [summary] = await run(ANALYTICS.summary);
    const hourRows = await run(ANALYTICS.hours);
    const hours = Array.from({ length: 24 }, (_, hour) => (hourRows.find((r) => r.hour === hour) || { n: 0 }).n);
    const [appointments] = await run(ANALYTICS.appointments);
    return {
      branch: { id: branch.id, name: branch.name }, days, summary, hours, appointments,
      services: await run(ANALYTICS.services), counters: await run(ANALYTICS.counters), daily: await run(ANALYTICS.daily),
    };
  });
  res.json(ok(data));
}));

adminRouter.get('/config', wrap(async (req, res) => {
  const data = await withTx(req.staff.org, async (c) => {
    const branch = await scopeBranch(c, req);
    const org = await c.query('SELECT name, primary_color FROM organizations WHERE id = $1', [req.staff.org]);
    const branches = await c.query('SELECT id, name FROM branches WHERE is_active ORDER BY name');
    const services = await c.query(`
      SELECT id, name, mode, duration_minutes AS "durationMinutes", capacity,
             no_show_grace_minutes AS "noShowGraceMinutes",
             cancellation_deadline_minutes AS "cancellationDeadlineMinutes", is_active AS "isActive"
      FROM services WHERE branch_id = $1 ORDER BY name`, [branch.id]);
    const counters = await c.query('SELECT id, name, is_active AS "isActive" FROM counters WHERE branch_id = $1 ORDER BY name', [branch.id]);
    const hours = await c.query(`
      SELECT weekday, to_char(opens_at, 'HH24:MI') AS opens, to_char(closes_at, 'HH24:MI') AS closes
      FROM business_hours WHERE branch_id = $1 AND NOT is_closed ORDER BY weekday, opens_at`, [branch.id]);
    return {
      role: req.staff.role, org: { name: org.rows[0].name, primaryColor: org.rows[0].primary_color },
      branch: { id: branch.id, name: branch.name, timezone: branch.timezone }, branches: branches.rows,
      services: services.rows, counters: counters.rows, hours: hours.rows,
    };
  });
  res.json(ok(data));
}));

adminRouter.put('/services/:id', wrap(async (req, res) => {
  const id = needUuid(req.params.id, 'SERVICE_NOT_FOUND');
  const b = req.body || {};
  const name = b.name == null ? null : String(b.name).trim();
  if (name !== null && (name.length < 1 || name.length > 150)) throw new HttpError(400, 'BAD_REQUEST', 'Name must be 1 to 150 characters.');
  if (b.mode != null && !MODES.includes(b.mode)) throw new HttpError(400, 'BAD_REQUEST', 'Pick a valid service type.');
  const args = [
    name, b.mode ?? null,
    optInt(b.durationMinutes, 1, 480, 'Duration'), optInt(b.capacity, 1, 20, 'Capacity'),
    optInt(b.noShowGraceMinutes, 0, 240, 'No-show grace'), optInt(b.cancellationDeadlineMinutes, 0, 10080, 'Cancellation deadline'),
    typeof b.isActive === 'boolean' ? b.isActive : null,
  ];
  await withTx(req.staff.org, async (c) => {
    const branch = await scopeBranch(c, req);
    const r = await c.query(
      `UPDATE services SET name = COALESCE($2, name), mode = COALESCE($3, mode),
              duration_minutes = COALESCE($4, duration_minutes), capacity = COALESCE($5, capacity),
              no_show_grace_minutes = COALESCE($6, no_show_grace_minutes),
              cancellation_deadline_minutes = COALESCE($7, cancellation_deadline_minutes),
              is_active = COALESCE($8, is_active)
       WHERE id = $1 AND branch_id = $9 RETURNING id`,
      [id, ...args, branch.id],
    );
    if (!r.rowCount) throw new HttpError(404, 'SERVICE_NOT_FOUND', 'Service not found.');
    await adminAudit(c, req, 'service.update', 'service', id, { name, mode: b.mode ?? null });
  });
  res.json(ok({ updated: true }));
}));

adminRouter.post('/services', wrap(async (req, res) => {
  const b = req.body || {};
  const name = String(b.name || '').trim();
  if (name.length < 1 || name.length > 150) throw new HttpError(400, 'BAD_REQUEST', 'Name must be 1 to 150 characters.');
  if (!MODES.includes(b.mode)) throw new HttpError(400, 'BAD_REQUEST', 'Pick a valid service type.');
  const duration = intIn(b.durationMinutes ?? 15, 1, 480, 'Duration');
  const capacity = intIn(b.capacity ?? 1, 1, 20, 'Capacity');
  const id = await withTx(req.staff.org, async (c) => {
    const branch = await scopeBranch(c, req);
    const r = await c.query(
      `INSERT INTO services (organization_id, branch_id, name, mode, duration_minutes, capacity)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [req.staff.org, branch.id, name, b.mode, duration, capacity],
    );
    await adminAudit(c, req, 'service.create', 'service', r.rows[0].id, { name });
    return r.rows[0].id;
  });
  res.status(201).json(ok({ id }));
}));

adminRouter.post('/counters', wrap(async (req, res) => {
  const name = String(req.body?.name || '').trim();
  if (name.length < 1 || name.length > 100) throw new HttpError(400, 'BAD_REQUEST', 'Name must be 1 to 100 characters.');
  const id = await withTx(req.staff.org, async (c) => {
    const branch = await scopeBranch(c, req);
    try {
      const r = await c.query(
        'INSERT INTO counters (organization_id, branch_id, name) VALUES ($1, $2, $3) RETURNING id',
        [req.staff.org, branch.id, name],
      );
      await adminAudit(c, req, 'counter.create', 'counter', r.rows[0].id, { name });
      return r.rows[0].id;
    } catch (e) {
      if (e.code === '23505') throw new HttpError(409, 'NAME_TAKEN', 'A counter with that name already exists.');
      throw e;
    }
  });
  res.status(201).json(ok({ id }));
}));

adminRouter.put('/counters/:id', wrap(async (req, res) => {
  const id = needUuid(req.params.id, 'COUNTER_NOT_FOUND');
  const name = req.body?.name == null ? null : String(req.body.name).trim();
  if (name !== null && (name.length < 1 || name.length > 100)) throw new HttpError(400, 'BAD_REQUEST', 'Name must be 1 to 100 characters.');
  const active = typeof req.body?.isActive === 'boolean' ? req.body.isActive : null;
  await withTx(req.staff.org, async (c) => {
    const branch = await scopeBranch(c, req);
    try {
      const r = await c.query(
        'UPDATE counters SET name = COALESCE($2, name), is_active = COALESCE($3, is_active) WHERE id = $1 AND branch_id = $4 RETURNING id',
        [id, name, active, branch.id],
      );
      if (!r.rowCount) throw new HttpError(404, 'COUNTER_NOT_FOUND', 'Counter not found.');
    } catch (e) {
      if (e.code === '23505') throw new HttpError(409, 'NAME_TAKEN', 'A counter with that name already exists.');
      throw e;
    }
    await adminAudit(c, req, 'counter.update', 'counter', id, { name, active });
  });
  res.json(ok({ updated: true }));
}));

adminRouter.put('/hours', wrap(async (req, res) => {
  const list = req.body?.hours;
  if (!Array.isArray(list) || list.length > 7) throw new HttpError(400, 'BAD_REQUEST', 'Send up to 7 days of opening hours.');
  const seen = new Set();
  const rows = list.map((row) => {
    const weekday = intIn(row.weekday, 0, 6, 'Weekday');
    if (seen.has(weekday)) throw new HttpError(400, 'BAD_REQUEST', 'Each day can only appear once.');
    seen.add(weekday);
    if (!HHMM.test(row.opens) || !HHMM.test(row.closes) || row.opens >= row.closes) {
      throw new HttpError(400, 'BAD_REQUEST', 'Opening time must be before closing time.');
    }
    return [weekday, row.opens, row.closes];
  });
  await withTx(req.staff.org, async (c) => {
    const branch = await scopeBranch(c, req);
    await c.query('DELETE FROM business_hours WHERE branch_id = $1', [branch.id]);
    for (const [weekday, opens, closes] of rows) {
      await c.query(
        `INSERT INTO business_hours (organization_id, branch_id, weekday, opens_at, closes_at)
         VALUES ($1, $2, $3, $4::time, $5::time)`,
        [req.staff.org, branch.id, weekday, opens, closes],
      );
    }
    await adminAudit(c, req, 'hours.update', 'branch', branch.id, { days: rows.length });
  });
  res.json(ok({ updated: true }));
}));

adminRouter.put('/org', wrap(async (req, res) => {
  if (req.staff.role !== 'org_admin') throw new HttpError(403, 'FORBIDDEN', 'Only organization admins can change branding.');
  const name = String(req.body?.name || '').trim();
  const color = String(req.body?.primaryColor || '');
  if (name.length < 1 || name.length > 150) throw new HttpError(400, 'BAD_REQUEST', 'Name must be 1 to 150 characters.');
  if (!/^#[0-9A-Fa-f]{6}$/.test(color)) throw new HttpError(400, 'BAD_REQUEST', 'Pick a valid color.');
  await withTx(req.staff.org, async (c) => {
    await c.query('UPDATE organizations SET name = $1, primary_color = $2 WHERE id = $3', [name, color, req.staff.org]);
    await adminAudit(c, req, 'org.update', 'organization', req.staff.org, { name });
  });
  res.json(ok({ updated: true }));
}));

// CSV of tickets and outcomes. No phone numbers or other personal data.
adminRouter.get('/export.csv', wrap(async (req, res) => {
  const days = intIn(req.query.days || 30, 1, 365, 'Days');
  const rows = await withTx(req.staff.org, async (c) => {
    const branch = await scopeBranch(c, req);
    return (await c.query(`
      SELECT t.ticket_number, s.name AS service, ct.name AS counter, t.status,
             t.joined_at, t.called_at, t.started_at, t.completed_at,
             m.wait_seconds, m.service_seconds, (t.booking_id IS NOT NULL) AS appointment
      FROM queue_tickets t
      JOIN services s ON s.id = t.service_id
      LEFT JOIN counters ct ON ct.id = t.counter_id
      LEFT JOIN service_metrics m ON m.ticket_id = t.id
      WHERE t.branch_id = $1 AND t.joined_at >= now() - ($2::int * interval '1 day')
      ORDER BY t.joined_at`, [branch.id, days])).rows;
  });
  const cols = ['ticket_number', 'service', 'counter', 'status', 'joined_at', 'called_at', 'started_at',
    'completed_at', 'wait_seconds', 'service_seconds', 'appointment'];
  const esc = (v) => {
    if (v == null) return '';
    let t = v instanceof Date ? v.toISOString() : String(v);
    if (/^[=+\-@\t\r]/.test(t)) t = `'${t}`; // stop spreadsheet formula injection
    return /[",\n\r]/.test(t) ? `"${t.replace(/"/g, '""')}"` : t;
  };
  const csv = [cols.join(','), ...rows.map((r) => cols.map((k) => esc(r[k])).join(','))].join('\n');
  res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': `attachment; filename="queueless-${days}d.csv"` });
  res.send(csv);
}));

// ================================================================ web assets
const APP_JS = fs.readFileSync(path.join(__dirname, 'app.js'), 'utf8');
const INDEX_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#2563eb">
<meta name="robots" content="noindex">
<title>QueueLess</title>
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon.svg" type="image/svg+xml">
<link rel="stylesheet" href="/style.css">
</head>
<body>
<main id="app"><p class="muted">Loading…</p></main>
<script type="module" src="/app.js"></script>
</body>
</html>
`;
const STYLE_CSS = `:root {
  --accent: #2563eb;
  --bg: #f6f7f9; --card: #ffffff; --text: #111827; --muted: #6b7280; --line: #e5e7eb;
  --bad: #b91c1c; --warn-bg: #fef3c7; --warn-text: #92400e;
  color-scheme: light dark;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0f1115; --card: #181b22; --text: #f3f4f6; --muted: #9ca3af; --line: #2a2f3a;
    --bad: #f87171; --warn-bg: #3b2f10; --warn-text: #fcd34d;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; background: var(--bg); color: var(--text);
  font: 16px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
}
main {
  max-width: 560px; margin: 0 auto;
  padding: max(16px, env(safe-area-inset-top)) 16px max(32px, env(safe-area-inset-bottom));
}
h1 { font-size: 1.5rem; margin: 8px 0 4px; }
h2 { font-size: 1.1rem; margin: 20px 0 8px; }
.card h2 { margin-top: 0; }
.muted { color: var(--muted); }
.meta { color: var(--muted); font-size: .9rem; margin: 4px 0 12px; }
.card {
  background: var(--card); border: 1px solid var(--line); border-radius: 14px;
  padding: 16px; margin: 12px 0;
}
.card.error { border-color: var(--bad); }
.row { display: flex; gap: 8px; flex-wrap: wrap; }
.between { justify-content: space-between; align-items: center; }
.btn {
  min-height: 48px; padding: 10px 16px; border-radius: 12px; border: 1px solid var(--line);
  background: var(--card); color: var(--text); font: inherit; font-weight: 600; cursor: pointer;
}
.btn.primary { background: var(--accent); border-color: var(--accent); color: #fff; }
.btn.danger { color: var(--bad); border-color: var(--bad); }
.btn.block { display: block; width: 100%; margin: 8px 0; text-align: center; text-decoration: none; }
.btn.small { min-height: 40px; padding: 6px 12px; }
.btn:disabled { opacity: .5; cursor: not-allowed; }
.btn:focus-visible, input:focus-visible, select:focus-visible { outline: 3px solid var(--accent); outline-offset: 2px; }
label { display: block; font-weight: 600; margin: 12px 0; }
input, select {
  display: block; width: 100%; min-height: 48px; margin-top: 6px; padding: 10px 12px;
  border: 1px solid var(--line); border-radius: 12px; background: var(--card); color: var(--text); font: inherit;
}
.slots { display: grid; grid-template-columns: repeat(auto-fill, minmax(92px, 1fr)); gap: 8px; margin: 12px 0; }
.slot { padding: 8px; }
.ticket-no { font-size: 3.2rem; font-weight: 800; letter-spacing: .02em; margin: 4px 0 8px; color: var(--accent); }
.status .big { font-size: 1.6rem; font-weight: 800; margin: 0 0 4px; }
.banner { background: var(--warn-bg); color: var(--warn-text); border-radius: 12px; padding: 12px 14px; margin: 12px 0; font-weight: 600; }
.qr { display: block; margin: 16px auto; border-radius: 8px; background: #fff; padding: 6px; }
.list { padding-left: 20px; margin: 8px 0; }
.list li { margin: 4px 0; }
[hidden] { display: none !important; }
main.wide { max-width: 1100px; }
.tv-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
.tv-card { text-align: center; }
.tv-card.active { border-color: var(--accent); }
.tv-no { font-size: clamp(2.4rem, 8vw, 4.5rem); font-weight: 800; color: var(--accent); line-height: 1.1; margin: 8px 0; }
.tv-wait { padding: 10px 16px; font-size: 1.2rem; }
.kiosk-btn { min-height: 96px; font-size: 1.5rem; }
details.card summary { cursor: pointer; font-weight: 600; min-height: 32px; }
.stats { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; margin: 12px 0; }
.stat { text-align: center; margin: 0; }
.stat b { display: block; font-size: 1.7rem; color: var(--accent); }
.bars { display: flex; align-items: flex-end; gap: 3px; height: 120px; margin: 8px 0 4px; }
.bar { flex: 1; background: var(--accent); border-radius: 3px 3px 0 0; min-height: 2px; }
.bar-labels { display: flex; justify-content: space-between; font-size: .75rem; color: var(--muted); }
.scroll { overflow-x: auto; }
table.t { width: 100%; border-collapse: collapse; font-size: .95rem; }
.t th, .t td { text-align: left; padding: 6px 8px 6px 0; border-bottom: 1px solid var(--line); white-space: nowrap; }
.inline { display: flex; gap: 8px; flex-wrap: wrap; align-items: end; }
.inline label { flex: 1 1 130px; margin: 6px 0; }
.check { display: flex; align-items: center; gap: 10px; font-weight: 600; }
.check input { width: 24px; min-height: 24px; margin: 0; }
@media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
`;
const MANIFEST = `{
  "name": "QueueLess",
  "short_name": "QueueLess",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#f6f7f9",
  "theme_color": "#2563eb",
  "icons": [{ "src": "/icon.svg", "sizes": "any", "type": "image/svg+xml", "purpose": "any" }]
}
`;
const SW_JS = `// Minimal service worker so the app can be installed. It caches nothing,
// so live queue data is never stale.
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', () => {});
`;
const ICON_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="112" fill="#2563eb"/><circle cx="244" cy="244" r="120" fill="none" stroke="#fff" stroke-width="44"/><path d="M300 300l96 96" stroke="#fff" stroke-width="44" stroke-linecap="round"/></svg>
`;

// ==================================================================== server
const app = express();

app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    // Ticket links carry a secret in the query string, so never send a referrer.
    'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=15552000',
    'Content-Security-Policy':
      "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; " +
      "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  });
  next();
});
app.use(express.json({ limit: '20kb' }));

app.get('/healthz', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  next();
});
app.use('/api/staff', staffRouter);
app.use('/api/admin', adminRouter);
app.use('/api', publicRouter);
app.use('/api', (req, res) =>
  res.status(404).json({ success: false, error: { code: 'NOT_FOUND', message: 'Not found' } }));

const asset = (type, body) => (req, res) => {
  res.set('Cache-Control', 'no-cache');
  res.type(type).send(body);
};
app.get('/app.js', asset('text/javascript', APP_JS));
app.get('/style.css', asset('text/css', STYLE_CSS));
app.get('/manifest.json', asset('application/manifest+json', MANIFEST));
app.get('/sw.js', asset('text/javascript', SW_JS));
app.get('/icon.svg', asset('image/svg+xml', ICON_SVG));
app.get(['/', '/staff', '/t/:id', '/b/:id', '/display', '/kiosk', '/admin'], asset('text/html', INDEX_HTML));
app.use((req, res) => res.status(404).type('text/plain').send('Not found'));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err instanceof HttpError) {
    return res.status(err.status).json({ success: false, error: { code: err.code, message: err.message } });
  }
  if (err.type === 'entity.parse.failed' || err.type === 'entity.too.large') {
    return res.status(400).json({ success: false, error: { code: 'BAD_REQUEST', message: 'Invalid request.' } });
  }
  console.error(err);
  return res.status(500).json({ success: false, error: { code: 'INTERNAL', message: 'Something went wrong. Please try again.' } });
});

// ============================================================ background jobs
// Every 15 seconds, per organization: expire unattended appointments, auto no-show
// customers who were called but never arrived (after the service's grace period),
// and, when SMS is enabled, queue "almost up" alerts and deliver pending SMS.
const EXPIRE_CALLED_SQL = `
  UPDATE queue_tickets t SET status = 'no_show'
  FROM services s
  WHERE s.id = t.service_id AND t.status = 'called'
    AND t.called_at < now() - (s.no_show_grace_minutes * interval '1 minute')
  RETURNING t.id, t.booking_id`;

// Position <= 3 and waiting a few minutes, so a customer who just joined an empty
// queue is not told "almost up" seconds after getting their ticket.
const ALMOST_UP_SQL = `
  INSERT INTO notifications (organization_id, ticket_id, channel, template, params, recipient_enc)
  SELECT t.organization_id, t.id, 'sms', 'almost_up',
         jsonb_build_object('ticket', t.ticket_number, 'branch', b.name, 'ahead', t.ahead),
         t.customer_phone_enc
  FROM (SELECT q.*, row_number() OVER (PARTITION BY q.branch_id, q.service_id
                                       ORDER BY q.priority DESC, q.joined_at, q.id) - 1 AS ahead
        FROM queue_tickets q WHERE q.status = 'waiting') t
  JOIN branches b ON b.id = t.branch_id
  WHERE t.ahead <= 2 AND t.joined_at < now() - interval '3 minutes'
  ON CONFLICT DO NOTHING`;

async function deliver(orgId) {
  const due = await withTx(orgId, async (c) => (await c.query(`
    UPDATE notifications SET status = 'sending', attempts = attempts + 1
    WHERE id IN (SELECT id FROM notifications WHERE status = 'pending' AND scheduled_for <= now()
                 ORDER BY scheduled_for LIMIT 20 FOR UPDATE SKIP LOCKED)
    RETURNING id, template, params, recipient_enc, attempts`)).rows);

  for (const n of due) {
    let status = 'sent';
    let error = null;
    let providerId = null;
    try {
      const phone = decryptField(orgId, n.recipient_enc);
      // Kiosk tickets have no phone number, so there is nobody to text.
      if (!/^\+[0-9]{8,15}$/.test(phone)) status = 'cancelled';
      else providerId = await sendSms(phone, smsBody(n.template, n.params));
    } catch (e) {
      error = String(e.message).slice(0, 200);
      status = n.attempts >= 3 ? 'failed' : 'pending';
    }
    await withTx(orgId, (c) => c.query(
      `UPDATE notifications SET status = $2::varchar, last_error = $3::text, provider_message_id = $4::text,
         sent_at = CASE WHEN $2::varchar = 'sent' THEN now() ELSE sent_at END,
         scheduled_for = CASE WHEN $2::varchar = 'pending' THEN now() + interval '1 minute' ELSE scheduled_for END
       WHERE id = $1`,
      [n.id, status, error, providerId],
    ));
  }
}

let sweeping = false;
async function sweep() {
  if (sweeping) return;
  sweeping = true;
  try {
    const orgs = await pool.query('SELECT * FROM active_org_ids()');
    for (const row of orgs.rows) {
      const orgId = row.active_org_ids;
      await withTx(orgId, async (c) => {
        await c.query("UPDATE bookings SET status = 'no_show' WHERE status = 'confirmed' AND scheduled_end < now()");
        const expired = await c.query(EXPIRE_CALLED_SQL);
        for (const t of expired.rows) {
          if (t.booking_id) await c.query("UPDATE bookings SET status = 'no_show' WHERE id = $1", [t.booking_id]);
          await c.query(
            "INSERT INTO audit_logs (organization_id, action, entity_type, entity_id) VALUES ($1, 'ticket.auto_no_show', 'queue_ticket', $2)",
            [orgId, t.id],
          );
        }
        if (smsEnabled()) await c.query(ALMOST_UP_SQL);
      });
      if (smsEnabled()) await deliver(orgId);
    }
  } catch (e) {
    console.error('background sweep failed:', e.message);
  } finally {
    sweeping = false;
  }
}
setInterval(sweep, 15000).unref();

const port = Number(process.env.PORT) || 3000;
app.listen(port, '0.0.0.0', () => console.log(`QueueLess listening on ${port}`));
