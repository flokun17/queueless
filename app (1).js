const root = document.getElementById('app');

// ------------------------------------------------------------------ helpers

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
  let json = null;
  try { json = await res.json(); } catch { /* not JSON */ }
  if (!res.ok || !json || !json.success) {
    const err = new Error((json && json.error && json.error.message) || 'Something went wrong. Please try again.');
    err.code = json && json.error && json.error.code;
    err.status = res.status;
    throw err;
  }
  return json.data;
}

// Builds DOM nodes. Text is always inserted as text, never as HTML.
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const mount = (...nodes) => root.replaceChildren(...nodes.flat().filter((n) => n != null && n !== false));
const fmt = (iso, tz, opts) => new Date(iso).toLocaleString(undefined, { timeZone: tz, ...opts });
const WHEN = { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' };

const errorView = (e, retry) => h('div', { class: 'card error', role: 'alert' },
  h('p', {}, e.message || 'Something went wrong.'),
  retry && h('button', { class: 'btn', onclick: retry }, 'Try again'));

if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js').catch(() => {});

// ------------------------------------------------------------------- router

const path = location.pathname;
if (path === '/staff') staffPage();
else if (path === '/display') displayPage();
else if (path === '/kiosk') kioskPage();
else if (path.startsWith('/t/')) ticketPage();
else if (path.startsWith('/b/')) bookingPage();
else homePage();

// ---------------------------------------------------------------- customers

async function homePage() {
  const st = { slug: null, data: null, branchId: null, token: null };

  try {
    const cfg = await api('/api/config');
    st.slug = new URLSearchParams(location.search).get('org') || cfg.defaultOrg;
    if (!st.slug) return mount(h('p', { class: 'muted' }, 'No organization selected.'));
    st.data = await api(`/api/orgs/${encodeURIComponent(st.slug)}`);
    st.branchId = st.data.branches[0] && st.data.branches[0].id;
    document.title = `${st.data.org.name} · QueueLess`;
    document.documentElement.style.setProperty('--accent', st.data.org.primaryColor);
    return services();
  } catch (e) {
    return mount(errorView(e, homePage));
  }

  function services() {
    const { org, branches } = st.data;
    const branch = branches.find((b) => b.id === st.branchId);
    const list = st.data.services.filter((s) => s.branchId === st.branchId);
    mount(
      h('header', {}, h('h1', {}, org.name), h('p', { class: 'muted' }, 'Skip the line. Join a queue or book a time.')),
      branches.length > 1 && h('label', {}, 'Branch',
        h('select', { onchange: (e) => { st.branchId = e.target.value; services(); } },
          branches.map((b) => h('option', { value: b.id, selected: b.id === st.branchId }, b.name)))),
      branch && h('p', { class: 'muted' }, [branch.name, branch.address].filter(Boolean).join(' · ')),
      list.length ? list.map(serviceCard) : h('p', { class: 'muted' }, 'No services available at this branch.'),
    );
  }

  function serviceCard(s) {
    return h('section', { class: 'card' },
      h('h2', {}, s.name),
      s.description && h('p', { class: 'muted' }, s.description),
      h('p', { class: 'meta' }, `${s.durationMinutes} min`, s.mode !== 'scheduled' && ` · ${s.waiting} waiting`),
      h('div', { class: 'row' },
        s.mode !== 'scheduled' && h('button', { class: 'btn primary', onclick: () => start(s, 'queue') }, 'Join queue now'),
        s.mode !== 'virtual' && h('button', { class: 'btn', onclick: () => start(s, 'book') }, 'Book appointment')));
  }

  function start(s, kind) {
    if (!st.token) return verify(s, kind);
    return kind === 'queue' ? join(s) : book(s);
  }

  function back() { return h('button', { class: 'btn', onclick: services }, 'Back'); }

  function verify(s, kind) {
    const msg = h('p', { class: 'muted', role: 'status' });
    const phoneIn = h('input', {
      type: 'tel', inputmode: 'tel', autocomplete: 'tel', placeholder: '+2348012345678', 'aria-label': 'Phone number',
    });
    const codeIn = h('input', {
      type: 'text', inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: '6',
      placeholder: '6-digit code', 'aria-label': 'Verification code',
    });
    const verifyBtn = h('button', { class: 'btn primary block' }, 'Verify and continue');
    const codeBox = h('div', { hidden: true }, h('label', {}, 'Verification code', codeIn), verifyBtn);
    const sendBtn = h('button', { class: 'btn primary block' }, 'Send code');

    sendBtn.addEventListener('click', async () => {
      sendBtn.disabled = true;
      msg.textContent = '';
      try {
        const r = await api('/api/otp/request', { method: 'POST', body: { slug: st.slug, phone: phoneIn.value } });
        codeBox.hidden = false;
        msg.textContent = r.devCode
          ? `Demo mode: no SMS is sent yet. Your code is ${r.devCode}.`
          : 'We sent you a code by SMS.';
        codeIn.focus();
      } catch (e) {
        msg.textContent = e.message;
      } finally {
        sendBtn.disabled = false;
      }
    });

    verifyBtn.addEventListener('click', async () => {
      verifyBtn.disabled = true;
      try {
        const r = await api('/api/otp/verify', {
          method: 'POST', body: { slug: st.slug, phone: phoneIn.value, code: codeIn.value },
        });
        st.token = r.token;
        start(s, kind);
      } catch (e) {
        msg.textContent = e.message;
        verifyBtn.disabled = false;
      }
    });

    mount(
      h('h1', {}, s.name),
      h('p', { class: 'muted' }, 'Confirm your phone number so we can keep your place.'),
      h('label', {}, 'Phone number (with country code)', phoneIn),
      sendBtn,
      msg,
      codeBox,
      back(),
    );
  }

  async function join(s) {
    mount(h('p', { class: 'muted', role: 'status' }, 'Getting your ticket…'));
    try {
      const r = await api('/api/queue/join', {
        method: 'POST', body: { slug: st.slug, branchId: st.branchId, serviceId: s.id, token: st.token },
      });
      location.href = r.url;
    } catch (e) {
      if (e.code === 'PHONE_NOT_VERIFIED') { st.token = null; verify(s, 'queue'); return; }
      mount(errorView(e), back());
    }
  }

  function book(s) {
    const branch = st.data.branches.find((b) => b.id === st.branchId);
    const tz = branch.timezone;
    const today = new Intl.DateTimeFormat('en-CA', { timeZone: tz }).format(new Date());
    const msg = h('p', { class: 'muted', role: 'status' });
    const slotsBox = h('div', { class: 'slots', role: 'group', 'aria-label': 'Available times' });
    const dateIn = h('input', { type: 'date', min: today, value: today, onchange: load });

    async function load() {
      slotsBox.replaceChildren();
      msg.textContent = 'Loading times…';
      try {
        const r = await api(`/api/orgs/${encodeURIComponent(st.slug)}/services/${s.id}/slots?date=${dateIn.value}`);
        msg.textContent = r.slots.length ? '' : 'No times left on this day.';
        slotsBox.replaceChildren(...r.slots.map((sl) => h('button', {
          class: 'btn slot', disabled: !sl.available, onclick: () => choose(sl),
        }, fmt(sl.start, tz, { hour: '2-digit', minute: '2-digit' }))));
      } catch (e) {
        msg.textContent = e.message;
      }
    }

    async function choose(sl) {
      if (!window.confirm(`Book ${s.name} on ${fmt(sl.start, tz, WHEN)}?`)) return;
      try {
        const r = await api('/api/bookings', {
          method: 'POST', body: { slug: st.slug, serviceId: s.id, start: sl.start, token: st.token },
        });
        location.href = r.url;
      } catch (e) {
        if (e.code === 'PHONE_NOT_VERIFIED') { st.token = null; verify(s, 'book'); return; }
        msg.textContent = e.message;
        if (e.code === 'SLOT_FULL') load();
      }
    }

    mount(
      h('h1', {}, `Book: ${s.name}`),
      s.requiredDocuments && s.requiredDocuments.length > 0 && h('p', { class: 'muted' }, `Bring: ${s.requiredDocuments.join(', ')}`),
      h('label', {}, 'Date', dateIn),
      msg,
      slotsBox,
      back(),
    );
    load();
  }
}

async function ticketPage() {
  const id = location.pathname.split('/')[2];
  const k = new URLSearchParams(location.search).get('k') || '';
  let qr = null;
  let timer = null;
  let buzzed = false;

  async function load() {
    clearTimeout(timer);
    try {
      const t = await api(`/api/tickets/${id}?k=${encodeURIComponent(k)}${qr ? '' : '&qr=1'}`);
      if (t.qr) qr = t.qr;
      render(t);
      if (['waiting', 'called', 'serving'].includes(t.status)) timer = setTimeout(load, 4000);
    } catch (e) {
      if (e.status === 404 || e.status === 400) return mount(errorView(e));
      timer = setTimeout(load, 8000);
    }
  }

  function statusView(t) {
    switch (t.status) {
      case 'waiting': return [
        h('p', { class: 'big' }, `You are #${t.position} in line`),
        h('p', { class: 'muted' }, `${t.ahead} ${t.ahead === 1 ? 'person' : 'people'} ahead · about ${t.etaMinutes} min`),
        h('p', { class: 'muted' }, "We'll update this page automatically. Keep it open."),
      ];
      case 'called': return [
        h('p', { class: 'big' }, `Go to ${t.counterName || 'the counter'} now`),
        h('p', { class: 'muted' }, 'It is your turn. Show this ticket number.'),
      ];
      case 'serving': return [h('p', { class: 'big' }, `Being served at ${t.counterName || 'the counter'}`)];
      case 'completed': return [h('p', { class: 'big' }, 'All done'), h('p', { class: 'muted' }, 'Thank you for visiting.')];
      case 'no_show': return [h('p', { class: 'big' }, 'Ticket expired'), h('p', { class: 'muted' }, 'You were called but did not arrive. Please join the queue again.')];
      case 'cancelled': return [h('p', { class: 'big' }, 'Ticket cancelled')];
      default: return [h('p', { class: 'big' }, 'Ticket closed')];
    }
  }

  function render(t) {
    if (t.almostUp && !buzzed) {
      buzzed = true;
      if (navigator.vibrate) navigator.vibrate([200, 100, 200]);
    }
    mount(
      h('header', {},
        h('p', { class: 'muted' }, `${t.serviceName} · ${t.branchName}`),
        h('div', { class: 'ticket-no', 'aria-label': `Ticket ${t.ticketNumber}` }, t.ticketNumber)),
      h('section', { class: 'card status', 'aria-live': 'polite' }, statusView(t)),
      t.almostUp && h('div', { class: 'banner', role: 'status' }, "You're almost up. Please head to the branch now."),
      qr && ['waiting', 'called', 'serving'].includes(t.status) && h('img', { class: 'qr', src: qr, alt: 'QR code for this ticket', width: 200, height: 200 }),
      t.status === 'waiting' && h('button', { class: 'btn danger block', onclick: cancel }, 'Leave the queue'),
      t.address && h('p', { class: 'muted' }, t.address),
    );
  }

  async function cancel() {
    if (!window.confirm('Leave the queue? You will lose your place.')) return;
    try {
      await api(`/api/tickets/${id}/cancel`, { method: 'POST', body: { k } });
      load();
    } catch (e) {
      mount(errorView(e, load));
    }
  }

  load();
}

async function bookingPage() {
  const id = location.pathname.split('/')[2];
  const k = new URLSearchParams(location.search).get('k') || '';
  let qr = null;
  let timer = null;

  async function load() {
    clearTimeout(timer);
    try {
      const b = await api(`/api/bookings/${id}?k=${encodeURIComponent(k)}${qr ? '' : '&qr=1'}`);
      if (b.qr) qr = b.qr;
      render(b);
      if (b.status === 'confirmed') timer = setTimeout(load, 30000);
    } catch (e) {
      if (e.status === 404 || e.status === 400) return mount(errorView(e));
      timer = setTimeout(load, 30000);
    }
  }

  const LABEL = {
    confirmed: 'Confirmed', checked_in: 'Checked in', completed: 'Completed',
    cancelled: 'Cancelled', no_show: 'Missed',
  };

  function render(b) {
    mount(
      h('header', {},
        h('p', { class: 'muted' }, `${b.serviceName} · ${b.branchName}`),
        h('div', { class: 'ticket-no', 'aria-label': `Ticket ${b.ticketNumber}` }, b.ticketNumber)),
      h('section', { class: 'card status', 'aria-live': 'polite' },
        h('p', { class: 'big' }, fmt(b.start, b.timezone, WHEN)),
        h('p', { class: 'muted' }, `Status: ${LABEL[b.status] || b.status}`),
        b.status === 'confirmed' && h('p', { class: 'muted' }, 'Arrive 10 minutes early. Check in below once you are close.')),
      b.requiredDocuments && b.requiredDocuments.length > 0 && h('section', { class: 'card' },
        h('h2', {}, 'Bring with you'),
        h('ul', { class: 'list' }, b.requiredDocuments.map((d) => h('li', {}, d)))),
      b.ticketId && h('a', { class: 'btn primary block', href: `/t/${b.ticketId}?k=${encodeURIComponent(k)}` }, 'Track my place in line'),
      b.canCheckIn && h('button', { class: 'btn primary block', onclick: checkIn }, "I'm here: check in"),
      b.canCancel && h('button', { class: 'btn danger block', onclick: cancel }, 'Cancel appointment'),
      qr && ['confirmed', 'checked_in'].includes(b.status) && h('img', { class: 'qr', src: qr, alt: 'QR code for this appointment', width: 200, height: 200 }),
      b.address && h('p', { class: 'muted' }, b.address),
    );
  }

  async function checkIn() {
    try {
      const r = await api(`/api/bookings/${id}/check-in`, { method: 'POST', body: { k } });
      location.href = `/t/${r.ticketId}?k=${encodeURIComponent(k)}`;
    } catch (e) {
      mount(errorView(e, load));
    }
  }

  async function cancel() {
    if (!window.confirm('Cancel this appointment?')) return;
    try {
      await api(`/api/bookings/${id}/cancel`, { method: 'POST', body: { k } });
      load();
    } catch (e) {
      mount(errorView(e, load));
    }
  }

  load();
}

// -------------------------------------------------------------------- staff

async function staffPage() {
  const st = { counterId: localStorage.getItem('ql.counter') || '', msg: '', last: '' };
  let timer = null;
  const pwForm = passwordForm();

  // Built once and reused, so typing is not wiped when the queue refreshes.
  function passwordForm() {
    const msg = h('p', { class: 'muted', role: 'status' });
    const current = h('input', { type: 'password', autocomplete: 'current-password' });
    const next = h('input', { type: 'password', autocomplete: 'new-password', minlength: '10' });
    const btn = h('button', { class: 'btn block', type: 'button' }, 'Change password');
    btn.addEventListener('click', async () => {
      try {
        await api('/api/staff/password', { method: 'POST', body: { current: current.value, next: next.value } });
        current.value = '';
        next.value = '';
        msg.textContent = 'Password changed.';
      } catch (e) {
        msg.textContent = e.message;
      }
    });
    return h('details', { class: 'card' },
      h('summary', {}, 'Change password'),
      h('label', {}, 'Current password', current),
      h('label', {}, 'New password (10+ characters)', next),
      btn,
      msg);
  }

  async function load(force) {
    clearTimeout(timer);
    try {
      const d = await api('/api/staff/queue');
      const sig = JSON.stringify(d);
      if (force || sig !== st.last) {
        st.last = sig;
        render(d);
      }
      timer = setTimeout(load, 4000);
    } catch (e) {
      if (e.status === 401) return loginView();
      timer = setTimeout(load, 8000);
      return undefined;
    }
    return undefined;
  }

  function loginView(message) {
    const msg = h('p', { class: 'muted', role: 'alert' }, message || '');
    const email = h('input', { type: 'email', autocomplete: 'username', required: true });
    const password = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const form = h('form', {},
      h('label', {}, 'Email', email),
      h('label', {}, 'Password', password),
      h('button', { class: 'btn primary block', type: 'submit' }, 'Sign in'),
      msg);
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      try {
        await api('/api/staff/login', { method: 'POST', body: { email: email.value, password: password.value } });
        st.last = '';
        load(true);
      } catch (e) {
        msg.textContent = e.message;
      }
    });
    mount(h('h1', {}, 'Staff sign in'), form);
  }

  async function act(path, body, okMsg) {
    try {
      const r = await api(path, { method: 'POST', body });
      st.msg = okMsg ? okMsg(r) : '';
    } catch (e) {
      st.msg = e.message;
    }
    load(true);
  }

  async function logout() {
    await api('/api/staff/logout', { method: 'POST' }).catch(() => {});
    clearTimeout(timer);
    loginView();
  }

  function activeCard(t, d) {
    const service = d.services.find((s) => s.id === t.serviceId);
    const counter = d.counters.find((c) => c.id === t.counterId);
    const base = `/api/staff/tickets/${t.id}`;
    return h('section', { class: 'card' },
      h('div', { class: 'ticket-no' }, t.ticketNumber),
      h('p', { class: 'muted' }, `${service ? service.name : ''} · ${counter ? counter.name : ''} · ${t.status === 'called' ? 'called' : 'serving'}`),
      h('div', { class: 'row' },
        t.status === 'called' && h('button', { class: 'btn primary', onclick: () => act(`${base}/start`) }, 'Start serving'),
        t.status === 'called' && h('button', { class: 'btn', onclick: () => act(`${base}/recall`, undefined, () => 'Recalled.') }, 'Recall'),
        t.status === 'called' && h('button', { class: 'btn danger', onclick: () => act(`${base}/skip`, undefined, () => 'Marked no-show.') }, 'No-show'),
        t.status === 'serving' && h('button', { class: 'btn primary', onclick: () => act(`${base}/complete`, undefined, () => 'Completed.') }, 'Complete')));
  }

  function render(d) {
    if (!d.counters.find((c) => c.id === st.counterId)) st.counterId = (d.counters[0] && d.counters[0].id) || '';
    const nameOf = (id) => (d.services.find((s) => s.id === id) || {}).name || '';
    mount(
      h('header', { class: 'row between' },
        h('h1', {}, d.branch.name),
        h('button', { class: 'btn small', onclick: logout }, 'Sign out')),
      st.msg && h('div', { class: 'banner', role: 'status' }, st.msg),
      h('label', {}, 'My counter',
        h('select', {
          onchange: (e) => { st.counterId = e.target.value; localStorage.setItem('ql.counter', st.counterId); },
        }, d.counters.map((c) => h('option', { value: c.id, selected: c.id === st.counterId }, c.name)))),
      h('h2', {}, 'Call next'),
      d.services.map((s) => {
        const n = d.waiting.filter((t) => t.serviceId === s.id).length;
        return h('button', {
          class: 'btn primary block', disabled: n === 0,
          onclick: () => act('/api/staff/call-next', { serviceId: s.id, counterId: st.counterId }, (r) => `Called ${r.ticketNumber}.`),
        }, `${s.name}: ${n} waiting`);
      }),
      h('h2', {}, 'At counters now'),
      d.active.length ? d.active.map((t) => activeCard(t, d)) : h('p', { class: 'muted' }, 'No one is being served.'),
      h('h2', {}, 'Waiting'),
      d.waiting.length
        ? h('ul', { class: 'list' }, d.waiting.slice(0, 20).map((t) => h('li', {},
          h('strong', {}, t.ticketNumber), ` ${nameOf(t.serviceId)}`, t.priority > 0 && ' · priority')))
        : h('p', { class: 'muted' }, 'The queue is empty.'),
      pwForm,
    );
  }

  load(true);
}

// ---------------------------------------------------------------- TV display

async function displayPage() {
  root.classList.add('wide');
  const params = new URLSearchParams(location.search);
  let slug = null;
  let shown = false;

  async function load() {
    try {
      if (!slug) slug = params.get('org') || (await api('/api/config')).defaultOrg;
      const branch = params.get('branch') ? `?branch=${encodeURIComponent(params.get('branch'))}` : '';
      render(await api(`/api/orgs/${encodeURIComponent(slug)}/display${branch}`));
      shown = true;
    } catch (e) {
      if (!shown) mount(errorView(e));
    }
    setTimeout(load, 3000);
  }

  function render(d) {
    mount(
      h('header', { class: 'row between' },
        h('h1', {}, d.branch),
        h('p', { class: 'muted' }, new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }))),
      h('h2', {}, 'Now serving'),
      h('div', { class: 'tv-grid', 'aria-live': 'polite' }, d.counters.map((c) => h('div',
        { class: `card tv-card${c.ticketNumber ? ' active' : ''}` },
        h('p', { class: 'muted' }, c.name),
        h('div', { class: 'tv-no' }, c.ticketNumber || '-'),
        c.status && h('p', { class: 'muted' }, c.status === 'called' ? 'Please come to the counter' : 'Being served')))),
      h('h2', {}, 'Waiting'),
      h('div', { class: 'row' }, d.waiting.map((w) => h('div', { class: 'card tv-wait' }, h('strong', {}, w.waiting), ` ${w.name}`))),
    );
  }

  load();
}

// -------------------------------------------------------------------- kiosk

async function kioskPage() {
  root.classList.add('wide');
  const params = new URLSearchParams(location.search);
  const key = params.get('key') || '';
  let timer = null;
  let slug;
  let data;
  let branchId;

  try {
    slug = params.get('org') || (await api('/api/config')).defaultOrg;
    data = await api(`/api/orgs/${encodeURIComponent(slug)}`);
    branchId = params.get('branch') || (data.branches[0] && data.branches[0].id);
  } catch (e) {
    return mount(errorView(e));
  }
  document.documentElement.style.setProperty('--accent', data.org.primaryColor);

  function menu() {
    clearTimeout(timer);
    const list = data.services.filter((s) => s.branchId === branchId && s.mode !== 'scheduled');
    mount(
      h('h1', {}, data.org.name),
      h('p', { class: 'muted' }, 'Tap a service to get your queue number.'),
      list.length ? list.map((s) => h('button', { class: 'btn primary block kiosk-btn', onclick: () => take(s) }, s.name))
        : h('p', { class: 'muted' }, 'No walk-in services are available here.'),
    );
  }

  async function take(s) {
    mount(h('p', { class: 'muted', role: 'status' }, 'Getting your number…'));
    try {
      const r = await api('/api/kiosk/ticket', { method: 'POST', body: { key, slug, branchId, serviceId: s.id } });
      mount(
        h('p', { class: 'muted' }, s.name),
        h('div', { class: 'ticket-no' }, r.ticketNumber),
        h('p', {}, 'Please wait until your number is called.'),
        h('img', { class: 'qr', src: r.qr, alt: 'QR code to follow this ticket on your phone', width: 200, height: 200 }),
        h('p', { class: 'muted' }, 'Scan to follow your place in line on your phone.'),
        h('button', { class: 'btn block', onclick: menu }, 'Done'),
      );
      timer = setTimeout(menu, 20000);
    } catch (e) {
      mount(errorView(e), h('button', { class: 'btn block', onclick: menu }, 'Back'));
    }
  }

  return menu();
}
