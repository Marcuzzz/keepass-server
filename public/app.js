// Admin / account web UI. Vault contents are never decrypted here: the server only holds
// encrypted .kdbx files. This page manages accounts, sharing, revisions and conflict copies.

const main = document.getElementById('main');
const state = { token: sessionStorage.getItem('kps-token'), me: null };

/** Minimal element builder; text is always set via textContent (no HTML injection). */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}

function toast(message, isError = false) {
  const t = document.getElementById('toast');
  t.textContent = message;
  t.className = isError ? 'error' : '';
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { t.hidden = true; }, 4000);
}

async function api(method, path, body, headers = {}) {
  const init = { method, headers: { ...headers } };
  if (state.token) init.headers.Authorization = `Bearer ${state.token}`;
  if (body instanceof ArrayBuffer || body instanceof Blob) init.body = body;
  else if (body !== undefined) { init.body = JSON.stringify(body); init.headers['Content-Type'] = 'application/json'; }
  const res = await fetch(`/api/v1${path}`, init);
  if (res.status === 401 && state.token) { signOut(); throw new Error('Session expired'); }
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error?.message ?? res.statusText);
  }
  return (res.headers.get('Content-Type') ?? '').includes('json') ? res.json() : res.blob();
}

/** Wraps an async UI action: shows errors as a toast and re-renders on success. */
function action(fn, rerender) {
  return async (event) => {
    event?.preventDefault?.();
    try {
      const message = await fn(event);
      if (message) toast(message);
      if (rerender) await rerender();
    } catch (err) {
      toast(err.message, true);
    }
  };
}

async function download(path, filename) {
  const blob = await api('GET', path);
  const url = URL.createObjectURL(blob);
  h('a', { href: url, download: filename }).click();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

const fmtDate = (iso) => (iso ? new Date(iso).toLocaleString() : '—');
const fmtSize = (n) => (n == null ? '—' : n < 1024 * 1024 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
const field = (form, name) => form.elements.namedItem(name).value;

function table(headers, rows) {
  return h('div', { class: 'table-wrap' }, h('table', {},
    h('thead', {}, h('tr', {}, headers.map((x) => h('th', {}, x)))),
    h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: headers.length, class: 'muted' }, 'Nothing here yet'))),
  ));
}

// --- views ---------------------------------------------------------------------------------------

function renderLogin() {
  document.getElementById('nav').hidden = true;
  const form = h('form', { class: 'card stack', onsubmit: action(async () => {
    const res = await api('POST', '/auth/login', { username: field(form, 'username'), password: field(form, 'password'), deviceName: `Web (${navigator.platform || 'browser'})` });
    state.token = res.token;
    sessionStorage.setItem('kps-token', res.token);
    await start();
  }) },
  h('h2', {}, 'Sign in'),
  h('label', {}, 'Username', h('input', { name: 'username', autocomplete: 'username', required: true })),
  h('label', {}, 'Password', h('input', { name: 'password', type: 'password', autocomplete: 'current-password', required: true })),
  h('button', { class: 'primary', type: 'submit' }, 'Sign in'));
  main.replaceChildren(form);
}

async function renderVaults() {
  const vaults = await api('GET', '/vaults');
  const create = h('form', { class: 'row', onsubmit: action(async () => {
    const vault = await api('POST', '/vaults', { name: field(create, 'name') });
    const file = create.elements.namedItem('file').files[0];
    if (file) await api('PUT', `/vaults/${vault.id}/content`, await file.arrayBuffer(), { 'If-Match': '"0"', 'Content-Type': 'application/octet-stream' });
    return `Vault "${vault.name}" created`;
  }, renderVaults) },
  h('input', { name: 'name', placeholder: 'Vault name', required: true, 'aria-label': 'Vault name' }),
  h('label', { class: 'row' }, 'Upload existing .kdbx (optional)', h('input', { name: 'file', type: 'file', accept: '.kdbx' })),
  h('button', { class: 'primary', type: 'submit' }, 'Create vault'));

  main.replaceChildren(
    h('section', { class: 'card' }, h('h2', {}, 'Vaults'),
      table(['Name', 'Role', 'Revision', 'Updated', 'Size', ''], vaults.map((v) => h('tr', {},
        h('td', {}, h('a', { onclick: () => renderVault(v.id) }, v.name), v.conflicts ? [' ', h('span', { class: 'badge warn' }, `${v.conflicts} conflict${v.conflicts > 1 ? 's' : ''}`)] : null),
        h('td', {}, h('span', { class: 'badge' }, v.role)),
        h('td', {}, v.revision || '—'),
        h('td', {}, fmtDate(v.updatedAt)),
        h('td', {}, fmtSize(v.size)),
        h('td', { class: 'actions' }, v.revision ? h('button', { onclick: action(() => download(`/vaults/${v.id}/content`, `${v.name}.kdbx`)) }, 'Download') : null),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'New vault'),
      h('p', { class: 'muted' }, 'Upload an existing database, or create an empty vault and let a client (KeePassDX, KeePassXC, kps) upload the first version.'),
      create),
  );
}

async function renderVault(id) {
  const [vault, revisions, conflicts, members] = await Promise.all([
    api('GET', `/vaults/${id}`), api('GET', `/vaults/${id}/revisions`), api('GET', `/vaults/${id}/conflicts`), api('GET', `/vaults/${id}/members`),
  ]);
  const rerender = () => renderVault(id);
  const isOwner = vault.role === 'owner';
  const canWrite = vault.role !== 'reader';

  const addMember = h('form', { class: 'row', onsubmit: action(async () => {
    await api('PUT', `/vaults/${id}/members/${encodeURIComponent(field(addMember, 'username'))}`, { role: field(addMember, 'role') });
    return 'Member saved';
  }, rerender) },
  h('input', { name: 'username', placeholder: 'Username', required: true, 'aria-label': 'Username' }),
  h('select', { name: 'role', 'aria-label': 'Role' }, ['editor', 'reader', 'owner'].map((r) => h('option', { value: r }, r))),
  h('button', { type: 'submit' }, 'Add / change'));

  const rename = h('form', { class: 'row', onsubmit: action(async () => {
    await api('PATCH', `/vaults/${id}`, { name: field(rename, 'name') });
    return 'Renamed';
  }, rerender) },
  h('input', { name: 'name', value: vault.name, required: true, 'aria-label': 'Vault name' }),
  h('button', { type: 'submit' }, 'Rename'),
  h('button', { type: 'button', class: 'danger', onclick: action(async () => {
    if (!window.confirm(`Delete vault "${vault.name}" and all its revisions? This cannot be undone.`)) return null;
    await api('DELETE', `/vaults/${id}`);
    return 'Vault deleted';
  }, renderVaults) }, 'Delete vault'));

  main.replaceChildren(
    h('p', {}, h('a', { onclick: renderVaults }, '← All vaults')),
    h('section', { class: 'card' },
      h('h2', {}, vault.name),
      h('p', { class: 'muted' }, `Vault id ${vault.id} · your role: ${vault.role} · revision ${vault.revision}`),
      isOwner ? rename : null),
    h('section', { class: 'card' }, h('h2', {}, `Conflict copies (${conflicts.length})`),
      h('p', { class: 'muted' }, 'Saved when a device could not merge its changes (e.g. the master key was changed elsewhere). Download one, open it next to the current database, use KeePass "Merge/Synchronize", then delete the copy.'),
      table(['Created', 'By', 'Base rev', 'Reason', ''], conflicts.map((c) => h('tr', {},
        h('td', {}, fmtDate(c.createdAt)), h('td', {}, `${c.username ?? '?'} · ${c.deviceName ?? ''}`), h('td', {}, c.baseRevision ?? '—'), h('td', {}, c.reason ?? ''),
        h('td', { class: 'actions' },
          h('button', { onclick: action(() => download(`/vaults/${id}/conflicts/${c.id}/content`, `${vault.name}-conflict.kdbx`)) }, 'Download'), ' ',
          canWrite ? h('button', { class: 'danger', onclick: action(async () => {
            if (!window.confirm('Delete this conflict copy?')) return null;
            await api('DELETE', `/vaults/${id}/conflicts/${c.id}`);
            return 'Conflict copy deleted';
          }, rerender) }, 'Resolved') : null),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'Revisions'),
      table(['Rev', 'Saved', 'By', 'Based on', 'Size', ''], revisions.map((r) => h('tr', {},
        h('td', {}, r.revision, r.current ? [' ', h('span', { class: 'badge' }, 'current')] : null),
        h('td', {}, fmtDate(r.createdAt), r.note ? h('div', { class: 'muted' }, r.note) : null),
        h('td', {}, `${r.username ?? '?'} · ${r.deviceName ?? ''}`),
        h('td', {}, r.baseRevision ?? '—'),
        h('td', {}, fmtSize(r.size)),
        h('td', { class: 'actions' },
          h('button', { onclick: action(() => download(`/vaults/${id}/revisions/${r.revision}/content`, `${vault.name}-r${r.revision}.kdbx`)) }, 'Download'), ' ',
          canWrite && !r.current ? h('button', { onclick: action(async () => {
            if (!window.confirm(`Make revision ${r.revision} the current version? Devices will download it on their next sync.`)) return null;
            await api('POST', `/vaults/${id}/revisions/${r.revision}/restore`);
            return `Revision ${r.revision} restored`;
          }, rerender) }, 'Restore') : null),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'Members'),
      h('p', { class: 'muted' }, 'Every member needs the vault\'s master password (and key file) to open it. Server accounts only control who can download and upload.'),
      table(['User', 'Role', ''], members.map((m) => h('tr', {},
        h('td', {}, m.username), h('td', {}, h('span', { class: 'badge' }, m.role)),
        h('td', { class: 'actions' }, isOwner ? h('button', { class: 'danger', onclick: action(async () => {
          await api('DELETE', `/vaults/${id}/members/${encodeURIComponent(m.username)}`);
          return `${m.username} removed`;
        }, rerender) }, 'Remove') : null),
      ))),
      isOwner ? [h('h3', {}, 'Add member'), addMember] : null),
  );
}

async function renderUsers() {
  const users = await api('GET', '/users');
  const create = h('form', { class: 'row', onsubmit: action(async () => {
    await api('POST', '/users', { username: field(create, 'username'), password: field(create, 'password'), isAdmin: create.elements.namedItem('isAdmin').checked });
    return 'User created';
  }, renderUsers) },
  h('input', { name: 'username', placeholder: 'Username', required: true, autocomplete: 'off', 'aria-label': 'Username' }),
  h('input', { name: 'password', type: 'password', placeholder: 'Password (min. 10)', required: true, minlength: 10, autocomplete: 'new-password', 'aria-label': 'Password' }),
  h('label', { class: 'row' }, h('input', { name: 'isAdmin', type: 'checkbox' }), 'Administrator'),
  h('button', { class: 'primary', type: 'submit' }, 'Create user'));

  main.replaceChildren(
    h('section', { class: 'card' }, h('h2', {}, 'Users'),
      table(['Username', 'Admin', 'Status', 'Created', ''], users.map((u) => h('tr', {},
        h('td', {}, u.username), h('td', {}, u.isAdmin ? 'yes' : ''), h('td', {}, u.disabled ? h('span', { class: 'badge warn' }, 'disabled') : 'active'),
        h('td', {}, fmtDate(u.createdAt)),
        h('td', { class: 'actions' },
          h('button', { onclick: action(async () => {
            const password = window.prompt(`New password for ${u.username} (min. 10 characters)`);
            if (!password) return null;
            await api('PATCH', `/users/${u.id}`, { password });
            return 'Password changed; the user\'s sessions were signed out';
          }, renderUsers) }, 'Reset password'), ' ',
          h('button', { onclick: action(async () => { await api('PATCH', `/users/${u.id}`, { isAdmin: !u.isAdmin }); }, renderUsers) }, u.isAdmin ? 'Revoke admin' : 'Make admin'), ' ',
          h('button', { onclick: action(async () => { await api('PATCH', `/users/${u.id}`, { disabled: !u.disabled }); }, renderUsers) }, u.disabled ? 'Enable' : 'Disable'), ' ',
          h('button', { class: 'danger', onclick: action(async () => {
            if (!window.confirm(`Delete user ${u.username}?`)) return null;
            await api('DELETE', `/users/${u.id}`);
            return 'User deleted';
          }, renderUsers) }, 'Delete')),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'New user'), create),
  );
}

async function renderAccount() {
  const tokens = await api('GET', '/me/tokens');
  const pw = h('form', { class: 'stack', onsubmit: action(async () => {
    await api('POST', '/me/password', { currentPassword: field(pw, 'current'), newPassword: field(pw, 'next') });
    pw.reset();
    return 'Password changed; other devices were signed out';
  }, renderAccount) },
  h('label', {}, 'Current password', h('input', { name: 'current', type: 'password', required: true, autocomplete: 'current-password' })),
  h('label', {}, 'New password (min. 10)', h('input', { name: 'next', type: 'password', required: true, minlength: 10, autocomplete: 'new-password' })),
  h('button', { type: 'submit', class: 'primary' }, 'Change password'));

  main.replaceChildren(
    h('section', { class: 'card' }, h('h2', {}, `Signed-in devices of ${state.me.username}`),
      table(['Device', 'Last used', 'Expires', ''], tokens.map((t) => h('tr', {},
        h('td', {}, t.deviceName, t.current ? [' ', h('span', { class: 'badge' }, 'this browser')] : null),
        h('td', {}, fmtDate(t.lastUsedAt)), h('td', {}, fmtDate(t.expiresAt)),
        h('td', { class: 'actions' }, t.current ? null : h('button', { class: 'danger', onclick: action(async () => {
          await api('DELETE', `/me/tokens/${t.id}`);
          return 'Device signed out';
        }, renderAccount) }, 'Sign out')),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'Password'), pw),
  );
}

// --- shell ---------------------------------------------------------------------------------------

function signOut() {
  if (state.token) fetch('/api/v1/auth/logout', { method: 'POST', headers: { Authorization: `Bearer ${state.token}` } }).catch(() => {});
  state.token = null;
  state.me = null;
  sessionStorage.removeItem('kps-token');
  renderLogin();
}

const views = { vaults: renderVaults, users: renderUsers, account: renderAccount };

document.getElementById('nav').addEventListener('click', (e) => {
  const view = e.target.closest('button')?.dataset.view;
  if (view) action(() => views[view]())();
});
document.getElementById('logout').addEventListener('click', signOut);

async function start() {
  if (!state.token) return renderLogin();
  try {
    state.me = await api('GET', '/me');
  } catch {
    return signOut();
  }
  document.getElementById('nav').hidden = false;
  document.getElementById('nav-users').hidden = !state.me.isAdmin;
  await action(renderVaults)();
}

start();
