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

/** Font Awesome icon (decorative; the button carries the label). */
const icon = (name) => h('i', { class: `fa-solid fa-${name}`, 'aria-hidden': 'true' });
/** Icon + text, for form buttons. */
const withIcon = (name, text) => [icon(name), ' ', text];
/** Icon-only button; `label` becomes the tooltip and the accessible name. */
const iconButton = (name, label, attrs = {}) =>
  h('button', { type: 'button', ...attrs, class: `icon ${attrs.class ?? ''}`.trim(), title: attrs.title ?? label, 'aria-label': label }, icon(name));

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

const ROLE_OPTIONS = ['editor', 'reader', 'owner'];
const roleSelect = (name = 'role') => h('select', { name, 'aria-label': 'Role' }, ROLE_OPTIONS.map((r) => h('option', { value: r }, r)));

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
  h('button', { class: 'primary', type: 'submit' }, withIcon('right-to-bracket', 'Sign in')));
  main.replaceChildren(form);
}

/** Asks for a new name and renames the vault; returns the toast message, or null when cancelled. */
async function renameVault(vault) {
  const name = window.prompt(`New name for "${vault.name}"`, vault.name)?.trim();
  if (!name || name === vault.name) return null;
  await api('PATCH', `/vaults/${vault.id}`, { name });
  return `Renamed to "${name}"`;
}

/** Deletes a vault after the user typed its name; returns the toast message, or null when cancelled. */
async function deleteVault(vault) {
  const typed = window.prompt(`Delete vault "${vault.name}" with all its revisions and conflict copies? This cannot be undone.\n\nType the vault name to confirm:`);
  if (typed === null) return null;
  if (typed.trim() !== vault.name) throw new Error('Name did not match; nothing was deleted');
  await api('DELETE', `/vaults/${vault.id}`);
  return `Vault "${vault.name}" deleted`;
}

/** Turns deletion protection on or off; returns the toast message. */
async function setProtected(vault, value) {
  await api('PATCH', `/vaults/${vault.id}`, { protected: value });
  return value ? `"${vault.name}" is protected from deletion` : `Deletion protection of "${vault.name}" turned off`;
}

const protectedBadge = () => h('span', { class: 'badge', title: 'Protected from deletion' }, icon('lock'), ' protected');

/** Copies a vault (current database only) and opens the copy. */
async function duplicateVault(vault, name, copySharing) {
  const copy = await api('POST', `/vaults/${vault.id}/duplicate`, { name, copySharing });
  await renderVault(copy.id);
  return `Vault "${copy.name}" created`;
}

async function renderVaults() {
  const [vaults, groups] = await Promise.all([api('GET', '/vaults'), api('GET', '/groups')]);
  const create = h('form', { class: 'row', onsubmit: action(async () => {
    const group = groups.length ? field(create, 'group') : '';
    const body = { name: field(create, 'name') };
    if (group) body.groups = [{ name: group, role: field(create, 'groupRole') }];
    const vault = await api('POST', '/vaults', body);
    const file = create.elements.namedItem('file').files[0];
    if (file) await api('PUT', `/vaults/${vault.id}/content`, await file.arrayBuffer(), { 'If-Match': '"0"', 'Content-Type': 'application/octet-stream' });
    return `Vault "${vault.name}" created`;
  }, renderVaults) },
  h('input', { name: 'name', placeholder: 'Vault name', required: true, 'aria-label': 'Vault name' }),
  h('label', { class: 'row' }, 'Upload existing .kdbx (optional)', h('input', { name: 'file', type: 'file', accept: '.kdbx' })),
  groups.length ? h('label', { class: 'row' }, 'Share with group',
    h('select', { name: 'group', 'aria-label': 'Group' }, h('option', { value: '' }, '(none)'), groups.map((g) => h('option', { value: g.name }, g.name))),
    roleSelect('groupRole')) : null,
  h('button', { class: 'primary', type: 'submit' }, withIcon('plus', 'Create vault')));

  main.replaceChildren(
    h('section', { class: 'card' }, h('h2', {}, 'Vaults'),
      table(['Name', 'Role', 'Revision', 'Updated', 'Size', ''], vaults.map((v) => h('tr', {},
        h('td', {}, h('a', { onclick: () => renderVault(v.id) }, v.name), v.protected ? [' ', protectedBadge()] : null, v.conflicts ? [' ', h('span', { class: 'badge warn' }, `${v.conflicts} conflict${v.conflicts > 1 ? 's' : ''}`)] : null),
        h('td', {}, h('span', { class: 'badge' }, v.role)),
        h('td', {}, v.revision || '—'),
        h('td', {}, fmtDate(v.updatedAt)),
        h('td', {}, fmtSize(v.size)),
        h('td', { class: 'actions' },
          v.revision ? iconButton('download', 'Download', { onclick: action(() => download(`/vaults/${v.id}/content`, `${v.name}.kdbx`)) }) : null, ' ',
          v.role === 'owner' ? iconButton('pen', 'Rename', { onclick: action(() => renameVault(v), renderVaults) }) : null, ' ',
          iconButton('copy', 'Duplicate', { title: 'Copy this vault (current database, same master password)', onclick: action(async () => {
            const name = window.prompt(`Name for the copy of "${v.name}"`, `${v.name} (copy)`)?.trim();
            if (!name) return null;
            return duplicateVault(v, name, false);
          }) }), ' ',
          v.role === 'owner' ? iconButton(v.protected ? 'lock' : 'lock-open', v.protected ? 'Turn off deletion protection' : 'Protect from deletion', {
            class: v.protected ? 'active' : '', 'aria-pressed': String(v.protected), onclick: action(() => setProtected(v, !v.protected), renderVaults),
          }) : null, ' ',
          v.role === 'owner' ? iconButton('trash', v.protected ? 'Protected from deletion; turn protection off first' : 'Delete', {
            class: 'danger', disabled: v.protected, onclick: action(() => deleteVault(v), renderVaults),
          }) : null),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'New vault'),
      h('p', { class: 'muted' }, 'Upload an existing database, or create an empty vault and let a client (KeePassDX, KeePassXC, kps) upload the first version.'),
      create),
  );
}

async function renderVault(id) {
  const [vault, revisions, conflicts, members, vaultGroups, groups] = await Promise.all([
    api('GET', `/vaults/${id}`), api('GET', `/vaults/${id}/revisions`), api('GET', `/vaults/${id}/conflicts`), api('GET', `/vaults/${id}/members`),
    api('GET', `/vaults/${id}/groups`), api('GET', '/groups'),
  ]);
  const rerender = () => renderVault(id);
  const isOwner = vault.role === 'owner';
  const canWrite = vault.role !== 'reader';

  const addMember = h('form', { class: 'row', onsubmit: action(async () => {
    await api('PUT', `/vaults/${id}/members/${encodeURIComponent(field(addMember, 'username'))}`, { role: field(addMember, 'role') });
    return 'Member saved';
  }, rerender) },
  h('input', { name: 'username', placeholder: 'Username', required: true, 'aria-label': 'Username' }),
  roleSelect(),
  h('button', { type: 'submit' }, withIcon('plus', 'Add / change')));

  // Owners who are not administrators only see their own groups, so the name can also be typed.
  const addGroup = h('form', { class: 'row', onsubmit: action(async () => {
    await api('PUT', `/vaults/${id}/groups/${encodeURIComponent(field(addGroup, 'group'))}`, { role: field(addGroup, 'role') });
    return 'Group access saved';
  }, rerender) },
  h('input', { name: 'group', placeholder: 'Group name', required: true, list: 'group-names', 'aria-label': 'Group name' }),
  h('datalist', { id: 'group-names' }, groups.map((g) => h('option', { value: g.name }))),
  roleSelect(),
  h('button', { type: 'submit' }, withIcon('plus', 'Add / change')));

  const rename = h('form', { class: 'row', onsubmit: action(async () => {
    await api('PATCH', `/vaults/${id}`, { name: field(rename, 'name') });
    return 'Renamed';
  }, rerender) },
  h('input', { name: 'name', value: vault.name, required: true, 'aria-label': 'Vault name' }),
  h('button', { type: 'submit' }, withIcon('pen', 'Rename')),
  h('button', { type: 'button', onclick: action(() => setProtected(vault, !vault.protected), rerender) },
    vault.protected ? withIcon('lock-open', 'Turn off protection') : withIcon('lock', 'Protect from deletion')),
  h('button', { type: 'button', class: 'danger', disabled: vault.protected, title: vault.protected ? 'Turn off deletion protection first' : undefined, onclick: action(async () => {
    const message = await deleteVault(vault);
    if (message) await renderVaults();
    return message;
  }) }, withIcon('trash', 'Delete vault')));

  const duplicate = h('form', { class: 'row', onsubmit: action(() => duplicateVault(vault, field(duplicate, 'name'),
    isOwner && duplicate.elements.namedItem('copySharing').checked)) },
  h('input', { name: 'name', value: `${vault.name} (copy)`, required: true, maxlength: 200, 'aria-label': 'Name of the copy' }),
  isOwner ? h('label', { class: 'row' }, h('input', { name: 'copySharing', type: 'checkbox' }), 'Also copy members and groups') : null,
  h('button', { type: 'submit' }, withIcon('copy', 'Duplicate')));

  main.replaceChildren(
    h('p', {}, h('a', { onclick: renderVaults }, '← All vaults')),
    h('section', { class: 'card' },
      h('h2', {}, vault.name, vault.protected ? [' ', protectedBadge()] : null),
      h('p', { class: 'muted' }, `Vault id ${vault.id} · your role: ${vault.role} · revision ${vault.revision}`),
      isOwner ? [h('h3', {}, 'Rename, protect or delete'),
        h('p', { class: 'muted' }, 'A protected vault cannot be deleted until an owner or administrator turns protection off.'), rename] : null,
      h('h3', {}, 'Duplicate'),
      h('p', { class: 'muted' }, 'Creates a new vault you own with the current database (same master password). Revision history and conflict copies stay here.'),
      duplicate),
    h('section', { class: 'card' }, h('h2', {}, `Conflict copies (${conflicts.length})`),
      h('p', { class: 'muted' }, 'Saved when a device could not merge its changes (e.g. the master key was changed elsewhere). Download one, open it next to the current database, use KeePass "Merge/Synchronize", then delete the copy.'),
      table(['Created', 'By', 'Base rev', 'Reason', ''], conflicts.map((c) => h('tr', {},
        h('td', {}, fmtDate(c.createdAt)), h('td', {}, `${c.username ?? '?'} · ${c.deviceName ?? ''}`), h('td', {}, c.baseRevision ?? '—'), h('td', {}, c.reason ?? ''),
        h('td', { class: 'actions' },
          iconButton('download', 'Download', { onclick: action(() => download(`/vaults/${id}/conflicts/${c.id}/content`, `${vault.name}-conflict.kdbx`)) }), ' ',
          canWrite ? iconButton('check', 'Resolved', { class: 'danger', onclick: action(async () => {
            if (!window.confirm('Delete this conflict copy?')) return null;
            await api('DELETE', `/vaults/${id}/conflicts/${c.id}`);
            return 'Conflict copy deleted';
          }, rerender) }) : null),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'Revisions'),
      table(['Rev', 'Saved', 'By', 'Based on', 'Size', ''], revisions.map((r) => h('tr', {},
        h('td', {}, r.revision, r.current ? [' ', h('span', { class: 'badge' }, 'current')] : null),
        h('td', {}, fmtDate(r.createdAt), r.note ? h('div', { class: 'muted' }, r.note) : null),
        h('td', {}, `${r.username ?? '?'} · ${r.deviceName ?? ''}`),
        h('td', {}, r.baseRevision ?? '—'),
        h('td', {}, fmtSize(r.size)),
        h('td', { class: 'actions' },
          iconButton('download', 'Download', { onclick: action(() => download(`/vaults/${id}/revisions/${r.revision}/content`, `${vault.name}-r${r.revision}.kdbx`)) }), ' ',
          canWrite && !r.current ? iconButton('clock-rotate-left', 'Restore', { onclick: action(async () => {
            if (!window.confirm(`Make revision ${r.revision} the current version? Devices will download it on their next sync.`)) return null;
            await api('POST', `/vaults/${id}/revisions/${r.revision}/restore`);
            return `Revision ${r.revision} restored`;
          }, rerender) }) : null),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'Members'),
      h('p', { class: 'muted' }, 'Every member needs the vault\'s master password (and key file) to open it. Server accounts only control who can download and upload.'),
      table(['User', 'Role', ''], members.map((m) => h('tr', {},
        h('td', {}, m.username), h('td', {}, h('span', { class: 'badge' }, m.role)),
        h('td', { class: 'actions' }, isOwner ? iconButton('xmark', 'Remove', { class: 'danger', onclick: action(async () => {
          await api('DELETE', `/vaults/${id}/members/${encodeURIComponent(m.username)}`);
          return `${m.username} removed`;
        }, rerender) }) : null),
      ))),
      isOwner ? [h('h3', {}, 'Add member'), addMember] : null),
    h('section', { class: 'card' }, h('h2', {}, 'Groups'),
      h('p', { class: 'muted' }, 'Every member of a group gets its role. A user\'s role is the highest of their own role and their groups\' roles.'),
      table(['Group', 'Role', ''], vaultGroups.map((g) => h('tr', {},
        h('td', {}, g.name), h('td', {}, h('span', { class: 'badge' }, g.role)),
        h('td', { class: 'actions' }, isOwner ? iconButton('xmark', 'Remove', { class: 'danger', onclick: action(async () => {
          await api('DELETE', `/vaults/${id}/groups/${encodeURIComponent(g.name)}`);
          return `Group ${g.name} removed`;
        }, rerender) }) : null),
      ))),
      isOwner ? [h('h3', {}, 'Add group'), addGroup] : null),
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
  h('button', { class: 'primary', type: 'submit' }, withIcon('user-plus', 'Create user')));

  main.replaceChildren(
    h('section', { class: 'card' }, h('h2', {}, 'Users'),
      table(['Username', 'Admin', 'Status', 'Created', ''], users.map((u) => h('tr', {},
        h('td', {}, u.username), h('td', {}, u.isAdmin ? 'yes' : ''), h('td', {}, u.disabled ? h('span', { class: 'badge warn' }, 'disabled') : 'active'),
        h('td', {}, fmtDate(u.createdAt)),
        h('td', { class: 'actions' },
          iconButton('key', 'Reset password', { onclick: action(async () => {
            const password = window.prompt(`New password for ${u.username} (min. 10 characters)`);
            if (!password) return null;
            await api('PATCH', `/users/${u.id}`, { password });
            return 'Password changed; the user\'s sessions were signed out';
          }, renderUsers) }), ' ',
          iconButton(u.isAdmin ? 'user-minus' : 'user-shield', u.isAdmin ? 'Revoke admin' : 'Make admin', { onclick: action(async () => { await api('PATCH', `/users/${u.id}`, { isAdmin: !u.isAdmin }); }, renderUsers) }), ' ',
          iconButton(u.disabled ? 'circle-check' : 'ban', u.disabled ? 'Enable' : 'Disable', { onclick: action(async () => { await api('PATCH', `/users/${u.id}`, { disabled: !u.disabled }); }, renderUsers) }), ' ',
          iconButton('trash', 'Delete', { class: 'danger', onclick: action(async () => {
            if (!window.confirm(`Delete user ${u.username}?`)) return null;
            await api('DELETE', `/users/${u.id}`);
            return 'User deleted';
          }, renderUsers) })),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'New user'), create),
  );
}

/**
 * Checkbox list of users with a filter, select all / deselect all (of the visible users) and
 * shift-click to toggle a range. Returns the element and a function giving the checked usernames.
 */
function userPicker(users, selected = [], label = 'Members') {
  const chosen = new Set(selected);
  let last = null;
  const boxes = users.map((u) => h('input', { type: 'checkbox', value: u.username, checked: chosen.has(u.username) }));
  const items = users.map((u, i) => h('label', { class: 'pick' }, boxes[i], u.username,
    u.disabled ? [' ', h('span', { class: 'badge warn' }, 'disabled')] : null));
  const visible = () => boxes.filter((_, i) => !items[i].hidden);
  const setAll = (checked) => visible().forEach((b) => { b.checked = checked; });
  const count = h('span', { class: 'muted' });
  const updateCount = () => { count.textContent = `${boxes.filter((b) => b.checked).length} of ${users.length} selected`; };

  const list = h('div', { class: 'picker-list', role: 'group', 'aria-label': label, onclick: (e) => {
    const i = boxes.indexOf(e.target);
    if (i < 0) return;
    if (e.shiftKey && last !== null) {
      const [from, to] = [Math.min(last, i), Math.max(last, i)];
      for (let j = from; j <= to; j++) if (!items[j].hidden) boxes[j].checked = boxes[i].checked;
    }
    last = i;
    updateCount();
  } }, users.length ? items : h('span', { class: 'muted' }, 'No users yet'));

  const filter = h('input', { type: 'search', placeholder: 'Filter users', 'aria-label': `Filter ${label.toLowerCase()}`, autocomplete: 'off', oninput: () => {
    const q = filter.value.trim().toLowerCase();
    users.forEach((u, i) => { items[i].hidden = !u.username.toLowerCase().includes(q); });
  }, onkeydown: (e) => { if (e.key === 'Enter') e.preventDefault(); } });

  updateCount();
  const el = h('div', { class: 'picker' },
    h('div', { class: 'row' }, filter,
      h('button', { type: 'button', onclick: () => { setAll(true); updateCount(); } }, withIcon('square-check', 'Select all')),
      h('button', { type: 'button', onclick: () => { setAll(false); updateCount(); } }, withIcon('square', 'Deselect all')),
      count),
    list,
    h('p', { class: 'muted' }, 'Shift-click to select or deselect a range.'));
  return { el, values: () => boxes.filter((b) => b.checked).map((b) => b.value) };
}

async function renderGroups() {
  const [groups, users] = await Promise.all([api('GET', '/groups'), api('GET', '/users')]);
  const newMembers = userPicker(users, [], 'New group members');
  const create = h('form', { class: 'stack wide', onsubmit: action(async () => {
    await api('POST', '/groups', { name: field(create, 'name'), members: newMembers.values() });
    return 'Group created';
  }, renderGroups) },
  h('label', {}, 'Group name', h('input', { name: 'name', required: true, autocomplete: 'off' })),
  h('div', { class: 'field' }, h('span', { class: 'muted' }, 'Members (optional)'), newMembers.el),
  h('div', {}, h('button', { class: 'primary', type: 'submit' }, withIcon('users', 'Create group'))));

  const editMembers = (g) => {
    const current = g.members.map((m) => m.username);
    const picker = userPicker(users, current, `Members of ${g.name}`);
    const form = h('form', { class: 'stack wide', onsubmit: action(async () => {
      const next = new Set(picker.values());
      const add = [...next].filter((u) => !current.includes(u));
      const remove = current.filter((u) => !next.has(u));
      for (const u of add) await api('PUT', `/groups/${g.id}/members/${encodeURIComponent(u)}`);
      for (const u of remove) await api('DELETE', `/groups/${g.id}/members/${encodeURIComponent(u)}`);
      return add.length || remove.length ? `Members saved (+${add.length} −${remove.length})` : 'No changes';
    }, renderGroups) },
    picker.el,
    h('div', {}, h('button', { class: 'primary', type: 'submit' }, withIcon('floppy-disk', 'Save members'))));
    return h('details', { class: 'edit-members' }, h('summary', {}, 'Edit members'), form);
  };

  main.replaceChildren(
    h('section', { class: 'card' }, h('h2', {}, 'Groups'),
      h('p', { class: 'muted' }, 'Vault owners give a group a role on a vault (on the vault page); every member gets that role.'),
      table(['Group', 'Members', 'Created', ''], groups.map((g) => h('tr', {},
        h('td', {}, g.name),
        h('td', {},
          g.members.map((m) => h('span', { class: 'badge' }, m.username, ' ', h('button', { class: 'danger', 'aria-label': `Remove ${m.username} from ${g.name}`, onclick: action(async () => {
            await api('DELETE', `/groups/${g.id}/members/${encodeURIComponent(m.username)}`);
            return `${m.username} removed`;
          }, renderGroups) }, icon('xmark')))),
          editMembers(g)),
        h('td', {}, fmtDate(g.createdAt)),
        h('td', { class: 'actions' },
          iconButton('pen', 'Rename', { onclick: action(async () => {
            const name = window.prompt(`New name for ${g.name}`, g.name);
            if (!name) return null;
            await api('PATCH', `/groups/${g.id}`, { name });
            return 'Group renamed';
          }, renderGroups) }), ' ',
          iconButton('trash', 'Delete', { class: 'danger', onclick: action(async () => {
            if (!window.confirm(`Delete group ${g.name}? Its members lose the vault access they had through it.`)) return null;
            await api('DELETE', `/groups/${g.id}`);
            return 'Group deleted';
          }, renderGroups) })),
      )))),
    h('section', { class: 'card' }, h('h2', {}, 'New group'), create),
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
  h('button', { type: 'submit', class: 'primary' }, withIcon('key', 'Change password')));

  main.replaceChildren(
    h('section', { class: 'card' }, h('h2', {}, `Signed-in devices of ${state.me.username}`),
      table(['Device', 'Last used', 'Expires', ''], tokens.map((t) => h('tr', {},
        h('td', {}, t.deviceName, t.current ? [' ', h('span', { class: 'badge' }, 'this browser')] : null),
        h('td', {}, fmtDate(t.lastUsedAt)), h('td', {}, fmtDate(t.expiresAt)),
        h('td', { class: 'actions' }, t.current ? null : iconButton('right-from-bracket', 'Sign out', { class: 'danger', onclick: action(async () => {
          await api('DELETE', `/me/tokens/${t.id}`);
          return 'Device signed out';
        }, renderAccount) })),
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

const views = { vaults: renderVaults, users: renderUsers, groups: renderGroups, account: renderAccount };

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
  document.getElementById('nav-groups').hidden = !state.me.isAdmin;
  await action(renderVaults)();
}

start();
