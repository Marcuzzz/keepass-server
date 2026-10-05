// Renders /api/openapi.json without third-party code (the CSP only allows same-origin scripts),
// with a small "try it" form per endpoint. The token is kept in sessionStorage like the web UI.

const main = document.getElementById('main');
const TOKEN_KEY = 'kps-token';

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

/** Splits `text` on `code` spans (backticks) into text and <code> nodes. */
const md = (text = '') => text.split(/`([^`]*)`/).map((part, i) => (i % 2 ? h('code', {}, part) : part));

let spec;
const resolve = (schema) => (schema?.$ref ? spec.components.schemas[schema.$ref.split('/').pop()] : schema);
const refName = (schema) => schema?.$ref?.split('/').pop();

/** One-line, TypeScript-like rendering of a schema. */
function typeText(schema, depth = 0) {
  if (!schema) return 'unknown';
  if (schema.$ref) return depth > 0 ? refName(schema) : typeText(resolve(schema), depth);
  if (schema.allOf) return schema.allOf.map((s) => typeText(s, depth + 1)).join(' & ');
  if (schema.const !== undefined) return JSON.stringify(schema.const);
  if (schema.enum) return schema.enum.map((v) => JSON.stringify(v)).join(' | ');
  const types = [].concat(schema.type ?? 'unknown');
  return types.map((t) => {
    if (t === 'array') return `${typeText(schema.items, depth + 1)}[]`;
    if (t === 'object' && schema.properties) {
      const req = new Set(schema.required ?? []);
      const props = Object.entries(schema.properties).map(([k, v]) => `${k}${req.has(k) ? '' : '?'}: ${typeText(v, depth + 1)}`);
      return `{ ${props.join(', ')} }`;
    }
    return schema.format === 'binary' ? 'binary' : t;
  }).join(' | ');
}

/** Example JSON value for a request body. */
function example(schema) {
  schema = resolve(schema);
  if (!schema) return null;
  if (schema.const !== undefined) return schema.const;
  if (schema.enum) return schema.enum[0];
  if (schema.allOf) return Object.assign({}, ...schema.allOf.map(example));
  switch ([].concat(schema.type)[0]) {
    case 'object': return Object.fromEntries(Object.entries(schema.properties ?? {}).map(([k, v]) => [k, example(v)]));
    case 'array': return [example(schema.items)];
    case 'integer': return 0;
    case 'boolean': return false;
    case 'string': return schema.format === 'date-time' ? new Date().toISOString() : '';
    default: return null;
  }
}

function tokenCard() {
  const input = h('input', { type: 'password', placeholder: 'Bearer token', 'aria-label': 'Bearer token', autocomplete: 'off', value: sessionStorage.getItem(TOKEN_KEY) ?? '' });
  const save = () => {
    if (input.value.trim()) sessionStorage.setItem(TOKEN_KEY, input.value.trim());
    else sessionStorage.removeItem(TOKEN_KEY);
  };
  return h('section', { class: 'card' },
    h('h2', {}, spec.info.title, ' ', h('span', { class: 'badge' }, `v${spec.info.version}`)),
    h('p', {}, md(spec.info.description)),
    h('p', { class: 'muted' }, 'Base URL: ', h('code', {}, `${location.origin}${spec.servers[0].url}`)),
    h('form', { class: 'row', onsubmit: (e) => { e.preventDefault(); save(); } },
      input, h('button', { type: 'submit' }, 'Use token'),
      h('span', { class: 'muted' }, 'Or run POST /auth/login below; its token is used automatically.')),
  );
}

function tryIt(method, pathTemplate, op) {
  const params = op.parameters ?? [];
  const jsonSchema = op.requestBody?.content?.['application/json']?.schema;
  const binary = !!op.requestBody?.content?.['application/octet-stream'];
  const output = h('pre', { class: 'response', hidden: true });

  const inputs = params.map((p) => h('label', {}, `${p.name} (${p.in}${p.required ? ', required' : ''})`,
    h('input', { name: `${p.in}:${p.name}`, required: p.in === 'path' || undefined, autocomplete: 'off' })));
  const bodyField = jsonSchema
    ? h('label', {}, 'JSON body', h('textarea', { name: 'body', rows: 4, spellcheck: 'false' }, JSON.stringify(example(jsonSchema), null, 2)))
    : binary ? h('label', {}, '.kdbx file', h('input', { name: 'file', type: 'file', accept: '.kdbx' })) : null;

  const form = h('form', { class: 'stack try', onsubmit: async (e) => {
    e.preventDefault();
    const headers = {};
    const query = new URLSearchParams();
    let url = pathTemplate;
    for (const p of params) {
      const value = form.elements.namedItem(`${p.in}:${p.name}`).value;
      if (!value) continue;
      if (p.in === 'path') url = url.replace(`{${p.name}}`, encodeURIComponent(value));
      else if (p.in === 'query') query.set(p.name, value);
      else headers[p.name] = value;
    }
    const token = sessionStorage.getItem(TOKEN_KEY);
    if (token) headers.Authorization = `Bearer ${token}`;
    const init = { method: method.toUpperCase(), headers };
    if (jsonSchema) { init.body = form.elements.namedItem('body').value; headers['Content-Type'] = 'application/json'; }
    const file = binary && form.elements.namedItem('file').files[0];
    if (file) { init.body = file; headers['Content-Type'] = 'application/octet-stream'; }

    output.hidden = false;
    output.textContent = '…';
    try {
      const res = await fetch(`${spec.servers[0].url}${url}${query.size ? `?${query}` : ''}`, init);
      const type = res.headers.get('Content-Type') ?? '';
      let text;
      if (type.includes('json')) {
        const data = await res.json();
        if (pathTemplate === '/auth/login' && data.token) { sessionStorage.setItem(TOKEN_KEY, data.token); main.querySelector('input[type=password]').value = data.token; }
        text = JSON.stringify(data, null, 2);
      } else {
        text = res.body ? `(${(await res.arrayBuffer()).byteLength} bytes, ${type || 'no content type'})` : '';
      }
      const shown = ['ETag', 'X-KPS-Revision', 'X-KPS-SHA256'].filter((k) => res.headers.has(k)).map((k) => `${k}: ${res.headers.get(k)}\n`).join('');
      output.textContent = `${res.status} ${res.statusText}\n${shown}\n${text}`;
    } catch (err) {
      output.textContent = String(err);
    }
  } }, inputs, bodyField, h('div', {}, h('button', { class: 'primary', type: 'submit' }, 'Send')), output);
  return form;
}

function operation(method, path, op) {
  const params = op.parameters ?? [];
  const reqSchema = op.requestBody?.content?.['application/json']?.schema;
  const reqBinary = op.requestBody?.content?.['application/octet-stream'];
  const isPublic = Array.isArray(op.security) && op.security.length === 0;
  return h('details', { class: 'op', id: `${method}-${path}` },
    h('summary', {}, h('span', { class: `method ${method}` }, method.toUpperCase()), ' ', h('code', {}, path), ' ',
      h('span', { class: 'muted' }, op.summary), isPublic ? [' ', h('span', { class: 'badge' }, 'public')] : null),
    op.description ? h('p', {}, md(op.description)) : null,
    params.length ? [h('h3', {}, 'Parameters'), h('div', { class: 'table-wrap' }, h('table', {},
      h('tbody', {}, params.map((p) => h('tr', {},
        h('td', {}, h('code', {}, p.name), p.required ? ' *' : ''), h('td', { class: 'muted' }, p.in),
        h('td', {}, h('code', {}, typeText(p.schema))), h('td', {}, md(p.description)))))))] : null,
    reqSchema ? [h('h3', {}, 'Request body (JSON)'), h('pre', {}, typeText(reqSchema))] : null,
    reqBinary ? [h('h3', {}, 'Request body'), h('p', {}, h('code', {}, 'application/octet-stream'), ' (.kdbx file)')] : null,
    h('h3', {}, 'Responses'),
    h('div', { class: 'table-wrap' }, h('table', {}, h('tbody', {}, Object.entries(op.responses).map(([status, r]) => {
      const content = r.content ?? {};
      const schema = content['application/json']?.schema;
      return h('tr', {},
        h('td', {}, h('span', { class: `badge${Number(status) >= 400 ? ' warn' : ''}` }, status)),
        h('td', {}, md(r.description)),
        h('td', {}, schema ? h('code', {}, refName(schema) ?? typeText(schema)) : content['application/octet-stream'] ? h('code', {}, 'binary') : null));
    })))),
    h('h3', {}, 'Try it'),
    tryIt(method, path, op),
  );
}

function schemasCard() {
  return h('section', { class: 'card' }, h('h2', {}, 'Schemas'),
    Object.entries(spec.components.schemas).map(([name, s]) => h('div', { id: `schema-${name}` },
      h('h3', {}, name), h('pre', {}, typeText(s)))));
}

async function start() {
  try {
    spec = await (await fetch('/api/openapi.json')).json();
  } catch (err) {
    main.replaceChildren(h('section', { class: 'card' }, `Could not load the API description: ${err.message}`));
    return;
  }
  const byTag = new Map();
  for (const [path, ops] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(ops)) {
      const tag = op.tags?.[0] ?? 'Other';
      if (!byTag.has(tag)) byTag.set(tag, []);
      byTag.get(tag).push(operation(method, path, op));
    }
  }
  main.replaceChildren(
    tokenCard(),
    ...[...byTag].map(([tag, ops]) => h('section', { class: 'card' }, h('h2', {}, tag), ops)),
    schemasCard(),
  );
}

start();
