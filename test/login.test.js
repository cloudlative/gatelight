'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { startApp } = require('./helpers');
const { hashPassword, verifyHash } = require('../src/login');

const emptyInstances = () => { const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'nx-')), 'i.json'); fs.writeFileSync(f, '[]'); return f; };
const dataDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'nx-data-'));
const env = (extra = {}) => ({ INSTANCES_FILE: emptyInstances(), DATA_DIR: dataDir(), DEMO_MODE: 'true', AUTH_USER: 'ops', AUTH_PASS: 'a-long-test-password', ...extra });
const login = (base, body, headers = {}) => fetch(`${base}/auth/login`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });
const cookieOf = (res) => (res.headers.get('set-cookie') || '').split(';')[0];

test('the main page and API need a session; the sign-in page and its assets do not', async () => {
  const t = await startApp(env());
  try {
    const page = await fetch(`${t.base}/`, { redirect: 'manual', headers: { Accept: 'text/html' } });
    assert.equal(page.status, 302); assert.equal(page.headers.get('location'), '/login');
    assert.equal((await fetch(`${t.base}/api/instances`)).status, 401);
    assert.equal((await fetch(`${t.base}/api/instances`)).headers.get('www-authenticate'), null, 'no browser Basic prompt');
    for (const p of ['/login', '/login.js', '/app.css', '/logo.svg', '/healthz', '/brands/cyferio.svg', '/brands/invisibly.svg', '/brands/braintally.svg']) assert.equal((await fetch(`${t.base}${p}`)).status, 200, p);
    for (const p of ['/app.js', '/index.html', '/metrics', '/readyz', '/api/meta']) assert.notEqual((await fetch(`${t.base}${p}`)).status, 200, `${p} must stay behind the login`);
  } finally { await t.close(); }
});

test('sign in sets an HttpOnly SameSite=Strict cookie that unlocks the app; sign out ends it', async () => {
  const t = await startApp(env());
  try {
    const bad = await login(t.base, { username: 'ops', password: 'nope' });
    assert.equal(bad.status, 401); assert.ok(!bad.headers.get('set-cookie'));
    assert.equal((await login(t.base, { username: 'nobody', password: 'a-long-test-password' })).status, 401);
    const ok = await login(t.base, { username: 'ops', password: 'a-long-test-password' });
    assert.equal(ok.status, 200);
    const sc = ok.headers.get('set-cookie');
    assert.match(sc, /gl_auth=/); assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/);
    const c = cookieOf(ok);
    assert.equal((await fetch(`${t.base}/api/instances`, { headers: { Cookie: c } })).status, 200);
    assert.equal((await (await fetch(`${t.base}/api/meta`, { headers: { Cookie: c } })).json()).authUser, 'ops');
    assert.equal((await fetch(`${t.base}/`, { headers: { Cookie: c, Accept: 'text/html' } })).status, 200);
    // a tampered cookie is rejected
    const [p, sig] = c.slice('gl_auth='.length).split('.');
    assert.equal((await fetch(`${t.base}/api/instances`, { headers: { Cookie: `gl_auth=${p}.${sig.slice(1)}x` } })).status, 401);
    // sign-out clears it in the browser
    const out = await fetch(`${t.base}/auth/logout`, { method: 'POST', headers: { Cookie: c } });
    assert.match(out.headers.get('set-cookie'), /Max-Age=0/);
  } finally { await t.close(); }
});

test('sign-in refuses cross-origin and non-JSON posts, and locks out repeated failures', async () => {
  const t = await startApp(env());
  try {
    assert.equal((await login(t.base, { username: 'ops', password: 'a-long-test-password' }, { Origin: 'https://evil.example' })).status, 403);
    const form = await fetch(`${t.base}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'text/plain' }, body: '{}' });
    assert.equal(form.status, 415);
    for (let i = 0; i < 5; i++) assert.equal((await login(t.base, { username: 'ops', password: `wrong${i}` })).status, 401);
    const locked = await login(t.base, { username: 'ops', password: 'a-long-test-password' }); // even the right password is refused while locked
    assert.equal(locked.status, 429); assert.ok(Number(locked.headers.get('retry-after')) > 0);
  } finally { await t.close(); }
});

test('scripts keep working with Bearer/Basic, and AUTH_PASS_HASH replaces a plaintext password', async () => {
  const hash = hashPassword('hash-based-secret');
  assert.ok(verifyHash('hash-based-secret', hash)); assert.ok(!verifyHash('other', hash));
  const t = await startApp({ INSTANCES_FILE: emptyInstances(), DATA_DIR: dataDir(), DEMO_MODE: 'true', AUTH_USER: 'ops', AUTH_PASS_HASH: hash, AUTH_TOKEN: 'tok' });
  try {
    assert.equal((await fetch(`${t.base}/metrics`, { headers: { Authorization: 'Bearer tok' } })).status, 200);
    assert.equal((await fetch(`${t.base}/api/instances`, { headers: { Authorization: `Basic ${Buffer.from('ops:hash-based-secret').toString('base64')}` } })).status, 200);
    assert.equal((await login(t.base, { username: 'ops', password: 'wrong' })).status, 401);
    assert.equal((await login(t.base, { username: 'ops', password: 'hash-based-secret' })).status, 200);
  } finally { await t.close(); }
});

test('with no password configured nothing changes: no login wall, no sign-out button data', async () => {
  const t = await startApp({ INSTANCES_FILE: emptyInstances(), DEMO_MODE: 'true' });
  try {
    assert.equal((await fetch(`${t.base}/api/instances`)).status, 200);
    assert.equal((await (await fetch(`${t.base}/api/meta`)).json()).authUser, null);
    assert.equal((await login(t.base, { username: 'a', password: 'b' })).status, 400);
  } finally { await t.close(); }
});

test('a sign-in survives a restart: the session secret is kept in the data volume', async () => {
  const e = env();
  let t = await startApp(e);
  let cookie;
  try { cookie = cookieOf(await login(t.base, { username: 'ops', password: 'a-long-test-password' })); } finally { await t.close(); }
  assert.ok(fs.statSync(path.join(e.DATA_DIR, '.auth-secret')).mode & 0o600, 'secret file exists');
  assert.equal(fs.statSync(path.join(e.DATA_DIR, '.auth-secret')).mode & 0o077, 0, 'and is private (0600)');
  t = await startApp(e); // "redeploy"
  try { assert.equal((await fetch(`${t.base}/api/instances`, { headers: { Cookie: cookie } })).status, 200, 'old cookie still valid after restart'); } finally { await t.close(); }
});

test('first run: a random password is generated once, kept, and an explicit password wins', () => {
  const fs = require('fs'); const os = require('os'); const path = require('path');
  const { ensureInitialPassword } = require('../src/initialAuth');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'gl-init-'));
  const mk = () => ({ auth: { user: 'admin', pass: null, passHash: null, token: null, enabled: false }, ui: { dir } });
  const s1 = mk(); const r1 = ensureInitialPassword(s1, { AUTH_AUTOGEN: 'true' });
  assert.equal(r1.generated, true); assert.ok(r1.password.length >= 16); assert.equal(s1.auth.enabled, true); assert.equal(s1.auth.pass, r1.password);
  assert.equal(fs.statSync(path.join(dir, '.initial-password')).mode & 0o777, 0o600);
  const s2 = mk(); const r2 = ensureInitialPassword(s2, { AUTH_AUTOGEN: 'true' });
  assert.equal(r2.generated, false); assert.equal(s2.auth.pass, r1.password, 'same password after a restart');
  const s3 = mk(); s3.auth.pass = 'chosen-by-the-user'; assert.equal(ensureInitialPassword(s3, { AUTH_AUTOGEN: 'true' }).active, false); assert.equal(s3.auth.pass, 'chosen-by-the-user');
  assert.equal(ensureInitialPassword(mk(), {}).active, false, 'off unless AUTH_AUTOGEN=true');
});
