const test = require('node:test');
const assert = require('node:assert/strict');
const { PassThrough } = require('node:stream');
const { spawnSync } = require('node:child_process');
const { Security, normalizePhone } = require('../security');

function createMemoryStore() {
  const data = new Map();
  return { read: (k, fallback) => data.has(k) ? structuredClone(data.get(k)) : fallback, write: (k, v) => data.set(k, structuredClone(v)), data };
}
function request(data = {}, headers = {}) {
  const req = new PassThrough(); req.headers = headers; req.socket = { remoteAddress: '127.0.0.1' };
  process.nextTick(() => req.end(JSON.stringify(data))); return req;
}
function response() {
  return { status: 200, headers: {}, body: '', writeHead(status, headers = {}) { this.status = status; Object.assign(this.headers, headers); }, setHeader(k, v) { this.headers[k] = v; }, end(value = '') { this.body = value.toString(); }, json() { return JSON.parse(this.body || '{}'); } };
}

test('normalizes Persian and Iranian phone number formats', () => {
  assert.equal(normalizePhone('۰۹۱۲۱۲۳۴۵۶۷'), '+989121234567');
  assert.equal(normalizePhone('9121234567'), '+989121234567');
  assert.equal(normalizePhone('+98 912 123 4567'), '+989121234567');
  assert.equal(normalizePhone('12345'), null);
});

test('sets iframe-compatible partitioned cookies only with secure transport', () => {
  const db = createMemoryStore();
  const auth = new Security({ readJson: db.read, saveJson: db.write, audit: () => {}, env: { NODE_ENV: 'test', AUTH_COOKIE_SECURE: 'true', AUTH_COOKIE_SAMESITE: 'None', AUTH_COOKIE_PARTITIONED: 'true' } });
  const res = response(); auth.setCookie(res, 'hy_session', 'token', 100, request({}, { 'x-forwarded-proto': 'https' }));
  assert.match(res.headers['Set-Cookie'][0], /SameSite=None/);
  assert.match(res.headers['Set-Cookie'][0], /Secure/);
  assert.match(res.headers['Set-Cookie'][0], /Partitioned/);
  const sessionRes = response(), user = { id: 'test-user', phone: '+989121234567', role: 'system_admin', status: 'active' }; db.write('users.json', [user]);
  auth.sessionCookieName = 'hy_session_preview'; auth.createSession(request({}, { 'x-forwarded-proto': 'https' }), sessionRes, user);
  const cookieValue = sessionRes.headers['Set-Cookie'][0].match(/hy_session_preview=([^;]+)/)[1];
  assert.equal(auth.activeSession({ headers: { cookie: `hy_session_preview=${cookieValue}` }, socket: { remoteAddress: '127.0.0.1' } }).user.id, 'test-user');
  const insecure = new Security({ readJson: db.read, saveJson: db.write, audit: () => {}, env: { NODE_ENV: 'test', AUTH_COOKIE_SAMESITE: 'None' } });
  assert.throws(() => insecure.setCookie(response(), 'hy_session', 'token', 100, request()), /SameSite=None cookies require Secure HTTPS/);
});

test('OTP verifies, creates a bootstrap admin, and requires CSRF on writes', async () => {
  const db = createMemoryStore(); let code = null;
  const env = { NODE_ENV: 'test', AUTH_DEV_MODE: 'true', AUTH_PREVIEW_BEARER: 'true', SMS_GATEWAY_URL: 'https://sms.example.test/send', SMS_GATEWAY_TOKEN: 'dummy', ADMIN_BOOTSTRAP_PHONE: '+989121234567', OTP_HMAC_SECRET: 'test-secret' };
  const auth = new Security({ readJson: db.read, saveJson: db.write, audit: () => {}, env });
  auth.sendSms = async (_phone, value) => { code = value; };
  const sent = response(); await auth.requestOtp(request({ phone: '09121234567' }), sent);
  assert.equal(sent.status, 200); assert.ok(code);
  const challengeId = sent.json().challengeId;
  const verified = response(); await auth.verifyOtp(request({ challengeId, phone: '+989121234567', code, name: 'مدیر آزمایشی', municipality: 'سازمان' }), verified);
  const session = verified.json();
  assert.equal(verified.status, 200); assert.equal(session.user.role, 'system_admin'); assert.equal(session.user.status, 'active'); assert.ok(session.previewToken);
  assert.equal(auth.activeSession(request({}, { authorization: `Bearer ${session.previewToken}` })).user.id, session.user.id);
  const setCookie = Array.isArray(verified.headers['Set-Cookie']) ? verified.headers['Set-Cookie'].join(';') : verified.headers['Set-Cookie'];
  const tokenCookie = setCookie.match(/hy_session=([^;]+)/)[1];
  const cookie = `hy_session=${decodeURIComponent(tokenCookie)}`;
  const unsafe = request({}, { cookie }); unsafe.method = 'POST'; const deny = response();
  assert.equal(auth.authorize(unsafe, deny), null); assert.equal(deny.status, 403);
  const safe = request({}, { cookie, 'x-csrf-token': session.csrfToken }); safe.method = 'POST'; const allow = response();
  assert.equal(auth.authorize(safe, allow).id, session.user.id);
});

test('new users cannot choose their own privileged role and await approval', async () => {
  const db = createMemoryStore(); let code;
  const env = { NODE_ENV: 'test', SMS_GATEWAY_URL: 'https://sms.example.test/send', SMS_GATEWAY_TOKEN: 'dummy', ADMIN_BOOTSTRAP_PHONE: '+989121234567' };
  const auth = new Security({ readJson: db.read, saveJson: db.write, audit: () => {}, env }); auth.sendSms = async (_p, c) => { code = c; };
  let res = response(); await auth.requestOtp(request({ phone: '+989121234568' }), res); const challengeId = res.json().challengeId;
  res = response(); await auth.verifyOtp(request({ challengeId, phone: '+989121234568', code, name: 'کاربر شهرداری', municipality: 'نیشابور', role: 'system_admin' }), res);
  assert.equal(res.json().user.role, 'municipality_member'); assert.equal(res.json().user.status, 'pending');
});

test('production refuses to start without an encryption key', () => {
  const result = spawnSync(process.execPath, ['server.js'], { cwd: require('node:path').join(__dirname, '..'), encoding: 'utf8', env: { ...process.env, NODE_ENV: 'production', DATA_ENCRYPTION_KEY: '', PUBLIC_URL: 'https://example.test', ADMIN_BOOTSTRAP_PHONE: '+989121234567', SMS_GATEWAY_URL: 'https://sms.example.test/send', SMS_GATEWAY_TOKEN: 'dummy', AUTH_DEV_MODE: 'false' } });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /DATA_ENCRYPTION_KEY/);
});
