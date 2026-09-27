const crypto = require('node:crypto');

const ROLES = new Set(['system_admin', 'knowledge_manager', 'municipality_member']);
function normalizeDigits(value) { return String(value || '').replace(/[۰-۹]/g, d => String('۰۱۲۳۴۵۶۷۸۹'.indexOf(d))).replace(/[٠-٩]/g, d => String('٠١٢٣٤٥٦٧٨٩'.indexOf(d))); }
function normalizePhone(value) {
  let phone = normalizeDigits(value).replace(/[\s()-]/g, '');
  if (/^09\d{9}$/.test(phone)) phone = '+98' + phone.slice(1);
  else if (/^9\d{9}$/.test(phone)) phone = '+98' + phone;
  else if (/^0098\d{10}$/.test(phone)) phone = '+' + phone.slice(2);
  else if (/^98\d{10}$/.test(phone)) phone = '+' + phone;
  return /^\+[1-9]\d{7,14}$/.test(phone) ? phone : null;
}
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function parseCookies(req) {
  const out = {};
  for (const item of (req.headers.cookie || '').split(';')) {
    const i = item.indexOf('='); if (i > 0) out[item.slice(0, i).trim()] = decodeURIComponent(item.slice(i + 1).trim());
  }
  return out;
}
function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(data));
}
function textBody(req, max = 64_000) {
  return new Promise((resolve, reject) => {
    let value = '';
    req.on('data', chunk => { value += chunk; if (value.length > max) { reject(new Error('حجم درخواست بیش از حد مجاز است.')); req.destroy(); } });
    req.on('end', () => { try { resolve(JSON.parse(value || '{}')); } catch { reject(new Error('درخواست معتبر نیست.')); } });
    req.on('error', reject);
  });
}

class Security {
  constructor({ readJson, saveJson, audit, env = process.env }) {
    this.readJson = readJson; this.saveJson = saveJson; this.audit = audit; this.env = env;
    this.sessionCookieName = env.AUTH_COOKIE_NAME || 'hy_session';
    this.dev = env.AUTH_DEV_MODE === 'true' && env.NODE_ENV !== 'production';
    if (env.NODE_ENV === 'production' && env.AUTH_DEV_MODE === 'true') throw new Error('AUTH_DEV_MODE is forbidden in production.');
    if (env.NODE_ENV === 'production' && env.DEV_AUTO_APPROVE_USERS === 'true') throw new Error('DEV_AUTO_APPROVE_USERS is forbidden in production.');
    this.otpSecret = env.OTP_HMAC_SECRET || env.DATA_ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
    this.challenges = new Map(); this.pendingGoogle = new Map(); this.oauthStates = new Map(); this.rate = new Map();
    this.jwks = null; this.jwksUntil = 0;
    if (this.dev && env.DEV_AUTO_APPROVE_USERS === 'true') {
      const users = this.users(); let changed = false;
      for (const user of users) if (user.status === 'pending') { user.status = 'active'; changed = true; }
      if (changed) this.saveJson('users.json', users);
    }
  }
  users() { return this.readJson('users.json', []); }
  sessions() { return this.readJson('sessions.json', []); }
  activeSession(req) {
    const cookies = parseCookies(req);
    const bearer = /^Bearer ([A-Za-z0-9_-]+)$/.exec(req.headers.authorization || '');
    const token = this.dev && this.env.AUTH_PREVIEW_BEARER === 'true' && bearer ? bearer[1] : cookies[this.sessionCookieName];
    if (!token) return null;
    const digest = crypto.createHash('sha256').update(token).digest('hex');
    const sessions = this.sessions(); const session = sessions.find(s => safeEqual(s.tokenHash, digest) && Date.parse(s.expiresAt) > Date.now());
    if (!session) return null;
    const user = this.users().find(u => u.id === session.userId);
    return user ? { user, session } : null;
  }
  userView(user) { return { id: user.id, name: user.name, phone: user.phone, email: user.email || null, municipality: user.municipality || '', role: user.role, status: user.status, createdAt: user.createdAt }; }
  isAdmin(user) { return user.role === 'system_admin'; }
  isLibraryManager(user) { return user.role === 'system_admin' || user.role === 'knowledge_manager'; }
  isActive(user) { return user.status === 'active'; }
  adminPhone(phone) { return (this.env.ADMIN_BOOTSTRAP_PHONE || '').split(',').map(normalizePhone).filter(Boolean).includes(phone); }
  checkRate(req, key, limit, windowMs) {
    const forwarded = this.env.TRUST_PROXY === 'true' ? req.headers['x-forwarded-for'] : '';
    const ip = String(forwarded || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
    const now = Date.now(); const bucket = `${key}:${ip}`; const old = this.rate.get(bucket) || [];
    const recent = old.filter(t => now - t < windowMs);
    if (recent.length >= limit) return false;
    recent.push(now); this.rate.set(bucket, recent);
    if (this.rate.size > 5000) for (const [k, v] of this.rate) if (!v.length || now - v.at(-1) > windowMs) this.rate.delete(k);
    return true;
  }
  otpHash(id, phone, code) { return crypto.createHmac('sha256', this.otpSecret).update(`${id}:${phone}:${code}`).digest('hex'); }
  async sendSms(phone, code) {
    const url = this.env.SMS_GATEWAY_URL;
    if (this.dev) { console.info(`[AUTH DEV ONLY] OTP for ${phone}: ${code}`); return; }
    if (!url || !this.env.SMS_GATEWAY_TOKEN) throw new Error('درگاه پیامک سازمانی تنظیم نشده است.');
    const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 8000);
    try {
      const r = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${this.env.SMS_GATEWAY_TOKEN}` }, body: JSON.stringify({ to: phone, message: `کد ورود همیار: ${code} — این کد را در اختیار دیگران قرار ندهید.` }), signal: controller.signal, redirect: 'error' });
      if (!r.ok) throw new Error('ارسال پیامک از درگاه سازمانی انجام نشد.');
    } finally { clearTimeout(timer); }
  }
  config() { return { googleEnabled: Boolean(this.env.GOOGLE_CLIENT_ID && this.env.GOOGLE_CLIENT_SECRET && this.env.GOOGLE_REDIRECT_URI), phoneEnabled: this.dev || Boolean(this.env.SMS_GATEWAY_URL && this.env.SMS_GATEWAY_TOKEN), devMode: this.dev, devAutoApproval: this.dev && this.env.DEV_AUTO_APPROVE_USERS === 'true', production: this.env.NODE_ENV === 'production' }; }
  async requestOtp(req, res, googleKey = null) {
    if (!this.checkRate(req, 'otp-ip', 8, 15 * 60_000)) return json(res, 429, { error: 'درخواست‌های زیاد؛ چند دقیقه دیگر دوباره امتحان کنید.' });
    const data = await textBody(req); const phone = normalizePhone(data.phone);
    const now = Date.now();
    for (const [id, item] of this.challenges) if (item.expiresAt < now) this.challenges.delete(id);
    for (const [id, item] of this.pendingGoogle) if (item.expiresAt < now) this.pendingGoogle.delete(id);
    for (const [id, item] of this.oauthStates) if (item.expiresAt < now) this.oauthStates.delete(id);
    if (!phone) return json(res, 400, { error: 'شماره را با کد کشور وارد کنید؛ مانند ‎+989121234567.' });
    if (!this.config().phoneEnabled) return json(res, 503, { error: 'درگاه امن پیامک هنوز پیکربندی نشده است.' });
    if (!this.checkRate(req, `otp-phone-${phone}`, 3, 60 * 60_000)) return json(res, 429, { error: 'برای این شماره بیش از حد کد درخواست شده است.' });
    const id = crypto.randomUUID(), code = String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
    const record = { phone, hash: this.otpHash(id, phone, code), expiresAt: Date.now() + 5 * 60_000, tries: 0, googleKey };
    this.challenges.set(id, record);
    try { await this.sendSms(phone, code); }
    catch (e) { this.challenges.delete(id); return json(res, 503, { error: e.message || 'ارسال پیامک ممکن نشد.' }); }
    const result = { ok: true, challengeId: id, expiresIn: 300 };
    if (this.dev) result.debugCode = code;
    return json(res, 200, result);
  }
  appendCookie(res, cookie) {
    const previous = res.getHeader?.('Set-Cookie');
    const values = previous ? (Array.isArray(previous) ? previous : [previous]) : [];
    res.setHeader('Set-Cookie', [...values, cookie]);
  }
  cookiePolicy(req) {
    const secure = this.env.NODE_ENV === 'production' || this.env.AUTH_COOKIE_SECURE === 'true' || String(this.env.PUBLIC_URL || '').startsWith('https://') || req?.headers?.['x-forwarded-proto'] === 'https';
    const rawSameSite = String(this.env.AUTH_COOKIE_SAMESITE || 'Lax').toLowerCase();
    const sameSite = ({ lax: 'Lax', strict: 'Strict', none: 'None' })[rawSameSite];
    if (!sameSite) throw new Error('AUTH_COOKIE_SAMESITE must be Lax, Strict or None.');
    if (sameSite === 'None' && !secure) throw new Error('SameSite=None cookies require Secure HTTPS.');
    const partitioned = this.env.AUTH_COOKIE_PARTITIONED === 'true';
    if (partitioned && (!secure || sameSite !== 'None')) throw new Error('Partitioned cookies require Secure and SameSite=None.');
    return { secure, sameSite, partitioned };
  }
  setCookie(res, name, value, maxAge, req) {
    const policy = this.cookiePolicy(req);
    this.appendCookie(res, `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=${policy.sameSite}; Max-Age=${maxAge}${policy.secure ? '; Secure' : ''}${policy.partitioned ? '; Partitioned' : ''}`);
  }
  clearCookie(res, name, req) {
    const policy = this.cookiePolicy(req);
    this.appendCookie(res, `${name}=; Path=/; HttpOnly; SameSite=${policy.sameSite}; Max-Age=0${policy.secure ? '; Secure' : ''}${policy.partitioned ? '; Partitioned' : ''}`);
  }
  createSession(req, res, user) {
    const raw = crypto.randomBytes(32).toString('base64url'), csrf = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + 8 * 60 * 60_000).toISOString();
    const sessions = this.sessions().filter(s => Date.parse(s.expiresAt) > Date.now());
    sessions.push({ tokenHash: crypto.createHash('sha256').update(raw).digest('hex'), csrfToken: csrf, userId: user.id, createdAt: new Date().toISOString(), expiresAt });
    this.saveJson('sessions.json', sessions); this.setCookie(res, this.sessionCookieName, raw, 8 * 60 * 60, req);
    this.audit('login', { userId: user.id, role: user.role }, req);
    return { ok: true, user: this.userView(user), csrfToken: csrf, expiresAt, ...(this.dev && this.env.AUTH_PREVIEW_BEARER === 'true' ? { previewToken: raw } : {}) };
  }
  async verifyOtp(req, res) {
    if (!this.checkRate(req, 'otp-verify-ip', 30, 15 * 60_000)) return json(res, 429, { error: 'تلاش‌های زیاد؛ کمی بعد دوباره امتحان کنید.' });
    const data = await textBody(req); const record = this.challenges.get(String(data.challengeId || ''));
    const phone = normalizePhone(data.phone);
    if (!record || record.phone !== phone || record.expiresAt < Date.now()) return json(res, 400, { error: 'کد منقضی شده یا درخواست معتبر نیست.' });
    if (++record.tries > 5) { this.challenges.delete(String(data.challengeId)); return json(res, 429, { error: 'تعداد تلاش مجاز تمام شد؛ کد تازه بگیرید.' }); }
    const candidate = this.otpHash(String(data.challengeId), phone, normalizeDigits(data.code).trim());
    if (!safeEqual(candidate, record.hash)) return json(res, 400, { error: 'کد تأیید درست نیست.' });
    this.challenges.delete(String(data.challengeId));
    if (record.googleKey) return this.finishGooglePhone(req, res, record, data);
    const users = this.users(); let user = users.find(u => u.phone === phone);
    const name = String(data.name || '').trim().slice(0, 100);
    const municipality = String(data.municipality || '').trim().slice(0, 100);
    if (!user) {
      if (!name) return json(res, 400, { error: 'برای ساخت حساب، نام و نام خانوادگی را وارد کنید.' });
      if (!municipality) return json(res, 400, { error: 'نام شهرداری یا واحد سازمانی را وارد کنید.' });
      const firstDevAdmin = this.dev && this.env.ALLOW_FIRST_ADMIN === 'true' && !users.length;
      const admin = this.adminPhone(phone) || firstDevAdmin;
      const autoApprovedPreview = this.dev && this.env.DEV_AUTO_APPROVE_USERS === 'true';
      user = { id: crypto.randomUUID(), name, phone, municipality, role: admin ? 'system_admin' : 'municipality_member', status: admin || autoApprovedPreview ? 'active' : 'pending', createdAt: new Date().toISOString(), lastLoginAt: new Date().toISOString() };
      users.push(user); this.saveJson('users.json', users); this.audit('signup', { userId: user.id, role: user.role, municipality }, req);
    } else {
      user.lastLoginAt = new Date().toISOString();
      if (data.name?.trim()) user.name = name;
      if (data.municipality?.trim() && user.status === 'pending') user.municipality = municipality;
      if (this.adminPhone(phone)) { user.role = 'system_admin'; user.status = 'active'; }
      this.saveJson('users.json', users);
    }
    return json(res, 200, this.createSession(req, res, user));
  }
  async finishGooglePhone(req, res, challenge, data) {
    const pending = this.pendingGoogle.get(challenge.googleKey);
    if (!pending || pending.expiresAt < Date.now()) return json(res, 400, { error: 'ورود گوگل منقضی شده؛ دوباره تلاش کنید.' });
    const phone = challenge.phone, users = this.users(); let user = users.find(u => u.phone === phone);
    const emailOwner = users.find(u => u.email && u.email.toLowerCase() === pending.email.toLowerCase());
    const subjectOwner = users.find(u => u.googleSub && u.googleSub === pending.sub);
    if ((emailOwner && emailOwner.phone !== phone) || (subjectOwner && subjectOwner.phone !== phone)) return json(res, 409, { error: 'این حساب گوگل قبلاً به شماره دیگری متصل شده است. با مدیر سامانه تماس بگیرید.' });
    if (!user) {
      const name = String(data.name || pending.name || '').trim().slice(0, 100);
      const municipality = String(data.municipality || '').trim().slice(0, 100);
      if (!name || !municipality) return json(res, 400, { error: 'نام و نام شهرداری/واحد سازمانی لازم است.' });
      const admin = this.adminPhone(phone), autoApprovedPreview = this.dev && this.env.DEV_AUTO_APPROVE_USERS === 'true';
      user = { id: crypto.randomUUID(), name, phone, email: pending.email, googleSub: pending.sub, municipality, role: admin ? 'system_admin' : 'municipality_member', status: admin || autoApprovedPreview ? 'active' : 'pending', createdAt: new Date().toISOString(), lastLoginAt: new Date().toISOString() };
      users.push(user);
    } else {
      user.email = pending.email; user.googleSub = pending.sub; user.lastLoginAt = new Date().toISOString();
    }
    this.saveJson('users.json', users); this.pendingGoogle.delete(challenge.googleKey); this.clearCookie(res, 'hy_google_pending', req);
    this.audit('google_phone_link', { userId: user.id }, req);
    return json(res, 200, this.createSession(req, res, user));
  }
  async me(req, res) {
    const session = this.activeSession(req);
    if (!session) { this.clearCookie(res, this.sessionCookieName, req); return json(res, 200, { authenticated: false, config: this.config() }); }
    return json(res, 200, { authenticated: true, user: this.userView(session.user), csrfToken: session.session.csrfToken, expiresAt: session.session.expiresAt, config: this.config() });
  }
  async logout(req, res) {
    const session = this.activeSession(req);
    if (session) {
      const sent = req.headers['x-csrf-token'];
      if (!sent || !safeEqual(sent, session.session.csrfToken)) return json(res, 403, { error: 'درخواست خروج معتبر نیست؛ صفحه را تازه‌سازی کنید.' });
      this.saveJson('sessions.json', this.sessions().filter(s => s.userId !== session.user.id || s.tokenHash !== session.session.tokenHash));
    }
    this.clearCookie(res, this.sessionCookieName, req); this.clearCookie(res, 'hy_google_pending', req); this.audit('logout', { userId: session?.user.id || null }, req); return json(res, 200, { ok: true });
  }
  authorize(req, res) {
    const session = this.activeSession(req);
    if (!session) { json(res, 401, { error: 'برای ادامه وارد حساب کاربری شوید.', code: 'AUTH_REQUIRED' }); return null; }
    if (!this.isActive(session.user)) { json(res, 403, { error: session.user.status === 'disabled' ? 'حساب شما غیرفعال شده است؛ با مدیر سامانه تماس بگیرید.' : 'حساب شما در انتظار تأیید مدیر سامانه است.', code: session.user.status === 'disabled' ? 'ACCOUNT_DISABLED' : 'ACCOUNT_PENDING' }); return null; }
    req.user = session.user;
    if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      const sent = req.headers['x-csrf-token'];
      if (!sent || !safeEqual(sent, session.session.csrfToken)) { json(res, 403, { error: 'اعتبار امنیتی درخواست منقضی شده است؛ صفحه را تازه‌سازی کنید.', code: 'CSRF' }); return null; }
    }
    return session.user;
  }
  async startGoogle(req, res) {
    if (!this.config().googleEnabled) return json(res, 503, { error: 'ورود گوگل پیکربندی نشده است.' });
    if (!this.checkRate(req, 'google-start-ip', 20, 15 * 60_000)) return json(res, 429, { error: 'درخواست‌های زیاد؛ کمی بعد دوباره تلاش کنید.' });
    const now = Date.now(); for (const [id, item] of this.oauthStates) if (item.expiresAt < now) this.oauthStates.delete(id);
    const state = crypto.randomBytes(32).toString('base64url'), nonce = crypto.randomBytes(32).toString('base64url'), verifier = crypto.randomBytes(48).toString('base64url');
    const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
    this.oauthStates.set(state, { nonce, verifier, expiresAt: Date.now() + 10 * 60_000 });
    this.setCookie(res, 'hy_oauth_state', state, 600, req);
    const params = new URLSearchParams({ client_id: this.env.GOOGLE_CLIENT_ID, redirect_uri: this.env.GOOGLE_REDIRECT_URI, response_type: 'code', scope: 'openid email profile', state, nonce, code_challenge: challenge, code_challenge_method: 'S256', prompt: 'select_account' });
    res.writeHead(302, { Location: `https://accounts.google.com/o/oauth2/v2/auth?${params}`, 'Cache-Control': 'no-store' }); res.end();
  }
  async googleCallback(req, res) {
    const url = new URL(req.url, 'http://localhost'), state = url.searchParams.get('state'), code = url.searchParams.get('code'), record = this.oauthStates.get(state);
    const stateCookie = parseCookies(req).hy_oauth_state; this.clearCookie(res, 'hy_oauth_state', req); this.oauthStates.delete(state);
    if (url.searchParams.has('error') || !record || record.expiresAt < Date.now() || !code || !stateCookie || !safeEqual(state, stateCookie)) { res.writeHead(302, { Location: '/?authError=google' }); return res.end(); }
    try {
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code, client_id: this.env.GOOGLE_CLIENT_ID, client_secret: this.env.GOOGLE_CLIENT_SECRET, redirect_uri: this.env.GOOGLE_REDIRECT_URI, grant_type: 'authorization_code', code_verifier: record.verifier }), signal: AbortSignal.timeout(8000), redirect: 'error' });
      if (!tokenResponse.ok) throw new Error('Google token exchange failed');
      const tokens = await tokenResponse.json(), claims = await this.verifyGoogleIdToken(tokens.id_token, record.nonce);
      const googleKey = crypto.randomBytes(32).toString('base64url');
      this.pendingGoogle.set(googleKey, { email: claims.email, sub: claims.sub, name: claims.name || claims.email.split('@')[0], expiresAt: Date.now() + 10 * 60_000 });
      this.setCookie(res, 'hy_google_pending', googleKey, 600, req); res.writeHead(302, { Location: '/?google=verify-phone', 'Cache-Control': 'no-store' }); res.end();
    } catch (e) { console.error('Google sign-in failed:', e.message); res.writeHead(302, { Location: '/?authError=google' }); res.end(); }
  }
  async verifyGoogleIdToken(jwt, expectedNonce) {
    const parts = String(jwt || '').split('.'); if (parts.length !== 3) throw new Error('Invalid Google ID token');
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString()); const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (header.alg !== 'RS256' || !header.kid) throw new Error('Invalid Google token algorithm');
    if (!this.jwks || this.jwksUntil < Date.now()) {
      const r = await fetch('https://www.googleapis.com/oauth2/v3/certs', { signal: AbortSignal.timeout(5000) }); if (!r.ok) throw new Error('Google signing keys unavailable');
      this.jwks = (await r.json()).keys; this.jwksUntil = Date.now() + 60 * 60_000;
    }
    const jwk = this.jwks.find(k => k.kid === header.kid); if (!jwk) throw new Error('Google signing key not found');
    const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
    const valid = crypto.verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), key, Buffer.from(parts[2], 'base64url'));
    const now = Math.floor(Date.now() / 1000);
    if (!valid || !['accounts.google.com', 'https://accounts.google.com'].includes(claims.iss) || claims.aud !== this.env.GOOGLE_CLIENT_ID || (claims.azp && claims.azp !== this.env.GOOGLE_CLIENT_ID) || !Number.isFinite(claims.exp) || !Number.isFinite(claims.iat) || claims.exp < now || claims.iat > now + 60 || claims.nonce !== expectedNonce || claims.email_verified !== true || !claims.sub || !claims.email) throw new Error('Google identity validation failed');
    return claims;
  }
  async adminUsers(req, res) {
    if (!this.isAdmin(req.user)) return json(res, 403, { error: 'فقط مدیر سامانه به این بخش دسترسی دارد.' });
    return json(res, 200, this.users().map(u => this.userView(u)));
  }
  async updateUser(req, res, id) {
    if (!this.isAdmin(req.user)) return json(res, 403, { error: 'فقط مدیر سامانه می‌تواند دسترسی کاربران را تغییر دهد.' });
    const data = await textBody(req), users = this.users(), user = users.find(u => u.id === id);
    if (!user) return json(res, 404, { error: 'کاربر پیدا نشد.' });
    if (id === req.user.id && data.status === 'disabled') return json(res, 400, { error: 'نمی‌توانید حساب خودتان را غیرفعال کنید.' });
    if (id === req.user.id && data.role && data.role !== 'system_admin') return json(res, 400, { error: 'برای جلوگیری از قفل‌شدن سامانه، نقش مدیر خودتان را تغییر ندهید.' });
    const wouldRemoveAdmin = user.role === 'system_admin' && ((data.role && data.role !== 'system_admin') || data.status === 'disabled' || data.status === 'pending');
    if (wouldRemoveAdmin && users.filter(u => u.role === 'system_admin' && u.status === 'active').length <= 1) return json(res, 400, { error: 'ابتدا مدیر سامانهٔ دیگری فعال کنید.' });
    if (data.status && !['active', 'pending', 'disabled'].includes(data.status)) return json(res, 400, { error: 'وضعیت نامعتبر است.' });
    if (data.role && !ROLES.has(data.role)) return json(res, 400, { error: 'نقش نامعتبر است.' });
    if (data.municipality !== undefined) user.municipality = String(data.municipality).trim().slice(0, 100);
    if (data.status) user.status = data.status;
    if (data.role) user.role = data.role;
    this.saveJson('users.json', users);
    if (data.status && data.status !== 'active') this.saveJson('sessions.json', this.sessions().filter(s => s.userId !== id));
    this.audit('admin_user_update', { actorId: req.user.id, targetId: id, changes: { status: data.status, role: data.role, municipality: data.municipality } }, req);
    return json(res, 200, this.userView(user));
  }
  async googleCompleteOtp(req, res) {
    const key = parseCookies(req).hy_google_pending;
    if (!key || !this.pendingGoogle.has(key)) return json(res, 401, { error: 'مرحلهٔ گوگل منقضی شده؛ دوباره شروع کنید.' });
    return this.requestOtp(req, res, key);
  }
}
module.exports = { Security, normalizePhone, parseCookies, textBody, json };
