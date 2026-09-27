const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Security, json: authJson, parseCookies } = require('./security');

const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
const DOCS = path.join(DATA, 'documents');
const PORT = Number(process.env.PORT || 8000);
const OLLAMA_URL = (process.env.OLLAMA_URL || 'http://127.0.0.1:11434').replace(/\/$/, '');
const MODEL = process.env.OLLAMA_MODEL || 'qwen2.5:7b';
function parseEncryptionKey(value) {
  if (!value) return null;
  if (/^[a-f0-9]{64}$/i.test(value)) return Buffer.from(value, 'hex');
  const key = Buffer.from(value, 'base64');
  if (key.length !== 32) throw new Error('DATA_ENCRYPTION_KEY must be a 32-byte base64 string or 64 hexadecimal characters.');
  return key;
}
const ENCRYPTION_KEY = parseEncryptionKey(process.env.DATA_ENCRYPTION_KEY);
if (process.env.NODE_ENV === 'production') {
  if (!ENCRYPTION_KEY) throw new Error('Production startup refused: set DATA_ENCRYPTION_KEY to protect stored documents, accounts and audit logs.');
  if (!/^https:\/\//i.test(process.env.PUBLIC_URL || '')) throw new Error('Production startup refused: PUBLIC_URL must be the public HTTPS origin.');
  if (!process.env.SMS_GATEWAY_URL || !/^https:\/\//i.test(process.env.SMS_GATEWAY_URL) || !process.env.SMS_GATEWAY_TOKEN) throw new Error('Production startup refused: configure an HTTPS SMS gateway and token.');
}
fs.mkdirSync(DATA, { recursive: true, mode: 0o700 });
fs.mkdirSync(DOCS, { recursive: true, mode: 0o700 });
if (process.env.NODE_ENV === 'production') {
  fs.chmodSync(DATA, 0o700); fs.chmodSync(DOCS, 0o700);
  for (const name of ['documents.json','feedback.json','users.json','sessions.json','audit.json']) { const file = path.join(DATA, name); if (fs.existsSync(file)) fs.chmodSync(file, 0o600); }
}
const jsonPath = name => path.join(DATA, name);
function readJson(name, fallback) {
  try {
    let raw = fs.readFileSync(jsonPath(name), 'utf8');
    if (raw.startsWith('ENC1:')) {
      if (!ENCRYPTION_KEY) throw new Error(`Encrypted ${name} cannot be opened without DATA_ENCRYPTION_KEY.`);
      const [iv64, tag64, payload64] = raw.slice(5).split(':');
      const decipher = crypto.createDecipheriv('aes-256-gcm', ENCRYPTION_KEY, Buffer.from(iv64, 'base64'));
      decipher.setAuthTag(Buffer.from(tag64, 'base64'));
      raw = Buffer.concat([decipher.update(Buffer.from(payload64, 'base64')), decipher.final()]).toString('utf8');
    } else if (process.env.NODE_ENV === 'production' && ENCRYPTION_KEY && ['documents.json','feedback.json','users.json','sessions.json','audit.json'].includes(name)) {
      throw new Error(`Refusing plaintext ${name} in production; migrate it to encrypted storage before startup.`);
    }
    return JSON.parse(raw);
  } catch (e) { if (e.code === 'ENOENT') return fallback; throw e; }
}
function saveJson(name, value) {
  let raw = JSON.stringify(value, null, 2);
  if (ENCRYPTION_KEY && ['documents.json','feedback.json','users.json','sessions.json','audit.json'].includes(name)) {
    const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
    const encrypted = Buffer.concat([cipher.update(raw, 'utf8'), cipher.final()]);
    raw = `ENC1:${iv.toString('base64')}:${cipher.getAuthTag().toString('base64')}:${encrypted.toString('base64')}`;
  }
  const target = jsonPath(name), temporary = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(temporary, raw, { mode: 0o600 }); fs.renameSync(temporary, target);
}
// Install the public-information starter pack once, preserving any documents already uploaded.
const starterMarker = path.join(DATA, '.starter-pack-installed');
if (!fs.existsSync(starterMarker)) {
  const existing = readJson('documents.json', []);
  const ids = new Set(existing.map(d => d.id));
  const starter = require('./seed-docs').filter(d => !ids.has(d.id));
  if (starter.length) saveJson('documents.json', [...starter, ...existing]);
  fs.writeFileSync(starterMarker, new Date().toISOString(), 'utf8');
}
function send(res, status, data, type = 'application/json; charset=utf-8') { res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }); res.end(type.startsWith('application/json') ? JSON.stringify(data) : data); }
function body(req) { return new Promise((resolve, reject) => { let text = ''; req.on('data', c => { text += c; if (text.length > 18_000_000) req.destroy(); }); req.on('end', () => { try { resolve(JSON.parse(text || '{}')); } catch (e) { reject(e); } }); req.on('error', reject); }); }
function audit(action, details, req) {
  const records = readJson('audit.json', []);
  records.push({ id: crypto.randomUUID(), action, at: new Date().toISOString(), ip: String(process.env.TRUST_PROXY === 'true' ? (req?.headers['x-forwarded-for'] || req?.socket.remoteAddress) : (req?.socket.remoteAddress || 'unknown')).split(',')[0].slice(0, 100), details });
  saveJson('audit.json', records.slice(-10000));
}
if (process.env.NODE_ENV === 'production' && !process.env.ADMIN_BOOTSTRAP_PHONE && !readJson('users.json', []).some(u => u.role === 'system_admin' && u.status === 'active')) {
  throw new Error('Production startup refused: set ADMIN_BOOTSTRAP_PHONE until the first active system administrator is bootstrapped.');
}
const security = new Security({ readJson, saveJson, audit });
function visibleDocsFor(user) {
  const all = readJson('documents.json', []);
  return all.filter(d => user.role === 'system_admin' || !d.municipalityScope || d.municipalityScope === user.municipality);
}
function tokenize(s) { return (s.normalize('NFKC').replace(/[يى]/g, 'ی').replace(/ك/g, 'ک').toLocaleLowerCase('fa').match(/[\p{L}\p{N}]{2,}/gu) || []).filter(w => !STOP.has(w)); }
const STOP = new Set('از به با برای که و در را این آن است هستند شود شده می یک یا تا بر اگر شود درباره لطفا لطفاً کنید'.split(' '));
function chunksFor(doc) {
  const text = doc.text.replace(/\r/g, '').trim();
  const paras = text.split(/\n\s*\n/).map(s => s.trim()).filter(Boolean);
  const chunks = []; let current = '';
  for (const para of paras.length ? paras : [text]) {
    if ((current + '\n' + para).length > 1050 && current) { chunks.push(current); current = ''; }
    if (para.length > 1300) { for (let i = 0; i < para.length; i += 950) chunks.push(para.slice(i, i + 950)); }
    else current += (current ? '\n' : '') + para;
  }
  if (current) chunks.push(current);
  return chunks.map((text, i) => ({ text, index: i }));
}
function retrieve(question, docs, limit = 5) {
  const q = tokenize(question); if (!q.length) return [];
  const chunks = docs.flatMap(d => chunksFor(d).map(c => ({ ...c, doc: d })));
  const df = new Map();
  for (const c of chunks) for (const t of new Set(tokenize(c.text))) df.set(t, (df.get(t) || 0) + 1);
  const scored = chunks.map(c => {
    const terms = tokenize(c.text), freq = new Map(); terms.forEach(t => freq.set(t, (freq.get(t) || 0) + 1));
    let score = 0;
    for (const t of q) { const f = freq.get(t) || 0; if (f) score += (1 + Math.log(f)) * (1 + Math.log((chunks.length + 1) / ((df.get(t) || 0) + 1))); }
    const title = tokenize(c.doc.name).join(' '); if (q.some(t => title.includes(t))) score *= 1.35;
    return { ...c, score };
  }).filter(c => c.score > 0).sort((a, b) => b.score - a.score);
  const selected = [], seenDocs = new Set();
  for (const hit of scored) {
    if (seenDocs.has(hit.doc.id)) continue;
    selected.push(hit); seenDocs.add(hit.doc.id);
    if (selected.length >= limit) break;
  }
  return selected;
}
function publicDoc(d) { return { id: d.id, name: d.name, size: Buffer.byteLength(d.text, 'utf8'), addedAt: d.addedAt, chars: d.text.length, municipalityScope: d.municipalityScope || null, uploadedBy: d.uploadedBy || null }; }
async function ollamaGenerate(question, contexts, feedback) {
  const context = contexts.map((c, i) => `منبع ${i + 1}: ${c.doc.name}\n${c.text}`).join('\n\n---\n\n');
  const learned = feedback.filter(f => f.correction).slice(-12).map(f => `پرسش: ${f.question}\nپاسخ اصلاح‌شده: ${f.correction}`).join('\n\n');
  const prompt = `شما دستیار داخلی سازمان همیاری شهرداری‌های خراسان رضوی هستید. فقط بر اساس متن منابع پاسخ بده. اگر پاسخ در منابع نیست، صریح بگو اطلاعات کافی در اسناد بارگذاری‌شده پیدا نشد و حدس نزن. پاسخ فارسی، روشن و اداری باشد. به بازخوردهای اصلاحی زیر در حد راهنمای پاسخ توجه کن؛ این موارد جایگزین بخشنامه رسمی نیستند.\n\nبازخوردهای تاییدشده/اصلاحی:\n${learned || 'هنوز بازخورد اصلاحی ثبت نشده است.'}\n\nمنابع مرتبط:\n${context || 'منبع مرتبطی پیدا نشد.'}\n\nپرسش: ${question}`;
  const controller = new AbortController(); const timer = setTimeout(() => controller.abort(), 45_000);
  try {
    const response = await fetch(`${OLLAMA_URL}/api/generate`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model: MODEL, prompt, stream: false, options: { temperature: 0.15 } }), signal: controller.signal });
    if (!response.ok) return null;
    const data = await response.json(); return data.response?.trim() || null;
  } catch { return null; } finally { clearTimeout(timer); }
}
function staticFile(req, res) {
  const pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  const allowed = new Map([['/', 'index.html'], ['/index.html', 'index.html'], ['/styles.css', 'styles.css'], ['/app.js', 'app.js']]);
  const filename = allowed.get(pathname);
  if (!filename) return send(res, 404, 'پیدا نشد', 'text/plain; charset=utf-8');
  const file = path.join(ROOT, filename);
  const ext = path.extname(file); const types = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8' };
  send(res, 200, fs.readFileSync(file), types[ext]);
}

const server = http.createServer(async (req, res) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] !== 'https') {
    res.writeHead(308, { Location: `${process.env.PUBLIC_URL}${req.url}`, 'Cache-Control': 'no-store' }); return res.end();
  }
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'");
  res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  if (process.env.NODE_ENV === 'production' && req.headers['x-forwarded-proto'] === 'https') res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  try {
    if (req.method === 'GET' && pathname === '/api/auth/config') return authJson(res, 200, security.config());
    if (req.method === 'GET' && pathname === '/api/auth/me') return security.me(req, res);
    if (req.method === 'POST' && pathname === '/api/auth/otp/request') return security.requestOtp(req, res);
    if (req.method === 'POST' && pathname === '/api/auth/otp/verify') return security.verifyOtp(req, res);
    if (req.method === 'POST' && pathname === '/api/auth/google/complete-otp') {
      if (!parseCookies(req).hy_google_pending) return authJson(res, 401, { error: 'ورود گوگل منقضی شده است.' });
      return security.googleCompleteOtp(req, res);
    }
    if (req.method === 'POST' && pathname === '/api/auth/logout') return security.logout(req, res);
    if (req.method === 'GET' && pathname === '/auth/google') return security.startGoogle(req, res);
    if (req.method === 'GET' && pathname === '/auth/google/callback') return security.googleCallback(req, res);
    if (pathname.startsWith('/api/')) {
      if (req.method === 'GET' && pathname === '/api/admin/users') {
        const user = security.authorize(req, res); if (!user) return; return security.adminUsers(req, res);
      }
      const user = security.authorize(req, res); if (!user) return;
      const userMatch = pathname.match(/^\/api\/admin\/users\/([a-f0-9-]+)$/i);
      if (userMatch && req.method === 'PATCH') return security.updateUser(req, res, userMatch[1]);
    }
    if (req.method === 'GET' && pathname === '/api/status') {
      let ollama = false; let models = [];
      try { const r = await fetch(`${OLLAMA_URL}/api/tags`, { signal: AbortSignal.timeout(1600) }); if (r.ok) { ollama = true; models = (await r.json()).models?.map(m => m.name) || []; } } catch {}
      const docs = visibleDocsFor(req.user), allFeedback = readJson('feedback.json', []);
      const feedback = allFeedback.filter(f => security.isAdmin(req.user) || f.userId === req.user.id);
      return send(res, 200, { ok: true, ollama, model: MODEL, models, docs: docs.length, feedback: feedback.length, storage: 'local' });
    }
    if (req.method === 'GET' && pathname === '/api/documents') return send(res, 200, visibleDocsFor(req.user).map(publicDoc));
    if (req.method === 'POST' && pathname === '/api/documents') {
      if (!security.isLibraryManager(req.user)) return send(res, 403, { error: 'مجوز بارگذاری سند ندارید.' });
      const data = await body(req); const name = String(data.name || '').trim().slice(0, 180); const text = String(data.text || '').trim();
      if (!name || !text) return send(res, 400, { error: 'نام فایل و محتوای متنی لازم است.' });
      if (Buffer.byteLength(text, 'utf8') > 12_000_000) return send(res, 413, { error: 'حجم فایل از ۱۲ مگابایت بیشتر است.' });
      const scope = String(data.municipalityScope || '').trim();
      if (!security.isAdmin(req.user) && !scope) return send(res, 403, { error: 'انتشار سند برای همه شهرداری‌ها فقط با مجوز مدیر سامانه ممکن است.' });
      if (scope && !req.user.municipality && !security.isAdmin(req.user)) return send(res, 400, { error: 'برای سند محدود، شهرداری کاربر باید مشخص باشد.' });
      if (scope && !security.isAdmin(req.user) && scope !== req.user.municipality) return send(res, 403, { error: 'مدیر دانش فقط می‌تواند سند را برای واحد خود محدود کند.' });
      const docs = readJson('documents.json', []); const id = crypto.randomUUID();
      const doc = { id, name, text, municipalityScope: scope || null, uploadedBy: req.user.id, addedAt: new Date().toISOString() }; docs.unshift(doc); saveJson('documents.json', docs);
      audit('document_upload', { userId: req.user.id, documentId: id, name, municipalityScope: scope || null }, req);
      return send(res, 201, publicDoc(doc));
    }
    if (req.method === 'DELETE' && pathname.startsWith('/api/documents/')) {
      if (!security.isLibraryManager(req.user)) return send(res, 403, { error: 'مجوز حذف سند ندارید.' });
      const id = pathname.split('/').pop(); const docs = readJson('documents.json', []); const target = docs.find(d => d.id === id);
      if (!target || (!security.isAdmin(req.user) && (target.uploadedBy !== req.user.id || (target.municipalityScope && target.municipalityScope !== req.user.municipality)))) return send(res, 404, { error: 'سند پیدا نشد.' });
      const next = docs.filter(d => d.id !== id); saveJson('documents.json', next);
      audit('document_delete', { userId: req.user.id, documentId: id, name: target.name }, req); return send(res, 200, { ok: true });
    }
    if (req.method === 'POST' && pathname === '/api/chat') {
      const data = await body(req); const question = String(data.question || '').trim().slice(0, 3000);
      if (!question) return send(res, 400, { error: 'پرسش را وارد کنید.' });
      const docs = visibleDocsFor(req.user); const hits = retrieve(question, docs);
      const feedback = readJson('feedback.json', []).filter(f => security.isAdmin(req.user) || f.userId === req.user.id);
      const answer = await ollamaGenerate(question, hits, feedback);
      const fallback = hits.length ? `در اسناد بارگذاری‌شده این بخش‌ها با پرسش شما مرتبط هستند. برای استناد دقیق، متن اصلی و شماره/تاریخ بخشنامه را بررسی کنید:\n\n${hits.slice(0, 3).map(h => `«${h.text.slice(0, 720)}${h.text.length > 720 ? '…' : ''}»`).join('\n\n')}${hits.length ? '' : ''}` : 'در اسناد فعلی مورد مرتبطی پیدا نشد. لطفاً بخشنامه یا دستورالعمل مربوط را بارگذاری کنید. این سامانه بدون منبع رسمی پاسخ حدسی نمی‌دهد.';
      return send(res, 200, { answer: answer || fallback, mode: answer ? 'local-ai' : 'retrieval', sources: hits.map(h => ({ name: h.doc.name, excerpt: h.text.slice(0, 330), score: Math.round(h.score * 10) / 10 })) });
    }
    if (req.method === 'POST' && pathname === '/api/feedback') {
      const data = await body(req); const question = String(data.question || '').trim().slice(0, 3000); const correction = String(data.correction || '').trim().slice(0, 5000);
      if (!question) return send(res, 400, { error: 'پرسش ثبت نشده است.' });
      const feedback = readJson('feedback.json', []); feedback.push({ id: crypto.randomUUID(), userId: req.user.id, municipality: req.user.municipality, question, correction, rating: data.rating === 'up' ? 'up' : data.rating === 'down' ? 'down' : null, createdAt: new Date().toISOString() }); saveJson('feedback.json', feedback);
      audit('answer_feedback', { userId: req.user.id, rating: data.rating || null }, req);
      return send(res, 201, { ok: true });
    }
    if (req.method === 'GET' && pathname === '/api/feedback') return send(res, 200, readJson('feedback.json', []).filter(f => security.isAdmin(req.user) || f.userId === req.user.id).slice(-50).reverse());
    if (pathname.startsWith('/api/')) return send(res, 404, { error: 'مسیر API پیدا نشد.' });
    return staticFile(req, res);
  } catch (error) { console.error(error); return send(res, 500, { error: 'خطای داخلی سامانه.' }); }
});
server.listen(PORT, '0.0.0.0', () => console.log(`HamYari local AI listening on http://0.0.0.0:${PORT}`));
