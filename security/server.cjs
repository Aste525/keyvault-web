'use strict';
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const ALGOS = Object.freeze(['X448', 'RSA-2048', 'Serpent-256', 'ARIA-256-GCM', 'CAST-256', 'SHA-256', 'RIPEMD-320', 'Ed448', 'ECDSA', 'Schnorr']);
const DIR = path.join(process.cwd(), '.keyvault-v2');
const FILE = path.join(DIR, 'state.json');
const sessions = new Map();
const challenges = new Map();
const limits = new Map();
const DNS_SERVERS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/dns-query', 'https://dns.quad9.net/dns-query'];
const now = () => Date.now();
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
const random = () => crypto.randomBytes(32).toString('base64url');
const hexAddress = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const json = (res, code, value, extra = {}) => {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra });
  res.end(JSON.stringify(value));
};
const bad = (res, code, error) => json(res, code, { ok: false, error });
let state = { version: 2, accounts: {} };
try {
  state = JSON.parse(fs.readFileSync(FILE, 'utf8'));
  if (!state || typeof state.accounts !== 'object' || !state.accounts) throw Error('State tidak valid');
} catch (e) {
  if (e.code !== 'ENOENT') throw e;
}
const persist = () => {
  fs.mkdirSync(DIR, { recursive: true, mode: 0o700 });
  const tmp = path.join(DIR, `state.${process.pid}.${random().slice(0, 8)}.tmp`);
  fs.writeFileSync(tmp, JSON.stringify(state), { mode: 0o600, flag: 'wx' });
  fs.renameSync(tmp, FILE);
};
const loopback = ip => /^(::1|127\.|::ffff:127\.)/.test(String(ip || ''));
const secure = req => !!(req.socket.encrypted || (loopback(req.socket.remoteAddress) && req.headers['x-forwarded-proto'] === 'https'));
const local = req => loopback(req.socket.remoteAddress) && !req.headers['x-forwarded-proto'];
const verifyTransport = req => secure(req) || local(req);
const sameOrigin = req => {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    const input = new URL(origin);
    const host = req.headers.host;
    return input.host === host && (input.protocol === 'https:' ? secure(req) : local(req));
  } catch { return false; }
};
const isJson = req => (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() === 'application/json';
const read = async (req, max = 16384) => {
  const chunks = []; let size = 0;
  for await (const data of req) {
    size += data.length;
    if (size > max) throw Error('Ukuran permintaan melebihi batas');
    chunks.push(data);
  }
  return Buffer.concat(chunks);
};
const body = async req => JSON.parse((await read(req)).toString('utf8'));
const budget = (id, cap, duration) => {
  const time = now();
  let item = limits.get(id);
  if (!item || item.until < time) item = { count: 0, until: time + duration };
  item.count++;
  limits.set(id, item);
  if (limits.size > 5000) for (const [k, v] of limits) if (v.until < time) limits.delete(k);
  return item.count <= cap;
};
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';').map(s => s.trim().split(/=(.*)/s).slice(0, 2)).filter(a => a[0]));
const signedIn = req => {
  const cookie = cookies(req).kv_session;
  if (typeof cookie !== 'string' || !/^[\w-]{32,128}$/.test(cookie)) return null;
  const key = digest(cookie);
  const entry = sessions.get(key);
  if (!entry) return null;
  if (entry.expires <= now()) { sessions.delete(key); return null; }
  return entry.address;
};
const makeCookie = (value, req, maxAge = 43200) => `kv_session=${value}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${secure(req) ? '; Secure' : ''}`;
const parseSelected = data => {
  const values = data.algorithms ?? data.selected ?? data.selectedAlgorithms;
  if (!Array.isArray(values) || values.some(v => typeof v !== 'string' || !ALGOS.includes(v))) throw Error('Pilihan algoritma invalid');
  return [...new Set(values)];
};
const getEnabled = data => {
  const raw = data.enabled ?? data.active ?? data.on ?? data.mode;
  if (raw === true || raw === 'ON' || raw === 'on') return true;
  if (raw === false || raw === 'OFF' || raw === 'off') return false;
  throw Error('Status mode harus ON atau OFF');
};
const normalizeSpki = value => {
  if (typeof value !== 'string' || value.length > 1024 || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('Public key invalid');
  const der = Buffer.from(value, 'base64url');
  const pub = crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  if (pub.asymmetricKeyType !== 'ec' || pub.asymmetricKeyDetails?.namedCurve !== 'prime256v1') throw Error('Kunci wajib ECDSA P-256');
  const canonical = pub.export({ format: 'der', type: 'spki' });
  if (!der.equals(canonical)) throw Error('Public key nonkanonis');
  return { pub, der };
};
const validSig = (pub, text, signature) => {
  if (typeof signature !== 'string' || signature.length > 256 || !/^[A-Za-z0-9_-]+$/.test(signature)) return false;
  const buf = Buffer.from(signature, 'base64url');
  return buf.length === 64 && crypto.verify('sha256', Buffer.from(text), { key: pub, dsaEncoding: 'ieee-p1363' }, buf);
};
const takeChallenge = (challengeId, address) => {
  const item = challenges.get(challengeId);
  challenges.delete(challengeId);
  if (!item || item.address !== address || item.expires <= now()) throw Error('Tantangan kedaluwarsa');
  return `KeyVault-v2:${address}:${item.nonce}`;
};
const saveMode = (res, address, data) => {
  let enabled, algorithms;
  try {
    enabled = getEnabled(data);
    algorithms = parseSelected(data);
    if (enabled && algorithms.length === 0) throw Error('Pilih paling sedikit satu algoritma');
  } catch (e) { return bad(res, 400, e.message); }
  const account = state.accounts[address];
  account.mode = { enabled, algorithms, updatedAt: new Date().toISOString() };
  if (!enabled) account.doh = null;
  persist();
  json(res, 200, { ok: true, ...account.mode, dohAvailable: enabled && !!account.doh });
};
const dns = async (req, res, pathname, search) => {
  if (req.method !== 'GET' && req.method !== 'POST') return bad(res, 405, 'Metode invalid');
  const token = pathname.slice('/dns/'.length);
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) return bad(res, 401, 'Akses DNS ditolak');
  const hashed = digest(token);
  let account = null;
  for (const item of Object.values(state.accounts)) {
    if (item.mode?.enabled && item.doh === hashed) { account = item; break; }
  }
  if (!account) return bad(res, 401, 'Mode DNS OFF atau token tidak valid');
  if (!budget(`dns:${hashed}`, 600, 60000)) return bad(res, 429, 'Batas frekuensi DNS sementara');
  let packet;
  try {
    if (req.method === 'GET') {
      const q = search.get('dns');
      if (typeof q !== 'string' || !/^[A-Za-z0-9_-]{16,8192}$/.test(q)) return bad(res, 400, 'Kueri DNS invalid');
      packet = Buffer.from(q, 'base64url');
    } else {
      if ((req.headers['content-type'] || '').split(';')[0] !== 'application/dns-message') return bad(res, 415, 'Gunakan application/dns-message');
      packet = await read(req, 65535);
    }
  } catch { return bad(res, 413, 'Paket DNS terlalu besar'); }
  if (packet.length < 12 || packet.length > 65535) return bad(res, 400, 'Paket DNS invalid');
  const first = (Math.floor(now() / 10000)) % DNS_SERVERS.length;
  for (let i = 0; i < DNS_SERVERS.length; i++) {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5000);
      try {
        const upstream = await fetch(DNS_SERVERS[(first + i) % DNS_SERVERS.length], {
          method: 'POST', body: packet, headers: { 'accept': 'application/dns-message', 'content-type': 'application/dns-message' }, signal: controller.signal, redirect: 'error'
        });
        if (!upstream.ok || !(upstream.headers.get('content-type') || '').startsWith('application/dns-message')) continue;
        const response = Buffer.from(await upstream.arrayBuffer());
        if (response.length < 12 || response.length > 65535) continue;
        res.writeHead(200, { 'content-type': 'application/dns-message', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
        return res.end(response);
      } finally { clearTimeout(timeout); }
    } catch {}
  }
  bad(res, 502, 'Resolver DNS upstream gagal');
};
const route = async (req, res, next) => {
  let url;
  try { url = new URL(req.url, 'http://localhost'); }
  catch { return bad(res, 400, 'URL invalid'); }
  const pathname = url.pathname;
  if (['/secure.html', '/secure.js', '/secure.css'].includes(pathname)) {
    if (req.method !== 'GET' && req.method !== 'HEAD') return bad(res, 405, 'Metode invalid');
    if (!verifyTransport(req)) return bad(res, 403, 'HTTPS diperlukan');
    const file = path.join(process.cwd(), 'public', pathname.slice(1));
    const mime = pathname.endsWith('.js') ? 'text/javascript' : pathname.endsWith('.css') ? 'text/css' : 'text/html';
    try {
      const data = fs.readFileSync(file);
      res.writeHead(200, {
        'content-type': `${mime}; charset=utf-8`, 'cache-control': 'no-store', 'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY',
        'content-security-policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
      });
      return res.end(req.method === 'HEAD' ? undefined : data);
    } catch { return bad(res, 404, 'Halaman keamanan tidak ditemukan'); }
  }
  const managed = pathname === '/api/mode' || pathname === '/api/modes' || pathname.startsWith('/api/v2/') || pathname.startsWith('/dns/');
  if (!managed) return next();
  if (!verifyTransport(req)) return bad(res, 403, 'HTTPS diperlukan');
  if (pathname === '/api/v2/health') return json(res, 200, { ok: true, service: 'keyvault-v2', backend: true });
  if (pathname.startsWith('/dns/')) return dns(req, res, pathname, url.searchParams);
  if (req.method === 'POST' && (!isJson(req) || !sameOrigin(req))) return bad(res, 403, 'JSON atau Origin tidak valid');
  if (pathname === '/api/v2/challenge' && req.method === 'POST') {
    if (!budget(`auth:${req.socket.remoteAddress}`, 30, 60000)) return bad(res, 429, 'Terlalu banyak percobaan');
    const input = await body(req);
    if (!hexAddress(input.address)) return bad(res, 400, 'Alamat invalid');
    const challengeId = random(); const nonce = random();
    challenges.set(challengeId, { address: input.address, nonce, expires: now() + 90000 });
    if (challenges.size > 2000) for (const [k, v] of challenges) if (v.expires < now()) challenges.delete(k);
    return json(res, 200, { ok: true, challengeId, message: `KeyVault-v2:${input.address}:${nonce}` });
  }
  if (pathname === '/api/v2/register' && req.method === 'POST') {
    if (!budget(`register:${req.socket.remoteAddress}`, 12, 60000)) return bad(res, 429, 'Terlalu banyak percobaan');
    const input = await body(req);
    if (!hexAddress(input.address) || typeof input.challengeId !== 'string') return bad(res, 400, 'Identitas invalid');
    const { pub, der } = normalizeSpki(input.publicKey);
    if (digest(der) !== input.address) return bad(res, 403, 'Alamat harus berasal dari public key');
    const message = takeChallenge(input.challengeId, input.address);
    if (!validSig(pub, message, input.signature)) return bad(res, 403, 'Tanda tangan salah');
    const existing = state.accounts[input.address];
    if (existing && existing.publicKey !== input.publicKey) return bad(res, 409, 'Akun sudah terdaftar');
    if (!existing) {
      state.accounts[input.address] = { publicKey: input.publicKey, mode: { enabled: false, algorithms: [], updatedAt: null }, doh: null };
      persist();
    }
    return json(res, 200, { ok: true, address: input.address });
  }
  if (pathname === '/api/v2/login' && req.method === 'POST') {
    if (!budget(`login:${req.socket.remoteAddress}`, 20, 60000)) return bad(res, 429, 'Terlalu banyak percobaan');
    const input = await body(req);
    if (!hexAddress(input.address) || typeof input.challengeId !== 'string') return bad(res, 400, 'Identitas invalid');
    const account = state.accounts[input.address];
    if (!account) return bad(res, 404, 'Identitas belum didaftarkan');
    const msg = takeChallenge(input.challengeId, input.address);
    const { pub } = normalizeSpki(account.publicKey);
    if (!validSig(pub, msg, input.signature)) return bad(res, 403, 'Tanda tangan salah');
    const token = random();
    sessions.set(digest(token), { address: input.address, expires: now() + 43200000 });
    return json(res, 200, { ok: true, address: input.address }, { 'set-cookie': makeCookie(token, req) });
  }
  const address = signedIn(req);
  if (pathname === '/api/v2/status' && req.method === 'GET') {
    if (!address) return json(res, 200, { ok: true, loggedIn: false });
    return json(res, 200, { ok: true, loggedIn: true, address, ...state.accounts[address].mode });
  }
  if (!address) return bad(res, 401, 'Login diperlukan');
  if (pathname === '/api/v2/logout' && req.method === 'POST') {
    const cookie = cookies(req).kv_session;
    if (cookie) sessions.delete(digest(cookie));
    return json(res, 200, { ok: true }, { 'set-cookie': makeCookie('', req, 0) });
  }
  if ((pathname === '/api/v2/mode' || pathname === '/api/mode' || pathname === '/api/modes') && req.method === 'POST') return saveMode(res, address, await body(req));
  if ((pathname === '/api/v2/mode' || pathname === '/api/mode' || pathname === '/api/modes') && req.method === 'GET') return json(res, 200, { ok: true, ...state.accounts[address].mode });
  if (pathname === '/api/v2/doh-token' && req.method === 'POST') {
    if (!state.accounts[address].mode.enabled) return bad(res, 409, 'Aktifkan mode ON lebih dulu');
    const token = random();
    state.accounts[address].doh = digest(token);
    persist();
    const host = req.headers.host;
    const scheme = secure(req) ? 'https' : 'http';
    return json(res, 200, { ok: true, dohUrl: `${scheme}://${host}/dns/${token}`, note: 'URL ini rahasia. Token lama otomatis dicabut.' });
  }
  return bad(res, 404, 'Endpoint tidak ditemukan');
};

module.exports = { route(req, res, next) { Promise.resolve().then(() => route(req, res, next)).catch(e => {
  if (res.headersSent) return res.destroy();
  const msg = e instanceof SyntaxError ? 'JSON invalid' : (e.message === 'Ukuran permintaan melebihi batas' ? e.message : 'Permintaan gagal');
  bad(res, e.message === 'Ukuran permintaan melebihi batas' ? 413 : 400, msg);
}); }, ALGOS };
