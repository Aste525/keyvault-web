// core.js - logika API Key Vault. Dipakai bersama oleh Cloudflare Workers (worker.js) dan Node (server.js).
// Hanya memakai API web standar (Request, Response, fetch, WebCrypto), tanpa dependensi npm.
import { ripemd320, toHex } from './public/ciphers.js';

const ROTATE_MS = 10000;
const AUTH_WINDOW_MS = 120000;
const ADDR_RE = /^[a-z2-7]{26}$/;
const ALGOS = new Set(['x448', 'rsa2048', 'serpent256', 'aria256gcm', 'cast256', 'sha256', 'ripemd320', 'ed448', 'ecdsa', 'schnorr', 'combo']);
const MAX_LEDGER = 10 * 1024 * 1024;
const MAX_BODY = 8192;
const HASH_HEX = { sha256: 64, ripemd320: 80 };

// Maksimal 10 DNS upstream (DoH)
const UPSTREAM = [
  'https://cloudflare-dns.com/dns-query',
  'https://dns.google/dns-query',
  'https://dns.quad9.net/dns-query',
  'https://dns.adguard-dns.com/dns-query',
  'https://doh.mullvad.net/dns-query',
  'https://doh.opendns.com/dns-query',
  'https://doh.cleanbrowsing.org/doh/security-filter/',
  'https://doh.dns.sb/dns-query',
  'https://freedns.controld.com/p0',
  'https://doh.libredns.gr/dns-query'
];

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET, POST, OPTIONS',
  'access-control-allow-headers': 'content-type, x-kv-ed, x-kv-p256, x-kv-ts, x-kv-sig'
};

const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const B32 = 'abcdefghijklmnopqrstuvwxyz234567';
function b32(bytes) {
  let bits = 0, v = 0, o = '';
  for (const x of bytes) {
    v = (v << 8) | x; bits += 8;
    while (bits >= 5) { o += B32[(v >>> (bits - 5)) & 31]; bits -= 5; }
    v &= (1 << bits) - 1;
  }
  return o;
}
const sha256 = async (data) => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof data === 'string' ? enc.encode(data) : data));
const sha256Hex = async (data) => hex(await sha256(data));
const safeEq = (a, b) => { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; };

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
const json = (code, obj) => new Response(JSON.stringify(obj), { status: code, headers: { ...CORS, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });
const plain = (code) => new Response(null, { status: code, headers: CORS });
async function readText(req) {
  const t = await req.text();
  if (t.length > MAX_BODY) throw new HttpError(413, 'Permintaan terlalu besar');
  return t;
}

/* ===================== Autentikasi backend =====================
   Alamat = base32(SHA-256(kunci publik Ed448 || kunci publik P-256))[:26].
   Setiap permintaan yang mengubah data atau membaca data pribadi ditandatangani ECDSA P-256 oleh pemilik alamat:
   pesan = KV1 \n host \n METHOD \n path+query \n timestamp \n SHA-256(body)
   Server memeriksa: alamat cocok dengan hash kunci publik, jam dalam jendela 120 detik, tanda tangan sah, bukan permintaan ulang. */
const seen = new Map();
async function authenticate(req, u, bodyText) {
  const ed = req.headers.get('x-kv-ed') || '';
  const p256 = req.headers.get('x-kv-p256') || '';
  const sig = req.headers.get('x-kv-sig') || '';
  const ts = Number(req.headers.get('x-kv-ts'));
  if (!/^[0-9a-f]{114}$/.test(ed) || !/^[0-9a-f]{130}$/.test(p256) || !/^[0-9a-f]{128}$/.test(sig) || !Number.isFinite(ts)) throw new HttpError(401, 'Tanda tangan tidak ada atau formatnya salah');
  const now = Date.now();
  if (Math.abs(now - ts) > AUTH_WINDOW_MS) throw new HttpError(401, 'Jam perangkat tidak sinkron dengan server');
  if (seen.has(sig)) throw new HttpError(401, 'Permintaan ulang ditolak');
  const addr = b32(await sha256(unhex(ed + p256))).slice(0, 26);
  const key = await crypto.subtle.importKey('raw', unhex(p256), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const msg = enc.encode(`KV1\n${u.host}\n${req.method}\n${u.pathname}${u.search}\n${ts}\n${await sha256Hex(bodyText)}`);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, unhex(sig), msg);
  if (!ok) throw new HttpError(401, 'Tanda tangan tidak sah');
  seen.set(sig, now);
  if (seen.size > 2000) for (const [k, t] of seen) if (now - t > AUTH_WINDOW_MS * 2) seen.delete(k);
  return addr;
}

/* ===================== Profil mode ON per alamat ===================== */
const cache = new Map();
async function loadProfile(env, addr) {
  const c = cache.get(addr);
  if (c && c.exp > Date.now()) return c;
  const [m, h] = await Promise.all([env.KV.get('modes:' + addr), env.KV.get('dohhash:' + addr)]);
  const p = { exp: Date.now() + 60000, on: Boolean(m && JSON.parse(m).length), hash: h || '' };
  cache.set(addr, p);
  if (cache.size > 1000) cache.clear();
  return p;
}

/* ===================== Ledger (blok head 0x01, maksimal 10MB, hash blok: SHA-256 atau RIPEMD-320) ===================== */
const blockData = (b) => { const d = [b.index, b.prev, b.ts, b.file, b.a, b.b, b.result]; if (b.signer) d.push(b.signer); return JSON.stringify(d); };
async function hashBlock(algo, data) {
  if (algo === 'ripemd320') return toHex(ripemd320(enc.encode(data)));
  return sha256Hex(data);
}
async function seal(b, algo) {
  b.algo = algo;
  b.hash = await hashBlock(algo, blockData(b));
  return b;
}
async function loadChain(env) {
  const raw = await env.KV.get('chain');
  if (raw) return JSON.parse(raw);
  const g = await seal({ index: 1, prev: '0x00', ts: Date.now(), file: 'HEAD', a: '0x01', b: '0x01', result: 'GENESIS' }, 'sha256');
  await env.KV.put('chain', JSON.stringify([g]));
  return [g];
}
const appendLog = new Map();
function allowAppend(addr) {
  const now = Date.now();
  const arr = (appendLog.get(addr) || []).filter((t) => now - t < 3600000);
  if (arr.length >= 30) return false;
  arr.push(now); appendLog.set(addr, arr);
  if (appendLog.size > 2000) appendLog.clear();
  return true;
}
async function appendBlock(env, signer, file, algo, a, b) {
  const len = HASH_HEX[algo];
  if (!len || typeof file !== 'string' || typeof a !== 'string' || typeof b !== 'string') return { code: 400, error: 'Data tidak valid' };
  if (!new RegExp(`^[0-9a-f]{${len}}$`).test(a) || !new RegExp(`^[0-9a-f]{${len}}$`).test(b)) return { code: 400, error: 'Data tidak valid' };
  if (a !== b) return { code: 422, error: 'Hasil tidak sah: hash berbeda, tidak dicatat' };
  if (!allowAppend(signer)) return { code: 429, error: 'Terlalu banyak catatan ledger dari alamat ini (maksimal 30 per jam)' };
  const chain = await loadChain(env);
  const last = chain[chain.length - 1];
  const blk = await seal({ index: last.index + 1, prev: last.hash, ts: Date.now(), file: file.slice(0, 200), a, b, result: 'ASLI', signer }, algo);
  const text = JSON.stringify([...chain, blk]);
  if (text.length > MAX_LEDGER) return { code: 507, error: 'Ledger penuh (10MB)' };
  await env.KV.put('chain', text);
  return { code: 200, block: blk };
}

/* ===================== DNS-over-HTTPS dengan Auto Mix, dengan token ===================== */
const hits = new Map();
function upstreamIndex(addr) {
  let o = 0;
  for (let i = 0; i < addr.length; i++) o = (o * 31 + addr.charCodeAt(i)) & 255;
  return (Math.floor(Date.now() / ROTATE_MS) + o) % UPSTREAM.length;
}
// Auto Mix DNS: tiap permintaan dikirim ke resolver acak (urutan diacak dengan RNG kriptografis),
// sehingga tidak ada satu resolver pun yang melihat semua pencarian satu pengguna.
function randomOrder(n) {
  const a = Array.from({ length: n }, (_, i) => i);
  const r = crypto.getRandomValues(new Uint32Array(n));
  for (let i = n - 1; i > 0; i--) { const j = r[i] % (i + 1); [a[i], a[j]] = [a[j], a[i]]; }
  return a;
}
async function forwardDns(addr, query) {
  for (const idx of randomOrder(UPSTREAM.length)) {
    const url = UPSTREAM[idx];
    try {
      const r = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
        body: query,
        signal: AbortSignal.timeout(4000)
      });
      if (r.ok) return await r.arrayBuffer();
    } catch { /* coba upstream berikutnya */ }
  }
  return null;
}
function fromBase64Url(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  const o = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) o[i] = b.charCodeAt(i);
  return o;
}

/* ===================== Handler ===================== */
export async function handle(req, env) {
  const u = new URL(req.url);
  const p = u.pathname;
  if (req.method === 'OPTIONS') return plain(204);
  try {
    if (p === '/' || p === '/api/health') {
      return json(200, { status: 'ok', nama: 'Key Vault API', versi: 2, kv: Boolean(env.KV), waktu: Date.now(), colo: (req.cf && req.cf.colo) || null });
    }
    if (!env.KV) throw new HttpError(500, 'Binding KV belum dipasang');

    // DNS: /dns/<alamat>/<token>. Hanya jalan bila Mode ON aktif dan token cocok dengan hash yang didaftarkan pemilik alamat.
    const m = p.match(/^\/dns\/([a-z2-7]{26})\/([0-9a-f]{32})$/);
    if (m) {
      const addr = m[1];
      const prof = await loadProfile(env, addr);
      if (!prof.on || !prof.hash || !safeEq(await sha256Hex(m[2]), prof.hash)) return plain(403);
      const bucket = Math.floor(Date.now() / 1000);
      const h = hits.get(addr);
      const n = h && h.t === bucket ? h.n + 1 : 1;
      hits.set(addr, { t: bucket, n });
      if (hits.size > 500) hits.clear();
      if (n > 100) return plain(429);
      let q;
      if (req.method === 'POST') q = await req.arrayBuffer();
      else if (req.method === 'GET' && u.searchParams.get('dns')) q = fromBase64Url(u.searchParams.get('dns'));
      else return plain(400);
      if (q.byteLength > 4096) return plain(413);
      const ans = await forwardDns(addr, q);
      if (!ans) return plain(502);
      return new Response(ans, { status: 200, headers: { ...CORS, 'content-type': 'application/dns-message', 'cache-control': 'no-store' } });
    }

    // Profil DNS untuk iPhone/iPad: satu ketukan, tanpa menempel URL
    const mp = p.match(/^\/dns-profile\/([a-z2-7]{26})\/([0-9a-f]{32})\.mobileconfig$/);
    if (mp) {
      const prof = await loadProfile(env, mp[1]);
      if (!prof.on || !prof.hash || !safeEq(await sha256Hex(mp[2]), prof.hash)) return plain(403);
      const id = await sha256Hex('kv-profile|' + mp[1]);
      const uuid = (s) => `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20, 32)}`.toUpperCase();
      const xml = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>DNSSettings</key><dict><key>DNSProtocol</key><string>HTTPS</string><key>ServerURL</key><string>${u.origin}/dns/${mp[1]}/${mp[2]}</string></dict>
<key>PayloadDescription</key><string>DNS aman Key Vault</string>
<key>PayloadDisplayName</key><string>Key Vault DNS</string>
<key>PayloadIdentifier</key><string>com.keyvault.dns.${mp[1]}</string>
<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
<key>PayloadUUID</key><string>${uuid(id)}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></array>
<key>PayloadDisplayName</key><string>Key Vault DNS</string>
<key>PayloadIdentifier</key><string>com.keyvault.profile.${mp[1]}</string>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>${uuid(await sha256Hex('kv-profile-root|' + mp[1]))}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>
`;
      return new Response(xml, { status: 200, headers: { ...CORS, 'content-type': 'application/x-apple-aspen-config', 'content-disposition': 'attachment; filename="keyvault-dns.mobileconfig"', 'cache-control': 'no-store' } });
    }
    if (p.startsWith('/dns/')) throw new HttpError(401, 'Token DNS diperlukan');

    if (p === '/api/rotation' && req.method === 'GET') {
      const addr = u.searchParams.get('addr') || '';
      if (!ADDR_RE.test(addr)) throw new HttpError(400, 'Alamat tidak valid');
      return json(200, { n: upstreamIndex(addr) + 1, total: UPSTREAM.length, nextMs: ROTATE_MS - (Date.now() % ROTATE_MS) });
    }

    if (p === '/api/ledger' && req.method === 'GET') {
      const limit = Math.min(parseInt(u.searchParams.get('limit') || '20', 10) || 20, 100);
      const chain = await loadChain(env);
      return json(200, { blocks: chain.slice(-limit).reverse(), total: chain.length, bytes: JSON.stringify(chain).length, max: MAX_LEDGER });
    }

    if (p === '/api/mode' && req.method === 'GET') {
      const auth = await authenticate(req, u, '');
      if ((u.searchParams.get('addr') || '') !== auth) throw new HttpError(403, 'Alamat tidak sesuai dengan tanda tangan');
      const raw = await env.KV.get('modes:' + auth);
      return json(200, { active: raw ? JSON.parse(raw) : [] });
    }

    if (p === '/api/mode' && req.method === 'POST') {
      const text = await readText(req);
      const auth = await authenticate(req, u, text);
      const { addr, algo, on, dohHash } = JSON.parse(text);
      if (addr !== auth) throw new HttpError(403, 'Alamat tidak sesuai dengan tanda tangan');
      if (!ALGOS.has(algo)) throw new HttpError(400, 'Algoritma tidak dikenal');
      const raw = await env.KV.get('modes:' + auth);
      const set = new Set(raw ? JSON.parse(raw) : []);
      if (on) set.add(algo); else set.delete(algo);
      if (typeof dohHash === 'string' && /^[0-9a-f]{64}$/.test(dohHash)) await env.KV.put('dohhash:' + auth, dohHash);
      if (set.size) await env.KV.put('modes:' + auth, JSON.stringify([...set]));
      else await env.KV.delete('modes:' + auth);
      cache.delete(auth);
      return json(200, { active: [...set] });
    }

    if (p === '/api/ledger' && req.method === 'POST') {
      const text = await readText(req);
      const auth = await authenticate(req, u, text);
      const { file, algo, a, b } = JSON.parse(text);
      const r = await appendBlock(env, auth, file, algo || 'sha256', a, b);
      return json(r.code, r.code === 200 ? { block: r.block } : { error: r.error });
    }

    throw new HttpError(404, 'Tidak ditemukan');
  } catch (e) {
    if (e instanceof HttpError) return json(e.status, { error: e.message });
    return json(400, { error: 'Permintaan tidak valid' });
  }
}
