// worker.js - API Key Vault untuk Cloudflare Workers (paket gratis, tanpa kartu kredit)
// Website statis ada di GitHub Pages. Worker ini menyediakan ledger, mode ON, dan DNS-over-HTTPS.
// Wajib: pasang binding KV Namespace dengan nama variabel KV.

const ROTATE_MS = 10000;
const ADDR_RE = /^[a-z2-7]{26}$/;
const ALGOS = new Set(['x448', 'rsa2048', 'serpent256', 'aria256gcm', 'cast256', 'sha256', 'ripemd320', 'ed448', 'ecdsa', 'schnorr', 'combo']);
const MAX_ACTIVE = 2;
const MAX_LEDGER = 10 * 1024 * 1024;
const HASH_HEX = { sha256: 64, ripemd320: 80 };

// Maksimal 10 DNS upstream (DoH), berputar tiap 10 detik
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
  'access-control-allow-headers': 'content-type'
};

const rotl = (x, n) => (x << n) | (x >>> (32 - n));
const enc = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');

/* ===================== RIPEMD-320 ===================== */
const RL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8, 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
const RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2, 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
const SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12, 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
const SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11, 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
const KLc = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
const KRc = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];
function rf(j, x, y, z) {
  switch (j >> 4) {
    case 0: return x ^ y ^ z;
    case 1: return (x & y) | (~x & z);
    case 2: return (x | ~y) ^ z;
    case 3: return (x & z) | (y & ~z);
    default: return x ^ (y | ~z);
  }
}
class RIPEMD320 {
  constructor() {
    this.h = new Uint32Array([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567, 0x3C2D1E0F]);
    this.buf = new Uint8Array(64); this.n = 0; this.len = 0; this.X = new Int32Array(16);
  }
  _block(d, o) {
    const X = this.X, h = this.h;
    for (let i = 0; i < 16; i++) X[i] = d[o + 4 * i] | (d[o + 4 * i + 1] << 8) | (d[o + 4 * i + 2] << 16) | (d[o + 4 * i + 3] << 24);
    let a = h[0] | 0, b = h[1] | 0, c = h[2] | 0, dd = h[3] | 0, e = h[4] | 0;
    let a2 = h[5] | 0, b2 = h[6] | 0, c2 = h[7] | 0, d2 = h[8] | 0, e2 = h[9] | 0, t;
    for (let j = 0; j < 80; j++) {
      t = (rotl((a + rf(j, b, c, dd) + X[RL[j]] + KLc[j >> 4]) | 0, SL[j]) + e) | 0;
      a = e; e = dd; dd = rotl(c, 10); c = b; b = t;
      t = (rotl((a2 + rf(79 - j, b2, c2, d2) + X[RR[j]] + KRc[j >> 4]) | 0, SR[j]) + e2) | 0;
      a2 = e2; e2 = d2; d2 = rotl(c2, 10); c2 = b2; b2 = t;
      if (j === 15) { t = b; b = b2; b2 = t; }
      else if (j === 31) { t = dd; dd = d2; d2 = t; }
      else if (j === 47) { t = a; a = a2; a2 = t; }
      else if (j === 63) { t = c; c = c2; c2 = t; }
      else if (j === 79) { t = e; e = e2; e2 = t; }
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += dd; h[4] += e;
    h[5] += a2; h[6] += b2; h[7] += c2; h[8] += d2; h[9] += e2;
  }
  update(d) {
    this.len += d.length; let i = 0;
    if (this.n) {
      while (i < d.length && this.n < 64) this.buf[this.n++] = d[i++];
      if (this.n === 64) { this._block(this.buf, 0); this.n = 0; }
    }
    for (; i + 64 <= d.length; i += 64) this._block(d, i);
    while (i < d.length) this.buf[this.n++] = d[i++];
    return this;
  }
  digest() {
    const bits = this.len * 8;
    const pad = new Uint8Array((this.n < 56 ? 56 : 120) - this.n + 8);
    pad[0] = 0x80;
    const lo = bits >>> 0, hi = Math.floor(bits / 4294967296), L = pad.length - 8;
    for (let i = 0; i < 4; i++) { pad[L + i] = (lo >>> (8 * i)) & 255; pad[L + 4 + i] = (hi >>> (8 * i)) & 255; }
    this.update(pad);
    const out = new Uint8Array(40);
    for (let i = 0; i < 10; i++) for (let k = 0; k < 4; k++) out[4 * i + k] = (this.h[i] >>> (8 * k)) & 255;
    return out;
  }
}

/* ===================== Ledger (blok head 0x01, maksimal 10MB, hash blok: SHA-256 atau RIPEMD-320) ===================== */
const blockData = (b) => JSON.stringify([b.index, b.prev, b.ts, b.file, b.a, b.b, b.result]);
async function hashBlock(algo, data) {
  if (algo === 'ripemd320') return hex(new RIPEMD320().update(enc.encode(data)).digest());
  return hex(await crypto.subtle.digest('SHA-256', enc.encode(data)));
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
async function appendBlock(env, file, algo, a, b) {
  const len = HASH_HEX[algo];
  if (!len || typeof file !== 'string' || typeof a !== 'string' || typeof b !== 'string') return { code: 400, error: 'Data tidak valid' };
  const hexRe = new RegExp(`^[0-9a-f]{${len}}$`);
  if (!hexRe.test(a) || !hexRe.test(b)) return { code: 400, error: 'Data tidak valid' };
  if (a !== b) return { code: 422, error: 'Hasil tidak sah: hash berbeda, tidak dicatat' };
  const chain = await loadChain(env);
  const last = chain[chain.length - 1];
  const blk = await seal({ index: last.index + 1, prev: last.hash, ts: Date.now(), file: file.slice(0, 200), a, b, result: 'ASLI' }, algo);
  const text = JSON.stringify([...chain, blk]);
  if (text.length > MAX_LEDGER) return { code: 507, error: 'Ledger penuh (10MB)' };
  await env.KV.put('chain', text);
  return { code: 200, block: blk };
}

/* ===================== DoH berputar ===================== */
const hits = new Map();
function upstreamIndex(addr) {
  let o = 0;
  for (let i = 0; i < addr.length; i++) o = (o * 31 + addr.charCodeAt(i)) & 255;
  return (Math.floor(Date.now() / ROTATE_MS) + o) % UPSTREAM.length;
}
async function forwardDns(addr, query) {
  const start = upstreamIndex(addr);
  for (let i = 0; i < UPSTREAM.length; i++) {
    const url = UPSTREAM[(start + i) % UPSTREAM.length];
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
const json = (code, obj) => new Response(JSON.stringify(obj), { status: code, headers: { ...CORS, 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' } });

export default {
  async fetch(req, env) {
    const u = new URL(req.url);
    const p = u.pathname;
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
    try {
      if (p === '/') return json(200, { status: 'ok', nama: 'Key Vault API', kv: Boolean(env.KV) });
      if (!env.KV) return json(500, { error: 'Binding KV belum dipasang' });

      // DoH: /dns/<alamat>
      const m = p.match(/^\/dns\/([a-z2-7]{26})$/);
      if (m) {
        const addr = m[1];
        const bucket = Math.floor(Date.now() / 1000);
        const h = hits.get(addr);
        const n = h && h.t === bucket ? h.n + 1 : 1;
        hits.set(addr, { t: bucket, n });
        if (hits.size > 500) hits.clear();
        if (n > 100) return new Response(null, { status: 429, headers: CORS });
        let q;
        if (req.method === 'POST') q = await req.arrayBuffer();
        else if (req.method === 'GET' && u.searchParams.get('dns')) q = fromBase64Url(u.searchParams.get('dns'));
        else return new Response(null, { status: 400, headers: CORS });
        if (q.byteLength > 4096) return new Response(null, { status: 413, headers: CORS });
        const ans = await forwardDns(addr, q);
        if (!ans) return new Response(null, { status: 502, headers: CORS });
        return new Response(ans, { status: 200, headers: { ...CORS, 'content-type': 'application/dns-message', 'cache-control': 'no-store' } });
      }

      if (p === '/api/rotation' && req.method === 'GET') {
        const addr = u.searchParams.get('addr') || '';
        if (!ADDR_RE.test(addr)) return json(400, { error: 'Alamat tidak valid' });
        return json(200, { n: upstreamIndex(addr) + 1, total: UPSTREAM.length, nextMs: ROTATE_MS - (Date.now() % ROTATE_MS) });
      }

      if (p === '/api/mode' && req.method === 'GET') {
        const addr = u.searchParams.get('addr') || '';
        if (!ADDR_RE.test(addr)) return json(400, { error: 'Alamat tidak valid' });
        const raw = await env.KV.get('modes:' + addr);
        return json(200, { active: raw ? JSON.parse(raw) : [] });
      }

      if (p === '/api/mode' && req.method === 'POST') {
        const { addr, algo, on } = await req.json();
        if (!ADDR_RE.test(addr || '') || !ALGOS.has(algo)) return json(400, { error: 'Data tidak valid' });
        const raw = await env.KV.get('modes:' + addr);
        const set = new Set(raw ? JSON.parse(raw) : []);
        if (on) {
          if (!set.has(algo) && set.size >= MAX_ACTIVE) return json(409, { error: `Maksimal ${MAX_ACTIVE} mode aktif bersamaan`, active: [...set] });
          set.add(algo);
        } else set.delete(algo);
        if (set.size) await env.KV.put('modes:' + addr, JSON.stringify([...set]));
        else await env.KV.delete('modes:' + addr);
        return json(200, { active: [...set] });
      }

      if (p === '/api/ledger' && req.method === 'GET') {
        const limit = Math.min(parseInt(u.searchParams.get('limit') || '20', 10) || 20, 100);
        const chain = await loadChain(env);
        return json(200, { blocks: chain.slice(-limit).reverse(), total: chain.length, bytes: JSON.stringify(chain).length, max: MAX_LEDGER });
      }

      if (p === '/api/ledger' && req.method === 'POST') {
        const { file, algo, a, b } = await req.json();
        const r = await appendBlock(env, file, algo || 'sha256', a, b);
        return json(r.code, r.code === 200 ? { block: r.block } : { error: r.error });
      }

      return json(404, { error: 'Tidak ditemukan' });
    } catch {
      return json(400, { error: 'Permintaan tidak valid' });
    }
  }
};
