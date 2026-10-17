import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ripemd320, toHex } from './public/ciphers.js';

const PORT = Number(process.env.PORT) || 28836;
const HOST = '0.0.0.0';
const DIR = path.dirname(fileURLToPath(import.meta.url));
const PUB = path.join(DIR, 'public');
const LEDGER_FILE = path.join(DIR, 'ledger.json');
const MODES_FILE = path.join(DIR, 'modes.json');
const MAX_LEDGER = 10 * 1024 * 1024;
const ROTATE_MS = 10000;
const ADDR_RE = /^[a-z2-7]{26}$/;
const ALGOS = new Set(['x448', 'rsa2048', 'serpent256', 'aria256gcm', 'cast256', 'sha256', 'ripemd320', 'ed448', 'ecdsa', 'schnorr', 'combo']);
const MAX_ACTIVE = 2;
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

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// ---------- Mode ON/OFF (tanpa timeout, tersimpan di disk) ----------
let modes = {};
try { modes = JSON.parse(fs.readFileSync(MODES_FILE, 'utf8')); } catch { modes = {}; }
const saveModes = () => fs.writeFileSync(MODES_FILE, JSON.stringify(modes));

// ---------- Ledger (blok head 0x01, maksimal 10MB, hash blok: SHA-256 atau RIPEMD-320) ----------
const blockData = (b) => JSON.stringify([b.index, b.prev, b.ts, b.file, b.a, b.b, b.result]);
function hashBlock(algo, data) {
  if (algo === 'ripemd320') return toHex(ripemd320(new TextEncoder().encode(data)));
  return crypto.createHash('sha256').update(data).digest('hex');
}
function seal(b, algo) {
  b.algo = algo;
  b.hash = hashBlock(algo, blockData(b));
  return b;
}
function loadLedger() {
  try {
    return JSON.parse(fs.readFileSync(LEDGER_FILE, 'utf8'));
  } catch {
    const g = seal({ index: 1, prev: '0x00', ts: Date.now(), file: 'HEAD', a: '0x01', b: '0x01', result: 'GENESIS' }, 'sha256');
    fs.writeFileSync(LEDGER_FILE, JSON.stringify([g]));
    return [g];
  }
}
let chain = loadLedger();

function appendBlock(file, algo, a, b) {
  const len = HASH_HEX[algo];
  if (!len || typeof file !== 'string' || typeof a !== 'string' || typeof b !== 'string') return { code: 400, error: 'Data tidak valid' };
  const hexRe = new RegExp(`^[0-9a-f]{${len}}$`);
  if (!hexRe.test(a) || !hexRe.test(b)) return { code: 400, error: 'Data tidak valid' };
  if (a !== b) return { code: 422, error: 'Hasil tidak sah: hash berbeda, tidak dicatat' };
  const last = chain[chain.length - 1];
  const blk = seal({ index: last.index + 1, prev: last.hash, ts: Date.now(), file: file.slice(0, 200), a, b, result: 'ASLI' }, algo);
  const size = Buffer.byteLength(JSON.stringify([...chain, blk]));
  if (size > MAX_LEDGER) return { code: 507, error: 'Ledger penuh (10MB)' };
  chain.push(blk);
  fs.writeFileSync(LEDGER_FILE, JSON.stringify(chain));
  return { code: 200, block: blk };
}

// ---------- DoH berputar ----------
const hits = new Map();
setInterval(() => hits.clear(), 1000).unref();

function upstreamIndex(addr) {
  const off = crypto.createHash('sha256').update(addr).digest()[0];
  return (Math.floor(Date.now() / ROTATE_MS) + off) % UPSTREAM.length;
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
      if (r.ok) return Buffer.from(await r.arrayBuffer());
    } catch { /* coba upstream berikutnya */ }
  }
  return null;
}

// ---------- Util HTTP ----------
const readBody = (req, max) => new Promise((ok, no) => {
  const c = [];
  let n = 0;
  req.on('data', (d) => {
    n += d.length;
    if (n > max) { no(new Error('too big')); req.destroy(); return; }
    c.push(d);
  });
  req.on('end', () => ok(Buffer.concat(c)));
  req.on('error', no);
});
const json = (res, code, obj) => {
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(obj));
};

const server = http.createServer(async (req, res) => {
  try {
    // Tidak ada logging IP, tidak ada X-Forwarded-For yang diteruskan
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    // CORS: website di GitHub Pages (atau domain lain) boleh memakai server ini
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-methods', 'GET, POST, OPTIONS');
    res.setHeader('access-control-allow-headers', 'content-type');
    if (req.method === 'OPTIONS') { res.writeHead(204); return res.end(); }

    // DoH: /dns/<alamat>
    const m = p.match(/^\/dns\/([a-z2-7]{26})$/);
    if (m) {
      const addr = m[1];
      const n = (hits.get(addr) || 0) + 1;
      hits.set(addr, n);
      if (n > 100) { res.writeHead(429); return res.end(); }
      let q;
      if (req.method === 'POST') q = await readBody(req, 4096);
      else if (req.method === 'GET' && u.searchParams.get('dns')) q = Buffer.from(u.searchParams.get('dns'), 'base64url');
      else { res.writeHead(400); return res.end(); }
      const ans = await forwardDns(addr, q);
      if (!ans) { res.writeHead(502); return res.end(); }
      res.writeHead(200, { 'content-type': 'application/dns-message', 'cache-control': 'no-store' });
      return res.end(ans);
    }

    if (p === '/api/rotation' && req.method === 'GET') {
      const addr = u.searchParams.get('addr') || '';
      if (!ADDR_RE.test(addr)) return json(res, 400, { error: 'Alamat tidak valid' });
      return json(res, 200, {
        n: upstreamIndex(addr) + 1,
        total: UPSTREAM.length,
        nextMs: ROTATE_MS - (Date.now() % ROTATE_MS)
      });
    }

    if (p === '/api/mode' && req.method === 'GET') {
      const addr = u.searchParams.get('addr') || '';
      if (!ADDR_RE.test(addr)) return json(res, 400, { error: 'Alamat tidak valid' });
      return json(res, 200, { active: modes[addr] || [] });
    }

    if (p === '/api/mode' && req.method === 'POST') {
      const { addr, algo, on } = JSON.parse((await readBody(req, 2048)).toString() || '{}');
      if (!ADDR_RE.test(addr || '') || !ALGOS.has(algo)) return json(res, 400, { error: 'Data tidak valid' });
      const set = new Set(modes[addr] || []);
      if (on) {
        if (!set.has(algo) && set.size >= MAX_ACTIVE) return json(res, 409, { error: `Maksimal ${MAX_ACTIVE} mode aktif bersamaan`, active: [...set] });
        set.add(algo);
      } else set.delete(algo);
      modes[addr] = [...set];
      if (!modes[addr].length) delete modes[addr];
      saveModes();
      return json(res, 200, { active: modes[addr] || [] });
    }

    if (p === '/api/ledger' && req.method === 'GET') {
      const limit = Math.min(parseInt(u.searchParams.get('limit') || '20', 10) || 20, 100);
      return json(res, 200, {
        blocks: chain.slice(-limit).reverse(),
        total: chain.length,
        bytes: Buffer.byteLength(JSON.stringify(chain)),
        max: MAX_LEDGER
      });
    }

    if (p === '/api/ledger' && req.method === 'POST') {
      const { file, algo, a, b } = JSON.parse((await readBody(req, 4096)).toString() || '{}');
      const r = appendBlock(file, algo || 'sha256', a, b);
      return json(res, r.code, r.code === 200 ? { block: r.block } : { error: r.error });
    }

    // Statis
    if (req.method !== 'GET') { res.writeHead(405); return res.end(); }
    const rel = p === '/' ? 'index.html' : decodeURIComponent(p).replace(/^\/+/, '');
    const file = path.join(PUB, rel);
    if (!file.startsWith(PUB + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404); return res.end('Tidak ditemukan');
    }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  } catch {
    res.writeHead(400); res.end();
  }
});

server.listen(PORT, HOST, () => console.log(`Key Vault berjalan di ${HOST}:${PORT}`));
