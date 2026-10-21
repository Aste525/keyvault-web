// server.js - server Node untuk menjalankan Key Vault sendiri (npm start). Logika API ada di core.js.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { handle } from './core.js';
import { emptyState, metricsRequest } from './metrics.js';

const PORT = Number(process.env.PORT) || 28836;
const HOST = '0.0.0.0';
const DIR = path.dirname(fileURLToPath(import.meta.url));
const PUB = path.join(DIR, 'public');
const DATA_FILE = process.env.DATA_FILE || path.join(DIR, 'data.json');
const MAX_BODY = 65536;
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

let data = {};
try { data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { data = {}; }
let saveTimer = null;
const saveNow = () => { clearTimeout(saveTimer); saveTimer = null; fs.writeFileSync(DATA_FILE, JSON.stringify(data)); };
const saveSoon = () => { if (!saveTimer) saveTimer = setTimeout(saveNow, 3000); };

const counters = new Map();
const counter = (addr) => {
  if (!counters.has(addr)) { const raw = data['metrics:' + addr]; counters.set(addr, raw ? JSON.parse(raw) : emptyState()); }
  return counters.get(addr);
};
const env = {
  KV: {
    get: async (k) => (Object.prototype.hasOwnProperty.call(data, k) ? data[k] : null),
    put: async (k, v) => { data[k] = String(v); saveNow(); },
    delete: async (k) => { delete data[k]; saveNow(); }
  },
  METRICS: {
    idFromName: (name) => name,
    get: (addr) => ({
      fetch: async (url, init = {}) => {
        const s = counter(addr);
        const { out, changed } = metricsRequest(s, init.method || 'GET', new URL(url).pathname, init.body ? JSON.parse(init.body) : {});
        if (changed) { data['metrics:' + addr] = JSON.stringify(s); saveSoon(); }
        return new Response(JSON.stringify(out), { headers: { 'content-type': 'application/json' } });
      }
    })
  }
};

const server = http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, 'http://x');
    const p = u.pathname;
    const isApi = p.startsWith('/api/') || p.startsWith('/dns/') || p.startsWith('/dns-profile/');
    if (!isApi && req.method === 'GET') {
      const rel = p === '/' ? 'index.html' : decodeURIComponent(p).replace(/^\/+/, '');
      const file = path.join(PUB, rel);
      if (!file.startsWith(PUB + path.sep) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
        res.writeHead(404); return res.end('Tidak ditemukan');
      }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      return fs.createReadStream(file).pipe(res);
    }
    const chunks = [];
    let n = 0;
    for await (const c of req) {
      n += c.length;
      if (n > MAX_BODY) { res.writeHead(413); return res.end(); }
      chunks.push(c);
    }
    const hasBody = req.method !== 'GET' && req.method !== 'HEAD' && n > 0;
    const request = new Request(`http://${req.headers.host || 'localhost'}${req.url}`, {
      method: req.method,
      headers: req.headers,
      body: hasBody ? Buffer.concat(chunks) : undefined
    });
    const r = await handle(request, env, { waitUntil: (p2) => p2 });
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  } catch {
    res.writeHead(400); res.end();
  }
});

process.on('SIGINT', () => { if (saveTimer) saveNow(); process.exit(0); });
server.listen(PORT, HOST, () => console.log(`Key Vault berjalan di ${HOST}:${PORT}`));
