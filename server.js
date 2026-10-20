// server.js - server Node untuk menjalankan Key Vault sendiri (npm start). Logika API ada di core.js.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { handle } from './core.js';

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

// Penyimpanan key-value berbasis file, antarmukanya sama dengan Workers KV
let data = {};
try { data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { data = {}; }
const save = () => fs.writeFileSync(DATA_FILE, JSON.stringify(data));
const env = {
  KV: {
    get: async (k) => (Object.prototype.hasOwnProperty.call(data, k) ? data[k] : null),
    put: async (k, v) => { data[k] = String(v); save(); },
    delete: async (k) => { delete data[k]; save(); }
  }
};

const server = http.createServer(async (req, res) => {
  try {
    // Tidak ada logging IP, tidak ada X-Forwarded-For yang diteruskan
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
    const r = await handle(request, env);
    res.writeHead(r.status, Object.fromEntries(r.headers));
    res.end(Buffer.from(await r.arrayBuffer()));
  } catch {
    res.writeHead(400); res.end();
  }
});

server.listen(PORT, HOST, () => console.log(`Key Vault berjalan di ${HOST}:${PORT}`));
