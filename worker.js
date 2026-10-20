// worker.js - titik masuk Cloudflare Workers. Semua logika ada di core.js.
// Wajib: binding KV Namespace dengan nama variabel KV (dibuat otomatis oleh wrangler.toml).
import { handle } from './core.js';

export default {
  fetch: (req, env) => handle(req, env)
};
