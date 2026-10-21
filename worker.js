// worker.js - titik masuk Cloudflare Workers. Logika di core.js.
// Binding: KV (penyimpanan) dan METRICS (Durable Object penghitung DNS), diatur di wrangler.toml.
import { handle } from './core.js';
import { emptyState, metricsRequest } from './metrics.js';

export class Metrics {
  constructor(ctx) {
    this.ctx = ctx;
    this.state = null;
    this.dirty = false;
    ctx.blockConcurrencyWhile(async () => { this.state = (await ctx.storage.get('s')) || emptyState(); });
  }
  async fetch(req) {
    const path = new URL(req.url).pathname;
    const body = req.method === 'POST' ? await req.json().catch(() => ({})) : {};
    const { out, changed } = metricsRequest(this.state, req.method, path, body);
    if (changed && !this.dirty) { this.dirty = true; await this.ctx.storage.setAlarm(Date.now() + 15000); }
    return new Response(JSON.stringify(out), { headers: { 'content-type': 'application/json' } });
  }
  async alarm() {
    await this.ctx.storage.put('s', this.state);
    this.dirty = false;
  }
}

export default {
  fetch: (req, env, ctx) => handle(req, env, ctx)
};
