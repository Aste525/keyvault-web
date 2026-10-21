// metrics.js - penghitung permintaan DNS per alamat. Hanya angka: tidak ada nama situs, tidak ada alamat IP.
// Dipakai oleh Durable Object (Cloudflare Workers) dan oleh memori+file (Node).
export const emptyState = () => ({ since: Date.now(), total: 0, fails: 0, up: Array(10).fill(0), last: 0, hours: {} });

function addHit(s, up, now) {
  s.total++; s.last = now;
  if (Number.isInteger(up) && up >= 0 && up < 10) s.up[up]++;
  const h = Math.floor(now / 3600000);
  s.hours[h] = (s.hours[h] || 0) + 1;
  for (const k of Object.keys(s.hours)) if (Number(k) < h - 48) delete s.hours[k];
}
export function summary(s, now = Date.now()) {
  const nowH = Math.floor(now / 3600000);
  const series = [];
  let q24 = 0;
  for (let i = 23; i >= 0; i--) { const v = s.hours[nowH - i] || 0; series.push(v); q24 += v; }
  return { since: s.since, total: s.total, fails: s.fails, q24, series, up: s.up, last: s.last, ago: s.last ? Math.max(0, Math.round((now - s.last) / 1000)) : null };
}
// Menangani permintaan internal ke penghitung. Mengembalikan { out, changed }.
export function metricsRequest(state, method, path, body, now = Date.now()) {
  if (method === 'POST' && path === '/hit') { addHit(state, body && body.up, now); return { out: { ok: true }, changed: true }; }
  if (method === 'POST' && path === '/fail') { state.fails++; return { out: { ok: true }, changed: true }; }
  if (method === 'GET' && path === '/read') return { out: summary(state, now), changed: false };
  return { out: { error: 'tidak dikenal' }, changed: false };
}
