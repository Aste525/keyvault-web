import { sha256 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.4.0/sha256/+esm';
import { ed448, x448 } from 'https://cdn.jsdelivr.net/npm/@noble/curves@1.4.0/ed448/+esm';
import { secp256k1, schnorr } from 'https://cdn.jsdelivr.net/npm/@noble/curves@1.4.0/secp256k1/+esm';
import { RIPEMD320, makeCipher, GCM } from './ciphers.js';

const $ = (s) => document.querySelector(s);
const enc = new TextEncoder();
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
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

// ---------- Data pilihan ----------
const CATS = {
  enc: {
    title: 'Enkripsi', icon: '🔒', blurb: 'Mengunci data supaya hanya kamu yang bisa membukanya.',
    items: [
      { id: 'x448', name: 'X448', ready: true, desc: 'Mengamankan website dan koneksi.', ex: 'Cocok kalau kamu punya website perusahaan atau bisnis dan ingin kunjungan ke website terlindungi.' },
      { id: 'rsa2048', name: 'RSA-2048', ready: true, desc: 'Mengamankan dokumen besar, total hingga 8GB atau lebih sesuai ruang penyimpanan perangkat.', ex: 'Cocok untuk 4-5 dokumen sekaligus yang totalnya sangat besar. Kunci RSA hanya membungkus kunci acak AES-256 per file, sehingga ukuran file tidak dibatasi RSA.' },
      { id: 'serpent256', name: 'Serpent-256', ready: true, desc: 'Mengamankan aktivitas software dan media sosial.', ex: 'Cocok kalau kamu punya aplikasi atau akun Instagram, Facebook, TikTok, Twitter dan ingin kerahasiaan terjaga.' },
      { id: 'aria256gcm', name: 'ARIA-256-GCM', ready: true, desc: 'Mengamankan arsip, laporan keuangan, dan laporan jaringan yang sering dikirim dan diterima.', ex: 'Si A akuntan melapor ke manajer: tidak ada mata-mata, rekan kerja tidak bisa mencuri atau mengubah, bahkan A sendiri tidak bisa membuka dan mengubah sembarangan.' },
      { id: 'cast256', name: 'CAST-256', ready: true, desc: 'Mengamankan RPC.', ex: 'Cocok untuk layanan yang memakai RPC, karena beberapa RPC pada TLS 1.3 pernah berhasil dieksploitasi.' }
    ]
  },
  hash: {
    title: 'Hashing', icon: '🧬', blurb: 'Sidik jari file untuk membuktikan file asli atau sudah dipalsukan. Pilihan hash juga dipakai untuk blok ledger.',
    items: [
      { id: 'sha256', name: 'SHA-256', ready: true, desc: 'Sidik jari file. File sama menghasilkan sidik jari sama, diubah satu huruf saja sidik jarinya berbeda.', ex: 'Upload kontrak yang kamu terima dan kontrak aslinya. Kalau sidik jari cocok, file tidak diubah.' },
      { id: 'ripemd320', name: 'RIPEMD-320', ready: true, desc: 'Sidik jari file versi lebih panjang (320 bit).', ex: 'Dipakai sebagai pembanding kedua untuk arsip penting.' }
    ]
  },
  sig: {
    title: 'Tanda Tangan Digital', icon: '✍️', blurb: 'Bukti bahwa dokumen ini ditandatangani oleh kamu.',
    items: [
      { id: 'ed448', name: 'Goldilocks / Curve448 (Ed448)', ready: true, desc: 'Tanda tangan dengan kurva Goldilocks, tingkat keamanan tinggi.', ex: 'Upload surat perjanjian, kamu mendapat bukti tanda tangan yang tidak bisa dipalsukan orang lain.' },
      { id: 'ecdsa', name: 'ECDSA', ready: true, desc: 'Tanda tangan standar yang dipakai banyak aplikasi.', ex: 'Menandatangani laporan yang akan diperiksa lewat aplikasi lain.' },
      { id: 'schnorr', name: 'Schnorr', ready: true, desc: 'Tanda tangan ringkas dan cepat diperiksa.', ex: 'Menandatangani banyak dokumen sekaligus dengan bukti yang ringan.' }
    ]
  },
  combo: { title: 'Kombinasi Crypto', icon: '🧩', blurb: 'Pilih satu dari tiap kategori, lalu Key Vault milikmu dirakit otomatis.', items: [{ id: 'combo', name: 'Key Vault Kombinasi', ready: true, desc: 'Gabungan satu enkripsi, satu hashing, satu tanda tangan digital dalam satu alur.', ex: 'Masukkan banyak dokumen kapan saja: dihash, ditandatangani, lalu dienkripsi. Mode ON mengaktifkan DNS terenkripsi untuk berinternet lebih aman.' }] }
};
const sel = { enc: 'x448', hash: 'sha256', sig: 'ed448' };
let active = [];

// ---------- Vault lokal ----------
let vault = JSON.parse(localStorage.getItem('kv.vault') || 'null');
const saveVault = () => localStorage.setItem('kv.vault', JSON.stringify(vault));

async function createVault() {
  const edPriv = ed448.utils.randomPrivateKey();
  const edPub = ed448.getPublicKey(edPriv);
  const addr = b32(sha256(edPub)).slice(0, 26);
  const pair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
  vault = {
    addr,
    ed: hex(edPriv),
    x: hex(x448.utils.randomPrivateKey()),
    sp: hex(secp256k1.utils.randomPrivateKey()),
    rsa: await crypto.subtle.exportKey('jwk', pair.privateKey),
    rsaPub: await crypto.subtle.exportKey('jwk', pair.publicKey)
  };
  saveVault();
}

// ---------- File helpers ----------
const CH = 4 * 1024 * 1024;
async function openSink(name) {
  if (window.showSaveFilePicker) {
    const fh = await window.showSaveFilePicker({ suggestedName: name });
    const w = await fh.createWritable();
    return { write: (d) => w.write(d), close: () => w.close() };
  }
  const parts = [];
  return {
    write: async (d) => { parts.push(d); },
    close: async () => {
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob(parts));
      a.download = name; a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 60000);
    }
  };
}
// Hash file bertahap (SHA-256 atau RIPEMD-320)
async function hashFile(file, algo = 'sha256') {
  const h = algo === 'ripemd320' ? new RIPEMD320() : sha256.create();
  for (let o = 0; o < file.size; o += CH) h.update(new Uint8Array(await file.slice(o, o + CH).arrayBuffer()));
  return hex(h.digest());
}

// ---------- Enkripsi ----------
// id format: 1 X448, 2 RSA-2048, 3 Serpent-256, 4 ARIA-256-GCM, 5 CAST-256
const CIPHER_ID = { serpent256: 3, aria256gcm: 4, cast256: 5 };
const CIPHER_NAME = { 3: 'serpent256', 4: 'aria256gcm', 5: 'cast256' };

async function kdf(shared) {
  const base = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('keyvault-x448') }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function newFileKey(algo) {
  if (algo === 'x448') {
    const eph = x448.utils.randomPrivateKey();
    const key = await kdf(x448.getSharedSecret(eph, x448.getPublicKey(unhex(vault.x))));
    return { id: 1, wrapped: x448.getPublicKey(eph), key };
  }
  if (algo === 'rsa2048') {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    const pub = await crypto.subtle.importKey('jwk', vault.rsaPub, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['encrypt']);
    const wrapped = new Uint8Array(await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, pub, raw));
    return { id: 2, wrapped, key: await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']) };
  }
  if (CIPHER_ID[algo]) {
    // Kunci data acak 32 byte dibungkus dengan X448 + AES-256-GCM; isi file memakai cipher pilihan dalam mode GCM
    const dataKey = crypto.getRandomValues(new Uint8Array(32));
    const eph = x448.utils.randomPrivateKey();
    const kek = await kdf(x448.getSharedSecret(eph, x448.getPublicKey(unhex(vault.x))));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, dataKey));
    const wrapped = new Uint8Array(56 + 12 + ct.length);
    wrapped.set(x448.getPublicKey(eph), 0); wrapped.set(iv, 56); wrapped.set(ct, 68);
    return { id: CIPHER_ID[algo], wrapped, key: new GCM(makeCipher(algo, dataKey)) };
  }
  throw new Error('Algoritma belum tersedia');
}
async function openFileKey(id, wrapped) {
  if (id === 1) return kdf(x448.getSharedSecret(unhex(vault.x), wrapped));
  if (id === 2) {
    const priv = await crypto.subtle.importKey('jwk', vault.rsa, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    const raw = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, priv, wrapped);
    return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }
  if (CIPHER_NAME[id]) {
    const kek = await kdf(x448.getSharedSecret(unhex(vault.x), wrapped.slice(0, 56)));
    const dataKey = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: wrapped.slice(56, 68) }, kek, wrapped.slice(68)));
    return new GCM(makeCipher(CIPHER_NAME[id], dataKey));
  }
  throw new Error('Format tidak dikenal');
}
const ctr = (i) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, i); return b; };
const sealChunk = async (key, iv, aad, pt) => key instanceof GCM
  ? key.seal(iv, aad, new Uint8Array(pt))
  : new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, pt));
const openChunk = async (key, iv, aad, ct) => key instanceof GCM
  ? key.open(iv, aad, new Uint8Array(ct))
  : new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, ct));

async function encryptFile(file, algo) {
  const { id, wrapped, key } = await newFileKey(algo);
  const sink = await openSink(file.name + '.kv');
  const head = new Uint8Array(6 + wrapped.length);
  head.set([75, 86, 49, id], 0);
  new DataView(head.buffer).setUint16(4, wrapped.length);
  head.set(wrapped, 6);
  await sink.write(head);
  let i = 0;
  for (let o = 0; o < file.size; o += CH, i++) {
    const pt = await file.slice(o, o + CH).arrayBuffer();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await sealChunk(key, iv, ctr(i), pt);
    const len = new Uint8Array(4);
    new DataView(len.buffer).setUint32(0, ct.length);
    await sink.write(len); await sink.write(iv); await sink.write(ct);
  }
  await sink.close();
}
async function decryptFile(file) {
  const head = new Uint8Array(await file.slice(0, 6).arrayBuffer());
  if (head[0] !== 75 || head[1] !== 86 || head[2] !== 49) throw new Error('Bukan file Key Vault');
  const wl = new DataView(head.buffer).getUint16(4);
  const wrapped = new Uint8Array(await file.slice(6, 6 + wl).arrayBuffer());
  const key = await openFileKey(head[3], wrapped);
  const sink = await openSink(file.name.replace(/\.kv$/, '') || 'hasil');
  let off = 6 + wl, i = 0;
  while (off < file.size) {
    const len = new DataView(await file.slice(off, off + 4).arrayBuffer()).getUint32(0);
    const iv = new Uint8Array(await file.slice(off + 4, off + 16).arrayBuffer());
    const ct = await file.slice(off + 16, off + 16 + len).arrayBuffer();
    await sink.write(await openChunk(key, iv, ctr(i), ct));
    off += 16 + len; i++;
  }
  await sink.close();
}

// ---------- Tanda tangan ----------
function signHash(algo, h) {
  const m = unhex(h);
  if (algo === 'ed448') { const p = unhex(vault.ed); return { pub: hex(ed448.getPublicKey(p)), sig: hex(ed448.sign(m, p)) }; }
  if (algo === 'ecdsa') { const p = unhex(vault.sp); return { pub: hex(secp256k1.getPublicKey(p)), sig: secp256k1.sign(m, p).toCompactHex() }; }
  if (algo === 'schnorr') { const p = unhex(vault.sp); return { pub: hex(schnorr.getPublicKey(p)), sig: hex(schnorr.sign(m, p)) }; }
  throw new Error('Algoritma belum tersedia');
}
function verifyHash(algo, h, pub, sig) {
  const m = unhex(h);
  if (algo === 'ed448') return ed448.verify(unhex(sig), m, unhex(pub));
  if (algo === 'ecdsa') return secp256k1.verify(sig, m, unhex(pub));
  if (algo === 'schnorr') return schnorr.verify(unhex(sig), m, unhex(pub));
  return false;
}
async function signFile(file, algo, hashAlgo = 'sha256') {
  const h = await hashFile(file, hashAlgo);
  const { pub, sig } = signHash(algo, h);
  const sink = await openSink(file.name + '.sig.json');
  await sink.write(enc.encode(JSON.stringify({ file: file.name, algo, hash: hashAlgo, digest: h, pub, sig, address: vault.addr }, null, 2)));
  await sink.close();
  return h;
}

// ---------- API ----------
// Alamat server: kosong = server yang sama dengan halaman ini; atau link server lain
// Website di GitHub Pages otomatis memakai server Render ini; kotak Server bisa menggantinya
const DEFAULT_SERVER = location.hostname.endsWith('github.io') ? 'https://keyvault-aste525.onrender.com' : '';
let base = (localStorage.getItem('kv.server') || DEFAULT_SERVER).replace(/\/+$/, '');
let serverOk = false;
const api = async (url, body) => {
  try {
    const r = await fetch(base + url, body ? { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) } : undefined);
    return { ok: r.ok, data: await r.json().catch(() => ({})) };
  } catch {
    return { ok: false, data: { error: 'Server tidak terjangkau' } };
  }
};
async function refreshServer() {
  const r = await api('/api/ledger?limit=1');
  serverOk = r.ok && Array.isArray(r.data.blocks);
  const st = $('#srvStat');
  if (st) st.textContent = serverOk ? 'Terhubung ke ' + (base || location.origin) : 'Server belum aktif. Ledger dan mode ON mati; alamat, enkripsi, hashing, dan tanda tangan tetap berfungsi.';
}
// Server gratis di Render tidur setelah 15 menit sepi dan butuh sekitar 1 menit untuk bangun
async function wakeServer() {
  const st = $('#srvStat');
  for (let i = 0; i < 12 && !serverOk; i++) {
    if (st) st.textContent = 'Membangunkan server, bisa sampai 1 menit...';
    await new Promise((r) => setTimeout(r, 7000));
    await refreshServer();
  }
  if (serverOk) { await loadModes(); loadLedger(); renderPanel(currentCat); renderDoh(); }
}
function mountServerBox() {
  if ($('#srvBox')) return;
  const box = el('div', 'card bg-dark border-secondary mt-3'); box.id = 'srvBox';
  const body = el('div', 'card-body'); box.appendChild(body);
  body.appendChild(el('div', 'fw-semibold mb-1', 'Server (ledger dan mode ON)'));
  const st = el('div', 'small-note mb-2'); st.id = 'srvStat'; body.appendChild(st);
  const row = el('div', 'input-group');
  const inp = el('input', 'form-control'); inp.id = 'srvUrl'; inp.placeholder = 'https://xxxx.trycloudflare.com'; inp.value = base;
  const b = el('button', 'btn btn-outline-light', 'Hubungkan');
  b.onclick = async () => {
    const v = inp.value.trim().replace(/\/+$/, '');
    if (v && !/^https?:\/\/\S+$/.test(v)) { st.textContent = 'Alamat server harus diawali https://'; return; }
    base = v; localStorage.setItem('kv.server', base);
    await refreshServer(); await loadModes(); loadLedger(); renderPanel(currentCat); renderDoh();
  };
  row.appendChild(inp); row.appendChild(b); body.appendChild(row);
  body.appendChild(el('div', 'small-note mt-2', 'Server hanya menerima alamat anonim dan blok ledger. Jalankan server sendiri dengan npm start dari repo GitHub, lalu tempel link HTTPS-nya di sini.'));
  $('#dohBox').before(box);
}
async function setMode(algo, on) {
  if (!serverOk) { alert('Server belum aktif. Isi alamat server di kotak Server di bawah, atau jalankan npm start dari repo GitHub.'); renderPanel(currentCat); return; }
  const r = await api('/api/mode', { addr: vault.addr, algo, on });
  if (!r.ok) alert(r.data.error || 'Gagal mengubah mode');
  active = r.data.active || active;
  renderPanel(currentCat);
  renderDoh();
}
async function loadModes() {
  if (!serverOk) { active = []; renderDoh(); return; }
  const r = await api('/api/mode?addr=' + vault.addr); active = r.data.active || []; renderDoh();
}
async function loadLedger() {
  if (!serverOk) { $('#ledgerStat').textContent = 'Server belum aktif, riwayat blockchain tidak tersedia.'; $('#ledgerList').textContent = ''; return; }
  const r = await api('/api/ledger?limit=10');
  const d = r.data;
  $('#ledgerStat').textContent = `${d.total} blok, ${(d.bytes / 1048576).toFixed(2)} MB dari ${(d.max / 1048576).toFixed(0)} MB. Blok head: 0x01`;
  const box = $('#ledgerList'); box.textContent = '';
  for (const b of d.blocks || []) {
    const row = document.createElement('div');
    row.className = 'border-top border-secondary py-2';
    row.textContent = `#${b.index} | ${b.file} | ${b.result} | ${b.algo || 'sha256'} ${b.hash.slice(0, 20)}...`;
    box.appendChild(row);
  }
}

// ---------- DoH ----------
let rot = { n: 0, ms: 0 }, rotTimer = null;
function renderDoh() {
  const on = active.length > 0;
  $('#dohBox').classList.toggle('d-none', !on);
  if (!on) { clearInterval(rotTimer); rotTimer = null; return; }
  $('#dohUrl').textContent = `${base || location.origin}/dns/${vault.addr}`;
  if (rotTimer) return;
  const sync = async () => { const r = await api('/api/rotation?addr=' + vault.addr); rot = { n: r.data.n, ms: Date.now() + r.data.nextMs }; };
  sync();
  rotTimer = setInterval(() => {
    const left = Math.max(0, Math.ceil((rot.ms - Date.now()) / 1000));
    $('#rotN').textContent = rot.n || '-'; $('#rotT').textContent = left;
    if (left === 0) sync();
  }, 500);
}

// ---------- UI ----------
let currentCat = null;
function renderCats() {
  const box = $('#cats'); box.textContent = '';
  for (const [k, c] of Object.entries(CATS)) {
    const col = document.createElement('div'); col.className = 'col-6 col-md-3';
    const card = document.createElement('div');
    card.className = 'card cat-card bg-dark border-secondary h-100' + (currentCat === k ? ' active' : '');
    card.innerHTML = '<div class="card-body text-center p-3"><div class="fs-3"></div><div class="fw-semibold small mt-1"></div></div>';
    card.querySelector('.fs-3').textContent = c.icon;
    card.querySelector('.fw-semibold').textContent = c.title;
    card.onclick = () => { currentCat = k; renderCats(); renderPanel(k); };
    col.appendChild(card); box.appendChild(col);
  }
}
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text) e.textContent = text; return e; }
function status(box, msg, ok = true) { box.className = 'small mt-2 ' + (ok ? 'text-success' : 'text-danger'); box.textContent = msg; }

function renderPanel(k) {
  const panel = $('#panel'); panel.textContent = '';
  if (!k) return;
  const c = CATS[k];
  const card = el('div', 'card bg-dark border-secondary');
  const body = el('div', 'card-body'); card.appendChild(body);
  body.appendChild(el('div', 'h5', c.title));
  body.appendChild(el('div', 'small-note mb-3', c.blurb));

  for (const it of c.items) {
    const row = el('div', 'algo-row border border-secondary rounded p-3 mb-2' + (it.ready ? '' : ' off'));
    const top = el('div', 'd-flex justify-content-between align-items-start gap-2');
    const left = el('div', 'flex-grow-1');
    if (k !== 'combo') {
      const lab = el('label', 'fw-semibold d-flex align-items-center gap-2');
      const rd = el('input'); rd.type = 'radio'; rd.name = 'sel-' + k; rd.disabled = !it.ready; rd.checked = sel[k] === it.id;
      rd.onchange = () => { sel[k] = it.id; };
      lab.appendChild(rd); lab.appendChild(document.createTextNode(it.name));
      left.appendChild(lab);
    } else left.appendChild(el('div', 'fw-semibold', it.name));
    left.appendChild(el('div', 'small mt-1', it.desc));
    left.appendChild(el('div', 'small-note mt-1', 'Contoh: ' + it.ex));
    const sw = el('div', 'form-check form-switch');
    const cb = el('input', 'form-check-input'); cb.type = 'checkbox'; cb.role = 'switch';
    cb.disabled = !it.ready; cb.checked = active.includes(it.id);
    cb.onchange = () => setMode(it.id, cb.checked);
    sw.appendChild(cb); sw.appendChild(el('label', 'form-check-label small', cb.checked ? 'ON' : 'OFF'));
    top.appendChild(left); top.appendChild(sw); row.appendChild(top); body.appendChild(row);
  }
  body.appendChild(el('div', 'small-note mb-3', `Mode ON aktif: ${active.length}/2. Maksimal 2 mode bersamaan.`));

  const out = el('div');
  const mkFile = (label, multiple = false, accept) => {
    const w = el('div', 'mb-2'); w.appendChild(el('label', 'form-label small', label));
    const i = el('input', 'form-control'); i.type = 'file'; i.multiple = multiple; if (accept) i.accept = accept;
    w.appendChild(i); body.appendChild(w); return i;
  };
  const btn = (text, cls, fn) => {
    const b = el('button', 'btn ' + cls + ' me-2 mb-1', text);
    b.onclick = async () => { try { b.disabled = true; await fn(); } catch (e) { status(out, e.message || 'Gagal', false); } finally { b.disabled = false; } };
    body.appendChild(b); return b;
  };

  if (k === 'enc') {
    const f = mkFile('Pilih file (satu atau beberapa)', true);
    btn('Enkripsi', 'btn-primary', async () => { for (const x of f.files) await encryptFile(x, sel.enc); status(out, 'Selesai dienkripsi.'); });
    btn('Dekripsi', 'btn-outline-light', async () => { for (const x of f.files) await decryptFile(x); status(out, 'Selesai didekripsi.'); });
  }
  if (k === 'hash') {
    const a = mkFile('File asli'); const b = mkFile('File yang dibandingkan');
    btn('Bandingkan', 'btn-primary', async () => {
      if (!a.files[0] || !b.files[0]) throw new Error('Pilih kedua file');
      const algo = sel.hash;
      const [h1, h2] = [await hashFile(a.files[0], algo), await hashFile(b.files[0], algo)];
      if (h1 === h2) {
        const r = await api('/api/ledger', { file: b.files[0].name, algo, a: h1, b: h2 });
        status(out, `ASLI (${algo}): ${h1}` + (r.ok ? ` | Tercatat di blok #${r.data.block.index}` : ' | Ledger: ' + (r.data.error || 'server belum aktif')));
        loadLedger();
      } else status(out, `TIDAK SAMA (dipalsukan atau berbeda). Asli: ${h1.slice(0, 16)}... Dibandingkan: ${h2.slice(0, 16)}...`, false);
    });
  }
  if (k === 'sig') {
    const f = mkFile('Dokumen');
    btn('Tanda Tangani', 'btn-primary', async () => { if (!f.files[0]) throw new Error('Pilih dokumen'); const h = await signFile(f.files[0], sel.sig, sel.hash); status(out, `Ditandatangani (${sel.sig} + ${sel.hash}). Digest: ${h}`); });
    const s = mkFile('File tanda tangan (.sig.json) untuk verifikasi', false, '.json');
    btn('Verifikasi', 'btn-outline-light', async () => {
      if (!f.files[0] || !s.files[0]) throw new Error('Pilih dokumen dan file tanda tangan');
      const j = JSON.parse(await s.files[0].text());
      const h = await hashFile(f.files[0], j.hash || 'sha256');
      const ok = h === (j.digest || j.sha256) && verifyHash(j.algo, h, j.pub, j.sig);
      status(out, ok ? `Tanda tangan sah (${j.algo}), alamat penanda tangan: ${j.address}` : 'Tanda tangan TIDAK sah atau dokumen berubah.', ok);
    });
  }
  if (k === 'combo') {
    for (const [cat, label] of [['enc', 'Enkripsi'], ['hash', 'Hashing'], ['sig', 'Tanda Tangan']]) {
      const w = el('div', 'mb-2'); w.appendChild(el('label', 'form-label small', label));
      const s = el('select', 'form-select');
      for (const it of CATS[cat].items.filter((x) => x.ready)) { const o = el('option', '', it.name); o.value = it.id; o.selected = sel[cat] === it.id; s.appendChild(o); }
      s.onchange = () => { sel[cat] = s.value; };
      w.appendChild(s); body.appendChild(w);
    }
    const f = mkFile('Dokumen (banyak file)', true);
    btn('Proses ke Key Vault', 'btn-primary', async () => {
      for (const x of f.files) { await signFile(x, sel.sig, sel.hash); await encryptFile(x, sel.enc); }
      status(out, `Selesai: ${f.files.length} dokumen di-hash (${sel.hash}), ditandatangani (${sel.sig}), dan dienkripsi (${sel.enc}).`);
    });
  }
  body.appendChild(out);
  panel.appendChild(card);
}

// ---------- Dokumen kebijakan ----------
const DOCS = {
  privacy: ['Kebijakan Privasi', 'Key Vault tidak meminta email atau nomor telepon. Kunci dan dokumen diproses di browser kamu dan tidak diunggah. Server tidak mencatat alamat IP, tidak meneruskan IP ke DNS upstream, dan hanya menyimpan: alamat anonim, daftar mode ON, dan blok ledger (nama file, dua hash yang dibandingkan, hasil). Cadangan kunci adalah tanggung jawab kamu: kunci yang hilang tidak bisa dipulihkan siapa pun.'],
  rules: ['Aturan', 'Gunakan Key Vault untuk melindungi data milikmu sendiri. Dilarang memakainya untuk melanggar hukum, menyerang sistem lain, atau menyebarkan konten ilegal. Ledger hanya mencatat perbandingan yang sah (hash sama). Maksimal 2 mode ON bersamaan. Layanan diberikan apa adanya.'],
  copyright: ['Copyright', '© 2026 Farrel. Seluruh hak cipta atas Key Vault dilindungi. Pustaka pihak ketiga (Bootstrap, noble-curves, noble-hashes) memakai lisensi masing-masing.']
};
document.querySelectorAll('[data-doc]').forEach((a) => a.addEventListener('click', (e) => {
  e.preventDefault();
  const [t, b] = DOCS[a.dataset.doc];
  $('#docTitle').textContent = t; $('#docBody').textContent = b;
  bootstrap.Modal.getOrCreateInstance($('#docModal')).show();
}));

// ---------- Mulai ----------
async function enter() {
  $('#hero').classList.add('d-none'); $('#main').classList.remove('d-none');
  $('#addr').textContent = vault.addr;
  mountServerBox(); await refreshServer(); renderCats(); await loadModes(); loadLedger();
  if (!serverOk && base) wakeServer();
}
$('#btnAddr').onclick = async () => {
  const b = $('#btnAddr'); b.disabled = true; b.textContent = 'Membuat alamat...';
  try { if (!vault) await createVault(); await enter(); } finally { b.disabled = false; b.textContent = 'Dapatkan Alamat'; }
};
$('#btnCopy').onclick = () => navigator.clipboard.writeText(vault.addr);
$('#btnBackup').onclick = async () => { const s = await openSink('keyvault-backup.json'); await s.write(enc.encode(JSON.stringify(vault))); await s.close(); };
$('#restore').onchange = async (e) => {
  const f = e.target.files[0]; if (!f) return;
  const v = JSON.parse(await f.text());
  if (!/^[a-z2-7]{26}$/.test(v.addr || '') || !v.ed || !v.x || !v.sp || !v.rsa || !v.rsaPub) return alert('File cadangan tidak valid');
  vault = v; saveVault(); await enter();
};
if (vault) $('#btnAddr').textContent = 'Buka Key Vault';
