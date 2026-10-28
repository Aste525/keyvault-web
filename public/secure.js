'use strict';
(() => {
  const STORAGE = 'keyvault-secure-v2-identity';
  const ITERATIONS = 600000;
  const ALGOS = ['X448', 'RSA-2048', 'Serpent-256', 'ARIA-256-GCM', 'CAST-256', 'SHA-256', 'RIPEMD-320', 'Ed448', 'ECDSA', 'Schnorr'];
  const $ = id => document.getElementById(id);
  const encoder = new TextEncoder();
  let identity = null;
  let loggedIn = false;
  const output = (value) => { $('status').textContent = String(value); };
  const base64url = bytes => {
    let s = '';
    const u8 = new Uint8Array(bytes);
    for (let i = 0; i < u8.length; i += 8192) s += String.fromCharCode(...u8.subarray(i, i + 8192));
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  };
  const unbase64url = value => {
    const text = value.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(text + '='.repeat((4 - text.length % 4) % 4));
    return Uint8Array.from(raw, ch => ch.charCodeAt(0));
  };
  const sha256 = async bytes => Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), b => b.toString(16).padStart(2, '0')).join('');
  const kdf = async (pass, salt) => {
    const material = await crypto.subtle.importKey('raw', encoder.encode(pass), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  };
  const encryptPrivate = async (privateKey, pass, publicKey) => {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await kdf(pass, salt);
    const pkcs8 = await crypto.subtle.exportKey('pkcs8', privateKey);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: encoder.encode('KeyVault-v2-P256') }, key, pkcs8);
    return { version: 2, curve: 'P-256', kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, cipher: 'AES-256-GCM', salt: base64url(salt), iv: base64url(iv), publicKey, ciphertext: base64url(encrypted) };
  };
  const decryptPrivate = async (blob, pass) => {
    if (blob?.version !== 2 || blob?.curve !== 'P-256' || blob?.iterations !== ITERATIONS || typeof blob.publicKey !== 'string') throw Error('Format backup tidak dikenali');
    const key = await kdf(pass, unbase64url(blob.salt));
    const pkcs8 = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unbase64url(blob.iv), additionalData: encoder.encode('KeyVault-v2-P256') }, key, unbase64url(blob.ciphertext));
    const privateKey = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const publicKey = await crypto.subtle.importKey('spki', unbase64url(blob.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    const challenge = encoder.encode('keyvault-v2-self-check');
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, challenge);
    if (!(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, publicKey, sig, challenge))) throw Error('Public key dan private key tidak cocok');
    return { privateKey, publicKey: blob.publicKey, address: await sha256(unbase64url(blob.publicKey)) };
  };
  const api = async (route, data) => {
    const res = await fetch(`/api/v2/${route}`, { method: data === undefined ? 'GET' : 'POST', credentials: 'same-origin', headers: data === undefined ? {} : { 'content-type': 'application/json' }, body: data === undefined ? undefined : JSON.stringify(data), cache: 'no-store' });
    const value = await res.json();
    if (!res.ok || !value.ok) throw Error(value.error || `HTTP ${res.status}`);
    return value;
  };
  const unlock = async () => {
    const raw = localStorage.getItem(STORAGE);
    if (!raw) throw Error('Buat identitas terlebih dahulu');
    const pass = $('pass').value;
    if (pass.length < 12) throw Error('Masukkan kata sandi identitas');
    identity = await decryptPrivate(JSON.parse(raw), pass);
    $('pass').value = '';
    $('address').textContent = `Alamat identitas V2: ${identity.address}`;
    return identity;
  };
  const sign = async message => base64url(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, identity.privateKey, encoder.encode(message)));
  const challenge = async () => api('challenge', { address: identity.address });
  const run = async fn => { try { await fn(); } catch (e) { output(`Gagal: ${e.message}`); } };
  const render = status => {
    loggedIn = status.loggedIn === true;
    $('enabled').checked = !!status.enabled;
    document.querySelectorAll('#algorithms input').forEach(el => el.checked = (status.algorithms || []).includes(el.value));
    if (!loggedIn) $('doh').value = '';
    output(loggedIn ? `Backend terhubung. Login aktif. Mode ${status.enabled ? 'ON' : 'OFF'}.` : 'Backend terhubung. Silakan buka identitas dan login.');
  };
  ALGOS.forEach(name => {
    const label = document.createElement('label');
    const input = document.createElement('input'); input.type = 'checkbox'; input.value = name;
    label.append(input, document.createTextNode(' ' + name)); $('algorithms').append(label);
  });
  $('create').addEventListener('click', () => run(async () => {
    const pass = $('pass').value;
    if (pass.length < 12) throw Error('Kata sandi minimal 12 karakter');
    if (localStorage.getItem(STORAGE)) {
      if (!identity) await unlock();
      const c = await challenge();
      await api('register', { address: identity.address, publicKey: identity.publicKey, challengeId: c.challengeId, signature: await sign(c.message) });
      output('Identitas terdaftar. Pilih Buka dan login.');
      return;
    }
    if (!crypto.subtle) throw Error('Butuh HTTPS atau localhost');
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const publicKey = base64url(await crypto.subtle.exportKey('spki', pair.publicKey));
    const blob = await encryptPrivate(pair.privateKey, pass, publicKey);
    localStorage.setItem(STORAGE, JSON.stringify(blob));
    identity = await decryptPrivate(blob, pass);
    $('pass').value = '';
    $('address').textContent = `Alamat identitas V2: ${identity.address}`;
    const c = await challenge();
    await api('register', { address: identity.address, publicKey, challengeId: c.challengeId, signature: await sign(c.message) });
    output('Identitas dibuat dan terdaftar. Pilih Buka dan login.');
  }));
  $('login').addEventListener('click', () => run(async () => {
    if (!identity) await unlock();
    const c = await challenge();
    const result = await api('login', { address: identity.address, challengeId: c.challengeId, signature: await sign(c.message) });
    const status = await api('status');
    if (!status.loggedIn || status.address !== result.address) throw Error('Sesi server tidak cocok');
    render(status);
  }));
  $('lock').addEventListener('click', () => run(async () => {
    try { await api('logout', {}); } catch {}
    identity = null; loggedIn = false; $('pass').value = ''; $('address').textContent = 'Identitas terkunci';
    $('doh').value = ''; render({ loggedIn: false, enabled: false, algorithms: [] });
  }));
  $('save').addEventListener('click', () => run(async () => {
    if (!loggedIn) throw Error('Login dahulu');
    const algorithms = [...document.querySelectorAll('#algorithms input:checked')].map(x => x.value);
    const enabled = $('enabled').checked;
    const result = await api('mode', { enabled, algorithms });
    $('doh').value = '';
    output(`Mode ${result.enabled ? 'ON' : 'OFF'}. ${result.algorithms.length} algoritma dipilih. Pengaturan tersimpan di server.`);
  }));
  $('token').addEventListener('click', () => run(async () => {
    if (!loggedIn) throw Error('Login dahulu');
    const value = await api('doh-token', {});
    $('doh').value = value.dohUrl;
    output('URL DNS privat siap. Mengganti URL membatalkan token sebelumnya. Simpan URL dengan aman.');
  }));
  $('copy').addEventListener('click', () => run(async () => {
    if (!$('doh').value) throw Error('Belum ada URL DNS');
    await navigator.clipboard.writeText($('doh').value);
    output('URL DNS privat disalin. Jangan sebarkan.');
  }));
  $('export').addEventListener('click', () => run(async () => {
    const raw = localStorage.getItem(STORAGE);
    if (!raw) throw Error('Identitas belum dibuat');
    const link = document.createElement('a');
    const blob = new Blob([raw], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    link.href = url; link.download = 'keyvault-identity-v2-encrypted.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    output('Backup terenkripsi diunduh. Simpan kata sandinya terpisah.');
  }));
  $('import').addEventListener('change', () => run(async () => {
    const file = $('import').files[0];
    if (!file || file.size > 32768) throw Error('File backup invalid');
    if (localStorage.getItem(STORAGE)) throw Error('Identitas sudah ada. Ekspor backup sebelum impor ke perangkat ini');
    const raw = await file.text();
    const parsed = JSON.parse(raw);
    if (parsed.version !== 2 || parsed.curve !== 'P-256' || typeof parsed.ciphertext !== 'string') throw Error('Format backup invalid');
    localStorage.setItem(STORAGE, JSON.stringify(parsed));
    output('Backup terenkripsi diimpor. Masukkan kata sandi, kemudian login.');
  }));
  api('health').then(() => api('status')).then(render).catch(e => output(`Backend belum terhubung: ${e.message}`));
})();
