import { makeCipher, GCM } from './ciphers.js';
const enc = new TextEncoder();
const dec = new TextDecoder();
export const ITER = 600000;
const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h) => Uint8Array.from(h.match(/../g) || [], (x) => parseInt(x, 16));
const cat = (a, b) => { const o = new Uint8Array(a.length + b.length); o.set(a, 0); o.set(b, a.length); return o; };
export async function deriveMaster(pass, salt, iter = ITER) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, base, 256));
}
async function layerKey(master, name) {
  const k = await crypto.subtle.importKey('raw', master, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: enc.encode('kv-vault-layer|' + name) }, k, 256));
}
async function layerSeal(name, key, iv, aad, data) {
  if (name === 'aes256gcm') { const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']); return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, k, data)); }
  return new GCM(makeCipher(name, key)).seal(iv, aad, data);
}
async function layerOpen(name, key, iv, aad, data) {
  if (name === 'aes256gcm') { const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']); return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, k, data)); }
  return new GCM(makeCipher(name, key)).open(iv, aad, data);
}
export async function sealVault(vaultObj, master, header) {
  const h = JSON.stringify(header);
  const aad = enc.encode(h);
  let data = enc.encode(JSON.stringify(vaultObj));
  for (const name of ['aes256gcm', ...header.layers]) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    data = cat(iv, await layerSeal(name, await layerKey(master, name), iv, aad, data));
  }
  return { h, ct: hex(data) };
}
export async function openVault(stored, master) {
  const header = JSON.parse(stored.h);
  const aad = enc.encode(stored.h);
  const names = ['aes256gcm', ...header.layers];
  let data = unhex(stored.ct);
  for (let i = names.length - 1; i >= 0; i--) data = await layerOpen(names[i], await layerKey(master, names[i]), data.slice(0, 12), aad, data.slice(12));
  return JSON.parse(dec.decode(data));
}
