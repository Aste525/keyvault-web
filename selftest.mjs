import crypto from 'node:crypto';
import { ripemd320, toHex, makeCipher, GCM } from './public/ciphers.js';

const kb = (n) => Uint8Array.from({ length: n }, (_, i) => i);
const out = new Uint8Array(16);
let gagal = 0;
const cek = (nama, got, exp) => { const ok = got === exp; if (!ok) gagal++; console.log(ok ? 'LULUS' : 'GAGAL', nama); };

cek('RIPEMD-320 ""', toHex(ripemd320(new TextEncoder().encode(''))), '22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8');
cek('RIPEMD-320 "abc"', toHex(ripemd320(new TextEncoder().encode('abc'))), 'de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d');
makeCipher('serpent256', kb(32)).encryptBlock(kb(16), out);
cek('Serpent-256', toHex(out), 'de269ff833e432b85b2e88d2701ce75c');
makeCipher('cast256', Uint8Array.from(Buffer.from('2342bb9efa38542cbed0ac83940ac2988d7c47ce264908461cc1b5137ae6b604', 'hex'))).encryptBlock(new Uint8Array(16), out);
cek('CAST-256', toHex(out), '4f6a2038286897b9c9870136553317fa');

if (crypto.getCiphers().includes('aria-256-gcm')) {
  for (const len of [0, 1, 16, 17, 1000]) {
    const key = crypto.randomBytes(32), iv = crypto.randomBytes(12), aad = crypto.randomBytes(4), pt = crypto.randomBytes(len);
    const c = crypto.createCipheriv('aria-256-gcm', key, iv); c.setAAD(aad);
    const ref = Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]).toString('hex');
    cek('ARIA-256-GCM vs OpenSSL, panjang ' + len, Buffer.from(new GCM(makeCipher('aria256gcm', key)).seal(iv, aad, pt)).toString('hex'), ref);
  }
} else console.log('OpenSSL di perangkat ini tidak punya ARIA, tes pembanding dilewati');

console.log(gagal ? 'ADA YANG GAGAL: ' + gagal : 'SEMUA LULUS');
process.exit(gagal ? 1 : 0);
