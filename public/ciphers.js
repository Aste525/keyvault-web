// ciphers.js - Serpent-256, ARIA-256, CAST-256, RIPEMD-320, dan GCM generik (blok 128-bit)
// Modul ini dipakai bersama oleh browser (public/app.js) dan server (server.js).

const rotl = (x, n) => (x << n) | (x >>> (32 - n));
const h2b = (h) => { const o = new Uint8Array(h.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(h.substr(i * 2, 2), 16); return o; };
export const toHex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');

/* ===================== RIPEMD-320 ===================== */
const RL = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8, 3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2, 4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
const RR = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2, 15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14, 12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
const SL = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12, 11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12, 9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
const SR = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11, 9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8, 8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
const KLc = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
const KRc = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];
function rf(j, x, y, z) {
  switch (j >> 4) {
    case 0: return x ^ y ^ z;
    case 1: return (x & y) | (~x & z);
    case 2: return (x | ~y) ^ z;
    case 3: return (x & z) | (y & ~z);
    default: return x ^ (y | ~z);
  }
}
export class RIPEMD320 {
  constructor() {
    this.h = new Uint32Array([0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0, 0x76543210, 0xFEDCBA98, 0x89ABCDEF, 0x01234567, 0x3C2D1E0F]);
    this.buf = new Uint8Array(64); this.n = 0; this.len = 0; this.X = new Int32Array(16);
  }
  _block(d, o) {
    const X = this.X, h = this.h;
    for (let i = 0; i < 16; i++) X[i] = d[o + 4 * i] | (d[o + 4 * i + 1] << 8) | (d[o + 4 * i + 2] << 16) | (d[o + 4 * i + 3] << 24);
    let a = h[0] | 0, b = h[1] | 0, c = h[2] | 0, dd = h[3] | 0, e = h[4] | 0;
    let a2 = h[5] | 0, b2 = h[6] | 0, c2 = h[7] | 0, d2 = h[8] | 0, e2 = h[9] | 0, t;
    for (let j = 0; j < 80; j++) {
      t = (rotl((a + rf(j, b, c, dd) + X[RL[j]] + KLc[j >> 4]) | 0, SL[j]) + e) | 0;
      a = e; e = dd; dd = rotl(c, 10); c = b; b = t;
      t = (rotl((a2 + rf(79 - j, b2, c2, d2) + X[RR[j]] + KRc[j >> 4]) | 0, SR[j]) + e2) | 0;
      a2 = e2; e2 = d2; d2 = rotl(c2, 10); c2 = b2; b2 = t;
      if (j === 15) { t = b; b = b2; b2 = t; }
      else if (j === 31) { t = dd; dd = d2; d2 = t; }
      else if (j === 47) { t = a; a = a2; a2 = t; }
      else if (j === 63) { t = c; c = c2; c2 = t; }
      else if (j === 79) { t = e; e = e2; e2 = t; }
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += dd; h[4] += e;
    h[5] += a2; h[6] += b2; h[7] += c2; h[8] += d2; h[9] += e2;
  }
  update(d) {
    this.len += d.length; let i = 0;
    if (this.n) {
      while (i < d.length && this.n < 64) this.buf[this.n++] = d[i++];
      if (this.n === 64) { this._block(this.buf, 0); this.n = 0; }
    }
    for (; i + 64 <= d.length; i += 64) this._block(d, i);
    while (i < d.length) this.buf[this.n++] = d[i++];
    return this;
  }
  digest() {
    const bits = this.len * 8;
    const pad = new Uint8Array((this.n < 56 ? 56 : 120) - this.n + 8);
    pad[0] = 0x80;
    const lo = bits >>> 0, hi = Math.floor(bits / 4294967296), L = pad.length - 8;
    for (let i = 0; i < 4; i++) { pad[L + i] = (lo >>> (8 * i)) & 255; pad[L + 4 + i] = (hi >>> (8 * i)) & 255; }
    this.update(pad);
    const out = new Uint8Array(40);
    for (let i = 0; i < 10; i++) for (let k = 0; k < 4; k++) out[4 * i + k] = (this.h[i] >>> (8 * k)) & 255;
    return out;
  }
}
export const ripemd320 = (bytes) => new RIPEMD320().update(bytes).digest();

/* ===================== Serpent-256 ===================== */
const SERP_SB = [
  [3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12], [15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4],
  [8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2], [0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14],
  [1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13], [15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1],
  [7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0], [1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6]
];
// S-box dihitung bitslice lewat bentuk aljabar (ANF) tiap bit keluaran
const SERP_ANF = SERP_SB.map((box) => [0, 1, 2, 3].map((bit) => {
  const c = box.map((v) => (v >> bit) & 1);
  for (let i = 0; i < 4; i++) for (let m = 0; m < 16; m++) if (m & (1 << i)) c[m] ^= c[m ^ (1 << i)];
  const ms = []; for (let m = 0; m < 16; m++) if (c[m]) ms.push(m);
  return Int8Array.from(ms);
}));
const SM = new Int32Array(16);
function serpSbox(s, a, b, c, d, out) {
  SM[0] = -1; SM[1] = a; SM[2] = b; SM[4] = c; SM[8] = d;
  SM[3] = a & b; SM[5] = a & c; SM[6] = b & c; SM[9] = a & d; SM[10] = b & d; SM[12] = c & d;
  SM[7] = SM[3] & c; SM[11] = SM[3] & d; SM[13] = SM[5] & d; SM[14] = SM[6] & d; SM[15] = SM[7] & d;
  for (let k = 0; k < 4; k++) { let v = 0; const l = SERP_ANF[s][k]; for (let i = 0; i < l.length; i++) v ^= SM[l[i]]; out[k] = v; }
}
class Serpent256 {
  constructor(key) {
    if (key.length !== 32) throw new Error('Serpent-256 butuh kunci 32 byte');
    const w = new Int32Array(140), o = new Int32Array(4);
    for (let i = 0; i < 8; i++) w[i] = key[4 * i] | (key[4 * i + 1] << 8) | (key[4 * i + 2] << 16) | (key[4 * i + 3] << 24);
    for (let j = 8; j < 140; j++) w[j] = rotl(w[j - 8] ^ w[j - 5] ^ w[j - 3] ^ w[j - 1] ^ 0x9e3779b9 ^ (j - 8), 11);
    this.k = new Int32Array(132);
    for (let r = 0; r < 33; r++) {
      serpSbox((((3 - r) % 8) + 8) % 8, w[8 + 4 * r], w[9 + 4 * r], w[10 + 4 * r], w[11 + 4 * r], o);
      this.k.set(o, 4 * r);
    }
    this.o = new Int32Array(4);
  }
  encryptBlock(src, dst) {
    const k = this.k, o = this.o;
    let a = src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
    let b = src[4] | (src[5] << 8) | (src[6] << 16) | (src[7] << 24);
    let c = src[8] | (src[9] << 8) | (src[10] << 16) | (src[11] << 24);
    let d = src[12] | (src[13] << 8) | (src[14] << 16) | (src[15] << 24);
    for (let r = 0; r < 32; r++) {
      serpSbox(r & 7, a ^ k[4 * r], b ^ k[4 * r + 1], c ^ k[4 * r + 2], d ^ k[4 * r + 3], o);
      a = o[0]; b = o[1]; c = o[2]; d = o[3];
      if (r < 31) {
        a = rotl(a, 13); c = rotl(c, 3); b ^= a ^ c; d ^= c ^ (a << 3);
        b = rotl(b, 1); d = rotl(d, 7); a ^= b ^ d; c ^= d ^ (b << 7);
        a = rotl(a, 5); c = rotl(c, 22);
      } else { a ^= k[128]; b ^= k[129]; c ^= k[130]; d ^= k[131]; }
    }
    const v = [a, b, c, d];
    for (let i = 0; i < 4; i++) { dst[4 * i] = v[i] & 255; dst[4 * i + 1] = (v[i] >>> 8) & 255; dst[4 * i + 2] = (v[i] >>> 16) & 255; dst[4 * i + 3] = (v[i] >>> 24) & 255; }
  }
}

/* ===================== ARIA-256 ===================== */
const ARIA_S1 = h2b([
  '637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275',
  '09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2',
  'cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08',
  'ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16'
].join(''));
const ARIA_S2 = h2b([
  'e24e54fc94c24acc620d6a463c4d8bd15efa64cbb497be2bbc772e03d31959c11d06416b55f09969ea9c18ae63dfe7bb007366fb964c85e43a0945aa0fee10eb',
  '2d7ff429accfad918d78c895f92fcecd087a88385c832a2847dbb8c793a41253ff870e3136215848018e377432cae9b1b7ab0cd7c4564226079860d9b6b91140',
  'ec208cbda0c984044923f14f501f13dcd8c09e57e3c37b653b028f3ee82592e515ddfd17a9bfd49a7ec53967fe769d43a7e1d0f568f21b347005a38ad57986a8',
  '30c6514b1ea627f635d26e2416825fdae675a2ef2cb21c9f5d6f800a72449b6c900b5b337d5a52f361a1f7b0d63f7c6ded14e0a53d22b3f889de711aafbab581'
].join(''));
const ARIA_X1 = new Uint8Array(256), ARIA_X2 = new Uint8Array(256);
for (let i = 0; i < 256; i++) { ARIA_X1[ARIA_S1[i]] = i; ARIA_X2[ARIA_S2[i]] = i; }
const ARIA_L1 = [ARIA_S1, ARIA_S2, ARIA_X1, ARIA_X2];
const ARIA_L2 = [ARIA_X1, ARIA_X2, ARIA_S1, ARIA_S2];
const ARIA_C = [h2b('517cc1b727220a94fe13abe8fa9a6ee0'), h2b('6db14acc9e21c820ff28b1d5ef5de2b0'), h2b('db92371d2126e9700324977504e8c90e')];
function ariaDiff(x, y) {
  y[0] = x[3] ^ x[4] ^ x[6] ^ x[8] ^ x[9] ^ x[13] ^ x[14];
  y[1] = x[2] ^ x[5] ^ x[7] ^ x[8] ^ x[9] ^ x[12] ^ x[15];
  y[2] = x[1] ^ x[4] ^ x[6] ^ x[10] ^ x[11] ^ x[12] ^ x[15];
  y[3] = x[0] ^ x[5] ^ x[7] ^ x[10] ^ x[11] ^ x[13] ^ x[14];
  y[4] = x[0] ^ x[2] ^ x[5] ^ x[8] ^ x[11] ^ x[14] ^ x[15];
  y[5] = x[1] ^ x[3] ^ x[4] ^ x[9] ^ x[10] ^ x[14] ^ x[15];
  y[6] = x[0] ^ x[2] ^ x[7] ^ x[9] ^ x[10] ^ x[12] ^ x[13];
  y[7] = x[1] ^ x[3] ^ x[6] ^ x[8] ^ x[11] ^ x[12] ^ x[13];
  y[8] = x[0] ^ x[1] ^ x[4] ^ x[7] ^ x[10] ^ x[13] ^ x[15];
  y[9] = x[0] ^ x[1] ^ x[5] ^ x[6] ^ x[11] ^ x[12] ^ x[14];
  y[10] = x[2] ^ x[3] ^ x[5] ^ x[6] ^ x[8] ^ x[13] ^ x[15];
  y[11] = x[2] ^ x[3] ^ x[4] ^ x[7] ^ x[9] ^ x[12] ^ x[14];
  y[12] = x[1] ^ x[2] ^ x[6] ^ x[7] ^ x[9] ^ x[11] ^ x[12];
  y[13] = x[0] ^ x[3] ^ x[6] ^ x[7] ^ x[8] ^ x[10] ^ x[13];
  y[14] = x[0] ^ x[3] ^ x[4] ^ x[5] ^ x[9] ^ x[11] ^ x[14];
  y[15] = x[1] ^ x[2] ^ x[4] ^ x[5] ^ x[8] ^ x[10] ^ x[15];
}
function ariaRot(a, n) { // rotasi kiri 128-bit sebesar n bit
  const o = new Uint8Array(16), bs = n >> 3, bt = n & 7;
  for (let i = 0; i < 16; i++) o[i] = ((a[(i + bs) & 15] << bt) | (a[(i + bs + 1) & 15] >> (8 - bt))) & 255;
  return o;
}
const ariaXor = (a, b) => a.map((v, i) => v ^ b[i]);
function ariaF(d, rk, layer, out) {
  const t = new Uint8Array(16);
  for (let i = 0; i < 16; i++) t[i] = layer[i & 3][d[i] ^ rk[i]];
  ariaDiff(t, out);
  return out;
}
class Aria256 {
  constructor(key) {
    if (key.length !== 32) throw new Error('ARIA-256 butuh kunci 32 byte');
    const KL = key.slice(0, 16), KR = key.slice(16), tmp = new Uint8Array(16);
    const CK = [ARIA_C[2], ARIA_C[0], ARIA_C[1]];
    const W0 = KL;
    const W1 = ariaXor(ariaF(W0, CK[0], ARIA_L1, tmp).slice(), KR);
    const W2 = ariaXor(ariaF(W1, CK[1], ARIA_L2, tmp).slice(), W0);
    const W3 = ariaXor(ariaF(W2, CK[2], ARIA_L1, tmp).slice(), W1);
    const W = [W0, W1, W2, W3], ek = [];
    for (const [n, left] of [[19, false], [31, false], [61, true], [31, true]]) {
      for (let i = 0; i < 4; i++) {
        const a = W[i], b = W[(i + 1) & 3];
        if (i < 3) ek.push(ariaXor(a, ariaRot(b, left ? n : 128 - n)));
        else ek.push(ariaXor(ariaRot(W[0], left ? n : 128 - n), W[3]));
      }
    }
    ek.push(ariaXor(W0, ariaRot(W1, 19)));
    this.ek = ek; this.a = new Uint8Array(16); this.b = new Uint8Array(16);
  }
  encryptBlock(src, dst) {
    let s = this.a, t = this.b; s.set(src);
    for (let i = 0; i < 15; i++) {
      ariaF(s, this.ek[i], i % 2 === 0 ? ARIA_L1 : ARIA_L2, t);
      const x = s; s = t; t = x;
    }
    for (let i = 0; i < 16; i++) dst[i] = ARIA_L2[i & 3][s[i] ^ this.ek[15][i]] ^ this.ek[16][i];
  }
}

/* ===================== CAST-256 ===================== */
const CAST = h2b([
  '30fb40d49fa0ff0b6beccd2f3f258c7a1e213f2f9c004dd36003e540cf9fc949bfd4af2788bbbdb5e203409098d096756e63a0e015c361d2c2e7661d22d4ff8e',
  '28683b6fc07fd059ff2379c8775f50e243c340d3df2f8656887ca41aa2d2bd2da1c9e0d6346c481961b76d8722540f2f2abe32e1aa54166b22568e3aa2d341d0',
  '66db40c8a784392f004dff2f2db9d2de97943fac4a97c1d8527644b7b5f437a7b82cbaefd751d1596ff7f0ed5a097a1f827b68d090ecf52e22b0c054bc8e5935',
  '4b6d2f7f50bb64a2d2664910bee5812db7332290e93b159fb48ee4114bff345dfd45c240ad31973fc4f6d02e55fc8165d5b1caada1ac2daea2d4b76dc19b0c50',
  '882240f20c6e4f38a4e4bfd74f5ba272564c1d2fc59c5319b949e354b04669feb1b6ab8ac71358dd6385c545110f935d57538ad56a390493e63d37e02a54f6b3',
  '3a787d5f6276a0b519a6fcdf7a42206a29f9d4d5f61b1891bb72275eaa50816738901091c6b505eb84c7cb8c2ad75a0f874a1427a2d1936b2ad286afaa56d291',
  'd7894360425c750d93b39e26187184c96c00b32d73e2bb14a0bebc3c5462377964459eab3f328b827718cf8259a2cea604ee002e89fe78e63fab0950325ff6c2',
  '81383f056963c5c876cb5ad6d49974c9ca180dcf380782d5c7fa5cf68ac3151135e79e1347da91d0f40f9086a7e2419e31366241051ef495aa573b044a805d8d',
  '548300d000322a3cbf64cddfba57a68e75c6372b50afd341a7c13275915a0bf56b54bfab2b0b1426ab4cc9d7449ccd82f7fbf265ab85c5f31b55db94aad4e324',
  'cfa4bd3f2deaa3e29e204d02c8bd25aceadf55b3d5bd9e98e31231b22ad5ad6c954329deadbe4528d8710f69aa51c90faa786bf622513f1eaa51a79b2ad344cc',
  '7b5a41f0d37cfbad1b06950541ece491b4c332e6032268d4c9600accce387e6dbf6bb16c6a70fb780d03d9c9d4df39dee01063da4736f4645ad328d8b347cc96',
  '75bb0fc398511bfb4ffbcc35b58bcf6ae11f0abcbfc5fe4aa70aec10ac39570a3f04442f6188b153e0397a2e5727cb799ceb418f1cacd68d2ad37c960175cb9d',
  'c69dff09c75b65f0d9db40d8ec0e77794744ead4b11c3274dd24cb9e7e1c54bdf01144f9d2240eb19675b3fda3ac3755d47c27af51c85f4d56907596a5bb15e6',
  '580304f0ca042cf1011a37ea8dbfaadb35ba3e4a3526ffa0c37b4d09bc306ed998a526665648f725ff5e569d0ced63d07c63b2cf700b45e1d5ea50f185a92872',
  'af1fbda7d4234870a7870bf32d3b4d7942e041980cd0ede726470db8f881814c474d6ad77c0c5e5cd1231959381b7298f5d2f4dbab8386536e2f1e2383719c9e',
  'bd91e0469a56456edc39200c20c8c571962bda1ce1e696ffb141ab087cca89b91a69e78302cc4843a2f7c579429ef47d427b169c5ac9f049dd8f0f005c8165bf',
  '1f201094ef0ba75b69e3cf7e393f4380fe61cf7aeec5207a55889c9472fc0651ada7ef794e1d7235d55a63cede0436ba99c430ef5f0c079418dcdb7da1d6eff3',
  'a0b52f7b59e83605ee15b094e9ffd909dc440086ef944459ba83ccb3e0c3cdfbd1da41813b092ab1f997f1c1a5e6cf7b01420ddbe4e7ef5b25a1ff41e180f806',
  '1fc41080179bee7ad37ac6a9fe5830a498de8b7f77e83f4e7992926924fa9f7be113c85bacc40083d7503525f7ea615f621431540d554b635d681121c866c359',
  '3d63cf73cee234c0d4d87e875c672b21071f618139f7627f361e3084e4eb573b602f64a4d63acd9c1bbc46359e81032d2701f50c99847ab4a0e3df79ba6cf38c',
  '108430942537a95ef46f6ffea1ff3b1f208cfb6a8f458c74d9e0a2274ec73a34fc884f693e4de8dfef0e00883559648d8a45388c1d804366721d9bfda58684bb',
  'e8256333844e8212128d8098fed33fb4ce280ae127e19ba5d5a6c252e49754bdc5d655ddeb66706477840b4da1b6a80184db26a9e0b5671421f043b7e5d05860',
  '54f03084066ff472a31aa153dadc4755b5625dbf68561be683ca6b942d6ed23beccf01dba6d3d0bab6803d5caf77a70933b4a34c397bc8d65ee22b955f0e5304',
  '81ed6f6120e74364b45e1378de18639b881ca122b96726d18049a7e822b7da7b5e552d255272d23779d2951cc60d894c488cb4021ba4fe5ba4b09f6b1ca815cf',
  'a20c30058871df63b9de2fcb0cc6c9e90beeff53e3214517b45428359f63293cee41e7296e1d2d7c500452861e6685f3f33401c630a22c9531a7085060930f13',
  '73f98417a1269859ec645c4452c877a9cdff33a6a02b17417cbad9a22180036f50d99c08cb3f4861c26bd76564a3f6ab8034267625a75e7be4e6d1fc20c710e6',
  'cdf0b68017844d3b31eef84d7e0824e42ccb49eb846a3bae8ff77888ee5d60f67af756732fdd5cdba11631c130f66f43b3faec54157fd7faef8579ccd152de58',
  'db2ffd5e8f32ce19306af97a02f03ef899319ad5c242fa0fa7e3ebb0c68e4906b8da230c80823028dcdef3c8d35fb171088a1bc8bec0c56061a3c9e8bca8f54d',
  'c72feffa22822e9982c570b4d8d94e898b1c34bc301e16e6273be979b0ffeaa661d9b8c600b24869b7ffce3f08dc283b43daf65af7e197987619b72f8f1c9ba4',
  'dc8637a016a7d3b19fc393b7a7136eebc6bcc63e1a513742ef6828bc520365d62d6a77ab3527ed4b821fd216095c6e2edb92f2fb5eea29cb145892f591584f7f',
  '5483697b2667a8cc851960488c4bacea833860d40d23e0f96c387e8a0ae6d249b284600cd835731ddcb1c647ac4c56ea3ebd81b3230eabb06438bc87f0b5b1fa',
  '8f5ea2b3fc1846420a036b7a4fb089bd649da589a345415e5c0383233e5d3bb943d795727e6dd07c06dfdf1e6c6cc4ef7160a53973bfbe70838776054523ecf1',
  '8defc24025fa5d9feb903dbfe810c90747607fff369fe44b8c1fc644aececa90beb1f9bfeefbcaeae8cf195051df07ae920e8806f0ad0548e13c8d83927010d5',
  '11107d9f07647db9b2e3e4d43d4f285eb9afa820fade82e0a067268b8272792e553fb2c0489ae22bd4ef9794125e3fbc21fffcee825b1bfd9255c5ed1257a240',
  '4e1a8302bae07fff528246e78e57140e3373f7bf8c9f8188a6fc4ee8c982b5a5a8c01db7579fc26467094f31f2bd3f5f40fff7c11fb78dfc8e6bd2c1437be59b',
  '99b03dbfb5dbc64b638dc0e655819d99a197c81c4a012d6ec5884a28ccc36f71b843c2136c0743f18309893c0feddd5f2f7fe850d7c07f7e02507fbf5afb9a04',
  'a747d2d01651192eaf70bf3e58c313805f98302e727cc3c40a0fb4020f7fef828c96fdad5d2c2aae8ee99a4950da88b88427f4a01eac5790796fb4498252dc15',
  'efbd7d9ba672597dada840d845f54504fa5d7403e83ec3054f91751a925669c223efe941a903f12e60270df20276e4b694fd6574927985b28276dbcb02778176',
  'f8af918d4e48f79e8f616ddfe29d840e842f7d83340ce5c896bbb68293b4b148ef303cab984faf28779faf9b92dc560d224d1e208437aa887d29dc962756d3dc',
  '8b907ceeb51fd240e7c07ce3e566b4a1c3e9615e3cf8209d6094d1e3cd9ca3415c76460e00ea983bd4d67881fd47572cf76cedd9bda8229c127dadaa438a074e',
  '1f97c090081bdb8a93a07ebeb938ca1597b03cff3dc2c0f88d1ab2ec64380e5168cc7bfbd90f2788124901815de5ffd4dd7ef86a76a2e214b9a40368925d958f',
  '4b39fffaba39aee9a4ffd30bfaf7933b6d498623193cbcfa27627545825cf47a61bd8ba0d11e42d1cead04f4127ea39210428db78272a9729270c4a8127de50b',
  '285ba1c83c62f44f35c0eaa5e805d231428929fbb4fcdf824fb66a530e7dc15b1f081fab108618aefcfd086df9ff2889694bcc11236a5cae12deca4d2c3f8cc5',
  'd2d02dfef8ef5896e4cf52da95155b67494a488cb9b6a80c5c8f82bc89d36b453a609437ec00c9a9447152530a874b49d773bc407c34671c02717ef64feb5536',
  'a2d02fffd2bf60c4d43f03c050b4ef6d07478cd1006e1888a2e53f55b9e6d4bca204801697573833d7207d67de0f8f3d72f87b33abcc4f337688c55d7b00a6b0',
  '947b0001570075d2f9bb88f88942019e4264a5ff856302e072dbd92bee971b696ea22fde5f08ae2baf7a616de5c98767cf1febd261efc8c2f1ac2571cc8239c2',
  '67214cb8b1e583d1b7dc3e627f10bdcef90a5c380ff0443d606e6dc660543a495727c1482be98a1d8ab4173820e1be24af96da0f6845842599833be5600d457d',
  '282f93508334b362d91d11202b6d8da0642b1e319c305a0052bce6881b03588af7baefd54142ed9ca4315c1183323ec5dfef4636a133c501e9d3531cee353783',
  '9db304201fb6e9dea7be7befd273a2984a4f7bdb64ad8c5785510443fa020ed17e287affe60fb663095f35a179ebf120fd059d436497b7b1f3641f63241e4adf',
  '28147f5f4fa2b8cdc94300400cc32220fdd30b30c0a5374f1d2d00d924147b15ee4d111a0fca516771ff904c2d195ffe1a05645f0c13fefe081b08ca05170121',
  '80530100e83e5efeac9af4f87fe72701d2b8ee5f06df4261bb9e9b8a7293ea25ce84ffdff57188013dd64b04a26f263b7ed48400547eebe6446d4ca06cf3d6f5',
  '2649abdfaea0c7f536338cc1503f7e93d377206111b638e172500e03f80eb2bbabe0502eec8d77de57971e81e14f6746c93354006920318f081dbb99ffc304a5',
  '4d3518057f3d5ce3a6c866c65d5bcca9daec6fea9f926f919f46222f3991467da5bf6d8e1143c44f43958302d0214eeb022083b83fb6180c18f8931e281658e6',
  '26486e3e8bd78a707477e4c1b506e07cf32d0a2579098b02e4eabb8128123b2369dead381574ca16df871b62211c40b7a51a9ef90014377b041e8ac809114003',
  'bd59e4d2e3d156d54fe876d52f91a340557be8de00eae4a70ce5c2ec4db4bba6e756bdffdd3369acec17b0350657232799afc8b056c8c3916b65811c5e146119',
  '6e85cb75be07c002c2325577893ff4ec5bbfc92dd0ec3b25b7801ab78d6d3b2420c763efc366a5fc9c3828800ace3205aac9548aeca1d7c7041afa321d16625a',
  '6701902c9b757a5431d477f79126b03136cc6fdbc70b8b46d9e66a4856e55a79026a4ceb52437eff2f8f76b40df980a58674cde3edda04eb17a9be042c18f4df',
  'b7747f9dab2af7b4efc34d202e096b7c1741a254e5b6a035213d42f62c1c7c2661c2f50f6552daf9d2c231f825130f69d8167fa20418f2c8001a96a60d1526ab',
  '63315c215e0a72ec49bafefd187908d98d0dbd86311170a73e9b640ccc3e10d7d5cad3b60caec388f73001e16c728aff71eae2a11f9af36ecfcbd12fc1de8417',
  'ac07be6bcb44a1d88b9b0f56013988c3b1c52fcab4be31cdd878280612a3a4e26f7de53258fd7eb6d01ee90024adffc2f4990fc59711aac5001d7b9582e5e7d2',
  '109873f600613096c32d9521ada121ff299084157fbb977faf9eb3db29c9ed2a5ce2a465a730f32cd0aa3fe88a5cc091d49e2ce70ce454a9d60acd86015f1919',
  '77079103dea03af678a8565edee356df21f05cbe8b75e387b3c50651b8a5c3efd8eeb6d2e523be77c21545292f69efdfafe67afbf470c4b2f3e0eb5bd6cc9876',
  '39e4460c1fda85381987832fca007367a99144f8296b299e492fc2959266beabb5676e699bd3dddadf7e052fdb25701c1b5e51eef65324e66afce36c0316cc04',
  '8644213eb7dc59d07965291fccd6fd4341823979932bcdf6b657c34d4edfd2827ae5290c3cb9536b851e20fe9833557e13ecf0b0d3ffb3723f85c5c10aef7ed2'
].join(''));
const CS = [0, 1, 2, 3].map((n) => { const t = new Int32Array(256); for (let i = 0; i < 256; i++) { const o = (n * 256 + i) * 4; t[i] = (CAST[o] << 24) | (CAST[o + 1] << 16) | (CAST[o + 2] << 8) | CAST[o + 3]; } return t; });
const CTm = [], CTr = [];
{ let cm = 0x5a827999, cr = 19; for (let i = 0; i < 24; i++) { CTm.push([]); CTr.push([]); for (let j = 0; j < 8; j++) { CTm[i].push(cm | 0); cm = (cm + 0x6ed9eba1) | 0; CTr[i].push(cr); cr = (cr + 17) & 31; } } }
const cf1 = (D, r, m) => { const I = rotl((m + D) | 0, r); return ((((CS[0][I >>> 24] ^ CS[1][(I >>> 16) & 255]) - CS[2][(I >>> 8) & 255]) | 0) + CS[3][I & 255]) | 0; };
const cf2 = (D, r, m) => { const I = rotl(m ^ D, r); return ((((CS[0][I >>> 24] - CS[1][(I >>> 16) & 255]) | 0) + CS[2][(I >>> 8) & 255]) | 0) ^ CS[3][I & 255]; };
const cf3 = (D, r, m) => { const I = rotl((m - D) | 0, r); return ((((CS[0][I >>> 24] + CS[1][(I >>> 16) & 255]) | 0) ^ CS[2][(I >>> 8) & 255]) - CS[3][I & 255]) | 0; };
class Cast256 {
  constructor(key) {
    if (key.length !== 32) throw new Error('CAST-256 butuh kunci 32 byte');
    const k = new Int32Array(8);
    for (let i = 0; i < 8; i++) k[i] = (key[4 * i] << 24) | (key[4 * i + 1] << 16) | (key[4 * i + 2] << 8) | key[4 * i + 3];
    const W = (i) => {
      const r = CTr[i], m = CTm[i];
      k[6] ^= cf1(k[7], r[0], m[0]); k[5] ^= cf2(k[6], r[1], m[1]); k[4] ^= cf3(k[5], r[2], m[2]); k[3] ^= cf1(k[4], r[3], m[3]);
      k[2] ^= cf2(k[3], r[4], m[4]); k[1] ^= cf3(k[2], r[5], m[5]); k[0] ^= cf1(k[1], r[6], m[6]); k[7] ^= cf2(k[0], r[7], m[7]);
    };
    this.Kr = []; this.Km = [];
    for (let i = 0; i < 12; i++) {
      W(2 * i); W(2 * i + 1);
      this.Kr.push([k[0] & 31, k[2] & 31, k[4] & 31, k[6] & 31]);
      this.Km.push([k[7], k[5], k[3], k[1]]);
    }
  }
  encryptBlock(src, dst) {
    const rd = (o) => (src[o] << 24) | (src[o + 1] << 16) | (src[o + 2] << 8) | src[o + 3];
    let A = rd(0), B = rd(4), C = rd(8), D = rd(12);
    for (let i = 0; i < 6; i++) {
      const r = this.Kr[i], m = this.Km[i];
      C ^= cf1(D, r[0], m[0]); B ^= cf2(C, r[1], m[1]); A ^= cf3(B, r[2], m[2]); D ^= cf1(A, r[3], m[3]);
    }
    for (let i = 6; i < 12; i++) {
      const r = this.Kr[i], m = this.Km[i];
      D ^= cf1(A, r[3], m[3]); A ^= cf3(B, r[2], m[2]); B ^= cf2(C, r[1], m[1]); C ^= cf1(D, r[0], m[0]);
    }
    [A, B, C, D].forEach((v, i) => { dst[4 * i] = v >>> 24; dst[4 * i + 1] = (v >>> 16) & 255; dst[4 * i + 2] = (v >>> 8) & 255; dst[4 * i + 3] = v & 255; });
  }
}

export const CIPHERS = { serpent256: Serpent256, aria256gcm: Aria256, cast256: Cast256 };
export function makeCipher(name, key) {
  const C = CIPHERS[name];
  if (!C) throw new Error('Cipher tidak dikenal: ' + name);
  return new C(key);
}

/* ===================== GCM generik (blok 128-bit) ===================== */
const REM4 = [0x0000, 0x1C20, 0x3840, 0x2460, 0x7080, 0x6CA0, 0x48C0, 0x54E0, 0xE100, 0xFD20, 0xD940, 0xC560, 0x9180, 0x8DA0, 0xA9C0, 0xB5E0];
export class GCM {
  constructor(cipher) {
    this.c = cipher;
    const Hb = new Uint8Array(16);
    cipher.encryptBlock(new Uint8Array(16), Hb);
    const T = (this.T = new Int32Array(64));
    const v = [0, 4, 8, 12].map((o) => (Hb[o] << 24) | (Hb[o + 1] << 16) | (Hb[o + 2] << 8) | Hb[o + 3]);
    const set = (i) => { for (let k = 0; k < 4; k++) T[i * 4 + k] = v[k]; };
    const red = () => {
      const t = (v[3] & 1) ? 0xe1000000 | 0 : 0;
      v[3] = (v[3] >>> 1) | (v[2] << 31); v[2] = (v[2] >>> 1) | (v[1] << 31); v[1] = (v[1] >>> 1) | (v[0] << 31); v[0] = (v[0] >>> 1) ^ t;
    };
    const xr = (i, a, b) => { for (let k = 0; k < 4; k++) T[i * 4 + k] = T[a * 4 + k] ^ T[b * 4 + k]; };
    set(8); red(); set(4); red(); set(2); red(); set(1);
    xr(3, 2, 1); xr(5, 4, 1); xr(6, 4, 2); xr(7, 4, 3);
    for (let i = 9; i < 16; i++) xr(i, 8, i - 8);
    this.X = new Uint8Array(16);
  }
  _mul() {
    const X = this.X, T = this.T;
    let cnt = 15, nlo = X[15], nhi = nlo >> 4, o;
    nlo &= 15; o = nlo * 4;
    let z0 = T[o], z1 = T[o + 1], z2 = T[o + 2], z3 = T[o + 3], rem;
    for (;;) {
      rem = z3 & 15;
      z3 = (z3 >>> 4) | (z2 << 28); z2 = (z2 >>> 4) | (z1 << 28); z1 = (z1 >>> 4) | (z0 << 28); z0 = (z0 >>> 4) ^ (REM4[rem] << 16);
      o = nhi * 4; z0 ^= T[o]; z1 ^= T[o + 1]; z2 ^= T[o + 2]; z3 ^= T[o + 3];
      if (--cnt < 0) break;
      nlo = X[cnt]; nhi = nlo >> 4; nlo &= 15;
      rem = z3 & 15;
      z3 = (z3 >>> 4) | (z2 << 28); z2 = (z2 >>> 4) | (z1 << 28); z1 = (z1 >>> 4) | (z0 << 28); z0 = (z0 >>> 4) ^ (REM4[rem] << 16);
      o = nlo * 4; z0 ^= T[o]; z1 ^= T[o + 1]; z2 ^= T[o + 2]; z3 ^= T[o + 3];
    }
    [z0, z1, z2, z3].forEach((z, i) => { X[4 * i] = z >>> 24; X[4 * i + 1] = (z >>> 16) & 255; X[4 * i + 2] = (z >>> 8) & 255; X[4 * i + 3] = z & 255; });
  }
  _ghash(d, len) {
    for (let i = 0; i < len; i += 16) {
      const n = Math.min(16, len - i);
      for (let k = 0; k < n; k++) this.X[k] ^= d[i + k];
      this._mul();
    }
  }
  _xcrypt(iv, inp, out) {
    const cb = new Uint8Array(16), ks = new Uint8Array(16);
    cb.set(iv); let ctr = 2;
    for (let i = 0; i < inp.length; i += 16) {
      cb[12] = ctr >>> 24; cb[13] = (ctr >>> 16) & 255; cb[14] = (ctr >>> 8) & 255; cb[15] = ctr & 255; ctr = (ctr + 1) >>> 0;
      this.c.encryptBlock(cb, ks);
      const n = Math.min(16, inp.length - i);
      for (let k = 0; k < n; k++) out[i + k] = inp[i + k] ^ ks[k];
    }
  }
  _tag(iv, aad, ct) {
    this.X.fill(0);
    this._ghash(aad, aad.length);
    this._ghash(ct, ct.length);
    const lb = new Uint8Array(16), ab = aad.length * 8, cbits = ct.length * 8;
    const put = (o, bits) => { const hi = Math.floor(bits / 4294967296), lo = bits >>> 0; for (let i = 0; i < 4; i++) { lb[o + i] = (hi >>> (24 - 8 * i)) & 255; lb[o + 4 + i] = (lo >>> (24 - 8 * i)) & 255; } };
    put(0, ab); put(8, cbits);
    this._ghash(lb, 16);
    const j0 = new Uint8Array(16), e = new Uint8Array(16);
    j0.set(iv); j0[15] = 1;
    this.c.encryptBlock(j0, e);
    return e.map((v, i) => v ^ this.X[i]);
  }
  // iv: 12 byte. Hasil: ciphertext || tag(16)
  seal(iv, aad, pt) {
    const out = new Uint8Array(pt.length + 16);
    const ct = out.subarray(0, pt.length);
    this._xcrypt(iv, pt, ct);
    out.set(this._tag(iv, aad, ct), pt.length);
    return out;
  }
  open(iv, aad, data) {
    if (data.length < 16) throw new Error('Data rusak');
    const ct = data.subarray(0, data.length - 16), tag = data.subarray(data.length - 16);
    const t = this._tag(iv, aad, ct);
    let diff = 0; for (let i = 0; i < 16; i++) diff |= t[i] ^ tag[i];
    if (diff) throw new Error('Autentikasi gagal: file rusak atau kunci salah');
    const pt = new Uint8Array(ct.length);
    this._xcrypt(iv, ct, pt);
    return pt;
  }
}
