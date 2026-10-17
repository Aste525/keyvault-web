# Key Vault

Key Vault all-in-one berbasis website: enkripsi, hashing, tanda tangan digital, dan kombinasi kripto. Tanpa email, tanpa nomor telepon. Alamat pengguna dihasilkan dari SHA-256 + Ed448 (Goldilocks).

## Algoritma

- Enkripsi: X448, RSA-2048 (hybrid), Serpent-256, ARIA-256-GCM, CAST-256 (mode GCM per chunk 4MB)
- Hashing: SHA-256, RIPEMD-320 (juga untuk hash blok ledger)
- Tanda tangan digital: Ed448 (Goldilocks/Curve448), ECDSA, Schnorr
- Kombinasi: satu dari tiap kategori

Serpent-256, ARIA-256, CAST-256, RIPEMD-320, dan GCM ditulis sendiri di `public/ciphers.js` (JavaScript murni) dan diuji dengan `npm test`.

## Menjalankan

Syarat: Node.js 18 atau lebih baru. Tanpa dependensi npm.

    git clone https://github.com/USERNAME/keyvault-web.git
    cd keyvault-web
    npm test
    npm start

Buka http://localhost:28836

## Link publik HTTPS (gratis)

Pasang cloudflared (Termux: `pkg install cloudflared`), lalu:

    npm run public

Link https://xxxx.trycloudflare.com muncul di terminal. Link berubah setiap dijalankan ulang; link tetap butuh domain sendiri.

## DNS-over-HTTPS (mode ON)

Server mendengarkan di 0.0.0.0:28836 dan meneruskan DNS ke 10 resolver upstream yang berganti tiap 10 detik. DoH wajib HTTPS (pakai link publik di atas). URL DoH pengguna: https://DOMAIN-KAMU/dns/ALAMAT

## Catatan keamanan

- Kunci dan dokumen diproses di browser, tidak diunggah.
- Server tidak mencatat IP pengguna. Situs tujuan tetap melihat IP pengguna.
- Ledger dan daftar mode ON tersimpan per server (ledger.json, modes.json).
- Modul Serpent, ARIA, CAST, dan RIPEMD-320 belum diaudit pihak ketiga.

## Lisensi

MIT
