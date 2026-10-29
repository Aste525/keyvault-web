package com.keyvault.vpn

import java.security.SecureRandom

class PacketCipher(key: ByteArray) {
    private val cipher = Serpent256(key)
    private val rng = SecureRandom()

    fun encrypt(plain: ByteArray): ByteArray {
        val nonce = ByteArray(12).also { rng.nextBytes(it) }
        val out = ByteArray(plain.size)
        val ks = ByteArray(16)
        var ctr = 0; var off = 0
        while (off < plain.size) {
            val blk = ByteArray(16)
            System.arraycopy(nonce, 0, blk, 0, 12)
            blk[12]=(ctr ushr 24).toByte(); blk[13]=(ctr ushr 16).toByte(); blk[14]=(ctr ushr 8).toByte(); blk[15]=ctr.toByte()
            cipher.encryptBlock(blk, 0, ks, 0)
            val n = minOf(16, plain.size - off)
            for (i in 0 until n) out[off+i] = (plain[off+i].toInt() xor ks[i].toInt()).toByte()
            off += n; ctr++
        }
        val result = ByteArray(2 + 12 + out.size)
        result[0]=(out.size ushr 8).toByte(); result[1]=out.size.toByte()
        System.arraycopy(nonce, 0, result, 2, 12)
        System.arraycopy(out, 0, result, 14, out.size)
        return result
    }
}
