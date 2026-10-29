package com.keyvault.vpn

class Serpent256(key: ByteArray) {
    private val k = IntArray(132)
    companion object {
        private val SB = arrayOf(
            intArrayOf(3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12),
            intArrayOf(15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4),
            intArrayOf(8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2),
            intArrayOf(0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14),
            intArrayOf(1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13),
            intArrayOf(15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1),
            intArrayOf(7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0),
            intArrayOf(1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6)
        )
        private val ANF = Array(8) { s ->
            Array(4) { bit ->
                val c = IntArray(16) { m -> (SB[s][m] shr bit) and 1 }
                for (i in 0 until 4) for (m in 0 until 16) if ((m and (1 shl i)) != 0) c[m] = c[m] xor c[m xor (1 shl i)]
                val list = ArrayList<Int>()
                for (m in 0 until 16) if (c[m] != 0) list.add(m)
                list.toIntArray()
            }
        }
        private fun rotl(x: Int, n: Int) = (x shl n) or (x ushr (32 - n))
    }
    private fun sbox(s: Int, a: Int, b: Int, c: Int, d: Int): IntArray {
        val m = IntArray(16)
        m[0]=-1; m[1]=a; m[2]=b; m[4]=c; m[8]=d
        m[3]=a and b; m[5]=a and c; m[6]=b and c; m[9]=a and d; m[10]=b and d; m[12]=c and d
        m[7]=m[3] and c; m[11]=m[3] and d; m[13]=m[5] and d; m[14]=m[6] and d; m[15]=m[7] and d
        val out = IntArray(4)
        for (bit in 0 until 4) { var v = 0; for (idx in ANF[s][bit]) v = v xor m[idx]; out[bit] = v }
        return out
    }
    init {
        require(key.size == 32)
        val w = IntArray(140)
        for (i in 0 until 8) w[i] = (key[4*i].toInt() and 0xFF) or ((key[4*i+1].toInt() and 0xFF) shl 8) or ((key[4*i+2].toInt() and 0xFF) shl 16) or ((key[4*i+3].toInt() and 0xFF) shl 24)
        for (j in 8 until 140) w[j] = rotl(w[j-8] xor w[j-5] xor w[j-3] xor w[j-1] xor (-0x61c88647) xor (j-8), 11)
        for (r in 0 until 33) { val si = (((3-r)%8)+8)%8; val o = sbox(si, w[8+4*r], w[9+4*r], w[10+4*r], w[11+4*r]); for (t in 0 until 4) k[4*r+t] = o[t] }
    }
    fun encryptBlock(src: ByteArray, so: Int, dst: ByteArray, do_: Int) {
        fun rd(o: Int) = (src[so+o].toInt() and 0xFF) or ((src[so+o+1].toInt() and 0xFF) shl 8) or ((src[so+o+2].toInt() and 0xFF) shl 16) or ((src[so+o+3].toInt() and 0xFF) shl 24)
        var a=rd(0); var b=rd(4); var c=rd(8); var d=rd(12)
        for (r in 0 until 32) {
            val o = sbox(r and 7, a xor k[4*r], b xor k[4*r+1], c xor k[4*r+2], d xor k[4*r+3])
            a=o[0]; b=o[1]; c=o[2]; d=o[3]
            if (r < 31) { a=rotl(a,13); c=rotl(c,3); b=b xor a xor c; d=d xor c xor (a shl 3); b=rotl(b,1); d=rotl(d,7); a=a xor b xor d; c=c xor d xor (b shl 7); a=rotl(a,5); c=rotl(c,22) }
            else { a=a xor k[128]; b=b xor k[129]; c=c xor k[130]; d=d xor k[131] }
        }
        val v = intArrayOf(a,b,c,d)
        for (i in 0 until 4) { dst[do_+4*i]=(v[i] and 0xFF).toByte(); dst[do_+4*i+1]=((v[i] ushr 8) and 0xFF).toByte(); dst[do_+4*i+2]=((v[i] ushr 16) and 0xFF).toByte(); dst[do_+4*i+3]=((v[i] ushr 24) and 0xFF).toByte() }
    }
}
