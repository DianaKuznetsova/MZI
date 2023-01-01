package hash


/**
 * Gost 34.11-94 implementation of hasher
 */
class Gost34_11Hasher {

    private val k87 = UIntArray(256)
    private val k65 = UIntArray(256)
    private val k43 = UIntArray(256)
    private val k21 = UIntArray(256)

    init {
        for (i in 0..255) {
            val j = i ushr 4
            val t = i and 15
            k87[i] = K8[j].toUInt() shl 4 or K7[t].toUInt() shl 24
            k65[i] = K6[j].toUInt() shl 4 or K5[t].toUInt() shl 16
            k43[i] = K4[j].toUInt() shl 4 or K3[t].toUInt() shl 8
            k21[i] = K2[j].toUInt() shl 4 or K1[t].toUInt()
        }
    }

    fun calculateHash(data: UByteArray): UByteArray {
        val context = Context()
        hashBlock(context, data)
        return finishHash(context)
    }

    private fun xor_blocks(result: UByteArray, a: UByteArray, b: UByteArray, bStart: Int, len: Int) {
        for (i in 0 until len) {
            result[i] = a[i] xor b[bStart + i]
        }
    }

    private fun swap_bytes(w: UByteArray, k: UByteArray) {
        for (i in 0 until 4) {
            for (j in 0 until 8) {
                k[i + 4 * j] = w[8 * i + j]
            }
        }
    }

    private fun circle_xor8(w: UByteArray, k: UByteArray) {
        circle_xor8(w, 0, k)
    }

    private fun circle_xor8(w: UByteArray, wStart: Int, k: UByteArray) {
        val buf = UByteArray(8)
        arraycopy(w, wStart, buf, 0, 8)
        arraycopy(w, wStart + 8, k, 0, 24)
        for (i in 0 until 8) {
            k[i + 24] = buf[i] xor k[i]
        }
    }

    private fun transform_3(data: UByteArray) {
        val acc: UInt = (data[0].toUInt() xor data[2].toUInt() xor
                data[4].toUInt() xor data[6].toUInt() xor
                data[24].toUInt() xor data[30].toUInt()) or
                ((data[1].toUInt() xor data[3].toUInt() xor
                        data[5].toUInt() xor data[7].toUInt() xor
                        data[25].toUInt() xor data[31].toUInt()) shl 8)
        val buf = data.copyOf()
        arraycopy(buf, 2, data, 0, 30)
        data[30] = (acc and 0xffu).toUByte()
        data[31] = (acc shr 8).toUByte()
    }

    private fun addBlocks(n: Int, left: UByteArray, right: UByteArray, rightPos: Int): UInt {
        var carry: UInt = 0u
        for (i in 0 until n) {
            val sum = left[i].toUInt() + right[rightPos + i].toUInt() + carry
            left[i] = (sum and 0xffu).toUByte()
            carry = sum shr 8
        }
        return carry
    }

    private fun f(n: UInt, x: UInt): UInt {
        var tmp: ULong = n.toULong() + x.toULong()
        val result: UInt = (k87[(tmp shr 24).toInt() and 255] or
                k65[(tmp shr 16).toInt() and 255] or
                k43[(tmp shr 8).toInt() and 255] or
                k21[tmp.toInt() and 255])
        return (result.toULong() shl 11).toUInt() or (result shr (32 - 11))
    }

    /* Low-level encryption routine - encrypts one 64 bit block*/
    private fun gostCrypt(block: UByteArray, blockPos: Int, output: UByteArray, outputPos: Int, k: UIntArray) {
        var n1: UInt = block[blockPos + 0].toUInt() or
                (block[blockPos + 1].toUInt() shl 8) or
                (block[blockPos + 2].toUInt() shl 16) or
                (block[blockPos + 3].toUInt() shl 24)
        var n2: UInt = block[blockPos + 4].toUInt() or
                (block[blockPos + 5].toUInt() shl 8) or
                (block[blockPos + 6].toUInt() shl 16) or
                (block[blockPos + 7].toUInt() shl 24)

        n2 = n2 xor f(n1, k[0])
        n1 = n1 xor f(n2, k[1])
        n2 = n2 xor f(n1, k[2])
        n1 = n1 xor f(n2, k[3])
        n2 = n2 xor f(n1, k[4])
        n1 = n1 xor f(n2, k[5])
        n2 = n2 xor f(n1, k[6])
        n1 = n1 xor f(n2, k[7])
        n2 = n2 xor f(n1, k[0])
        n1 = n1 xor f(n2, k[1])
        n2 = n2 xor f(n1, k[2])
        n1 = n1 xor f(n2, k[3])
        n2 = n2 xor f(n1, k[4])
        n1 = n1 xor f(n2, k[5])
        n2 = n2 xor f(n1, k[6])
        n1 = n1 xor f(n2, k[7])
        n2 = n2 xor f(n1, k[0])
        n1 = n1 xor f(n2, k[1])
        n2 = n2 xor f(n1, k[2])
        n1 = n1 xor f(n2, k[3])
        n2 = n2 xor f(n1, k[4])
        n1 = n1 xor f(n2, k[5])
        n2 = n2 xor f(n1, k[6])
        n1 = n1 xor f(n2, k[7])
        n2 = n2 xor f(n1, k[7])
        n1 = n1 xor f(n2, k[6])
        n2 = n2 xor f(n1, k[5])
        n1 = n1 xor f(n2, k[4])
        n2 = n2 xor f(n1, k[3])
        n1 = n1 xor f(n2, k[2])
        n2 = n2 xor f(n1, k[1])
        n1 = n1 xor f(n2, k[0])
        output[outputPos + 0] = (n2 and 0xffu).toUByte()
        output[outputPos + 1] = (n2 shr 8 and 0xffu).toUByte()
        output[outputPos + 2] = (n2 shr 16 and 0xffu).toUByte()
        output[outputPos + 3] = (n2 shr 24).toUByte()
        output[outputPos + 4] = (n1 and 0xffu).toUByte()
        output[outputPos + 5] = (n1 shr 8 and 0xffu).toUByte()
        output[outputPos + 6] = (n1 shr 16 and 0xffu).toUByte()
        output[outputPos + 7] = (n1 shr 24).toUByte()
    }

    private fun gostSetKey(xk: UByteArray, k: UIntArray) {
        for (i in 0 until 8) {
            k[i] = xk[i * 4].toUInt() or
                    (xk[i * 4 + 1].toUInt() shl 8) or
                    (xk[i * 4 + 2].toUInt() shl 16) or
                    (xk[i * 4 + 3].toUInt() shl 24)
        }
    }

    private fun gostEncrypt(
        key: UByteArray,
        inBlock: UByteArray,
        inPos: Int,
        outBlock: UByteArray,
        outPos: Int
    ) {
        val k = UIntArray(8)
        gostSetKey(key, k)
        gostCrypt(inBlock, inPos, outBlock, outPos, k)
    }

    /**
     * Hash block of arbitrary length
     */
    private fun hashBlock(context: Context, block: UByteArray, _pos: Int, length: Int) {
        var pos = _pos
        val lastPos = pos + length
        if (context.left > 0) {
            /* There are some bytes from previous step */
            var addBytes: Int = 32 - context.left
            if (addBytes > length) addBytes = length
            arraycopy(block, pos, context.remainder, context.left, addBytes)
            context.left += addBytes
            if (context.left < 32) return
            pos += addBytes
            hashStep(context.H, context.remainder, 0)
            addBlocks(32, context.S, context.remainder, 0)
            context.len += 32u
            context.left = 0
        }
        while (lastPos - pos >= 32) {
            hashStep(context.H, block, pos)
            addBlocks(32, context.S, block, pos)
            context.len += 32u
            pos += 32
        }
        if (pos != length) {
            context.left = lastPos - pos
            arraycopy(block, pos, context.remainder, 0, context.left)
        }
    }

    private fun hashBlock(context: Context, data: UByteArray, len: Int) {
        hashBlock(context, data, 0, len)
    }

    private fun hashBlock(context: Context, data: UByteArray) {
        hashBlock(context, data, 0, data.size)
    }

    private fun finishHash(context: Context): UByteArray {
        val buf = UByteArray(32) { 0u }
        val xH = UByteArray(32)
        val xS = UByteArray(32)
        var fin_len: ULong = context.len
        arraycopy(context.H, 0, xH, 0, 32)
        arraycopy(context.S, 0, xS, 0, 32)
        if (context.left > 0) {
            arraycopy(context.remainder, 0, buf, 0, context.left)
            hashStep(xH, buf, 0)
            addBlocks(32, xS, buf, 0)
            fin_len += context.left.toUInt()
            buf.fill(0u)
        }
        fin_len = fin_len shl 3 /* Hash length in BITS!!*/
        var bptr = 0
        while (fin_len > 0u) {
            buf[bptr++] = (fin_len and 0xFFu).toUByte()
            fin_len = fin_len shr 8
        }
        hashStep(xH, buf, 0)
        hashStep(xH, xS, 0)
        return xH
    }

    private fun hashStep(xH: UByteArray, xM: UByteArray, mStart: Int) {
        val xU = UByteArray(32)
        val xW = UByteArray(32)
        val xV = UByteArray(32)
        val xS = UByteArray(32)
        val key = UByteArray(32)

        xor_blocks(xW, xH, xM, mStart, 32)
        swap_bytes(xW, key)
        gostEncrypt(key, xH, 0, xS, 0)

        circle_xor8(xH, xU)
        circle_xor8(xM, mStart, xV)
        circle_xor8(xV, xV)
        xor_blocks(xW, xU, xV, 0, 32)
        swap_bytes(xW, key)
        gostEncrypt(key, xH, 8, xS, 8)

        circle_xor8(xU, xU)

        xU[31] = xU[31].inv()
        xU[29] = xU[29].inv()
        xU[28] = xU[28].inv()
        xU[24] = xU[24].inv()
        xU[23] = xU[23].inv()
        xU[20] = xU[20].inv()
        xU[18] = xU[18].inv()
        xU[17] = xU[17].inv()
        xU[14] = xU[14].inv()
        xU[12] = xU[12].inv()
        xU[10] = xU[10].inv()
        xU[8] = xU[8].inv()
        xU[7] = xU[7].inv()
        xU[5] = xU[5].inv()
        xU[3] = xU[3].inv()
        xU[1] = xU[1].inv()

        circle_xor8(xV, xV)
        circle_xor8(xV, xV)
        xor_blocks(xW, xU, xV, 0, 32)
        swap_bytes(xW, key)
        gostEncrypt(key, xH, 16, xS, 16)

        circle_xor8(xU, xU)
        circle_xor8(xV, xV)
        circle_xor8(xV, xV)
        xor_blocks(xW, xU, xV, 0, 32)
        swap_bytes(xW, key)
        gostEncrypt(key, xH, 24, xS, 24)

        for (i in 0 until 12) {
            transform_3(xS)
        }
        xor_blocks(xS, xS, xM, mStart, 32)
        transform_3(xS)
        xor_blocks(xS, xS, xH, 0, 32)
        for (i in 0 until 61) {
            transform_3(xS)
        }
        arraycopy(xS, 0, xH, 0, 32)
    }

    private data class Context(
        var len: ULong = 0u,
        var left: Int = 0,
        val H: UByteArray = UByteArray(32) { 0u },
        val S: UByteArray = UByteArray(32) { 0u },
        val remainder: UByteArray = UByteArray(32) { 0u },
    )

    private companion object {
        val K8 =
            ubyteArrayOf(0x1u, 0x3u, 0xAu, 0x9u, 0x5u, 0xBu, 0x4u, 0xFu, 0x8u, 0x6u, 0x7u, 0xEu, 0xDu, 0x0u, 0x2u, 0xCu)
        val K7 =
            ubyteArrayOf(0xDu, 0xEu, 0x4u, 0x1u, 0x7u, 0x0u, 0x5u, 0xAu, 0x3u, 0xCu, 0x8u, 0xFu, 0x6u, 0x2u, 0x9u, 0xBu)
        val K6 =
            ubyteArrayOf(0x7u, 0x6u, 0x2u, 0x4u, 0xDu, 0x9u, 0xFu, 0x0u, 0xAu, 0x1u, 0x5u, 0xBu, 0x8u, 0xEu, 0xCu, 0x3u)
        val K5 =
            ubyteArrayOf(0x7u, 0x6u, 0x4u, 0xBu, 0x9u, 0xCu, 0x2u, 0xAu, 0x1u, 0x8u, 0x0u, 0xEu, 0xFu, 0xDu, 0x3u, 0x5u)
        val K4 =
            ubyteArrayOf(0x4u, 0xAu, 0x7u, 0xCu, 0x0u, 0xFu, 0x2u, 0x8u, 0xEu, 0x1u, 0x6u, 0x5u, 0xDu, 0xBu, 0x9u, 0x3u)
        val K3 =
            ubyteArrayOf(0x7u, 0xFu, 0xCu, 0xEu, 0x9u, 0x4u, 0x1u, 0x0u, 0x3u, 0xBu, 0x5u, 0x2u, 0x6u, 0xAu, 0x8u, 0xDu)
        val K2 =
            ubyteArrayOf(0x5u, 0xFu, 0x4u, 0x0u, 0x2u, 0xDu, 0xBu, 0x9u, 0x1u, 0x7u, 0x6u, 0x3u, 0xCu, 0xEu, 0xAu, 0x8u)
        val K1 =
            ubyteArrayOf(0xAu, 0x4u, 0x5u, 0x6u, 0x8u, 0x1u, 0x3u, 0x7u, 0xDu, 0xCu, 0xEu, 0x0u, 0x9u, 0x2u, 0xBu, 0xFu)

        fun arraycopy(
            src: UByteArray, srcPos: Int,
            dest: UByteArray, destPos: Int,
            length: Int
        ) {
            src.copyInto(
                destination = dest,
                destinationOffset = destPos,
                startIndex = srcPos,
                endIndex = srcPos + length
            )
        }
    }

}