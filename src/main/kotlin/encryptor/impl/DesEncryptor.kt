package encryptor.impl

import bitset.*
import encryptor.Encryptor

/**
 * Implementation of the DES encryption based on the info from [Wikipedia](https://ru.wikipedia.org/wiki/DES).
 * @param key must be 7 bytes long
 */
internal class DesEncryptor(
    key: UByteArray,
) : Encryptor {

    private val keys: Array<BitSet>

    init {
        require(key.size == 7) {
            "Key must be 7 bytes but was ${key.size}"
        }
        keys = Array(16) {
            BitSet(48)
        }
        val keyBits = key.toBitSet()
        val C0D0 = BitSet(56) { index ->
            val extendedKeyIndex = KP[index]
            val keyIndex = (extendedKeyIndex / 8) * 7 + extendedKeyIndex.rem(8)
            keyBits[keyIndex]
        }

        fun getCiDi(Ci_1Di_1: BitSet, i: Int): BitSet {
            val Ci_1 = Ci_1Di_1.take(0, 27)
            val Di_1 = Ci_1Di_1.take(28, 55)
            val shiftCount = SHT[i].toInt()
            Ci_1.shlCycled(shiftCount)
            Di_1.shlCycled(shiftCount)
            return Ci_1.extendWith(Di_1)
        }

        var Ci_1Di_1 = C0D0
        for (i in keys.indices) {
            Ci_1Di_1 = getCiDi(Ci_1Di_1, i)
            keys[i].apply {
                for (j in 0 until size) {
                    set(j, Ci_1Di_1[KT[j].toInt()])
                }
            }
        }
    }

    override fun encrypt(data: UByteArray): UByteArray {
        return data.toList()
            .chunked(8)
            .let { blocks ->
                blocks + listOf(extensionBlock(8 - (blocks.lastOrNull()?.size ?: 8)))
            }
            .map { bytes ->
                val block = bytes.toUByteArray().toBitSet()
                if (block.size < 64) {
                    println("Extending block to 64 bits (original size - ${block.size})")
                    block.set(63, false)
                }
                encryptBlock(block).toUByteArray().toList()
            }.flatten()
            .toUByteArray()
    }

    private fun encryptBlock(block: BitSet): BitSet {
        var transformedBlock = BitSet(block.size) { index ->
            block[IP[index] - 1]
        }
        for (i in 0 until 16) {
            transformedBlock = encryptionFunction(transformedBlock, keys[i])
        }
        return BitSet(transformedBlock.size) { index ->
            transformedBlock[IPLast[index] - 1]
        }
    }

    private fun encryptionFunction(block: BitSet, key: BitSet): BitSet {
        val L = block.take(0, 31)
        val R = block.take(32, 63)
        L.xor(feiselFunction(R, key))
        return R.extendWith(L)
    }

    private fun feiselFunction(block: BitSet, key: BitSet): BitSet {
        val extendedBlock = BitSet(48) { index ->
            block[E[index] - 1]
        }
        extendedBlock.xor(key)
        val transformedBlock = BitSet(32)
        for (bIndex in 0 until 8) {
            val a = 2 * extendedBlock.getInt(bIndex * 6) + extendedBlock.getInt(bIndex * 6 + 5)
            val b = 8 * extendedBlock.getInt(bIndex * 6 + 1) + 4 * extendedBlock.getInt(bIndex * 6 + 2) +
                    2 * extendedBlock.getInt(bIndex * 6 + 3) + extendedBlock.getInt(bIndex * 6 + 4)
            val s = S[bIndex][a * 16 + b]
            for (i in 0 until 4) {
                transformedBlock.set(bIndex * 4 + i, s.toInt() and (1 shl (3 - i)) != 0)
            }
        }
        return BitSet(transformedBlock.size) { index ->
            transformedBlock[P[index] - 1]
        }
    }

    override fun decrypt(data: UByteArray): UByteArray {
        return data.toList()
            .chunked(8)
            .map { bytes ->
                val block = bytes.toUByteArray().toBitSet()
                if (block.size < 64) {
                    println("Extending block to 64 bits (original size - ${block.size}")
                    block.set(63, false)
                }
                decryptBlock(block).toUByteArray().toList()
            }.flatten()
            .let { bytes ->
                bytes.dropLast(8 + bytes.last().toInt())
            }
            .toUByteArray()
    }

    private fun decryptBlock(block: BitSet): BitSet {
        var transformedBlock = BitSet(block.size) { index ->
            block[IP[index] - 1]
        }
        for (i in 15 downTo 0) {
            transformedBlock = decryptionFunction(transformedBlock, keys[i])
        }
        return BitSet(transformedBlock.size) { index ->
            transformedBlock[IPLast[index] - 1]
        }
    }

    private fun decryptionFunction(block: BitSet, key: BitSet): BitSet {
        val L = block.take(0, 31)
        val R = block.take(32, 63)
        R.xor(feiselFunction(L, key))
        return R.extendWith(L)
    }

    override fun toString(): String {
        return "DES encryptor"
    }

    private companion object {
        /**
         * Initial permutation table.
         * Each number represents an index of the bit from the block.
         * Indexes start from 1.
         */
        val IP: ByteArray = byteArrayOf(
            58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
        )

        /**
         * Extension table. Extends 32 bit block into 48 bit block.
         * Each number represents an index of the bit from the block.
         * Indexes start from 1.
         */
        val E: ByteArray = byteArrayOf(
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1,
        )

        /**
         * Feisel transformation table.
         * Each number represents a result 4 bit value.
         * Indexes start from 1.
         */
        val S1: ByteArray = byteArrayOf(
            14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
            0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
            4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
            15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13,
        )

        /**
         * Feisel transformation table.
         * Each number represents a result 4 bit value.
         * Indexes start from 1.
         */
        val S2: ByteArray = byteArrayOf(
            15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
            3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
            0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
            13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9,
        )

        /**
         * Feisel transformation table.
         * Each number represents a result 4 bit value.
         * Indexes start from 1.
         */
        val S3: ByteArray = byteArrayOf(
            10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
            13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
            13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
            1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12,
        )

        /**
         * Feisel transformation table.
         * Each number represents a result 4 bit value.
         * Indexes start from 1.
         */
        val S4: ByteArray = byteArrayOf(
            7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
            13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
            10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
            3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14,
        )

        /**
         * Feisel transformation table.
         * Each number represents a result 4 bit value.
         * Indexes start from 1.
         */
        val S5: ByteArray = byteArrayOf(
            2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
            14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
            4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
            11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3,
        )

        /**
         * Feisel transformation table.
         * Each number represents a result 4 bit value.
         * Indexes start from 1.
         */
        val S6: ByteArray = byteArrayOf(
            12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
            10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
            9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
            4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13,
        )

        /**
         * Feisel transformation table.
         * Each number represents a result 4 bit value.
         * Indexes start from 1.
         */
        val S7: ByteArray = byteArrayOf(
            4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
            13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
            1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
            6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12,
        )

        /**
         * Feisel transformation table.
         * Each number represents a result 4 bit value.
         * Indexes start from 1.
         */
        val S8: ByteArray = byteArrayOf(
            13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
            1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
            7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
            2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11,
        )

        /**
         * Feisel transformation tables.
         */
        val S: Array<ByteArray> = arrayOf(
            S1, S2, S3, S4, S5, S6, S7, S8,
        )

        /**
         * Feisel permutation table.
         * Each number represents an index of the bit from the block.
         * Indexes start from 1.
         */
        val P: ByteArray = byteArrayOf(
            16, 7, 20, 21, 29, 12, 28, 17,
            1, 15, 23, 26, 5, 18, 31, 10,
            2, 8, 24, 14, 32, 27, 3, 9,
            19, 13, 30, 6, 22, 11, 4, 25,
        )

        /**
         * Key permutation table.
         * Each number represents an index of the bit.
         * Indexes start from 1.
         */
        val KP: ByteArray = byteArrayOf(
            57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
        )

        /**
         * Key shift table.
         * Each number represents cycled left shift number.
         */
        val SHT: ByteArray = byteArrayOf(
            1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1,
        )

        /**
         * Key bits choose table.
         * Each number represents an index of the bit.
         * Indexes start from 1.
         */
        val KT: ByteArray = byteArrayOf(
            14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4,
            26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40,
            51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
        )

        /**
         * Last permutation table.
         * Each number represents an index of the bit from the block.
         * Indexes start from 1.
         */
        val IPLast: ByteArray = byteArrayOf(
            40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
        )

        private fun extensionBlock(numberOfExtendedBytes: Int): List<UByte> {
            return List(8) { index ->
                if (index == 7) {
                    numberOfExtendedBytes.toUByte()
                } else {
                    0u
                }
            }
        }
    }
}