package encryptor.impl

import encryptor.Encryptor
import java.nio.ByteBuffer

/**
 * Implementation of GOST 28147-89 encryptor based on the [Wikipedia](https://ru.wikipedia.org/wiki/%D0%93%D0%9E%D0%A1%D0%A2_28147-89)
 * @param key must be 32 bytes long
 */
internal class Gost28147_89Encryptor(
    key: UByteArray,
) : Encryptor {

    private val keys: UIntArray

    init {
        require(key.size == 32) {
            "Key size must be 32 bytes but was ${key.size}"
        }
        keys = UIntArray(8) { i ->
            val startIndex = i * 4
            key.sliceArray(startIndex..startIndex + 3).toUInt()
        }
    }

    override fun encrypt(data: UByteArray): UByteArray {
        return data.toList()
            .chunked(8)
            .let { blocks ->
                blocks + listOf(extensionBlock(8 - (blocks.lastOrNull()?.size ?: 8)))
            }
            .map { bytes ->
                val block = bytes.toUByteArray().copyOf(8)
                processBlock(block, this::getEncryptionKey).toList()
            }.flatten()
            .toUByteArray()
    }

    private fun processBlock(block: UByteArray, keyProvider: (roundIndex: Int) -> UInt): UByteArray {
        var A = block.sliceArray(0..3).toUInt()
        var B = block.sliceArray(4..7).toUInt()
        for (i in 0 until 32) {
            val key = keyProvider(i)
            val feiselResult = feiselFunction(A, key)
            val roundResult = B xor feiselResult
            if (i < 31) {
                B = A
                A = roundResult
            } else {
                B = roundResult
            }
        }
        val result = UByteArray(8)
        A.toUBytes().copyInto(result, destinationOffset = 0)
        B.toUBytes().copyInto(result, destinationOffset = 4)
        return result
    }

    private fun feiselFunction(block: UInt, key: UInt): UInt {
        val value = (block + key) % UInt.MAX_VALUE
        var result: UInt = 0u
        for (i in 0 until 8) {
            val sIndex = (value shr (4 * i)) and 0x0Fu
            val sValue = S[i][sIndex.toInt()]
            result = result or (sValue.toUInt() shl (4 * i))
        }
        return result
    }

    override fun decrypt(data: UByteArray): UByteArray {
        return data.toList()
            .chunked(8)
            .map { bytes ->
                val block = bytes.toUByteArray().copyOf(8)
                processBlock(block, this::getDecryptionKey).toList()
            }.flatten()
            .let { bytes ->
                bytes.dropLast(8 + bytes.last().toInt())
            }
            .toUByteArray()
    }

    private fun getEncryptionKey(index: Int): UInt {
        return if (index < 24) {
            keys[index % 8]
        } else {
            keys[7 - index % 8]
        }
    }

    private fun getDecryptionKey(index: Int): UInt {
        return if (index < 8) {
            keys[index % 8]
        } else {
            keys[7 - index % 8]
        }
    }

    override fun toString(): String {
        return "GOST 28147-89 encryptor"
    }

    private fun UByteArray.toUInt(): UInt {
        return ByteBuffer.wrap(this.toByteArray()).getInt(0).toUInt()
    }

    private fun UInt.toUBytes(): UByteArray {
        return ByteBuffer.allocate(4).putInt(this.toInt()).array().toUByteArray()
    }

    private companion object {

        val S1: ByteArray = byteArrayOf(0x9, 0x6, 0x3, 0x2, 0x8, 0xB, 0x1, 0x7, 0xA, 0x4, 0xE, 0xF, 0xC, 0x0, 0xD, 0x5)
        val S2: ByteArray = byteArrayOf(0x3, 0x7, 0xE, 0x9, 0x8, 0xA, 0xF, 0x0, 0x5, 0x2, 0x6, 0xC, 0xB, 0x4, 0xD, 0x1)
        val S3: ByteArray = byteArrayOf(0xE, 0x4, 0x6, 0x2, 0xB, 0x3, 0xD, 0x8, 0xC, 0xF, 0x5, 0xA, 0x0, 0x7, 0x1, 0x9)
        val S4: ByteArray = byteArrayOf(0xE, 0x7, 0xA, 0xC, 0xD, 0x1, 0x3, 0x9, 0x0, 0x2, 0xB, 0x4, 0xF, 0x8, 0x5, 0x6)
        val S5: ByteArray = byteArrayOf(0xB, 0x5, 0x1, 0x9, 0x8, 0xD, 0xF, 0x0, 0xE, 0x4, 0x2, 0x3, 0xC, 0x7, 0xA, 0x6)
        val S6: ByteArray = byteArrayOf(0x3, 0xA, 0xD, 0xC, 0x1, 0x2, 0x0, 0xB, 0x7, 0x5, 0x9, 0x4, 0x8, 0xF, 0xE, 0x6)
        val S7: ByteArray = byteArrayOf(0x1, 0xD, 0x2, 0x9, 0x7, 0xA, 0x6, 0x0, 0x8, 0xC, 0x4, 0x5, 0xF, 0x3, 0xB, 0xE)
        val S8: ByteArray = byteArrayOf(0xB, 0xA, 0xF, 0x5, 0x0, 0xC, 0xE, 0x8, 0x6, 0x2, 0x3, 0x9, 0x1, 0x7, 0xD, 0x4)

        /**
         * S-blocks (id-Gost28147-89-CryptoPro-A-ParamSet)
         */
        val S: Array<ByteArray> = arrayOf(S1, S2, S3, S4, S5, S6, S7, S8)

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