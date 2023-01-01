package encryptor.impl

import encryptor.Encryptor
import java.math.BigInteger

/**
 * RSA encryptor implementation based on [Wikipedia](https://simple.wikipedia.org/wiki/RSA_algorithm)
 */
internal class RsaEncryptor(
    private val n: BigInteger,
    private val e: BigInteger,
    private val d: BigInteger,
) : Encryptor {

    private val encryptedPartLen = (n.bitLength() + 7) / 8
    private val unencryptedPartLen = encryptedPartLen - 1

    init {
        require(unencryptedPartLen > 0) { "n is too small and should be > 255" }
    }

    override fun encrypt(data: UByteArray): UByteArray {
        return data.chunked(unencryptedPartLen)
            .map { message ->
                val m = BigInteger(1, message.toUByteArray().toByteArray())
                val c = m.modPow(e, n)
                padToSize(c.toByteArray().toUByteArray(), encryptedPartLen)
            }.flatten()
            .toUByteArray()
    }

    override fun decrypt(data: UByteArray): UByteArray {
        return data.chunked(encryptedPartLen)
            .map { message ->
                val c = BigInteger(1, message.toUByteArray().toByteArray())
                val m = c.modPow(d, n)
                padToSize(m.toByteArray().toUByteArray(), unencryptedPartLen)
            }.flatten()
            .toUByteArray()
    }

    private fun padToSize(bytes: UByteArray, size: Int): UByteArray {
        return if (bytes.size == size) {
            return bytes
        } else {
            UByteArray(size - bytes.size) { 0u } + bytes
        }
    }

    override fun toString(): String {
        return "RSA encryptor"
    }
}