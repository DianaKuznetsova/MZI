package signature

import hash.Gost34_11Hasher
import java.math.BigInteger
import java.security.SecureRandom
import java.util.*


/**
 * GOST 34.10-94 implementation of signer
 */
class Gost3410_94_Signer(
    private val privateKey: BigInteger,
    private val publicKey: BigInteger,
    private val p: BigInteger,
    private val q: BigInteger,
    private val a: BigInteger,
    private val random: Random = SecureRandom(),
) {

    /**
     * Calculates signature for the "clear text" message [message]
     *
     * @return pair BigIntegers representing signature R and S
     */
    fun calculateSignature(message: UByteArray): Pair<BigInteger, BigInteger> {
        val messageHash = Gost34_11Hasher().calculateHash(message)
        val mRev: UByteArray = messageHash.reversedArray() // conversion is little-endian
        val m = BigInteger(1, mRev.toByteArray())
        var k: BigInteger

        var r: BigInteger
        var s: BigInteger

        do {
            do {
                k = createRandomBigInteger(q.bitLength(), random)
            } while (k <= BigInteger.ZERO || k >= q)
            r = a.modPow(k, p).mod(q)
            s = k.multiply(m).add(privateKey.multiply(r)).mod(q)
        } while (r == BigInteger.ZERO || s == BigInteger.ZERO)

        return r to s
    }

    /**
     * Calculates verifies signature for the "clear text" message [message]
     * Signature represented by [r] and [s]
     *
     * @return true if signature is correct
     */
    fun verifySignature(
        message: UByteArray,
        r: BigInteger,
        s: BigInteger,
    ): Boolean {
        val messageHash = Gost34_11Hasher().calculateHash(message)
        val mRev: UByteArray = messageHash.reversedArray() // conversion is little-endian
        val m = BigInteger(1, mRev.toByteArray())
        val zero = BigInteger.valueOf(0)
        if (zero >= r || q <= r) {
            return false
        }
        if (zero >= s || q <= s) {
            return false
        }
        val v = m.modPow(q.subtract(BigInteger("2")), q)
        var z1 = s.multiply(v).mod(q)
        var z2: BigInteger = q.subtract(r).multiply(v).mod(q)
        z1 = a.modPow(z1, p)
        z2 = publicKey.modPow(z2, p)
        val u = z1.multiply(z2).mod(p).mod(q)
        return u == r
    }

    private fun createRandomBigInteger(bitLength: Int, random: Random): BigInteger {
        return BigInteger(1, createRandom(bitLength, random))
    }

    @Throws(IllegalArgumentException::class)
    private fun createRandom(bitLength: Int, random: Random): ByteArray {
        require(bitLength >= 1) { "bitLength must be at least 1" }
        val nBytes = (bitLength + 7) / 8
        val rv = ByteArray(nBytes)
        random.nextBytes(rv)

        // strip off any excess bits in the MSB
        val xBits = 8 * nBytes - bitLength
        rv[0] = (rv[0].toInt() and (255 ushr xBits)).toByte()
        return rv
    }
}