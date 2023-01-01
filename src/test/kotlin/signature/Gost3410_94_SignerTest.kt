package signature

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.math.BigInteger

internal class Gost3410_94_SignerTest {
    private val signer = Gost3410_94_Signer(
        privateKey = PRIVATE_KEY,
        publicKey = PUBLIC_KEY,
        p = P,
        q = Q,
        a = A,
    )

    @Test
    fun `Verify signature calculated successfully`() {
        val (r, s) = signer.calculateSignature(MESSAGE.toByteArray().toUByteArray())

        assertNotNull(r, "R must not be null")
        assertNotNull(s, "S must not be null")
    }

    @Test
    fun `Signature verified successfully`() {
        val message = MESSAGE.toByteArray().toUByteArray()
        val (r, s) = signer.calculateSignature(message)

        assertTrue(signer.verifySignature(message, r, s), "Signature must be verified successfully")
    }

    @Test
    fun `Signature verified unsuccessfully`() {
        val message = MESSAGE.toByteArray().toUByteArray()
        val (r, s) = signer.calculateSignature(message)

        assertFalse(signer.verifySignature(message, r.add(BigInteger.ONE), s), "Signature must be verified unsuccessfully")
    }

    private companion object {
        val PRIVATE_KEY = BigInteger.valueOf(3)
        val PUBLIC_KEY = BigInteger.valueOf(9)
        val P = BigInteger.valueOf(11)
        val Q = BigInteger.valueOf(5)
        val A = BigInteger.valueOf(4)

        val MESSAGE = "Some very very long secret message!"
    }
}