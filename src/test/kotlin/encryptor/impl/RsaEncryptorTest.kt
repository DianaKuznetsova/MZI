package encryptor.impl

import encryptor.Encryptor
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.math.BigInteger

internal class RsaEncryptorTest {

    private val encryptor: Encryptor

    init {
        encryptor = RsaEncryptor(n = N, e = E, d = D)
    }

    @Test
    fun `Encrypted message is different from original`() {
        val encryptedMessage = encryptor.encrypt(MESSAGE.toByteArray().toUByteArray())
        val cypherText = String(encryptedMessage.toByteArray())

        assertNotEquals(MESSAGE, cypherText, "Encrypted message must differ from original")
    }

    @Test
    fun `Message decrypted successfully`() {
        val encryptedMessage = encryptor.encrypt(MESSAGE.toByteArray().toUByteArray())
        val decryptedBytes = encryptor.decrypt(encryptedMessage)
        val decryptedText = String(decryptedBytes.toByteArray())

        assertEquals(MESSAGE, decryptedText, "Decrypted message must be equal to the original")
    }

    private companion object {
        private val MESSAGE = "Very secret message"
        private val N = BigInteger.valueOf(3233)
        private val E = BigInteger.valueOf(17)
        private val D = BigInteger.valueOf(2753)
    }
}