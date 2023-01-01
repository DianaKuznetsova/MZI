package encryptor.impl

import encryptor.Encryptor
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class Gost28147_89EncryptorTest {

    private val encryptor: Encryptor

    init {
        encryptor = Gost28147_89Encryptor(KEY)
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
        private val KEY = ubyteArrayOf(
            255u, 0u, 128u, 0u, 1u, 129u, 233u, 17u, 23u, 14u, 222u, 43u, 255u, 11u, 1u, 0u, 72u,
            44u, 128u, 127u, 215u, 156u, 162u, 41u, 199u, 225u, 145u, 1u, 23u, 69u, 249u, 114u,
        )
    }
}