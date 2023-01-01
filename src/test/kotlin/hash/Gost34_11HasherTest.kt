package hash

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class Gost34_11HasherTest {

    private val hasher = Gost34_11Hasher()

    @Test
    fun `Verify hash calculated success`() {
        val hash = hasher.calculateHash(MESSAGE.toByteArray().toUByteArray())

        assertTrue(hash.isNotEmpty(), "Hash must not be empty")
    }

    @Test
    fun `Verify hash differs`() {
        val hash1 = hasher.calculateHash(MESSAGE.toByteArray().toUByteArray())
        val hash2 = hasher.calculateHash(MESSAGE2.toByteArray().toUByteArray())

        assertNotEquals(hash1, hash2, "Hashes of different messages must be different")
    }

    private companion object {
        val MESSAGE = "Some message"
        val MESSAGE2 = "Some messagf"
    }
}