import encryptor.Encryptor
import encryptor.impl.DesEncryptor
import encryptor.impl.Gost28147_89Encryptor
import encryptor.impl.RsaEncryptor
import hash.Gost34_11Hasher
import signature.Gost3410_94_Signer
import java.math.BigInteger

fun main() {
    val clearText = TEXT_TO_ENCRYPT

    val desEncryptor = DesEncryptor(DES_KEY)
    verifyEncryption(clearText, desEncryptor)

    val gostEncryptor = Gost28147_89Encryptor(GOST_KEY)
    verifyEncryption(clearText, gostEncryptor)

    val rsaEncryptor = RsaEncryptor(n = RSA_N, e = RSA_E, d = RSA_D)
    verifyEncryption(clearText, rsaEncryptor)

    println("Text to calculate hash from - $clearText")
    println(
        Gost34_11Hasher().calculateHash(clearText.toByteArray().toUByteArray())
            .joinToString(separator = " ") { it.toString(16).uppercase() })
    println()

    println("Text to calculate signature from - $clearText")
    val signer = Gost3410_94_Signer(
        privateKey = BigInteger.valueOf(3),
        publicKey = BigInteger.valueOf(9),
        p = BigInteger.valueOf(11),
        q = BigInteger.valueOf(5),
        a = BigInteger.valueOf(4),
    )
    val (r, s) = signer.calculateSignature(clearText.toByteArray().toUByteArray())
    println("Signature for the message r - $r, s - $s")
    require(signer.verifySignature(clearText.toByteArray().toUByteArray(), r, s)) { "Signature verification failed" }
    println("Signature verified success")
}

private fun verifyEncryption(clearText: String, encryptor: Encryptor) {
    println("Verifying $encryptor")
    println("Clear text - $clearText")
    val encryptedBytes = encryptor.encrypt(clearText.toByteArray().toUByteArray())
    val cypherText = String(encryptedBytes.toByteArray())
    println("Cypher text - $cypherText")
    val decryptedBytes = encryptor.decrypt(encryptedBytes)
    val decryptedText = String(decryptedBytes.toByteArray())
    println("Decrypted text - $decryptedText")

    require(clearText == decryptedText) { "Result of encryption and backward decryption doesn't match for encryptor - $encryptor" }

    println("$encryptor verified success!")
    println()
}

private const val TEXT_TO_ENCRYPT = "message"
private val DES_KEY = ubyteArrayOf(255u, 0u, 128u, 0u, 1u, 129u, 233u)
private val GOST_KEY = ubyteArrayOf(
    255u, 0u, 128u, 0u, 1u, 129u, 233u, 17u, 23u, 14u, 222u, 43u, 255u, 11u, 1u, 0u, 72u,
    44u, 128u, 127u, 215u, 156u, 162u, 41u, 199u, 225u, 145u, 1u, 23u, 69u, 249u, 114u,
)
private val RSA_N = BigInteger.valueOf(3233)
private val RSA_E = BigInteger.valueOf(17)
private val RSA_D = BigInteger.valueOf(2753)