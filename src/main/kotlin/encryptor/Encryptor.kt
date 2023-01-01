package encryptor

interface Encryptor {
    fun encrypt(data: UByteArray): UByteArray
    fun decrypt(data: UByteArray): UByteArray
}