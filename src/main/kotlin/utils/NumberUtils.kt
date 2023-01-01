package utils

/**
 * Returns value of the [n] bit of the [this] using little-endian notation
 */
fun Byte.getBit(n: Int): Boolean {
    require(n < 8) { "Byte has only 8 bits but n was $n" }
    return this.toInt().getBit(n)
}

/**
 * Returns value of the [n] bit of the [this] using little-endian notation
 */
fun Int.getBit(n: Int): Boolean {
    require(n < 32) { "Int has only 32 bits but n was $n" }
    return this and (1 shl n) != 0
}