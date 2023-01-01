package bitset

/**
 * Converts array of bytes to [BitSet]
 */
fun UByteArray.toBitSet(): BitSet {
    return BitSet(size * 8) { bitIndex ->
        val byteIndex = bitIndex / 8
        val byte = this@toBitSet[byteIndex]
        val bitInByte = 7 - bitIndex + byteIndex * 8
        return@BitSet byte.toInt() and (1 shl bitInByte) != 0
    }
}

/**
 * Returns a new [BitSet] containing bits from [this] starting from
 * [startIndex] and ending with [endIndex] (including).
 */
fun BitSet.take(startIndex: Int, endIndex: Int): BitSet {
    return BitSet(endIndex - startIndex + 1) { index ->
        get(startIndex + index)
    }
}

/**
 * Returns a new [BitSet] with [other] added at the end
 */
fun BitSet.extendWith(other: BitSet): BitSet {
    return BitSet(this.size + other.size) { index ->
        if (index < this.size) {
            get(index)
        } else {
            other[index - this.size]
        }
    }
}

/**
 * Shifts left by [n] bits
 */
infix fun BitSet.shl(n: Int) {
    for (i in 0 until size - n) {
        set(i, get(i + n))
    }
    for (i in size - n until size) {
        set(i, false)
    }
}

/**
 * Shifts right by [n] bits
 */
infix fun BitSet.shr(n: Int) {
    for (i in size downTo n) {
        set(i, get(i - n))
    }
    for (i in 0 until n) {
        set(i, false)
    }
}

/**
 * Cycled shift left by [n] bits
 */
infix fun BitSet.shlCycled(n: Int) {
    val cycledBits = BooleanArray(n) { index ->
        get(index)
    }
    shl(n)
    for (i in 0 until n) {
        set(size - n + i - 1, cycledBits[i])
    }
}

/**
 * Cycled shift right by [n] bits
 */
infix fun BitSet.shrCycled(n: Int) {
    val cycledBits = BooleanArray(n) { index ->
        get(size - n + index - 1)
    }
    shr(n)
    for (i in 0 until n) {
        set(n - i - 1, cycledBits[i])
    }
}

fun BitSet.toUByteArray(): UByteArray {
    val bytes = UByteArray((size + 7) / 8) { 0u }
    for (i in 0 until size) {
        val byteIndex = i / 8
        val bit = if (get(i)) 1u else 0u
        bytes[byteIndex] = (bytes[byteIndex] + (bit shl (7 - i + byteIndex * 8))).toUByte()
    }
    return bytes
}

fun BitSet.getInt(index: Int): Int {
    return if (get(index)) {
        1
    } else {
        0
    }
}

/**
 * Performs logical sum by specified [mod]
 * The size of the [BitSet]s should have size dividable by [mod] and have the same size.
 *
 * @return result of the operation
 */
fun BitSet.sumByMod(mod: Int, other: BitSet): BitSet {
    require(size == other.size) { "Trying to sum bit sets with different sizes. This size - $size, other size - ${other.size}" }
    require(size % mod == 0) { "Bit set must have the size that can be divided by $mod. Actual size - $mod" }
    val result = BitSet(size) { false }
    for (i in size - 1 downTo 0) {
        val setBitsCount = this.getInt(i) + other.getInt(i) + result.getInt(i)
        result.set(i, setBitsCount % 2 == 1)
        if (setBitsCount > 1 && i > 0 && i % mod != 0) {
            result.set(i - 1, true)
        }
    }
    return result
}