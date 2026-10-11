package com.gallifrey.authenticator.haptics

/** One element of a haptic pattern: a short (DOT) or long (DASH) vibration. */
enum class PatternElement { DOT, DASH }

/**
 * A temporary DOT/DASH pattern shown to the user for one transaction.
 *
 * Four binary elements give only 2^4 = 16 patterns, so this is an interaction
 * mechanism, not a cryptographic secret. It is still kept off the network and
 * out of logs (M2-R11): toString() reports the length only, never the elements.
 */
class HapticPattern(elements: List<PatternElement>) {
    val elements: List<PatternElement> = elements.toList()

    val size: Int get() = elements.size

    init {
        require(elements.isNotEmpty()) { "A pattern needs at least one element" }
    }

    override fun equals(other: Any?): Boolean =
        other is HapticPattern && other.elements == elements

    override fun hashCode(): Int = elements.hashCode()

    override fun toString(): String = "HapticPattern(size=$size)"

    companion object {
        /** Pattern length from the design (D03 / M2-R01). */
        const val DEFAULT_LENGTH = 4
    }
}
