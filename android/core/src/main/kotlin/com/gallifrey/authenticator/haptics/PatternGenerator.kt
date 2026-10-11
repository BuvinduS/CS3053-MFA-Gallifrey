package com.gallifrey.authenticator.haptics

import java.security.SecureRandom

/**
 * Generates a fresh pattern per transaction using a CSPRNG (design section 9).
 *
 * The random source is injectable so tests can make it deterministic; the
 * default is always SecureRandom, never kotlin.random or java.util.Random.
 */
class PatternGenerator(private val random: SecureRandom = SecureRandom()) {

    fun generate(length: Int = HapticPattern.DEFAULT_LENGTH): HapticPattern {
        require(length > 0) { "Pattern length must be positive" }
        val elements = List(length) {
            if (random.nextBoolean()) PatternElement.DASH else PatternElement.DOT
        }
        return HapticPattern(elements)
    }
}
