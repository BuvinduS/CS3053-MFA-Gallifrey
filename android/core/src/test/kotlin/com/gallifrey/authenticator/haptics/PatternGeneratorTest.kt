package com.gallifrey.authenticator.haptics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class PatternGeneratorTest {

    private val generator = PatternGenerator()

    // M2-T01: correct length and only DOT/DASH values
    @Test
    fun `generates four DOT or DASH elements by default`() {
        repeat(200) {
            val pattern = generator.generate()
            assertEquals(4, pattern.size)
            assertTrue(pattern.elements.all { it == PatternElement.DOT || it == PatternElement.DASH })
        }
    }

    @Test
    fun `supports a custom length`() {
        assertEquals(6, generator.generate(6).size)
    }

    @Test
    fun `rejects non-positive length`() {
        assertFailsWith<IllegalArgumentException> { generator.generate(0) }
    }

    @Test
    fun `all 16 four-element patterns are reachable`() {
        // Sanity check of the random source, not a statistical test:
        // 2000 draws over 16 outcomes miss one with negligible probability.
        val seen = HashSet<List<PatternElement>>()
        repeat(2000) { seen += generator.generate().elements }
        assertEquals(16, seen.size)
    }
}
