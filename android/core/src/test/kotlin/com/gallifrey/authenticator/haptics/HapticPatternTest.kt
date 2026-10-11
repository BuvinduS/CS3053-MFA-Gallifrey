package com.gallifrey.authenticator.haptics

import com.gallifrey.authenticator.haptics.PatternElement.DASH
import com.gallifrey.authenticator.haptics.PatternElement.DOT
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

class HapticPatternTest {

    @Test
    fun `patterns with the same elements are equal`() {
        assertEquals(HapticPattern(listOf(DOT, DASH, DOT, DOT)), HapticPattern(listOf(DOT, DASH, DOT, DOT)))
        assertNotEquals(HapticPattern(listOf(DOT, DASH, DOT, DOT)), HapticPattern(listOf(DOT, DOT, DOT, DOT)))
    }

    @Test
    fun `toString never reveals the elements`() {
        val text = HapticPattern(listOf(DOT, DASH, DOT, DOT)).toString()
        assertEquals("HapticPattern(size=4)", text)
        assertFalse(text.contains("DOT") || text.contains("DASH"))
    }

    @Test
    fun `pattern is a defensive copy`() {
        val source = mutableListOf(DOT, DASH, DOT, DOT)
        val pattern = HapticPattern(source)
        source[0] = DASH
        assertEquals(DOT, pattern.elements[0])
    }

    @Test
    fun `empty pattern is rejected`() {
        assertFailsWith<IllegalArgumentException> { HapticPattern(emptyList()) }
    }
}
