package com.gallifrey.authenticator.input

import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.PatternElement.DASH
import com.gallifrey.authenticator.haptics.PatternElement.DOT
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PatternInputTest {

    @Test
    fun `buttons build the expected pattern`() {
        val input = PatternInput()
        input.addDot(); input.addDash(); input.addDot(); input.addDot()
        assertTrue(input.isComplete)
        assertEquals(HapticPattern(listOf(DOT, DASH, DOT, DOT)), input.toPattern())
    }

    @Test
    fun `gestures are classified by hold duration`() {
        val input = PatternInput(mode = InputMode.GESTURE)
        assertEquals(DOT, input.addGesture(0, 150))
        assertEquals(DASH, input.addGesture(1_000, 1_600))
        assertEquals(2, input.count)
    }

    @Test
    fun `cancelled gesture adds nothing`() {
        val input = PatternInput(mode = InputMode.GESTURE)
        assertNull(input.addGesture(0, 700, cancelled = true))
        assertEquals(0, input.count)
    }

    @Test
    fun `incomplete entry has no pattern`() {
        val input = PatternInput()
        input.addDot()
        assertFalse(input.isComplete)
        assertNull(input.toPattern())
    }

    @Test
    fun `entry cannot exceed the expected length`() {
        val input = PatternInput()
        repeat(4) { assertTrue(input.addDash()) }
        assertFalse(input.addDot())
        assertNull(input.addGesture(0, 100))
        assertEquals(4, input.count)
    }

    @Test
    fun `remove last counts corrections`() {
        val input = PatternInput()
        input.addDot(); input.addDash()
        assertTrue(input.removeLast())
        assertEquals(1, input.count)
        assertEquals(1, input.corrections)
        input.reset()
        assertFalse(input.removeLast())
        assertEquals(1, input.corrections)
    }

    @Test
    fun `reset clears the entry`() {
        val input = PatternInput()
        input.addDot(); input.addDot()
        input.reset()
        assertTrue(input.isEmpty)
    }

    @Test
    fun `switching mode keeps the entry`() {
        val input = PatternInput()
        input.addDot()
        input.switchMode(InputMode.GESTURE)
        input.addGesture(0, 800)
        assertEquals(InputMode.GESTURE, input.mode)
        assertEquals(2, input.count)
    }

    @Test
    fun `toString does not reveal entered elements`() {
        val input = PatternInput()
        input.addDot(); input.addDash()
        val text = input.toString()
        assertFalse(text.contains("DOT") || text.contains("DASH"))
    }
}
