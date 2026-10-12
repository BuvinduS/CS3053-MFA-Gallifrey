package com.gallifrey.authenticator.input

import com.gallifrey.authenticator.haptics.HapticTiming
import com.gallifrey.authenticator.haptics.PatternElement.DASH
import com.gallifrey.authenticator.haptics.PatternElement.DOT
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class GestureClassifierTest {

    private val classifier = GestureClassifier()

    // M2-T06: hold < 400 ms -> DOT
    @Test
    fun `holds shorter than the threshold are DOT`() {
        assertEquals(DOT, classifier.classify(0))
        assertEquals(DOT, classifier.classify(150))
        assertEquals(DOT, classifier.classify(399))
    }

    // M2-T07: hold >= 400 ms -> DASH
    @Test
    fun `holds at or above the threshold are DASH`() {
        assertEquals(DASH, classifier.classify(400))
        assertEquals(DASH, classifier.classify(650))
    }

    @Test
    fun `uses press and release timestamps`() {
        assertEquals(DOT, classifier.classify(pressedAtMs = 10_000, releasedAtMs = 10_120))
        assertEquals(DASH, classifier.classify(pressedAtMs = 10_000, releasedAtMs = 10_700))
    }

    @Test
    fun `cancelled touch produces no element`() {
        assertNull(classifier.classify(pressedAtMs = 0, releasedAtMs = 700, cancelled = true))
    }

    @Test
    fun `release before press produces no element`() {
        assertNull(classifier.classify(pressedAtMs = 500, releasedAtMs = 100))
    }

    @Test
    fun `calibrated threshold is respected`() {
        val slow = GestureClassifier(HapticTiming(holdThresholdMs = 700))
        assertEquals(DOT, slow.classify(600))
        assertEquals(DASH, slow.classify(700))
    }

    @Test
    fun `negative duration is rejected`() {
        assertFailsWith<IllegalArgumentException> { classifier.classify(-1) }
    }
}
