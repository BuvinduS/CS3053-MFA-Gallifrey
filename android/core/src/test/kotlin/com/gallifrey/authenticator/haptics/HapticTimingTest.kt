package com.gallifrey.authenticator.haptics

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class HapticTimingTest {

    @Test
    fun `defaults match the design document`() {
        val t = HapticTiming.DEFAULT
        assertEquals(200, t.dotMs)
        assertEquals(600, t.dashMs)
        assertEquals(200, t.gapMs)
        assertEquals(1_000, t.startDelayMs)
        assertEquals(400, t.holdThresholdMs)
    }

    @Test
    fun `durationOf maps elements to pulse lengths`() {
        assertEquals(200, HapticTiming.DEFAULT.durationOf(PatternElement.DOT))
        assertEquals(600, HapticTiming.DEFAULT.durationOf(PatternElement.DASH))
    }

    @Test
    fun `playback unit scales pulses and leaves gap, delay and hold threshold alone`() {
        val t = HapticTiming.DEFAULT.withGap(350).withStartDelay(1_500).withPlaybackUnit(300)
        assertEquals(300, t.dotMs)
        assertEquals(900, t.dashMs)
        assertEquals(350, t.gapMs)
        assertEquals(1_500, t.startDelayMs)
        assertEquals(400, t.holdThresholdMs)
    }

    @Test
    fun `gap and start delay are adjusted independently`() {
        val t = HapticTiming.DEFAULT.withGap(500).withStartDelay(0)
        assertEquals(500, t.gapMs)
        assertEquals(0, t.startDelayMs)
        assertEquals(200, t.dotMs)
    }

    @Test
    fun `gap shorter than 100 ms is rejected`() {
        assertFailsWith<IllegalArgumentException> { HapticTiming.DEFAULT.withGap(99) }
        assertEquals(100, HapticTiming.DEFAULT.withGap(100).gapMs)
    }

    @Test
    fun `dash too close to dot is rejected`() {
        assertFailsWith<IllegalArgumentException> { HapticTiming(dotMs = 300, dashMs = 400) }
    }

    @Test
    fun `out of range values are rejected`() {
        assertFailsWith<IllegalArgumentException> { HapticTiming(dotMs = 10) }
        assertFailsWith<IllegalArgumentException> { HapticTiming(gapMs = 5_000) }
        assertFailsWith<IllegalArgumentException> { HapticTiming(startDelayMs = -1) }
        assertFailsWith<IllegalArgumentException> { HapticTiming(holdThresholdMs = 50) }
    }
}
