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
    fun `playback unit keeps proportions and leaves hold threshold alone`() {
        val t = HapticTiming.DEFAULT.withPlaybackUnit(300)
        assertEquals(300, t.dotMs)
        assertEquals(900, t.dashMs)
        assertEquals(300, t.gapMs)
        assertEquals(400, t.holdThresholdMs)
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
