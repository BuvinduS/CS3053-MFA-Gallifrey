package com.gallifrey.authenticator.haptics

import com.gallifrey.authenticator.haptics.PatternElement.DASH
import com.gallifrey.authenticator.haptics.PatternElement.DOT
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class HapticWaveformTest {

    private val dotDashDotDot = HapticPattern(listOf(DOT, DASH, DOT, DOT))

    @Test
    fun `builds the design example Dot Dash Dot Dot`() {
        val w = HapticWaveform.build(dotDashDotDot)
        assertContentEquals(longArrayOf(1000, 200, 200, 600, 200, 200, 200, 200), w.timings)
        assertContentEquals(intArrayOf(0, 255, 0, 255, 0, 255, 0, 255), w.amplitudes)
        assertEquals(2_800, w.totalDurationMs)
    }

    @Test
    fun `pulse durations follow calibrated timing`() {
        val timing = HapticTiming.DEFAULT.withPlaybackUnit(250)
        val w = HapticWaveform.build(dotDashDotDot, timing)
        assertEquals(listOf(250L, 750L, 250L, 250L), w.pulseDurationsMs)
    }

    @Test
    fun `starts with silence and has no trailing gap`() {
        val w = HapticWaveform.build(dotDashDotDot)
        assertEquals(0, w.amplitudes.first())
        assertEquals(255, w.amplitudes.last())
        assertEquals(w.timings.size, w.amplitudes.size)
    }

    @Test
    fun `custom amplitude is applied to pulses only`() {
        val w = HapticWaveform.build(dotDashDotDot, amplitude = 128)
        assertEquals(setOf(0, 128), w.amplitudes.toSet())
    }

    @Test
    fun `invalid amplitude is rejected`() {
        assertFailsWith<IllegalArgumentException> { HapticWaveform.build(dotDashDotDot, amplitude = 0) }
        assertFailsWith<IllegalArgumentException> { HapticWaveform.build(dotDashDotDot, amplitude = 256) }
    }
}
