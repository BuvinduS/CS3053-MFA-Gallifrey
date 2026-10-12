package com.gallifrey.authenticator.haptics

/**
 * A vibration waveform in the shape Android's VibrationEffect.createWaveform
 * expects: [timings] alternate OFF, ON, OFF, ON... and [amplitudes] gives the
 * strength of each segment (0 = off, 1..255 = on).
 *
 * Example for DOT DASH DOT DOT with default timing:
 *   off 1000 | on 200 | off 200 | on 600 | off 200 | on 200 | off 200 | on 200
 */
class HapticWaveform private constructor(
    val timings: LongArray,
    val amplitudes: IntArray,
) {
    val totalDurationMs: Long get() = timings.sum()

    /** Durations of the ON segments only, in playback order. */
    val pulseDurationsMs: List<Long>
        get() = timings.indices.filter { amplitudes[it] > 0 }.map { timings[it] }

    companion object {
        const val MAX_AMPLITUDE = 255

        fun build(
            pattern: HapticPattern,
            timing: HapticTiming = HapticTiming.DEFAULT,
            amplitude: Int = MAX_AMPLITUDE,
        ): HapticWaveform {
            require(amplitude in 1..MAX_AMPLITUDE) { "amplitude must be 1..255" }
            val timings = ArrayList<Long>()
            val amplitudes = ArrayList<Int>()

            // Preparation time before the first pulse.
            timings += timing.startDelayMs
            amplitudes += 0

            pattern.elements.forEachIndexed { index, element ->
                if (index > 0) {
                    // Silence separates elements; no extra pulses that could be
                    // mistaken for pattern elements.
                    timings += timing.gapMs
                    amplitudes += 0
                }
                timings += timing.durationOf(element)
                amplitudes += amplitude
            }
            return HapticWaveform(timings.toLongArray(), amplitudes.toIntArray())
        }
    }
}
