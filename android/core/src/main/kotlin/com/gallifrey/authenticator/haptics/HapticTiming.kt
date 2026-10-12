package com.gallifrey.authenticator.haptics

/**
 * Playback and gesture timing (design sections 6-7, defaults D03/D04).
 *
 * All values are prototype engineering defaults that must be validated through
 * user testing; they are not claimed as universal human thresholds. Playback
 * (dot/dash/gap) and the gesture hold threshold are calibrated independently.
 */
data class HapticTiming(
    val dotMs: Long = DEFAULT_DOT_MS,
    val dashMs: Long = DEFAULT_DASH_MS,
    val gapMs: Long = DEFAULT_GAP_MS,
    val startDelayMs: Long = DEFAULT_START_DELAY_MS,
    val holdThresholdMs: Long = DEFAULT_HOLD_THRESHOLD_MS,
) {
    init {
        require(dotMs in MIN_PULSE_MS..MAX_PULSE_MS) { "dotMs out of range" }
        require(dashMs in MIN_PULSE_MS..MAX_PULSE_MS) { "dashMs out of range" }
        // Keep DOT and DASH clearly distinguishable by touch.
        require(dashMs >= dotMs * MIN_DASH_TO_DOT_RATIO) {
            "dashMs must be at least $MIN_DASH_TO_DOT_RATIO x dotMs"
        }
        // Long enough that two pulses are never felt as one.
        require(gapMs in MIN_GAP_MS..MAX_PULSE_MS) { "gapMs out of range" }
        require(startDelayMs in 0..MAX_START_DELAY_MS) { "startDelayMs out of range" }
        require(holdThresholdMs in MIN_HOLD_THRESHOLD_MS..MAX_HOLD_THRESHOLD_MS) {
            "holdThresholdMs out of range"
        }
    }

    fun durationOf(element: PatternElement): Long = when (element) {
        PatternElement.DOT -> dotMs
        PatternElement.DASH -> dashMs
    }

    /**
     * Rescales the pulses from a single user-chosen unit (DOT = 1 unit,
     * DASH = 3 units). The gap, start delay and hold threshold are adjusted
     * separately, so changing speed never overrides them.
     */
    fun withPlaybackUnit(unitMs: Long): HapticTiming =
        copy(dotMs = unitMs, dashMs = unitMs * 3)

    /** Silence between elements. */
    fun withGap(gapMs: Long): HapticTiming = copy(gapMs = gapMs)

    /** Preparation time before the first pulse. */
    fun withStartDelay(startDelayMs: Long): HapticTiming = copy(startDelayMs = startDelayMs)

    companion object {
        const val DEFAULT_DOT_MS = 200L
        const val DEFAULT_DASH_MS = 600L
        const val DEFAULT_GAP_MS = 200L
        const val DEFAULT_START_DELAY_MS = 1_000L
        const val DEFAULT_HOLD_THRESHOLD_MS = 400L

        const val MIN_PULSE_MS = 50L
        const val MIN_GAP_MS = 100L
        const val MAX_PULSE_MS = 2_000L
        const val MAX_START_DELAY_MS = 5_000L
        const val MIN_HOLD_THRESHOLD_MS = 100L
        const val MAX_HOLD_THRESHOLD_MS = 2_000L
        const val MIN_DASH_TO_DOT_RATIO = 2

        val DEFAULT = HapticTiming()
    }
}
