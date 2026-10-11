package com.gallifrey.authenticator.input

import com.gallifrey.authenticator.haptics.HapticTiming
import com.gallifrey.authenticator.haptics.PatternElement

/**
 * Turns one press-and-release into a DOT or DASH (decision table, section 7):
 *
 *   hold duration <  threshold  -> DOT
 *   hold duration >= threshold  -> DASH
 *   touch cancelled             -> no element
 *
 * Timestamps must come from a monotonic clock (SystemClock.uptimeMillis or
 * MotionEvent times on Android), never wall-clock time, which can jump.
 */
class GestureClassifier(private val holdThresholdMs: Long = HapticTiming.DEFAULT_HOLD_THRESHOLD_MS) {

    constructor(timing: HapticTiming) : this(timing.holdThresholdMs)

    init {
        require(holdThresholdMs > 0) { "holdThresholdMs must be positive" }
    }

    fun classify(holdDurationMs: Long): PatternElement {
        require(holdDurationMs >= 0) { "hold duration cannot be negative" }
        return if (holdDurationMs < holdThresholdMs) PatternElement.DOT else PatternElement.DASH
    }

    /** Returns null for a cancelled touch or inconsistent timestamps. */
    fun classify(pressedAtMs: Long, releasedAtMs: Long, cancelled: Boolean = false): PatternElement? {
        if (cancelled || releasedAtMs < pressedAtMs) return null
        return classify(releasedAtMs - pressedAtMs)
    }
}
