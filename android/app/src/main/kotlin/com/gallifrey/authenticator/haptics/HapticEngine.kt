package com.gallifrey.authenticator.haptics

import android.content.Context
import android.media.AudioAttributes
import android.os.Build
import android.os.VibrationAttributes
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager

/**
 * Plays DOT/DASH patterns on the device vibrator (design section 5, HapticEngine).
 *
 * The waveform itself comes from core's HapticWaveform, so timing is unit
 * tested on the JVM; this class only hands it to the platform. Playback is
 * marked as accessibility usage so it follows the user's accessibility
 * vibration settings rather than touch-feedback settings.
 *
 * Callers start playback only after an explicit user action (never
 * automatically from a notification) and never log the pattern.
 */
class HapticEngine(context: Context) {

    private val vibrator: Vibrator =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            context.getSystemService(VibratorManager::class.java).defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            context.getSystemService(Vibrator::class.java)
        }

    /** False on devices without a vibrator: offer direct approval instead. */
    val isAvailable: Boolean get() = vibrator.hasVibrator()

    /** Whether pulse strength can be adjusted; otherwise pulses use the default strength. */
    val hasAmplitudeControl: Boolean get() = vibrator.hasAmplitudeControl()

    /**
     * Plays [pattern] once, cancelling anything already playing.
     * Returns the playback duration in milliseconds (0 if no vibrator).
     */
    fun play(
        pattern: HapticPattern,
        timing: HapticTiming = HapticTiming.DEFAULT,
        amplitude: Int = HapticWaveform.MAX_AMPLITUDE,
    ): Long {
        if (!isAvailable) return 0
        val waveform = HapticWaveform.build(pattern, timing, amplitude)
        vibrate(waveform)
        return waveform.totalDurationMs
    }

    /** Plays a single element without the start delay, for calibration and practice. */
    fun preview(
        element: PatternElement,
        timing: HapticTiming = HapticTiming.DEFAULT,
        amplitude: Int = HapticWaveform.MAX_AMPLITUDE,
    ): Long = play(HapticPattern(listOf(element)), timing.copy(startDelayMs = 0), amplitude)

    fun cancel() {
        vibrator.cancel()
    }

    private fun vibrate(waveform: HapticWaveform) {
        vibrator.cancel()
        // Both overloads read timings as alternating OFF/ON segments, starting with OFF.
        val effect = if (hasAmplitudeControl) {
            VibrationEffect.createWaveform(waveform.timings, waveform.amplitudes, NO_REPEAT)
        } else {
            VibrationEffect.createWaveform(waveform.timings, NO_REPEAT)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            vibrator.vibrate(effect, VibrationAttributes.createForUsage(VibrationAttributes.USAGE_ACCESSIBILITY))
        } else {
            @Suppress("DEPRECATION")
            vibrator.vibrate(
                effect,
                AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_ASSISTANCE_ACCESSIBILITY)
                    .build(),
            )
        }
    }

    private companion object {
        const val NO_REPEAT = -1
    }
}
