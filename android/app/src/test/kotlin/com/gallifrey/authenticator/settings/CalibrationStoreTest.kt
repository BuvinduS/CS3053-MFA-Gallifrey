package com.gallifrey.authenticator.settings

import androidx.datastore.preferences.core.mutablePreferencesOf
import androidx.datastore.preferences.core.preferencesOf
import com.gallifrey.authenticator.haptics.HapticTiming
import com.gallifrey.authenticator.input.InputMode
import org.junit.Assert.assertEquals
import org.junit.Test

class CalibrationStoreTest {

    @Test
    fun emptyPreferencesGiveDesignDefaults() {
        assertEquals(HapticSettings(), CalibrationStore.decode(preferencesOf()))
    }

    @Test
    fun savedSettingsRoundTrip() {
        val settings = HapticSettings(
            timing = HapticTiming.DEFAULT.withPlaybackUnit(300).copy(holdThresholdMs = 550),
            inputMode = InputMode.GESTURE,
        )
        val prefs = mutablePreferencesOf()
        CalibrationStore.encode(settings, prefs)
        assertEquals(settings, CalibrationStore.decode(prefs))
    }

    @Test
    fun invalidStoredTimingFallsBackToDefaults() {
        // DASH not at least twice DOT: rejected by HapticTiming.
        val prefs = preferencesOf(
            CalibrationStore.DOT_MS to 400L,
            CalibrationStore.DASH_MS to 500L,
            CalibrationStore.INPUT_MODE to "GESTURE",
        )
        val decoded = CalibrationStore.decode(prefs)
        assertEquals(HapticTiming.DEFAULT, decoded.timing)
        assertEquals(InputMode.GESTURE, decoded.inputMode)
    }

    @Test
    fun unknownInputModeFallsBackToButtons() {
        val prefs = preferencesOf(CalibrationStore.INPUT_MODE to "TELEPATHY")
        assertEquals(InputMode.BUTTONS, CalibrationStore.decode(prefs).inputMode)
    }

    @Test
    fun partialSettingsKeepOtherDefaults() {
        val prefs = preferencesOf(CalibrationStore.HOLD_THRESHOLD_MS to 600L)
        val timing = CalibrationStore.decode(prefs).timing
        assertEquals(600L, timing.holdThresholdMs)
        assertEquals(HapticTiming.DEFAULT_DOT_MS, timing.dotMs)
    }
}
