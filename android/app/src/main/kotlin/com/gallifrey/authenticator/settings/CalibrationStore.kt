package com.gallifrey.authenticator.settings

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.MutablePreferences
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import com.gallifrey.authenticator.haptics.HapticTiming
import com.gallifrey.authenticator.input.InputMode
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map

/** The user's haptic preferences. Nothing here is secret. */
data class HapticSettings(
    val timing: HapticTiming = HapticTiming.DEFAULT,
    val inputMode: InputMode = InputMode.BUTTONS,
)

private val Context.calibrationDataStore: DataStore<Preferences> by preferencesDataStore(name = "haptic_calibration")

/**
 * Persists calibration (design section 7, default D06) with Jetpack DataStore
 * in app-private storage, which is excluded from backup and device transfer.
 *
 * Only preferences are stored here: never patterns, keys or tokens.
 */
class CalibrationStore(private val dataStore: DataStore<Preferences>) {

    constructor(context: Context) : this(context.applicationContext.calibrationDataStore)

    val settings: Flow<HapticSettings> = dataStore.data.map(::decode)

    suspend fun save(settings: HapticSettings) {
        dataStore.edit { encode(settings, it) }
    }

    /** Returns to the design defaults (200/600/200 ms, 1 s, 400 ms, buttons). */
    suspend fun reset() {
        dataStore.edit { it.clear() }
    }

    companion object {
        internal val DOT_MS = longPreferencesKey("dot_ms")
        internal val DASH_MS = longPreferencesKey("dash_ms")
        internal val GAP_MS = longPreferencesKey("gap_ms")
        internal val START_DELAY_MS = longPreferencesKey("start_delay_ms")
        internal val HOLD_THRESHOLD_MS = longPreferencesKey("hold_threshold_ms")
        internal val INPUT_MODE = stringPreferencesKey("input_mode")

        /**
         * Missing values use the defaults. A stored combination that no longer
         * passes HapticTiming validation (e.g. after limits change) falls back
         * to the defaults instead of crashing the app.
         */
        internal fun decode(prefs: Preferences): HapticSettings {
            val d = HapticTiming.DEFAULT
            val timing = try {
                HapticTiming(
                    dotMs = prefs[DOT_MS] ?: d.dotMs,
                    dashMs = prefs[DASH_MS] ?: d.dashMs,
                    gapMs = prefs[GAP_MS] ?: d.gapMs,
                    startDelayMs = prefs[START_DELAY_MS] ?: d.startDelayMs,
                    holdThresholdMs = prefs[HOLD_THRESHOLD_MS] ?: d.holdThresholdMs,
                )
            } catch (e: IllegalArgumentException) {
                d
            }
            val mode = prefs[INPUT_MODE]
                ?.let { name -> InputMode.entries.firstOrNull { it.name == name } }
                ?: InputMode.BUTTONS
            return HapticSettings(timing, mode)
        }

        internal fun encode(settings: HapticSettings, prefs: MutablePreferences) {
            val t = settings.timing
            prefs[DOT_MS] = t.dotMs
            prefs[DASH_MS] = t.dashMs
            prefs[GAP_MS] = t.gapMs
            prefs[START_DELAY_MS] = t.startDelayMs
            prefs[HOLD_THRESHOLD_MS] = t.holdThresholdMs
            prefs[INPUT_MODE] = settings.inputMode.name
        }
    }
}
