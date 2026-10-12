package com.gallifrey.authenticator.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import com.gallifrey.authenticator.haptics.HapticEngine
import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.PatternElement
import com.gallifrey.authenticator.input.GestureClassifier
import com.gallifrey.authenticator.input.HoldGestureArea
import com.gallifrey.authenticator.input.InputMode
import kotlin.math.roundToLong

private val MinTarget = 56.dp

/** Playback unit (DOT length) range; DASH = 3 units, gap = 1 unit. */
private const val MIN_UNIT_MS = 100L
private const val MAX_UNIT_MS = 400L
private const val UNIT_STEP_MS = 50L

private const val MIN_HOLD_MS = 250L
private const val MAX_HOLD_MS = 800L
private const val HOLD_STEP_MS = 50L

/**
 * Haptic calibration (design section 7). Playback speed and the gesture hold
 * threshold are adjusted independently, as the design requires, and every
 * change is saved immediately through [onChange].
 *
 * The sample pattern here is fixed and is never a transaction pattern.
 */
@Composable
fun CalibrationScreen(
    settings: HapticSettings,
    haptics: HapticEngine,
    onChange: (HapticSettings) -> Unit,
    onReset: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val timing = settings.timing
    var holdFeedback by remember { mutableStateOf("Tap or hold the area below to test.") }

    Column(
        modifier = modifier.verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            "Haptic calibration",
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.semantics { heading() },
        )

        // --- Playback speed ---------------------------------------------------
        Text("Vibration speed", style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
        val speedDescription = "Dot ${timing.dotMs} milliseconds, Dash ${timing.dashMs} milliseconds"
        Text(speedDescription, style = MaterialTheme.typography.bodyLarge)
        Slider(
            value = timing.dotMs.toFloat(),
            onValueChange = { value ->
                val unit = snap(value, UNIT_STEP_MS)
                if (unit != timing.dotMs) onChange(settings.copy(timing = timing.withPlaybackUnit(unit)))
            },
            valueRange = MIN_UNIT_MS.toFloat()..MAX_UNIT_MS.toFloat(),
            steps = ((MAX_UNIT_MS - MIN_UNIT_MS) / UNIT_STEP_MS - 1).toInt(),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = MinTarget)
                .semantics { stateDescription = speedDescription },
        )
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
            FilledTonalButton(
                onClick = { haptics.preview(PatternElement.DOT, timing) },
                modifier = Modifier.weight(1f).heightIn(min = MinTarget),
            ) { Text("Feel Dot") }
            FilledTonalButton(
                onClick = { haptics.preview(PatternElement.DASH, timing) },
                modifier = Modifier.weight(1f).heightIn(min = MinTarget),
            ) { Text("Feel Dash") }
        }
        FilledTonalButton(
            onClick = { haptics.play(SAMPLE_PATTERN, timing) },
            modifier = Modifier.fillMaxWidth().heightIn(min = MinTarget),
        ) { Text("Play sample: Dot Dash Dot Dot") }

        HorizontalDivider()

        // --- Hold threshold ---------------------------------------------------
        Text("Hold length", style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
        val holdDescription = "Holds shorter than ${timing.holdThresholdMs} milliseconds count as Dot"
        Text(holdDescription, style = MaterialTheme.typography.bodyLarge)
        Slider(
            value = timing.holdThresholdMs.toFloat(),
            onValueChange = { value ->
                val threshold = snap(value, HOLD_STEP_MS)
                if (threshold != timing.holdThresholdMs) {
                    onChange(settings.copy(timing = timing.copy(holdThresholdMs = threshold)))
                }
            },
            valueRange = MIN_HOLD_MS.toFloat()..MAX_HOLD_MS.toFloat(),
            steps = ((MAX_HOLD_MS - MIN_HOLD_MS) / HOLD_STEP_MS - 1).toInt(),
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = MinTarget)
                .semantics { stateDescription = holdDescription },
        )
        val classifier = GestureClassifier(timing)
        HoldGestureArea(
            classifier = classifier,
            onElement = {},
            onHoldMeasured = { ms ->
                val name = if (classifier.classify(ms) == PatternElement.DOT) "Dot" else "Dash"
                holdFeedback = "You held for $ms milliseconds: $name."
            },
        )
        Text(
            holdFeedback,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )

        HorizontalDivider()

        // --- Default input method --------------------------------------------
        Text("Default input method", style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
        SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
            InputMode.entries.forEachIndexed { index, mode ->
                SegmentedButton(
                    selected = settings.inputMode == mode,
                    onClick = { onChange(settings.copy(inputMode = mode)) },
                    shape = SegmentedButtonDefaults.itemShape(index, InputMode.entries.size),
                    modifier = Modifier.heightIn(min = MinTarget),
                ) { Text(if (mode == InputMode.BUTTONS) "Dot and Dash buttons" else "Hold area") }
            }
        }

        OutlinedButton(
            onClick = {
                haptics.cancel()
                onReset()
                holdFeedback = "Settings reset to defaults."
            },
            modifier = Modifier.fillMaxWidth().heightIn(min = MinTarget),
        ) { Text("Reset to defaults") }
    }
}

private fun snap(value: Float, step: Long): Long = (value / step).roundToLong() * step

// The design document's example (Figure 3); a calibration sample, not a secret.
private val SAMPLE_PATTERN = HapticPattern(
    listOf(PatternElement.DOT, PatternElement.DASH, PatternElement.DOT, PatternElement.DOT),
)
