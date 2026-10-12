package com.gallifrey.authenticator.settings

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import com.gallifrey.authenticator.R
import com.gallifrey.authenticator.haptics.HapticEngine
import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.PatternElement
import com.gallifrey.authenticator.input.GestureClassifier
import com.gallifrey.authenticator.input.HoldGestureArea
import com.gallifrey.authenticator.input.InputModeSelector
import com.gallifrey.authenticator.ui.AdaptiveButtonRow
import kotlin.math.roundToLong

private val MinTarget = 56.dp

/** Slider ranges in milliseconds. DOT length is the playback unit; DASH = 3 units. */
private val UNIT_RANGE = 100L..400L
private val GAP_RANGE = 100L..1_000L
private val START_DELAY_RANGE = 0L..3_000L
private val HOLD_RANGE = 250L..800L
private const val STEP_MS = 50L
private const val START_DELAY_STEP_MS = 250L

/**
 * Haptic calibration (design section 7). Pulse speed, gap, start delay and
 * the gesture hold threshold are adjusted independently, and every change is
 * saved immediately through [onChange].
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
    val res = LocalContext.current.resources
    var holdFeedback by remember { mutableStateOf(res.getString(R.string.calibration_hold_prompt)) }

    Column(
        modifier = modifier.verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.calibration_title),
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.semantics { heading() },
        )

        // --- Playback ---------------------------------------------------------
        SectionHeading(stringResource(R.string.calibration_speed))
        TimingSlider(
            description = stringResource(R.string.calibration_speed_value, timing.dotMs.toInt(), timing.dashMs.toInt()),
            valueMs = timing.dotMs,
            range = UNIT_RANGE,
            stepMs = STEP_MS,
            onValue = { onChange(settings.copy(timing = timing.withPlaybackUnit(it))) },
        )
        AdaptiveButtonRow { itemModifier ->
            FilledTonalButton(
                onClick = { haptics.preview(PatternElement.DOT, timing) },
                modifier = itemModifier.heightIn(min = MinTarget),
            ) { Text(stringResource(R.string.feel_dot)) }
            FilledTonalButton(
                onClick = { haptics.preview(PatternElement.DASH, timing) },
                modifier = itemModifier.heightIn(min = MinTarget),
            ) { Text(stringResource(R.string.feel_dash)) }
        }

        SectionHeading(stringResource(R.string.calibration_gap))
        TimingSlider(
            description = stringResource(R.string.calibration_gap_value, timing.gapMs.toInt()),
            valueMs = timing.gapMs,
            range = GAP_RANGE,
            stepMs = STEP_MS,
            onValue = { onChange(settings.copy(timing = timing.withGap(it))) },
        )

        SectionHeading(stringResource(R.string.calibration_start_delay))
        TimingSlider(
            description = stringResource(R.string.calibration_start_delay_value, timing.startDelayMs.toInt()),
            valueMs = timing.startDelayMs,
            range = START_DELAY_RANGE,
            stepMs = START_DELAY_STEP_MS,
            onValue = { onChange(settings.copy(timing = timing.withStartDelay(it))) },
        )

        FilledTonalButton(
            onClick = { haptics.play(SAMPLE_PATTERN, timing) },
            modifier = Modifier.fillMaxWidth().heightIn(min = MinTarget),
        ) { Text(stringResource(R.string.play_sample)) }

        HorizontalDivider()

        // --- Hold threshold ---------------------------------------------------
        SectionHeading(stringResource(R.string.calibration_hold))
        TimingSlider(
            description = stringResource(R.string.calibration_hold_value, timing.holdThresholdMs.toInt()),
            valueMs = timing.holdThresholdMs,
            range = HOLD_RANGE,
            stepMs = STEP_MS,
            onValue = { onChange(settings.copy(timing = timing.copy(holdThresholdMs = it))) },
        )
        val classifier = GestureClassifier(timing)
        HoldGestureArea(
            classifier = classifier,
            onElement = {},
            onHoldMeasured = { ms ->
                val name = res.getString(if (classifier.classify(ms) == PatternElement.DOT) R.string.dot else R.string.dash)
                holdFeedback = res.getString(R.string.calibration_hold_result, ms.toInt(), name)
            },
        )
        Text(
            holdFeedback,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )

        HorizontalDivider()

        // --- Default input method --------------------------------------------
        SectionHeading(stringResource(R.string.calibration_default_mode))
        InputModeSelector(
            selected = settings.inputMode,
            onSelect = { onChange(settings.copy(inputMode = it)) },
        )

        OutlinedButton(
            onClick = {
                haptics.cancel()
                onReset()
                holdFeedback = res.getString(R.string.calibration_reset_done)
            },
            modifier = Modifier.fillMaxWidth().heightIn(min = MinTarget),
        ) { Text(stringResource(R.string.calibration_reset)) }
    }
}

@Composable
private fun SectionHeading(text: String) {
    Text(text, style = MaterialTheme.typography.titleLarge, modifier = Modifier.semantics { heading() })
}

/**
 * A labelled millisecond slider. The description is shown as text and is also
 * what TalkBack reads as the slider's value, so it is spoken in words rather
 * than as a bare percentage.
 */
@Composable
private fun TimingSlider(
    description: String,
    valueMs: Long,
    range: LongRange,
    stepMs: Long,
    onValue: (Long) -> Unit,
) {
    Text(description, style = MaterialTheme.typography.bodyLarge)
    Slider(
        value = valueMs.coerceIn(range).toFloat(),
        onValueChange = { raw ->
            val snapped = ((raw / stepMs).roundToLong() * stepMs).coerceIn(range)
            if (snapped != valueMs) onValue(snapped)
        },
        valueRange = range.first.toFloat()..range.last.toFloat(),
        steps = ((range.last - range.first) / stepMs - 1).toInt(),
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = MinTarget)
            .semantics { stateDescription = description },
    )
}

// The design document's example (Figure 3); a calibration sample, not a secret.
private val SAMPLE_PATTERN = HapticPattern(
    listOf(PatternElement.DOT, PatternElement.DASH, PatternElement.DOT, PatternElement.DOT),
)
