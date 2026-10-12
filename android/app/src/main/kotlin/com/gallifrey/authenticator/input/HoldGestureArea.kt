package com.gallifrey.authenticator.input

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.gestures.waitForUpOrCancellation
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.semantics.CustomAccessibilityAction
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.customActions
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import com.gallifrey.authenticator.haptics.PatternElement

/**
 * A large touch area for the optional tap/hold input (design section 8).
 *
 * Press duration is measured from the pointer events' own uptime timestamps
 * (monotonic) and classified by core's GestureClassifier: shorter than the
 * threshold is DOT, otherwise DASH. A touch that is cancelled or slides out
 * of the area adds nothing.
 *
 * Only touches inside this area are handled, so TalkBack's own gestures
 * elsewhere are not intercepted. TalkBack users can also pick "Add dot" /
 * "Add dash" from the accessibility actions menu instead of timing a hold.
 */
@Composable
fun HoldGestureArea(
    classifier: GestureClassifier,
    onElement: (PatternElement) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    /** Optional: the measured hold in milliseconds, for calibration feedback. */
    onHoldMeasured: ((Long) -> Unit)? = null,
) {
    val currentClassifier by rememberUpdatedState(classifier)
    val currentOnElement by rememberUpdatedState(onElement)
    val currentOnHoldMeasured by rememberUpdatedState(onHoldMeasured)
    var pressed by remember { mutableStateOf(false) }

    val colors = MaterialTheme.colorScheme
    val background = when {
        !enabled -> colors.surfaceVariant
        pressed -> colors.primary
        else -> colors.primaryContainer
    }
    val content = if (pressed) colors.onPrimary else colors.onPrimaryContainer

    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .fillMaxWidth()
            .heightIn(min = 160.dp)
            .background(background, RoundedCornerShape(16.dp))
            .border(2.dp, colors.outline, RoundedCornerShape(16.dp))
            .semantics(mergeDescendants = true) {
                contentDescription = "Hold area. Tap for dot, hold for dash."
                if (enabled) {
                    customActions = listOf(
                        CustomAccessibilityAction("Add dot") { currentOnElement(PatternElement.DOT); true },
                        CustomAccessibilityAction("Add dash") { currentOnElement(PatternElement.DASH); true },
                    )
                } else {
                    disabled()
                }
            }
            .pointerInput(enabled) {
                if (!enabled) return@pointerInput
                awaitEachGesture {
                    val down = awaitFirstDown(requireUnconsumed = false)
                    pressed = true
                    // null when the touch is cancelled or leaves the area.
                    val up = waitForUpOrCancellation()
                    pressed = false
                    if (up != null) {
                        up.consume()
                        currentOnHoldMeasured?.invoke(up.uptimeMillis - down.uptimeMillis)
                        currentClassifier.classify(down.uptimeMillis, up.uptimeMillis)
                            ?.let(currentOnElement)
                    }
                }
            },
    ) {
        Text(
            text = if (pressed) "Holding…" else "Tap for Dot · Hold for Dash",
            color = content,
            style = MaterialTheme.typography.titleLarge,
            textAlign = TextAlign.Center,
            modifier = Modifier.padding(16.dp),
        )
    }
}
