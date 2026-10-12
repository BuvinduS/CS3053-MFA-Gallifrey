package com.gallifrey.authenticator.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.unit.dp

/** At or above this font scale, side-by-side buttons are stacked. */
private const val STACK_FONT_SCALE = 1.3f

/**
 * Buttons side by side at normal text size, stacked full-width when the user
 * has enlarged text, so labels are never clipped or squeezed.
 *
 * [content] receives the modifier each button should use (equal widths in a
 * row, full width when stacked).
 */
@Composable
fun AdaptiveButtonRow(
    modifier: Modifier = Modifier,
    content: @Composable (itemModifier: Modifier) -> Unit,
) {
    val spacing = Arrangement.spacedBy(8.dp)
    if (LocalDensity.current.fontScale >= STACK_FONT_SCALE) {
        Column(modifier = modifier.fillMaxWidth(), verticalArrangement = spacing) {
            content(Modifier.fillMaxWidth())
        }
    } else {
        Row(modifier = modifier.fillMaxWidth(), horizontalArrangement = spacing) {
            content(Modifier.weight(1f))
        }
    }
}
