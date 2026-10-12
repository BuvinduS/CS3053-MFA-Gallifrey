package com.gallifrey.authenticator.ui

import androidx.compose.foundation.focusable
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle

/**
 * A heading that takes focus when it first appears. Used when the screen
 * changes state (e.g. after Submit), so keyboard and TalkBack users land on
 * the new content instead of on a control that has just disappeared.
 */
@Composable
fun FocusedHeading(
    text: String,
    modifier: Modifier = Modifier,
    style: TextStyle = MaterialTheme.typography.titleLarge,
) {
    val focusRequester = remember { FocusRequester() }
    Text(
        text = text,
        style = style,
        modifier = modifier
            .semantics { heading() }
            .focusRequester(focusRequester)
            .focusable(),
    )
    LaunchedEffect(Unit) { focusRequester.requestFocus() }
}
