package com.gallifrey.authenticator.practice

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.ProgressBarRangeInfo
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.progressBarRangeInfo
import androidx.compose.ui.unit.dp
import com.gallifrey.authenticator.R

/**
 * How many elements have been entered, as filled circles plus "2 of 4".
 *
 * Every circle looks the same whether the element was a Dot or a Dash, so
 * the display shows progress without revealing the sequence (design section 6:
 * feedback announces the number of elements entered, not the sequence).
 */
@Composable
fun EntryProgress(entered: Int, total: Int, modifier: Modifier = Modifier) {
    val description = stringResource(R.string.entry_progress, entered, total)
    val colors = MaterialTheme.colorScheme
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
        modifier = modifier.clearAndSetSemantics {
            contentDescription = description
            progressBarRangeInfo = ProgressBarRangeInfo(entered.toFloat(), 0f..total.toFloat(), steps = total - 1)
        },
    ) {
        repeat(total) { index ->
            val filled = index < entered
            Box(
                modifier = Modifier
                    .size(28.dp)
                    .background(if (filled) colors.primary else Color.Transparent, CircleShape)
                    // Outline on every circle keeps empty slots visible in both themes.
                    .border(2.dp, if (filled) colors.primary else colors.outline, CircleShape),
            )
        }
        Text(description, style = MaterialTheme.typography.titleMedium)
    }
}
