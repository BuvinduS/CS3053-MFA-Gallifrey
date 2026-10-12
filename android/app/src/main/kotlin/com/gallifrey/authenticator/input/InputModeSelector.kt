package com.gallifrey.authenticator.input

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.gallifrey.authenticator.R

/**
 * Choice between Dot/Dash buttons and the hold area, as a vertical radio
 * list: each option is one full-width row (radio + label), so long labels and
 * large text wrap instead of being squeezed. TalkBack reads it as a radio
 * group ("Hold area, radio button, not selected, 2 of 2").
 */
@Composable
fun InputModeSelector(
    selected: InputMode,
    onSelect: (InputMode) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(modifier = modifier.fillMaxWidth().selectableGroup()) {
        InputMode.entries.forEach { mode ->
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(12.dp),
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 56.dp)
                    .selectable(
                        selected = selected == mode,
                        onClick = { onSelect(mode) },
                        role = Role.RadioButton,
                    )
                    .padding(horizontal = 8.dp),
            ) {
                // onClick = null: the whole row is the touch target and the single TalkBack stop.
                RadioButton(selected = selected == mode, onClick = null)
                Text(stringResource(label(mode)), style = MaterialTheme.typography.bodyLarge)
            }
        }
    }
}

private fun label(mode: InputMode): Int = when (mode) {
    InputMode.BUTTONS -> R.string.input_mode_buttons
    InputMode.GESTURE -> R.string.input_mode_gesture
}
