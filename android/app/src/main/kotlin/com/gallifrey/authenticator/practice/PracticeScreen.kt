package com.gallifrey.authenticator.practice

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.gallifrey.authenticator.haptics.HapticEngine
import com.gallifrey.authenticator.haptics.HapticTiming
import com.gallifrey.authenticator.input.GestureClassifier
import com.gallifrey.authenticator.input.HoldGestureArea
import com.gallifrey.authenticator.input.InputMode
import com.gallifrey.authenticator.verify.LocalState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private val MinTarget = 56.dp
private val LargeTarget = 72.dp

/**
 * Practice mode for the full approval flow (design section 17: onboarding /
 * practice). The same rules as a real request apply: play only after a user
 * action, count-only progress feedback, three attempts, explicit approval
 * and Android device verification before anything is signed.
 *
 * @param onApprove runs device verification and signs; returns true if signed.
 */
@Composable
fun PracticeScreen(
    session: PracticeSession,
    haptics: HapticEngine,
    timing: HapticTiming,
    onApprove: suspend () -> Boolean,
    modifier: Modifier = Modifier,
) {
    // PracticeSession is a plain object; bump this after every change to redraw.
    var version by remember { mutableIntStateOf(0) }
    var status by remember { mutableStateOf("Press Play pattern to feel the pattern.") }
    var played by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun refresh(message: String? = null) {
        if (message != null) status = message
        version++
    }

    // Expiry happens with no user action, so re-check the state every second.
    LaunchedEffect(version) {
        while (!session.state.isTerminal) {
            delay(1_000)
            if (session.state == LocalState.EXPIRED) {
                haptics.cancel()
                refresh("Request expired. Start a new practice.")
            }
        }
    }

    val state = version.let { session.state }

    Column(
        modifier = modifier.verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            "Practice approval",
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            status,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )

        when (state) {
            LocalState.AWAITING_PATTERN -> EntrySection(
                session = session,
                version = version,
                timing = timing,
                played = played,
                onPlay = {
                    haptics.play(session.patternForPlayback(), timing)
                    played = true
                    refresh("Playing. Feel the pattern, then enter it.")
                },
                onChanged = ::refresh,
            )

            LocalState.AWAITING_APPROVAL -> {
                Text("Approve this practice request?", style = MaterialTheme.typography.titleLarge)
                Button(
                    onClick = {
                        scope.launch {
                            val signed = onApprove()
                            if (signed && session.canApprove) {
                                session.recordDecision(approved = true)
                                refresh("Approved. Your phone signed the practice request.")
                            } else if (!signed) {
                                refresh("Not approved. Nothing was signed.")
                            } else {
                                refresh()
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = LargeTarget),
                ) { Text("Approve") }
                OutlinedButton(
                    onClick = {
                        session.recordDecision(approved = false)
                        refresh("Denied. Nothing was approved.")
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = LargeTarget),
                ) { Text("Deny") }
            }

            else -> ResultSection(
                session = session,
                version = version,
                onRestart = {
                    haptics.cancel()
                    session.restart()
                    played = false
                    refresh("New practice started. Press Play pattern.")
                },
            )
        }
    }
}

@Composable
private fun EntrySection(
    session: PracticeSession,
    // Read below so this section redraws whenever the session changes.
    version: Int,
    timing: HapticTiming,
    played: Boolean,
    onPlay: () -> Unit,
    onChanged: (String?) -> Unit,
) {
    val count = version.let { session.input.count }
    val classifier = remember(timing.holdThresholdMs) { GestureClassifier(timing) }

    FilledTonalButton(onClick = onPlay, modifier = Modifier.fillMaxWidth().heightIn(min = MinTarget)) {
        Text(if (played) "Replay pattern" else "Play pattern")
    }

    Text("Input method", style = MaterialTheme.typography.titleMedium)
    SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
        InputMode.entries.forEachIndexed { index, mode ->
            SegmentedButton(
                selected = session.input.mode == mode,
                onClick = {
                    session.switchMode(mode)
                    onChanged(null)
                },
                shape = SegmentedButtonDefaults.itemShape(index, InputMode.entries.size),
                modifier = Modifier.heightIn(min = MinTarget),
            ) { Text(if (mode == InputMode.BUTTONS) "Dot and Dash buttons" else "Hold area") }
        }
    }

    // Count only: the sequence itself is never shown or spoken.
    fun added(ok: Boolean) =
        onChanged(if (ok) "${session.input.count} of 4 entered." else "Already 4 entered. Submit or undo.")

    when (session.input.mode) {
        InputMode.BUTTONS -> Row(horizontalArrangement = Arrangement.spacedBy(16.dp)) {
            Button(
                onClick = { added(session.addDot()) },
                modifier = Modifier.weight(1f).heightIn(min = LargeTarget),
            ) { Text("Dot", style = MaterialTheme.typography.titleLarge) }
            Button(
                onClick = { added(session.addDash()) },
                modifier = Modifier.weight(1f).heightIn(min = LargeTarget),
            ) { Text("Dash", style = MaterialTheme.typography.titleLarge) }
        }

        InputMode.GESTURE -> HoldGestureArea(
            classifier = classifier,
            onElement = { added(session.addElement(it)) },
        )
    }

    Text("$count of 4 entered", style = MaterialTheme.typography.titleMedium)

    Row(horizontalArrangement = Arrangement.spacedBy(8.dp), modifier = Modifier.fillMaxWidth()) {
        OutlinedButton(
            onClick = { if (session.removeLast()) onChanged("Removed one. ${session.input.count} of 4 entered.") },
            enabled = count > 0,
            modifier = Modifier.weight(1f).heightIn(min = MinTarget),
        ) { Text("Undo") }
        OutlinedButton(
            onClick = { session.resetEntry(); onChanged("Entry cleared. 0 of 4 entered.") },
            enabled = count > 0,
            modifier = Modifier.weight(1f).heightIn(min = MinTarget),
        ) { Text("Reset") }
        Button(
            onClick = {
                val message = when (val outcome = session.submit()) {
                    SubmitOutcome.Matched -> "Pattern matched."
                    is SubmitOutcome.Mismatch ->
                        "Pattern did not match. ${outcome.attemptsRemaining} " +
                            (if (outcome.attemptsRemaining == 1) "attempt" else "attempts") + " left."
                    SubmitOutcome.Locked -> "Pattern did not match. No attempts left. This request is locked."
                    is SubmitOutcome.Incomplete -> "Enter ${outcome.required} elements. ${outcome.entered} entered so far."
                    is SubmitOutcome.NotAccepting -> "This request is no longer accepting input."
                }
                onChanged(message)
            },
            modifier = Modifier.weight(1f).heightIn(min = MinTarget),
        ) { Text("Submit") }
    }

    Text("Attempts left: ${session.attemptsRemaining}", style = MaterialTheme.typography.bodyLarge)

    TextButton(
        onClick = {
            if (session.chooseDirectApproval()) onChanged("Direct approval chosen. Approve or deny the request.")
        },
        modifier = Modifier.heightIn(min = MinTarget),
    ) { Text("Skip the pattern and approve directly") }

    OutlinedButton(
        onClick = { session.recordDecision(approved = false); onChanged("Denied. Nothing was approved.") },
        modifier = Modifier.fillMaxWidth().heightIn(min = MinTarget),
    ) { Text("Deny request") }
}

@Composable
private fun ResultSection(
    session: PracticeSession,
    version: Int,
    onRestart: () -> Unit,
) {
    val stats = version.let { session.stats() }
    val title = when (stats.outcome) {
        LocalState.APPROVED -> "Approved"
        LocalState.DENIED -> "Denied"
        LocalState.LOCKED -> "Locked after 3 attempts"
        LocalState.EXPIRED -> "Expired"
        else -> stats.outcome.name
    }
    Text(title, style = MaterialTheme.typography.titleLarge)
    Text(
        buildString {
            append("Submissions: ${stats.submissions}. Mismatches: ${stats.failures}. Corrections: ${stats.corrections}.")
            stats.entryTimeMs?.let { append(" Entry time: ${"%.1f".format(it / 1000.0)} seconds.") }
        },
        style = MaterialTheme.typography.bodyLarge,
    )
    Button(onClick = onRestart, modifier = Modifier.fillMaxWidth().heightIn(min = LargeTarget)) {
        Text("Start new practice")
    }
}
