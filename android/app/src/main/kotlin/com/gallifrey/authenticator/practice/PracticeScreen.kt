package com.gallifrey.authenticator.practice

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.heading
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.gallifrey.authenticator.R
import com.gallifrey.authenticator.haptics.HapticEngine
import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.HapticTiming
import com.gallifrey.authenticator.input.GestureClassifier
import com.gallifrey.authenticator.input.HoldGestureArea
import com.gallifrey.authenticator.input.InputMode
import com.gallifrey.authenticator.input.InputModeSelector
import com.gallifrey.authenticator.ui.AdaptiveButtonRow
import com.gallifrey.authenticator.ui.FocusedHeading
import com.gallifrey.authenticator.verify.LocalState
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch

private val MinTarget = 56.dp
private const val EXPIRY_WARNING_MS = 30_000L
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
    val res = LocalContext.current.resources
    // PracticeSession is a plain object; bump this after every change to redraw.
    var version by remember { mutableIntStateOf(0) }
    var status by remember { mutableStateOf(res.getString(R.string.practice_status_start)) }
    var played by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun refresh(message: String? = null) {
        if (message != null) status = message
        version++
    }

    var remainingMs by remember { mutableLongStateOf(session.remainingMs()) }
    var warned by remember { mutableStateOf(false) }

    // Expiry happens with no user action, so re-check every second. One
    // spoken warning at 30 seconds (design D01: warn accessibly before expiry);
    // the visible countdown itself is not announced every second.
    LaunchedEffect(version) {
        while (true) {
            remainingMs = session.remainingMs()
            if (remainingMs > EXPIRY_WARNING_MS) warned = false
            val state = session.state
            when {
                state == LocalState.EXPIRED -> {
                    haptics.cancel()
                    refresh(res.getString(R.string.practice_status_expired))
                    break
                }
                state.isTerminal -> break
                !warned && remainingMs <= EXPIRY_WARNING_MS -> {
                    warned = true
                    status = res.getString(R.string.practice_status_expiry_warning)
                }
            }
            delay(1_000)
        }
    }

    val state = version.let { session.state }

    Column(
        modifier = modifier.verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text(
            stringResource(R.string.practice_title),
            style = MaterialTheme.typography.headlineMedium,
            modifier = Modifier.semantics { heading() },
        )
        Text(
            status,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
        )
        if (!state.isTerminal) TimeLeft(remainingMs)

        when (state) {
            LocalState.AWAITING_PATTERN -> EntrySection(
                session = session,
                version = version,
                timing = timing,
                played = played,
                onPlay = {
                    haptics.play(session.patternForPlayback(), timing)
                    played = true
                    refresh(res.getString(R.string.practice_status_playing))
                },
                onChanged = ::refresh,
            )

            LocalState.AWAITING_APPROVAL -> {
                FocusedHeading(stringResource(R.string.approve_question))
                Button(
                    onClick = {
                        scope.launch {
                            val signed = onApprove()
                            if (signed && session.canApprove) {
                                session.recordDecision(approved = true)
                                refresh(res.getString(R.string.practice_status_approved))
                            } else if (!signed) {
                                refresh(res.getString(R.string.practice_status_not_approved))
                            } else {
                                refresh()
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = LargeTarget),
                ) { Text(stringResource(R.string.approve)) }
                OutlinedButton(
                    onClick = {
                        session.recordDecision(approved = false)
                        refresh(res.getString(R.string.practice_status_denied))
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = LargeTarget),
                ) { Text(stringResource(R.string.deny)) }
            }

            else -> ResultSection(
                session = session,
                version = version,
                onRestart = {
                    haptics.cancel()
                    session.restart()
                    played = false
                    refresh(res.getString(R.string.practice_status_restarted))
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
    val res = LocalContext.current.resources
    val total = HapticPattern.DEFAULT_LENGTH
    val count = version.let { session.input.count }
    val classifier = remember(timing.holdThresholdMs) { GestureClassifier(timing) }

    FilledTonalButton(onClick = onPlay, modifier = Modifier.fillMaxWidth().heightIn(min = MinTarget)) {
        Text(stringResource(if (played) R.string.replay_pattern else R.string.play_pattern))
    }

    Text(stringResource(R.string.input_method), style = MaterialTheme.typography.titleMedium)
    InputModeSelector(
        selected = session.input.mode,
        onSelect = { mode ->
            session.switchMode(mode)
            onChanged(null)
        },
    )

    // Count only: the sequence itself is never shown or spoken.
    fun added(ok: Boolean) =
        onChanged(
            if (ok) res.getString(R.string.practice_status_entered, session.input.count, total)
            else res.getString(R.string.practice_status_full, total),
        )

    when (session.input.mode) {
        InputMode.BUTTONS -> AdaptiveButtonRow { itemModifier ->
            Button(
                onClick = { added(session.addDot()) },
                modifier = itemModifier.heightIn(min = LargeTarget),
            ) { Text(stringResource(R.string.dot), style = MaterialTheme.typography.titleLarge) }
            Button(
                onClick = { added(session.addDash()) },
                modifier = itemModifier.heightIn(min = LargeTarget),
            ) { Text(stringResource(R.string.dash), style = MaterialTheme.typography.titleLarge) }
        }

        InputMode.GESTURE -> HoldGestureArea(
            classifier = classifier,
            onElement = { added(session.addElement(it)) },
        )
    }

    EntryProgress(entered = count, total = total)

    AdaptiveButtonRow { itemModifier ->
        OutlinedButton(
            onClick = { if (session.removeLast()) onChanged(res.getString(R.string.practice_status_removed, session.input.count, total)) },
            enabled = count > 0,
            modifier = itemModifier.heightIn(min = MinTarget),
        ) { Text(stringResource(R.string.undo)) }
        OutlinedButton(
            onClick = { session.resetEntry(); onChanged(res.getString(R.string.practice_status_cleared, total)) },
            enabled = count > 0,
            modifier = itemModifier.heightIn(min = MinTarget),
        ) { Text(stringResource(R.string.reset)) }
        Button(
            onClick = {
                val message = when (val outcome = session.submit()) {
                    SubmitOutcome.Matched -> res.getString(R.string.practice_status_matched)
                    is SubmitOutcome.Mismatch -> res.getQuantityString(
                        R.plurals.practice_status_mismatch, outcome.attemptsRemaining, outcome.attemptsRemaining,
                    )
                    SubmitOutcome.Locked -> res.getString(R.string.practice_status_locked)
                    is SubmitOutcome.Incomplete ->
                        res.getString(R.string.practice_status_incomplete, outcome.required, outcome.entered)
                    is SubmitOutcome.NotAccepting -> res.getString(R.string.practice_status_not_accepting)
                }
                onChanged(message)
            },
            modifier = itemModifier.heightIn(min = MinTarget),
        ) { Text(stringResource(R.string.submit)) }
    }

    Text(stringResource(R.string.attempts_left, session.attemptsRemaining), style = MaterialTheme.typography.bodyLarge)

    TextButton(
        onClick = {
            if (session.chooseDirectApproval()) onChanged(res.getString(R.string.practice_status_direct))
        },
        modifier = Modifier.heightIn(min = MinTarget),
    ) { Text(stringResource(R.string.direct_approval)) }

    OutlinedButton(
        onClick = { session.recordDecision(approved = false); onChanged(res.getString(R.string.practice_status_denied)) },
        modifier = Modifier.fillMaxWidth().heightIn(min = MinTarget),
    ) { Text(stringResource(R.string.deny_request)) }
}

@Composable
private fun TimeLeft(remainingMs: Long) {
    val totalSeconds = (remainingMs + 999) / 1000
    val minutes = totalSeconds / 60
    val seconds = totalSeconds % 60
    val res = LocalContext.current.resources
    // "1:45" is shown; "1 minute 45 seconds" is what TalkBack reads.
    val duration = listOfNotNull(
        if (minutes > 0) res.getQuantityString(R.plurals.minutes, minutes.toInt(), minutes.toInt()) else null,
        res.getQuantityString(R.plurals.seconds, seconds.toInt(), seconds.toInt()),
    ).joinToString(" ")
    val spoken = res.getString(R.string.time_left_spoken, duration)
    Text(
        stringResource(R.string.time_left, minutes.toInt(), seconds.toInt()),
        style = MaterialTheme.typography.bodyLarge,
        color = if (remainingMs <= EXPIRY_WARNING_MS) MaterialTheme.colorScheme.error else LocalContentColor.current,
        modifier = Modifier.semantics { contentDescription = spoken },
    )
}

@Composable
private fun ResultSection(
    session: PracticeSession,
    version: Int,
    onRestart: () -> Unit,
) {
    val stats = version.let { session.stats() }
    val res = LocalContext.current.resources
    val title = when (stats.outcome) {
        LocalState.APPROVED -> res.getString(R.string.result_approved)
        LocalState.DENIED -> res.getString(R.string.result_denied)
        LocalState.LOCKED -> res.getString(R.string.result_locked)
        LocalState.EXPIRED -> res.getString(R.string.result_expired)
        else -> stats.outcome.name
    }
    FocusedHeading(title)
    Text(
        listOfNotNull(
            res.getString(R.string.result_stats, stats.submissions, stats.failures, stats.corrections),
            stats.entryTimeMs?.let { res.getString(R.string.result_entry_time, it / 1000.0) },
        ).joinToString(" "),
        style = MaterialTheme.typography.bodyLarge,
    )
    Button(onClick = onRestart, modifier = Modifier.fillMaxWidth().heightIn(min = LargeTarget)) {
        Text(stringResource(R.string.start_new_practice))
    }
}
