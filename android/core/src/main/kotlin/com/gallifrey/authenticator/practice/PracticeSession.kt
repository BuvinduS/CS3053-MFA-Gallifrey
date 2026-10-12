package com.gallifrey.authenticator.practice

import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.PatternElement
import com.gallifrey.authenticator.haptics.PatternGenerator
import com.gallifrey.authenticator.input.GestureClassifier
import com.gallifrey.authenticator.input.InputMode
import com.gallifrey.authenticator.input.PatternInput
import com.gallifrey.authenticator.verify.LocalState
import com.gallifrey.authenticator.verify.TransactionGuard
import com.gallifrey.authenticator.verify.VerifyResult
import java.util.UUID

/** Outcome of submitting an entry, for the screen to announce. */
sealed interface SubmitOutcome {
    data object Matched : SubmitOutcome
    data class Mismatch(val attemptsRemaining: Int) : SubmitOutcome
    data object Locked : SubmitOutcome
    data class Incomplete(val required: Int, val entered: Int) : SubmitOutcome
    data class NotAccepting(val state: LocalState) : SubmitOutcome
}

/** Usability evidence for one practice round (design section 16). Contains no pattern data. */
data class PracticeStats(
    val inputMode: InputMode,
    val submissions: Int,
    val failures: Int,
    val corrections: Int,
    /** From the first entered element to the matching submission; null if never matched. */
    val entryTimeMs: Long?,
    val outcome: LocalState,
)

/**
 * One local practice round of the full approval flow: the same generator,
 * input buffer, three-attempt guard and explicit-approval rule as a real
 * request, without a server. Failure events are acknowledged locally because
 * there is no auth service to report them to.
 *
 * Playback, device verification and signing are done by the Android layer;
 * it calls [recordDecision] only after the signature was produced.
 */
class PracticeSession(
    private val generator: PatternGenerator = PatternGenerator(),
    classifier: GestureClassifier = GestureClassifier(),
    inputMode: InputMode = InputMode.BUTTONS,
    private val expiryMs: Long = DEFAULT_EXPIRY_MS,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private var pattern: HapticPattern = generator.generate()
    private var expiresAtMs: Long = 0
    private var guard: TransactionGuard = newGuard()

    val input = PatternInput(classifier = classifier, mode = inputMode)

    private var submissions = 0
    // PatternInput keeps a running total; stats count corrections per round.
    private var correctionsAtStart = 0
    private var firstElementAtMs: Long? = null
    private var matchedAfterMs: Long? = null

    val state: LocalState get() = guard.currentState
    val attemptsRemaining: Int get() = guard.attemptsRemaining
    val canEnter: Boolean get() = state == LocalState.AWAITING_PATTERN
    val canApprove: Boolean get() = guard.canApprove()
    val canDeny: Boolean get() = guard.canDeny()

    /** Milliseconds until this round expires; 0 once expired. */
    fun remainingMs(): Long = (expiresAtMs - clock()).coerceAtLeast(0)

    /** The pattern to hand to the HapticEngine. Never display, speak or log it. */
    fun patternForPlayback(): HapticPattern = pattern

    /** Starts a fresh round: new pattern, attempts and expiry. The input mode is kept. */
    fun restart() {
        pattern = generator.generate()
        guard = newGuard()
        input.reset()
        submissions = 0
        correctionsAtStart = input.corrections
        firstElementAtMs = null
        matchedAfterMs = null
    }

    fun addDot(): Boolean = add { input.addDot() }

    fun addDash(): Boolean = add { input.addDash() }

    fun addElement(element: PatternElement): Boolean = when (element) {
        PatternElement.DOT -> addDot()
        PatternElement.DASH -> addDash()
    }

    fun removeLast(): Boolean = canEnter && input.removeLast()

    /** Clears the entry only; attempts are not reset (design: reset never resets failures). */
    fun resetEntry() {
        input.reset()
    }

    fun switchMode(mode: InputMode) {
        input.switchMode(mode)
    }

    fun submit(): SubmitOutcome {
        if (canEnter && !input.isComplete) {
            // Report the real count; an incomplete entry is never an attempt.
            return SubmitOutcome.Incomplete(HapticPattern.DEFAULT_LENGTH, input.count)
        }
        val result = guard.verify(input.toPattern())
        if (result !is VerifyResult.Incomplete && result !is VerifyResult.Rejected) submissions++
        return when (result) {
            VerifyResult.Matched -> {
                matchedAfterMs = firstElementAtMs?.let { clock() - it }
                SubmitOutcome.Matched
            }
            is VerifyResult.Mismatch -> {
                guard.acknowledgeFailure(result.event.eventId, guard.failureCount)
                input.reset()
                SubmitOutcome.Mismatch(result.attemptsRemaining)
            }
            is VerifyResult.Locked -> {
                guard.acknowledgeFailure(result.event.eventId, guard.failureCount)
                input.reset()
                SubmitOutcome.Locked
            }
            is VerifyResult.Incomplete -> SubmitOutcome.Incomplete(result.required, result.entered)
            is VerifyResult.Rejected -> SubmitOutcome.NotAccepting(result.state)
        }
    }

    /** Direct approval: skip pattern reproduction, keep explicit approval and device verification. */
    fun chooseDirectApproval(): Boolean = guard.chooseDirectApproval()

    /** Records the user's explicit decision after the Android layer has signed it. */
    fun recordDecision(approved: Boolean) {
        guard.markDecided(approved)
    }

    fun stats(): PracticeStats = PracticeStats(
        inputMode = input.mode,
        submissions = submissions,
        failures = guard.failureCount,
        corrections = input.corrections - correctionsAtStart,
        entryTimeMs = matchedAfterMs,
        outcome = state,
    )

    override fun toString(): String = "PracticeSession(state=$state, entered=${input.count})"

    private fun add(action: () -> Boolean): Boolean {
        if (!canEnter) return false
        val added = action()
        if (added && firstElementAtMs == null) firstElementAtMs = clock()
        return added
    }

    private fun newGuard(): TransactionGuard {
        expiresAtMs = clock() + expiryMs
        return TransactionGuard(
            transactionId = "practice-" + UUID.randomUUID(),
            expected = pattern,
            expiresAtMs = expiresAtMs,
            clock = clock,
        )
    }

    companion object {
        /** Same as a real request (design D01). */
        const val DEFAULT_EXPIRY_MS = 120_000L
    }
}
