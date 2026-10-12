package com.gallifrey.authenticator.verify

import com.gallifrey.authenticator.haptics.HapticPattern
import java.security.MessageDigest
import java.util.UUID

/** Local (phone-side) state of one authentication transaction. */
enum class LocalState {
    /** Waiting for the user to reproduce the pattern. */
    AWAITING_PATTERN,

    /** Pattern matched, or direct approval chosen: waiting for explicit Approve/Deny. */
    AWAITING_APPROVAL,

    /** Three mismatches: this transaction can no longer be approved. */
    LOCKED,

    /** Past the server-supplied expiry. */
    EXPIRED,

    /** A signed APPROVE was produced. */
    APPROVED,

    /** A signed DENY was produced. */
    DENIED;

    val isTerminal: Boolean get() = this == LOCKED || this == EXPIRED || this == APPROVED || this == DENIED
}

/**
 * A mismatch report for the auth service. Carries a unique event ID (so a
 * retried delivery cannot increment the count twice) and never the expected
 * or entered pattern.
 */
data class FailureEvent(val eventId: String, val transactionId: String)

sealed interface VerifyResult {
    /** Pattern matched. Explicit approval is still required (M2 "explicit approval"). */
    data object Matched : VerifyResult

    /** Wrong pattern; report [event] to the server. */
    data class Mismatch(val event: FailureEvent, val attemptsRemaining: Int) : VerifyResult

    /** Wrong pattern and this was the last attempt; report [event] to the server. */
    data class Locked(val event: FailureEvent) : VerifyResult

    /** Entry is not the required length. Does not count as an attempt. */
    data class Incomplete(val required: Int, val entered: Int) : VerifyResult

    /** Rejected without comparing, because the transaction is not accepting input. */
    data class Rejected(val state: LocalState) : VerifyResult
}

/**
 * Enforces design sections 10 (individual) and 7 (unified) on the phone:
 *
 *   if expired            -> reject
 *   if failures >= 3      -> locked
 *   if entered != expected-> failure event, failures++
 *   else                  -> ask for explicit approval
 *
 * The three-attempt rule is a user-flow control, not a defence based on pattern
 * entropy. The server's failure count is authoritative: a guard is always
 * rebuilt from fetched server state, so an earlier local match never survives
 * an app restart.
 *
 * @param expiresAtMs server-supplied expiry, as epoch milliseconds.
 * @param clock returns the current epoch milliseconds (injectable for tests).
 */
class TransactionGuard(
    val transactionId: String,
    private val expected: HapticPattern,
    private val expiresAtMs: Long,
    serverFailureCount: Int = 0,
    private val clock: () -> Long = System::currentTimeMillis,
    private val newEventId: () -> String = { UUID.randomUUID().toString() },
) {
    init {
        require(serverFailureCount in 0..MAX_ATTEMPTS) { "failure count must be 0..$MAX_ATTEMPTS" }
    }

    var failureCount: Int = serverFailureCount
        private set

    private var state: LocalState =
        if (serverFailureCount >= MAX_ATTEMPTS) LocalState.LOCKED else LocalState.AWAITING_PATTERN

    private val unacknowledged = LinkedHashMap<String, FailureEvent>()

    /** Current state; moves to EXPIRED automatically once the expiry passes. */
    val currentState: LocalState
        get() {
            if (!state.isTerminal && isExpired()) state = LocalState.EXPIRED
            return state
        }

    val attemptsRemaining: Int get() = (MAX_ATTEMPTS - failureCount).coerceAtLeast(0)

    /** Failure events that have not been acknowledged by the server yet. */
    val pendingFailureEvents: List<FailureEvent> get() = unacknowledged.values.toList()

    fun isExpired(): Boolean = clock() >= expiresAtMs

    fun verify(entered: HapticPattern?): VerifyResult {
        val current = currentState
        if (current != LocalState.AWAITING_PATTERN) return VerifyResult.Rejected(current)

        if (entered == null || entered.size != expected.size) {
            return VerifyResult.Incomplete(expected.size, entered?.size ?: 0)
        }

        if (constantTimeEquals(expected, entered)) {
            state = LocalState.AWAITING_APPROVAL
            return VerifyResult.Matched
        }

        val event = FailureEvent(newEventId(), transactionId)
        unacknowledged[event.eventId] = event
        failureCount++
        return if (failureCount >= MAX_ATTEMPTS) {
            state = LocalState.LOCKED
            VerifyResult.Locked(event)
        } else {
            VerifyResult.Mismatch(event, attemptsRemaining)
        }
    }

    /**
     * Direct approval (FR03): skip pattern reproduction but keep request review,
     * explicit approval and device verification. Only allowed before lockout.
     */
    fun chooseDirectApproval(): Boolean {
        if (currentState != LocalState.AWAITING_PATTERN) return false
        state = LocalState.AWAITING_APPROVAL
        return true
    }

    /**
     * Records the server's acknowledgement of a failure event. The server count
     * is authoritative, but never lowers the local count.
     */
    fun acknowledgeFailure(eventId: String, serverFailureCount: Int) {
        unacknowledged.remove(eventId)
        if (serverFailureCount > failureCount) failureCount = serverFailureCount.coerceAtMost(MAX_ATTEMPTS)
        if (failureCount >= MAX_ATTEMPTS && !state.isTerminal) state = LocalState.LOCKED
    }

    /** True when an APPROVE may be signed now. */
    fun canApprove(): Boolean =
        currentState == LocalState.AWAITING_APPROVAL && unacknowledged.isEmpty()

    /** True when a DENY may be signed now. Deny is available at any point before a terminal state. */
    fun canDeny(): Boolean = !currentState.isTerminal

    /** Called once a decision has been signed, so the same transaction cannot be decided twice. */
    fun markDecided(approved: Boolean) {
        check(if (approved) canApprove() else canDeny()) { "Decision not allowed in state $state" }
        state = if (approved) LocalState.APPROVED else LocalState.DENIED
    }

    override fun toString(): String =
        "TransactionGuard(tx=$transactionId, state=$state, failures=$failureCount)"

    companion object {
        /** Maximum mismatches per transaction (M2-R07 / D02). */
        const val MAX_ATTEMPTS = 3

        private fun constantTimeEquals(a: HapticPattern, b: HapticPattern): Boolean =
            MessageDigest.isEqual(a.toBytes(), b.toBytes())

        private fun HapticPattern.toBytes(): ByteArray =
            ByteArray(size) { elements[it].ordinal.toByte() }
    }
}
