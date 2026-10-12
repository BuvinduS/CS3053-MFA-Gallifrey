package com.gallifrey.authenticator.verify

import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.PatternElement.DASH
import com.gallifrey.authenticator.haptics.PatternElement.DOT
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class TransactionGuardTest {

    private val expected = HapticPattern(listOf(DOT, DASH, DOT, DOT))
    private val wrong = HapticPattern(listOf(DASH, DASH, DOT, DOT))
    private var now = 1_000_000L

    private fun guard(failures: Int = 0) = TransactionGuard(
        transactionId = "tx-1",
        expected = expected,
        expiresAtMs = now + 120_000,
        serverFailureCount = failures,
        clock = { now },
    )

    // M2-T02
    @Test
    fun `correct pattern is accepted and asks for explicit approval`() {
        val g = guard()
        assertEquals(VerifyResult.Matched, g.verify(expected))
        assertEquals(LocalState.AWAITING_APPROVAL, g.currentState)
        assertTrue(g.canApprove())
    }

    // M2-T03
    @Test
    fun `incorrect pattern increases the attempt count`() {
        val g = guard()
        val result = assertIs<VerifyResult.Mismatch>(g.verify(wrong))
        assertEquals(1, g.failureCount)
        assertEquals(2, result.attemptsRemaining)
        assertEquals("tx-1", result.event.transactionId)
        assertEquals(LocalState.AWAITING_PATTERN, g.currentState)
    }

    // M2-T04
    @Test
    fun `three failures lock the transaction`() {
        val g = guard()
        assertIs<VerifyResult.Mismatch>(g.verify(wrong))
        assertIs<VerifyResult.Mismatch>(g.verify(wrong))
        assertIs<VerifyResult.Locked>(g.verify(wrong))
        assertEquals(LocalState.LOCKED, g.currentState)
        // Even the correct pattern is now rejected.
        assertEquals(VerifyResult.Rejected(LocalState.LOCKED), g.verify(expected))
        assertFalse(g.canApprove())
        assertFalse(g.chooseDirectApproval())
    }

    @Test
    fun `server failure count is carried over after restart`() {
        val g = guard(failures = 2)
        assertEquals(1, g.attemptsRemaining)
        assertIs<VerifyResult.Locked>(g.verify(wrong))
    }

    @Test
    fun `transaction already at three failures starts locked`() {
        assertEquals(LocalState.LOCKED, guard(failures = 3).currentState)
    }

    // M2-T05
    @Test
    fun `expired transaction rejects input`() {
        val g = guard()
        now += 120_000
        assertEquals(VerifyResult.Rejected(LocalState.EXPIRED), g.verify(expected))
        assertEquals(LocalState.EXPIRED, g.currentState)
    }

    @Test
    fun `expiry after a match blocks approval`() {
        val g = guard()
        g.verify(expected)
        now += 200_000
        assertFalse(g.canApprove())
        assertFalse(g.canDeny())
    }

    @Test
    fun `incomplete entry is not an attempt`() {
        val g = guard()
        assertEquals(VerifyResult.Incomplete(4, 0), g.verify(null))
        assertEquals(VerifyResult.Incomplete(4, 2), g.verify(HapticPattern(listOf(DOT, DOT))))
        assertEquals(0, g.failureCount)
    }

    @Test
    fun `approval waits for failure events to be acknowledged`() {
        val g = guard()
        val event = assertIs<VerifyResult.Mismatch>(g.verify(wrong)).event
        g.verify(expected)
        assertFalse(g.canApprove())
        assertEquals(listOf(event), g.pendingFailureEvents)

        g.acknowledgeFailure(event.eventId, serverFailureCount = 1)
        assertTrue(g.canApprove())
    }

    @Test
    fun `each failure event has a unique id`() {
        val g = guard()
        val first = assertIs<VerifyResult.Mismatch>(g.verify(wrong)).event
        val second = assertIs<VerifyResult.Mismatch>(g.verify(wrong)).event
        assertNotEquals(first.eventId, second.eventId)
    }

    @Test
    fun `server acknowledgement can raise but never lower the count`() {
        val g = guard()
        val event = assertIs<VerifyResult.Mismatch>(g.verify(wrong)).event
        g.acknowledgeFailure(event.eventId, serverFailureCount = 0)
        assertEquals(1, g.failureCount)
        g.acknowledgeFailure(event.eventId, serverFailureCount = 3)
        assertEquals(LocalState.LOCKED, g.currentState)
    }

    @Test
    fun `direct approval skips the pattern but still needs a decision`() {
        val g = guard(failures = 1)
        assertTrue(g.chooseDirectApproval())
        assertEquals(LocalState.AWAITING_APPROVAL, g.currentState)
        assertEquals(1, g.failureCount)
    }

    @Test
    fun `deny is allowed before a match`() {
        val g = guard()
        assertTrue(g.canDeny())
        g.markDecided(approved = false)
        assertEquals(LocalState.DENIED, g.currentState)
    }

    @Test
    fun `a transaction cannot be decided twice`() {
        val g = guard()
        g.verify(expected)
        g.markDecided(approved = true)
        assertEquals(LocalState.APPROVED, g.currentState)
        assertFailsWith<IllegalStateException> { g.markDecided(approved = true) }
        assertFailsWith<IllegalStateException> { g.markDecided(approved = false) }
    }

    @Test
    fun `approve without a match is refused`() {
        assertFailsWith<IllegalStateException> { guard().markDecided(approved = true) }
    }

    @Test
    fun `toString does not reveal the pattern`() {
        val text = guard().toString()
        assertFalse(text.contains("DOT") || text.contains("DASH"))
    }
}
