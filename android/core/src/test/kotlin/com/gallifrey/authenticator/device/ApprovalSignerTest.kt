package com.gallifrey.authenticator.device

import com.gallifrey.authenticator.crypto.Base64Url
import com.gallifrey.authenticator.crypto.Decision
import com.gallifrey.authenticator.crypto.DecisionMessage
import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.PatternElement.DASH
import com.gallifrey.authenticator.haptics.PatternElement.DOT
import com.gallifrey.authenticator.verify.LocalState
import com.gallifrey.authenticator.verify.TransactionGuard
import com.gallifrey.authenticator.verify.VerifyResult
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class ApprovalSignerTest {

    private val txId = "3f2b8c1e-4d5a-4e6f-9a7b-8c9d0e1f2a3b"
    private val deviceId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
    private val expected = HapticPattern(listOf(DOT, DASH, DOT, DOT))
    private val wrong = HapticPattern(listOf(DASH, DASH, DASH, DASH))
    private var now = 1_790_000_000_000L

    private val signer = SoftwareDeviceSigner()
    private val device = SecureDevice(signer)
    private val approvals = ApprovalSigner(device)
    private lateinit var publicKeySpki: String

    @BeforeTest
    fun enroll() {
        publicKeySpki = device.beginEnrollment().publicKeySpki
        device.activate(deviceId)
    }

    private fun guard(id: String = txId) =
        TransactionGuard(id, expected, expiresAtMs = now + 120_000, clock = { now })

    private fun message(
        decision: Decision = Decision.APPROVE,
        transactionId: String = txId,
        nonce: String = Base64Url.encode(ByteArray(32) { 5 }),
        accountId: String = "11111111-2222-4333-8444-555555555555",
        rpId: String = "gallifrey-demo",
        loginBinding: String = "binding-abc",
        expiresAt: Long = now / 1000 + 120,
    ) = DecisionMessage(transactionId, nonce, accountId, deviceId, rpId, loginBinding, decision, expiresAt)

    private fun matchedGuard() = guard().also { assertEquals(VerifyResult.Matched, it.verify(expected)) }

    // M2-T08
    @Test
    fun `approval signature verifies with the registered public key`() {
        val g = matchedGuard()
        val msg = message()
        val signed = approvals.sign(g, msg)
        assertEquals(Decision.APPROVE, signed.decision)
        assertTrue(BackendVerifier.verify(publicKeySpki, msg.toBytes(), signed.signature))
        assertEquals(LocalState.APPROVED, g.currentState)
    }

    // M2-T09
    @Test
    fun `altering any signed field breaks verification`() {
        val msg = message()
        val signed = approvals.sign(matchedGuard(), msg)
        val altered = listOf(
            msg.copy(challengeNonce = Base64Url.encode(ByteArray(32) { 6 })),
            msg.copy(accountId = "99999999-2222-4333-8444-555555555555"),
            msg.copy(rpId = "evil-rp"),
            msg.copy(loginBinding = "binding-xyz"),
            msg.copy(decision = Decision.DENY),
            msg.copy(expiresAtEpochSeconds = msg.expiresAtEpochSeconds + 600),
            msg.copy(transactionId = "00000000-0000-4000-8000-000000000000"),
        )
        altered.forEach { assertFalse(BackendVerifier.verify(publicKeySpki, it.toBytes(), signed.signature), "$it") }
    }

    // M2-T10 (phone side): an old signature does not cover a new request,
    // and the same transaction cannot be signed twice.
    @Test
    fun `old signature does not verify for a new transaction or nonce`() {
        val old = message()
        val oldSig = approvals.sign(matchedGuard(), old).signature

        val newTx = "4f2b8c1e-4d5a-4e6f-9a7b-8c9d0e1f2a3b"
        val fresh = message(transactionId = newTx, nonce = Base64Url.encode(ByteArray(32) { 8 }))
        assertFalse(BackendVerifier.verify(publicKeySpki, fresh.toBytes(), oldSig))
    }

    @Test
    fun `same transaction cannot be signed twice`() {
        val g = matchedGuard()
        approvals.sign(g, message())
        assertFailsWith<DecisionNotAllowedException> { approvals.sign(g, message()) }
        assertEquals(1, signer.signCount)
    }

    // M2-T11
    @Test
    fun `deny produces a DENY signature and never an approval`() {
        val g = guard()
        val denyMsg = message(Decision.DENY)
        val signed = approvals.sign(g, denyMsg)
        assertEquals(Decision.DENY, signed.decision)
        assertTrue(BackendVerifier.verify(publicKeySpki, denyMsg.toBytes(), signed.signature))
        assertFalse(BackendVerifier.verify(publicKeySpki, message(Decision.APPROVE).toBytes(), signed.signature))
        assertEquals(LocalState.DENIED, g.currentState)
        assertFailsWith<DecisionNotAllowedException> { approvals.sign(g, message(Decision.APPROVE)) }
    }

    // M2-T12 (phone side)
    @Test
    fun `revoked device does not sign`() {
        val g = matchedGuard()
        device.markRevoked()
        assertFailsWith<IllegalStateException> { approvals.sign(g, message()) }
        assertEquals(0, signer.signCount)
        assertEquals(LocalState.AWAITING_APPROVAL, g.currentState)
    }

    @Test
    fun `approve without a matched pattern is refused`() {
        assertFailsWith<DecisionNotAllowedException> { approvals.sign(guard(), message()) }
        assertEquals(0, signer.signCount)
    }

    @Test
    fun `direct approval can be signed`() {
        val g = guard()
        assertTrue(g.chooseDirectApproval())
        approvals.sign(g, message())
        assertEquals(LocalState.APPROVED, g.currentState)
    }

    @Test
    fun `locked transaction cannot be approved`() {
        val g = guard()
        repeat(3) { g.verify(wrong) }
        assertFailsWith<DecisionNotAllowedException> { approvals.sign(g, message()) }
    }

    @Test
    fun `expired transaction cannot be approved or denied`() {
        val g = matchedGuard()
        now += 121_000
        assertFailsWith<DecisionNotAllowedException> { approvals.sign(g, message()) }
        assertFailsWith<DecisionNotAllowedException> { approvals.sign(g, message(Decision.DENY)) }
    }

    @Test
    fun `approval waits for pending failure reports`() {
        val g = guard()
        val event = assertIs<VerifyResult.Mismatch>(g.verify(wrong)).event
        g.verify(expected)
        assertFailsWith<DecisionNotAllowedException> { approvals.sign(g, message()) }
        g.acknowledgeFailure(event.eventId, 1)
        approvals.sign(g, message())
    }

    @Test
    fun `message for another transaction or device is refused`() {
        val g = matchedGuard()
        assertFailsWith<IllegalArgumentException> {
            approvals.sign(g, message(transactionId = "00000000-0000-4000-8000-000000000000"))
        }
        assertFailsWith<IllegalArgumentException> {
            approvals.sign(g, message().copy(deviceId = "bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee"))
        }
    }

    @Test
    fun `user authentication required leaves the transaction open for retry`() {
        val g = matchedGuard()
        signer.failNextSignWith = UserAuthenticationRequiredException()
        assertFailsWith<UserAuthenticationRequiredException> { approvals.sign(g, message()) }
        assertEquals(LocalState.AWAITING_APPROVAL, g.currentState)
        approvals.sign(g, message())
        assertEquals(LocalState.APPROVED, g.currentState)
    }
}
