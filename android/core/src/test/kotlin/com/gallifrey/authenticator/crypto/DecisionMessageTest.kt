package com.gallifrey.authenticator.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class DecisionMessageTest {

    private val nonce = Base64Url.encode(ByteArray(32) { 7 })

    private fun message(
        transactionId: String = "3f2b8c1e-4d5a-4e6f-9a7b-8c9d0e1f2a3b",
        challengeNonce: String = nonce,
        accountId: String = "11111111-2222-4333-8444-555555555555",
        deviceId: String = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        rpId: String = "gallifrey-demo",
        loginBinding: String = "Zm9vYmFyYmF6",
        decision: Decision = Decision.APPROVE,
        expiresAt: Long = 1_790_000_000,
    ) = DecisionMessage(transactionId, challengeNonce, accountId, deviceId, rpId, loginBinding, decision, expiresAt)

    @Test
    fun `serializes the exact canonical byte sequence`() {
        val expected = "GALLIFREY-MFA-DECISION-V1\n" +
            "3f2b8c1e-4d5a-4e6f-9a7b-8c9d0e1f2a3b\n" +
            "$nonce\n" +
            "11111111-2222-4333-8444-555555555555\n" +
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n" +
            "gallifrey-demo\n" +
            "Zm9vYmFyYmF6\n" +
            "APPROVE\n" +
            "1790000000"
        assertEquals(expected, message().toBytes().toString(Charsets.US_ASCII))
    }

    @Test
    fun `has no trailing newline`() {
        val bytes = message(decision = Decision.DENY).toBytes()
        assertEquals('0'.code.toByte(), bytes.last())
    }

    @Test
    fun `rejects upper-case or non-canonical UUIDs`() {
        assertFailsWith<IllegalArgumentException> { message(transactionId = "3F2B8C1E-4D5A-4E6F-9A7B-8C9D0E1F2A3B") }
        assertFailsWith<IllegalArgumentException> { message(deviceId = "aaaaaaaabbbb4ccc8dddeeeeeeeeeeee") }
    }

    @Test
    fun `rejects a nonce that is not 32 bytes`() {
        assertFailsWith<IllegalArgumentException> { message(challengeNonce = Base64Url.encode(ByteArray(16))) }
        assertFailsWith<IllegalArgumentException> { message(challengeNonce = "not base64!") }
    }

    @Test
    fun `rejects line breaks and whitespace that could inject fields`() {
        assertFailsWith<IllegalArgumentException> { message(rpId = "demo\nAPPROVE") }
        assertFailsWith<IllegalArgumentException> { message(loginBinding = "a b") }
        assertFailsWith<IllegalArgumentException> { message(rpId = "") }
    }

    @Test
    fun `rejects non-ASCII and oversized fields`() {
        assertFailsWith<IllegalArgumentException> { message(rpId = "gallifréy") }
        assertFailsWith<IllegalArgumentException> { message(loginBinding = "a".repeat(129)) }
    }

    @Test
    fun `rejects a non-positive expiry`() {
        assertFailsWith<IllegalArgumentException> { message(expiresAt = 0) }
    }
}
