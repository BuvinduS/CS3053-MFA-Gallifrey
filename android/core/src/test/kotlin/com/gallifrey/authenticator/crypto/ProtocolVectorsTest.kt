package com.gallifrey.authenticator.crypto

import com.gallifrey.authenticator.device.BackendVerifier
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Checks this client against the shared vectors in vectors/protocol-v1.json.
 * The auth service runs the same checks with Python `cryptography`, so both
 * sides agree on the exact signed bytes and signature encoding.
 */
class ProtocolVectorsTest {

    private val vectors: Map<String, String> = run {
        val text = checkNotNull(javaClass.getResource("/vectors/protocol-v1.json")).readText()
        // Flat "key": "value" pairs only, so a regex is enough without a JSON library.
        Regex("\"([a-z_]+)\":\\s*\"((?:[^\"\\\\]|\\\\.)*)\"")
            .findAll(text)
            .associate { it.groupValues[1] to it.groupValues[2].replace("\\n", "\n") }
    }

    private fun v(key: String) = checkNotNull(vectors[key]) { "missing vector $key" }

    private fun decision(decision: Decision) = DecisionMessage(
        transactionId = v("decision_transaction_id"),
        challengeNonce = v("decision_challenge_nonce"),
        accountId = v("decision_account_id"),
        deviceId = v("decision_device_id"),
        rpId = v("decision_rp_id"),
        loginBinding = v("decision_login_binding"),
        decision = decision,
        expiresAtEpochSeconds = v("decision_expires_at").toLong(),
    )

    @Test
    fun `approve message bytes match the vector and its signature verifies`() {
        val bytes = decision(Decision.APPROVE).toBytes()
        assertEquals(v("approve_message"), bytes.toString(Charsets.US_ASCII))
        assertTrue(BackendVerifier.verify(v("public_key_spki"), bytes, v("approve_signature")))
    }

    @Test
    fun `deny message bytes match the vector and its signature verifies`() {
        val bytes = decision(Decision.DENY).toBytes()
        assertEquals(v("deny_message"), bytes.toString(Charsets.US_ASCII))
        assertTrue(BackendVerifier.verify(v("public_key_spki"), bytes, v("deny_signature")))
    }

    @Test
    fun `deny signature does not verify as an approval`() {
        assertFalse(
            BackendVerifier.verify(v("public_key_spki"), decision(Decision.APPROVE).toBytes(), v("deny_signature")),
        )
    }

    @Test
    fun `enrollment message bytes match the vector and its signature verifies`() {
        val spki = Base64Url.decode(v("public_key_spki"))
        assertEquals(v("public_key_fingerprint"), PublicKeys.fingerprint(spki))

        val message = EnrollmentMessage(
            enrollmentId = v("enroll_enrollment_id"),
            enrollmentNonce = v("enroll_nonce"),
            accountRef = v("enroll_account_ref"),
            deviceId = v("enroll_device_id"),
            publicKeyFingerprint = v("public_key_fingerprint"),
        )
        assertEquals(v("enroll_message"), message.toBytes().toString(Charsets.US_ASCII))
        assertTrue(BackendVerifier.verify(v("public_key_spki"), message.toBytes(), v("enroll_signature")))
    }

    @Test
    fun `enrollment signature is not accepted as a decision`() {
        assertFalse(
            BackendVerifier.verify(v("public_key_spki"), decision(Decision.APPROVE).toBytes(), v("enroll_signature")),
        )
    }
}
