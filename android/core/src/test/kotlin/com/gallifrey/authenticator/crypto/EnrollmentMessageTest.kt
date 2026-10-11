package com.gallifrey.authenticator.crypto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class EnrollmentMessageTest {

    private val nonce = Base64Url.encode(ByteArray(32) { 1 })
    private val fingerprint = Base64Url.encode(ByteArray(32) { 2 })

    private fun message(fp: String = fingerprint) = EnrollmentMessage(
        enrollmentId = "0e9d8c7b-6a5f-4e3d-8c2b-1a0f9e8d7c6b",
        enrollmentNonce = nonce,
        accountRef = "acct-42",
        deviceId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee",
        publicKeyFingerprint = fp,
    )

    @Test
    fun `serializes with the enrollment prefix`() {
        val expected = "GALLIFREY-MFA-ENROLL-V1\n" +
            "0e9d8c7b-6a5f-4e3d-8c2b-1a0f9e8d7c6b\n" +
            "$nonce\n" +
            "acct-42\n" +
            "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee\n" +
            fingerprint
        assertEquals(expected, message().toBytes().toString(Charsets.US_ASCII))
    }

    @Test
    fun `enrollment and decision prefixes differ`() {
        assertTrue(EnrollmentMessage.PREFIX != DecisionMessage.PREFIX)
    }

    @Test
    fun `rejects a fingerprint that is not a SHA-256 digest`() {
        assertFailsWith<IllegalArgumentException> { message(fp = Base64Url.encode(ByteArray(20))) }
        assertFailsWith<IllegalArgumentException> { message(fp = "x y") }
    }
}
