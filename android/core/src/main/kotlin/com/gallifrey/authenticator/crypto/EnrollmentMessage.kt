package com.gallifrey.authenticator.crypto

/**
 * The bytes signed to prove possession of a newly generated key during
 * enrollment (unified design section 8). Same line format as
 * [DecisionMessage] but with its own purpose/version prefix, so an enrollment
 * signature can never be accepted as a login decision or vice versa.
 *
 *   GALLIFREY-MFA-ENROLL-V1
 *   enrollment_id          lower-case canonical UUID
 *   enrollment_nonce       base64url of 32 random bytes
 *   account_ref            account reference supplied by the service
 *   device_id              lower-case canonical UUID
 *   public_key_fingerprint base64url(SHA-256(DER SPKI))
 */
data class EnrollmentMessage(
    val enrollmentId: String,
    val enrollmentNonce: String,
    val accountRef: String,
    val deviceId: String,
    val publicKeyFingerprint: String,
) {
    init {
        ProtocolFields.requireUuid("enrollment_id", enrollmentId)
        ProtocolFields.requireNonce("enrollment_nonce", enrollmentNonce)
        ProtocolFields.requireToken("account_ref", accountRef)
        ProtocolFields.requireUuid("device_id", deviceId)
        val digest = try {
            Base64Url.decode(publicKeyFingerprint)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("public_key_fingerprint must be base64url", e)
        }
        require(digest.size == SHA256_BYTES) { "public_key_fingerprint must be a SHA-256 digest" }
    }

    fun toBytes(): ByteArray = listOf(
        PREFIX,
        enrollmentId,
        enrollmentNonce,
        accountRef,
        deviceId,
        publicKeyFingerprint,
    ).joinToString("\n").toByteArray(Charsets.US_ASCII)

    companion object {
        const val PREFIX = "GALLIFREY-MFA-ENROLL-V1"
        private const val SHA256_BYTES = 32
    }
}
