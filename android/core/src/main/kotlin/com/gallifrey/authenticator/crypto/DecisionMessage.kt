package com.gallifrey.authenticator.crypto

/** The user's decision for one transaction. */
enum class Decision { APPROVE, DENY }

/**
 * The exact bytes the phone signs for a login decision (unified design
 * section 10). The individual design sketched a JSON payload; the unified
 * design replaces it with this fixed line format so the client and backend
 * always sign and verify the same byte sequence.
 *
 * Fields are strict ASCII, joined with a single LF, in this order, with no
 * trailing newline:
 *
 *   GALLIFREY-MFA-DECISION-V1
 *   transaction_id     lower-case canonical UUID
 *   challenge_nonce    base64url (no padding) of 32 random bytes
 *   account_id         lower-case canonical UUID
 *   device_id          lower-case canonical UUID
 *   rp_id              registered relying-party identifier
 *   login_binding      random binding created by the RP
 *   APPROVE or DENY
 *   expires_at         decimal Unix seconds
 *
 * All values come from the server's request details; the phone adds only the
 * decision. Construction fails for any malformed field instead of signing it.
 */
data class DecisionMessage(
    val transactionId: String,
    val challengeNonce: String,
    val accountId: String,
    val deviceId: String,
    val rpId: String,
    val loginBinding: String,
    val decision: Decision,
    val expiresAtEpochSeconds: Long,
) {
    init {
        ProtocolFields.requireUuid("transaction_id", transactionId)
        ProtocolFields.requireNonce("challenge_nonce", challengeNonce)
        ProtocolFields.requireUuid("account_id", accountId)
        ProtocolFields.requireUuid("device_id", deviceId)
        ProtocolFields.requireToken("rp_id", rpId)
        ProtocolFields.requireToken("login_binding", loginBinding)
        require(expiresAtEpochSeconds > 0) { "expires_at must be positive" }
    }

    fun toBytes(): ByteArray = listOf(
        PREFIX,
        transactionId,
        challengeNonce,
        accountId,
        deviceId,
        rpId,
        loginBinding,
        decision.name,
        expiresAtEpochSeconds.toString(),
    ).joinToString("\n").toByteArray(Charsets.US_ASCII)

    companion object {
        const val PREFIX = "GALLIFREY-MFA-DECISION-V1"
    }
}

/** Validation shared by every signed protocol message. */
internal object ProtocolFields {
    const val NONCE_BYTES = 32
    const val MAX_TOKEN_LENGTH = 128

    private val uuid = Regex("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

    // Printable ASCII without spaces: no LF, CR or other separators can sneak in.
    private val token = Regex("^[\\x21-\\x7E]+$")

    fun requireUuid(name: String, value: String) {
        require(uuid.matches(value)) { "$name must be a lower-case canonical UUID" }
    }

    fun requireNonce(name: String, value: String) {
        val bytes = try {
            Base64Url.decode(value)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("$name must be base64url", e)
        }
        require(bytes.size == NONCE_BYTES) { "$name must encode $NONCE_BYTES bytes" }
    }

    fun requireToken(name: String, value: String) {
        require(value.length in 1..MAX_TOKEN_LENGTH) { "$name length must be 1..$MAX_TOKEN_LENGTH" }
        require(token.matches(value)) { "$name must be printable ASCII without whitespace" }
    }
}
