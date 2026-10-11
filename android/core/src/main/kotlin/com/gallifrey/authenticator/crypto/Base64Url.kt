package com.gallifrey.authenticator.crypto

import java.util.Base64

/**
 * base64url without padding, as used by the protocol for nonces, DER
 * signatures and DER SubjectPublicKeyInfo public keys (design section 10).
 * Decoding is strict: padding, non-alphabet characters and non-canonical
 * encodings are rejected.
 */
object Base64Url {
    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val decoder = Base64.getUrlDecoder()
    private val alphabet = Regex("^[A-Za-z0-9_-]*$")

    fun encode(bytes: ByteArray): String = encoder.encodeToString(bytes)

    fun decode(text: String): ByteArray {
        require(alphabet.matches(text)) { "Not unpadded base64url" }
        val bytes = try {
            decoder.decode(text)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("Not unpadded base64url", e)
        }
        // Reject encodings with non-zero spare bits, which would give two
        // strings for the same bytes.
        require(encode(bytes) == text) { "Non-canonical base64url" }
        return bytes
    }
}
