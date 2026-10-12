package com.gallifrey.authenticator.crypto

import java.security.KeyFactory
import java.security.MessageDigest
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec

/**
 * Public-key encoding for registration: DER SubjectPublicKeyInfo, sent as
 * base64url (design section 10). Only NIST P-256 keys are accepted.
 */
object PublicKeys {
    private const val P256_FIELD_BITS = 256

    // Order n of the P-256 group; distinguishes it from other 256-bit curves.
    private val P256_ORDER = java.math.BigInteger(
        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16,
    )

    /** DER SubjectPublicKeyInfo of an EC P-256 key. */
    fun spkiDer(key: PublicKey): ByteArray {
        requireP256(key)
        return key.encoded
    }

    fun spkiBase64Url(key: PublicKey): String = Base64Url.encode(spkiDer(key))

    /** Parses and checks a DER SubjectPublicKeyInfo. */
    fun parseSpki(der: ByteArray): ECPublicKey {
        val key = try {
            KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(der))
        } catch (e: Exception) {
            throw IllegalArgumentException("Not an EC SubjectPublicKeyInfo", e)
        }
        requireP256(key)
        return key as ECPublicKey
    }

    /** base64url(SHA-256(DER SPKI)): identifies the key inside signed enrollment messages. */
    fun fingerprint(spkiDer: ByteArray): String =
        Base64Url.encode(MessageDigest.getInstance("SHA-256").digest(spkiDer))

    fun fingerprint(key: PublicKey): String = fingerprint(spkiDer(key))

    private fun requireP256(key: PublicKey) {
        require(key is ECPublicKey) { "Expected an EC public key" }
        val params = key.params
        require(params.curve.field.fieldSize == P256_FIELD_BITS && params.order == P256_ORDER) {
            "Expected a NIST P-256 key"
        }
    }
}
