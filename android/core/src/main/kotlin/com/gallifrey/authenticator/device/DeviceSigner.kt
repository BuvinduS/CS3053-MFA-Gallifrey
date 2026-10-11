package com.gallifrey.authenticator.device

import java.security.PublicKey

/** Where the private key lives, as reported by the platform. Recorded as test evidence. */
enum class KeySecurityLevel { STRONGBOX, TRUSTED_ENVIRONMENT, SOFTWARE, UNKNOWN }

/** Signing failed because the platform wants the user to verify (biometric or device credential). */
class UserAuthenticationRequiredException(cause: Throwable? = null) :
    Exception("Recent device authentication is required", cause)

/**
 * The key can no longer be used (e.g. the screen lock was removed). The
 * device must be re-enrolled; a replacement key is never generated silently.
 */
class KeyInvalidatedException(cause: Throwable? = null) :
    Exception("The device key has been permanently invalidated", cause)

/**
 * Holds the device's ECDSA P-256 private key and signs with SHA256withECDSA.
 *
 * On Android this is backed by the Android Keystore (KeystoreDeviceSigner),
 * so the private key never leaves the platform and is never exposed to this
 * interface. Signatures are ASN.1 DER, as the backend expects.
 */
interface DeviceSigner {
    fun hasKey(): Boolean

    /** Generates a new key pair and returns its public key. Fails if a key already exists. */
    fun generateKey(): PublicKey

    fun publicKey(): PublicKey

    /**
     * @throws UserAuthenticationRequiredException when the user must verify first.
     * @throws KeyInvalidatedException when the key is permanently unusable.
     */
    fun sign(message: ByteArray): ByteArray

    fun deleteKey()

    fun securityLevel(): KeySecurityLevel
}
