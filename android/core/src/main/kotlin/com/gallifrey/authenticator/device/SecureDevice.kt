package com.gallifrey.authenticator.device

import com.gallifrey.authenticator.crypto.Base64Url
import com.gallifrey.authenticator.crypto.EnrollmentMessage
import com.gallifrey.authenticator.crypto.PublicKeys

/** Registration lifecycle of this phone's key (Appendix A, key lifecycle). */
enum class RegistrationStatus {
    /** No key, or a previous key was removed. */
    UNREGISTERED,

    /** Key generated and claimed with an enrollment token, but not yet activated. */
    PROVISIONAL,

    /** The service verified proof of possession and bound the public key. */
    ACTIVE,

    /** The service revoked this device (lost phone, replacement or recovery). */
    REVOKED,

    /** The platform invalidated the key; re-enrollment is required. */
    KEY_INVALIDATED,
}

/** What the app persists about registration. Contains no secret material. */
data class DeviceRegistration(
    val status: RegistrationStatus = RegistrationStatus.UNREGISTERED,
    val deviceId: String? = null,
)

/** Values sent to the service when claiming an enrollment token. */
data class EnrollmentKey(
    val publicKeySpki: String,
    val publicKeyFingerprint: String,
    val securityLevel: KeySecurityLevel,
)

/**
 * The phone's registered-device identity: owns the key lifecycle and refuses
 * to sign anything unless the registration state allows it.
 *
 * The private key stays inside [signer]; only public keys and signatures
 * leave this class. Callers persist [registration] after each change.
 */
class SecureDevice(
    private val signer: DeviceSigner,
    registration: DeviceRegistration = DeviceRegistration(),
) {
    var registration: DeviceRegistration = registration
        private set

    val status: RegistrationStatus get() = registration.status

    /**
     * Starts (re-)enrollment by generating a fresh key. Allowed when there is
     * no active registration; any old key from a revoked or invalidated
     * registration is deleted first. An ACTIVE device must be revoked through
     * the service before it can be replaced.
     */
    fun beginEnrollment(): EnrollmentKey {
        check(status != RegistrationStatus.ACTIVE) { "Revoke the active device before replacing its key" }
        if (signer.hasKey()) signer.deleteKey()
        val publicKey = signer.generateKey()
        registration = DeviceRegistration(RegistrationStatus.PROVISIONAL, deviceId = null)
        return EnrollmentKey(
            publicKeySpki = PublicKeys.spkiBase64Url(publicKey),
            publicKeyFingerprint = PublicKeys.fingerprint(publicKey),
            securityLevel = signer.securityLevel(),
        )
    }

    /** Signs the enrollment challenge to prove possession of the new key. */
    fun signEnrollment(message: EnrollmentMessage): String {
        check(status == RegistrationStatus.PROVISIONAL) { "No enrollment in progress" }
        require(message.publicKeyFingerprint == PublicKeys.fingerprint(signer.publicKey())) {
            "Enrollment challenge is for a different key"
        }
        return Base64Url.encode(signWithLifecycle(message.toBytes()))
    }

    /** The service activated the device after verifying the enrollment signature. */
    fun activate(deviceId: String) {
        check(status == RegistrationStatus.PROVISIONAL) { "No enrollment in progress" }
        registration = DeviceRegistration(RegistrationStatus.ACTIVE, deviceId)
    }

    /** The service reported this device as revoked. Signing stops immediately. */
    fun markRevoked() {
        registration = registration.copy(status = RegistrationStatus.REVOKED)
    }

    /** Signs exact protocol bytes for an ACTIVE device. Used by ApprovalSigner. */
    internal fun signForActiveDevice(message: ByteArray): ByteArray {
        check(status == RegistrationStatus.ACTIVE) { "Device is not active (status=$status)" }
        return signWithLifecycle(message)
    }

    private fun signWithLifecycle(message: ByteArray): ByteArray = try {
        signer.sign(message)
    } catch (e: KeyInvalidatedException) {
        registration = registration.copy(status = RegistrationStatus.KEY_INVALIDATED)
        throw e
    }
}
