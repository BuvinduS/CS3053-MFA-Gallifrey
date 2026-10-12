package com.gallifrey.authenticator.device

import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * DeviceSigner backed by the Android Keystore (design section 11).
 *
 *  - ECDSA on NIST P-256 with SHA-256, signatures in ASN.1 DER.
 *  - The private key is generated inside the Keystore and is non-exportable;
 *    this class only ever holds a handle to it.
 *  - Use requires Android user verification (strong biometric or device
 *    credential) within the last [AUTH_VALIDITY_SECONDS] seconds.
 *  - StrongBox is used when the device has it, otherwise the regular
 *    (TEE or software) Keystore. The level is reported, never assumed.
 *  - Removing the screen lock permanently invalidates the key; that surfaces
 *    as KeyInvalidatedException and requires re-enrollment.
 */
class KeystoreDeviceSigner internal constructor(
    private val context: Context,
    private val alias: String,
    // Only instrumented tests turn this off, to check signatures end to end
    // without a person present. The app always uses the public constructor.
    private val requireUserAuthentication: Boolean,
) : DeviceSigner {

    constructor(context: Context) : this(context, DEFAULT_ALIAS, requireUserAuthentication = true)

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /** A secure lock screen is required before a user-authenticated key can be created. */
    val isDeviceSecure: Boolean
        get() = context.getSystemService(KeyguardManager::class.java).isDeviceSecure

    override fun hasKey(): Boolean = keyStore.containsAlias(alias)

    override fun generateKey(): PublicKey {
        check(!hasKey()) { "A device key already exists" }
        if (requireUserAuthentication) {
            check(isDeviceSecure) { "Set a screen lock before enrolling this device" }
        }
        val hasStrongBox = context.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        if (hasStrongBox) {
            try {
                return generate(strongBox = true)
            } catch (e: StrongBoxUnavailableException) {
                // Fall through to the regular Keystore.
            }
        }
        return generate(strongBox = false)
    }

    override fun publicKey(): PublicKey =
        checkNotNull(keyStore.getCertificate(alias)) { "No device key" }.publicKey

    override fun sign(message: ByteArray): ByteArray {
        val signature = Signature.getInstance(SIGNATURE_ALGORITHM)
        try {
            signature.initSign(privateKey())
        } catch (e: UserNotAuthenticatedException) {
            throw UserAuthenticationRequiredException(e)
        } catch (e: KeyPermanentlyInvalidatedException) {
            throw KeyInvalidatedException(e)
        }
        signature.update(message)
        return signature.sign()
    }

    override fun deleteKey() {
        if (hasKey()) keyStore.deleteEntry(alias)
    }

    override fun securityLevel(): KeySecurityLevel {
        val key = privateKey()
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE).getKeySpec(key, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeySecurityLevel.TRUSTED_ENVIRONMENT
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeySecurityLevel.SOFTWARE
                else -> KeySecurityLevel.UNKNOWN
            }
        }
        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) KeySecurityLevel.TRUSTED_ENVIRONMENT else KeySecurityLevel.SOFTWARE
    }

    private fun privateKey(): PrivateKey =
        checkNotNull(keyStore.getKey(alias, null) as PrivateKey?) { "No device key" }

    private fun generate(strongBox: Boolean): PublicKey {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec(CURVE))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(strongBox)
            .apply {
                if (requireUserAuthentication) {
                    setUserAuthenticationRequired(true)
                    setUserAuthenticationParameters(
                        AUTH_VALIDITY_SECONDS,
                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                    )
                }
            }
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        generator.initialize(spec)
        return generator.generateKeyPair().public
    }

    companion object {
        const val DEFAULT_ALIAS = "gallifrey_device_signing_key"

        /** Recent device authentication window (design D04). */
        const val AUTH_VALIDITY_SECONDS = 30

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val CURVE = "secp256r1"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }
}
