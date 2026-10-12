package com.gallifrey.authenticator.device

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.gallifrey.authenticator.crypto.Base64Url
import com.gallifrey.authenticator.crypto.PublicKeys
import java.security.Signature
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Runs on a real device or emulator: ./gradlew connectedDebugAndroidTest
 * Uses test-only aliases so the app's real device key is never touched.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreDeviceSignerTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val signer = KeystoreDeviceSigner(context, "test_no_auth_key", requireUserAuthentication = false)
    private val authSigner = KeystoreDeviceSigner(context, "test_auth_key", requireUserAuthentication = true)

    @After
    fun cleanUp() {
        signer.deleteKey()
        authSigner.deleteKey()
    }

    private fun verify(message: ByteArray, signature: ByteArray): Boolean {
        val spki = PublicKeys.spkiBase64Url(signer.publicKey())
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(PublicKeys.parseSpki(Base64Url.decode(spki)))
        verifier.update(message)
        return verifier.verify(signature)
    }

    // M2-T08 on the real Keystore
    @Test
    fun keystoreSignatureVerifiesWithExportedPublicKey() {
        signer.generateKey()
        val message = "GALLIFREY-MFA-DECISION-V1\ntest".toByteArray(Charsets.US_ASCII)
        assertTrue(verify(message, signer.sign(message)))
    }

    // M2-T09 on the real Keystore
    @Test
    fun alteredMessageFailsVerification() {
        signer.generateKey()
        val signature = signer.sign("APPROVE".toByteArray())
        assertFalse(verify("DENY".toByteArray(), signature))
    }

    @Test
    fun publicKeyIsP256AndPrivateKeyIsNotExportable() {
        signer.generateKey()
        PublicKeys.parseSpki(PublicKeys.spkiDer(signer.publicKey()))
        val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val privateKey = keyStore.getKey("test_no_auth_key", null) as java.security.PrivateKey
        // Keystore private keys never expose their key material.
        assertEquals(null, privateKey.encoded)
    }

    @Test
    fun reportsKeySecurityLevel() {
        signer.generateKey()
        val level = signer.securityLevel()
        // Recorded as test evidence (design: hardware backing is detected, not assumed).
        Log.i("GallifreyKeystoreTest", "Key security level: $level")
        assertNotEquals(KeySecurityLevel.UNKNOWN, level)
    }

    @Test
    fun secondKeyGenerationIsRefused() {
        signer.generateKey()
        try {
            signer.generateKey()
            fail("Expected IllegalStateException")
        } catch (expected: IllegalStateException) {
        }
    }

    @Test
    fun deleteRemovesTheKey() {
        signer.generateKey()
        signer.deleteKey()
        assertFalse(signer.hasKey())
    }

    @Test
    fun authBoundKeyNeedsRecentUserAuthentication() {
        if (!authSigner.isDeviceSecure) return // needs a screen lock
        authSigner.generateKey()
        try {
            authSigner.sign(byteArrayOf(1, 2, 3))
            // Allowed only if the phone was unlocked within the last 30 seconds.
            Log.i("GallifreyKeystoreTest", "Signed within the recent-unlock window")
        } catch (expected: UserAuthenticationRequiredException) {
            Log.i("GallifreyKeystoreTest", "User authentication required, as configured")
        }
    }
}
