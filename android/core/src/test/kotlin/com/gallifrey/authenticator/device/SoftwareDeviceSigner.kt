package com.gallifrey.authenticator.device

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec

/**
 * TEST ONLY: an in-memory P-256 signer standing in for the Android Keystore.
 * Lets the JVM tests exercise the same SHA256withECDSA/DER format.
 */
class SoftwareDeviceSigner : DeviceSigner {
    private var keyPair: KeyPair? = null

    /** Next sign() call throws this, to simulate platform failures. */
    var failNextSignWith: Exception? = null

    var signCount = 0
        private set

    override fun hasKey() = keyPair != null

    override fun generateKey(): PublicKey {
        check(keyPair == null) { "Key already exists" }
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        return generator.generateKeyPair().also { keyPair = it }.public
    }

    override fun publicKey(): PublicKey = checkNotNull(keyPair) { "No key" }.public

    override fun sign(message: ByteArray): ByteArray {
        failNextSignWith?.let { failNextSignWith = null; throw it }
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(checkNotNull(keyPair) { "No key" }.private)
        signature.update(message)
        signCount++
        return signature.sign()
    }

    override fun deleteKey() {
        keyPair = null
    }

    override fun securityLevel() = KeySecurityLevel.SOFTWARE
}
