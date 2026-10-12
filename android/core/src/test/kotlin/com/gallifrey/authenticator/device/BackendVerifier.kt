package com.gallifrey.authenticator.device

import com.gallifrey.authenticator.crypto.Base64Url
import com.gallifrey.authenticator.crypto.PublicKeys
import java.security.Signature

/**
 * TEST ONLY: mirrors what the auth service does with the registered public
 * key (base64url DER SPKI) and a base64url DER signature.
 */
object BackendVerifier {
    fun verify(publicKeySpki: String, message: ByteArray, signatureB64: String): Boolean {
        val key = PublicKeys.parseSpki(Base64Url.decode(publicKeySpki))
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(key)
        verifier.update(message)
        return try {
            verifier.verify(Base64Url.decode(signatureB64))
        } catch (e: java.security.SignatureException) {
            false
        }
    }
}
