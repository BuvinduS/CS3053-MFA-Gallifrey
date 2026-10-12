package com.gallifrey.authenticator.crypto

import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class PublicKeysTest {

    private fun ecKey(curve: String) = KeyPairGenerator.getInstance("EC")
        .apply { initialize(ECGenParameterSpec(curve)) }
        .generateKeyPair().public

    @Test
    fun `P-256 key round trips through SPKI`() {
        val key = ecKey("secp256r1")
        val parsed = PublicKeys.parseSpki(Base64Url.decode(PublicKeys.spkiBase64Url(key)))
        assertEquals(key, parsed)
    }

    @Test
    fun `fingerprint is a base64url SHA-256 digest`() {
        val key = ecKey("secp256r1")
        val fp = PublicKeys.fingerprint(key)
        assertEquals(43, fp.length)
        assertEquals(fp, PublicKeys.fingerprint(PublicKeys.spkiDer(key)))
    }

    @Test
    fun `other curves and key types are rejected`() {
        assertFailsWith<IllegalArgumentException> { PublicKeys.spkiDer(ecKey("secp384r1")) }
        val rsa = KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair().public
        assertFailsWith<IllegalArgumentException> { PublicKeys.spkiDer(rsa) }
        assertFailsWith<IllegalArgumentException> { PublicKeys.parseSpki(rsa.encoded) }
    }

    @Test
    fun `malformed SPKI is rejected`() {
        assertFailsWith<IllegalArgumentException> { PublicKeys.parseSpki(byteArrayOf(1, 2, 3)) }
    }
}
