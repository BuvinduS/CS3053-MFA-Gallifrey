package com.gallifrey.authenticator.device

import com.gallifrey.authenticator.crypto.Base64Url
import com.gallifrey.authenticator.crypto.EnrollmentMessage
import com.gallifrey.authenticator.crypto.PublicKeys
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class SecureDeviceTest {

    private val signer = SoftwareDeviceSigner()
    private val device = SecureDevice(signer)
    private val deviceId = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    private fun enrollmentMessage(fingerprint: String) = EnrollmentMessage(
        enrollmentId = "0e9d8c7b-6a5f-4e3d-8c2b-1a0f9e8d7c6b",
        enrollmentNonce = Base64Url.encode(ByteArray(32) { 9 }),
        accountRef = "acct-42",
        deviceId = deviceId,
        publicKeyFingerprint = fingerprint,
    )

    @Test
    fun `enrollment generates a key and proves possession`() {
        val key = device.beginEnrollment()
        assertEquals(RegistrationStatus.PROVISIONAL, device.status)

        val message = enrollmentMessage(key.publicKeyFingerprint)
        val signature = device.signEnrollment(message)
        assertTrue(BackendVerifier.verify(key.publicKeySpki, message.toBytes(), signature))

        device.activate(deviceId)
        assertEquals(DeviceRegistration(RegistrationStatus.ACTIVE, deviceId), device.registration)
    }

    @Test
    fun `enrollment challenge for another key is refused`() {
        device.beginEnrollment()
        val other = Base64Url.encode(ByteArray(32))
        assertFailsWith<IllegalArgumentException> { device.signEnrollment(enrollmentMessage(other)) }
    }

    @Test
    fun `active device cannot silently replace its key`() {
        val key = device.beginEnrollment()
        device.activate(deviceId)
        assertFailsWith<IllegalStateException> { device.beginEnrollment() }
        assertEquals(key.publicKeyFingerprint, PublicKeys.fingerprint(signer.publicKey()))
    }

    @Test
    fun `revoked device can re-enroll with a new key`() {
        val first = device.beginEnrollment()
        device.activate(deviceId)
        device.markRevoked()
        assertEquals(RegistrationStatus.REVOKED, device.status)

        val second = device.beginEnrollment()
        assertNotEquals(first.publicKeySpki, second.publicKeySpki)
        assertEquals(RegistrationStatus.PROVISIONAL, device.status)
    }

    @Test
    fun `signing requires an active registration`() {
        assertFailsWith<IllegalStateException> { device.signForActiveDevice(byteArrayOf(1)) }
        device.beginEnrollment()
        assertFailsWith<IllegalStateException> { device.signForActiveDevice(byteArrayOf(1)) }
        device.activate(deviceId)
        device.signForActiveDevice(byteArrayOf(1))
        device.markRevoked()
        assertFailsWith<IllegalStateException> { device.signForActiveDevice(byteArrayOf(1)) }
    }

    @Test
    fun `invalidated key moves the device to KEY_INVALIDATED`() {
        device.beginEnrollment()
        device.activate(deviceId)
        signer.failNextSignWith = KeyInvalidatedException()
        assertFailsWith<KeyInvalidatedException> { device.signForActiveDevice(byteArrayOf(1)) }
        assertEquals(RegistrationStatus.KEY_INVALIDATED, device.status)
    }

    @Test
    fun `authentication required leaves the registration active`() {
        device.beginEnrollment()
        device.activate(deviceId)
        signer.failNextSignWith = UserAuthenticationRequiredException()
        assertFailsWith<UserAuthenticationRequiredException> { device.signForActiveDevice(byteArrayOf(1)) }
        assertEquals(RegistrationStatus.ACTIVE, device.status)
    }

    @Test
    fun `enrollment reports the key security level`() {
        assertEquals(KeySecurityLevel.SOFTWARE, device.beginEnrollment().securityLevel)
    }
}
