package com.gallifrey.authenticator.crypto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class Base64UrlTest {

    @Test
    fun `encodes without padding using the url alphabet`() {
        assertEquals("-_8", Base64Url.encode(byteArrayOf(0xFB.toByte(), 0xFF.toByte())))
        assertEquals("AQ", Base64Url.encode(byteArrayOf(1)))
    }

    @Test
    fun `round trips`() {
        val bytes = ByteArray(32) { it.toByte() }
        assertContentEquals(bytes, Base64Url.decode(Base64Url.encode(bytes)))
    }

    @Test
    fun `rejects padding and the standard alphabet`() {
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("AQ==") }
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("+/8") }
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("AQ\n") }
    }

    @Test
    fun `rejects non-canonical spare bits`() {
        // "AR" decodes to the same byte as "AQ" but is not the canonical form.
        assertFailsWith<IllegalArgumentException> { Base64Url.decode("AR") }
    }
}
