package io.veracrypt.android.coreapi

import org.junit.Test
import org.junit.Assert.*

class VolumeHeaderTest {
    @Test
    fun `VolumeHeader isVeraCrypt flag reflects magic`() {
        val header = VolumeHeader(
            magic = "VERA",
            version = 5,
            minProgramVersion = 0x10b,
            volumeSize = 104857600L,
            encryptionAlgorithm = EncryptionAlgorithm.AES,
            hashAlgorithm = HashAlgorithm.SHA512,
            sectorSize = 512,
            isVeraCrypt = true
        )
        assertTrue(header.isVeraCrypt)
        assertEquals("VERA", header.magic)
    }

    @Test
    fun `OpenResult WrongPassword is distinct from NotAContainer`() {
        assertNotEquals(OpenResult.WrongPassword, OpenResult.NotAContainer)
    }
}
