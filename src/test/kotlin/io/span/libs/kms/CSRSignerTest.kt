package io.span.libs.kms

import java.io.File
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow

class CSRSignerTest {

    @Test
    fun `decoding a PEM encoded CSR works`() {
        val csrPemString = contentsOfFile("csr.pem")
        assertDoesNotThrow { CSRSigner.readCSRInPem(csrPemString.toByteArray()) }
    }

    companion object {
        private fun getPath(fileName: String): String =
            this.javaClass.classLoader.getResource(fileName).file

        private fun contentsOfFile(fileName: String): String =
            File(getPath(fileName)).readText(Charsets.UTF_8)
    }
}