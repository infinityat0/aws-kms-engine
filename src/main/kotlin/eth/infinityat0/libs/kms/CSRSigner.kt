package eth.infinityat0.libs.kms

import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.math.BigInteger
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import kotlin.time.Duration
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.pkcs.PKCS10CertificationRequest

interface CSRSigner {

    enum class CSREncoding {
        DER,
        PEM,
    }

    /**
     * Generates a self-signed cert and returns the encoded DER X509 certificate
     */
    fun generateSelfSignedCert(
        keyId: String,
        subjectCN: String,
        validity: Duration
    ): ByteArray

    /**
     * Signs a given CSR with a key present in the KMS. CSR is PEM encoded.
     *
     * @param csrPemBytes PEM encoded CSR byte array.
     * @return DER encoded X509 certificate.
     */
    fun signCSR(csrPemBytes: ByteArray): ByteArray

    companion object {
        init {
            Security.addProvider(BouncyCastleProvider())
        }

        protected val sRandom = SecureRandom()


        fun getRandomSerial(): BigInteger = with(ByteArray(16)) {
            sRandom.nextBytes(this)
            BigInteger(this).abs()
        }


        /**
         * Reads the CSR and returns the [PublicKey] inside it.
         */
        fun getPublicKeyFromCSR(csr: PKCS10CertificationRequest): PublicKey =
            JcaPEMKeyConverter().getPublicKey(csr.subjectPublicKeyInfo)

        /**
         * Reads DER encoded X509 Public key and returns the [PublicKey]
         */
        fun getPublicKey(publicKeyBytes: ByteArray): PublicKey =
            JcaPEMKeyConverter().getPublicKey(SubjectPublicKeyInfo.getInstance(publicKeyBytes))

        fun readCSR(csr: ByteArray, encoding: CSREncoding): PKCS10CertificationRequest =
            when (encoding) {
                CSREncoding.DER -> readCSRInDer(csr)
                CSREncoding.PEM -> readCSRInPem(csr)
            }

        /**
         * Reads PEM encoded CSR bytes into a [PKCS10CertificationRequest]
         */
        private fun readCSRInPem(csrPemBytes: ByteArray): PKCS10CertificationRequest {
            val pemReader = ByteArrayInputStream(csrPemBytes)
            val pemParser = PEMParser(InputStreamReader(pemReader))
            return pemParser.readObject() as PKCS10CertificationRequest
        }

        private fun readCSRInDer(csrDerBytes: ByteArray): PKCS10CertificationRequest =
            PKCS10CertificationRequest(csrDerBytes)
    }
}
