package io.span.libs.kms

import org.bouncycastle.asn1.pkcs.CertificationRequest
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.math.BigInteger
import java.security.KeyFactory
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Security
import java.security.spec.PKCS8EncodedKeySpec
import kotlin.time.Duration

interface CSRSigner {

    fun generateSelfSignedCert(
        keyId: String,
        subjectCN: String,
        validity: Duration
    ): ByteArray

    fun signCSR(csrPemBytes: ByteArray): ByteArray

    companion object {
        init {
            Security.addProvider(BouncyCastleProvider())
        }

        protected val sRandom = SecureRandom()


        fun getRandomSerial(): BigInteger = with(ByteArray(16)) {
            sRandom.nextBytes(this)
            BigInteger(this)
        }

        /**
         * Reads the CSR and returns the [PublicKey] inside it.
         */
        fun getPublicKey(csr: PKCS10CertificationRequest): PublicKey =
            JcaPEMKeyConverter().getPublicKey(csr.subjectPublicKeyInfo)

        /**
         * Reads DER encoded X509 Public key and returns the [PublicKey]
         */
        fun getPublicKey(publicKeyBytes: ByteArray): PublicKey =
            KeyFactory
                .getInstance("EC")
                .generatePublic(PKCS8EncodedKeySpec(publicKeyBytes))

        /**
         * Reads PEM encoded CSR bytes into a [PKCS10CertificationRequest]
         */
        fun readCSRInPem(csrPemBytes: ByteArray): PKCS10CertificationRequest {
            val pemReader = ByteArrayInputStream(csrPemBytes)
            val pemParser = PEMParser(InputStreamReader(pemReader))
            return pemParser.readObject() as PKCS10CertificationRequest
        }

        fun readCSRInDer(csrDerBytes: ByteArray): PKCS10CertificationRequest {
            val csr = CertificationRequest.getInstance(ByteArrayInputStream(csrDerBytes))
            return PKCS10CertificationRequest(csr)
        }
    }
}