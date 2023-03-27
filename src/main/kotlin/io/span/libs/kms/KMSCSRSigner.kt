package io.span.libs.kms

import com.amazonaws.services.kms.AWSKMSClient
import jakarta.inject.Singleton
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.slf4j.LoggerFactory
import java.io.StringReader
import java.security.PublicKey
import java.time.Duration
import java.util.*
import javax.security.auth.x500.X500Principal

@Singleton
class KMSBasedCSRSigner(
    private val caConfig: CertConfig,
    private val kmsClient: AWSKMSClient
) {

    /**
     * Reads the csr, (expected to validate it) and then generates a certificate by signing it with an
     * intermediate CA's private key present in KMS
     * @param csrBytes encoded CSR
     * @return DER encoded ASN.1 sequence representing the generated X509 Certificate
     */
    fun signCSR(csrBytes: ByteArray): ByteArray {

        val csr = readCSR(String(csrBytes))
        val now = Date()
        val then = Date(now.time + CERT_VALIDITY.toMillis())
        val subject = X500Principal("CN=${UUID.randomUUID()}")

        logger.ifDebug { "CertSigner: Creating a cert for $subject, from=$now, until=$then" }

        // CA Certificate is a certificate that wraps the public key for which private key is in KMS
        val caCert = caConfig.certificate
        val caCertContentSigner = KMSContenSigner(caConfig.privateKeyArn, kmsClient)

        val operationCertBuilder = JcaX509v3CertificateBuilder(
            /* issuer = */ caCert.issuerX500Principal,
            /* serial = */ caCert.serialNumber,
            /* notBefore = */ now,
            /* notAfter = */ then,
            /* subject = */ subject,
            /* publicKey = */ getPublicKey(csr)
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(false))
            .addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
            .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(csr.subjectPublicKeyInfo))
            .addExtension(Extension.keyUsage, false, KeyUsage(KeyUsage.digitalSignature))

        return operationCertBuilder.build(caCertContentSigner).encoded
    }

    companion object {
        private val CERT_VALIDITY = Duration.ofDays(365)
        private val extUtils = JcaX509ExtensionUtils()

        private val logger = LoggerFactory.getLogger("KMSBasedCSRSigner")

        private fun readCSR(csr: String): PKCS10CertificationRequest {
            val pemReader = StringReader(csr)
            val pemParser = PEMParser(pemReader)
            return pemParser.readObject() as PKCS10CertificationRequest
        }

        fun getPublicKey(csr: PKCS10CertificationRequest): PublicKey =
            JcaPEMKeyConverter().getPublicKey(csr.subjectPublicKeyInfo)
    }
}