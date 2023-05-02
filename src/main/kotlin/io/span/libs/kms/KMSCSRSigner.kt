package io.span.libs.kms

import com.amazonaws.services.kms.AWSKMSClient
import com.amazonaws.services.kms.model.GetPublicKeyRequest
import io.span.libs.kms.CSRSigner.Companion.getPublicKey
import io.span.libs.kms.CSRSigner.Companion.getRandomSerial
import io.span.libs.kms.CSRSigner.Companion.readCSRInPem
import java.security.PublicKey
import java.util.Date
import java.util.UUID
import javax.security.auth.x500.X500Principal
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension.authorityKeyIdentifier
import org.bouncycastle.asn1.x509.Extension.basicConstraints
import org.bouncycastle.asn1.x509.Extension.extendedKeyUsage
import org.bouncycastle.asn1.x509.Extension.keyUsage
import org.bouncycastle.asn1.x509.Extension.subjectKeyIdentifier
import org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_clientAuth
import org.bouncycastle.asn1.x509.KeyPurposeId.id_kp_serverAuth
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.slf4j.LoggerFactory

class KMSBasedCSRSigner(
    private val caConfig: CertConfig,
    private val kmsClient: AWSKMSClient
): CSRSigner {

    /**
     * Given a key id of a private key present in KMS,
     * generates a self-signed certificate for the given subject and validity.
     * @param kmsKeyId - keyId of the private/public key pair present in KMS
     * @param subjectCN - SubjectCN for the Root Certificate to be generated
     * @param validity - the amount of time the certificate needs to be valid.
     * @return DER encoded ASN.1 sequence representing the generated X509 Certificate
     */
    override fun generateSelfSignedCert(
        kmsKeyId: String,
        subjectCN: String,
        validity: Duration
    ): ByteArray {
        val serialNumber = getRandomSerial()
        val publicKey = getPublicKeyFromKMS(privateKeyId = kmsKeyId)
        val now = Date()
        val then = Date(now.time + validity.inWholeMilliseconds)
        val subject = X500Principal("CN=$subjectCN")
        val keyUsages = KeyUsage(KeyUsage.digitalSignature + KeyUsage.keyCertSign + KeyUsage.cRLSign)
        val extendedKeyUsages = ExtendedKeyUsage(arrayOf(id_kp_serverAuth, id_kp_clientAuth))

        logger.ifDebug { "CertSigner: Creating a root cert for $subject, from=$now, until=$then" }

        val contentSigner = KMSContentSigner(kmsKeyId, kmsClient)
        val rootCertBuilder = JcaX509v3CertificateBuilder(
            /* issuer = */ subject,
            /* serial = */ serialNumber,
            /* notBefore = */ now,
            /* notAfter = */ then,
            /* subject = */ subject,
            /* publicKey = */ publicKey
        )
            // Since this is self-signed, we DO NOT need authorityKeyIdentifier
            .addExtension(basicConstraints, true, BasicConstraints(/* cA = */ true))
            .addExtension(subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey))
            .addExtension(keyUsage, false, keyUsages)
            .addExtension(extendedKeyUsage, true, extendedKeyUsages)

        return rootCertBuilder.build(contentSigner).encoded
    }

    /**
     * Reads the csr, (expected to validate it) and then generates a certificate by signing it with an
     * intermediate CA's private key present in KMS
     * @param csrPemBytes encoded CSR in PEM format
     * @return DER encoded ASN.1 sequence representing the generated X509 Certificate
     */
    override fun signCSR(csrPemBytes: ByteArray): ByteArray {
        val csr = readCSRInPem(csrPemBytes)
        val now = Date()
        val then = Date(now.time + CERT_VALIDITY.inWholeMilliseconds)
        val subject = X500Principal("CN=${UUID.randomUUID()}")

        logger.ifDebug { "CertSigner: Creating a cert for $subject, from=$now, until=$then" }

        // CA Certificate is a certificate that wraps the public key for which private key is in KMS
        val caCert = caConfig.certificate
        val caCertContentSigner = KMSContentSigner(caConfig.privateKeyArn, kmsClient)
        val extendedKeyUsages = ExtendedKeyUsage(arrayOf(id_kp_serverAuth, id_kp_clientAuth))

        val operationCertBuilder = JcaX509v3CertificateBuilder(
            /* issuer = */ caCert.issuerX500Principal,
            /* serial = */ caCert.serialNumber,
            /* notBefore = */ now,
            /* notAfter = */ then,
            /* subject = */ subject,
            /* publicKey = */ getPublicKey(csr)
        )
            .addExtension(basicConstraints, true, BasicConstraints(/* cA = */ false))
            .addExtension(authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert))
            .addExtension(subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(csr.subjectPublicKeyInfo))
            .addExtension(keyUsage, false, KeyUsage(KeyUsage.digitalSignature))
            .addExtension(extendedKeyUsage, true, extendedKeyUsages)

        return operationCertBuilder.build(caCertContentSigner).encoded
    }

    private fun getPublicKeyFromKMS(privateKeyId: String): PublicKey {
        val publicKeyBytes = kmsClient
            .getPublicKey(GetPublicKeyRequest().withKeyId(privateKeyId))
            .publicKey
            .array()
        return getPublicKey(publicKeyBytes)
    }

    companion object {
        private val CERT_VALIDITY = 365.days
        private val extUtils = JcaX509ExtensionUtils()

        private val logger = LoggerFactory.getLogger("KMSBasedCSRSigner")
    }
}
