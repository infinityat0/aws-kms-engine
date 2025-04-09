package eth.infinityat0.libs.kms

import com.amazonaws.services.kms.AWSKMSClient
import com.amazonaws.services.kms.model.GetPublicKeyRequest
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
import eth.infinityat0.libs.kms.CSRSigner.CSREncoding
import eth.infinityat0.libs.kms.CSRSigner.Companion.readCSR
import eth.infinityat0.libs.kms.CSRSigner.Companion.getRandomSerial
import eth.infinityat0.libs.kms.CSRSigner.Companion.getPublicKeyFromCSR
import eth.infinityat0.libs.kms.CSRSigner.Companion.getPublicKey

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

        val extUtils = JcaX509ExtensionUtils()
        val contentSigner = KMSContentSigner(kmsKeyId, kmsClient)

        return JcaX509v3CertificateBuilder(
            /* issuer = */ subject,
            /* serial = */ serialNumber,
            /* notBefore = */ now,
            /* notAfter = */ then,
            /* subject = */ subject,
            /* publicKey = */ publicKey,
        ).apply {
            // Since this is self-signed, we DO NOT need authorityKeyIdentifier
            addExtension(basicConstraints, true, BasicConstraints(/* cA = */ true))
            addExtension(subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey))
            addExtension(keyUsage, false, keyUsages)
            addExtension(extendedKeyUsage, true, extendedKeyUsages)
        }.build(contentSigner).encoded
    }

    /**
     * Reads the csr, (expected to validate it) and then generates a certificate by signing it with an
     * intermediate CA's private key present in KMS
     * @param csrPemBytes encoded CSR in PEM format
     * @return DER encoded ASN.1 sequence representing the generated X509 Certificate
     */
    override fun signCSR(csrPemBytes: ByteArray): ByteArray {
        val csr = readCSR(csrPemBytes, CSREncoding.PEM)
        val now = Date()
        val then = Date(now.time + CERT_VALIDITY.inWholeMilliseconds)
        val subject = X500Principal("CN=${UUID.randomUUID()}")
        val serialNumber = getRandomSerial()

        logger.ifDebug { "CertSigner: Creating a cert for $subject, from=$now, until=$then" }

        // CA Certificate is a certificate that wraps the public key for which private key is in KMS
        val caCert = caConfig.certificate
        val extUtils = JcaX509ExtensionUtils()
        val caCertContentSigner = KMSContentSigner(caConfig.privateKeyArn, kmsClient)
        val extendedKeyUsages = ExtendedKeyUsage(arrayOf(id_kp_serverAuth, id_kp_clientAuth))

        return JcaX509v3CertificateBuilder(
            /* issuer = */ caCert.subjectX500Principal,
            /* serial = */ serialNumber,
            /* notBefore = */ now,
            /* notAfter = */ then,
            /* subject = */ subject,
            /* publicKey = */ getPublicKeyFromCSR(csr)
        ).apply {
            addExtension(basicConstraints, true, BasicConstraints(/* cA = */ false))
            // There's a bug in bouncycastle that sets the signer certificate's
            // issuer as the authorityKeyIdentifier's GivenName. That's wrong. Do not pass caCert here
            // See: https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.1
            addExtension(authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCert.publicKey))
            addExtension(subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(csr.subjectPublicKeyInfo))
            addExtension(keyUsage, false, KeyUsage(KeyUsage.digitalSignature))
            addExtension(extendedKeyUsage, true, extendedKeyUsages)
        }.build(caCertContentSigner).encoded
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

        private val logger = LoggerFactory.getLogger("KMSBasedCSRSigner")
    }
}
