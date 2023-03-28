package io.span.libs.kms

import com.amazonaws.services.kms.AWSKMSClient
import com.amazonaws.services.kms.model.GetPublicKeyRequest
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
import java.math.BigInteger
import java.security.Key
import java.security.KeyFactory
import java.util.Date
import java.util.UUID
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import javax.security.auth.x500.X500Principal
import kotlin.math.log
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days

@Singleton
class KMSBasedCSRSigner(
    private val caConfig: CertConfig,
    private val kmsClient: AWSKMSClient
) {

    /**
     * Given a key id of a private key present in KMS,
     * generates a self-signed certificate for the given subject and validity.
     * @param kmsKeyId - keyId of the private/public key pair present in KMS
     * @param subjectCN - SubjectCN for the Root Certificate to be generated
     * @param validity - the amount of time the certificate needs to be valid.
     * @return DER encoded ASN.1 sequence representing the generated X509 Certificate
     */
    fun generateSelfSignedCert(kmsKeyId: String, subjectCN: String, validity: Duration): ByteArray {
        val serialNumber = getRandomSerial()
        val publicKey = getPublicKey(privateKeyId = kmsKeyId)
        val now = Date()
        val then = Date(now.time + validity.inWholeMilliseconds)
        val subject = X500Principal("CN=$subjectCN")
        val keyUsages = KeyUsage(KeyUsage.digitalSignature + KeyUsage.keyCertSign + KeyUsage.cRLSign)

        logger.ifDebug { "CertSigner: Creating a root cert for $subject, from=$now, until=$then" }

        val contentSigner = KMSContenSigner(kmsKeyId, kmsClient)
        val rootCertBuilder = JcaX509v3CertificateBuilder(
            /* issuer = */ subject,
            /* serial = */ serialNumber,
            /* notBefore = */ now,
            /* notAfter = */ then,
            /* subject = */ subject,
            /* publicKey = */ publicKey
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(true))
            .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey))
            .addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(publicKey))
            .addExtension(Extension.keyUsage, false, keyUsages)

        return rootCertBuilder.build(contentSigner).encoded
    }

    /**
     * Reads the csr, (expected to validate it) and then generates a certificate by signing it with an
     * intermediate CA's private key present in KMS
     * @param csrBytes encoded CSR
     * @return DER encoded ASN.1 sequence representing the generated X509 Certificate
     */
    fun signCSR(csrBytes: ByteArray): ByteArray {
        val csr = readCSR(String(csrBytes))
        val now = Date()
        val then = Date(now.time + CERT_VALIDITY.inWholeMilliseconds)
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

    private fun getPublicKey(privateKeyId: String): PublicKey {
        val publicKeyBytes = kmsClient
            .getPublicKey(GetPublicKeyRequest().withKeyId(privateKeyId))
            .publicKey
            .array()
        return getPublicKey(publicKeyBytes)
    }

    companion object {
        private val CERT_VALIDITY = 365.days
        private val extUtils = JcaX509ExtensionUtils()
        private val sRandom = SecureRandom()

        private val logger = LoggerFactory.getLogger("KMSBasedCSRSigner")

        private fun readCSR(csr: String): PKCS10CertificationRequest {
            val pemReader = StringReader(csr)
            val pemParser = PEMParser(pemReader)
            return pemParser.readObject() as PKCS10CertificationRequest
        }

        /**
         * Reads DER encoded X509 Public key and returns the [PublicKey]
         */
        fun getPublicKey(publicKeyBytes: ByteArray): PublicKey =
            KeyFactory
                .getInstance("EC")
                .generatePublic(PKCS8EncodedKeySpec(publicKeyBytes))

        /**
         * Reads the CSR and returns the [PublicKey] inside it.
         */
        fun getPublicKey(csr: PKCS10CertificationRequest): PublicKey =
            JcaPEMKeyConverter().getPublicKey(csr.subjectPublicKeyInfo)

        fun getRandomSerial(): BigInteger = with(ByteArray(16)) {
            sRandom.nextBytes(this)
            BigInteger(this)
        }
    }
}
/**
sequenceDiagram
    participant M as Mobile
    participant C as Cloud
    participant D1 as HVAC
    participant D2 as Compressor TraitHandler

    Note over M: User turns off Compressor
    Note right of M: Create TurnOffCompressor Command
    M   ->> +C: Send Command to HVAC
    C   ->> D1: Proxy Command to HVAC
    D1  ->> C: CommonResponse (Command ACK)
    C   ->> M: CommonResponse
    D1 -->> D2: TurnOffCompressor Command
    Note over D2: Connect to breaker
    Note over D2: Flip breaker to OFF
    D2 -->> D1: Send BreakerFlipped event
    D2 -->> D1: CommandSuccessful Response
    D1  ->> C: CommandSuccessful Response
    C   ->> M: CommandSuccessful

sequenceDiagram
    participant M as Mobile
    participant C as Cloud
    participant D1 as HVAC
    participant D2 as Compressor TraitHandler
    participant D3 as Boiler TraitHandler

    Note over M: User turns off entire HVAC
    Note right of M: Create TurnOffHVAC Command
    M   ->> +C: Send Command to HVAC
    C   ->> D1: Proxy Command to HVAC
    D1  ->> C: CommonResponse (Command ACK)
    C   ->> M: CommonResponse
    D1 -->> D2: TurnOffCompressor Command
    Note over D2: Connect to breaker
    Note over D2: Flip breaker to OFF
    D2 -->> D1: Send BreakerFlipped event
    D2 -->> D1: CommandSuccessful Response
    D1  ->> C: PartialResponse (CompressorShutOff Success)

    D1 -->> D3: TurnOffBoiler Command
    Note over D3: Connect to breaker failed
    D3 -->> D1: CommandFailed Response
    D1   ->> C: PartialResponse (BoilerShutOff Failed)

    D1 -->> C: CommandFailed
    C  -->> M: CommandFailed

sequenceDiagram
    participant D as Span Panel
    participant C as Cloud
    participant I as AWS IOT
    participant KMS as AWS KMS

    Note over D, C: Operational cert expires in 30 days
    Note over D: Generate a new Operational Key Pair
    Note over D: Create a CSR
    D ->> C: Send CSR, Current Operational Cert
    Note over C: Validate the Operational Cert
    C ->> KMS: Sign Operational CSR
    Note over C: Create new Operational Cert

    C ->> I: Detach Certificate from the Thing,
    C ->> I: Delete Certificate
    C ->> I: Attach new Operational Cert to the Thing
    C ->> I: Mark Certificate Active

    C -> D: Success

*/

