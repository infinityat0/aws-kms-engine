package eth.infinityat0.libs.kms

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

data class CertConfig(
    val certStr: String,
    val privateKeyArn: String
) {
    val certificate by lazy {
        CertificateFactory
            .getInstance("X509", BouncyCastleProvider())
            .generateCertificate(ByteArrayInputStream(certStr.toByteArray())) as X509Certificate
    }
}
