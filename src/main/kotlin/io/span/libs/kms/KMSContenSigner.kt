package io.span.libs.kms

import com.amazonaws.services.kms.AWSKMSClient
import com.amazonaws.services.kms.model.MessageType
import com.amazonaws.services.kms.model.SignRequest
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers
import org.bouncycastle.operator.ContentSigner
import java.io.ByteArrayOutputStream
import java.io.OutputStream
import java.nio.ByteBuffer

// This is not a singleton because it will maintain state.
class KMSContenSigner(
    private val kmsKeyId: String,
    private val kmsClient: AWSKMSClient
) : ContentSigner {

    private val stream = ByteArrayOutputStream()

    override fun getAlgorithmIdentifier() =
        AlgorithmIdentifier(X9ObjectIdentifiers.ecdsa_with_SHA256)

    override fun getOutputStream(): OutputStream = stream

    override fun getSignature(): ByteArray {
        val request = SignRequest()
            .withKeyId(kmsKeyId)
            .withMessageType(MessageType.RAW)
            .withMessage(ByteBuffer.wrap(stream.toByteArray()))

        return kmsClient.sign(request).signature.array()
    }
}