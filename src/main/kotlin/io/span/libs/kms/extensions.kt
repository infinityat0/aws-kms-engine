package io.span.libs.kms

import org.slf4j.Logger

fun Logger.ifDebug(message: () -> String) {
    if (this.isDebugEnabled) message()
}

fun Logger.ifInfo(message: () -> String) {
    if (this.isInfoEnabled) message()
}

fun Logger.ifWarn(message: () -> String) {
    if (this.isWarnEnabled) message()
}
