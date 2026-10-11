package com.gallifrey.authenticator.device

import com.gallifrey.authenticator.crypto.Base64Url
import com.gallifrey.authenticator.crypto.Decision
import com.gallifrey.authenticator.crypto.DecisionMessage
import com.gallifrey.authenticator.verify.TransactionGuard

/** What the app submits to POST /v1/device/requests/{id}/decision. */
data class SignedDecision(
    val transactionId: String,
    val decision: Decision,
    /** base64url (no padding) ASN.1 DER ECDSA signature over DecisionMessage.toBytes(). */
    val signature: String,
)

/** The decision is not allowed in the transaction's current local state. */
class DecisionNotAllowedException(message: String) : Exception(message)

/**
 * Signs a transaction-specific decision only when every local rule allows it:
 *
 *  - the message belongs to this transaction and this registered device;
 *  - APPROVE needs a matched pattern (or direct approval), no unacknowledged
 *    failure events, and an unexpired, unlocked transaction;
 *  - DENY is allowed at any point before a terminal state;
 *  - the device registration is ACTIVE (revoked or invalidated devices never sign).
 *
 * The caller shows the explicit Approve/Deny screen and the platform's device
 * verification before calling [sign]. If the platform still requires user
 * authentication, UserAuthenticationRequiredException propagates and the
 * transaction is left unchanged so the user can retry.
 *
 * The backend verifies the signature independently and is the authority on
 * expiry, nonce reuse and revocation.
 */
class ApprovalSigner(private val device: SecureDevice) {

    fun sign(guard: TransactionGuard, message: DecisionMessage): SignedDecision {
        require(message.transactionId == guard.transactionId) { "Message is for a different transaction" }
        require(message.deviceId == device.registration.deviceId) { "Message is for a different device" }

        val allowed = when (message.decision) {
            Decision.APPROVE -> guard.canApprove()
            Decision.DENY -> guard.canDeny()
        }
        if (!allowed) {
            throw DecisionNotAllowedException(
                "${message.decision} not allowed in state ${guard.currentState}" +
                    if (guard.pendingFailureEvents.isNotEmpty()) " (failure reports pending)" else "",
            )
        }

        val signature = device.signForActiveDevice(message.toBytes())
        guard.markDecided(approved = message.decision == Decision.APPROVE)
        return SignedDecision(message.transactionId, message.decision, Base64Url.encode(signature))
    }
}
