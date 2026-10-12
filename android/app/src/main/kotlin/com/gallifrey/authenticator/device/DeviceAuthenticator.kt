package com.gallifrey.authenticator.device

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine

/** Whether this phone can verify the user for the device key. */
enum class DeviceAuthAvailability {
    READY,

    /** No screen lock or biometric is set up: ask the user to add a screen lock. */
    NOT_SET_UP,

    /** Hardware missing, unavailable or needs a security update. */
    UNAVAILABLE,
}

sealed interface DeviceAuthResult {
    data object Success : DeviceAuthResult

    /** The user dismissed the prompt or chose not to verify. Nothing is signed. */
    data object Cancelled : DeviceAuthResult

    /** Too many attempts, lockout, or another platform error. */
    data class Failed(val message: String) : DeviceAuthResult
}

/**
 * Android device verification before key use (design section 10, "Local user
 * verification"). Strong biometrics and the device PIN/pattern/password are
 * both accepted, so a fingerprint sensor is never mandatory.
 *
 * Verification proves only that someone who can unlock this phone was
 * present. It does not prove to the backend which person completed the
 * haptic sequence.
 */
class DeviceAuthenticator(private val activity: FragmentActivity) {

    fun availability(): DeviceAuthAvailability =
        when (BiometricManager.from(activity).canAuthenticate(ALLOWED)) {
            BiometricManager.BIOMETRIC_SUCCESS -> DeviceAuthAvailability.READY
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> DeviceAuthAvailability.NOT_SET_UP
            else -> DeviceAuthAvailability.UNAVAILABLE
        }

    /** Shows the system prompt. [title] should name the action, e.g. the requesting service. */
    suspend fun authenticate(title: String, subtitle: String? = null): DeviceAuthResult =
        suspendCancellableCoroutine { continuation ->
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (continuation.isActive) continuation.resume(DeviceAuthResult.Success)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (!continuation.isActive) return
                    val cancelled = errorCode == BiometricPrompt.ERROR_USER_CANCELED ||
                        errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON ||
                        errorCode == BiometricPrompt.ERROR_CANCELED
                    continuation.resume(
                        if (cancelled) DeviceAuthResult.Cancelled else DeviceAuthResult.Failed(errString.toString()),
                    )
                }

                // onAuthenticationFailed (one unrecognised finger) is not final:
                // the system prompt lets the user try again.
            }

            val prompt = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity), callback)
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .apply { if (subtitle != null) setSubtitle(subtitle) }
                .setAllowedAuthenticators(ALLOWED)
                .setConfirmationRequired(true)
                .build()
            prompt.authenticate(info)
            continuation.invokeOnCancellation { prompt.cancelAuthentication() }
        }

    /**
     * Runs [sign]. If the key needs fresh verification, shows the prompt once
     * and retries; the key's 30-second window covers the retry. Returns null
     * if the user cancels or verification fails, so nothing is signed.
     */
    suspend fun <T> withUserVerification(title: String, subtitle: String? = null, sign: () -> T): T? {
        try {
            return sign()
        } catch (e: UserAuthenticationRequiredException) {
            // Fall through to the prompt.
        }
        return when (authenticate(title, subtitle)) {
            DeviceAuthResult.Success -> sign()
            else -> null
        }
    }

    private companion object {
        const val ALLOWED = BIOMETRIC_STRONG or DEVICE_CREDENTIAL
    }
}
