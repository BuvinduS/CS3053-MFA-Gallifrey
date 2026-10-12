package com.gallifrey.authenticator

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.ui.Modifier
import androidx.fragment.app.FragmentActivity
import com.gallifrey.authenticator.device.DeviceAuthAvailability
import com.gallifrey.authenticator.device.DeviceAuthenticator
import com.gallifrey.authenticator.device.KeystoreDeviceSigner
import com.gallifrey.authenticator.haptics.HapticEngine
import com.gallifrey.authenticator.practice.PracticeSession
import com.gallifrey.authenticator.settings.CalibrationStore

// FragmentActivity (a ComponentActivity) is required by BiometricPrompt.
class MainActivity : FragmentActivity() {

    private lateinit var haptics: HapticEngine
    private lateinit var deviceAuth: DeviceAuthenticator
    private lateinit var practiceSigner: KeystoreDeviceSigner
    private lateinit var calibration: CalibrationStore
    private val session = PracticeSession()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        haptics = HapticEngine(this)
        deviceAuth = DeviceAuthenticator(this)
        // Practice key: separate from the enrolled device key, still needs device verification.
        practiceSigner = KeystoreDeviceSigner(this, PRACTICE_KEY_ALIAS, requireUserAuthentication = true)
        calibration = CalibrationStore(this)

        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AuthenticatorApp(
                        session = session,
                        haptics = haptics,
                        calibration = calibration,
                        onApprove = ::signPracticeApproval,
                    )
                }
            }
        }
    }

    /** Device verification, then a practice signature. Returns false if nothing was signed. */
    private suspend fun signPracticeApproval(): Boolean {
        if (deviceAuth.availability() != DeviceAuthAvailability.READY) return false
        if (!practiceSigner.hasKey()) practiceSigner.generateKey()
        val signature = deviceAuth.withUserVerification(
            title = "Approve practice request",
            subtitle = "Verify it's you to sign the practice approval",
        ) { practiceSigner.sign(PRACTICE_MESSAGE) }
        return signature != null
    }

    override fun onStop() {
        super.onStop()
        haptics.cancel()
    }

    private companion object {
        const val PRACTICE_KEY_ALIAS = "gallifrey_practice_key"
        val PRACTICE_MESSAGE = "GALLIFREY-PRACTICE".toByteArray(Charsets.US_ASCII)
    }
}
