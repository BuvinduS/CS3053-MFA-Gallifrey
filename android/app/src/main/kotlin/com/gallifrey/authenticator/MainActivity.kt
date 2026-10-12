package com.gallifrey.authenticator

import android.os.Bundle
import androidx.activity.compose.setContent
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import com.gallifrey.authenticator.device.DeviceAuthAvailability
import com.gallifrey.authenticator.device.DeviceAuthenticator
import com.gallifrey.authenticator.device.KeystoreDeviceSigner
import com.gallifrey.authenticator.haptics.HapticEngine
import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.PatternElement
import com.gallifrey.authenticator.input.GestureClassifier
import com.gallifrey.authenticator.input.HoldGestureArea
import com.gallifrey.authenticator.input.InputMode
import com.gallifrey.authenticator.input.PatternInput
import kotlinx.coroutines.launch

// FragmentActivity (a ComponentActivity) is required by BiometricPrompt.
class MainActivity : FragmentActivity() {

    private lateinit var haptics: HapticEngine
    private lateinit var deviceAuth: DeviceAuthenticator
    private lateinit var practiceSigner: KeystoreDeviceSigner

    private var status by mutableStateOf("")
    private val gestureClassifier = GestureClassifier()
    private val gestureInput = PatternInput(classifier = gestureClassifier, mode = InputMode.GESTURE)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        haptics = HapticEngine(this)
        deviceAuth = DeviceAuthenticator(this)
        // Practice key: separate from the enrolled device key, still needs device verification.
        practiceSigner = KeystoreDeviceSigner(this, PRACTICE_KEY_ALIAS, requireUserAuthentication = true)

        setContent {
            MaterialTheme(colorScheme = if (isSystemInDarkTheme()) darkColorScheme() else lightColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    Column(
                        modifier = Modifier.padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        Text(
                            text = getString(R.string.app_name),
                            style = MaterialTheme.typography.headlineMedium,
                        )
                        // Temporary checks; replaced by the practice screen.
                        Button(
                            onClick = { haptics.play(EXAMPLE_PATTERN) },
                            enabled = haptics.isAvailable,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                        ) {
                            Text("Play example: Dot Dash Dot Dot")
                        }
                        Button(
                            onClick = { practiceApproval() },
                            modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                        ) {
                            Text("Practice approval")
                        }
                        HoldGestureArea(
                            classifier = gestureClassifier,
                            onElement = {
                                // Temporary check only: a full entry restarts on the next element.
                                if (gestureInput.isComplete) gestureInput.reset()
                                when (it) {
                                    PatternElement.DOT -> gestureInput.addDot()
                                    PatternElement.DASH -> gestureInput.addDash()
                                }
                                status = "Entered ${gestureInput.count} of 4 (practice: last was $it)"
                            },
                        )
                        Text(
                            text = status,
                            modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                        )
                    }
                }
            }
        }
    }

    private fun practiceApproval() {
        when (deviceAuth.availability()) {
            DeviceAuthAvailability.NOT_SET_UP -> {
                status = "Set a screen lock in Android settings first."
                return
            }
            DeviceAuthAvailability.UNAVAILABLE -> {
                status = "Device verification is not available on this phone."
                return
            }
            DeviceAuthAvailability.READY -> Unit
        }
        lifecycleScope.launch {
            if (!practiceSigner.hasKey()) practiceSigner.generateKey()
            val signature = deviceAuth.withUserVerification(
                title = "Practice approval",
                subtitle = "Verify it's you to sign a practice request",
            ) { practiceSigner.sign(PRACTICE_MESSAGE) }
            status = if (signature != null) {
                "Practice approval signed. Key storage: ${practiceSigner.securityLevel()}."
            } else {
                "Not approved. Nothing was signed."
            }
        }
    }

    override fun onStop() {
        super.onStop()
        haptics.cancel()
    }

    private companion object {
        const val PRACTICE_KEY_ALIAS = "gallifrey_practice_key"
        val PRACTICE_MESSAGE = "GALLIFREY-PRACTICE".toByteArray(Charsets.US_ASCII)

        // The design document's example (Figure 3), not a real transaction pattern.
        val EXAMPLE_PATTERN = HapticPattern(
            listOf(PatternElement.DOT, PatternElement.DASH, PatternElement.DOT, PatternElement.DOT),
        )
    }
}
