package com.gallifrey.authenticator

import android.os.Bundle
import androidx.activity.ComponentActivity
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.gallifrey.authenticator.haptics.HapticEngine
import com.gallifrey.authenticator.haptics.HapticPattern
import com.gallifrey.authenticator.haptics.PatternElement

class MainActivity : ComponentActivity() {

    private lateinit var haptics: HapticEngine

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        haptics = HapticEngine(this)
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
                        // Temporary haptic check; replaced by the practice screen.
                        Button(
                            onClick = { haptics.play(EXAMPLE_PATTERN) },
                            enabled = haptics.isAvailable,
                            modifier = Modifier.fillMaxWidth().heightIn(min = 56.dp),
                        ) {
                            Text("Play example: Dot Dash Dot Dot")
                        }
                    }
                }
            }
        }
    }

    override fun onStop() {
        super.onStop()
        haptics.cancel()
    }

    private companion object {
        // The design document's example (Figure 3), not a real transaction pattern.
        val EXAMPLE_PATTERN = HapticPattern(
            listOf(PatternElement.DOT, PatternElement.DASH, PatternElement.DOT, PatternElement.DOT),
        )
    }
}
