package com.gallifrey.authenticator

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawingPadding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.PrimaryTabRow
import androidx.compose.material3.Tab
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.gallifrey.authenticator.haptics.HapticEngine
import com.gallifrey.authenticator.practice.PracticeScreen
import com.gallifrey.authenticator.practice.PracticeSession
import com.gallifrey.authenticator.settings.CalibrationScreen
import com.gallifrey.authenticator.settings.CalibrationStore
import com.gallifrey.authenticator.settings.HapticSettings
import kotlinx.coroutines.launch

/** Top-level UI: practice and calibration, sharing the saved haptic settings. */
@OptIn(ExperimentalMaterial3Api::class) // PrimaryTabRow
@Composable
fun AuthenticatorApp(
    session: PracticeSession,
    haptics: HapticEngine,
    calibration: CalibrationStore,
    onApprove: suspend () -> Boolean,
) {
    val settings by calibration.settings.collectAsState(initial = HapticSettings())
    val scope = rememberCoroutineScope()
    var tab by rememberSaveable { mutableIntStateOf(0) }

    // Practice starts in the user's preferred input method.
    LaunchedEffect(settings.inputMode) { session.switchMode(settings.inputMode) }

    Column(modifier = Modifier.fillMaxSize().safeDrawingPadding()) {
        PrimaryTabRow(selectedTabIndex = tab) {
            listOf("Practice", "Calibration").forEachIndexed { index, title ->
                Tab(
                    selected = tab == index,
                    onClick = {
                        haptics.cancel()
                        tab = index
                    },
                    text = { Text(title) },
                    modifier = Modifier.heightIn(min = 56.dp),
                )
            }
        }
        val contentModifier = Modifier.padding(24.dp)
        when (tab) {
            0 -> PracticeScreen(
                session = session,
                haptics = haptics,
                timing = settings.timing,
                onApprove = onApprove,
                modifier = contentModifier,
            )
            else -> CalibrationScreen(
                settings = settings,
                haptics = haptics,
                onChange = { scope.launch { calibration.save(it) } },
                onReset = { scope.launch { calibration.reset() } },
                modifier = contentModifier,
            )
        }
    }
}
