# Gallifrey Authenticator: haptics and secure device module

Android side of the Gallifrey accessible MFA prototype, covering the
**Mobile Haptic Engine and Secure Device Module** (H.A. Gunawardena, 230219K).

It generates and plays DOT/DASH vibration patterns, accepts the user's
reproduction through Dot/Dash buttons or a tap/hold area, verifies the entry
locally with a three-attempt lockout, and signs transaction-specific decisions
with an ECDSA P-256 key held in the Android Keystore.

The haptic pattern is an accessible interaction step, **not** a cryptographic
secret (4 elements = 16 patterns). Authentication strength comes from the
registered device key, fresh transaction context and server-side checks.

## Layout

```
android/
├── core/   Plain Kotlin/JVM, no Android SDK needed. All protocol and decision logic.
│   ├── haptics/   HapticPattern, PatternGenerator (SecureRandom), HapticTiming, HapticWaveform
│   ├── input/     GestureClassifier (hold -> DOT/DASH), PatternInput (buttons + gestures)
│   ├── verify/    TransactionGuard: local comparison, 3-attempt lockout, expiry, failure events
│   ├── crypto/    Base64Url, DecisionMessage (V1), EnrollmentMessage, PublicKeys (P-256 SPKI)
│   ├── device/    DeviceSigner interface, SecureDevice (key lifecycle), ApprovalSigner
│   └── practice/  PracticeSession: the full flow without a server
└── app/    Android application (Kotlin, Jetpack Compose, minSdk 30)
    ├── haptics/   HapticEngine: VibrationEffect waveform playback
    ├── device/    KeystoreDeviceSigner (Android Keystore), DeviceAuthenticator (BiometricPrompt)
    ├── input/     HoldGestureArea: touch timing for the tap/hold input
    ├── settings/  CalibrationStore (DataStore), CalibrationScreen
    └── practice/  PracticeScreen
```

`core` holds everything that can be tested without a phone. `app` only
binds it to platform APIs.

## Requirements to code to tests

| ID | Requirement | Code | Tests |
|---|---|---|---|
| M2-R01 | Four-element DOT/DASH pattern | `PatternGenerator` | `PatternGeneratorTest` (M2-T01) |
| M2-R02 | Defined vibration timing | `HapticTiming`, `HapticWaveform`, `HapticEngine` | `HapticWaveformTest`, on-device log below |
| M2-R03 | Timing calibration | `HapticTiming.withPlaybackUnit`, `CalibrationStore`, `CalibrationScreen` | `HapticTimingTest`, `CalibrationStoreTest` |
| M2-R04 | DOT/DASH from one hold gesture | `GestureClassifier`, `HoldGestureArea` | `GestureClassifierTest` (M2-T06/T07), on-device below |
| M2-R05 | Alternative Dot/Dash buttons | `PatternInput`, `PracticeScreen` | `PatternInputTest` |
| M2-R06 | Local pattern comparison | `TransactionGuard` (constant-time compare) | `TransactionGuardTest` (M2-T02/T03) |
| M2-R07 | Maximum 3 failed attempts | `TransactionGuard.MAX_ATTEMPTS` | `TransactionGuardTest` (M2-T04) |
| M2-R08 | Reject expired/locked transactions | `TransactionGuard`, `ApprovalSigner` | `TransactionGuardTest` (M2-T05), `ApprovalSignerTest` |
| M2-R09 | Private key in Android Keystore | `KeystoreDeviceSigner` | `KeystoreDeviceSignerTest` (on device) |
| M2-R10 | Sign transaction-specific data | `DecisionMessage`, `ApprovalSigner` | `ApprovalSignerTest` (M2-T08…T11), `ProtocolVectorsTest` |
| M2-R11 | Never transmit/log keys or raw patterns | redacted `toString()`s, `FailureEvent` without pattern, non-exportable key | `HapticPatternTest`, `PatternInputTest`, `KeystoreDeviceSignerTest` |
| M2-R12 | Registration and revocation | `SecureDevice` lifecycle | `SecureDeviceTest`, `ApprovalSignerTest` (M2-T12) |

## Signed message format

The unified design (section 10) replaces the JSON payload sketched in the
individual design with an exact line format, so the phone and the backend
sign and verify identical bytes. Fields are strict ASCII joined by a single LF,
with no trailing newline:

```
GALLIFREY-MFA-DECISION-V1
transaction_id      lower-case UUID
challenge_nonce     base64url (no padding) of 32 random bytes
account_id          lower-case UUID
device_id           lower-case UUID
rp_id
login_binding
APPROVE | DENY
expires_at          decimal Unix seconds
```

Signature: SHA256withECDSA on P-256, ASN.1 DER, base64url without padding.
Public key: DER SubjectPublicKeyInfo, base64url. Enrollment proof of possession
uses the separate `GALLIFREY-MFA-ENROLL-V1` prefix, so the two signatures can
never be swapped.

**For the auth service:** `core/src/test/resources/vectors/protocol-v1.json`
contains a public key, the fields, the exact message text and valid signatures
for APPROVE, DENY and ENROLL. Rebuild each message from its fields, compare it
with the vector, then verify the signature with Python `cryptography`.

## Rules enforced on the phone

- A matched pattern only unlocks the explicit Approve/Deny step; it never approves by itself.
- APPROVE is signed only when the transaction is unexpired, unlocked, matched (or
  direct approval was chosen) and every failure report has been acknowledged.
- DENY can be signed at any point before a terminal state.
- A transaction can be decided only once.
- Revoked or invalidated devices never sign. An ACTIVE key is never replaced silently.
- The key needs strong biometric or device-credential verification within 30 s (D04).
- Reset and replay clear the entry only; they never restore attempts.

The backend remains the authority on nonce reuse, expiry, revocation and the
failure count. A compromised app could bypass the local pattern check, which
is a threat-model limit stated in the design.

## Build, test and run

Requirements: JDK 17+ and, for the app, Android SDK Platform 35 (Android Studio
installs it). Open the `android/` folder in Android Studio.

```bash
./gradlew :core:test                    # 109 JVM tests, no SDK needed
./gradlew :app:testDebugUnitTest        # 5 JVM tests for settings storage
./gradlew :app:connectedDebugAndroidTest  # 7 Keystore tests on a connected phone
./gradlew :app:installDebug             # install on the phone
```

`settings.gradle.kts` includes `:app` only when an Android SDK is configured,
so `:core:test` also runs on machines without one. Connected tests uninstall
the app afterwards (AGP default); reinstall with `installDebug`.

A real phone is needed to feel vibration and to test TalkBack. Emulators do not vibrate.

## Evidence collected on a Galaxy A25 5G (SM-A256E, Android 16)

| Measurement | Result |
|---|---|
| Playback of Dot Dash Dot Dot (vibrator service log) | delay 1002 ms, pulses 200 / 600 / 200 / 200 ms, gaps 200 ms, total 2.805 s |
| Vibration usage | ACCESSIBILITY; no amplitude control on this device, so on/off timing is used |
| Hold classification at 400 ms threshold | 112, 259, 353 ms → Dot; 453, 600, 911 ms → Dash |
| Recalibrated threshold 650 ms | 500 ms → Dot; setting kept after app restart |
| Key security level | TRUSTED_ENVIRONMENT (no StrongBox on this device) |
| Keystore signature | verifies with the exported public key; altered message fails |
| Private key export | `PrivateKey.encoded` is null |
| Auth-bound key, more than 30 s after unlock | signing refused until device verification |
| Practice flow | count-only feedback; lockout after 3 mismatches; expiry at 120 s; deny signs nothing |

Hold durations were injected with `adb shell input swipe`. They show that the
classifier works on the device, not how accurately people perform holds; that
needs participant testing.

## Out of scope for this module

These parts belong to other modules of the group design:

- HTTPS calls to the auth service: fetching requests, reporting failure
  events, submitting signed decisions, enrollment endpoints.
- The real request review screen, notifications (FCM) and recovery.
- Server-side verification, nonce storage, replay prevention and the demo website.

The practice mode uses a separate practice key (`gallifrey_practice_key`) and
never touches the enrolled device key.

## Limitations

- Four-element patterns have low entropy; haptics are not a security factor.
- Timing defaults (200/600/200 ms, 1 s, 400 ms) are engineering starting points
  that need validation with blind and low-vision participants.
- Haptic hardware differs between phones (e.g. no amplitude control on the test device).
- Hardware-backed and StrongBox key storage are detected, not assumed.
- Without key attestation the server cannot independently confirm the key configuration.
- Academic prototype; not a production authenticator.
