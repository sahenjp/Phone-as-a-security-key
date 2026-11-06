# Phone-as-a-securitykey — Android app

The Android counterpart of the iOS app in `../ios/`: an Android phone acts
as the FIDO2/WebAuthn authenticator for a PC over USB. The PC side (Rust
daemon) terminates CTAPHID/CTAP2 and talks to this app over the bridge
protocol; the phone holds the keys, shows the request, and signs only
after an on-screen approval tap **and** a biometric prompt.

**The shared specification is `../docs/BRIDGE-PROTOCOL.md` — it is the
single source of truth.** This app implements the phone side of that
protocol with the same message shapes, field names and error codes as the
iOS app, so the existing daemon works with either phone.

> **Status: NOT yet built or verified on a real device.** The code was
> written against the spec and the iOS reference implementation, but it
> has not been compiled in CI or run on hardware yet. Treat everything
> below as "intended behavior" until a device run proves it.

## What differs from the iOS build

- Keys live in the **Android Keystore** instead of the Secure Enclave:
  one EC P-256 key pair per credential, generated with
  `setUserAuthenticationRequired(true)` and per-use authentication
  (validity duration `-1`), so signing is only possible inside a
  `BiometricPrompt` CryptoObject right after approval. Keys are also
  invalidated when the biometric enrollment changes (the counterpart of
  iOS `.biometryCurrentSet`).
- The pairing PSK and each credential's PRF (hmac-secret) key are stored
  **AES-GCM-encrypted** under a Keystore wrapping key in app-private
  storage; credential metadata is a JSON file in the same place.
- The AAGUID is ASCII `and-fido-0000001` (the iOS build uses
  `iph-fido-0000001`), so relying parties can tell the models apart.
- The bridge listener runs in a **foreground service** (port 18765, all
  interfaces). Approvals still require this app in the foreground — when
  a request arrives otherwise, a high-priority notification asks the user
  to open the app, and the usual 60-second approval timeout applies.
- Platform ChaCha20-Poly1305 (`javax.crypto`) only exists on API 28+, so
  API 26/27 use a hand-rolled RFC 8439 implementation included in
  `ChaChaPoly.kt`.

## Build

Requirements: JDK 17 and the Android SDK (compileSdk 35). Gradle 8.9
(wrapper properties are in `gradle/wrapper/`; CI pins the same version
via `gradle/actions/setup-gradle`).

```sh
cd android
gradle :app:assembleDebug     # debug APK (signed with the debug key)
gradle :app:assembleRelease   # release APK, UNSIGNED (no signing config)
```

Outputs land in `app/build/outputs/apk/<variant>/`. The release build is
deliberately unsigned, mirroring the iOS unsigned-IPA flow: sign it with
your own key before installing if you use it.

CI: `.github/workflows/android-apk.yml` builds the debug APK on pushes to
`android/**` and uploads it as an artifact.

## Pairing and connecting

1. Open the app. The foreground service starts and listens on port 18765.
2. Tap **Generate pairing key**. The app shows:
   - the PSK as 52 Base32 characters — type it into the PC:
     `iphone-fido pair <CODE>` (the PSK never travels over USB);
   - the 6-digit SAS confirmation code — check it matches the PC's.
3. Forward the port from the PC (USB debugging enabled on the phone):

   ```sh
   adb forward tcp:18766 tcp:18765
   ```

   The daemon then connects to `127.0.0.1:18766` exactly as it does with
   iproxy on iOS. (Pointing the daemon's transport at `adb forward`
   instead of `iproxy` is PC-side configuration; this app only provides
   the same listener.)
4. Use WebAuthn as usual: for every credential creation or sign-in, this
   app shows the site (rp_id) and user name; tap Approve and pass the
   biometric prompt. Nothing is ever approved automatically.

Credentials can be reviewed and deleted in the app's credential list.

## Layout

```
app/src/main/java/site/sahen/phonefido/
  MainActivity.kt          status / pairing / credential list / approval screen, BiometricPrompt host
  BridgeService.kt         foreground service hosting the listener
  BridgeServer.kt          ServerSocket listener (one live session, newest wins, auto-restart)
  BridgeSession.kt         framing, handshake, encrypted request loop
  SessionCrypto.kt         HKDF-SHA256, session key derivation, confirm MACs, ECDH, SessionCipher
  ChaChaPoly.kt            ChaCha20-Poly1305 (javax.crypto on API 28+, hand-rolled fallback)
  AuthenticatorService.kt  the BRIDGE-PROTOCOL 3 operations incl. PRF two-phase flows
  CredentialStore.kt       pairing PSK + credential metadata persistence
  KeyStore.kt              Android Keystore: per-credential EC keys, AES-GCM wrapping key
  Approval.kt              approval coordinator (60 s, single pending) + biometric sign bridge
  Cbor.kt                  tiny CBOR encoder + COSE_Key builder
  CryptoUtils.kt           SHA-256 / HMAC / Base32 / SAS / base64 helpers
  Models.kt                protocol constants (AAGUID `and-fido-0000001`), metadata types
  AppRuntime.kt            shared state between service, session threads and UI
  PhoneFidoApp.kt          Application: notification channels, runtime init
```

## Security notes

- Private keys never leave the phone; the PC cannot request signatures
  over arbitrary bytes — the phone builds authData from the rp_id itself.
- Pairing is out-of-band: the session keys are bound to the PSK via
  ECDH + HKDF, both sides prove it with HMAC confirmations, and every
  frame after that is ChaCha20-Poly1305 with strictly checked sequence
  numbers.
- The PRF (hmac-secret) secret stays on the phone; only raw HMAC outputs
  for daemon-supplied salts are returned, after approval + biometrics.
- Known protocol note: `list_credentials` returns
  `{"credentials": [...]}` exactly like the iOS app. The Rust daemon's
  `TcpPhone` currently parses a bare array instead — a pre-existing
  mismatch in the daemon (BRIDGE-PROTOCOL 3.4 does not pin the envelope)
  that affects iOS identically and should be fixed on whichever side is
  adjusted first, in the spec.
