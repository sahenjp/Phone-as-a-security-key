# Phone-as-a-security-key

[日本語](README.md) | **English**

Open-source software that turns a smartphone (iPhone / Android) connected to Fedora Linux over USB into a FIDO2 / WebAuthn security key.

Private keys stay in the phone's hardware — the Secure Enclave on iPhone, the Android Keystore on Android. For every signature, the phone displays the relying party (RP), the user approves with a tap, and signing happens only after biometric verification (Face ID etc.) succeeds. The Fedora side appears to the browser as a virtual FIDO2 device (UHID) and terminates CTAP2. Private keys never reach Fedora.

- No Bluetooth
- No jailbreak
- The iPhone app is meant to be sideloaded (App Store distribution is not a goal)
- It does not read your existing iCloud passkeys. It creates new, project-specific credentials.

The shared specification is [docs/BRIDGE-PROTOCOL.md](docs/BRIDGE-PROTOCOL.md), and it is the single source of truth. If the Rust implementation and a phone implementation (Swift / Kotlin) ever disagree, the code follows the spec, not the other way around.

## Quick setup (Fedora + iPhone)

1. Download `phone-fido-<version>-linux-x86_64.tar.gz` from the releases page, extract it, and run `./setup.sh`. It installs the daemon, registers the systemd user services, and installs the udev rule in one go. sudo is needed only for the udev part.
2. Install the app on the iPhone: sign the unsigned IPA with SideStore / iLoader and install it. See [docs/SIDELOAD.md](docs/SIDELOAD.md).
3. Open the app, take the pairing key it shows, and run `iphone-fido pair <key>` on the PC. Check that the confirmation code (SAS) matches on both sides.

From then on, just plug in the USB cable — the browser sees an ordinary USB security key. For Android, the only difference is that `adb forward tcp:18766 tcp:18765` is used instead of iproxy (details in [android/README.md](android/README.md)).

## Architecture

```text
Browser / WebAuthn RP
  GitHub / Google / webauthn.io etc.
        |  WebAuthn (navigator.credentials)
        v
Browser CTAP2 transport
        |  CTAPHID over UHID
        v
Fedora: iphone-fido daemon (Rust)          <-- this repo, crates/
  - Registers a virtual FIDO2 device on /dev/uhid
  - Terminates CTAP2: getInfo / makeCredential / getAssertion
  - Receives authData material and signatures from the phone (unmodified)
        |  Bridge Protocol v1 (docs/BRIDGE-PROTOCOL.md)
        |  PSK pairing + ephemeral ECDH + HKDF
        |  Authenticated encryption with ChaCha20-Poly1305
        v
Fedora: iproxy 18766 18765 (libusbmuxd-tools)
        |  via usbmuxd / USB
        v
Phone app (Swift / Kotlin)                 <-- this repo, ios/ and android/
  - Listens on TCP 18765 (foreground only)
  - Displays rp_id and user_name and waits for a tap approval
  - Generates and signs with hardware keys (P-256 / ES256)
  - Biometrics required for signing (access control)
  - Builds authData on the phone itself
```

Division of responsibility:

| Layer | Does | Does not do |
|---|---|---|
| Fedora daemon (Rust) | UHID, CTAPHID, CTAP2 termination, pairing PSK storage (`~/.config/iphone-fido/pairing.bin`, mode 0600) | Hold private keys, ask for signatures over arbitrary bytes, tamper with authData |
| Phone app (Swift / Kotlin) | Key generation and storage, RP display, tap approval, biometrics, authData construction, signing | Interpret CTAP, trust what the Fedora side displays |
| Bridge Protocol | Pairing, session keys, encrypted frames, semantic operations (`ping` / `create_credential` / `get_assertion` / `list_credentials`) | Accept plaintext signing requests |

How this differs from prior open-source work: virtual FIDO2 authenticators that run entirely on the PC already exist (Go's virtual-fido, Rust's soft-fido2 / passless, and others). This project is not a wrapper around them. The PC handles only transport and CTAP termination; the authenticator itself — the keys and the user verification — lives on the phone.

## Verification status (no exaggeration)

Legend: ✅ verified / ⚠️ confirmed from public material but not verified in this project / ❌ not yet verified / 🚧 in progress

| Item | Status | Evidence / notes |
|---|---|---|
| Bridge Protocol v1 specification | ✅ | [docs/BRIDGE-PROTOCOL.md](docs/BRIDGE-PROTOCOL.md) |
| iproxy can relay to an on-device socket in principle | ⚠️ | Confirmed from public material; precedent: WebDriverAgent (port 8100) over iproxy |
| USB path between a real iPhone and Fedora (this app, port 18765) | ✅ | Passed stage (b) on 2026-11-06: handshake + encrypted ping round-trip with the real phone (iPhone 17 / iOS 27.0). Records: [docs/REAL-DEVICE-TEST.md](docs/REAL-DEVICE-TEST.md) |
| iproxy forwarding reaches an app's listening port on iOS 17+ | ✅ | On iOS 27.0 hardware, the app's NWListener was reached via iproxy and full ceremonies completed (2026-11-06). See FEASIBILITY |
| Rust virtual FIDO2 device (UHID / CTAPHID / CTAP2 getInfo) | ✅ | Verified on real Fedora on 2026-11-05: after the udev rule, the daemon starts without root, the virtual HID appears (VID 0x1209 / PID 0xF1D0), and external processes got CTAPHID INIT and CTAP2 getInfo (status 0x00) over the real UHID. Firefox then recognized it as an authenticator and completed webauthn.io registration and authentication (below) |
| Secure Enclave supports P-256 / ES256 (COSE `-7`) | ✅ | makeCredential (flags 0x45) and getAssertion completed with status 0x00 on the real phone (2026-11-06) |
| Hardware-enforced biometrics at signing time | ✅ | Real ceremonies completed with tap approval + Face ID mandatory. The timing split between the key-creation and signing prompts is unmeasured |
| CTAP2 makeCredential / getAssertion with the phone | ✅ | Verified with both the mock phone (2026-11-05) and the real phone (2026-11-06) |
| Registration / authentication on test sites such as webauthn.io | ✅ | Real phone: Firefox completed ceremonies (daemon logs); Brave (Chromium) verified registration + authentication on screen on 2026-11-06 after fixing two GetInfo interpretation bugs (canonical CBOR, clientPin handling) |
| Seamless connection (plug in and it just connects) | ✅ | Daemon and iproxy run as systemd user services; the daemon keeps a warm session and recovers automatically on unplug/replug, verified on the real device (2026-11-06) |
| WebAuthn PRF (hmac-secret / CTAP "prf" extension) | ✅ | Verified with the real phone and a real service (2026-11-06): the hmac-secret flow passes scripts/ctap_prf_test.py, and on ppq.ai (PayPerQ), a service that requires PRF, registration completed and the follow-up PRF evaluation for its encryption feature succeeded. When GetInfo advertises "prf", Chromium uses the CTAP prf extension and results are returned in response keys 6/8 (details: REAL-DEVICE-TEST 2026-11-06 addendum, BRIDGE-PROTOCOL 3.8) |
| Registration / authentication on GitHub | ❌ Not done | Real-device stage (f). Whether `fmt:"none"` is accepted is unknown |
| Registration / authentication on Google | ❌ Not done | Real-device stage (g). Whether `fmt:"none"` is accepted is unknown |
| Authenticated, protected PC ⇄ phone channel (pairing + ECDH + AEAD) | ✅ | Spec: BRIDGE-PROTOCOL §1–2. Test vectors matched (2026-11-05) and the live run with the real phone passed on 2026-11-06: SAS match, mutual confirm authentication, encrypted ping round-trip, makeCredential (flags 0x45) / getAssertion at status 0x00 via approval + Face ID |
| Choosing among multiple credentials for one RP | ❌ Not implemented | The phone app currently picks the first-created matching credential. A selection UI is future work |
| Swift app builds and installs on a real device | ✅ | GitHub Actions (macOS runner) produces the unsigned IPA; installed on the real device via iLoader and in daily use (2026-11-06). Steps: [docs/SIDELOAD.md](docs/SIDELOAD.md) |
| Android app builds | ✅ | `:app:assembleDebug` succeeds (first compile 2026-11-06; a debug APK is attached to the release). **Not yet run on a real device** — the adb transport and on-device flows are unverified |

Unverified features are not presented as finished. When a status changes, update this table and the related documents in the same change.

## Documents

- [docs/BRIDGE-PROTOCOL.md](docs/BRIDGE-PROTOCOL.md) — the Fedora ⇄ phone shared specification (the single source of truth; edit with care)
- [docs/FEASIBILITY.md](docs/FEASIBILITY.md) — verification report for step 1, USB feasibility, with troubleshooting procedures
- [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) — threat model, countermeasures, residual risks
- [docs/REAL-DEVICE-TEST.md](docs/REAL-DEVICE-TEST.md) — real-device test procedures and record templates (Japanese)
- [docs/SIDELOAD.md](docs/SIDELOAD.md) — sideloading onto iPhone (SideStore + LiveContainer / iLoader)
- [scripts/verify-usb-fedora.sh](scripts/verify-usb-fedora.sh) — mostly read-only USB verification script for Fedora

## Building and using (overview)

See each component's README and [docs/REAL-DEVICE-TEST.md](docs/REAL-DEVICE-TEST.md) for details. This is only the overall flow.

### Fedora side

Required packages (details in REAL-DEVICE-TEST):

```sh
sudo dnf install libimobiledevice usbmuxd libusbmuxd-tools
```

Flow:

1. Connect the iPhone over USB and establish trust with `idevicepair pair`.
2. Verify the USB path on its own first: `scripts/verify-usb-fedora.sh`
3. Build the daemon (Rust / Cargo). It needs access to `/dev/uhid`; putting `packaging/99-iphone-fido-uhid.rules` into `/etc/udev/rules.d/` lets it run as a regular user. (Or just use the release tarball and `setup.sh`, which does all of this.)
4. With the phone app running, pair: type the Base32 code (52 characters) shown in the app into `iphone-fido pair`, and visually confirm the 6-digit SAS matches on both sides.
5. Start the daemon and register / authenticate on a WebAuthn test site from the browser.

To run it persistently, use `packaging/setup.sh`, or the systemd user units in `packaging/` (they auto-start the daemon and iproxy; when the phone is present, the daemon connects and keeps the session):

```sh
cp packaging/iphone-fido.service packaging/iphone-fido-iproxy.service ~/.config/systemd/user/
systemctl --user enable --now iphone-fido-iproxy.service iphone-fido.service
```

(Adjust the path in `iphone-fido.service` to your clone location.)

For development only, there is a mock phone (`--mock-phone`, with a loud warning at startup). The mock uses software keys — no Secure Enclave, no Face ID. Never use it for real verification.

### Phone side

1. Build the app in `ios/` (or `android/`) and install it on the device in sideloadable form (for iPhone, see SIDELOAD.md).
2. Keep the app in the foreground (on iOS the listener is not maintained in the background).
3. On first use, complete pairing. After that, for each operation, check the RP shown on screen, approve, and pass biometrics.

## Security essentials

Full text: [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

- Private keys are generated and kept only inside the phone's hardware keystore. Fedora receives only public keys, authData, and signatures.
- A USB connection alone never approves anything. An explicit tap approval on the phone plus biometrics are both mandatory.
- The PC never asks the phone to sign arbitrary bytes. The phone builds authData from the rpId itself, displays it, and signs only after approval.
- PC ⇄ phone traffic is authenticated and protected by out-of-band PSK pairing plus per-connection ephemeral ECDH + AEAD.
- If Fedora itself is compromised, deceptive displays and similar attacks cannot be fully prevented. The residual risks are written down honestly in THREAT-MODEL.

## License

MIT License — see [LICENSE](LICENSE).
