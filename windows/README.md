# Phone FIDO Key for Windows (passkey plugin)

Use an iPhone or Android phone as a FIDO2 / WebAuthn security key for
**Windows 11**, over USB. Keys never leave the phone (Secure Enclave on
iOS, Android Keystore on Android); every signature needs an on-phone
approval tap plus Face ID / biometrics. This directory contains the
Windows host side: a WebAuthn **passkey plugin** that forwards CTAP2
requests to the phone through the same Bridge Protocol v1 as the Linux
daemon.

> ## ⚠️ PREVIEW — not yet verified on hardware
>
> This code was written against Microsoft's official PasskeyManager
> sample and the `microsoft/webauthn` headers, but it has **never been
> compiled or run on a real Windows machine**. Every place that had to
> guess is marked `// VERIFY:` in the source. Expect the first build and
> the first on-device run to shake out issues. Do not rely on this build
> for accounts you cannot recover until the verification checklist in
> [docs/WINDOWS.md](../docs/WINDOWS.md) has been worked through on real
> hardware. The Linux + real-phone path *is* verified; the Windows path
> is not.

## How it works

```
Browser / Windows WebAuthn platform
        │  CTAP2 CBOR (plugin API)
        ▼
PhoneFidoKey.exe          ← COM local server in this MSIX
  IPluginAuthenticator       (C++ shim, derived from Microsoft's sample)
        │  pfk_process() — same bytes in, same bytes out
        ▼
iphone_fido.lib           ← the project's Rust core, as a C static library
        │  Bridge Protocol v1 (pairing PSK + ECDH + ChaCha20-Poly1305)
        ├─ TCP 127.0.0.1:18766 ── iproxy-style forward / `adb forward`
        └─ built-in usbmuxd client ── iPhone via Apple Devices drivers
        ▼
Phone app (iOS / Android) — builds authData, shows the approval sheet,
signs with the hardware-backed key after biometric approval.
```

Pieces in this directory:

| Path | What |
| ---- | ---- |
| `src/server/` | `PhoneFidoKey.exe` — the COM local server implementing `IPluginAuthenticator`. Verify platform signature → forward to `pfk_process()` → return bytes. |
| `src/setup/` | `PhoneFidoKeySetup.exe` — console tool: platform registration, pairing, status. |
| `src/common/` | Shared code: registration (sample-derived), request-signature verification (sample-derived, CNG), state paths, a minimal CBOR reader for metadata sync. |
| `include/phone_fido.h` | The fixed C ABI contract of the Rust static library. |
| `Package.appxmanifest` | MSIX manifest: `windows.comServer` extension for the plugin class + `runFullTrust`. |
| `build-msix.ps1` | One-shot build: cargo → MSBuild → makeappx → self-signed signing. |
| `Assets/` | Placeholder tile PNGs (regenerate: `tools/make-assets.py`). |

The plugin CLSID is `{1a4166a9-3797-4898-aec3-e39ea0823f5d}` — it is
baked into the source, the manifest and the platform registration, and
must not change once users have registered the authenticator.

## What the authenticator advertises

The GetInfo registered with the platform comes from the Rust core:
`pfk_static_get_info()` returns the daemon's full getInfo *response*
(status byte `0x00` + CBOR map), and registration passes the bytes
after the status byte, i.e. the bare authenticator-info map the
platform expects. That means the Windows plugin currently advertises
**`hmac-secret`, `hmac-secret-mc` and `prf`**, AAGUID per platform, and
transports `["usb"]`.

One open question, flagged in [docs/WINDOWS.md](../docs/WINDOWS.md):
under the plugin model there is no ClientPIN round-trip to the plugin,
and Microsoft's documentation does not say how `hmac-secret` salt
encryption is keyed in that case (their sample ignores it). **PRF is
unaffected** — the platform decodes `prf` into raw salts and the
existing PRF path (the one Chromium uses, verified end-to-end on Linux
with ppq.ai) applies. If interop testing shows `hmac-secret` ceremonies
failing on Windows, the fallback is to stop advertising `hmac-secret`
in the GetInfo registered on Windows (a Rust-side change, tracked
outside this directory) while keeping `prf` + `hmac-secret-mc`.

## Prerequisites

**Runtime**

- Windows 11 **24H2 or 25H2** with the **November 2025 cumulative
  update** installed (plugin platform GA build: 26100.6725 / 26200.6725
  or later). Check with `winver`.
- For an **iPhone**: the **Apple Devices** app (Microsoft Store) —
  provides the USB drivers and the usbmuxd service the built-in
  transport talks to.
- For an **Android phone**: `adb` (Android platform-tools) for
  `adb forward`, or use the phone over the same TCP transport as Linux.
- The Phone FIDO Key app on the phone (iOS via sideloading, Android via
  the project APK), same as for Linux.

**Build**

- Visual Studio 2022 (v143 toolset) with the Windows 11 SDK
  **10.0.26100.7175 or newer** (the first SDK carrying the plugin
  headers; the projects pin `10.0.26100.0`).
- Rust with the `x86_64-pc-windows-msvc` target:
  `rustup target add x86_64-pc-windows-msvc`.

## Build

```powershell
cd windows
.\build-msix.ps1
```

Outputs `windows\dist\PhoneFidoKey.msix` and
`windows\dist\PhoneFidoKey.cer`. A self-signed code-signing certificate
(`CN=PhoneFidoKey`) is created in your user store on first run and
reused afterwards; the manifest `Publisher` must match it.

## Install

1. **Trust the certificate.** Right-click `PhoneFidoKey.cer` →
   *Install Certificate* → **Local Machine** → *Place all certificates
   in the following store* → **Trusted People**. (Self-signed MSIX
   packages install only when the signing certificate is trusted.)
2. **Install the package.** Double-click `PhoneFidoKey.msix` → Install.
3. **Register + pair.** Open any terminal and run:
   ```text
   PhoneFidoKeySetup
   ```
   The guided flow registers the authenticator with the platform (if
   needed), then asks for the pairing key shown in the phone app,
   stores it at `%LOCALAPPDATA%\PhoneFidoKey\pairing.bin`, and prints a
   6-digit **SAS code — compare it with the phone** before trusting the
   pairing. Individual steps: `PhoneFidoKeySetup register | pair
   [--tcp|--usbmuxd] | status | unregister`.
4. **Enable the provider.** *Settings → Accounts → Passkeys* → turn on
   **Phone FIDO Key**. Windows asks for this once; the plugin cannot do
   it programmatically.
5. **Connect the phone.**
   - iPhone: plug in USB, unlock, trust the PC if asked. Use transport
     `usbmuxd` (`PhoneFidoKeySetup pair --usbmuxd`, or set it during the
     guided pairing).
   - Android: `adb forward tcp:18766 tcp:18765` with the TCP transport
     (the default).
6. **Test** at <https://webauthn.io>: register, then sign in. The phone
   must show the approval sheet for both.

State kept on the PC: the pairing file above, and two values under
`HKCU\Software\PhoneFidoKey` (operation-signing public key copy +
transport choice). Credentials themselves live only on the phone.

## Known gaps (honest list)

- **Not compiled / not run yet** — see the banner at the top. The C++
  was reduced from Microsoft's sample by hand; `// VERIFY:` comments
  mark every assumption (COM apartment choice, activation argument
  matching, metadata field requirements, lock-status semantics…).
- **CancelOperation is cooperative.** The C ABI has no `pfk_cancel()`,
  so a cancelled ceremony is discarded after the phone answers; the
  phone's approval sheet can outlive the browser's request until it is
  denied or times out (60 s). Same behavior as the Linux daemon.
- **Credential metadata sync is one-directional.** The platform's
  autofill list learns about a credential when it is created here
  (RP/user from the request, credential ID from the response). The ABI
  has no list-credentials call, so deletions on the phone and
  credentials created on other PCs never reconcile. Adding
  `pfk_list_credentials` to the ABI would close this.
- **GetLockStatus is approximate.** With no session-liveness call in
  the ABI, it reports *paired → unlocked, unpaired → locked*. If the
  platform treats "locked" as "must run Windows Hello first", this
  mapping needs revisiting on hardware (docs/WINDOWS.md, open
  question 1).
- **hmac-secret salt keying under plugins** is undocumented — see
  "What the authenticator advertises" above. PRF is unaffected.
- **Tile art is a placeholder** generated by `tools/make-assets.py`;
  the real logo lands separately.
