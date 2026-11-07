# macOS support

Status: **implemented, awaiting verification on a real Mac.**
The daemon, the bridge protocol, pairing and the CTAP2 core are the
same code as on Linux and are covered by the same unit tests and
`selftest`. What is macOS-specific is how the virtual authenticator
device is presented to the OS, and that part can only be proven on
real hardware (the maintainers' testing so far is Linux + iPhone).

## How it works

On Linux the daemon creates the virtual security key with the
kernel's UHID subsystem. macOS has no UHID; the equivalent is IOKit's
**IOHIDUserDevice**, which creates a userspace HID device that
IOHIDManager clients enumerate exactly like a USB security key
(FIDO usage page 0xF1D0, VID 0x1209 / PID 0xF1D0, the standard
34-byte report descriptor — identical device identity to the Linux
build).

```
Chrome / libfido2 / pam_u2f          (IOHIDManager / hidapi)
        |  CTAPHID 64-byte reports
IOHIDUserDevice  <-- src/transport.rs `MacHidTransport` (macOS only)
        |
iphone-fido daemon (same CTAP2 core as Linux)
        |  bridge protocol over TCP 127.0.0.1:18766 (unchanged)
iproxy (iPhone) / adb forward (Android)
        |
phone app (unchanged)
```

Select it with `--transport machid`; it is the default transport
when the daemon is built for macOS (`--transport uhid` remains
Linux-only, `--transport stdio` works everywhere).

## The one hard constraint: privilege for virtual HID

On modern macOS, `IOHIDUserDeviceCreate` returns NULL unless the
process is either

1. **root** — e.g. a LaunchDaemon, or
2. signed with the **restricted entitlement**
   `com.apple.developer.hid.virtual.device`, which requires a
   provisioning profile from a **paid Apple Developer team**.
   Ad-hoc signing with this entitlement is worse than no
   entitlement: AMFI kills the binary at launch.

There is no third route (the SoftU2F kernel extension is dead since
Big Sur; DriverKit would need the same class of Apple-granted
entitlement plus a system-extension install flow). This mirrors
what other software-FIDO projects document for macOS.

The daemon detects the NULL case and exits with an error naming
both routes instead of failing silently.

## Setup (root / LaunchDaemon route)

```sh
# Build (or download a release binary once macOS builds ship).
cargo build --release

# Phone-side forwarder — same as Linux. The phone app listens on
# TCP 18765; the daemon expects it forwarded to 127.0.0.1:18766.
brew install libimobiledevice   # iPhone: provides iproxy + tools
iproxy 18766 18765              # iPhone, USB connected
# Android instead: adb forward tcp:18766 tcp:18765

# Pair once. The daemon runs as root, so pair as root too (the
# pairing secret lands in /var/root/.config/iphone-fido/pairing.bin).
sudo ./target/release/iphone-fido pair-qr   # scan with the phone app

# Install the daemon.
sudo cp target/release/iphone-fido /usr/local/bin/
sudo cp packaging/macos/site.sahen.phonefido.plist /Library/LaunchDaemons/
sudo launchctl load -w /Library/LaunchDaemons/site.sahen.phonefido.plist
tail -f /var/log/phonefido.log
```

## Setup (signed, non-root route)

With a paid-team profile that includes the virtual-HID entitlement:

```sh
codesign --entitlements packaging/macos/phonefido.entitlements \
         --sign "Developer ID Application: ..." \
         target/release/iphone-fido
./target/release/iphone-fido run        # machid is the default
```

## What should work, and what is not promised

| Client on macOS | Expected | Notes |
| --- | --- | --- |
| Chrome | Should work | Chrome enumerates HID FIDO devices directly via IOHIDManager; it does not use Apple's WebAuthn API for roaming authenticators. |
| libfido2 tools (`fido2-token -L`) | Should work | hidapi enumerates via IOHIDManager, same as Chrome. |
| `pam_u2f` for macOS login / lock | Should work | Same mechanism as the verified Fedora setup; needs `pam-u2f` + `libfido2` (Homebrew) and the usual `u2f_keys` enrollment. Not yet tested. |
| Firefox | Unlikely | Firefox on macOS routes WebAuthn through Apple's OS-managed API, not raw HID. |
| Safari | Unlikely | Safari uses AuthenticationServices / CryptoTokenKit, which historically binds to USB-plane HID devices, not IOHIDUserDevice nodes. |

## Verification checklist (for whoever runs this on a Mac first)

1. `sudo iphone-fido run --transport machid --verbose` starts
   without the NULL error, phone paired, bridge ping OK.
2. `fido2-token -L` (from `brew install libfido2`) lists
   `vendor=0x1209, product=0xf1d0`.
3. Chrome → webauthn.io: register + authenticate with the real
   phone (tap + Face ID), same as the Linux stage (e) test.
4. `pamu2fcfg` enrollment + a `pamtester` service, mirroring the
   Fedora Plasma-login verification, before touching the real
   macOS login PAM stack.

Please report results (macOS version, which privilege route,
which clients worked) as a GitHub issue so this document can drop
the "awaiting verification" label.
