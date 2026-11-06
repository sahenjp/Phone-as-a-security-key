# Vendored WebAuthn plugin headers

These headers are **vendored verbatim** from Microsoft's official
[`microsoft/webauthn`](https://github.com/microsoft/webauthn) repository:

- **Pinned commit:** `ef82c157125a0490e05f6ea82a7adb1b8e1bad08`
  ("Merge pull request #32 from luis-zamarripa/finalizeV2 — Finalize new APIs")
- **Fetched:** 2026-11-06
- **License:** MIT (Microsoft Corporation) — see `LICENSE` in this folder.
- **Files:** `webauthn.h`, `webauthnplugin.h`, `pluginauthenticator.h`,
  `pluginauthenticator.idl` (the `.idl` is kept for reference; the build
  uses the MIDL-generated `pluginauthenticator.h` that the repository
  itself checks in, so no MIDL step is needed).

## Why vendored

The passkey plugin APIs were serviced into the Windows SDK only in
10.0.26100.7175+. The SDK copies in 10.0.26100.0 — what GitHub's
`windows-2025` runners ship — are internally inconsistent
(`webauthnplugin.h` there references operation-request fields its own
sibling `webauthn.h` predates) and do not compile. Vendoring the
canonical headers from the source repository makes the build
independent of the SDK servicing level for these headers.

## How the shim consumes them

All shim sources include them with the path prefix, in this order:

```cpp
#include <windows.h>
#include <webauthn/webauthn.h>
#include <webauthn/webauthnplugin.h>   // and/or <webauthn/pluginauthenticator.h>
```

`windows/include` is on both projects' `AdditionalIncludeDirectories`,
so these resolve here before any SDK copy. Nothing in the shim includes
a bare `<webauthn.h>` / `<webauthnplugin.h>` / `<pluginauthenticator.h>`.

`IPluginAuthenticator`, `WEBAUTHN_PLUGIN_OPERATION_REQUEST` /
`_RESPONSE`, `WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST` and
`PLUGIN_LOCK_STATUS` come from `pluginauthenticator.h`. The
registration / credential-metadata APIs and the CTAP-CBOR decode
helpers (`WebAuthNDecodeMakeCredentialRequest`, …) come from
`webauthnplugin.h`, which in turn relies on the base entity types in
`webauthn.h` — hence the include order above.

Do not edit the vendored files. To update, re-fetch the four files at a
new pinned commit, update the commit hash above, and re-check the shim
against any signature changes.
