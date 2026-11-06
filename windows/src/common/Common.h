// Common.h - shared constants and helpers for the Windows shim:
// the plugin COM server (PhoneFidoKey.exe) and the console companion
// (PhoneFidoKeySetup.exe).

#pragma once

#include <windows.h>

#include <cstdint>
#include <string>
#include <string_view>

namespace pfk {

// CLSID of the IPluginAuthenticator implementation. This is OUR class id:
// it appears in Package.appxmanifest (com:Class Id), in the
// CoRegisterClassObject call, and in every WebAuthNPlugin* call.
// It must never change once a build has been distributed, or existing
// installs would register a second, orphaned authenticator.
//   {1a4166a9-3797-4898-aec3-e39ea0823f5d}
inline constexpr GUID kPluginClsid = {
    0x1a4166a9, 0x3797, 0x4898, {0xae, 0xc3, 0xe3, 0x9e, 0xa0, 0x82, 0x3f, 0x5d}};

// Display name used at registration time (WebAuthNPluginAddAuthenticator)
// and shown by Windows in Settings > Accounts > Passkeys.
inline constexpr wchar_t kPluginName[] = L"Phone FIDO Key";

// Plugin RP ID. Only used if the plugin itself originates a nested
// WebAuthn call (the sample uses it for its vault-unlock passkey). We
// never originate nested calls; the value only has to be a syntactically
// valid RP ID.
// VERIFY: whether the platform accepts/uses this value for anything else
// (e.g. filtering ceremonies whose RP matches it) is undocumented. The
// sample (PluginRegistrationManager.h, c_pluginRpId) rejects requests for
// its own plugin RP name in MakeCredential; we do not replicate that
// check because we forward raw CBOR and never decode requests on the
// MakeCredential path (except in best-effort metadata sync).
inline constexpr wchar_t kPluginRpId[] = L"sahen.site";

// Per-user state, mirroring the sample's HKCU storage:
//   Software\PhoneFidoKey\RequestSigningKeyBlob  (REG_BINARY, op-sign key)
//   Software\PhoneFidoKey\Transport              (REG_DWORD, PFK_TRANSPORT_*)
inline constexpr wchar_t kRegistryPath[] = L"Software\\PhoneFidoKey";
inline constexpr wchar_t kRequestSigningKeyValueName[] = L"RequestSigningKeyBlob";
inline constexpr wchar_t kTransportValueName[] = L"Transport";

// Package logo (base64 SVG 1.1) passed at registration time, taken from
// the sample's approach of embedding the logo in
// WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS. Simple key glyph; the same
// image is used for light and dark themes.
// VERIFY: the sample ships two different gradient logos; whether the
// platform falls back gracefully when both are identical (or null) is
// untested on hardware.
inline constexpr wchar_t kLogoSvgBase64[] =
    L"PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgdmlld0JveD0iMCAwIDEwMCAxMDAiPjxjaXJj"
    L"bGUgY3g9IjM2IiBjeT0iMzYiIHI9IjE5IiBmaWxsPSJub25lIiBzdHJva2U9IiM1OEE2RkYiIHN0cm9rZS13aWR0aD0iMTAiLz48cGF0aCBk"
    L"PSJNNTAgNTAgTDg1IDg1IE03MSA3MSBMODMgNTkgTTYxIDYxIEw3MSA1MSIgc3Ryb2tlPSIjNThBNkZGIiBzdHJva2Utd2lkdGg9IjEwIiBz"
    L"dHJva2UtbGluZWNhcD0icm91bmQiIGZpbGw9Im5vbmUiLz48L3N2Zz4=";

// %LOCALAPPDATA%\PhoneFidoKey - created if missing. Empty on failure.
std::wstring StateDirectory();
// Full path of the pairing file: StateDirectory() + L"\\pairing.bin".
std::wstring PairingFilePath();
// True when a non-empty pairing file exists (used by GetLockStatus and
// the companion's status output; says nothing about phone reachability).
bool IsPaired();

// Transport for pfk_create(): the registry value wins, the PFK_TRANSPORT
// environment variable ("0" / "1") overrides it, default is
// PFK_TRANSPORT_TCP.
int32_t ReadTransportSetting();
// Persist the transport choice (used by the companion's pair command).
bool WriteTransportSetting(int32_t transport);

std::string Utf8FromWide(std::wstring_view text);
std::wstring WideFromUtf8(std::string_view text);

// HRESULT for the last Win32 error, like wil::ResultFromWin32Error.
inline HRESULT HresultFromLastWin32Error() {
    const DWORD err = GetLastError();
    return err ? HRESULT_FROM_WIN32(err) : E_FAIL;
}

}  // namespace pfk
