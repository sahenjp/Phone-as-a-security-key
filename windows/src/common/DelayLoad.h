// DelayLoad.h - runtime resolution of the WebAuthN plugin APIs from
// webauthn.dll.
//
// Derived from the Microsoft PasskeyManager sample's DelayLoad.h, trimmed
// to the functions the shim actually calls. The plugin APIs only exist on
// Windows 11 24H2/25H2 with the November 2025 update; resolving them at
// runtime (instead of linking webauthn.lib) makes the binaries start -
// and fail cleanly with E_NOTIMPL - on older systems, exactly like the
// sample.
//
// Adaptation from the sample: the sample resolves through WIL's
// GetProcAddressByFunctionDeclaration(). We depend only on the SDK, so
// ResolveWebAuthnProc() below does the equivalent GetProcAddress with an
// explicit export name. Wrapper signatures match webauthnplugin.h and
// webauthn.h verbatim.

#pragma once

#include <windows.h>
#include <webauthn.h>
#include <webauthnplugin.h>

#include <type_traits>

#include "Raii.h"

#pragma region Checking for Windows SDK version 10.0.26100.7175 or higher
template <typename, typename = void>
constexpr bool pfk_is_type_complete_v = false;
template <typename T>
constexpr bool pfk_is_type_complete_v<T, std::void_t<decltype(sizeof(T))>> = true;

static_assert(pfk_is_type_complete_v<struct _WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS>,
              "This project requires Windows SDK version 10.0.26100.7175 or higher");
#pragma endregion

namespace pfk {

inline HMODULE GetWebAuthnDll() {
    static HMODULE s_dll = LoadLibraryExW(L"webauthn.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    return s_dll;
}

template <typename TFn>
inline TFn ResolveWebAuthnProc(const char* exportName) {
    HMODULE dll = GetWebAuthnDll();
    if (!dll) {
        return nullptr;
    }
    return reinterpret_cast<TFn>(GetProcAddress(dll, exportName));
}

}  // namespace pfk

// ---------------------------------------------------------------------------
// Plugin management APIs (webauthnplugin.h)
// ---------------------------------------------------------------------------

inline HRESULT WINAPI WebAuthNPluginAddAuthenticator(
    _In_ PCWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS pPluginAddAuthenticatorOptions,
    _Outptr_result_maybenull_ PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE* ppPluginAddAuthenticatorResponse) {
    using Fn = decltype(&WebAuthNPluginAddAuthenticator);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNPluginAddAuthenticator");
    if (!s_fn) return E_NOTIMPL;
    return s_fn(pPluginAddAuthenticatorOptions, ppPluginAddAuthenticatorResponse);
}

inline void WINAPI WebAuthNPluginFreeAddAuthenticatorResponse(
    _In_opt_ PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE pPluginAddAuthenticatorResponse) {
    using Fn = decltype(&WebAuthNPluginFreeAddAuthenticatorResponse);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNPluginFreeAddAuthenticatorResponse");
    if (s_fn) s_fn(pPluginAddAuthenticatorResponse);
}

inline HRESULT WINAPI WebAuthNPluginRemoveAuthenticator(_In_ REFCLSID rclsid) {
    using Fn = decltype(&WebAuthNPluginRemoveAuthenticator);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNPluginRemoveAuthenticator");
    if (!s_fn) return E_NOTIMPL;
    return s_fn(rclsid);
}

inline HRESULT WINAPI WebAuthNPluginGetAuthenticatorState(
    _In_ REFCLSID rclsid,
    _Out_ AUTHENTICATOR_STATE* pluginAuthenticatorState) {
    using Fn = decltype(&WebAuthNPluginGetAuthenticatorState);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNPluginGetAuthenticatorState");
    if (!s_fn) return E_NOTIMPL;
    return s_fn(rclsid, pluginAuthenticatorState);
}

inline HRESULT WINAPI WebAuthNPluginGetOperationSigningPublicKey(
    _In_ REFCLSID rclsid,
    _Out_ DWORD* pcbOpSignPubKey,
    _Outptr_result_buffer_maybenull_(*pcbOpSignPubKey) PBYTE* ppbOpSignPubKey) {
    using Fn = decltype(&WebAuthNPluginGetOperationSigningPublicKey);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNPluginGetOperationSigningPublicKey");
    if (!s_fn) return E_NOTIMPL;
    return s_fn(rclsid, pcbOpSignPubKey, ppbOpSignPubKey);
}

inline void WINAPI WebAuthNPluginFreePublicKeyResponse(_In_opt_ PBYTE pbOpSignPubKey) {
    using Fn = decltype(&WebAuthNPluginFreePublicKeyResponse);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNPluginFreePublicKeyResponse");
    if (s_fn) s_fn(pbOpSignPubKey);
}

// ---------------------------------------------------------------------------
// Credential metadata APIs (webauthnplugin.h)
// ---------------------------------------------------------------------------

inline HRESULT WINAPI WebAuthNPluginAuthenticatorAddCredentials(
    _In_ REFCLSID rclsid,
    _In_ DWORD cCredentialDetails,
    _In_reads_(cCredentialDetails) PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS pCredentialDetails) {
    using Fn = decltype(&WebAuthNPluginAuthenticatorAddCredentials);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNPluginAuthenticatorAddCredentials");
    if (!s_fn) return E_NOTIMPL;
    return s_fn(rclsid, cCredentialDetails, pCredentialDetails);
}

inline HRESULT WINAPI WebAuthNPluginAuthenticatorRemoveCredentials(
    _In_ REFCLSID rclsid,
    _In_ DWORD cCredentialDetails,
    _In_reads_(cCredentialDetails) PCWEBAUTHN_PLUGIN_CREDENTIAL_DETAILS pCredentialDetails) {
    using Fn = decltype(&WebAuthNPluginAuthenticatorRemoveCredentials);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNPluginAuthenticatorRemoveCredentials");
    if (!s_fn) return E_NOTIMPL;
    return s_fn(rclsid, cCredentialDetails, pCredentialDetails);
}

inline HRESULT WINAPI WebAuthNPluginAuthenticatorRemoveAllCredentials(_In_ REFCLSID rclsid) {
    using Fn = decltype(&WebAuthNPluginAuthenticatorRemoveAllCredentials);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNPluginAuthenticatorRemoveAllCredentials");
    if (!s_fn) return E_NOTIMPL;
    return s_fn(rclsid);
}

// ---------------------------------------------------------------------------
// Request decoding helpers (webauthn.h) - used only by best-effort
// credential metadata sync after a successful MakeCredential.
// ---------------------------------------------------------------------------

inline _Success_(return == S_OK) HRESULT WINAPI WebAuthNDecodeMakeCredentialRequest(
    _In_ DWORD cbEncoded,
    _In_reads_bytes_(cbEncoded) const BYTE* pbEncoded,
    _Outptr_ PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST* ppMakeCredentialRequest) {
    using Fn = decltype(&WebAuthNDecodeMakeCredentialRequest);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNDecodeMakeCredentialRequest");
    if (!s_fn) return E_NOTIMPL;
    return s_fn(cbEncoded, pbEncoded, ppMakeCredentialRequest);
}

inline void WINAPI WebAuthNFreeDecodedMakeCredentialRequest(
    _In_opt_ PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST pMakeCredentialRequest) {
    using Fn = decltype(&WebAuthNFreeDecodedMakeCredentialRequest);
    static auto s_fn = pfk::ResolveWebAuthnProc<Fn>("WebAuthNFreeDecodedMakeCredentialRequest");
    if (s_fn) s_fn(pMakeCredentialRequest);
}

namespace pfk {

// RAII for buffers returned by WebAuthNPluginGetOperationSigningPublicKey
// (freed with WebAuthNPluginFreePublicKeyResponse). Corresponds to the
// sample's unique_plugin_public_key typedef in its pch.h.
struct PluginPublicKeyDeleter {
    void operator()(PBYTE p) const {
        if (p) WebAuthNPluginFreePublicKeyResponse(p);
    }
};
using UniquePluginPublicKey = UniqueHandle<PBYTE, PluginPublicKeyDeleter>;

}  // namespace pfk
