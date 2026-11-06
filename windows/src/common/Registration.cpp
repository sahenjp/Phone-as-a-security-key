// Registration.cpp - see Registration.h. Derived from the sample's
// PluginRegistrationManager::RegisterPlugin / UnregisterPlugin /
// RefreshPluginState.

#include "Registration.h"

#include <vector>

#include "Common.h"
#include "DelayLoad.h"
#include "Raii.h"
#include "phone_fido.h"

namespace pfk {
namespace {

// GetInfo bytes from the Rust core. pfk_static_get_info() returns the
// full CTAP2 getInfo RESPONSE - a leading status byte (0x00) followed
// by the CBOR authenticator-info map, byte-identical to the daemon's
// getInfo response - while WebAuthNPluginAddAuthenticator's
// pbAuthenticatorInfo wants the bare map, so the status byte is
// checked and stripped here. The function is pure (never touches the
// phone), so the two-call sizing pattern is safe (unlike pfk_process()).
HRESULT GetAuthenticatorInfo(std::vector<BYTE>& out) {
    size_t len = 0;
    int32_t rc = pfk_static_get_info(nullptr, 0, &len);
    if (rc != PFK_ERR_BUFFER_TOO_SMALL || len < 2) {
        return E_FAIL;
    }
    std::vector<BYTE> full(len, 0);
    rc = pfk_static_get_info(full.data(), full.size(), &len);
    if (rc != PFK_OK || len < 2) {
        return E_FAIL;
    }
    full.resize(len);
    if (full[0] != 0x00) {  // CTAP status byte must be success
        return E_FAIL;
    }
    out.assign(full.begin() + 1, full.end());
    return S_OK;
}

// Store the operation signing public key returned by AddAuthenticator
// under HKCU\Software\PhoneFidoKey, as the sample does
// (c_windowsPluginRequestSigningKeyRegKeyName). At operation time the
// key is re-fetched via WebAuthNPluginGetOperationSigningPublicKey, so
// this copy is a fallback/forensics aid, not the source of truth.
HRESULT StoreOpSignPubKey(const BYTE* blob, DWORD cbBlob) {
    HKEY rawKey = nullptr;
    LONG err = RegCreateKeyExW(HKEY_CURRENT_USER, kRegistryPath, 0, nullptr,
                               REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr,
                               &rawKey, nullptr);
    if (err != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(err);
    }
    UniqueHkey key(rawKey);
    err = RegSetValueExW(key.get(), kRequestSigningKeyValueName, 0, REG_BINARY,
                         blob, cbBlob);
    if (err != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(err);
    }
    return S_OK;
}

}  // namespace

HRESULT RegisterPlugin() {
    std::vector<BYTE> authenticatorInfo;
    HRESULT hr = GetAuthenticatorInfo(authenticatorInfo);
    if (FAILED(hr)) {
        return hr;
    }

    // rclsid is REFCLSID (a reference member), so the options struct
    // cannot be default-initialized and assigned to; it must be
    // aggregate-initialized in member order.
    WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS addOptions{
        kPluginName,          // pwszAuthenticatorName
        kPluginClsid,         // rclsid
        kPluginRpId,          // pwszPluginRpId
        kLogoSvgBase64,       // pwszLightThemeLogoSvg
        kLogoSvgBase64,       // pwszDarkThemeLogoSvg
        static_cast<DWORD>(authenticatorInfo.size()),  // cbAuthenticatorInfo
        authenticatorInfo.data(),                      // pbAuthenticatorInfo
        0,        // cSupportedRpIds: 0/nullptr = all RPs supported
        nullptr,  // ppwszSupportedRpIds
    };

    PWEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE addResponse = nullptr;
    hr = WebAuthNPluginAddAuthenticator(&addOptions, &addResponse);
    if (FAILED(hr)) {
        return hr;
    }
    // Ensure the response is freed when it goes out of scope (sample:
    // wil::scope_exit + WebAuthNPluginFreeAddAuthenticatorResponse).
    ScopeExit freeResponse([&] { WebAuthNPluginFreeAddAuthenticatorResponse(addResponse); });

    if (addResponse && addResponse->pbOpSignPubKey && addResponse->cbOpSignPubKey > 0) {
        // Best effort: a registry failure must not fail registration.
        (void)StoreOpSignPubKey(addResponse->pbOpSignPubKey, addResponse->cbOpSignPubKey);
    }
    return S_OK;
}

HRESULT UnregisterPlugin() {
    // Best effort: drop synced credential metadata first so the
    // platform's autofill list does not keep entries for an
    // authenticator that is gone.
    (void)WebAuthNPluginAuthenticatorRemoveAllCredentials(kPluginClsid);
    return WebAuthNPluginRemoveAuthenticator(kPluginClsid);
}

HRESULT QueryPluginState(bool& registered, AUTHENTICATOR_STATE& state) {
    registered = false;
    state = AuthenticatorState_Disabled;
    AUTHENTICATOR_STATE localState = AuthenticatorState_Disabled;
    const HRESULT hr = WebAuthNPluginGetAuthenticatorState(kPluginClsid, &localState);
    if (FAILED(hr)) {
        return hr;  // e.g. NTE_NOT_FOUND when never registered
    }
    registered = true;
    state = localState;
    return S_OK;
}

}  // namespace pfk
