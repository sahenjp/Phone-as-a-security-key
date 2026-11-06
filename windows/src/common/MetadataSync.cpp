// MetadataSync.cpp - see MetadataSync.h.

#include "MetadataSync.h"

#include <span>
#include <vector>

#include "CborMini.h"
#include "Common.h"
#include "DelayLoad.h"
#include "Raii.h"

namespace pfk {

bool SyncNewCredential(std::span<const BYTE> request,
                       std::span<const BYTE> response) {
    // The response must be a success status byte + CBOR map containing
    // authData under key 2.
    if (response.size() < 2 || response[0] != 0x00) {
        return false;
    }
    std::span<const BYTE> authData;
    if (!cbor::FindMapByteString(response.subspan(1), 2, authData)) {
        return false;
    }
    std::span<const BYTE> credentialId;
    if (!cbor::ExtractCredentialId(authData, credentialId)) {
        return false;
    }

    // Decode the request for RP / user metadata (platform helper, as in
    // the sample's MakeCredential).
    PWEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST decoded = nullptr;
    const HRESULT hr = WebAuthNDecodeMakeCredentialRequest(
        static_cast<DWORD>(request.size()), request.data(), &decoded);
    if (FAILED(hr) || !decoded) {
        return false;
    }
    ScopeExit freeDecoded([&] { WebAuthNFreeDecodedMakeCredentialRequest(decoded); });

    const auto* rp = decoded->pRpInformation;
    const auto* user = decoded->pUserInformation;
    if (!rp || !user || !rp->pwszId || !user->pbId || user->cbId == 0) {
        return false;
    }

    WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS details{};
    details.cbCredentialId = static_cast<DWORD>(credentialId.size());
    details.pbCredentialId = credentialId.data();
    details.pwszRpId = rp->pwszId;
    // pwszName is optional in the request entity; fall back to the ID so
    // the required field is never null.
    // VERIFY: WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS::pwszRpName is marked
    // "required" in webauthnplugin.h; whether the platform accepts the
    // RP ID duplicated into the name slot is untested.
    details.pwszRpName = rp->pwszName ? rp->pwszName : rp->pwszId;
    details.cbUserId = user->cbId;
    details.pbUserId = user->pbId;
    details.pwszUserName = user->pwszName;
    details.pwszUserDisplayName = user->pwszDisplayName;

    return SUCCEEDED(
        WebAuthNPluginAuthenticatorAddCredentials(kPluginClsid, 1, &details));
}

}  // namespace pfk
