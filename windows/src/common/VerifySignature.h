// VerifySignature.h - verification of the platform's signature over
// operation requests.
//
// Every WEBAUTHN_PLUGIN_OPERATION_REQUEST carries pbRequestSignature: the
// platform signs the encoded request with the operation signing key whose
// public half it handed out at registration time
// (WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_RESPONSE::pbOpSignPubKey). The plugin
// must verify before trusting a request - otherwise any local process
// could drive the COM server. See pluginauthenticator.idl.

#pragma once

#include <windows.h>

#include <cstdint>
#include <span>
#include <vector>

namespace pfk {

// Fetch the platform's operation signing public key (a CNG
// PUBLIC_KEY_BLOB) via WebAuthNPluginGetOperationSigningPublicKey.
// Returns an empty vector on failure. Mirrors the sample's
// GetRequestSigningPubKey().
std::vector<uint8_t> GetRequestSigningPubKey();

// Verify that `signature` is the platform's signature over
// SHA-256(`dataBuffer`), using the CNG public key blob `keyBlob`.
// RSA keys are verified with PSS padding (SHA-256, 32-byte salt), other
// keys (ECDSA) without padding - exactly the sample's
// VerifySignatureHelper() from PluginAuthenticatorImpl.cpp.
// Returns S_OK only if the signature is valid.
HRESULT VerifyRequestSignature(std::span<const BYTE> dataBuffer,
                               const BYTE* keyBlob, DWORD cbKeyBlob,
                               const BYTE* signature, DWORD cbSignature);

// Convenience: fetch the key and verify. Fails (returns a failing
// HRESULT) if the key cannot be obtained at all; callers must treat that
// as "do not trust this request".
HRESULT VerifyPlatformRequest(std::span<const BYTE> encodedRequest,
                              const BYTE* signature, DWORD cbSignature);

}  // namespace pfk
