// VerifySignature.cpp
//
// Derived from Microsoft's PasskeyManager sample,
// PluginAuthenticator/PluginAuthenticatorImpl.cpp: GetRequestSigningPubKey()
// and VerifySignatureHelper(). The CNG call sequence is unchanged; only
// the WIL RAII types / return macros were replaced with the local
// equivalents in Raii.h and explicit checks.

#include "VerifySignature.h"

#include <bcrypt.h>
#include <ncrypt.h>

#include "Common.h"
#include "DelayLoad.h"
#include "Raii.h"

namespace pfk {

std::vector<uint8_t> GetRequestSigningPubKey() {
    DWORD cbKeyData = 0;
    PBYTE pbKeyDataRaw = nullptr;
    const HRESULT hr = WebAuthNPluginGetOperationSigningPublicKey(
        kPluginClsid, &cbKeyData, &pbKeyDataRaw);
    UniquePluginPublicKey pbKeyData(pbKeyDataRaw);

    if (SUCCEEDED(hr) && pbKeyData && cbKeyData > 0) {
        return std::vector<uint8_t>(pbKeyData.get(), pbKeyData.get() + cbKeyData);
    }
    return {};
}

HRESULT VerifyRequestSignature(std::span<const BYTE> dataBuffer,
                               const BYTE* keyBlob, DWORD cbKeyBlob,
                               const BYTE* signature, DWORD cbSignature) {
    // Create key provider
    NCRYPT_PROV_HANDLE provRaw = 0;
    HRESULT hr = NCryptOpenStorageProvider(&provRaw, nullptr, 0);
    if (FAILED(hr)) {
        return hr;
    }
    UniqueNcryptProv hProvider(provRaw);

    // Create an NCrypt key handle from the public key
    NCRYPT_KEY_HANDLE keyRaw = 0;
    hr = NCryptImportKey(hProvider.get(), NULL, BCRYPT_PUBLIC_KEY_BLOB,
                         nullptr, &keyRaw,
                         const_cast<PBYTE>(keyBlob), cbKeyBlob, 0);
    if (FAILED(hr)) {
        return hr;
    }
    UniqueNcryptKey reqSigningKey(keyRaw);

    // Hash the request buffer with SHA-256 (the signature is over the
    // hash, not over the buffer itself).
    DWORD objLenSize = 0;
    DWORD bytesRead = 0;
    NTSTATUS status = BCryptGetProperty(
        BCRYPT_SHA256_ALG_HANDLE, BCRYPT_OBJECT_LENGTH,
        reinterpret_cast<PBYTE>(&objLenSize), sizeof(objLenSize), &bytesRead, 0);
    if (status < 0) {
        return HRESULT_FROM_NT(status);
    }

    auto objLen = std::make_unique<BYTE[]>(objLenSize);

    BCRYPT_HASH_HANDLE hashRaw = nullptr;
    status = BCryptCreateHash(BCRYPT_SHA256_ALG_HANDLE, &hashRaw, objLen.get(),
                              objLenSize, nullptr, 0, 0);
    if (status < 0) {
        return HRESULT_FROM_NT(status);
    }
    UniqueBcryptHash hashHandle(hashRaw);

    status = BCryptHashData(hashHandle.get(),
                            const_cast<PUCHAR>(dataBuffer.data()),
                            static_cast<ULONG>(dataBuffer.size()), 0);
    if (status < 0) {
        return HRESULT_FROM_NT(status);
    }

    DWORD localHashByteCount = 0;
    status = BCryptGetProperty(BCRYPT_SHA256_ALG_HANDLE, BCRYPT_HASH_LENGTH,
                               reinterpret_cast<PBYTE>(&localHashByteCount),
                               sizeof(localHashByteCount), &bytesRead, 0);
    if (status < 0) {
        return HRESULT_FROM_NT(status);
    }

    auto localHashBuffer = std::make_unique<BYTE[]>(localHashByteCount);

    status = BCryptFinishHash(hashHandle.get(), localHashBuffer.get(),
                              localHashByteCount, 0);
    if (status < 0) {
        return HRESULT_FROM_NT(status);
    }

    // RSA operation signing keys sign with PSS padding; ECDSA keys sign
    // raw. The key blob magic tells us which one we hold.
    if (cbKeyBlob < sizeof(BCRYPT_KEY_BLOB)) {
        return E_INVALIDARG;
    }
    const auto* pKeyBlob = reinterpret_cast<const BCRYPT_KEY_BLOB*>(keyBlob);

    BCRYPT_PSS_PADDING_INFO paddingInfoStruct = {BCRYPT_SHA256_ALGORITHM, 32};
    PVOID paddingInfo = nullptr;
    DWORD dwCngFlags = 0;
    if (pKeyBlob->Magic == BCRYPT_RSAPUBLIC_MAGIC) {
        paddingInfo = &paddingInfoStruct;
        dwCngFlags = BCRYPT_PAD_PSS;
    }

    const DWORD verifyError = NCryptVerifySignature(
        reqSigningKey.get(), paddingInfo, localHashBuffer.get(),
        localHashByteCount, const_cast<PBYTE>(signature), cbSignature,
        dwCngFlags);
    if (verifyError != ERROR_SUCCESS) {
        return HRESULT_FROM_WIN32(verifyError);
    }
    return S_OK;
}

HRESULT VerifyPlatformRequest(std::span<const BYTE> encodedRequest,
                              const BYTE* signature, DWORD cbSignature) {
    const std::vector<uint8_t> pubKeyData = GetRequestSigningPubKey();
    if (pubKeyData.empty()) {
        // Without the platform's key we cannot establish that this
        // request really came from the platform. Fail closed.
        return E_FAIL;
    }
    return VerifyRequestSignature(encodedRequest, pubKeyData.data(),
                                  static_cast<DWORD>(pubKeyData.size()),
                                  signature, cbSignature);
}

}  // namespace pfk
