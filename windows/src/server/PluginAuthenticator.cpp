// PluginAuthenticator.cpp - see PluginAuthenticator.h.
//
// Flow for MakeCredential / GetAssertion, following the sample's
// PluginAuthenticatorImpl where it applies to a transport-only plugin:
//   1. Validate the request and check it is a CTAP2 CBOR request.
//   2. Verify the platform signature over the encoded request
//      (VerifySignature.cpp; the sample performs the same verification
//      and then additionally runs its Hello UV flow - which is the
//      sample's real gate. We have no second gate on the PC, so a
//      failed verification is fatal here; see the VERIFY note below).
//   3. Forward the raw bytes to the Rust core (pfk_process) and return
//      its raw response. The phone displays the RP, the user approves
//      and biometrics run on the phone; authData is built there.
//   4. After a successful MakeCredential, best-effort metadata sync.

#include "PluginAuthenticator.h"

#include <cstdio>
#include <cstring>
#include <mutex>
#include <new>
#include <vector>

#include "Common.h"
#include "MetadataSync.h"
#include "Raii.h"
#include "VerifySignature.h"
#include "phone_fido.h"

namespace pfk {
namespace {

// Response buffer for pfk_process(). CTAP responses from this
// authenticator are a few hundred bytes; 64 KiB is far above anything
// the bridge can produce (its frame limit is 1 MiB, but attestation
// objects here carry no certificate chains - fmt "none").
constexpr size_t kResponseBufferSize = 64 * 1024;

// Serializes ceremonies: the phone shows one approval sheet at a time,
// and a PfkHandle is not safe for concurrent use.
std::mutex g_opMutex;

// In-flight operation bookkeeping for CancelOperation. Guarded by
// g_stateMutex, which is never held across pfk_process(), so a cancel
// can always get through while a ceremony is blocked on the phone.
std::mutex g_stateMutex;
GUID g_inflightTransaction{};
bool g_hasInflight = false;
GUID g_cancelledTransaction{};
bool g_hasCancelled = false;

// The shared Rust handle. Guarded by g_opMutex. Created lazily on the
// first operation; destroyed and recreated after a cancellation,
// because the bridge session may hold a late response for the cancelled
// transaction.
PfkHandle* g_handle = nullptr;

bool EnsureHandle() {
    if (g_handle) {
        return true;
    }
    const std::string pairingPath = Utf8FromWide(PairingFilePath());
    if (pairingPath.empty()) {
        return false;
    }
    char errBuf[256] = {};
    // pfk_create() loads the pairing file EAGERLY: a NULL return with a
    // "missing/malformed pairing file" message is the not-paired-yet
    // state (the fix is `PhoneFidoKeySetup pair`, which the user runs;
    // this server has no UI to guide them). It does NOT connect to the
    // phone - the bridge session comes up lazily inside pfk_process().
    g_handle = pfk_create(pairingPath.c_str(), ReadTransportSetting(),
                          errBuf, sizeof(errBuf));
    if (!g_handle) {
        OutputDebugStringA("PhoneFidoKey: pfk_create failed: ");
        OutputDebugStringA(errBuf);
        OutputDebugStringA("\n");
        return false;
    }
    return true;
}

void DropHandle() {
    if (g_handle) {
        pfk_destroy(g_handle);
        g_handle = nullptr;
    }
}

bool ConsumeCancellation(const GUID& transactionId) {
    std::lock_guard lock(g_stateMutex);
    if (g_hasCancelled && IsEqualGUID(g_cancelledTransaction, transactionId)) {
        g_hasCancelled = false;
        return true;
    }
    return false;
}

// --- Server lifetime state -------------------------------------------------
std::atomic<long> g_serverObjects{0};
std::atomic<long> g_serverLocks{0};
std::atomic<bool> g_serverServed{false};
HANDLE g_shutdownEvent = nullptr;
std::once_flag g_shutdownEventOnce;

void MaybeSignalShutdown() {
    if (g_serverServed.load() && g_serverObjects.load() == 0 &&
        g_serverLocks.load() == 0) {
        SetEvent(ServerShutdownEvent());
    }
}

}  // namespace

void ServerNotifyObjectCreated() {
    g_serverServed = true;
    g_serverObjects.fetch_add(1);
}

void ServerNotifyObjectDestroyed() {
    g_serverObjects.fetch_sub(1);
    MaybeSignalShutdown();
}

void ServerNotifyServerLock(bool lock) {
    if (lock) {
        g_serverLocks.fetch_add(1);
    } else {
        g_serverLocks.fetch_sub(1);
        MaybeSignalShutdown();
    }
}

bool ServerHasServed() { return g_serverServed.load(); }

HANDLE ServerShutdownEvent() {
    std::call_once(g_shutdownEventOnce, [] {
        g_shutdownEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    });
    return g_shutdownEvent;
}

// --- PhoneFidoPlugin -------------------------------------------------------

PhoneFidoPlugin::PhoneFidoPlugin() { ServerNotifyObjectCreated(); }

PhoneFidoPlugin::~PhoneFidoPlugin() { ServerNotifyObjectDestroyed(); }

HRESULT STDMETHODCALLTYPE PhoneFidoPlugin::QueryInterface(REFIID riid, void** ppvObject) {
    if (!ppvObject) {
        return E_INVALIDARG;
    }
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, __uuidof(IPluginAuthenticator))) {
        *ppvObject = static_cast<IPluginAuthenticator*>(this);
        AddRef();
        return S_OK;
    }
    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE PhoneFidoPlugin::AddRef() {
    return static_cast<ULONG>(m_refCount.fetch_add(1) + 1);
}

ULONG STDMETHODCALLTYPE PhoneFidoPlugin::Release() {
    const long count = m_refCount.fetch_sub(1) - 1;
    if (count == 0) {
        delete this;
    }
    return static_cast<ULONG>(count);
}

HRESULT PhoneFidoPlugin::DoOperation(
    PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
    PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response, bool isMakeCredential) {
    if (!response) {
        return E_INVALIDARG;
    }
    *response = {};
    if (!request || !request->pbEncodedRequest || request->cbEncodedRequest == 0) {
        return E_INVALIDARG;
    }
    if (request->requestType != WEBAUTHN_PLUGIN_REQUEST_TYPE_CTAP2_CBOR) {
        // Currently the only request type the platform sends.
        return E_NOTIMPL;
    }

    const std::span<const BYTE> requestBytes(request->pbEncodedRequest,
                                             request->cbEncodedRequest);

    // The platform signs every request with its operation signing key;
    // refuse anything we cannot attribute to the platform.
    //
    // VERIFY (deviation from the sample, deliberate): the sample records
    // the verification result in its UI state and continues, because its
    // PerformUserVerification() then verifies a *second* signature (the
    // Hello UV signature over the same buffer) before touching keys.
    // This plugin performs no Hello UV - the phone does user
    // verification - so request signature verification is the only
    // platform-authenticity check and must be fatal. If real platform
    // requests ever fail this check (e.g. key rollover races), the
    // fallback would be to mirror the sample and only log; that would
    // need a conscious security decision, not a silent change.
    const HRESULT verifyHr = VerifyPlatformRequest(
        requestBytes, request->pbRequestSignature, request->cbRequestSignature);
    if (FAILED(verifyHr)) {
        return E_ACCESSDENIED;
    }

    std::lock_guard opLock(g_opMutex);
    {
        std::lock_guard stateLock(g_stateMutex);
        g_inflightTransaction = request->transactionId;
        g_hasInflight = true;
    }
    ScopeExit clearInflight([&] {
        std::lock_guard stateLock(g_stateMutex);
        if (g_hasInflight && IsEqualGUID(g_inflightTransaction, request->transactionId)) {
            g_hasInflight = false;
        }
    });

    if (!EnsureHandle()) {
        return E_FAIL;
    }

    std::vector<BYTE> outBuffer(kResponseBufferSize);
    size_t outLen = 0;
    const int32_t rc = pfk_process(g_handle, requestBytes.data(),
                                   requestBytes.size(), outBuffer.data(),
                                   outBuffer.size(), &outLen);

    // A cancel that arrived while the phone was deciding wins over the
    // (now meaningless) result. Drop the bridge session too: it may
    // still hold state tied to the cancelled transaction.
    if (ConsumeCancellation(request->transactionId)) {
        DropHandle();
        return NTE_USER_CANCELLED;
    }

    if (rc != PFK_OK) {
        // Per the canonical ABI (windows/include/phone_fido.h), a
        // negative return means no CTAP response exists at all - and
        // for PFK_ERR_BUFFER_TOO_SMALL the ceremony did not even run.
        // Every phone/bridge failure (phone unreachable, user denied
        // on the phone, no credentials) instead arrives as a CTAP
        // status byte inside a PFK_OK payload. With a 64 KiB buffer
        // none of the negative codes (BUFFER_TOO_SMALL,
        // INVALID_ARGUMENT, PANIC) are expected in practice; map them
        // all to a generic failure.
        // VERIFY: whether the platform distinguishes plugin HRESULTs in
        // any user-visible way (the sample only ever returns success,
        // NTE_USER_CANCELLED, NTE_NOT_FOUND and HRESULT_FROM_WIN32(
        // ERROR_BUSY)).
        return E_FAIL;
    }
    if (outLen == 0 || outLen > outBuffer.size()) {
        return E_FAIL;
    }

    // Ceremony-outcome inspection: outBuffer[0] is the CTAP status
    // byte - 0x00 success, 0x27 user cancelled on the phone, 0x2E no
    // credentials, 0x2B unknown command, 0x7F phone/bridge failure.
    // The payload is handed to the platform verbatim in every case
    // (the platform maps CTAP statuses to WebAuthn errors); the shim
    // only observes it - here for diagnostics, and in MetadataSync,
    // which publishes credential metadata exclusively on 0x00. The
    // handle is deliberately kept even on 0x7F: the Rust core
    // re-establishes a broken bridge session itself, and dropping the
    // handle would also drop the CTAP key-agreement state that is
    // shared across calls (ClientPIN / PRF flows).
    if (outBuffer[0] != 0x00) {
        char msg[64] = {};
        std::snprintf(msg, sizeof(msg), "PhoneFidoKey: CTAP status 0x%02X\n",
                      outBuffer[0]);
        OutputDebugStringA(msg);
    }

    auto responseBuffer = MakeCotaskmemBytes(outLen);
    if (!responseBuffer) {
        return E_OUTOFMEMORY;
    }
    memcpy(responseBuffer.get(), outBuffer.data(), outLen);
    response->cbEncodedResponse = static_cast<DWORD>(outLen);
    response->pbEncodedResponse = responseBuffer.release();

    if (isMakeCredential) {
        // Fire-and-forget platform metadata sync (autofill list). Any
        // failure is ignored by design.
        const std::span<const BYTE> responseBytes(response->pbEncodedResponse, outLen);
        (void)SyncNewCredential(requestBytes, responseBytes);
    }
    return S_OK;
}

HRESULT STDMETHODCALLTYPE PhoneFidoPlugin::MakeCredential(
    __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
    __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) {
    return DoOperation(request, response, /*isMakeCredential=*/true);
}

HRESULT STDMETHODCALLTYPE PhoneFidoPlugin::GetAssertion(
    __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
    __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) {
    return DoOperation(request, response, /*isMakeCredential=*/false);
}

HRESULT STDMETHODCALLTYPE PhoneFidoPlugin::CancelOperation(
    __RPC__in PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request) {
    if (!request) {
        return E_INVALIDARG;
    }
    // Mirrors the sample: the transaction ID must match the in-flight
    // operation, and the request signature is not verified (the sample
    // does not verify it either, and there is no payload defined to
    // verify it over - VERIFY if the platform expects otherwise).
    //
    // ABI gap: the Rust C ABI has no pfk_cancel(). pfk_process() blocks
    // its calling thread until the phone answers, and pfk_destroy() must
    // not run concurrently with it, so a cancel cannot interrupt the
    // in-flight bridge request. We only mark the transaction; the
    // operation thread discards its result when pfk_process() returns
    // and the handle is recreated. The phone's approval sheet stays up
    // until the user denies or it times out (60 s) - the same behavior
    // as the Linux daemon today.
    std::lock_guard stateLock(g_stateMutex);
    if (!g_hasInflight || !IsEqualGUID(g_inflightTransaction, request->transactionId)) {
        return NTE_NOT_FOUND;
    }
    g_cancelledTransaction = request->transactionId;
    g_hasCancelled = true;
    return S_OK;
}

HRESULT STDMETHODCALLTYPE PhoneFidoPlugin::GetLockStatus(
    __RPC__out PLUGIN_LOCK_STATUS* lockStatus) {
    if (!lockStatus) {
        return E_INVALIDARG;
    }
    // The sample reports its vault lock state. Our "vault" is the phone,
    // and the ABI has no session-liveness query (no pfk_ping), so the
    // closest honest equivalent is the configuration state: a pairing
    // file that pfk_create() would accept means "ready" (each ceremony
    // still requires approval + biometrics on the phone), no pairing
    // file means "locked" until pairing runs. File presence is a
    // heuristic for the eager load pfk_create() performs - a corrupt
    // file reads as unlocked here but fails in EnsureHandle().
    // VERIFY: platform UX consequences of PluginLocked here (e.g. an
    // unlock prompt we cannot service) are untested on hardware. If the
    // platform treats PluginLocked as "must call Hello UV first", this
    // mapping needs revisiting - see docs/WINDOWS.md open question 1.
    *lockStatus = IsPaired() ? PluginUnlocked : PluginLocked;
    return S_OK;
}

// --- PhoneFidoPluginFactory ------------------------------------------------

HRESULT STDMETHODCALLTYPE PhoneFidoPluginFactory::QueryInterface(REFIID riid, void** ppvObject) {
    if (!ppvObject) {
        return E_INVALIDARG;
    }
    if (IsEqualIID(riid, IID_IUnknown) || IsEqualIID(riid, IID_IClassFactory)) {
        *ppvObject = static_cast<IClassFactory*>(this);
        AddRef();
        return S_OK;
    }
    *ppvObject = nullptr;
    return E_NOINTERFACE;
}

ULONG STDMETHODCALLTYPE PhoneFidoPluginFactory::AddRef() {
    return static_cast<ULONG>(m_refCount.fetch_add(1) + 1);
}

ULONG STDMETHODCALLTYPE PhoneFidoPluginFactory::Release() {
    const long count = m_refCount.fetch_sub(1) - 1;
    if (count == 0) {
        delete this;
    }
    return static_cast<ULONG>(count);
}

HRESULT STDMETHODCALLTYPE PhoneFidoPluginFactory::CreateInstance(
    IUnknown* pUnkOuter, REFIID riid, void** ppvObject) {
    if (!ppvObject) {
        return E_INVALIDARG;
    }
    *ppvObject = nullptr;
    if (pUnkOuter) {
        return CLASS_E_NOAGGREGATION;
    }
    auto* plugin = new (std::nothrow) PhoneFidoPlugin();
    if (!plugin) {
        return E_OUTOFMEMORY;
    }
    const HRESULT hr = plugin->QueryInterface(riid, ppvObject);
    plugin->Release();
    return hr;
}

HRESULT STDMETHODCALLTYPE PhoneFidoPluginFactory::LockServer(BOOL fLock) {
    ServerNotifyServerLock(fLock != FALSE);
    return S_OK;
}

}  // namespace pfk
