// PluginAuthenticator.h - IPluginAuthenticator implementation.
//
// Reduced from the sample's PluginAuthenticator/PluginAuthenticatorImpl:
// the sample's class coordinates with a WinUI front-end (vault unlock
// prompt, credential picker, Hello UV) through events on the app object.
// Our authenticator is the phone: it renders its own approval UI and
// performs user verification with biometrics, so this class is just
//
//   verify platform signature -> pfk_process() -> hand bytes back
//
// with no UI and no Windows Hello (see docs/WINDOWS.md, "UV" section).
// COM is hand-rolled (no C++/WinRT) to keep the build dependency-free;
// the class-factory shape matches the sample's ContosoPluginFactory.

#pragma once

#include <windows.h>
// Include order matters: the MIDL-generated pluginauthenticator.h uses
// the plugin types from webauthnplugin.h and the base types from
// webauthn.h but includes neither.
#include <webauthn/webauthn.h>
#include <webauthn/webauthnplugin.h>
#include <webauthn/pluginauthenticator.h>

#include <atomic>

namespace pfk {

// --- Server lifetime -------------------------------------------------------
// The COM server process exits once every plugin object has been
// released and no server locks remain (after at least one object was
// created). wWinMain waits on ServerShutdownEvent().
void ServerNotifyObjectCreated();
void ServerNotifyObjectDestroyed();
void ServerNotifyServerLock(bool lock);
bool ServerHasServed();
HANDLE ServerShutdownEvent();

class PhoneFidoPlugin final : public IPluginAuthenticator {
public:
    PhoneFidoPlugin();
    ~PhoneFidoPlugin();

    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
    ULONG STDMETHODCALLTYPE AddRef() override;
    ULONG STDMETHODCALLTYPE Release() override;

    // IPluginAuthenticator
    HRESULT STDMETHODCALLTYPE MakeCredential(
        __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
        __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) override;
    HRESULT STDMETHODCALLTYPE GetAssertion(
        __RPC__in PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
        __RPC__out PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response) override;
    HRESULT STDMETHODCALLTYPE CancelOperation(
        __RPC__in PCWEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request) override;
    HRESULT STDMETHODCALLTYPE GetLockStatus(
        __RPC__out PLUGIN_LOCK_STATUS* lockStatus) override;

private:
    HRESULT DoOperation(PCWEBAUTHN_PLUGIN_OPERATION_REQUEST request,
                        PWEBAUTHN_PLUGIN_OPERATION_RESPONSE response,
                        bool isMakeCredential);

    std::atomic<long> m_refCount{1};
};

class PhoneFidoPluginFactory final : public IClassFactory {
public:
    // IUnknown
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppvObject) override;
    ULONG STDMETHODCALLTYPE AddRef() override;
    ULONG STDMETHODCALLTYPE Release() override;

    // IClassFactory
    HRESULT STDMETHODCALLTYPE CreateInstance(IUnknown* pUnkOuter, REFIID riid,
                                             void** ppvObject) override;
    HRESULT STDMETHODCALLTYPE LockServer(BOOL fLock) override;

private:
    std::atomic<long> m_refCount{1};
};

}  // namespace pfk
