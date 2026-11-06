// main.cpp (server) - COM local server entry point for PhoneFidoKey.exe.
//
// Reduced from the sample's App.cpp. The sample hosts a full WinUI app
// (main window, settings, vault UI) and registers its class factory
// from App::OnLaunched when the "-PluginActivated" argument is present.
// This plugin has no UI at all - the phone is the UI - so the process
// is only ever launched by COM with "-PluginActivated" (the argument
// declared in Package.appxmanifest's com:ExeServer extension), and its
// whole job is: register the class factory, serve IPluginAuthenticator
// objects, exit when the platform lets go.

#include <windows.h>
#include <objbase.h>

#include "Common.h"
#include "PluginAuthenticator.h"

int WINAPI wWinMain(_In_ HINSTANCE /*hInstance*/, _In_opt_ HINSTANCE /*hPrevInstance*/,
                    _In_ PWSTR pCmdLine, _In_ int /*nCmdShow*/) {
    // Mirrors the sample: without the activation argument we do nothing
    // (registration / pairing live in PhoneFidoKeySetup.exe).
    // VERIFY: the sample checks Application::Current().Arguments, which
    // for a full-trust packaged app is the command line passed by the
    // COM activator; matching on the raw command line string is the
    // classic local-server equivalent. Whether the activator quotes or
    // prefixes the arguments differently must be confirmed on hardware.
    if (!pCmdLine || !wcsstr(pCmdLine, L"-PluginActivated")) {
        return 0;
    }

    // MTA apartment: plugin objects must be thread-safe, and they are
    // (all shared state is mutex-guarded; ceremonies are serialized).
    // The sample uses an STA because its authenticator talks to UI
    // elements; we have none, so no message pump is needed and RPC
    // threads can call straight in.
    // VERIFY: if the platform expects the plugin in an STA (some COM
    // servers in this API family are apartment-sensitive), switching to
    // COINIT_APARTMENTTHREADED plus a GetMessage loop is the fallback.
    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        return 1;
    }
    // Same security settings as the sample's wWinMain:
    // winrt::init_apartment + CoInitializeSecurity(RPC_C_IMP_LEVEL_IMPERSONATE).
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                              RPC_C_AUTHN_LEVEL_DEFAULT,
                              RPC_C_IMP_LEVEL_IMPERSONATE, nullptr,
                              EOAC_NONE, nullptr);
    if (FAILED(hr)) {
        CoUninitialize();
        return 1;
    }

    auto* factory = new pfk::PhoneFidoPluginFactory();
    DWORD registrationCookie = 0;
    hr = CoRegisterClassObject(pfk::kPluginClsid, factory, CLSCTX_LOCAL_SERVER,
                               REGCLS_MULTIPLEUSE, &registrationCookie);
    if (FAILED(hr)) {
        factory->Release();
        CoUninitialize();
        return 1;
    }

    // Serve until the last object/lock goes away (shutdown event is
    // signaled from PluginAuthenticator.cpp). Give up after ~2 minutes
    // if nothing ever connected, so a stray activation cannot leave an
    // idle process behind forever.
    HANDLE shutdownEvent = pfk::ServerShutdownEvent();
    const DWORD startTick = GetTickCount();
    for (;;) {
        const DWORD wait = WaitForSingleObject(shutdownEvent, 30000);
        if (wait == WAIT_OBJECT_0) {
            break;
        }
        if (!pfk::ServerHasServed() && GetTickCount() - startTick > 120000) {
            break;
        }
    }

    CoRevokeClassObject(registrationCookie);
    factory->Release();
    // Let COM drain in-flight calls before tearing the apartment down.
    CoUninitialize();
    return 0;
}
