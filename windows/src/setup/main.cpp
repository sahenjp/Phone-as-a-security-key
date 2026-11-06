// main.cpp (setup) - PhoneFidoKeySetup.exe: registration + pairing tool.
//
// The sample puts registration behind buttons in its WinUI settings
// page (PluginRegistrationManager::RegisterPlugin called from UI event
// handlers). The flow is identical here, minus the UI: this console tool
// is run by the user once after installing the MSIX.
//
// Subcommands:
//   (none)       guided: register if needed, pair if needed, show status
//   register     WebAuthNPluginAddAuthenticator + show the state
//   unregister   remove credential metadata + the registration
//   pair         prompt for the phone's Base32 pairing key, call
//                pfk_pair(), print the 6-digit SAS to compare
//                [--tcp|--usbmuxd selects the bridge transport]
//   status       registration state, pairing file, transport
//
// Pairing: the phone app displays a Base32 pairing key (Bridge Protocol
// v1, same as Linux). pfk_pair() decodes it, stores it at
// %LOCALAPPDATA%\PhoneFidoKey\pairing.bin and returns the SAS; the user
// must confirm the same 6 digits on the phone before using the key.

#include <windows.h>

#include <cstdio>
#include <iostream>
#include <string>

#include "Common.h"
#include "Registration.h"
#include "phone_fido.h"

namespace {

void PrintHresultError(const char* what, HRESULT hr) {
    std::printf("%s failed: HRESULT 0x%08lX\n", what,
                static_cast<unsigned long>(hr));
}

int PrintStatus() {
    bool registered = false;
    AUTHENTICATOR_STATE state = AuthenticatorState_Disabled;
    const HRESULT hr = pfk::QueryPluginState(registered, state);
    if (FAILED(hr)) {
        std::printf("Platform registration: not registered (0x%08lX)\n",
                    static_cast<unsigned long>(hr));
    } else {
        std::printf("Platform registration: registered, %s\n",
                    state == AuthenticatorState_Enabled
                        ? "ENABLED in Settings"
                        : "DISABLED - enable it under Settings > Accounts > Passkeys");
    }
    const std::string pairingPath = pfk::Utf8FromWide(pfk::PairingFilePath());
    std::printf("Pairing file: %s (%s)\n", pairingPath.c_str(),
                pfk::IsPaired() ? "present" : "MISSING - run 'pair'");
    std::printf("Transport: %s\n", pfk::ReadTransportSetting() == PFK_TRANSPORT_USBMUXD
                                       ? "usbmuxd (iPhone via Apple Devices)"
                                       : "TCP 127.0.0.1:18766 (iproxy / adb forward)");
    return 0;
}

int DoRegister() {
    const HRESULT hr = pfk::RegisterPlugin();
    if (FAILED(hr)) {
        PrintHresultError("RegisterPlugin", hr);
        return 1;
    }
    std::printf("Registered with the platform.\n");
    return PrintStatus();
}

int DoUnregister() {
    const HRESULT hr = pfk::UnregisterPlugin();
    if (FAILED(hr)) {
        PrintHresultError("UnregisterPlugin", hr);
        return 1;
    }
    std::printf("Unregistered. (The pairing file is kept; delete it by hand if wanted.)\n");
    return 0;
}

int DoPair(int32_t transportOverride /*-1 = keep current setting*/) {
    if (transportOverride >= 0) {
        pfk::WriteTransportSetting(transportOverride);
    }

    std::printf("On the phone, open Phone FIDO Key and show the pairing key.\n");
    std::printf("Paste the Base32 pairing key here and press Enter:\n> ");
    std::fflush(stdout);

    std::string pasted;
    if (!std::getline(std::cin, pasted)) {
        std::printf("No input.\n");
        return 1;
    }
    // Tolerate grouped/pasted keys: drop all whitespace.
    std::string base32;
    for (const char c : pasted) {
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') {
            base32 += c;
        }
    }
    if (base32.empty()) {
        std::printf("Empty pairing key.\n");
        return 1;
    }

    const std::string pairingPath = pfk::Utf8FromWide(pfk::PairingFilePath());
    if (pairingPath.empty()) {
        std::printf("Could not resolve the pairing file path.\n");
        return 1;
    }

    char sas[32] = {};
    const int32_t rc = pfk_pair(base32.c_str(), pairingPath.c_str(), sas, sizeof(sas));
    if (rc != PFK_OK) {
        std::printf("Pairing failed (pfk_pair rc=%d).\n", static_cast<int>(rc));
        if (rc == PFK_ERR_INVALID_ARGUMENT) {
            std::printf("The key was not valid Base32 - copy it exactly as the phone shows it.\n");
        } else if (rc == PFK_ERR_IO) {
            std::printf("The pairing file could not be written under %%LOCALAPPDATA%%.\n");
        }
        return 1;
    }

    std::printf("\nPairing saved to %s\n", pairingPath.c_str());
    std::printf("==================================================\n");
    std::printf("  Compare this code with the phone:  %s\n", sas);
    std::printf("==================================================\n");
    std::printf("If the phone shows a different code, delete the pairing on\n");
    std::printf("the phone and run 'pair' again - do not use a mismatched key.\n");
    return 0;
}

void PrintUsage() {
    std::printf(
        "PhoneFidoKeySetup - registration and pairing for Phone FIDO Key\n"
        "Usage:\n"
        "  PhoneFidoKeySetup                guided setup (register + pair + status)\n"
        "  PhoneFidoKeySetup register       register the authenticator with Windows\n"
        "  PhoneFidoKeySetup unregister     remove the registration\n"
        "  PhoneFidoKeySetup pair [--tcp|--usbmuxd]\n"
        "                                   pair with the phone (Base32 key)\n"
        "  PhoneFidoKeySetup status         show registration / pairing state\n");
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
    std::string command = "guided";
    int32_t transportOverride = -1;
    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i];
        if (arg == L"--tcp") {
            transportOverride = PFK_TRANSPORT_TCP;
        } else if (arg == L"--usbmuxd") {
            transportOverride = PFK_TRANSPORT_USBMUXD;
        } else if (arg == L"register" || arg == L"unregister" || arg == L"pair" ||
                   arg == L"status" || arg == L"guided") {
            command = pfk::Utf8FromWide(arg);
        } else {
            PrintUsage();
            return 1;
        }
    }

    if (command == "register") {
        return DoRegister();
    }
    if (command == "unregister") {
        return DoUnregister();
    }
    if (command == "pair") {
        return DoPair(transportOverride);
    }
    if (command == "status") {
        return PrintStatus();
    }

    // Guided flow: register if the platform does not know us, pair if
    // there is no pairing file, then show where things stand.
    bool registered = false;
    AUTHENTICATOR_STATE state = AuthenticatorState_Disabled;
    const HRESULT hr = pfk::QueryPluginState(registered, state);
    if (FAILED(hr) || !registered) {
        if (DoRegister() != 0) {
            return 1;
        }
    }
    if (!pfk::IsPaired()) {
        if (DoPair(transportOverride) != 0) {
            return 1;
        }
    }
    std::printf("\n");
    return PrintStatus();
}
