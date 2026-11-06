#include "Common.h"

#include <shlobj_core.h>

#include <cstdlib>
#include <vector>

#include "phone_fido.h"

namespace pfk {

std::wstring StateDirectory() {
    PWSTR localAppData = nullptr;
    if (FAILED(SHGetKnownFolderPath(FOLDERID_LocalAppData, 0, nullptr, &localAppData))) {
        return {};
    }
    std::wstring dir(localAppData);
    CoTaskMemFree(localAppData);
    dir += L"\\PhoneFidoKey";
    // Best effort: create the directory so the pairing file can be
    // written later. SHCreateDirectoryEx returns ERROR_ALREADY_EXISTS
    // when it is already there; both are fine.
    SHCreateDirectoryExW(nullptr, dir.c_str(), nullptr);
    return dir;
}

std::wstring PairingFilePath() {
    const std::wstring dir = StateDirectory();
    if (dir.empty()) {
        return {};
    }
    return dir + L"\\pairing.bin";
}

bool IsPaired() {
    const std::wstring path = PairingFilePath();
    if (path.empty()) {
        return false;
    }
    WIN32_FILE_ATTRIBUTE_DATA data{};
    if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &data)) {
        return false;
    }
    return data.nFileSizeLow > 0 || data.nFileSizeHigh > 0;
}

int32_t ReadTransportSetting() {
    // Environment override first (debugging / CI).
    if (const char* env = std::getenv("PFK_TRANSPORT")) {
        if (env[0] == '1' && env[1] == '\0') {
            return PFK_TRANSPORT_USBMUXD;
        }
        if (env[0] == '0' && env[1] == '\0') {
            return PFK_TRANSPORT_TCP;
        }
    }
    DWORD value = PFK_TRANSPORT_TCP;
    DWORD size = sizeof(value);
    DWORD type = 0;
    if (RegGetValueW(HKEY_CURRENT_USER, kRegistryPath, kTransportValueName,
                     RRF_RT_REG_DWORD, &type,
                     reinterpret_cast<BYTE*>(&value), &size) == ERROR_SUCCESS &&
        (value == PFK_TRANSPORT_TCP || value == PFK_TRANSPORT_USBMUXD)) {
        return static_cast<int32_t>(value);
    }
    return PFK_TRANSPORT_TCP;
}

bool WriteTransportSetting(int32_t transport) {
    HKEY rawKey = nullptr;
    if (RegCreateKeyExW(HKEY_CURRENT_USER, kRegistryPath, 0, nullptr,
                        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &rawKey,
                        nullptr) != ERROR_SUCCESS) {
        return false;
    }
    UniqueHkey key(rawKey);
    const DWORD value = static_cast<DWORD>(transport);
    return RegSetValueExW(key.get(), kTransportValueName, 0, REG_DWORD,
                          reinterpret_cast<const BYTE*>(&value),
                          sizeof(value)) == ERROR_SUCCESS;
}

std::string Utf8FromWide(std::wstring_view text) {
    if (text.empty()) {
        return {};
    }
    const int needed = WideCharToMultiByte(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0,
        nullptr, nullptr);
    if (needed <= 0) {
        return {};
    }
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring WideFromUtf8(std::string_view text) {
    if (text.empty()) {
        return {};
    }
    const int needed = MultiByteToWideChar(
        CP_UTF8, 0, text.data(), static_cast<int>(text.size()), nullptr, 0);
    if (needed <= 0) {
        return {};
    }
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.data(), static_cast<int>(text.size()),
                        out.data(), needed);
    return out;
}

}  // namespace pfk
