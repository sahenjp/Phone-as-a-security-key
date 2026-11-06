// Raii.h - minimal RAII wrappers for the CNG / registry / COM handles used
// by the shim.
//
// The Microsoft PasskeyManager sample uses WIL (wil::unique_ncrypt_prov,
// wil::unique_hkey, ...) for the same job. We deliberately depend only on
// the Windows SDK so the shim builds with a bare MSVC + SDK install.
// Note that NCRYPT_* handles are integer types (ULONG_PTR), not pointers,
// so a value-semantics UniqueHandle is used instead of std::unique_ptr.

#pragma once

#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>

#include <type_traits>
#include <utility>

namespace pfk {

// scope_exit: minimal stand-in for wil::scope_exit.
template <typename F>
class ScopeExit {
public:
    explicit ScopeExit(F&& f) : m_f(std::forward<F>(f)) {}
    ~ScopeExit() { if (m_active) m_f(); }
    ScopeExit(const ScopeExit&) = delete;
    ScopeExit& operator=(const ScopeExit&) = delete;
    void release() { m_active = false; }
private:
    F m_f;
    bool m_active = true;
};
template <typename F>
ScopeExit(F&&) -> ScopeExit<std::decay_t<F>>;

// UniqueHandle<T, Deleter>: owns a handle value of type T; the deleter is
// invoked on the value at destruction/reset unless it equals T{} (the
// null handle for every handle type used here).
template <typename T, typename Deleter>
class UniqueHandle {
public:
    UniqueHandle() = default;
    explicit UniqueHandle(T value) : m_value(value) {}
    ~UniqueHandle() { Reset(); }

    UniqueHandle(const UniqueHandle&) = delete;
    UniqueHandle& operator=(const UniqueHandle&) = delete;

    UniqueHandle(UniqueHandle&& other) noexcept : m_value(other.release()) {}
    UniqueHandle& operator=(UniqueHandle&& other) noexcept {
        if (this != &other) {
            Reset(other.release());
        }
        return *this;
    }

    T get() const { return m_value; }
    explicit operator bool() const { return m_value != T{}; }

    T release() {
        T value = m_value;
        m_value = T{};
        return value;
    }
    void Reset(T value = T{}) {
        if (m_value != T{}) {
            Deleter{}(m_value);
        }
        m_value = value;
    }

private:
    T m_value{};
};

// NCRYPT_PROV_HANDLE
struct NcryptProvDeleter {
    void operator()(NCRYPT_PROV_HANDLE h) const { if (h) NCryptFreeObject(h); }
};
using UniqueNcryptProv = UniqueHandle<NCRYPT_PROV_HANDLE, NcryptProvDeleter>;

// NCRYPT_KEY_HANDLE
struct NcryptKeyDeleter {
    void operator()(NCRYPT_KEY_HANDLE h) const { if (h) NCryptFreeObject(h); }
};
using UniqueNcryptKey = UniqueHandle<NCRYPT_KEY_HANDLE, NcryptKeyDeleter>;

// BCRYPT_HASH_HANDLE
struct BcryptHashDeleter {
    void operator()(BCRYPT_HASH_HANDLE h) const { if (h) BCryptDestroyHash(h); }
};
using UniqueBcryptHash = UniqueHandle<BCRYPT_HASH_HANDLE, BcryptHashDeleter>;

// HKEY
struct HkeyDeleter {
    void operator()(HKEY h) const { if (h) RegCloseKey(h); }
};
using UniqueHkey = UniqueHandle<HKEY, HkeyDeleter>;

// HMODULE
struct HmoduleDeleter {
    void operator()(HMODULE h) const { if (h) FreeLibrary(h); }
};
using UniqueHmodule = UniqueHandle<HMODULE, HmoduleDeleter>;

// CoTaskMem-allocated byte buffer. The platform frees
// WEBAUTHN_PLUGIN_OPERATION_RESPONSE::pbEncodedResponse with
// CoTaskMemFree, so buffers handed to the platform must come from
// CoTaskMemAlloc - use AllocateResponseBuffer() in PluginAuthenticator.
struct CotaskmemDeleter {
    void operator()(BYTE* p) const { CoTaskMemFree(p); }
};
using UniqueCotaskmemBytes = UniqueHandle<BYTE*, CotaskmemDeleter>;

inline UniqueCotaskmemBytes MakeCotaskmemBytes(size_t count) {
    return UniqueCotaskmemBytes(
        static_cast<BYTE*>(CoTaskMemAlloc(count * sizeof(BYTE))));
}

}  // namespace pfk
