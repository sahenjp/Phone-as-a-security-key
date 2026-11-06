// phone_fido.h - C ABI between the Rust core of Phone-as-a-security-key and
// its Windows host (the IPluginAuthenticator COM shim in windows/src).
//
// CANONICAL CONTRACT. This header is generated from the Rust
// implementation (src/ffi.rs) and is the single source of truth for
// both sides. The payloads are raw CTAP2 messages: one command byte
// followed by the CBOR parameter map, exactly what ctap2::process()
// consumes on Linux and exactly what IPluginAuthenticator::
// MakeCredential / GetAssertion receive in
// WEBAUTHN_PLUGIN_OPERATION_REQUEST::pbEncodedRequest. Responses are
// one CTAP status byte followed by the CBOR response map.
//
// All strings are UTF-8, NUL-terminated. All functions are callable
// from any thread, but a single PfkHandle must NOT be used
// concurrently: pfk_process() runs a full ceremony (including waiting
// for the user to approve on the phone), and the C++ shim serializes
// operations itself.

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to one authenticator instance: CTAP state (including
// the hmac-secret key-agreement key pair) plus the bridge session
// state for one paired phone. Created with pfk_create(), released
// with pfk_destroy().
typedef struct PfkHandle PfkHandle;

// Return codes for the int32_t functions below.
enum {
    PFK_OK = 0,
    // The caller's output buffer was too small (or NULL); *out_len
    // (or the SAS size requirement) holds the size that would have
    // been required, and nothing was copied. For pfk_process() note
    // that the ceremony has NOT run when this is returned: get the
    // size first (or pass a generously sized buffer; 64 KiB is far
    // beyond any CTAP2 response this authenticator produces) instead
    // of retrying a ceremony.
    PFK_ERR_BUFFER_TOO_SMALL = -1,
    // NULL / empty argument, malformed Base32, unknown transport
    // value, bad pairing path encoding, ...
    PFK_ERR_INVALID_ARGUMENT = -2,
    // An I/O error, e.g. the pairing file could not be written
    // (pfk_pair). Load failures in pfk_create are reported by a NULL
    // return plus the error buffer instead.
    PFK_ERR_IO = -3,
    // An internal Rust panic was caught at the FFI boundary.
    PFK_ERR_PANIC = -4,
};

// Transport selection for pfk_create().
enum {
    // Plain TCP to 127.0.0.1:18766. Something else must provide the
    // last hop to the phone's TCP 18765: `adb forward tcp:18766
    // tcp:18765` for Android, or an iproxy-equivalent for iPhone.
    PFK_TRANSPORT_TCP = 0,
    // Built-in usbmuxd client: talks to the Apple Mobile Device
    // Service usbmuxd on 127.0.0.1:27015 (installed by Apple's "Apple
    // Devices" app) and connects to the phone's TCP 18765 directly.
    // iPhone only. The usbmuxd address can be overridden with the
    // environment variable IPHONE_FIDO_USBMUX_ADDR ("host:port").
    PFK_TRANSPORT_USBMUXD = 1,
};

// Create an authenticator handle.
//
// pairing_path_utf8: path of the pairing file (on Windows:
//   %LOCALAPPDATA%\PhoneFidoKey\pairing.bin; the same 32-byte file the
//   CLI's `iphone-fido pair` writes). NULL or "" selects the CLI's
//   default path. The file is loaded EAGERLY: if it is missing or
//   malformed, pfk_create fails. Creating the handle does NOT connect
//   to the phone; the bridge session is established lazily by the
//   first pfk_process() that needs it and re-established when it
//   breaks, mirroring the Linux daemon.
// transport: PFK_TRANSPORT_TCP or PFK_TRANSPORT_USBMUXD.
// err_buf / err_cap: on failure, receives a NUL-terminated human
//   readable message when err_buf != NULL and err_cap > 0.
//
// Returns NULL on failure.
PfkHandle* pfk_create(const char* pairing_path_utf8, int32_t transport,
                      char* err_buf, size_t err_cap);

// The static authenticatorGetInfo response bytes: status byte 0x00
// followed by the CBOR map, byte-identical to what the daemon's CTAP2
// getInfo produces (src/ctap2.rs). For WebAuthNPluginAddAuthenticator,
// pass these bytes starting AFTER the leading status byte if
// pbAuthenticatorInfo expects the bare CBOR map.
//
// Pure and thread-safe; needs no handle and never touches the phone.
// May be called with out == NULL (or cap == 0) to query the size:
// *out_len always receives the full length; if the buffer is too
// small the function returns PFK_ERR_BUFFER_TOO_SMALL.
int32_t pfk_static_get_info(uint8_t* out, size_t cap, size_t* out_len);

// Run one CTAP2 operation.
//
// req / req_len: command byte + CBOR parameters, verbatim from the
//   platform (WEBAUTHN_PLUGIN_OPERATION_REQUEST::pbEncodedRequest).
// out / cap / out_len: on PFK_OK, out holds status byte + CBOR
//   response (WEBAUTHN_PLUGIN_OPERATION_RESPONSE::pbEncodedResponse
//   content) and *out_len its length.
//
// A CTAP error status (e.g. 0x27 user cancelled, 0x2E no credentials,
// 0x7F phone/bridge failure) is a successful call: it is part of the
// payload, NOT a negative return code. This mirrors the Linux stack,
// where every phone error is mapped to a CTAP status by the CTAP2
// layer. Negative returns are reserved for PFK_ERR_BUFFER_TOO_SMALL,
// PFK_ERR_INVALID_ARGUMENT and PFK_ERR_PANIC.
//
// Blocks until the phone answers, the user denies on the phone, or
// the approval/bridge timeouts expire (phone approval ~60 s, bridge
// read guard 120 s). Call from a worker thread. Not thread-safe per
// handle.
int32_t pfk_process(PfkHandle* h, const uint8_t* req, size_t req_len,
                    uint8_t* out, size_t cap, size_t* out_len);

// Pair with a phone: decode the Base32 pairing secret shown by the
// phone app (52 characters, as displayed; lowercase accepted), store
// it in the pairing file at pairing_path_utf8 (NULL/"" = default
// path; parent directories are created; permissions 0600 where the
// platform supports it), and write the 6-digit SAS confirmation code
// (NUL-terminated, decimal) to sas_out so the user can compare it
// with the code shown on the phone.
//
// sas_out may be NULL (code not reported). If sas_out is given,
// sas_cap must be at least 7; 16 is recommended. When sas_cap is too
// small the function returns PFK_ERR_BUFFER_TOO_SMALL but the pairing
// file has still been written.
// Returns PFK_OK or a negative PFK_ERR_* code. No handle is needed.
int32_t pfk_pair(const char* base32_psk, const char* pairing_path_utf8,
                 char* sas_out, size_t sas_cap);

// Destroy a handle created by pfk_create(). NULL-safe. Must not be
// called while pfk_process() is running on the same handle.
void pfk_destroy(PfkHandle* h);

#ifdef __cplusplus
}  // extern "C"
#endif
