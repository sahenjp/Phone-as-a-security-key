//! C ABI for the Windows plugin host (docs/WINDOWS.md).
//!
//! The C++ COM shim in `windows/` receives raw CTAP2 CBOR from the
//! Windows WebAuthn plugin broker and forwards it here 1:1 -- the
//! request/response byte formats are exactly what the Linux daemon's
//! `ctap2::process` consumes and produces (command/status byte + CBOR),
//! because the plugin payload and the CTAPHID CBOR payload above the
//! transport are the same bytes. The public contract is
//! `windows/include/phone_fido.h`; this module implements it.
//!
//! Conventions (mirrored in the header):
//! - Return 0 on success, negative on failure. -1 always means "the
//!   output buffer was too small (or NULL); `*out_len` / the SAS size
//!   requirement says how much room is needed". Other negatives are
//!   per-function.
//! - Every function is panic-safe (panics are caught at the boundary)
//!   and tolerates NULL pointers wherever the header says so.
//! - A handle is NOT thread-safe: the caller must serialize calls on
//!   one handle (the underlying bridge session is a single ordered
//!   stream). Different handles are independent.
//! - Phone connection is lazy: `pfk_create` only loads the pairing
//!   file. The bridge session is established on the first
//!   `pfk_process` that needs the phone and re-established when it
//!   breaks, exactly like the Linux daemon's TcpPhone behavior.
//!   GetInfo is answered offline, without the phone.

use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::ptr;

use crate::bridge;
use crate::ctap2::{self, CtapState};
use crate::phone::{MockPhone, Phone, TcpPhone};
use crate::usbmux;

/// `pfk_create` transport selector: TCP bridge at 127.0.0.1:18766
/// (an iproxy / adb-style forward already listening on the PC).
pub const PFK_TRANSPORT_TCP: i32 = 0;
/// `pfk_create` transport selector: the built-in usbmuxd client
/// (crate::usbmux; AMDS on Windows at 127.0.0.1:27015 by default,
/// overridable with $IPHONE_FIDO_USBMUX_ADDR).
pub const PFK_TRANSPORT_USBMUXD: i32 = 1;

pub const PFK_OK: i32 = 0;
/// Output buffer too small or NULL; size requirement was reported.
pub const PFK_ERR_BUFFER_TOO_SMALL: i32 = -1;
/// Invalid argument (NULL handle/request, bad pairing code, ...).
pub const PFK_ERR_INVALID_ARGUMENT: i32 = -2;
/// I/O error (e.g. the pairing file could not be written).
pub const PFK_ERR_IO: i32 = -3;
/// An internal panic was caught at the FFI boundary.
pub const PFK_ERR_PANIC: i32 = -4;

/// Opaque authenticator handle (C: `typedef struct PfkHandle PfkHandle`).
pub struct PfkHandle {
    state: CtapState,
    phone: Box<dyn Phone>,
}

impl PfkHandle {
    /// Build a handle around an arbitrary phone implementation.
    /// Used by the FFI constructors and by tests (MockPhone).
    pub(crate) fn from_phone(phone: Box<dyn Phone>) -> Self {
        Self {
            state: CtapState::new(),
            phone,
        }
    }
}

// ---------------------------------------------------------------- helpers

/// Resolve the pairing path argument: NULL or empty means the default
/// path (the same one the CLI uses).
fn path_from_c(ptr: *const c_char) -> Result<PathBuf, String> {
    if ptr.is_null() {
        return Ok(bridge::default_pairing_path());
    }
    // SAFETY: the caller guarantees a NUL-terminated string (or NULL,
    // handled above) that outlives the call.
    let s = unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| "pairing path is not valid UTF-8".to_string())?;
    if s.is_empty() {
        return Ok(bridge::default_pairing_path());
    }
    Ok(PathBuf::from(s))
}

/// Copy `msg` into the caller's error buffer, NUL-terminated and
/// truncated to fit. NULL buffer / zero capacity are allowed.
fn write_err(err_buf: *mut c_char, err_cap: usize, msg: &str) {
    if err_buf.is_null() || err_cap == 0 {
        return;
    }
    let bytes = msg.as_bytes();
    let n = bytes.len().min(err_cap - 1);
    // SAFETY: err_buf has room for err_cap bytes per the contract.
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), err_buf as *mut u8, n);
        *err_buf.add(n) = 0;
    }
}

/// Shared byte-output semantics: always store the needed length in
/// `*out_len` (when given); copy only when the buffer is big enough.
fn write_output(out: *mut u8, cap: usize, out_len: *mut usize, bytes: &[u8]) -> i32 {
    if !out_len.is_null() {
        // SAFETY: out_len is either NULL (checked) or caller-owned.
        unsafe { *out_len = bytes.len() };
    }
    if out.is_null() || cap < bytes.len() {
        return PFK_ERR_BUFFER_TOO_SMALL;
    }
    // SAFETY: out has room for cap >= bytes.len() bytes per the contract.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
    PFK_OK
}

/// The static GetInfo response (status byte + CBOR), produced by the
/// very code path the daemon uses, so it cannot drift from it.
fn static_get_info_bytes() -> Vec<u8> {
    let mut state = CtapState::new();
    let mut phone = MockPhone::new();
    ctap2::process(&mut state, &mut phone, &[ctap2::CMD_GET_INFO])
}

// ------------------------------------------------------------- pfk_create

fn create_impl(pairing_path: *const c_char, transport: i32) -> Result<PfkHandle, String> {
    let path = path_from_c(pairing_path)?;
    let psk = bridge::load_pairing(&path).map_err(|e| {
        format!(
            "cannot load pairing file {}: {e} (run pairing first)",
            path.display()
        )
    })?;
    let phone: Box<dyn Phone> = match transport {
        PFK_TRANSPORT_TCP => {
            let mut phone = TcpPhone::new(bridge::DEFAULT_PHONE_ADDR, &psk);
            // Later re-pairing is picked up on reconnect, like the CLI.
            phone.set_pairing_path(path.clone());
            Box::new(phone)
        }
        PFK_TRANSPORT_USBMUXD => {
            let mut phone = TcpPhone::new_usbmux(&usbmux::usbmux_addr(), &psk);
            phone.set_pairing_path(path.clone());
            Box::new(phone)
        }
        other => {
            return Err(format!(
                "unknown transport {other} (0 = TCP forward at {}, 1 = built-in usbmuxd client)",
                bridge::DEFAULT_PHONE_ADDR
            ))
        }
    };
    Ok(PfkHandle::from_phone(phone))
}

/// Create an authenticator handle. Loads the pairing file at
/// `pairing_path_utf8` (NULL/empty = the CLI's default path) but does
/// NOT connect to the phone yet. Returns NULL on error and writes a
/// human-readable message to `err_buf` when provided.
#[no_mangle]
pub extern "C" fn pfk_create(
    pairing_path_utf8: *const c_char,
    transport: i32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> *mut PfkHandle {
    match catch_unwind(AssertUnwindSafe(|| {
        create_impl(pairing_path_utf8, transport)
    })) {
        Ok(Ok(handle)) => Box::into_raw(Box::new(handle)),
        Ok(Err(msg)) => {
            write_err(err_buf, err_cap, &msg);
            ptr::null_mut()
        }
        Err(_) => {
            write_err(err_buf, err_cap, "internal panic in pfk_create");
            ptr::null_mut()
        }
    }
}

// -------------------------------------------------- pfk_static_get_info

/// Write the static GetInfo response (0x00 + CBOR) into `out`.
/// No handle and no phone are needed. Returns 0 on success, -1 when
/// the buffer is too small/NULL (`*out_len` then holds the size).
#[no_mangle]
pub extern "C" fn pfk_static_get_info(out: *mut u8, cap: usize, out_len: *mut usize) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| static_get_info_bytes())) {
        Ok(bytes) => write_output(out, cap, out_len, &bytes),
        Err(_) => PFK_ERR_PANIC,
    }
}

// ------------------------------------------------------------ pfk_process

fn process_impl(
    h: *mut PfkHandle,
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    if h.is_null() || (req.is_null() && req_len > 0) {
        if !out_len.is_null() {
            // SAFETY: as in write_output.
            unsafe { *out_len = 0 };
        }
        return PFK_ERR_INVALID_ARGUMENT;
    }
    // SAFETY: h is a live handle from pfk_create (caller's contract);
    // req points to req_len readable bytes (or is NULL with len 0).
    let handle = unsafe { &mut *h };
    let req_slice: &[u8] = if req_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(req, req_len) }
    };
    let response = ctap2::process(&mut handle.state, &mut *handle.phone, req_slice);
    write_output(out, cap, out_len, &response)
}

/// Feed one raw CTAP2 request (command byte + CBOR params) through the
/// authenticator; `out` receives the raw CTAP2 response (status byte +
/// CBOR). Returns 0 whenever a CTAP response was produced (the CTAP
/// status travels inside `out`); negative only for buffer/argument
/// errors (-1 too small, -2 invalid argument, -4 panic).
#[no_mangle]
pub extern "C" fn pfk_process(
    h: *mut PfkHandle,
    req: *const u8,
    req_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        process_impl(h, req, req_len, out, cap, out_len)
    })) {
        Ok(code) => code,
        Err(_) => PFK_ERR_PANIC,
    }
}

// --------------------------------------------------------------- pfk_pair

fn pair_impl(base32_psk: *const c_char, pairing_path_utf8: *const c_char) -> Result<String, i32> {
    if base32_psk.is_null() {
        return Err(PFK_ERR_INVALID_ARGUMENT);
    }
    // SAFETY: caller guarantees a NUL-terminated string (checked non-NULL).
    let code = unsafe { CStr::from_ptr(base32_psk) }
        .to_str()
        .map_err(|_| PFK_ERR_INVALID_ARGUMENT)?;
    let bytes = bridge::base32_decode_nopad(code).map_err(|_| PFK_ERR_INVALID_ARGUMENT)?;
    if bytes.len() != 32 {
        return Err(PFK_ERR_INVALID_ARGUMENT);
    }
    let mut psk = [0u8; 32];
    psk.copy_from_slice(&bytes);
    let path = path_from_c(pairing_path_utf8).map_err(|_| PFK_ERR_INVALID_ARGUMENT)?;
    bridge::save_pairing(&path, &psk).map_err(|_| PFK_ERR_IO)?;
    Ok(bridge::sas_for_psk(&psk))
}

/// Pair with a phone: decode the Base32 secret it displays and store
/// it as the pairing file (mode 0600 where the platform supports it),
/// exactly like the CLI `pair` command. On success the 6-digit SAS
/// (NUL-terminated, needs 7 bytes) is written to `sas_out` when given.
/// Returns 0, -1 (SAS buffer too small), -2 (bad code/path),
/// -3 (file could not be written), -4 (panic).
#[no_mangle]
pub extern "C" fn pfk_pair(
    base32_psk: *const c_char,
    pairing_path_utf8: *const c_char,
    sas_out: *mut c_char,
    sas_cap: usize,
) -> i32 {
    let sas = match catch_unwind(AssertUnwindSafe(|| pair_impl(base32_psk, pairing_path_utf8))) {
        Ok(Ok(sas)) => sas,
        Ok(Err(code)) => return code,
        Err(_) => return PFK_ERR_PANIC,
    };
    if sas_out.is_null() {
        return PFK_OK;
    }
    if sas_cap < sas.len() + 1 {
        return PFK_ERR_BUFFER_TOO_SMALL;
    }
    // SAFETY: sas_out has room for sas_cap >= 7 bytes per the contract.
    unsafe {
        ptr::copy_nonoverlapping(sas.as_ptr(), sas_out as *mut u8, sas.len());
        *sas_out.add(sas.len()) = 0;
    }
    PFK_OK
}

// ------------------------------------------------------------ pfk_destroy

/// Destroy a handle created by `pfk_create`. NULL is a no-op.
#[no_mangle]
pub extern "C" fn pfk_destroy(h: *mut PfkHandle) {
    if h.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: h came from Box::into_raw in pfk_create and is
        // destroyed at most once (caller's contract).
        unsafe { drop(Box::from_raw(h)) };
    }));
}

// Keep CString referenced for hosts that build with older lint sets:
// the FFI surface takes only borrowed C strings, never owned ones.
#[allow(dead_code)]
fn _unused(_: &CString) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor_util as cu;
    use ciborium::value::Value;

    // Thin wrappers over the extern "C" functions with friendlier
    // names, keeping the test bodies readable.
    fn create(p: *const c_char, t: i32, e: *mut c_char, c: usize) -> *mut PfkHandle {
        pfk_create(p, t, e, c)
    }
    fn destroy(h: *mut PfkHandle) {
        pfk_destroy(h)
    }
    fn process(
        h: *mut PfkHandle,
        r: *const u8,
        rl: usize,
        o: *mut u8,
        c: usize,
        ol: *mut usize,
    ) -> i32 {
        pfk_process(h, r, rl, o, c, ol)
    }
    fn pair(b: *const c_char, p: *const c_char, s: *mut c_char, c: usize) -> i32 {
        pfk_pair(b, p, s, c)
    }
    fn static_info(o: *mut u8, c: usize, ol: *mut usize) -> i32 {
        pfk_static_get_info(o, c, ol)
    }

    fn cstring(s: &str) -> CString {
        CString::new(s).unwrap()
    }

    fn temp_pairing_path(tag: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        dir.push(format!(
            "iphone-fido-ffi-test-{}-{}",
            std::process::id(),
            tag
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("pairing.bin")
    }

    fn test_psk() -> [u8; 32] {
        let mut psk = [0u8; 32];
        for (i, b) in psk.iter_mut().enumerate() {
            *b = i as u8;
        }
        psk
    }

    /// Write a valid pairing file and create a handle on it.
    fn create_test_handle(path: &PathBuf, transport: i32) -> *mut PfkHandle {
        bridge::save_pairing(path, &test_psk()).unwrap();
        let cpath = cstring(path.to_str().unwrap());
        let mut err = vec![0i8; 256];
        let h = create(
            cpath.as_ptr(),
            transport,
            err.as_mut_ptr(),
            err.len(),
        );
        assert!(!h.is_null(), "pfk_create failed");
        h
    }

    #[test]
    fn static_get_info_buffer_semantics() {
        // NULL out: reports the needed size and returns -1.
        let mut len = 0usize;
        let rc = static_info(ptr::null_mut(), 0, &mut len);
        assert_eq!(rc, PFK_ERR_BUFFER_TOO_SMALL);
        assert!(len > 1, "getInfo response should be non-trivial");
        // Too small: same, with the needed size again.
        let mut tiny = [0u8; 4];
        let mut len2 = 0usize;
        let rc = static_info(tiny.as_mut_ptr(), tiny.len(), &mut len2);
        assert_eq!(rc, PFK_ERR_BUFFER_TOO_SMALL);
        assert_eq!(len2, len);
        // Right size: 0x00 + CBOR equal to the in-process code path.
        let mut buf = vec![0u8; len];
        let mut len3 = 0usize;
        let rc = static_info(buf.as_mut_ptr(), buf.len(), &mut len3);
        assert_eq!(rc, PFK_OK);
        assert_eq!(len3, len);
        assert_eq!(buf[0], 0x00);
        assert_eq!(buf, static_get_info_bytes());
        // NULL out_len is tolerated when the buffer fits.
        let rc = static_info(buf.as_mut_ptr(), buf.len(), ptr::null_mut());
        assert_eq!(rc, PFK_OK);
    }

    #[test]
    fn pair_then_create_and_get_info_via_process() {
        let path = temp_pairing_path("pair-create");
        let psk = test_psk();
        let code = cstring(&bridge::base32_encode_nopad(&psk));
        let cpath = cstring(path.to_str().unwrap());

        // SAS buffer too small -> -1, but the pairing file was written.
        let mut sas_small = vec![0i8; 4];
        let rc = pair(
            code.as_ptr(),
            cpath.as_ptr(),
            sas_small.as_mut_ptr(),
            sas_small.len(),
        );
        assert_eq!(rc, PFK_ERR_BUFFER_TOO_SMALL);

        // Proper pair: SAS matches the library's own SAS for this PSK.
        let mut sas = vec![0i8; 16];
        let rc = pair(code.as_ptr(), cpath.as_ptr(), sas.as_mut_ptr(), sas.len());
        assert_eq!(rc, PFK_OK);
        let sas_str = unsafe { CStr::from_ptr(sas.as_ptr()) }.to_str().unwrap();
        assert_eq!(sas_str, bridge::sas_for_psk(&psk));
        assert_eq!(bridge::load_pairing(&path).unwrap(), psk);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "pairing file must be 0600");
        }

        // Create a handle on the file and run GetInfo through
        // pfk_process: answered offline, never touches the phone.
        let h = create_test_handle(&path, PFK_TRANSPORT_TCP);
        let req = [ctap2::CMD_GET_INFO];
        let mut out = vec![0u8; 2048];
        let mut out_len = 0usize;
        let rc = process(
            h,
            req.as_ptr(),
            req.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        assert_eq!(rc, PFK_OK);
        out.truncate(out_len);
        assert_eq!(out, static_get_info_bytes());
        destroy(h);

        // A usbmux-transport handle also constructs lazily.
        let h2 = create_test_handle(&path, PFK_TRANSPORT_USBMUXD);
        destroy(h2);

        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn create_failures_return_null_and_message() {
        let mut err = vec![0i8; 256];
        // Missing pairing file.
        let missing = cstring("/nonexistent-dir-xyz/pairing.bin");
        let h = create(missing.as_ptr(), 0, err.as_mut_ptr(), err.len());
        assert!(h.is_null());
        let msg = unsafe { CStr::from_ptr(err.as_ptr()) }.to_str().unwrap();
        assert!(msg.contains("cannot load pairing file"), "msg: {msg}");
        // Unknown transport: file exists, transport is invalid.
        let path = temp_pairing_path("bad-transport");
        bridge::save_pairing(&path, &test_psk()).unwrap();
        let cpath = cstring(path.to_str().unwrap());
        let h = create(cpath.as_ptr(), 99, err.as_mut_ptr(), err.len());
        assert!(h.is_null());
        let msg = unsafe { CStr::from_ptr(err.as_ptr()) }.to_str().unwrap();
        assert!(msg.contains("unknown transport 99"), "msg: {msg}");
        // NULL error buffer is tolerated on failure.
        let h = create(missing.as_ptr(), 0, ptr::null_mut(), 0);
        assert!(h.is_null());
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    #[test]
    fn pair_rejects_bad_codes() {
        let path = temp_pairing_path("bad-code");
        let cpath = cstring(path.to_str().unwrap());
        let garbage = cstring("NOT!BASE32");
        assert_eq!(
            pair(garbage.as_ptr(), cpath.as_ptr(), ptr::null_mut(), 0),
            PFK_ERR_INVALID_ARGUMENT
        );
        // Valid Base32 but decodes to != 32 bytes.
        let short = cstring("MZXW6YTBOI");
        assert_eq!(
            pair(short.as_ptr(), cpath.as_ptr(), ptr::null_mut(), 0),
            PFK_ERR_INVALID_ARGUMENT
        );
        assert_eq!(
            pair(ptr::null(), cpath.as_ptr(), ptr::null_mut(), 0),
            PFK_ERR_INVALID_ARGUMENT
        );
        assert!(!path.exists(), "failed pairing must not write a file");
    }

    #[test]
    fn process_null_and_buffer_semantics() {
        // NULL handle.
        let mut out_len = 9usize;
        let rc = process(
            ptr::null_mut(),
            [4u8].as_ptr(),
            1,
            ptr::null_mut(),
            0,
            &mut out_len,
        );
        assert_eq!(rc, PFK_ERR_INVALID_ARGUMENT);
        assert_eq!(out_len, 0);

        // Mock-backed handle: too-small buffer reports needed size.
        let h = Box::into_raw(Box::new(PfkHandle::from_phone(Box::new(MockPhone::new()))));
        let req = [ctap2::CMD_GET_INFO];
        let mut tiny = [0u8; 2];
        let mut needed = 0usize;
        let rc = process(
            h,
            req.as_ptr(),
            req.len(),
            tiny.as_mut_ptr(),
            tiny.len(),
            &mut needed,
        );
        assert_eq!(rc, PFK_ERR_BUFFER_TOO_SMALL);
        assert!(needed > 2);
        // NULL out with len query.
        let mut needed2 = 0usize;
        let rc = process(h, req.as_ptr(), req.len(), ptr::null_mut(), 0, &mut needed2);
        assert_eq!(rc, PFK_ERR_BUFFER_TOO_SMALL);
        assert_eq!(needed2, needed);
        destroy(h);
        destroy(ptr::null_mut()); // no-op, must not crash
    }

    /// Full makeCredential + getAssertion through the C ABI against a
    /// MockPhone handle: proves the FFI drives the same stack the
    /// daemon uses, including CtapState persistence across calls.
    #[test]
    fn process_full_ceremony_with_mock_phone() {
        let h = Box::into_raw(Box::new(PfkHandle::from_phone(Box::new(MockPhone::new()))));
        let call = |req: &[u8]| -> Vec<u8> {
            let mut out = vec![0u8; 4096];
            let mut out_len = 0usize;
            let rc = process(
                h,
                req.as_ptr(),
                req.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            );
            assert_eq!(rc, PFK_OK);
            out.truncate(out_len);
            out
        };

        let params = cu::imap(vec![
            (1, cu::vbytes(vec![7u8; 32])),
            (
                2,
                cu::tmap(vec![
                    ("id", cu::vtext("example.com")),
                    ("name", cu::vtext("Example")),
                ]),
            ),
            (
                3,
                cu::tmap(vec![
                    ("id", cu::vbytes(b"user-1".to_vec())),
                    ("name", cu::vtext("sahen")),
                ]),
            ),
            (
                4,
                Value::Array(vec![cu::tmap(vec![
                    ("type", cu::vtext("public-key")),
                    ("alg", cu::vint(-7)),
                ])]),
            ),
        ]);
        let mut mc_req = vec![ctap2::CMD_MAKE_CREDENTIAL];
        mc_req.extend_from_slice(&cu::encode(&params));
        let mc_resp = call(&mc_req);
        assert_eq!(mc_resp[0], ctap2::CTAP1_ERR_SUCCESS);
        let mc_map = cu::decode(&mc_resp[1..]).unwrap();
        let auth_data = cu::get_int_key(&mc_map, 2).and_then(cu::as_bytes).unwrap();
        assert_eq!(auth_data[32], 0x45, "UP|UV|AT flags");
        // Credential id = authData[55..57] len || [57..57+len].
        let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
        let cred_id = auth_data[55..55 + cred_len].to_vec();

        let ga_params = cu::imap(vec![
            (1, cu::vtext("example.com")),
            (2, cu::vbytes(vec![9u8; 32])),
            (
                3,
                Value::Array(vec![cu::tmap(vec![
                    ("type", cu::vtext("public-key")),
                    ("id", cu::vbytes(cred_id)),
                ])]),
            ),
        ]);
        let mut ga_req = vec![ctap2::CMD_GET_ASSERTION];
        ga_req.extend_from_slice(&cu::encode(&ga_params));
        let ga_resp = call(&ga_req);
        assert_eq!(ga_resp[0], ctap2::CTAP1_ERR_SUCCESS);
        let ga_map = cu::decode(&ga_resp[1..]).unwrap();
        let sig = cu::get_int_key(&ga_map, 3).and_then(cu::as_bytes).unwrap();
        assert!(!sig.is_empty());

        // Unknown command -> CTAP error status inside the response.
        let resp = call(&[0x7F]);
        assert_eq!(resp, vec![ctap2::CTAP2_ERR_UNSUPPORTED_OPTION]);

        destroy(h);
    }
}
