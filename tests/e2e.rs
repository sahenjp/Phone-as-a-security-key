//! Integration tests: bridge handshake against an in-process phone-side
//! server, CBOR round-trip of getInfo, and the full selftest E2E.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use iphone_fido::bridge;
use iphone_fido::cbor_util as cu;
use iphone_fido::ctap2;
use iphone_fido::phone::MockPhone;
use serde_json::json;

#[test]
fn handshake_and_encrypted_ping_against_in_process_server() {
    let mut psk = [0u8; 32];
    iphone_fido::fill_random(&mut psk);

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();

    // Phone side: handshake, then answer one encrypted ping, then one
    // more encrypted message to prove sequence numbers advance.
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut session = bridge::server_handshake(stream, &psk).expect("server handshake");
        let req = session.recv_json().expect("server recv ping");
        assert_eq!(req.get("op").and_then(|v| v.as_str()), Some("ping"));
        let id = req.get("id").and_then(|v| v.as_u64()).unwrap();
        session
            .send_json(&json!({
                "id": id, "ok": true,
                "result": {"app": "iphone-fido", "version": 1}
            }))
            .expect("server send pong");
        let req2 = session.recv_json().expect("server recv second message");
        assert_eq!(req2.get("op").and_then(|v| v.as_str()), Some("ping"));
        session
            .send_json(&json!({"id": 2, "ok": true, "result": {"app": "iphone-fido", "version": 1}}))
            .expect("server send second pong");
    });

    let stream = TcpStream::connect(&addr).unwrap();
    let mut session = bridge::client_handshake(stream, &psk).expect("client handshake");
    session
        .send_json(&json!({"op": "ping", "id": 1}))
        .expect("client send ping");
    let res = session.recv_json().expect("client recv pong");
    assert_eq!(res.get("ok").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        res.pointer("/result/app").and_then(|v| v.as_str()),
        Some("iphone-fido")
    );
    session
        .send_json(&json!({"op": "ping", "id": 2}))
        .expect("client send second ping");
    let res2 = session.recv_json().expect("client recv second pong");
    assert_eq!(res2.get("ok").and_then(|v| v.as_bool()), Some(true));

    server.join().unwrap();
}

#[test]
fn handshake_rejects_wrong_psk() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server_psk = [7u8; 32];
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // Server must reject the client's confirm MAC.
        let _ = bridge::server_handshake(stream, &server_psk);
    });
    let stream = TcpStream::connect(&addr).unwrap();
    let result = bridge::client_handshake(stream, &[9u8; 32]);
    assert!(result.is_err(), "handshake with wrong PSK must fail");
    server.join().unwrap();
}

#[test]
fn get_info_cbor_roundtrip() {
    let mut phone = MockPhone::new();
    let mut state = ctap2::CtapState::new();
    let response = ctap2::process(&mut state, &mut phone, &[ctap2::CMD_GET_INFO]);
    assert_eq!(response[0], ctap2::CTAP1_ERR_SUCCESS);
    let info = cu::decode(&response[1..]).unwrap();
    assert_eq!(info, cu::decode(&cu::encode(&info)).unwrap());
    assert_eq!(
        cu::get_int_key(&info, 0x03).and_then(cu::as_bytes).unwrap(),
        &iphone_fido::AAGUID
    );
    let max_msg = cu::get_int_key(&info, 0x05)
        .and_then(cu::as_int)
        .expect("getInfo: maxMsgSize must be an integer");
    assert!(max_msg >= 1200, "maxMsgSize must be >= 1200, got {max_msg}");
}

#[test]
fn unsupported_ctap2_commands_return_error() {
    let mut phone = MockPhone::new();
    let mut state = ctap2::CtapState::new();
    // authenticatorReset (0x07): unsupported.
    assert_eq!(
        ctap2::process(&mut state, &mut phone, &[0x07]),
        vec![ctap2::CTAP2_ERR_UNSUPPORTED_OPTION]
    );
    // clientPIN (0x06) exists (getKeyAgreement) but a bare command with
    // no parameters is a missing-parameter error, not "unsupported".
    assert_eq!(
        ctap2::process(&mut state, &mut phone, &[0x06]),
        vec![ctap2::CTAP2_ERR_MISSING_PARAMETER]
    );
}

#[test]
fn selftest_e2e_signature_verification() {
    let lines = iphone_fido::selftest::run_selftest().expect("selftest must pass");
    assert!(lines.iter().any(|l| l.contains("signature verified")));
}

// Silence unused-import warnings for Read/Write in case of API drift.
#[allow(dead_code)]
fn _unused(_: &dyn Read, _: &dyn Write) {}
