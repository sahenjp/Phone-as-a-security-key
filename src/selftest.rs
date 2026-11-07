//! End-to-end self test: MockPhone + MockTransport.
//!
//! Drives the authenticator exactly like a host would (CTAPHID INIT,
//! CBOR getInfo -> makeCredential -> getAssertion), then verifies the
//! assertion signature with the credential public key taken from the
//! attested authData. Returns log lines; the caller prints PASS/FAIL.

use ciborium::value::Value;

use crate::authenticator::Authenticator;
use crate::cbor_util as cu;
use crate::ctaphid::{self, Assembler, BROADCAST_CID, PACKET_SIZE};
use crate::phone::{verifying_key_from_x963, verify_der_signature, MockPhone};
use crate::transport::MockTransport;
use crate::AAGUID;

/// Minimal host-side HID client driving an Authenticator through a
/// MockTransport, reassembling response messages itself.
struct HidClient {
    assembler: Assembler,
}

impl HidClient {
    fn new() -> Self {
        Self {
            assembler: Assembler::new(),
        }
    }

    fn exchange(
        &mut self,
        auth: &mut Authenticator<MockPhone>,
        transport: &mut MockTransport,
        cid: u32,
        cmd: u8,
        payload: &[u8],
    ) -> Result<(u8, Vec<u8>), String> {
        for pkt in ctaphid::fragment(cid, cmd, payload) {
            transport.queue_incoming(pkt);
        }
        auth.pump(transport).map_err(|e| format!("pump: {e}"))?;
        let sent = transport.take_sent();
        if sent.is_empty() {
            return Err("no response packets from authenticator".into());
        }
        let mut completed = None;
        for pkt in &sent {
            let parsed = ctaphid::parse_packet(pkt);
            if let Some(done) = self
                .assembler
                .feed(&parsed)
                .map_err(|c| format!("response reassembly error {c:#x}"))?
            {
                completed = Some(done);
            }
        }
        completed.ok_or_else(|| "response message did not complete".to_string())
    }
}

fn expect_status0(response: &[u8]) -> Result<&[u8], String> {
    match response.first() {
        Some(0x00) => Ok(&response[1..]),
        Some(code) => Err(format!("CTAP error status {code:#04x}")),
        None => Err("empty CTAP response".into()),
    }
}

pub fn run_selftest() -> Result<Vec<String>, String> {
    let mut log: Vec<String> = Vec::new();
    let mut auth = Authenticator::new(MockPhone::new());
    let mut transport = MockTransport::new();
    let mut client = HidClient::new();

    // ---- CTAPHID INIT on the broadcast channel
    let nonce: [u8; 8] = [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE];
    let (_cmd, init_resp) = client.exchange(
        &mut auth,
        &mut transport,
        BROADCAST_CID,
        ctaphid::CMD_INIT,
        &nonce,
    )?;
    if init_resp.len() != 17 {
        return Err(format!("INIT response must be 17 bytes, got {}", init_resp.len()));
    }
    if init_resp[..8] != nonce {
        return Err("INIT nonce was not echoed".into());
    }
    let cid = u32::from_be_bytes(init_resp[8..12].try_into().unwrap());
    if cid == 0 || cid == BROADCAST_CID {
        return Err("INIT assigned an invalid channel id".into());
    }
    let capabilities = init_resp[16];
    if capabilities & ctaphid::CAPABILITY_CBOR == 0 {
        return Err("INIT capabilities do not advertise CBOR".into());
    }
    log.push(format!(
        "INIT ok: channel {cid:#010x}, capabilities {capabilities:#04x}"
    ));

    // ---- PING echo
    let (_cmd, pong) = client.exchange(
        &mut auth,
        &mut transport,
        cid,
        ctaphid::CMD_PING,
        b"selftest-ping",
    )?;
    if pong != b"selftest-ping" {
        return Err("PING payload not echoed".into());
    }
    log.push("PING ok".into());

    // ---- CTAP2 getInfo
    let (_cmd, resp) = client.exchange(
        &mut auth,
        &mut transport,
        cid,
        ctaphid::CMD_CBOR,
        &[crate::ctap2::CMD_GET_INFO],
    )?;
    let info = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let versions = cu::get_int_key(&info, 0x01).ok_or("getInfo: missing versions")?;
    let versions_ok = cu::as_array(versions)
        .map(|a| a.iter().any(|v| cu::as_text(v) == Some("FIDO_2_0")))
        .unwrap_or(false);
    if !versions_ok {
        return Err("getInfo: versions does not contain FIDO_2_0".into());
    }
    let aaguid = cu::get_int_key(&info, 0x03).and_then(cu::as_bytes).ok_or("getInfo: missing aaguid")?;
    if aaguid != AAGUID {
        return Err("getInfo: AAGUID mismatch".into());
    }
    log.push("getInfo ok: versions=[FIDO_2_0], aaguid matches".into());

    // ---- CTAP2 makeCredential (rp example.com)
    let client_data_hash_1 = crate::sha256(b"selftest clientData #1");
    let mc_params = cu::imap(vec![
        (1, cu::vbytes(client_data_hash_1.to_vec())),
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
                ("id", cu::vbytes(b"user-123".to_vec())),
                ("name", cu::vtext("sahen")),
                ("displayName", cu::vtext("sahen")),
            ]),
        ),
        (
            4,
            Value::Array(vec![cu::tmap(vec![
                ("type", cu::vtext("public-key")),
                ("alg", cu::vint(-7)),
            ])]),
        ),
        (7, cu::tmap(vec![("rk", cu::vbool(true))])),
    ]);
    let mut mc_msg = vec![crate::ctap2::CMD_MAKE_CREDENTIAL];
    mc_msg.extend_from_slice(&cu::encode(&mc_params));
    let (_cmd, resp) = client.exchange(&mut auth, &mut transport, cid, ctaphid::CMD_CBOR, &mc_msg)?;
    let mc = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let fmt = cu::get_int_key(&mc, 1).and_then(cu::as_text).ok_or("makeCredential: missing fmt")?;
    if fmt != "packed" {
        return Err(format!("makeCredential: expected fmt packed, got {fmt}"));
    }
    let auth_data = cu::get_int_key(&mc, 2)
        .and_then(cu::as_bytes)
        .ok_or("makeCredential: missing authData")?
        .to_vec();
    // Parse attested credential data out of authData.
    if auth_data.len() < 55 {
        return Err("makeCredential: authData too short".into());
    }
    if auth_data[..32] != crate::sha256(b"example.com") {
        return Err("makeCredential: authData rpIdHash mismatch".into());
    }
    if auth_data[32] != 0x45 {
        return Err(format!(
            "makeCredential: expected flags 0x45, got {:#04x}",
            auth_data[32]
        ));
    }
    if auth_data[37..53] != AAGUID {
        return Err("makeCredential: authData AAGUID mismatch".into());
    }
    let cred_len = u16::from_be_bytes([auth_data[53], auth_data[54]]) as usize;
    let credential_id = auth_data[55..55 + cred_len].to_vec();
    let cose = cu::decode(&auth_data[55 + cred_len..]).map_err(|e| format!("COSE key: {e}"))?;
    let x = cu::get_int_key(&cose, -2).and_then(cu::as_bytes).ok_or("COSE: missing x")?;
    let y = cu::get_int_key(&cose, -3).and_then(cu::as_bytes).ok_or("COSE: missing y")?;
    let mut x963 = vec![0x04u8];
    x963.extend_from_slice(x);
    x963.extend_from_slice(y);
    let verifying_key =
        verifying_key_from_x963(&x963).ok_or("COSE: cannot build verifying key")?;
    // Packed self-attestation: attStmt {alg: -7, sig} must carry a
    // signature by the credential key over authData || clientDataHash
    // — the same check libfido2's fido_cred_verify_self performs for
    // pamu2fcfg (which rejects fmt "none" outright).
    let att_stmt = cu::get_int_key(&mc, 3).ok_or("makeCredential: missing attStmt")?;
    let att_alg = cu::get_text_key(att_stmt, "alg")
        .and_then(cu::as_int)
        .ok_or("attStmt: missing alg")?;
    if att_alg != -7 {
        return Err(format!("attStmt: expected alg -7, got {att_alg}"));
    }
    let att_sig = cu::get_text_key(att_stmt, "sig")
        .and_then(cu::as_bytes)
        .ok_or("attStmt: missing sig")?;
    let mut att_signed = auth_data.clone();
    att_signed.extend_from_slice(&client_data_hash_1);
    if !verify_der_signature(&verifying_key, &att_signed, att_sig) {
        return Err("attStmt: self-attestation signature does not verify".into());
    }
    log.push(format!(
        "makeCredential ok: fmt=packed, self-attestation verified, credential_id {} bytes, COSE ES256 key parsed",
        credential_id.len()
    ));

    // ---- CTAP2 getAssertion
    let client_data_hash_2 = crate::sha256(b"selftest clientData #2");
    let ga_params = cu::imap(vec![
        (1, cu::vtext("example.com")),
        (2, cu::vbytes(client_data_hash_2.to_vec())),
        (
            3,
            Value::Array(vec![cu::tmap(vec![
                ("type", cu::vtext("public-key")),
                ("id", cu::vbytes(credential_id.clone())),
            ])]),
        ),
        (
            5,
            cu::tmap(vec![("up", cu::vbool(true)), ("uv", cu::vbool(true))]),
        ),
    ]);
    let mut ga_msg = vec![crate::ctap2::CMD_GET_ASSERTION];
    ga_msg.extend_from_slice(&cu::encode(&ga_params));
    let (_cmd, resp) = client.exchange(&mut auth, &mut transport, cid, ctaphid::CMD_CBOR, &ga_msg)?;
    let ga = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let resp_cred = cu::get_int_key(&ga, 1).ok_or("getAssertion: missing credential")?;
    let resp_cred_id = cu::get_text_key(resp_cred, "id")
        .and_then(cu::as_bytes)
        .ok_or("getAssertion: credential has no id")?;
    if resp_cred_id != credential_id.as_slice() {
        return Err("getAssertion: credential id mismatch".into());
    }
    let assert_auth_data = cu::get_int_key(&ga, 2)
        .and_then(cu::as_bytes)
        .ok_or("getAssertion: missing authData")?
        .to_vec();
    let signature = cu::get_int_key(&ga, 3)
        .and_then(cu::as_bytes)
        .ok_or("getAssertion: missing signature")?
        .to_vec();
    if assert_auth_data.len() != 37 {
        return Err("getAssertion: authData must be 37 bytes".into());
    }
    if assert_auth_data[..32] != crate::sha256(b"example.com") {
        return Err("getAssertion: authData rpIdHash mismatch".into());
    }
    if assert_auth_data[32] != 0x05 {
        return Err("getAssertion: expected flags 0x05".into());
    }
    let sign_count = u32::from_be_bytes(assert_auth_data[33..37].try_into().unwrap());
    if sign_count != 1 {
        return Err(format!("getAssertion: expected signCount 1, got {sign_count}"));
    }
    // The actual signature check, with the p256 verifying key.
    let mut signed = assert_auth_data.clone();
    signed.extend_from_slice(&client_data_hash_2);
    if !verify_der_signature(&verifying_key, &signed, &signature) {
        return Err("getAssertion: signature verification FAILED".into());
    }
    log.push("getAssertion ok: signCount=1, DER signature verified with credential public key".into());

    // ---- PRF (hmac-secret): makeCredential with the extension enabled
    let mc2_params = cu::imap(vec![
        (1, cu::vbytes(crate::sha256(b"selftest clientData prf").to_vec())),
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
                ("id", cu::vbytes(b"user-123".to_vec())),
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
        (6, cu::tmap(vec![("hmac-secret", cu::vbool(true))])),
    ]);
    let mut mc2_msg = vec![crate::ctap2::CMD_MAKE_CREDENTIAL];
    mc2_msg.extend_from_slice(&cu::encode(&mc2_params));
    let (_cmd, resp) = client.exchange(&mut auth, &mut transport, cid, ctaphid::CMD_CBOR, &mc2_msg)?;
    let mc2 = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let auth_data2 = cu::get_int_key(&mc2, 2)
        .and_then(cu::as_bytes)
        .ok_or("PRF makeCredential: missing authData")?
        .to_vec();
    if auth_data2[32] != 0x65 {
        return Err(format!(
            "PRF makeCredential: expected flags 0x65 (UP|UV|AT|ED), got {:#04x}",
            auth_data2[32]
        ));
    }
    let cred2_len = u16::from_be_bytes([auth_data2[53], auth_data2[54]]) as usize;
    let credential_id2 = auth_data2[55..55 + cred2_len].to_vec();
    // Two consecutive CBOR values follow: the COSE key, then the
    // authenticator extension outputs map.
    let mut cursor = std::io::Cursor::new(&auth_data2[55 + cred2_len..]);
    let cose2: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|e| format!("PRF COSE: {e}"))?;
    let mc_ext: Value =
        ciborium::de::from_reader(&mut cursor).map_err(|e| format!("PRF extensions: {e}"))?;
    if cu::get_text_key(&mc_ext, "hmac-secret").and_then(cu::as_bool) != Some(true) {
        return Err("PRF makeCredential: extension output hmac-secret != true".into());
    }
    let x2 = cu::get_int_key(&cose2, -2).and_then(cu::as_bytes).ok_or("PRF COSE: missing x")?;
    let y2 = cu::get_int_key(&cose2, -3).and_then(cu::as_bytes).ok_or("PRF COSE: missing y")?;
    let mut x963_2 = vec![0x04u8];
    x963_2.extend_from_slice(x2);
    x963_2.extend_from_slice(y2);
    let verifying_key2 =
        verifying_key_from_x963(&x963_2).ok_or("PRF COSE: cannot build verifying key")?;
    log.push("PRF makeCredential ok: ED flag set, extension output hmac-secret=true".into());

    // ---- PRF: ClientPIN getKeyAgreement
    let pin_params = cu::imap(vec![(1, cu::vint(1)), (2, cu::vint(2))]);
    let mut pin_msg = vec![crate::ctap2::CMD_CLIENT_PIN];
    pin_msg.extend_from_slice(&cu::encode(&pin_params));
    let (_cmd, resp) = client.exchange(&mut auth, &mut transport, cid, ctaphid::CMD_CBOR, &pin_msg)?;
    let pin_resp = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let auth_cose = cu::get_int_key(&pin_resp, 1).ok_or("getKeyAgreement: missing key")?;
    let ax = cu::get_int_key(auth_cose, -2).and_then(cu::as_bytes).ok_or("getKeyAgreement: missing x")?;
    let ay = cu::get_int_key(auth_cose, -3).and_then(cu::as_bytes).ok_or("getKeyAgreement: missing y")?;
    let mut auth_x963 = vec![0x04u8];
    auth_x963.extend_from_slice(ax);
    auth_x963.extend_from_slice(ay);
    let auth_pub =
        verifying_key_from_x963(&auth_x963).ok_or("getKeyAgreement: bad authenticator key")?;

    // Platform side of pinUvAuthProtocol ONE.
    let platform_secret = p256::SecretKey::random(&mut rand_core::OsRng);
    let shared = p256::ecdh::diffie_hellman(
        platform_secret.to_nonzero_scalar(),
        auth_pub.as_affine(),
    );
    let protocol_key = crate::sha256(shared.raw_secret_bytes());
    let platform_pub = platform_secret.public_key().to_sec1_bytes();
    let platform_cose = cu::imap(vec![
        (1, cu::vint(2)),
        (3, cu::vint(-25)),
        (-1, cu::vint(1)),
        (-2, cu::vbytes(platform_pub[1..33].to_vec())),
        (-3, cu::vbytes(platform_pub[33..65].to_vec())),
    ]);

    // One PRF evaluation round-trip; returns the decrypted PRF output.
    let prf_eval = |auth: &mut Authenticator<MockPhone>,
                    transport: &mut MockTransport,
                    client: &mut HidClient,
                    salt: &[u8; 32],
                    cdh: &[u8; 32]|
     -> Result<Vec<u8>, String> {
        let salt_enc = crate::ctap2::aes256_cbc_encrypt(&protocol_key, salt)
            .ok_or("prf: salt encrypt failed")?;
        let salt_auth_full = crate::hmac_sha256(&protocol_key, &salt_enc);
        let hs = cu::imap(vec![
            (1, platform_cose.clone()),
            (2, cu::vbytes(salt_enc)),
            (3, cu::vbytes(salt_auth_full[..16].to_vec())),
        ]);
        let ga_params = cu::imap(vec![
            (1, cu::vtext("example.com")),
            (2, cu::vbytes(cdh.to_vec())),
            (
                3,
                Value::Array(vec![cu::tmap(vec![
                    ("type", cu::vtext("public-key")),
                    ("id", cu::vbytes(credential_id2.clone())),
                ])]),
            ),
            (4, cu::tmap(vec![("hmac-secret", hs)])),
        ]);
        let mut ga_msg = vec![crate::ctap2::CMD_GET_ASSERTION];
        ga_msg.extend_from_slice(&cu::encode(&ga_params));
        let (_cmd, resp) = client.exchange(auth, transport, cid, ctaphid::CMD_CBOR, &ga_msg)?;
        let ga = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
        let ad = cu::get_int_key(&ga, 2)
            .and_then(cu::as_bytes)
            .ok_or("prf getAssertion: missing authData")?
            .to_vec();
        if ad.len() <= 37 || ad[32] != 0x25 {
            return Err(format!(
                "prf getAssertion: expected ED flags 0x25 and extension bytes, flags {:#04x}, len {}",
                ad[32],
                ad.len()
            ));
        }
        let sig = cu::get_int_key(&ga, 3)
            .and_then(cu::as_bytes)
            .ok_or("prf getAssertion: missing signature")?;
        let mut signed = ad.clone();
        signed.extend_from_slice(cdh);
        if !verify_der_signature(&verifying_key2, &signed, sig) {
            return Err("prf getAssertion: signature verification FAILED".into());
        }
        let ext = cu::decode(&ad[37..]).map_err(|e| format!("prf extensions: {e}"))?;
        let enc_out = cu::get_text_key(&ext, "hmac-secret")
            .and_then(cu::as_bytes)
            .ok_or("prf getAssertion: missing hmac-secret output")?;
        crate::ctap2::aes256_cbc_decrypt(&protocol_key, enc_out)
            .ok_or("prf: output decrypt failed".into())
    };

    let salt_a = crate::sha256(b"selftest prf salt A");
    let out1 = prf_eval(
        &mut auth,
        &mut transport,
        &mut client,
        &salt_a,
        &crate::sha256(b"selftest prf cdh 1"),
    )?;
    if out1.len() != 32 {
        return Err(format!("prf: expected 32-byte output, got {}", out1.len()));
    }
    let out2 = prf_eval(
        &mut auth,
        &mut transport,
        &mut client,
        &salt_a,
        &crate::sha256(b"selftest prf cdh 2"),
    )?;
    if out1 != out2 {
        return Err("prf: same salt must give the same output".into());
    }
    let out3 = prf_eval(
        &mut auth,
        &mut transport,
        &mut client,
        &crate::sha256(b"selftest prf salt B"),
        &crate::sha256(b"selftest prf cdh 3"),
    )?;
    if out3 == out1 {
        return Err("prf: different salt must give a different output".into());
    }
    log.push("PRF getAssertion ok: outputs deterministic per salt, signatures verified".into());

    // ---- hmac-secret-mc: PRF evaluated inside makeCredential (the
    // flow Chromium requires before it returns PRF results at
    // registration time, e.g. for ppq.ai). The platform encrypts the
    // salts up front; the outputs come back encrypted inside the
    // attested authData extension outputs.
    let mc_salt = crate::sha256(b"selftest mc salt");
    let mc_salt_enc = crate::ctap2::aes256_cbc_encrypt(&protocol_key, &mc_salt)
        .ok_or("mc: salt encrypt failed")?;
    let mc_salt_auth = crate::hmac_sha256(&protocol_key, &mc_salt_enc);
    let mc_hs = cu::imap(vec![
        (1, platform_cose.clone()),
        (2, cu::vbytes(mc_salt_enc)),
        (3, cu::vbytes(mc_salt_auth[..16].to_vec())),
        (4, cu::vint(1)),
    ]);
    let mc3_params = cu::imap(vec![
        (1, cu::vbytes(crate::sha256(b"selftest clientData mc").to_vec())),
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
                ("id", cu::vbytes(b"user-3".to_vec())),
                ("name", cu::vtext("three@example.com")),
            ]),
        ),
        (
            4,
            Value::Array(vec![cu::tmap(vec![
                ("type", cu::vtext("public-key")),
                ("alg", cu::vint(-7)),
            ])]),
        ),
        (6, cu::tmap(vec![("hmac-secret-mc", mc_hs)])),
    ]);
    let mut mc3_msg = vec![crate::ctap2::CMD_MAKE_CREDENTIAL];
    mc3_msg.extend_from_slice(&cu::encode(&mc3_params));
    let (_cmd, resp) = client.exchange(&mut auth, &mut transport, cid, ctaphid::CMD_CBOR, &mc3_msg)?;
    let mc3 = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let auth_data3 = cu::get_int_key(&mc3, 2)
        .and_then(cu::as_bytes)
        .ok_or("mc makeCredential: missing authData")?
        .to_vec();
    if auth_data3[32] != 0x65 {
        return Err(format!(
            "mc makeCredential: expected flags 0x65, got {:#04x}",
            auth_data3[32]
        ));
    }
    let cred3_len = u16::from_be_bytes([auth_data3[53], auth_data3[54]]) as usize;
    let credential_id3 = auth_data3[55..55 + cred3_len].to_vec();
    let mut cursor3 = std::io::Cursor::new(&auth_data3[55 + cred3_len..]);
    let cose3: Value =
        ciborium::de::from_reader(&mut cursor3).map_err(|e| format!("mc COSE: {e}"))?;
    let mc3_ext: Value =
        ciborium::de::from_reader(&mut cursor3).map_err(|e| format!("mc extensions: {e}"))?;
    let mc_enc_out = cu::get_text_key(&mc3_ext, "hmac-secret-mc")
        .and_then(cu::as_bytes)
        .ok_or("mc makeCredential: missing hmac-secret-mc output")?;
    let mc_out = crate::ctap2::aes256_cbc_decrypt(&protocol_key, mc_enc_out)
        .ok_or("mc: output decrypt failed")?;
    if mc_out.len() != 32 {
        return Err(format!("mc: expected 32-byte output, got {}", mc_out.len()));
    }
    let x3 = cu::get_int_key(&cose3, -2).and_then(cu::as_bytes).ok_or("mc COSE: missing x")?;
    let y3 = cu::get_int_key(&cose3, -3).and_then(cu::as_bytes).ok_or("mc COSE: missing y")?;
    let mut x963_3 = vec![0x04u8];
    x963_3.extend_from_slice(x3);
    x963_3.extend_from_slice(y3);
    let verifying_key3 =
        verifying_key_from_x963(&x963_3).ok_or("mc COSE: cannot build verifying key")?;

    // The creation-time output must equal a later assertion-time PRF
    // evaluation with the same salt on the same credential.
    let ga_salt_enc = crate::ctap2::aes256_cbc_encrypt(&protocol_key, &mc_salt)
        .ok_or("mc ga: salt encrypt failed")?;
    let ga_salt_auth = crate::hmac_sha256(&protocol_key, &ga_salt_enc);
    let ga_hs = cu::imap(vec![
        (1, platform_cose.clone()),
        (2, cu::vbytes(ga_salt_enc)),
        (3, cu::vbytes(ga_salt_auth[..16].to_vec())),
    ]);
    let ga3_cdh = crate::sha256(b"selftest mc ga cdh");
    let ga3_params = cu::imap(vec![
        (1, cu::vtext("example.com")),
        (2, cu::vbytes(ga3_cdh.to_vec())),
        (
            3,
            Value::Array(vec![cu::tmap(vec![
                ("type", cu::vtext("public-key")),
                ("id", cu::vbytes(credential_id3.clone())),
            ])]),
        ),
        (4, cu::tmap(vec![("hmac-secret", ga_hs)])),
    ]);
    let mut ga3_msg = vec![crate::ctap2::CMD_GET_ASSERTION];
    ga3_msg.extend_from_slice(&cu::encode(&ga3_params));
    let (_cmd, resp) = client.exchange(&mut auth, &mut transport, cid, ctaphid::CMD_CBOR, &ga3_msg)?;
    let ga3 = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
    let ga3_ad = cu::get_int_key(&ga3, 2)
        .and_then(cu::as_bytes)
        .ok_or("mc ga: missing authData")?
        .to_vec();
    let ga3_sig = cu::get_int_key(&ga3, 3)
        .and_then(cu::as_bytes)
        .ok_or("mc ga: missing signature")?;
    let mut ga3_signed = ga3_ad.clone();
    ga3_signed.extend_from_slice(&ga3_cdh);
    if !verify_der_signature(&verifying_key3, &ga3_signed, ga3_sig) {
        return Err("mc ga: signature verification FAILED".into());
    }
    let ga3_ext = cu::decode(&ga3_ad[37..]).map_err(|e| format!("mc ga extensions: {e}"))?;
    let ga3_enc = cu::get_text_key(&ga3_ext, "hmac-secret")
        .and_then(cu::as_bytes)
        .ok_or("mc ga: missing hmac-secret output")?;
    let ga3_out = crate::ctap2::aes256_cbc_decrypt(&protocol_key, ga3_enc)
        .ok_or("mc ga: output decrypt failed")?;
    if ga3_out != mc_out {
        return Err("mc: creation-time output must equal assertion-time output".into());
    }
    log.push("hmac-secret-mc ok: creation-time PRF output matches assertion-time output".into());

    // ---- CTAP "prf" extension: what Chromium actually uses when the
    // authenticator advertises "prf" in GetInfo. Enable-only create
    // returns {"prf": {"enabled": true}} in the response at key 6 with
    // CLEAN authData (flags 0x45, no extension outputs); a create with
    // an eval input also returns plaintext results at key 6; assertion
    // results travel at response key 8.
    let prf_salt = crate::sha256(b"selftest prf-ext salt");
    let mut prf_create = |phone_auth: &mut crate::authenticator::Authenticator<MockPhone>,
                      transport: &mut MockTransport,
                      cid: u32,
                      user: &[u8],
                      prf_value: Value|
     -> Result<(Value, Vec<u8>, Vec<u8>), String> {
        let params = cu::imap(vec![
            (1, cu::vbytes(crate::sha256(b"selftest prf-ext cdh").to_vec())),
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
                    ("id", cu::vbytes(user.to_vec())),
                    ("name", cu::vtext("prf@example.com")),
                ]),
            ),
            (
                4,
                Value::Array(vec![cu::tmap(vec![
                    ("type", cu::vtext("public-key")),
                    ("alg", cu::vint(-7)),
                ])]),
            ),
            (6, cu::tmap(vec![("prf", prf_value)])),
        ]);
        let mut msg = vec![crate::ctap2::CMD_MAKE_CREDENTIAL];
        msg.extend_from_slice(&cu::encode(&params));
        let (_cmd, resp) = client.exchange(phone_auth, transport, cid, ctaphid::CMD_CBOR, &msg)?;
        let mc: Value = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
        let ad = cu::get_int_key(&mc, 2)
            .and_then(cu::as_bytes)
            .ok_or("prf-ext create: missing authData")?
            .to_vec();
        if ad[32] != 0x45 {
            return Err(format!(
                "prf-ext create: expected clean flags 0x45, got {:#04x}",
                ad[32]
            ));
        }
        let clen = u16::from_be_bytes([ad[53], ad[54]]) as usize;
        let cred_id = ad[55..55 + clen].to_vec();
        let mut cur = std::io::Cursor::new(&ad[55 + clen..]);
        let cose: Value =
            ciborium::de::from_reader(&mut cur).map_err(|e| format!("prf-ext COSE: {e}"))?;
        let x = cu::get_int_key(&cose, -2).and_then(cu::as_bytes).ok_or("prf-ext COSE x")?;
        let y = cu::get_int_key(&cose, -3).and_then(cu::as_bytes).ok_or("prf-ext COSE y")?;
        let mut x963 = vec![0x04u8];
        x963.extend_from_slice(x);
        x963.extend_from_slice(y);
        Ok((mc, cred_id, x963))
    };

    // Enable-only.
    let (en_mc, _en_cred, _en_x963) = prf_create(
        &mut auth,
        &mut transport,
        cid,
        b"user-prf-enable",
        cu::tmap(vec![]),
    )?;
    let en6 = cu::get_int_key(&en_mc, 6).ok_or("prf-ext enable: missing response key 6")?;
    let en_prf = cu::get_text_key(en6, "prf").ok_or("prf-ext enable: missing prf output")?;
    if cu::get_text_key(en_prf, "enabled").and_then(cu::as_bool) != Some(true) {
        return Err("prf-ext enable: enabled != true".into());
    }
    if cu::get_text_key(en_prf, "results").is_some() {
        return Err("prf-ext enable: results must be absent without eval".into());
    }

    // Create with eval.
    let eval_map = cu::tmap(vec![("first", cu::vbytes(prf_salt.to_vec()))]);
    let (ev_mc, ev_cred, ev_x963) = prf_create(
        &mut auth,
        &mut transport,
        cid,
        b"user-prf-eval",
        cu::tmap(vec![("eval", eval_map)]),
    )?;
    let ev6 = cu::get_int_key(&ev_mc, 6).ok_or("prf-ext eval create: missing key 6")?;
    let ev_prf = cu::get_text_key(ev6, "prf").ok_or("prf-ext eval create: missing prf")?;
    let ev_results =
        cu::get_text_key(ev_prf, "results").ok_or("prf-ext eval create: missing results")?;
    let create_out = cu::get_text_key(ev_results, "first")
        .and_then(cu::as_bytes)
        .ok_or("prf-ext eval create: missing first")?
        .to_vec();
    if create_out.len() != 32 {
        return Err("prf-ext eval create: first must be 32 bytes".into());
    }
    let ev_vk = verifying_key_from_x963(&ev_x963).ok_or("prf-ext: bad verifying key")?;

    // Assertion with eval, then with evalByCredential: outputs must
    // match the creation-time output for the same salt.
    for by_cred in [false, true] {
        let prf_input = if by_cred {
            let mut m = Vec::new();
            m.push((cu::vbytes(ev_cred.clone()), cu::tmap(vec![("first", cu::vbytes(prf_salt.to_vec()))])));
            cu::tmap(vec![("evalByCredential", Value::Map(m))])
        } else {
            cu::tmap(vec![("eval", cu::tmap(vec![("first", cu::vbytes(prf_salt.to_vec()))]))])
        };
        let ga_cdh = crate::sha256(b"selftest prf-ext ga cdh");
        let ga_params = cu::imap(vec![
            (1, cu::vtext("example.com")),
            (2, cu::vbytes(ga_cdh.to_vec())),
            (
                3,
                Value::Array(vec![cu::tmap(vec![
                    ("type", cu::vtext("public-key")),
                    ("id", cu::vbytes(ev_cred.clone())),
                ])]),
            ),
            (4, cu::tmap(vec![("prf", prf_input)])),
        ]);
        let mut ga_msg = vec![crate::ctap2::CMD_GET_ASSERTION];
        ga_msg.extend_from_slice(&cu::encode(&ga_params));
        let (_cmd, resp) = client.exchange(&mut auth, &mut transport, cid, ctaphid::CMD_CBOR, &ga_msg)?;
        let ga: Value = cu::decode(expect_status0(&resp)?).map_err(|e| e)?;
        let ga_ad = cu::get_int_key(&ga, 2)
            .and_then(cu::as_bytes)
            .ok_or("prf-ext ga: missing authData")?
            .to_vec();
        if ga_ad[32] != 0x05 {
            return Err(format!(
                "prf-ext ga: expected flags 0x05, got {:#04x}",
                ga_ad[32]
            ));
        }
        let ga_sig = cu::get_int_key(&ga, 3)
            .and_then(cu::as_bytes)
            .ok_or("prf-ext ga: missing signature")?;
        let mut signed = ga_ad.clone();
        signed.extend_from_slice(&ga_cdh);
        if !verify_der_signature(&ev_vk, &signed, ga_sig) {
            return Err("prf-ext ga: signature verification FAILED".into());
        }
        let ga8 = cu::get_int_key(&ga, 8).ok_or("prf-ext ga: missing response key 8")?;
        let ga_prf = cu::get_text_key(ga8, "prf").ok_or("prf-ext ga: missing prf output")?;
        let ga_results =
            cu::get_text_key(ga_prf, "results").ok_or("prf-ext ga: missing results")?;
        let ga_out = cu::get_text_key(ga_results, "first")
            .and_then(cu::as_bytes)
            .ok_or("prf-ext ga: missing first")?;
        if ga_out != create_out.as_slice() {
            return Err("prf-ext: assertion output must equal creation-time output".into());
        }
    }
    log.push("prf extension ok: enabled at key 6, eval results match create/assert (eval + evalByCredential)".into());

    // Keep PACKET_SIZE referenced (packet size sanity).
    debug_assert_eq!(PACKET_SIZE, 64);
    Ok(log)
}
