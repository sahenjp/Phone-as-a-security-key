//! CTAP2 processing (CBOR). The PC terminates CTAP2; the phone only
//! performs the semantic operations in BRIDGE-PROTOCOL.md section 3.

use ciborium::value::Value;

use crate::cbor_util as cu;
use crate::phone::{
    CreateCredentialRequest, GetAssertionRequest, Phone, PhoneError,
};
use crate::AAGUID;

// CTAP2 commands
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;

// CTAP status codes
pub const CTAP1_ERR_SUCCESS: u8 = 0x00;
pub const CTAP1_ERR_INVALID_COMMAND: u8 = 0x01;
pub const CTAP1_ERR_INVALID_PARAMETER: u8 = 0x02;
pub const CTAP1_ERR_INVALID_LENGTH: u8 = 0x03;
pub const CTAP2_ERR_MISSING_PARAMETER: u8 = 0x14;
pub const CTAP2_ERR_CREDENTIAL_EXCLUDED: u8 = 0x19;
pub const CTAP2_ERR_UNSUPPORTED_ALGORITHM: u8 = 0x26;
pub const CTAP2_ERR_OPERATION_DENIED: u8 = 0x27;
pub const CTAP2_ERR_NO_CREDENTIALS: u8 = 0x2E;
pub const CTAP2_ERR_UNSUPPORTED_OPTION: u8 = 0x2B;
pub const CTAP1_ERR_OTHER: u8 = 0x7F;

pub const MAX_MSG_SIZE: u64 = 1200;

/// Process one CTAP2 message (command byte + CBOR params) and return the
/// response bytes (status byte + optional CBOR payload).
pub fn process<P: Phone>(phone: &mut P, payload: &[u8]) -> Vec<u8> {
    if payload.is_empty() {
        return vec![CTAP1_ERR_INVALID_LENGTH];
    }
    let (cmd, params_bytes) = (payload[0], &payload[1..]);
    match cmd {
        CMD_GET_INFO => {
            let mut out = vec![CTAP1_ERR_SUCCESS];
            out.extend_from_slice(&cu::encode(&get_info()));
            out
        }
        CMD_MAKE_CREDENTIAL => respond(make_credential(phone, params_bytes)),
        CMD_GET_ASSERTION => respond(get_assertion(phone, params_bytes)),
        // authenticatorReset (0x07), authenticatorClientPIN (0x06),
        // authenticatorBioEnrollment (0x09), authenticatorCredentialManagement
        // (0x0A), authenticatorSelection (0x0B), getNextAssertion (0x08),
        // and anything else: not supported by this authenticator.
        _ => vec![CTAP2_ERR_UNSUPPORTED_OPTION],
    }
}

fn respond(result: Result<Value, u8>) -> Vec<u8> {
    match result {
        Ok(v) => {
            let mut out = vec![CTAP1_ERR_SUCCESS];
            out.extend_from_slice(&cu::encode(&v));
            out
        }
        Err(code) => vec![code],
    }
}

fn parse_params(bytes: &[u8]) -> Result<Value, u8> {
    if bytes.is_empty() {
        return Err(CTAP2_ERR_MISSING_PARAMETER);
    }
    cu::decode(bytes).map_err(|_| CTAP1_ERR_INVALID_PARAMETER)
}

fn map_phone_error(e: &PhoneError) -> u8 {
    match e.code.as_str() {
        "user_cancelled" => CTAP2_ERR_OPERATION_DENIED,
        "no_credentials" => CTAP2_ERR_NO_CREDENTIALS,
        "not_found" => CTAP2_ERR_NO_CREDENTIALS,
        "bad_request" => CTAP1_ERR_INVALID_PARAMETER,
        _ => CTAP1_ERR_OTHER,
    }
}

/// authenticatorGetInfo (0x04) response value.
pub fn get_info() -> Value {
    cu::imap(vec![
        (
            0x01,
            Value::Array(vec![cu::vtext("FIDO_2_0")]),
        ),
        (0x03, cu::vbytes(AAGUID.to_vec())),
        (
            0x04,
            cu::tmap(vec![
                ("rk", cu::vbool(true)),
                ("up", cu::vbool(true)),
                ("uv", cu::vbool(true)),
                // NOTE: no "clientPin" key here, deliberately. This
                // authenticator has no PIN support (UV is internal to the
                // phone). Chromium's ReadCTAPGetInfoResponse treats an
                // explicitly present clientPin:false as "PIN supported but
                // not set" (kSupportedButPinNotSet) and then REQUIRES
                // pinUvAuthProtocols (key 0x06) to be present as well;
                // without it the whole GetInfo response is rejected and
                // the device is misclassified as U2F-only. Omitting the
                // key leaves Chromium's default (kNotSupported) and the
                // response parses. authenticator-rs/libfido2 likewise
                // treat an absent clientPin option as unsupported.
            ]),
        ),
        (0x05, Value::Integer(MAX_MSG_SIZE.into())),
        (
            0x09,
            Value::Array(vec![cu::vtext("usb")]),
        ),
        (
            0x0A,
            Value::Array(vec![cu::tmap(vec![
                ("type", cu::vtext("public-key")),
                ("alg", cu::vint(-7)), // ES256
            ])]),
        ),
    ])
}

fn make_credential<P: Phone>(phone: &mut P, params_bytes: &[u8]) -> Result<Value, u8> {
    let params = parse_params(params_bytes)?;

    // 1: clientDataHash (32 bytes, required)
    let cdh_v = cu::get_int_key(&params, 1).ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    let cdh = cu::as_bytes(cdh_v).ok_or(CTAP1_ERR_INVALID_PARAMETER)?;
    if cdh.len() != 32 {
        return Err(CTAP1_ERR_INVALID_PARAMETER);
    }
    let mut client_data_hash = [0u8; 32];
    client_data_hash.copy_from_slice(cdh);

    // 2: rp { id (required), name }
    let rp = cu::get_int_key(&params, 2).ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    let rp_id = cu::get_text_key(rp, "id")
        .and_then(cu::as_text)
        .ok_or(CTAP2_ERR_MISSING_PARAMETER)?
        .to_string();
    let rp_name = cu::get_text_key(rp, "name")
        .and_then(cu::as_text)
        .map(|s| s.to_string());

    // 3: user { id (required), name, displayName }
    let user = cu::get_int_key(&params, 3).ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    let user_id = cu::get_text_key(user, "id")
        .and_then(cu::as_bytes)
        .ok_or(CTAP2_ERR_MISSING_PARAMETER)?
        .to_vec();
    let user_name = cu::get_text_key(user, "name")
        .and_then(cu::as_text)
        .map(|s| s.to_string());
    let user_display_name = cu::get_text_key(user, "displayName")
        .and_then(cu::as_text)
        .map(|s| s.to_string());

    // 4: pubKeyCredParams must offer ES256 (-7)
    let cred_params = cu::get_int_key(&params, 4).ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    let alg_list = cu::as_array(cred_params).ok_or(CTAP1_ERR_INVALID_PARAMETER)?;
    let mut es256_offered = false;
    for entry in alg_list {
        let alg = cu::get_text_key(entry, "alg").and_then(cu::as_int);
        let ty = cu::get_text_key(entry, "type").and_then(cu::as_text);
        // type absent is tolerated; type present must be "public-key".
        if alg == Some(-7) && (ty.is_none() || ty == Some("public-key")) {
            es256_offered = true;
        }
    }
    if !es256_offered {
        return Err(CTAP2_ERR_UNSUPPORTED_ALGORITHM);
    }

    // 5: excludeList — if the phone already holds one of these credentials
    // for this RP, the credential is excluded.
    if let Some(exclude) = cu::get_int_key(&params, 5) {
        if let Some(list) = cu::as_array(exclude) {
            if !list.is_empty() {
                if let Ok(existing) = phone.list_credentials() {
                    for item in list {
                        if let Some(id) = cu::get_text_key(item, "id").and_then(cu::as_bytes) {
                            if existing
                                .iter()
                                .any(|c| c.rp_id == rp_id && c.credential_id == id)
                            {
                                return Err(CTAP2_ERR_CREDENTIAL_EXCLUDED);
                            }
                        }
                    }
                }
            }
        }
    }

    // Pin/UV auth parameters are not supported (uv is internal to the
    // phone). Some clients nevertheless attach an EMPTY pinUvAuthParam;
    // that carries no authentication information, so tolerate it and
    // reject only a non-empty one.
    if let Some(p) = cu::get_int_key(&params, 8) {
        let empty = cu::as_bytes(p).map(|b| b.is_empty()).unwrap_or(false);
        if !empty {
            return Err(CTAP2_ERR_UNSUPPORTED_OPTION);
        }
    }

    let result = phone
        .create_credential(&CreateCredentialRequest {
            rp_id,
            rp_name,
            user_id,
            user_name,
            user_display_name,
            client_data_hash,
        })
        .map_err(|e| map_phone_error(&e))?;

    Ok(cu::imap(vec![
        (1, cu::vtext(result.fmt)),
        (2, cu::vbytes(result.auth_data)),
        (3, cu::imap(vec![])), // attStmt: empty for fmt "none"
    ]))
}

fn get_assertion<P: Phone>(phone: &mut P, params_bytes: &[u8]) -> Result<Value, u8> {
    let params = parse_params(params_bytes)?;

    // 1: rpId (required)
    let rp_id = cu::get_int_key(&params, 1)
        .and_then(cu::as_text)
        .ok_or(CTAP2_ERR_MISSING_PARAMETER)?
        .to_string();

    // 2: clientDataHash (required, 32 bytes)
    let cdh_v = cu::get_int_key(&params, 2).ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    let cdh = cu::as_bytes(cdh_v).ok_or(CTAP1_ERR_INVALID_PARAMETER)?;
    if cdh.len() != 32 {
        return Err(CTAP1_ERR_INVALID_PARAMETER);
    }
    let mut client_data_hash = [0u8; 32];
    client_data_hash.copy_from_slice(cdh);

    // 3: allowList (optional)
    let mut allow_credential_ids: Vec<Vec<u8>> = Vec::new();
    if let Some(allow) = cu::get_int_key(&params, 3) {
        if let Some(list) = cu::as_array(allow) {
            for item in list {
                if let Some(id) = cu::get_text_key(item, "id").and_then(cu::as_bytes) {
                    allow_credential_ids.push(id.to_vec());
                }
            }
        }
    }

    // Same empty-pinUvAuthParam tolerance as in make_credential (key 6 is
    // pinUvAuthParam for getAssertion).
    if let Some(p) = cu::get_int_key(&params, 6) {
        let empty = cu::as_bytes(p).map(|b| b.is_empty()).unwrap_or(false);
        if !empty {
            return Err(CTAP2_ERR_UNSUPPORTED_OPTION);
        }
    }

    let result = phone
        .get_assertion(&GetAssertionRequest {
            rp_id,
            client_data_hash,
            allow_credential_ids,
        })
        .map_err(|e| map_phone_error(&e))?;

    let credential = cu::tmap(vec![
        ("type", cu::vtext("public-key")),
        ("id", cu::vbytes(result.credential_id.clone())),
    ]);

    let mut pairs: Vec<(i64, Value)> = vec![
        (1, credential),
        (2, cu::vbytes(result.auth_data)),
        (3, cu::vbytes(result.signature)),
    ];
    if !result.user_handle.is_empty() {
        let mut user_pairs: Vec<(&str, Value)> = vec![("id", cu::vbytes(result.user_handle))];
        if let Some(name) = &result.user_name {
            user_pairs.push(("name", cu::vtext(name.clone())));
        }
        pairs.push((4, cu::tmap(user_pairs)));
    }
    Ok(cu::imap(pairs))
}
