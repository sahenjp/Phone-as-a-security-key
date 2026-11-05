//! CTAP2 processing (CBOR). The PC terminates CTAP2; the phone only
//! performs the semantic operations in BRIDGE-PROTOCOL.md section 3.

use ciborium::value::Value;

use crate::cbor_util as cu;
use crate::phone::{
    CreateCredentialRequest, EvalHmacSecretRequest, FinishAssertionRequest, GetAssertionRequest,
    GetAssertionResponse, Phone, PhoneError,
};
use crate::AAGUID;

// CTAP2 commands
pub const CMD_MAKE_CREDENTIAL: u8 = 0x01;
pub const CMD_GET_ASSERTION: u8 = 0x02;
pub const CMD_GET_INFO: u8 = 0x04;
pub const CMD_CLIENT_PIN: u8 = 0x06;

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
pub const CTAP2_ERR_PIN_AUTH_INVALID: u8 = 0x33;
pub const CTAP1_ERR_OTHER: u8 = 0x7F;

pub const MAX_MSG_SIZE: u64 = 1200;

/// Authenticator-level CTAP state that persists across messages: the
/// pinUvAuthProtocol ONE ephemeral keypair. ClientPIN getKeyAgreement
/// hands its public half to the platform, and the hmac-secret extension
/// (WebAuthn PRF) derives the salt/output encryption key from it. The
/// keypair is per daemon run, like a real authenticator's per-boot
/// key agreement state; no PIN is ever set or verified with it (user
/// verification happens inside the phone via Face ID).
pub struct CtapState {
    pin_ephemeral: p256::SecretKey,
}

impl CtapState {
    pub fn new() -> Self {
        Self {
            pin_ephemeral: p256::SecretKey::random(&mut rand_core::OsRng),
        }
    }

    /// This authenticator's key-agreement public key as a COSE_Key
    /// (ECDH, alg -25), as returned by ClientPIN getKeyAgreement.
    fn key_agreement_cose(&self) -> Value {
        let pub_bytes = self.pin_ephemeral.public_key().to_sec1_bytes();
        cu::imap(vec![
            (1, cu::vint(2)),   // kty: EC2
            (3, cu::vint(-25)), // alg: ECDH-ES + HKDF-256
            (-1, cu::vint(1)),  // crv: P-256
            (-2, cu::vbytes(pub_bytes[1..33].to_vec())),
            (-3, cu::vbytes(pub_bytes[33..65].to_vec())),
        ])
    }

    /// pinUvAuthProtocol ONE shared secret for a platform key-agreement
    /// COSE_Key: K = SHA-256(ECDH(ephemeral, platform) x-coordinate).
    /// K keys both the AES-256-CBC encryption and the HMAC
    /// authentication of the hmac-secret salt exchange.
    fn shared_key_protocol1(&self, platform_cose: &Value) -> Option<[u8; 32]> {
        let x = cu::get_int_key(platform_cose, -2).and_then(cu::as_bytes)?;
        let y = cu::get_int_key(platform_cose, -3).and_then(cu::as_bytes)?;
        if x.len() != 32 || y.len() != 32 {
            return None;
        }
        let mut x963 = [0u8; 65];
        x963[0] = 0x04;
        x963[1..33].copy_from_slice(x);
        x963[33..65].copy_from_slice(y);
        let peer = crate::phone::verifying_key_from_x963(&x963)?;
        let shared = p256::ecdh::diffie_hellman(
            self.pin_ephemeral.to_nonzero_scalar(),
            peer.as_affine(),
        );
        Some(crate::sha256(shared.raw_secret_bytes()))
    }
}

impl Default for CtapState {
    fn default() -> Self {
        Self::new()
    }
}

/// AES-256-CBC with an all-zero IV and no padding (pinUvAuthProtocol
/// ONE encrypt/decrypt). Input must be block-aligned.
pub(crate) fn aes256_cbc_encrypt(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{block_padding::NoPadding, BlockEncryptMut, KeyIvInit};
    if data.is_empty() || data.len() % 16 != 0 {
        return None;
    }
    Some(
        cbc::Encryptor::<aes::Aes256>::new(key.into(), &[0u8; 16].into())
            .encrypt_padded_vec_mut::<NoPadding>(data),
    )
}

pub(crate) fn aes256_cbc_decrypt(key: &[u8; 32], data: &[u8]) -> Option<Vec<u8>> {
    use aes::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
    if data.is_empty() || data.len() % 16 != 0 {
        return None;
    }
    cbc::Decryptor::<aes::Aes256>::new(key.into(), &[0u8; 16].into())
        .decrypt_padded_vec_mut::<NoPadding>(data)
        .ok()
}

/// Process one CTAP2 message (command byte + CBOR params) and return the
/// response bytes (status byte + optional CBOR payload).
pub fn process<P: Phone>(state: &mut CtapState, phone: &mut P, payload: &[u8]) -> Vec<u8> {
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
        CMD_GET_ASSERTION => respond(get_assertion(state, phone, params_bytes)),
        CMD_CLIENT_PIN => respond(client_pin(state, params_bytes)),
        // authenticatorReset (0x07), authenticatorBioEnrollment (0x09),
        // authenticatorCredentialManagement (0x0A), authenticatorSelection
        // (0x0B), getNextAssertion (0x08), and anything else: not
        // supported by this authenticator.
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

/// authenticatorClientPIN (0x06). Only the getKeyAgreement subcommand
/// of pinUvAuthProtocol ONE is implemented: the hmac-secret extension
/// needs a key agreement, but this authenticator has no PIN (user
/// verification is the phone's Face ID), so every PIN-management
/// subcommand is refused.
fn client_pin(state: &mut CtapState, params_bytes: &[u8]) -> Result<Value, u8> {
    let params = parse_params(params_bytes)?;
    let sub_command = cu::get_int_key(&params, 2)
        .and_then(cu::as_int)
        .ok_or(CTAP2_ERR_MISSING_PARAMETER)?;
    match sub_command {
        2 => {
            // getKeyAgreement
            let protocol = cu::get_int_key(&params, 1).and_then(cu::as_int);
            if protocol != Some(1) {
                return Err(CTAP2_ERR_UNSUPPORTED_OPTION);
            }
            Ok(cu::imap(vec![(1, state.key_agreement_cose())]))
        }
        _ => Err(CTAP2_ERR_UNSUPPORTED_OPTION),
    }
}

/// authenticatorGetInfo (0x04) response value.
pub fn get_info() -> Value {
    cu::imap(vec![
        (
            0x01,
            Value::Array(vec![cu::vtext("FIDO_2_0"), cu::vtext("FIDO_2_1")]),
        ),
        (
            0x02,
            Value::Array(vec![cu::vtext("hmac-secret")]),
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
            // pinUvAuthProtocols: protocol ONE only, for the
            // hmac-secret key agreement (see CtapState). With this key
            // present, Chromium's GetInfo parser is satisfied even
            // alongside its clientPin-availability rules.
            0x06,
            Value::Array(vec![cu::vint(1)]),
        ),
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

    // 6: extensions (optional). hmac-secret:true asks for a
    // per-credential PRF key (WebAuthn PRF); other extension inputs are
    // ignored, as an authenticator may do.
    let hmac_secret = cu::get_int_key(&params, 6)
        .and_then(|ext| cu::get_text_key(ext, "hmac-secret"))
        .and_then(cu::as_bool)
        .unwrap_or(false);

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
            hmac_secret,
        })
        .map_err(|e| map_phone_error(&e))?;

    Ok(cu::imap(vec![
        (1, cu::vtext(result.fmt)),
        (2, cu::vbytes(result.auth_data)),
        (3, cu::imap(vec![])), // attStmt: empty for fmt "none"
    ]))
}

/// Build the getAssertion response map from a phone assertion result.
fn assertion_response(result: GetAssertionResponse) -> Value {
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
    cu::imap(pairs)
}

fn get_assertion<P: Phone>(
    state: &mut CtapState,
    phone: &mut P,
    params_bytes: &[u8],
) -> Result<Value, u8> {
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

    // 4: extensions (optional) — the hmac-secret extension (WebAuthn
    // PRF) runs a two-phase flow with the phone; when the chosen
    // credential has no PRF key it degrades to a plain assertion.
    if let Some(hs) = cu::get_int_key(&params, 4)
        .and_then(|ext| cu::get_text_key(ext, "hmac-secret"))
    {
        if let Some(value) = hmac_secret_assertion(
            state,
            phone,
            hs,
            &rp_id,
            client_data_hash,
            allow_credential_ids.clone(),
        )? {
            return Ok(value);
        }
    }

    let result = phone
        .get_assertion(&GetAssertionRequest {
            rp_id,
            client_data_hash,
            allow_credential_ids,
        })
        .map_err(|e| map_phone_error(&e))?;

    Ok(assertion_response(result))
}

/// The hmac-secret (WebAuthn PRF) assertion flow.
/// Returns Ok(None) when the credential has no PRF key (degrade to a
/// plain assertion), Ok(Some(response)) on success.
///
/// Protocol (CTAP2 hmac-secret + pinUvAuthProtocol ONE): the platform
/// fetched our key agreement via ClientPIN, derived K = SHA-256(ECDH),
/// and sent the salts AES-256-CBC-encrypted under K with saltAuth =
/// HMAC(K, saltEnc)[..16]. We verify and decrypt, the phone evaluates
/// HMAC(credential key, salt) after user approval, we encrypt the
/// outputs under K, and the phone embeds them in the signed authData.
fn hmac_secret_assertion<P: Phone>(
    state: &mut CtapState,
    phone: &mut P,
    hs: &Value,
    rp_id: &str,
    client_data_hash: [u8; 32],
    allow_credential_ids: Vec<Vec<u8>>,
) -> Result<Option<Value>, u8> {
    let key_agreement = cu::get_int_key(hs, 1).ok_or(CTAP1_ERR_INVALID_PARAMETER)?;
    let salt_enc = cu::get_int_key(hs, 2)
        .and_then(cu::as_bytes)
        .ok_or(CTAP1_ERR_INVALID_PARAMETER)?;
    let salt_auth = cu::get_int_key(hs, 3)
        .and_then(cu::as_bytes)
        .ok_or(CTAP1_ERR_INVALID_PARAMETER)?;

    let key = state
        .shared_key_protocol1(key_agreement)
        .ok_or(CTAP1_ERR_INVALID_PARAMETER)?;
    let expected_auth = crate::hmac_sha256(&key, salt_enc);
    if salt_auth.len() != 16 || expected_auth[..16] != salt_auth[..] {
        return Err(CTAP2_ERR_PIN_AUTH_INVALID);
    }
    let salts = aes256_cbc_decrypt(&key, salt_enc).ok_or(CTAP1_ERR_INVALID_PARAMETER)?;
    let (salt1, salt2) = match salts.len() {
        32 => {
            let mut s = [0u8; 32];
            s.copy_from_slice(&salts);
            (s, None)
        }
        64 => {
            let mut s1 = [0u8; 32];
            let mut s2 = [0u8; 32];
            s1.copy_from_slice(&salts[..32]);
            s2.copy_from_slice(&salts[32..]);
            (s1, Some(s2))
        }
        _ => return Err(CTAP1_ERR_INVALID_PARAMETER),
    };

    let eval = phone
        .eval_hmac_secret(&EvalHmacSecretRequest {
            rp_id: rp_id.to_string(),
            client_data_hash,
            allow_credential_ids,
            salt1,
            salt2,
        })
        .map_err(|e| map_phone_error(&e))?;
    if !eval.supported {
        return Ok(None);
    }
    if eval.raw_outputs.len() != salts.len() {
        return Err(CTAP1_ERR_OTHER);
    }
    let encrypted = aes256_cbc_encrypt(&key, &eval.raw_outputs).ok_or(CTAP1_ERR_OTHER)?;
    let extension_map = cu::encode(&cu::tmap(vec![(
        "hmac-secret",
        cu::vbytes(encrypted),
    )]));

    let result = phone
        .finish_assertion(&FinishAssertionRequest {
            ticket: eval.ticket,
            auth_data_extensions: extension_map,
        })
        .map_err(|e| map_phone_error(&e))?;

    Ok(Some(assertion_response(result)))
}
