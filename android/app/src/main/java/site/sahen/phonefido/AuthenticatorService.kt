package site.sahen.phonefido

import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream

/**
 * The semantic operations of BRIDGE-PROTOCOL 3 — a field-for-field port of
 * the Swift AuthenticatorService.
 *
 * Principle: the PC can never ask the phone to sign arbitrary bytes. The
 * phone builds authData itself from the rp_id, displays rp_id + user name,
 * and signs only after an on-screen approval tap AND a successful biometric
 * prompt. Blocking calls (approval wait, biometric wait) run on the bridge
 * session thread.
 */
class AuthenticatorService(
    private val store: CredentialStore,
    private val approval: ApprovalCoordinator,
    private val signer: BiometricSignCoordinator,
    private val onCredentialsChanged: () -> Unit = {}
) {
    // PRF (hmac-secret) two-phase state. Tickets are random 16 bytes,
    // valid 60 s, single use; the maps are keyed by the ticket's hex form.
    // All access happens on the single session thread, like the Swift side.

    private class PendingPrfAssertion(
        val metadata: CredentialMetadata,
        val clientDataHash: ByteArray,
        val createdAtMillis: Long
    )

    private class PendingCreate(
        val metadata: CredentialMetadata,
        val clientDataHash: ByteArray,
        val createdAtMillis: Long
    )

    private val pendingCreates = HashMap<String, PendingCreate>()
    private val pendingPrf = HashMap<String, PendingPrfAssertion>()

    // MARK: - Dispatch

    /** Takes one decrypted JSON request object and returns the JSON response object. */
    fun handle(request: JSONObject): JSONObject {
        val id = (request.opt("id") as? Number)?.toInt()
            ?: return failure(0, BridgeError.BAD_REQUEST)
        val op = request.opt("op") as? String
            ?: return failure(id, BridgeError.BAD_REQUEST)
        return when (op) {
            "ping" -> success(
                id,
                JSONObject()
                    .put("app", "iphone-fido")
                    .put("version", BridgeConstants.PROTOCOL_VERSION)
            )
            "create_credential" -> createCredential(id, request)
            "create_credential_finish" -> finishCreateCredential(id, request)
            "get_assertion" -> getAssertion(id, request)
            "get_assertion_finish" -> getAssertionFinish(id, request)
            "list_credentials" -> listCredentials(id)
            else -> failure(id, BridgeError.BAD_REQUEST)
        }
    }

    private fun success(id: Int, result: JSONObject): JSONObject =
        JSONObject().put("id", id).put("ok", true).put("result", result)

    private fun failure(id: Int, code: String): JSONObject =
        JSONObject().put("id", id).put("ok", false).put("error", code)

    // MARK: - Request field helpers (mirror the Swift `as? String` guards)

    /** String fields only; JSON null / wrong types count as absent. */
    private fun reqString(request: JSONObject, name: String): String? =
        request.opt(name) as? String

    private fun reqBytes(request: JSONObject, name: String): ByteArray? =
        reqString(request, name)?.let { CryptoUtils.base64Decode(it) }

    private fun reqBool(request: JSONObject, name: String): Boolean =
        request.opt(name) == true

    // MARK: - 3.2 create_credential

    private fun createCredential(id: Int, request: JSONObject): JSONObject {
        val rpId = reqString(request, "rp_id")?.takeIf { it.isNotEmpty() }
            ?: return failure(id, BridgeError.BAD_REQUEST)
        val userId = reqBytes(request, "user_id")
            ?: return failure(id, BridgeError.BAD_REQUEST)
        val userName = reqString(request, "user_name")
            ?: return failure(id, BridgeError.BAD_REQUEST)
        val clientDataHash = reqBytes(request, "client_data_hash")?.takeIf { it.size == 32 }
            ?: return failure(id, BridgeError.BAD_REQUEST)
        // clientDataHash is signed at creation time as part of the
        // packed self-attestation (authData || clientDataHash), and is
        // kept in the pending-create record for two-phase creations.
        val rpName = reqString(request, "rp_name")
        val userDisplayName = reqString(request, "user_display_name")

        // hmac-secret-mc: creation that also evaluates PRF. The daemon
        // passes the salts already decrypted from the pinUvAuthProtocol
        // exchange. Salts are optional (an enable-only "prf" creation runs
        // the same two-phase flow with nothing to evaluate yet).
        val isMc = reqString(request, "hmac_phase") == "mc"
        var mcSalt1: ByteArray? = null
        var mcSalt2: ByteArray? = null
        if (isMc) {
            if (reqString(request, "salt1") != null) {
                mcSalt1 = reqBytes(request, "salt1")?.takeIf { it.size == 32 }
                    ?: return failure(id, BridgeError.BAD_REQUEST)
            }
            if (reqString(request, "salt2") != null) {
                mcSalt2 = reqBytes(request, "salt2")?.takeIf { it.size == 32 }
                    ?: return failure(id, BridgeError.BAD_REQUEST)
            }
        }
        val wantsHmacSecret = reqBool(request, "hmac_secret") || isMc

        // 1. Show rp_id + user_name and wait for the user's Create tap.
        val approved = approval.requestApproval(
            PendingApproval(id, "create_credential", rpId, userName, System.currentTimeMillis())
        )
        if (!approved) return failure(id, BridgeError.USER_CANCELLED)

        // 2. Generate a fresh P-256 key in the Android Keystore.
        val credentialId = CryptoUtils.randomBytes(32)
        val generated = try {
            KeystoreKeys.generateCredentialKey(credentialId)
        } catch (e: Exception) {
            return failure(id, BridgeError.INTERNAL)
        }

        // 3. Save the metadata (roll the key back if saving fails).
        val hmacSecret = if (wantsHmacSecret) CryptoUtils.randomBytes(32) else null
        val metadata = CredentialMetadata(
            credentialId = credentialId,
            rpId = rpId,
            rpName = rpName,
            userId = userId,
            userName = userName,
            userDisplayName = userDisplayName,
            publicKeyX963 = generated.publicKeyX963,
            signCount = 0,
            keyAlias = generated.alias,
            createdAtSeconds = System.currentTimeMillis() / 1000,
            hmacSecret = hmacSecret
        )
        if (!store.saveCredential(metadata)) {
            KeystoreKeys.deleteKey(generated.alias)
            return failure(id, BridgeError.INTERNAL)
        }
        onCredentialsChanged()

        // Two-phase creation, phase 1 (hmac-secret-mc / CTAP "prf"):
        // register the pending creation and hand back a ticket; authData
        // is built in phase 2 from the extension segment the daemon
        // supplies. PRF outputs are included only when salts were given.
        if (isMc && hmacSecret != null) {
            val ticket = CryptoUtils.randomBytes(16)
            pendingCreates[CryptoUtils.toHex(ticket)] =
                PendingCreate(metadata, clientDataHash, System.currentTimeMillis())
            val result = JSONObject()
                .put("supported", true)
                .put("ticket", CryptoUtils.base64Encode(ticket))
                .put("credential_id", CryptoUtils.base64Encode(credentialId))
                .put("public_key_x963", CryptoUtils.base64Encode(generated.publicKeyX963))
            if (mcSalt1 != null) {
                var outputs = CryptoUtils.hmacSHA256(hmacSecret, mcSalt1)
                if (mcSalt2 != null) {
                    outputs += CryptoUtils.hmacSHA256(hmacSecret, mcSalt2)
                }
                result.put("hmac_outputs", CryptoUtils.base64Encode(outputs))
            }
            return success(id, result)
        }

        // 4. The phone builds the attested authData itself.
        val extensionOutputs = if (hmacSecret != null) {
            CborValue.Map(
                listOf(CborValue.Text("hmac-secret") to CborValue.Bool(true))
            ).encoded()
        } else {
            null
        }
        val authData = attestedAuthData(rpId, credentialId, generated.publicKeyX963, extensionOutputs)
            ?: return failure(id, BridgeError.INTERNAL)

        // 5. Packed self-attestation: sign authData || clientDataHash
        // with the new credential's key and return it as att_sig (the
        // daemon answers fmt "packed" with attStmt {alg: -7, sig}).
        // pam-u2f (libfido2 fido_cred_verify_self) rejects fmt "none",
        // so this signature is required there. If signing fails, the
        // whole creation fails and the key + metadata are rolled back.
        val attSig = try {
            attestationSignature(metadata, clientDataHash, authData)
        } catch (e: AuthError) {
            store.deleteCredential(credentialId)
            KeystoreKeys.deleteKey(generated.alias)
            onCredentialsChanged()
            return failure(id, e.code)
        }
        return success(
            id,
            JSONObject()
                .put("credential_id", CryptoUtils.base64Encode(credentialId))
                .put("public_key_x963", CryptoUtils.base64Encode(generated.publicKeyX963))
                .put("auth_data", CryptoUtils.base64Encode(authData))
                .put("fmt", "none")
                .put("att_sig", CryptoUtils.base64Encode(attSig))
        )
    }

    /**
     * The attestation signature: authData || client_data_hash signed
     * with the credential key (DER). This call is what raises the
     * biometric prompt at creation time.
     */
    private fun attestationSignature(
        metadata: CredentialMetadata,
        clientDataHash: ByteArray,
        authData: ByteArray
    ): ByteArray = signer.sign(metadata.keyAlias, authData + clientDataHash, metadata.rpId)

    /**
     * Attested authData:
     * sha256(rpId) || flags(0x45, +0x20 ED iff extension outputs) ||
     * signCount(4BE, 0) || AAGUID || credIdLen(2BE) || credId || COSE_Key
     * || extensions?. An empty extension segment means "no extension
     * outputs": no ED flag, nothing appended.
     */
    private fun attestedAuthData(
        rpId: String,
        credentialId: ByteArray,
        publicKeyX963: ByteArray,
        extensions: ByteArray?
    ): ByteArray? {
        val ext = if (extensions == null || extensions.isEmpty()) null else extensions
        val coseKey = CoseKeyBuilder.ec2ES256(publicKeyX963) ?: return null
        val out = ByteArrayOutputStream()
        out.write(CryptoUtils.sha256(rpId.toByteArray(Charsets.UTF_8)))
        var flags = 0x45 // UP | UV | AT
        if (ext != null) flags = flags or 0x20 // ED
        out.write(flags)
        out.write(CryptoUtils.uint32BigEndian(0))
        out.write(BridgeConstants.AAGUID)
        out.write(CryptoUtils.uint16BigEndian(credentialId.size))
        out.write(credentialId)
        out.write(coseKey)
        if (ext != null) out.write(ext)
        return out.toByteArray()
    }

    // MARK: - hmac-secret-mc phase 2 (create_credential_finish)

    private fun finishCreateCredential(id: Int, request: JSONObject): JSONObject {
        // Every failure here is not_found, mirroring the Swift single guard
        // (unknown, malformed or expired ticket are indistinguishable).
        val ticket = reqBytes(request, "ticket")
            ?: return failure(id, BridgeError.NOT_FOUND)
        val extensions = reqBytes(request, "auth_data_extensions")
            ?: return failure(id, BridgeError.NOT_FOUND)
        val pending = pendingCreates.remove(CryptoUtils.toHex(ticket))
            ?: return failure(id, BridgeError.NOT_FOUND)
        if (System.currentTimeMillis() - pending.createdAtMillis >= 60_000) {
            return failure(id, BridgeError.NOT_FOUND)
        }
        val metadata = pending.metadata
        val authData = attestedAuthData(
            metadata.rpId, metadata.credentialId, metadata.publicKeyX963, extensions
        ) ?: return failure(id, BridgeError.INTERNAL)
        // The self-attestation signs the FINAL authData (extension
        // segment embedded). Failure rolls the phase-1 credential back.
        val attSig = try {
            attestationSignature(metadata, pending.clientDataHash, authData)
        } catch (e: AuthError) {
            store.deleteCredential(metadata.credentialId)
            KeystoreKeys.deleteKey(metadata.keyAlias)
            onCredentialsChanged()
            return failure(id, e.code)
        }
        return success(
            id,
            JSONObject()
                .put("credential_id", CryptoUtils.base64Encode(metadata.credentialId))
                .put("public_key_x963", CryptoUtils.base64Encode(metadata.publicKeyX963))
                .put("auth_data", CryptoUtils.base64Encode(authData))
                .put("fmt", "none")
                .put("att_sig", CryptoUtils.base64Encode(attSig))
        )
    }

    // MARK: - 3.3 get_assertion

    private fun getAssertion(id: Int, request: JSONObject): JSONObject {
        val rpId = reqString(request, "rp_id")?.takeIf { it.isNotEmpty() }
            ?: return failure(id, BridgeError.BAD_REQUEST)
        val clientDataHash = reqBytes(request, "client_data_hash")?.takeIf { it.size == 32 }
            ?: return failure(id, BridgeError.BAD_REQUEST)
        val allowIds = parseAllowList(request)

        // PRF (hmac-secret) phase 1 has its own path.
        if (reqString(request, "hmac_phase") == "eval") {
            return evalHmacSecret(id, request, rpId, clientDataHash, allowIds)
        }

        // 1. Find a credential for this rp_id inside the allow list
        //    (empty list = all credentials of the rp).
        val metadata = findCandidate(rpId, allowIds)
            ?: return failure(id, BridgeError.NO_CREDENTIALS)

        // 2. Show rp_id + user_name and wait for the Approve tap (mandatory).
        val approved = approval.requestApproval(
            PendingApproval(id, "get_assertion", rpId, metadata.userName, System.currentTimeMillis())
        )
        if (!approved) return failure(id, BridgeError.USER_CANCELLED)

        // 3. Increment and persist the signature counter.
        metadata.signCount = (metadata.signCount + 1) and 0xFFFF_FFFFL
        if (!store.saveCredential(metadata)) {
            return failure(id, BridgeError.INTERNAL)
        }

        // 4. Build authData and sign it.
        val out = ByteArrayOutputStream()
        out.write(CryptoUtils.sha256(rpId.toByteArray(Charsets.UTF_8)))
        out.write(0x05) // flags: UP | UV
        out.write(CryptoUtils.uint32BigEndian(metadata.signCount))
        return signAndRespond(id, metadata, out.toByteArray(), clientDataHash)
    }

    private fun parseAllowList(request: JSONObject): List<ByteArray> {
        val array = request.opt("allow_credential_ids") as? JSONArray ?: return emptyList()
        // Mirror the Swift `[String]` cast: one non-string element voids
        // the whole list (the daemon always sends strings).
        val strings = ArrayList<String>(array.length())
        for (i in 0 until array.length()) {
            val element = array.opt(i) as? String ?: return emptyList()
            strings.add(element)
        }
        return strings.mapNotNull { CryptoUtils.base64Decode(it) }
    }

    private fun findCandidate(rpId: String, allowIds: List<ByteArray>): CredentialMetadata? =
        store.allCredentials().firstOrNull { metadata ->
            metadata.rpId == rpId &&
                (allowIds.isEmpty() || allowIds.any { it.contentEquals(metadata.credentialId) })
        }

    /**
     * Signs authData || client_data_hash with the credential key and builds
     * the assertion response. This call is what raises the biometric
     * prompt. Signature format is ASN.1 DER (WebAuthn ES256), which is what
     * "SHA256withECDSA" produces.
     */
    private fun signAndRespond(
        id: Int,
        metadata: CredentialMetadata,
        authData: ByteArray,
        clientDataHash: ByteArray
    ): JSONObject {
        val message = authData + clientDataHash
        val signature = try {
            signer.sign(metadata.keyAlias, message, metadata.rpId)
        } catch (e: AuthError) {
            return failure(id, e.code)
        }
        return success(
            id,
            JSONObject()
                .put("credential_id", CryptoUtils.base64Encode(metadata.credentialId))
                .put("auth_data", CryptoUtils.base64Encode(authData))
                .put("signature", CryptoUtils.base64Encode(signature))
                .put("user_handle", CryptoUtils.base64Encode(metadata.userId))
        )
    }

    // MARK: - PRF (hmac-secret) two-phase flow (BRIDGE-PROTOCOL 3.6)
    //
    // The CTAP layer (PC) decrypts the salts from the pinUvAuthProtocol
    // exchange before calling us. Phase 1 (eval) returns the raw
    // HMAC-SHA256(secret, salt) outputs — only after the same approval +
    // biometric flow as a normal assertion — plus a 60 s single-use
    // ticket. Phase 2 (get_assertion_finish) builds the authData with the
    // PC-encrypted extension outputs and signs in the eval context.
    // The secret itself never leaves the phone in either phase.

    private fun evalHmacSecret(
        id: Int,
        request: JSONObject,
        rpId: String,
        clientDataHash: ByteArray,
        allowIds: List<ByteArray>
    ): JSONObject {
        val salt1 = reqBytes(request, "salt1")?.takeIf { it.size == 32 }
            ?: return failure(id, BridgeError.BAD_REQUEST)
        var salt2: ByteArray? = null
        if (reqString(request, "salt2") != null) {
            salt2 = reqBytes(request, "salt2")?.takeIf { it.size == 32 }
                ?: return failure(id, BridgeError.BAD_REQUEST)
        }

        val metadata = findCandidate(rpId, allowIds)
            ?: return failure(id, BridgeError.NO_CREDENTIALS)
        // A credential without a PRF key answers "unsupported" WITHOUT an
        // approval prompt, so the PC can fall back to a plain assertion.
        val hmacSecret = metadata.hmacSecret ?: return success(
            id,
            JSONObject()
                .put("supported", false)
                .put("credential_id", CryptoUtils.base64Encode(metadata.credentialId))
        )

        val approved = approval.requestApproval(
            PendingApproval(id, "get_assertion", rpId, metadata.userName, System.currentTimeMillis())
        )
        if (!approved) return failure(id, BridgeError.USER_CANCELLED)

        var outputs = CryptoUtils.hmacSHA256(hmacSecret, salt1)
        if (salt2 != null) {
            outputs += CryptoUtils.hmacSHA256(hmacSecret, salt2)
        }
        val ticket = CryptoUtils.randomBytes(16)
        pendingPrf[CryptoUtils.toHex(ticket)] =
            PendingPrfAssertion(metadata, clientDataHash, System.currentTimeMillis())
        return success(
            id,
            JSONObject()
                .put("supported", true)
                .put("ticket", CryptoUtils.base64Encode(ticket))
                .put("credential_id", CryptoUtils.base64Encode(metadata.credentialId))
                .put("hmac_outputs", CryptoUtils.base64Encode(outputs))
        )
    }

    private fun getAssertionFinish(id: Int, request: JSONObject): JSONObject {
        val ticket = reqBytes(request, "ticket")
            ?: return failure(id, BridgeError.BAD_REQUEST)
        val extensions = reqBytes(request, "auth_data_extensions")
            ?: return failure(id, BridgeError.BAD_REQUEST)
        val pending = pendingPrf.remove(CryptoUtils.toHex(ticket))
            ?: return failure(id, BridgeError.NOT_FOUND)
        if (System.currentTimeMillis() - pending.createdAtMillis > 60_000) {
            return failure(id, BridgeError.NOT_FOUND)
        }

        val metadata = pending.metadata
        metadata.signCount = (metadata.signCount + 1) and 0xFFFF_FFFFL
        if (!store.saveCredential(metadata)) {
            return failure(id, BridgeError.INTERNAL)
        }

        val out = ByteArrayOutputStream()
        out.write(CryptoUtils.sha256(metadata.rpId.toByteArray(Charsets.UTF_8)))
        // ED only when there are actual extension outputs to embed; the
        // CTAP "prf" extension finishes with an empty segment and returns
        // its results in the response map instead.
        val hasExtensions = extensions.isNotEmpty()
        out.write(if (hasExtensions) 0x25 else 0x05) // flags: UP | UV [| ED]
        out.write(CryptoUtils.uint32BigEndian(metadata.signCount))
        if (hasExtensions) {
            out.write(extensions)
        }
        return signAndRespond(id, metadata, out.toByteArray(), pending.clientDataHash)
    }

    // MARK: - 3.4 list_credentials (management only; no signing, no secrets)
    //
    // Shape note: like the Swift app, the result is {"credentials": [...]}.
    // (BRIDGE-PROTOCOL 3.4 does not pin the envelope; the Rust daemon's
    // TcpPhone currently parses a bare array instead — a pre-existing
    // mismatch that affects the iOS app identically.)

    private fun listCredentials(id: Int): JSONObject {
        val items = JSONArray()
        for (metadata in store.allCredentials()) {
            items.put(
                JSONObject()
                    .put("rp_id", metadata.rpId)
                    .put("user_name", metadata.userName)
                    .put("credential_id", CryptoUtils.base64Encode(metadata.credentialId))
            )
        }
        return success(id, JSONObject().put("credentials", items))
    }
}
