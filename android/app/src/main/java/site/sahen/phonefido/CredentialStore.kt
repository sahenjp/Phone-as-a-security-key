package site.sahen.phonefido

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Persistence layer (counterpart of the Swift KeychainStore).
 *
 * - Pairing PSK (32 bytes): stored AES-GCM-encrypted (Keystore wrapping
 *   key) in the private file `pairing.enc`.
 * - Credential metadata: JSON array in the private file `credentials.json`,
 *   in creation order. Each entry carries the metadata fields; the
 *   per-credential PRF secret is stored only as `hmac_secret_enc`
 *   (AES-GCM blob, base64) — never in plaintext.
 *
 * App-private storage plus `allowBackup=false` keeps these files on this
 * device only, like the iOS ThisDeviceOnly keychain items.
 */
class CredentialStore(context: Context) {
    private val filesDir: File = context.applicationContext.filesDir
    private val lock = Any()

    private val pskFile: File get() = File(filesDir, "pairing.enc")
    private val credentialsFile: File get() = File(filesDir, "credentials.json")

    // MARK: - Pairing PSK

    fun loadPSK(): ByteArray? {
        val blob = synchronized(lock) {
            try {
                if (pskFile.exists()) pskFile.readBytes() else null
            } catch (e: Exception) {
                null
            }
        } ?: return null
        val psk = KeystoreKeys.decryptBlob(blob) ?: return null
        return if (psk.size == 32) psk else null
    }

    val isPaired: Boolean get() = loadPSK() != null

    /**
     * Generates a fresh PSK and stores it encrypted. Overwriting breaks
     * pairing with any PC that stored the old PSK (same as iOS).
     */
    fun generateAndSavePSK(): ByteArray? {
        val psk = CryptoUtils.randomBytes(32)
        val blob = try {
            KeystoreKeys.encryptBlob(psk)
        } catch (e: Exception) {
            return null
        }
        return if (writeAtomically(pskFile, blob)) psk else null
    }

    fun deletePSK(): Boolean = synchronized(lock) {
        !pskFile.exists() || pskFile.delete()
    }

    // MARK: - Credential metadata

    /** Inserts or replaces (by credential id) one metadata record. False on any failure. */
    fun saveCredential(metadata: CredentialMetadata): Boolean = synchronized(lock) {
        try {
            val all = readAllLocked().toMutableList()
            val index = all.indexOfFirst { it.credentialId.contentEquals(metadata.credentialId) }
            if (index >= 0) all[index] = metadata else all.add(metadata)
            writeAllLocked(all)
        } catch (e: Exception) {
            false
        }
    }

    fun loadCredential(credentialId: ByteArray): CredentialMetadata? = synchronized(lock) {
        readAllLocked().firstOrNull { it.credentialId.contentEquals(credentialId) }
    }

    /** All credentials in creation order (the iOS store sorts by createdAt the same way). */
    fun allCredentials(): List<CredentialMetadata> = synchronized(lock) { readAllLocked() }

    fun deleteCredential(credentialId: ByteArray): Boolean = synchronized(lock) {
        try {
            val all = readAllLocked().filterNot { it.credentialId.contentEquals(credentialId) }
            writeAllLocked(all)
        } catch (e: Exception) {
            false
        }
    }

    // MARK: - JSON file handling (callers hold `lock`)

    private fun readAllLocked(): List<CredentialMetadata> {
        val text = try {
            if (credentialsFile.exists()) credentialsFile.readText(Charsets.UTF_8) else return emptyList()
        } catch (e: Exception) {
            return emptyList()
        }
        val array = try {
            JSONArray(text)
        } catch (e: Exception) {
            return emptyList()
        }
        val result = ArrayList<CredentialMetadata>(array.length())
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i) ?: continue
            decodeCredential(item)?.let { result.add(it) }
        }
        return result
    }

    private fun writeAllLocked(all: List<CredentialMetadata>): Boolean {
        val array = JSONArray()
        for (metadata in all) {
            array.put(encodeCredential(metadata))
        }
        return writeAtomically(credentialsFile, array.toString().toByteArray(Charsets.UTF_8))
    }

    private fun encodeCredential(m: CredentialMetadata): JSONObject {
        val obj = JSONObject()
        obj.put("credential_id", CryptoUtils.base64Encode(m.credentialId))
        obj.put("rp_id", m.rpId)
        obj.put("rp_name", m.rpName ?: JSONObject.NULL)
        obj.put("user_id", CryptoUtils.base64Encode(m.userId))
        obj.put("user_name", m.userName)
        obj.put("user_display_name", m.userDisplayName ?: JSONObject.NULL)
        obj.put("public_key_x963", CryptoUtils.base64Encode(m.publicKeyX963))
        obj.put("sign_count", m.signCount)
        obj.put("key_alias", m.keyAlias)
        obj.put("created_at", m.createdAtSeconds)
        if (m.hmacSecret != null) {
            // The PRF secret is stored only encrypted; if encryption fails
            // the encoding throws and the whole save fails, like the Swift
            // side failing to persist the metadata.
            obj.put("hmac_secret_enc", CryptoUtils.base64Encode(KeystoreKeys.encryptBlob(m.hmacSecret)))
        }
        return obj
    }

    private fun decodeCredential(obj: JSONObject): CredentialMetadata? {
        val credentialId = obj.optString("credential_id", null)?.let { CryptoUtils.base64Decode(it) } ?: return null
        val rpId = obj.optString("rp_id", null) ?: return null
        val userId = obj.optString("user_id", null)?.let { CryptoUtils.base64Decode(it) } ?: return null
        val userName = obj.optString("user_name", null) ?: return null
        val publicKeyX963 = obj.optString("public_key_x963", null)?.let { CryptoUtils.base64Decode(it) } ?: return null
        val keyAlias = obj.optString("key_alias", null) ?: return null
        val hmacSecret = obj.optString("hmac_secret_enc", null)
            ?.let { CryptoUtils.base64Decode(it) }
            ?.let { KeystoreKeys.decryptBlob(it) }
        return CredentialMetadata(
            credentialId = credentialId,
            rpId = rpId,
            rpName = if (obj.isNull("rp_name")) null else obj.optString("rp_name", null),
            userId = userId,
            userName = userName,
            userDisplayName = if (obj.isNull("user_display_name")) null else obj.optString("user_display_name", null),
            publicKeyX963 = publicKeyX963,
            signCount = obj.optLong("sign_count", 0),
            keyAlias = keyAlias,
            createdAtSeconds = obj.optLong("created_at", 0),
            hmacSecret = hmacSecret
        )
    }

    /** Write via a temp file + rename so a crash cannot leave a torn file. */
    private fun writeAtomically(target: File, bytes: ByteArray): Boolean = synchronized(lock) {
        try {
            val tmp = File(target.parentFile, target.name + ".tmp")
            tmp.writeBytes(bytes)
            if (!tmp.renameTo(target)) {
                target.writeBytes(bytes)
                tmp.delete()
            }
            true
        } catch (e: Exception) {
            false
        }
    }
}
