package site.sahen.phonefido

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** A freshly generated credential key: its Keystore alias and x963 public key. */
class GeneratedKey(val alias: String, val publicKeyX963: ByteArray)

/**
 * Android Keystore access.
 *
 * - One EC P-256 key pair per credential, alias "phonefido.cred.<hex id>".
 *   Keys are generated with user authentication required for EVERY use
 *   (validity duration -1), so a signature is only possible through a
 *   BiometricPrompt CryptoObject right after the user approves on screen —
 *   the Android counterpart of the iOS Secure Enclave
 *   `.privateKeyUsage + .biometryCurrentSet` policy
 *   (setInvalidatedByBiometricEnrollment mirrors biometryCurrentSet).
 *   Generation itself does not prompt; only signing does.
 * - One AES-256-GCM wrapping key ("phonefido.wrap") that encrypts the
 *   pairing PSK file and each credential's PRF (hmac-secret) key at rest.
 */
object KeystoreKeys {
    private const val WRAP_ALIAS = "phonefido.wrap"
    private const val GCM_IV_BYTES = 12
    private const val GCM_TAG_BITS = 128

    fun credentialAlias(credentialId: ByteArray): String =
        "phonefido.cred." + CryptoUtils.toHex(credentialId)

    private fun androidKeyStore(): KeyStore =
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    // MARK: - Per-credential signing keys

    fun generateCredentialKey(credentialId: ByteArray): GeneratedKey {
        val alias = credentialAlias(credentialId)
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            // -1: authentication is required for every single use of the
            // key, and only via a BiometricPrompt CryptoObject.
            .setUserAuthenticationValidityDurationSeconds(-1)
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(spec)
        val keyPair = generator.generateKeyPair()
        return GeneratedKey(alias, Ec.x963(keyPair.public as ECPublicKey))
    }

    fun privateKey(alias: String): PrivateKey? =
        androidKeyStore().getKey(alias, null) as? PrivateKey

    fun deleteKey(alias: String) {
        try {
            androidKeyStore().deleteEntry(alias)
        } catch (e: Exception) {
            // Deleting a missing key is not an error (mirrors the Swift side).
        }
    }

    // MARK: - AES-GCM wrapping key (PSK file / PRF secrets at rest)

    @Synchronized
    private fun wrapKey(): SecretKey {
        val keyStore = androidKeyStore()
        (keyStore.getKey(WRAP_ALIAS, null) as? SecretKey)?.let { return it }
        val spec = KeyGenParameterSpec.Builder(
            WRAP_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(spec)
        return generator.generateKey()
    }

    /** Encrypts to iv(12) || ciphertext || tag under the wrapping key. */
    fun encryptBlob(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, wrapKey())
        return cipher.iv + cipher.doFinal(plaintext)
    }

    /** Inverse of [encryptBlob]; null when the blob is malformed or the key is gone. */
    fun decryptBlob(blob: ByteArray): ByteArray? {
        if (blob.size <= GCM_IV_BYTES + GCM_TAG_BITS / 8) return null
        val iv = blob.copyOfRange(0, GCM_IV_BYTES)
        val ciphertext = blob.copyOfRange(GCM_IV_BYTES, blob.size)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, wrapKey(), GCMParameterSpec(GCM_TAG_BITS, iv))
            cipher.doFinal(ciphertext)
        } catch (e: Exception) {
            null
        }
    }
}
