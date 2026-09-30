package dev.phonegate.keys

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import dev.phonegate.data.KeyLevel
import dev.phonegate.protocol.Crypto
import dev.phonegate.protocol.Signer
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * All phone key material lives in Android Keystore, non-exportable (Constitution III):
 *
 * - `pc_<id>_device`: P-256 SIGN, no user auth. Signs envelopes, deny / not-me and relay auth.
 * - `pc_<id>_approve`: P-256 SIGN, strong biometric or device credential for EVERY use,
 *   invalidated by new biometric enrollment, usable only while the device is unlocked.
 * - `pc_<id>_offline_wrap`: AES-256-GCM, biometric per use; encrypts `k_offline`.
 * - `store_wrap`: AES-256-GCM, no auth; encrypts the app state file at rest.
 *
 * Both signing keys carry an attestation chain whose challenge is the pairing's `attest_chal`.
 */
object KeyManager {
    private const val PROVIDER = "AndroidKeyStore"
    const val STORE_ALIAS = "store_wrap"
    private const val AUTH = KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL

    private val keyStore: KeyStore by lazy { KeyStore.getInstance(PROVIDER).apply { load(null) } }

    class PairKeys(
        val deviceAlias: String,
        val approveAlias: String,
        val offlineAlias: String,
        val devicePub: ByteArray,
        val approvePub: ByteArray,
        val deviceChain: List<ByteArray>,
        val approveChain: List<ByteArray>,
        val level: KeyLevel,
    )

    /** Signals that a key can no longer be used and the PC must be paired again. */
    class KeyInvalidated(val reason: String, cause: Throwable? = null) : Exception(reason, cause)

    fun aliasBase(pcIdHex: String, alreadyPaired: Boolean): String =
        if (alreadyPaired) "pc_${pcIdHex}_${System.currentTimeMillis().toString(36)}" else "pc_$pcIdHex"

    /** Generates the three per-PC keys; attestation challenge = the pairing's `attest_chal`. */
    fun generatePairKeys(base: String, attestChallenge: ByteArray): PairKeys {
        val deviceAlias = "${base}_device"
        val approveAlias = "${base}_approve"
        val offlineAlias = "${base}_offline_wrap"
        deleteAliases(listOf(deviceAlias, approveAlias, offlineAlias))
        try {
            generateEc(deviceAlias, attestChallenge, approve = false)
            generateEc(approveAlias, attestChallenge, approve = true)
            generateOfflineKey(offlineAlias)
        } catch (e: Exception) {
            deleteAliases(listOf(deviceAlias, approveAlias, offlineAlias))
            throw e
        }
        // Report the weaker of the two keys (StrongBox < TEE < Software < Unknown by ordinal).
        val level = listOf(levelOf(deviceAlias), levelOf(approveAlias)).maxBy { it.ordinal }
        return PairKeys(
            deviceAlias, approveAlias, offlineAlias,
            publicOf(deviceAlias), publicOf(approveAlias),
            chainOf(deviceAlias), chainOf(approveAlias),
            level,
        )
    }

    private fun ecSpec(alias: String, challenge: ByteArray, approve: Boolean, strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setAttestationChallenge(challenge)
            .setIsStrongBoxBacked(strongBox)
        if (approve) {
            b.setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, AUTH)
                .setInvalidatedByBiometricEnrollment(true)
                .setUnlockedDeviceRequired(true)
        }
        return b.build()
    }

    private fun generateEc(alias: String, challenge: ByteArray, approve: Boolean) {
        val g = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, PROVIDER)
        try {
            g.initialize(ecSpec(alias, challenge, approve, strongBox = true))
            g.generateKeyPair()
        } catch (e: StrongBoxUnavailableException) {
            g.initialize(ecSpec(alias, challenge, approve, strongBox = false))
            g.generateKeyPair()
        } catch (e: ProviderException) {
            // Some StrongBox implementations fail attestation or the curve; fall back to the TEE.
            keyStore.deleteEntry(alias)
            g.initialize(ecSpec(alias, challenge, approve, strongBox = false))
            g.generateKeyPair()
        }
    }

    private fun aesSpec(alias: String, auth: Boolean, strongBox: Boolean): KeyGenParameterSpec {
        val b = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setIsStrongBoxBacked(strongBox)
        if (auth) {
            b.setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(0, AUTH)
                .setInvalidatedByBiometricEnrollment(true)
        }
        return b.build()
    }

    private fun generateAes(alias: String, auth: Boolean) {
        val g = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, PROVIDER)
        try {
            g.init(aesSpec(alias, auth, strongBox = true))
            g.generateKey()
        } catch (e: StrongBoxUnavailableException) {
            g.init(aesSpec(alias, auth, strongBox = false))
            g.generateKey()
        } catch (e: ProviderException) {
            keyStore.deleteEntry(alias)
            g.init(aesSpec(alias, auth, strongBox = false))
            g.generateKey()
        }
    }

    private fun generateOfflineKey(alias: String) = generateAes(alias, auth = true)

    fun publicOf(alias: String): ByteArray =
        Crypto.pubBytes(keyStore.getCertificate(alias).publicKey as ECPublicKey)

    fun chainOf(alias: String): List<ByteArray> =
        keyStore.getCertificateChain(alias)?.map { it.encoded } ?: emptyList()

    fun exists(alias: String): Boolean = keyStore.containsAlias(alias)

    fun levelOf(alias: String): KeyLevel = try {
        val key = keyStore.getKey(alias, null)
        val info: KeyInfo = when (key) {
            is PrivateKey -> KeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java)
            is SecretKey -> SecretKeyFactory.getInstance(key.algorithm, PROVIDER).getKeySpec(key, KeyInfo::class.java) as KeyInfo
            else -> return KeyLevel.Unknown
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyLevel.StrongBox
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyLevel.Tee
                KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeyLevel.Software
                else -> KeyLevel.Unknown
            }
        } else {
            @Suppress("DEPRECATION")
            if (info.isInsideSecureHardware) KeyLevel.Tee else KeyLevel.Software
        }
    } catch (e: Exception) {
        KeyLevel.Unknown
    }

    fun deleteAliases(aliases: List<String>) {
        for (a in aliases) runCatching { if (keyStore.containsAlias(a)) keyStore.deleteEntry(a) }
    }

    private fun privateKey(alias: String): PrivateKey =
        keyStore.getKey(alias, null) as? PrivateKey ?: throw KeyInvalidated("Key $alias is missing")

    /** Signer for a no-auth device key. */
    fun deviceSigner(alias: String): Signer = object : Signer {
        override val public: ByteArray = publicOf(alias)
        override fun sign(msg: ByteArray): ByteArray = Crypto.signRaw(privateKey(alias), msg)
    }

    /**
     * A Signature initialized with the approve key, to be unlocked by BiometricPrompt via a
     * CryptoObject. Throws [KeyInvalidated] if new biometrics invalidated the key.
     */
    fun approveSignature(alias: String): Signature = try {
        Signature.getInstance("SHA256withECDSA").apply { initSign(privateKey(alias)) }
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw KeyInvalidated("Biometrics on this phone changed, so its approval key was switched off.", e)
    }

    /** Signs with an authenticated Signature and returns raw r‖s. */
    fun finishSign(sig: Signature, msg: ByteArray): ByteArray {
        sig.update(msg)
        return Crypto.derToRaw(sig.sign())
    }

    fun offlineEncryptCipher(alias: String): Cipher = try {
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, keyStore.getKey(alias, null) as SecretKey) }
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw KeyInvalidated("Biometrics on this phone changed, so its offline key was switched off.", e)
    }

    /** `wrapped` = iv(12) ‖ ciphertext. */
    fun offlineDecryptCipher(alias: String, wrapped: ByteArray): Cipher = try {
        Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, keyStore.getKey(alias, null) as SecretKey, GCMParameterSpec(128, wrapped.copyOfRange(0, 12)))
        }
    } catch (e: KeyPermanentlyInvalidatedException) {
        throw KeyInvalidated("Biometrics on this phone changed, so its offline key was switched off.", e)
    }

    fun wrapWith(cipher: Cipher, plain: ByteArray): ByteArray = cipher.iv + cipher.doFinal(plain)

    fun unwrapWith(cipher: Cipher, wrapped: ByteArray): ByteArray = cipher.doFinal(wrapped.copyOfRange(12, wrapped.size))

    // ---- app state at rest -------------------------------------------------------------------

    private fun storeKey(): SecretKey {
        if (!keyStore.containsAlias(STORE_ALIAS)) generateAes(STORE_ALIAS, auth = false)
        return keyStore.getKey(STORE_ALIAS, null) as SecretKey
    }

    fun sealState(plain: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, storeKey())
        c.updateAAD("phonegate/v1/phone-state".toByteArray())
        return c.iv + c.doFinal(plain)
    }

    fun openState(blob: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.DECRYPT_MODE, storeKey(), GCMParameterSpec(128, blob.copyOfRange(0, 12)))
        c.updateAAD("phonegate/v1/phone-state".toByteArray())
        return c.doFinal(blob.copyOfRange(12, blob.size))
    }
}
