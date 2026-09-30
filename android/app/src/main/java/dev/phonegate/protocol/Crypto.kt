package dev.phonegate.protocol

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import java.security.spec.EllipticCurve
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptographic suite (protocol §1) on top of JCA only (Android: Conscrypt; JVM tests: SunEC).
 * Mirrors `pg-core/src/crypto.rs`. No primitive is hand-rolled: this file only converts between
 * the wire formats (raw r‖s, SEC1 uncompressed points) and the JCA ones.
 */
object Crypto {
    const val PUB_LEN = 65
    const val SIG_LEN = 64

    private val rng = SecureRandom()

    // NIST P-256 domain parameters (public constants from SEC 2 / FIPS 186-4).
    val P: BigInteger = BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    private val A: BigInteger = P.subtract(BigInteger.valueOf(3))
    private val B: BigInteger = BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16)
    val N: BigInteger = BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    private val GX = BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16)
    private val GY = BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16)

    /** secp256r1 parameters, preferring the platform's named-curve instance. */
    val P256: ECParameterSpec by lazy {
        try {
            val ap = AlgorithmParameters.getInstance("EC")
            ap.init(ECGenParameterSpec("secp256r1"))
            ap.getParameterSpec(ECParameterSpec::class.java)
        } catch (e: Exception) {
            ECParameterSpec(EllipticCurve(ECFieldFp(P), A, B), ECPoint(GX, GY), N, 1)
        }
    }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun hmac(key: ByteArray, msg: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // An empty HMAC key is equivalent to an all-zero key (RFC 2104 zero padding); JCA
        // refuses empty keys, so substitute the equivalent one.
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        return mac.doFinal(msg)
    }

    /** Constant-time MAC comparison. */
    fun hmacVerify(key: ByteArray, msg: ByteArray, tag: ByteArray): Boolean = ctEq(hmac(key, msg), tag)

    /** Constant-time equality for values of equal public length. */
    fun ctEq(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    /** RFC 5869 HKDF-SHA256 with a 32-byte output. */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: ByteArray): ByteArray {
        val prk = hmac(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        // L = 32 = HashLen, so a single expand block: T(1) = HMAC(PRK, info ‖ 0x01).
        return hmac(prk, info + byteArrayOf(1))
    }

    fun random(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    /** Uniform integer in `[lo, hi]`. */
    fun randomRange(lo: Int, hi: Int): Int = lo + rng.nextInt(hi - lo + 1)

    fun aeadSeal(key: ByteArray, nonce: ByteArray, plaintext: ByteArray, aad: ByteArray): ByteArray {
        if (key.size != 32 || nonce.size != 12) throw ProtocolException.CryptoFailure("bad aead key or nonce")
        val c = Cipher.getInstance("AES/GCM/NoPadding")
        c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        c.updateAAD(aad)
        return c.doFinal(plaintext)
    }

    fun aeadOpen(key: ByteArray, nonce: ByteArray, ciphertext: ByteArray, aad: ByteArray): ByteArray {
        if (key.size != 32 || nonce.size != 12) throw ProtocolException.CryptoFailure("bad aead key or nonce")
        return try {
            val c = Cipher.getInstance("AES/GCM/NoPadding")
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
            c.updateAAD(aad)
            c.doFinal(ciphertext)
        } catch (e: java.security.GeneralSecurityException) {
            throw ProtocolException.Verify("aead authentication failed")
        }
    }

    /** Parses and validates an uncompressed SEC1 P-256 point (65 bytes, `0x04`, on curve). */
    fun parsePub(bytes: ByteArray): ECPublicKey {
        if (bytes.size != PUB_LEN || bytes[0] != 0x04.toByte()) {
            throw ProtocolException.Decode("public key must be 65-byte uncompressed SEC1")
        }
        val x = BigInteger(1, bytes.copyOfRange(1, 33))
        val y = BigInteger(1, bytes.copyOfRange(33, 65))
        if (x >= P || y >= P) throw ProtocolException.Decode("public key not on curve")
        val lhs = y.multiply(y).mod(P)
        val rhs = x.multiply(x).multiply(x).add(A.multiply(x)).add(B).mod(P)
        if (lhs != rhs) throw ProtocolException.Decode("public key not on curve")
        return try {
            KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), P256)) as ECPublicKey
        } catch (e: java.security.GeneralSecurityException) {
            throw ProtocolException.Decode("public key not on curve")
        }
    }

    fun pubBytes(key: ECPublicKey): ByteArray {
        val w = key.w
        return byteArrayOf(0x04) + fixed32(w.affineX) + fixed32(w.affineY)
    }

    fun idOf(pub: ByteArray): ByteArray = sha256(pub)

    fun fixed32(v: BigInteger): ByteArray {
        val b = v.toByteArray()
        return when {
            b.size == 32 -> b
            b.size == 33 && b[0] == 0.toByte() -> b.copyOfRange(1, 33)
            b.size < 32 -> ByteArray(32 - b.size) + b
            else -> throw ProtocolException.CryptoFailure("integer larger than 32 bytes")
        }
    }

    /**
     * Verifies an ECDSA P-256/SHA-256 signature in raw `r‖s` form. Rejects `r` or `s` outside
     * `[1, n-1]`; accepts both low-S and high-S (Keystore does not normalize S).
     */
    fun verify(pub: ByteArray, msg: ByteArray, sig: ByteArray) {
        if (sig.size != SIG_LEN) throw ProtocolException.Verify("malformed signature")
        val r = BigInteger(1, sig.copyOfRange(0, 32))
        val s = BigInteger(1, sig.copyOfRange(32, 64))
        if (r.signum() == 0 || s.signum() == 0 || r >= N || s >= N) {
            throw ProtocolException.Verify("malformed signature")
        }
        val key = parsePub(pub)
        val ok = try {
            val v = Signature.getInstance("SHA256withECDSA")
            v.initVerify(key)
            v.update(msg)
            v.verify(rawToDer(sig))
        } catch (e: java.security.GeneralSecurityException) {
            false
        }
        if (!ok) throw ProtocolException.Verify("bad signature")
    }

    /** Raw `r‖s` → DER `SEQUENCE { INTEGER r, INTEGER s }` for JCA verification. */
    fun rawToDer(sig: ByteArray): ByteArray {
        require(sig.size == SIG_LEN)
        val r = BigInteger(1, sig.copyOfRange(0, 32)).toByteArray()
        val s = BigInteger(1, sig.copyOfRange(32, 64)).toByteArray()
        val body = byteArrayOf(0x02, r.size.toByte()) + r + byteArrayOf(0x02, s.size.toByte()) + s
        return byteArrayOf(0x30, body.size.toByte()) + body
    }

    /** Strict DER ECDSA signature (as produced by JCA / Keystore) → raw `r‖s`. */
    fun derToRaw(der: ByteArray): ByteArray {
        fun fail(): Nothing = throw ProtocolException.Decode("malformed DER signature")
        if (der.size < 8 || der[0] != 0x30.toByte()) fail()
        var pos = 1
        val total: Int
        val l0 = der[pos++].toInt() and 0xff
        total = when {
            l0 < 0x80 -> l0
            l0 == 0x81 -> der[pos++].toInt() and 0xff
            else -> fail()
        }
        if (total != der.size - pos) fail()
        fun readInt(): BigInteger {
            if (pos + 2 > der.size || der[pos] != 0x02.toByte()) fail()
            val len = der[pos + 1].toInt() and 0xff
            pos += 2
            if (len == 0 || len > 33 || pos + len > der.size) fail()
            val v = BigInteger(1, der.copyOfRange(pos, pos + len))
            pos += len
            return v
        }
        val r = readInt()
        val s = readInt()
        if (pos != der.size) fail()
        if (r.signum() == 0 || s.signum() == 0 || r >= N || s >= N) fail()
        return fixed32(r) + fixed32(s)
    }

    /** Signs with a software or Keystore private key and returns raw `r‖s`. */
    fun signRaw(key: PrivateKey, msg: ByteArray): ByteArray {
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(key)
        s.update(msg)
        return derToRaw(s.sign())
    }

    /** ECDH on P-256; shared secret = 32-byte big-endian x-coordinate. */
    fun ecdh(priv: PrivateKey, peerPub: ByteArray): ByteArray {
        val peer = parsePub(peerPub)
        val ka = KeyAgreement.getInstance("ECDH")
        ka.init(priv)
        ka.doPhase(peer, true)
        val secret = ka.generateSecret()
        return if (secret.size == 32) secret else fixed32(BigInteger(1, secret))
    }

    /** Builds a software private key from a 32-byte scalar (tests and ephemeral keys). */
    fun privateFromScalar(scalar: ByteArray): PrivateKey {
        val d = BigInteger(1, scalar)
        if (d.signum() == 0 || d >= N) throw ProtocolException.CryptoFailure("invalid scalar")
        return KeyFactory.getInstance("EC").generatePrivate(ECPrivateKeySpec(d, P256))
    }
}

/** An ephemeral P-256 key pair for ECDH (software, never persisted). */
class EphemeralKey private constructor(val private: PrivateKey, val public: ByteArray) {
    fun agree(peerPub: ByteArray): ByteArray = Crypto.ecdh(private, peerPub)

    companion object {
        fun generate(): EphemeralKey {
            val g = KeyPairGenerator.getInstance("EC")
            g.initialize(ECGenParameterSpec("secp256r1"))
            val kp = g.generateKeyPair()
            return EphemeralKey(kp.private, Crypto.pubBytes(kp.public as ECPublicKey))
        }

        /** Deterministic key for test vectors; `public` must be supplied by the caller. */
        fun fromScalar(scalar: ByteArray, public: ByteArray): EphemeralKey {
            Crypto.parsePub(public)
            return EphemeralKey(Crypto.privateFromScalar(scalar), public)
        }
    }
}

/** base64url without padding (RFC 4648 §5), strict. */
object B64 {
    private val enc = java.util.Base64.getUrlEncoder().withoutPadding()
    private val dec = java.util.Base64.getUrlDecoder()

    fun encode(b: ByteArray): String = enc.encodeToString(b)

    fun decode(s: String): ByteArray {
        if (s.contains('=') || s.any { !(it.isLetterOrDigit() && it.code < 128) && it != '-' && it != '_' }) {
            throw ProtocolException.Decode("invalid base64url")
        }
        return try {
            dec.decode(s)
        } catch (e: IllegalArgumentException) {
            throw ProtocolException.Decode("invalid base64url")
        }
    }

    fun decodeFixed(s: String, n: Int): ByteArray {
        val b = decode(s)
        if (b.size != n) throw ProtocolException.Decode("base64 field has wrong length")
        return b
    }
}

/** Something that produces raw `r‖s` P-256 signatures (Keystore key or software key). */
interface Signer {
    val public: ByteArray
    fun sign(msg: ByteArray): ByteArray
}

/** Software signer for tests only (production phone keys live in Android Keystore). */
class SoftSigner(private val priv: PrivateKey, override val public: ByteArray) : Signer {
    override fun sign(msg: ByteArray): ByteArray = Crypto.signRaw(priv, msg)

    companion object {
        fun generate(): SoftSigner {
            val g = KeyPairGenerator.getInstance("EC")
            g.initialize(ECGenParameterSpec("secp256r1"))
            val kp = g.generateKeyPair()
            return SoftSigner(kp.private, Crypto.pubBytes(kp.public as ECPublicKey))
        }
    }
}

fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }

fun String.unhex(): ByteArray {
    require(length % 2 == 0)
    return ByteArray(length / 2) { i -> substring(2 * i, 2 * i + 2).toInt(16).toByte() }
}
