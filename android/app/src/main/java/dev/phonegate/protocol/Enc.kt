package dev.phonegate.protocol

import java.io.ByteArrayOutputStream

/**
 * Canonical length-prefixed encoding (protocol §2), byte-identical with `pg-core/src/encoding.rs`.
 * Every field is `u32_be(len) ‖ bytes`; the first field is always a `phonegate/v1/` label.
 */
class Enc(label: String) {
    private val buf = ByteArrayOutputStream(128)

    init {
        require(label.startsWith("phonegate/v1/")) { "labels must start with phonegate/v1/" }
        bytes(label.toByteArray(Charsets.UTF_8))
    }

    fun bytes(b: ByteArray): Enc {
        writeLen(buf, b.size)
        buf.write(b)
        return this
    }

    fun str(s: String): Enc = bytes(s.toByteArray(Charsets.UTF_8))

    fun u64(v: Long): Enc = bytes(u64be(v))

    /** A list of byte strings, itself canonically encoded (no label). */
    fun list(items: List<ByteArray>): Enc = bytes(encList(items))

    fun finish(): ByteArray = buf.toByteArray()

    companion object {
        const val MAX_ENCODED = 64 * 1024
        const val MAX_STRING = 256

        fun encList(items: List<ByteArray>): ByteArray {
            val out = ByteArrayOutputStream()
            for (it in items) {
                writeLen(out, it.size)
                out.write(it)
            }
            return out.toByteArray()
        }

        fun u64be(v: Long): ByteArray = ByteArray(8) { i -> (v ushr (56 - 8 * i)).toByte() }

        fun readU64be(b: ByteArray): Long {
            var v = 0L
            for (x in b) v = (v shl 8) or (x.toLong() and 0xff)
            return v
        }

        private fun writeLen(out: ByteArrayOutputStream, len: Int) {
            out.write(len ushr 24 and 0xff)
            out.write(len ushr 16 and 0xff)
            out.write(len ushr 8 and 0xff)
            out.write(len and 0xff)
        }

        /** Splits raw canonical bytes into fields without interpreting them. */
        fun split(data: ByteArray): List<ByteArray> {
            if (data.size > MAX_ENCODED) throw ProtocolException.Decode("encoded structure too large")
            val fields = ArrayList<ByteArray>()
            var pos = 0
            while (pos < data.size) {
                if (data.size - pos < 4) throw ProtocolException.Decode("truncated length prefix")
                val len = ((data[pos].toLong() and 0xff) shl 24) or
                    ((data[pos + 1].toLong() and 0xff) shl 16) or
                    ((data[pos + 2].toLong() and 0xff) shl 8) or
                    (data[pos + 3].toLong() and 0xff)
                pos += 4
                if (len > data.size - pos) throw ProtocolException.Decode("truncated field")
                fields.add(data.copyOfRange(pos, pos + len.toInt()))
                pos += len.toInt()
            }
            return fields
        }

        fun decodeList(data: ByteArray): List<ByteArray> = split(data)

        /** Decodes `data`, requiring `label` and exactly `count` fields **including** the label. */
        fun decode(data: ByteArray, label: String, count: Int): Fields {
            val fields = split(data)
            if (fields.isEmpty() || !fields[0].contentEquals(label.toByteArray(Charsets.UTF_8))) {
                throw ProtocolException.Decode("label mismatch")
            }
            if (fields.size != count) throw ProtocolException.Decode("wrong field count")
            return Fields(fields)
        }
    }
}

/** Decoded fields of a labelled structure. Index 0 is the label. */
class Fields internal constructor(private val fields: List<ByteArray>) {
    fun bytes(i: Int): ByteArray = fields[i]

    fun fixed(i: Int, n: Int): ByteArray {
        val b = fields[i]
        if (b.size != n) throw ProtocolException.Decode("fixed-size field has wrong length")
        return b
    }

    fun u64(i: Int): Long = Enc.readU64be(fixed(i, 8))

    fun string(i: Int): String = stringMax(i, Enc.MAX_STRING)

    fun stringMax(i: Int, max: Int): String {
        val b = fields[i]
        if (b.size > max) throw ProtocolException.Decode("string too long")
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
        return try {
            decoder.decode(java.nio.ByteBuffer.wrap(b)).toString()
        } catch (e: java.nio.charset.CharacterCodingException) {
            throw ProtocolException.Decode("invalid utf-8")
        }
    }

    fun list(i: Int): List<ByteArray> = Enc.decodeList(fields[i])
}
