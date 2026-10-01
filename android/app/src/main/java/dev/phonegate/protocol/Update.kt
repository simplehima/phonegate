package dev.phonegate.protocol

import org.json.JSONObject

/**
 * Update-check helpers (feature 004), a port of `crates/pg-core/src/update.rs`. Pure and shared
 * so the Kotlin and Rust/companion sides agree on what "newer" means. Fetching is done by the
 * caller; this only parses the GitHub "latest release" body and compares versions.
 */
object Update {
    /** Extracts `tag_name` from the GitHub "latest release" JSON, trimmed; null if absent/empty. */
    fun parseLatestTag(json: String): String? {
        val tag = try {
            JSONObject(json).optString("tag_name", "").trim()
        } catch (e: Exception) {
            return null
        }
        return tag.ifEmpty { null }
    }

    /**
     * Dotted numeric version, ignoring a leading `v` and any pre-release/build suffix. Missing
     * components are 0: `1.2` -> `[1,2,0]`. Unparsable -> all zeros.
     */
    private fun parts(version: String): LongArray {
        val v = version.trim().trimStart('v', 'V')
        val core = v.split('-', '+').firstOrNull() ?: ""
        val out = LongArray(3)
        for ((i, seg) in core.split('.').take(3).withIndex()) {
            val digits = seg.takeWhile { it in '0'..'9' }
            out[i] = digits.toLongOrNull() ?: 0L
        }
        return out
    }

    /** True only when `latest` is strictly greater than `current`. */
    fun isNewer(current: String, latest: String): Boolean {
        val a = parts(latest)
        val b = parts(current)
        for (i in 0 until 3) {
            if (a[i] != b[i]) return a[i] > b[i]
        }
        return false
    }
}
