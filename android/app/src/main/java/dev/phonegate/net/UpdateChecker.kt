package dev.phonegate.net

import android.content.Context
import dev.phonegate.protocol.Update
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

/**
 * Looks for a newer GitHub release (feature 004). The only request this app makes outside your
 * relay: an unauthenticated GET of the latest release number from a fixed URL. It never downloads
 * or installs anything, can be switched off, and says nothing when it fails.
 */
object UpdateChecker {
    const val REPO_URL = "https://github.com/simplehima/phonegate"
    const val RELEASES_URL = "$REPO_URL/releases"
    const val LICENSE_URL = "$REPO_URL/blob/main/LICENSE"
    const val SECURITY_URL = "$REPO_URL/security/advisories/new"
    const val ISSUES_URL = "$REPO_URL/issues"
    private const val LATEST_URL = "https://api.github.com/repos/simplehima/phonegate/releases/latest"
    private const val PREFS = "phonegate_prefs"
    private const val KEY = "update_checks"

    private val http: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .callTimeout(8, TimeUnit.SECONDS)
            .build()
    }

    fun enabled(context: Context): Boolean =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getBoolean(KEY, true)

    fun setEnabled(context: Context, on: Boolean) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putBoolean(KEY, on).apply()
    }

    /** Outcome of one look at GitHub. */
    sealed class Result {
        data class Newer(val tag: String) : Result()
        data class Current(val tag: String) : Result()
        data object Failed : Result()
    }

    /** One look at the latest release; never throws, never shows an error to the owner by itself. */
    suspend fun check(current: String): Result = withContext(Dispatchers.IO) {
        try {
            val req = Request.Builder().url(LATEST_URL).header("Accept", "application/vnd.github+json").build()
            http.newCall(req).execute().use { resp ->
                if (!resp.isSuccessful) return@withContext Result.Failed
                val tag = Update.parseLatestTag(resp.body?.string().orEmpty()) ?: return@withContext Result.Failed
                if (Update.isNewer(current, tag)) Result.Newer(tag) else Result.Current(tag)
            }
        } catch (e: Exception) {
            Result.Failed
        }
    }

    /** The release tag if it is strictly newer than [current]; null when not newer or on any failure. */
    suspend fun newerRelease(current: String): String? = (check(current) as? Result.Newer)?.tag
}
