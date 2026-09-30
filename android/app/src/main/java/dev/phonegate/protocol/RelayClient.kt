package dev.phonegate.protocol

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONObject
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * Relay WebSocket client (contracts/relay-api.md), mirroring `pg-core/src/relay_client.rs`.
 * The relay is untrusted: this only moves opaque bodies, all verification is in [Inbox].
 * Reconnects with exponential backoff (1 s .. 60 s, jittered) until [close] is called.
 */
class RelayClient(
    relayUrl: String,
    private val signer: Signer,
    private val listener: Listener,
    private val http: OkHttpClient = sharedHttp,
) {
    interface Listener {
        fun onReady(client: RelayClient) {}
        fun onMessage(from: ByteArray, to: ByteArray, body: ByteArray)
        fun onAck(ref: String) {}
        fun onError(ref: String?, code: String) {}
        fun onStatus(status: Status) {}
    }

    enum class Status { Connecting, Ready, Disconnected, Closed }

    private val url = wsUrl(relayUrl)
    private val expectedId = Crypto.idOf(signer.public)
    private val refs = AtomicInteger(0)
    private val subscriptions = LinkedHashSet<String>()

    @Volatile private var ws: WebSocket? = null
    @Volatile private var ready = false
    @Volatile private var closed = false
    private var attempt = 0
    private var generation = 0

    @Volatile var status: Status = Status.Disconnected
        private set

    val isReady: Boolean get() = ready && !closed

    fun start() {
        synchronized(this) {
            if (closed) return
            connectLocked()
        }
    }

    private fun connectLocked() {
        generation += 1
        val gen = generation
        ready = false
        setStatus(Status.Connecting)
        ws = http.newWebSocket(Request.Builder().url(url).build(), Handler(gen))
    }

    private fun setStatus(s: Status) {
        status = s
        listener.onStatus(s)
    }

    private inner class Handler(val gen: Int) : WebSocketListener() {
        private var authed = false

        override fun onMessage(webSocket: WebSocket, text: String) {
            if (gen != generation) return
            val v = try { JSONObject(text) } catch (e: Exception) { return }
            when (v.optString("t")) {
                "hello" -> {
                    if (authed) return
                    try {
                        val challenge = B64.decodeFixed(v.optString("challenge"), 32)
                        val sig = signer.sign(authBytes(challenge))
                        val auth = JSONObject().put("t", "auth").put("pub", B64.encode(signer.public)).put("sig", B64.encode(sig))
                        webSocket.send(auth.toString())
                        authed = true
                    } catch (e: Exception) {
                        webSocket.close(1000, "auth failed")
                    }
                }
                "ready" -> {
                    val id = try { B64.decodeFixed(v.optString("id"), 32) } catch (e: Exception) { null }
                    if (id == null || !id.contentEquals(expectedId)) {
                        webSocket.close(1000, "unexpected id")
                        return
                    }
                    synchronized(this@RelayClient) {
                        ready = true
                        attempt = 0
                        for (slot in subscriptions) {
                            webSocket.send(JSONObject().put("t", "sub").put("slot", slot).toString())
                        }
                    }
                    setStatus(Status.Ready)
                    listener.onReady(this@RelayClient)
                }
                "msg" -> {
                    try {
                        val from = B64.decodeFixed(v.optString("from"), 32)
                        val to = B64.decodeFixed(v.optString("to"), 32)
                        val body = B64.decode(v.optString("body"))
                        listener.onMessage(from, to, body)
                    } catch (e: ProtocolException) {
                        // Malformed frame from an untrusted relay: ignore.
                    }
                }
                "ack" -> listener.onAck(v.optString("ref"))
                "error" -> listener.onError(if (v.has("ref")) v.optString("ref") else null, v.optString("code"))
            }
        }

        override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
            webSocket.close(1000, null)
        }

        override fun onClosed(webSocket: WebSocket, code: Int, reason: String) = lost()

        override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) = lost()

        private fun lost() {
            synchronized(this@RelayClient) {
                if (gen != generation) return
                ready = false
                ws = null
                if (closed) return
                setStatus(Status.Disconnected)
                val base = (1000L shl attempt.coerceAtMost(6)).coerceAtMost(60_000L)
                val delay = base / 2 + (Math.random() * base / 2).toLong()
                attempt += 1
                val scheduledGen = gen
                scheduler.schedule({
                    synchronized(this@RelayClient) {
                        if (!closed && generation == scheduledGen) connectLocked()
                    }
                }, delay, TimeUnit.MILLISECONDS)
            }
        }
    }

    private fun sendFrame(f: JSONObject): Boolean {
        val w = ws ?: return false
        if (!ready) return false
        return w.send(f.toString())
    }

    /** Sends to a mailbox. Returns the frame ref, or null if not connected. */
    fun send(to: ByteArray, body: ByteArray, ttlS: Int = 60): String? {
        val ref = "r" + refs.incrementAndGet()
        val f = JSONObject().put("t", "send").put("ref", ref).put("to", B64.encode(to)).put("body", B64.encode(body)).put("ttl", ttlS)
        return if (sendFrame(f)) ref else null
    }

    /** Sends to a pairing slot (retained until the TTL for late subscribers). */
    fun sendSlot(slot: ByteArray, body: ByteArray, ttlS: Int = 300): String? {
        val ref = "r" + refs.incrementAndGet()
        val f = JSONObject().put("t", "send").put("ref", ref).put("to", B64.encode(slot)).put("body", B64.encode(body))
            .put("ttl", ttlS).put("slot", true)
        return if (sendFrame(f)) ref else null
    }

    /** Subscribes to a pairing slot; re-subscribed automatically after reconnects. */
    fun subscribe(slot: ByteArray) {
        val s = B64.encode(slot)
        synchronized(this) { subscriptions.add(s) }
        sendFrame(JSONObject().put("t", "sub").put("slot", s))
    }

    fun unsubscribeAll() {
        synchronized(this) { subscriptions.clear() }
    }

    fun close() {
        synchronized(this) {
            closed = true
            ready = false
            generation += 1
            ws?.close(1000, null)
            ws = null
        }
        setStatus(Status.Closed)
    }

    companion object {
        private val scheduler: ScheduledExecutorService = ScheduledThreadPoolExecutor(1) { r ->
            Thread(r, "relay-reconnect").apply { isDaemon = true }
        }

        val sharedHttp: OkHttpClient by lazy {
            OkHttpClient.Builder()
                .connectTimeout(15, TimeUnit.SECONDS)
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .pingInterval(25, TimeUnit.SECONDS)
                .build()
        }

        /** `https://host[/prefix]` → `wss://host[/prefix]/v1/ws`. */
        fun wsUrl(relayUrl: String): String {
            val base = relayUrl.trimEnd('/')
            return when {
                base.startsWith("https://") -> "wss://" + base.removePrefix("https://") + "/v1/ws"
                base.startsWith("http://") -> "ws://" + base.removePrefix("http://") + "/v1/ws"
                else -> throw ProtocolException.Decode("relay url must start with https:// or http://")
            }
        }

        fun authBytes(challenge: ByteArray): ByteArray = Enc("phonegate/v1/relay-auth").bytes(challenge).finish()
    }
}
