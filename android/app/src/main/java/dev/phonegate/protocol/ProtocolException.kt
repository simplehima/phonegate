package dev.phonegate.protocol

/**
 * Every protocol failure. Callers treat any of these as "discard silently" (fail-secure): an
 * unverified message is never shown and never answered.
 */
sealed class ProtocolException(message: String) : Exception(message) {
    class Decode(message: String) : ProtocolException(message)
    class Verify(message: String) : ProtocolException(message)
    class Expired : ProtocolException("expired")
    class Replay : ProtocolException("replayed message")
    class State(message: String) : ProtocolException(message)
    class CryptoFailure(message: String) : ProtocolException(message)
}
