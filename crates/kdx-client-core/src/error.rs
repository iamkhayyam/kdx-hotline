/// Errors surfaced by the client library.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(#[from] kdx_protocol::ProtocolError),
    #[error("crypto error: {0}")]
    Crypto(#[from] kdx_crypto::CryptoError),
    #[error("tls error: {0}")]
    Tls(String),
    /// The server's certificate is not trusted. `previous` is `Some` when a
    /// different key was previously pinned for this host — a possible MITM,
    /// warranting a loud warning rather than a routine first-contact prompt.
    #[error("untrusted server certificate for {host}")]
    UntrustedCertificate {
        host: String,
        fingerprint: String,
        previous: Option<String>,
    },
    #[error("server rejected the handshake")]
    HandshakeRejected,
    #[error("authentication failed: {0}")]
    AuthFailed(String),
    #[error("not connected")]
    NotConnected,
    #[error("connection closed by server")]
    Disconnected,
    #[error("server error: {0}")]
    Server(String),
    #[error("transfer failed: {0}")]
    Transfer(String),
    #[error("invalid server name: {0}")]
    InvalidServerName(String),
}
