//! Credential-related crypto for KDX: Argon2id password hashing and
//! challenge-response auth helpers. Transport security is TLS 1.3 (rustls),
//! handled at the connection layer — nothing here touches transport keys.
