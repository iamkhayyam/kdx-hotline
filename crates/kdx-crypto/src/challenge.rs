//! Login challenge and the Argon2id cost parameters shipped with it.
//!
//! The proof a client sends back is computed in [`crate::scram`]; this module
//! only holds the pieces both sides share: the fresh random challenge and the
//! [`KdfParams`] (plus the bounds a client enforces before it spends any
//! memory or CPU on a server-chosen KDF).

use argon2::Params;
use rand::RngCore;

use crate::CryptoError;

/// Smallest Argon2 memory cost (KiB) a client accepts. Equal to the argon2
/// crate's default (19 MiB, the OWASP minimum): anything cheaper would let a
/// malicious server make the client's proof cheap to brute-force offline.
pub const MIN_M_COST: u32 = 19_456;
/// Largest Argon2 memory cost (KiB) a client accepts (256 MiB). Above this a
/// malicious server could abort or OOM-kill the client.
pub const MAX_M_COST: u32 = 262_144;
/// Smallest Argon2 time cost (passes) a client accepts.
pub const MIN_T_COST: u32 = 2;
/// Largest Argon2 time cost a client accepts; bounds login CPU time.
pub const MAX_T_COST: u32 = 10;
/// Smallest Argon2 parallelism a client accepts.
pub const MIN_P_COST: u32 = 1;
/// Largest Argon2 parallelism a client accepts.
pub const MAX_P_COST: u32 = 4;
/// Shortest salt a client accepts (bytes).
pub const MIN_SALT_LEN: usize = 16;
/// Longest salt a client accepts (bytes).
pub const MAX_SALT_LEN: usize = 64;
/// Length of every salt this crate generates (and of the server's decoy salts).
pub const SALT_LEN: usize = 16;

/// Argon2id cost parameters shipped to the client so it can recompute its
/// salted password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl KdfParams {
    /// The parameters new credentials are derived with: the argon2 crate's
    /// defaults (m = 19 MiB, t = 2, p = 1). The server's decoy challenges for
    /// unknown usernames use exactly these too.
    pub const DEFAULT: KdfParams = KdfParams {
        m_cost: Params::DEFAULT_M_COST,
        t_cost: Params::DEFAULT_T_COST,
        p_cost: Params::DEFAULT_P_COST,
    };

    /// Check server-supplied parameters (and salt length) against the
    /// client-side floors and ceilings before deriving anything. A malicious
    /// server must not be able to make the client allocate terabytes, spin
    /// for hours, or produce a cheaply crackable proof.
    pub fn check_bounds(&self, salt_len: usize) -> Result<(), CryptoError> {
        if !(MIN_M_COST..=MAX_M_COST).contains(&self.m_cost) {
            return Err(CryptoError::UnacceptableKdf("memory cost out of range"));
        }
        if !(MIN_T_COST..=MAX_T_COST).contains(&self.t_cost) {
            return Err(CryptoError::UnacceptableKdf("time cost out of range"));
        }
        if !(MIN_P_COST..=MAX_P_COST).contains(&self.p_cost) {
            return Err(CryptoError::UnacceptableKdf("parallelism out of range"));
        }
        if !(MIN_SALT_LEN..=MAX_SALT_LEN).contains(&salt_len) {
            return Err(CryptoError::UnacceptableKdf("salt length out of range"));
        }
        Ok(())
    }
}

/// A fresh random 32-byte login challenge.
pub fn generate_challenge() -> [u8; 32] {
    let mut challenge = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut challenge);
    challenge
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenges_are_unique() {
        assert_ne!(generate_challenge(), generate_challenge());
    }

    #[test]
    fn default_params_are_within_client_bounds() {
        assert_eq!(KdfParams::DEFAULT.m_cost, 19_456);
        assert_eq!(KdfParams::DEFAULT.t_cost, 2);
        assert_eq!(KdfParams::DEFAULT.p_cost, 1);
        KdfParams::DEFAULT.check_bounds(SALT_LEN).unwrap();
    }

    #[test]
    fn hostile_params_are_rejected() {
        let ok = KdfParams::DEFAULT;
        let cases = [
            KdfParams {
                m_cost: u32::MAX,
                ..ok
            },
            KdfParams { m_cost: 8, ..ok },
            KdfParams {
                m_cost: MAX_M_COST + 1,
                ..ok
            },
            KdfParams {
                t_cost: u32::MAX,
                ..ok
            },
            KdfParams { t_cost: 1, ..ok },
            KdfParams { p_cost: 0, ..ok },
            KdfParams {
                p_cost: 0xFF_FFFF,
                ..ok
            },
        ];
        for params in cases {
            assert!(
                matches!(
                    params.check_bounds(SALT_LEN),
                    Err(CryptoError::UnacceptableKdf(_))
                ),
                "{params:?} accepted"
            );
        }
        assert!(ok.check_bounds(8).is_err());
        assert!(ok.check_bounds(65).is_err());
        assert!(ok.check_bounds(MIN_SALT_LEN).is_ok());
        assert!(ok.check_bounds(MAX_SALT_LEN).is_ok());
    }
}
