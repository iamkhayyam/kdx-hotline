//! Shamir t-of-n secret sharing over GF(2⁸) with Merkle-verified shares.
//!
//! This is **Slice 1** of the hive-entropy design (`docs/hive-entropy-design.md`):
//! a payload is split into `n` shares such that any `t` reconstruct it and any
//! `t-1` reveal nothing (information-theoretic secrecy). Each share is covered
//! by a Merkle commitment published by the dealer, so holders can prove their
//! share is exactly the one committed — tamper-evidence against corrupted
//! relays and infiltrators modifying shares in flight.
//!
//! Upgrade path (Slice 2): Feldman verifiable secret sharing over a prime-order
//! group (BLS12-381) replaces the Merkle commitments with per-share polynomial
//! proofs, catching a *dealer* who hands a node an off-polynomial share.

use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::CryptoError;

/// Upper bound on share count. Keeps every x-coordinate in a `u8` and leaves
/// headroom below the 255-point limit of the field.
pub const MAX_SHARES: u8 = 250;

/// One share: the point `(index, f(index))` on the degree `t-1` polynomial.
/// `index` is 1-based and doubles as the x-coordinate; `data[j]` is the y-value
/// for byte column `j` of the secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
}

/// Everything a dealer publishes after a split: the shares (secret) and the
/// public commitment tree (verifiable by anyone).
#[derive(Debug, Clone)]
pub struct SplitResult {
    pub shares: Vec<Share>,
    pub commitments: Commitments,
}

/// One step of a Merkle proof: the sibling digest and which side the current
/// digest sits on, so verification can fold without knowing the tree size.
#[derive(Debug, Clone)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    /// True when the accumulated digest is the *left* child of the parent.
    pub current_is_left: bool,
}

/// A membership proof for one share against a commitment root.
#[derive(Debug, Clone)]
pub struct MerkleProof {
    pub steps: Vec<ProofStep>,
}

/// Public commitment tree over the shares of one split. The root is small and
/// safe to publish on a channel; proofs let any holder audit its own share.
#[derive(Debug, Clone)]
pub struct Commitments {
    root: [u8; 32],
    tree: Vec<[u8; 32]>,
    leaf_count: usize,
}

/// Split `secret` into `shares` shares, any `threshold` of which reconstruct it.
///
/// Requires `2 <= threshold <= shares <= MAX_SHARES`. Random coefficients are
/// drawn from the OS CSPRNG and zeroized after use.
pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Result<SplitResult, CryptoError> {
    if threshold < 2 {
        return Err(CryptoError::ShamirParams(format!(
            "threshold must be at least 2, got {threshold}"
        )));
    }
    if shares < threshold {
        return Err(CryptoError::ShamirParams(format!(
            "share count {shares} must be at least threshold {threshold}"
        )));
    }
    if shares > MAX_SHARES {
        return Err(CryptoError::ShamirParams(format!(
            "share count {shares} exceeds max {MAX_SHARES}"
        )));
    }

    let t = threshold as usize;
    let n = shares as usize;
    let mut rng = rand::rngs::OsRng;
    let mut holder: Vec<Vec<u8>> = vec![Vec::with_capacity(secret.len()); n];

    for col in 0..secret.len() {
        // One random degree-(t-1) polynomial per byte column, constant term = secret byte.
        let mut coeffs = vec![0u8; t - 1];
        rng.fill_bytes(&mut coeffs);
        for (pos, data) in holder.iter_mut().enumerate() {
            let x = (pos + 1) as u8;
            let mut acc = secret[col];
            let mut xp = x;
            for &c in &coeffs {
                acc ^= gf_mul(c, xp);
                xp = gf_mul(xp, x);
            }
            data.push(acc);
        }
        coeffs.zeroize();
    }

    let shares: Vec<Share> = holder
        .into_iter()
        .enumerate()
        .map(|(pos, data)| Share {
            index: (pos + 1) as u8,
            data,
        })
        .collect();
    let commitments = Commitments::new(&shares);
    Ok(SplitResult { shares, commitments })
}

/// Reconstruct the secret from `threshold` (or more) distinct shares.
///
/// Extra shares beyond `threshold` are ignored; order does not matter.
/// `threshold` must match the value used at split time — it is not recoverable
/// from the shares themselves.
pub fn combine(shares: &[Share], threshold: u8) -> Result<Vec<u8>, CryptoError> {
    if threshold < 2 {
        return Err(CryptoError::ShamirParams(format!(
            "threshold must be at least 2, got {threshold}"
        )));
    }
    if shares.len() < threshold as usize {
        return Err(CryptoError::ShamirThreshold {
            required: threshold,
            got: shares.len(),
        });
    }

    let mut chosen: Vec<&Share> = shares.iter().collect();
    chosen.sort_by_key(|s| s.index);
    chosen.dedup_by_key(|s| s.index);
    if chosen.len() < threshold as usize {
        return Err(CryptoError::ShamirThreshold {
            required: threshold,
            got: shares.len(),
        });
    }
    chosen.truncate(threshold as usize);

    let len = chosen[0].data.len();
    if chosen.iter().any(|s| s.data.len() != len) {
        return Err(CryptoError::ShamirLengthMismatch);
    }

    let mut out = vec![0u8; len];
    for col in 0..len {
        // Lagrange interpolation at x = 0: f(0) = Σ yᵢ · Lᵢ(0).
        let mut acc = 0u8;
        for (i, si) in chosen.iter().enumerate() {
            let xi = si.index;
            let mut num = 1u8;
            let mut den = 1u8;
            for (j, sj) in chosen.iter().enumerate() {
                if i == j {
                    continue;
                }
                let xj = sj.index;
                num = gf_mul(num, xj);
                den = gf_mul(den, xj ^ xi);
            }
            let li = gf_mul(num, gf_inv(den));
            acc ^= gf_mul(si.data[col], li);
        }
        out[col] = acc;
    }
    Ok(out)
}

/// Verify one share against a commitment root and its proof. Fails on a
/// modified share, a proof from a different tree, or a mismatched index.
pub fn verify_share(share: &Share, root: &[u8; 32], proof: &MerkleProof) -> bool {
    let mut digest = leaf_digest(share);
    for step in &proof.steps {
        digest = if step.current_is_left {
            node_digest(&digest, &step.sibling)
        } else {
            node_digest(&step.sibling, &digest)
        };
    }
    digest == *root
}

impl Commitments {
    /// Build the commitment tree over `shares`. The tree is padded to a power
    /// of two; padding leaves digest to zero bytes.
    pub fn new(shares: &[Share]) -> Self {
        let leaf_count = shares.len().max(1).next_power_of_two();
        let mut tree = vec![[0u8; 32]; leaf_count * 2];
        for (i, share) in shares.iter().enumerate() {
            tree[leaf_count + i] = leaf_digest(share);
        }
        for i in (1..leaf_count).rev() {
            tree[i] = node_digest(&tree[i << 1], &tree[i << 1 | 1]);
        }
        Self {
            root: tree[1],
            tree,
            leaf_count,
        }
    }

    /// The public commitment root; safe to publish on a channel.
    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }

    /// Merkle proof for the share with 1-based `share_index`, if present.
    pub fn proof(&self, share_index: u8) -> Option<MerkleProof> {
        if share_index == 0 {
            return None;
        }
        let leaf = share_index as usize - 1;
        if leaf >= self.leaf_count {
            return None;
        }
        let mut idx = self.leaf_count + leaf;
        let mut steps = Vec::with_capacity(usize::BITS as usize);
        while idx > 1 {
            steps.push(ProofStep {
                sibling: self.tree[idx ^ 1],
                current_is_left: idx & 1 == 0,
            });
            idx >>= 1;
        }
        Some(MerkleProof { steps })
    }

    /// Convenience: verify `share` against this tree's own root.
    pub fn verify_share(&self, share: &Share) -> bool {
        match self.proof(share.index) {
            Some(proof) => verify_share(share, &self.root, &proof),
            None => false,
        }
    }
}

// --- GF(2⁸) arithmetic, modulo x⁸ + x⁴ + x³ + x + 1 (0x11b) ---

fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    while b != 0 {
        if b & 1 == 1 {
            p ^= a;
        }
        let carry = a & 0x80 != 0;
        a <<= 1;
        if carry {
            a ^= 0x1B;
        }
        b >>= 1;
    }
    p
}

fn gf_pow(mut base: u8, mut exp: u64) -> u8 {
    let mut acc = 1u8;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = gf_mul(acc, base);
        }
        base = gf_mul(base, base);
        exp >>= 1;
    }
    acc
}

/// Multiplicative inverse via a^254 = a⁻¹ in GF(2⁸). Callers must not pass 0.
fn gf_inv(a: u8) -> u8 {
    debug_assert!(a != 0, "gf_inv(0) is undefined");
    gf_pow(a, 254)
}

fn leaf_digest(share: &Share) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([share.index]);
    h.update(&share.data);
    h.finalize().into()
}

fn node_digest(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random_bytes(n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        rand::rngs::OsRng.fill_bytes(&mut buf);
        buf
    }

    #[test]
    fn round_trip_2_of_3() {
        let secret = b"our thoughts stay ours";
        let r = split(secret, 2, 3).unwrap();
        assert_eq!(r.shares.len(), 3);

        // Any pair reconstructs.
        assert_eq!(combine(&[r.shares[0].clone(), r.shares[1].clone()], 2).unwrap(), secret);
        assert_eq!(combine(&[r.shares[1].clone(), r.shares[2].clone()], 2).unwrap(), secret);
        assert_eq!(combine(&[r.shares[0].clone(), r.shares[2].clone()], 2).unwrap(), secret);
        // All three also reconstruct.
        assert_eq!(combine(&r.shares.clone(), 2).unwrap(), secret);
    }

    #[test]
    fn insufficient_shares_rejected() {
        let secret = b"threshold guard";
        let r = split(secret, 3, 5).unwrap();
        let err = combine(&r.shares[..2], 3).unwrap_err();
        assert!(matches!(err, CryptoError::ShamirThreshold { required: 3, got: 2 }), "{err}");
    }

    #[test]
    fn invalid_parameters_rejected() {
        assert!(split(b"x", 1, 3).is_err());
        assert!(split(b"x", 4, 3).is_err());
        assert!(split(b"x", 2, 251).is_err());
    }

    #[test]
    fn all_commitments_verify() {
        let r = split(b"verifiable", 2, 4).unwrap();
        for share in &r.shares {
            assert!(r.commitments.verify_share(share), "share {} failed", share.index);
        }
    }

    #[test]
    fn tampered_share_fails_verification() {
        let r = split(b"tamper me", 2, 3).unwrap();
        let mut bad = r.shares[0].clone();
        bad.data[0] ^= 0xFF;
        assert!(!r.commitments.verify_share(&bad));
    }

    #[test]
    fn share_from_other_split_fails_verification() {
        let a = split(b"first payload", 2, 3).unwrap();
        let b = split(b"second payload", 2, 3).unwrap();
        // Same index, different split: leaf digest differs, proof cannot match.
        let mut foreign = b.shares[0].clone();
        foreign.index = a.shares[0].index;
        assert!(!a.commitments.verify_share(&foreign));
    }

    #[test]
    fn combine_order_independent() {
        let secret = b"order does not matter";
        let r = split(secret, 3, 5).unwrap();
        let mut reversed = r.shares.clone();
        reversed.reverse();
        assert_eq!(combine(&reversed, 3).unwrap(), secret);
    }

    #[test]
    fn indices_are_1_based_and_distinct() {
        let r = split(b"indices", 2, 6).unwrap();
        let mut seen = std::collections::HashSet::new();
        for share in &r.shares {
            assert!(share.index >= 1 && share.index <= 6);
            assert!(seen.insert(share.index));
        }
    }

    #[test]
    fn larger_payload_5_of_9() {
        let secret = random_bytes(1024);
        let r = split(&secret, 5, 9).unwrap();
        // Collect the five shares with odd indices — arbitrary subset.
        let subset: Vec<Share> = r
            .shares
            .iter()
            .filter(|s| s.index % 2 == 1)
            .take(5)
            .cloned()
            .collect();
        assert_eq!(combine(&subset, 5).unwrap(), secret);
    }
}
