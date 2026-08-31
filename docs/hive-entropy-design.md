# KDX Hive Entropy Design — a "nodeless" swarm that keeps data ours

> **The one-liner:** every node contributes a piece of randomness so that the
> whole never holds a key, and every secret is cut into pieces so that no part
> ever looks like one. Zero-knowledge proofs decide *who may touch the pieces*;
> Shamir + distributed key generation decide *why the pieces are safe to touch*.

Status: **design v1 / Slice 1 implemented** (`crates/kdx-crypto/src/shamir.rs`).
This document is the architecture note; the roadmap at the end tracks what is
built vs. designed.

---

## 1. Goals and threat model

The properties we want, in the order a hostile operator would attack them:

| # | Property | Meaning |
|---|----------|---------|
| P1 | **No single point** | No node, server, or daemon holds a key or a complete record. Nothing worth stealing lives in one place. |
| P2 | **Looks like noise** | Any fragment a stranger obtains is information-theoretically useless — it is *actually* incomplete. |
| P3 | **Infiltration-resistant** | A stranger cannot gain access (prove-less), and a *compromised member* cannot poison shares, mint membership, or steer entropy. |
| P4 | **Data sovereignty** | Our conversations/records are encrypted end-to-end; relays are oblivious; storage is verifiable; deletion is provable. Brokers cannot copy what they cannot read. |
| P5 | **Trusted-source sharing** | Sharing is capability-based and tied to recipient credentials — "trusted" is an auditable fact, not a claim. |

Adversaries covered: (a) the **stranger** — no credential, tries to join or read;
(b) the **infiltrator** — a node that was admitted (or cloned a credential) and
then acts maliciously; (c) the **compromised relay/server** — wants to harvest
content or metadata; (d) the **data broker** — a legal operator of a relay that
quietly copies "anonymized" data.

---

## 2. Part one: the secret is noise — Shamir t-of-n splitting

**Mechanism.** Every payload is split into **n shares** using a degree `t-1`
polynomial over a finite field (Shamir secret sharing). Share *i* is the point
`(xᵢ, f(xᵢ))` with `f(0) = secret`.

- **"Looks discombobulated and incomplete" is true by construction.** Fewer
  than `t` points determine *no* polynomial: every candidate secret is equally
  consistent with them. This is information-theoretic — a stolen share leaks
  strictly nothing, not even "a bit less than the plaintext."
- **"While it definitely is not"** — any `t` distinct shares reconstruct the
  secret exactly via Lagrange interpolation in microseconds.

**Rules we enforce (Slice 1):**

- `t ≥ 2` (1-of-n has no secrecy), `t ≤ n ≤ 250`, indices are `1..=n`.
- Field: GF(2⁸) with the AES polynomial `0x11b` (byte-oriented, dependency-free).
- Every share is covered by a **Merkle commitment** published by the dealer, so
  any holder (or auditor) can prove *its* share is exactly the one committed —
  tamper-evidence against corrupted relays and infiltrators modifying shares in
  flight. See `Commitments::new / proof / verify_share`.

**Slice 2 upgrade — Feldman verifiable secret sharing.** Hash commitments prove
a share is *unmodified*; they do not prove the dealer gave each node a point
*on the same* polynomial. Feldman VSS adds public coefficient commitments
`Cₖ = g^{aₖ}`; each holder checks `g^{f(xᵢ)} = ∏ Cₖ^{xᵢᵏ}` without revealing its
share. This is the piece that makes "infiltrator feeds garbage shares and poisons
reconstruction" fail: a bad share is detected *before* reconstruction. Requires
a prime-order group (BLS12-381 G1 — planned dependency for Slice 2).

**Do not confuse secrecy with availability.** Shamir gives secrecy +
recoverability at threshold `t`. Reed–Solomon erasure coding gives availability
at any `k` but **no secrecy**. If nodes must die without losing data, layer RS
on top of *ciphertext*, never instead of Shamir.

---

## 3. Part two: the hive has no key — DKG + threshold BLS

"Nodeless" does not mean no cryptography; it means **the master secret never
exists in one place — not during setup, not during signing**.

- **Distributed key generation (DKG).** The swarm runs a one-time protocol where
  every node contributes a random polynomial; the *sum* is a joint key that no
  node ever sees assembled. Each node holds only its own share. There is no
  "creator" who can reconstruct the hive key alone.
- **Entropy from everyone.** Each contribution is additive, so **one honest
  contributor suffices** to make the joint key and the epoch beacon
  unpredictable: an attacker must corrupt *all* contributors (or be the last
  one) to steer it. This is the rigorous form of "all nodes contribute to the
  entropy."
- **Threshold BLS signatures.** Nodes sign routing announcements, admission
  tickets, and epoch beacons by producing signature *shares*; `t` of them
  combine into a valid group signature. The group key never touches a single
  process. (Rust: `blst`/`bls12_381`; FROST for Schnorr-based groups.)
- **Randomness beacon.** Each epoch, nodes commit to random values, reveal, and
  combine (hash of the concatenation, or a threshold BLS signature over the
  epoch number). The result is fresh, public, unpredictable-before-reveal
  entropy that drives re-keying, share re-layout, and routing rotation.

**Proactive secret sharing.** Re-randomize the shares every epoch so that
shares stolen "old" become worthless: the joint key is unchanged but the share
set is fresh. Combined with the beacon, this is how a hive self-heals after a
member leaves or is expelled.

---

## 4. Part three: the hive's nervous system — gossip, no leaders

- **Gossip membership.** Every node knows a few peers; membership changes
  propagate epidemic-style. No registry, no central directory, no choke point to
  poison.
- **Quorum decisions, not leaders.** Admission, re-sharing, and revocation go
  through t-of-n threshold signatures. Compromising `t-1` nodes changes nothing.
- **BFT for active adversaries.** Threshold signatures assume honest
  *share-holders*; a node that *lies or forges* needs Byzantine fault tolerance
  (HotStuff/HBFT-style consensus) on top. Heavy — deferred to a later slice, but
  it is the difference between "safe from passive compromise" and "safe from
  active infiltration."
- **Share shuffling.** The beacon picks a fresh layout; nodes re-slice and
  re-distribute. No node retains the same fragment long enough to matter, and
  the layout is never stored — it is re-derived from the beacon.

---

## 5. Locking it to the zero-knowledge layer

ZKP is the access gate in front of all of the above (see
`convergence-analysis.md` context / the handshake design):

- **Admission = anonymous credential (BBS+/CL).** A node proves possession of a
  threshold-issued credential with the right attributes ("peer in channel X")
  *without revealing which credential or any identity*. Unlinkable, non-replayable
  (bound to a fresh challenge), and revocable without revealing who was revoked.
- **Share custody is accountable.** Merkle roots over share commitments let any
  node verify the hive is storing *something coherent* without learning what;
  Feldman (Slice 2) adds per-share polynomial proofs; deletion proofs let a node
  prove it dropped its share.

---

## 6. Protocol flows

### Flow A — admission (threshold-issued credential)

```
Applicant ──> t existing members (gossip):  "join request for channel X"
Members   ──> threshold sign an admission ticket (t-of-n BLS)
Applicant ──> receives credential attributes {channel, role, issued_at}
             (blinded issuance: members never learn the applicant's id)
```

### Flow B — hive join (ZKP of membership)

```
Applicant ──> relay:  proof of credential possession + selective disclosure
Relay     ──> challenges with fresh nonce (binds the proof; kills replay)
Relay     ──> issues share-layout ticket for the epoch (beacon-derived)
Node      ──> enters gossip; starts receiving its share assignments
```

### Flow C — store (split → commit → distribute → verify)

```
Client  split(payload, t, n)          → n shares + Merkle root
Client  distribute(share_i → node_i)  via oblivious relay (sealed)
Client  publish root to channel (signed, gossip)
Node_i  verify_share(share_i, root)   → stores only its share
```

### Flow D — retrieve (collect t → verify → combine)

```
Client  asks t neighbors for shares (each returns ciphertext share + proof path)
Client  verify each share against the channel root
Client  combine(t shares) → payload   (zeroize intermediates)
```

### Flow E — epoch re-share (beacon-driven proactive re-sharing)

```
Beacon  → fresh epoch randomness
Nodes   → re-slice holdings; new Feldman commitments; old shares expire
        → any t of the *new* share set reconstructs the same payload
```

---

## 7. Honest limits

1. **Threshold ≠ unanimous.** `t` colluding nodes *can* reconstruct. Tune `t`
   high (e.g., 3-of-5 across your own devices + trusted peers) and prefer a
   **closed hive**: an open swarm is only as safe as its admission rules.
2. **Metadata still leaks** at the mesh layer without oblivious routing / cover
   traffic. Entropy hides *content*; only onion-style relays (Sphinx/Nym) hide
   *who talks to whom*. The relay must be a sealed dumb pipe — no plaintext, no
   long-term logs, no cross-session correlation.
3. **Liveness.** Losing `t-1` shares kills recoverability. Match `t` to your
   real device count; add erasure coding *above* encryption for redundancy.

---

## 8. Mapping to crates and roadmap

| Slice | Scope | Where | Status |
|-------|-------|-------|--------|
| 1 | Shamir t-of-n split/combine, GF(2⁸), Merkle-verified shares | `kdx-crypto/src/shamir.rs` | ✅ implemented |
| 2 | Feldman VSS (BLS12-381) + per-share polynomial proofs | `kdx-crypto` | designed |
| 3 | DKG + threshold BLS signing (`blst`) | `kdx-crypto` / `kdxd` | designed |
| 4 | Epoch beacon + proactive re-sharing + share shuffling | `kdxd` | designed |
| 5 | Oblivious sealed relay (no logging, no correlation) | `kdxd` / `kdx-server-core` | designed |
| 6 | Anonymous credential admission (BBS+) bound to share tickets | `kdx-crypto` / `kdx-protocol` | designed |
| 7 | Verifiable storage + deletion proofs | `kdx-storage` | designed |

Crate-level notes:

- **`kdx-crypto`** — today: argon2id + challenge-response (credentials at rest,
  wire auth). Adds: field arithmetic + Shamir (done), then groups, VSS, DKG,
  threshold BLS, anonymous credentials.
- **`kdx-protocol`** — add share-transfer / share-verification frames and a
  nonce-bound challenge handshake carrying ZKP-of-membership (not raw keys).
- **`kdxd`** — daemon becomes a hive peer: gossip membership, share custody,
  beacon participation.
- **`kdx-storage`** — encrypted records split into verifiable shares; Merkle
  commitment chain; deletion proofs.

---

## 9. Reference

- Prototype: `crates/kdx-crypto/src/shamir.rs` (Slice 1).
- Handshake/credential context: `docs/convergence-analysis.md`.
- Threat framing: conversation notes on ZKP access control + data sovereignty
  (Part one/Part two of this series).
