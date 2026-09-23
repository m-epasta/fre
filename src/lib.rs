//! FRE - Fast Rotating Encoding.
//!
//! Reference implementation of the spec in `README.md`.
//!
//! FRE is a keyed, self-rotating encoding: every seed `S_g` is derived from the
//! previous one, all devices sharing `S_0` produce byte-identical outputs, and
//! no secret (including `S_0`) makes reversing an output cheap.
//!
//! Caller owns the rotation: hold `S_g`, the per-generation rotation key `K_g`
//! and `g` yourself; `fpr`/`rotate`/`fre` are pure functions with no hidden
//! state. Rotating ratchets **both** the seed and the rotation key, so a
//! compromise of the key material at some generation exposes only later ones.
//! The exchanged root key `K_r` seeds `K_0`; keep `FPR` (and, until the chain
//! is ratified, `K_r`) next to the chain.
//!
//! # Example
//!
//! ```
//! use rust_fre::{fpr, fre, rotate};
//!
//! let mut s0 = [0u8; 32];
//! for (i, b) in s0.iter_mut().enumerate() {
//!     *b = i as u8;
//! }
//!
//! let kr = [0x2a; 32];                   // out-of-band exchanged root key
//! let f = fpr(&s0, &kr);
//! let (s1, _k1) = rotate(&s0, &kr, &f, 0); // next seed + ratcheted rotation key
//! assert_eq!(fre(b"nsc", &s1, &f, 1, b"").len(), 32);
//! ```
//!
//! # Security reminder
//!
//! FRE does not protect low-entropy payloads (reversal is `min(2^entropy, 2^λ)`)
//! and low-entropy reversal additionally requires the fingerprint `FPR`.
//! `S_0` together with `K_r` is the whole lock. Intercepting `S_g` alone
//! reveals no future seed: rotation needs the current rotation key `K_g`. See
//! the README security model.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Input block size in bytes (`B = 64` in the spec).
///
/// The output length of [`fre`] is `(input.len() / B + 1) * 32` bytes.
pub const B: usize = 64;

/// Size of every seed and of every output block in bytes (`k = 256` bits).
pub const K: usize = 32;

/// Maximum `ctx` length in bytes (`FRE_CTX_MAX` in the C port).
///
/// Each block's HMAC key is `S_g ‖ le64(g) ‖ le64(i) ‖ ctx`, so this keeps
/// key material and stack use bounded identically in both ports. [`fre`]
/// panics if `ctx.len() > CTX_MAX`; the C port returns `0` instead.
pub const CTX_MAX: usize = 64;

const TAG_FINGERPRINT: &[u8] = b"fre:v1:fingerprint";
const TAG_ROTATE: &[u8] = b"fre:v1:rotate";
const TAG_RATCHET: &[u8] = b"fre:v1:ratchet";

type HmacSha256 = Hmac<Sha256>;

fn mac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    m.update(msg);
    m.finalize().into_bytes().into()
}

/// Computes the fingerprint `FPR` for an initial seed and rotation key.
///
/// `FPR = HMAC-SHA-256(S_0 ‖ K_r, "fre:v1:fingerprint")`. It is constant for a
/// given `(S_0, K_r)`, secret as long as both are, and binds a chain to its
/// seed and its rotation key. It does not authorize rotation: advancing the
/// chain additionally requires `K_r` (see [`rotate`]). Neither secret alone
/// can reproduce `FPR`, so a leaked `S_0` reveals no fingerprint and no output
/// of any generation. Call once at init and keep it next to the chain.
///
/// # Arguments
///
/// * `s0`: the initial secret seed, MUST come from a CSPRNG with at least
///   `k` bits of entropy (R9).
/// * `kr`: the root rotation key `K_r`, established out of band between the
///   machines (R9′). It seeds `K_0` and `FPR` (see [`rotate`]). You SHOULD
///   erase it once the chain is up: after that, only the per-generation
///   `K_g` and the stored `FPR` are needed, and a future root leak can no
///   longer resurrect captured seeds.
///
/// # Returns
///
/// The 32-byte fingerprint `FPR`.
///
/// # Examples
///
/// ```
/// use rust_fre::fpr;
///
/// let s0 = [0u8; 32];
/// let kr = [0x2a; 32];
/// let f = fpr(&s0, &kr);
/// assert_eq!(f.len(), 32);
/// assert_eq!(f, fpr(&s0, &kr));       // deterministic
/// ```
pub fn fpr(s0: &[u8; 32], kr: &[u8; 32]) -> [u8; 32] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(s0);
    key[32..].copy_from_slice(kr);
    mac(&key, TAG_FINGERPRINT)
}

/// Advances the seed and rotation-key chains one generation.
///
/// Both chains ratchet together, so the two devices stay in lockstep with a
/// single call per generation:
///
/// `S_{g+1} = HMAC-SHA-256(S_g ‖ K_g, "fre:v1:rotate" ‖ FPR ‖ le64(g))`
///
/// `K_{g+1} = HMAC-SHA-256(K_g, "fre:v1:ratchet" ‖ FPR ‖ le64(g))`
///
/// Pure and side-effect free; the caller owns `S_g`, `K_g` and `g`. Both the
/// seed and the current rotation key are required: holding `S_g` alone (e.g.
/// an intercepted seed) reveals no future seed, and holding `K_g` alone is
/// useless without a seed. The ratchet gives the rotation gate the same
/// forward secrecy as the seed chain: holding the pair `(S_j, K_j)` exposes
/// only generations `≥ j`, never earlier ones, and a leaked `K_g` cannot be
/// turned into `K_{g'}` for `g' < g` or resurrect a seed captured before it
/// became current.
///
/// `K_0` is the exchanged root key `K_r` (secure key exchange, or any
/// authenticated out-of-band channel), which MUST have ≥ `k` bits of entropy.
/// It is used once to derive `K_0` and `FPR`; erasing it afterwards means a
/// root leak is no longer catastrophic (see [`fpr`]).
///
/// # Arguments
///
/// * `sg`: the current seed `S_g`.
/// * `kg`: the current rotation key `K_g` (pass `K_r` for generation `0`).
/// * `fpr`: the fingerprint, as returned by [`fpr`].
/// * `g`: the current generation counter. MUST NOT wrap: rotating at
///   `g == u64::MAX` would re-derive already-used generations on the next
///   call. Wrapping is physically unreachable for a real deployment (2^64
///   rotations), but it is a hard contract, not an accident to rely on.
///
/// # Returns
///
/// A `(S_{g+1}, K_{g+1})` pair. Advance with the same `(S_g, K_g)` pair and
/// the same `g` on every device to stay synchronized.
///
/// # Examples
///
/// ```
/// use rust_fre::{fpr, rotate};
///
/// let s0 = [0u8; 32];
/// let kr = [0x2a; 32];
/// let f = fpr(&s0, &kr);
/// let (s1, k1) = rotate(&s0, &kr, &f, 0);
/// let (s2, k2) = rotate(&s1, &k1, &f, 1);
/// assert_ne!(s1, s2);
/// assert_ne!(k1, k2);
/// ```
pub fn rotate(sg: &[u8; 32], kg: &[u8; 32], fpr: &[u8; 32], g: u64) -> ([u8; 32], [u8; 32]) {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(sg);
    key[32..].copy_from_slice(kg);

    let mut msg = Vec::with_capacity(TAG_ROTATE.len() + 32 + 8);
    msg.extend_from_slice(TAG_ROTATE);
    msg.extend_from_slice(fpr);
    msg.extend_from_slice(&g.to_le_bytes());
    let sg_next = mac(&key, &msg);

    let mut km = Vec::with_capacity(TAG_RATCHET.len() + 32 + 8);
    km.extend_from_slice(TAG_RATCHET);
    km.extend_from_slice(fpr);
    km.extend_from_slice(&g.to_le_bytes());
    let kg_next = mac(kg, &km);

    (sg_next, kg_next)
}

fn padded_block(input: &[u8], i: usize) -> [u8; B] {
    let mut block = [0u8; B];
    let start = i * B;
    let end = start + B;
    let filled = if end <= input.len() {
        block.copy_from_slice(&input[start..end]);
        B
    } else {
        let len = input.len().saturating_sub(start);
        block[..len].copy_from_slice(&input[start..]);
        block[len] = 0x80;
        len + 1
    };
    debug_assert!(filled <= B);
    block
}

/// Encodes `input` under seed `S_g`, generation `g`, and purpose tag `ctx`.
///
/// For every block `i` of `⌊input.len()/B⌋ + 1` (input padded with a `0x80`
/// terminator then `0x00` fill, see README):
///
/// `d_i = HMAC-SHA-256(S_g ‖ le64(g) ‖ le64(i) ‖ ctx, FPR ‖ block)`
///
/// The output is the concatenation of the per-block 32-byte `d_i`, so its
/// length is `(input.len() / B + 1) * 32` (never more than `⌈n/B⌉·32`).
///
/// # Arguments
///
/// * `input`: the bytes to encode. Any length, including empty.
/// * `sg`: the current seed `S_g`.
/// * `fpr`: the fingerprint, as returned by [`fpr`]. Required explicitly
///   because it is not recoverable from `S_g` for `g > 0` (R5).
/// * `g`: the current generation counter. Mixed into every block's key, so
///   outputs across generations differ (R6).
/// * `ctx`: a per-use domain separator (e.g. `b"nsc:relay"` vs `b"nsc:msg"`).
///   Empty is allowed, meaning "any purpose, no isolation". MUST be at most
///   [`CTX_MAX`] (64) bytes; panics otherwise (the C port returns `0`).
///
/// # Panics
///
/// Panics if `ctx.len() > `[`CTX_MAX`].
///
/// # Returns
///
/// A new `Vec<u8>` of `(input.len() / B + 1) * 32` bytes.
///
/// # Determinism
///
/// The same `(input, sg, fpr, g, ctx)` always yields the same output (R1).
///
/// # Security note
///
/// Low-entropy inputs are trivially reversible: the reversal cost is
/// `min(2^entropy(input), 2^λ)`. A 4-byte PIN reverses in ~`2^32` attempts
/// for anyone holding the fingerprint (and the seed), enumerating a candidate
/// requires being able to recompute the output, which needs `FPR`. Pad or
/// diversify small/guessable payloads before encoding. If both `S_g` and `K_g`
/// leak, every generation `≥ g` is exposed; `S_g` alone does not allow
/// rotation (see [`rotate`]).
///
/// # Examples
///
/// ```
/// use rust_fre::{fpr, fre};
///
/// let s0 = [0u8; 32];
/// let kr = [0x2a; 32];
/// let f = fpr(&s0, &kr);
/// let out = fre(b"nsc", &s0, &f, 0, b"");
/// assert_eq!(out.len(), 32);
/// assert_eq!(out, fre(b"nsc", &s0, &f, 0, b""));   // deterministic
/// assert_ne!(out, fre(b"nsc", &s0, &f, 0, b"other")); // ctx separates
/// ```
pub fn fre(input: &[u8], sg: &[u8; 32], fpr: &[u8; 32], g: u64, ctx: &[u8]) -> Vec<u8> {
    assert!(
        ctx.len() <= CTX_MAX,
        "ctx is {} bytes, must be <= CTX_MAX ({})",
        ctx.len(),
        CTX_MAX
    );
    let blocks = input.len() / B + 1;
    let mut out = Vec::with_capacity(blocks * 32);

    let mut key = vec![0u8; 32 + 8 + 8 + ctx.len()];
    key[..32].copy_from_slice(sg);
    key[32..40].copy_from_slice(&g.to_le_bytes());
    key[40..48].copy_from_slice(&0u64.to_le_bytes());
    key[48..].copy_from_slice(ctx);

    for i in 0..blocks {
        key[40..48].copy_from_slice(&(i as u64).to_le_bytes());
        let block = padded_block(input, i);
        let mut m = HmacSha256::new_from_slice(&key).expect("HMAC accepts keys of any length");
        m.update(fpr);
        m.update(&block);
        out.extend_from_slice(&m.finalize().into_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const S0: [u8; 32] = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    const KR: [u8; 32] = [0x2a; 32];

    fn fv(sg: &[u8; 32], g: u64, ctx: &[u8], input: &[u8]) -> [u8; 32] {
        let out = fre(input, sg, &fpr(&S0, &KR), g, ctx);
        assert_eq!(out.len(), 32);
        let v: [u8; 32] = out.try_into().unwrap();
        v
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let f = fpr(&S0, &KR);
        assert_eq!(f, fpr(&S0, &KR));
        assert_ne!(f, fpr(&[1u8; 32], &KR));
    }

    #[test]
    fn fingerprint_keyed_by_kr() {
        let kr2 = [0x2b; 32];
        let with_kr = fpr(&S0, &KR);
        let wrong_kr = fpr(&S0, &kr2);
        assert_ne!(with_kr, wrong_kr, "fingerprint must be keyed by K_r");
    }

    #[test]
    fn rotate_chain_consistent() {
        let f = fpr(&S0, &KR);
        let (s1, k1) = rotate(&S0, &KR, &f, 0);
        let (s2, k2) = rotate(&s1, &k1, &f, 1);
        let (s3, k3) = rotate(&s2, &k2, &f, 2);
        let (s1b, k1b) = rotate(&S0, &KR, &f, 0);
        assert_eq!((s1, k1), (s1b, k1b));
        assert_eq!(s2, rotate(&s1b, &k1b, &f, 1).0);
        assert_eq!(k2, rotate(&s1b, &k1b, &f, 1).1);
        assert_ne!((s1, k1), (s2, k2), "each generation advances both chains");
        assert_ne!((s2, k2), (s3, k3));
    }

    #[test]
    fn rotate_changes_per_generation() {
        let f = fpr(&S0, &KR);
        let (s1, _) = rotate(&S0, &KR, &f, 0);
        let (s1x, _) = rotate(&S0, &KR, &f, 1);
        assert_ne!(s1, s1x);
        let (_, k1) = rotate(&S0, &KR, &f, 0);
        let (_, k1x) = rotate(&S0, &KR, &f, 1);
        assert_ne!(k1, k1x);
    }

    #[test]
    fn ratchet_changes_and_is_one_way() {
        let f = fpr(&S0, &KR);
        let (s1, k1) = rotate(&S0, &KR, &f, 0);
        let (_, k2) = rotate(&s1, &k1, &f, 1);
        assert_ne!(KR, k1, "K_1 differs from the root key");
        assert_ne!(k1, k2, "every generation ratchets K forward");
    }

    #[test]
    fn rotate_requires_kr() {
        let f = fpr(&S0, &KR);
        let rotate_attempt = |kr: &[u8; 32]| rotate(&S0, kr, &f, 0);
        let (with_kr, _) = rotate_attempt(&KR);
        let (wrong_kr, kw) = rotate_attempt(&[0x2b; 32]);
        assert_ne!(with_kr, wrong_kr, "rotation must be keyed by K_r");
        assert_ne!(KR, kw, "ratchet must be keyed by K_r");
    }

    #[test]
    fn vector_rotate_chain_pins() {
        let f = fpr(&S0, &KR);
        let (s1, k1) = rotate(&S0, &KR, &f, 0);
        let (s2, k2) = rotate(&s1, &k1, &f, 1);
        let (mut s, mut k) = (S0, KR);
        for g in 0..42 {
            (s, k) = rotate(&s, &k, &f, g);
        }
        assert_eq!(
            hex::encode(s1),
            "56970be00fb8136159e66ffe0237481f3d78c9819fe5aa022254176a8e70a122"
        );
        assert_eq!(
            hex::encode(k1),
            "5b45c66c033725a0b94c3f7b5d006aedee67ab8c02f0abd7d0f684b2c251ea41"
        );
        assert_eq!(
            hex::encode(s2),
            "582805b9c9b98c13ad97d4548f9a7aa1026684f2f427671c7c4b2743bfa8f11c"
        );
        assert_eq!(
            hex::encode(k2),
            "5c1cd1b2a8a9115701e0b960f64a1ab60c646be933815dc8a9ce0dffc9318b1b"
        );
        assert_eq!(
            hex::encode(s),
            "3ae4d54f85f4dbd49e5251e208e0bcdcfeeeb19708aea5e894dfb1ed8fc44e75"
        );
        assert_eq!(
            hex::encode(k),
            "a0958ee52ba9841af473d3cd1aa439c94f76f19cb53795d067bfcfbec894ecca"
        );
    }

    #[test]
    fn single_block_shortcut() {
        assert_eq!(fre(b"nsc", &S0, &fpr(&S0, &KR), 0, b"").len(), 32);
        assert_eq!(fre(b"", &S0, &fpr(&S0, &KR), 0, b"").len(), 32);
        assert_eq!(fre(&[0u8; 63], &S0, &fpr(&S0, &KR), 0, b"").len(), 32);
    }

    #[test]
    fn padded_down_boundary() {
        let f = fpr(&S0, &KR);
        assert_eq!(fre(&[0u8; 63], &S0, &f, 0, b"").len(), 32);
        assert_eq!(fre(&[0u8; 64], &S0, &f, 0, b"").len(), 64);
        assert_eq!(fre(&[0u8; 65], &S0, &f, 0, b"").len(), 64);
        assert_eq!(fre(&[0u8; 128], &S0, &f, 0, b"").len(), 96);
    }

    #[test]
    fn distinct_trailing_zeros() {
        let f = fpr(&S0, &KR);
        let a = fre(b"a\0", &S0, &f, 0, b"");
        let b = fre(b"a\0\0", &S0, &f, 0, b"");
        assert_ne!(a, b);
    }

    #[test]
    fn full_block_does_not_collapse() {
        let f = fpr(&S0, &KR);
        let mut full = [0u8; B];
        full[0] = b'a';
        full[1] = 0x80;
        let short = fre(b"a", &S0, &f, 0, b"");
        let long = fre(&full, &S0, &f, 0, b"");
        assert_eq!(short.len(), 32);
        assert_eq!(long.len(), 64);
        assert_ne!(short, long);
    }

    #[test]
    fn ctx_separates_domains() {
        let f = fpr(&S0, &KR);
        let a = fre(b"payload", &S0, &f, 0, b"nsc:relay");
        let b = fre(b"payload", &S0, &f, 0, b"nsc:msg");
        assert_ne!(a, b);
    }

    #[test]
    fn generation_and_position_separate() {
        let f = fpr(&S0, &KR);
        let g0 = fre(&[0xabu8; 128], &S0, &f, 0, b"");
        let g1 = fre(&[0xabu8; 128], &S0, &f, 1, b"");
        assert_ne!(g0, g1);
        assert_ne!(fre(b"x", &S0, &f, 0, b""), fre(b"y", &S0, &f, 0, b""));
    }

    #[test]
    fn deterministic_double_call() {
        let f = fpr(&S0, &KR);
        let input = [7u8; 200];
        assert_eq!(
            fre(&input, &S0, &f, 5, b"nsc:msg"),
            fre(&input, &S0, &f, 5, b"nsc:msg")
        );
    }

    #[test]
    fn vector_g0_nsc_empty_ctx() {
        assert_eq!(
            hex::encode(fv(&S0, 0, b"", b"nsc")),
            "33b143a2e4e1f02bfca78024a34f00d71ff6fa9736af8fcd1c635026d64988ac"
        );
    }

    #[test]
    fn vector_g1_g42_nsc_empty_ctx() {
        let f = fpr(&S0, &KR);
        let (mut s, mut k) = (S0, KR);
        (s, k) = rotate(&s, &k, &f, 0);
        assert_eq!(
            hex::encode(fv(&s, 1, b"", b"nsc")),
            "9739e11076bae58ca80d7b8d505b7b612c84729079e1d04b081eb6cb34f65e10"
        );
        for g in 1..42 {
            (s, k) = rotate(&s, &k, &f, g);
        }
        assert_eq!(
            hex::encode(fv(&s, 42, b"", b"nsc")),
            "7a1ce5d36dd55f4e908be5b40fc099a6f59cca09b568b7e1b7043fc99810f27f"
        );
    }

    #[test]
    fn vector_g0_long_ctx_key_above_64() {
        // ctx = 40 bytes -> HMAC key = 48 + 40 = 88 > 64: exercises the
        // key-reduction branch (RFC 2104) that every other vector misses.
        let ctx = b"nsc:audit:long-context-vector-v1-pad-pad";
        assert_eq!(48 + ctx.len(), 88);
        assert_eq!(
            hex::encode(fv(&S0, 0, ctx, b"nsc")),
            "0cc816a3444e2746ce8c21a74f8ba11a205ff6e713f0a750fc26fa2bb9c2c7cd"
        );
    }

    #[test]
    fn vector_g0_ctx_at_max() {
        // Largest legal ctx: 64 bytes -> HMAC key = 112 bytes.
        let ctx = [b'x'; CTX_MAX];
        assert_eq!(
            hex::encode(fv(&S0, 0, &ctx, b"nsc")),
            "f57c98cb53c946e9cf1ec693f23d94d3b357d2574dd500bc8c1b9daca823c82c"
        );
    }

    #[test]
    #[should_panic(expected = "must be <= CTX_MAX")]
    fn ctx_above_max_panics() {
        let ctx = [0u8; CTX_MAX + 1];
        fre(b"nsc", &S0, &fpr(&S0, &KR), 0, &ctx);
    }

    #[test]
    fn vector_1kb_budget_ceiling() {
        let f = fpr(&S0, &KR);
        let input = vec![0x5au8; 1024];
        let start = std::time::Instant::now();
        let out = fre(&input, &S0, &f, 0, b"nsc:msg");
        let elapsed = start.elapsed();
        assert_eq!(out.len(), (1024 / B + 1) * 32);
        assert!(
            elapsed.as_millis() < 100,
            "1kB encode took {:?}, exceeds 100ms ceiling",
            elapsed
        );
    }
}
