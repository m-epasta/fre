/*
 * fre.h - FRE (Fast Rotating Encoding), C reference port.
 *
 * Dep-free C99 port of the spec in ../README.md. Matches the Rust reference
 * implementation byte-for-byte (vectors pinned in c/tests.c and README).
 *
 * API overview:
 *   fre_fpr         once, at init:  FPR from S_0 and K_r
 *   fre_rotate      advance seed + rotation-key chains one generation
 *   fre_out_len     size an output buffer for fre_encode
 *   fre_encode      the encoding itself (spec section 3)
 *   fre_hmac_sha256 the exact HMAC-SHA-256 primitive fre_encode uses, exposed
 *                   so ports can self-test against RFC 4231 conformance vectors
 *
 * Rotation is caller-owned: keep S_g, the per-generation rotation key K_g,
 * FPR and g yourself. All functions are pure and have no hidden state. Seeds
 * (32 bytes) MUST come from a CSPRNG (R9); FRE does not protect low-entropy
 * inputs. K_r is the out-of-band root rotation key, exchanged between the
 * machines at init (secure key exchange or any authenticated out-of-band
 * channel). It seeds K_0 and FPR; erase it once the chain is up. Rotating
 * ratchets BOTH S_g and K_g, and requires both: intercepting a seed alone
 * reveals no future one.
 *
 * HMAC-SHA-256 is provided by the vendored SHA-256 in sha256.c / sha256.h.
 */

#ifndef FRE_H
#define FRE_H

#include <stddef.h>
#include <stdint.h>

/* Seed and output-block size in bytes (k = 256 bits). */
#define FRE_K 32u

/* Input block size in bytes (B in the spec). */
#define FRE_B 64u

/*
 * FRE_CTX_MAX - maximum length in bytes of the purpose tag ctx.
 *
 * The HMAC key for each block is S_g || le64(g) || le64(i) || ctx (48 +
 * ctx_len bytes) and is held on the C stack, so ctx is bounded to keep that
 * frame fixed (112 bytes worst case) and portable: VLAs are optional in
 * C11 and removed in C23, and some toolchains (e.g. MSVC) never had them.
 * fre_encode returns 0 for ctx_len > FRE_CTX_MAX. The Rust reference
 * enforces the same bound (rust_fre::CTX_MAX, panics on violation).
 */
#define FRE_CTX_MAX 64u

/*
 * fre_fpr - compute the fingerprint FPR from the initial seed and rotation key.
 *
 *   FPR = HMAC-SHA-256(S_0 || K_r, "fre:v1:fingerprint")
 *
 * FPR is constant for a given (S_0, K_r) and secret while both are: it binds a
 * chain to its seed and its rotation key. It does not authorize rotation;
 * advancing the chain additionally requires the out-of-band rotation key K_r
 * (fre_rotate). Neither secret alone can reproduce FPR, so a leaked S_0
 * reveals no fingerprint and no output of any generation. Call once at init.
 *
 * s0  [in]  the initial seed, 32 bytes (FRE_K).
 * kr  [in]  the root rotation key K_r, 32 bytes, exchanged out of band (R9').
 *           Seeds K_0 and FPR; erase it once the chain is up.
 * fpr [out] the 32-byte fingerprint (may alias s0 or kr).
 */
void fre_fpr(const uint8_t s0[FRE_K], const uint8_t kr[FRE_K],
             uint8_t fpr[FRE_K]);

/*
 * fre_rotate - advance the seed AND rotation-key chains one generation.
 *
 *   S_{g+1} = HMAC-SHA-256(S_g || K_g, "fre:v1:rotate" || FPR || le64(g))
 *   K_{g+1} = HMAC-SHA-256(K_g,     "fre:v1:ratchet" || FPR || le64(g))
 *
 * g is the CURRENT generation; the results are S_{g+1} and K_{g+1}. Pure, no
 * side effects. Both S_g and K_g are required: intercepting a seed alone
 * reveals no future one. Pass K_r as K_g for generation 0. Every device must
 * call this exactly once per generation with the same (S_g, K_g, FPR, g) to
 * stay in lockstep. Each K_g is one-way, so compromising the pair (S_j, K_j)
 * exposes only generations >= j; erased earlier key material is unrecoverable.
 *
 * sg     [in]  the current seed S_g, 32 bytes.
 * kg     [in]  the current rotation key K_g, 32 bytes (K_r at generation 0).
 * fpr    [in]  the fingerprint from fre_fpr, 32 bytes.
 * g      [in]  current generation counter (u64, little-endian encoded).
 *               MUST NOT wrap: rotating at g = 2^64-1 would restart the
 *               counter and re-derive already-used generations.
 * next_sg [out] the next seed, 32 bytes (may alias sg or kg).
 * next_kg [out] the next rotation key, 32 bytes (may alias sg or kg).
 */
void fre_rotate(const uint8_t sg[FRE_K], const uint8_t kg[FRE_K],
                const uint8_t fpr[FRE_K], uint64_t g, uint8_t next_sg[FRE_K],
                uint8_t next_kg[FRE_K]);

/*
 * fre_hmac_sha256 - plain HMAC-SHA-256 over the port's own primitive.
 *
 * Exposed so conformance suites can pin the HMAC used inside fre_encode
 * directly against published vectors (RFC 4231), including the key-longer-
 * than-64-byte reduction path that fre_encode only reaches with
 * ctx_len > 16 (HMAC key = 48 + ctx_len > 64).
 *
 * key    [in]  HMAC key; any length (0..=64 is used verbatim, > 64 is
 *              SHA-256-reduced first per RFC 2104). NULL allowed when
 *              keylen is 0.
 * keylen [in]  key length in bytes.
 * msg    [in]  message; NULL allowed when msglen is 0.
 * msglen [in]  message length in bytes.
 * out    [out] 32-byte tag.
 */
void fre_hmac_sha256(const uint8_t *key, size_t keylen, const void *msg,
                     size_t msglen, uint8_t out[32]);

/*
 * fre_out_len - size of the output buffer needed by fre_encode.
 *
 * Input is padded with a 0x80 terminator even at an exact FRE_B boundary, so
 * the block count is in_len / FRE_B + 1 and the output is that times 32.
 *
 * in_len [in] input length in bytes.
 * returns the output length in bytes ((in_len / FRE_B + 1) * 32).
 */
size_t fre_out_len(size_t in_len);

/*
 * fre_encode - encode input under S_g, generation g and purpose tag ctx.
 *
 * Per block i: d_i = HMAC-SHA-256(S_g || le64(g) || le64(i) || ctx,
 *                                FPR || block)
 * where block is a FRE_B-byte slice of input padded with 0x80 then 0x00.
 * Output is the concatenation of the d_i.
 *
 * Blocks are written to out as they are produced; nothing is buffered.
 *
 * input   [in]  the bytes to encode; any length, empty is valid.
 * in_len  [in]  input length in bytes.
 * sg      [in]  current seed S_g, 32 bytes.
 * fpr     [in]  the fingerprint from fre_fpr, 32 bytes. Explicit because it
 *               is not recoverable from S_g for g > 0 (forward secrecy).
 * g       [in]  current generation counter.
 * ctx     [in]  purpose tag / domain separator; NULL is allowed only when
 *               ctx_len is 0. Empty ctx means "any purpose, no isolation".
 * ctx_len [in]  ctx length in bytes; MUST be <= FRE_CTX_MAX (64).
 * out     [out] buffer of at least fre_out_len(in_len) bytes. MUST NOT alias
 *               input.
 *
 * returns the number of bytes written (== fre_out_len(in_len)), or 0 if
 * ctx_len > FRE_CTX_MAX or ctx is NULL with ctx_len > 0 (out untouched).
 */
size_t fre_encode(const uint8_t *input, size_t in_len, const uint8_t sg[FRE_K],
                  const uint8_t fpr[FRE_K], uint64_t g, const uint8_t *ctx,
                  size_t ctx_len, uint8_t *out);

#endif /* FRE_H */