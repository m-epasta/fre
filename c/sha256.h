/*
 * sha256.h - SHA-256 (FIPS 180-4), vendored for the FRE C port.
 *
 * Streaming implementation used by the HMAC inside fre.c. Self-contained
 * (only <stddef.h>/<stdint.h>), intended to be portable to embedded targets.
 *
 * Usage:
 *   sha256_ctx c;
 *   sha256_init(&c);
 *   sha256_update(&c, data, len);   // call any number of times
 *   sha256_final(&c, out);          // writes the 32-byte digest
 *
 * The same ctx is single-use: after sha256_final it must be re-initialized
 * with sha256_init before reuse.
 */

#ifndef FRE_SHA256_H
#define FRE_SHA256_H

#include <stddef.h>
#include <stdint.h>

/* Incremental SHA-256 state; opaque to callers. */
typedef struct {
    uint32_t state[8];
    uint64_t count;
    uint8_t buf[64];
} sha256_ctx;

/*
 * sha256_init - start a new digest.
 *
 * ctx [in] context to initialize.
 */
void sha256_init(sha256_ctx *ctx);

/*
 * sha256_update - absorb bytes into the running digest.
 *
 * May be called any number of times (including with len == 0); data is
 * buffered until a full 64-byte block is available.
 *
 * ctx  [in] initialized context.
 * data [in] bytes to absorb; may be NULL when len == 0.
 * len  [in] number of bytes to absorb.
 */
void sha256_update(sha256_ctx *ctx, const void *data, size_t len);

/*
 * sha256_final - finish the digest and write the result.
 *
 * Appends the 0x80 padding, the 64-bit big-endian length, and writes the
 * 32-byte digest. The context is consumed; re-initialize before reuse.
 *
 * ctx [in]  initialized context with all input absorbed via sha256_update.
 * out [out] 32-byte digest buffer.
 */
void sha256_final(sha256_ctx *ctx, uint8_t out[32]);

#endif /* FRE_SHA256_H */