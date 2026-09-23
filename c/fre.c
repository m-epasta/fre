#include "fre.h"

#include <string.h>

#include "sha256.h"

static const char FRE_TAG_FINGERPRINT[] = "fre:v1:fingerprint";
static const char FRE_TAG_ROTATE[] = "fre:v1:rotate";
static const char FRE_TAG_RATCHET[] = "fre:v1:ratchet";

static void le64_store(uint8_t out[8], uint64_t v) {
  int i;
  for (i = 0; i < 8; i++) {
    out[i] = (uint8_t)(v & 0xffu);
    v >>= 8;
  }
}

typedef struct {
  sha256_ctx inner;
  sha256_ctx outer;
} hmac_ctx;

static void hmac_begin(hmac_ctx *h, const uint8_t *key, size_t keylen) {
  uint8_t k0[64], hkey[32];
  size_t i;
  if (keylen > 64) {
    sha256_ctx t;
    sha256_init(&t);
    sha256_update(&t, key, keylen);
    sha256_final(&t, hkey);
    memcpy(k0, hkey, 32);
    memset(k0 + 32, 0, 32);
  } else {
    memcpy(k0, key, keylen);
    memset(k0 + keylen, 0, 64 - keylen);
  }
  for (i = 0; i < 64; i++) {
    k0[i] ^= 0x36;
  }
  sha256_init(&h->inner);
  sha256_update(&h->inner, k0, 64);
  for (i = 0; i < 64; i++) {
    k0[i] ^= 0x36 ^ 0x5c;
  }
  sha256_init(&h->outer);
  sha256_update(&h->outer, k0, 64);
}

static void hmac_update(hmac_ctx *h, const void *data, size_t len) {
  sha256_update(&h->inner, data, len);
}

static void hmac_end(hmac_ctx *h, uint8_t out[32]) {
  uint8_t ihash[32];
  sha256_final(&h->inner, ihash);
  sha256_update(&h->outer, ihash, 32);
  sha256_final(&h->outer, out);
}

void fre_fpr(const uint8_t s0[FRE_K], const uint8_t kr[FRE_K],
             uint8_t fpr[FRE_K]) {
  uint8_t key[2 * FRE_K];
  hmac_ctx h;
  memcpy(key, s0, FRE_K);
  memcpy(key + FRE_K, kr, FRE_K);
  hmac_begin(&h, key, 2 * FRE_K);
  hmac_update(&h, FRE_TAG_FINGERPRINT, sizeof(FRE_TAG_FINGERPRINT) - 1);
  hmac_end(&h, fpr);
}

void fre_rotate(const uint8_t sg[FRE_K], const uint8_t kg[FRE_K],
                const uint8_t fpr[FRE_K], uint64_t g, uint8_t next_sg[FRE_K],
                uint8_t next_kg[FRE_K]) {
  uint8_t le_g[8];
  uint8_t key[2 * FRE_K], kg_save[FRE_K];
  hmac_ctx h;
  le64_store(le_g, g);
  memcpy(kg_save, kg, FRE_K);
  memcpy(key, sg, FRE_K);
  memcpy(key + FRE_K, kg_save, FRE_K);

  hmac_begin(&h, key, 2 * FRE_K);
  hmac_update(&h, FRE_TAG_ROTATE, sizeof(FRE_TAG_ROTATE) - 1);
  hmac_update(&h, fpr, FRE_K);
  hmac_update(&h, le_g, 8);
  hmac_end(&h, next_sg);

  hmac_begin(&h, kg_save, FRE_K);
  hmac_update(&h, FRE_TAG_RATCHET, sizeof(FRE_TAG_RATCHET) - 1);
  hmac_update(&h, fpr, FRE_K);
  hmac_update(&h, le_g, 8);
  hmac_end(&h, next_kg);
}

void fre_hmac_sha256(const uint8_t *key, size_t keylen, const void *msg,
                     size_t msglen, uint8_t out[32]) {
  hmac_ctx h;
  hmac_begin(&h, key, keylen);
  hmac_update(&h, msg, msglen);
  hmac_end(&h, out);
}

size_t fre_out_len(size_t in_len) { return (in_len / FRE_B + 1) * 32; }

static void fre_pad_block(const uint8_t *input, size_t in_len, size_t i,
                          uint8_t block[FRE_B]) {
  size_t start = i * FRE_B, filled = 0;
  if (start < in_len) {
    size_t take = in_len - start;
    if (take > FRE_B) {
      take = FRE_B;
    }
    memcpy(block, input + start, take);
    filled = take;
  }
  if (filled < FRE_B) {
    block[filled] = 0x80;
    memset(block + filled + 1, 0, FRE_B - filled - 1);
  }
}

size_t fre_encode(const uint8_t *input, size_t in_len, const uint8_t sg[FRE_K],
                  const uint8_t fpr[FRE_K], uint64_t g, const uint8_t *ctx,
                  size_t ctx_len, uint8_t *out) {
  size_t blocks = in_len / FRE_B + 1;
  size_t key_len;
  uint8_t key[48 + FRE_CTX_MAX];
  uint8_t le_g[8], le_i[8], block[FRE_B];
  size_t i;
  if (ctx_len > FRE_CTX_MAX || (ctx == NULL && ctx_len > 0)) {
    return 0;
  }
  key_len = 48 + ctx_len;
  le64_store(le_g, g);
  memcpy(key, sg, FRE_K);
  memcpy(key + 32, le_g, 8);
  if (ctx_len) {
    memcpy(key + 48, ctx, ctx_len);
  }
  for (i = 0; i < blocks; i++) {
    hmac_ctx h;
    fre_pad_block(input, in_len, i, block);
    le64_store(le_i, (uint64_t)i);
    memcpy(key + 40, le_i, 8);
    hmac_begin(&h, key, key_len);
    hmac_update(&h, fpr, FRE_K);
    hmac_update(&h, block, FRE_B);
    hmac_end(&h, out + i * 32);
  }
  return blocks * 32;
}
