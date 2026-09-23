#include "sha256.h"

#include <string.h>

static const uint32_t SHA256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define SIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static uint32_t be32_load(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void be32_store(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

void sha256_init(sha256_ctx *ctx) {
  ctx->state[0] = 0x6a09e667u;
  ctx->state[1] = 0xbb67ae85u;
  ctx->state[2] = 0x3c6ef372u;
  ctx->state[3] = 0xa54ff53au;
  ctx->state[4] = 0x510e527fu;
  ctx->state[5] = 0x9b05688cu;
  ctx->state[6] = 0x1f83d9abu;
  ctx->state[7] = 0x5be0cd19u;
  ctx->count = 0;
}

static void sha256_block(uint32_t s[8], const uint8_t *p) {
  uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
  int i;
  for (i = 0; i < 16; i++) {
    w[i] = be32_load(p + 4 * i);
  }
  for (i = 16; i < 64; i++) {
    w[i] = SSIG1(w[i - 2]) + w[i - 7] + SSIG0(w[i - 15]) + w[i - 16];
  }
  a = s[0];
  b = s[1];
  c = s[2];
  d = s[3];
  e = s[4];
  f = s[5];
  g = s[6];
  h = s[7];
  for (i = 0; i < 64; i++) {
    t1 = h + SIG1(e) + CH(e, f, g) + SHA256_K[i] + w[i];
    t2 = SIG0(a) + MAJ(a, b, c);
    h = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = b;
    b = a;
    a = t1 + t2;
  }
  s[0] += a;
  s[1] += b;
  s[2] += c;
  s[3] += d;
  s[4] += e;
  s[5] += f;
  s[6] += g;
  s[7] += h;
}

void sha256_update(sha256_ctx *ctx, const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  if (len == 0) {
    return;
  }
  size_t have = (size_t)(ctx->count % 64);
  ctx->count += (uint64_t)len;
  if (have) {
    size_t need = 64 - have;
    if (len < need) {
      memcpy(ctx->buf + have, p, len);
      return;
    }
    memcpy(ctx->buf + have, p, need);
    sha256_block(ctx->state, ctx->buf);
    p += need;
    len -= need;
  }
  while (len >= 64) {
    sha256_block(ctx->state, p);
    p += 64;
    len -= 64;
  }
  if (len) {
    memcpy(ctx->buf, p, len);
  }
}

void sha256_final(sha256_ctx *ctx, uint8_t out[32]) {
  uint64_t bits = ctx->count * 8;
  uint8_t lenbuf[8], zero[64];
  size_t i, to_pad;
  for (i = 0; i < 8; i++) {
    lenbuf[i] = (uint8_t)(bits >> (56 - 8 * i));
  }
  sha256_update(ctx, "\x80", 1);
  to_pad = (56u - (size_t)(ctx->count % 64)) % 64;
  if (to_pad) {
    memset(zero, 0, sizeof(zero));
    sha256_update(ctx, zero, to_pad);
  }
  sha256_update(ctx, lenbuf, 8);
  for (i = 0; i < 8; i++) {
    be32_store(out + 4 * i, ctx->state[i]);
  }
}
