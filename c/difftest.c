/*
 * difftest.c - differential harness between the C port and the Rust reference.
 *
 * Reads lines of the form
 *
 *   g,input_hex,ctx_hex,out_hex
 *
 * produced by `cargo run --release --example difftest` (see ../examples/
 * difftest.rs). For every case it derives FPR once, ratchets the two chains
 * from (S_0, K_r) to generation g, re-encodes the input with fre_encode, and
 * compares byte-for-byte against out_hex. Any mismatch or length anomaly
 * exits non-zero with diagnostics.
 *
 * Uses the same pinned test constants as c/tests.c and the vectors in the
 * README, so this doubles as a chain-agreement check: if the Rust and C
 * rotations ever diverge at some generation, every encode at or past it
 * mismatches here.
 */

#define _POSIX_C_SOURCE 200809L /* getline / ssize_t under -std=c99 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fre.h"

static const uint8_t S0[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                               0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static const uint8_t KR[32] = {0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a,
                               0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a,
                               0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a,
                               0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a};

static int hexval(int c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static size_t decode_hex(const char *s, uint8_t **out) {
  size_t len = strlen(s), bytes, i;
  uint8_t *buf;
  if (len % 2) {
    fprintf(stderr, "difftest: odd hex length in field '%s'\n", s);
    exit(3);
  }
  bytes = len / 2;
  buf = malloc(bytes ? bytes : 1);
  if (!buf) {
    fprintf(stderr, "difftest: out of memory\n");
    exit(3);
  }
  for (i = 0; i < bytes; i++) {
    int hi = hexval((unsigned char)s[2 * i]);
    int lo = hexval((unsigned char)s[2 * i + 1]);
    if (hi < 0 || lo < 0) {
      fprintf(stderr, "difftest: bad hex in field '%.64s'\n", s);
      exit(3);
    }
    buf[i] = (uint8_t)((hi << 4) | lo);
  }
  *out = buf;
  return bytes;
}

static void to_hex(const uint8_t *b, size_t n, char *out) {
  static const char d[] = "0123456789abcdef";
  size_t i;
  for (i = 0; i < n; i++) {
    out[2 * i] = d[b[i] >> 4];
    out[2 * i + 1] = d[b[i] & 0x0f];
  }
  out[2 * n] = 0;
}

int main(void) {
  char *line = NULL;
  size_t cap = 0;
  ssize_t n;
  uint8_t fpr[32];
  uint64_t cases = 0;

  fre_fpr(S0, KR, fpr);

  while ((n = getline(&line, &cap, stdin)) >= 0) {
    uint64_t g;
    char *g_str, *in_hex, *ctx_hex, *out_hex, *c1, *c2, *c3;
    uint8_t *in = NULL, *c = NULL, *outb = NULL, *got;
    size_t in_len, ctx_len, out_len, expect, got_n;
    uint8_t sg[32], kg[32];
    char *got_hex;
    uint64_t gi;

    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
      line[--n] = 0;
    }
    if (n == 0) {
      continue;
    }

    g_str = line;
    c1 = strchr(line, ',');
    if (!c1) {
      fprintf(stderr, "difftest: no generation field\n");
      return 2;
    }
    *c1 = 0;
    in_hex = c1 + 1;
    c2 = strchr(in_hex, ',');
    if (!c2) {
      fprintf(stderr, "difftest: no input field\n");
      return 2;
    }
    *c2 = 0;
    ctx_hex = c2 + 1;
    c3 = strchr(ctx_hex, ',');
    if (!c3) {
      fprintf(stderr, "difftest: no ctx field\n");
      return 2;
    }
    *c3 = 0;
    out_hex = c3 + 1;

    g = strtoull(g_str, NULL, 10);
    in_len = decode_hex(in_hex, &in);
    ctx_len = decode_hex(ctx_hex, &c);
    out_len = decode_hex(out_hex, &outb);
    if (ctx_len > FRE_CTX_MAX) {
      fprintf(stderr, "difftest: ctx_len %zu exceeds FRE_CTX_MAX\n", ctx_len);
      return 2;
    }

    memcpy(sg, S0, 32);
    memcpy(kg, KR, 32);
    for (gi = 0; gi < g; gi++) {
      fre_rotate(sg, kg, fpr, gi, sg, kg);
    }

    expect = fre_out_len(in_len);
    if (expect != out_len) {
      fprintf(stderr,
              "difftest: case %llu g=%llu in_len=%zu: C output length %zu "
              "!= Rust output length %zu\n",
              (unsigned long long)cases, (unsigned long long)g, in_len, expect,
              out_len);
      return 1;
    }

    got = malloc(expect ? expect : 1);
    if (!got) {
      fprintf(stderr, "difftest: out of memory\n");
      return 3;
    }
    got_n = fre_encode(in, in_len, sg, fpr, (uint64_t)g,
                       ctx_len ? c : NULL, ctx_len, got);
    if (got_n != expect) {
      fprintf(stderr, "difftest: case %llu: fre_encode returned %zu, want %zu\n",
              (unsigned long long)cases, got_n, expect);
      return 1;
    }

    got_hex = malloc(expect * 2 + 1);
    if (!got_hex) {
      fprintf(stderr, "difftest: out of memory\n");
      return 3;
    }
    to_hex(got, expect, got_hex);
    if (strcmp(got_hex, out_hex) != 0) {
      fprintf(stderr,
              "MISMATCH case %llu: g=%llu in_len=%zu ctx_len=%zu\n"
              "  rust out_hex = %.80s...\n"
              "  c    out_hex = %.80s...\n",
              (unsigned long long)cases, (unsigned long long)g, in_len,
              ctx_len, out_hex, got_hex);
      return 1;
    }

    cases++;
    free(in);
    free(c);
    free(outb);
    free(got);
    free(got_hex);
  }

  free(line);
  printf("difftest: %llu cases OK\n", (unsigned long long)cases);
  return 0;
}