#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fre.h"
#include "sha256.h"

static const uint8_t S0[32] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                               0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                               0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                               0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

static const uint8_t KR[32] = {0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a,
                               0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a,
                               0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a,
                               0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a, 0x2a};

static int failures = 0;

static int hexval(int c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

static int expect_hex(const uint8_t *got, size_t got_len, const char *want) {
  size_t i;
  if (strlen(want) != got_len * 2) {
    printf("FAIL: length mismatch (want %zu hex chars, got %zu bytes)\n",
           strlen(want), got_len);
    failures++;
    return 0;
  }
  for (i = 0; i < got_len; i++) {
    int hi = hexval((unsigned char)want[2 * i]);
    int lo = hexval((unsigned char)want[2 * i + 1]);
    if (hi < 0 || lo < 0 || ((hi << 4) | lo) != got[i]) {
      printf("FAIL at byte %zu\n", i);
      failures++;
      return 0;
    }
  }
  return 1;
}

static void test_sha256(void) {
  uint8_t out[32];
  sha256_ctx c;
  sha256_init(&c);
  sha256_final(&c, out);
  expect_hex(
      out, 32,
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

  sha256_init(&c);
  sha256_update(&c, "abc", 3);
  sha256_final(&c, out);
  expect_hex(
      out, 32,
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

  sha256_init(&c);
  sha256_update(&c, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                56);
  sha256_final(&c, out);
  expect_hex(
      out, 32,
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");

  printf("sha256 fips vectors\n");
}

static void test_basic(void) {
  uint8_t fpr[32];
  uint8_t s1[32], s2[32], s42[32];
  uint8_t k1[32], k2[32], k42[32];
  size_t i;

  fre_fpr(S0, KR, fpr);
  expect_hex(
      fpr, 32,
      "7d7a69ef67ec88e50dddb455359bc87642b537ee3ba8e91866667690c7028676");
  printf("fpr(S_0, K_r)\n");

  fre_rotate(S0, KR, fpr, 0, s1, k1);
  expect_hex(
      s1, 32,
      "56970be00fb8136159e66ffe0237481f3d78c9819fe5aa022254176a8e70a122");
  expect_hex(
      k1, 32,
      "5b45c66c033725a0b94c3f7b5d006aedee67ab8c02f0abd7d0f684b2c251ea41");
  fre_rotate(s1, k1, fpr, 1, s2, k2);
  expect_hex(
      s2, 32,
      "582805b9c9b98c13ad97d4548f9a7aa1026684f2f427671c7c4b2743bfa8f11c");
  expect_hex(
      k2, 32,
      "5c1cd1b2a8a9115701e0b960f64a1ab60c646be933815dc8a9ce0dffc9318b1b");
  memcpy(s42, S0, 32);
  memcpy(k42, KR, 32);
  for (i = 0; i < 42; i++) {
    fre_rotate(s42, k42, fpr, (uint64_t)i, s42, k42);
  }
  expect_hex(
      s42, 32,
      "3ae4d54f85f4dbd49e5251e208e0bcdcfeeeb19708aea5e894dfb1ed8fc44e75");
  expect_hex(
      k42, 32,
      "a0958ee52ba9841af473d3cd1aa439c94f76f19cb53795d067bfcfbec894ecca");
  printf("rotate chain S_1/K_1, S_2/K_2, S_42/K_42\n");

  {
    uint8_t other_s[32], other_k[32], wrong_kr[32];
    memset(wrong_kr, 0x2b, 32);
    fre_rotate(S0, wrong_kr, fpr, 0, other_s, other_k);
    if (memcmp(other_s, s1, 32) == 0) {
      printf("FAIL: rotation must be keyed by K_r\n");
      failures++;
    }
    if (memcmp(other_k, k1, 32) == 0) {
      printf("FAIL: ratchet must be keyed by K_r\n");
      failures++;
    }
  }
  printf("rotate keyed by K_r\n");

  {
    uint8_t a_s[32], a_k[32];
    uint8_t aliased_s[32], aliased_k[32];
    memcpy(aliased_s, S0, 32);
    memcpy(aliased_k, KR, 32);
    fre_rotate(aliased_s, aliased_k, fpr, 0, aliased_s, aliased_k);
    fre_rotate(S0, KR, fpr, 0, a_s, a_k);
    if (memcmp(aliased_s, a_s, 32) || memcmp(aliased_k, a_k, 32)) {
      printf("FAIL: in-place rotation disagrees with fresh buffers\n");
      failures++;
    }
  }
  printf("rotate in-place aliasing\n");
}

static void test_hmac_rfc4231(void) {
  uint8_t key[131], data[160], tag[32];
  size_t i;

  /* Case 1: key 20x0b, data "Hi There" (key < 64). */
  memset(key, 0x0b, 20);
  fre_hmac_sha256(key, 20, "Hi There", 8, tag);
  expect_hex(
      tag, 32,
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");

  /* Case 2: key "Jefe", short key + printable data. */
  fre_hmac_sha256((const uint8_t *)"Jefe", 4,
                  "what do ya want for nothing?", 28, tag);
  expect_hex(
      tag, 32,
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");

  /* Case 3: combined key+data > 64 (multi-block message). */
  memset(key, 0xaa, 20);
  memset(data, 0xdd, 50);
  fre_hmac_sha256(key, 20, data, 50, tag);
  expect_hex(
      tag, 32,
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");

  /* Case 4: key+data > 64, structured key 01..19. */
  for (i = 0; i < 25; i++) {
    key[i] = (uint8_t)(i + 1);
  }
  memset(data, 0xcd, 50);
  fre_hmac_sha256(key, 25, data, 50, tag);
  expect_hex(
      tag, 32,
      "82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");

  /* Case 5: RFC truncates to 128 bits; check the first 16 bytes. */
  memset(key, 0x0c, 20);
  fre_hmac_sha256(key, 20, "Test With Truncation", 20, tag);
  {
    static const uint8_t want16[16] = {0xa3, 0xb6, 0x16, 0x74, 0x73, 0x10,
                                       0x0e, 0xe0, 0x6e, 0x0c, 0x79, 0x6c,
                                       0x29, 0x55, 0x55, 0x2b};
    if (memcmp(tag, want16, 16) != 0) {
      printf("FAIL: rfc4231 case 5 (128-bit truncation)\n");
      failures++;
    }
  }

  /* Case 6: 131-byte key (> 64) -> SHA-256 reduction branch, never before
   * reachable from fre_encode without ctx_len > 16. */
  memset(key, 0xaa, 131);
  fre_hmac_sha256(
      key, 131,
      "Test Using Larger Than Block-Size Key - Hash Key First", 54, tag);
  expect_hex(
      tag, 32,
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54");

  /* Case 7: 131-byte key AND 160-byte data (both > 64). */
  {
    static const char c7[] =
        "This is a test using a larger than block-size key and a larger "
        "than block-size data. The key needs to be hashed before being "
        "used by the HMAC algorithm.";
    fre_hmac_sha256(key, 131, c7, sizeof(c7) - 1, tag);
    expect_hex(
        tag, 32,
        "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2");
  }
  printf("hmac rfc 4231 vectors (cases 1-7)\n");
}

static void test_encode(void) {
  uint8_t fpr[32];
  uint8_t sg[32], kg[32], out[512];
  size_t n;
  size_t i;

  fre_fpr(S0, KR, fpr);

  n = fre_encode((const uint8_t *)"nsc", 3, S0, fpr, 0, (const uint8_t *)"", 0,
                 out);
  if (n != 32)
    failures++;
  expect_hex(
      out, n,
      "33b143a2e4e1f02bfca78024a34f00d71ff6fa9736af8fcd1c635026d64988ac");
  printf("encode \"nsc\" g=0 ctx=\"\"\n");

  fre_rotate(S0, KR, fpr, 0, sg, kg);
  n = fre_encode((const uint8_t *)"nsc", 3, sg, fpr, 1, (const uint8_t *)"", 0,
                 out);
  if (n != 32)
    failures++;
  expect_hex(
      out, n,
      "9739e11076bae58ca80d7b8d505b7b612c84729079e1d04b081eb6cb34f65e10");
  printf("encode \"nsc\" g=1 ctx=\"\"\n");

  for (int g = 1; g < 42; g++) {
    fre_rotate(sg, kg, fpr, (uint64_t)g, sg, kg);
  }
  n = fre_encode((const uint8_t *)"nsc", 3, sg, fpr, 42, (const uint8_t *)"", 0,
                 out);
  if (n != 32)
    failures++;
  expect_hex(
      out, n,
      "7a1ce5d36dd55f4e908be5b40fc099a6f59cca09b568b7e1b7043fc99810f27f");
  printf("encode \"nsc\" g=42 ctx=\"\"\n");

  n = fre_encode((const uint8_t *)"", 0, sg, fpr, 42,
                 (const uint8_t *)"nsc:relay", 9, out);
  if (n != 32)
    failures++;
  expect_hex(
      out, n,
      "e5971d59ed5156e1cec9e74c7e971588082527fc92bae7eedd16b85501429672");
  printf("encode \"\" g=42 ctx=\"nsc:relay\"\n");

  n = fre_encode((const uint8_t *)"nsc", 3, S0, fpr, 0,
                 (const uint8_t *)"nsc:relay", 9, out);
  if (n != 32)
    failures++;
  expect_hex(
      out, n,
      "a53393e090066281662f106f7dd5dc5f86755b36671b9de1d3bc4f0f4db5ef31");
  printf("encode \"nsc\" g=0 ctx=\"nsc:relay\"\n");

  n = fre_encode((const uint8_t *)"nsc", 3, S0, fpr, 0,
                 (const uint8_t *)"nsc:msg", 7, out);
  if (n != 32)
    failures++;
  expect_hex(
      out, n,
      "b005df527f3c821de3bebb4fd683f815c2b7643ddf9265989eea9e0d5cd2c86f");
  printf("encode \"nsc\" g=0 ctx=\"nsc:msg\"\n");

  n = fre_encode((const uint8_t *)"", 0, S0, fpr, 0, (const uint8_t *)"", 0,
                 out);
  if (n != 32)
    failures++;
  expect_hex(
      out, n,
      "c261e1f9f214eba416fd00407ed5e60a9b270005c09c6827ddfb39ffadd54cab");
  printf("encode \"\" g=0 ctx=\"\"\n");

  n = fre_encode((const uint8_t *)"nsc", 3, S0, fpr, 0, NULL, 0, out);
  if (n != 32)
    failures++;
  expect_hex(out, n,
             "33b143a2e4e1f02bfca78024a34f00d71ff6fa9736af8fcd1c635026d64988ac");
  printf("encode \"nsc\" g=0 ctx=NULL (len 0)\n");

  /* Long ctx: 40 bytes -> HMAC key 88 > 64 (RFC 2104 reduction branch). */
  n = fre_encode((const uint8_t *)"nsc", 3, S0, fpr, 0,
                 (const uint8_t *)"nsc:audit:long-context-vector-v1-pad-pad",
                 40, out);
  if (n != 32)
    failures++;
  expect_hex(
      out, n,
      "0cc816a3444e2746ce8c21a74f8ba11a205ff6e713f0a750fc26fa2bb9c2c7cd");
  printf("encode \"nsc\" g=0 ctx=40 bytes (key 88 > 64)\n");

  /* ctx at FRE_CTX_MAX: 64 bytes -> HMAC key 112. */
  {
    char ctx64[64];
    memset(ctx64, 'x', sizeof(ctx64));
    n = fre_encode((const uint8_t *)"nsc", 3, S0, fpr, 0,
                   (const uint8_t *)ctx64, 64, out);
    if (n != 32)
      failures++;
    expect_hex(
        out, n,
        "f57c98cb53c946e9cf1ec693f23d94d3b357d2574dd500bc8c1b9daca823c82c");
  }
  printf("encode \"nsc\" g=0 ctx=64 bytes (FRE_CTX_MAX)\n");

  /* ctx above FRE_CTX_MAX: rejected, out untouched. */
  {
    char ctx65[65];
    memset(ctx65, 'x', sizeof(ctx65));
    memset(out, 0xee, 32);
    n = fre_encode((const uint8_t *)"nsc", 3, S0, fpr, 0, (const uint8_t *)ctx65,
                   65, out);
    if (n != 0) {
      printf("FAIL: ctx_len 65 must return 0, got %zu\n", n);
      failures++;
    }
    for (i = 0; i < 32; i++) {
      if (out[i] != 0xee) {
        printf("FAIL: rejected encode must not touch out\n");
        failures++;
        break;
      }
    }
  }
  printf("reject ctx_len 65 (> FRE_CTX_MAX)\n");

  /* NULL ctx with nonzero length: rejected, no crash, out untouched. */
  memset(out, 0xee, 32);
  n = fre_encode((const uint8_t *)"nsc", 3, S0, fpr, 0, NULL, 1, out);
  if (n != 0) {
    printf("FAIL: NULL ctx with len 1 must return 0, got %zu\n", n);
    failures++;
  }
  if (out[0] != 0xee) {
    printf("FAIL: rejected NULL ctx must not touch out\n");
    failures++;
  }
  printf("reject ctx=NULL with len 1\n");
}

static void test_boundaries(void) {
  uint8_t fpr[32];
  uint8_t out[160];
  uint8_t buf[66];
  size_t n;

  fre_fpr(S0, KR, fpr);

  n = fre_encode((const uint8_t *)"a\0", 2, S0, fpr, 0, (const uint8_t *)"", 0,
                 out);
  expect_hex(
      out, n,
      "3da0c452ce5ec0e6e2aa612216e218c8fdaf4619d6a316c9593d4f68353e37f1");

  n = fre_encode((const uint8_t *)"a\0\0", 3, S0, fpr, 0, (const uint8_t *)"",
                 0, out);
  expect_hex(
      out, n,
      "e5b22044373ac1d55f6da3c9c56324ab8fa1110355da22d6e03ccdc24448934e");

  memset(buf, 0, sizeof(buf));
  n = fre_encode(buf, 63, S0, fpr, 0, (const uint8_t *)"", 0, out);
  if (n != 32)
    failures++;
  expect_hex(
      out, n,
      "65a209fc4b48696a4556a1b2f519062d4a0ba70565b4aa6d5032ad9180c50d11");

  memset(buf, 0, sizeof(buf));
  n = fre_encode(buf, 64, S0, fpr, 0, (const uint8_t *)"", 0, out);
  if (n != 64)
    failures++;
  expect_hex(out, n,
             "7fa054c8133de834e5cd9b50a284f51fdd889de6c0bde333260e7c314de2ba47"
             "9664b9d5d1f64b357a909fa08265e3fb1b3fe0dbff93798fb157a695b4f551d7");

  memset(buf, 0, sizeof(buf));
  n = fre_encode(buf, 65, S0, fpr, 0, (const uint8_t *)"", 0, out);
  if (n != 64)
    failures++;
  expect_hex(out, n,
             "7fa054c8133de834e5cd9b50a284f51fdd889de6c0bde333260e7c314de2ba47"
             "d1eaa88f825827842c6d243c040427a1b1f8f8deb84a0a8680cd870f27c90d10");

  printf("boundary cases (63/64/65 bytes, trailing NUL)\n");
}

static void test_1kb(void) {
  uint8_t fpr[32];
  uint8_t *input = malloc(1024);
  uint8_t *out = malloc(fre_out_len(1024));
  size_t n;

  fre_fpr(S0, KR, fpr);
  memset(input, 0x5a, 1024);
  n = fre_encode(input, 1024, S0, fpr, 0, (const uint8_t *)"nsc:msg", 7, out);
  if (n != fre_out_len(1024)) {
    failures++;
  }
  expect_hex(
      out, n,
      "ae6acbaaac0f006bb0c1232b166964ed60c68d2392ad211bce6df97b3dcba00c"
      "012cebc38e1d059e288e735fb03d840730cfacb1a3b82fed61f512ce81c25a76"
      "4d247fbadd37055d5c86f0222f0e8dec3451c6e275bb04f6d3b55a4ab5d110a2"
      "feb0a622cd4ba3a01b9f17fc17dd6e89ac9630f653825ec050db903b5bc89bed"
      "c9d8e97f906cc12a8e4a30f82403e2659ead7d10d8a7d7c3e5e4fb0a4443c8a1"
      "63a4215cbe8ed1d475e160af4567543d208f1660913ea286bbf075a9f8d89200"
      "09266fdb631de3b259c4216f4b436773deabdd3e9ec72e1509673bb67bdbc401"
      "031b76dea1866bdb18bbf7899eb66ffbfc6b80ad1982ccd6bc13f8c117772cef"
      "60f6fd69131a0b04cf203c3d833fa94dbf9873d523c771de92cd37fec87a910d"
      "96cca6c0574bb5c343a0f9ba6593e19aded6c25b82e2c66b9b63837aa4b2d0f4"
      "579edd071a0ab6090c603788435af5b2b0b2b88b52210cdf158b288337b60e89"
      "a3f72f196ad2c0c39b26223fc5428d9f93432277299e4444dfdb1cfe057ee8a0"
      "01bf1790c99b597a772b916c83bc90ae37f6ca7424824932aeaafaa2d0c51a57"
      "3d5b756b4b41c3f06307e7991957d3a3d7c41ef1085a7fb070870c2007909e20"
      "a635566fab8070f0344bc0c3b77e682322283dfb1bc11407bbc6d4c994785cbc"
      "6d566f61eb84140e53437d84a6c2292d2f06e5cd93ede4fc2f612df1d6843e50"
      "551533a0258a63f6773eb0891bc39d601113d9212c444fd12bea1d05093a3834");
  printf("encode 1kB payload g=0 ctx=\"nsc:msg\"\n");

  free(input);
  free(out);
}

int main(void) {
  test_sha256();
  test_hmac_rfc4231();
  test_basic();
  test_encode();
  test_boundaries();
  test_1kb();
  if (failures) {
    printf("%d FAILURES\n", failures);
    return 1;
  }
  printf("all C tests passed\n");
  return 0;
}
