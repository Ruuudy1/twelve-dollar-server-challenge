// SHA-256 and HMAC-SHA256: NIST and RFC 4231 vectors, openssl known answers, scalar against SHA-NI.
#define FM_TEST 1
// The test build has no -march flag, so it enables SHA-NI for this file and checks the CPU before using it.
#if defined(__x86_64__) && !defined(__SHA__) && !defined(FM_NO_SHA_NI)
#pragma GCC target("sha,sse4.1,ssse3")
#endif
#include "../src/main.c"
#include "kat_sha256.h"
#include <cpuid.h>

static int failures;

#ifdef __SHA__
// True when the CPU running the test has the SHA extensions.
static bool cpu_has_sha_ni(void) {
    unsigned a, b, c, d;
    return __get_cpuid_count(7, 0, &a, &b, &c, &d) && (b & (1u << 29));
}
#endif

// Records a failed expectation with its line.
#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

// Writes 64 lowercase hex characters for a digest.
static void hex32(const uint8_t d[32], char out[65]) {
    static const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        out[2 * i] = digits[d[i] >> 4];
        out[2 * i + 1] = digits[d[i] & 15];
    }
    out[64] = 0;
}

// Fills n bytes with the pattern byte i = (i * mul + add) & 255 used by gen_kat.sh.
static void pattern(uint8_t *buf, size_t n, unsigned mul, unsigned add) {
    for (size_t i = 0; i < n; i++) {
        buf[i] = (uint8_t)((i * mul + add) & 255);
    }
}

// Checks a digest against its expected hex text, naming the case on failure.
static void expect_hex(const uint8_t d[32], const char *want, const char *what, unsigned n) {
    char got[65];
    hex32(d, got);
    if (strcmp(got, want)) {
        fprintf(stderr, "FAIL %s %u\n  got  %s\n  want %s\n", what, n, got, want);
        failures++;
    }
}

// Hashes text and compares with the expected hex digest.
static void expect_hash(const void *msg, size_t n, const char *want) {
    uint8_t d[32];
    sha256_hash(msg, n, d);
    expect_hex(d, want, "hash", (unsigned)n);
}

static void test_nist(void) {
    expect_hash("", 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect_hash("abc", 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    const char *m448 = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    expect_hash(m448, strlen(m448), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    const char *m896 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrs"
                       "mnopqrstnopqrstu";
    expect_hash(m896, strlen(m896), "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1");
    static uint8_t million[1000000];
    memset(million, 'a', sizeof million);
    expect_hash(million, sizeof million, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

static void test_lengths(void) {
    static uint8_t msg[301];
    pattern(msg, sizeof msg, 131, 17);
    for (unsigned n = 0; n <= 300; n++) {
        expect_hash(msg, n, kat_sha256_len[n]);
    }
}

// Runs HMAC with a key given as bytes and compares with the expected hex tag.
static void expect_hmac(const void *key, size_t kn, const void *msg, size_t mn, const char *want, const char *what) {
    struct sha256_hmac_key k;
    uint8_t tag[32];
    sha256_hmac_init(&k, key, kn);
    sha256_hmac(&k, msg, mn, tag);
    expect_hex(tag, want, what, (unsigned)kn);
}

static void test_rfc4231(void) {
    uint8_t key[131];
    memset(key, 0x0b, 20);
    expect_hmac(key, 20, "Hi There", 8, "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", "rfc1");
    expect_hmac("Jefe", 4, "what do ya want for nothing?", 28,
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "rfc2");
    memset(key, 0xaa, 20);
    uint8_t data[50];
    memset(data, 0xdd, sizeof data);
    expect_hmac(key, 20, data, 50, "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", "rfc3");
    memset(key, 0xaa, 131);
    const char *m6 = "Test Using Larger Than Block-Size Key - Hash Key First";
    expect_hmac(key, 131, m6, strlen(m6), "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54", "rfc6");
    const char *m7 = "This is a test using a larger than block-size key and a larger than block-size data. The key "
                     "needs to be hashed before being used by the HMAC algorithm.";
    expect_hmac(key, 131, m7, strlen(m7), "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2", "rfc7");
}

static void test_hmac_tables(void) {
    static uint8_t msg[301];
    static uint8_t key[201];
    static uint8_t tags[301 * 32];
    pattern(msg, sizeof msg, 131, 17);
    pattern(key, sizeof key, 29, 5);
    for (unsigned kn = 0; kn <= 200; kn++) {
        unsigned mn = (kn * 37) % 301;
        expect_hmac(key, kn, msg, mn, kat_hmac_by_key[kn], "hmac by key length");
    }
    for (unsigned mn = 0; mn <= 300; mn++) {
        expect_hmac(key, 20, msg, mn, kat_hmac_key20[mn], "hmac key20 message length");
        expect_hmac(key, 65, msg, mn, kat_hmac_key65[mn], "hmac key65 message length");
    }
    for (unsigned kn = 0; kn <= 200; kn++) {
        struct sha256_hmac_key k;
        sha256_hmac_init(&k, key, kn);
        for (unsigned mn = 0; mn <= 300; mn++) {
            sha256_hmac(&k, msg, mn, tags + 32 * mn);
        }
        uint8_t digest[32];
        sha256_hash(tags, sizeof tags, digest);
        expect_hex(digest, kat_hmac_cross[kn], "hmac every message length for key length", kn);
    }
}

// Tiny deterministic generator so the differential cases repeat.
static uint64_t rng_state = 88172645463325252ULL;
static uint32_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 16);
}

#ifdef __SHA__
// Scalar and SHA-NI must agree on random states, block counts, hashes and HMACs.
static void test_paths_agree(void) {
    static uint8_t buf[4096];
    for (unsigned round = 0; round < 2000; round++) {
        uint32_t s1[8];
        uint32_t s2[8];
        for (unsigned i = 0; i < 8; i++) {
            s1[i] = rng_next() ^ (rng_next() << 16);
            s2[i] = s1[i];
        }
        size_t blocks = rng_next() % 40;
        for (size_t i = 0; i < blocks * 64; i++) {
            buf[i] = (uint8_t)rng_next();
        }
        sha256_blocks_scalar(s1, buf, blocks);
        sha256_blocks_ni(s2, buf, blocks);
        CHECK(!memcmp(s1, s2, sizeof s1));
    }
    for (unsigned round = 0; round < 500; round++) {
        size_t n = rng_next() % 700;
        size_t kn = rng_next() % 150;
        for (size_t i = 0; i < n + kn; i++) {
            buf[i] = (uint8_t)rng_next();
        }
        uint8_t a[32];
        uint8_t b[32];
        struct sha256_hmac_key ka;
        struct sha256_hmac_key kb;
        sha256_scalar_only = true;
        sha256_hmac_init(&ka, buf + n, kn);
        sha256_hmac(&ka, buf, n, a);
        sha256_scalar_only = false;
        sha256_hmac_init(&kb, buf + n, kn);
        sha256_hmac(&kb, buf, n, b);
        CHECK(!memcmp(&ka, &kb, sizeof ka) && !memcmp(a, b, 32));
    }
}
#endif

static void test_ct_equal(void) {
    uint8_t a[32];
    uint8_t b[32];
    pattern(a, sizeof a, 3, 1);
    memcpy(b, a, sizeof b);
    CHECK(sha256_ct_equal(a, b, 32));
    CHECK(sha256_ct_equal(a, b, 0));
    for (unsigned i = 0; i < 32; i++) {
        b[i] ^= 0x80;
        CHECK(!sha256_ct_equal(a, b, 32));
        b[i] ^= 0x80;
    }
}

// Runs every hash test once on the portable path and, when the build has SHA-NI, once on that path.
int main(void) {
#ifdef __SHA__
    bool ni = cpu_has_sha_ni();
    for (unsigned pass = 0; pass < (ni ? 2u : 1u); pass++) {
        sha256_scalar_only = pass == 0;
        printf("unit_sha256: %s path\n", pass == 0 ? "scalar" : "sha-ni");
#else
    for (unsigned pass = 0; pass < 1; pass++) {
        printf("unit_sha256: scalar path (no SHA-NI in this build)\n");
#endif
        test_nist();
        test_lengths();
        test_rfc4231();
        test_hmac_tables();
        test_ct_equal();
    }
#ifdef __SHA__
    if (ni) {
        sha256_scalar_only = false;
        test_paths_agree();
    }
#endif
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_sha256 ok");
    return 0;
}
