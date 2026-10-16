// Owner: crypto module. SHA-256 and HMAC-SHA256 with precomputed key pads.

#ifdef __SHA__
#include <immintrin.h>
#endif

// HMAC key state: SHA-256 midstates after absorbing the 64-byte inner and outer pads.
struct sha256_hmac_key {
    uint32_t inner[8];
    uint32_t outer[8];
};

enum {
    SHA256_BLOCK = 64,
    SHA256_DIGEST = 32,
    SHA256_STATE_WORDS = 8,
    SHA256_ROUNDS = 64,
    SHA256_TAIL_MAX = 2 * SHA256_BLOCK,
    SHA256_IPAD = 0x36,
    SHA256_OPAD = 0x5c,
};

static const uint32_t SHA256_IV[SHA256_STATE_WORDS] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static const uint32_t SHA256_K[SHA256_ROUNDS] __attribute__((aligned(16))) = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#ifdef __SHA__
// Tests set this to force the portable path on a machine that has SHA-NI.
static bool sha256_scalar_only;
#endif

// Rotates a 32-bit word right by a constant count in 1 to 31.
static inline uint32_t sha256_ror(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

// Loads a big-endian 32-bit word.
static inline uint32_t sha256_load_be(const uint8_t *p) {
    uint32_t v;
    memcpy(&v, p, sizeof v);
    return __builtin_bswap32(v);
}

// Stores a big-endian 32-bit word.
static inline void sha256_store_be(uint8_t *p, uint32_t v) {
    uint32_t be = __builtin_bswap32(v);
    memcpy(p, &be, sizeof be);
}

// Expands the message schedule for one block.
static inline void sha256_schedule(uint32_t w[SHA256_ROUNDS], const uint8_t *block) {
    for (unsigned i = 0; i < 16; i++) {
        w[i] = sha256_load_be(block + 4 * i);
    }
    for (unsigned i = 16; i < SHA256_ROUNDS; i++) {
        uint32_t s0 = sha256_ror(w[i - 15], 7) ^ sha256_ror(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sha256_ror(w[i - 2], 17) ^ sha256_ror(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
}

// Portable compression of nblocks consecutive 64-byte blocks into the state.
static void sha256_blocks_scalar(uint32_t st[SHA256_STATE_WORDS], const uint8_t *p, size_t nblocks) {
    for (; nblocks; nblocks--, p += SHA256_BLOCK) {
        uint32_t w[SHA256_ROUNDS] = {0};
        sha256_schedule(w, p);
        uint32_t a = st[0], b = st[1], c = st[2], d = st[3];
        uint32_t e = st[4], f = st[5], g = st[6], h = st[7];
        for (unsigned i = 0; i < SHA256_ROUNDS; i++) {
            uint32_t s1 = sha256_ror(e, 6) ^ sha256_ror(e, 11) ^ sha256_ror(e, 25);
            uint32_t t1 = h + s1 + ((e & f) ^ (~e & g)) + SHA256_K[i] + w[i];
            uint32_t s0 = sha256_ror(a, 2) ^ sha256_ror(a, 13) ^ sha256_ror(a, 22);
            uint32_t t2 = s0 + ((a & b) ^ (a & c) ^ (b & c));
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        st[0] += a;
        st[1] += b;
        st[2] += c;
        st[3] += d;
        st[4] += e;
        st[5] += f;
        st[6] += g;
        st[7] += h;
    }
}

#ifdef __SHA__
// Four rounds with the SHA extensions; msg already holds the schedule words plus the round constants.
static inline void sha256_ni_rounds(__m128i *abef, __m128i *cdgh, __m128i msg) {
    *cdgh = _mm_sha256rnds2_epu32(*cdgh, *abef, msg);
    *abef = _mm_sha256rnds2_epu32(*abef, *cdgh, _mm_shuffle_epi32(msg, 0x0E));
}

// SHA-NI compression of nblocks consecutive 64-byte blocks into the state.
static void sha256_blocks_ni(uint32_t st[SHA256_STATE_WORDS], const uint8_t *p, size_t nblocks) {
    const __m128i swap = _mm_set_epi64x(0x0c0d0e0f08090a0bLL, 0x0405060700010203LL);
    __m128i tmp = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)(const void *)&st[0]), 0xB1);
    __m128i cdgh = _mm_shuffle_epi32(_mm_loadu_si128((const __m128i *)(const void *)&st[4]), 0x1B);
    __m128i abef = _mm_alignr_epi8(tmp, cdgh, 8);
    cdgh = _mm_blend_epi16(cdgh, tmp, 0xF0);
    for (; nblocks; nblocks--, p += SHA256_BLOCK) {
        const __m128i save_abef = abef;
        const __m128i save_cdgh = cdgh;
        __m128i m[4];
#pragma GCC unroll 16
        for (unsigned i = 0; i < 16; i++) {
            if (i < 4) {
                m[i] = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i *)(const void *)(p + 16 * i)), swap);
            } else {
                __m128i mix = _mm_add_epi32(_mm_sha256msg1_epu32(m[i & 3], m[(i + 1) & 3]),
                                            _mm_alignr_epi8(m[(i + 3) & 3], m[(i + 2) & 3], 4));
                m[i & 3] = _mm_sha256msg2_epu32(mix, m[(i + 3) & 3]);
            }
            __m128i k = _mm_load_si128((const __m128i *)(const void *)&SHA256_K[4 * i]);
            sha256_ni_rounds(&abef, &cdgh, _mm_add_epi32(m[i & 3], k));
        }
        abef = _mm_add_epi32(abef, save_abef);
        cdgh = _mm_add_epi32(cdgh, save_cdgh);
    }
    tmp = _mm_shuffle_epi32(abef, 0x1B);
    cdgh = _mm_shuffle_epi32(cdgh, 0xB1);
    abef = _mm_blend_epi16(tmp, cdgh, 0xF0);
    cdgh = _mm_alignr_epi8(cdgh, tmp, 8);
    _mm_storeu_si128((__m128i *)(void *)&st[0], abef);
    _mm_storeu_si128((__m128i *)(void *)&st[4], cdgh);
}
#endif

// Compresses nblocks blocks with SHA-NI when the build has it, otherwise with the portable code.
static inline void sha256_blocks(uint32_t st[SHA256_STATE_WORDS], const uint8_t *p, size_t nblocks) {
#ifdef __SHA__
    if (!sha256_scalar_only) {
        sha256_blocks_ni(st, p, nblocks);
        return;
    }
#endif
    sha256_blocks_scalar(st, p, nblocks);
}

// Hashes msg after a state that already absorbed prefix bytes, and writes the digest.
static void sha256_run(const uint32_t init[SHA256_STATE_WORDS], uint64_t prefix, const void *msg, size_t n,
                       uint8_t out[SHA256_DIGEST]) {
    const uint8_t *p = msg;
    uint32_t st[SHA256_STATE_WORDS];
    memcpy(st, init, sizeof st);
    size_t full = n / SHA256_BLOCK;
    sha256_blocks(st, p, full);
    size_t rest = n - full * SHA256_BLOCK;
    uint8_t tail[SHA256_TAIL_MAX] = {0};
    memcpy(tail, p + full * SHA256_BLOCK, rest);
    tail[rest] = 0x80;
    size_t tail_blocks = rest < SHA256_BLOCK - 8 ? 1 : 2;
    uint64_t bits = (prefix + n) * 8;
    sha256_store_be(tail + tail_blocks * SHA256_BLOCK - 8, (uint32_t)(bits >> 32));
    sha256_store_be(tail + tail_blocks * SHA256_BLOCK - 4, (uint32_t)bits);
    sha256_blocks(st, tail, tail_blocks);
    for (unsigned i = 0; i < SHA256_STATE_WORDS; i++) {
        sha256_store_be(out + 4 * i, st[i]);
    }
}

// Hashes msg into a 32-byte digest.
static void sha256_hash(const void *msg, size_t n, uint8_t out[SHA256_DIGEST]) {
    sha256_run(SHA256_IV, 0, msg, n, out);
}

// Zeroes a buffer in a way the compiler cannot drop, so key material does not linger on the stack.
static void sha256_wipe(void *p, size_t n) {
    memset(p, 0, n);
    __asm__ volatile("" : : "r"(p) : "memory");
}

// Absorbs one pad block (key xor pad byte) from the IV into a midstate.
static void sha256_pad_state(uint32_t st[SHA256_STATE_WORDS], const uint8_t key[SHA256_BLOCK], uint8_t pad) {
    uint8_t block[SHA256_BLOCK] = {0};
    for (unsigned i = 0; i < SHA256_BLOCK; i++) {
        block[i] = (uint8_t)(key[i] ^ pad);
    }
    memcpy(st, SHA256_IV, sizeof SHA256_IV);
    sha256_blocks(st, block, 1);
    sha256_wipe(block, sizeof block);
}

// Hashes the pads for key once at startup; keys longer than 64 bytes are hashed first.
static void sha256_hmac_init(struct sha256_hmac_key *k, const void *key, size_t n) {
    uint8_t block[SHA256_BLOCK] = {0};
    if (n > SHA256_BLOCK) {
        sha256_hash(key, n, block);
    } else if (n) {
        memcpy(block, key, n);
    }
    sha256_pad_state(k->inner, block, SHA256_IPAD);
    sha256_pad_state(k->outer, block, SHA256_OPAD);
    sha256_wipe(block, sizeof block);
}

// Computes HMAC-SHA256 of msg with the precomputed pads into a 32-byte tag.
static void sha256_hmac(const struct sha256_hmac_key *k, const void *msg, size_t n, uint8_t out[SHA256_DIGEST]) {
    uint8_t inner[SHA256_DIGEST];
    sha256_run(k->inner, SHA256_BLOCK, msg, n, inner);
    sha256_run(k->outer, SHA256_BLOCK, inner, sizeof inner, out);
}

// Compares two byte ranges of equal length in constant time.
static bool sha256_ct_equal(const void *a, const void *b, size_t n) {
    const uint8_t *x = a;
    const uint8_t *y = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(x[i] ^ y[i]);
    }
    return !diff;
}
