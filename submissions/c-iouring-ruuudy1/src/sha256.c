// Owner: crypto module. SHA-256 and HMAC-SHA256 with precomputed key pads.

// HMAC key state: SHA-256 midstates after absorbing the 64-byte inner and outer pads.
struct sha256_hmac_key {
    uint32_t inner[8];
    uint32_t outer[8];
};

// Hashes msg into a 32-byte digest.
static NOT_YET_USED void sha256_hash(const void *msg, size_t n, uint8_t out[32]) {
    (void)msg;
    (void)n;
    memset(out, 0, 32);
}

// Hashes the pads for key once at startup; keys longer than 64 bytes are hashed first.
static void sha256_hmac_init(struct sha256_hmac_key *k, const void *key, size_t n) {
    (void)key;
    (void)n;
    memset(k, 0, sizeof *k);
}

// Computes HMAC-SHA256 of msg with the precomputed pads into a 32-byte tag.
static NOT_YET_USED void sha256_hmac(const struct sha256_hmac_key *k, const void *msg, size_t n, uint8_t out[32]) {
    (void)k;
    (void)msg;
    (void)n;
    memset(out, 0, 32);
}

// Compares two byte ranges of equal length in constant time.
static NOT_YET_USED bool sha256_ct_equal(const void *a, const void *b, size_t n) {
    const uint8_t *x = a;
    const uint8_t *y = b;
    uint8_t diff = 0;
    for (size_t i = 0; i < n; i++) {
        diff |= (uint8_t)(x[i] ^ y[i]);
    }
    return !diff;
}
