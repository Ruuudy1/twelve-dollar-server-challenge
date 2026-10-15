// Fuzz test for auth_check: random and mutated tokens never crash, never read outside the header,
// never accept a signature that does not match, and every accepted token has a sane identity.
// Usage: fuzz_auth <iterations> [seed]
#define FM_TEST 1
#include "../src/main.c"
#include "jwt_helpers.h"

static uint64_t rng_state;
static struct sha256_hmac_key other_key;

// Returns the next pseudo-random 32-bit value (xorshift64).
static uint32_t rng_next(void) {
    rng_state ^= rng_state << 13;
    rng_state ^= rng_state >> 7;
    rng_state ^= rng_state << 17;
    return (uint32_t)(rng_state >> 16);
}

// Returns a value below n.
static uint32_t rng_below(uint32_t n) {
    return rng_next() % n;
}

static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static const char *const payload_templates[] = {
    "{'sub':'7','username':'alice','iat':1699999000,'exp':1700003600}",
    "{'sub':'12345','username':'caf\\u00e9 \\ud83d\\ude00','exp':1700000100,'nbf':1600000000}",
    "{'username':'bob','sub':'9223372036854775807'}",
    "{'a':[1,2,{'b':null}],'sub':'1','username':'','exp':1e10}",
};

// Applies one random mutation to a buffer of length n (capacity cap) and returns the new length.
static size_t mutate(char *buf, size_t n, size_t cap) {
    switch (rng_below(7)) {
    case 0:
        if (n) {
            buf[rng_below((uint32_t)n)] ^= (char)(1u << rng_below(8));
        }
        return n;
    case 1:
        if (n) {
            buf[rng_below((uint32_t)n)] = (char)rng_next();
        }
        return n;
    case 2:
        return n ? rng_below((uint32_t)n) : 0;
    case 3:
        if (n && n < cap) {
            size_t at = rng_below((uint32_t)n);
            memmove(buf + at + 1, buf + at, n - at);
            buf[at] = rng_below(2) ? alphabet[rng_below(64)] : "{}[]\",.:=\\ "[rng_below(12)];
            return n + 1;
        }
        return n;
    case 4:
        if (n > 1) {
            size_t at = rng_below((uint32_t)n);
            memmove(buf + at, buf + at + 1, n - at - 1);
            return n - 1;
        }
        return n;
    case 5:
        if (n) {
            buf[rng_below((uint32_t)n)] = '.';
        }
        return n;
    default:
        if (n) {
            buf[rng_below((uint32_t)n)] = alphabet[rng_below(64)];
        }
        return n;
    }
}

// Builds a candidate header value in buf and returns its length; signed_ok is set when it carries a correct signature
// over its first two segments, signed_bad when it was signed with another key and must never be accepted.
static size_t make_input(char *buf, size_t cap, bool *signed_bad) {
    *signed_bad = false;
    unsigned kind = rng_below(6);
    if (kind == 0) {
        size_t n = rng_below(300);
        for (size_t i = 0; i < n; i++) {
            buf[i] = (char)rng_next();
        }
        return n;
    }
    if (kind == 1) {
        size_t n = 7 + rng_below(250);
        memcpy(buf, "Bearer ", 7);
        for (size_t i = 7; i < n; i++) {
            unsigned r = rng_below(40);
            buf[i] = r == 0 ? '.' : alphabet[rng_below(64)];
        }
        return n;
    }
    char payload[512];
    snprintf(payload, sizeof payload, "%s", payload_templates[rng_below(ARRAY_LEN(payload_templates))]);
    size_t pn = strlen(payload);
    char head[64] = JWT_TEST_HEADER;
    size_t hn = strlen(head);
    if (kind >= 4) {
        unsigned rounds = 1 + rng_below(3);
        for (unsigned i = 0; i < rounds; i++) {
            pn = mutate(payload, pn, sizeof payload - 1);
            if (rng_below(3) == 0) {
                hn = mutate(head, hn, sizeof head - 1);
            }
        }
        payload[pn] = 0;
        head[hn] = 0;
    }
    bool wrong_key = kind == 3;
    memcpy(buf, "Bearer ", 7);
    size_t n = 7 + jwt_make(buf + 7, head, payload, wrong_key ? &other_key : &auth_key);
    *signed_bad = wrong_key;
    if (kind == 2) {
        unsigned rounds = 1 + rng_below(3);
        for (unsigned i = 0; i < rounds; i++) {
            n = mutate(buf, n, cap - 1);
        }
    }
    return n;
}

// For an accepted header, checks that the signature segment really is the HMAC of the first two segments.
static bool accepted_is_signed(const char *text, size_t n) {
    const char *tok = text + 7;
    size_t tn = n - 7;
    const char *d1 = memchr(tok, '.', tn);
    const char *d2 = memchr(d1 + 1, '.', tn - (size_t)(d1 + 1 - tok));
    size_t signed_len = (size_t)(d2 - tok);
    uint8_t tag[32];
    uint8_t sig[33];
    sha256_hmac(&auth_key, tok, signed_len, tag);
    int64_t sn = auth_b64url_decode((struct slice){d2 + 1, (uint32_t)(tn - signed_len - 1)}, sig, sizeof sig);
    return sn == 32 && !memcmp(tag, sig, 32);
}

int main(int argc, char **argv) {
    unsigned long long iters = argc > 1 ? strtoull(argv[1], NULL, 10) : 100000;
    rng_state = argc > 2 ? strtoull(argv[2], NULL, 10) * 2654435761ULL + 88172645463325252ULL : 88172645463325252ULL;
    auth_init(JWT_TEST_SECRET, sizeof JWT_TEST_SECRET - 1);
    sha256_hmac_init(&other_key, "a different secret", 18);
    static char buf[2048];
    static char scratch[4096];
    unsigned long long accepted = 0;
    unsigned long long status_count[4] = {0};
    for (unsigned long long it = 0; it < iters; it++) {
        bool signed_bad;
        size_t n = make_input(buf, sizeof buf, &signed_bad);
        char *exact = NULL;
        struct jwt_guarded g = {0};
        const char *p;
        if (it % 16 == 0) {
            g = jwt_guard(buf, n, it % 32 == 0);
            p = g.p;
        } else {
            exact = malloc(n ? n : 1);
            memcpy(exact, buf, n);
            p = exact;
        }
        uint32_t cap = rng_below(4) ? (uint32_t)sizeof scratch : rng_below(40);
        struct auth_identity id = {0, {NULL, 0}};
        enum auth_status st = auth_check((struct slice){n ? p : NULL, (uint32_t)n}, JWT_TEST_NOW, scratch, cap, &id);
        status_count[st]++;
        if (st == AUTH_OK) {
            accepted++;
            bool sane = n >= 7 && id.user_id > 0 && id.name.n <= cap && (!id.name.n || (id.name.p >= scratch &&
                        id.name.p + id.name.n <= scratch + cap));
            if (signed_bad || !sane || !accepted_is_signed(buf, n)) {
                fprintf(stderr, "FAIL iteration %llu accepted a bad token (%zu bytes, user %lld)\n", it, n,
                        (long long)id.user_id);
                return 1;
            }
        } else if (st > AUTH_BAD_PAYLOAD) {
            fprintf(stderr, "FAIL iteration %llu returned status %d\n", it, st);
            return 1;
        }
        if (exact) {
            free(exact);
        } else {
            jwt_unguard(&g);
        }
    }
    printf("fuzz_auth ok: %llu iterations, ok %llu missing %llu invalid %llu bad_payload %llu\n", iters, accepted,
           status_count[AUTH_MISSING], status_count[AUTH_INVALID], status_count[AUTH_BAD_PAYLOAD]);
    return 0;
}
