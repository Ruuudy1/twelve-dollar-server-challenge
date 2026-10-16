// Shared helpers for the JWT tests: token building, guarded buffers and a base64url encoder.
// Included after ../src/main.c by unit_jwt.c and fuzz_auth.c.

static const char JWT_TEST_SECRET[] = "twelve-dollar-challenge";
#define JWT_TEST_NOW 1700000000LL
#define JWT_TEST_HEADER "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"

// Encodes n bytes as unpadded base64url and returns the length written.
static size_t jwt_b64_encode(const uint8_t *in, size_t n, char *out) {
    static const char digits[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    size_t i = 0;
    for (; i + 3 <= n; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8 | in[i + 2];
        out[o++] = digits[v >> 18];
        out[o++] = digits[(v >> 12) & 63];
        out[o++] = digits[(v >> 6) & 63];
        out[o++] = digits[v & 63];
    }
    if (n - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = digits[v >> 18];
        out[o++] = digits[(v >> 12) & 63];
    } else if (n - i == 2) {
        uint32_t v = (uint32_t)in[i] << 16 | (uint32_t)in[i + 1] << 8;
        out[o++] = digits[v >> 18];
        out[o++] = digits[(v >> 12) & 63];
        out[o++] = digits[(v >> 6) & 63];
    }
    out[o] = 0;
    return o;
}

// Replaces every single quote with a double quote so JSON in test tables stays readable.
static void jwt_unquote(char *dst, const char *src) {
    for (; *src; src++, dst++) {
        *dst = *src == '\'' ? '"' : *src;
    }
    *dst = 0;
}

// Builds "head.payload.sig" for two JSON texts, signing with key; returns the token length.
static size_t jwt_make(char *out, const char *head_json, const char *payload_json, const struct sha256_hmac_key *key) {
    char h[512];
    char p[16384];
    jwt_unquote(h, head_json);
    jwt_unquote(p, payload_json);
    size_t n = jwt_b64_encode((const uint8_t *)h, strlen(h), out);
    out[n++] = '.';
    n += jwt_b64_encode((const uint8_t *)p, strlen(p), out + n);
    uint8_t tag[32];
    sha256_hmac(key, out, n, tag);
    out[n++] = '.';
    n += jwt_b64_encode(tag, sizeof tag, out + n);
    return n;
}

// A header value copied so that its last (or first) byte sits next to an inaccessible page.
struct jwt_guarded {
    uint8_t *map;
    size_t map_len;
    const char *p;
};

// Copies s into a mapping flanked by PROT_NONE pages; tail places the bytes against the end, otherwise the start.
static struct jwt_guarded jwt_guard(const char *s, size_t n, bool tail) {
    size_t page = 4096;
    size_t body = (n + page - 1) / page * page;
    struct jwt_guarded g = {.map_len = body + 2 * page};
    g.map = mmap(NULL, g.map_len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (g.map == MAP_FAILED) {
        perror("mmap");
        exit(2);
    }
    mprotect(g.map, page, PROT_NONE);
    mprotect(g.map + page + body, page, PROT_NONE);
    uint8_t *dst = tail ? g.map + page + body - n : g.map + page;
    if (n) {
        memcpy(dst, s, n);
    }
    g.p = (const char *)dst;
    return g;
}

// Releases a guarded copy.
static void jwt_unguard(struct jwt_guarded *g) {
    munmap(g->map, g->map_len);
}
