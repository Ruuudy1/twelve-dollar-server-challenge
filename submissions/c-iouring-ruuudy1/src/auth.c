// Owner: crypto module. Bearer token parsing, base64url and JWT checks.

// The user a valid token names; name points into the scratch buffer passed to auth_check.
struct auth_identity {
    int64_t user_id;
    struct slice name;
};

enum auth_status {
    AUTH_OK,
    // No Authorization header or not exactly "Bearer ".
    AUTH_MISSING,
    // Bad shape, algorithm, signature, exp or nbf.
    AUTH_INVALID,
    // Valid token whose sub or username is unusable.
    AUTH_BAD_PAYLOAD,
};

// The three segments of a token, each a slice of the header value.
struct auth_token {
    struct slice head;
    struct slice payload;
    struct slice sig;
};

enum {
    // Bytes a segment of JWT_SEGMENT_MAX characters can decode to.
    AUTH_DECODED_MAX = JWT_SEGMENT_MAX / 4 * 3,
    // Longest token: two full segments, the signature and two dots.
    AUTH_TOKEN_MAX = 2 * JWT_SEGMENT_MAX + JWT_SIG_CHARS + 2,
    // Largest value in the base64url table; anything above it is a foreign character.
    AUTH_B64_MAX = 0x3f,
    // Room for the short string fields (alg and sub) after unescaping.
    AUTH_SHORT_MAX = 32,
};

// Fields read from the payload, in the order of the extraction table.
enum { AUTH_F_EXP, AUTH_F_NBF, AUTH_F_SUB, AUTH_F_USERNAME, AUTH_F_COUNT };

#define AUTH_SCHEME "Bearer "
// Base64url of {"alg":"HS256","typ":"JWT"}, the header every issuer uses.
#define AUTH_HEADER_FAST "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

static struct sha256_hmac_key auth_key;

static const uint8_t auth_b64_table[256] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3e, 0xff, 0xff,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
    0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xff, 0xff, 0xff, 0xff, 0x3f,
    0xff, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
};

// Precomputes the HMAC pads from JWT_SECRET; called once at startup.
static void auth_init(const char *secret, size_t n) {
    sha256_hmac_init(&auth_key, secret, n);
}

// Decodes the last one to three characters of a segment, writing their bytes at out; false on a foreign character.
static bool auth_b64url_tail(const uint8_t *p, uint32_t rem, uint8_t *out) {
    uint32_t bits = 0;
    for (uint32_t i = 0; i < rem; i++) {
        uint32_t v = auth_b64_table[p[i]];
        if (v > AUTH_B64_MAX) {
            return false;
        }
        bits = bits << 6 | v;
    }
    bits >>= (rem * 6) % 8;
    for (uint32_t i = rem - 1; i; i--) {
        out[i - 1] = (uint8_t)bits;
        bits >>= 8;
    }
    return true;
}

// Decodes unpadded base64url into out; returns the byte count or -1 on a foreign character or small cap.
static int64_t auth_b64url_decode(struct slice in, uint8_t *out, uint32_t cap) {
    uint32_t rem = in.n % 4;
    uint32_t groups = in.n / 4;
    if (rem == 1 || cap < groups * 3 + (rem ? rem - 1 : 0)) {
        return -1;
    }
    const uint8_t *p = (const uint8_t *)in.p;
    for (uint32_t g = 0; g < groups; g++) {
        uint32_t a = auth_b64_table[p[4 * g]];
        uint32_t b = auth_b64_table[p[4 * g + 1]];
        uint32_t c = auth_b64_table[p[4 * g + 2]];
        uint32_t d = auth_b64_table[p[4 * g + 3]];
        if ((a | b | c | d) > AUTH_B64_MAX) {
            return -1;
        }
        uint32_t v = a << 18 | b << 12 | c << 6 | d;
        out[3 * g] = (uint8_t)(v >> 16);
        out[3 * g + 1] = (uint8_t)(v >> 8);
        out[3 * g + 2] = (uint8_t)v;
    }
    if (rem && !auth_b64url_tail(p + 4 * groups, rem, out + 3 * groups)) {
        return -1;
    }
    return groups * 3 + (rem ? rem - 1 : 0);
}

// Splits the token at its two dots into slices of the header value; false when the shape is wrong.
static bool auth_split(struct slice token, struct auth_token *t) {
    if (token.n > AUTH_TOKEN_MAX) {
        return false;
    }
    const char *dot1 = memchr(token.p, '.', token.n);
    if (!dot1) {
        return false;
    }
    uint32_t head_n = (uint32_t)(dot1 - token.p);
    uint32_t rest_n = token.n - head_n - 1;
    const char *dot2 = memchr(dot1 + 1, '.', rest_n);
    if (!dot2) {
        return false;
    }
    uint32_t payload_n = (uint32_t)(dot2 - (dot1 + 1));
    uint32_t sig_n = rest_n - payload_n - 1;
    if (head_n > JWT_SEGMENT_MAX || payload_n > JWT_SEGMENT_MAX || sig_n != JWT_SIG_CHARS) {
        return false;
    }
    t->head = (struct slice){token.p, head_n};
    t->payload = (struct slice){dot1 + 1, payload_n};
    t->sig = (struct slice){dot2 + 1, sig_n};
    return true;
}

// Unescapes a JSON string field into dst; false when the field is not a string or does not fit.
static bool auth_string_value(const struct json_field *f, char *dst, uint32_t cap, struct slice *out) {
    if (f->type != JSON_STRING) {
        return false;
    }
    int64_t n = json_unescape(f->raw, dst, cap);
    if (n < 0) {
        return false;
    }
    *out = (struct slice){dst, (uint32_t)n};
    return true;
}

// True when the header segment is the usual HS256 header or decodes to an object whose alg is HS256.
static bool auth_header_is_hs256(struct slice head) {
    if (head.n == LIT_LEN(AUTH_HEADER_FAST) && !memcmp(head.p, AUTH_HEADER_FAST, head.n)) {
        return true;
    }
    // The buffer is written by the decoder before any byte is read, so zeroing it would only cost time.
    uint8_t buf[AUTH_DECODED_MAX];
    int64_t n = auth_b64url_decode(head, buf, sizeof buf);
    struct json_field alg = {.key = "alg"};
    if (n < 0 || json_extract((struct slice){(const char *)buf, (uint32_t)n}, &alg, 1) != JSON_OK) {
        return false;
    }
    char tmp[AUTH_SHORT_MAX];
    struct slice value;
    return auth_string_value(&alg, tmp, sizeof tmp, &value) && value.n == LIT_LEN("HS256") &&
           !memcmp(value.p, "HS256", value.n);
}

// Recomputes the HMAC over "header.payload" and compares it in constant time with the decoded signature.
static bool auth_signature_ok(const struct auth_token *t) {
    uint8_t want[SHA256_DIGEST + 1];
    if (auth_b64url_decode(t->sig, want, sizeof want) != SHA256_DIGEST) {
        return false;
    }
    uint8_t have[SHA256_DIGEST];
    sha256_hmac(&auth_key, t->head.p, (size_t)t->head.n + 1 + t->payload.n, have);
    return sha256_ct_equal(have, want, SHA256_DIGEST);
}

// Parses a positive decimal user id that fits int64; leading zeros are accepted, anything else is rejected.
static bool auth_parse_sub(struct slice s, int64_t *out) {
    uint64_t v = 0;
    if (!s.n) {
        return false;
    }
    for (uint32_t i = 0; i < s.n; i++) {
        uint64_t digit = (uint64_t)(uint8_t)s.p[i] - '0';
        if (digit > 9 || v > ((uint64_t)INT64_MAX - digit) / 10) {
            return false;
        }
        v = v * 10 + digit;
    }
    *out = (int64_t)v;
    return v != 0;
}

// Applies the rules for exp (a number after now when present) and nbf (a number not after now when present).
static bool auth_times_ok(const struct json_field *exp, const struct json_field *nbf, int64_t now_s) {
    double now = (double)now_s;
    if (exp->type != JSON_ABSENT && (exp->type != JSON_NUMBER || exp->num <= now)) {
        return false;
    }
    return nbf->type == JSON_ABSENT || (nbf->type == JSON_NUMBER && nbf->num <= now);
}

// Checks the payload: object, exp and nbf (invalid token), then sub and username (bad payload).
static enum auth_status auth_check_payload(struct slice payload, int64_t now_s, char *scratch, uint32_t cap,
                                           struct auth_identity *id) {
    // The buffer is written by the decoder before any byte is read, so zeroing it would only cost time.
    uint8_t buf[AUTH_DECODED_MAX];
    int64_t n = auth_b64url_decode(payload, buf, sizeof buf);
    struct json_field f[AUTH_F_COUNT] = {
        [AUTH_F_EXP] = {.key = "exp"},
        [AUTH_F_NBF] = {.key = "nbf"},
        [AUTH_F_SUB] = {.key = "sub"},
        [AUTH_F_USERNAME] = {.key = "username"},
    };
    if (n < 0 || json_extract((struct slice){(const char *)buf, (uint32_t)n}, f, AUTH_F_COUNT) != JSON_OK ||
        !auth_times_ok(&f[AUTH_F_EXP], &f[AUTH_F_NBF], now_s)) {
        return AUTH_INVALID;
    }
    char tmp[AUTH_SHORT_MAX];
    struct slice sub;
    struct slice name;
    int64_t user_id = 0;
    if (!auth_string_value(&f[AUTH_F_SUB], tmp, sizeof tmp, &sub) || !auth_parse_sub(sub, &user_id) ||
        !auth_string_value(&f[AUTH_F_USERNAME], scratch, cap, &name)) {
        return AUTH_BAD_PAYLOAD;
    }
    id->user_id = user_id;
    id->name = name;
    return AUTH_OK;
}

// Checks an Authorization header value in the order the spec fixes: scheme, shape, algorithm, signature, exp, payload.
static NOT_YET_USED enum auth_status auth_check(struct slice header, int64_t now_s, char *scratch, uint32_t cap,
                                                struct auth_identity *id) {
    if (header.n < LIT_LEN(AUTH_SCHEME) || memcmp(header.p, AUTH_SCHEME, LIT_LEN(AUTH_SCHEME))) {
        return AUTH_MISSING;
    }
    struct auth_token t;
    struct slice token = {header.p + LIT_LEN(AUTH_SCHEME), header.n - (uint32_t)LIT_LEN(AUTH_SCHEME)};
    if (!auth_split(token, &t) || !auth_header_is_hs256(t.head) || !auth_signature_ok(&t)) {
        return AUTH_INVALID;
    }
    return auth_check_payload(t.payload, now_s, scratch, cap, id);
}
