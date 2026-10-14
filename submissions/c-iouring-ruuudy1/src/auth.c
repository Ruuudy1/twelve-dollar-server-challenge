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

static struct sha256_hmac_key auth_key;

// Precomputes the HMAC pads from JWT_SECRET; called once at startup.
static void auth_init(const char *secret, size_t n) {
    sha256_hmac_init(&auth_key, secret, n);
}

// Decodes unpadded base64url into out; returns the byte count or -1 on a foreign character or small cap.
static NOT_YET_USED int64_t auth_b64url_decode(struct slice in, uint8_t *out, uint32_t cap) {
    (void)in;
    (void)out;
    (void)cap;
    return -1;
}

// Checks an Authorization header value in the order the spec fixes: scheme, shape, algorithm, signature, exp, payload.
static NOT_YET_USED enum auth_status auth_check(struct slice header, int64_t now_s, char *scratch, uint32_t cap,
                                   struct auth_identity *id) {
    (void)now_s;
    (void)scratch;
    (void)cap;
    (void)id;
    if (header.n < LIT_LEN("Bearer ") || memcmp(header.p, "Bearer ", LIT_LEN("Bearer "))) {
        return AUTH_MISSING;
    }
    return AUTH_INVALID;
}
