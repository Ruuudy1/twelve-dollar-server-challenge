// JWT tests: HMAC against openssl, base64url decoding, every auth_check outcome and its precedence.
// Run with the argument "bench" to print the cost of one auth_check (build with the release flags to compare).
#define FM_TEST 1
#include "../src/main.c"
#include "jwt_helpers.h"

static int failures;
static struct sha256_hmac_key other_key;

// Records a failed expectation with its line.
#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

// Result of one auth_check call.
struct outcome {
    enum auth_status status;
    int64_t user_id;
    char name[16384];
    uint32_t name_n;
};

// Runs auth_check on header text copied against a guard page, once at each end of the mapping.
static void run_check(const char *text, size_t n, uint32_t cap, struct outcome *o) {
    static char scratch[32768];
    for (int placement = 0; placement < 2; placement++) {
        struct jwt_guarded g = jwt_guard(text, n, placement == 0);
        struct auth_identity id = {-1, {NULL, 0}};
        memset(scratch, 0x55, sizeof scratch);
        enum auth_status st = auth_check((struct slice){n ? g.p : NULL, (uint32_t)n}, JWT_TEST_NOW, scratch, cap, &id);
        if (placement == 0) {
            o->status = st;
            o->user_id = id.user_id;
            o->name_n = id.name.n;
            memcpy(o->name, id.name.p ? id.name.p : "", id.name.n);
        } else if (st != o->status) {
            fprintf(stderr, "FAIL placement changes the result for a %zu byte header\n", n);
            failures++;
        }
        jwt_unguard(&g);
    }
}

// Checks one header value against the expected status, and for success the user and name.
static void expect_auth(const char *label, const char *text, size_t n, enum auth_status want, int64_t uid,
                        const char *name) {
    struct outcome *o = malloc(sizeof *o);
    run_check(text, n, 32768, o);
    bool ok = o->status == want;
    if (ok && want == AUTH_OK) {
        ok = o->user_id == uid && o->name_n == strlen(name) && !memcmp(o->name, name, o->name_n);
    }
    if (!ok) {
        fprintf(stderr, "FAIL %s: status %d want %d (user %lld, name %.*s)\n", label, o->status, want,
                (long long)o->user_id, (int)o->name_n, o->name);
        failures++;
    }
    free(o);
}

// Signs the two JSON texts with the server key and checks "Bearer <token>".
static void expect_signed(const char *label, const char *head_json, const char *payload_json, enum auth_status want,
                          int64_t uid, const char *name) {
    static char hdr[40000];
    memcpy(hdr, "Bearer ", 7);
    size_t n = 7 + jwt_make(hdr + 7, head_json, payload_json, &auth_key);
    expect_auth(label, hdr, n, want, uid, name);
}

// Checks a literal header value.
static void expect_text(const char *label, const char *text, enum auth_status want) {
    expect_auth(label, text, strlen(text), want, 0, "");
}

// Runs a command and returns its first line of output.
static bool read_command(const char *cmd, char *out, size_t cap) {
    FILE *f = popen(cmd, "r");
    if (!f) {
        return false;
    }
    bool ok = fgets(out, (int)cap, f) != NULL;
    return pclose(f) == 0 && ok;
}

// Compares HMAC for secret lengths 0 to 200 with the openssl command line tool.
static void test_hmac_against_openssl(void) {
    char path[] = "/tmp/jwt_hmac_msg_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    char msg[160];
    for (unsigned i = 0; i < sizeof msg; i++) {
        msg[i] = (char)('a' + i % 26);
    }
    CHECK(write(fd, msg, sizeof msg) == (ssize_t)sizeof msg);
    close(fd);
    uint8_t key[200];
    for (unsigned i = 0; i < sizeof key; i++) {
        key[i] = (uint8_t)(i * 7 + 1);
    }
    unsigned compared = 0;
    for (unsigned kn = 0; kn <= sizeof key; kn++) {
        char hexkey[512] = "";
        for (unsigned i = 0; i < kn; i++) {
            snprintf(hexkey + 2 * i, 3, "%02x", key[i]);
        }
        char cmd[1024];
        if (kn) {
            snprintf(cmd, sizeof cmd, "openssl dgst -sha256 -mac HMAC -macopt hexkey:%s -r < %s 2>/dev/null", hexkey, path);
        } else {
            snprintf(cmd, sizeof cmd, "openssl dgst -sha256 -hmac '' -r < %s 2>/dev/null", path);
        }
        char line[256];
        if (!read_command(cmd, line, sizeof line)) {
            fprintf(stderr, "unit_jwt: openssl not usable, skipping the live HMAC comparison\n");
            unlink(path);
            return;
        }
        struct sha256_hmac_key k;
        uint8_t tag[32];
        char got[65];
        sha256_hmac_init(&k, key, kn);
        sha256_hmac(&k, msg, sizeof msg, tag);
        for (unsigned i = 0; i < 32; i++) {
            snprintf(got + 2 * i, 3, "%02x", tag[i]);
        }
        if (strncmp(line, got, 64)) {
            fprintf(stderr, "FAIL hmac with %u byte secret differs from openssl\n", kn);
            failures++;
        }
        compared++;
    }
    unlink(path);
    CHECK(compared == 201);
}

// Decodes text into a buffer exactly the size of the result plus slack and returns the decoder result.
static int64_t decode_text(const char *text, uint8_t *out, uint32_t cap) {
    return auth_b64url_decode((struct slice){text, (uint32_t)strlen(text)}, out, cap);
}

static void test_b64url(void) {
    uint8_t out[64];
    CHECK(decode_text("", out, 0) == 0);
    CHECK(decode_text("Zg", out, 1) == 1 && out[0] == 'f');
    CHECK(decode_text("Zm8", out, 2) == 2 && !memcmp(out, "fo", 2));
    CHECK(decode_text("Zm9v", out, 3) == 3 && !memcmp(out, "foo", 3));
    CHECK(decode_text("Zm9vYmFy", out, 6) == 6 && !memcmp(out, "foobar", 6));
    CHECK(decode_text("-_-_", out, 3) == 3 && out[0] == 0xfb && out[1] == 0xff && out[2] == 0xbf);
    CHECK(decode_text("Zm9vYmFy", out, 5) == -1);
    CHECK(decode_text("Zg", out, 0) == -1);
    CHECK(decode_text("Z", out, 8) == -1);
    CHECK(decode_text("Zm9vY", out, 8) == -1);
    CHECK(decode_text("Zg==", out, 8) == -1);
    CHECK(decode_text("Zm8=", out, 8) == -1);
    CHECK(decode_text("Zm9v YmFy", out, 8) == -1);
    CHECK(decode_text("Zm9v\n", out, 8) == -1);
    CHECK(decode_text("Zm+v", out, 8) == -1);
    CHECK(decode_text("Zm/v", out, 8) == -1);
    for (unsigned c = 0; c < 256; c++) {
        bool valid = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
        for (unsigned pos = 0; pos < 7; pos++) {
            char text[8] = "AAAAAAA";
            text[pos] = (char)c;
            bool ok = auth_b64url_decode((struct slice){text, 7}, out, sizeof out) == 5;
            if (ok != valid) {
                fprintf(stderr, "FAIL b64 byte %u at %u: accepted=%d valid=%d\n", c, pos, ok, valid);
                failures++;
            }
        }
    }
    uint8_t src[100];
    for (unsigned i = 0; i < sizeof src; i++) {
        src[i] = (uint8_t)(i * 53 + 11);
    }
    for (unsigned n = 0; n <= sizeof src; n++) {
        char enc[160];
        uint8_t back[100];
        size_t en = jwt_b64_encode(src, n, enc);
        CHECK(auth_b64url_decode((struct slice){enc, (uint32_t)en}, back, n) == (int64_t)n);
        CHECK(!memcmp(src, back, n));
    }
}

// Known token from the challenge's own test script format, signed with the challenge secret.
static void test_known_token(void) {
    const char *tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3IiwidXNlcm5hbWUiOiJhbGljZSJ9."
                      "NqAfIcLN65t0PKdZ1FhbFUImGabKVehoYLtrcCysUlc";
    char header[256];
    char want[256];
    snprintf(header, sizeof header, "Bearer %s", tok);
    uint8_t tag[32];
    const char *signed_part = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI3IiwidXNlcm5hbWUiOiJhbGljZSJ9";
    sha256_hmac(&auth_key, signed_part, strlen(signed_part), tag);
    size_t n = jwt_b64_encode(tag, sizeof tag, want);
    CHECK(n == 43);
    CHECK(!strcmp(want, tok + strlen(tok) - 43));
    struct outcome *o = malloc(sizeof *o);
    run_check(header, strlen(header), 32768, o);
    CHECK(o->status == AUTH_OK && o->user_id == 7 && o->name_n == 5 && !memcmp(o->name, "alice", 5));
    free(o);
}

// Every row signs a payload with the standard header and expects one outcome.
struct payload_case {
    const char *name;
    const char *payload;
    enum auth_status want;
    int64_t uid;
    const char *uname;
};

static const struct payload_case payload_cases[] = {
    {"valid", "{'sub':'7','username':'alice','iat':1699999000,'exp':1700003600}", AUTH_OK, 7, "alice"},
    {"no exp", "{'sub':'7','username':'alice'}", AUTH_OK, 7, "alice"},
    {"exp one second ahead", "{'sub':'7','username':'a','exp':1700000001}", AUTH_OK, 7, "a"},
    {"exp equals now", "{'sub':'7','username':'a','exp':1700000000}", AUTH_INVALID, 0, ""},
    {"exp expired", "{'sub':'7','username':'a','exp':1699999999}", AUTH_INVALID, 0, ""},
    {"exp fractional ahead", "{'sub':'7','username':'a','exp':1700000000.5}", AUTH_OK, 7, "a"},
    {"exp exponent", "{'sub':'7','username':'a','exp':1.7000001e9}", AUTH_OK, 7, "a"},
    {"exp huge", "{'sub':'7','username':'a','exp':1e300}", AUTH_OK, 7, "a"},
    {"exp negative", "{'sub':'7','username':'a','exp':-5}", AUTH_INVALID, 0, ""},
    {"exp string", "{'sub':'7','username':'a','exp':'9999999999'}", AUTH_INVALID, 0, ""},
    {"exp null", "{'sub':'7','username':'a','exp':null}", AUTH_INVALID, 0, ""},
    {"exp true", "{'sub':'7','username':'a','exp':true}", AUTH_INVALID, 0, ""},
    {"exp array", "{'sub':'7','username':'a','exp':[1700009999]}", AUTH_INVALID, 0, ""},
    {"exp duplicate last wins", "{'sub':'7','username':'a','exp':1,'exp':1700009999}", AUTH_OK, 7, "a"},
    {"nbf equals now", "{'sub':'7','username':'a','nbf':1700000000,'exp':1700003600}", AUTH_OK, 7, "a"},
    {"nbf in the past", "{'sub':'7','username':'a','nbf':1600000000}", AUTH_OK, 7, "a"},
    {"nbf in the future", "{'sub':'7','username':'a','nbf':1700000001}", AUTH_INVALID, 0, ""},
    {"nbf string", "{'sub':'7','username':'a','nbf':'1'}", AUTH_INVALID, 0, ""},
    {"nbf null", "{'sub':'7','username':'a','nbf':null}", AUTH_INVALID, 0, ""},
    {"expired beats bad sub", "{'sub':'0','username':'a','exp':1}", AUTH_INVALID, 0, ""},
    {"future nbf beats missing username", "{'sub':'7','nbf':1800000000}", AUTH_INVALID, 0, ""},
    {"payload not json", "not json at all", AUTH_INVALID, 0, ""},
    {"payload empty object ok but no sub", "{}", AUTH_BAD_PAYLOAD, 0, ""},
    {"payload array", "[1,2,3]", AUTH_INVALID, 0, ""},
    {"payload string", "'text'", AUTH_INVALID, 0, ""},
    {"payload number", "42", AUTH_INVALID, 0, ""},
    {"payload null", "null", AUTH_INVALID, 0, ""},
    {"payload trailing comma", "{'sub':'7','username':'a',}", AUTH_INVALID, 0, ""},
    {"payload truncated", "{'sub':'7','username':'a'", AUTH_INVALID, 0, ""},
    {"payload empty", "", AUTH_INVALID, 0, ""},
    {"sub zero", "{'sub':'0','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub leading zero", "{'sub':'01','username':'a'}", AUTH_OK, 1, "a"},
    {"sub padded with spaces", "{'sub':'  1 ','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub number", "{'sub':5,'username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub negative", "{'sub':'-3','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub negative number", "{'sub':-3,'username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub int64 max", "{'sub':'9223372036854775807','username':'a'}", AUTH_OK, INT64_MAX, "a"},
    {"sub int64 max plus one", "{'sub':'9223372036854775808','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub twenty digits", "{'sub':'99999999999999999999','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub empty", "{'sub':'','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub decimal", "{'sub':'1.5','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub hex", "{'sub':'0x10','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub plus sign", "{'sub':'+1','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub exponent", "{'sub':'1e3','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub missing", "{'username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub null", "{'sub':null,'username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub escaped digit", "{'sub':'\\u0031','username':'a'}", AUTH_OK, 1, "a"},
    {"sub duplicate last wins bad", "{'sub':'1','sub':'abc','username':'a'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"sub duplicate last wins good", "{'sub':'abc','sub':'7','username':'a'}", AUTH_OK, 7, "a"},
    {"username number", "{'sub':'7','username':42}", AUTH_BAD_PAYLOAD, 0, ""},
    {"username missing", "{'sub':'7'}", AUTH_BAD_PAYLOAD, 0, ""},
    {"username null", "{'sub':'7','username':null}", AUTH_BAD_PAYLOAD, 0, ""},
    {"username object", "{'sub':'7','username':{'a':1}}", AUTH_BAD_PAYLOAD, 0, ""},
    {"username empty string", "{'sub':'7','username':''}", AUTH_OK, 7, ""},
    {"username escaped", "{'sub':'7','username':'a\\u00e9\\n\\'b\\\\c\\/'}", AUTH_OK, 7, "a\xc3\xa9\n\"b\\c/"},
    {"username surrogate pair", "{'sub':'7','username':'\\ud83d\\ude00'}", AUTH_OK, 7, "\xf0\x9f\x98\x80"},
    {"username lone surrogate", "{'sub':'7','username':'\\ud800'}", AUTH_OK, 7, "\xef\xbf\xbd"},
    {"username raw utf8", "{'sub':'7','username':'h\xc3\xa9llo \xe2\x9c\x93'}", AUTH_OK, 7, "h\xc3\xa9llo \xe2\x9c\x93"},
    {"username last duplicate wins", "{'sub':'7','username':5,'username':'b'}", AUTH_OK, 7, "b"},
    {"extra keys and nesting", "{'a':{'b':[1,2,{'c':null}]},'sub':'7','username':'a','z':[]}", AUTH_OK, 7, "a"},
    {"keys with escapes", "{'s\\u0075b':'7','user\\u006eame':'a'}", AUTH_OK, 7, "a"},
    {"whitespace around", " {'sub' : '7' , 'username' : 'a'} ", AUTH_OK, 7, "a"},
};

static void test_payload_cases(void) {
    for (size_t i = 0; i < ARRAY_LEN(payload_cases); i++) {
        const struct payload_case *c = &payload_cases[i];
        expect_signed(c->name, JWT_TEST_HEADER, c->payload, c->want, c->uid, c->uname);
    }
}

static void test_header_cases(void) {
    const char *payload = "{'sub':'7','username':'alice','exp':1700003600}";
    expect_signed("header keys reordered", "{'typ':'JWT','alg':'HS256'}", payload, AUTH_OK, 7, "alice");
    expect_signed("header without typ", "{'alg':'HS256'}", payload, AUTH_OK, 7, "alice");
    expect_signed("header with spaces", "{ 'alg' : 'HS256' }", payload, AUTH_OK, 7, "alice");
    expect_signed("header alg escaped", "{'alg':'HS\\u0032\\u0035\\u0036'}", payload, AUTH_OK, 7, "alice");
    expect_signed("alg none", "{'alg':'none','typ':'JWT'}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg None", "{'alg':'None'}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg HS512", "{'alg':'HS512','typ':'JWT'}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg HS384", "{'alg':'HS384'}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg lowercase", "{'alg':'hs256'}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg with space", "{'alg':'HS256 '}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg RS256", "{'alg':'RS256'}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg missing", "{'typ':'JWT'}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg number", "{'alg':256}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg null", "{'alg':null}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg array", "{'alg':['HS256']}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg duplicate last wins none", "{'alg':'HS256','alg':'none'}", payload, AUTH_INVALID, 0, "");
    expect_signed("alg duplicate last wins hs256", "{'alg':'none','alg':'HS256'}", payload, AUTH_OK, 7, "alice");
    expect_signed("header is an array", "['HS256']", payload, AUTH_INVALID, 0, "");
    expect_signed("header is a string", "'HS256'", payload, AUTH_INVALID, 0, "");
    expect_signed("header not json", "HS256", payload, AUTH_INVALID, 0, "");
    expect_signed("header empty object", "{}", payload, AUTH_INVALID, 0, "");
    expect_signed("header empty", "", payload, AUTH_INVALID, 0, "");
    expect_signed("alg none beats bad payload", "{'alg':'none'}", "{'sub':'0'}", AUTH_INVALID, 0, "");
}

// Builds "Bearer <good token>" and returns its length.
static size_t good_header(char *out, const char *payload) {
    memcpy(out, "Bearer ", 7);
    return 7 + jwt_make(out + 7, JWT_TEST_HEADER, payload, &auth_key);
}

static void test_signature_cases(void) {
    static char h[1024];
    static char t[1024];
    const char *payload = "{'sub':'7','username':'alice','exp':1700003600}";
    size_t n = good_header(h, payload);
    expect_auth("good token", h, n, AUTH_OK, 7, "alice");
    size_t tn = jwt_make(t, JWT_TEST_HEADER, payload, &other_key);
    char other[1100];
    snprintf(other, sizeof other, "Bearer %s", t);
    expect_text("signed with another secret", other, AUTH_INVALID);
    for (size_t pos = 7; pos < n; pos++) {
        char m[1024];
        memcpy(m, h, n);
        m[pos] = m[pos] == 'A' ? 'B' : 'A';
        if (m[pos - 0] == h[pos] || h[pos] == '.') {
            continue;
        }
        struct outcome *o = malloc(sizeof *o);
        run_check(m, n, 32768, o);
        if (o->status != AUTH_INVALID && !(pos >= n - 1 && o->status == AUTH_OK)) {
            fprintf(stderr, "FAIL tamper at %zu gave status %d\n", pos, o->status);
            failures++;
        }
        free(o);
    }
    char s[1100];
    snprintf(s, sizeof s, "%.*s0", (int)n, h);
    expect_text("signature 44 chars", s, AUTH_INVALID);
    snprintf(s, sizeof s, "%.*s=", (int)n, h);
    expect_text("signature with padding", s, AUTH_INVALID);
    snprintf(s, sizeof s, "%.*s=", (int)n - 1, h);
    expect_text("signature last char is padding", s, AUTH_INVALID);
    snprintf(s, sizeof s, "%.*s", (int)n - 1, h);
    expect_text("signature 42 chars", s, AUTH_INVALID);
    snprintf(s, sizeof s, "%.*s+", (int)n - 1, h);
    expect_text("signature with plus", s, AUTH_INVALID);
    snprintf(s, sizeof s, "%.*s/", (int)n - 1, h);
    expect_text("signature with slash", s, AUTH_INVALID);
    snprintf(s, sizeof s, "%.*s ", (int)n - 1, h);
    expect_text("signature with space", s, AUTH_INVALID);
    snprintf(s, sizeof s, "%s ", h);
    expect_text("trailing space after token", s, AUTH_INVALID);
    snprintf(s, sizeof s, "%s\r\n", h);
    expect_text("trailing newline after token", s, AUTH_INVALID);
    (void)tn;
}

static void test_shape_cases(void) {
    static char h[1024];
    size_t n = good_header(h, "{'sub':'7','username':'alice'}");
    const char *tok = h + 7;
    const char *dot1 = strchr(tok, '.');
    const char *dot2 = strchr(dot1 + 1, '.');
    char s[1200];
    expect_auth("absent header", NULL, 0, AUTH_MISSING, 0, "");
    expect_text("empty header", "", AUTH_MISSING);
    expect_text("Bearer without space", "Bearer", AUTH_MISSING);
    expect_text("Basic scheme", "Basic abc", AUTH_MISSING);
    expect_text("lowercase scheme", "bearer abc.def.ghi", AUTH_MISSING);
    expect_text("scheme with tab", "Bearer\tabc", AUTH_MISSING);
    snprintf(s, sizeof s, "Token %s", tok);
    expect_text("other scheme with a good token", s, AUTH_MISSING);
    snprintf(s, sizeof s, "BEARER %s", tok);
    expect_text("uppercase scheme with a good token", s, AUTH_MISSING);
    snprintf(s, sizeof s, " Bearer %s", tok);
    expect_text("leading space before scheme", s, AUTH_MISSING);
    expect_text("Bearer and nothing", "Bearer ", AUTH_INVALID);
    expect_text("garbage token", "Bearer abc", AUTH_INVALID);
    expect_text("one dot", "Bearer abc.def", AUTH_INVALID);
    expect_text("two dots, empty segments", "Bearer ..", AUTH_INVALID);
    expect_text("three dots", "Bearer a.b.c.d", AUTH_INVALID);
    snprintf(s, sizeof s, "Bearer  %s", tok);
    expect_text("two spaces after scheme", s, AUTH_INVALID);
    snprintf(s, sizeof s, "Bearer %.*s", (int)(dot2 - tok), tok);
    expect_text("signature segment missing", s, AUTH_INVALID);
    snprintf(s, sizeof s, "Bearer %.*s.", (int)(dot2 - tok), tok);
    expect_text("signature segment empty", s, AUTH_INVALID);
    snprintf(s, sizeof s, "%s.AAAA", h);
    expect_text("extra segment", s, AUTH_INVALID);
    snprintf(s, sizeof s, "Bearer .%s", dot1 + 1);
    expect_text("header segment empty", s, AUTH_INVALID);
    snprintf(s, sizeof s, "Bearer %.*s..%s", (int)(dot1 - tok), tok, dot2 + 1);
    expect_text("payload segment empty", s, AUTH_INVALID);
    snprintf(s, sizeof s, "Bearer %.*s=.%s", (int)(dot1 - tok), tok, dot1 + 1);
    expect_text("header segment padded", s, AUTH_INVALID);
    snprintf(s, sizeof s, "Bearer %.*s.%.*s=.%s", (int)(dot1 - tok), tok, (int)(dot2 - dot1 - 1), dot1 + 1, dot2 + 1);
    expect_text("payload segment padded", s, AUTH_INVALID);
    snprintf(s, sizeof s, "Bearer %.*s+.%s", (int)(dot1 - tok), tok, dot1 + 1);
    expect_text("header segment foreign character", s, AUTH_INVALID);
    expect_auth("whole token", h, n, AUTH_OK, 7, "alice");
}

// Builds a token whose payload is a JSON object padded to the given decoded size.
static size_t padded_token(char *out, size_t payload_bytes) {
    static char json[16384];
    int n = snprintf(json, sizeof json, "{'sub':'7','username':'");
    size_t fill = payload_bytes - (size_t)n - LIT_LEN("'}");
    memset(json + n, 'x', fill);
    memcpy(json + n + fill, "'}", 3);
    memcpy(out, "Bearer ", 7);
    return 7 + jwt_make(out + 7, JWT_TEST_HEADER, json, &auth_key);
}

static void test_bounds(void) {
    static char big[40000];
    size_t n = padded_token(big, 6144);
    CHECK(n > 0);
    struct outcome *o = malloc(sizeof *o);
    run_check(big, n, 32768, o);
    CHECK(o->status == AUTH_OK && o->name_n == 6144 - 23 - 2);
    n = padded_token(big, 6147);
    expect_auth("payload of 8196 characters", big, n, AUTH_INVALID, 0, "");
    n = padded_token(big, 6150);
    expect_auth("payload of 8200 characters", big, n, AUTH_INVALID, 0, "");
    run_check(big, padded_token(big, 6144), 10, o);
    CHECK(o->status == AUTH_BAD_PAYLOAD);
    free(o);
    char long_head[9000];
    memset(long_head, 'A', sizeof long_head);
    memcpy(long_head, "Bearer ", 7);
    memcpy(long_head + 7 + 8193, ".AAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 51);
    expect_auth("header segment of 8193 characters", long_head, 7 + 8193 + 51, AUTH_INVALID, 0, "");
    static char huge[200000];
    memset(huge, 'A', sizeof huge);
    memcpy(huge, "Bearer ", 7);
    expect_auth("one hundred kilobytes without dots", huge, sizeof huge, AUTH_INVALID, 0, "");
    huge[5000] = '.';
    huge[9000] = '.';
    expect_auth("one hundred kilobytes with two dots", huge, sizeof huge, AUTH_INVALID, 0, "");
}

// The local sub parser must agree with the router's id parser on every shape of input.
static void test_sub_matches_route(void) {
    const char *samples[] = {"1", "0", "00", "007", "-1", "+1", "1.5", "abc", "12abc", " 1", "1 ", "", "9223372036854775807",
                             "9223372036854775808", "99999999999999999999", "0000000000000000000000001", "٣", "1e3"};
    for (size_t i = 0; i < ARRAY_LEN(samples); i++) {
        struct slice s = {samples[i], (uint32_t)strlen(samples[i])};
        int64_t a = 0;
        int64_t b = 0;
        bool mine = auth_parse_sub(s, &a);
        bool theirs = route_parse_id(s, &b) == ID_OK;
        CHECK(mine == theirs);
        CHECK(!mine || a == b);
    }
}

// Prints the cost of one auth_check for a token of about 160 bytes.
static void bench(void) {
    char tok[256];
    char payload[128];
    size_t un = 8;
    size_t n;
    do {
        snprintf(payload, sizeof payload, "{'sub':'1234','username':'%.*s','exp':1700003600}", (int)un,
                 "abcdefghijklmnopqrstuvwxyz");
        memcpy(tok, "Bearer ", 7);
        n = jwt_make(tok + 7, JWT_TEST_HEADER, payload, &auth_key);
    } while (n + 7 != 7 + 160 && ++un < 26);
    static char scratch[256];
    unsigned long long iters = 2000000;
    for (int pass = 0; pass < 2; pass++) {
#ifdef __SHA__
        sha256_scalar_only = pass == 0;
#else
        if (pass) {
            break;
        }
#endif
        uint64_t t0 = util_mono_ns();
        unsigned ok = 0;
        for (unsigned long long i = 0; i < iters; i++) {
            struct auth_identity id;
            ok += auth_check((struct slice){tok, (uint32_t)(n + 7)}, JWT_TEST_NOW, scratch, sizeof scratch, &id) == AUTH_OK;
        }
        uint64_t t1 = util_mono_ns();
        printf("bench: token %zu bytes, %s: %.1f ns per auth_check (%u ok)\n", n, pass == 0 ? "scalar" : "sha-ni",
               (double)(t1 - t0) / (double)iters, ok);
    }
}

int main(int argc, char **argv) {
    auth_init(JWT_TEST_SECRET, sizeof JWT_TEST_SECRET - 1);
    sha256_hmac_init(&other_key, "a different secret", 18);
    if (argc > 1 && !strcmp(argv[1], "bench")) {
        bench();
        return 0;
    }
    test_hmac_against_openssl();
    test_b64url();
    test_known_token();
    test_payload_cases();
    test_header_cases();
    test_signature_cases();
    test_shape_cases();
    test_bounds();
    test_sub_matches_route();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_jwt ok");
    return 0;
}
