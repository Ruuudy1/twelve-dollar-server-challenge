// Owner: json module. Strict body parser, unescape, JavaScript-style trim and the escaping writer.

#include <float.h>
#ifdef __SSE2__
#include <emmintrin.h>
#endif

// Type of a field found by json_extract.
enum json_type {
    JSON_ABSENT,
    JSON_STRING,
    JSON_NUMBER,
    JSON_OTHER,
};

// One requested key and what the document held for it; the last duplicate wins.
struct json_field {
    const char *key;
    uint8_t type;
    // True when a string value still contains backslash escapes.
    bool escaped;
    // For strings the bytes between the quotes, still escaped; for numbers the literal text.
    struct slice raw;
    double num;
};

enum json_status {
    JSON_OK,
    JSON_MALFORMED,
    JSON_NOT_OBJECT,
};

// Result of validating a create-post body.
enum json_body_status {
    JSON_BODY_OK,
    JSON_BODY_MALFORMED,
    JSON_BODY_REQUIRED,
    JSON_BODY_TOO_LONG,
};

// Bytes the escaping writer can emit for n input bytes.
#define JSON_ESCAPED_MAX(n) (6 * (size_t)(n))

// Parser positions between tokens.
enum json_state {
    JSON_ST_VALUE,
    JSON_ST_ARR_FIRST,
    JSON_ST_OBJ_FIRST,
    JSON_ST_KEY,
    JSON_ST_COLON,
    JSON_ST_AFTER,
    JSON_ST_BAD,
};

// Parse position of one json_extract call; kinds holds one bit per open container, set for an object.
struct json_ctx {
    const char *p;
    const char *end;
    struct json_field *fields;
    uint64_t kinds;
    unsigned count;
    unsigned depth;
    int cur;
    bool top_obj;
};

enum {
    JSON_KEY_MAX = 32,
    JSON_REPLACEMENT = 0xFFFD,
};

static_assert(JSON_DEPTH_MAX <= 64, "the container kind stack is one 64-bit word");

// Powers of ten that a 64-bit long double mantissa holds exactly.
static const long double json_pow10[] = {
    1e0L,  1e1L,  1e2L,  1e3L,  1e4L,  1e5L,  1e6L,  1e7L,  1e8L,  1e9L,  1e10L, 1e11L, 1e12L, 1e13L,
    1e14L, 1e15L, 1e16L, 1e17L, 1e18L, 1e19L, 1e20L, 1e21L, 1e22L, 1e23L, 1e24L, 1e25L, 1e26L, 1e27L,
};

// Returns true for the four whitespace bytes that RFC 8259 allows between tokens.
static bool json_is_ws(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

// Returns the first byte at or after p that is not JSON whitespace.
static const char *json_skip_ws(const char *p, const char *end) {
    while (p < end && json_is_ws(*p)) {
        p++;
    }
    return p;
}

// Returns the first byte at or after p that is not an ASCII digit.
static const char *json_skip_digits(const char *p, const char *end) {
    while (p < end && *p >= '0' && *p <= '9') {
        p++;
    }
    return p;
}

// Returns true when c lies in [lo, hi].
static bool json_in_range(char c, unsigned lo, unsigned hi) {
    unsigned u = (unsigned char)c;
    return u >= lo && u <= hi;
}

// Returns the length of the valid UTF-8 sequence starting at p (a byte of 0x80 or more), or 0 when it is invalid.
static uint32_t json_utf8_seq(const char *p, const char *end) {
    size_t avail = (size_t)(end - p);
    unsigned lead = (unsigned char)p[0];
    if (lead < 0xC2 || lead > 0xF4) {
        return 0;
    }
    if (lead < 0xE0) {
        return avail >= 2 && json_in_range(p[1], 0x80, 0xBF) ? 2 : 0;
    }
    if (lead < 0xF0) {
        unsigned lo = lead == 0xE0 ? 0xA0 : 0x80;
        unsigned hi = lead == 0xED ? 0x9F : 0xBF;
        return avail >= 3 && json_in_range(p[1], lo, hi) && json_in_range(p[2], 0x80, 0xBF) ? 3 : 0;
    }
    unsigned lo = lead == 0xF0 ? 0x90 : 0x80;
    unsigned hi = lead == 0xF4 ? 0x8F : 0xBF;
    bool ok = avail >= 4 && json_in_range(p[1], lo, hi) && json_in_range(p[2], 0x80, 0xBF) &&
              json_in_range(p[3], 0x80, 0xBF);
    return ok ? 4 : 0;
}

// Decodes the code point at p into cp and returns its length; an invalid sequence is one byte of U+FFFD.
static uint32_t json_decode_cp(const char *p, const char *end, uint32_t *cp) {
    uint32_t c0 = (unsigned char)p[0];
    uint32_t len = c0 < 0x80 ? 1 : json_utf8_seq(p, end);
    if (!len) {
        *cp = JSON_REPLACEMENT;
        return 1;
    }
    if (len == 1) {
        *cp = c0;
        return 1;
    }
    uint32_t v = c0 & (0xFFU >> (len + 1));
    for (uint32_t i = 1; i < len; i++) {
        v = (v << 6) | ((unsigned char)p[i] & 0x3FU);
    }
    *cp = v;
    return len;
}

// Returns the length of the UTF-8 form of cp.
static uint32_t json_utf8_len(uint32_t cp) {
    return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
}

// Writes cp as UTF-8 at dst and returns the length (1 to 4).
static uint32_t json_put_utf8(char *dst, uint32_t cp) {
    uint32_t len = json_utf8_len(cp);
    if (len == 1) {
        dst[0] = (char)cp;
        return 1;
    }
    static const uint32_t lead[] = {0, 0, 0xC0, 0xE0, 0xF0};
    for (uint32_t i = len - 1; i > 0; i--) {
        dst[i] = (char)(0x80 | (cp & 0x3F));
        cp >>= 6;
    }
    dst[0] = (char)(lead[len] | cp);
    return len;
}

// Returns the value of a hex digit, or 16 for any other byte.
static uint32_t json_hex_digit(char c) {
    if (c >= '0' && c <= '9') {
        return (uint32_t)(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return (uint32_t)(c - 'a') + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return (uint32_t)(c - 'A') + 10;
    }
    return 16;
}

// Reads four hex digits at p (the caller guarantees four bytes); returns false when one is not a hex digit.
static bool json_hex4(const char *p, uint32_t *v) {
    uint32_t r = 0;
    for (unsigned i = 0; i < 4; i++) {
        uint32_t d = json_hex_digit(p[i]);
        if (d > 15) {
            return false;
        }
        r = (r << 4) | d;
    }
    *v = r;
    return true;
}

// Returns the code point of a one-character escape such as n or t, or 0 when c is not an escape letter.
static uint32_t json_simple_escape(char c) {
    switch (c) {
    case '"':
    case '\\':
    case '/':
        return (unsigned char)c;
    case 'b':
        return '\b';
    case 'f':
        return '\f';
    case 'n':
        return '\n';
    case 'r':
        return '\r';
    case 't':
        return '\t';
    default:
        return 0;
    }
}

// Decodes a \uXXXX escape at p (pointing at the backslash); joins a surrogate pair and maps a lone one to U+FFFD.
static uint32_t json_decode_u_escape(const char *p, const char *end, uint32_t *cp) {
    uint32_t hi = 0;
    *cp = JSON_REPLACEMENT;
    if ((size_t)(end - p) < 6 || !json_hex4(p + 2, &hi)) {
        return 1;
    }
    if (hi < 0xD800 || hi > 0xDFFF) {
        *cp = hi;
        return 6;
    }
    uint32_t lo = 0;
    bool pair = hi < 0xDC00 && (size_t)(end - p) >= 12 && p[6] == '\\' && p[7] == 'u' && json_hex4(p + 8, &lo) &&
                lo >= 0xDC00 && lo <= 0xDFFF;
    if (pair) {
        *cp = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
        return 12;
    }
    return 6;
}

// Decodes the escape at p (pointing at the backslash) into cp and returns the bytes it spans; malformed gives U+FFFD.
static uint32_t json_decode_escape(const char *p, const char *end, uint32_t *cp) {
    *cp = JSON_REPLACEMENT;
    if (end - p < 2) {
        return 1;
    }
    if (p[1] == 'u') {
        return json_decode_u_escape(p, end, cp);
    }
    uint32_t simple = json_simple_escape(p[1]);
    if (!simple) {
        return 1;
    }
    *cp = simple;
    return 2;
}

// Decodes a string body into dst, joining surrogate pairs; returns the length or -1 when cap is too small.
static int64_t json_unescape(struct slice s, char *dst, uint32_t cap) {
    const char *p = s.p;
    const char *end = s.p + s.n;
    uint32_t w = 0;
    while (p < end) {
        const char *bs = memchr(p, '\\', (size_t)(end - p));
        size_t run = (size_t)((bs ? bs : end) - p);
        if (run > cap - w) {
            return -1;
        }
        memcpy(dst + w, p, run);
        w += (uint32_t)run;
        p += run;
        if (!bs) {
            break;
        }
        uint32_t cp = 0;
        uint32_t used = json_decode_escape(p, end, &cp);
        if (json_utf8_len(cp) > cap - w) {
            return -1;
        }
        w += json_put_utf8(dst + w, cp);
        p += used;
    }
    return w;
}

#ifdef __SSE2__
// Returns the first byte at or after p that a string scan must look at: a control byte, a quote, a backslash or 0x80+.
static const char *json_skip_plain(const char *p, const char *end) {
    const __m128i low = _mm_set1_epi8(0x20);
    const __m128i quote = _mm_set1_epi8('"');
    const __m128i slash = _mm_set1_epi8('\\');
    while ((size_t)(end - p) >= 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)p);
        __m128i special = _mm_or_si128(_mm_cmpeq_epi8(v, quote), _mm_cmpeq_epi8(v, slash));
        unsigned mask = (unsigned)_mm_movemask_epi8(_mm_or_si128(special, _mm_cmplt_epi8(v, low)));
        if (mask) {
            return p + __builtin_ctz(mask);
        }
        p += 16;
    }
    while (p < end && (unsigned char)*p >= 0x20 && (unsigned char)*p < 0x80 && *p != '"' && *p != '\\') {
        p++;
    }
    return p;
}
#else
// Returns the first byte at or after p that a string scan must look at: a control byte, a quote, a backslash or 0x80+.
static const char *json_skip_plain(const char *p, const char *end) {
    while (p < end && (unsigned char)*p >= 0x20 && (unsigned char)*p < 0x80 && *p != '"' && *p != '\\') {
        p++;
    }
    return p;
}
#endif

// Scans one escape after a backslash at p; returns the byte after it, or NULL when it is not valid JSON.
static const char *json_scan_escape(const char *p, const char *end) {
    if (end - p < 2) {
        return NULL;
    }
    if (json_simple_escape(p[1])) {
        return p + 2;
    }
    uint32_t unused = 0;
    if (p[1] != 'u' || end - p < 6 || !json_hex4(p + 2, &unused)) {
        return NULL;
    }
    return p + 6;
}

// Scans a string body that starts after the opening quote; returns the closing quote, or NULL when malformed.
static const char *json_scan_string(const char *p, const char *end, bool *escaped) {
    while (p < end) {
        p = json_skip_plain(p, end);
        if (p == end) {
            return NULL;
        }
        unsigned char c = (unsigned char)*p;
        if (c == '"') {
            return p;
        }
        if (c < 0x20) {
            return NULL;
        }
        uint32_t seq = json_utf8_seq(p, end);
        if (c == '\\') {
            *escaped = true;
            p = json_scan_escape(p, end);
        } else {
            p = seq ? p + seq : NULL;
        }
        if (!p) {
            return NULL;
        }
    }
    return NULL;
}

// Scans an RFC 8259 number starting at p; returns the byte after it, or NULL when malformed.
static const char *json_scan_number(const char *p, const char *end) {
    if (p < end && *p == '-') {
        p++;
    }
    if (p == end || *p < '0' || *p > '9') {
        return NULL;
    }
    p = *p == '0' ? p + 1 : json_skip_digits(p, end);
    if (p < end && *p == '.') {
        const char *frac = json_skip_digits(p + 1, end);
        if (frac == p + 1) {
            return NULL;
        }
        p = frac;
    }
    if (p < end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < end && (*p == '+' || *p == '-')) {
            p++;
        }
        const char *exp = json_skip_digits(p, end);
        if (exp == p) {
            return NULL;
        }
        p = exp;
    }
    return p;
}

// Reads the exponent digits of a validated number literal at p, saturating at 100000.
static int32_t json_exponent(const char *p, const char *end) {
    int32_t x = 0;
    bool neg = false;
    if (p < end && (*p == '+' || *p == '-')) {
        neg = *p == '-';
        p++;
    }
    for (; p < end && x < 100000; p++) {
        x = x * 10 + (*p - '0');
    }
    return neg ? -x : x;
}

// Scales v by 10 to the power e10, with e10 already clamped to a few hundred.
static long double json_scale10(long double v, int32_t e10) {
    while (e10 >= 27) {
        v *= json_pow10[27];
        e10 -= 27;
    }
    while (e10 <= -27) {
        v /= json_pow10[27];
        e10 += 27;
    }
    return e10 >= 0 ? v * json_pow10[e10] : v / json_pow10[-e10];
}

// Converts a validated number literal to a double: exact for up to 19 digits and small exponents, close otherwise.
static double json_number_value(struct slice s) {
    const char *p = s.p;
    const char *end = s.p + s.n;
    bool neg = p < end && *p == '-';
    uint64_t m = 0;
    unsigned sig = 0;
    int32_t e10 = 0;
    p += neg;
    for (bool frac = false; p < end && *p != 'e' && *p != 'E'; p++) {
        if (*p == '.') {
            frac = true;
        } else if (sig < 19) {
            m = m * 10 + (uint64_t)(*p - '0');
            sig += m != 0;
            e10 -= frac;
        } else {
            e10 += !frac;
        }
    }
    if (!m) {
        return neg ? -0.0 : 0.0;
    }
    int32_t total = e10 + (p < end ? json_exponent(p + 1, end) : 0);
    if (total > 400) {
        return neg ? -__builtin_inf() : __builtin_inf();
    }
    long double v = total < -500 ? 0.0L : json_scale10((long double)m, total);
    double r = v > (long double)DBL_MAX ? __builtin_inf() : (double)v;
    return neg ? -r : r;
}

// Returns the index of the requested field whose key equals the string raw (compared after unescaping), or -1.
static int json_match_key(struct slice raw, bool escaped, const struct json_field *fields, unsigned count) {
    char tmp[JSON_KEY_MAX];
    const char *key = raw.p;
    size_t n = raw.n;
    if (escaped) {
        int64_t len = json_unescape(raw, tmp, sizeof tmp);
        if (len < 0) {
            return -1;
        }
        key = tmp;
        n = (size_t)len;
    }
    for (unsigned i = 0; i < count; i++) {
        if (strlen(fields[i].key) == n && !memcmp(fields[i].key, key, n)) {
            return (int)i;
        }
    }
    return -1;
}

// Records a value for the requested field cur, replacing an earlier duplicate.
static void json_store(struct json_ctx *c, int cur, uint8_t type, struct slice raw, bool escaped) {
    struct json_field *f = &c->fields[cur];
    f->type = type;
    f->escaped = escaped;
    f->raw = raw;
    f->num = type == JSON_NUMBER ? json_number_value(raw) : 0.0;
}

// Marks every requested field absent.
static void json_fields_reset(struct json_field *fields, unsigned count) {
    for (unsigned i = 0; i < count; i++) {
        fields[i].type = JSON_ABSENT;
        fields[i].escaped = false;
        fields[i].raw = (struct slice){NULL, 0};
        fields[i].num = 0.0;
    }
}

// Returns true when the innermost open container is an object.
static bool json_in_object(const struct json_ctx *c) {
    return ((c->kinds >> (c->depth - 1)) & 1) != 0;
}

// Opens a container if the depth cap allows it.
static bool json_open(struct json_ctx *c, char ch) {
    if (c->depth >= JSON_DEPTH_MAX) {
        return false;
    }
    uint64_t bit = 1ULL << c->depth;
    bool obj = ch == '{';
    if (!c->depth) {
        c->top_obj = obj;
    }
    c->kinds = obj ? c->kinds | bit : c->kinds & ~bit;
    c->depth++;
    return true;
}

// Closes the innermost container when ch is its matching bracket.
static enum json_state json_close(struct json_ctx *c, char ch) {
    if (ch != (json_in_object(c) ? '}' : ']')) {
        return JSON_ST_BAD;
    }
    c->depth--;
    c->p++;
    return JSON_ST_AFTER;
}

// Consumes the literal word true, false or null.
static bool json_literal(struct json_ctx *c, const char *word, size_t n) {
    if ((size_t)(c->end - c->p) < n || memcmp(c->p, word, n)) {
        return false;
    }
    c->p += n;
    return true;
}

// Consumes a literal word starting with t, f or n.
static bool json_word(struct json_ctx *c) {
    switch (*c->p) {
    case 't':
        return json_literal(c, "true", 4);
    case 'f':
        return json_literal(c, "false", 5);
    case 'n':
        return json_literal(c, "null", 4);
    default:
        return false;
    }
}

// Consumes a string value; cur names the requested field to fill, or is negative.
static bool json_scalar_string(struct json_ctx *c, int cur) {
    const char *start = c->p + 1;
    bool escaped = false;
    const char *close = json_scan_string(start, c->end, &escaped);
    if (!close) {
        return false;
    }
    c->p = close + 1;
    if (cur >= 0) {
        json_store(c, cur, JSON_STRING, (struct slice){start, (uint32_t)(close - start)}, escaped);
    }
    return true;
}

// Consumes a number value; cur names the requested field to fill, or is negative.
static bool json_scalar_number(struct json_ctx *c, int cur) {
    const char *start = c->p;
    const char *stop = json_scan_number(start, c->end);
    if (!stop) {
        return false;
    }
    c->p = stop;
    if (cur >= 0) {
        json_store(c, cur, JSON_NUMBER, (struct slice){start, (uint32_t)(stop - start)}, false);
    }
    return true;
}

// Consumes a string, number or literal value, recording it when cur names a requested field.
static bool json_scalar(struct json_ctx *c, int cur) {
    char ch = *c->p;
    if (ch == '"') {
        return json_scalar_string(c, cur);
    }
    if (ch == '-' || (ch >= '0' && ch <= '9')) {
        return json_scalar_number(c, cur);
    }
    if (!json_word(c)) {
        return false;
    }
    if (cur >= 0) {
        json_store(c, cur, JSON_OTHER, (struct slice){NULL, 0}, false);
    }
    return true;
}

// Handles the first byte of a value: opens a container or consumes a scalar.
static enum json_state json_step_value(struct json_ctx *c) {
    char ch = *c->p;
    int cur = c->cur;
    c->cur = -1;
    if (ch != '{' && ch != '[') {
        return json_scalar(c, cur) ? JSON_ST_AFTER : JSON_ST_BAD;
    }
    if (!json_open(c, ch)) {
        return JSON_ST_BAD;
    }
    if (cur >= 0) {
        json_store(c, cur, JSON_OTHER, (struct slice){NULL, 0}, false);
    }
    c->p++;
    return ch == '{' ? JSON_ST_OBJ_FIRST : JSON_ST_ARR_FIRST;
}

// Handles an object key: scans the string and notes which requested field it names at the top level.
static enum json_state json_step_key(struct json_ctx *c) {
    bool escaped = false;
    if (*c->p != '"') {
        return JSON_ST_BAD;
    }
    const char *close = json_scan_string(c->p + 1, c->end, &escaped);
    if (!close) {
        return JSON_ST_BAD;
    }
    if (c->depth == 1) {
        struct slice raw = {c->p + 1, (uint32_t)(close - c->p - 1)};
        c->cur = json_match_key(raw, escaped, c->fields, c->count);
    }
    c->p = close + 1;
    return JSON_ST_COLON;
}

// Handles the byte after a completed value: a comma or the closing bracket of the innermost container.
static enum json_state json_step_after(struct json_ctx *c) {
    char ch = *c->p;
    if (!c->depth) {
        return JSON_ST_BAD;
    }
    if (ch != ',') {
        return json_close(c, ch);
    }
    c->p++;
    return json_in_object(c) ? JSON_ST_KEY : JSON_ST_VALUE;
}

// Advances the parser by one token starting at the non-whitespace byte at c->p.
static enum json_state json_step(struct json_ctx *c, enum json_state st) {
    char ch = *c->p;
    switch (st) {
    case JSON_ST_VALUE:
        return json_step_value(c);
    case JSON_ST_ARR_FIRST:
        return ch == ']' ? json_close(c, ch) : json_step_value(c);
    case JSON_ST_OBJ_FIRST:
        return ch == '}' ? json_close(c, ch) : json_step_key(c);
    case JSON_ST_KEY:
        return json_step_key(c);
    case JSON_ST_COLON:
        c->p++;
        return ch == ':' ? JSON_ST_VALUE : JSON_ST_BAD;
    case JSON_ST_AFTER:
        return json_step_after(c);
    case JSON_ST_BAD:
    default:
        return JSON_ST_BAD;
    }
}

// Validates the whole document as RFC 8259 JSON and fills the requested top-level fields of an object.
static enum json_status json_extract(struct slice doc, struct json_field *fields, unsigned count) {
    struct json_ctx c = {.p = doc.p, .end = doc.p + doc.n, .fields = fields, .count = count, .cur = -1};
    enum json_state st = JSON_ST_VALUE;
    json_fields_reset(fields, count);
    // Every step consumes at least one byte of the document or ends the scan.
    while (st != JSON_ST_BAD) {
        c.p = json_skip_ws(c.p, c.end);
        if (c.p == c.end) {
            break;
        }
        st = json_step(&c, st);
    }
    if (st != JSON_ST_AFTER || c.depth) {
        json_fields_reset(fields, count);
        return JSON_MALFORMED;
    }
    return c.top_obj ? JSON_OK : JSON_NOT_OBJECT;
}

// Returns true for the code points of the JavaScript String.prototype.trim whitespace set.
static bool json_is_space_cp(uint32_t cp) {
    if (cp <= 0x20) {
        return cp == 0x20 || (cp >= 0x09 && cp <= 0x0D);
    }
    if (cp >= 0x2000 && cp <= 0x200A) {
        return true;
    }
    return cp == 0xA0 || cp == 0x1680 || cp == 0x2028 || cp == 0x2029 || cp == 0x202F || cp == 0x205F ||
           cp == 0x3000 || cp == 0xFEFF;
}

// Returns the start of the code point that ends at e, looking back at most three continuation bytes.
static const char *json_prev_start(const char *b, const char *e) {
    const char *s = e - 1;
    for (unsigned i = 0; i < 3 && s > b && ((unsigned char)*s & 0xC0) == 0x80; i++) {
        s--;
    }
    return s;
}

// Trims the JavaScript whitespace set from both ends of UTF-8 text.
static struct slice json_trim_js(struct slice s) {
    const char *b = s.p;
    const char *e = s.p + s.n;
    uint32_t cp = 0;
    while (b < e) {
        uint32_t len = json_decode_cp(b, e, &cp);
        if (!json_is_space_cp(cp)) {
            break;
        }
        b += len;
    }
    while (e > b) {
        const char *start = json_prev_start(b, e);
        uint32_t len = json_decode_cp(start, e, &cp);
        if (start + len != e || !json_is_space_cp(cp)) {
            break;
        }
        e = start;
    }
    return (struct slice){b, (uint32_t)(e - b)};
}

// Counts Unicode code points in UTF-8 text.
static uint32_t json_count_chars(struct slice s) {
    uint32_t chars = 0;
    for (uint32_t i = 0; i < s.n; i++) {
        chars += (s.p[i] & 0xC0) != 0x80;
    }
    return chars;
}

// Parses a create body, unescapes and trims its "body" string into scratch, and applies the length rules.
static NOT_YET_USED enum json_body_status json_create_body(struct slice doc, char *scratch, uint32_t cap, struct slice *out) {
    struct json_field body = {.key = "body"};
    out->p = scratch;
    out->n = 0;
    enum json_status st = json_extract(doc, &body, 1);
    if (st == JSON_MALFORMED) {
        return JSON_BODY_MALFORMED;
    }
    if (st == JSON_NOT_OBJECT || body.type != JSON_STRING) {
        return JSON_BODY_REQUIRED;
    }
    int64_t n = json_unescape(body.raw, scratch, cap);
    if (n < 0) {
        return JSON_BODY_MALFORMED;
    }
    struct slice text = json_trim_js((struct slice){scratch, (uint32_t)n});
    if (!text.n) {
        return JSON_BODY_REQUIRED;
    }
    if (json_count_chars(text) > BODY_MAX_CHARS) {
        return JSON_BODY_TOO_LONG;
    }
    *out = text;
    return JSON_BODY_OK;
}

// Writes the escaped form of s (without quotes) at o one byte at a time; the reference for the vector path.
static char *json_put_string_scalar(char *o, const char *s, size_t n) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 0x20 && c != '"' && c != '\\') {
            *o++ = (char)c;
            continue;
        }
        *o++ = '\\';
        switch (c) {
        case '"':
        case '\\':
            *o++ = (char)c;
            break;
        case '\b':
            *o++ = 'b';
            break;
        case '\f':
            *o++ = 'f';
            break;
        case '\n':
            *o++ = 'n';
            break;
        case '\r':
            *o++ = 'r';
            break;
        case '\t':
            *o++ = 't';
            break;
        default:
            *o++ = 'u';
            *o++ = '0';
            *o++ = '0';
            *o++ = hex[c >> 4];
            *o++ = hex[c & 15];
            break;
        }
    }
    return o;
}

#ifdef __SSE2__
// Writes the escaped form of s (without quotes) at o and returns the end; room for JSON_ESCAPED_MAX(n) is required.
static char *json_put_string(char *o, const char *s, size_t n) {
    const __m128i ctrl_max = _mm_set1_epi8(0x1F);
    const __m128i quote = _mm_set1_epi8('"');
    const __m128i slash = _mm_set1_epi8('\\');
    while (n >= 16) {
        __m128i v = _mm_loadu_si128((const __m128i *)s);
        __m128i special = _mm_or_si128(_mm_cmpeq_epi8(v, quote), _mm_cmpeq_epi8(v, slash));
        __m128i hit = _mm_or_si128(special, _mm_cmpeq_epi8(_mm_min_epu8(v, ctrl_max), v));
        unsigned mask = (unsigned)_mm_movemask_epi8(hit);
        // All sixteen bytes are stored even when fewer are kept, which the sixfold room guarantee allows.
        _mm_storeu_si128((__m128i *)o, v);
        if (!mask) {
            o += 16;
            s += 16;
            n -= 16;
            continue;
        }
        unsigned keep = (unsigned)__builtin_ctz(mask);
        o = json_put_string_scalar(o + keep, s + keep, 1);
        s += keep + 1;
        n -= keep + 1;
    }
    return json_put_string_scalar(o, s, n);
}
#else
// Writes the escaped form of s (without quotes) at o and returns the end; room for JSON_ESCAPED_MAX(n) is required.
static char *json_put_string(char *o, const char *s, size_t n) {
    return json_put_string_scalar(o, s, n);
}
#endif
