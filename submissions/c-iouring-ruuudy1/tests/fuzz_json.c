// Fuzz driver for the json module: random and mutated documents, writer equality and memory safety under ASan.
// Usage: fuzz_json <iterations> [seed] [emit]. With emit, one binary record per document goes to stdout for
// tests/fuzz_json.py, which compares every result with Python's json module.
#define FM_TEST 1
#include "../src/main.c"

enum {
    DOC_MAX = 4096,
    FIELD_COUNT = 4,
};

static uint64_t rng_state;

// Returns the next pseudo-random 64-bit value (xorshift64).
static uint64_t rnd(void) {
    uint64_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    rng_state = x;
    return x;
}

// Returns a pseudo-random value below n (n above zero).
static uint32_t below(uint32_t n) {
    return (uint32_t)(rnd() % n);
}

// Returns true with probability one in n.
static bool one_in(uint32_t n) {
    return below(n) == 0;
}

struct gen {
    char buf[DOC_MAX];
    uint32_t n;
};

// Appends bytes unless the document is full.
static void put(struct gen *g, const char *s, size_t n) {
    if (n <= DOC_MAX - g->n) {
        memcpy(g->buf + g->n, s, n);
        g->n += (uint32_t)n;
    }
}

// Appends a NUL-terminated literal.
static void puts_lit(struct gen *g, const char *s) {
    put(g, s, strlen(s));
}

// Appends optional whitespace, rarely including bytes JSON does not allow.
static void put_ws(struct gen *g) {
    static const char good[] = {' ', '\t', '\n', '\r'};
    static const char *const bad[] = {"\f", "\v", "\xc2\xa0", "\xef\xbb\xbf", "\xe2\x80\xa8"};
    uint32_t r = below(24);
    if (r < 6) {
        put(g, &good[r % 4], 1);
    } else if (r == 6 && one_in(8)) {
        puts_lit(g, bad[below(ARRAY_LEN(bad))]);
    }
}

static const char *const str_pieces[] = {
    "a", "hello", " ", "  ", "x y z", "body", "</b>&amp;", "/", "caf\xc3\xa9", "\xe2\x9c\x93", "\xf0\x9f\x98\x80",
    "\xef\xbf\xbd", "\xc2\xa0", "\xe3\x80\x80", "\xef\xbb\xbf", "\xe2\x80\xa8", "\xe1\x9a\x80", "\xc2\x85", "\xe2\x80\x8b",
    "\xf4\x8f\xbf\xbf", "\xdf\xbf", "\xed\x9f\xbf", "\x7f", "\\\"", "\\\\", "\\/", "\\b", "\\f", "\\n", "\\r", "\\t",
    "\\u0041", "\\u00e9", "\\u20ac", "\\u0000", "\\u001f", "\\u00a0", "\\u3000", "\\ufeff", "\\u2028", "\\u200b",
    "\\u0020", "\\u000b", "\\ud83d\\ude00", "\\uD83D\\uDE00", "\\ud800", "\\udc00", "\\ud83d", "\\udbff\\udfff",
    "\\ud83d\\ud83d", "\\ude00\\ud83d", "\\ud83d\\u0041",
};

static const char *const str_bad_pieces[] = {
    "\"", "\\", "\\x", "\\u", "\\u12", "\\uZZZZ", "\\U0041", "\n", "\t", "\x01", "\x1f", "\xff", "\x80", "\xc0\x80",
    "\xc3", "\xe2\x82", "\xed\xa0\x80", "\xed\xb0\x80", "\xf0\x80\x80\x80", "\xf4\x90\x80\x80", "\xf5", "\xe0\x80\x80",
};

// Appends a quoted string made of pieces, sometimes invalid.
static void gen_string(struct gen *g, bool allow_bad) {
    put(g, "\"", 1);
    uint32_t pieces = below(8);
    for (uint32_t i = 0; i < pieces; i++) {
        if (allow_bad && one_in(20)) {
            puts_lit(g, str_bad_pieces[below(ARRAY_LEN(str_bad_pieces))]);
        } else if (one_in(6)) {
            uint32_t run = below(40);
            for (uint32_t j = 0; j < run; j++) {
                char c = (char)('a' + below(26));
                put(g, &c, 1);
            }
        } else {
            puts_lit(g, str_pieces[below(ARRAY_LEN(str_pieces))]);
        }
    }
    put(g, "\"", 1);
}

static const char *const key_pool[] = {
    "\"body\"", "\"n\"", "\"a\"", "\"caf\xc3\xa9\"", "\"caf\\u00e9\"", "\"b\\u006fdy\"", "\"\\u0062ody\"", "\"Body\"",
    "\"bod\"", "\"bodyy\"", "\"\"", "\"x\"", "\"n\\u0000\"", "\"\\ud800\"", "\"caf\\u00E9\"", "\"\\u0061\"",
};

static const char *const number_pool[] = {
    "0", "-0", "1", "-1", "12", "123", "1700000000", "1.5", "-2.5", "0.1", "1e2", "1E2", "1e+2", "1e-2", "1.5e3",
    "0e0", "0.0", "123456789012345678901234567890", "1e999", "-1e999", "1e-999", "9007199254740993", "0.000001",
    "12345678901234567890", "1.7976931348623157e308", "4.9e-324", "0.5e-1", "100000000000000000000000000000000000000",
};

static const char *const number_bad_pool[] = {
    "01", "-01", "00", "1.", ".5", "-", "+1", "1e", "1e+", "1.e5", "0x1", "NaN", "Infinity", "-Infinity", "1_0",
    "--1", "1-", "1.5.5", "0e", "1ee5", "١٢",
};

// Appends a number, sometimes malformed.
static void gen_number(struct gen *g, bool allow_bad) {
    if (allow_bad && one_in(12)) {
        puts_lit(g, number_bad_pool[below(ARRAY_LEN(number_bad_pool))]);
    } else if (one_in(5)) {
        char digits[24];
        uint32_t n = 1 + below(20);
        digits[0] = (char)('1' + below(9));
        for (uint32_t i = 1; i < n; i++) {
            digits[i] = (char)('0' + below(10));
        }
        put(g, digits, n);
    } else {
        puts_lit(g, number_pool[below(ARRAY_LEN(number_pool))]);
    }
}

// Appends a scalar value, sometimes malformed.
static void gen_scalar(struct gen *g, bool allow_bad) {
    uint32_t r = below(10);
    if (r < 4) {
        gen_string(g, allow_bad);
    } else if (r < 7) {
        gen_number(g, allow_bad);
    } else if (allow_bad && one_in(10)) {
        static const char *const bad[] = {"True", "NULL", "nul", "tru", "nulll", "undefined", "NaN", "Infinity", "'x'"};
        puts_lit(g, bad[below(ARRAY_LEN(bad))]);
    } else {
        static const char *const lit[] = {"true", "false", "null"};
        puts_lit(g, lit[below(3)]);
    }
}

// Appends a container value with the given nesting budget; every level is bounded by the budget.
static void gen_value(struct gen *g, uint32_t budget, bool allow_bad) {
    if (!budget || one_in(3) || g->n > DOC_MAX - 256) {
        gen_scalar(g, allow_bad);
        return;
    }
    bool obj = one_in(2);
    uint32_t members = below(4);
    put(g, obj ? "{" : "[", 1);
    for (uint32_t i = 0; i < members; i++) {
        put_ws(g);
        if (i) {
            if (!allow_bad || !one_in(30)) {
                put(g, ",", 1);
            }
            put_ws(g);
        }
        if (obj) {
            puts_lit(g, key_pool[below(ARRAY_LEN(key_pool))]);
            put_ws(g);
            if (!allow_bad || !one_in(40)) {
                put(g, ":", 1);
            }
            put_ws(g);
        }
        gen_value(g, budget - 1, allow_bad);
    }
    put_ws(g);
    put(g, obj ? "}" : "]", 1);
}

// Appends a chain of containers whose depth sits near the cap.
static void gen_deep(struct gen *g) {
    uint32_t depth = 58 + below(12);
    bool closers[80];
    for (uint32_t i = 0; i < depth; i++) {
        bool obj = one_in(2);
        closers[i] = obj;
        puts_lit(g, obj ? "{\"body\":" : "[");
    }
    puts_lit(g, "\"leaf\"");
    for (uint32_t i = depth; i > 0; i--) {
        put(g, closers[i - 1] ? "}" : "]", 1);
    }
}

// Appends a create-body document whose string is padded with trim candidates and sometimes near the length cap.
static void gen_body_doc(struct gen *g) {
    static const char *const pad[] = {" ", "  ", "\\n", "\\u00a0", "\\u3000", "\\ufeff", "\\t", "\\u2028", "\\u200b", "\\u0085"};
    static const char *const unit[] = {"a", "\xc3\xa9", "\xf0\x9f\x98\x80", "\\ud83d\\ude00", "\\u20ac", "\\ud800", "\\n"};
    puts_lit(g, one_in(4) ? "{\"b\\u006fdy\":\"" : "{\"body\":\"");
    uint32_t lead = below(4);
    for (uint32_t i = 0; i < lead; i++) {
        puts_lit(g, pad[below(ARRAY_LEN(pad))]);
    }
    const char *u = unit[below(ARRAY_LEN(unit))];
    uint32_t count = one_in(2) ? 495 + below(12) : below(30);
    for (uint32_t i = 0; i < count && g->n < DOC_MAX - 64; i++) {
        puts_lit(g, u);
    }
    uint32_t trail = below(4);
    for (uint32_t i = 0; i < trail; i++) {
        puts_lit(g, pad[below(ARRAY_LEN(pad))]);
    }
    puts_lit(g, one_in(5) ? "\",\"n\":1}" : "\"}");
}

// Builds a document: usually an object with the keys the module reads, sometimes any value or a deep chain.
static void gen_document(struct gen *g) {
    g->n = 0;
    bool allow_bad = one_in(3);
    uint32_t r = below(20);
    put_ws(g);
    if (r == 0) {
        gen_deep(g);
    } else if (r == 1) {
        gen_value(g, 4, allow_bad);
    } else if (r < 8) {
        gen_body_doc(g);
    } else {
        puts_lit(g, "{");
        uint32_t members = below(5);
        for (uint32_t i = 0; i < members; i++) {
            put_ws(g);
            if (i) {
                put(g, ",", 1);
            }
            puts_lit(g, key_pool[below(ARRAY_LEN(key_pool))]);
            put_ws(g);
            put(g, ":", 1);
            put_ws(g);
            gen_value(g, 3, allow_bad);
        }
        put_ws(g);
        puts_lit(g, "}");
    }
    put_ws(g);
}

static const char *const splice_pool[] = {
    "NaN", "Infinity", "-Infinity", "\\ud800", "\\udc00", "\\u", "\\", "\"", "{", "}", "[", "]", ",", ":", "\0", "\x1f",
    "\xff", "\x80", "\xc0", "\xed\xa0\x80", "\xef\xbb\xbf", "-0", "e5", "01", "//", "/*", "true", "null", " ", "\n",
};

// Applies one to four random edits to the document.
static void mutate(struct gen *g) {
    uint32_t edits = 1 + below(4);
    for (uint32_t e = 0; e < edits && g->n; e++) {
        uint32_t pos = below(g->n);
        uint32_t op = below(7);
        if (op == 0) {
            g->buf[pos] = (char)below(256);
        } else if (op == 1) {
            g->buf[pos] = (char)(g->buf[pos] ^ (1U << below(8)));
        } else if (op == 2) {
            memmove(g->buf + pos, g->buf + pos + 1, g->n - pos - 1);
            g->n--;
        } else if (op == 3) {
            g->n = pos;
        } else if (op == 4 && g->n < DOC_MAX - 64) {
            uint32_t len = 1 + below(g->n - pos < 32 ? g->n - pos : 32);
            memmove(g->buf + pos + len, g->buf + pos, g->n - pos);
            g->n += len;
        } else if (op == 5 && g->n < DOC_MAX - 64) {
            const char *s = splice_pool[below(ARRAY_LEN(splice_pool))];
            size_t len = s[0] ? strlen(s) : 1;
            memmove(g->buf + pos + len, g->buf + pos, g->n - pos);
            memcpy(g->buf + pos, s, len);
            g->n += (uint32_t)len;
        } else if (g->n < DOC_MAX - 1) {
            memmove(g->buf + pos + 1, g->buf + pos, g->n - pos);
            g->buf[pos] = "\"\\{}[],: \t\n\x01\x7f\x80\xbf\xc2\xe2\xf0\xff" "0e.-+"[below(24)];
            g->n++;
        }
    }
}

// Reports a self-check failure and aborts so the sanitizer-free case still stops.
static void fail(const char *what, const struct gen *g) {
    fprintf(stderr, "fuzz_json: %s on document of %u bytes: ", what, g->n);
    for (uint32_t i = 0; i < g->n && i < 200; i++) {
        fprintf(stderr, "%02x", (unsigned char)g->buf[i]);
    }
    fputc('\n', stderr);
    exit(1);
}

static const char *const field_keys[FIELD_COUNT] = {"body", "n", "a", "caf\xc3\xa9"};

static uint64_t counts[3];
static uint64_t body_counts[4];

// Writes a little-endian u32.
static void emit_u32(uint32_t v) {
    unsigned char b[4] = {(unsigned char)v, (unsigned char)(v >> 8), (unsigned char)(v >> 16), (unsigned char)(v >> 24)};
    fwrite(b, 1, 4, stdout);
}

// Writes one result record for the python driver.
static void emit_record(const struct gen *g, enum json_status st, enum json_body_status bst, const struct json_field *f,
                        struct slice body) {
    static char text[DOC_MAX * 3 + 8];
    emit_u32(g->n);
    fwrite(g->buf, 1, g->n, stdout);
    fputc((int)st, stdout);
    fputc((int)bst, stdout);
    for (unsigned i = 0; i < FIELD_COUNT; i++) {
        fputc(f[i].type, stdout);
        if (f[i].type == JSON_STRING) {
            int64_t n = json_unescape(f[i].raw, text, sizeof text);
            if (n < 0) {
                fail("unescape of a validated string failed", g);
            }
            emit_u32((uint32_t)n);
            fwrite(text, 1, (size_t)n, stdout);
        } else if (f[i].type == JSON_NUMBER) {
            fwrite(&f[i].num, sizeof f[i].num, 1, stdout);
        }
    }
    emit_u32(bst == JSON_BODY_OK ? body.n : 0);
    if (bst == JSON_BODY_OK) {
        fwrite(body.p, 1, body.n, stdout);
    }
}

// Runs the module on one document and checks the invariants that need no reference.
static void run_case(const struct gen *g, bool emit) {
    static char scratch[SCRATCH_SIZE];
    char *doc = malloc(g->n ? g->n : 1);
    if (!doc) {
        fail("out of memory", g);
    }
    memcpy(doc, g->buf, g->n);
    struct slice d = {doc, g->n};
    struct json_field f[FIELD_COUNT];
    for (unsigned i = 0; i < FIELD_COUNT; i++) {
        f[i] = (struct json_field){.key = field_keys[i]};
    }
    enum json_status st = json_extract(d, f, FIELD_COUNT);
    enum json_status plain = json_extract(d, NULL, 0);
    struct slice body = {scratch, 0};
    enum json_body_status bst = json_create_body(d, scratch, sizeof scratch, &body);
    if (st != plain) {
        fail("extract status depends on the requested fields", g);
    }
    if ((st == JSON_MALFORMED) != (bst == JSON_BODY_MALFORMED)) {
        fail("create body disagrees with extract about malformed", g);
    }
    if (bst == JSON_BODY_OK) {
        struct slice again = json_trim_js(body);
        if (again.n != body.n || json_count_chars(body) > BODY_MAX_CHARS || !body.n) {
            fail("trimmed body violates its contract", g);
        }
    }
    counts[st]++;
    body_counts[bst]++;
    if (emit) {
        emit_record(g, st, bst, f, body);
    }
    free(doc);
}

// Checks the vector writer against the scalar one on a random byte string in a tightly sized heap buffer.
static void check_writer(void) {
    static const unsigned char pool[] = {'a', 'z', ' ', '"', '\\', '\n', 0x00, 0x1f, 0x20, 0x7f, 0x80, 0xc3, 0xff, '/', 0x08};
    size_t n = below(130);
    unsigned char *s = malloc(n ? n : 1);
    size_t room = n ? JSON_ESCAPED_MAX(n) : 1;
    char *scalar = malloc(room);
    char *simd = malloc(room);
    if (!s || !scalar || !simd) {
        exit(1);
    }
    uint32_t mode = below(3);
    for (size_t i = 0; i < n; i++) {
        s[i] = mode == 0 ? (unsigned char)below(256) : pool[below(sizeof pool)];
        if (mode == 2 && below(10)) {
            s[i] = 'k';
        }
    }
    char *a = json_put_string_scalar(scalar, (const char *)s, n);
    char *b = json_put_string(simd, (const char *)s, n);
    if (a - scalar != b - simd || memcmp(scalar, simd, (size_t)(a - scalar))) {
        fprintf(stderr, "fuzz_json: writer mismatch for %zu bytes\n", n);
        exit(1);
    }
    free(s);
    free(scalar);
    free(simd);
}

// Feeds random bytes to the unescape with a random capacity; ASan reports any overrun.
static void check_unescape(void) {
    size_t n = below(48);
    char *in = malloc(n ? n : 1);
    uint32_t cap = below(64);
    char *out = malloc(cap ? cap : 1);
    if (!in || !out) {
        exit(1);
    }
    for (size_t i = 0; i < n; i++) {
        in[i] = one_in(3) ? "\\u0123456789abcdefABCDEF\"nrt"[below(27)] : (char)below(256);
    }
    int64_t got = json_unescape((struct slice){in, (uint32_t)n}, out, cap);
    if (got < -1 || got > (int64_t)cap) {
        fprintf(stderr, "fuzz_json: unescape returned %lld for cap %u\n", (long long)got, cap);
        exit(1);
    }
    free(in);
    free(out);
}

int main(int argc, char **argv) {
    uint64_t iters = argc > 1 ? strtoull(argv[1], NULL, 10) : 100000;
    rng_state = argc > 2 ? strtoull(argv[2], NULL, 10) : 0x2545F4914F6CDD1DULL;
    bool emit = argc > 3 && !strcmp(argv[3], "emit");
    if (!rng_state) {
        rng_state = 1;
    }
    static char outbuf[1 << 20];
    if (emit) {
        setvbuf(stdout, outbuf, _IOFBF, sizeof outbuf);
    }
    static struct gen g;
    for (uint64_t i = 0; i < iters; i++) {
        gen_document(&g);
        if (one_in(3)) {
            mutate(&g);
        }
        run_case(&g, emit);
        check_writer();
        check_unescape();
    }
    fflush(stdout);
    fprintf(stderr, "fuzz_json: %llu iterations, extract ok %llu malformed %llu not-object %llu, body ok %llu malformed %llu "
                    "required %llu too-long %llu\n",
            (unsigned long long)iters, (unsigned long long)counts[JSON_OK], (unsigned long long)counts[JSON_MALFORMED],
            (unsigned long long)counts[JSON_NOT_OBJECT], (unsigned long long)body_counts[JSON_BODY_OK],
            (unsigned long long)body_counts[JSON_BODY_MALFORMED], (unsigned long long)body_counts[JSON_BODY_REQUIRED],
            (unsigned long long)body_counts[JSON_BODY_TOO_LONG]);
    return 0;
}
