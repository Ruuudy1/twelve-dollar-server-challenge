// Unit tests for the json module: strict parsing, field extraction, unescape, trim, create body and the writer.
#define FM_TEST 1
#include "../src/main.c"
#include "json_expect.h"

static int failures;

// Records a failed expectation with its line.
#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

// Wraps a string literal, which may hold NUL and non-UTF-8 bytes, as a slice.
#define LIT(s) ((struct slice){(s), (uint32_t)(sizeof(s) - 1)})

struct doc_case {
    const char *text;
    uint32_t n;
    enum json_status want;
};

// Builds a table row from a literal.
#define DOC(s, st) {(s), (uint32_t)(sizeof(s) - 1), (st)}

static const struct doc_case doc_cases[] = {
    DOC("{}", JSON_OK),
    DOC(" \t\r\n{ \t\r\n} \t\r\n", JSON_OK),
    DOC("{\"a\":1}", JSON_OK),
    DOC("{ \"a\" : 1 , \"b\" : [ 1 , 2 , { } ] }", JSON_OK),
    DOC("{\"a\":{\"b\":{\"c\":[[],[{}]]}}}", JSON_OK),
    DOC("{\"\":1}", JSON_OK),
    DOC("{\"a\":1,\"a\":2}", JSON_OK),
    DOC("{\"a\":true,\"b\":false,\"c\":null}", JSON_OK),
    DOC("{\"a\":-0,\"b\":0,\"c\":-0.0,\"d\":0e0,\"e\":0E+0,\"f\":1e-0}", JSON_OK),
    DOC("{\"a\":123456789012345678901234567890,\"b\":1e999,\"c\":-1e999,\"d\":1e-999}", JSON_OK),
    DOC("{\"a\":0.000000000000000000000000000000000000001,\"b\":9007199254740993}", JSON_OK),
    DOC("{\"a\":\"\\\"\\\\\\/\\b\\f\\n\\r\\t\"}", JSON_OK),
    DOC("{\"a\":\"\\u0000\\u001f\\u00e9\\u20ac\\uD83D\\uDE00\\ud83d\\ude00\"}", JSON_OK),
    DOC("{\"a\":\"\\ud800\",\"b\":\"\\udc00\",\"c\":\"\\ud800\\ud800\",\"d\":\"\\udc00\\ud800\"}", JSON_OK),
    DOC("{\"a\":\"caf\xc3\xa9 \xe2\x9c\x93 \xf0\x9f\x98\x80\"}", JSON_OK),
    DOC("{\"a\":\"\xc2\x80\xdf\xbf\xe0\xa0\x80\xed\x9f\xbf\xee\x80\x80\xef\xbf\xbf\xf0\x90\x80\x80\xf4\x8f\xbf\xbf\"}", JSON_OK),
    DOC("{\"\xc3\xa9\":\"\x7f\"}", JSON_OK),
    DOC("[]", JSON_NOT_OBJECT),
    DOC("[1,\"a\",null,[],{}]", JSON_NOT_OBJECT),
    DOC("0", JSON_NOT_OBJECT),
    DOC("-12.5e+3", JSON_NOT_OBJECT),
    DOC("\"text\"", JSON_NOT_OBJECT),
    DOC("true", JSON_NOT_OBJECT),
    DOC("false", JSON_NOT_OBJECT),
    DOC("null", JSON_NOT_OBJECT),
    DOC(" null ", JSON_NOT_OBJECT),
    DOC("", JSON_MALFORMED),
    DOC(" ", JSON_MALFORMED),
    DOC("\n\t\r ", JSON_MALFORMED),
    DOC("{", JSON_MALFORMED),
    DOC("}", JSON_MALFORMED),
    DOC("[", JSON_MALFORMED),
    DOC("]", JSON_MALFORMED),
    DOC("{\"a\"}", JSON_MALFORMED),
    DOC("{\"a\":}", JSON_MALFORMED),
    DOC("{\"a\"1}", JSON_MALFORMED),
    DOC("{\"a\":1,}", JSON_MALFORMED),
    DOC("{,}", JSON_MALFORMED),
    DOC("{,\"a\":1}", JSON_MALFORMED),
    DOC("{\"a\":1,,\"b\":2}", JSON_MALFORMED),
    DOC("{\"a\":1 \"b\":2}", JSON_MALFORMED),
    DOC("{\"a\"::1}", JSON_MALFORMED),
    DOC("{'a':1}", JSON_MALFORMED),
    DOC("{a:1}", JSON_MALFORMED),
    DOC("{1:1}", JSON_MALFORMED),
    DOC("{\"a\":1]", JSON_MALFORMED),
    DOC("[1}", JSON_MALFORMED),
    DOC("[1,]", JSON_MALFORMED),
    DOC("[,1]", JSON_MALFORMED),
    DOC("[1 2]", JSON_MALFORMED),
    DOC("[1,,2]", JSON_MALFORMED),
    DOC("{} x", JSON_MALFORMED),
    DOC("{}{}", JSON_MALFORMED),
    DOC("{}}", JSON_MALFORMED),
    DOC("[]]", JSON_MALFORMED),
    DOC("1 2", JSON_MALFORMED),
    DOC("01", JSON_MALFORMED),
    DOC("-01", JSON_MALFORMED),
    DOC("00", JSON_MALFORMED),
    DOC("{\"a\":01}", JSON_MALFORMED),
    DOC("1.", JSON_MALFORMED),
    DOC(".5", JSON_MALFORMED),
    DOC("-", JSON_MALFORMED),
    DOC("- 1", JSON_MALFORMED),
    DOC("+1", JSON_MALFORMED),
    DOC("1e", JSON_MALFORMED),
    DOC("1e+", JSON_MALFORMED),
    DOC("1E-", JSON_MALFORMED),
    DOC("1.e5", JSON_MALFORMED),
    DOC("0x10", JSON_MALFORMED),
    DOC("1_000", JSON_MALFORMED),
    DOC("NaN", JSON_MALFORMED),
    DOC("-NaN", JSON_MALFORMED),
    DOC("Infinity", JSON_MALFORMED),
    DOC("-Infinity", JSON_MALFORMED),
    DOC("{\"a\":NaN}", JSON_MALFORMED),
    DOC("{\"a\":Infinity}", JSON_MALFORMED),
    DOC("{\"a\":-Infinity}", JSON_MALFORMED),
    DOC("nan", JSON_MALFORMED),
    DOC("inf", JSON_MALFORMED),
    DOC("True", JSON_MALFORMED),
    DOC("NULL", JSON_MALFORMED),
    DOC("nul", JSON_MALFORMED),
    DOC("nulll", JSON_MALFORMED),
    DOC("truee", JSON_MALFORMED),
    DOC("fals", JSON_MALFORMED),
    DOC("undefined", JSON_MALFORMED),
    DOC("\"abc", JSON_MALFORMED),
    DOC("{\"a", JSON_MALFORMED),
    DOC("{\"a\":\"b", JSON_MALFORMED),
    DOC("\"\\x\"", JSON_MALFORMED),
    DOC("\"\\", JSON_MALFORMED),
    DOC("\"\\\"", JSON_MALFORMED),
    DOC("\"\\u12\"", JSON_MALFORMED),
    DOC("\"\\u12G4\"", JSON_MALFORMED),
    DOC("\"\\u+123\"", JSON_MALFORMED),
    DOC("\"\\U0041\"", JSON_MALFORMED),
    DOC("\"\\'\"", JSON_MALFORMED),
    DOC("\"a\tb\"", JSON_MALFORMED),
    DOC("\"a\nb\"", JSON_MALFORMED),
    DOC("\"a\rb\"", JSON_MALFORMED),
    DOC("\"a\x01" "b\"", JSON_MALFORMED),
    DOC("\"a\x1f" "b\"", JSON_MALFORMED),
    DOC("\"a\0b\"", JSON_MALFORMED),
    DOC("{\"a\tb\":1}", JSON_MALFORMED),
    DOC("// c\n{}", JSON_MALFORMED),
    DOC("/* c */{}", JSON_MALFORMED),
    DOC("{} // c", JSON_MALFORMED),
    DOC("{\"a\":1 /* c */}", JSON_MALFORMED),
    DOC("#{}", JSON_MALFORMED),
    DOC("\xef\xbb\xbf{}", JSON_MALFORMED),
    DOC("\f{}", JSON_MALFORMED),
    DOC("\v{}", JSON_MALFORMED),
    DOC("{}\f", JSON_MALFORMED),
    DOC("\xc2\xa0{}", JSON_MALFORMED),
    DOC("{}\xe2\x80\xa8", JSON_MALFORMED),
    DOC("{\0}", JSON_MALFORMED),
    DOC("{}\0", JSON_MALFORMED),
    DOC("\"\x80\"", JSON_MALFORMED),
    DOC("\"\xbf\"", JSON_MALFORMED),
    DOC("\"\xc0\x80\"", JSON_MALFORMED),
    DOC("\"\xc1\xbf\"", JSON_MALFORMED),
    DOC("\"\xc2\"", JSON_MALFORMED),
    DOC("\"\xc2\x41\"", JSON_MALFORMED),
    DOC("\"\xe0\x80\x80\"", JSON_MALFORMED),
    DOC("\"\xe0\x9f\xbf\"", JSON_MALFORMED),
    DOC("\"\xe2\x82\"", JSON_MALFORMED),
    DOC("\"\xe2\x82\x41\"", JSON_MALFORMED),
    DOC("\"\xed\xa0\x80\"", JSON_MALFORMED),
    DOC("\"\xed\xaf\xbf\"", JSON_MALFORMED),
    DOC("\"\xed\xb0\x80\"", JSON_MALFORMED),
    DOC("\"\xed\xbf\xbf\"", JSON_MALFORMED),
    DOC("\"\xed\xa0\x80\xed\xb0\x80\"", JSON_MALFORMED),
    DOC("\"\xf0\x80\x80\x80\"", JSON_MALFORMED),
    DOC("\"\xf0\x8f\xbf\xbf\"", JSON_MALFORMED),
    DOC("\"\xf0\x9f\x98\"", JSON_MALFORMED),
    DOC("\"\xf4\x90\x80\x80\"", JSON_MALFORMED),
    DOC("\"\xf5\x80\x80\x80\"", JSON_MALFORMED),
    DOC("\"\xf8\x88\x80\x80\x80\"", JSON_MALFORMED),
    DOC("\"\xfe\"", JSON_MALFORMED),
    DOC("\"\xff\"", JSON_MALFORMED),
    DOC("{\"\xff\":1}", JSON_MALFORMED),
    DOC("{\"a\":\"\xc3\"}", JSON_MALFORMED),
    DOC("\xc3\xa9", JSON_MALFORMED),
    DOC("{\"a\":1}\xc3\xa9", JSON_MALFORMED),
};

// Runs json_extract on one table row with no requested fields.
static enum json_status extract_plain(struct slice doc) {
    return json_extract(doc, NULL, 0);
}

static void test_doc_table(void) {
    for (size_t i = 0; i < ARRAY_LEN(doc_cases); i++) {
        const struct doc_case *tc = &doc_cases[i];
        enum json_status got = extract_plain((struct slice){tc->text, tc->n});
        if (got != tc->want) {
            fprintf(stderr, "FAIL doc row %zu (%.*s): got %d want %d\n", i, (int)tc->n, tc->text, (int)got,
                    (int)tc->want);
            failures++;
        }
    }
}

// Builds depth nested containers around a leaf; kind is 'a' for arrays, 'o' for objects and 'm' for alternating.
static uint32_t build_nested(char *buf, unsigned depth, char kind) {
    char *o = buf;
    char closers[JSON_DEPTH_MAX + 8];
    for (unsigned i = 0; i < depth; i++) {
        bool obj = kind == 'o' || (kind == 'm' && i % 2 == 1);
        if (obj) {
            memcpy(o, "{\"k\":", 5);
            o += 5;
        } else {
            *o++ = '[';
        }
        closers[i] = obj ? '}' : ']';
    }
    *o++ = '1';
    for (unsigned i = depth; i > 0; i--) {
        *o++ = closers[i - 1];
    }
    return (uint32_t)(o - buf);
}

static void test_depth(void) {
    static char buf[4096];
    static const char kinds[] = "aom";
    for (size_t k = 0; k < sizeof(kinds) - 1; k++) {
        for (unsigned depth = 1; depth <= 70; depth++) {
            uint32_t n = build_nested(buf, depth, kinds[k]);
            enum json_status got = extract_plain((struct slice){buf, n});
            bool outer_obj = kinds[k] == 'o';
            enum json_status want = depth > 64 ? JSON_MALFORMED : outer_obj ? JSON_OK : JSON_NOT_OBJECT;
            if (kinds[k] == 'm') {
                want = depth > 64 ? JSON_MALFORMED : JSON_NOT_OBJECT;
            }
            if (got != want) {
                fprintf(stderr, "FAIL depth %u kind %c: got %d want %d\n", depth, kinds[k], (int)got, (int)want);
                failures++;
            }
        }
    }
    CHECK(JSON_DEPTH_MAX == 64);
    memset(buf, '[', sizeof buf);
    CHECK(extract_plain((struct slice){buf, sizeof buf}) == JSON_MALFORMED);
    memset(buf, '{', sizeof buf);
    CHECK(extract_plain((struct slice){buf, sizeof buf}) == JSON_MALFORMED);
    memset(buf, ']', sizeof buf);
    CHECK(extract_plain((struct slice){buf, sizeof buf}) == JSON_MALFORMED);
    uint32_t n = build_nested(buf, 64, 'o');
    CHECK(extract_plain((struct slice){buf, n}) == JSON_OK);
    buf[n++] = ' ';
    CHECK(extract_plain((struct slice){buf, n}) == JSON_OK);
}

static void test_deep_values_in_siblings(void) {
    static char buf[4096];
    uint32_t n = 0;
    memcpy(buf, "{\"a\":", 5);
    n = 5;
    n += build_nested(buf + n, 63, 'a');
    memcpy(buf + n, ",\"b\":", 5);
    n += 5;
    n += build_nested(buf + n, 63, 'a');
    buf[n++] = '}';
    CHECK(extract_plain((struct slice){buf, n}) == JSON_OK);
    memcpy(buf, "{\"a\":", 5);
    n = 5;
    n += build_nested(buf + n, 64, 'a');
    buf[n++] = '}';
    CHECK(extract_plain((struct slice){buf, n}) == JSON_MALFORMED);
}

// Reads one requested field set from a literal document.
static enum json_status extract_fields(struct slice doc, struct json_field *f, unsigned count) {
    return json_extract(doc, f, count);
}

// Returns true when a double is within a relative tolerance of want.
static bool near_value(double got, double want) {
    double diff = got > want ? got - want : want - got;
    double mag = want < 0 ? -want : want;
    return diff <= mag * 1e-15;
}

static void test_extract_fields(void) {
    struct json_field f[3] = {{.key = "a"}, {.key = "b"}, {.key = "c"}};
    CHECK(extract_fields(LIT("{\"a\":\"hi\",\"b\":12,\"c\":null,\"d\":1}"), f, 3) == JSON_OK);
    CHECK(f[0].type == JSON_STRING && !f[0].escaped && f[0].raw.n == 2 && !memcmp(f[0].raw.p, "hi", 2));
    CHECK(f[1].type == JSON_NUMBER && f[1].raw.n == 2 && !memcmp(f[1].raw.p, "12", 2) && near_value(f[1].num, 12.0));
    CHECK(f[2].type == JSON_OTHER);
    CHECK(extract_fields(LIT("{\"x\":1}"), f, 3) == JSON_OK);
    CHECK(f[0].type == JSON_ABSENT && f[1].type == JSON_ABSENT && f[2].type == JSON_ABSENT);
    CHECK(extract_fields(LIT("{\"a\":\"x\\ny\"}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_STRING && f[0].escaped && f[0].raw.n == 4 && !memcmp(f[0].raw.p, "x\\ny", 4));
    CHECK(extract_fields(LIT("{\"a\":1,\"a\":\"two\"}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_STRING && f[0].raw.n == 3 && !f[0].escaped);
    CHECK(extract_fields(LIT("{\"a\":\"two\",\"a\":7}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_NUMBER && f[0].raw.n == 1 && !f[0].escaped);
    CHECK(extract_fields(LIT("{\"a\":\"two\",\"a\":{\"z\":1}}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_OTHER && f[0].raw.n == 0);
    CHECK(extract_fields(LIT("{\"a\":\"x\\ny\",\"a\":\"plain\"}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_STRING && !f[0].escaped && f[0].raw.n == 5);
    CHECK(extract_fields(LIT("{\"a\":[1,2,\"a\"],\"b\":{\"a\":\"deep\",\"b\":3}}"), f, 2) == JSON_OK);
    CHECK(f[0].type == JSON_OTHER && f[1].type == JSON_OTHER);
    CHECK(extract_fields(LIT("{\"o\":{\"a\":\"deep\"}}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_ABSENT);
    CHECK(extract_fields(LIT("{\"o\":[{\"a\":\"deep\"}],\"a\":\"top\"}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_STRING && f[0].raw.n == 3 && !memcmp(f[0].raw.p, "top", 3));
    CHECK(extract_fields(LIT("{\"\\u0061\":\"esc\"}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_STRING && f[0].raw.n == 3);
    CHECK(extract_fields(LIT("{\"a\\u0000\":\"nul\"}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_ABSENT);
    CHECK(extract_fields(LIT("{\"\\ud800\":1,\"a \":2,\" a\":3,\"A\":4}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_ABSENT);
    CHECK(extract_fields(LIT("{\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\n\":1,\"a\":2}"), f, 1) == JSON_OK);
    CHECK(f[0].type == JSON_NUMBER && near_value(f[0].num, 2.0));
}

static void test_extract_failures_clear_fields(void) {
    struct json_field f[2] = {{.key = "a"}, {.key = "b"}};
    CHECK(extract_fields(LIT("{\"a\":\"x\",\"b\":1,"), f, 2) == JSON_MALFORMED);
    CHECK(f[0].type == JSON_ABSENT && f[1].type == JSON_ABSENT);
    CHECK(extract_fields(LIT("{\"a\":\"x\",\"b\":1}"), f, 2) == JSON_OK);
    CHECK(f[0].type == JSON_STRING && f[1].type == JSON_NUMBER);
    CHECK(extract_fields(LIT("[\"a\",1]"), f, 2) == JSON_NOT_OBJECT);
    CHECK(f[0].type == JSON_ABSENT && f[1].type == JSON_ABSENT);
    CHECK(extract_fields(LIT("{\"a\":\"x\",\"b\":1}"), f, 2) == JSON_OK);
    CHECK(extract_fields(LIT("{\"a\":\"x\",\"b\":1} junk"), f, 2) == JSON_MALFORMED);
    CHECK(f[0].type == JSON_ABSENT && f[1].type == JSON_ABSENT);
    CHECK(extract_fields((struct slice){NULL, 0}, f, 2) == JSON_MALFORMED);
}

static void test_numbers(void) {
    struct json_field f = {.key = "n"};
    static const struct {
        const char *doc;
        double want;
    } rows[] = {
        {"{\"n\":0}", 0.0},
        {"{\"n\":1700000000}", 1700000000.0},
        {"{\"n\":9007199254740993}", 9007199254740993.0},
        {"{\"n\":-12}", -12.0},
        {"{\"n\":1.5}", 1.5},
        {"{\"n\":0.1}", 0.1},
        {"{\"n\":-2.5e3}", -2500.0},
        {"{\"n\":1e2}", 100.0},
        {"{\"n\":1E+2}", 100.0},
        {"{\"n\":25e-1}", 2.5},
        {"{\"n\":0.00012345}", 0.00012345},
        {"{\"n\":1234567.8901234}", 1234567.8901234},
        {"{\"n\":123456789012345678901234567890}", 1.2345678901234568e29},
        {"{\"n\":0.000000000000000000000000000000000000001}", 1e-39},
        {"{\"n\":1e300}", 1e300},
        {"{\"n\":1.7976931348623157e308}", 1.7976931348623157e308},
        {"{\"n\":1.79769313486231576931348623157e308}", 1.7976931348623157e308},
        {"{\"n\":1700000000.000000000000000000001}", 1700000000.0},
    };
    for (size_t i = 0; i < ARRAY_LEN(rows); i++) {
        struct slice doc = {rows[i].doc, (uint32_t)strlen(rows[i].doc)};
        CHECK(json_extract(doc, &f, 1) == JSON_OK && f.type == JSON_NUMBER);
        if (!near_value(f.num, rows[i].want)) {
            fprintf(stderr, "FAIL number row %zu: %s got %.17g\n", i, rows[i].doc, f.num);
            failures++;
        }
    }
    CHECK(json_extract(LIT("{\"n\":1e999}"), &f, 1) == JSON_OK && f.num > 1e308);
    CHECK(json_extract(LIT("{\"n\":-1e999}"), &f, 1) == JSON_OK && f.num < -1e308);
    CHECK(json_extract(LIT("{\"n\":1e-999}"), &f, 1) == JSON_OK && f.num >= 0.0 && f.num < 1e-300);
    CHECK(json_extract(LIT("{\"n\":-0}"), &f, 1) == JSON_OK && f.num < 1e-300 && f.num > -1e-300);
    CHECK(json_extract(LIT("{\"n\":0e999999999999}"), &f, 1) == JSON_OK && f.num < 1e-300 && f.num > -1e-300);
    CHECK(json_extract(LIT("{\"n\":1e99999999999999999999}"), &f, 1) == JSON_OK && f.num > 1e308);
    CHECK(json_extract(LIT("{\"n\":1e-99999999999999999999}"), &f, 1) == JSON_OK && f.num < 1e-300);
}

// Unescapes into a canary-guarded buffer and compares with the expected bytes.
static bool unescape_is(struct slice raw, const char *want, size_t want_n) {
    char buf[64];
    memset(buf, 0x7e, sizeof buf);
    uint32_t cap = (uint32_t)want_n;
    int64_t n = json_unescape(raw, buf + 8, cap);
    bool guard_ok = true;
    for (size_t i = 0; i < 8; i++) {
        guard_ok = guard_ok && buf[i] == 0x7e;
    }
    for (size_t i = 8 + cap; i < sizeof buf; i++) {
        guard_ok = guard_ok && buf[i] == 0x7e;
    }
    return guard_ok && n == (int64_t)want_n && !memcmp(buf + 8, want, want_n);
}

// Checks unescaping of a literal against an expected literal.
#define UNESC(raw, want) CHECK(unescape_is(LIT(raw), (want), sizeof(want) - 1))

static void test_unescape(void) {
    UNESC("", "");
    UNESC("plain", "plain");
    UNESC("caf\xc3\xa9", "caf\xc3\xa9");
    UNESC("\\\"\\\\\\/\\b\\f\\n\\r\\t", "\"\\/\b\f\n\r\t");
    UNESC("a\\nb", "a\nb");
    UNESC("\\u0041", "A");
    UNESC("\\u0000", "\0");
    UNESC("\\u001F", "\x1f");
    UNESC("\\u007f", "\x7f");
    UNESC("\\u0080", "\xc2\x80");
    UNESC("\\u00e9", "\xc3\xa9");
    UNESC("\\u00E9", "\xc3\xa9");
    UNESC("\\u07ff", "\xdf\xbf");
    UNESC("\\u0800", "\xe0\xa0\x80");
    UNESC("\\u20ac", "\xe2\x82\xac");
    UNESC("\\ud7ff", "\xed\x9f\xbf");
    UNESC("\\ue000", "\xee\x80\x80");
    UNESC("\\uffff", "\xef\xbf\xbf");
    UNESC("\\ud83d\\ude00", "\xf0\x9f\x98\x80");
    UNESC("\\uD83D\\uDE00", "\xf0\x9f\x98\x80");
    UNESC("\\ud800\\udc00", "\xf0\x90\x80\x80");
    UNESC("\\udbff\\udfff", "\xf4\x8f\xbf\xbf");
    UNESC("x\\ud83d\\ude00y", "x\xf0\x9f\x98\x80y");
    UNESC("\\ud800", "\xef\xbf\xbd");
    UNESC("\\udbff", "\xef\xbf\xbd");
    UNESC("\\udc00", "\xef\xbf\xbd");
    UNESC("\\udfff", "\xef\xbf\xbd");
    UNESC("\\ud83dx", "\xef\xbf\xbdx");
    UNESC("\\ud83d\\u0041", "\xef\xbf\xbd" "A");
    UNESC("\\ud83d\\n", "\xef\xbf\xbd\n");
    UNESC("\\ud83d\\ud83d", "\xef\xbf\xbd\xef\xbf\xbd");
    UNESC("\\ud83d\\ud83d\\ude00", "\xef\xbf\xbd\xf0\x9f\x98\x80");
    UNESC("\\ude00\\ud83d", "\xef\xbf\xbd\xef\xbf\xbd");
    UNESC("\\ude00\\ude00", "\xef\xbf\xbd\xef\xbf\xbd");
    UNESC("\\ud83d\\ude00\\ude00", "\xf0\x9f\x98\x80\xef\xbf\xbd");
}

static void test_unescape_limits(void) {
    char buf[16];
    CHECK(json_unescape(LIT("abc"), buf, 3) == 3);
    CHECK(json_unescape(LIT("abc"), buf, 2) == -1);
    CHECK(json_unescape(LIT("abc"), buf, 0) == -1);
    CHECK(json_unescape(LIT(""), buf, 0) == 0);
    CHECK(json_unescape((struct slice){NULL, 0}, NULL, 0) == 0);
    CHECK(json_unescape(LIT("\\u20ac"), buf, 3) == 3);
    CHECK(json_unescape(LIT("\\u20ac"), buf, 2) == -1);
    CHECK(json_unescape(LIT("\\ud83d\\ude00"), buf, 4) == 4);
    CHECK(json_unescape(LIT("\\ud83d\\ude00"), buf, 3) == -1);
    CHECK(json_unescape(LIT("\\ud800"), buf, 3) == 3);
    CHECK(json_unescape(LIT("\\ud800"), buf, 2) == -1);
    CHECK(json_unescape(LIT("ab\\n"), buf, 3) == 3);
    CHECK(json_unescape(LIT("ab\\n"), buf, 2) == -1);
}

// Pseudo-random generator for the table-free robustness checks.
static uint64_t rng_next(uint64_t *state) {
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void test_unescape_arbitrary_bytes(void) {
    static const char pool[] = "\\\\\\\\uuu00ddDD89abfAF\"nrtbf/xz\xc3\xa9\xed\xa0\x80\xff\x80";
    uint64_t rng = 0x9E3779B97F4A7C15ULL;
    char in[64];
    for (unsigned iter = 0; iter < 20000; iter++) {
        uint32_t n = (uint32_t)(rng_next(&rng) % sizeof in);
        for (uint32_t i = 0; i < n; i++) {
            in[i] = pool[rng_next(&rng) % (sizeof pool - 1)];
        }
        uint32_t cap = (uint32_t)(rng_next(&rng) % 80);
        char *out = malloc(cap ? cap : 1);
        CHECK(out != NULL);
        int64_t got = json_unescape((struct slice){in, n}, out, cap);
        CHECK(got >= -1 && got <= (int64_t)cap);
        free(out);
        char *full = malloc(3 * (size_t)n + 3);
        CHECK(full != NULL);
        int64_t need = json_unescape((struct slice){in, n}, full, 3 * n + 3);
        CHECK(need >= 0 && need <= 3 * (int64_t)n + 3);
        if (need > 0) {
            char *tight = malloc((size_t)need);
            CHECK(tight != NULL);
            CHECK(json_unescape((struct slice){in, n}, tight, (uint32_t)need) == need);
            CHECK(json_unescape((struct slice){in, n}, tight, (uint32_t)need - 1) == -1);
            free(tight);
        }
        free(full);
    }
}

// Appends the UTF-8 form of cp to buf at n and returns the new length.
static size_t append_cp(char *buf, size_t n, uint32_t cp) {
    return n + json_put_utf8(buf + n, cp);
}

static const uint32_t trim_set[] = {0x09,   0x0A,   0x0B,   0x0C,   0x0D,   0x20,   0xA0,   0x1680, 0x2000, 0x2001,
                                    0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200A, 0x2028,
                                    0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF};

static const uint32_t not_trimmed[] = {0x00, 0x08, 0x0E, 0x1F,   0x21,   0x85,   0xA1,   0x180E, 0x200B, 0x200C,
                                       0x200D, 0x2060, 0x2027, 0x202A, 0x202E, 0x2030, 0x205E, 0x2060, 0x3001, 0xFFFD,
                                       0xFEFE, 0xFFFE, 0x1680 + 1, 0x10000, 0x1F600, 0x10FFFF, 'a', '0'};

static void test_trim(void) {
    char buf[64];
    for (size_t i = 0; i < ARRAY_LEN(trim_set); i++) {
        size_t n = append_cp(buf, 0, trim_set[i]);
        CHECK(json_trim_js((struct slice){buf, (uint32_t)n}).n == 0);
        n = append_cp(buf, 0, trim_set[i]);
        buf[n++] = 'x';
        n = append_cp(buf, n, trim_set[i]);
        struct slice t = json_trim_js((struct slice){buf, (uint32_t)n});
        CHECK(t.n == 1 && t.p == buf + (n - 1) / 2 && t.p[0] == 'x');
        n = append_cp(buf, 0, trim_set[i]);
        n = append_cp(buf, n, trim_set[i]);
        buf[n++] = 'a';
        buf[n++] = ' ';
        buf[n++] = 'b';
        n = append_cp(buf, n, trim_set[(i + 7) % ARRAY_LEN(trim_set)]);
        t = json_trim_js((struct slice){buf, (uint32_t)n});
        CHECK(t.n == 3 && !memcmp(t.p, "a b", 3));
    }
    for (size_t i = 0; i < ARRAY_LEN(not_trimmed); i++) {
        size_t n = append_cp(buf, 0, not_trimmed[i]);
        struct slice t = json_trim_js((struct slice){buf, (uint32_t)n});
        CHECK(t.n == n && t.p == buf);
        n = append_cp(buf, 0, 0x20);
        size_t mid = n;
        n = append_cp(buf, n, not_trimmed[i]);
        size_t mid_end = n;
        n = append_cp(buf, n, 0x3000);
        t = json_trim_js((struct slice){buf, (uint32_t)n});
        CHECK(t.p == buf + mid && t.n == mid_end - mid);
    }
}

static void test_trim_all_and_edges(void) {
    char buf[256];
    size_t n = 0;
    for (size_t i = 0; i < ARRAY_LEN(trim_set); i++) {
        n = append_cp(buf, n, trim_set[i]);
    }
    CHECK(json_trim_js((struct slice){buf, (uint32_t)n}).n == 0);
    CHECK(json_trim_js((struct slice){NULL, 0}).n == 0);
    CHECK(json_trim_js(LIT("")).n == 0);
    CHECK(json_trim_js(LIT("x")).n == 1);
    CHECK(json_trim_js(LIT("  x  y  ")).n == 4);
    CHECK(json_trim_js(LIT("\xc2\xa0\xc2\xa0")).n == 0);
    CHECK(json_trim_js(LIT("\xc2\x85x")).n == 3);
    CHECK(json_trim_js(LIT("x\xc2\x85")).n == 3);
    CHECK(json_trim_js(LIT("\xe2\x80\x80\xe2\x80\x8b")).n == 3);
    CHECK(json_trim_js(LIT("\xe2\x80\x8b\xe2\x80\x80")).n == 3);
    CHECK(json_trim_js(LIT("\xe1\x9a\x80x\xe1\x9a\x80")).n == 1);
    CHECK(json_trim_js(LIT("\xef\xbb\xbfx\xef\xbb\xbf")).n == 1);
    CHECK(json_trim_js(LIT("\xe1\xa0\x8ex")).n == 4);
    CHECK(json_trim_js(LIT("\xff")).n == 1);
    CHECK(json_trim_js(LIT("\x80\x80\x80\x80\x80")).n == 5);
    CHECK(json_trim_js(LIT(" \x80 ")).n == 1);
    CHECK(json_trim_js(LIT("\xe2\x80")).n == 2);
}

static void test_count_chars(void) {
    CHECK(json_count_chars(LIT("")) == 0);
    CHECK(json_count_chars(LIT("abc")) == 3);
    CHECK(json_count_chars(LIT("caf\xc3\xa9")) == 4);
    CHECK(json_count_chars(LIT("\xe2\x9c\x93")) == 1);
    CHECK(json_count_chars(LIT("\xf0\x9f\x98\x80")) == 1);
    CHECK(json_count_chars(LIT("a\xc3\xa9\xe2\x9c\x93\xf0\x9f\x98\x80z")) == 5);
    CHECK(json_count_chars(LIT("\xef\xbf\xbd")) == 1);
}

// Result of one create-body call.
struct body_result {
    enum json_body_status st;
    char text[SCRATCH_SIZE];
    uint32_t n;
};

// Runs json_create_body on a document and copies out the trimmed text; checks it lies inside the scratch.
static void run_body(struct slice doc, uint32_t cap, struct body_result *r) {
    static char scratch[SCRATCH_SIZE];
    struct slice out = {NULL, 0};
    r->st = json_create_body(doc, scratch, cap, &out);
    r->n = out.n;
    CHECK(out.p >= scratch && out.p + out.n <= scratch + cap);
    if (r->st == JSON_BODY_OK) {
        memcpy(r->text, out.p, out.n);
    } else {
        CHECK(out.n == 0);
    }
}

static struct body_result body_res;

// Checks the status of a create body for a literal document.
#define BODY_ST(doc, want) \
    do { \
        run_body(LIT(doc), SCRATCH_SIZE, &body_res); \
        if (body_res.st != (want)) { \
            fprintf(stderr, "FAIL line %d: body status %d want %d for %s\n", __LINE__, (int)body_res.st, (int)(want), \
                    (doc)); \
            failures++; \
        } \
    } while (0)

// Checks an accepted create body for a literal document and the exact trimmed bytes.
#define BODY_OK(doc, want) \
    do { \
        BODY_ST(doc, JSON_BODY_OK); \
        CHECK(body_res.n == sizeof(want) - 1 && !memcmp(body_res.text, (want), sizeof(want) - 1)); \
    } while (0)

// Builds {"body":"<fill repeated count times><pad spaces both sides>"} and returns its length.
static uint32_t build_body_doc(char *buf, const char *fill, size_t fill_n, unsigned count, unsigned pad) {
    char *o = buf;
    memcpy(o, "{\"body\":\"", 9);
    o += 9;
    memset(o, ' ', pad);
    o += pad;
    for (unsigned i = 0; i < count; i++) {
        memcpy(o, fill, fill_n);
        o += fill_n;
    }
    memset(o, ' ', pad);
    o += pad;
    memcpy(o, "\"}", 2);
    o += 2;
    return (uint32_t)(o - buf);
}

static void test_create_body_table(void) {
    BODY_ST("{\"body\":\"\"}", JSON_BODY_REQUIRED);
    BODY_ST("{\"body\":\"   \"}", JSON_BODY_REQUIRED);
    BODY_ST("{\"body\":123}", JSON_BODY_REQUIRED);
    BODY_ST("{}", JSON_BODY_REQUIRED);
    BODY_ST("{bad json", JSON_BODY_MALFORMED);
    BODY_ST("", JSON_BODY_MALFORMED);
    BODY_ST("   ", JSON_BODY_MALFORMED);
    BODY_ST("{\"body\":null}", JSON_BODY_REQUIRED);
    BODY_ST("{\"body\":true}", JSON_BODY_REQUIRED);
    BODY_ST("{\"body\":[\"x\"]}", JSON_BODY_REQUIRED);
    BODY_ST("{\"body\":{\"body\":\"x\"}}", JSON_BODY_REQUIRED);
    BODY_ST("{\"other\":\"x\"}", JSON_BODY_REQUIRED);
    BODY_ST("{\"Body\":\"x\"}", JSON_BODY_REQUIRED);
    BODY_ST("{\"inner\":{\"body\":\"x\"}}", JSON_BODY_REQUIRED);
    BODY_ST("[]", JSON_BODY_REQUIRED);
    BODY_ST("[\"x\"]", JSON_BODY_REQUIRED);
    BODY_ST("\"x\"", JSON_BODY_REQUIRED);
    BODY_ST("1", JSON_BODY_REQUIRED);
    BODY_ST("null", JSON_BODY_REQUIRED);
    BODY_ST("{\"body\":\"x\"} trailing", JSON_BODY_MALFORMED);
    BODY_ST("{\"body\":\"x\",}", JSON_BODY_MALFORMED);
    BODY_ST("{\"body\":\"x\xff\"}", JSON_BODY_MALFORMED);
    BODY_ST("{\"body\":\"x\xc0\x80\"}", JSON_BODY_MALFORMED);
    BODY_ST("{\"body\":\"\xed\xa0\x80\"}", JSON_BODY_MALFORMED);
    BODY_ST("{\"body\":\"line\nbreak\"}", JSON_BODY_MALFORMED);
    BODY_ST("{\"body\":\"\\q\"}", JSON_BODY_MALFORMED);
    BODY_ST("{\"body\":NaN}", JSON_BODY_MALFORMED);
    BODY_ST("{\"body\":\"x\",\"n\":Infinity}", JSON_BODY_MALFORMED);
    BODY_ST("\xef\xbb\xbf{\"body\":\"x\"}", JSON_BODY_MALFORMED);
    BODY_OK("{\"body\":\"x\"}", "x");
    BODY_OK("{\"body\":\"  hello world  \"}", "hello world");
    BODY_OK("  {\"body\" : \"x\"}\n", "x");
    BODY_OK("{\"body\":\"x\",\"body\":\"y\"}", "y");
    BODY_OK("{\"body\":1,\"body\":\"y\"}", "y");
    BODY_ST("{\"body\":\"x\",\"body\":1}", JSON_BODY_REQUIRED);
    BODY_ST("{\"body\":\"x\",\"body\":null}", JSON_BODY_REQUIRED);
    BODY_ST("{\"body\":\"x\",\"body\":\"  \"}", JSON_BODY_REQUIRED);
    BODY_OK("{\"b\\u006fdy\":\"esc key\"}", "esc key");
    BODY_OK("{\"a\":[1,{\"body\":2}],\"body\":\"after nested\"}", "after nested");
    BODY_OK("{\"body\":\"  test: <b>&amp;</b> \\\"quoted\\\" / caf\xc3\xa9 \xe2\x9c\x93  \"}",
            "test: <b>&amp;</b> \"quoted\" / caf\xc3\xa9 \xe2\x9c\x93");
}

static void test_create_body_unescape_and_trim(void) {
    BODY_OK("{\"body\":\"\\u00e9\\n\"}", "\xc3\xa9");
    BODY_OK("{\"body\":\"\\n\\t x \\r\\f\\u000b\"}", "x");
    BODY_ST("{\"body\":\"\\n\\t \\r\"}", JSON_BODY_REQUIRED);
    BODY_ST("{\"body\":\"\\u00a0\\u3000\\ufeff\\u2028\\u2029\\u202f\\u205f\\u1680\\u2000\\u200a\"}", JSON_BODY_REQUIRED);
    BODY_OK("{\"body\":\"\\u00a0\\u3000x\\ufeff y\\u2003\"}", "x\xef\xbb\xbf y");
    BODY_OK("{\"body\":\"\\u200bx\\u200b\"}", "\xe2\x80\x8bx\xe2\x80\x8b");
    BODY_OK("{\"body\":\"\\u0085x\\u180e\"}", "\xc2\x85x\xe1\xa0\x8e");
    BODY_OK("{\"body\":\"a\\u0000b\"}", "a\0b");
    BODY_OK("{\"body\":\"\\ud83d\\ude00\"}", "\xf0\x9f\x98\x80");
    BODY_OK("{\"body\":\"\\ud83d\"}", "\xef\xbf\xbd");
    BODY_OK("{\"body\":\" \\udc00 \"}", "\xef\xbf\xbd");
    BODY_OK("{\"body\":\"\\ud83d\\ud83d\"}", "\xef\xbf\xbd\xef\xbf\xbd");
}

static void test_create_body_lengths(void) {
    static char doc[32768];
    uint32_t n = build_body_doc(doc, "a", 1, 500, 0);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_OK && body_res.n == 500);
    n = build_body_doc(doc, "a", 1, 501, 0);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_TOO_LONG);
    n = build_body_doc(doc, "a", 1, 500, 40);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_OK && body_res.n == 500);
    n = build_body_doc(doc, "a", 1, 501, 40);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_TOO_LONG);
    n = build_body_doc(doc, "\xf0\x9f\x98\x80", 4, 500, 0);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_OK && body_res.n == 2000);
    n = build_body_doc(doc, "\xf0\x9f\x98\x80", 4, 501, 0);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_TOO_LONG);
    n = build_body_doc(doc, "\xc3\xa9", 2, 500, 3);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_OK && body_res.n == 1000);
    n = build_body_doc(doc, "\\ud83d\\ude00", 12, 500, 0);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_OK && body_res.n == 2000);
    n = build_body_doc(doc, "\\ud83d\\ude00", 12, 501, 0);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_TOO_LONG);
    n = build_body_doc(doc, "\\ud83d", 6, 500, 0);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_OK && body_res.n == 1500);
    n = build_body_doc(doc, "\\u0020", 6, 800, 0);
    run_body((struct slice){doc, n}, SCRATCH_SIZE, &body_res);
    CHECK(body_res.st == JSON_BODY_REQUIRED);
}

static void test_create_body_scratch(void) {
    static const char doc[] = "{\"body\":\"  abcd  \"}";
    struct slice d = {doc, sizeof doc - 1};
    run_body(d, 8, &body_res);
    CHECK(body_res.st == JSON_BODY_OK && body_res.n == 4);
    run_body(d, 7, &body_res);
    CHECK(body_res.st == JSON_BODY_MALFORMED);
    run_body(d, 0, &body_res);
    CHECK(body_res.st == JSON_BODY_MALFORMED);
    static const char esc[] = "{\"body\":\"\\u20ac\"}";
    run_body((struct slice){esc, sizeof esc - 1}, 3, &body_res);
    CHECK(body_res.st == JSON_BODY_OK && body_res.n == 3);
    run_body((struct slice){esc, sizeof esc - 1}, 2, &body_res);
    CHECK(body_res.st == JSON_BODY_MALFORMED);
    static const char empty[] = "{\"body\":\"\"}";
    run_body((struct slice){empty, sizeof empty - 1}, 0, &body_res);
    CHECK(body_res.st == JSON_BODY_REQUIRED);
}

// Builds the JSON.stringify expectation for n raw bytes into out and returns its length.
static size_t expected_escape(const unsigned char *s, size_t n, char *out) {
    size_t w = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] >= 0x80) {
            out[w++] = (char)s[i];
            continue;
        }
        size_t len = strlen(json_expect_ascii[s[i]]);
        memcpy(out + w, json_expect_ascii[s[i]], len);
        w += len;
    }
    return w;
}

// Writes with both writers into exactly sized heap buffers and compares them with the expectation.
static void check_writer(const unsigned char *s, size_t n) {
    size_t room = JSON_ESCAPED_MAX(n) + 1;
    char *want = malloc(room);
    char *scalar = malloc(room);
    char *simd = malloc(room);
    CHECK(want && scalar && simd);
    size_t want_n = expected_escape(s, n, want);
    char *scalar_end = json_put_string_scalar(scalar, (const char *)s, n);
    char *simd_end = json_put_string(simd, (const char *)s, n);
    CHECK((size_t)(scalar_end - scalar) == want_n && !memcmp(scalar, want, want_n));
    CHECK((size_t)(simd_end - simd) == want_n && !memcmp(simd, want, want_n));
    free(want);
    free(scalar);
    free(simd);
}

// Writes with both writers into buffers of exactly JSON_ESCAPED_MAX(n) bytes, as handlers guarantee.
static void check_writer_tight(const unsigned char *s, size_t n) {
    size_t room = n ? JSON_ESCAPED_MAX(n) : 1;
    char *scalar = malloc(room);
    char *simd = malloc(room);
    CHECK(scalar && simd);
    char *scalar_end = json_put_string_scalar(scalar, (const char *)s, n);
    char *simd_end = json_put_string(simd, (const char *)s, n);
    CHECK(scalar_end - scalar == simd_end - simd && !memcmp(scalar, simd, (size_t)(scalar_end - scalar)));
    free(scalar);
    free(simd);
}

static void test_writer_all_bytes(void) {
    unsigned char all[256];
    for (unsigned b = 0; b < 256; b++) {
        all[b] = (unsigned char)b;
        check_writer(&all[b], 1);
    }
    check_writer(all, sizeof all);
    unsigned char rev[256];
    for (unsigned b = 0; b < 256; b++) {
        rev[b] = (unsigned char)(255 - b);
    }
    check_writer(rev, sizeof rev);
    CHECK(strcmp(json_expect_ascii['"'], "\\\"") == 0 && strcmp(json_expect_ascii['\\'], "\\\\") == 0);
    CHECK(strcmp(json_expect_ascii['/'], "/") == 0 && strcmp(json_expect_ascii[0x7f], "\x7f") == 0);
    CHECK(strcmp(json_expect_ascii[0x08], "\\b") == 0 && strcmp(json_expect_ascii[0x1f], "\\u001f") == 0);
}

static const unsigned char special_bytes[] = {0x00, 0x01, 0x08, 0x09, 0x0a, 0x0c, 0x0d, 0x1f, 0x20, '"',
                                              0x5c, '/',  0x7f, 0x80, 0xc3, 0xff, 'a'};

static void test_writer_positions(void) {
    unsigned char buf[96];
    for (size_t n = 0; n <= 80; n++) {
        for (size_t k = 0; k < sizeof special_bytes; k++) {
            for (size_t pos = 0; pos < n; pos += (pos < 20 || pos + 20 >= n) ? 1 : 7) {
                memset(buf, 'a', sizeof buf);
                buf[pos] = special_bytes[k];
                check_writer(buf, n);
                check_writer_tight(buf, n);
            }
        }
        memset(buf, 'z', sizeof buf);
        check_writer_tight(buf, n);
        memset(buf, '"', sizeof buf);
        check_writer_tight(buf, n);
        memset(buf, 0x01, sizeof buf);
        check_writer_tight(buf, n);
        memset(buf, 0xe9, sizeof buf);
        check_writer(buf, n);
    }
}

static void test_writer_random(void) {
    static const unsigned char pool[] = {'a', 'b', ' ', '"', '\\', '\n', 0x00, 0x1f, 0x20, 0x7f, 0x80, 0xc3, 0xa9, 0xff, '/'};
    uint64_t rng = 0xD1B54A32D192ED03ULL;
    unsigned char buf[300];
    for (unsigned iter = 0; iter < 20000; iter++) {
        size_t n = (size_t)(rng_next(&rng) % sizeof buf);
        unsigned mode = (unsigned)(rng_next(&rng) % 3);
        for (size_t i = 0; i < n; i++) {
            uint64_t r = rng_next(&rng);
            buf[i] = mode == 0 ? (unsigned char)r : pool[r % sizeof pool];
            if (mode == 2 && (r >> 40) % 8) {
                buf[i] = 'q';
            }
        }
        check_writer(buf, n);
        check_writer_tight(buf, n);
    }
}

static void test_writer_known_strings(void) {
    char out[128];
    char *end = json_put_string(out, "hello \"world\"\n", 14);
    CHECK((size_t)(end - out) == 17 && !memcmp(out, "hello \\\"world\\\"\\n", 17));
    static const char long_text[] = "0123456789abcdef0123456789abcdef\"0123456789abcdef\\0123456789abcdef";
    end = json_put_string(out, long_text, sizeof long_text - 1);
    CHECK((size_t)(end - out) == sizeof long_text + 1 &&
          !memcmp(out, "0123456789abcdef0123456789abcdef\\\"0123456789abcdef\\\\0123456789abcdef", sizeof long_text + 1));
    end = json_put_string(out, "", 0);
    CHECK(end == out);
}

int main(void) {
    test_doc_table();
    test_depth();
    test_deep_values_in_siblings();
    test_extract_fields();
    test_extract_failures_clear_fields();
    test_numbers();
    test_unescape();
    test_unescape_limits();
    test_unescape_arbitrary_bytes();
    test_trim();
    test_trim_all_and_edges();
    test_count_chars();
    test_create_body_table();
    test_create_body_unescape_and_trim();
    test_create_body_lengths();
    test_create_body_scratch();
    test_writer_all_bytes();
    test_writer_positions();
    test_writer_random();
    test_writer_known_strings();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_json ok");
    return 0;
}
