// Unit tests for the HTTP parser: valid requests split at every byte offset, pipelining, chunked bodies, Expect,
// HTTP/1.0 rules, duplicate and conflicting headers, every limit, and every rejected shape.
#define FM_TEST 1
#include "../src/main.c"

static int failures;

// Records a failed expectation with its line.
#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

// What a valid request must parse to; a zero consumed means the whole text.
struct want {
    uint8_t method;
    const char *path;
    const char *auth;
    const char *body;
    uint8_t close_after;
    uint32_t consumed;
};

// Copies bytes into a heap block of exactly n bytes so the address sanitizer sees any read past the end.
static char *exact_copy(const char *s, size_t n) {
    char *b = malloc(n ? n : 1);
    if (!b) {
        abort();
    }
    memcpy(b, s, n);
    return b;
}

// Returns true when a slice holds exactly the text.
static bool slice_is(const char *p, uint32_t n, const char *text) {
    return n == strlen(text) && (!n || !memcmp(p, text, n));
}

// Parses the first n bytes of text on an exact-size heap copy; the copy is returned through *copy for inspection.
static enum http_parse_status parse_prefix(const char *text, size_t n, struct request *req, char **copy) {
    char *b = exact_copy(text, n);
    enum http_parse_status st = http_parse(b, (uint32_t)n, req);
    *copy = b;
    return st;
}

// Checks one valid request, then feeds every strict prefix and expects the parser to wait.
static void check_request(int line, const char *text, size_t n, const struct want *w) {
    struct request req;
    char *b = NULL;
    enum http_parse_status st = parse_prefix(text, n, &req, &b);
    bool ok = st == HTTP_PARSE_OK && req.method == w->method && slice_is(req.path, req.path_len, w->path) &&
              req.close_after == w->close_after && req.consumed == (w->consumed ? w->consumed : n) &&
              !req.expect_continue && slice_is(req.body, req.body_len, w->body ? w->body : "") &&
              (w->auth ? slice_is(req.auth, req.auth_len, w->auth) : (!req.auth && !req.auth_len));
    if (!ok) {
        fprintf(stderr, "FAIL line %d: request did not parse as expected (status %d)\n", line, (int)st);
        failures++;
    }
    free(b);
    size_t limit = w->consumed ? w->consumed : n;
    for (size_t s = 0; s < limit; s++) {
        st = parse_prefix(text, s, &req, &b);
        if (st != HTTP_PARSE_INCOMPLETE || memcmp(b, text, s) != 0) {
            fprintf(stderr, "FAIL line %d: prefix of %zu bytes gave status %d or changed the bytes\n", line, s, (int)st);
            failures++;
            free(b);
            return;
        }
        free(b);
    }
}

// Checks one request given as a string literal.
#define EXPECT_OK(text, ...) check_request(__LINE__, text, sizeof(text) - 1, &(const struct want){__VA_ARGS__})

// Checks that a text is rejected, and that no prefix is OK or goes back to waiting after a rejection.
static void check_bad(int line, const char *text, size_t n) {
    struct request req;
    char *b = NULL;
    bool seen_bad = false;
    for (size_t s = 0; s <= n; s++) {
        enum http_parse_status st = parse_prefix(text, s, &req, &b);
        free(b);
        if (st == HTTP_PARSE_OK || (seen_bad && st != HTTP_PARSE_BAD)) {
            fprintf(stderr, "FAIL line %d: prefix of %zu bytes gave status %d\n", line, s, (int)st);
            failures++;
            return;
        }
        seen_bad = st == HTTP_PARSE_BAD;
        if (st == HTTP_PARSE_BAD && req.consumed != s) {
            fprintf(stderr, "FAIL line %d: rejected input must report all bytes consumed\n", line);
            failures++;
            return;
        }
    }
    if (!seen_bad) {
        fprintf(stderr, "FAIL line %d: request was not rejected\n", line);
        failures++;
    }
}

#define EXPECT_BAD(text) check_bad(__LINE__, text, sizeof(text) - 1)

// A dynamic text builder for the limit tests.
struct text {
    char *p;
    size_t n, cap;
};

// Appends bytes, growing the buffer.
static void text_add(struct text *t, const char *s, size_t n) {
    if (t->n + n > t->cap) {
        t->cap = (t->n + n) * 2;
        t->p = realloc(t->p, t->cap);
        if (!t->p) {
            abort();
        }
    }
    memcpy(t->p + t->n, s, n);
    t->n += n;
}

// Appends a repeated byte.
static void text_fill(struct text *t, char c, size_t n) {
    for (size_t i = 0; i < n; i++) {
        text_add(t, &c, 1);
    }
}

// Appends a C string.
static void text_str(struct text *t, const char *s) {
    text_add(t, s, strlen(s));
}

// Result of parsing a built text in full.
static enum http_parse_status parse_text(const struct text *t, struct request *req) {
    char *b = NULL;
    enum http_parse_status st = parse_prefix(t->p, t->n, req, &b);
    free(b);
    return st;
}

static void test_basic_requests(void) {
    EXPECT_OK("GET /feed HTTP/1.1\r\nHost: 127.0.0.1:3000\r\nUser-Agent: k6/2.3.0 (https://k6.io/)\r\n\r\n", HTTP_GET,
              "/feed", NULL, NULL, 0, 0);
    EXPECT_OK("GET /health HTTP/1.1\r\n\r\n", HTTP_GET, "/health", NULL, NULL, 0, 0);
    EXPECT_OK("GET /posts/12?x=1&y=2 HTTP/1.1\r\nHost: x\r\n\r\n", HTTP_GET, "/posts/12", NULL, NULL, 0, 0);
    EXPECT_OK("GET /feed? HTTP/1.1\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 0, 0);
    EXPECT_OK("GET /? HTTP/1.1\r\n\r\n", HTTP_GET, "/", NULL, NULL, 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nHost: x\r\nContent-Length: 18\r\nAuthorization: Bearer a.b.c\r\n"
              "Content-Type: application/json\r\n\r\n{\"body\":\"hello!!\"}",
              HTTP_POST, "/posts", "Bearer a.b.c", "{\"body\":\"hello!!\"}", 0, 0);
    EXPECT_OK("POST /posts/7/like HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nAuthorization: Bearer t\r\n\r\n", HTTP_POST,
              "/posts/7/like", "Bearer t", NULL, 0, 0);
    EXPECT_OK("DELETE /posts/1 HTTP/1.1\r\n\r\n", HTTP_OTHER, "/posts/1", NULL, NULL, 0, 0);
    EXPECT_OK("get /feed HTTP/1.1\r\n\r\n", HTTP_OTHER, "/feed", NULL, NULL, 0, 0);
    EXPECT_OK("PUT /feed HTTP/1.1\r\nContent-Length: 2\r\n\r\nab", HTTP_OTHER, "/feed", NULL, "ab", 0, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nAccept-Encoding: gzip, br\r\nX-Empty:\r\nX-Tab:\tv\t\r\n\r\n", HTTP_GET, "/feed", NULL,
              NULL, 0, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nX-A: b:c:d\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 0, 0);
    EXPECT_OK("GET /f\x80\xff HTTP/1.1\r\nX: \x80\xff\r\n\r\n", HTTP_GET, "/f\x80\xff", NULL, NULL, 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nContent-Length: 4\r\n\r\n\r\n\r\n", HTTP_POST, "/posts", NULL, "\r\n\r\n", 0, 0);
}

static void test_header_names_and_values(void) {
    EXPECT_OK("POST /posts HTTP/1.1\r\nCONTENT-length: 2\r\nauthorization: Bearer x\r\n\r\nab", HTTP_POST, "/posts",
              "Bearer x", "ab", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nCoNtEnT-LeNgTh:\t 3 \t\r\nAuThOrIzAtIoN: Bearer y\r\n\r\nabc", HTTP_POST, "/posts",
              "Bearer y", "abc", 0, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nAuthorization:  \t Bearer x \t\r\n\r\n", HTTP_GET, "/feed", "Bearer x \t", NULL, 0, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nAuthorization:\r\n\r\n", HTTP_GET, "/feed", "", NULL, 0, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nAuthorization: Bearer a:b\r\n\r\n", HTTP_GET, "/feed", "Bearer a:b", NULL, 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nContent-Length: 5\r\ncontent-length: 05\r\n\r\nhello", HTTP_POST, "/posts", NULL,
              "hello", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nContent-Length: 0000000000000003\r\n\r\nabc", HTTP_POST, "/posts", NULL, "abc", 0, 0);
}

static void test_connection_rules(void) {
    EXPECT_OK("GET /feed HTTP/1.0\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 1, 0);
    EXPECT_OK("GET /feed HTTP/1.0\r\nConnection: keep-alive\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 0, 0);
    EXPECT_OK("GET /feed HTTP/1.0\r\nConnection: Keep-Alive\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 0, 0);
    EXPECT_OK("GET /feed HTTP/1.0\r\nConnection: close\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 1, 0);
    EXPECT_OK("GET /feed HTTP/1.0\r\nConnection: keep-alive, close\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 1, 0);
    EXPECT_OK("GET /feed HTTP/1.0\r\nConnection: close, keep-alive\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 1, 0);
    EXPECT_OK("GET /feed HTTP/1.0\r\nConnection: Upgrade ,\tKeep-Alive\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 0, 0);
    EXPECT_OK("GET /feed HTTP/1.0\r\nConnection: upgrade\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 1, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 0, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nConnection: close\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 1, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nConnection: CLOSE\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 1, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nConnection: keep-alive\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 0, 0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nConnection: keep-alive\r\nConnection: close\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 1,
              0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nConnection: close\r\nConnection: keep-alive\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 1,
              0);
    EXPECT_OK("GET /feed HTTP/1.1\r\nConnection: closed\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 0, 0);
}

static void test_chunked(void) {
    EXPECT_OK("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n",
              HTTP_POST, "/posts", NULL, "hello world", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\ntransfer-encoding: CHUNKED\r\n\r\n0\r\n\r\n", HTTP_POST, "/posts", NULL, "", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nA\r\n0123456789\r\na\r\nabcdefghij\r\n0\r\n\r\n",
              HTTP_POST, "/posts", NULL, "0123456789abcdefghij", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0005\r\nhello\r\n000\r\n\r\n", HTTP_POST, "/posts",
              NULL, "hello", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3 ; a=b\r\nabc\r\n2\t;x\r\nde\r\n0;z\r\n\r\n", HTTP_POST,
              "/posts", NULL, "abcde", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: v\r\nY: w\r\n\r\n", HTTP_POST,
              "/posts", NULL, "abc", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 99\r\n\r\n2\r\nok\r\n0\r\n\r\n", HTTP_POST,
              "/posts", NULL, "ok", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n\r\n\r\n\r\n0\r\n\r\n", HTTP_POST, "/posts", NULL,
              "\r\n\r\n", 0, 0);
    EXPECT_OK("POST /posts HTTP/1.1\r\nTransfer-Encoding:  chunked \t\r\n\r\n1\r\nx\r\n0\r\n\r\n", HTTP_POST, "/posts", NULL, "x",
              0, 0);
}

// Checks a pipelined text request by request: each parse must start where the last one ended.
static void check_pipeline(int line, const char *text, size_t n, const char *const *bodies, size_t count) {
    char *b = exact_copy(text, n);
    uint32_t off = 0;
    for (size_t i = 0; i < count; i++) {
        struct request req;
        enum http_parse_status st = http_parse(b + off, (uint32_t)(n - off), &req);
        if (st != HTTP_PARSE_OK || !slice_is(req.body, req.body_len, bodies[i])) {
            fprintf(stderr, "FAIL line %d: pipelined request %zu status %d\n", line, i, (int)st);
            failures++;
            free(b);
            return;
        }
        off += req.consumed;
    }
    CHECK(off == n);
    free(b);
}

static void test_pipelining(void) {
    static const char two[] = "GET /feed HTTP/1.1\r\n\r\nPOST /posts HTTP/1.1\r\nContent-Length: 3\r\n\r\nabcGET /health HTTP/1.1\r\n\r\n";
    static const char *const two_bodies[] = {"", "abc", ""};
    check_pipeline(__LINE__, two, sizeof two - 1, two_bodies, 3);
    static const char mixed[] =
        "POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\nPOST /posts HTTP/1.1\r\n"
        "Transfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n2\r\nyo\r\n0\r\nT: 1\r\n\r\nGET /feed HTTP/1.1\r\n\r\n";
    static const char *const mixed_bodies[] = {"abc", "hiyo", ""};
    check_pipeline(__LINE__, mixed, sizeof mixed - 1, mixed_bodies, 3);
#define FIRST_GET "GET /feed HTTP/1.1\r\n\r\n"
#define FIRST_POST "POST /posts HTTP/1.1\r\nContent-Length: 2\r\n\r\nab"
#define FIRST_CHUNKED "POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n0\r\n\r\n"
    EXPECT_OK(FIRST_GET "GET /next HTTP/1.1\r\n\r\n", HTTP_GET, "/feed", NULL, NULL, 0, sizeof(FIRST_GET) - 1);
    EXPECT_OK(FIRST_POST "GARBAGE", HTTP_POST, "/posts", NULL, "ab", 0, sizeof(FIRST_POST) - 1);
    EXPECT_OK(FIRST_CHUNKED "\x01" "garbage", HTTP_POST, "/posts", NULL, "ab", 0, sizeof(FIRST_CHUNKED) - 1);
}

// Parses text and returns the Expect flag and status.
static enum http_parse_status parse_expect(const char *text, size_t n, uint8_t *expect) {
    struct request req;
    char *b = NULL;
    enum http_parse_status st = parse_prefix(text, n, &req, &b);
    free(b);
    *expect = req.expect_continue;
    return st;
}

static void test_expect(void) {
    static const char head[] = "POST /posts HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n";
    uint8_t expect = 9;
    CHECK(parse_expect(head, sizeof head - 1, &expect) == HTTP_PARSE_INCOMPLETE && expect == 1);
    CHECK(parse_expect(head, sizeof head - 3, &expect) == HTTP_PARSE_INCOMPLETE && expect == 0);
    static const char part[] = "POST /posts HTTP/1.1\r\nExpect: 100-CONTINUE\r\nContent-Length: 5\r\n\r\nab";
    CHECK(parse_expect(part, sizeof part - 1, &expect) == HTTP_PARSE_INCOMPLETE && expect == 1);
    static const char full[] = "POST /posts HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\nabcde";
    CHECK(parse_expect(full, sizeof full - 1, &expect) == HTTP_PARSE_OK && expect == 0);
    static const char other[] = "POST /posts HTTP/1.1\r\nExpect: something\r\nContent-Length: 5\r\n\r\n";
    CHECK(parse_expect(other, sizeof other - 1, &expect) == HTTP_PARSE_INCOMPLETE && expect == 0);
    static const char old[] = "POST /posts HTTP/1.0\r\nExpect: 100-continue\r\nContent-Length: 5\r\n\r\n";
    CHECK(parse_expect(old, sizeof old - 1, &expect) == HTTP_PARSE_INCOMPLETE && expect == 0);
    static const char chunked[] = "POST /posts HTTP/1.1\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n";
    CHECK(parse_expect(chunked, sizeof chunked - 1, &expect) == HTTP_PARSE_INCOMPLETE && expect == 1);
    static const char chunk_part[] = "POST /posts HTTP/1.1\r\nExpect: 100-continue\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nab";
    CHECK(parse_expect(chunk_part, sizeof chunk_part - 1, &expect) == HTTP_PARSE_INCOMPLETE && expect == 1);
    static const char empty[] = "POST /posts HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n";
    CHECK(parse_expect(empty, sizeof empty - 1, &expect) == HTTP_PARSE_OK && expect == 0);
}

static void test_rejected_requests(void) {
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost: a\rb\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost: a\nb\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost: a\r\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\n\rHost: a\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\nHost: a\n\n");
    EXPECT_BAD("GET /feed\rHTTP/1.1\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost: a\r\n\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost: a\0b\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost: a\x01\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost: a\x7f\r\n\r\n");
    EXPECT_BAD("GET /fe\ted HTTP/1.1\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost : a\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost\t: a\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nContent-Length : 0\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost: a\r\n b\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\n Host: a\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\n: a\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nHost a\r\n\r\n");
    EXPECT_BAD("\r\n\r\n");
    EXPECT_BAD("\r\nGET /feed HTTP/1.1\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\n\r\r\n\r\n");
}

static void test_rejected_request_line(void) {
    EXPECT_BAD("GET /feed HTTP/2.0\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.2\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/0.9\r\n\r\n");
    EXPECT_BAD("GET /feed http/1.1\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1 \r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.\r\n\r\n");
    EXPECT_BAD("GET /feed\r\n\r\n");
    EXPECT_BAD("GET\r\n\r\n");
    EXPECT_BAD("GET  /feed HTTP/1.1\r\n\r\n");
    EXPECT_BAD("GET /fe ed HTTP/1.1\r\n\r\n");
    EXPECT_BAD(" /feed HTTP/1.1\r\n\r\n");
    EXPECT_BAD("GET feed HTTP/1.1\r\n\r\n");
    EXPECT_BAD("GET * HTTP/1.1\r\n\r\n");
    EXPECT_BAD("GET http://x/feed HTTP/1.1\r\n\r\n");
    EXPECT_BAD("GET  HTTP/1.1\r\n\r\n");
    EXPECT_BAD("GET /feed  HTTP/1.1\r\n\r\n");
    EXPECT_BAD("HTTP/1.1 200 OK\r\n\r\n");
}

static void test_rejected_framing(void) {
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: 0\r\ncontent-length: 1\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: +5\r\n\r\nhello");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: -1\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: 5x\r\n\r\nhello");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: 0x5\r\n\r\nhello");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: \r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: 1 2\r\n\r\nab");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: 1,2\r\n\r\nab");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: 1.0\r\n\r\na");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nContent-Length: 16001\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nTransfer-Encoding: identity\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nTransfer-Encoding:\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: x\r\n\r\n0\r\n\r\n");
    EXPECT_BAD("POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n0\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nAuthorization: Bearer a\r\nAuthorization: Bearer a\r\n\r\n");
    EXPECT_BAD("GET /feed HTTP/1.1\r\nAuthorization: Bearer a\r\nauthorization: Bearer b\r\n\r\n");
}

// A chunked body to append after the head, the status it must give, and how many filler bytes follow it.
struct chunk_case {
    const char *body;
    enum http_parse_status want;
    size_t fill;
};

static void test_rejected_chunks(void) {
    static const char head[] = "POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n";
    static const struct chunk_case cases[] = {
        {"g\r\nx\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"\r\nabc\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"-1\r\nabc\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3\r\nabcX\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3\r\nabc\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3\r\nabc\r0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3\nabc\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3 \r\nabc\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3 x\r\nabc\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3;a\nb\r\nabc\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3;a\x01\r\nabc\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3\rabc\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"0\r\nbad\nline\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"0\r\nbad\x01line\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"0\r\n\rx", HTTP_PARSE_BAD, 0},
        {"3e80\r\n", HTTP_PARSE_BAD, 16000},
        {"FFFFFFFFFFFFFFFFFFFF\r\n", HTTP_PARSE_BAD, 0},
        {"0\r\n\r", HTTP_PARSE_INCOMPLETE, 0},
        {"3\r\nabc\r\n\r\n", HTTP_PARSE_BAD, 0},
        {"3\r\nabc\r\n3\r\nabcde\r\n0\r\n\r\n", HTTP_PARSE_BAD, 0},
    };
    for (size_t i = 0; i < ARRAY_LEN(cases); i++) {
        struct text t = {0};
        text_str(&t, head);
        text_str(&t, cases[i].body);
        text_fill(&t, 'a', cases[i].fill);
        struct request req;
        enum http_parse_status st = parse_text(&t, &req);
        if (st != cases[i].want) {
            fprintf(stderr, "FAIL chunk case %zu status %d\n", i, (int)st);
            failures++;
        }
        free(t.p);
    }
}

static void test_head_limits(void) {
    for (int delta = -1; delta <= 1; delta++) {
        struct text t = {0};
        text_str(&t, "GET /feed HTTP/1.1\r\nX: ");
        size_t fixed = t.n;
        text_fill(&t, 'a', (size_t)((int)HEADER_MAX - (int)fixed + delta));
        text_str(&t, "\r\n\r\n");
        struct request req;
        enum http_parse_status st = parse_text(&t, &req);
        CHECK(st == (delta <= 0 ? HTTP_PARSE_OK : HTTP_PARSE_BAD));
        free(t.p);
    }
    struct text t = {0};
    text_str(&t, "GET /feed HTTP/1.1\r\nX: ");
    text_fill(&t, 'a', HEADER_MAX + 200);
    struct request req;
    t.n = HEADER_MAX + 3;
    CHECK(parse_text(&t, &req) == HTTP_PARSE_INCOMPLETE);
    t.n = HEADER_MAX + 4;
    CHECK(parse_text(&t, &req) == HTTP_PARSE_BAD);
    t.n = HEADER_MAX + 4 + 100;
    CHECK(parse_text(&t, &req) == HTTP_PARSE_BAD);
    free(t.p);
}

static void test_target_limit(void) {
    for (int delta = -1; delta <= 1; delta++) {
        struct text t = {0};
        text_str(&t, "GET /");
        text_fill(&t, 'a', (size_t)(TARGET_MAX - 1 + delta));
        text_str(&t, " HTTP/1.1\r\n\r\n");
        struct request req;
        CHECK(parse_text(&t, &req) == (delta <= 0 ? HTTP_PARSE_OK : HTTP_PARSE_BAD));
        free(t.p);
    }
    struct text q = {0};
    text_str(&q, "GET /feed?");
    text_fill(&q, 'q', TARGET_MAX);
    text_str(&q, " HTTP/1.1\r\n\r\n");
    struct request req;
    CHECK(parse_text(&q, &req) == HTTP_PARSE_BAD);
    free(q.p);
}

static void test_header_count_limit(void) {
    for (int extra = 0; extra <= 1; extra++) {
        struct text t = {0};
        text_str(&t, "GET /feed HTTP/1.1\r\n");
        for (int i = 0; i < HTTP_HEADER_COUNT_MAX + extra; i++) {
            text_str(&t, "A: b\r\n");
        }
        text_str(&t, "\r\n");
        struct request req;
        CHECK(parse_text(&t, &req) == (extra ? HTTP_PARSE_BAD : HTTP_PARSE_OK));
        free(t.p);
    }
}

static void test_body_limits(void) {
    struct text t = {0};
    text_str(&t, "POST /posts HTTP/1.1\r\nContent-Length: ");
    size_t cl_at = t.n;
    char num[16];
    for (int over = -1; over <= 1; over++) {
        t.n = cl_at;
        size_t head_len = cl_at + 5 + 4;
        int cl = (int)(REQUEST_MAX - head_len) + over;
        snprintf(num, sizeof num, "%5d", cl);
        for (char *c = num; *c == ' '; c++) {
            *c = '0';
        }
        text_str(&t, num);
        text_str(&t, "\r\n\r\n");
        struct request req;
        CHECK(parse_text(&t, &req) == (over <= 0 ? HTTP_PARSE_INCOMPLETE : HTTP_PARSE_BAD));
        text_fill(&t, 'b', over <= 0 ? (size_t)cl : 0);
        CHECK(parse_text(&t, &req) == (over <= 0 ? HTTP_PARSE_OK : HTTP_PARSE_BAD));
        CHECK(over > 0 || req.consumed == head_len + (size_t)cl);
    }
    free(t.p);
}

static void test_chunked_body_limit(void) {
    struct text t = {0};
    text_str(&t, "POST /posts HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
    size_t head = t.n;
    struct request req;
    for (int over = 0; over <= 1; over++) {
        t.n = head;
        size_t room = REQUEST_MAX - head - 13;
        char line[16];
        int n = snprintf(line, sizeof line, "%zx\r\n", room + (size_t)over);
        text_add(&t, line, (size_t)n);
        text_fill(&t, 'c', room + (size_t)over);
        text_str(&t, "\r\n0\r\n\r\n");
        enum http_parse_status st = parse_text(&t, &req);
        CHECK(st == (over ? HTTP_PARSE_BAD : HTTP_PARSE_OK));
    }
    free(t.p);
}

// A request followed by bytes that are not a request: the first parses, the rest is rejected.
static void test_pipelined_garbage_after_request(void) {
    static const char text[] = "GET /feed HTTP/1.1\r\n\r\n\x01\x02 garbage that is not a request";
    char *b = exact_copy(text, sizeof text - 1);
    struct request req;
    CHECK(http_parse(b, sizeof text - 1, &req) == HTTP_PARSE_OK && req.consumed == 22);
    CHECK(http_parse(b + 22, (uint32_t)sizeof text - 1 - 22, &req) == HTTP_PARSE_BAD);
    free(b);
}

static void test_empty_input(void) {
    struct request req;
    char dummy = 0;
    CHECK(http_parse(&dummy, 0, &req) == HTTP_PARSE_INCOMPLETE);
    CHECK(!req.expect_continue && !req.consumed);
}

// Reaching every block boundary of the SIMD scan: a CRLF pair straddling each 16-byte edge.
static void test_block_boundaries(void) {
    for (size_t pad = 0; pad < 40; pad++) {
        struct text t = {0};
        text_str(&t, "GET /feed HTTP/1.1\r\nX: ");
        text_fill(&t, 'v', pad);
        text_str(&t, "\r\nY: z\r\n\r\nrest");
        struct request req;
        char *b = NULL;
        CHECK(parse_prefix(t.p, t.n, &req, &b) == HTTP_PARSE_OK);
        CHECK(req.consumed == t.n - 4);
        free(b);
        free(t.p);
    }
}

int main(void) {
    test_basic_requests();
    test_header_names_and_values();
    test_connection_rules();
    test_chunked();
    test_pipelining();
    test_expect();
    test_rejected_requests();
    test_rejected_request_line();
    test_rejected_framing();
    test_rejected_chunks();
    test_head_limits();
    test_target_limit();
    test_header_count_limit();
    test_body_limits();
    test_chunked_body_limit();
    test_pipelined_garbage_after_request();
    test_empty_input();
    test_block_boundaries();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_http ok");
    return 0;
}
