// Unit tests for routing: every route, every near miss, the id parsing table, cohorts and the auth flag.
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

// Routes a method and path that did not come through the parser.
static void classify(uint8_t method, const char *path, struct route *r) {
    struct request req = {0};
    req.method = method;
    req.path = path;
    req.path_len = (uint32_t)strlen(path);
    route_classify(&req, r);
}

// One routing expectation: method, path, kind and the raw id text ("" when none).
struct route_case {
    uint8_t method;
    const char *path;
    uint8_t kind;
    const char *id;
};

static void test_route_table(void) {
    static const struct route_case cases[] = {
        {HTTP_GET, "/health", ROUTE_HEALTH, ""},
        {HTTP_GET, "/feed", ROUTE_FEED, ""},
        {HTTP_GET, "/posts/1", ROUTE_POST, "1"},
        {HTTP_GET, "/posts/abc", ROUTE_POST, "abc"},
        {HTTP_GET, "/posts/1.5", ROUTE_POST, "1.5"},
        {HTTP_GET, "/posts/-1", ROUTE_POST, "-1"},
        {HTTP_GET, "/posts/%31", ROUTE_POST, "%31"},
        {HTTP_GET, "/posts/99999999999999999999", ROUTE_POST, "99999999999999999999"},
        {HTTP_POST, "/posts", ROUTE_CREATE, ""},
        {HTTP_POST, "/posts/1/like", ROUTE_LIKE, "1"},
        {HTTP_POST, "/posts/abc/like", ROUTE_LIKE, "abc"},
        {HTTP_POST, "/posts/0/like", ROUTE_LIKE, "0"},
        {HTTP_GET, "/posts", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/posts/", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/posts/", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/posts/1/", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/posts/1/like", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/posts/1/2", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/posts/1", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/posts//like", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/posts/1/like/", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/posts/1/likes", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/posts/1/Like", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/posts/1/lik", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/posts/a/b/like", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/posts/1/like/x", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/health/", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/healthz", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/Health", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/health", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/feed/", ROUTE_NOT_FOUND, ""},
        {HTTP_POST, "/feed", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/POSTS/1", ROUTE_NOT_FOUND, ""},
        {HTTP_GET, "/post/1", ROUTE_NOT_FOUND, ""},
        {HTTP_OTHER, "/health", ROUTE_NOT_FOUND, ""},
        {HTTP_OTHER, "/feed", ROUTE_NOT_FOUND, ""},
        {HTTP_OTHER, "/posts", ROUTE_NOT_FOUND, ""},
        {HTTP_OTHER, "/posts/1", ROUTE_NOT_FOUND, ""},
        {HTTP_OTHER, "/posts/1/like", ROUTE_NOT_FOUND, ""},
        {0, "/health", ROUTE_NOT_FOUND, ""},
    };
    for (size_t i = 0; i < ARRAY_LEN(cases); i++) {
        struct route r;
        classify(cases[i].method, cases[i].path, &r);
        bool id_ok = r.id.n == strlen(cases[i].id) && (!r.id.n || !memcmp(r.id.p, cases[i].id, r.id.n));
        if (r.kind != cases[i].kind || !id_ok) {
            fprintf(stderr, "FAIL route case %zu (%s): kind %d\n", i, cases[i].path, (int)r.kind);
            failures++;
        }
    }
}

// Parses request text and routes it, so the query string rule is covered end to end.
static void test_query_strings(void) {
    static char text[] = "GET /posts/12?like=1/like HTTP/1.1\r\n\r\n";
    struct request req;
    struct route r;
    CHECK(http_parse(text, sizeof text - 1, &req) == HTTP_PARSE_OK);
    route_classify(&req, &r);
    CHECK(r.kind == ROUTE_POST && r.id.n == 2 && !memcmp(r.id.p, "12", 2));
    static char text2[] = "POST /posts/5/like?x=/y HTTP/1.1\r\nContent-Length: 0\r\n\r\n";
    CHECK(http_parse(text2, sizeof text2 - 1, &req) == HTTP_PARSE_OK);
    route_classify(&req, &r);
    CHECK(r.kind == ROUTE_LIKE && r.id.n == 1 && r.id.p[0] == '5');
    static char text3[] = "GET /feed?limit=5 HTTP/1.1\r\n\r\n";
    CHECK(http_parse(text3, sizeof text3 - 1, &req) == HTTP_PARSE_OK);
    route_classify(&req, &r);
    CHECK(r.kind == ROUTE_FEED && !r.id.n);
}

// One id expectation: text, status and parsed value when the status is ID_OK.
struct id_case {
    const char *text;
    enum route_id_status status;
    int64_t value;
};

static void test_id_table(void) {
    static const struct id_case cases[] = {
        {"1", ID_OK, 1},
        {"12", ID_OK, 12},
        {"007", ID_OK, 7},
        {"0000000000000000000000001", ID_OK, 1},
        {"9223372036854775807", ID_OK, INT64_MAX},
        {"09223372036854775807", ID_OK, INT64_MAX},
        {"9223372036854775808", ID_NOT_FOUND, 0},
        {"9999999999999999999", ID_NOT_FOUND, 0},
        {"18446744073709551615", ID_NOT_FOUND, 0},
        {"18446744073709551616", ID_NOT_FOUND, 0},
        {"99999999999999999999", ID_NOT_FOUND, 0},
        {"100000000000000000000000000000", ID_NOT_FOUND, 0},
        {"", ID_INVALID, 0},
        {"0", ID_INVALID, 0},
        {"000", ID_INVALID, 0},
        {"-1", ID_INVALID, 0},
        {"+1", ID_INVALID, 0},
        {"abc", ID_INVALID, 0},
        {"1.5", ID_INVALID, 0},
        {"12abc", ID_INVALID, 0},
        {"abc12", ID_INVALID, 0},
        {" 1", ID_INVALID, 0},
        {"1 ", ID_INVALID, 0},
        {"0x10", ID_INVALID, 0},
        {"1e3", ID_INVALID, 0},
        {"%31", ID_INVALID, 0},
        {"\xd9\xa1", ID_INVALID, 0},
        {"99999999999999999999x", ID_INVALID, 0},
        {"-99999999999999999999", ID_INVALID, 0},
    };
    for (size_t i = 0; i < ARRAY_LEN(cases); i++) {
        int64_t v = -5;
        enum route_id_status st = route_parse_id((struct slice){cases[i].text, (uint32_t)strlen(cases[i].text)}, &v);
        bool ok = st == cases[i].status && (st != ID_OK || v == cases[i].value) && (st == ID_OK || v == -5);
        if (!ok) {
            fprintf(stderr, "FAIL id case %zu (%s): status %d value %lld\n", i, cases[i].text, (int)st, (long long)v);
            failures++;
        }
    }
    int64_t v = 0;
    const char embedded[] = {'1', '\0', '2'};
    CHECK(route_parse_id((struct slice){embedded, 3}, &v) == ID_INVALID);
}

static void test_cohorts_and_auth(void) {
    CHECK(route_cohort(ROUTE_CREATE) == COHORT_WRITE);
    CHECK(route_cohort(ROUTE_LIKE) == COHORT_WRITE);
    CHECK(route_cohort(ROUTE_FEED) == COHORT_FEED);
    CHECK(route_cohort(ROUTE_POST) == COHORT_POST);
    CHECK(route_cohort(ROUTE_HEALTH) == COHORT_OTHER);
    CHECK(route_cohort(ROUTE_NOT_FOUND) == COHORT_OTHER);
    CHECK(route_cohort(ROUTE_BAD_REQUEST) == COHORT_OTHER);
    CHECK(COHORT_WRITE == 0 && COHORT_FEED == 1 && COHORT_POST == 2 && COHORT_OTHER == 3 && COHORT_COUNT == 4);
    CHECK(route_needs_auth(ROUTE_CREATE) && route_needs_auth(ROUTE_LIKE));
    CHECK(!route_needs_auth(ROUTE_HEALTH) && !route_needs_auth(ROUTE_FEED) && !route_needs_auth(ROUTE_POST));
    CHECK(!route_needs_auth(ROUTE_NOT_FOUND) && !route_needs_auth(ROUTE_BAD_REQUEST));
}

int main(void) {
    test_route_table();
    test_query_strings();
    test_id_table();
    test_cohorts_and_auth();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_route ok");
    return 0;
}
