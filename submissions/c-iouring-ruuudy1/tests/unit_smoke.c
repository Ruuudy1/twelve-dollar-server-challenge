// Smoke test for the skeleton contracts: pool, response writer, parser, router and id parsing.
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

// Returns true when a finished block holds exactly the expected bytes.
static bool block_is(const struct block *b, const char *want) {
    return b->len == strlen(want) && !memcmp(b->data + b->off, want, b->len);
}

// Parses one request text and routes it.
static enum http_parse_status parse_text(const char *text, struct request *req, struct route *route) {
    static char buf[4096];
    size_t n = strlen(text);
    memcpy(buf, text, n);
    enum http_parse_status st = http_parse(buf, (uint32_t)n, req);
    if (st == HTTP_PARSE_OK) {
        route_classify(req, route);
    }
    return st;
}

static void test_writer(void) {
    struct resp r;
    CHECK(block_pool_init());
    CHECK(resp_begin(&r));
    CHECK(resp_put(&r, "{\"a\":1}", 7));
    resp_finish(&r, 200, false);
    CHECK(block_is(r.blk, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 7\r\n\r\n{\"a\":1}"));
    block_put(r.blk);
    CHECK(resp_begin(&r));
    resp_error(&r, ERR_INVALID_ID, true);
    CHECK(block_is(r.blk, "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 27\r\n"
                          "Connection: close\r\n\r\n{\"error\":\"invalid post id\"}"));
    resp_rewrite_500(r.blk);
    CHECK(r.blk->status == 500 && (r.blk->flags & BLOCK_F_CLOSE));
    block_put(r.blk);
}

static void test_jumbo_growth(void) {
    struct resp r;
    CHECK(resp_begin(&r));
    CHECK(resp_put(&r, "x", 1));
    char *o = resp_need(&r, 30000);
    CHECK(o && (r.blk->flags & BLOCK_F_JUMBO));
    CHECK(r.blk->data[RESP_HDR_ROOM] == 'x');
    block_put(r.blk);
}

static void test_parse_and_route(void) {
    struct request req;
    struct route route;
    CHECK(parse_text("GET /health HTTP/1.1\r\nHost: x\r\n\r\n", &req, &route) == HTTP_PARSE_OK);
    CHECK(route.kind == ROUTE_HEALTH && !req.close_after);
    CHECK(parse_text("GET /feed?x=1 HTTP/1.0\r\n\r\n", &req, &route) == HTTP_PARSE_OK);
    CHECK(route.kind == ROUTE_FEED && req.close_after);
    CHECK(parse_text("POST /posts/12/like HTTP/1.1\r\nAuthorization: Bearer t\r\nContent-Length: 0\r\n\r\n", &req,
                     &route) == HTTP_PARSE_OK);
    CHECK(route.kind == ROUTE_LIKE && route.id.n == 2 && req.auth_len == 8);
    CHECK(parse_text("POST /posts HTTP/1.1\r\nContent-Length: 5\r\n\r\nab", &req, &route) == HTTP_PARSE_INCOMPLETE);
    CHECK(parse_text("GET /posts/1/ HTTP/1.1\r\n\r\n", &req, &route) == HTTP_PARSE_OK && route.kind == ROUTE_NOT_FOUND);
    CHECK(parse_text("GET /posts/ HTTP/1.1\r\n\r\n", &req, &route) == HTTP_PARSE_OK && route.kind == ROUTE_NOT_FOUND);
    CHECK(parse_text("GET /feed HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", &req, &route) == HTTP_PARSE_BAD);
}

static void test_ids(void) {
    int64_t id = 0;
    CHECK(route_parse_id((struct slice){"12", 2}, &id) == ID_OK && id == 12);
    CHECK(route_parse_id((struct slice){"007", 3}, &id) == ID_OK && id == 7);
    CHECK(route_parse_id((struct slice){"0", 1}, &id) == ID_INVALID);
    CHECK(route_parse_id((struct slice){"-1", 2}, &id) == ID_INVALID);
    CHECK(route_parse_id((struct slice){"1.5", 3}, &id) == ID_INVALID);
    CHECK(route_parse_id((struct slice){"99999999999999999999", 20}, &id) == ID_NOT_FOUND);
}

int main(void) {
    test_writer();
    test_jumbo_growth();
    test_parse_and_route();
    test_ids();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_smoke ok");
    return 0;
}
