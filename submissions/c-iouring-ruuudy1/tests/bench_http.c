// Times http_parse plus route_classify on requests shaped like the k6 client's. Not run by make; build it with the release
// flags: gcc $(bash build.sh --print-cflags) -no-pie -Wno-unused-function -DFM_TEST -DFM_EXTERNAL_SQLITE $(bash build.sh --print-sqlite-defs)
//   -Isrc -isystem deps/sqlite -isystem deps/liburing/src/include tests/bench_http.c build/tests/sqlite3.o
//   deps/liburing/src/liburing.a -o build/bench_http
#define FM_TEST 1
#include "../src/main.c"

static volatile uint64_t sink;

// Parses and routes the request n times and returns nanoseconds per call.
static double bench(const char *text, size_t len, uint64_t n) {
    char buf[2048];
    memcpy(buf, text, len);
    struct request req;
    struct route route;
    uint64_t t0 = util_mono_ns();
    for (uint64_t i = 0; i < n; i++) {
        enum http_parse_status st = http_parse(buf, (uint32_t)len, &req);
        route_classify(&req, &route);
        sink += (uint64_t)st + route.kind + req.consumed;
        __asm__ volatile("" ::: "memory");
    }
    return (double)(util_mono_ns() - t0) / (double)n;
}

int main(void) {
    static const char token[] =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NSIsInVzZXJuYW1lIjoidXNlcjEyMzQ1IiwiaWF0IjoxNzYwMDAwMDAwLCJleHAi"
        "OjE3NjAwMDM2MDB9.dBjftJeZ4CVP-mB92K4uWFZ7bBzC0WvyVnW9nA1xQp4";
    static char get_feed[512];
    static char get_post[512];
    static char create[1024];
    static char like[1024];
    int g1 = snprintf(get_feed, sizeof get_feed,
                      "GET /feed HTTP/1.1\r\nHost: 10.0.0.5\r\nUser-Agent: k6/2.3.0 (https://k6.io/)\r\n\r\n");
    int g2 = snprintf(get_post, sizeof get_post,
                      "GET /posts/48213 HTTP/1.1\r\nHost: 10.0.0.5\r\nUser-Agent: k6/2.3.0 (https://k6.io/)\r\n\r\n");
    int c1 = snprintf(create, sizeof create,
                      "POST /posts HTTP/1.1\r\nHost: 10.0.0.5\r\nUser-Agent: k6/2.3.0 (https://k6.io/)\r\nContent-Length: 38\r\n"
                      "Authorization: Bearer %s\r\nContent-Type: application/json\r\n\r\n{\"body\":\"hello from a load test user\"}",
                      token);
    int l1 = snprintf(like, sizeof like,
                      "POST /posts/48213/like HTTP/1.1\r\nHost: 10.0.0.5\r\nUser-Agent: k6/2.3.0 (https://k6.io/)\r\n"
                      "Content-Length: 0\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n\r\n",
                      token);
    const uint64_t n = 20000000;
    bench(get_feed, (size_t)g1, n / 10);
    printf("GET /feed (%d bytes, 2 headers): %.1f ns per parse and route\n", g1, bench(get_feed, (size_t)g1, n));
    printf("GET /posts/id (%d bytes, 2 headers): %.1f ns\n", g2, bench(get_post, (size_t)g2, n));
    printf("POST /posts (%d bytes, 5 headers, auth): %.1f ns\n", c1, bench(create, (size_t)c1, n));
    printf("POST like (%d bytes, 5 headers, auth): %.1f ns\n", l1, bench(like, (size_t)l1, n));
    return 0;
}
