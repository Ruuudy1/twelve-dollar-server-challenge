// Every endpoint and error row of the spec, auth before id, and exact bytes against test/golden on a fresh seed copy.
// Run with the argument "db" to skip the cases that need the crypto and json modules (token checks and create bodies).
#define FM_TEST 1
#include "../src/main.c"
#include "db_fixture.h"

static const char *const head_200 = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ";
static bool db_only;
static char tmp_dir[64];
static char db_file[128];
static char token[1024];
static char bearer[1100];

// Reads a golden file into a buffer and returns its length, or 0 when missing.
static size_t read_file(const char *path, char *out, size_t cap) {
    FILE *f = fopen(path, "rb");
    size_t n = 0;
    if (f) {
        n = fread(out, 1, cap - 1, f);
        fclose(f);
    }
    out[n] = 0;
    return n;
}

// Copies the seed database into the temporary directory; returns false when it is not present.
static bool copy_seed(void) {
    const char *seed = getenv("FM_SEED") ? getenv("FM_SEED") : "../../../seed/feed.db";
    char cmd[512];
    if (access(seed, R_OK)) {
        fprintf(stderr, "seed %s not found, golden checks skipped\n", seed);
        return false;
    }
    snprintf(cmd, sizeof cmd, "cp '%s' '%s'", seed, db_file);
    return system(cmd) == 0;
}

// Expects a status and an exact body.
static void expect(const struct fx_resp *r, unsigned status, const char *body, int line) {
    if (r->status != status || !fx_body_is(r, body)) {
        fprintf(stderr, "line %d: want %u %s\n got  %u %s\n", line, status, body, r->status, fx_body(r));
        fx_failures++;
    }
}

#define EXPECT(r, status, body) expect(&(r), (status), (body), __LINE__)

// Checks the exact bytes of a response against a status line, then a body.
static void expect_bytes(const struct fx_resp *r, const char *head, const char *body, int line) {
    char want[1 << 16];
    snprintf(want, sizeof want, "%s%zu\r\n\r\n%s", head, strlen(body), body);
    if (r->n != strlen(want) || memcmp(r->bytes, want, r->n)) {
        fprintf(stderr, "line %d: bytes differ\n want %s\n got  %s\n", line, want, r->bytes);
        fx_failures++;
    }
}

// Reads from a fresh seed copy and compares with the golden files byte for byte.
static void test_golden(void) {
    static char golden[1 << 15];
    struct fx_resp r;
    static const char *const posts[] = {"1", "250000", "500000"};
    CHECK(read_file("../../../test/golden/feed.json", golden, sizeof golden) > 1000);
    fx_get("/feed", &r);
    expect_bytes(&r, head_200, golden, __LINE__);
    for (unsigned i = 0; i < ARRAY_LEN(posts); i++) {
        char path[64];
        char file[96];
        snprintf(path, sizeof path, "/posts/%s", posts[i]);
        snprintf(file, sizeof file, "../../../test/golden/post-%s.json", posts[i]);
        CHECK(read_file(file, golden, sizeof golden) > 50);
        fx_get(path, &r);
        expect_bytes(&r, head_200, golden, __LINE__);
    }
}

// Health, unknown paths, id validation and not-found rows that need no token.
static void test_reads(void) {
    struct fx_resp r;
    fx_get("/health", &r);
    CHECK(r.status == 200 && !strncmp(fx_body(&r), "{\"status\":\"ok\",\"db\":\"ok\",\"uptime_s\":", 33));
    fx_get("/nope", &r);
    EXPECT(r, 404, "{\"error\":\"not found\"}");
    fx_get("/posts/", &r);
    EXPECT(r, 404, "{\"error\":\"not found\"}");
    fx_get("/posts/1/", &r);
    EXPECT(r, 404, "{\"error\":\"not found\"}");
    fx_get("/posts", &r);
    EXPECT(r, 404, "{\"error\":\"not found\"}");
    static const char *const bad_ids[] = {"0", "000", "-1", "abc", "1.5", "12abc", "+1", "1e3", "0x10"};
    for (unsigned i = 0; i < ARRAY_LEN(bad_ids); i++) {
        char path[64];
        snprintf(path, sizeof path, "/posts/%s", bad_ids[i]);
        fx_get(path, &r);
        EXPECT(r, 400, "{\"error\":\"invalid post id\"}");
    }
    static const char *const missing_ids[] = {"999999999", "9223372036854775807", "9223372036854775808",
                                              "99999999999999999999"};
    for (unsigned i = 0; i < ARRAY_LEN(missing_ids); i++) {
        char path[64];
        snprintf(path, sizeof path, "/posts/%s", missing_ids[i]);
        fx_get(path, &r);
        EXPECT(r, 404, "{\"error\":\"post not found\"}");
    }
    fx_get("/posts/0000001", &r);
    CHECK(r.status == 200 && !strncmp(fx_body(&r), "{\"post\":{\"id\":1,", 16));
}

// Authentication rows: every failure string, and the fact that auth runs before the id.
static void test_auth(void) {
    struct fx_resp r;
    char bad[1100];
    char payload[256];
    fx_token(token, sizeof token, "1", "golden_ember_1", 3600);
    snprintf(bearer, sizeof bearer, "Bearer %s", token);
    fx_post_json("/posts", NULL, "{\"body\":\"x\"}", &r);
    EXPECT(r, 401, "{\"error\":\"missing bearer token\"}");
    fx_post_json("/posts", "Basic abc", "{\"body\":\"x\"}", &r);
    EXPECT(r, 401, "{\"error\":\"missing bearer token\"}");
    fx_post_json("/posts", "Bearer abc", "{\"body\":\"x\"}", &r);
    EXPECT(r, 401, "{\"error\":\"invalid or expired token\"}");
    snprintf(bad, sizeof bad, "Bearer %.*sA", (int)strlen(token) - 1, token);
    fx_post_json("/posts", bad, "{\"body\":\"x\"}", &r);
    EXPECT(r, 401, "{\"error\":\"invalid or expired token\"}");
    fx_token(token, sizeof token, "1", "golden_ember_1", -3600);
    snprintf(bad, sizeof bad, "Bearer %s", token);
    fx_post_json("/posts", bad, "{\"body\":\"x\"}", &r);
    EXPECT(r, 401, "{\"error\":\"invalid or expired token\"}");
    fx_token(token, sizeof token, "abc", "golden_ember_1", 3600);
    snprintf(bad, sizeof bad, "Bearer %s", token);
    fx_post_json("/posts", bad, "{\"body\":\"x\"}", &r);
    EXPECT(r, 401, "{\"error\":\"invalid token payload\"}");
    snprintf(payload, sizeof payload, "{\"sub\":\"1\",\"exp\":%lld}", (long long)clk.real_s + 3600);
    fx_sign(token, sizeof token, payload);
    snprintf(bad, sizeof bad, "Bearer %s", token);
    fx_post_json("/posts", bad, "{\"body\":\"x\"}", &r);
    EXPECT(r, 401, "{\"error\":\"invalid token payload\"}");
    fx_post_json("/posts/abc/like", NULL, NULL, &r);
    EXPECT(r, 401, "{\"error\":\"missing bearer token\"}");
    fx_post_json("/posts/abc/like", bearer, NULL, &r);
    EXPECT(r, 400, "{\"error\":\"invalid post id\"}");
    fx_post_json("/posts/0/like", bearer, NULL, &r);
    EXPECT(r, 400, "{\"error\":\"invalid post id\"}");
    fx_post_json("/posts/999999999/like", bearer, NULL, &r);
    EXPECT(r, 404, "{\"error\":\"post not found\"}");
    fx_post_json("/posts/99999999999999999999/like", bearer, NULL, &r);
    EXPECT(r, 404, "{\"error\":\"post not found\"}");
}

// Create validation rows, then create, like, repeat like and read back on the seed copy.
static void test_create_and_like(void) {
    struct fx_resp r;
    char body[1200];
    char want[1400];
    char id[32];
    char path[64];
    fx_post_json("/posts", bearer, "{\"body\":\"\"}", &r);
    EXPECT(r, 400, "{\"error\":\"body is required\"}");
    fx_post_json("/posts", bearer, "{\"body\":\"   \"}", &r);
    EXPECT(r, 400, "{\"error\":\"body is required\"}");
    fx_post_json("/posts", bearer, "{\"body\":123}", &r);
    EXPECT(r, 400, "{\"error\":\"body is required\"}");
    fx_post_json("/posts", bearer, "{}", &r);
    EXPECT(r, 400, "{\"error\":\"body is required\"}");
    fx_post_json("/posts", bearer, "{bad json", &r);
    EXPECT(r, 400, "{\"error\":\"malformed JSON body\"}");
    fx_post_json("/posts", bearer, "", &r);
    EXPECT(r, 400, "{\"error\":\"malformed JSON body\"}");
    snprintf(body, sizeof body, "{\"body\":\"%0501d\"}", 0);
    memset(body + 9, 'a', 501);
    fx_post_json("/posts", bearer, body, &r);
    EXPECT(r, 400, "{\"error\":\"body must be at most 500 characters\"}");
    fx_post_json("/posts", bearer, "{\"body\":\"  test: <b>&amp;</b> \\\"quoted\\\" / caf\xc3\xa9 \xe2\x9c\x93  \"}", &r);
    CHECK(r.status == 201);
    CHECK(strstr(fx_body(&r), "\"body\":\"test: <b>&amp;</b> \\\"quoted\\\" / caf\xc3\xa9 \xe2\x9c\x93\"") != NULL);
    CHECK(strstr(fx_body(&r), "\"author\":\"golden_ember_1\",\"like_count\":0}}") != NULL);
    snprintf(body, sizeof body, "{\"body\":\"  %0500d \"}", 0);
    memset(body + 11, 'b', 500);
    fx_post_json("/posts", bearer, body, &r);
    CHECK(r.status == 201);
    const char *p = strstr(fx_body(&r), "\"id\":");
    CHECK(p != NULL);
    snprintf(id, sizeof id, "%lld", p ? atoll(p + 5) : 0);
    char created[32] = {0};
    p = strstr(fx_body(&r), "\"created_at\":\"");
    CHECK(p != NULL);
    if (p) {
        memcpy(created, p + 14, 24);
    }
    snprintf(want, sizeof want, "{\"post\":{\"id\":%s,\"body\":\"%.500s\",\"created_at\":\"%s\",\"author\":\"golden_ember_1\","
                                "\"like_count\":0}}",
             id, body + 11, created);
    EXPECT(r, 201, want);
    CHECK(strlen(created) == 24 && created[23] == 'Z');
    snprintf(path, sizeof path, "/posts/%s/like", id);
    fx_post_json(path, bearer, NULL, &r);
    snprintf(want, sizeof want, "{\"liked\":true,\"already_liked\":false,\"post_id\":%s}", id);
    EXPECT(r, 201, want);
    fx_post_json(path, bearer, NULL, &r);
    snprintf(want, sizeof want, "{\"liked\":true,\"already_liked\":true,\"post_id\":%s}", id);
    EXPECT(r, 200, want);
    snprintf(path, sizeof path, "/posts/%s", id);
    fx_get(path, &r);
    CHECK(r.status == 200 && strstr(fx_body(&r), "\"like_count\":1}}") != NULL);
    fx_get("/feed", &r);
    CHECK(r.status == 200);
    snprintf(want, sizeof want, "{\"posts\":[{\"id\":%s,", id);
    CHECK(!strncmp(fx_body(&r), want, strlen(want)));
    fx_post_json("/posts/1/like", bearer, NULL, &r);
    CHECK(r.status == 201);
    fx_get("/posts/1", &r);
    CHECK(strstr(fx_body(&r), "\"like_count\":12}}") != NULL);
}

// Runs the post-seed checks that need no token, then the ones that do.
int main(int argc, char **argv) {
    db_only = argc > 1 && !strcmp(argv[1], "db");
    fx_tmpdir(tmp_dir, sizeof tmp_dir);
    snprintf(db_file, sizeof db_file, "%s/feed.db", tmp_dir);
    if (!copy_seed()) {
        fx_rmdir(tmp_dir);
        puts("unit_handlers skipped");
        return 0;
    }
    fx_init();
    util_clock_update();
    auth_init("twelve-dollar-challenge", strlen("twelve-dollar-challenge"));
    fx_server_open(db_file);
    test_golden();
    test_reads();
    if (!db_only) {
        test_auth();
        test_create_and_like();
    }
    fx_server_close();
    fx_rmdir(tmp_dir);
    if (fx_failures) {
        fprintf(stderr, "%d failures\n", fx_failures);
        return 1;
    }
    puts("unit_handlers ok");
    return 0;
}
