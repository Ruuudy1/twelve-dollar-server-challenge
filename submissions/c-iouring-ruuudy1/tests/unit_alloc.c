// Zero heap allocations on the request path: libc malloc (counted when no sanitizer is active) and the region that
// backs SQLite's allocator must both stay flat over 10,000 warm requests of every endpoint, checkpoints included.
#define FM_TEST 1
#include "../src/main.c"
#include "db_fixture.h"

static bool alloc_counting;
static uint64_t alloc_count;

#ifndef __SANITIZE_ADDRESS__
extern void *__libc_malloc(size_t n);
extern void *__libc_calloc(size_t n, size_t m);
extern void *__libc_realloc(void *p, size_t n);

void *malloc(size_t n) {
    alloc_count += alloc_counting;
    return __libc_malloc(n);
}

void *calloc(size_t n, size_t m) {
    alloc_count += alloc_counting;
    return __libc_calloc(n, m);
}

void *realloc(void *p, size_t n) {
    alloc_count += alloc_counting;
    return __libc_realloc(p, n);
}
#endif

static char bearer[1100];

// Runs count requests built by make, each as its own pass, and returns the libc allocations they caused; the region
// SQLite draws from must stay flat apart from a few blocks and must never fall back to libc.
static uint64_t measure(const char *label, unsigned count, bool (*make)(unsigned i, struct fx_req *rq, char *scratch)) {
    char scratch[128];
    struct fx_req rq;
    struct fx_resp *out = malloc(sizeof *out);
    uint64_t base_all = alloc_count;
    uint64_t base_calls = db_mem.calls;
    uint64_t base_libc = db_mem.libc_calls;
    uint8_t *base_next = db_mem.next;
    for (unsigned i = 0; i < count; i++) {
        CHECK(make(i, &rq, scratch));
        alloc_counting = true;
        fx_pass(&rq, 1, out);
        db_checkpoint();
        alloc_counting = false;
        if (out->status >= 500) {
            fprintf(stderr, "%s: request %u answered %u\n", label, i, out->status);
            fx_failures++;
            break;
        }
    }
    uint64_t total = alloc_count - base_all;
    printf("%-10s %u requests: %llu libc allocations, %llu SQLite allocations from the region (%llu to libc, region grew %lld bytes)\n",
           label, count, (unsigned long long)total, (unsigned long long)(db_mem.calls - base_calls),
           (unsigned long long)(db_mem.libc_calls - base_libc), (long long)(db_mem.next - base_next));
    CHECK(db_mem.libc_calls == base_libc);
    if (count >= 10000) {
        // A recycled block can still need one more of a size class the first time two are live at once; a leak would grow
        // by the request count.
        CHECK(db_mem.next - base_next <= 16384);
    }
    free(out);
    return total;
}

static bool make_feed(unsigned i, struct fx_req *rq, char *scratch) {
    (void)i;
    (void)scratch;
    *rq = (struct fx_req){"GET", "/feed", NULL, NULL, 0, false};
    return true;
}

static bool make_post(unsigned i, struct fx_req *rq, char *scratch) {
    snprintf(scratch, 128, "/posts/%u", 1 + (unsigned)(fx_below(300) + i) % 300);
    *rq = (struct fx_req){"GET", scratch, NULL, NULL, 0, false};
    return true;
}

static bool make_health(unsigned i, struct fx_req *rq, char *scratch) {
    (void)i;
    (void)scratch;
    *rq = (struct fx_req){"GET", "/health", NULL, NULL, 0, false};
    return true;
}

static bool make_missing(unsigned i, struct fx_req *rq, char *scratch) {
    (void)i;
    (void)scratch;
    *rq = (struct fx_req){"GET", "/nothing/here", NULL, NULL, 0, false};
    return true;
}

static bool make_create(unsigned i, struct fx_req *rq, char *scratch) {
    (void)i;
    (void)scratch;
    *rq = (struct fx_req){"POST", "/posts", bearer, "{\"body\":\"allocation test post\"}", 31, true};
    return true;
}

static bool make_like(unsigned i, struct fx_req *rq, char *scratch) {
    snprintf(scratch, 128, "/posts/%u/like", 1 + (unsigned)(fx_below(300) + i) % 300);
    *rq = (struct fx_req){"POST", scratch, bearer, NULL, 0, false};
    return true;
}

static bool make_unauthorized(unsigned i, struct fx_req *rq, char *scratch) {
    (void)i;
    (void)scratch;
    *rq = (struct fx_req){"POST", "/posts", "Bearer abc.def.ghi", "{\"body\":\"x\"}", 12, true};
    return true;
}

int main(void) {
    char dir[64];
    char path[128];
    char token[1024];
    fx_tmpdir(dir, sizeof dir);
    snprintf(path, sizeof path, "%s/a.db", dir);
    fx_seed(5);
    sqlite3 *db = fx_create(path);
    fx_user(db, 1, "alloc_user");
    fx_exec(db, "BEGIN;");
    for (int i = 1; i <= 300; i++) {
        char stamp[32];
        fx_stamp(stamp, (int64_t)i * 1000);
        fx_post(db, i, 1, stamp, "seed post");
        fx_like(db, 1, i);
    }
    fx_exec(db, "COMMIT;");
    sqlite3_close(db);
    util_clock_update();
    auth_init("twelve-dollar-challenge", strlen("twelve-dollar-challenge"));
    fx_server_open(path);
    fx_token(token, sizeof token, "1", "alloc_user", 36000);
    snprintf(bearer, sizeof bearer, "Bearer %s", token);
    static const struct {
        const char *label;
        bool (*make)(unsigned, struct fx_req *, char *);
    } kinds[] = {{"feed", make_feed}, {"post", make_post}, {"health", make_health}, {"404", make_missing},
                 {"401", make_unauthorized}, {"create", make_create}, {"like", make_like}};
    for (unsigned k = 0; k < ARRAY_LEN(kinds); k++) {
        measure(kinds[k].label, 6000, kinds[k].make);
        CHECK(measure(kinds[k].label, 10000, kinds[k].make) == 0);
    }
    sqlite3_int64 overflow = 0;
    sqlite3_int64 high = 0;
    CHECK(sqlite3_status64(SQLITE_STATUS_PAGECACHE_OVERFLOW, &overflow, &high, 0) == SQLITE_OK);
    printf("page cache overflow bytes %lld\n", (long long)overflow);
    CHECK(overflow == 0);
    fx_server_close();
    fx_rmdir(dir);
    if (fx_failures) {
        fprintf(stderr, "%d failures\n", fx_failures);
        return 1;
    }
    puts("unit_alloc ok");
    return 0;
}
