// Feed differential: the fast, dense and reference paths must emit identical bytes on random databases,
// and every statement's query plan must use only the indexes the schema already has.
#define FM_TEST 1
#include "../src/main.c"
#include "db_fixture.h"

enum { SHAPE_CONSECUTIVE, SHAPE_GAPS, SHAPE_TIES, SHAPE_BACKWARDS, SHAPE_MISSING_USER, SHAPE_FEW, SHAPE_EMPTY,
       SHAPE_WIDE, SHAPE_SHUFFLED, SHAPE_ESCAPES, SHAPE_COUNT };

static const char *const shape_names[SHAPE_COUNT] = {"consecutive", "gaps", "ties", "backwards", "missing-user", "few",
                                                     "empty", "wide", "shuffled", "escapes"};
static unsigned path_runs[3];
static unsigned path_fallbacks[3];

// Picks a body from a list that covers plain text, escapes, control bytes, multibyte text and the 500-char limit.
static void pick_body(char *out, size_t cap, bool nasty) {
    static const char *const nasty_bodies[] = {"quote \" and \\ backslash", "line\nbreak\ttab\rreturn", "ctl \x01\x1f del \x7f",
                                               "caf\xc3\xa9 \xe2\x9c\x93 \xf0\x9f\x98\x80", "</script> & <b>/</b>", "\b\f"};
    if (nasty && fx_below(4)) {
        snprintf(out, cap, "%s", nasty_bodies[fx_below(ARRAY_LEN(nasty_bodies))]);
    } else if (fx_below(20) == 0) {
        memset(out, 'x', 500);
        out[500] = 0;
    } else {
        snprintf(out, cap, "post number %llu about nothing", (unsigned long long)fx_below(1000000));
    }
}

// Fills a database for one shape with users, posts and likes; the newest posts are the interesting ones.
static void build_db(const char *path, int shape, unsigned count) {
    sqlite3 *db = fx_create(path);
    char stamp[32];
    char body[512];
    char name[64];
    int64_t id = 0;
    unsigned users = 30;
    fx_exec(db, "BEGIN;");
    for (unsigned u = 1; u <= users; u++) {
        snprintf(name, sizeof name, shape == SHAPE_ESCAPES && u % 3 == 0 ? "we\"ird\\user_%u" : "user_%u", u);
        fx_user(db, u, name);
    }
    for (unsigned i = 0; i < count; i++) {
        int64_t ms = (int64_t)i * 1500;
        id += shape == SHAPE_GAPS ? 1 + (int64_t)fx_below(3) : shape == SHAPE_WIDE ? 50 : 1;
        ms = shape == SHAPE_TIES ? (int64_t)(i / 5) * 1000 : shape == SHAPE_BACKWARDS ? (int64_t)(count - i) * 1500 : ms;
        ms = shape == SHAPE_SHUFFLED ? (int64_t)fx_below(count) * 1000 : ms;
        fx_stamp(stamp, ms);
        pick_body(body, sizeof body, shape == SHAPE_ESCAPES);
        fx_post(db, id, 1 + (int64_t)fx_below(users), stamp, body);
    }
    for (unsigned i = 0; i < count * 3; i++) {
        fx_like(db, 1 + (int64_t)fx_below(users), 1 + (int64_t)fx_below((uint64_t)id));
    }
    if (shape == SHAPE_MISSING_USER) {
        fx_exec(db, "DELETE FROM users WHERE id IN (3, 11, 25);");
    }
    fx_exec(db, "COMMIT;");
    sqlite3_close(db);
}

// Runs one path on the id list (which: 0 fast, 1 dense, 2 reference); returns its outcome and the body text.
static int run_path(int which, char *out, size_t *n) {
    int64_t ids[FEED_LIMIT];
    unsigned count = 0;
    struct resp r;
    CHECK(resp_begin(&r));
    CHECK(db_touch());
    CHECK(handler_feed_ids(ids, &count));
    int64_t lo = ids[count - 1];
    int64_t hi = ids[0];
    for (unsigned i = 0; i < count; i++) {
        lo = ids[i] < lo ? ids[i] : lo;
        hi = ids[i] > hi ? ids[i] : hi;
    }
    CHECK(resp_put(&r, "{\"posts\":[", 10));
    int rc = which == 0 ? handler_feed_fast(&r, ids, count)
             : which == 1 ? handler_feed_dense(&r, ids, count, lo, hi)
                          : handler_feed_ref(&r);
    CHECK(resp_put(&r, "]}", 2));
    char *start = (char *)r.blk->data + RESP_HDR_ROOM;
    *n = (size_t)(r.w - start);
    memcpy(out, start, *n);
    out[*n] = 0;
    block_put(r.blk);
    CHECK(db_commit());
    return rc;
}

// True when the newest ids are exactly hi, hi - 1, ...; the fast path applies then.
static bool ids_consecutive(const int64_t *ids, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
        if (ids[i] != ids[0] - (int64_t)i) {
            return false;
        }
    }
    return n > 0;
}

// Checks every applicable path and the automatic choice against the oracle for one database.
static void check_db(const char *path, int shape, unsigned round) {
    static char want[1 << 17];
    static char got[1 << 17];
    size_t want_n = fx_oracle_feed(path, want);
    size_t got_n = 0;
    fx_server_open(path);
    struct fx_resp resp;
    fx_get("/feed", &resp);
    if (resp.status != 200 || !fx_body_is(&resp, want)) {
        fprintf(stderr, "shape %s round %u: auto path differs\n want %s\n got  %s\n", shape_names[shape], round, want,
                fx_body(&resp));
    }
    CHECK(resp.status == 200 && fx_body_is(&resp, want));
    int64_t ids[FEED_LIMIT];
    unsigned n = 0;
    CHECK(db_touch());
    CHECK(handler_feed_ids(ids, &n));
    CHECK(db_commit());
    if (n) {
        int64_t lo = ids[0];
        int64_t hi = ids[0];
        for (unsigned i = 0; i < n; i++) {
            lo = ids[i] < lo ? ids[i] : lo;
            hi = ids[i] > hi ? ids[i] : hi;
        }
        for (int which = 0; which < 3; which++) {
            bool applies = which == 0 ? ids_consecutive(ids, n) : which == 1 ? hi - lo < FEED_SPAN_MAX : true;
            if (!applies) {
                continue;
            }
            int rc = run_path(which, got, &got_n);
            path_runs[which]++;
            if (rc == HANDLER_FALLBACK) {
                path_fallbacks[which]++;
                continue;
            }
            CHECK(rc == HANDLER_OK);
            if (got_n != want_n || memcmp(got, want, want_n)) {
                fprintf(stderr, "shape %s round %u: path %d differs\n want %s\n got  %s\n", shape_names[shape], round, which,
                        want, got);
            }
            CHECK(got_n == want_n && !memcmp(got, want, want_n));
        }
    }
    fx_server_close();
}

// Runs every shape several times with fresh random contents.
static void test_differential(void) {
    char dir[64];
    char path[128];
    fx_tmpdir(dir, sizeof dir);
    snprintf(path, sizeof path, "%s/feed.db", dir);
    static const unsigned counts[SHAPE_COUNT] = {100, 60, 80, 50, 100, 7, 0, 40, 80, 60};
    for (int shape = 0; shape < SHAPE_COUNT; shape++) {
        for (unsigned round = 0; round < 6; round++) {
            fx_seed(1000 + (uint64_t)shape * 31 + round);
            unlink(path);
            build_db(path, shape, counts[shape]);
            check_db(path, shape, round);
        }
    }
    CHECK(path_runs[0] > 10 && path_runs[1] > 10 && path_runs[2] > 10);
    CHECK(path_fallbacks[0] > 0);
    fx_rmdir(dir);
}

// Returns the detail column of every EXPLAIN QUERY PLAN row of a statement, joined with newlines.
static void plan_of(const char *sql, char *out, size_t cap) {
    char text[1024];
    sqlite3_stmt *st = NULL;
    snprintf(text, sizeof text, "EXPLAIN QUERY PLAN %s", sql);
    CHECK(sqlite3_prepare_v2(db_handle, text, -1, &st, NULL) == SQLITE_OK);
    out[0] = 0;
    while (st && sqlite3_step(st) == SQLITE_ROW) {
        snprintf(out + strlen(out), cap - strlen(out), "%s\n", (const char *)sqlite3_column_text(st, 3));
    }
    sqlite3_finalize(st);
}

// True when the plan text contains the fragment.
static bool plan_has(const char *plan, const char *fragment) {
    return strstr(plan, fragment) != NULL;
}

// Asserts that no plan names an index outside the schema's own and none sorts or builds a temporary index.
static void check_plan_rules(const char *plan, const char *sql) {
    const char *at = plan;
    while ((at = strstr(at, "INDEX ")) != NULL) {
        at += 6;
        bool known = !strncmp(at, "posts_created_at_id_idx", 23) || !strncmp(at, "posts_user_id_idx", 17) ||
                     !strncmp(at, "likes_post_id_idx", 17) || !strncmp(at, "sqlite_autoindex_", 17);
        if (!known) {
            fprintf(stderr, "unknown index in plan of %s\n%s\n", sql, plan);
        }
        CHECK(known);
    }
    CHECK(!plan_has(plan, "TEMP B-TREE"));
    CHECK(!plan_has(plan, "AUTOMATIC"));
}

// Checks the plan of every statement on the pinned SQLite version.
static void test_plans(void) {
    char dir[64];
    char path[128];
    char plan[2048];
    fx_tmpdir(dir, sizeof dir);
    snprintf(path, sizeof path, "%s/plan.db", dir);
    fx_seed(7);
    build_db(path, SHAPE_CONSECUTIVE, 100);
    fx_server_open(path);
    if (sqlite3_libversion_number() != 3053004) {
        fprintf(stderr, "note: SQLite %s, plans were pinned on 3.53.4\n", sqlite3_libversion());
    }
    for (int i = DB_FEED_IDS; i < DB_STMT_COUNT; i++) {
        plan_of(DB_SQL[i], plan, sizeof plan);
        if (getenv("FX_SHOW_PLANS")) {
            printf("--- %d %s\n%s", i, DB_SQL[i], plan);
        }
        check_plan_rules(plan, DB_SQL[i]);
    }
    plan_of(DB_SQL[DB_FEED_IDS], plan, sizeof plan);
    CHECK(plan_has(plan, "SCAN posts USING COVERING INDEX posts_created_at_id_idx"));
    plan_of(DB_SQL[DB_FEED_LIKES], plan, sizeof plan);
    CHECK(plan_has(plan, "SEARCH likes USING COVERING INDEX likes_post_id_idx (post_id>? AND post_id<?)"));
    plan_of(DB_SQL[DB_FEED_ROWS_DESC], plan, sizeof plan);
    CHECK(plan_has(plan, "SEARCH p USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)"));
    CHECK(plan_has(plan, "SEARCH u USING INTEGER PRIMARY KEY (rowid=?)"));
    plan_of(DB_SQL[DB_FEED_ROWS], plan, sizeof plan);
    CHECK(plan_has(plan, "SEARCH p USING INTEGER PRIMARY KEY (rowid>? AND rowid<?)"));
    plan_of(DB_SQL[DB_FEED_REF], plan, sizeof plan);
    CHECK(plan_has(plan, "SCAN p USING INDEX posts_created_at_id_idx"));
    CHECK(plan_has(plan, "SEARCH l USING COVERING INDEX likes_post_id_idx (post_id=?)"));
    plan_of(DB_SQL[DB_POST], plan, sizeof plan);
    CHECK(plan_has(plan, "SEARCH p USING INTEGER PRIMARY KEY (rowid=?)"));
    plan_of(DB_SQL[DB_CREATE_TS], plan, sizeof plan);
    CHECK(plan_has(plan, "SEARCH posts USING INTEGER PRIMARY KEY (rowid=?)"));
    plan_of(DB_SQL[DB_EXISTS], plan, sizeof plan);
    CHECK(plan_has(plan, "SEARCH posts USING INTEGER PRIMARY KEY (rowid=?)"));
    fx_server_close();
    fx_rmdir(dir);
}

int main(void) {
    test_differential();
    test_plans();
    if (fx_failures) {
        fprintf(stderr, "%d failures\n", fx_failures);
        return 1;
    }
    puts("unit_feed ok");
    return 0;
}
