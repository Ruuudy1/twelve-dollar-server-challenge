// One pass that creates, likes, re-likes and reads, then the failure semantics: a failing xWrite (through a VFS shim)
// or a fatal statement result turns every response of the pass into a 500 and nothing is persisted.
#define FM_TEST 1
#include "../src/main.c"
#include "db_fixture.h"

// A VFS that wraps the default one and fails every xWrite while shim_fail_writes is set.
struct shim_file {
    sqlite3_file base;
    sqlite3_file *real;
};

static bool shim_fail_writes;
static sqlite3_vfs shim_vfs;
static sqlite3_vfs *shim_real;
static sqlite3_io_methods shim_methods;

static int shim_close(sqlite3_file *f) {
    struct shim_file *s = (struct shim_file *)f;
    int rc = s->real->pMethods ? s->real->pMethods->xClose(s->real) : SQLITE_OK;
    sqlite3_free(s->real);
    return rc;
}

static int shim_read(sqlite3_file *f, void *buf, int n, sqlite3_int64 off) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xRead(s->real, buf, n, off);
}

static int shim_write(sqlite3_file *f, const void *buf, int n, sqlite3_int64 off) {
    struct shim_file *s = (struct shim_file *)f;
    if (shim_fail_writes) {
        return SQLITE_IOERR_WRITE;
    }
    return s->real->pMethods->xWrite(s->real, buf, n, off);
}

static int shim_truncate(sqlite3_file *f, sqlite3_int64 size) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xTruncate(s->real, size);
}

static int shim_sync(sqlite3_file *f, int flags) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xSync(s->real, flags);
}

static int shim_size(sqlite3_file *f, sqlite3_int64 *size) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xFileSize(s->real, size);
}

static int shim_lock(sqlite3_file *f, int level) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xLock(s->real, level);
}

static int shim_unlock(sqlite3_file *f, int level) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xUnlock(s->real, level);
}

static int shim_reserved(sqlite3_file *f, int *out) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xCheckReservedLock(s->real, out);
}

static int shim_control(sqlite3_file *f, int op, void *arg) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xFileControl(s->real, op, arg);
}

static int shim_sector(sqlite3_file *f) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xSectorSize(s->real);
}

static int shim_device(sqlite3_file *f) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xDeviceCharacteristics(s->real);
}

static int shim_shm_map(sqlite3_file *f, int page, int size, int extend, void volatile **out) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xShmMap(s->real, page, size, extend, out);
}

static int shim_shm_lock(sqlite3_file *f, int off, int n, int flags) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xShmLock(s->real, off, n, flags);
}

static void shim_shm_barrier(sqlite3_file *f) {
    struct shim_file *s = (struct shim_file *)f;
    s->real->pMethods->xShmBarrier(s->real);
}

static int shim_shm_unmap(sqlite3_file *f, int del) {
    struct shim_file *s = (struct shim_file *)f;
    return s->real->pMethods->xShmUnmap(s->real, del);
}

static int shim_open(sqlite3_vfs *vfs, const char *name, sqlite3_file *f, int flags, int *out_flags) {
    struct shim_file *s = (struct shim_file *)f;
    (void)vfs;
    s->real = sqlite3_malloc(shim_real->szOsFile);
    memset(s->real, 0, (size_t)shim_real->szOsFile);
    int rc = shim_real->xOpen(shim_real, name, s->real, flags, out_flags);
    s->base.pMethods = rc == SQLITE_OK ? &shim_methods : NULL;
    return rc;
}

// Registers the shim as the default VFS; every file opened after this goes through it.
static void shim_install(void) {
    shim_real = sqlite3_vfs_find(NULL);
    shim_vfs = *shim_real;
    shim_vfs.zName = "failwrite";
    shim_vfs.szOsFile = (int)sizeof(struct shim_file);
    shim_vfs.xOpen = shim_open;
    shim_vfs.pNext = NULL;
    shim_methods = (sqlite3_io_methods){.iVersion = 2, .xClose = shim_close, .xRead = shim_read, .xWrite = shim_write,
                                        .xTruncate = shim_truncate, .xSync = shim_sync, .xFileSize = shim_size,
                                        .xLock = shim_lock, .xUnlock = shim_unlock, .xCheckReservedLock = shim_reserved,
                                        .xFileControl = shim_control, .xSectorSize = shim_sector,
                                        .xDeviceCharacteristics = shim_device, .xShmMap = shim_shm_map,
                                        .xShmLock = shim_shm_lock, .xShmBarrier = shim_shm_barrier,
                                        .xShmUnmap = shim_shm_unmap};
    CHECK(sqlite3_vfs_register(&shim_vfs, 1) == SQLITE_OK);
}

static char bearer[1100];

// Counts rows with a query on the server's own connection.
static int64_t count_rows(const char *sql) {
    return fx_scalar(db_handle, sql);
}

// The sequence the tests replay: create, like, repeat like, read back, feed, a 404 and a health check.
static void make_sequence(struct fx_req *reqs, int64_t next_id, char paths[3][64]) {
    snprintf(paths[0], 64, "/posts/%lld/like", (long long)next_id);
    snprintf(paths[1], 64, "/posts/%lld", (long long)next_id);
    snprintf(paths[2], 64, "/posts/999999999/like");
    reqs[0] = (struct fx_req){"POST", "/posts", bearer, "{\"body\":\"batch test\"}", 21, true};
    reqs[1] = (struct fx_req){"POST", paths[0], bearer, NULL, 0, false};
    reqs[2] = (struct fx_req){"POST", paths[0], bearer, NULL, 0, false};
    reqs[3] = (struct fx_req){"GET", paths[1], NULL, NULL, 0, false};
    reqs[4] = (struct fx_req){"GET", "/feed", NULL, NULL, 0, false};
    reqs[5] = (struct fx_req){"POST", paths[2], bearer, NULL, 0, false};
    reqs[6] = (struct fx_req){"GET", "/health", NULL, NULL, 0, false};
}

// A successful pass answers like a serial server would and persists everything.
static void test_pass_commits(void) {
    struct fx_req reqs[7];
    struct fx_resp out[7];
    char paths[3][64];
    int64_t next_id = count_rows("SELECT max(id) FROM posts") + 1;
    int64_t likes = count_rows("SELECT count(*) FROM likes");
    make_sequence(reqs, next_id, paths);
    CHECK(fx_pass(reqs, 7, out));
    CHECK(out[0].status == 201 && strstr(fx_body(&out[0]), "\"like_count\":0}}"));
    CHECK(out[1].status == 201 && strstr(fx_body(&out[1]), "\"already_liked\":false"));
    CHECK(out[2].status == 200 && strstr(fx_body(&out[2]), "\"already_liked\":true"));
    CHECK(out[3].status == 200 && strstr(fx_body(&out[3]), "\"like_count\":1}}"));
    CHECK(out[4].status == 200 && strstr(fx_body(&out[4]), "\"body\":\"batch test\"") &&
          strstr(fx_body(&out[4]), "\"like_count\":1}"));
    CHECK(out[5].status == 404);
    CHECK(out[6].status == 200);
    CHECK(count_rows("SELECT max(id) FROM posts") == next_id);
    CHECK(count_rows("SELECT count(*) FROM likes") == likes + 1);
}

// A failing xWrite makes the commit fail: every response is a 500 and no row is persisted.
static void test_failed_write(void) {
    struct fx_req reqs[7];
    struct fx_resp out[7];
    char paths[3][64];
    int64_t posts = count_rows("SELECT count(*) FROM posts");
    int64_t likes = count_rows("SELECT count(*) FROM likes");
    make_sequence(reqs, count_rows("SELECT max(id) FROM posts") + 1, paths);
    shim_fail_writes = true;
    bool ok = fx_pass(reqs, 7, out);
    shim_fail_writes = false;
    CHECK(!ok);
    for (int i = 0; i < 7; i++) {
        CHECK(out[i].status == 500);
        CHECK(fx_body_is(&out[i], "{\"error\":\"internal server error\"}"));
    }
    CHECK(count_rows("SELECT count(*) FROM posts") == posts);
    CHECK(count_rows("SELECT count(*) FROM likes") == likes);
    CHECK(sqlite3_get_autocommit(db_handle));
    test_pass_commits();
}

// A fatal statement result marks the pass failed: later requests get 500 at once and COMMIT is skipped.
static void test_noted_failure(void) {
    struct fx_resp r;
    struct work w;
    static char buf[512];
    struct fx_req create = {"POST", "/posts", bearer, "{\"body\":\"doomed\"}", 17, true};
    struct fx_req get = {"GET", "/posts/1", NULL, NULL, 0, false};
    int64_t posts = count_rows("SELECT count(*) FROM posts");
    CHECK(fx_make_work(&create, buf, sizeof buf, &w));
    handler_run(&w);
    CHECK(w.status == 201);
    block_put(w.blk);
    db_note_result(SQLITE_FULL);
    CHECK(!db_touch());
    CHECK(fx_make_work(&get, buf, sizeof buf, &w));
    handler_run(&w);
    CHECK(w.status == 500);
    block_put(w.blk);
    CHECK(!db_commit());
    CHECK(count_rows("SELECT count(*) FROM posts") == posts);
    fx_get("/posts/1", &r);
    CHECK(r.status == 200);
    struct fx_resp ok;
    fx_post_json("/posts", bearer, "{\"body\":\"after failure\"}", &ok);
    CHECK(ok.status == 201);
    CHECK(count_rows("SELECT count(*) FROM posts") == posts + 1);
}

// A constraint failure fails only its own request and the pass still commits the rest.
static void test_constraint_failure(void) {
    struct fx_resp out[2];
    struct fx_req reqs[2];
    int64_t posts = count_rows("SELECT count(*) FROM posts");
    CHECK(db_touch());
    CHECK(sqlite3_bind_int64(db_stmts[DB_CREATE], 1, 1) == SQLITE_OK);
    CHECK(sqlite3_bind_text(db_stmts[DB_CREATE], 2, "", 0, SQLITE_STATIC) == SQLITE_OK);
    int rc = db_step(DB_CREATE);
    db_reset(DB_CREATE);
    CHECK((rc & 0xff) == SQLITE_CONSTRAINT);
    CHECK(db_commit());
    reqs[0] = (struct fx_req){"POST", "/posts", bearer, "{\"body\":\"survivor\"}", 19, true};
    reqs[1] = (struct fx_req){"GET", "/health", NULL, NULL, 0, false};
    CHECK(fx_pass(reqs, 2, out));
    CHECK(out[0].status == 201 && out[1].status == 200);
    CHECK(count_rows("SELECT count(*) FROM posts") == posts + 1);
}

// The WAL frame arithmetic matches the file: header plus (page + 24) bytes per frame.
static void test_wal_layout(char *dir) {
    char wal[160];
    struct stat st;
    uint64_t off = 0;
    uint32_t len = 0;
    snprintf(wal, sizeof wal, "%s/b.db-wal", dir);
    CHECK(!stat(wal, &st));
    CHECK(db_wal_frames > 0);
    CHECK(db_wal_range(0, db_wal_frames, &off, &len));
    CHECK(off == 32 && (uint64_t)st.st_size >= off + len);
    CHECK(db_wal_range(3, 5, &off, &len) && off == 32 + 3 * (db_page_size + 24) && len == 2 * (db_page_size + 24));
}

int main(void) {
    char dir[64];
    char path[128];
    char token[1024];
    fx_tmpdir(dir, sizeof dir);
    snprintf(path, sizeof path, "%s/b.db", dir);
    fx_seed(99);
    sqlite3 *db = fx_create(path);
    fx_user(db, 1, "batch_user");
    fx_post(db, 1, 1, "2025-01-01T00:00:00.000Z", "first");
    fx_exec(db, "PRAGMA wal_checkpoint(TRUNCATE);");
    sqlite3_close(db);
    shim_install();
    util_clock_update();
    auth_init("twelve-dollar-challenge", strlen("twelve-dollar-challenge"));
    fx_server_open(path);
    fx_token(token, sizeof token, "1", "batch_user", 3600);
    snprintf(bearer, sizeof bearer, "Bearer %s", token);
    test_pass_commits();
    test_failed_write();
    test_noted_failure();
    test_constraint_failure();
    test_wal_layout(dir);
    fx_server_close();
    fx_rmdir(dir);
    if (fx_failures) {
        fprintf(stderr, "%d failures\n", fx_failures);
        return 1;
    }
    puts("unit_batch ok");
    return 0;
}
