// Owner: db module. SQLite open, pragmas, prepared statements, the per-pass transaction and checkpoints.

// Defined in ring.c.
static void ring_queue_wal_sync(int fd, uint64_t off, uint32_t len);

// Prepared statements; every one is prepared once at startup with SQLITE_PREPARE_PERSISTENT.
enum db_stmt {
    DB_PING,
    DB_BEGIN,
    DB_COMMIT,
    DB_ROLLBACK,
    // Ids of the 20 newest posts, newest first, from the created_at index alone.
    DB_FEED_IDS,
    // Likes per post over an id range: columns post_id, count.
    DB_FEED_LIKES,
    // Post rows over an id range, id descending: columns id, body, created_at, username.
    DB_FEED_ROWS_DESC,
    // Same rows ascending, for the dense path.
    DB_FEED_ROWS,
    // The reference feed query: columns id, body, created_at, username, like_count.
    DB_FEED_REF,
    // One post by id: same columns as DB_FEED_REF.
    DB_POST,
    // Plain insert of (user_id ?1, body ?2); the id comes from sqlite3_last_insert_rowid.
    DB_CREATE,
    // created_at of a post by id ?1.
    DB_CREATE_TS,
    // Insert of like (user_id ?1, post_id ?2) with ON CONFLICT DO NOTHING; sqlite3_changes tells new from repeat.
    DB_LIKE,
    // Row exists check for post id ?1.
    DB_EXISTS,
    DB_STMT_COUNT,
};

#define DB_POST_COLUMNS \
    "SELECT p.id, p.body, p.created_at, u.username, (SELECT count(*) FROM likes l WHERE l.post_id = p.id) " \
    "FROM posts p JOIN users u ON u.id = p.user_id "

#define DB_FEED_ROW_COLUMNS "SELECT p.id, p.body, p.created_at, u.username FROM posts p JOIN users u ON u.id = p.user_id "

static const char *const db_sql[DB_STMT_COUNT] = {
    [DB_PING] = "SELECT 1",
    [DB_BEGIN] = "BEGIN",
    [DB_COMMIT] = "COMMIT",
    [DB_ROLLBACK] = "ROLLBACK",
    [DB_FEED_IDS] = "SELECT id FROM posts ORDER BY created_at DESC, id DESC LIMIT 20",
    [DB_FEED_LIKES] = "SELECT post_id, count(*) FROM likes WHERE post_id BETWEEN ?1 AND ?2 GROUP BY post_id",
    [DB_FEED_ROWS_DESC] = DB_FEED_ROW_COLUMNS "WHERE p.id BETWEEN ?1 AND ?2 ORDER BY p.id DESC",
    [DB_FEED_ROWS] = DB_FEED_ROW_COLUMNS "WHERE p.id BETWEEN ?1 AND ?2",
    [DB_FEED_REF] = DB_POST_COLUMNS "ORDER BY p.created_at DESC, p.id DESC LIMIT 20",
    [DB_POST] = DB_POST_COLUMNS "WHERE p.id = ?1",
    [DB_CREATE] = "INSERT INTO posts (user_id, body) VALUES (?1, ?2)",
    [DB_CREATE_TS] = "SELECT created_at FROM posts WHERE id = ?1",
    [DB_LIKE] = "INSERT INTO likes (user_id, post_id) VALUES (?1, ?2) ON CONFLICT (user_id, post_id) DO NOTHING",
    [DB_EXISTS] = "SELECT 1 FROM posts WHERE id = ?1",
};

// Pragmas in the order the spec fixes; locking_mode must come before the first WAL access.
static const char db_pragmas[] =
    "PRAGMA locking_mode=EXCLUSIVE;"
    "PRAGMA journal_mode=WAL;"
    "PRAGMA synchronous=NORMAL;"
    "PRAGMA mmap_size=" DB_MMAP_SIZE ";"
    "PRAGMA cache_size=" DB_CACHE_SIZE ";"
    "PRAGMA temp_store=MEMORY;"
    "PRAGMA wal_autocheckpoint=0;"
    "PRAGMA journal_size_limit=" DB_JOURNAL_SIZE_LIMIT ";";

// The WAL file starts with a 32-byte header and then holds one 24-byte frame header plus one page per frame.
enum {
    DB_WAL_HEADER_BYTES = 32,
    DB_WAL_FRAME_HEADER_BYTES = 24,
};

static sqlite3 *db_handle;
static sqlite3_stmt *db_stmts[DB_STMT_COUNT];
static const char *db_path;
static bool db_in_txn;
static bool db_batch_failed;
static int db_wal_frames;
static int db_wal_synced;
static int db_wal_fd = -1;
static int db_ckpt_at = CKPT_FRAMES;
static uint32_t db_page_size = DB_PAGE_BYTES;

// Records the WAL length after each commit; the checkpoint and presync decisions read it after the sends.
static int db_wal_hook(void *arg, sqlite3 *handle, const char *name, int frames) {
    (void)arg;
    (void)handle;
    (void)name;
    db_wal_frames = frames;
    return SQLITE_OK;
}

// Records a statement result; a fatal code marks the whole pass failed so COMMIT is skipped.
static void db_note_result(int rc) {
    int primary = rc & 0xff;
    if (primary == SQLITE_FULL || primary == SQLITE_IOERR || primary == SQLITE_NOMEM || primary == SQLITE_CORRUPT) {
        db_batch_failed = true;
    }
    if (db_in_txn && sqlite3_get_autocommit(db_handle)) {
        db_batch_failed = true;
    }
}

// Steps a statement that returns no rows, resets it and returns the result code.
static int db_run(enum db_stmt id) {
    int rc = sqlite3_step(db_stmts[id]);
    // The reset code repeats the step result that is returned.
    (void)sqlite3_reset(db_stmts[id]);
    return rc;
}

// Steps a statement once and leaves it positioned; a failure is classified for the pass.
static int db_step(enum db_stmt id) {
    int rc = sqlite3_step(db_stmts[id]);
    if (UNLIKELY(rc != SQLITE_ROW && rc != SQLITE_DONE)) {
        db_note_result(rc);
    }
    return rc;
}

// Resets a statement after its rows were read; the code repeats the step's error, which db_step already recorded.
static void db_reset(enum db_stmt id) {
    (void)sqlite3_reset(db_stmts[id]);
}

// Gives SQLite one region of huge pages for the page cache so a cache hit never reaches malloc.
static void db_pagecache_config(void) {
    static const size_t huge = (size_t)2 << 20;
    static bool configured;
    int hdr = 0;
    if (configured) {
        return;
    }
    configured = true;
    if (sqlite3_config(SQLITE_CONFIG_PCACHE_HDRSZ, &hdr) != SQLITE_OK || hdr <= 0) {
        return;
    }
    size_t slot = ((size_t)DB_PAGE_BYTES + (size_t)hdr + 7) & ~(size_t)7;
    size_t slots = (size_t)DB_PAGECACHE_KIB * 1024 / DB_PAGE_BYTES + DB_PAGECACHE_SLACK;
    size_t len = (slot * slots + huge - 1) & ~(huge - 1);
    void *m = mmap(NULL, len + huge, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        return;
    }
    char *base = (char *)m + ((huge - (uintptr_t)m % huge) % huge);
    if (madvise(base, len, MADV_HUGEPAGE)) {
        util_log_limited(0, "warning: no transparent huge pages for the page cache");
    }
    memset(base, 0, len);
    if (sqlite3_config(SQLITE_CONFIG_PAGECACHE, base, (int)slot, (int)slots) != SQLITE_OK) {
        util_log_limited(0, "warning: page cache region rejected");
    }
}

// Prepares a one-row pragma and steps to its row; exits when that fails.
static void db_pragma_row(const char *sql, sqlite3_stmt **out) {
    if (sqlite3_prepare_v2(db_handle, sql, -1, out, NULL) != SQLITE_OK || sqlite3_step(*out) != SQLITE_ROW) {
        util_die("%s failed: %s", sql, sqlite3_errmsg(db_handle));
    }
}

// Checks that the file is in WAL mode and records its page size for the WAL offset arithmetic.
static void db_check_wal(void) {
    sqlite3_stmt *st = NULL;
    db_pragma_row("PRAGMA journal_mode", &st);
    const unsigned char *mode = sqlite3_column_text(st, 0);
    if (!mode || strcmp((const char *)mode, "wal")) {
        util_die("database is not in WAL mode");
    }
    sqlite3_finalize(st);
    db_pragma_row("PRAGMA page_size", &st);
    db_page_size = (uint32_t)sqlite3_column_int(st, 0);
    sqlite3_finalize(st);
}

// Opens the database, applies the pragmas, prepares every statement and checks SELECT 1; exits on failure.
static void db_open(const char *path) {
    db_path = path;
    db_pagecache_config();
    if (sqlite3_initialize() != SQLITE_OK) {
        util_die("sqlite3_initialize failed");
    }
    if (sqlite3_open_v2(path, &db_handle, SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        util_die("cannot open %s: %s", path, sqlite3_errmsg(db_handle));
    }
    char *err = NULL;
    if (sqlite3_exec(db_handle, db_pragmas, NULL, NULL, &err) != SQLITE_OK) {
        util_die("pragmas failed: %s", err ? err : "unknown");
    }
    db_check_wal();
    sqlite3_wal_hook(db_handle, db_wal_hook, NULL);
    for (int i = 0; i < DB_STMT_COUNT; i++) {
        int rc = sqlite3_prepare_v3(db_handle, db_sql[i], -1, SQLITE_PREPARE_PERSISTENT, &db_stmts[i], NULL);
        if (rc != SQLITE_OK) {
            util_die("prepare failed (%s): %s", sqlite3_errmsg(db_handle), db_sql[i]);
        }
    }
    if (db_run(DB_PING) != SQLITE_ROW) {
        util_die("SELECT 1 failed: %s", sqlite3_errmsg(db_handle));
    }
}

// Runs SELECT 1 for /health; on failure sets *msg to the SQLite error text.
static bool db_ping(const char **msg) {
    if (db_run(DB_PING) == SQLITE_ROW) {
        return true;
    }
    *msg = sqlite3_errmsg(db_handle);
    return false;
}

// Opens the pass transaction on the first database touch; false when BEGIN fails or the pass is already doomed.
static bool db_touch(void) {
    if (db_in_txn) {
        db_note_result(SQLITE_OK);
        return !db_batch_failed;
    }
    int rc = db_run(DB_BEGIN);
    if (rc != SQLITE_DONE) {
        return false;
    }
    db_in_txn = true;
    return true;
}

// Ends the pass transaction; returns true when nothing was open or COMMIT succeeded, false after a rollback.
static bool db_commit(void) {
    if (!db_in_txn) {
        return true;
    }
    bool ok = !db_batch_failed && db_run(DB_COMMIT) == SQLITE_DONE;
    if (!ok && !sqlite3_get_autocommit(db_handle)) {
        (void)db_run(DB_ROLLBACK);
    }
    db_in_txn = false;
    db_batch_failed = false;
    return ok;
}

// Fills the byte range of the WAL frames in [from, to); returns false when it does not fit the ring call.
static bool db_wal_range(int from, int to, uint64_t *off, uint32_t *len) {
    uint64_t frame_bytes = (uint64_t)db_page_size + DB_WAL_FRAME_HEADER_BYTES;
    uint64_t bytes = (uint64_t)(to - from) * frame_bytes;
    *off = DB_WAL_HEADER_BYTES + (uint64_t)from * frame_bytes;
    *len = (uint32_t)bytes;
    return bytes <= UINT32_MAX;
}

// Opens the WAL read-only the first time it is needed; false while it does not exist yet.
static bool db_wal_open(void) {
    if (db_wal_fd >= 0) {
        return true;
    }
    char wal_path[4096];
    int n = snprintf(wal_path, sizeof wal_path, "%s-wal", db_path);
    if (n < 0 || (size_t)n >= sizeof wal_path) {
        return false;
    }
    db_wal_fd = open(wal_path, O_RDONLY | O_CLOEXEC);
    return db_wal_fd >= 0;
}

// Queues the kernel write-back hint for the WAL frames added since the last hint, every WAL_PRESYNC_FRAMES frames.
static void db_wal_presync(void) {
    uint64_t off = 0;
    uint32_t len = 0;
    if (db_wal_frames - db_wal_synced < WAL_PRESYNC_FRAMES || !db_wal_open()) {
        return;
    }
    if (db_wal_range(db_wal_synced, db_wal_frames, &off, &len)) {
        ring_queue_wal_sync(db_wal_fd, off, len);
    }
    db_wal_synced = db_wal_frames;
}

// Runs a PASSIVE checkpoint once the WAL holds CKPT_FRAMES frames and records how long it blocked the loop.
static void db_checkpoint(void) {
    int log_frames = 0;
    int done_frames = 0;
    if (db_wal_frames < db_ckpt_at) {
        return;
    }
    uint64_t t0 = util_mono_ns();
    int rc = sqlite3_wal_checkpoint_v2(db_handle, NULL, SQLITE_CHECKPOINT_PASSIVE, &log_frames, &done_frames);
    uint64_t took = util_mono_ns() - t0;
    stats.ckpt_count++;
    stats.ckpt_ns_total += took;
    stats.ckpt_ns_max = took > stats.ckpt_ns_max ? took : stats.ckpt_ns_max;
    if (rc == SQLITE_OK && done_frames >= log_frames) {
        db_wal_frames = 0;
        db_wal_synced = 0;
        db_ckpt_at = CKPT_FRAMES;
        return;
    }
    db_ckpt_at = db_wal_frames + CKPT_FRAMES / 4;
}

// Queues a write-back hint for new WAL frames and runs a PASSIVE checkpoint when the WAL is long enough.
static void db_after_pass(void) {
    if (db_wal_frames < db_wal_synced) {
        db_wal_synced = 0;
    }
    db_wal_presync();
    db_checkpoint();
}

// Closes the database at shutdown after the final commit.
static void db_close(void) {
    for (int i = 0; i < DB_STMT_COUNT; i++) {
        sqlite3_finalize(db_stmts[i]);
    }
    sqlite3_close(db_handle);
    db_handle = NULL;
    db_in_txn = false;
    db_batch_failed = false;
    db_wal_frames = 0;
    db_wal_synced = 0;
    db_ckpt_at = CKPT_FRAMES;
    if (db_wal_fd >= 0) {
        close(db_wal_fd);
        db_wal_fd = -1;
    }
}
