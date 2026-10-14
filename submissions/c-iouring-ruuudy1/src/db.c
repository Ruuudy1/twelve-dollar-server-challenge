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

static sqlite3 *db_handle;
static sqlite3_stmt *db_stmts[DB_STMT_COUNT];
static const char *db_path;
static bool db_in_txn;
static bool db_batch_failed;
static int db_wal_frames;
static int db_wal_synced;
static int db_wal_fd = -1;
static uint32_t db_page_size = 4096;

// Records the WAL length after each commit; the checkpoint and presync decisions read it after the sends.
static int db_wal_hook(void *arg, sqlite3 *handle, const char *name, int frames) {
    (void)arg;
    (void)handle;
    (void)name;
    db_wal_frames = frames;
    return SQLITE_OK;
}

// Steps a statement that returns no rows, resets it and returns the result code.
static int db_run(enum db_stmt id) {
    int rc = sqlite3_step(db_stmts[id]);
    sqlite3_reset(db_stmts[id]);
    return rc;
}

// Opens the database, applies the pragmas, prepares every statement and checks SELECT 1; exits on failure.
static void db_open(const char *path) {
    db_path = path;
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

// Opens the pass transaction on the first database touch; returns false if BEGIN fails.
static NOT_YET_USED bool db_touch(void) {
    if (db_in_txn) {
        return true;
    }
    if (db_run(DB_BEGIN) != SQLITE_DONE) {
        return false;
    }
    db_in_txn = true;
    return true;
}

// Records a statement result; a fatal code marks the whole pass failed so COMMIT is skipped.
static NOT_YET_USED void db_note_result(int rc) {
    if (rc == SQLITE_FULL || rc == SQLITE_IOERR || rc == SQLITE_NOMEM || rc == SQLITE_CORRUPT) {
        db_batch_failed = true;
    }
    if (db_in_txn && sqlite3_get_autocommit(db_handle)) {
        db_batch_failed = true;
    }
}

// Ends the pass transaction; returns true when nothing was open or COMMIT succeeded, false after a rollback.
static bool db_commit(void) {
    if (!db_in_txn) {
        return true;
    }
    bool ok = !db_batch_failed && db_run(DB_COMMIT) == SQLITE_DONE;
    if (!ok && !sqlite3_get_autocommit(db_handle)) {
        db_run(DB_ROLLBACK);
    }
    db_in_txn = false;
    db_batch_failed = false;
    return ok;
}

// Queues a write-back hint for new WAL frames and runs a PASSIVE checkpoint when the WAL is long enough.
static void db_after_pass(void) {
    if (db_wal_fd < 0) {
        char wal_path[4096];
        snprintf(wal_path, sizeof wal_path, "%s-wal", db_path);
        db_wal_fd = open(wal_path, O_RDONLY | O_CLOEXEC);
    }
    uint32_t frame_bytes = db_page_size + 24;
    if (db_wal_fd >= 0 && db_wal_frames - db_wal_synced >= WAL_PRESYNC_FRAMES) {
        uint64_t off = 32 + (uint64_t)db_wal_synced * frame_bytes;
        ring_queue_wal_sync(db_wal_fd, off, (uint32_t)(db_wal_frames - db_wal_synced) * frame_bytes);
        db_wal_synced = db_wal_frames;
    }
    if (db_wal_frames < CKPT_FRAMES) {
        return;
    }
    uint64_t t0 = util_mono_ns();
    sqlite3_wal_checkpoint_v2(db_handle, NULL, SQLITE_CHECKPOINT_PASSIVE, NULL, NULL);
    uint64_t took = util_mono_ns() - t0;
    stats.ckpt_count++;
    stats.ckpt_ns_total += took;
    stats.ckpt_ns_max = took > stats.ckpt_ns_max ? took : stats.ckpt_ns_max;
    db_wal_frames = 0;
    db_wal_synced = 0;
}

// Closes the database at shutdown after the final commit.
static void db_close(void) {
    for (int i = 0; i < DB_STMT_COUNT; i++) {
        sqlite3_finalize(db_stmts[i]);
    }
    sqlite3_close(db_handle);
}
