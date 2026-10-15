// Shared helpers for the io module tests; include after ../src/main.c.
#pragma once

static int failures;

// Records a failed expectation with its line.
#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); \
            failures++; \
        } \
    } while (0)

// Creates a bound, listening loopback socket on port.
static int tu_listen(int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    int one = 1;
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    int rc = -1;
    for (int tries = 0; tries < 700 && rc; tries++) {
        rc = bind(fd, (struct sockaddr *)&a, sizeof a);
        if (rc) {
            usleep(100000);
        }
    }
    if (fd < 0 || rc || listen(fd, 1024)) {
        perror("tu_listen");
        exit(2);
    }
    return fd;
}

// Creates a database file with the challenge schema and no rows.
static void tu_make_db(const char *path) {
    static const char schema[] =
        "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,"
        " created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));"
        "CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),"
        " body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 500),"
        " created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')));"
        "CREATE TABLE likes (user_id INTEGER NOT NULL REFERENCES users(id), post_id INTEGER NOT NULL REFERENCES posts(id),"
        " created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')), PRIMARY KEY (user_id, post_id));"
        "CREATE INDEX posts_created_at_id_idx ON posts (created_at DESC, id DESC);"
        "CREATE INDEX posts_user_id_idx ON posts (user_id);"
        "CREATE INDEX likes_post_id_idx ON likes (post_id);"
        "INSERT INTO users (id, username) VALUES (1, 'alice');";
    sqlite3 *h = NULL;
    sqlite3_initialize();
    unlink(path);
    if (sqlite3_open(path, &h) != SQLITE_OK || sqlite3_exec(h, schema, NULL, NULL, NULL) != SQLITE_OK) {
        fprintf(stderr, "tu_make_db failed\n");
        exit(2);
    }
    sqlite3_close(h);
}

// Brings up the pools, the database and the ring so conn, pass and ring code can run in the test process.
static void tu_boot(int port, const char *db_path) {
    tu_make_db(db_path);
    start_mono_ns = util_mono_ns();
    util_clock_update();
    db_open(db_path);
    auth_init("secret", 6);
    if (!block_pool_init() || !conn_table_init()) {
        fprintf(stderr, "pools failed\n");
        exit(2);
    }
    ring_init(tu_listen(port));
}

// Counts the blocks on the free list.
static uint32_t tu_free_blocks(void) {
    uint32_t n = 0;
    for (const struct block *b = block_free; b; b = b->next) {
        n++;
    }
    return n;
}

// Copies text into provided buffer buf_id and returns a pointer to it.
static char *tu_buf(int buf_id, const char *text, size_t n) {
    char *p = (char *)ring_buf_mem + (size_t)buf_id * PROV_BUF_SIZE;
    memcpy(p, text, n);
    return p;
}

// Feeds text to a connection through provided buffer buf_id.
static void tu_feed(uint32_t idx, int buf_id, const char *text, size_t n) {
    conn_feed(idx, tu_buf(buf_id, text, n), (uint32_t)n, buf_id);
}

// Opens a connection record at idx as the accept path would.
static void tu_open(uint32_t idx) {
    conn_open(idx);
}

// Runs the middle of a pass: schedule, execute, commit, publish.
static void tu_run_pass_body(void) {
    pass_schedule();
    pass_execute();
    pass_commit();
    pass_publish();
}
