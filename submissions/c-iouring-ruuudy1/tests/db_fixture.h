// Test-only helpers shared by the db unit tests: temporary databases, a request driver and an independent JSON oracle.
// Included after ../src/main.c, so every module is in scope.
#include <dirent.h>
#include <sys/stat.h>
#include <sys/wait.h>

static int fx_failures;

// Records a failed expectation with its line.
#define CHECK(cond) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); \
            fx_failures++; \
        } \
    } while (0)

// The schema every submission shares, copied from schema.sql.
static const char fx_schema[] =
    "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,"
    " created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));"
    "CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id),"
    " body TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 500),"
    " created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')));"
    "CREATE TABLE likes (user_id INTEGER NOT NULL REFERENCES users(id), post_id INTEGER NOT NULL REFERENCES posts(id),"
    " created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')), PRIMARY KEY (user_id, post_id));"
    "CREATE INDEX posts_created_at_id_idx ON posts (created_at DESC, id DESC);"
    "CREATE INDEX posts_user_id_idx ON posts (user_id);"
    "CREATE INDEX likes_post_id_idx ON likes (post_id);";

static uint64_t fx_rng_state = 88172645463325252ULL;

// Returns the next xorshift64 value; the sequence is fixed unless fx_seed is called.
static uint64_t fx_rand(void) {
    fx_rng_state ^= fx_rng_state << 13;
    fx_rng_state ^= fx_rng_state >> 7;
    fx_rng_state ^= fx_rng_state << 17;
    return fx_rng_state;
}

// Restarts the generator from a seed.
static void fx_seed(uint64_t seed) {
    fx_rng_state = seed ? seed : 88172645463325252ULL;
}

// Returns a number in [0, n).
static uint64_t fx_below(uint64_t n) {
    return fx_rand() % n;
}

// Creates a fresh temporary directory and copies its path into dir.
static void fx_tmpdir(char *dir, size_t cap) {
    snprintf(dir, cap, "/tmp/fm-db-test-XXXXXX");
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        exit(2);
    }
}

// Removes the files of a temporary directory and the directory itself.
static void fx_rmdir(const char *dir) {
    DIR *d = opendir(dir);
    struct dirent *e;
    char path[512];
    while (d && (e = readdir(d))) {
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
            snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
            unlink(path);
        }
    }
    if (d) {
        closedir(d);
    }
    rmdir(dir);
}

// Runs SQL on a connection and aborts the test on failure.
static void fx_exec(sqlite3 *db, const char *sql) {
    char *err = NULL;
    if (sqlite3_exec(db, sql, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "fixture SQL failed: %s: %s\n", err ? err : "?", sql);
        exit(2);
    }
}

// Runs formatted SQL (printf style with %Q and %lld) on a connection.
static void fx_execf(sqlite3 *db, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char *sql = sqlite3_vmprintf(fmt, ap);
    va_end(ap);
    fx_exec(db, sql);
    sqlite3_free(sql);
}

// Configures the page cache and initializes SQLite once, as db_open does, before any other connection exists.
static void fx_init(void) {
    static bool done;
    if (!done) {
        db_mem_config();
        db_pagecache_config();
        CHECK(sqlite3_initialize() == SQLITE_OK);
        done = true;
    }
}

// Creates an empty WAL database with the shared schema and returns an open connection.
static sqlite3 *fx_create(const char *path) {
    sqlite3 *db = NULL;
    fx_init();
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL) != SQLITE_OK) {
        fprintf(stderr, "cannot create %s\n", path);
        exit(2);
    }
    fx_exec(db, "PRAGMA journal_mode=WAL;");
    fx_exec(db, fx_schema);
    return db;
}

// Writes a millisecond timestamp in the stored wire format: base 2025-01-01T00:00:00.000Z plus ms.
static void fx_stamp(char *out, int64_t ms) {
    time_t secs = 1735689600 + (time_t)(ms / 1000);
    struct tm tm;
    gmtime_r(&secs, &tm);
    char text[96];
    snprintf(text, sizeof text, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (int)(ms % 1000));
    memcpy(out, text, 25);
    out[24] = 'Z';
    out[25] = 0;
}

// Inserts a user.
static void fx_user(sqlite3 *db, int64_t id, const char *name) {
    fx_execf(db, "INSERT INTO users (id, username) VALUES (%lld, %Q);", (long long)id, name);
}

// Inserts a post with an explicit id and timestamp.
static void fx_post(sqlite3 *db, int64_t id, int64_t user, const char *created, const char *body) {
    fx_execf(db, "INSERT INTO posts (id, user_id, body, created_at) VALUES (%lld, %lld, %Q, %Q);", (long long)id,
             (long long)user, body, created);
}

// Inserts a like.
static void fx_like(sqlite3 *db, int64_t user, int64_t post) {
    fx_execf(db, "INSERT OR IGNORE INTO likes (user_id, post_id) VALUES (%lld, %lld);", (long long)user,
             (long long)post);
}

// Counts the rows a query returns in its first column as a number.
static int64_t fx_scalar(sqlite3 *db, const char *sql) {
    sqlite3_stmt *st = NULL;
    int64_t v = -1;
    if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK && sqlite3_step(st) == SQLITE_ROW) {
        v = sqlite3_column_int64(st, 0);
    }
    sqlite3_finalize(st);
    return v;
}

// Appends one JSON-escaped string (with quotes) the way JSON.stringify writes it; an independent encoder.
static size_t fx_json_string(char *out, const char *s, size_t n) {
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    out[o++] = '"';
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            out[o++] = '\\';
            out[o++] = (char)c;
        } else if (c == '\n' || c == '\r' || c == '\t' || c == '\b' || c == '\f') {
            out[o++] = '\\';
            out[o++] = c == '\n' ? 'n' : c == '\r' ? 'r' : c == '\t' ? 't' : c == '\b' ? 'b' : 'f';
        } else if (c < 0x20) {
            memcpy(out + o, "\\u00", 4);
            o += 4;
            out[o++] = hex[c >> 4];
            out[o++] = hex[c & 15];
        } else {
            out[o++] = (char)c;
        }
    }
    out[o++] = '"';
    return o;
}

// Builds the expected feed body with the spec's reference query on a separate connection and its own encoder.
static size_t fx_oracle_feed(const char *path, char *out) {
    sqlite3 *db = NULL;
    sqlite3_stmt *st = NULL;
    size_t o = 0;
    fx_init();
    const char *sql = "SELECT p.id, p.body, p.created_at, u.username,"
                      " (SELECT count(*) FROM likes l WHERE l.post_id = p.id)"
                      " FROM posts p JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC, p.id DESC LIMIT 20";
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK ||
        sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
        fprintf(stderr, "oracle cannot read %s\n", path);
        exit(2);
    }
    o += (size_t)sprintf(out + o, "{\"posts\":[");
    for (int row = 0; sqlite3_step(st) == SQLITE_ROW; row++) {
        o += (size_t)sprintf(out + o, "%s{\"id\":%lld,\"body\":", row ? "," : "", (long long)sqlite3_column_int64(st, 0));
        o += fx_json_string(out + o, (const char *)sqlite3_column_text(st, 1), (size_t)sqlite3_column_bytes(st, 1));
        o += (size_t)sprintf(out + o, ",\"created_at\":");
        o += fx_json_string(out + o, (const char *)sqlite3_column_text(st, 2), (size_t)sqlite3_column_bytes(st, 2));
        o += (size_t)sprintf(out + o, ",\"author\":");
        o += fx_json_string(out + o, (const char *)sqlite3_column_text(st, 3), (size_t)sqlite3_column_bytes(st, 3));
        o += (size_t)sprintf(out + o, ",\"like_count\":%lld}", (long long)sqlite3_column_int64(st, 4));
    }
    o += (size_t)sprintf(out + o, "]}");
    sqlite3_finalize(st);
    sqlite3_close(db);
    return o;
}

// One response as the client would see it.
struct fx_resp {
    char bytes[1 << 17];
    size_t n;
    unsigned status;
    size_t body_off;
    bool close;
};

// Copies a finished block into a response record and splits status and body.
static void fx_take(struct fx_resp *out, struct block *b) {
    out->n = b->len;
    memcpy(out->bytes, b->data + b->off, b->len);
    out->bytes[out->n] = 0;
    out->status = (unsigned)atoi(out->bytes + 9);
    const char *sep = strstr(out->bytes, "\r\n\r\n");
    out->body_off = sep ? (size_t)(sep - out->bytes) + 4 : out->n;
    out->close = (b->flags & BLOCK_F_CLOSE) != 0;
}

// Returns the body of a response.
static const char *fx_body(const struct fx_resp *r) {
    return r->bytes + r->body_off;
}

// Returns the body length of a response.
static size_t fx_body_len(const struct fx_resp *r) {
    return r->n - r->body_off;
}

// True when the body equals the given text.
static bool fx_body_is(const struct fx_resp *r, const char *want) {
    return fx_body_len(r) == strlen(want) && !memcmp(fx_body(r), want, fx_body_len(r));
}

// One request to drive through the handlers.
struct fx_req {
    const char *method;
    const char *path;
    const char *auth;
    const char *body;
    size_t body_n;
    bool has_body;
};

// Starts the block pool once per process.
static void fx_pool(void) {
    static bool done;
    if (!done) {
        CHECK(block_pool_init());
        done = true;
    }
}

// Opens the server database and the pools the handlers need.
static void fx_server_open(const char *path) {
    fx_pool();
    start_mono_ns = util_mono_ns();
    util_clock_update();
    db_open(path);
}

// Closes the server database so a test can inspect the file or open another one.
static void fx_server_close(void) {
    db_close();
}

// Parses request text with the real parser and routes it into a work item; the buffer must outlive the work.
static bool fx_make_work(const struct fx_req *rq, char *buf, size_t cap, struct work *w) {
    int n = snprintf(buf, cap, "%s %s HTTP/1.1\r\nHost: x\r\n", rq->method, rq->path);
    if (rq->auth) {
        n += snprintf(buf + n, cap - (size_t)n, "Authorization: %s\r\n", rq->auth);
    }
    if (rq->has_body) {
        n += snprintf(buf + n, cap - (size_t)n, "Content-Length: %zu\r\n", rq->body_n);
    }
    n += snprintf(buf + n, cap - (size_t)n, "\r\n");
    if (rq->has_body) {
        memcpy(buf + n, rq->body, rq->body_n);
        n += (int)rq->body_n;
    }
    memset(w, 0, sizeof *w);
    if (http_parse(buf, (uint32_t)n, &w->req) != HTTP_PARSE_OK) {
        return false;
    }
    route_classify(&w->req, &w->route);
    return true;
}

// Runs a list of requests as one pass: handlers in order, one commit, a 500 rewrite on failure; returns commit success.
static bool fx_pass(const struct fx_req *reqs, unsigned n, struct fx_resp *out) {
    static char bufs[64][20000];
    struct work works[64];
    util_clock_update();
    for (unsigned i = 0; i < n; i++) {
        CHECK(fx_make_work(&reqs[i], bufs[i], sizeof bufs[i], &works[i]));
        handler_run(&works[i]);
    }
    bool ok = db_commit();
    for (unsigned i = 0; i < n; i++) {
        if (!ok) {
            resp_rewrite_500(works[i].blk);
        }
        fx_take(&out[i], works[i].blk);
        block_put(works[i].blk);
    }
    return ok;
}

// Runs one request as its own pass.
static void fx_get(const char *path, struct fx_resp *out) {
    struct fx_req rq = {"GET", path, NULL, NULL, 0, false};
    fx_pass(&rq, 1, out);
}

// Runs one POST as its own pass.
static void fx_post_json(const char *path, const char *auth, const char *body, struct fx_resp *out) {
    struct fx_req rq = {"POST", path, auth, body, body ? strlen(body) : 0, body != NULL};
    fx_pass(&rq, 1, out);
}

// Signs a payload with the module's own HMAC and writes header.payload.signature.
static void fx_sign(char *out, size_t cap, const char *payload) {
    static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    char raw[1024];
    int pn = (int)strlen(payload);
    uint8_t mac[32];
    size_t o = 0;
    size_t on = 0;
    const char *hdr = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    for (int i = 0; i < pn; i += 3) {
        uint32_t v = (uint32_t)(uint8_t)payload[i] << 16;
        v |= i + 1 < pn ? (uint32_t)(uint8_t)payload[i + 1] << 8 : 0;
        v |= i + 2 < pn ? (uint32_t)(uint8_t)payload[i + 2] : 0;
        raw[on++] = b64[v >> 18];
        raw[on++] = b64[(v >> 12) & 63];
        if (i + 1 < pn) {
            raw[on++] = b64[(v >> 6) & 63];
        }
        if (i + 2 < pn) {
            raw[on++] = b64[v & 63];
        }
    }
    raw[on] = 0;
    o = (size_t)snprintf(out, cap, "%s.%s", hdr, raw);
    sha256_hmac(&auth_key, out, o, mac);
    out[o++] = '.';
    for (int i = 0; i < 32; i += 3) {
        uint32_t v = (uint32_t)mac[i] << 16;
        v |= i + 1 < 32 ? (uint32_t)mac[i + 1] << 8 : 0;
        v |= i + 2 < 32 ? (uint32_t)mac[i + 2] : 0;
        out[o++] = b64[v >> 18];
        out[o++] = b64[(v >> 12) & 63];
        if (i + 1 < 32) {
            out[o++] = b64[(v >> 6) & 63];
        }
        if (i + 2 < 32) {
            out[o++] = b64[v & 63];
        }
    }
    out[o] = 0;
}

// Builds a signed token for a user; exp is seconds from now.
static void fx_token(char *out, size_t cap, const char *sub, const char *name, int64_t exp_delta) {
    char payload[512];
    snprintf(payload, sizeof payload, "{\"sub\":\"%s\",\"username\":\"%s\",\"iat\":%lld,\"exp\":%lld}", sub, name,
             (long long)clk.real_s, (long long)(clk.real_s + exp_delta));
    fx_sign(out, cap, payload);
}
