// Owner: db module. Health, feed, single post, create and like handlers.

// One request inside a pass; request and route slices stay valid until the pass ends.
struct work {
    struct request req;
    struct route route;
    // Connection table index the request arrived on.
    uint32_t idx;
    // Finished response block, or NULL when the pool was exhausted and the connection must close.
    struct block *blk;
    uint16_t status;
    uint8_t cohort;
};

// Scratch for one handler call: unescaped body, token segments and username. Never kept past the call.
static char handler_scratch[SCRATCH_SIZE];

// Outcome of a body builder: HANDLER_OK, or the err_id of the error response to send in its place.
enum {
    HANDLER_OK = ERR_COUNT,
    // The feed scans disagreed with the id list, so the reference query must answer instead.
    HANDLER_FALLBACK,
};

// The first half of the scratch goes to the token check (its username stays there), the second to the create body.
enum {
    HANDLER_AUTH_SCRATCH = SCRATCH_SIZE / 2,
    // Bytes around the strings of one post object, with room for two 20-digit numbers.
    HANDLER_OBJECT_FIXED = 128,
    // Longest created_at the create handler copies out of the statement.
    HANDLER_STAMP_MAX = 48,
};

// The columns of one post row; the slices point into the statement until it is stepped or reset.
struct handler_row {
    int64_t id;
    struct slice body;
    struct slice created;
    struct slice author;
};

// Appends a string literal at o and returns the end.
static char *handler_put_lit(char *o, const char *s, size_t n) {
    memcpy(o, s, n);
    return o + n;
}

#define PUT_LIT(o, s) handler_put_lit((o), (s), LIT_LEN(s))

// Returns text column col of the current row of a statement, with its byte length.
static struct slice handler_column_text(sqlite3_stmt *st, int col) {
    const unsigned char *p = sqlite3_column_text(st, col);
    int n = sqlite3_column_bytes(st, col);
    return (struct slice){(const char *)p, p ? (uint32_t)n : 0};
}

// Reads columns id, body, created_at and username of the current row.
static void handler_row_read(enum db_stmt id, struct handler_row *row) {
    sqlite3_stmt *st = db_stmts[id];
    row->id = sqlite3_column_int64(st, 0);
    row->body = handler_column_text(st, 1);
    row->created = handler_column_text(st, 2);
    row->author = handler_column_text(st, 3);
}

// Bytes needed for the escaped text of a row plus its fixed parts, as a request for resp_need.
static uint32_t handler_row_room(const struct handler_row *row) {
    return (uint32_t)(HANDLER_OBJECT_FIXED + JSON_ESCAPED_MAX(row->body.n + row->created.n + row->author.n));
}

// Writes a post object up to and including the author string; the like count follows.
static char *handler_put_head(char *o, const struct handler_row *row) {
    o = PUT_LIT(o, "{\"id\":");
    o = util_fmt_u64(o, (uint64_t)row->id);
    o = PUT_LIT(o, ",\"body\":\"");
    o = json_put_string(o, row->body.p, row->body.n);
    o = PUT_LIT(o, "\",\"created_at\":\"");
    o = json_put_string(o, row->created.p, row->created.n);
    o = PUT_LIT(o, "\",\"author\":\"");
    o = json_put_string(o, row->author.p, row->author.n);
    *o++ = '"';
    return o;
}

// Writes the like count and the closing brace of a post object.
static char *handler_put_tail(char *o, uint64_t likes) {
    o = PUT_LIT(o, ",\"like_count\":");
    o = util_fmt_u64(o, likes);
    *o++ = '}';
    return o;
}

// Appends a whole post object to the response; false when no room can be found.
static bool handler_emit_object(struct resp *r, const struct handler_row *row, uint64_t likes) {
    char *o = resp_need(r, handler_row_room(row));
    if (UNLIKELY(!o)) {
        return false;
    }
    r->w = handler_put_tail(handler_put_head(o, row), likes);
    return true;
}

// Moves the write cursor back to the start of the body.
static void handler_body_reset(struct resp *r) {
    r->w = (char *)r->blk->data + RESP_HDR_ROOM;
}

// Binds one integer parameter of a prepared statement.
static bool handler_bind_int(enum db_stmt id, int col, int64_t v) {
    return sqlite3_bind_int64(db_stmts[id], col, v) == SQLITE_OK;
}

// Binds one text parameter without copying; the bytes stay valid until the statement is reset.
static bool handler_bind_text(enum db_stmt id, int col, struct slice s) {
    return sqlite3_bind_text(db_stmts[id], col, s.p, (int)s.n, SQLITE_STATIC) == SQLITE_OK;
}

// Fills ids with the newest post ids, newest first, and returns false on a SQLite error.
static bool handler_feed_ids(int64_t *ids, unsigned *n) {
    int rc = SQLITE_ROW;
    *n = 0;
    while (*n < FEED_LIMIT && (rc = db_step(DB_FEED_IDS)) == SQLITE_ROW) {
        ids[(*n)++] = sqlite3_column_int64(db_stmts[DB_FEED_IDS], 0);
    }
    db_reset(DB_FEED_IDS);
    return rc == SQLITE_ROW || rc == SQLITE_DONE;
}

// Counts likes for posts lo..hi into counts[id - lo]; the caller zeroed span entries.
static bool handler_feed_counts(int64_t lo, int64_t hi, uint32_t *counts, uint64_t span) {
    sqlite3_stmt *st = db_stmts[DB_FEED_LIKES];
    int rc = SQLITE_DONE;
    if (!handler_bind_int(DB_FEED_LIKES, 1, lo) || !handler_bind_int(DB_FEED_LIKES, 2, hi)) {
        return false;
    }
    while ((rc = db_step(DB_FEED_LIKES)) == SQLITE_ROW) {
        uint64_t at = (uint64_t)(sqlite3_column_int64(st, 0) - lo);
        if (at < span) {
            counts[at] = (uint32_t)sqlite3_column_int64(st, 1);
        }
    }
    db_reset(DB_FEED_LIKES);
    return rc == SQLITE_DONE;
}

// Binds the id range of a feed scan and zeroes the counters it will fill.
static bool handler_feed_range(enum db_stmt scan, int64_t lo, int64_t hi, uint32_t *counts) {
    uint64_t span = (uint64_t)(hi - lo) + 1;
    memset(counts, 0, span * sizeof *counts);
    return handler_feed_counts(lo, hi, counts, span) && handler_bind_int(scan, 1, lo) && handler_bind_int(scan, 2, hi);
}

// Fast path: the newest ids are consecutive, so one descending scan yields the rows in feed order.
static int handler_feed_fast(struct resp *r, const int64_t *ids, unsigned n) {
    uint32_t counts[FEED_LIMIT];
    int64_t lo = ids[n - 1];
    unsigned emitted = 0;
    int rc = SQLITE_DONE;
    if (!handler_feed_range(DB_FEED_ROWS_DESC, lo, ids[0], counts)) {
        db_reset(DB_FEED_ROWS_DESC);
        return ERR_INTERNAL;
    }
    while ((rc = db_step(DB_FEED_ROWS_DESC)) == SQLITE_ROW) {
        struct handler_row row;
        handler_row_read(DB_FEED_ROWS_DESC, &row);
        uint64_t at = (uint64_t)(row.id - lo);
        if (at >= n || (emitted && !resp_put(r, ",", 1)) || !handler_emit_object(r, &row, counts[at])) {
            rc = SQLITE_ERROR;
            break;
        }
        emitted++;
    }
    db_reset(DB_FEED_ROWS_DESC);
    if (rc != SQLITE_DONE) {
        return ERR_INTERNAL;
    }
    return emitted == n ? HANDLER_OK : HANDLER_FALLBACK;
}

// Per-slot object prefixes for the dense path, kept in the scratch until the rows are emitted in id-list order.
struct handler_dense {
    uint32_t off[FEED_LIMIT];
    uint32_t len[FEED_LIMIT];
    uint8_t slot[FEED_SPAN_MAX];
    uint32_t used;
    unsigned found;
};

// Stores the object prefix of a wanted row in its slot; false when the scratch is full.
static bool handler_dense_store(struct handler_dense *d, unsigned slot, const struct handler_row *row) {
    uint32_t room = handler_row_room(row);
    if (room > SCRATCH_SIZE - d->used) {
        return false;
    }
    char *start = handler_scratch + d->used;
    d->off[slot] = d->used;
    d->len[slot] = (uint32_t)(handler_put_head(start, row) - start);
    d->used += d->len[slot];
    d->found++;
    return true;
}

// Reads the ascending scan into the dense table; returns ERR_INTERNAL, HANDLER_FALLBACK or HANDLER_OK.
static int handler_dense_scan(struct handler_dense *d, int64_t lo, unsigned span) {
    int rc = SQLITE_DONE;
    while ((rc = db_step(DB_FEED_ROWS)) == SQLITE_ROW) {
        struct handler_row row;
        handler_row_read(DB_FEED_ROWS, &row);
        uint64_t at = (uint64_t)(row.id - lo);
        unsigned slot = at < span ? d->slot[at] : 0xff;
        if (slot == 0xff) {
            continue;
        }
        if (!handler_dense_store(d, slot, &row)) {
            db_reset(DB_FEED_ROWS);
            return HANDLER_FALLBACK;
        }
    }
    db_reset(DB_FEED_ROWS);
    return rc == SQLITE_DONE ? HANDLER_OK : ERR_INTERNAL;
}

// Dense path: the ids are close but gapped or out of order, so scan the span and emit by the id list.
static int handler_feed_dense(struct resp *r, const int64_t *ids, unsigned n, int64_t lo, int64_t hi) {
    uint32_t counts[FEED_SPAN_MAX];
    struct handler_dense d = {.used = 0, .found = 0};
    unsigned span = (unsigned)(hi - lo) + 1;
    memset(d.slot, 0xff, sizeof d.slot);
    for (unsigned i = 0; i < n; i++) {
        d.slot[ids[i] - lo] = (uint8_t)i;
    }
    if (!handler_feed_range(DB_FEED_ROWS, lo, hi, counts)) {
        db_reset(DB_FEED_ROWS);
        return ERR_INTERNAL;
    }
    int rc = handler_dense_scan(&d, lo, span);
    if (rc != HANDLER_OK || d.found != n) {
        return rc == HANDLER_OK ? HANDLER_FALLBACK : rc;
    }
    for (unsigned i = 0; i < n; i++) {
        char *o = resp_need(r, d.len[i] + HANDLER_OBJECT_FIXED);
        if (UNLIKELY(!o)) {
            return ERR_INTERNAL;
        }
        o = i ? handler_put_lit(o, ",", 1) : o;
        o = handler_put_lit(o, handler_scratch + d.off[i], d.len[i]);
        r->w = handler_put_tail(o, counts[ids[i] - lo]);
    }
    return HANDLER_OK;
}

// Reference path: the spec's own query, one correlated count per row.
static int handler_feed_ref(struct resp *r) {
    int rc = SQLITE_DONE;
    unsigned emitted = 0;
    while ((rc = db_step(DB_FEED_REF)) == SQLITE_ROW) {
        struct handler_row row;
        handler_row_read(DB_FEED_REF, &row);
        uint64_t likes = (uint64_t)sqlite3_column_int64(db_stmts[DB_FEED_REF], 4);
        if ((emitted && !resp_put(r, ",", 1)) || !handler_emit_object(r, &row, likes)) {
            rc = SQLITE_ERROR;
            break;
        }
        emitted++;
    }
    db_reset(DB_FEED_REF);
    return rc == SQLITE_DONE ? HANDLER_OK : ERR_INTERNAL;
}

// Picks the scan for the id list: consecutive ids, a small span, or the reference query.
static int handler_feed_scan(struct resp *r, const int64_t *ids, unsigned n) {
    int64_t hi = ids[0];
    int64_t lo = ids[0];
    bool consecutive = true;
    for (unsigned i = 0; i < n; i++) {
        consecutive &= ids[i] == ids[0] - (int64_t)i;
        lo = ids[i] < lo ? ids[i] : lo;
        hi = ids[i] > hi ? ids[i] : hi;
    }
    if (consecutive) {
        return handler_feed_fast(r, ids, n);
    }
    if (hi - lo < FEED_SPAN_MAX) {
        return handler_feed_dense(r, ids, n, lo, hi);
    }
    return HANDLER_FALLBACK;
}

// Builds the feed body: the 20 newest posts as a JSON array inside {"posts":[...]}.
static int handler_feed_body(struct resp *r) {
    int64_t ids[FEED_LIMIT];
    unsigned n = 0;
    if (!db_touch() || !handler_feed_ids(ids, &n)) {
        return ERR_INTERNAL;
    }
    if (!resp_put(r, "{\"posts\":[", LIT_LEN("{\"posts\":["))) {
        return ERR_INTERNAL;
    }
    int rc = n ? handler_feed_scan(r, ids, n) : HANDLER_OK;
    if (rc == HANDLER_FALLBACK) {
        handler_body_reset(r);
        rc = resp_put(r, "{\"posts\":[", LIT_LEN("{\"posts\":[")) ? handler_feed_ref(r) : ERR_INTERNAL;
    }
    if (rc == HANDLER_OK && !resp_put(r, "]}", 2)) {
        return ERR_INTERNAL;
    }
    return rc;
}

// Builds the body of a single post lookup; HANDLER_OK means a row was written.
static int handler_post_body(const struct work *w, struct resp *r) {
    int64_t id = 0;
    enum route_id_status parsed = route_parse_id(w->route.id, &id);
    if (parsed != ID_OK) {
        return parsed == ID_INVALID ? ERR_INVALID_ID : ERR_POST_NOT_FOUND;
    }
    if (!db_touch() || !handler_bind_int(DB_POST, 1, id)) {
        return ERR_INTERNAL;
    }
    int rc = db_step(DB_POST);
    int result = rc == SQLITE_DONE ? ERR_POST_NOT_FOUND : ERR_INTERNAL;
    if (rc == SQLITE_ROW) {
        struct handler_row row;
        handler_row_read(DB_POST, &row);
        uint64_t likes = (uint64_t)sqlite3_column_int64(db_stmts[DB_POST], 4);
        bool ok = resp_put(r, "{\"post\":", LIT_LEN("{\"post\":")) && handler_emit_object(r, &row, likes);
        result = ok && resp_put(r, "}", 1) ? HANDLER_OK : ERR_INTERNAL;
    }
    db_reset(DB_POST);
    return result;
}

// Maps a token check result to the error response that answers it.
static int handler_auth(const struct work *w, struct auth_identity *who) {
    struct slice header = {w->req.auth, w->req.auth_len};
    switch (auth_check(header, clk.real_s, handler_scratch, HANDLER_AUTH_SCRATCH, who)) {
    case AUTH_OK:
        return HANDLER_OK;
    case AUTH_MISSING:
        return ERR_MISSING_BEARER;
    case AUTH_BAD_PAYLOAD:
        return ERR_INVALID_PAYLOAD;
    case AUTH_INVALID:
    default:
        return ERR_INVALID_TOKEN;
    }
}

// Validates the create body into the second half of the scratch and maps a rejection to its error response.
static int handler_create_text(const struct work *w, struct slice *text) {
    struct slice doc = {w->req.body, w->req.body_len};
    char *scratch = handler_scratch + HANDLER_AUTH_SCRATCH;
    switch (json_create_body(doc, scratch, SCRATCH_SIZE - HANDLER_AUTH_SCRATCH, text)) {
    case JSON_BODY_OK:
        return HANDLER_OK;
    case JSON_BODY_REQUIRED:
        return ERR_BODY_REQUIRED;
    case JSON_BODY_TOO_LONG:
        return ERR_BODY_TOO_LONG;
    case JSON_BODY_MALFORMED:
    default:
        return ERR_MALFORMED_JSON;
    }
}

// Inserts the post and copies the stored created_at out of the statement; false when any statement fails.
static bool handler_insert_post(int64_t user_id, struct slice text, int64_t *post_id, struct slice *stamp) {
    static char copy[HANDLER_STAMP_MAX];
    bool bound = handler_bind_int(DB_CREATE, 1, user_id) && handler_bind_text(DB_CREATE, 2, text);
    int rc = bound ? db_step(DB_CREATE) : SQLITE_ERROR;
    db_reset(DB_CREATE);
    if (rc != SQLITE_DONE) {
        return false;
    }
    *post_id = sqlite3_last_insert_rowid(db_handle);
    if (!handler_bind_int(DB_CREATE_TS, 1, *post_id)) {
        return false;
    }
    struct slice found = {0};
    if (db_step(DB_CREATE_TS) == SQLITE_ROW) {
        found = handler_column_text(db_stmts[DB_CREATE_TS], 0);
    }
    bool ok = found.n && found.n <= sizeof copy;
    if (ok) {
        memcpy(copy, found.p, found.n);
        *stamp = (struct slice){copy, found.n};
    }
    db_reset(DB_CREATE_TS);
    return ok;
}

// Builds the body of a created post from the token, the validated text and the new row.
static int handler_create_body(const struct work *w, struct resp *r) {
    struct auth_identity who = {0};
    struct slice text = {0};
    struct handler_row row = {0};
    int rc = handler_auth(w, &who);
    if (rc != HANDLER_OK) {
        return rc;
    }
    rc = handler_create_text(w, &text);
    if (rc != HANDLER_OK) {
        return rc;
    }
    if (!db_touch() || !handler_insert_post(who.user_id, text, &row.id, &row.created)) {
        return ERR_INTERNAL;
    }
    row.body = text;
    row.author = who.name;
    bool ok = resp_put(r, "{\"post\":", LIT_LEN("{\"post\":")) && handler_emit_object(r, &row, 0);
    return ok && resp_put(r, "}", 1) ? HANDLER_OK : ERR_INTERNAL;
}

// Runs the existence check of a like; returns HANDLER_OK, ERR_POST_NOT_FOUND or ERR_INTERNAL.
static int handler_post_exists(int64_t post_id) {
    if (!handler_bind_int(DB_EXISTS, 1, post_id)) {
        return ERR_INTERNAL;
    }
    int rc = db_step(DB_EXISTS);
    db_reset(DB_EXISTS);
    if (rc == SQLITE_ROW) {
        return HANDLER_OK;
    }
    return rc == SQLITE_DONE ? ERR_POST_NOT_FOUND : ERR_INTERNAL;
}

// Builds the like answer; *fresh tells a first like (201) from a repeat (200).
static int handler_like_body(const struct work *w, struct resp *r, bool *fresh) {
    struct auth_identity who = {0};
    int64_t post_id = 0;
    int rc = handler_auth(w, &who);
    if (rc != HANDLER_OK) {
        return rc;
    }
    enum route_id_status parsed = route_parse_id(w->route.id, &post_id);
    if (parsed != ID_OK) {
        return parsed == ID_INVALID ? ERR_INVALID_ID : ERR_POST_NOT_FOUND;
    }
    if (!db_touch()) {
        return ERR_INTERNAL;
    }
    rc = handler_post_exists(post_id);
    if (rc != HANDLER_OK) {
        return rc;
    }
    bool bound = handler_bind_int(DB_LIKE, 1, who.user_id) && handler_bind_int(DB_LIKE, 2, post_id);
    rc = bound ? db_step(DB_LIKE) : SQLITE_ERROR;
    db_reset(DB_LIKE);
    char *o = resp_need(r, 96);
    if (rc != SQLITE_DONE || !o) {
        return ERR_INTERNAL;
    }
    *fresh = sqlite3_changes(db_handle) == 1;
    o = PUT_LIT(o, "{\"liked\":true,\"already_liked\":");
    o = *fresh ? PUT_LIT(o, "false") : PUT_LIT(o, "true");
    o = PUT_LIT(o, ",\"post_id\":");
    o = util_fmt_u64(o, (uint64_t)post_id);
    *o++ = '}';
    r->w = o;
    return HANDLER_OK;
}

// Finishes a response with the given success status, or replaces it with the error a builder returned.
static void handler_finish(const struct work *w, struct resp *r, int outcome, unsigned status) {
    if (outcome == HANDLER_OK) {
        resp_finish(r, status, w->req.close_after);
    } else {
        resp_error(r, (enum err_id)outcome, w->req.close_after);
    }
}

// Answers 200 with the uptime after SELECT 1, or 503 with the SQLite message.
static void handle_health(const struct work *w, struct resp *r) {
    static const char ok_head[] = "{\"status\":\"ok\",\"db\":\"ok\",\"uptime_s\":";
    static const char bad_head[] = "{\"status\":\"degraded\",\"db\":\"unreachable\",\"error\":\"";
    const char *msg = "";
    bool close = w->req.close_after;
    if (db_ping(&msg)) {
        char *o = resp_need(r, sizeof ok_head + 24);
        if (UNLIKELY(!o)) {
            resp_error(r, ERR_INTERNAL, close);
            return;
        }
        memcpy(o, ok_head, LIT_LEN(ok_head));
        o += LIT_LEN(ok_head);
        o = util_fmt_u64(o, (clk.mono_ns - start_mono_ns) / 1000000000ULL);
        *o++ = '}';
        r->w = o;
        resp_finish(r, 200, close);
        return;
    }
    size_t n = strlen(msg);
    char *o = resp_need(r, (uint32_t)(sizeof bad_head + 4 + JSON_ESCAPED_MAX(n)));
    if (UNLIKELY(!o)) {
        resp_error(r, ERR_INTERNAL, close);
        return;
    }
    memcpy(o, bad_head, LIT_LEN(bad_head));
    o += LIT_LEN(bad_head);
    o = json_put_string(o, msg, n);
    *o++ = '"';
    *o++ = '}';
    r->w = o;
    resp_finish(r, 503, close);
}

// Answers the feed: the 20 newest posts, or an error.
static void handle_feed(const struct work *w, struct resp *r) {
    handler_finish(w, r, handler_feed_body(r), 200);
}

// Answers a single post lookup.
static void handle_post(const struct work *w, struct resp *r) {
    handler_finish(w, r, handler_post_body(w, r), 200);
}

// Answers a create with 201 and the new post.
static void handle_create(const struct work *w, struct resp *r) {
    handler_finish(w, r, handler_create_body(w, r), 201);
}

// Answers a like with 201 the first time and 200 on a repeat.
static void handle_like(const struct work *w, struct resp *r) {
    bool fresh = false;
    int outcome = handler_like_body(w, r, &fresh);
    handler_finish(w, r, outcome, fresh ? 201 : 200);
}

// Runs one request: begins a response, dispatches on the route and stores the finished block in the work item.
static void handler_run(struct work *w) {
    struct resp r;
    if (UNLIKELY(!resp_begin(&r))) {
        w->blk = NULL;
        return;
    }
    switch (w->route.kind) {
    case ROUTE_HEALTH:
        handle_health(w, &r);
        break;
    case ROUTE_FEED:
        handle_feed(w, &r);
        break;
    case ROUTE_POST:
        handle_post(w, &r);
        break;
    case ROUTE_CREATE:
        handle_create(w, &r);
        break;
    case ROUTE_LIKE:
        handle_like(w, &r);
        break;
    case ROUTE_BAD_REQUEST:
        resp_error(&r, ERR_BAD_REQUEST, true);
        break;
    case ROUTE_NOT_FOUND:
    default:
        resp_error(&r, ERR_NOT_FOUND, w->req.close_after);
        break;
    }
    w->blk = r.blk;
    w->status = r.blk->status;
}
