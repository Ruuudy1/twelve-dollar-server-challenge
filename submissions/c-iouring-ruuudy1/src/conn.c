// Owner: io module. Block pool, connection table, response writer and input framing.

// Defined in batch.c.
static void pass_touch(uint32_t idx);
static void pass_add(uint32_t idx, const struct request *req);
static void pass_add_bad_request(uint32_t idx);
static void pass_hold_buf(int buf_id);
static void pass_note_closing(uint32_t idx);
// Defined in ring.c.
static void ring_buf_return(int buf_id);

// Block flags.
enum {
    // The connection closes after this block is sent.
    BLOCK_F_CLOSE = 1,
    // Content does not depend on the database and is never rewritten as a 500.
    BLOCK_F_NO_REWRITE = 2,
    // Block came from the jumbo pool.
    BLOCK_F_JUMBO = 4,
};

// One pooled buffer; a response body starts RESP_HDR_ROOM bytes into data and headers end where it starts.
struct block {
    struct block *next;
    uint32_t cap;
    // First byte to send, and how many bytes are valid from there.
    uint32_t off;
    uint32_t len;
    uint16_t status;
    uint16_t flags;
    uint8_t pad[40];
    uint8_t data[] __attribute__((aligned(64)));
};
static_assert(sizeof(struct block) == 64, "block header must stay one cache line");
static_assert(BLOCK_BYTES > 64 + RESP_HDR_ROOM + 4096, "block must hold a feed");
static_assert(REQUEST_MAX < BLOCK_BYTES - 64, "an input block must hold the largest request");

// Connection flags.
enum {
    CONN_OPEN = 1,
    CONN_RECV_ARMED = 2,
    CONN_SEND_INFLIGHT = 4,
    CONN_CLOSE_AFTER_SEND = 8,
    CONN_PAUSED = 16,
    CONN_DIRTY = 32,
    CONN_CLOSING = 64,
    CONN_SENT_CONTINUE = 128,
    // No further requests are parsed: the last one closes the connection after its response.
    CONN_STOP_PARSE = 256,
};

// One record per connection, exactly 64 bytes, indexed by direct slot or DIRECT_SLOTS + fd.
struct conn {
    // Generation checked against every CQE tag; bumped when the connection is released.
    uint32_t gen;
    // Monotonic seconds of the last progress, read by the stall sweep.
    uint32_t last_active_s;
    // Overflow input block, set only while a request spans receive buffers.
    struct block *in;
    // Queued response blocks, oldest first; every one is committed and ready to send.
    struct block *out_head, *out_tail;
    // Valid bytes in the input block, and bytes of out_head already sent.
    uint32_t in_len, sent;
    // Pass that last reset cohort and pass_works, and the offset of the first unparsed input byte.
    uint32_t batch_seq, in_off;
    uint16_t flags;
    // Queued response blocks, for backpressure.
    uint16_t out_blocks;
    // Highest cohort used by this connection in the current pass, and its requests in the current pass.
    uint8_t cohort, pass_works;
    uint8_t pad[10];
};
static_assert(sizeof(struct conn) == 64, "conn must stay one cache line");

static uint8_t *block_base;
static uint32_t block_carved;
static struct block *block_free;
static struct block *block_jumbo_free;
static uint32_t block_jumbo_made;
static struct conn *conn_table;
static uint32_t conn_live;
static uint32_t conn_direct_live;

// Carves n more blocks out of the reserved region, touching each page once; returns false at the cap.
static bool block_pool_grow(uint32_t n) {
    if (n > BLOCK_CAP - block_carved) {
        n = BLOCK_CAP - block_carved;
    }
    if (!n) {
        return false;
    }
    for (uint32_t i = 0; i < n; i++) {
        uint8_t *base = block_base + (size_t)(block_carved + i) * BLOCK_BYTES;
        for (size_t off = 0; off < BLOCK_BYTES; off += 4096) {
            base[off] = 0;
        }
        struct block *b = (struct block *)base;
        b->cap = BLOCK_BYTES - sizeof(struct block);
        b->next = block_free;
        block_free = b;
    }
    block_carved += n;
    return true;
}

// Reserves address space for the whole pool and carves the initial blocks; returns false on failure.
static bool block_pool_init(void) {
    size_t total = (size_t)BLOCK_CAP * BLOCK_BYTES;
    void *m = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (m == MAP_FAILED) {
        return false;
    }
    block_base = m;
    madvise(block_base, total, MADV_HUGEPAGE);
    return block_pool_grow(BLOCK_INITIAL);
}

// Takes a 16 KB block, growing the pool by BLOCK_GROW when empty; NULL means the cap is reached.
static struct block *block_get(void) {
    if (UNLIKELY(!block_free) && !block_pool_grow(BLOCK_GROW)) {
        return NULL;
    }
    struct block *b = block_free;
    block_free = b->next;
    b->next = NULL;
    b->off = 0;
    b->len = 0;
    b->status = 0;
    b->flags = 0;
    return b;
}

// Takes a 64 KB block for an oversized body; NULL when BLOCK_JUMBO_MAX are all in use.
static struct block *block_get_jumbo(void) {
    if (!block_jumbo_free) {
        if (block_jumbo_made >= BLOCK_JUMBO_MAX) {
            return NULL;
        }
        void *m = mmap(NULL, BLOCK_JUMBO_BYTES, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (m == MAP_FAILED) {
            return NULL;
        }
        struct block *made = m;
        made->cap = BLOCK_JUMBO_BYTES - sizeof(struct block);
        made->next = NULL;
        block_jumbo_free = made;
        block_jumbo_made++;
    }
    struct block *b = block_jumbo_free;
    block_jumbo_free = b->next;
    b->next = NULL;
    b->off = 0;
    b->len = 0;
    b->status = 0;
    b->flags = BLOCK_F_JUMBO;
    return b;
}

// Returns a block to its pool; the caller keeps no pointer to it afterwards.
static void block_put(struct block *b) {
    if (b->flags & BLOCK_F_JUMBO) {
        b->next = block_jumbo_free;
        block_jumbo_free = b;
    } else {
        b->next = block_free;
        block_free = b;
    }
}

// Error responses; the index doubles as the err_id passed to resp_error.
enum err_id {
    ERR_NOT_FOUND,
    ERR_INVALID_ID,
    ERR_POST_NOT_FOUND,
    ERR_MISSING_BEARER,
    ERR_INVALID_TOKEN,
    ERR_INVALID_PAYLOAD,
    ERR_MALFORMED_JSON,
    ERR_BODY_REQUIRED,
    ERR_BODY_TOO_LONG,
    ERR_INTERNAL,
    ERR_BAD_REQUEST,
    ERR_COUNT,
};

struct err_def {
    uint16_t status;
    struct slice json;
};

#define ERR_DEF(st, msg) {(st), {"{\"error\":\"" msg "\"}", sizeof("{\"error\":\"" msg "\"}") - 1}}

static const struct err_def err_defs[ERR_COUNT] = {
    [ERR_NOT_FOUND] = ERR_DEF(404, "not found"),
    [ERR_INVALID_ID] = ERR_DEF(400, "invalid post id"),
    [ERR_POST_NOT_FOUND] = ERR_DEF(404, "post not found"),
    [ERR_MISSING_BEARER] = ERR_DEF(401, "missing bearer token"),
    [ERR_INVALID_TOKEN] = ERR_DEF(401, "invalid or expired token"),
    [ERR_INVALID_PAYLOAD] = ERR_DEF(401, "invalid token payload"),
    [ERR_MALFORMED_JSON] = ERR_DEF(400, "malformed JSON body"),
    [ERR_BODY_REQUIRED] = ERR_DEF(400, "body is required"),
    [ERR_BODY_TOO_LONG] = ERR_DEF(400, "body must be at most 500 characters"),
    [ERR_INTERNAL] = ERR_DEF(500, "internal server error"),
    [ERR_BAD_REQUEST] = ERR_DEF(400, "bad request"),
};

// A response under construction: the body cursor inside a block.
struct resp {
    struct block *blk;
    char *w;
    char *end;
};

// Builds a slice from a string literal.
#define STATUS_LINE(s) ((struct slice){(s), LIT_LEN(s)})

// Returns the status line for a status code the server emits.
static struct slice resp_status_line(unsigned status) {
    switch (status) {
    case 200:
        return STATUS_LINE("HTTP/1.1 200 OK\r\n");
    case 201:
        return STATUS_LINE("HTTP/1.1 201 Created\r\n");
    case 400:
        return STATUS_LINE("HTTP/1.1 400 Bad Request\r\n");
    case 401:
        return STATUS_LINE("HTTP/1.1 401 Unauthorized\r\n");
    case 404:
        return STATUS_LINE("HTTP/1.1 404 Not Found\r\n");
    case 503:
        return STATUS_LINE("HTTP/1.1 503 Service Unavailable\r\n");
    default:
        return STATUS_LINE("HTTP/1.1 500 Internal Server Error\r\n");
    }
}

// Starts a response in a fresh block; returns false when the pool is exhausted.
static bool resp_begin(struct resp *r) {
    struct block *b = block_get();
    if (UNLIKELY(!b)) {
        return false;
    }
    r->blk = b;
    r->w = (char *)b->data + RESP_HDR_ROOM;
    r->end = (char *)b->data + b->cap;
    return true;
}

// Moves the body written so far into a jumbo block with at least n free bytes; NULL when that is impossible.
static char *resp_grow(struct resp *r, uint32_t n) {
    struct block *old = r->blk;
    if (old->flags & BLOCK_F_JUMBO) {
        return NULL;
    }
    struct block *jumbo = block_get_jumbo();
    if (!jumbo) {
        return NULL;
    }
    uint32_t used = (uint32_t)(r->w - ((char *)old->data + RESP_HDR_ROOM));
    if (jumbo->cap - RESP_HDR_ROOM - used < n) {
        block_put(jumbo);
        return NULL;
    }
    memcpy(jumbo->data + RESP_HDR_ROOM, old->data + RESP_HDR_ROOM, used);
    block_put(old);
    r->blk = jumbo;
    r->w = (char *)jumbo->data + RESP_HDR_ROOM + used;
    r->end = (char *)jumbo->data + jumbo->cap;
    return r->w;
}

// Returns the write cursor with at least n bytes of room, or NULL; any earlier cursor copy is invalid afterwards.
static char *resp_need(struct resp *r, uint32_t n) {
    if (LIKELY((size_t)(r->end - r->w) >= n)) {
        return r->w;
    }
    return resp_grow(r, n);
}

// Appends raw bytes to the body; returns false when no room can be found.
static NOT_YET_USED bool resp_put(struct resp *r, const char *s, uint32_t n) {
    char *o = resp_need(r, n);
    if (UNLIKELY(!o)) {
        return false;
    }
    memcpy(o, s, n);
    r->w = o + n;
    return true;
}

// Writes the status line and headers for a body of body_n bytes into head; returns their length.
static uint32_t resp_write_head(char *head, unsigned status, uint32_t body_n, bool close) {
    static const char fixed_head[] = "Content-Type: application/json\r\nContent-Length: ";
    struct slice line = resp_status_line(status);
    char *o = head;
    memcpy(o, line.p, line.n);
    o += line.n;
    memcpy(o, fixed_head, LIT_LEN(fixed_head));
    o += LIT_LEN(fixed_head);
    o = util_fmt_u64(o, body_n);
    memcpy(o, "\r\n", 2);
    o += 2;
    if (close) {
        memcpy(o, "Connection: close\r\n", LIT_LEN("Connection: close\r\n"));
        o += LIT_LEN("Connection: close\r\n");
    }
    memcpy(o, "\r\n", 2);
    o += 2;
    return (uint32_t)(o - head);
}

// Ends a response: places the headers so they end exactly at the body and records offset, length and status.
static void resp_finish(struct resp *r, unsigned status, bool close) {
    struct block *b = r->blk;
    char head[RESP_HDR_ROOM];
    uint32_t body_n = (uint32_t)(r->w - ((char *)b->data + RESP_HDR_ROOM));
    uint32_t head_n = resp_write_head(head, status, body_n, close);
    assert(head_n <= RESP_HDR_ROOM);
    memcpy(b->data + RESP_HDR_ROOM - head_n, head, head_n);
    b->off = RESP_HDR_ROOM - head_n;
    b->len = head_n + body_n;
    b->status = (uint16_t)status;
    b->flags = (uint16_t)((b->flags & ~BLOCK_F_CLOSE) | (close ? BLOCK_F_CLOSE : 0));
}

// Replaces whatever the response held with the prebuilt error body and finishes it.
static void resp_error(struct resp *r, enum err_id id, bool close) {
    r->w = (char *)r->blk->data + RESP_HDR_ROOM;
    memcpy(r->w, err_defs[id].json.p, err_defs[id].json.n);
    r->w += err_defs[id].json.n;
    resp_finish(r, err_defs[id].status, close);
}

// Rewrites a finished block in place as a 500, keeping its close flag; used when COMMIT fails.
static void resp_rewrite_500(struct block *b) {
    if (b->flags & BLOCK_F_NO_REWRITE) {
        return;
    }
    struct resp r = {b, (char *)b->data + RESP_HDR_ROOM, (char *)b->data + b->cap};
    resp_error(&r, ERR_INTERNAL, b->flags & BLOCK_F_CLOSE);
}

// Maps the connection table and zeroes it; returns false on failure.
static bool conn_table_init(void) {
    size_t total = (size_t)CONN_MAX * sizeof(struct conn);
    void *m = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (m == MAP_FAILED) {
        return false;
    }
    conn_table = m;
    madvise(conn_table, total, MADV_HUGEPAGE);
    return true;
}

// Returns the record for a table index.
static struct conn *conn_get(uint32_t idx) {
    return &conn_table[idx];
}

// Returns true for an index that names a direct descriptor slot.
static bool conn_is_direct(uint32_t idx) {
    return idx < DIRECT_SLOTS;
}

// Returns the descriptor an SQE names for this index: the slot for direct, the fd otherwise.
static int conn_target(uint32_t idx) {
    return conn_is_direct(idx) ? (int)idx : (int)(idx - DIRECT_SLOTS);
}

// Resets the record for a newly accepted connection, keeping its generation.
static void conn_open(uint32_t idx) {
    struct conn *c = conn_get(idx);
    uint32_t gen = c->gen;
    memset(c, 0, sizeof *c);
    c->gen = gen;
    c->flags = CONN_OPEN;
    c->last_active_s = (uint32_t)(clk.mono_ns / 1000000000ULL);
    conn_live++;
    conn_direct_live += conn_is_direct(idx);
}

// Frees every block of a connection, bumps its generation and clears it; the only way a connection ends.
static void conn_release(uint32_t idx) {
    struct conn *c = conn_get(idx);
    if (c->in) {
        block_put(c->in);
    }
    while (c->out_head) {
        struct block *b = c->out_head;
        c->out_head = b->next;
        block_put(b);
    }
    uint32_t gen = c->gen + 1;
    memset(c, 0, sizeof *c);
    c->gen = gen;
    conn_live--;
    conn_direct_live -= conn_is_direct(idx);
}

// Appends a committed response block to the connection's output queue.
static void conn_queue(struct conn *c, struct block *b) {
    b->next = NULL;
    if (c->out_tail) {
        c->out_tail->next = b;
    } else {
        c->out_head = b;
    }
    c->out_tail = b;
    c->out_blocks++;
    if (b->flags & BLOCK_F_CLOSE) {
        c->flags |= CONN_CLOSE_AFTER_SEND;
    }
}

// Removes and frees the fully sent head block.
static void conn_out_pop(struct conn *c) {
    struct block *b = c->out_head;
    c->out_head = b->next;
    if (!c->out_head) {
        c->out_tail = NULL;
    }
    c->out_blocks--;
    c->sent = 0;
    block_put(b);
}

// Marks a connection for close at the end of the pass; frees nothing yet because pass requests may point into it.
static void conn_request_close(uint32_t idx) {
    struct conn *c = conn_get(idx);
    if (!(c->flags & CONN_CLOSING)) {
        c->flags |= CONN_CLOSING;
        pass_note_closing(idx);
    }
}

// Queues an interim 100 Continue for a request whose headers arrived without its body.
static void conn_queue_continue(struct conn *c) {
    struct block *b = block_get();
    if (!b) {
        return;
    }
    static const char line[] = "HTTP/1.1 100 Continue\r\n\r\n";
    memcpy(b->data, line, LIT_LEN(line));
    b->off = 0;
    b->len = LIT_LEN(line);
    b->flags = BLOCK_F_NO_REWRITE;
    conn_queue(c, b);
    c->flags |= CONN_SENT_CONTINUE;
}

// Appends n received bytes to the overflow input block, allocating it when absent; false when it would overflow.
static bool conn_in_append(struct conn *c, const char *data, uint32_t n) {
    if (!c->in) {
        c->in = block_get();
        if (!c->in) {
            return false;
        }
    }
    if (n > c->in->cap || c->in_len > c->in->cap - n) {
        return false;
    }
    memcpy(c->in->data + c->in_len, data, n);
    c->in_len += n;
    return true;
}

// Drops consumed input after the pass: frees the block when empty, otherwise moves the tail to the front.
static void conn_in_compact(struct conn *c) {
    if (!c->in) {
        return;
    }
    if (c->in_off >= c->in_len) {
        block_put(c->in);
        c->in = NULL;
        c->in_len = 0;
    } else if (c->in_off) {
        memmove(c->in->data, c->in->data + c->in_off, c->in_len - c->in_off);
        c->in_len -= c->in_off;
    }
    c->in_off = 0;
}

// Parses every complete request in base[start, len), adding each to the pass; returns the new offset.
static uint32_t conn_parse(uint32_t idx, struct conn *c, char *base, uint32_t start, uint32_t len) {
    uint32_t off = start;
    while (off < len && !(c->flags & (CONN_PAUSED | CONN_CLOSING | CONN_STOP_PARSE))) {
        struct request req;
        enum http_parse_status st = http_parse(base + off, len - off, &req);
        if (st == HTTP_PARSE_INCOMPLETE) {
            if (req.expect_continue && !(c->flags & CONN_SENT_CONTINUE)) {
                conn_queue_continue(c);
            }
            break;
        }
        if (st == HTTP_PARSE_BAD) {
            pass_add_bad_request(idx);
            c->flags |= CONN_STOP_PARSE;
            return len;
        }
        pass_add(idx, &req);
        off += req.consumed;
        c->flags &= (uint16_t)~CONN_SENT_CONTINUE;
        if (req.close_after) {
            c->flags |= CONN_STOP_PARSE;
        } else if (c->out_blocks + c->pass_works >= PAUSE_BLOCKS) {
            c->flags |= CONN_PAUSED;
        }
    }
    return off;
}

// Takes bytes from receive buffer buf_id (or none when resuming) and queues every complete request into the pass.
static void conn_feed(uint32_t idx, char *data, uint32_t n, int buf_id) {
    struct conn *c = conn_get(idx);
    pass_touch(idx);
    c->last_active_s = (uint32_t)(clk.mono_ns / 1000000000ULL);
    uint32_t works_before = c->pass_works;
    bool ok = true;
    if (c->flags & CONN_STOP_PARSE) {
        if (buf_id >= 0) {
            ring_buf_return(buf_id);
        }
        return;
    }
    if (c->in || (c->flags & CONN_PAUSED)) {
        ok = !n || conn_in_append(c, data, n);
        if (buf_id >= 0) {
            ring_buf_return(buf_id);
        }
        if (ok && c->in && !(c->flags & CONN_PAUSED)) {
            c->in_off = conn_parse(idx, c, (char *)c->in->data, c->in_off, c->in_len);
        }
        if (c->in_len - c->in_off > PAUSE_IN_MAX || !ok) {
            conn_request_close(idx);
        }
        return;
    }
    uint32_t off = conn_parse(idx, c, data, 0, n);
    if (c->pass_works != works_before) {
        pass_hold_buf(buf_id);
    } else if (buf_id >= 0) {
        ring_buf_return(buf_id);
    }
    if (off < n && !(c->flags & CONN_CLOSING)) {
        if (!conn_in_append(c, data + off, n - off)) {
            conn_request_close(idx);
        }
    }
}

// Closes connections that made no progress for STALL_TIMEOUT_S; runs every SWEEP_INTERVAL_S.
static NOT_YET_USED void conn_sweep(uint32_t now_s) {
    (void)now_s;
}

// Closes up to count idle connections, least recently active first; called by the memory guard.
static NOT_YET_USED void conn_shed_idle(uint32_t count) {
    (void)count;
}
