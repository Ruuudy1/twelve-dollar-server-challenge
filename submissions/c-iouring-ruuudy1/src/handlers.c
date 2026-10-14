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
static NOT_YET_USED char handler_scratch[SCRATCH_SIZE];

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

// Placeholder for routes the db module has not written yet: answers 404 not found.
static void handle_unimplemented(const struct work *w, struct resp *r) {
    resp_error(r, ERR_NOT_FOUND, w->req.close_after);
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
    case ROUTE_BAD_REQUEST:
        resp_error(&r, ERR_BAD_REQUEST, true);
        break;
    case ROUTE_FEED:
    case ROUTE_POST:
    case ROUTE_CREATE:
    case ROUTE_LIKE:
    case ROUTE_NOT_FOUND:
    default:
        handle_unimplemented(w, &r);
        break;
    }
    w->blk = r.blk;
    w->status = r.blk->status;
}
