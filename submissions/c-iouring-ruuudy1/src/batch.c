// Owner: io module. Adaptive window controller, pass bookkeeping, cohort scheduling and commit hooks.

// Defined in ring.c.
static void ring_buf_commit(void);
static void ring_rearm_flush(void);
static void ring_queue_send(uint32_t idx);
static void ring_close_conn(uint32_t idx);

// Controller level: thresholds on box-wide CPU utilization, completions to wait for and the window ceiling.
struct ctl_level {
    double up, down;
    unsigned wait_nr;
    int64_t w_max_ns;
};

static const struct ctl_level CTL_LEVELS[] = {
    {0.0, 0.0, 1, IDLE_WAIT_NS},
    {0.35, 0.28, 32, 1000000LL},
    {0.50, 0.42, 128, 4000000LL},
    {0.65, 0.57, 256, 8000000LL},
    {0.78, 0.70, 512, 15000000LL},
};

// Controller state: current level, hysteresis counters, the previous pass and the last /proc/stat sample.
struct ctl {
    unsigned level, hot, cool;
    int64_t p_last_ns;
    uint32_t p_last_requests;
    uint64_t prev_busy, prev_total;
    int stat_fd;
};

static struct ctl ctl = {.stat_fd = -1};

// Reads a decimal number at *p, skipping leading blanks; false when there is none or it overflows.
static bool batch_scan_u64(const char **p, const char *end, uint64_t *out) {
    const char *s = *p;
    uint64_t v = 0;
    while (s < end && *s == ' ') {
        s++;
    }
    if (s >= end || *s < '0' || *s > '9') {
        return false;
    }
    while (s < end && *s >= '0' && *s <= '9') {
        uint64_t d = (uint64_t)(*s - '0');
        if (v > (UINT64_MAX - d) / 10) {
            return false;
        }
        v = v * 10 + d;
        s++;
    }
    *p = s;
    *out = v;
    return true;
}

// Opens /proc/stat for pread sampling; a missing file leaves the controller at level zero.
static void ctl_init(void) {
    ctl.stat_fd = open("/proc/stat", O_RDONLY | O_CLOEXEC);
}

// Parses the aggregate "cpu" line into busy and total jiffies; false when the text is not that line.
static bool ctl_parse_cpu(const char *buf, size_t n, uint64_t *busy, uint64_t *total) {
    const char *p = buf + 3;
    const char *end = buf + n;
    uint64_t f[8] = {0};
    if (n <= 4 || memcmp(buf, "cpu ", 4) != 0) {
        return false;
    }
    for (unsigned i = 0; i < ARRAY_LEN(f); i++) {
        if (!batch_scan_u64(&p, end, &f[i])) {
            return false;
        }
    }
    *busy = f[0] + f[1] + f[2] + f[5] + f[6] + f[7];
    *total = *busy + f[3] + f[4];
    return true;
}

// Reads the aggregate cpu line and returns busy and total jiffies; false when unreadable.
static bool ctl_read_cpu(uint64_t *busy, uint64_t *total) {
    char buf[256];
    ssize_t n = ctl.stat_fd < 0 ? -1 : pread(ctl.stat_fd, buf, sizeof buf, 0);
    return n > 0 && ctl_parse_cpu(buf, (size_t)n, busy, total);
}

// Moves at most one level per sample: up after CTL_UP_SAMPLES hot samples, down after CTL_DOWN_SAMPLES cool ones.
static void ctl_step(double util) {
    unsigned top = ARRAY_LEN(CTL_LEVELS) - 1;
    ctl.hot = ctl.level < top && util >= CTL_LEVELS[ctl.level + 1].up ? ctl.hot + 1 : 0;
    ctl.cool = ctl.level && util < CTL_LEVELS[ctl.level].down ? ctl.cool + 1 : 0;
    if (ctl.hot >= CTL_UP_SAMPLES) {
        ctl.level++;
        ctl.hot = 0;
    }
    if (ctl.cool >= CTL_DOWN_SAMPLES) {
        ctl.level--;
        ctl.cool = 0;
    }
    stats.level = ctl.level;
}

// Samples /proc/stat and steps the level; called every CTL_SAMPLE_MS.
static void ctl_sample(void) {
    uint64_t busy;
    uint64_t total;
    if (!ctl_read_cpu(&busy, &total)) {
        return;
    }
    uint64_t d_total = total - ctl.prev_total;
    if (ctl.prev_total && d_total) {
        ctl_step((double)(busy - ctl.prev_busy) / (double)d_total);
    }
    ctl.prev_busy = busy;
    ctl.prev_total = total;
}

// Completions to wait for in the next wait.
static unsigned ctl_wait_nr(void) {
    return CTL_LEVELS[ctl.level].wait_nr;
}

// Wait timeout: clamp(WINDOW_TARGET - 2 * previous pass, 0, level ceiling); an idle previous pass waits the full ceiling.
static int64_t ctl_timeout_ns(void) {
    int64_t w_max = CTL_LEVELS[ctl.level].w_max_ns;
    if (ctl.level && w_max > WINDOW_CEILING_NS) {
        w_max = WINDOW_CEILING_NS;
    }
    if (!ctl.level || !ctl.p_last_requests) {
        return w_max;
    }
    int64_t t = WINDOW_TARGET_NS - 2 * ctl.p_last_ns;
    if (t < 0) {
        return 0;
    }
    return t > w_max ? w_max : t;
}

// Records the duration and request count of the pass that just ended.
static void ctl_pass_done(int64_t pass_ns, uint32_t requests) {
    ctl.p_last_ns = pass_ns;
    ctl.p_last_requests = requests;
}

// All state of the pass being built; one static instance, reset by pass_begin.
struct pass {
    uint32_t seq, n_work, n_bufs, n_touched, n_closing, n_dirty, n_eof;
    uint64_t start_ns;
    struct work work[PASS_MAX_REQUESTS + PASS_WORK_SLACK];
    uint16_t order[PASS_MAX_REQUESTS + PASS_WORK_SLACK];
    uint16_t bufs[PASS_MAX_REQUESTS + PASS_WORK_SLACK];
    uint32_t dirty[PASS_CQE_MAX + PASS_MAX_REQUESTS + PASS_WORK_SLACK];
    uint32_t touched[PASS_CQE_MAX];
    uint32_t closing[PASS_CQE_MAX + PASS_MAX_REQUESTS + PASS_WORK_SLACK];
    uint32_t eof[PASS_CQE_MAX];
};

static struct pass pass;

// Starts a new pass: clears the per-pass counts and bumps the sequence that resets per-connection state.
static void pass_begin(void) {
    pass.seq++;
    pass.n_work = 0;
    pass.n_bufs = 0;
    pass.n_touched = 0;
    pass.n_closing = 0;
    pass.n_dirty = 0;
    pass.n_eof = 0;
    pass.start_ns = util_mono_ns();
}

// True once K requests are queued; the drain loop stops taking completions then.
static bool pass_full(void) {
    return pass.n_work >= PASS_MAX_REQUESTS;
}

// Registers a connection with this pass and resets its cohort and request count on first sight.
static void pass_touch(uint32_t idx) {
    struct conn *c = conn_get(idx);
    if (c->batch_seq == pass.seq) {
        return;
    }
    c->batch_seq = pass.seq;
    c->cohort = 0;
    c->pass_works = 0;
    pass.touched[pass.n_touched++] = idx;
}

// Appends a work item for a connection; its cohort never drops below the connection's earlier requests.
static void pass_push(uint32_t idx, const struct request *req, const struct route *route) {
    struct conn *c = conn_get(idx);
    struct work *w = &pass.work[pass.n_work++];
    uint8_t cohort = route_cohort(route->kind);
    cohort = cohort < c->cohort ? c->cohort : cohort;
    c->cohort = cohort;
    c->pass_works++;
    w->req = *req;
    w->route = *route;
    w->idx = idx;
    w->blk = NULL;
    w->status = 0;
    w->cohort = cohort;
}

// Classifies a parsed request and queues it; the connection must already be touched.
static void pass_add(uint32_t idx, const struct request *req) {
    struct route route;
    route_classify(req, &route);
    pass_push(idx, req, &route);
}

// Queues the synthetic 400 for a request the parser rejected.
static void pass_add_bad_request(uint32_t idx) {
    struct request req = {0};
    struct route route = {ROUTE_BAD_REQUEST, {NULL, 0}};
    req.close_after = 1;
    pass_push(idx, &req, &route);
}

// Keeps a receive buffer alive until the pass ends because queued requests point into it.
static void pass_hold_buf(int buf_id) {
    pass.bufs[pass.n_bufs++] = (uint16_t)buf_id;
}

// Remembers a connection to close at the end of this pass.
static void pass_note_closing(uint32_t idx) {
    pass.closing[pass.n_closing++] = idx;
}

// Remembers a connection whose peer sent end of input; it closes at the end of the pass unless output is pending.
static void pass_note_eof(uint32_t idx) {
    pass.eof[pass.n_eof++] = idx;
}

// Orders execution by cohort (writes, feeds, posts, rest), stable within a cohort so per-connection order holds.
static void pass_schedule(void) {
    uint32_t start[COHORT_COUNT + 1] = {0};
    for (uint32_t i = 0; i < pass.n_work; i++) {
        start[pass.work[i].cohort + 1]++;
    }
    for (uint32_t k = 0; k < COHORT_COUNT; k++) {
        start[k + 1] += start[k];
    }
    for (uint32_t i = 0; i < pass.n_work; i++) {
        pass.order[start[pass.work[i].cohort]++] = (uint16_t)i;
    }
}

// Runs every handler in scheduled order; handlers touch the database through db_touch.
static void pass_execute(void) {
    for (uint32_t i = 0; i < pass.n_work; i++) {
        handler_run(&pass.work[pass.order[i]]);
    }
}

// Commits the pass transaction and rewrites every response of the pass as a 500 when that fails.
static void pass_commit(void) {
    if (!pass.n_work) {
        return;
    }
    stats.commits++;
    if (db_commit()) {
        return;
    }
    stats.commit_failures++;
    for (uint32_t i = 0; i < pass.n_work; i++) {
        if (pass.work[i].blk) {
            resp_rewrite_500(pass.work[i].blk);
        }
    }
}

// Lists a connection for the send step once, however many blocks it gained.
static void pass_mark_dirty(uint32_t idx) {
    struct conn *c = conn_get(idx);
    if (!(c->flags & CONN_DIRTY)) {
        c->flags |= CONN_DIRTY;
        pass.dirty[pass.n_dirty++] = idx;
    }
}

// Appends the committed responses to their connections in arrival order, which fixes per-connection order.
static void pass_publish(void) {
    for (uint32_t i = 0; i < pass.n_work; i++) {
        struct work *w = &pass.work[i];
        struct conn *c = conn_get(w->idx);
        if (!w->blk) {
            conn_request_close(w->idx);
        } else if (c->flags & CONN_CLOSING) {
            block_put(w->blk);
        } else {
            conn_queue(c, w->blk);
            pass_mark_dirty(w->idx);
        }
    }
}

// Queues one send per connection that gained output and has no send in flight.
static void pass_send(void) {
    for (uint32_t i = 0; i < pass.n_dirty; i++) {
        struct conn *c = conn_get(pass.dirty[i]);
        c->flags &= (uint16_t)~CONN_DIRTY;
        if (!(c->flags & (CONN_CLOSING | CONN_SEND_INFLIGHT)) && c->out_head) {
            ring_queue_send(pass.dirty[i]);
        }
    }
}

// Closes connections whose peer finished sending and that have nothing left to send.
static void pass_close_eof(void) {
    for (uint32_t i = 0; i < pass.n_eof; i++) {
        const struct conn *c = conn_get(pass.eof[i]);
        if ((c->flags & CONN_OPEN) && !c->out_head && !(c->flags & CONN_SEND_INFLIGHT)) {
            ring_close_conn(pass.eof[i]);
        }
    }
}

// Releases what the pass pinned: receive buffers, consumed input and connections marked for close.
static void pass_finish(void) {
    for (uint32_t i = 0; i < pass.n_bufs; i++) {
        ring_buf_return(pass.bufs[i]);
    }
    ring_buf_commit();
    ring_rearm_flush();
    for (uint32_t i = 0; i < pass.n_touched; i++) {
        conn_in_compact(conn_get(pass.touched[i]));
    }
    conn_defer_flush();
    for (uint32_t i = 0; i < pass.n_closing; i++) {
        ring_close_conn(pass.closing[i]);
    }
    pass_close_eof();
    uint64_t took = util_mono_ns() - pass.start_ns;
    stats.passes++;
    stats.requests += pass.n_work;
    stats.pass_ns_max = took > stats.pass_ns_max ? took : stats.pass_ns_max;
    ctl_pass_done((int64_t)took, pass.n_work);
}

// Counters at the previous stats line, so each line reports one interval.
struct batch_mark {
    uint64_t passes, requests, cqes, ckpt_count, ckpt_ns_total;
};

static struct batch_mark batch_prev;

// Prints the periodic stats line to stderr: this interval's passes, CQEs per pass, level and checkpoints.
static void batch_stats_print(void) {
    uint64_t passes = stats.passes - batch_prev.passes;
    uint64_t cqes = stats.cqes - batch_prev.cqes;
    uint64_t ckpts = stats.ckpt_count - batch_prev.ckpt_count;
    double ckpt_avg_ms = ckpts ? (double)(stats.ckpt_ns_total - batch_prev.ckpt_ns_total) / (double)ckpts / 1e6 : 0.0;
    // A failed write to stderr is not actionable here.
    (void)fprintf(stderr,
                  "stats passes=%llu requests=%llu cqes_per_pass=%.1f level=%u live=%u commits=%llu "
                  "commit_failures=%llu ckpts=%llu ckpt_ms_avg=%.1f ckpt_ms_max=%.1f pass_ms_max=%.1f\n",
                  (unsigned long long)passes, (unsigned long long)(stats.requests - batch_prev.requests),
                  passes ? (double)cqes / (double)passes : 0.0, stats.level, conn_live,
                  (unsigned long long)stats.commits, (unsigned long long)stats.commit_failures,
                  (unsigned long long)ckpts, ckpt_avg_ms, (double)stats.ckpt_ns_max / 1e6,
                  (double)stats.pass_ns_max / 1e6);
    batch_prev = (struct batch_mark){stats.passes, stats.requests, stats.cqes, stats.ckpt_count, stats.ckpt_ns_total};
    stats.pass_ns_max = 0;
}
