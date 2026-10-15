// Owner: io module. The one io_uring: setup, accept, receive, send, close and completion dispatch.

// Operation kinds packed into the low byte of every SQE tag.
enum ring_op {
    RING_OP_ACCEPT_DIRECT = 1,
    RING_OP_ACCEPT_FD,
    RING_OP_RECV,
    RING_OP_SEND,
    RING_OP_IGNORE,
};

enum ring_accept_mode {
    RING_ACCEPT_OFF,
    RING_ACCEPT_DIRECT,
    RING_ACCEPT_FD,
};

static struct io_uring ring_io;
static struct io_uring_buf_ring *ring_bufs;
static uint8_t *ring_buf_mem;
static unsigned ring_buf_pending;
static bool ring_buf_legacy;
static bool ring_force_legacy;
static uint16_t ring_buf_ids[PROV_BUF_COUNT];
static int ring_listen_fd = -1;
static unsigned ring_accept_state = RING_ACCEPT_OFF;
static uint64_t ring_accept_tag;
static uint32_t ring_accept_gen;
static bool ring_fd_phase;
static bool ring_gate_open;
static unsigned ring_direct_limit = ACCEPT_DIRECT_LIMIT;
static unsigned ring_direct_resume = ACCEPT_DIRECT_RESUME;
static unsigned ring_accept_errs;
static uint64_t ring_accept_retry_ns;
static bool ring_backlog;
static bool ring_min_wait;
static uint64_t ring_rearm[PASS_CQE_MAX];
static uint32_t ring_rearm_n;
static uint64_t ring_stat_enobufs;
static uint64_t ring_stat_enfile;
static struct io_uring_sqe ring_sqe_dummy;

// Packs op, connection index and generation: bits 0-7 op, 8-31 index, 32-63 generation.
static uint64_t ring_tag(unsigned op, uint32_t idx, uint32_t gen) {
    return (uint64_t)op | (uint64_t)idx << 8 | (uint64_t)gen << 32;
}

// Returns an SQE, flushing the submission queue when it is full; a stuck queue yields a scratch entry that is never sent.
static struct io_uring_sqe *ring_sqe(void) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring_io);
    for (unsigned tries = 0; !sqe && tries < RING_SQE_RETRIES; tries++) {
        // A failed flush leaves the queue full, which the next attempt and the final fallback handle.
        (void)io_uring_submit(&ring_io);
        sqe = io_uring_get_sqe(&ring_io);
    }
    if (UNLIKELY(!sqe)) {
        util_log_limited(3, "submission queue stuck, dropping an operation");
        memset(&ring_sqe_dummy, 0, sizeof ring_sqe_dummy);
        return &ring_sqe_dummy;
    }
    return sqe;
}

// Hands every buffer to the kernel as classic provided buffers, for kernels that refuse a provided-buffer ring.
static void ring_provide_legacy(void) {
    struct io_uring_cqe *cqe;
    struct io_uring_sqe *sqe = ring_sqe();
    io_uring_prep_provide_buffers(sqe, ring_buf_mem, PROV_BUF_SIZE, PROV_BUF_COUNT, PROV_BUF_GROUP, 0);
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_IGNORE, 0, 0));
    int rc = io_uring_submit_and_wait(&ring_io, 1);
    if (rc >= 0) {
        rc = io_uring_wait_cqe(&ring_io, &cqe);
    }
    if (rc >= 0) {
        rc = cqe->res;
        io_uring_cqe_seen(&ring_io, cqe);
    }
    if (rc < 0) {
        util_die("provided buffers failed: %s", strerror(-rc));
    }
    ring_buf_legacy = true;
}

// Maps and touches the receive memory and hands every buffer to the kernel, by ring where the kernel allows it.
static void ring_setup_buffers(void) {
    int err = -EINVAL;
    size_t total = (size_t)PROV_BUF_COUNT * PROV_BUF_SIZE;
    ring_buf_mem = pool_map(total);
    if (!ring_buf_mem) {
        util_die("cannot map receive buffers");
    }
    pool_touch(ring_buf_mem, total);
    if (!ring_force_legacy) {
        ring_bufs = io_uring_setup_buf_ring(&ring_io, PROV_BUF_COUNT, PROV_BUF_GROUP, 0, &err);
    }
    if (!ring_bufs) {
        // Ubuntu 24.04's 6.8 kernels answer EINVAL to a provided-buffer ring, so classic buffers are the fallback.
        fprintf(stderr, "provided-buffer ring unavailable (%s), using classic provided buffers\n", strerror(-err));
        ring_provide_legacy();
        return;
    }
    for (unsigned i = 0; i < PROV_BUF_COUNT; i++) {
        io_uring_buf_ring_add(ring_bufs, ring_buf_mem + (size_t)i * PROV_BUF_SIZE, PROV_BUF_SIZE, (unsigned short)i,
                              io_uring_buf_ring_mask(PROV_BUF_COUNT), (int)i);
    }
    io_uring_buf_ring_advance(ring_bufs, PROV_BUF_COUNT);
}

// Creates the ring with the given extra setup flags on top of the 6.8 feature set.
static int ring_create(struct io_uring_params *p, unsigned extra_flags) {
    memset(p, 0, sizeof *p);
    p->flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE |
               IORING_SETUP_TASKRUN_FLAG | extra_flags;
    p->cq_entries = RING_CQ_ENTRIES;
    return io_uring_queue_init_params(RING_SQ_ENTRIES, &ring_io, p);
}

// Registers the sparse direct file table and scales the accept hand-off to its size.
static void ring_register_files(void) {
    struct rlimit rl;
    unsigned slots = DIRECT_SLOTS;
    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur < DIRECT_SLOTS) {
        slots = (unsigned)rl.rlim_cur;
    }
    int rc = io_uring_register_files_sparse(&ring_io, slots);
    if (rc < 0) {
        util_die("registering %u direct slots failed: %s", slots, strerror(-rc));
    }
    ring_direct_limit = (unsigned)((uint64_t)slots * ACCEPT_DIRECT_LIMIT / DIRECT_SLOTS);
    ring_direct_resume = (unsigned)((uint64_t)slots * ACCEPT_DIRECT_RESUME / DIRECT_SLOTS);
}

// Creates the ring (retrying without NO_SQARRAY), probes optional features and registers files and buffers.
static void ring_init(int listen_fd) {
    struct io_uring_params p;
    int rc = ring_create(&p, IORING_SETUP_NO_SQARRAY);
    if (rc == -EINVAL) {
        rc = ring_create(&p, 0);
    }
    if (rc < 0) {
        util_die("io_uring setup failed: %s", strerror(-rc));
    }
    ring_min_wait = p.features & IORING_FEAT_MIN_TIMEOUT;
    if (io_uring_register_ring_fd(&ring_io) < 0) {
        util_log_limited(2, "registered ring fd unavailable");
    }
    ring_register_files();
    ring_setup_buffers();
    ring_listen_fd = listen_fd;
}

// Hands a receive buffer back to the kernel; it becomes visible at the next ring_buf_commit.
static void ring_buf_return(int buf_id) {
    if (ring_buf_legacy) {
        ring_buf_ids[ring_buf_pending] = (uint16_t)buf_id;
    } else {
        io_uring_buf_ring_add(ring_bufs, ring_buf_mem + (size_t)buf_id * PROV_BUF_SIZE, PROV_BUF_SIZE,
                              (unsigned short)buf_id, io_uring_buf_ring_mask(PROV_BUF_COUNT), (int)ring_buf_pending);
    }
    ring_buf_pending++;
}

// Provides the returned classic buffers again, one SQE per run of consecutive buffer ids.
static void ring_buf_commit_legacy(void) {
    unsigned i = 0;
    while (i < ring_buf_pending) {
        unsigned first = ring_buf_ids[i];
        unsigned run = 1;
        while (i + run < ring_buf_pending && ring_buf_ids[i + run] == first + run) {
            run++;
        }
        struct io_uring_sqe *sqe = ring_sqe();
        io_uring_prep_provide_buffers(sqe, ring_buf_mem + (size_t)first * PROV_BUF_SIZE, PROV_BUF_SIZE, (int)run,
                                      PROV_BUF_GROUP, (int)first);
        io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_IGNORE, 0, 0));
        sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
        i += run;
    }
}

// Publishes every buffer returned since the last commit with one tail update, or one SQE per run of classic buffers.
static void ring_buf_commit(void) {
    if (!ring_buf_pending) {
        return;
    }
    if (ring_buf_legacy) {
        ring_buf_commit_legacy();
    } else {
        io_uring_buf_ring_advance(ring_bufs, (int)ring_buf_pending);
    }
    ring_buf_pending = 0;
}

// Arms a multishot accept: direct descriptors, or normal fds once the direct table is nearly full.
static void ring_accept_arm(unsigned mode) {
    struct io_uring_sqe *sqe = ring_sqe();
    if (mode == RING_ACCEPT_DIRECT) {
        io_uring_prep_multishot_accept_direct(sqe, ring_listen_fd, NULL, NULL, 0);
    } else {
        io_uring_prep_multishot_accept(sqe, ring_listen_fd, NULL, NULL, 0);
    }
    ring_accept_tag = ring_tag(mode == RING_ACCEPT_DIRECT ? RING_OP_ACCEPT_DIRECT : RING_OP_ACCEPT_FD, 0, ++ring_accept_gen);
    io_uring_sqe_set_data64(sqe, ring_accept_tag);
    ring_accept_state = mode;
}

// Cancels the armed accept; connections it already completed are still delivered.
static void ring_accept_cancel(void) {
    struct io_uring_sqe *sqe = ring_sqe();
    io_uring_prep_cancel64(sqe, ring_accept_tag, 0);
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_IGNORE, 0, 0));
    sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
    ring_accept_state = RING_ACCEPT_OFF;
}

// Picks the accept mode: off when the gate is closed, normal fds past the direct limit until below the resume mark.
static unsigned ring_accept_want(bool gate_open) {
    if (conn_direct_live >= ring_direct_limit) {
        ring_fd_phase = true;
    } else if (conn_direct_live < ring_direct_resume) {
        ring_fd_phase = false;
    }
    if (!gate_open) {
        return RING_ACCEPT_OFF;
    }
    return ring_fd_phase ? RING_ACCEPT_FD : RING_ACCEPT_DIRECT;
}

// Moves accept to the mode the gate and the live direct count call for, honouring the error backoff.
static void ring_accept_update(bool gate_open) {
    ring_gate_open = gate_open;
    if (ring_accept_retry_ns) {
        if (clk.mono_ns < ring_accept_retry_ns) {
            return;
        }
        ring_accept_retry_ns = 0;
    }
    unsigned want = ring_accept_want(gate_open);
    if (want == ring_accept_state) {
        return;
    }
    if (ring_accept_state != RING_ACCEPT_OFF) {
        ring_accept_cancel();
    }
    if (want != RING_ACCEPT_OFF) {
        ring_accept_arm(want);
    }
}

// Arms a multishot receive into the provided-buffer group.
static void ring_queue_recv(uint32_t idx) {
    struct conn *c = conn_get(idx);
    struct io_uring_sqe *sqe = ring_sqe();
    io_uring_prep_recv_multishot(sqe, conn_target(idx), NULL, 0, 0);
    sqe->flags |= (uint8_t)(IOSQE_BUFFER_SELECT | (conn_is_direct(idx) ? IOSQE_FIXED_FILE : 0));
    sqe->buf_group = PROV_BUF_GROUP;
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_RECV, idx, c->gen));
    c->flags |= CONN_RECV_ARMED;
}

// Cancels the armed receive of a paused connection so the socket buffer, not our memory, absorbs the burst.
static void ring_recv_cancel(uint32_t idx) {
    struct conn *c = conn_get(idx);
    struct io_uring_sqe *sqe = ring_sqe();
    io_uring_prep_cancel64(sqe, ring_tag(RING_OP_RECV, idx, c->gen), 0);
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_IGNORE, 0, 0));
    sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
    c->flags |= CONN_RECV_CANCEL;
}

// Brings the receive in line with the connection state: cancelled while paused, armed otherwise.
static void ring_recv_sync(uint32_t idx) {
    const struct conn *c = conn_get(idx);
    if (!(c->flags & CONN_OPEN) || (c->flags & (CONN_CLOSING | CONN_STOP_PARSE | CONN_RECV_WAIT_BUFS))) {
        return;
    }
    if (c->flags & CONN_PAUSED) {
        if ((c->flags & CONN_RECV_ARMED) && !(c->flags & CONN_RECV_CANCEL)) {
            ring_recv_cancel(idx);
        }
        return;
    }
    if (!(c->flags & CONN_RECV_ARMED)) {
        ring_queue_recv(idx);
    }
}

// Re-arms the receives that ended with -ENOBUFS; runs once the pass has returned its buffers.
static void ring_rearm_flush(void) {
    for (uint32_t i = 0; i < ring_rearm_n; i++) {
        uint32_t idx = (uint32_t)(ring_rearm[i] >> 8) & 0xFFFFFF;
        struct conn *c = conn_get(idx);
        if (c->gen == (uint32_t)(ring_rearm[i] >> 32) && (c->flags & CONN_OPEN)) {
            c->flags &= (uint16_t)~CONN_RECV_WAIT_BUFS;
            ring_recv_sync(idx);
        }
    }
    ring_rearm_n = 0;
}

// Sends the unsent remainder of the head output block; one send per connection is in flight at a time.
static void ring_queue_send(uint32_t idx) {
    struct conn *c = conn_get(idx);
    const struct block *b = c->out_head;
    struct io_uring_sqe *sqe = ring_sqe();
    io_uring_prep_send(sqe, conn_target(idx), b->data + b->off + c->sent, b->len - c->sent, MSG_NOSIGNAL);
    sqe->flags |= conn_is_direct(idx) ? IOSQE_FIXED_FILE : 0;
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_SEND, idx, c->gen));
    c->flags |= CONN_SEND_INFLIGHT;
}

// Queues a kernel write-back hint for a byte range of the WAL.
static void ring_queue_wal_sync(int fd, uint64_t off, uint32_t len) {
    struct io_uring_sqe *sqe = ring_sqe();
    io_uring_prep_sync_file_range(sqe, fd, len, off, SYNC_FILE_RANGE_WRITE);
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_IGNORE, 0, 0));
    sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
}

// Queues shutdown(SHUT_RDWR) on a connection; hard-linked to the next SQE when a close follows.
static void ring_queue_shutdown(uint32_t idx, bool linked) {
    struct io_uring_sqe *sqe = ring_sqe();
    io_uring_prep_shutdown(sqe, conn_target(idx), SHUT_RDWR);
    sqe->flags |= (uint8_t)((conn_is_direct(idx) ? IOSQE_FIXED_FILE : 0) | (linked ? IOSQE_IO_HARDLINK : 0) |
                            IOSQE_CQE_SKIP_SUCCESS);
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_IGNORE, 0, 0));
}

// Queues the close of a descriptor target: a direct slot or a normal fd.
static void ring_queue_close(int target, bool direct) {
    struct io_uring_sqe *sqe = ring_sqe();
    if (direct) {
        io_uring_prep_close_direct(sqe, (unsigned)target);
    } else {
        io_uring_prep_close(sqe, target);
    }
    sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_IGNORE, 0, 0));
}

// Shuts down and closes a connection and releases its record; waits while a send is in flight.
static void ring_close_conn(uint32_t idx) {
    const struct conn *c = conn_get(idx);
    if (!(c->flags & CONN_OPEN) || (c->flags & CONN_SEND_INFLIGHT)) {
        return;
    }
    ring_queue_shutdown(idx, true);
    ring_queue_close(conn_target(idx), conn_is_direct(idx));
    conn_release(idx);
}

// Ends a connection outside a pass: closes it now, or only shuts it down while a send is in flight.
static void ring_kill_conn(uint32_t idx) {
    const struct conn *c = conn_get(idx);
    if (!(c->flags & CONN_OPEN)) {
        return;
    }
    if (c->flags & CONN_SEND_INFLIGHT) {
        ring_queue_shutdown(idx, false);
        return;
    }
    ring_close_conn(idx);
}

// Marks a connection for close at the end of the pass, re-listing it when it was already marked.
static void ring_close_later(uint32_t idx) {
    if (conn_get(idx)->flags & CONN_CLOSING) {
        pass_note_closing(idx);
    } else {
        conn_request_close(idx);
    }
}

// Turns an accepted descriptor into a connection with its receive armed; refuses an index that is already in use.
static void ring_accept_conn(int res, bool direct) {
    uint32_t idx = direct ? (uint32_t)res : DIRECT_SLOTS + (uint32_t)res;
    bool bad = !direct && res >= NORMAL_FD_MAX;
    if (bad || idx >= CONN_MAX || (conn_get(idx)->flags & CONN_OPEN)) {
        util_log_limited(1, "accepted descriptor %d refused", res);
        ring_queue_close(res, direct);
        return;
    }
    conn_open(idx);
    ring_queue_recv(idx);
    if (ring_accept_state == RING_ACCEPT_DIRECT && conn_direct_live >= ring_direct_limit) {
        ring_accept_update(ring_gate_open);
    }
}

// Applies the defined action to a failed accept: count it, and note a full direct table.
static void ring_accept_error(int res) {
    if (res == -ECANCELED) {
        return;
    }
    if (res == -ENFILE && !ring_fd_phase) {
        ring_stat_enfile++;
        ring_fd_phase = true;
        util_log_limited(1, "direct table full, accepting on normal descriptors");
        return;
    }
    ring_accept_errs++;
    util_log_limited(1, "accept failed: %s", strerror(-res));
}

// Re-arms a terminated accept, or leaves it off for ACCEPT_BACKOFF_NS after a burst of errors.
static void ring_accept_continue(const struct io_uring_cqe *cqe) {
    if ((cqe->flags & IORING_CQE_F_MORE) || cqe->user_data != ring_accept_tag || ring_accept_state == RING_ACCEPT_OFF) {
        return;
    }
    if (ring_accept_errs >= ACCEPT_ERR_BURST) {
        ring_accept_state = RING_ACCEPT_OFF;
        ring_accept_retry_ns = clk.mono_ns + ACCEPT_BACKOFF_NS;
        return;
    }
    ring_accept_arm(ring_fd_phase ? RING_ACCEPT_FD : RING_ACCEPT_DIRECT);
}

// Handles an accept completion.
static void ring_on_accept(const struct io_uring_cqe *cqe, bool direct) {
    if (cqe->res >= 0) {
        ring_accept_errs = 0;
        ring_accept_conn(cqe->res, direct);
    } else {
        ring_accept_error(cqe->res);
    }
    ring_accept_continue(cqe);
}

// Applies the defined action to a receive that returned no data.
static void ring_on_recv_end(uint32_t idx, int res) {
    switch (res) {
    case 0:
        conn_peer_closed(idx);
        break;
    case -ENOBUFS:
        ring_stat_enobufs++;
        ring_buf_commit();
        conn_get(idx)->flags |= CONN_RECV_WAIT_BUFS;
        ring_rearm[ring_rearm_n++] = ring_tag(RING_OP_RECV, idx, conn_get(idx)->gen);
        break;
    case -ECANCELED:
        break;
    default:
        conn_request_close(idx);
        break;
    }
}

// Handles a receive completion: feeds data to the connection, or applies the defined action for EOF and errors.
static void ring_on_recv(const struct io_uring_cqe *cqe, uint32_t idx, uint32_t gen) {
    struct conn *c = conn_get(idx);
    bool has_buf = cqe->flags & IORING_CQE_F_BUFFER;
    int buf_id = (int)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    if (c->gen != gen || !(c->flags & CONN_OPEN) || (c->flags & CONN_CLOSING)) {
        if (has_buf) {
            ring_buf_return(buf_id);
        }
        return;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        c->flags &= (uint16_t) ~(CONN_RECV_ARMED | CONN_RECV_CANCEL);
    }
    if (cqe->res > 0 && has_buf) {
        conn_feed(idx, (char *)ring_buf_mem + (size_t)buf_id * PROV_BUF_SIZE, (uint32_t)cqe->res, buf_id);
    } else {
        if (has_buf) {
            ring_buf_return(buf_id);
        }
        ring_on_recv_end(idx, cqe->res > 0 ? -EIO : cqe->res);
    }
    ring_recv_sync(idx);
}

// Resumes a paused connection once its output has drained below the resume mark.
static void ring_resume(uint32_t idx, struct conn *c) {
    if ((c->flags & CONN_PAUSED) && c->out_blocks <= PAUSE_RESUME_BLOCKS) {
        c->flags &= (uint16_t)~CONN_PAUSED;
        conn_feed(idx, NULL, 0, -1);
        ring_recv_sync(idx);
    }
}

// Handles a send completion: advances or pops the head block, sends the next one and resumes a paused connection.
static void ring_on_send(const struct io_uring_cqe *cqe, uint32_t idx, uint32_t gen) {
    struct conn *c = conn_get(idx);
    if (c->gen != gen || !(c->flags & CONN_OPEN)) {
        return;
    }
    c->flags &= (uint16_t)~CONN_SEND_INFLIGHT;
    if (cqe->res <= 0 || !c->out_head) {
        ring_close_later(idx);
        return;
    }
    c->sent += (uint32_t)cqe->res;
    c->last_active_s = (uint32_t)(clk.mono_ns / 1000000000ULL);
    if (c->sent >= c->out_head->len) {
        conn_out_pop(c);
    }
    if (c->flags & CONN_CLOSING) {
        ring_close_later(idx);
    } else if (c->out_head) {
        ring_queue_send(idx);
        ring_resume(idx, c);
    } else if (c->flags & CONN_CLOSE_AFTER_SEND) {
        conn_request_close(idx);
    } else {
        ring_resume(idx, c);
    }
}

// Dispatches one completion by the operation packed in its tag; stale generations are dropped.
static void ring_handle_cqe(const struct io_uring_cqe *cqe) {
    uint64_t tag = cqe->user_data;
    uint32_t idx = (uint32_t)(tag >> 8) & 0xFFFFFF;
    uint32_t gen = (uint32_t)(tag >> 32);
    unsigned op = (unsigned)(tag & 0xFF);
    stats.cqes++;
    if ((op == RING_OP_RECV || op == RING_OP_SEND) && idx >= CONN_MAX) {
        return;
    }
    switch (op) {
    case RING_OP_ACCEPT_DIRECT:
        ring_on_accept(cqe, true);
        break;
    case RING_OP_ACCEPT_FD:
        ring_on_accept(cqe, false);
        break;
    case RING_OP_RECV:
        ring_on_recv(cqe, idx, gen);
        break;
    case RING_OP_SEND:
        ring_on_send(cqe, idx, gen);
        break;
    case RING_OP_IGNORE:
    default:
        break;
    }
}

// Shortens the wait so a pending accept backoff is retried on time.
static int64_t ring_cap_timeout(int64_t timeout_ns) {
    if (!ring_accept_retry_ns) {
        return timeout_ns;
    }
    int64_t due = (int64_t)ring_accept_retry_ns - (int64_t)util_mono_ns();
    if (due < 0) {
        due = 0;
    }
    return due < timeout_ns ? due : timeout_ns;
}

// Waits for wait_nr completions or the timeout; submits first, and with no sleep when work is already queued.
static int ring_wait_kernel(unsigned wait_nr, int64_t timeout_ns) {
    struct __kernel_timespec ts = {.tv_sec = timeout_ns / 1000000000LL, .tv_nsec = timeout_ns % 1000000000LL};
    struct io_uring_cqe *cqe;
    if (timeout_ns <= 0 || (PASS_WAIT_SKIP_BACKLOG && ring_backlog)) {
        return io_uring_submit_and_get_events(&ring_io);
    }
    if (RING_USE_MIN_WAIT && ring_min_wait) {
        return io_uring_submit_and_wait_min_timeout(&ring_io, &cqe, wait_nr, &ts, RING_MIN_WAIT_US, NULL);
    }
    return io_uring_submit_and_wait_timeout(&ring_io, &cqe, wait_nr, &ts, NULL);
}

// Submits queued SQEs and waits for wait_nr completions or the timeout; -ETIME, -EINTR and -EBUSY are normal.
static void ring_wait(unsigned wait_nr, int64_t timeout_ns) {
    int rc = ring_wait_kernel(wait_nr ? wait_nr : 1, ring_cap_timeout(timeout_ns));
    if (rc < 0 && rc != -ETIME && rc != -EINTR && rc != -EBUSY && rc != -EAGAIN) {
        util_log_limited(2, "ring wait failed: %s", strerror(-rc));
    }
}

// Handles completions until the pass holds K requests or PASS_CQE_MAX completions were taken.
static void ring_drain(void) {
    unsigned head;
    unsigned seen = 0;
    struct io_uring_cqe *cqe;
    ring_backlog = false;
    io_uring_for_each_cqe(&ring_io, head, cqe) {
        if (pass_full() || seen >= PASS_CQE_MAX) {
            ring_backlog = true;
            break;
        }
        ring_handle_cqe(cqe);
        seen++;
    }
    io_uring_cq_advance(&ring_io, seen);
}

// Submits every queued SQE without waiting; a busy or interrupted submit is retried at the next wait.
static void ring_submit(void) {
    int rc = io_uring_submit(&ring_io);
    if (rc < 0 && rc != -EBUSY && rc != -EAGAIN && rc != -EINTR) {
        util_log_limited(2, "ring submit failed: %s", strerror(-rc));
    }
}
