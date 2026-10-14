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
static int ring_listen_fd = -1;
static unsigned ring_accept_state = RING_ACCEPT_OFF;
static uint64_t ring_accept_tag;
static uint32_t ring_accept_gen;
static bool ring_fd_phase;

// Packs op, connection index and generation: bits 0-7 op, 8-31 index, 32-63 generation.
static uint64_t ring_tag(unsigned op, uint32_t idx, uint32_t gen) {
    return (uint64_t)op | (uint64_t)idx << 8 | (uint64_t)gen << 32;
}

// Returns an SQE, flushing the submission queue first when it is full.
static struct io_uring_sqe *ring_sqe(void) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring_io);
    while (UNLIKELY(!sqe)) {
        io_uring_submit(&ring_io);
        sqe = io_uring_get_sqe(&ring_io);
    }
    return sqe;
}

// Maps and touches the provided-buffer memory and hands every buffer to the kernel.
static void ring_setup_buffers(void) {
    int err = 0;
    size_t total = (size_t)PROV_BUF_COUNT * PROV_BUF_SIZE;
    ring_bufs = io_uring_setup_buf_ring(&ring_io, PROV_BUF_COUNT, PROV_BUF_GROUP, 0, &err);
    if (!ring_bufs) {
        util_die("provided buffer ring failed: %s", strerror(-err));
    }
    void *m = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED) {
        util_die("cannot map receive buffers");
    }
    ring_buf_mem = m;
    madvise(ring_buf_mem, total, MADV_HUGEPAGE);
    for (size_t off = 0; off < total; off += 4096) {
        ring_buf_mem[off] = 0;
    }
    for (unsigned i = 0; i < PROV_BUF_COUNT; i++) {
        io_uring_buf_ring_add(ring_bufs, ring_buf_mem + (size_t)i * PROV_BUF_SIZE, PROV_BUF_SIZE, (unsigned short)i,
                              io_uring_buf_ring_mask(PROV_BUF_COUNT), (int)i);
    }
    io_uring_buf_ring_advance(ring_bufs, PROV_BUF_COUNT);
}

// Creates the ring with the 6.8 feature set, retrying without NO_SQARRAY, and registers files and buffers.
static void ring_init(int listen_fd) {
    struct io_uring_params p = {0};
    struct rlimit rl;
    p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SUBMIT_ALL | IORING_SETUP_CQSIZE |
              IORING_SETUP_TASKRUN_FLAG | IORING_SETUP_NO_SQARRAY;
    p.cq_entries = RING_CQ_ENTRIES;
    int rc = io_uring_queue_init_params(RING_SQ_ENTRIES, &ring_io, &p);
    if (rc == -EINVAL) {
        memset(&p, 0, sizeof p);
        p.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SUBMIT_ALL |
                  IORING_SETUP_CQSIZE | IORING_SETUP_TASKRUN_FLAG;
        p.cq_entries = RING_CQ_ENTRIES;
        rc = io_uring_queue_init_params(RING_SQ_ENTRIES, &ring_io, &p);
    }
    if (rc < 0) {
        util_die("io_uring setup failed: %s", strerror(-rc));
    }
    io_uring_register_ring_fd(&ring_io);
    getrlimit(RLIMIT_NOFILE, &rl);
    unsigned slots = rl.rlim_cur < DIRECT_SLOTS ? (unsigned)rl.rlim_cur : DIRECT_SLOTS;
    rc = io_uring_register_files_sparse(&ring_io, slots);
    if (rc < 0) {
        util_die("registering %u direct slots failed: %s", slots, strerror(-rc));
    }
    ring_setup_buffers();
    ring_listen_fd = listen_fd;
}

// Hands a receive buffer back to the kernel; it becomes visible at the next ring_buf_commit.
static void ring_buf_return(int buf_id) {
    io_uring_buf_ring_add(ring_bufs, ring_buf_mem + (size_t)buf_id * PROV_BUF_SIZE, PROV_BUF_SIZE,
                          (unsigned short)buf_id, io_uring_buf_ring_mask(PROV_BUF_COUNT), (int)ring_buf_pending);
    ring_buf_pending++;
}

// Publishes every buffer returned since the last commit with one tail update.
static void ring_buf_commit(void) {
    if (ring_buf_pending) {
        io_uring_buf_ring_advance(ring_bufs, (int)ring_buf_pending);
        ring_buf_pending = 0;
    }
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

// Picks the accept mode: off when the gate is closed, normal fds past ACCEPT_DIRECT_LIMIT until below ACCEPT_DIRECT_RESUME.
static void ring_accept_update(bool gate_open) {
    unsigned want = RING_ACCEPT_OFF;
    if (conn_direct_live >= ACCEPT_DIRECT_LIMIT) {
        ring_fd_phase = true;
    } else if (conn_direct_live < ACCEPT_DIRECT_RESUME) {
        ring_fd_phase = false;
    }
    if (gate_open) {
        want = ring_fd_phase ? RING_ACCEPT_FD : RING_ACCEPT_DIRECT;
    }
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

// Sends the unsent remainder of the head output block; one send per connection is in flight at a time.
static void ring_queue_send(uint32_t idx) {
    struct conn *c = conn_get(idx);
    struct block *b = c->out_head;
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

// Shuts down and closes a connection and releases its record; waits while a send is in flight.
static void ring_close_conn(uint32_t idx) {
    struct conn *c = conn_get(idx);
    if (!(c->flags & CONN_OPEN) || (c->flags & CONN_SEND_INFLIGHT)) {
        return;
    }
    int target = conn_target(idx);
    uint8_t fixed = conn_is_direct(idx) ? IOSQE_FIXED_FILE : 0;
    struct io_uring_sqe *sqe = ring_sqe();
    io_uring_prep_shutdown(sqe, target, SHUT_RDWR);
    sqe->flags |= (uint8_t)(fixed | IOSQE_IO_HARDLINK | IOSQE_CQE_SKIP_SUCCESS);
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_IGNORE, 0, 0));
    sqe = ring_sqe();
    if (conn_is_direct(idx)) {
        io_uring_prep_close_direct(sqe, (unsigned)target);
    } else {
        io_uring_prep_close(sqe, target);
    }
    sqe->flags |= IOSQE_CQE_SKIP_SUCCESS;
    io_uring_sqe_set_data64(sqe, ring_tag(RING_OP_IGNORE, 0, 0));
    conn_release(idx);
}

// Marks a connection for close at the end of the pass, re-listing it when it was already marked.
static void ring_close_later(uint32_t idx) {
    if (conn_get(idx)->flags & CONN_CLOSING) {
        pass_note_closing(idx);
    } else {
        conn_request_close(idx);
    }
}

// Handles an accept completion; a direct slot or normal fd becomes a connection with its receive armed.
static void ring_on_accept(const struct io_uring_cqe *cqe, bool direct) {
    int res = cqe->res;
    if (res >= 0) {
        uint32_t idx = direct ? (uint32_t)res : DIRECT_SLOTS + (uint32_t)res;
        if (idx >= CONN_MAX || (!direct && res >= NORMAL_FD_MAX)) {
            close(res);
        } else {
            conn_open(idx);
            ring_queue_recv(idx);
        }
    } else if (res == -ENFILE) {
        ring_fd_phase = true;
    } else if (res != -ECANCELED) {
        util_log_limited(1, "accept failed: %s", strerror(-res));
    }
    if (!(cqe->flags & IORING_CQE_F_MORE) && cqe->user_data == ring_accept_tag && ring_accept_state != RING_ACCEPT_OFF) {
        ring_accept_arm(ring_fd_phase ? RING_ACCEPT_FD : RING_ACCEPT_DIRECT);
    }
}

// Handles a receive completion: feeds data to the connection, or marks it for close on EOF or error.
static void ring_on_recv(const struct io_uring_cqe *cqe, uint32_t idx, uint32_t gen) {
    struct conn *c = conn_get(idx);
    bool has_buf = cqe->flags & IORING_CQE_F_BUFFER;
    int buf_id = (int)(cqe->flags >> IORING_CQE_BUFFER_SHIFT);
    int res = cqe->res;
    if (c->gen != gen || !(c->flags & CONN_OPEN) || (c->flags & CONN_CLOSING)) {
        if (has_buf) {
            ring_buf_return(buf_id);
        }
        return;
    }
    if (!(cqe->flags & IORING_CQE_F_MORE)) {
        c->flags &= (uint16_t)~CONN_RECV_ARMED;
    }
    if (res > 0 && has_buf) {
        conn_feed(idx, (char *)ring_buf_mem + (size_t)buf_id * PROV_BUF_SIZE, (uint32_t)res, buf_id);
    } else if (res == -ENOBUFS) {
        ring_buf_commit();
    } else if (res != -ECANCELED) {
        if (has_buf) {
            ring_buf_return(buf_id);
        }
        conn_request_close(idx);
    }
    if (!(c->flags & (CONN_RECV_ARMED | CONN_CLOSING | CONN_STOP_PARSE)) && (res > 0 || res == -ENOBUFS)) {
        ring_queue_recv(idx);
    }
}

// Handles a send completion: advances or pops the head block, sends the next one and resumes a paused connection.
static void ring_on_send(const struct io_uring_cqe *cqe, uint32_t idx, uint32_t gen) {
    struct conn *c = conn_get(idx);
    if (c->gen != gen || !(c->flags & CONN_OPEN)) {
        return;
    }
    c->flags &= (uint16_t)~CONN_SEND_INFLIGHT;
    if (cqe->res < 0) {
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
    } else if (c->flags & CONN_CLOSE_AFTER_SEND) {
        conn_request_close(idx);
    }
    if ((c->flags & CONN_PAUSED) && c->out_blocks <= PAUSE_RESUME_BLOCKS) {
        c->flags &= (uint16_t)~CONN_PAUSED;
        conn_feed(idx, NULL, 0, -1);
    }
}

// Dispatches one completion by the operation packed in its tag; stale generations are dropped.
static void ring_handle_cqe(const struct io_uring_cqe *cqe) {
    uint64_t tag = cqe->user_data;
    uint32_t idx = (uint32_t)(tag >> 8) & 0xFFFFFF;
    uint32_t gen = (uint32_t)(tag >> 32);
    stats.cqes++;
    switch (tag & 0xFF) {
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
    default:
        break;
    }
}

// Submits queued SQEs and waits for wait_nr completions or the timeout; -ETIME, -EINTR and -EBUSY are normal.
static void ring_wait(unsigned wait_nr, int64_t timeout_ns) {
    struct __kernel_timespec ts = {.tv_sec = timeout_ns / 1000000000LL, .tv_nsec = timeout_ns % 1000000000LL};
    struct io_uring_cqe *cqe;
    int rc = io_uring_submit_and_wait_timeout(&ring_io, &cqe, wait_nr ? wait_nr : 1, &ts, NULL);
    if (rc < 0 && rc != -ETIME && rc != -EINTR && rc != -EBUSY && rc != -EAGAIN) {
        util_log_limited(2, "ring wait failed: %s", strerror(-rc));
    }
}

// Handles completions until the pass holds K requests or PASS_CQE_MAX completions were taken.
static void ring_drain(void) {
    unsigned head;
    unsigned seen = 0;
    struct io_uring_cqe *cqe;
    io_uring_for_each_cqe(&ring_io, head, cqe) {
        if (pass_full() || seen >= PASS_CQE_MAX) {
            break;
        }
        ring_handle_cqe(cqe);
        seen++;
    }
    io_uring_cq_advance(&ring_io, seen);
}

// Submits every queued SQE without waiting.
static void ring_submit(void) {
    io_uring_submit(&ring_io);
}
