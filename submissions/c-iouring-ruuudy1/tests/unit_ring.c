// Ring tests: injected completions (stale generations, -ENOBUFS, EOF, errors, accept errors) in this process, and a
// forked server with a small descriptor limit that exercises the normal-fd accept phase and -ENFILE over loopback.
#define FM_TEST 1
#include "../src/main.c"
#include "test_util.h"

#include <sys/wait.h>

#define SERVER_DB "/tmp/unit_ring_server.db"

// What the forked server reports when it is told to stop.
struct child_result {
    uint64_t enfile, enobufs;
    uint32_t live, direct_live;
    int fd_phase;
};

// Runs a server in a child process with the given descriptor limit; returns its pid and a pipe for its report.
static pid_t spawn_server(int port, rlim_t nofile, bool force_enfile, int *report_fd) {
    int p[2];
    char port_text[16];
    snprintf(port_text, sizeof port_text, "%d", port);
    if (pipe(p)) {
        exit(2);
    }
    pid_t pid = fork();
    if (pid) {
        close(p[1]);
        *report_fd = p[0];
        return pid;
    }
    close(p[0]);
    struct rlimit rl = {nofile, nofile};
    setrlimit(RLIMIT_NOFILE, &rl);
    struct main_config cfg = {.sqlite_path = SERVER_DB, .jwt_secret = "secret", .host = "127.0.0.1", .port = port};
    main_startup(&cfg);
    if (force_enfile) {
        ring_direct_limit = 1000000;
    }
    while (!stop_flag) {
        main_pass();
    }
    struct child_result r = {ring_stat_enfile, ring_stat_enobufs, conn_live, conn_direct_live, ring_fd_phase};
    if (write(p[1], &r, sizeof r) != (ssize_t)sizeof r) {
        _exit(3);
    }
    _exit(0);
}

// Connects to the loopback server, retrying while it starts.
static int client_connect(int port) {
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)};
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    for (int tries = 0; tries < 200; tries++) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (!connect(fd, (struct sockaddr *)&a, sizeof a)) {
            struct linger rst = {1, 0};
            setsockopt(fd, SOL_SOCKET, SO_LINGER, &rst, sizeof rst);
            return fd;
        }
        close(fd);
        usleep(20000);
    }
    return -1;
}

// Sends a health request and returns true when a 200 response arrives.
static bool health_ok(int fd, bool half_close) {
    static const char req[] = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
    char buf[512];
    size_t got = 0;
    if (send(fd, req, sizeof req - 1, MSG_NOSIGNAL) != (ssize_t)(sizeof req - 1)) {
        return false;
    }
    if (half_close) {
        shutdown(fd, SHUT_WR);
    }
    struct timeval tv = {5, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    while (got < sizeof buf - 1) {
        ssize_t n = recv(fd, buf + got, sizeof buf - 1 - got, 0);
        if (n <= 0) {
            break;
        }
        got += (size_t)n;
        buf[got] = 0;
        if (strstr(buf, "\r\n\r\n") && strstr(buf, "}")) {
            break;
        }
    }
    return got > 12 && !memcmp(buf, "HTTP/1.1 200", 12);
}

// Opens n connections to a child server, checks each answers, then stops the child and returns its report.
static struct child_result run_scenario(int port, rlim_t nofile, bool force_enfile, int n, int *ok_count) {
    int report_fd;
    pid_t pid = spawn_server(port, nofile, force_enfile, &report_fd);
    static int fds[2000];
    struct child_result r = {0};
    *ok_count = 0;
    for (int i = 0; i < n; i++) {
        fds[i] = client_connect(port);
    }
    for (int i = 0; i < n; i++) {
        *ok_count += fds[i] >= 0 && health_ok(fds[i], false);
    }
    int half = client_connect(port);
    CHECK(half >= 0 && health_ok(half, true));
    kill(pid, SIGTERM);
    CHECK(read(report_fd, &r, sizeof r) == (ssize_t)sizeof r);
    int status = 0;
    waitpid(pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    for (int i = 0; i < n; i++) {
        close(fds[i]);
    }
    close(half);
    close(report_fd);
    return r;
}

static void test_normal_fd_phase(void) {
    int ok;
    struct child_result r = run_scenario(3345, 700, false, 900, &ok);
    CHECK(ok == 900);
    CHECK(r.fd_phase);
    CHECK(r.direct_live <= 700 && r.direct_live >= 600);
    CHECK(r.live >= 900 && r.live - r.direct_live >= 200);
    CHECK(r.enfile == 0);
}

static void test_enfile(void) {
    int ok;
    struct child_result r = run_scenario(3346, 700, true, 720, &ok);
    CHECK(ok >= 718);
    CHECK(r.enfile >= 1 && r.fd_phase);
    CHECK(r.direct_live <= 700 && r.live > r.direct_live);
}

// Builds a completion as the kernel would post it.
static struct io_uring_cqe fake_cqe(uint64_t tag, int res, unsigned flags) {
    struct io_uring_cqe cqe = {.user_data = tag, .res = res, .flags = flags};
    return cqe;
}

static void test_stale_generations(void) {
    pass_begin();
    tu_open(50);
    struct conn *c = conn_get(50);
    unsigned with_buf = IORING_CQE_F_BUFFER | (9u << IORING_CQE_BUFFER_SHIFT);
    unsigned before = ring_buf_pending;
    struct io_uring_cqe stale = fake_cqe(ring_tag(RING_OP_RECV, 50, c->gen + 1), 20, with_buf | IORING_CQE_F_MORE);
    ring_handle_cqe(&stale);
    CHECK(ring_buf_pending == before + 1 && !pass.n_work && !c->in && c->flags == CONN_OPEN);
    struct io_uring_cqe closed = fake_cqe(ring_tag(RING_OP_RECV, 51, 0), 20, with_buf);
    ring_handle_cqe(&closed);
    CHECK(ring_buf_pending == before + 2 && !conn_get(51)->flags);
    c->flags |= CONN_SEND_INFLIGHT;
    struct io_uring_cqe send_stale = fake_cqe(ring_tag(RING_OP_SEND, 50, c->gen + 1), -EPIPE, 0);
    ring_handle_cqe(&send_stale);
    CHECK((c->flags & CONN_SEND_INFLIGHT) && !(c->flags & CONN_CLOSING));
    struct io_uring_cqe huge = fake_cqe(ring_tag(RING_OP_RECV, CONN_MAX + 5, 0), 1, 0);
    ring_handle_cqe(&huge);
    c->flags &= (uint16_t)~CONN_SEND_INFLIGHT;
    pass_finish();
    ring_close_conn(50);
}

static void test_recv_results(void) {
    pass_begin();
    tu_open(53);
    tu_open(54);
    tu_open(55);
    struct conn *eof = conn_get(53);
    struct io_uring_cqe c0 = fake_cqe(ring_tag(RING_OP_RECV, 53, eof->gen), 0, 0);
    ring_handle_cqe(&c0);
    CHECK(eof->flags & CONN_STOP_PARSE);
    struct io_uring_cqe c1 = fake_cqe(ring_tag(RING_OP_RECV, 54, conn_get(54)->gen), -ECONNRESET, 0);
    ring_handle_cqe(&c1);
    CHECK(conn_get(54)->flags & CONN_CLOSING);
    struct io_uring_cqe c2 = fake_cqe(ring_tag(RING_OP_RECV, 55, conn_get(55)->gen), -ENOBUFS, 0);
    uint64_t enobufs = ring_stat_enobufs;
    ring_handle_cqe(&c2);
    CHECK(ring_stat_enobufs == enobufs + 1 && (conn_get(55)->flags & CONN_RECV_WAIT_BUFS));
    CHECK(!(conn_get(55)->flags & CONN_RECV_ARMED) && ring_rearm_n == 1);
    pass_finish();
    CHECK(ring_rearm_n == 0 && (conn_get(55)->flags & CONN_RECV_ARMED) && !(conn_get(55)->flags & CONN_RECV_WAIT_BUFS));
    CHECK(!(conn_get(53)->flags & CONN_OPEN) && !(conn_get(54)->flags & CONN_OPEN));
    ring_close_conn(55);
}

static void test_pause_cancels_receive(void) {
    pass_begin();
    tu_open(56);
    struct conn *c = conn_get(56);
    ring_queue_recv(56);
    c->flags |= CONN_PAUSED;
    ring_recv_sync(56);
    CHECK(c->flags & CONN_RECV_CANCEL);
    ring_recv_sync(56);
    struct io_uring_cqe gone = fake_cqe(ring_tag(RING_OP_RECV, 56, c->gen), -ECANCELED, 0);
    ring_handle_cqe(&gone);
    CHECK(!(c->flags & (CONN_RECV_ARMED | CONN_RECV_CANCEL)));
    c->flags &= (uint16_t)~CONN_PAUSED;
    ring_recv_sync(56);
    CHECK(c->flags & CONN_RECV_ARMED);
    c->flags |= CONN_PAUSED;
    ring_recv_sync(56);
    c->flags &= (uint16_t)~CONN_PAUSED;
    ring_handle_cqe(&gone);
    CHECK(c->flags & CONN_RECV_ARMED);
    pass_finish();
    ring_close_conn(56);
}

static void test_accept_paths(void) {
    uint32_t live = conn_live;
    pass_begin();
    ring_accept_state = RING_ACCEPT_DIRECT;
    ring_accept_tag = ring_tag(RING_OP_ACCEPT_DIRECT, 0, 77);
    ring_gate_open = true;
    struct io_uring_cqe a = fake_cqe(ring_tag(RING_OP_ACCEPT_DIRECT, 0, 5), 60, IORING_CQE_F_MORE);
    ring_handle_cqe(&a);
    CHECK(conn_live == live + 1 && (conn_get(60)->flags & CONN_RECV_ARMED));
    ring_handle_cqe(&a);
    CHECK(conn_live == live + 1);
    ring_accept_errs = 0;
    clk.mono_ns = 1000000000000ULL;
    for (unsigned i = 0; i < ACCEPT_ERR_BURST; i++) {
        CHECK(ring_accept_state == RING_ACCEPT_DIRECT);
        struct io_uring_cqe e = fake_cqe(ring_accept_tag, -EMFILE, 0);
        ring_handle_cqe(&e);
    }
    CHECK(ring_accept_state == RING_ACCEPT_OFF && ring_accept_retry_ns == clk.mono_ns + ACCEPT_BACKOFF_NS);
    ring_accept_update(true);
    CHECK(ring_accept_state == RING_ACCEPT_OFF);
    CHECK(ring_cap_timeout(1000 * 1000000LL) <= ACCEPT_BACKOFF_NS);
    clk.mono_ns += ACCEPT_BACKOFF_NS + 1;
    ring_accept_update(true);
    CHECK(ring_accept_state == RING_ACCEPT_DIRECT && !ring_accept_retry_ns);
    ring_accept_errs = 0;
    ring_fd_phase = false;
    struct io_uring_cqe full = fake_cqe(ring_accept_tag, -ENFILE, 0);
    ring_handle_cqe(&full);
    CHECK(ring_fd_phase && ring_accept_state == RING_ACCEPT_FD && ring_stat_enfile == 1);
    ring_accept_errs = 0;
    unsigned saved = ring_direct_limit;
    ring_fd_phase = false;
    ring_accept_update(false);
    ring_accept_update(true);
    CHECK(ring_accept_state == RING_ACCEPT_DIRECT);
    ring_direct_limit = conn_direct_live + 1;
    struct io_uring_cqe b = fake_cqe(ring_tag(RING_OP_ACCEPT_DIRECT, 0, 5), 61, IORING_CQE_F_MORE);
    ring_handle_cqe(&b);
    CHECK(ring_accept_state == RING_ACCEPT_FD);
    ring_direct_limit = saved;
    ring_accept_update(false);
    CHECK(ring_accept_state == RING_ACCEPT_OFF);
    pass_finish();
    ring_close_conn(60);
    ring_close_conn(61);
    CHECK(conn_live == live);
}

int main(void) {
    tu_make_db(SERVER_DB);
    test_normal_fd_phase();
    test_enfile();
    tu_boot(3347, "/tmp/unit_ring.db");
    test_stale_generations();
    test_recv_results();
    test_pause_cancels_receive();
    test_accept_paths();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_ring ok");
    return 0;
}
