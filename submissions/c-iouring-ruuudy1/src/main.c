// Unity build entry: includes every module and SQLite itself, then runs startup and the pass loop.

// The feature-test macro must carry its reserved name, so the naming checks are silenced for this one line.
// NOLINTNEXTLINE(cert-dcl37-c,cert-dcl51-cpp,readability-identifier-naming,bugprone-reserved-identifier)
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <liburing.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

// SQLite comes first so its macros are settled before our code; tests link a separate SQLite object instead.
#ifdef FM_EXTERNAL_SQLITE
#include <sqlite3.h>
#else
#include <sqlite3.c>
#endif

#include "config.h"
#include "util.h"

#include "sha256.c"
#include "json.c"
#include "auth.c"
#include "http.c"
#include "route.c"
#include "conn.c"
#include "db.c"
#include "handlers.c"
#include "batch.c"
#include "memguard.c"
#include "ring.c"
#include "train.c"

// Next due times of the periodic jobs, in monotonic nanoseconds.
struct main_timers {
    uint64_t ctl_ns, mem_ns, sweep_ns, stats_ns;
};

// Settings read from the environment and argv.
struct main_config {
    const char *sqlite_path, *jwt_secret, *host;
    int port;
    bool stats;
};

// A socket address viewed as the generic type bind() takes, without a pointer cast.
union main_addr {
    struct sockaddr sa;
    struct sockaddr_in in;
};

// Sets the stop flag; the loop finishes its pass, commits and exits.
static void main_on_signal(int sig) {
    (void)sig;
    stop_flag = 1;
}

// Installs one signal disposition, exiting on failure because it only runs at startup.
static void main_sigaction(int sig, void (*handler)(int)) {
    struct sigaction sa = {0};
    sa.sa_handler = handler;
    sigemptyset(&sa.sa_mask);
    if (sigaction(sig, &sa, NULL)) {
        util_die("sigaction %d failed: %s", sig, strerror(errno));
    }
}

// Installs the stop handlers and ignores SIGPIPE.
static void main_install_signals(void) {
    main_sigaction(SIGTERM, main_on_signal);
    main_sigaction(SIGINT, main_on_signal);
    main_sigaction(SIGPIPE, SIG_IGN);
}

// Reads a required environment variable or exits with a message.
static const char *main_require_env(const char *name) {
    const char *v = getenv(name);
    if (!v || !*v) {
        util_die("missing environment variable %s", name);
    }
    return v;
}

// Reads SQLITE_PATH, JWT_SECRET, HOST and PORT; PORT must be 1 to 65535.
static void main_read_config(struct main_config *cfg) {
    cfg->sqlite_path = main_require_env("SQLITE_PATH");
    cfg->jwt_secret = main_require_env("JWT_SECRET");
    cfg->host = main_require_env("HOST");
    char *end;
    long port = strtol(main_require_env("PORT"), &end, 10);
    if (*end || port < 1 || port > 65535) {
        util_die("PORT must be between 1 and 65535");
    }
    cfg->port = (int)port;
}

// Raises the soft descriptor limit to the hard limit; a refusal keeps the current limit.
static void main_raise_nofile(void) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl)) {
        return;
    }
    rl.rlim_cur = rl.rlim_max;
    if (setrlimit(RLIMIT_NOFILE, &rl)) {
        util_log_limited(2, "cannot raise the descriptor limit: %s", strerror(errno));
    }
}

// Warns on stderr when conntrack is loaded, since its table can cap the connection count.
static void main_warn_conntrack(void) {
    FILE *f = fopen("/proc/sys/net/netfilter/nf_conntrack_max", "r");
    char buf[32] = "";
    if (!f) {
        return;
    }
    if (fgets(buf, sizeof buf, f)) {
        buf[strcspn(buf, "\n")] = 0;
        // A failed write to stderr is not actionable at startup.
        (void)fprintf(stderr, "warning: nf_conntrack_max is %s and may cap concurrent connections\n", buf);
    }
    // The file was only read, so a close failure loses nothing.
    (void)fclose(f);
}

// Sets one integer socket option, exiting on failure.
static void main_setopt(int fd, int level, int name, int value) {
    if (setsockopt(fd, level, name, &value, sizeof value)) {
        util_die("setsockopt %d failed: %s", name, strerror(errno));
    }
}

// Creates the listening socket; accepted sockets inherit TCP_NODELAY and keepalive from it.
static int main_listen(const char *host, int port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    union main_addr addr = {.in = {.sin_family = AF_INET, .sin_port = htons((uint16_t)port)}};
    if (fd < 0 || inet_pton(AF_INET, host, &addr.in.sin_addr) != 1) {
        util_die("cannot create listener for %s", host);
    }
    main_setopt(fd, SOL_SOCKET, SO_REUSEADDR, 1);
    main_setopt(fd, IPPROTO_TCP, TCP_NODELAY, 1);
    main_setopt(fd, SOL_SOCKET, SO_KEEPALIVE, 1);
    main_setopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, KEEPALIVE_IDLE_S);
    if (LISTEN_DEFER_ACCEPT_S) {
        main_setopt(fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, LISTEN_DEFER_ACCEPT_S);
    }
    if (bind(fd, &addr.sa, sizeof addr.in) || listen(fd, LISTEN_BACKLOG)) {
        util_die("cannot listen on %s:%d: %s", host, port, strerror(errno));
    }
    return fd;
}

// Samples memory and, while shedding, closes the idle connections that are least recently active.
static void main_memguard_tick(void) {
    memguard_sample();
    conn_shed_idle(memguard_shed_count(conn_live));
}

// Runs the periodic jobs that are due: controller sample, memory guard, stall sweep and stats line.
static void main_timers_run(struct main_timers *t, bool stats_on) {
    if (clk.mono_ns >= t->ctl_ns) {
        ctl_sample();
        t->ctl_ns = clk.mono_ns + CTL_SAMPLE_MS * 1000000ULL;
    }
    if (clk.mono_ns >= t->mem_ns) {
        main_memguard_tick();
        t->mem_ns = clk.mono_ns + MEMGUARD_INTERVAL_MS * 1000000ULL;
    }
    if (clk.mono_ns >= t->sweep_ns) {
        conn_sweep((uint32_t)(clk.mono_ns / 1000000000ULL));
        t->sweep_ns = clk.mono_ns + SWEEP_INTERVAL_S * 1000000000ULL;
    }
    if (stats_on && clk.mono_ns >= t->stats_ns) {
        batch_stats_print();
        t->stats_ns = clk.mono_ns + STATS_INTERVAL_S * 1000000000ULL;
    }
}

// One pass: wait, drain, schedule, execute, commit, publish, send, then checkpoint and release.
static void main_pass(void) {
    ring_wait(ctl_wait_nr(), ctl_timeout_ns());
    util_clock_update();
    pass_begin();
    ring_accept_update(memguard_state_now == MEMGUARD_OK);
    ring_drain();
    pass_schedule();
    pass_execute();
    pass_commit();
    pass_publish();
    pass_send();
    ring_submit();
    db_after_pass();
    pass_finish();
}

// Loops passes until a stop signal arrives, then commits whatever is open.
static void main_loop(bool stats_on) {
    struct main_timers timers = {0};
    while (!stop_flag) {
        main_pass();
        main_timers_run(&timers, stats_on);
    }
    db_commit();
}

// Opens everything the loop needs: database, pools, controller inputs, listener and ring.
static int main_startup(const struct main_config *cfg) {
    main_install_signals();
    main_raise_nofile();
    start_mono_ns = util_mono_ns();
    util_clock_update();
    db_open(cfg->sqlite_path);
    auth_init(cfg->jwt_secret, strlen(cfg->jwt_secret));
    if (!block_pool_init() || !conn_table_init()) {
        util_die("cannot map pools");
    }
    memguard_init();
    ctl_init();
    main_warn_conntrack();
    int listen_fd = main_listen(cfg->host, cfg->port);
    ring_init(listen_fd);
    ring_accept_update(true);
    return listen_fd;
}

#ifndef FM_TEST
int main(int argc, char **argv) {
    struct main_config cfg = {0};
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--pgo-train") && i + 1 < argc) {
            return train_run(argv[i + 1]);
        }
        if (!strcmp(argv[i], "--stats")) {
            cfg.stats = true;
        }
    }
    main_read_config(&cfg);
    int listen_fd = main_startup(&cfg);
    main_loop(cfg.stats);
    if (close(listen_fd)) {
        util_log_limited(2, "closing the listener failed: %s", strerror(errno));
    }
    db_close();
    return 0;
}
#endif
