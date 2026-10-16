// Controller and memory guard tests: level stepping, timeout formula, /proc parsers, guard hysteresis.
#define FM_TEST 1
#include "../src/main.c"
#include "test_util.h"

#define MS 1000000LL

// Feeds the same utilization n times.
static void steps(double util, unsigned n) {
    for (unsigned i = 0; i < n; i++) {
        ctl_step(util);
    }
}

static void test_level_stepping(void) {
    memset(&ctl, 0, sizeof ctl);
    steps(0.40, 1);
    CHECK(ctl.level == 0);
    steps(0.40, 1);
    CHECK(ctl.level == 1);
    steps(0.99, 1);
    CHECK(ctl.level == 1);
    steps(0.99, 1);
    CHECK(ctl.level == 2);
    steps(0.99, 20);
    CHECK(ctl.level == 4 && stats.level == 4);
    steps(0.75, 10);
    CHECK(ctl.level == 4);
    steps(0.10, CTL_DOWN_SAMPLES - 1);
    CHECK(ctl.level == 4);
    steps(0.10, 1);
    CHECK(ctl.level == 3);
    steps(0.10, CTL_DOWN_SAMPLES * 3);
    CHECK(ctl.level == 0);
    steps(0.40, 1);
    steps(0.10, 1);
    steps(0.40, 1);
    CHECK(ctl.level == 0);
}

static void test_timeout_formula(void) {
    memset(&ctl, 0, sizeof ctl);
    CHECK(ctl_wait_nr() == 1 && ctl_timeout_ns() == IDLE_WAIT_NS);
    ctl.level = 3;
    ctl.p_last_requests = 10;
    ctl.p_last_ns = 2 * MS;
    CHECK(ctl_timeout_ns() == 8 * MS);
    ctl.level = 4;
    CHECK(ctl_timeout_ns() == 15 * MS);
    ctl.p_last_ns = 12 * MS;
    CHECK(ctl_timeout_ns() == 11 * MS);
    ctl.p_last_ns = 17 * MS;
    CHECK(ctl_timeout_ns() == WINDOW_TARGET_NS - 34 * MS);
    ctl.p_last_ns = 18 * MS;
    CHECK(ctl_timeout_ns() == 0);
    ctl.p_last_ns = 500 * MS;
    CHECK(ctl_timeout_ns() == 0);
    ctl.p_last_requests = 0;
    CHECK(ctl_timeout_ns() == 15 * MS);
    for (unsigned l = 1; l < ARRAY_LEN(CTL_LEVELS); l++) {
        ctl.level = l;
        ctl.p_last_requests = 0;
        CHECK(ctl_timeout_ns() > 0 && ctl_timeout_ns() <= WINDOW_CEILING_NS);
        ctl.p_last_requests = 1;
        ctl.p_last_ns = 0;
        CHECK(ctl_timeout_ns() == CTL_LEVELS[l].w_max_ns);
    }
    ctl_pass_done(3 * MS, 7);
    CHECK(ctl.p_last_ns == 3 * MS && ctl.p_last_requests == 7);
}

static void test_cpu_parse(void) {
    static const char text[] = "cpu  100 10 50 800 40 5 5 3 0 0\ncpu0 1 2 3 4 5 6 7 8 9 10\n";
    uint64_t busy = 0;
    uint64_t total = 0;
    CHECK(ctl_parse_cpu(text, sizeof text - 1, &busy, &total));
    CHECK(busy == 100 + 10 + 50 + 5 + 5 + 3 && total == busy + 800 + 40);
    CHECK(!ctl_parse_cpu("cpu0 1 2 3 4 5 6 7 8", 20, &busy, &total));
    CHECK(!ctl_parse_cpu("cpu  1 2 3", 10, &busy, &total));
    CHECK(!ctl_parse_cpu("cpu  1 2 3 x 5 6 7 8", 20, &busy, &total));
    CHECK(!ctl_parse_cpu("cpu  99999999999999999999999 2 3 4 5 6 7 8", 42, &busy, &total));
    ctl.stat_fd = open("/proc/stat", O_RDONLY | O_CLOEXEC);
    CHECK(ctl_read_cpu(&busy, &total) && total >= busy && total > 0);
}

static void test_memguard(void) {
    memguard_state_now = MEMGUARD_OK;
    CHECK(memguard_step(1000) == MEMGUARD_OK);
    CHECK(memguard_step(MEM_STOP_MB + 1) == MEMGUARD_OK);
    CHECK(memguard_step(MEM_STOP_MB - 1) == MEMGUARD_NO_ACCEPT);
    CHECK(memguard_step(MEM_RESUME_MB) == MEMGUARD_NO_ACCEPT);
    CHECK(memguard_step(MEM_RESUME_MB + 1) == MEMGUARD_OK);
    CHECK(memguard_step(MEM_SHED_MB - 1) == MEMGUARD_SHED);
    CHECK(memguard_step(MEM_STOP_MB + 5) == MEMGUARD_NO_ACCEPT);
    CHECK(memguard_step(MEM_SHED_MB + 5) == MEMGUARD_NO_ACCEPT);
    CHECK(memguard_step(MEM_SHED_MB - 5) == MEMGUARD_SHED);
    CHECK(memguard_shed_count(1000) == 1000 * MEM_SHED_PERMILLE / 1000 + 1);
    memguard_state_now = MEMGUARD_NO_ACCEPT;
    CHECK(memguard_shed_count(1000) == 0);
    uint64_t mb = 0;
    static const char info[] = "MemTotal:       2000000 kB\nMemFree: 1 kB\nMemAvailable:    1048576 kB\nBuffers: 3 kB\n";
    CHECK(memguard_parse_mb(info, sizeof info - 1, &mb) && mb == 1024);
    CHECK(!memguard_parse_mb("MemTotal: 5 kB\n", 15, &mb));
    CHECK(!memguard_parse_mb("MemAvailable: abc\n", 18, &mb));
    memguard_fd = open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
    CHECK(memguard_read_mb(&mb) && mb > 0);
}

int main(void) {
    test_level_stepping();
    test_timeout_formula();
    test_cpu_parse();
    test_memguard();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_ctl ok");
    return 0;
}
