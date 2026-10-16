#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LIKELY(x) __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)
// Marks a skeleton function that has no caller yet; remove the attribute once it is used.
#define NOT_YET_USED __attribute__((unused))
#define ARRAY_LEN(a) (sizeof(a) / sizeof((a)[0]))
#define LIT_LEN(s) (sizeof(s) - 1)

// A read-only byte range; never NUL-terminated and never owned.
struct slice {
    const char *p;
    uint32_t n;
};

// Both clocks, read once at the start of every pass by util_clock_update().
struct clock_state {
    int64_t real_s;
    int64_t real_ms;
    uint64_t mono_ns;
};

// Counters printed by the stats line; every module increments its own fields.
struct stats {
    uint64_t passes, requests, cqes, commits, commit_failures;
    uint64_t ckpt_count, ckpt_ns_total, ckpt_ns_max, pass_ns_max;
    unsigned level;
};

static struct clock_state clk;
static struct stats stats;
static uint64_t start_mono_ns;
static volatile sig_atomic_t stop_flag;

// Reads a fresh monotonic timestamp in nanoseconds.
static uint64_t util_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// Refreshes the shared clocks; handlers and the JWT check read clk, never the syscall.
static void util_clock_update(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    clk.real_s = ts.tv_sec;
    clk.real_ms = ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
    clk.mono_ns = util_mono_ns();
}

// Writes v in decimal at o and returns the end; at most 20 bytes.
static char *util_fmt_u64(char *o, uint64_t v) {
    char tmp[20];
    unsigned n = 0;
    do {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    } while (v);
    while (n) {
        *o++ = tmp[--n];
    }
    return o;
}

// Prints one line to stderr at most once per second per kind (kind below 8).
static void util_log_limited(unsigned kind, const char *fmt, ...) {
    static uint64_t last_ns[8];
    uint64_t now = util_mono_ns();
    if (kind >= ARRAY_LEN(last_ns) || now - last_ns[kind] < 1000000000ULL) {
        return;
    }
    last_ns[kind] = now;
    va_list ap;
    va_start(ap, fmt);
    // A failed write to stderr is not actionable here.
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fputc('\n', stderr);
}

// Prints a startup failure and exits; never called once the loop is running.
static void util_die(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    // A failed write to stderr is not actionable here.
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fputc('\n', stderr);
    exit(1);
}
