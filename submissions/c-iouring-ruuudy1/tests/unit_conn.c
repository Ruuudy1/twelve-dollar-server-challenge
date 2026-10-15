// Connection tests: layout, pools, input framing at every split, pipelining with pause and resume,
// overflow, Expect, release accounting, stall sweep and idle shedding.
#define FM_TEST 1
#include "../src/main.c"
#include "test_util.h"

static const char REQ_HEALTH[] = "GET /health HTTP/1.1\r\nHost: x\r\n\r\n";
#define REQ_LEN (sizeof REQ_HEALTH - 1)

static void test_layout(void) {
    CHECK(sizeof(struct conn) == 64);
    CHECK(sizeof(struct block) == 64);
    CHECK(offsetof(struct block, data) == 64);
    struct block *probe = block_get();
    CHECK(((uintptr_t)probe + offsetof(struct block, data)) % 64 == 0);
    block_put(probe);
    CHECK(DIRECT_SLOTS + NORMAL_FD_MAX == CONN_MAX);
}

static void test_pool_exhaustion(void) {
    static struct block *all[BLOCK_CAP];
    uint32_t n = 0;
    uint32_t free_before = tu_free_blocks();
    struct block *b;
    while ((b = block_get())) {
        all[n++] = b;
    }
    CHECK(n + free_before >= BLOCK_CAP - 1);
    CHECK(!block_get());
    for (uint32_t i = 0; i < n; i++) {
        block_put(all[i]);
    }
    CHECK(tu_free_blocks() >= BLOCK_CAP - 1);
    struct block *jumbo[BLOCK_JUMBO_MAX + 1];
    uint32_t j = 0;
    while (j <= BLOCK_JUMBO_MAX && (jumbo[j] = block_get_jumbo())) {
        CHECK(jumbo[j]->cap == BLOCK_JUMBO_BYTES - 64 && (jumbo[j]->flags & BLOCK_F_JUMBO));
        j++;
    }
    CHECK(j == BLOCK_JUMBO_MAX);
    for (uint32_t i = 0; i < j; i++) {
        block_put(jumbo[i]);
    }
    CHECK(block_get_jumbo() != NULL);
}

// Counts the work items of the current pass with the given route kind.
static uint32_t count_kind(uint8_t kind) {
    uint32_t n = 0;
    for (uint32_t i = 0; i < pass.n_work; i++) {
        n += pass.work[i].route.kind == kind;
    }
    return n;
}

// Ends the pass and releases the connection the test used.
static void end_pass_release(uint32_t idx) {
    pass_finish();
    ring_close_conn(idx);
}

static void test_split_everywhere(void) {
    uint32_t free_before = tu_free_blocks();
    for (size_t k = 1; k < REQ_LEN; k++) {
        pass_begin();
        tu_open(10);
        tu_feed(10, 0, REQ_HEALTH, k);
        tu_feed(10, 1, REQ_HEALTH + k, REQ_LEN - k);
        CHECK(pass.n_work == 1 && count_kind(ROUTE_HEALTH) == 1);
        end_pass_release(10);
        CHECK(!conn_get(10)->in);
        pass_begin();
        tu_open(10);
        tu_feed(10, 0, REQ_HEALTH, k);
        pass_finish();
        CHECK(conn_get(10)->in && conn_get(10)->in_len == k && !pass.n_work);
        pass_begin();
        tu_feed(10, 1, REQ_HEALTH + k, REQ_LEN - k);
        CHECK(pass.n_work == 1);
        pass_finish();
        CHECK(!conn_get(10)->in && !conn_get(10)->in_len);
        ring_close_conn(10);
    }
    CHECK(tu_free_blocks() == free_before);
}

// Executes and publishes the pass, then pretends every queued block was sent.
static void drain_output(uint32_t idx) {
    struct conn *c = conn_get(idx);
    tu_run_pass_body();
    while (c->out_head) {
        conn_out_pop(c);
    }
}

static void test_pipeline_pause_resume(void) {
    char text[REQ_LEN * 10];
    uint32_t idx = 11;
    uint32_t served = 0;
    for (unsigned i = 0; i < 10; i++) {
        memcpy(text + i * REQ_LEN, REQ_HEALTH, REQ_LEN);
    }
    pass_begin();
    tu_open(idx);
    tu_feed(idx, 2, text, sizeof text);
    struct conn *c = conn_get(idx);
    CHECK(pass.n_work == PAUSE_BLOCKS && (c->flags & CONN_PAUSED));
    served += pass.n_work;
    while (served < 10) {
        drain_output(idx);
        pass_finish();
        pass_begin();
        CHECK(c->flags & CONN_PAUSED);
        c->flags &= (uint16_t)~CONN_PAUSED;
        conn_feed(idx, NULL, 0, -1);
        CHECK(pass.n_work >= 1 && pass.n_work <= PAUSE_BLOCKS);
        served += pass.n_work;
    }
    CHECK(served == 10);
    drain_output(idx);
    end_pass_release(idx);
}

static void test_paused_input_grows_and_overflows(void) {
    uint32_t idx = 12;
    char junk[1000];
    memset(junk, 'a', sizeof junk);
    pass_begin();
    tu_open(idx);
    struct conn *c = conn_get(idx);
    c->flags |= CONN_PAUSED;
    for (unsigned i = 0; i < 60; i++) {
        tu_feed(idx, 3, junk, sizeof junk);
    }
    CHECK(!(c->flags & CONN_CLOSING) && c->in && (c->in->flags & BLOCK_F_JUMBO) && c->in_len == 60000);
    CHECK(conn_deferred_n == 1);
    for (unsigned i = 0; i < 10; i++) {
        tu_feed(idx, 3, junk, sizeof junk);
    }
    CHECK(c->flags & CONN_CLOSING);
    end_pass_release(idx);
    CHECK(conn_deferred_n == 0 && !conn_get(idx)->in);
}

static void test_bad_request_stops_parsing(void) {
    uint32_t idx = 13;
    pass_begin();
    tu_open(idx);
    tu_feed(idx, 4, "GET / HTTP/1.1\r\nBad Header\r\n\r\n", 30);
    CHECK(pass.n_work == 1 && pass.work[0].route.kind == ROUTE_BAD_REQUEST);
    CHECK(conn_get(idx)->flags & CONN_STOP_PARSE);
    tu_feed(idx, 5, REQ_HEALTH, REQ_LEN);
    CHECK(pass.n_work == 1);
    end_pass_release(idx);
}

static void test_expect_continue(void) {
    static const char head[] = "POST /posts HTTP/1.1\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n";
    uint32_t idx = 14;
    pass_begin();
    tu_open(idx);
    tu_feed(idx, 6, head, sizeof head - 1);
    struct conn *c = conn_get(idx);
    CHECK(c->out_head && c->out_blocks == 1 && (c->out_head->flags & BLOCK_F_NO_REWRITE));
    CHECK(c->out_head->len == LIT_LEN("HTTP/1.1 100 Continue\r\n\r\n"));
    tu_feed(idx, 7, "", 0);
    CHECK(c->out_blocks == 1);
    tu_feed(idx, 8, "hello", 5);
    CHECK(pass.n_work == 1 && pass.work[0].route.kind == ROUTE_CREATE);
    CHECK(!(c->flags & CONN_SENT_CONTINUE));
    end_pass_release(idx);
}

static void test_release_frees_every_block_once(void) {
    uint32_t free_before = tu_free_blocks();
    uint32_t live_before = conn_live;
    uint32_t idx = 15;
    pass_begin();
    tu_open(idx);
    struct conn *c = conn_get(idx);
    CHECK(conn_in_append(c, "abc", 3));
    for (unsigned i = 0; i < 3; i++) {
        struct block *b = block_get();
        b->len = 1;
        conn_queue(c, b);
    }
    uint32_t gen = c->gen;
    pass_finish();
    ring_close_conn(idx);
    CHECK(tu_free_blocks() == free_before);
    CHECK(conn_live == live_before && c->gen == gen + 1 && !c->flags);
    conn_release(idx);
    CHECK(tu_free_blocks() == free_before && conn_live == live_before);
}

static void test_sweep_and_shed(void) {
    uint32_t base_live = conn_live;
    uint32_t now_s = 1000;
    clk.mono_ns = (uint64_t)now_s * 1000000000ULL;
    pass_begin();
    for (uint32_t i = 0; i < 6; i++) {
        tu_open(20 + i);
        conn_get(20 + i)->last_active_s = now_s - 10 * (i + 1);
    }
    tu_open(26);
    CHECK(conn_in_append(conn_get(26), "GET /he", 7));
    conn_get(26)->last_active_s = now_s - 31;
    tu_open(27);
    CHECK(conn_in_append(conn_get(27), "GET /he", 7));
    conn_get(27)->last_active_s = now_s - 5;
    CHECK(conn_watch_n == 2);
    conn_sweep(now_s);
    CHECK(!(conn_get(26)->flags & CONN_OPEN) && (conn_get(27)->flags & CONN_OPEN) && conn_watch_n == 1);
    conn_sweep(now_s + 40);
    CHECK(!(conn_get(27)->flags & CONN_OPEN) && conn_watch_n == 0);
    conn_shed_idle(3);
    CHECK(!(conn_get(25)->flags & CONN_OPEN) && !(conn_get(24)->flags & CONN_OPEN) && !(conn_get(23)->flags & CONN_OPEN));
    CHECK((conn_get(22)->flags & CONN_OPEN) && (conn_get(21)->flags & CONN_OPEN) && (conn_get(20)->flags & CONN_OPEN));
    conn_shed_idle(100);
    CHECK(conn_live == base_live);
    pass_finish();
}

static void test_peer_closed(void) {
    uint32_t live = conn_live;
    pass_begin();
    tu_open(30);
    tu_open(31);
    conn_peer_closed(30);
    struct block *b = block_get();
    b->len = 4;
    conn_queue(conn_get(31), b);
    conn_peer_closed(31);
    pass_finish();
    CHECK(!(conn_get(30)->flags & CONN_OPEN) && (conn_get(31)->flags & CONN_OPEN));
    CHECK(conn_get(31)->flags & CONN_CLOSE_AFTER_SEND);
    ring_close_conn(31);
    CHECK(conn_live == live);
}

int main(void) {
    tu_boot(3343, "/tmp/unit_conn.db");
    test_layout();
    test_pool_exhaustion();
    test_split_everywhere();
    test_pipeline_pause_resume();
    test_paused_input_grows_and_overflows();
    test_bad_request_stops_parsing();
    test_expect_continue();
    test_release_frees_every_block_once();
    test_sweep_and_shed();
    test_peer_closed();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_conn ok");
    return 0;
}
