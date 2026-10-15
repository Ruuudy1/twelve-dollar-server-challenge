// Pass tests: cohort order with per-connection order kept, commit failure rewrite, publish order, closing drops.
#define FM_TEST 1
#include "../src/main.c"
#include "test_util.h"

static const char GET_FEED[] = "GET /feed HTTP/1.1\r\n\r\n";
static const char GET_POST[] = "GET /posts/1 HTTP/1.1\r\n\r\n";
static const char GET_HEALTH[] = "GET /health HTTP/1.1\r\n\r\n";
static const char POST_CREATE[] = "POST /posts HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
static const char POST_LIKE[] = "POST /posts/1/like HTTP/1.1\r\nContent-Length: 0\r\n\r\n";

// Feeds one request through a fresh provided buffer id.
static void feed(uint32_t idx, const char *text) {
    static int next;
    tu_feed(idx, next++ % 200, text, strlen(text));
}

// Returns the position of work item w in the execution order.
static uint32_t pos_of(uint32_t w) {
    for (uint32_t i = 0; i < pass.n_work; i++) {
        if (pass.order[i] == w) {
            return i;
        }
    }
    return UINT32_MAX;
}

static void test_cohort_order(void) {
    pass_begin();
    tu_open(40);
    tu_open(41);
    tu_open(42);
    feed(40, GET_FEED);
    feed(40, POST_CREATE);
    feed(41, POST_CREATE);
    feed(41, GET_FEED);
    feed(42, GET_POST);
    feed(42, POST_LIKE);
    feed(42, GET_HEALTH);
    pass_schedule();
    CHECK(pass.n_work == 7);
    for (uint32_t i = 0; i < pass.n_work; i++) {
        CHECK(pass.order[i] < pass.n_work);
    }
    CHECK(pos_of(0) < pos_of(1));
    CHECK(pos_of(2) < pos_of(3));
    CHECK(pos_of(4) < pos_of(5) && pos_of(5) < pos_of(6));
    CHECK(pass.work[1].cohort == COHORT_FEED);
    CHECK(pass.work[5].cohort == COHORT_POST);
    CHECK(pos_of(2) < pos_of(0));
    for (uint32_t i = 1; i < pass.n_work; i++) {
        CHECK(pass.work[pass.order[i - 1]].cohort <= pass.work[pass.order[i]].cohort);
    }
    pass_finish();
    ring_close_conn(40);
    ring_close_conn(41);
    ring_close_conn(42);
}

static void test_commit_failure_rewrites_all(void) {
    uint32_t idx = 43;
    pass_begin();
    tu_open(idx);
    feed(idx, GET_HEALTH);
    feed(idx, GET_FEED);
    pass_schedule();
    pass_execute();
    CHECK(db_touch());
    db_note_result(SQLITE_FULL);
    pass.work[1].blk->flags |= BLOCK_F_NO_REWRITE;
    uint16_t kept = pass.work[1].blk->status;
    uint64_t failures_before = stats.commit_failures;
    pass_commit();
    CHECK(stats.commit_failures == failures_before + 1);
    CHECK(pass.work[0].blk->status == 500);
    CHECK(pass.work[0].blk->len > 0 && !memcmp(pass.work[0].blk->data + pass.work[0].blk->off, "HTTP/1.1 500", 12));
    CHECK(pass.work[1].blk->status == kept);
    pass_publish();
    pass_send();
    conn_get(idx)->flags &= (uint16_t)~CONN_SEND_INFLIGHT;
    pass_finish();
    ring_close_conn(idx);
    CHECK(!(conn_get(idx)->flags & CONN_OPEN));
}

static void test_publish_order_and_closing(void) {
    uint32_t free_before = tu_free_blocks();
    pass_begin();
    tu_open(44);
    tu_open(45);
    feed(44, GET_POST);
    feed(45, GET_HEALTH);
    feed(44, GET_HEALTH);
    feed(44, GET_FEED);
    tu_run_pass_body();
    struct conn *c = conn_get(44);
    CHECK(c->out_blocks == 3 && c->out_head == pass.work[0].blk);
    CHECK(c->out_head->next == pass.work[2].blk && c->out_head->next->next == pass.work[3].blk);
    CHECK(conn_get(45)->out_head == pass.work[1].blk);
    CHECK(pass.n_dirty == 2);
    pass_send();
    CHECK(!(c->flags & CONN_DIRTY));
    c->flags &= (uint16_t)~CONN_SEND_INFLIGHT;
    conn_get(45)->flags &= (uint16_t)~CONN_SEND_INFLIGHT;
    pass_finish();
    ring_close_conn(44);
    ring_close_conn(45);
    CHECK(tu_free_blocks() == free_before);
    pass_begin();
    tu_open(46);
    feed(46, GET_HEALTH);
    feed(46, GET_HEALTH);
    conn_request_close(46);
    tu_run_pass_body();
    CHECK(!conn_get(46)->out_head && conn_get(46)->out_blocks == 0);
    pass_finish();
    CHECK(!(conn_get(46)->flags & CONN_OPEN));
    CHECK(tu_free_blocks() == free_before);
}

static void test_pass_full_and_exhausted_pool(void) {
    pass_begin();
    tu_open(47);
    for (unsigned i = 0; i < PASS_MAX_REQUESTS; i++) {
        pass_add_bad_request(47);
    }
    CHECK(pass_full());
    pass_finish();
    ring_close_conn(47);
}

int main(void) {
    tu_boot(3344, "/tmp/unit_pass.db");
    test_cohort_order();
    test_commit_failure_rewrites_all();
    test_publish_order_and_closing();
    test_pass_full_and_exhausted_pool();
    if (failures) {
        fprintf(stderr, "%d failures\n", failures);
        return 1;
    }
    puts("unit_pass ok");
    return 0;
}
