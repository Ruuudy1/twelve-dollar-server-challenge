// Differential fuzz test for the HTTP parser against a slow scalar reference written here.
// Usage: fuzz_http <iterations> [seed]. Inputs are generated requests, pipelines, chunked bodies and limit cases, then
// mutated byte by byte; every input is also cut at random points to check that the parser never changes its mind.
#define FM_TEST 1
#include "../src/main.c"

enum { REF_OK, REF_INC, REF_BAD };

// Everything the reference reports for one input.
struct ref {
    int status;
    uint32_t method, path_off, path_len, auth_off, auth_len, consumed, head_end, body_len;
    bool has_auth;
    int close_after, expect;
    uint8_t body[REQUEST_MAX + 16];
};

// Header facts gathered by the reference.
struct ref_hdrs {
    bool has_cl, chunked, has_auth, expect, close, keep_alive, v10;
    uint32_t cl;
};

static uint64_t rng_state;

// xorshift64* generator.
static uint64_t rnd64(void) {
    rng_state ^= rng_state >> 12;
    rng_state ^= rng_state << 25;
    rng_state ^= rng_state >> 27;
    return rng_state * 2685821657736338717ULL;
}

// Returns a number below n.
static size_t below(size_t n) {
    return (size_t)(rnd64() % n);
}

// Returns true with the given chance in percent.
static bool chance(unsigned pct) {
    return below(100) < pct;
}

static int ref_lower(int c) {
    return c >= 'A' && c <= 'Z' ? c + 32 : c;
}

// Case-insensitive equality of a byte range with a lowercase text.
static bool ref_eq(const uint8_t *p, size_t n, const char *lower) {
    if (n != strlen(lower)) {
        return false;
    }
    for (size_t i = 0; i < n; i++) {
        if (ref_lower(p[i]) != lower[i]) {
            return false;
        }
    }
    return true;
}

static bool ref_ctl(int c) {
    return (c < 0x20 && c != '\t') || c == 0x7f;
}

// Finds the blank line and checks the head bytes; sets *h to the offset of the final CR LF CR LF or SIZE_MAX.
static int ref_head(const uint8_t *b, size_t len, size_t *h) {
    *h = SIZE_MAX;
    for (size_t i = 0; i <= HEADER_MAX && i + 4 <= len; i++) {
        if (!memcmp(b + i, "\r\n\r\n", 4)) {
            *h = i;
            break;
        }
    }
    size_t region = len < HEADER_MAX + 4 ? len : HEADER_MAX + 4;
    if (*h != SIZE_MAX) {
        region = *h + 4;
    }
    size_t crs = 0;
    for (size_t i = 0; i < region; i++) {
        if (b[i] == '\r') {
            crs++;
            if (i + 1 < len && b[i + 1] != '\n') {
                return REF_BAD;
            }
        } else if (b[i] == '\n') {
            if (i == 0 || b[i - 1] != '\r') {
                return REF_BAD;
            }
        } else if (ref_ctl(b[i])) {
            return REF_BAD;
        }
    }
    if (crs > HTTP_CR_MAX) {
        return REF_BAD;
    }
    if (*h == SIZE_MAX) {
        return len >= HEADER_MAX + 4 ? REF_BAD : REF_INC;
    }
    return REF_OK;
}

// Parses the request line b[0, n) by splitting it into exactly three blank-free tokens.
static bool ref_request_line(const uint8_t *b, size_t n, struct ref *r, struct ref_hdrs *h) {
    size_t sp[3];
    size_t count = 0;
    for (size_t i = 0; i < n; i++) {
        if (b[i] == '\t') {
            return false;
        }
        if (b[i] == ' ') {
            if (count == 2) {
                return false;
            }
            sp[count++] = i;
        }
    }
    if (count != 2 || sp[0] == 0 || sp[1] == sp[0] + 1 || sp[1] + 1 == n) {
        return false;
    }
    size_t t0 = sp[0] + 1;
    size_t tn = sp[1] - t0;
    const uint8_t *ver = b + sp[1] + 1;
    size_t vn = n - sp[1] - 1;
    if (vn != 8 || memcmp(ver, "HTTP/1.", 7) || (ver[7] != '0' && ver[7] != '1')) {
        return false;
    }
    if (b[t0] != '/' || tn > TARGET_MAX) {
        return false;
    }
    r->method = HTTP_OTHER;
    if (sp[0] == 3 && !memcmp(b, "GET", 3)) {
        r->method = HTTP_GET;
    } else if (sp[0] == 4 && !memcmp(b, "POST", 4)) {
        r->method = HTTP_POST;
    }
    size_t pn = 0;
    while (pn < tn && b[t0 + pn] != '?') {
        pn++;
    }
    r->path_off = (uint32_t)t0;
    r->path_len = (uint32_t)pn;
    h->v10 = ver[7] == '0';
    return true;
}

// Applies one header line b[s, e).
static bool ref_header(const uint8_t *b, size_t s, size_t e, struct ref *r, struct ref_hdrs *h) {
    size_t colon = s;
    while (colon < e && b[colon] != ':') {
        colon++;
    }
    if (colon == e || colon == s) {
        return false;
    }
    for (size_t i = s; i < colon; i++) {
        if (b[i] == ' ' || b[i] == '\t') {
            return false;
        }
    }
    size_t vs = colon + 1;
    while (vs < e && (b[vs] == ' ' || b[vs] == '\t')) {
        vs++;
    }
    size_t ve = e;
    while (ve > vs && (b[ve - 1] == ' ' || b[ve - 1] == '\t')) {
        ve--;
    }
    size_t nn = colon - s;
    if (ref_eq(b + s, nn, "authorization")) {
        if (h->has_auth) {
            return false;
        }
        h->has_auth = true;
        r->has_auth = true;
        r->auth_off = (uint32_t)vs;
        r->auth_len = (uint32_t)(e - vs);
    } else if (ref_eq(b + s, nn, "content-length")) {
        if (ve == vs) {
            return false;
        }
        uint64_t v = 0;
        for (size_t i = vs; i < ve; i++) {
            if (b[i] < '0' || b[i] > '9') {
                return false;
            }
            v = v * 10 + (uint64_t)(b[i] - '0');
            if (v > REQUEST_MAX) {
                return false;
            }
        }
        if (h->has_cl && h->cl != v) {
            return false;
        }
        h->has_cl = true;
        h->cl = (uint32_t)v;
    } else if (ref_eq(b + s, nn, "transfer-encoding")) {
        if (h->chunked || !ref_eq(b + vs, ve - vs, "chunked")) {
            return false;
        }
        h->chunked = true;
    } else if (ref_eq(b + s, nn, "expect")) {
        h->expect = h->expect || ref_eq(b + vs, ve - vs, "100-continue");
    } else if (ref_eq(b + s, nn, "connection")) {
        size_t ts = vs;
        for (size_t i = vs; i <= ve; i++) {
            if (i == ve || b[i] == ',') {
                size_t a = ts;
                size_t z = i;
                while (a < z && (b[a] == ' ' || b[a] == '\t')) {
                    a++;
                }
                while (z > a && (b[z - 1] == ' ' || b[z - 1] == '\t')) {
                    z--;
                }
                h->close = h->close || ref_eq(b + a, z - a, "close");
                h->keep_alive = h->keep_alive || ref_eq(b + a, z - a, "keep-alive");
                ts = i + 1;
            }
        }
    }
    return true;
}

// Splits b[0, h) into lines at CR LF and parses them.
static bool ref_lines(const uint8_t *b, size_t h, struct ref *r, struct ref_hdrs *hd) {
    size_t start = 0;
    for (int line = 0;; line++) {
        size_t cr = start;
        while (cr < h && b[cr] != '\r') {
            cr++;
        }
        bool ok = line == 0 ? ref_request_line(b, cr, r, hd) : ref_header(b, start, cr, r, hd);
        if (!ok) {
            return false;
        }
        if (cr >= h) {
            return true;
        }
        start = cr + 2;
    }
}

// Byte at i inside the window, or -1 past it.
static int ref_at(const uint8_t *b, size_t wlen, size_t i) {
    return i < wlen ? b[i] : -1;
}

static int ref_hex(int c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
}

// Expects CR LF at *p, byte by byte.
static int ref_crlf(const uint8_t *b, size_t wlen, size_t *p) {
    int c = ref_at(b, wlen, *p);
    if (c < 0) {
        return REF_INC;
    }
    if (c != '\r') {
        return REF_BAD;
    }
    c = ref_at(b, wlen, *p + 1);
    if (c < 0) {
        return REF_INC;
    }
    if (c != '\n') {
        return REF_BAD;
    }
    *p += 2;
    return REF_OK;
}

// Reads the rest of a chunk size line after the digits.
static int ref_chunk_line_end(const uint8_t *b, size_t wlen, size_t *p) {
    int c = ref_at(b, wlen, *p);
    if (c == '\r') {
        return ref_crlf(b, wlen, p);
    }
    if (c != ' ' && c != '\t' && c != ';') {
        return REF_BAD;
    }
    while ((c = ref_at(b, wlen, *p)) == ' ' || c == '\t') {
        (*p)++;
    }
    if (c < 0) {
        return REF_INC;
    }
    if (c != ';') {
        return REF_BAD;
    }
    for (;;) {
        c = ref_at(b, wlen, *p);
        if (c < 0) {
            return REF_INC;
        }
        if (c == '\r') {
            return ref_crlf(b, wlen, p);
        }
        if (ref_ctl(c)) {
            return REF_BAD;
        }
        (*p)++;
    }
}

// Reads the trailer section after the zero chunk, ending at the blank line.
static int ref_trailers(const uint8_t *b, size_t wlen, size_t *p) {
    for (;;) {
        size_t line = *p;
        for (;;) {
            int c = ref_at(b, wlen, *p);
            if (c < 0) {
                return REF_INC;
            }
            if (c == '\r') {
                break;
            }
            if (ref_ctl(c)) {
                return REF_BAD;
            }
            (*p)++;
        }
        int st = ref_crlf(b, wlen, p);
        if (st != REF_OK || *p == line + 2) {
            return st;
        }
    }
}

// Decodes a chunked body into r->body; returns the status of the walk.
static int ref_chunked(const uint8_t *b, size_t len, size_t start, struct ref *r) {
    size_t wlen = len < REQUEST_MAX ? len : REQUEST_MAX;
    size_t p = start;
    r->body_len = 0;
    for (;;) {
        size_t v = 0;
        size_t digits = 0;
        int c;
        while ((c = ref_at(b, wlen, p)) >= 0 && ref_hex(c) >= 0) {
            v = v * 16 + (size_t)ref_hex(c);
            if (v > REQUEST_MAX) {
                return REF_BAD;
            }
            digits++;
            p++;
        }
        if (c < 0) {
            return REF_INC;
        }
        if (!digits) {
            return REF_BAD;
        }
        int st = ref_chunk_line_end(b, wlen, &p);
        if (st != REF_OK) {
            return st;
        }
        if (!v) {
            st = ref_trailers(b, wlen, &p);
            r->consumed = (uint32_t)p;
            return st;
        }
        if (p + v > wlen) {
            return REF_INC;
        }
        memcpy(r->body + r->body_len, b + p, v);
        r->body_len += (uint32_t)v;
        p += v;
        st = ref_crlf(b, wlen, &p);
        if (st != REF_OK) {
            return st;
        }
    }
}

// The whole reference parse of one input.
static void ref_parse(const uint8_t *b, size_t len, struct ref *r) {
    struct ref_hdrs h = {0};
    size_t head = 0;
    memset(r, 0, offsetof(struct ref, body));
    int st = ref_head(b, len, &head);
    if (st != REF_OK) {
        r->status = st;
        return;
    }
    r->head_end = (uint32_t)head + 4;
    if (!ref_lines(b, head, r, &h)) {
        r->status = REF_BAD;
        return;
    }
    r->close_after = h.close || (h.v10 && !h.keep_alive);
    bool expect = h.expect && !h.v10;
    if (h.chunked) {
        st = ref_chunked(b, len, r->head_end, r);
        if (st == REF_INC && len >= REQUEST_MAX) {
            st = REF_BAD;
        }
    } else {
        size_t cl = h.has_cl ? h.cl : 0;
        st = REF_OK;
        if (r->head_end + cl > REQUEST_MAX) {
            st = REF_BAD;
        } else if (len < r->head_end + cl) {
            st = REF_INC;
        } else {
            memcpy(r->body, b + r->head_end, cl);
            r->body_len = (uint32_t)cl;
            r->consumed = r->head_end + (uint32_t)cl;
        }
    }
    r->status = st;
    r->expect = st == REF_INC && expect;
}

static uint64_t seen[3];

// Prints the input and aborts.
static void fail(const uint8_t *data, size_t len, const char *what) {
    fprintf(stderr, "MISMATCH: %s (len %zu)\n", what, len);
    for (size_t i = 0; i < len && i < 4000; i++) {
        fprintf(stderr, "%02x%s", data[i], (i % 32 == 31) ? "\n" : " ");
    }
    fputc('\n', stderr);
    abort();
}

// Parses on an exact-size heap copy, compares with the reference and returns the real status and request.
static int check_one(const uint8_t *data, size_t len, struct request *req, uint32_t *base_off) {
    static struct ref r;
    ref_parse(data, len, &r);
    char *b = malloc(len ? len : 1);
    if (!b) {
        abort();
    }
    memcpy(b, data, len);
    enum http_parse_status st = http_parse(b, (uint32_t)len, req);
    *base_off = 0;
    static const int map[] = {REF_OK, REF_INC, REF_BAD};
    if (map[st] != r.status) {
        fail(data, len, "status");
    }
    seen[r.status]++;
    if (st == HTTP_PARSE_OK) {
        bool same = req->method == r.method && req->path == b + r.path_off && req->path_len == r.path_len &&
                    req->close_after == r.close_after && req->consumed == r.consumed && req->body_len == r.body_len &&
                    !req->expect_continue && req->body == b + r.head_end &&
                    (r.has_auth ? req->auth == b + r.auth_off && req->auth_len == r.auth_len : !req->auth && !req->auth_len) &&
                    !memcmp(req->body, r.body, r.body_len) && !memcmp(b, data, r.head_end) &&
                    !memcmp(b + r.consumed, data + r.consumed, len - r.consumed);
        if (!same) {
            fail(data, len, "fields of an accepted request");
        }
    } else {
        bool same = !memcmp(b, data, len) && !req->path && !req->auth && !req->body && !req->path_len &&
                    !req->auth_len && !req->body_len && !req->method && !req->close_after &&
                    req->consumed == (st == HTTP_PARSE_BAD ? len : 0) &&
                    req->expect_continue == (st == HTTP_PARSE_INCOMPLETE ? r.expect : 0);
        if (!same) {
            fail(data, len, "fields or buffer after wait or reject");
        }
    }
    free(b);
    return (int)st;
}

// Cuts the input at s and checks the real parser agrees with itself between prefix and whole.
static void check_cut(const uint8_t *data, size_t len, size_t s, enum http_parse_status full, uint32_t full_consumed) {
    struct request req;
    uint32_t off = 0;
    enum http_parse_status pre = (enum http_parse_status)check_one(data, s, &req, &off);
    if (pre == HTTP_PARSE_OK && (full != HTTP_PARSE_OK || req.consumed != full_consumed)) {
        fail(data, len, "prefix accepted but the whole differs");
    }
    if (pre == HTTP_PARSE_BAD && full != HTTP_PARSE_BAD) {
        fail(data, len, "prefix rejected but the whole is not");
    }
    if (full == HTTP_PARSE_OK && s < full_consumed && pre != HTTP_PARSE_INCOMPLETE) {
        fail(data, len, "strict prefix of an accepted request did not wait");
    }
}

// Growing byte buffer for generated inputs.
struct gb {
    uint8_t d[40000];
    size_t n;
};

static void gb_add(struct gb *g, const void *p, size_t n) {
    if (g->n + n > sizeof g->d) {
        n = sizeof g->d - g->n;
    }
    memcpy(g->d + g->n, p, n);
    g->n += n;
}

static void gb_str(struct gb *g, const char *s) {
    gb_add(g, s, strlen(s));
}

// Appends n random token characters.
static void gb_token(struct gb *g, size_t n) {
    static const char set[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-";
    for (size_t i = 0; i < n; i++) {
        gb_add(g, &set[below(sizeof set - 1)], 1);
    }
}

// Appends text with each letter's case randomised.
static void gb_cased(struct gb *g, const char *s) {
    for (; *s; s++) {
        char c = *s;
        if (chance(30) && c >= 'a' && c <= 'z') {
            c = (char)(c - 32);
        }
        gb_add(g, &c, 1);
    }
}

// Appends zero to two blanks.
static void gb_blanks(struct gb *g) {
    static const char blank[] = " \t";
    for (size_t k = below(3); k; k--) {
        gb_add(g, &blank[chance(85) ? 0 : 1], 1);
    }
}

// Appends one header line with optional blanks around the value.
static void gb_header(struct gb *g, const char *name, const char *value) {
    gb_cased(g, name);
    gb_str(g, ":");
    if (chance(90)) {
        gb_str(g, " ");
    } else {
        gb_blanks(g);
    }
    gb_str(g, value);
    if (chance(5)) {
        gb_blanks(g);
    }
    gb_str(g, "\r\n");
}

// Appends the body as chunks with random sizes, extensions and trailers.
static void gb_chunked(struct gb *g, const uint8_t *body, size_t n) {
    char line[48];
    size_t at = 0;
    while (at < n) {
        size_t take = 1 + below(n - at);
        size_t shown = chance(3) ? REQUEST_MAX - 3 + below(6) : take;
        int w = snprintf(line, sizeof line, chance(50) ? "%zx" : "%zX", shown);
        gb_add(g, line, (size_t)w);
        if (chance(15)) {
            gb_str(g, chance(50) ? ";ext=1" : " ; a=\"b\"");
        }
        gb_str(g, "\r\n");
        gb_add(g, body + at, take);
        gb_str(g, "\r\n");
        at += take;
    }
    gb_str(g, chance(10) ? "00\r\n" : "0\r\n");
    for (size_t k = chance(25) ? 1 + below(2) : 0; k; k--) {
        gb_str(g, "X-Trailer: v\r\n");
    }
    gb_str(g, "\r\n");
}

// Appends one generated request.
static void gen_request(struct gb *g) {
    static const char *const methods[] = {"GET", "POST", "PUT", "DELETE", "get", "HEAD", "OPTIONS", "POST", "GET"};
    static const char *const targets[] = {"/feed", "/health", "/posts", "/posts/1", "/posts/123/like", "/posts/abc",
                                          "/feed?x=1&y=2", "/", "/posts/9223372036854775807", "/a?b?c", "/%2e", "/posts/1/"};
    static const char *const versions[] = {"HTTP/1.1", "HTTP/1.1", "HTTP/1.1", "HTTP/1.0", "HTTP/1.2"};
    static const char *const conns[] = {"close", "keep-alive", "Keep-Alive, close", "upgrade", "close ,keep-alive", "x,,y"};
    static const char *const extra[] = {"Host", "User-Agent", "Accept-Encoding", "Content-Type", "X-Custom", "Accept"};
    uint8_t body[REQUEST_MAX + 512];
    size_t body_n = chance(70) ? below(60) : (chance(95) ? below(900) : REQUEST_MAX - 150 + below(300));
    bool post = chance(60);
    bool chunk = post && chance(25);
    gb_str(g, methods[post ? (chance(80) ? 1 : below(ARRAY_LEN(methods))) : below(ARRAY_LEN(methods))]);
    gb_str(g, " ");
    if (chance(2)) {
        gb_str(g, "/");
        gb_token(g, TARGET_MAX - 3 + below(6));
    } else {
        gb_str(g, targets[below(ARRAY_LEN(targets))]);
    }
    gb_str(g, " ");
    gb_str(g, versions[chance(75) ? 0 : below(ARRAY_LEN(versions))]);
    gb_str(g, "\r\n");
    for (size_t i = 0; i < body_n; i++) {
        body[i] = (uint8_t)(chance(10) ? below(256) : 32 + below(95));
    }
    size_t headers = chance(97) ? below(8) : 90 + below(20);
    for (size_t i = 0; i < headers; i++) {
        char value[300];
        size_t k = 0;
        for (size_t v = below(40); v; v--) {
            value[k++] = (char)('a' + below(26));
        }
        value[k] = 0;
        gb_header(g, extra[below(ARRAY_LEN(extra))], value);
    }
    if (chance(40)) {
        gb_cased(g, "authorization: ");
        gb_str(g, "Bearer ");
        gb_token(g, 20 + below(chance(95) ? 200 : 8000));
        gb_str(g, "\r\n");
    }
    if (chance(25)) {
        gb_header(g, "Connection", conns[below(ARRAY_LEN(conns))]);
    }
    if (chance(10)) {
        gb_header(g, "Expect", chance(80) ? "100-continue" : "other");
    }
    if (chunk) {
        gb_header(g, "Transfer-Encoding", chance(95) ? "chunked" : "Chunked");
        if (chance(10)) {
            gb_header(g, "Content-Length", "5");
        }
    } else if (post || chance(10)) {
        char num[24];
        snprintf(num, sizeof num, "%zu", chance(4) ? REQUEST_MAX - 3 + below(6) : body_n + (chance(5) ? below(3) : 0));
        gb_header(g, "Content-Length", num);
        if (chance(3)) {
            gb_header(g, "Content-Length", num);
        }
    }
    gb_str(g, "\r\n");
    if (chunk) {
        gb_chunked(g, body, body_n);
    } else if (post) {
        gb_add(g, body, body_n);
    }
}

// Interesting bytes for mutation: framing characters, controls, digits, hex and high bytes.
static const uint8_t mutation_bytes[] = {'\r', '\n', ' ', ':', ';', ',', '\t', 0, 0x7f, 0x80, 0xff, '0', '1', '9', 'a',
                                         'F', 'g', '-', '+', '?', '/', 'x', 'C', 'T'};

// Applies one random mutation.
static void mutate(struct gb *g) {
    if (!g->n) {
        return;
    }
    size_t at = below(g->n);
    uint8_t c = chance(60) ? mutation_bytes[below(sizeof mutation_bytes)] : (uint8_t)below(256);
    switch (below(7)) {
    case 0:
        g->d[at] = c;
        break;
    case 1:
        if (g->n < sizeof g->d) {
            memmove(g->d + at + 1, g->d + at, g->n - at);
            g->d[at] = c;
            g->n++;
        }
        break;
    case 2:
        memmove(g->d + at, g->d + at + 1, g->n - at - 1);
        g->n--;
        break;
    case 3:
        g->n = at;
        break;
    case 4: {
        size_t k = 1 + below(8);
        if (at + k <= g->n && g->n + k <= sizeof g->d) {
            memmove(g->d + at + k, g->d + at, g->n - at);
            g->n += k;
        }
        break;
    }
    case 5:
        g->d[at] ^= (uint8_t)(1u << below(8));
        break;
    default: {
        const char *pairs[] = {"\r\n", "\r\n\r\n", ": ", "\n", "\r"};
        const char *p = pairs[below(ARRAY_LEN(pairs))];
        if (g->n + strlen(p) <= sizeof g->d) {
            memmove(g->d + at + strlen(p), g->d + at, g->n - at);
            memcpy(g->d + at, p, strlen(p));
            g->n += strlen(p);
        }
        break;
    }
    }
}

// Builds one fuzz input: one to three requests, mutations, and sometimes a cut.
static void gen_input(struct gb *g) {
    g->n = 0;
    for (size_t k = chance(80) ? 1 : 1 + below(3); k; k--) {
        gen_request(g);
    }
    for (size_t k = chance(65) ? below(4) : 0; k; k--) {
        mutate(g);
    }
    if (chance(15)) {
        g->n = below(g->n + 1);
    }
}

// Times nothing; runs the checks for one input: whole, one random cut, and every cut for small inputs.
static void run_input(const struct gb *g, uint64_t iter) {
    struct request req;
    uint32_t off = 0;
    enum http_parse_status full = (enum http_parse_status)check_one(g->d, g->n, &req, &off);
    uint32_t consumed = req.consumed;
    check_cut(g->d, g->n, below(g->n + 1), full, consumed);
    if (iter % 64 == 0 && g->n <= 700) {
        for (size_t s = 0; s <= g->n; s++) {
            check_cut(g->d, g->n, s, full, consumed);
        }
    }
}

int main(int argc, char **argv) {
    uint64_t iters = argc > 1 ? strtoull(argv[1], NULL, 10) : 200000;
    rng_state = argc > 2 ? strtoull(argv[2], NULL, 10) : 0x9e3779b97f4a7c15ULL;
    if (!rng_state) {
        rng_state = 1;
    }
    static struct gb g;
    for (uint64_t i = 0; i < iters; i++) {
        gen_input(&g);
        run_input(&g, i);
    }
    printf("fuzz_http ok: %llu inputs, reference results ok=%llu incomplete=%llu bad=%llu (including cuts)\n",
           (unsigned long long)iters, (unsigned long long)seen[REF_OK], (unsigned long long)seen[REF_INC],
           (unsigned long long)seen[REF_BAD]);
    return 0;
}
