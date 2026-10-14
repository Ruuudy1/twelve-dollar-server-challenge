// Owner: http module. Request framing and header parsing over a byte range.

#ifndef __SSE2__
#error "http.c needs SSE2"
#endif
#include <emmintrin.h>

enum http_method {
    HTTP_GET = 1,
    HTTP_POST,
    HTTP_OTHER,
};

// What the router needs from one request; every pointer is a slice of the buffer that was parsed.
struct request {
    const char *path, *auth, *body;
    uint32_t path_len, auth_len, body_len, consumed;
    uint8_t method, close_after, expect_continue;
};

enum http_parse_status {
    // One complete request was parsed and consumed bytes were set.
    HTTP_PARSE_OK,
    // More bytes are needed; expect_continue may be set when only the body is missing.
    HTTP_PARSE_INCOMPLETE,
    // Malformed or over a limit: answer 400 and close; consumed is the whole input.
    HTTP_PARSE_BAD,
};

enum http_scan {
    HTTP_SCAN_FOUND,
    HTTP_SCAN_MORE,
    HTTP_SCAN_BAD,
};

// Where every line of the head ends: the CR offsets, and the offset just past the blank line once it was found.
struct http_head {
    uint16_t eol[HTTP_CR_MAX];
    uint32_t cr_n, end;
};

// What the header lines said about framing and connection handling.
struct http_hdrs {
    uint32_t cl;
    bool has_cl, has_auth, chunked, expect, close, keep_alive, v10;
};

// Result of walking a chunked body: raw end offset and decoded length.
struct http_chunked {
    uint32_t end, decoded;
};

// Bit masks of one 16-byte block: CR, LF, and every control byte except CR, LF and tab.
struct http_masks {
    uint32_t cr, lf, bad;
};

static_assert(HEADER_MAX + 4 <= UINT16_MAX, "head offsets must fit the uint16_t line table");
static_assert(HEADER_MAX + 4 < REQUEST_MAX, "the head must always fit inside one request");
static_assert(REQUEST_MAX < 0x10000000, "chunk size arithmetic must not wrap");

// Loads 16 bytes at p, padding with a harmless letter when fewer than 16 remain.
static __m128i http_load16(const char *p, uint32_t rem) {
    if (LIKELY(rem >= 16)) {
        return _mm_loadu_si128((const __m128i_u *)p);
    }
    char tmp[16];
    memset(tmp, 'x', sizeof tmp);
    memcpy(tmp, p, rem);
    return _mm_loadu_si128((const __m128i_u *)tmp);
}

// Classifies 16 bytes at once: line ends, and any control byte that may not appear in a head.
static struct http_masks http_block_masks(__m128i v) {
    __m128i cr = _mm_cmpeq_epi8(v, _mm_set1_epi8('\r'));
    __m128i lf = _mm_cmpeq_epi8(v, _mm_set1_epi8('\n'));
    __m128i tab = _mm_cmpeq_epi8(v, _mm_set1_epi8('\t'));
    __m128i del = _mm_cmpeq_epi8(v, _mm_set1_epi8(0x7f));
    __m128i low = _mm_cmpeq_epi8(_mm_min_epu8(v, _mm_set1_epi8(0x1f)), v);
    __m128i bad = _mm_andnot_si128(_mm_or_si128(_mm_or_si128(cr, lf), tab), _mm_or_si128(low, del));
    return (struct http_masks){(uint32_t)_mm_movemask_epi8(cr), (uint32_t)_mm_movemask_epi8(lf),
                               (uint32_t)_mm_movemask_epi8(bad)};
}

// Scans buf[0, n) for the blank line while checking that every CR is followed by LF, every LF follows a CR and no other
// control byte appears; records each CR offset.
static enum http_scan http_scan_head(const char *buf, uint32_t n, struct http_head *h) {
    uint32_t prev_cr = 0;
    uint32_t prev_lf = 0;
    for (uint32_t base = 0; base < n; base += 16) {
        uint32_t rem = n - base;
        uint32_t valid = rem >= 16 ? 0xFFFFu : (1u << rem) - 1u;
        struct http_masks m = http_block_masks(http_load16(buf + base, rem));
        uint32_t lf = m.lf & valid;
        uint32_t wl = prev_lf | (lf << 16);
        uint32_t term = wl & (wl >> 2) & 0x3FFFC000u;
        uint32_t last = term ? (uint32_t)__builtin_ctz(term) - 14u : 0;
        if (term) {
            valid &= (2u << last) - 1u;
            lf &= valid;
        }
        uint32_t cr = m.cr & valid;
        if (UNLIKELY(lf != (((cr << 1) | (prev_cr >> 15)) & valid) || (m.bad & valid))) {
            return HTTP_SCAN_BAD;
        }
        for (uint32_t bits = cr; bits; bits &= bits - 1u) {
            if (UNLIKELY(h->cr_n == HTTP_CR_MAX)) {
                return HTTP_SCAN_BAD;
            }
            h->eol[h->cr_n++] = (uint16_t)(base + (uint32_t)__builtin_ctz(bits));
        }
        if (term) {
            h->end = base + last + 1u;
            return HTTP_SCAN_FOUND;
        }
        prev_cr = cr;
        prev_lf = lf;
    }
    return HTTP_SCAN_MORE;
}

// Drops leading spaces and tabs.
static struct slice http_ltrim(struct slice s) {
    while (s.n && (*s.p == ' ' || *s.p == '\t')) {
        s.p++;
        s.n--;
    }
    return s;
}

// Drops trailing spaces and tabs.
static struct slice http_rtrim(struct slice s) {
    while (s.n && (s.p[s.n - 1] == ' ' || s.p[s.n - 1] == '\t')) {
        s.n--;
    }
    return s;
}

// Compares with a lowercase literal of n bytes; the head scan already rejected the control bytes that would alias.
static bool http_ieq(struct slice s, const char *lower, uint32_t n) {
    if (s.n != n) {
        return false;
    }
    for (uint32_t i = 0; i < n; i++) {
        if (((unsigned char)s.p[i] | 0x20u) != (unsigned char)lower[i]) {
            return false;
        }
    }
    return true;
}

// Reads a decimal Content-Length of at most REQUEST_MAX; two different values are rejected.
static bool http_set_length(struct http_hdrs *hd, struct slice v) {
    uint32_t n = 0;
    if (!v.n) {
        return false;
    }
    for (uint32_t i = 0; i < v.n; i++) {
        uint32_t d = (uint32_t)(unsigned char)v.p[i] - (uint32_t)'0';
        if (d > 9) {
            return false;
        }
        n = n * 10 + d;
        if (n > REQUEST_MAX) {
            return false;
        }
    }
    if (hd->has_cl && hd->cl != n) {
        return false;
    }
    hd->has_cl = true;
    hd->cl = n;
    return true;
}

// Keeps the Authorization value from its first non-blank byte to the end of the line; a second one is rejected.
static bool http_set_auth(struct request *req, struct http_hdrs *hd, struct slice v) {
    if (hd->has_auth) {
        return false;
    }
    hd->has_auth = true;
    req->auth = v.p;
    req->auth_len = v.n;
    return true;
}

// Accepts only a single "chunked" coding; anything else cannot be framed here.
static bool http_set_chunked(struct http_hdrs *hd, struct slice v) {
    if (hd->chunked || !http_ieq(v, "chunked", LIT_LEN("chunked"))) {
        return false;
    }
    hd->chunked = true;
    return true;
}

// Reads the comma separated Connection tokens, remembering whether close or keep-alive was named.
static void http_connection(struct http_hdrs *hd, struct slice v) {
    uint32_t i = 0;
    while (i < v.n) {
        uint32_t j = i;
        while (j < v.n && v.p[j] != ',') {
            j++;
        }
        struct slice tok = http_rtrim(http_ltrim((struct slice){v.p + i, j - i}));
        hd->close |= http_ieq(tok, "close", LIT_LEN("close"));
        hd->keep_alive |= http_ieq(tok, "keep-alive", LIT_LEN("keep-alive"));
        i = j + 1;
    }
}

// Applies one header line: the name may not hold blanks, and only the five known names are read.
static bool http_header(const char *line, uint32_t n, struct request *req, struct http_hdrs *hd) {
    uint32_t nl = 0;
    while (nl < n && line[nl] != ':') {
        if (line[nl] == ' ' || line[nl] == '\t') {
            return false;
        }
        nl++;
    }
    if (!nl || nl == n) {
        return false;
    }
    struct slice name = {line, nl};
    struct slice val = http_ltrim((struct slice){line + nl + 1, n - nl - 1});
    if (http_ieq(name, "authorization", LIT_LEN("authorization"))) {
        return http_set_auth(req, hd, val);
    }
    val = http_rtrim(val);
    if (http_ieq(name, "content-length", LIT_LEN("content-length"))) {
        return http_set_length(hd, val);
    }
    if (http_ieq(name, "connection", LIT_LEN("connection"))) {
        http_connection(hd, val);
    } else if (http_ieq(name, "transfer-encoding", LIT_LEN("transfer-encoding"))) {
        return http_set_chunked(hd, val);
    } else if (http_ieq(name, "expect", LIT_LEN("expect"))) {
        hd->expect |= http_ieq(val, "100-continue", LIT_LEN("100-continue"));
    }
    return true;
}

// Parses "METHOD SP target SP HTTP/1.x" from buf[0, n); the query string is dropped from the path.
static bool http_request_line(const char *buf, uint32_t n, struct request *req, struct http_hdrs *hd) {
    const char *sp = memchr(buf, ' ', n);
    if (!sp || sp == buf) {
        return false;
    }
    uint32_t mn = (uint32_t)(sp - buf);
    if (n < mn + 1 + 1 + 1 + 8 || buf[n - 9] != ' ' || memcmp(buf + n - 8, "HTTP/1.", 7) ||
        (buf[n - 1] != '0' && buf[n - 1] != '1')) {
        return false;
    }
    const char *target = sp + 1;
    uint32_t tn = n - 9 - (mn + 1);
    if (tn > TARGET_MAX || *target != '/' || memchr(target, ' ', tn)) {
        return false;
    }
    const char *query = memchr(target, '?', tn);
    req->method = HTTP_OTHER;
    if (mn == 3 && !memcmp(buf, "GET", 3)) {
        req->method = HTTP_GET;
    } else if (mn == 4 && !memcmp(buf, "POST", 4)) {
        req->method = HTTP_POST;
    }
    req->path = target;
    req->path_len = query ? (uint32_t)(query - target) : tn;
    hd->v10 = buf[n - 1] == '0';
    return true;
}

// Parses the request line and every header line of a head whose line ends are known.
static bool http_parse_lines(const char *buf, const struct http_head *h, struct request *req, struct http_hdrs *hd) {
    if (!http_request_line(buf, h->eol[0], req, hd)) {
        return false;
    }
    for (uint32_t i = 1; i + 1 < h->cr_n; i++) {
        uint32_t start = (uint32_t)h->eol[i - 1] + 2;
        if (!http_header(buf + start, (uint32_t)h->eol[i] - start, req, hd)) {
            return false;
        }
    }
    return true;
}

// Rejects the whole input.
static enum http_parse_status http_reject(struct request *req, uint32_t len) {
    *req = (struct request){0};
    req->consumed = len;
    return HTTP_PARSE_BAD;
}

// Asks for more bytes; only the Expect flag survives.
static enum http_parse_status http_wait(struct request *req, bool expect) {
    *req = (struct request){0};
    req->expect_continue = expect;
    return HTTP_PARSE_INCOMPLETE;
}

// Out of bytes inside a chunked body: a request that cannot fit REQUEST_MAX is rejected, otherwise the caller waits.
static enum http_parse_status http_starved(struct request *req, uint32_t len, const struct http_hdrs *hd) {
    return len >= REQUEST_MAX ? http_reject(req, len) : http_wait(req, hd->expect && !hd->v10);
}

// Returns true for a control byte other than tab.
static bool http_is_ctl(char c) {
    unsigned char u = (unsigned char)c;
    return (u < 0x20 && u != '\t') || u == 0x7f;
}

// Value of a hex digit, or 16 for any other byte.
static uint32_t http_hex_value(char c) {
    uint32_t u = (uint32_t)(unsigned char)c;
    if (u - (uint32_t)'0' < 10) {
        return u - (uint32_t)'0';
    }
    u |= 0x20u;
    return u - (uint32_t)'a' < 6 ? u - (uint32_t)'a' + 10 : 16;
}

// Expects CR LF at *pos and steps over it; a wrong first byte is rejected even before the second one arrives.
static enum http_parse_status http_expect_crlf(const char *buf, uint32_t wlen, uint32_t *pos) {
    if (*pos >= wlen) {
        return HTTP_PARSE_INCOMPLETE;
    }
    if (buf[*pos] != '\r') {
        return HTTP_PARSE_BAD;
    }
    if (*pos + 1 >= wlen) {
        return HTTP_PARSE_INCOMPLETE;
    }
    if (buf[*pos + 1] != '\n') {
        return HTTP_PARSE_BAD;
    }
    *pos += 2;
    return HTTP_PARSE_OK;
}

// Skips an optional chunk extension (blanks, then ';' and anything printable) up to the CR of the size line.
static enum http_parse_status http_chunk_ext(const char *buf, uint32_t wlen, uint32_t *pos) {
    uint32_t p = *pos;
    while (p < wlen && (buf[p] == ' ' || buf[p] == '\t')) {
        p++;
    }
    if (p >= wlen) {
        return HTTP_PARSE_INCOMPLETE;
    }
    if (buf[p] != ';') {
        return HTTP_PARSE_BAD;
    }
    while (p < wlen && buf[p] != '\r') {
        if (http_is_ctl(buf[p])) {
            return HTTP_PARSE_BAD;
        }
        p++;
    }
    *pos = p;
    return http_expect_crlf(buf, wlen, pos);
}

// Reads one chunk size line: hex digits, an optional extension and CR LF.
static enum http_parse_status http_chunk_size(const char *buf, uint32_t wlen, uint32_t *pos, uint32_t *size) {
    uint32_t p = *pos;
    uint32_t v = 0;
    while (p < wlen && http_hex_value(buf[p]) < 16) {
        v = v * 16 + http_hex_value(buf[p]);
        if (v > REQUEST_MAX) {
            return HTTP_PARSE_BAD;
        }
        p++;
    }
    if (p >= wlen) {
        return HTTP_PARSE_INCOMPLETE;
    }
    if (p == *pos) {
        return HTTP_PARSE_BAD;
    }
    *pos = p;
    *size = v;
    if (buf[p] == '\r') {
        return http_expect_crlf(buf, wlen, pos);
    }
    if (buf[p] == ' ' || buf[p] == '\t' || buf[p] == ';') {
        return http_chunk_ext(buf, wlen, pos);
    }
    return HTTP_PARSE_BAD;
}

// Skips the trailer lines after the last chunk and the blank line that ends the body.
static enum http_parse_status http_chunk_trailers(const char *buf, uint32_t wlen, uint32_t *pos) {
    uint32_t p = *pos;
    while (p < wlen) {
        uint32_t line = p;
        while (p < wlen && buf[p] != '\r') {
            if (http_is_ctl(buf[p])) {
                return HTTP_PARSE_BAD;
            }
            p++;
        }
        enum http_parse_status st = http_expect_crlf(buf, wlen, &p);
        *pos = p;
        if (st != HTTP_PARSE_OK || p == line + 2) {
            return st;
        }
    }
    return HTTP_PARSE_INCOMPLETE;
}

// Walks a chunked body that starts at start; with copy set it also moves the data down so the body is contiguous.
static enum http_parse_status http_chunked(char *buf, uint32_t len, uint32_t start, bool copy, struct http_chunked *out) {
    uint32_t wlen = len < REQUEST_MAX ? len : REQUEST_MAX;
    uint32_t pos = start;
    uint32_t w = start;
    while (pos < wlen) {
        uint32_t size = 0;
        enum http_parse_status st = http_chunk_size(buf, wlen, &pos, &size);
        if (st != HTTP_PARSE_OK) {
            return st;
        }
        if (!size) {
            st = http_chunk_trailers(buf, wlen, &pos);
            out->end = pos;
            out->decoded = w - start;
            return st;
        }
        if (size > wlen - pos) {
            return HTTP_PARSE_INCOMPLETE;
        }
        if (copy && w != pos) {
            memmove(buf + w, buf + pos, size);
        }
        w += size;
        pos += size;
        st = http_expect_crlf(buf, wlen, &pos);
        if (st != HTTP_PARSE_OK) {
            return st;
        }
    }
    return HTTP_PARSE_INCOMPLETE;
}

// Finishes a request whose body is framed by Content-Length (or has none).
static enum http_parse_status http_body_plain(char *buf, uint32_t len, struct request *req, const struct http_hdrs *hd,
                                              uint32_t end) {
    uint32_t cl = hd->has_cl ? hd->cl : 0;
    if (cl > REQUEST_MAX - end) {
        return http_reject(req, len);
    }
    if (len - end < cl) {
        return http_wait(req, hd->expect && !hd->v10);
    }
    req->body = buf + end;
    req->body_len = cl;
    req->consumed = end + cl;
    return HTTP_PARSE_OK;
}

// Finishes a chunked request: the body is validated first and decoded in place only when it is complete.
static enum http_parse_status http_body_chunked(char *buf, uint32_t len, struct request *req, const struct http_hdrs *hd,
                                                uint32_t end) {
    struct http_chunked ck = {0};
    enum http_parse_status st = http_chunked(buf, len, end, false, &ck);
    if (st == HTTP_PARSE_INCOMPLETE) {
        return http_starved(req, len, hd);
    }
    if (st == HTTP_PARSE_BAD || http_chunked(buf, len, end, true, &ck) != HTTP_PARSE_OK) {
        return http_reject(req, len);
    }
    req->body = buf + end;
    req->body_len = ck.decoded;
    req->consumed = ck.end;
    return HTTP_PARSE_OK;
}

// Parses one request from the front of buf; a chunked body is decoded in place and consumed still counts raw bytes.
static enum http_parse_status http_parse(char *buf, uint32_t len, struct request *req) {
    struct http_head head = {{0}, 0, 0};
    struct http_hdrs hd = {0};
    uint32_t limit = len < HEADER_MAX + 4u ? len : HEADER_MAX + 4u;
    *req = (struct request){0};
    enum http_scan scan = http_scan_head(buf, limit, &head);
    if (UNLIKELY(scan == HTTP_SCAN_BAD)) {
        return http_reject(req, len);
    }
    if (scan == HTTP_SCAN_MORE) {
        return len >= HEADER_MAX + 4u ? http_reject(req, len) : http_wait(req, false);
    }
    if (UNLIKELY(!http_parse_lines(buf, &head, req, &hd))) {
        return http_reject(req, len);
    }
    req->close_after = hd.close || (hd.v10 && !hd.keep_alive);
    return hd.chunked ? http_body_chunked(buf, len, req, &hd, head.end) : http_body_plain(buf, len, req, &hd, head.end);
}
