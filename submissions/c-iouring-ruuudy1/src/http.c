// Owner: http module. Request framing and header parsing over a byte range.

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

// Compares a header name case-insensitively with a lowercase literal of the same length.
static bool http_name_eq(const char *name, uint32_t n, const char *lower, uint32_t lower_n) {
    if (n != lower_n) {
        return false;
    }
    for (uint32_t i = 0; i < n; i++) {
        char c = name[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c + 32);
        }
        if (c != lower[i]) {
            return false;
        }
    }
    return true;
}

// Parses a decimal Content-Length of at most REQUEST_MAX; returns false on anything else.
static bool http_parse_length(const char *p, uint32_t n, uint32_t *out) {
    uint32_t v = 0;
    if (!n || n > 6) {
        return false;
    }
    for (uint32_t i = 0; i < n; i++) {
        if (p[i] < '0' || p[i] > '9') {
            return false;
        }
        v = v * 10 + (uint32_t)(p[i] - '0');
    }
    *out = v;
    return v <= REQUEST_MAX;
}

// Applies one header line to the request; returns false when the request must be rejected.
static bool http_apply_header(struct request *req, const char *name, uint32_t name_n, const char *val, uint32_t val_n,
                              uint32_t *content_len) {
    if (http_name_eq(name, name_n, "content-length", LIT_LEN("content-length"))) {
        return http_parse_length(val, val_n, content_len);
    }
    if (http_name_eq(name, name_n, "authorization", LIT_LEN("authorization"))) {
        req->auth = val;
        req->auth_len = val_n;
    } else if (http_name_eq(name, name_n, "connection", LIT_LEN("connection"))) {
        if (http_name_eq(val, val_n, "close", LIT_LEN("close"))) {
            req->close_after = 1;
        } else if (http_name_eq(val, val_n, "keep-alive", LIT_LEN("keep-alive"))) {
            req->close_after = 0;
        }
    } else if (http_name_eq(name, name_n, "expect", LIT_LEN("expect"))) {
        req->expect_continue = 1;
    } else if (http_name_eq(name, name_n, "transfer-encoding", LIT_LEN("transfer-encoding"))) {
        return false;
    }
    return true;
}

// Parses the request line; returns the offset of the first header line or 0 on failure.
static uint32_t http_parse_request_line(const char *buf, uint32_t head_len, struct request *req) {
    const char *eol = memchr(buf, '\r', head_len);
    const char *sp1 = memchr(buf, ' ', (size_t)(eol - buf));
    if (!sp1) {
        return 0;
    }
    const char *target = sp1 + 1;
    const char *sp2 = memchr(target, ' ', (size_t)(eol - target));
    if (!sp2 || sp2 == target || *target != '/' || (size_t)(sp2 - target) > TARGET_MAX) {
        return 0;
    }
    uint32_t method_n = (uint32_t)(sp1 - buf);
    req->method = HTTP_OTHER;
    if (method_n == 3 && !memcmp(buf, "GET", 3)) {
        req->method = HTTP_GET;
    } else if (method_n == 4 && !memcmp(buf, "POST", 4)) {
        req->method = HTTP_POST;
    }
    const char *query = memchr(target, '?', (size_t)(sp2 - target));
    req->path = target;
    req->path_len = (uint32_t)((query ? query : sp2) - target);
    size_t version_n = (size_t)(eol - sp2);
    req->close_after = (uint8_t)(version_n == LIT_LEN(" HTTP/1.0") && !memcmp(sp2, " HTTP/1.0", version_n));
    return (uint32_t)(eol - buf) + 2;
}

// Parses one request from the front of buf; chunked bodies are rejected until the http module adds them.
static enum http_parse_status http_parse(char *buf, uint32_t len, struct request *req) {
    memset(req, 0, sizeof *req);
    uint32_t scan = len < HEADER_MAX + 4 ? len : HEADER_MAX + 4;
    const char *end = memmem(buf, scan, "\r\n\r\n", 4);
    if (!end) {
        return len > HEADER_MAX ? HTTP_PARSE_BAD : HTTP_PARSE_INCOMPLETE;
    }
    uint32_t head_len = (uint32_t)(end - buf) + 4;
    uint32_t pos = http_parse_request_line(buf, head_len, req);
    uint32_t content_len = 0;
    if (!pos) {
        return HTTP_PARSE_BAD;
    }
    while (pos < head_len - 2) {
        const char *line = buf + pos;
        const char *eol = memchr(line, '\r', head_len - pos);
        const char *colon = memchr(line, ':', (size_t)(eol - line));
        if (!colon) {
            return HTTP_PARSE_BAD;
        }
        const char *val = colon + 1;
        while (val < eol && *val == ' ') {
            val++;
        }
        if (!http_apply_header(req, line, (uint32_t)(colon - line), val, (uint32_t)(eol - val), &content_len)) {
            return HTTP_PARSE_BAD;
        }
        pos = (uint32_t)(eol - buf) + 2;
    }
    if (head_len + content_len > REQUEST_MAX) {
        return HTTP_PARSE_BAD;
    }
    if (len - head_len < content_len) {
        return HTTP_PARSE_INCOMPLETE;
    }
    req->body = buf + head_len;
    req->body_len = content_len;
    req->consumed = head_len + content_len;
    req->expect_continue = 0;
    return HTTP_PARSE_OK;
}
