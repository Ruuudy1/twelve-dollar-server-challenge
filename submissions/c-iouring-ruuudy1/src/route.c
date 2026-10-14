// Owner: http module. Routing by method and path shape, id parsing and cohort assignment.

enum route_kind {
    ROUTE_NOT_FOUND,
    ROUTE_HEALTH,
    ROUTE_FEED,
    ROUTE_POST,
    ROUTE_CREATE,
    ROUTE_LIKE,
    // Synthetic route for a request the parser rejected; answered 400 and the connection closes.
    ROUTE_BAD_REQUEST,
};

// Execution cohorts of a pass, in the order they run.
enum route_cohort {
    COHORT_WRITE,
    COHORT_FEED,
    COHORT_POST,
    COHORT_OTHER,
    COHORT_COUNT,
};

// Where a request goes; id is the raw text of {id} for ROUTE_POST and ROUTE_LIKE and is parsed by the handler.
struct route {
    uint8_t kind;
    struct slice id;
};

enum route_id_status {
    ID_OK,
    // Not a positive decimal integer: 400 invalid post id.
    ID_INVALID,
    // Positive but beyond int64: 404 post not found.
    ID_NOT_FOUND,
};

// Returns true when the route needs a valid token before anything else is checked.
static NOT_YET_USED bool route_needs_auth(uint8_t kind) {
    return kind == ROUTE_CREATE || kind == ROUTE_LIKE;
}

// Maps a route kind to its cohort: writes first, then feeds, then single posts, then the rest.
static uint8_t route_cohort(uint8_t kind) {
    switch (kind) {
    case ROUTE_CREATE:
    case ROUTE_LIKE:
        return COHORT_WRITE;
    case ROUTE_FEED:
        return COHORT_FEED;
    case ROUTE_POST:
        return COHORT_POST;
    default:
        return COHORT_OTHER;
    }
}

// Returns true when the path is exactly the literal.
static bool route_path_is(const struct request *req, const char *lit, uint32_t n) {
    return req->path_len == n && !memcmp(req->path, lit, n);
}

// Classifies a parsed request; every unknown shape is ROUTE_NOT_FOUND.
static void route_classify(const struct request *req, struct route *r) {
    r->kind = ROUTE_NOT_FOUND;
    r->id = (struct slice){0};
    if (req->method == HTTP_GET && route_path_is(req, "/health", LIT_LEN("/health"))) {
        r->kind = ROUTE_HEALTH;
    } else if (req->method == HTTP_GET && route_path_is(req, "/feed", LIT_LEN("/feed"))) {
        r->kind = ROUTE_FEED;
    } else if (req->method == HTTP_POST && route_path_is(req, "/posts", LIT_LEN("/posts"))) {
        r->kind = ROUTE_CREATE;
    } else if (req->path_len > LIT_LEN("/posts/") && !memcmp(req->path, "/posts/", LIT_LEN("/posts/"))) {
        const char *id = req->path + LIT_LEN("/posts/");
        uint32_t n = req->path_len - (uint32_t)LIT_LEN("/posts/");
        const char *slash = memchr(id, '/', n);
        if (!slash && req->method == HTTP_GET) {
            r->kind = ROUTE_POST;
            r->id = (struct slice){id, n};
        } else if (slash && req->method == HTTP_POST && slash != id &&
                   (uint32_t)(req->path + req->path_len - slash) == LIT_LEN("/like") &&
                   !memcmp(slash, "/like", LIT_LEN("/like"))) {
            r->kind = ROUTE_LIKE;
            r->id = (struct slice){id, (uint32_t)(slash - id)};
        }
    }
}

// Parses an id: ASCII digits only, nonzero, at most int64 range.
static NOT_YET_USED enum route_id_status route_parse_id(struct slice s, int64_t *out) {
    uint64_t v = 0;
    bool nonzero = false;
    bool overflow = false;
    if (!s.n) {
        return ID_INVALID;
    }
    for (uint32_t i = 0; i < s.n; i++) {
        if (s.p[i] < '0' || s.p[i] > '9') {
            return ID_INVALID;
        }
        uint64_t digit = (uint64_t)(s.p[i] - '0');
        nonzero |= digit != 0;
        if (v > (UINT64_MAX - digit) / 10) {
            overflow = true;
        } else {
            v = v * 10 + digit;
        }
    }
    if (!nonzero) {
        return ID_INVALID;
    }
    if (overflow || v > INT64_MAX) {
        return ID_NOT_FOUND;
    }
    *out = (int64_t)v;
    return ID_OK;
}
