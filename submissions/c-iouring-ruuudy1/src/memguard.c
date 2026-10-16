// Owner: io module. MemAvailable sampling, accept gating and idle shedding.

enum memguard_state {
    // Accepting normally.
    MEMGUARD_OK,
    // Accept is cancelled until MemAvailable recovers past the resume threshold.
    MEMGUARD_NO_ACCEPT,
    // Accept is cancelled and idle connections are being shed.
    MEMGUARD_SHED,
};

static int memguard_fd = -1;
static unsigned memguard_state_now = MEMGUARD_OK;

// Opens /proc/meminfo for pread sampling.
static void memguard_init(void) {
    memguard_fd = open("/proc/meminfo", O_RDONLY | O_CLOEXEC);
}

// Finds the MemAvailable line in meminfo text and returns its value in MB; false when absent or malformed.
static bool memguard_parse_mb(const char *buf, size_t n, uint64_t *mb) {
    static const char key[] = "MemAvailable:";
    const char *end = buf + n;
    for (const char *p = buf; (size_t)(end - p) > LIT_LEN(key); p++) {
        if (memcmp(p, key, LIT_LEN(key)) != 0) {
            continue;
        }
        const char *q = p + LIT_LEN(key);
        uint64_t kb;
        if (!batch_scan_u64(&q, end, &kb)) {
            return false;
        }
        *mb = kb / 1024;
        return true;
    }
    return false;
}

// Reads MemAvailable in MB; returns false when it cannot be read.
static bool memguard_read_mb(uint64_t *mb) {
    char buf[2048];
    ssize_t n = memguard_fd < 0 ? -1 : pread(memguard_fd, buf, sizeof buf, 0);
    return n > 0 && memguard_parse_mb(buf, (size_t)n, mb);
}

// Applies one MemAvailable reading (MB) to the state, with hysteresis between stop and resume.
static unsigned memguard_step(uint64_t mb) {
    if (mb < MEM_SHED_MB) {
        memguard_state_now = MEMGUARD_SHED;
    } else if (mb < MEM_STOP_MB) {
        memguard_state_now = MEMGUARD_NO_ACCEPT;
    } else if (mb > MEM_RESUME_MB) {
        memguard_state_now = MEMGUARD_OK;
    } else if (memguard_state_now == MEMGUARD_SHED) {
        memguard_state_now = MEMGUARD_NO_ACCEPT;
    }
    return memguard_state_now;
}

// Samples memory and returns the new state.
static unsigned memguard_sample(void) {
    uint64_t mb;
    if (!memguard_read_mb(&mb)) {
        return memguard_state_now;
    }
    return memguard_step(mb);
}

// Returns how many idle connections to close this tick: MEM_SHED_PERMILLE of the live ones while shedding.
static uint32_t memguard_shed_count(uint32_t live) {
    return memguard_state_now == MEMGUARD_SHED ? live * MEM_SHED_PERMILLE / 1000 + 1 : 0;
}
