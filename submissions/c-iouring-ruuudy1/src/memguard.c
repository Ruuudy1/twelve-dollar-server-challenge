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

// Reads MemAvailable in MB; returns false when it cannot be read.
static bool memguard_read_mb(uint64_t *mb) {
    char buf[2048];
    ssize_t n = memguard_fd < 0 ? -1 : pread(memguard_fd, buf, sizeof buf - 1, 0);
    if (n <= 0) {
        return false;
    }
    buf[n] = 0;
    const char *p = strstr(buf, "MemAvailable:");
    if (!p) {
        return false;
    }
    *mb = strtoull(p + LIT_LEN("MemAvailable:"), NULL, 10) / 1024;
    return true;
}

// Samples memory and returns the new state, with hysteresis between stop and resume.
static unsigned memguard_sample(void) {
    uint64_t mb;
    if (!memguard_read_mb(&mb)) {
        return memguard_state_now;
    }
    if (mb < MEM_SHED_MB) {
        memguard_state_now = MEMGUARD_SHED;
    } else if (mb < MEM_STOP_MB) {
        memguard_state_now = MEMGUARD_NO_ACCEPT;
    } else if (mb > MEM_RESUME_MB) {
        memguard_state_now = MEMGUARD_OK;
    }
    return memguard_state_now;
}

// Returns how many idle connections to close this tick: MEM_SHED_PERMILLE of the live ones while shedding.
static NOT_YET_USED uint32_t memguard_shed_count(uint32_t live) {
    return memguard_state_now == MEMGUARD_SHED ? live * MEM_SHED_PERMILLE / 1000 + 1 : 0;
}
