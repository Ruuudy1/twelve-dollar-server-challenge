#pragma once

// Checkpoint when the WAL holds this many frames.
#define CKPT_FRAMES 1024
// Ask the kernel to start writing the WAL back every this many frames.
#define WAL_PRESYNC_FRAMES 256
// SQLite pragma values (strings so they can be pasted into the pragma text).
#define DB_MMAP_SIZE "0"
#define DB_CACHE_SIZE "-131072"
#define DB_JOURNAL_SIZE_LIMIT "67108864"
// Scratch bytes for one request: unescaped bodies, usernames and token segments.
#define SCRATCH_SIZE 32768

// Ring geometry.
#define RING_SQ_ENTRIES 4096
#define RING_CQ_ENTRIES 65536
// Provided receive buffers: count must be a power of two.
#define PROV_BUF_COUNT 4096
#define PROV_BUF_SIZE 1024
#define PROV_BUF_GROUP 1
// Direct descriptor slots and the live-connection count past which accept switches to normal fds.
#define DIRECT_SLOTS 65535
#define ACCEPT_DIRECT_LIMIT 63000
#define ACCEPT_DIRECT_RESUME 61000
// Largest normal fd the connection table can index.
#define NORMAL_FD_MAX 65536
// Connection table size: direct slots first, then normal fds at DIRECT_SLOTS + fd.
#define CONN_MAX (DIRECT_SLOTS + NORMAL_FD_MAX)

// Listener options.
#define LISTEN_BACKLOG 65535
#define KEEPALIVE_IDLE_S 120
// Zero disables TCP_DEFER_ACCEPT; a positive value is the seconds to wait for the first request.
#define LISTEN_DEFER_ACCEPT_S 0

// Pass size K: requests served and committed together.
#define PASS_MAX_REQUESTS 256
// Requests one receive completion can add past the K check (pipeline cap per connection).
#define PASS_WORK_SLACK 4
// Completions drained per pass, so a pass of tiny partial reads still ends.
#define PASS_CQE_MAX 4096

// Response blocks: 16 KB each, grown by mmap, plus a few 64 KB jumbo blocks.
#define BLOCK_BYTES 16384
#define BLOCK_INITIAL 2048
#define BLOCK_GROW 1024
#define BLOCK_CAP 16384
#define BLOCK_JUMBO_BYTES 65536
#define BLOCK_JUMBO_MAX 64
// Bytes reserved in front of every response body for the status line and headers.
#define RESP_HDR_ROOM 128

// HTTP limits.
#define HEADER_MAX 8192
#define REQUEST_MAX 16000
#define TARGET_MAX 2048
// Queued response blocks that pause a connection, and the level at which it resumes.
#define PAUSE_BLOCKS 4
#define PAUSE_RESUME_BLOCKS 1
#define PAUSE_IN_MAX 65536
// Seconds without progress before a partial request or unsent response is closed, and the sweep period.
#define STALL_TIMEOUT_S 30
#define SWEEP_INTERVAL_S 5

// Memory guard thresholds in MB of MemAvailable, and the share of idle connections shed per tick.
#define MEM_STOP_MB 192
#define MEM_RESUME_MB 256
#define MEM_SHED_MB 96
#define MEM_SHED_PERMILLE 20
#define MEMGUARD_INTERVAL_MS 250

// Adaptive window: ceiling, the delayed-ACK target, controller sampling and hysteresis.
#define WINDOW_CEILING_NS 25000000LL
#define WINDOW_TARGET_NS 35000000LL
#define CTL_SAMPLE_MS 100
#define CTL_UP_SAMPLES 2
#define CTL_DOWN_SAMPLES 5
// Wait used at level zero, where the first completion wakes the loop and the timeout only paces timers.
#define IDLE_WAIT_NS 100000000LL

// JSON and feed limits.
#define JSON_DEPTH_MAX 64
#define BODY_MAX_CHARS 500
#define FEED_LIMIT 20
#define FEED_SPAN_MAX 128

// JWT limits (crypto module): longest header or payload segment, and the signature segment length (32 bytes, unpadded).
#define JWT_SEGMENT_MAX 8192
#define JWT_SIG_CHARS 43

// Stats line period in seconds when --stats is given.
#define STATS_INTERVAL_S 10

// Database module: page cache region for SQLite, sized for DB_CACHE_SIZE (keep the two in step).
#define DB_PAGE_BYTES 4096
#define DB_PAGECACHE_KIB 131072
// Slots beyond the cache_size page count, for pages SQLite holds outside the cache limit.
#define DB_PAGECACHE_SLACK 64
// Heap for SQLite own allocations (memsys5): high-water measured in the tests is under 0.2 MB, so 8 MB is a wide margin.
#define DB_HEAP_MB 8
#define DB_HEAP_MIN_ALLOC 32
