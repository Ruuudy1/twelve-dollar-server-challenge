// Owner: build module. The --pgo-train entry: synthetic database plus request replay.

// Runs the PGO training workload in dir and returns 0 on success; build.sh falls back to a plain build on failure.
static int train_run(const char *dir) {
    // A failed write to stderr is not actionable here.
    (void)fprintf(stderr, "pgo-train is not implemented yet (dir %s)\n", dir);
    return 1;
}
