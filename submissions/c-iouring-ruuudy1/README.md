# c-iouring-ruuudy1

A single-threaded C server on raw io_uring with SQLite compiled in. This README is a stub; the final text is written at the end.

## Stack and versions

- C (GNU C17), GCC 13.3 from Ubuntu 24.04 `build-essential`.
- io_uring through liburing 2.15, built statically from a pinned tarball. No framework.
- SQLite 3.53.4 amalgamation, compiled into the server from a pinned tarball.
- Linux 6.1 or newer with io_uring enabled.

## Serving mode

Direct on `0.0.0.0:80`, no Nginx.

## Build and run

```bash
sudo bash install.sh
bash build.sh
SQLITE_PATH=/path/to/feed.db JWT_SECRET=twelve-dollar-challenge HOST=0.0.0.0 PORT=80 bash start.sh
```

## Optimizations

To be written.

## Rules

To be written.

## Results

To be written.
