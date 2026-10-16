#!/usr/bin/env bash
# Builds bin/server as a normal user from two SHA-256-pinned downloads (SQLite and liburing) and the sources in src/.
# PGO=1 switches on the two-pass profile-guided build around --pgo-train; the default is a plain -O3 build.
set -euo pipefail
cd "$(dirname "$0")"

SQLITE_URL="https://www.sqlite.org/2026/sqlite-autoconf-3530400.tar.gz"
SQLITE_SHA256="0e9483900e92cd5de8fd48d16bf9200145a61f7fd5be542a5ac81d8a9516eb9c"
URING_URL="https://github.com/axboe/liburing/archive/refs/tags/liburing-2.15.tar.gz"
URING_SHA256="8d052f2622dcb3678cbaee5ff582a87572672a6c0a56533cdda5b65cb636120a"

CFLAGS=(-O3 -march=native -std=gnu17 -fno-plt -fno-semantic-interposition -DNDEBUG -g0)
# Distro hardening is off by default because it costs about 4% on the SQLite path.
HARDENING_OFF=(-fno-stack-protector -fcf-protection=none -fno-stack-clash-protection -U_FORTIFY_SOURCE
  -D_FORTIFY_SOURCE=0 -fno-pie)
WARNINGS=(-Wall -Wextra)
SQLITE_DEFS=(-DSQLITE_THREADSAFE=0 -DSQLITE_DEFAULT_MEMSTATUS=0 -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1
  -DSQLITE_DQS=0 -DSQLITE_LIKE_DOESNT_MATCH_BLOBS -DSQLITE_MAX_EXPR_DEPTH=0 -DSQLITE_OMIT_DEPRECATED
  -DSQLITE_OMIT_PROGRESS_CALLBACK -DSQLITE_OMIT_SHARED_CACHE -DSQLITE_OMIT_LOAD_EXTENSION
  -DSQLITE_OMIT_AUTOINIT -DSQLITE_OMIT_DECLTYPE -DSQLITE_OMIT_JSON -DSQLITE_USE_ALLOCA
  -DHAVE_FDATASYNC=1 -DSQLITE_TEMP_STORE=3 -DSQLITE_ENABLE_MEMSYS5)
# SQLite and liburing headers are system includes so only our own code is warned about.
INCLUDES=(-Isrc -isystem deps/sqlite -isystem deps/liburing/src/include)

# Lets tests/Makefile reuse the exact flag sets without duplicating them.
case "${1:-}" in
  --print-cflags) echo "${CFLAGS[*]} ${HARDENING_OFF[*]} ${WARNINGS[*]}"; exit 0 ;;
  --print-sqlite-defs) echo "${SQLITE_DEFS[*]}"; exit 0 ;;
esac

PGO="${PGO:-0}"

# Downloads <url> to deps/<file> unless a copy that matches <sha256> is already there.
fetch() {
  if ! echo "$2  deps/$3" | sha256sum -c --quiet - >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "deps/$3" "$1"
    echo "$2  deps/$3" | sha256sum -c --quiet -
  fi
}

# Extracts a tarball into deps/<dir> unless it was already extracted from the same pinned archive.
extract() {
  if [ ! -f "deps/$2/.sha256-$3" ]; then
    rm -rf "deps/$2"
    mkdir -p "deps/$2"
    tar -xzf "deps/$1" -C "deps/$2" --strip-components=1
    touch "deps/$2/.sha256-$3"
  fi
}

# Compiles the unity object; the same output path in every pass keeps the profile file name stable.
compile() {
  gcc "${CFLAGS[@]}" "${HARDENING_OFF[@]}" "${WARNINGS[@]}" "${SQLITE_DEFS[@]}" "${INCLUDES[@]}" "$@" \
    -c src/main.c -o build/main.o
}

# Links the unity object against the static liburing into the given output.
link() {
  gcc "${CFLAGS[@]}" "${HARDENING_OFF[@]}" -no-pie "$@" build/main.o deps/liburing/src/liburing.a -o "$OUT"
}

# Two-pass profile-guided build; any training failure falls back to a plain build with a warning.
build_pgo() {
  compile -fprofile-generate -fprofile-update=single
  OUT=build/server-train link -fprofile-generate
  if timeout 120 build/server-train --pgo-train build/train; then
    compile -fprofile-use -fprofile-partial-training -Wno-missing-profile
    OUT=bin/server link -fprofile-use
  else
    echo "warning: PGO training failed, building without profile" >&2
    compile
    OUT=bin/server link
  fi
  rm -rf build/train build/server-train build/*.gcda
}

mkdir -p deps bin build
fetch "$SQLITE_URL" "$SQLITE_SHA256" sqlite.tar.gz
fetch "$URING_URL" "$URING_SHA256" liburing.tar.gz
extract sqlite.tar.gz sqlite "$SQLITE_SHA256"
extract liburing.tar.gz liburing "$URING_SHA256"
if [ ! -f deps/liburing/src/liburing.a ]; then
  (cd deps/liburing && ./configure --cc=gcc >/dev/null && make -s -C src -j"$(nproc)" liburing.a >/dev/null)
fi
if [ "$PGO" = 1 ]; then
  build_pgo
else
  compile
  OUT=bin/server link
fi
echo "built bin/server"
