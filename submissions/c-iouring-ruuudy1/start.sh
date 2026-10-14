#!/usr/bin/env bash
# Runs the server in the foreground; configuration comes only from SQLITE_PATH, JWT_SECRET, HOST and PORT.
set -euo pipefail
exec "$(dirname "$0")/bin/server"
