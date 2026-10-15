#!/usr/bin/env bash
# Durability: drive creates and likes, kill -9 the server at random moments, restart on the same file and check that
# every acknowledged row exists. Usage: tests/durability.sh [rounds] (default 8). Needs bin/server (bash build.sh),
# seed/feed.db, curl, openssl and sqlite3. Environment: PORT (default 3331), WORKERS (default 4), SEED.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/.." && pwd)"
server="$root/bin/server"
seed="${SEED:-$here/../../../seed/feed.db}"
rounds="${1:-8}"
workers="${WORKERS:-4}"
port="${PORT:-3331}"
secret=twelve-dollar-challenge
[ -x "$server" ] || { echo "missing $server, run build.sh first"; exit 2; }
[ -f "$seed" ] || { echo "missing seed $seed"; exit 2; }
tmp="$(mktemp -d)"
db="$tmp/feed.db"
cp "$seed" "$db"
pid=0
stop_all() {
  [ "$pid" -gt 0 ] && kill -9 "$pid" 2>/dev/null
  jobs -p | xargs -r kill 2>/dev/null
  rm -rf "$tmp"
}
trap stop_all EXIT

b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }
# Prints a token for user id $1 valid for an hour.
token() {
  local now h p s
  now=$(date +%s)
  h="$(printf '%s' '{"alg":"HS256","typ":"JWT"}' | b64url)"
  p="$(printf '{"sub":"%s","username":"dur_user_%s","iat":%s,"exp":%s}' "$1" "$1" "$now" "$((now + 3600))" | b64url)"
  s="$(printf '%s' "$h.$p" | openssl dgst -sha256 -hmac "$secret" -binary | b64url)"
  echo "$h.$p.$s"
}

start_server() {
  SQLITE_PATH="$db" JWT_SECRET="$secret" HOST=127.0.0.1 PORT="$port" "$server" >"$tmp/server.log" 2>&1 &
  pid=$!
  for _ in $(seq 100); do
    curl -sf "http://127.0.0.1:$port/health" >/dev/null && return 0
    sleep 0.1
  done
  echo "server did not become healthy"
  cat "$tmp/server.log"
  exit 1
}

# One worker: create a post, record it once the 201 arrived, like it, record the like once the answer arrived.
worker() {
  local w="$1" round="$2" n=0 user tok out code body id
  user=$((w + 1))
  tok="$(token "$user")"
  while true; do
    n=$((n + 1))
    body="dur-$round-$w-$n"
    out="$(curl -s -m 2 -w '\n%{http_code}' -X POST "http://127.0.0.1:$port/posts" -H "Authorization: Bearer $tok" \
      --data-binary "{\"body\":\"$body\"}")" || continue
    code="${out##*$'\n'}"
    [ "$code" = 201 ] || continue
    id="$(printf '%s' "$out" | sed -n 's/.*"post":{"id":\([0-9]*\),.*/\1/p')"
    echo "post $id $body" >>"$tmp/acked.$w"
    out="$(curl -s -m 2 -w '\n%{http_code}' -X POST "http://127.0.0.1:$port/posts/$id/like" -H "Authorization: Bearer $tok")" || continue
    code="${out##*$'\n'}"
    [ "$code" = 201 ] && echo "like $user $id" >>"$tmp/acked.$w"
  done
}

fail=0
total_posts=0
total_likes=0
for round in $(seq "$rounds"); do
  start_server
  wpids=()
  for w in $(seq "$workers"); do
    worker "$w" "$round" 2>/dev/null &
    wpids+=($!)
  done
  sleep "0.$((RANDOM % 9 + 3))"
  kill -9 "$pid"
  wait "$pid" 2>/dev/null
  pid=0
  kill "${wpids[@]}" 2>/dev/null
  wait "${wpids[@]}" 2>/dev/null
  cat "$tmp"/acked.* >"$tmp/acked.all" 2>/dev/null || : >"$tmp/acked.all"
  rm -f "$tmp"/acked.[0-9]*
  missing=0
  while read -r kind a b c; do
    if [ "$kind" = post ]; then
      got="$(sqlite3 "$db" "SELECT body FROM posts WHERE id = $a;")"
      [ "$got" = "$b" ] || { echo "round $round: acknowledged post $a missing"; missing=$((missing + 1)); }
      total_posts=$((total_posts + 1))
    else
      got="$(sqlite3 "$db" "SELECT count(*) FROM likes WHERE user_id = $a AND post_id = $b;")"
      [ "$got" = 1 ] || { echo "round $round: acknowledged like $a/$b missing"; missing=$((missing + 1)); }
      total_likes=$((total_likes + 1))
    fi
  done <"$tmp/acked.all"
  rm -f "$tmp/acked.all"
  [ "$(sqlite3 "$db" 'PRAGMA integrity_check;')" = ok ] || { echo "round $round: integrity check failed"; missing=$((missing + 1)); }
  echo "round $round: $missing problems"
  fail=$((fail + missing))
done
echo "checked $total_posts acknowledged posts and $total_likes acknowledged likes over $rounds kills, problems: $fail"
[ "$fail" = 0 ]
