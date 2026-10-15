#!/usr/bin/env python3
"""Connection stress test for the io module.

Starts bin/server on a copy of a database (or uses --no-spawn with an already running server), then checks:
  idle      80,000 idle sockets (exercises the normal-fd accept phase), new connections still served, reuse after idle
  partial   partial headers are closed after about 30 s, idle and progressing connections stay open
  rst       clients that reset the connection while responses are in flight do not hurt the server
  pipeline  1,800 pipelined requests are all answered in order, also when the client reads slowly
  halfclose a request followed by shutdown(SHUT_WR) still gets its response
Run on the machine that hosts the server; needs a raised fd limit for the client (the script raises its own soft limit).

  python3 tests/conn_stress.py --port 3348 --db /home/ruuud/twelve/seed/feed.db
"""
import argparse
import os
import random
import resource
import selectors
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

HEALTH = b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n"
FEED = b"GET /feed HTTP/1.1\r\nHost: x\r\n\r\n"
IP_BIND_ADDRESS_NO_PORT = 24
results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (" - " + detail if detail else ""), flush=True)


def rst_close(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    sock.close()


def read_response(sock, timeout=10.0):
    """Reads one complete response (headers plus Content-Length body); returns (status line, body) or None."""
    sock.settimeout(timeout)
    data = b""
    try:
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                return None
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        length = 0
        for line in head.split(b"\r\n")[1:]:
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":")[1])
        while len(rest) < length:
            chunk = sock.recv(65536)
            if not chunk:
                return None
            rest += chunk
        return head.split(b"\r\n")[0], rest[:length]
    except OSError:
        return None


def healthy(port):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(HEALTH)
    r = read_response(s)
    s.close()
    return r is not None and r[0].startswith(b"HTTP/1.1 200")


def fd_count(pid):
    return len(os.listdir("/proc/%d/fd" % pid))


def open_idle(port, count, ips):
    """Opens count connections spread over source addresses; returns the connected sockets."""
    socks = []
    sel = selectors.DefaultSelector()
    batch = 1000
    for start in range(0, count, batch):
        pending = {}
        for i in range(start, min(count, start + batch)):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1)
            s.bind((ips[i % len(ips)], 0))
            s.setblocking(False)
            s.connect_ex(("127.0.0.1", port))
            pending[s.fileno()] = s
            sel.register(s, selectors.EVENT_WRITE)
        deadline = time.time() + 30
        while pending and time.time() < deadline:
            for key, _ in sel.select(1.0):
                s = key.fileobj
                sel.unregister(s)
                pending.pop(s.fileno(), None)
                if s.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                    socks.append(s)
                else:
                    s.close()
        for s in pending.values():
            sel.unregister(s)
            s.close()
        time.sleep(0.02)
    sel.close()
    return socks


def test_idle(port, pid, count):
    ips = ["127.0.0.%d" % n for n in range(2, 2 + max(2, count // 20000 + 1))]
    socks = open_idle(port, count, ips)
    check("idle: %d sockets connected" % count, len(socks) >= count - 5, "%d connected" % len(socks))
    time.sleep(1.0)
    fds = fd_count(pid)
    check("idle: normal-fd phase reached", fds > 10000, "server holds %d descriptors" % fds)
    check("idle: new connection served while idle sockets are open", healthy(port))
    sample = random.sample(socks, min(300, len(socks))) + socks[-50:]
    ok = 0
    for s in sample:
        try:
            s.sendall(HEALTH)
            r = read_response(s, 5)
            ok += r is not None and r[0].startswith(b"HTTP/1.1 200")
        except OSError:
            pass
    check("idle: reuse after idle", ok == len(sample), "%d of %d" % (ok, len(sample)))
    for s in socks:
        s.close()
    deadline = time.time() + 30
    while time.time() < deadline and fd_count(pid) > 100:
        time.sleep(0.5)
    check("idle: descriptors released after close", fd_count(pid) <= 100, "server holds %d descriptors" % fd_count(pid))
    check("idle: server healthy after release", healthy(port))


def test_partial(port):
    partial = []
    for _ in range(50):
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(b"GET /health HTTP/1.1\r\nHost:")
        partial.append(s)
    idle = socket.create_connection(("127.0.0.1", port))
    trickle = socket.create_connection(("127.0.0.1", port))
    trickle.sendall(b"GET /health HTTP/1.1\r\n")
    start = time.time()
    closed_at = {}
    while time.time() - start < 42 and len(closed_at) < len(partial):
        for i, s in enumerate(partial):
            if i in closed_at:
                continue
            s.settimeout(0.05)
            try:
                if s.recv(1) == b"":
                    closed_at[i] = time.time() - start
            except socket.timeout:
                pass
            except OSError:
                closed_at[i] = time.time() - start
        if int(time.time() - start) % 10 == 5:
            trickle.sendall(b"X-A: b\r\n")
            time.sleep(1)
    check("partial: all partial-header connections closed", len(closed_at) == len(partial), "%d closed" % len(closed_at))
    if closed_at:
        lo, hi = min(closed_at.values()), max(closed_at.values())
        check("partial: closed between 29 and 38 s", 29 <= lo and hi <= 38, "%.1f to %.1f s" % (lo, hi))
    idle.sendall(HEALTH)
    r = read_response(idle, 5)
    check("partial: silent connection stayed open and still works", r is not None and r[0].startswith(b"HTTP/1.1 200"))
    check("partial: server healthy", healthy(port))
    idle.close()
    trickle.close()


def test_rst(port):
    for _ in range(300):
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(FEED * 3)
        rst_close(s)
    for _ in range(100):
        s = socket.create_connection(("127.0.0.1", port))
        s.sendall(HEALTH * 40)
        time.sleep(0.001)
        rst_close(s)
    time.sleep(0.5)
    check("rst: server healthy after resets mid-send", healthy(port))


def test_pipeline(port):
    n = 1800
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(HEALTH * n)
    s.settimeout(20)
    data = b""
    deadline = time.time() + 20
    while data.count(b"HTTP/1.1 200 OK") < n and time.time() < deadline:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    check("pipeline: 1800 requests answered", data.count(b"HTTP/1.1 200 OK") == n, "%d" % data.count(b"HTTP/1.1 200 OK"))
    s.close()
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(HEALTH * (n - 1) + b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    data = b""
    t0 = time.time()
    while time.time() - t0 < 6:
        s.settimeout(1)
        try:
            chunk = s.recv(200)
        except socket.timeout:
            continue
        if not chunk:
            break
        data += chunk
        time.sleep(0.002)
    check("pipeline: slow reader gets every response and the close", data.count(b"HTTP/1.1 200 OK") == n and data.count(b"Connection: close") == 1,
          "%d responses" % data.count(b"HTTP/1.1 200 OK"))
    s.close()
    check("pipeline: server healthy", healthy(port))


def test_halfclose(port):
    s = socket.create_connection(("127.0.0.1", port))
    s.sendall(HEALTH * 3)
    s.shutdown(socket.SHUT_WR)
    data = b""
    s.settimeout(5)
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    except OSError:
        pass
    check("halfclose: responses delivered before close", data.count(b"HTTP/1.1 200 OK") >= 1, "%d" % data.count(b"HTTP/1.1 200 OK"))
    s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=3348)
    ap.add_argument("--server", default=os.path.join(os.path.dirname(__file__), "..", "bin", "server"))
    ap.add_argument("--db", default="/home/ruuud/twelve/seed/feed.db")
    ap.add_argument("--idle", type=int, default=80000)
    ap.add_argument("--no-spawn", action="store_true")
    ap.add_argument("--only", default="")
    args = ap.parse_args()
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(hard, 200000), hard))
    proc = None
    tmp = tempfile.mkdtemp()
    if not args.no_spawn:
        db = os.path.join(tmp, "feed.db")
        subprocess.check_call(["cp", args.db, db])
        env = dict(os.environ, SQLITE_PATH=db, JWT_SECRET="twelve-dollar-challenge", HOST="127.0.0.1", PORT=str(args.port))
        proc = subprocess.Popen(["prlimit", "--nofile=65535:65535", args.server, "--stats"], env=env,
                                stderr=open(os.path.join(tmp, "server.log"), "w"))
        for _ in range(100):
            try:
                if healthy(args.port):
                    break
            except OSError:
                time.sleep(0.2)
    pid = proc.pid if proc else int(subprocess.check_output(["pgrep", "-n", "server"]))
    suites = {"idle": lambda: test_idle(args.port, pid, args.idle), "pipeline": lambda: test_pipeline(args.port),
              "halfclose": lambda: test_halfclose(args.port), "rst": lambda: test_rst(args.port),
              "partial": lambda: test_partial(args.port)}
    for name, fn in suites.items():
        if args.only and name not in args.only.split(","):
            continue
        print("== " + name, flush=True)
        fn()
    if proc:
        proc.send_signal(signal.SIGTERM)
        check("server exits 0 on SIGTERM", proc.wait(timeout=20) == 0)
        print("server log: " + os.path.join(tmp, "server.log"))
    failed = results.count(False)
    print("RESULT %d passed, %d failed" % (results.count(True), failed))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
