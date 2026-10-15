#!/usr/bin/env python3
"""Differential driver for tests/fuzz_json.c against Python's json module.

Usage: fuzz_json.py [iterations] [seed] [path-to-fuzz_json-binary]
The binary streams one record per document (see emit_record in fuzz_json.c); every record is compared with a
reference built from json.loads (NaN and Infinity rejected, duplicate keys last wins, depth capped at 64).
"""
import json
import math
import re
import struct
import subprocess
import sys

sys.set_int_max_str_digits(0)
sys.setrecursionlimit(10000)

DEPTH_MAX = 64
BODY_MAX_CHARS = 500
FIELD_KEYS = ["body", "n", "a", "café"]
ABSENT, STRING, NUMBER, OTHER = 0, 1, 2, 3
OK, MALFORMED, NOT_OBJECT = 0, 1, 2
B_OK, B_MALFORMED, B_REQUIRED, B_TOO_LONG = 0, 1, 2, 3
TRIM = set(
    [0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF]
    + list(range(0x2000, 0x200B))
)
LONE = re.compile("[\ud800-\udfff]")


class Obj:
    """An object with its pairs kept in order so duplicates and depth stay visible."""

    def __init__(self, pairs):
        self.pairs = pairs
        self.map = dict(pairs)


def reject_constant(name):
    raise ValueError("constant " + name)


def depth_of(v):
    """Nesting depth with a top-level container counting 1, computed without recursion."""
    best = 0
    stack = [(v, 1)]
    while stack:
        cur, d = stack.pop()
        if isinstance(cur, Obj):
            best = max(best, d)
            stack.extend((c, d + 1) for _, c in cur.pairs)
        elif isinstance(cur, list):
            best = max(best, d)
            stack.extend((c, d + 1) for c in cur)
    return best


def parse(doc):
    """Returns the parsed value or None when the document is not accepted."""
    try:
        text = doc.decode("utf-8", errors="strict")
        value = json.loads(text, parse_constant=reject_constant, object_pairs_hook=Obj)
    except (ValueError, RecursionError, UnicodeDecodeError):
        return None
    if depth_of(value) > DEPTH_MAX:
        return None
    return (value,)


def fix_text(s):
    return LONE.sub("�", s)


def classify(v):
    if isinstance(v, bool) or v is None or isinstance(v, (list, Obj)):
        return OTHER
    if isinstance(v, str):
        return STRING
    return NUMBER


def to_float(v):
    try:
        return float(v)
    except OverflowError:
        return math.inf if v > 0 else -math.inf


def reference(doc):
    """Returns (extract status, [field results], body status, body bytes)."""
    parsed = parse(doc)
    if parsed is None:
        return MALFORMED, [(ABSENT, None)] * 4, B_MALFORMED, b""
    value = parsed[0]
    if not isinstance(value, Obj):
        return NOT_OBJECT, [(ABSENT, None)] * 4, B_REQUIRED, b""
    fields = []
    for key in FIELD_KEYS:
        if key not in value.map:
            fields.append((ABSENT, None))
            continue
        v = value.map[key]
        kind = classify(v)
        if kind == STRING:
            fields.append((kind, fix_text(v).encode("utf-8")))
        elif kind == NUMBER:
            fields.append((kind, to_float(v)))
        else:
            fields.append((kind, None))
    body = value.map.get("body")
    if not isinstance(body, str):
        return OK, fields, B_REQUIRED, b""
    text = fix_text(body)
    start, end = 0, len(text)
    while start < end and ord(text[start]) in TRIM:
        start += 1
    while end > start and ord(text[end - 1]) in TRIM:
        end -= 1
    text = text[start:end]
    if not text:
        return OK, fields, B_REQUIRED, b""
    if len(text) > BODY_MAX_CHARS:
        return OK, fields, B_TOO_LONG, b""
    return OK, fields, B_OK, text.encode("utf-8")


def read_exact(stream, n):
    data = stream.read(n)
    if len(data) != n:
        raise EOFError("truncated record stream")
    return data


def read_u32(stream):
    return struct.unpack("<I", read_exact(stream, 4))[0]


def read_record(stream):
    head = stream.read(4)
    if not head:
        return None
    doc = read_exact(stream, struct.unpack("<I", head)[0])
    status, body_status = read_exact(stream, 2)
    fields = []
    for _ in range(4):
        kind = read_exact(stream, 1)[0]
        if kind == STRING:
            fields.append((kind, read_exact(stream, read_u32(stream))))
        elif kind == NUMBER:
            fields.append((kind, struct.unpack("<d", read_exact(stream, 8))[0]))
        else:
            fields.append((kind, None))
    body = read_exact(stream, read_u32(stream))
    return doc, status, fields, body_status, body


def numbers_match(got, want):
    if math.isinf(want) or math.isinf(got):
        return got == want
    return math.isclose(got, want, rel_tol=1e-14, abs_tol=0.0)


def fields_match(got, want):
    for (gk, gv), (wk, wv) in zip(got, want):
        if gk != wk:
            return False
        if gk == STRING and gv != wv:
            return False
        if gk == NUMBER and not numbers_match(gv, wv):
            return False
    return True


def main():
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 100000
    seed = sys.argv[2] if len(sys.argv) > 2 else "12345"
    binary = sys.argv[3] if len(sys.argv) > 3 else "build/tests/fuzz/fuzz_json"
    proc = subprocess.Popen([binary, str(iters), seed, "emit"], stdout=subprocess.PIPE, bufsize=1 << 20)
    total = mismatches = 0
    kinds = {}
    while True:
        rec = read_record(proc.stdout)
        if rec is None:
            break
        doc, status, fields, body_status, body = rec
        want = reference(doc)
        total += 1
        kinds[(status, body_status)] = kinds.get((status, body_status), 0) + 1
        ok = (status, body_status, body) == (want[0], want[2], want[3]) and fields_match(fields, want[1])
        if not ok:
            mismatches += 1
            if mismatches <= 20:
                print("MISMATCH", doc[:300], "got", status, body_status, body[:60], fields, "want", want[0], want[2], want[3][:60], want[1])
    code = proc.wait()
    print("fuzz_json.py: %d documents compared, %d mismatches, binary exit %d" % (total, mismatches, code))
    print("(extract status, body status) counts:", dict(sorted(kinds.items())))
    if code or mismatches or total != iters:
        sys.exit(1)


if __name__ == "__main__":
    main()
