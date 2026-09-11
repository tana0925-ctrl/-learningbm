#!/usr/bin/env python3
"""
Remove the 5 per-request calls to ensureDefenseTables() from src/index.tsx and
record the same DDL as migrations/0030_defense_tables.sql.

The function definition itself is kept; only the call sites are removed.

Design:
  fail-closed : every pre-check runs BEFORE anything is written. If any check
                fails the script exits non-zero having touched no file at all.
  anchor      : the call site anchor must be unique - the exact anchor line must
                account for every call of ensureDefenseTables( in the file.
  sentinel    : idempotency is decided by its own sentinel (calls already gone +
                migration already present), which is deliberately NOT one of the
                verification conditions below.
  never touch : this script only ever opens src/index.tsx and the migration file.
                public/index.html is never opened, and the app.get('/') .replace()
                chain is counted before and after and must be identical.
"""

import os
import re
import sys

SRC = "src/index.tsx"
MIG = "migrations/0030_defense_tables.sql"

# Exact anchor line (2-space indent, no semicolon) - see repo style.
CALL = "  await ensureDefenseTables(c.env)\n"
FUNC_DEF = "async function ensureDefenseTables(env: any) {"

EXPECTED_CALLS = 5
EXPECTED_ROUTES = [
    ("get", "/api/defense/status"),
    ("post", "/api/defense/entry"),
    ("post", "/api/defense/resolve"),
    ("post", "/api/defense/reward-claim"),
    ("put", "/api/admin/defense-toggle"),
]
EXPECTED_TABLES = ["defense_entries", "defense_results", "defense_rewards"]
EXPECTED_CHAIN_REPLACE = 69
EXPECTED_TOTAL_REPLACE = 128

MIG_HEADER = """-- 0030_defense_tables.sql
-- Recorded from ensureDefenseTables() in src/index.tsx.
--
-- These three tables already exist in production D1 and the DDL below is
-- byte-for-byte the DDL that used to run on every defense API request.
-- The per-request DDL was removed because the defense event opens at 12:30
-- with a whole class (about 22 pupils) hitting these routes at once, and
-- awaiting DDL on each request serialises the concurrent queries (see the
-- 2026-09-03 incident: /api/teacher/classes, /api/teacher/all-students and
-- /api/defense/status all returning 500).
--
-- This file is for the record. Applying it is a no-op against the existing
-- database because every statement is CREATE TABLE IF NOT EXISTS.
"""


def die(msg):
    print("FAIL: %s" % msg)
    sys.exit(1)


def ok(msg):
    print("ok  : %s" % msg)


def brace_block(lines, start):
    """End index (exclusive) of the brace-balanced block starting at line start."""
    depth = 0
    started = False
    for i in range(start, len(lines)):
        for ch in lines[i]:
            if ch == "{":
                depth += 1
                started = True
            elif ch == "}":
                depth -= 1
        if started and depth <= 0:
            return i + 1
    return None


def root_block(lines):
    """(start, end) of the single multi-line app.get('/') handler block."""
    cands = []
    for i, line in enumerate(lines):
        if re.search(r"app\.get\((['\"])/\1", line):
            end = brace_block(lines, i)
            if end is not None and end - i > 10:
                cands.append((i, end))
    if len(cands) != 1:
        die("app.get('/') block is not uniquely identifiable: %r" % (cands,))
    return cands[0]


def chain_count(lines, span):
    return "".join(lines[span[0]:span[1]]).count(".replace(")


def main():
    if not os.path.exists(SRC):
        die("%s not found (wrong working directory?)" % SRC)

    with open(SRC, encoding="utf-8", newline="") as f:
        text = f.read()
    lines = text.splitlines(keepends=True)

    n_exact = text.count(CALL)
    n_ident = len(re.findall(r"\bensureDefenseTables\b", text))
    n_paren = len(re.findall(r"ensureDefenseTables\s*\(", text))
    mig_exists = os.path.exists(MIG)

    # ------------------------------------------------------------------
    # idempotency sentinel (deliberately separate from the checks below)
    # ------------------------------------------------------------------
    if n_exact == 0 and n_ident == 1 and mig_exists:
        print("SENTINEL: patch already applied - no files touched.")
        return 0
    if n_exact == 0:
        die("no call sites found but the sentinel does not hold "
            "(identifiers=%d, migration_exists=%s) - refusing to guess"
            % (n_ident, mig_exists))

    # ------------------------------------------------------------------
    # pre-checks - fail-closed: nothing is written until all of these pass
    # ------------------------------------------------------------------
    if n_exact != EXPECTED_CALLS:
        die("expected %d anchor lines, found %d" % (EXPECTED_CALLS, n_exact))
    ok("anchor lines = %d" % n_exact)

    if n_paren - 1 != EXPECTED_CALLS:
        die("anchor is not unique: %d call expression(s) vs %d exact anchor line(s)"
            % (n_paren - 1, n_exact))
    if n_ident != EXPECTED_CALLS + 1:
        die("expected %d identifiers (1 definition + %d calls), found %d"
            % (EXPECTED_CALLS + 1, EXPECTED_CALLS, n_ident))
    ok("anchor unique: every call expression matches the exact anchor line")

    if text.count(FUNC_DEF) != 1:
        die("the ensureDefenseTables definition was not found exactly once")
    ok("function definition found exactly once (it is kept)")

    # each anchor must sit inside the expected defense route
    call_idx = [i for i, l in enumerate(lines) if l == CALL]
    routes = []
    for i in call_idx:
        found = None
        for j in range(i - 1, -1, -1):
            m = re.search(r"app\.(get|post|put|delete)\(['\"]([^'\"]+)['\"]", lines[j])
            if m:
                found = (m.group(1), m.group(2))
                break
        if found is None:
            die("no enclosing route for the anchor at line %d" % (i + 1))
        routes.append(found)
    if routes != EXPECTED_ROUTES:
        die("route context mismatch: %r" % (routes,))
    ok("route context matches the 5 expected defense routes")

    # the function body must be exactly the 3 CREATE TABLE IF NOT EXISTS statements
    fstart = next(i for i, l in enumerate(lines) if FUNC_DEF in l)
    fend = brace_block(lines, fstart)
    if fend is None:
        die("could not brace-match the ensureDefenseTables body")
    body = "".join(lines[fstart:fend])
    ddl = re.findall(r'env\.DB\.prepare\("(CREATE TABLE IF NOT EXISTS [^"]+)"\)', body)
    if len(ddl) != 3:
        die("expected 3 CREATE TABLE statements in the body, found %d" % len(ddl))
    if "CREATE INDEX" in body:
        die("unexpected CREATE INDEX in the body")
    names = [re.match(r"CREATE TABLE IF NOT EXISTS (\w+)", d).group(1) for d in ddl]
    if names != EXPECTED_TABLES:
        die("unexpected table names: %r" % (names,))
    ok("body = 3 CREATE TABLE IF NOT EXISTS, 0 CREATE INDEX -> %s" % ", ".join(names))

    # the app.get('/') .replace() chain must be exactly 69 right now
    span = root_block(lines)
    chain_before = chain_count(lines, span)
    total_before = text.count(".replace(")
    if chain_before != EXPECTED_CHAIN_REPLACE:
        die("app.get('/') .replace( chain is %d, expected %d"
            % (chain_before, EXPECTED_CHAIN_REPLACE))
    if total_before != EXPECTED_TOTAL_REPLACE:
        die("file-wide .replace( is %d, expected %d"
            % (total_before, EXPECTED_TOTAL_REPLACE))
    ok("chain .replace( = %d (lines %d-%d); file-wide .replace( = %d"
       % (chain_before, span[0] + 1, span[1], total_before))

    # ------------------------------------------------------------------
    # build the result in memory and re-verify before writing anything
    # ------------------------------------------------------------------
    new_lines = [l for l in lines if l != CALL]
    if len(lines) - len(new_lines) != EXPECTED_CALLS:
        die("removal removed %d line(s), expected %d"
            % (len(lines) - len(new_lines), EXPECTED_CALLS))
    new_text = "".join(new_lines)

    if len(re.findall(r"\bensureDefenseTables\b", new_text)) != 1:
        die("post: expected exactly 1 remaining identifier (the definition)")
    if new_text.count(FUNC_DEF) != 1:
        die("post: the function definition was lost")
    span2 = root_block(new_lines)
    chain_after = chain_count(new_lines, span2)
    if chain_after != EXPECTED_CHAIN_REPLACE:
        die("post: chain .replace( became %d, expected %d"
            % (chain_after, EXPECTED_CHAIN_REPLACE))
    if new_text.count(".replace(") != EXPECTED_TOTAL_REPLACE:
        die("post: file-wide .replace( became %d, expected %d"
            % (new_text.count(".replace("), EXPECTED_TOTAL_REPLACE))
    ok("post: chain .replace( = %d unchanged; file-wide = %d unchanged"
       % (chain_after, EXPECTED_TOTAL_REPLACE))

    # ------------------------------------------------------------------
    # write
    # ------------------------------------------------------------------
    with open(SRC, "w", encoding="utf-8", newline="") as f:
        f.write(new_text)

    if not os.path.isdir("migrations"):
        os.makedirs("migrations")
    with open(MIG, "w", encoding="utf-8", newline="") as f:
        f.write(MIG_HEADER)
        f.write("\n")
        for statement in ddl:
            f.write(statement + ";\n\n")

    ok("wrote %s (-%d lines) and %s" % (SRC, EXPECTED_CALLS, MIG))
    print("DONE: removed %d call site(s); app.get('/') .replace( chain = %d"
          % (EXPECTED_CALLS, chain_after))
    return 0


if __name__ == "__main__":
    sys.exit(main())
