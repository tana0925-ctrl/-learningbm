#!/usr/bin/env python3
"""
Unify the class-base-defense base HP on 380 (src/index.tsx only).

Why 380 and not 1200:
  public/defense2.js builds the option object handed to window.autoBattleRT
  without a baseHp key, so the engine falls back to its own default
  (Number(opts.baseHp || 380)).  Every real battle has therefore been fought
  at 380.  DEFENSE_BASE_HP is only echoed back by GET /api/defense/status
  (and used as a win-fallback for base_hp_end), so the number shown never
  matched the number played.  The stored defense_results are balanced around
  380, so the constant is what moves.

Design:
  fail-closed : every pre-check runs BEFORE anything is written.  If any check
                fails the script exits non-zero having touched no file at all.
  anchor      : the anchor must be unique, and DEFENSE_BASE_HP must appear
                exactly twice in the file (definition + status response).
  sentinel    : idempotency is decided by its own sentinel comment, which is
                deliberately NOT one of the verification conditions.
  never touch : this script only ever opens src/index.tsx.  public/index.html
                is never opened, and the app.get('/') .replace() chain is
                counted before and after and must stay identical (69).
"""

import re
import sys

TARGET = "src/index.tsx"
ANCHOR = "const DEFENSE_BASE_HP = 1200"
PATCHED = "const DEFENSE_BASE_HP = 380"
SENTINEL = "// DEF2_BASEHP_UNIFY_380_20260911"
EXPECTED_CHAIN = 69


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


def chain_count(text):
    lines = text.split("\n")
    start, end = root_block(lines)
    return "\n".join(lines[start:end]).count(".replace(")


def main():
    with open(TARGET, encoding="utf-8", newline="") as f:
        src = f.read()

    # ---- idempotency sentinel (its own marker, not a verification condition)
    if SENTINEL in src:
        ok("sentinel already present - nothing to do")
        return

    # ---- pre-checks (fail-closed: nothing has been written yet)
    n_anchor = src.count(ANCHOR)
    if n_anchor != 1:
        die("anchor %r found %d times, expected exactly 1" % (ANCHOR, n_anchor))
    ok("anchor is unique")

    n_name = len(re.findall(r"\bDEFENSE_BASE_HP\b", src))
    if n_name != 2:
        die("DEFENSE_BASE_HP referenced %d times, expected 2; refusing to guess"
            % n_name)
    ok("DEFENSE_BASE_HP referenced exactly twice")

    if PATCHED in src:
        die("%r already present without the sentinel - inconsistent state"
            % PATCHED)

    before = chain_count(src)
    if before != EXPECTED_CHAIN:
        die("app.get('/') .replace() chain is %d, expected %d"
            % (before, EXPECTED_CHAIN))
    ok("app.get('/') .replace() chain = %d before" % before)

    # ---- apply (in memory only)
    nl = "\r\n" if "\r\n" in src else "\n"
    out = src.replace(ANCHOR, SENTINEL + nl + PATCHED, 1)

    # ---- post-checks (still in memory; any failure writes nothing)
    after = chain_count(out)
    if after != before:
        die("chain changed %d -> %d; aborting without writing" % (before, after))
    if out.count(PATCHED) != 1 or ANCHOR in out or SENTINEL not in out:
        die("post-check failed; aborting without writing")
    if len(re.findall(r"\bDEFENSE_BASE_HP\b", out)) != 2:
        die("DEFENSE_BASE_HP reference count changed; aborting without writing")
    ok("app.get('/') .replace() chain = %d after (unchanged)" % after)

    with open(TARGET, "w", encoding="utf-8", newline="") as f:
        f.write(out)
    ok("wrote %s : DEFENSE_BASE_HP 1200 -> 380" % TARGET)


if __name__ == "__main__":
    main()
