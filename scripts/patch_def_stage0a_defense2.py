#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# patch_def_stage0a_defense2.py
#
# Defense stage 0-a. Touches public/defense2.js ONLY. No balance change.
#   1. restoreGym() never cleared _gcHome -> stale parent/next reference
#   2. show the finish reason (rep.reason: 'wipe'|'base'|'judge'|'timeout')
#   3. forward-compat GET /api/defense/replay, falling back to the current
#      /api/defense/status path
#
# fail-closed: --check writes nothing; a real run writes only when every
# anchor resolved AND every post-condition holds. The idempotency sentinels
# are COMMENT markers and are deliberately NOT the strings used for
# verification, so a reverted edit that left its comment behind still fails.
import sys

PATH = "public/defense2.js"

EDITS = [
    {
        "name": "gchome",
        "sentinel": "DEF2_STAGE0A_GCHOME_20260911",
        "anchor": "  function restoreGym(){ try{ var g=document.getElementById('gymChallengeBody'); if(g&&_gcHome&&_gcHome.parent){ _gcHome.parent.insertBefore(g,_gcHome.next); } }catch(e){} }",
        "replace": "  /* DEF2_STAGE0A_GCHOME_20260911\n     restoreGym() never cleared _gcHome, so a stale parent/next pair survived a\n     re-render: insertBefore() then threw NotFoundError, was swallowed by catch,\n     and gymChallengeBody stayed orphaned inside the replay area. */\n  function restoreGym(){\n    try{\n      var g=document.getElementById('gymChallengeBody');\n      var h=_gcHome;\n      if(g && h && h.parent && document.contains(h.parent)){\n        var nx=(h.next && h.next.parentNode===h.parent) ? h.next : null;\n        h.parent.insertBefore(g, nx);\n      }\n    }catch(e){}\n    _gcHome = null;\n  }",
        "verify": ["_gcHome = null;", "document.contains(h.parent)"],
    },
    {
        "name": "reasonfn",
        "sentinel": "DEF2_STAGE0A_REASON_20260911",
        "anchor": "function def2HypeHtml(log, st){",
        "replace": "  /* DEF2_STAGE0A_REASON_20260911\n     autoBattleRT returns reason = 'wipe' | 'base' | 'judge' | 'timeout'.\n     'wipe' = one side was knocked out completely. Wording only; no balance\n     or difficulty change. */\n  function def2ReasonText(win, reason, baseEnd, baseMax){\n    try{\n      var noDmg = (baseMax!=null && baseEnd!=null && Math.round(baseEnd) >= Math.round(baseMax));\n      if(reason==='wipe'){\n        return win ? ('てきを ぜんぶ たおした！' + (noDmg ? 'きちは むきず！' : 'きちを まもりきったよ'))\n                   : 'みんな たおれてしまった…';\n      }\n      if(reason==='base'){ return win ? 'あいての きちを こわした！' : 'きちを こわされた…'; }\n      if(reason==='timeout' || reason==='judge'){ return win ? 'じかんぎれ！ はんていで かち！' : 'じかんぎれ… はんていで まけ'; }\n      return '';\n    }catch(e){ return ''; }\n  }\n\nfunction def2HypeHtml(log, st){",
        "verify": ["function def2ReasonText(win, reason, baseEnd, baseMax){", "reason==='wipe'"],
    },
    {
        "name": "hero",
        "sentinel": "DEF2_STAGE0A_HERO_20260911",
        "anchor": "        + '<div style=\"font-size:13px;opacity:.9;\">みんなの きち防衛 けっか</div>';",
        "replace": "        + '<div style=\"font-size:13px;opacity:.9;\">みんなの きち防衛 けっか</div>';\n      /* DEF2_STAGE0A_HERO_20260911 */\n      var _rsn = def2ReasonText(win, rep && rep.reason, baseEnd, baseMax);\n      if(_rsn){ hero += '<div style=\"margin-top:8px;display:inline-block;background:rgba(255,255,255,.20);border-radius:999px;padding:5px 14px;font-size:13px;font-weight:800;\">'+esc(_rsn)+'</div>'; }",
        "verify": ["var _rsn = def2ReasonText(win, rep && rep.reason, baseEnd, baseMax);", "hero += '<div style=\"margin-top:8px;"],
    },
    {
        "name": "replayfn",
        "sentinel": "DEF2_STAGE0A_REPLAYEP_20260911",
        "anchor": "  function makeReplay(orig){",
        "replace": "  /* DEF2_STAGE0A_REPLAYEP_20260911\n     Forward-compat: a later stage adds GET /api/defense/replay. Until it exists\n     (404, or the SPA HTML returned with 200) fall back to the current\n     /api/defense/status path, so today's behaviour is unchanged. */\n  function def2GetReplayData(){\n    function viaStatus(){\n      return jget('/api/defense/status').then(function(st){\n        return {st:st, log:(st && st.result) ? st.result.log : null};\n      });\n    }\n    try{\n      return fetch('/api/defense/replay',{cache:'no-store'}).then(function(r){\n        if(!r || !r.ok) return null;\n        var ct=(r.headers && r.headers.get && r.headers.get('content-type')) || '';\n        if(ct.indexOf('json')<0) return null;\n        return r.json();\n      }).catch(function(){ return null; }).then(function(j){\n        var lg = j && (j.log || (j.result && j.result.log));\n        if(lg && !Array.isArray(lg) && lg.v===2){ return {st:(j.status||j), log:lg}; }\n        return viaStatus();\n      }).catch(function(){ return viaStatus(); });\n    }catch(e){ return viaStatus(); }\n  }\n\n  function makeReplay(orig){",
        "verify": ["function def2GetReplayData(){", "fetch('/api/defense/replay',{cache:'no-store'})"],
    },
    {
        "name": "callsite",
        "sentinel": "DEF2_STAGE0A_CALLSITE_20260911",
        "anchor": "        jget('/api/defense/status').then(function(st){\n          var log = st && st.result ? st.result.log : null;",
        "replace": "        /* DEF2_STAGE0A_CALLSITE_20260911 */\n        def2GetReplayData().then(function(d){\n          var st = d && d.st, log = d && d.log;",
        "verify": ["def2GetReplayData().then(function(d){", "var st = d && d.st, log = d && d.log;"],
    },
]

MUST_SURVIVE = ["withFrozenStats", "makeResolve", "makeReplay", "makeSubmit", "buildBattle"]
MUST_BE_GONE = [EDITS[0]["anchor"], EDITS[4]["anchor"]]


def plan(src):
    steps, errors = [], []
    for e in EDITS:
        ns = src.count(e["sentinel"])
        na = src.count(e["anchor"])
        if ns >= 1:
            steps.append(("SKIP", e))
        elif na == 1:
            steps.append(("APPLY", e))
        elif na == 0:
            errors.append("%s: anchor NOT found and sentinel absent" % e["name"])
        else:
            errors.append("%s: anchor found %d times (must be exactly 1)" % (e["name"], na))
    return steps, errors


def apply_steps(src, steps):
    for action, e in steps:
        if action != "APPLY":
            continue
        if src.count(e["anchor"]) != 1:
            raise RuntimeError("anchor lost uniqueness mid-run: %s" % e["name"])
        src = src.replace(e["anchor"], e["replace"], 1)
    return src


def verify(src):
    bad = []
    for e in EDITS:
        for v in e["verify"]:
            if v not in src:
                bad.append("%s: missing post-condition %r" % (e["name"], v[:60]))
    for g in MUST_BE_GONE:
        if g in src:
            bad.append("old code still present: %r" % g[:60])
    for m in MUST_SURVIVE:
        if m not in src:
            bad.append("REGRESSION: %s disappeared" % m)
    n_raw = src.count("window.autoBattleRT(")
    n_frozen = src.count("withFrozenStats(entries, function(){ return window.autoBattleRT(")
    if n_raw != 1 or n_frozen != 1:
        bad.append("autoBattleRT guard broken: calls=%d wrapped=%d (want 1/1)" % (n_raw, n_frozen))
    if "\r" in src:
        bad.append("CRLF introduced")
    return bad


def main():
    check = "--check" in sys.argv
    with open(PATH, "r", encoding="utf-8", newline="") as f:
        src = f.read()

    steps, errors = plan(src)
    for action, e in steps:
        print("  %-5s %s" % (action, e["name"]))
    if errors:
        for x in errors:
            print("ANCHOR ERROR: " + x)
        print("FAIL: aborting, file untouched")
        return 1

    out = apply_steps(src, steps)

    bad = verify(out)
    if bad:
        for x in bad:
            print("VERIFY ERROR: " + x)
        print("FAIL: aborting, file untouched")
        return 1

    if check:
        print("CHECK OK (nothing written); would change: %s" % ("yes" if out != src else "no, already applied"))
        return 0

    if out == src:
        print("already applied; nothing written")
        return 0

    with open(PATH, "w", encoding="utf-8", newline="") as f:
        f.write(out)
    print("WROTE %s (%d -> %d bytes)" % (PATH, len(src), len(out)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
