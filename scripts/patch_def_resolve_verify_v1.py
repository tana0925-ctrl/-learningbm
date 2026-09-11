#!/usr/bin/env python3
"""
DEF_RESOLVE_VERIFY_V1 : cross-check POST /api/defense/resolve against the log
the client sent, instead of storing body.result outright (src/index.tsx only).

Why:
  The handler wrote body.result / body.base_hp_end verbatim with
  INSERT OR IGNORE, so whichever browser answered first decided the result for
  the whole class.  This is the first half of the fix: the server still does
  not re-run the battle, but it now refuses a payload that contradicts the
  replay log shipped alongside it.

Four cross-checks, all run on body.log BEFORE it is truncated by .slice():
  1  log.seed        == seedFromKey(event_key)             -> 400
  2  replay.winner   == body.result  (winner A means win)  -> 400
  3  replay.baseHpA  == body.base_hp_end                   -> 400
  4  log.entrants    == defense_entries (count and order)  -> { ok:true, retry:true }

  #4 is deliberately NOT a 400.  Carry-over entries are materialised by the
  first child of a class to open the page, so a child who presses at 12:30:02
  legitimately sees fewer entrants than one who presses at 12:30:40.  Turning
  that into a 400 would reject every child and the class would never get a
  result at all.  public/defense2.js never reads the response body - it just
  calls openDefense() again - so retry is harmless and the next child writes.

  #1-#3 only run for v2 logs (log.v === 2).  The legacy fallback resolver still
  embedded in public/index.html posts "log: sim.rounds", a bare array with no
  seed and no replay; failing that closed would break the fallback path.
  #3 additionally only runs when replay.baseHpA is a finite number, because the
  v2 client falls back to st.base_hp when the engine returns null, and a false
  400 there would again leave the class with no result.

Design:
  fail-closed : every pre-check runs BEFORE anything is written.  If any check
                fails the script exits non-zero having touched no file at all.
  anchor      : the anchor line must occur exactly once.
  sentinel    : idempotency is decided by its own sentinel comment
                (__DEF_RESOLVE_VERIFY_V1__), which is deliberately NOT one of
                the strings the workflow verifies afterwards.
"""
import sys

PATH = "src/index.tsx"
SENTINEL = "__DEF_RESOLVE_VERIFY_V1__"
ANCHOR = "  const baseHpEnd = Math.max(0, Math.floor(Number(body.base_hp_end || 0)))"
RESULT_LINE = "  const result = (String(body.result) === 'win') ? 'win' : 'lose'"

BLOCK = '''  // __DEF_RESOLVE_VERIFY_V1__ 送られてきた log と付き合わせて、矛盾する申告をはじく（切り詰める前の body.log を見る）
  const _dvFnv = (x: any) => { const s = String(x == null ? '' : x); let h = 2166136261 >>> 0; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) } return h >>> 0 }
  const _dvSeedFromKey = (k: any) => ((_dvFnv(k) ^ 0x9e3779b9) >>> 0)
  const _dvLog: any = body.log
  if (_dvLog && typeof _dvLog === 'object' && !Array.isArray(_dvLog) && Number(_dvLog.v) === 2) {
    // 1) seed が event_key から作られたものと一致するか
    if (Number(_dvLog.seed) !== _dvSeedFromKey(st.eventKey)) return jsonError(c, 400, 'log_seed_mismatch')
    const _dvRep: any = _dvLog.replay
    if (!_dvRep || typeof _dvRep !== 'object') return jsonError(c, 400, 'log_replay_missing')
    // 2) 勝敗が replay と一致するか
    if (((_dvRep.winner === 'A') ? 'win' : 'lose') !== result) return jsonError(c, 400, 'log_result_mismatch')
    // 3) 基地HP が replay と一致するか（replay が baseHpA を返さない時だけ client 側の代替値を許す）
    if (_dvRep.baseHpA != null && Number.isFinite(Number(_dvRep.baseHpA))) {
      if (Math.max(0, Math.floor(Number(_dvRep.baseHpA))) !== baseHpEnd) return jsonError(c, 400, 'log_base_hp_mismatch')
    }
    // 4) エントリーの件数と順序。持ち越しの materialize はクラスの1人目が引き金なので、
    //    人数が違うのは正常。ここで 400 にすると全員はじかれてクラスに結果が出ないため retry を返す。
    const _dvEs = await c.env.DB.prepare("SELECT de.monster_json as mj, u.name as nm FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC").bind(st.eventKey, classId).all<any>()
    const _dvWant: string[] = []
    for (const _r of ((_dvEs && _dvEs.results) || [])) { let _m: any = null; try { _m = JSON.parse(_r.mj) } catch (_e) {} if (_m && _m.id) _dvWant.push(String(_r.nm)) }
    const _dvGot: string[] = (Array.isArray(_dvLog.entrants) ? _dvLog.entrants : []).map((e: any) => String((e && e.name) || ''))
    if (_dvWant.length !== _dvGot.length) return c.json({ ok: true, retry: true })
    for (let _i = 0; _i < _dvWant.length; _i++) { if (_dvWant[_i] !== _dvGot[_i]) return c.json({ ok: true, retry: true }) }
  }
'''


def chain_count(s):
    try:
        i = s.index("let t = await a.text()")
        j = s.index("return c.html(", i)
    except ValueError:
        return -1
    return s[i:j].count(".replace(")


def main():
    src = open(PATH, encoding="utf-8").read()

    if SENTINEL in src:
        print("すでに適用済みです（番兵あり）。何もしません。")
        return 0

    problems = []
    if src.count(ANCHOR) != 1:
        problems.append("アンカーが1件ではありません: %d件" % src.count(ANCHOR))
    if src.count(RESULT_LINE) != 1:
        problems.append("result の行が1件ではありません")
    if src.count("INSERT OR IGNORE INTO defense_results") != 1:
        problems.append("defense_results への保存が1件ではありません")
    if src.count("ensureDefenseTables(") != 1:
        problems.append("ensureDefenseTables の呼び出しが増えています（定義のみ=1 が正しい）")
    if src.count("const DEFENSE_BASE_HP = 380") != 1:
        problems.append("基地HPが380ではありません")
    before = chain_count(src)
    if before != 71:
        problems.append("app.get('/') の .replace チェーンが71件ではありません: %d件" % before)
    for k in ("defense_standing", "defense_carry_lock", "defAutoAdvanceV1"):
        if src.count(k) < 1:
            problems.append("見つからない: " + k)

    if problems:
        print("中止します。src/index.tsx には触れていません。")
        for p in problems:
            print("  NG:", p)
        return 1

    out = src.replace(ANCHOR, ANCHOR + "\n" + BLOCK.rstrip("\n"), 1)
    if out == src:
        print("中止します（置換が起きませんでした）。src/index.tsx には触れていません。")
        return 1
    if SENTINEL not in out:
        print("中止します（番兵が入りませんでした）。")
        return 1
    after = chain_count(out)
    if after != 71:
        print("中止します（チェーン件数が %d に変わりました）。" % after)
        return 1

    open(PATH, "w", encoding="utf-8").write(out)
    print("適用しました。.replace チェーン: %d -> %d（今回はサーバ側だけなので変わらないのが正解）" % (before, after))
    return 0


if __name__ == "__main__":
    sys.exit(main())
