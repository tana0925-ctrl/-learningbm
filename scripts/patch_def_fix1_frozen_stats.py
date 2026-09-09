#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
防衛戦 修正#1 : public/defense2.js

問題:
  buildBattle() は保存済み monster_json の hp/atk/def を捨てて {id, level, strategy}
  だけを autoBattleRT に渡す。_abFighter は getStats(base, lvl) を呼び、その中で
  isDailyFatigued(id) / applyStarMultiplier(stats, id) が「決戦ボタンを押した児童の
  ローカルデータ」を参照する。結果、押した人が違うと全員の戦力が変わる。

修正:
  autoBattleRT の呼び出しを withFrozenStats() で包み、その間だけ
    - isDailyFatigued  -> 常に false
    - getStarMultiplier -> 常に 1
    - getStats(mon,lvl) -> 出陣時に保存された hp/atk/def を返す（spd は中立値）
  にする。elementType / わざ はモンスターテーブル由来のまま温存される
  （enemy 側と同じ raw 経路を使うと elementType が normal 固定になるため使わない）。

冪等性:
  目印(SENTINEL)はコメントとして埋めるが、適用済み判定には使わない。
  判定・検証はいずれも「結果そのもの」= ラッパ呼び出しが存在するかで行う。

使い方:
  python3 scripts/patch_def_fix1_frozen_stats.py            # 適用
  python3 scripts/patch_def_fix1_frozen_stats.py --check    # 適用せず状態だけ表示
"""

import hashlib
import pathlib
import sys

SENTINEL = "DEF2FIX_FROZEN_STATS_20260909"  # 目印。検証条件には使わない。

TARGET = pathlib.Path("public/defense2.js")

# --- アンカー（いずれもファイル内で一意であること） ---
ANCHOR_FN = "  function buildBattle(st){\n"

ANCHOR_CALL = (
    "    var rep = window.autoBattleRT(defenders, enemies, "
    "{bases:true,lanes:true,laneCount:3,seed:seed,program:true,"
    "programsA:programsA,programB:ENEMY_PROG,forts:false,tactics:true,contact:true});\n"
)

NEW_CALL = (
    "    var rep = withFrozenStats(entries, function(){ return window.autoBattleRT(defenders, enemies, "
    "{bases:true,lanes:true,laneCount:3,seed:seed,program:true,"
    "programsA:programsA,programB:ENEMY_PROG,forts:false,tactics:true,contact:true}); });\n"
)

HELPER = (
    "  /* " + SENTINEL + "\n"
    "     出陣時に保存されたステータスで戦わせる。決戦ボタンを押した児童の\n"
    "     isDailyFatigued / getStarMultiplier が他人のモンスターに適用されるのを防ぐ。\n"
    "     autoBattleRT は同期実行なので、finally で必ず元に戻る。 */\n"
    "  function withFrozenStats(entries, fn){\n"
    "    var g = window;\n"
    "    var oGS = g.getStats, oFat = g.isDailyFatigued, oStar = g.getStarMultiplier;\n"
    "    var q = {};\n"
    "    (entries || []).forEach(function(e){\n"
    "      var m = (e && e.monster) || null; if(!m) return;\n"
    "      var k = Number(m.id) + '@' + Number(m.level || 1);\n"
    "      (q[k] = q[k] || []).push(m);\n"
    "    });\n"
    "    try{\n"
    "      if(typeof oFat  === 'function') g.isDailyFatigued  = function(){ return false; };\n"
    "      if(typeof oStar === 'function') g.getStarMultiplier = function(){ return 1; };\n"
    "      if(typeof oGS   === 'function') g.getStats = function(mon, lvl){\n"
    "        var neutral = oGS.apply(this, arguments) || {};\n"
    "        var k = Number(mon && mon.id) + '@' + Number(lvl || 1);\n"
    "        var list = q[k];\n"
    "        if(list && list.length){\n"
    "          var m = list.shift();\n"
    "          var hp = Number(m.hp || neutral.hp || neutral.maxHp || 1);\n"
    "          return { hp: hp, maxHp: hp,\n"
    "                   atk: Number(m.atk || neutral.atk || 1),\n"
    "                   def: Number(m.def || neutral.def || 1),\n"
    "                   spd: Number(neutral.spd || 10) };\n"
    "        }\n"
    "        return neutral;\n"
    "      };\n"
    "      return fn();\n"
    "    } finally {\n"
    "      if(typeof oGS   === 'function') g.getStats          = oGS;\n"
    "      if(typeof oFat  === 'function') g.isDailyFatigued   = oFat;\n"
    "      if(typeof oStar === 'function') g.getStarMultiplier = oStar;\n"
    "    }\n"
    "  }\n"
)


def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def fail(msg: str):
    print("NG: " + msg)
    sys.exit(1)


def main():
    check_only = "--check" in sys.argv

    if not TARGET.exists():
        fail("対象が見つかりません: %s (リポジトリ直下で実行してください)" % TARGET)

    before = TARGET.read_bytes()
    src = before.decode("utf-8")

    print("=== 適用前 ===")
    print("file   : %s" % TARGET)
    print("bytes  : %d" % len(before))
    print("sha256 : %s" % sha(before))

    # --- 冪等性: 「結果そのもの」で判定する（SENTINEL では判定しない） ---
    already = (src.count(NEW_CALL) == 1) and (src.count("function withFrozenStats(") == 1)
    if already:
        print("=== 適用済み（変更なし） ===")
        print("withFrozenStats ラッパが既に存在します。")
        return

    # --- アンカー一意性検証 ---
    for name, anchor in (("ANCHOR_FN", ANCHOR_FN), ("ANCHOR_CALL", ANCHOR_CALL)):
        n = src.count(anchor)
        if n != 1:
            fail("%s の出現回数が %d です（1 であるべき）。アンカーを見直してください。" % (name, n))
    print("anchor : ANCHOR_FN=1, ANCHOR_CALL=1  (一意)")

    if src.count("function withFrozenStats(") != 0:
        fail("withFrozenStats が既に部分的に存在します。手で確認してください。")

    if check_only:
        print("--check のため書き込みません。適用可能です。")
        return

    # --- 適用 ---
    out = src.replace(ANCHOR_CALL, NEW_CALL, 1)
    out = out.replace(ANCHOR_FN, HELPER + ANCHOR_FN, 1)

    after = out.encode("utf-8")
    TARGET.write_bytes(after)

    # --- 適用後の照合（結果そのものを見る） ---
    verify = TARGET.read_bytes().decode("utf-8")
    checks = [
        ("ラッパ呼び出しが1つ", verify.count(NEW_CALL) == 1),
        ("withFrozenStats 定義が1つ", verify.count("function withFrozenStats(") == 1),
        ("素の autoBattleRT 呼び出しが残っていない", verify.count(ANCHOR_CALL) == 0),
        ("autoBattleRT の呼び出し総数が1つ", verify.count("window.autoBattleRT(defenders") == 1),
        ("getStats の一時差し替えがある", "g.getStats = function(mon, lvl)" in verify),
        ("finally で復元している", "g.getStats          = oGS;" in verify),
        ("buildBattle は1つのまま", verify.count("function buildBattle(st){") == 1),
        ("makeResolve は無傷", verify.count("function makeResolve(orig){") == 1),
    ]
    print("=== 適用後の照合 ===")
    ok = True
    for label, res in checks:
        print(("  OK  " if res else "  NG  ") + label)
        ok = ok and res

    print("bytes  : %d -> %d (+%d)" % (len(before), len(after), len(after) - len(before)))
    print("sha256 : %s -> %s" % (sha(before), sha(after)))

    if not ok:
        TARGET.write_bytes(before)
        fail("照合に失敗したためロールバックしました。")

    print("=== 完了 ===")


if __name__ == "__main__":
    main()
