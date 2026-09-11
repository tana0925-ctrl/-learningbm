# -*- coding: utf-8 -*-
# DEF_STAGE_V3_CURVE
# 防衛戦の敵の強さの曲線を入れ替える。書き換えるのは src/def_stage.ts の defStageEnemies だけ。
# 敵の体数は増やさない（エンジンは毎tick全員x全員を見るので体数はCPUに二乗で効く）。
# ステージ1の素は src/index.tsx の DEFENSE_ENEMIES。このファイルからは触らない。
# アンカーが1件でなければ 1 文字も書かずに異常終了する（fail-closed）。
import io
import re
import sys

PATH = 'src/def_stage.ts'
SENTINEL = 'DEF_STAGE_V3_CURVE'

OLD = (
    "export function defStageEnemies(base, stage) {\n"
    "  if (!Array.isArray(base)) return []\n"
    "  const k = defStageClamp(stage) - 1\n"
    "  return base.map(function (e) {\n"
    "    const o = {}\n"
    "    for (const p in e) o[p] = e[p]\n"
    "    o.hp = Math.round(Number(e.hp || 0) * (1 + 0.25 * k))\n"
    "    o.atk = Math.round(Number(e.atk || 0) * (1 + 0.12 * k))\n"
    "    o.def = Number(e.def || 0) + 2 * k\n"
    "    return o\n"
    "  })\n"
    "}\n"
)

NEW = (
    "export function defStageEnemies(base, stage) {\n"
    "  if (!Array.isArray(base)) return []\n"
    "  const k = defStageClamp(stage) - 1\n"
    "  const u = Math.pow(k / (DEF_STAGE_MAX - 1), 2.2)\n"
    "  return base.map(function (e) {\n"
    "    const o = {}\n"
    "    for (const p in e) o[p] = e[p]\n"
    "    o.hp = Math.round(Number(e.hp || 0) * (1 + 25 * u))\n"
    "    o.atk = Math.round(Number(e.atk || 0) * (1 + 19 * u))\n"
    "    o.def = Math.round(Number(e.def || 0) * (1 + 6 * u))\n"
    "    o.skillPow = Math.round(Number(e.skillPow || 10) * (1 + 18 * u))\n"
    "    if (k > 0) o.spd = Math.round(10 + 230 * u)\n"
    "    return o\n"
    "  })\n"
    "}\n"
)

# 旧倍率の見出しコメント3行。literal を書かずに正規表現で拾う。
DOC_RE = re.compile(
    r"//   hp  x \(1 \+ 0\.25[^\n]*\n"
    r"//   atk x \(1 \+ 0\.12[^\n]*\n"
    r"//   def \+ 2[^\n]*\n"
)

DOC_NEW = (
    "//   " + SENTINEL + " 倍率は u（0〜1）で効かせる。上の段ほど急に強くなる。\n"
    "//   いちばん下の段は u が 0 なので素のまま（spd も足さない）。\n"
    "//   hp       いちばん上で 26 倍\n"
    "//   atk      いちばん上で 20 倍\n"
    "//   def      いちばん上で 7 倍\n"
    "//   skillPow いちばん上で 19 倍\n"
    "//   spd      10 から 240 まで（速いほど手数が増える）\n"
)

AFTER_MUST = (
    ('export function defStageEnemies(base, stage) {', 1),
    ('export function defStageClamp(stage) {', 1),
    ('DEF_STAGE_MAX = 10', 1),
    ('Math.pow(k / (DEF_STAGE_MAX - 1), 2.2)', 1),
    ('(1 + 25 * u)', 1),
    ('(1 + 19 * u)', 1),
    ('(1 + 6 * u)', 1),
    ('(1 + 18 * u)', 1),
    ('Math.round(10 + 230 * u)', 1),
    ('base.map(', 1),
    (SENTINEL, 1),
)

AFTER_GONE = ('(1 + 0.25 * k)', '(1 + 0.12 * k)', '+ 2 * k')


def main():
    s = io.open(PATH, encoding='utf-8').read()

    if SENTINEL in s:
        print('already applied: ' + SENTINEL + ' / 何もしない')
        return 0

    n = s.count(OLD)
    if n != 1:
        print('NG: 関数の本体アンカーが %d 件（期待 1）' % n)
        return 1

    docs = DOC_RE.findall(s)
    if len(docs) != 1:
        print('NG: 旧倍率の見出しコメントが %d 件（期待 1）' % len(docs))
        return 1

    t = s.replace(OLD, NEW)
    t = DOC_RE.sub(DOC_NEW, t)

    ok = True
    for label, want in AFTER_MUST:
        got = t.count(label)
        if got != want:
            print('NG: %s が %d 件（期待 %d）' % (label, got, want))
            ok = False
    for gone in AFTER_GONE:
        if gone in t:
            print('NG: 古い倍率 %s が残っている' % gone)
            ok = False
    if t == s:
        print('NG: 中身が変わっていない')
        ok = False
    if not ok:
        print('NG: 自己点検に落ちたので書き込まない')
        return 1

    io.open(PATH, 'w', encoding='utf-8').write(t)
    print('OK: ' + PATH + ' を更新した')
    return 0


sys.exit(main())
