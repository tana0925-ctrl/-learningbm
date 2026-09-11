#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __DEF_SNAP_SPDSKILLS_V1__ : _defSnapshot() の出力に spd / skills を追加する .replace() を1本だけ足す
# fail-closed: 事前チェックに1つでも失敗したら src/index.tsx に一切触れずに exit 1
import sys, io

SRC = 'src/index.tsx'
HTML = 'public/index.html'
SENT = '__DEF_SNAP_SPDSKILLS_V1__'  # 冪等性の番兵（TSXのコメント＝HTML出力には出ない。検証条件とは別物）
BS = "app.get('/'"
BE = "app.get('/logout'"
EXPECT_CHAIN = 71
A = "buff:base.buff||'lucky',elementType:el,skillPow:10}"
B = ("buff:base.buff||'lucky',elementType:el,skillPow:10"
     ",spd:Number((s&&s.spd)||10)"
     ",skills:(Array.isArray(base.skills)?base.skills.map(function(_sk){return Object.assign({},_sk)}):[])"
     "}")
INS = "\n      _rootHtmlCache = t\n"
NEW = ("\n      // " + SENT + " _defSnapshot に spd / skills を追加"
       "\n      t = t.replace(\"" + A + "\", \"" + B + "\")")
GUARD = ['__DEF_STANDING_V1_SENTINEL__', 'defAutoAdvanceV1',
         '__DEF_RESOLVE_VERIFY_V1__', 'defense_standing',
         'defense_carry_lock', 'const DEFENSE_BASE_HP = 380']

def die(m):
    sys.stderr.write('FAIL: ' + m + '\n')
    sys.exit(1)

src = io.open(SRC, encoding='utf-8').read()
html = io.open(HTML, encoding='utf-8').read()

if SENT in src:
    print('ALREADY APPLIED (sentinel present) - no file touched')
    sys.exit(0)

if src.count(BS) != 1: die("app.get('/') not unique")
if src.count(BE) != 1: die("app.get('/logout') not unique")
st = src.find(BS); en = src.find(BE)
if en <= st: die('block bounds inverted')
chain = src[st:en].count('.replace(')
print('chain before = %d' % chain)
if chain != EXPECT_CHAIN: die('chain %d != %d' % (chain, EXPECT_CHAIN))
if html.count(A) != 1: die('html anchor count %d != 1' % html.count(A))
if src.count(A) != 0: die('html anchor already referenced in src')
if src.count(INS) != 1: die('insertion anchor not unique')
for g in GUARD:
    if g not in src: die('guard missing before: ' + g)
if src.count('ensureDefenseTables') != 1: die('ensureDefenseTables occurrences != 1 (calls must stay 0)')

out = src.replace(INS, NEW + INS, 1)

st2 = out.find(BS); en2 = out.find(BE)
chain2 = out[st2:en2].count('.replace(')
if chain2 != chain + 1: die('chain after %d != %d' % (chain2, chain + 1))
if out.count(SENT) != 1: die('sentinel count != 1')
if len(out) != len(src) + len(NEW): die('unexpected length delta')
if out.count(A) != 1: die('anchor not unique after')
if out.count(B) != 1: die('replacement not unique after')
for g in GUARD:
    if g not in out: die('guard lost: ' + g)
if out.count('ensureDefenseTables') != 1: die('ensureDefenseTables changed')

io.open(SRC, 'w', encoding='utf-8').write(out)
print('OK chain %d -> %d' % (chain, chain2))
