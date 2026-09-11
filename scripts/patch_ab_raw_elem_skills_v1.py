#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __AB_RAW_ELEM_SKILLS_V1__
# _abFighter() の spec.raw 経路が、本物の elementType と skills を読むようにする。
#   - 新しい .replace() は足さない。既存の raw 経路の「置換後文字列」だけを書き換える（チェーンは72件のまま）
#   - public/defense2.js の enemies マッピングにも elementType / skills を通す
# fail-closed: 事前チェックに1つでも失敗したらファイルに一切触れずに exit 1
import sys, io

SRC  = 'src/index.tsx'
D2   = 'public/defense2.js'
SENT = '__AB_RAW_ELEM_SKILLS_V1__'  # 冪等性の番兵（TSXのコメント＝HTML出力には出ない。検証条件とは別物）

BS = "app.get('/', async (c) => {"
BE = "app.get('/logout'"
EXPECT_CHAIN = 72

# アンカー（無傷のまま残すこと）
ANCHOR  = "var base=getMonster(Number(spec.id)); if(!base) return null;"
RAWHEAD = "var base=getMonster(Number(spec.id)); if(spec&&spec.raw){var R=spec.raw;"

# src/index.tsx : 既存 raw 経路の「置換後文字列」だけを書き換える（.replace は増やさない）
A_OLD = "elementType:'normal',skills:[{name:'こうげき',pow:Number(R.skillPow||12),acc:0.95,element:'normal'}]"
A_NEW = ("elementType:(R.elementType!=null?R.elementType:'normal')"
         ",skills:(Array.isArray(R.skills)&&R.skills.length)?R.skills"
         ":[{name:'こうげき',pow:Number(R.skillPow||12),acc:0.95,element:'normal'}]")

# public/defense2.js : enemies に elementType / skills を通す
B_OLD = "{raw:{name:en.name,sprite:en.sprite,hp:en.hp,atk:en.atk,def:en.def,buff:en.buff,skillPow:en.skillPow}"
B_NEW = "{raw:{name:en.name,sprite:en.sprite,hp:en.hp,atk:en.atk,def:en.def,buff:en.buff,skillPow:en.skillPow,elementType:en.elementType,skills:en.skills}"

INS  = "\n      _rootHtmlCache = t\n"
MARK = "\n      // " + SENT + " _abFighter の raw 経路が raw.elementType / raw.skills を読む（.replace は増やさない）"

GUARD = ['__DEF_SNAP_SPDSKILLS_V1__', '__DEF_RESOLVE_VERIFY_V1__', 'defAutoAdvanceV1',
         'defense_standing', 'defense_carry_lock', 'const DEFENSE_BASE_HP = 380']


def die(msg):
    print('ABORT: ' + msg)
    sys.exit(1)


src = io.open(SRC, encoding='utf-8').read()
d2  = io.open(D2,  encoding='utf-8').read()

if SENT in src:
    print('ALREADY APPLIED (sentinel present) - no file touched')
    sys.exit(0)

# ---- 事前チェック（1つでも落ちたら書かない） ----
if src.count(BS) != 1: die("app.get('/') not unique")
if src.count(BE) != 1: die("app.get('/logout') not unique")
st = src.find(BS); en = src.find(BE)
if en <= st: die('block bounds inverted')
chain = src[st:en].count('.replace(')
print('chain before = %d' % chain)
if chain != EXPECT_CHAIN: die('chain %d != %d' % (chain, EXPECT_CHAIN))

if src.count(ANCHOR)  != 1: die('anchor count %d != 1' % src.count(ANCHOR))
if src.count(RAWHEAD) != 1: die('raw head count %d != 1' % src.count(RAWHEAD))
if src.count(A_OLD)   != 1: die('src A_OLD count %d != 1' % src.count(A_OLD))
if src.count(A_NEW)   != 0: die('src A_NEW already present')
if src.count(INS)     != 1: die('insertion anchor not unique')
if d2.count(B_OLD)    != 1: die('d2 B_OLD count %d != 1' % d2.count(B_OLD))
if d2.count(B_NEW)    != 0: die('d2 B_NEW already present')
for g in GUARD:
    if g not in src: die('guard missing before: ' + g)
if src.count('ensureDefenseTables') != 1: die('ensureDefenseTables occurrences != 1 (calls must stay 0)')
if d2.count('autoBattleRT(') != d2.count('window.autoBattleRT('):
    die('bare autoBattleRT( call found in defense2.js')

# ---- 適用 ----
out_src = src.replace(A_OLD, A_NEW, 1)
out_src = out_src.replace(INS, MARK + INS, 1)
out_d2  = d2.replace(B_OLD, B_NEW, 1)

# ---- 事後チェック（書き出す前に） ----
st2 = out_src.find(BS); en2 = out_src.find(BE)
chain2 = out_src[st2:en2].count('.replace(')
print('chain after  = %d' % chain2)
if chain2 != EXPECT_CHAIN: die('chain changed: %d != %d' % (chain2, EXPECT_CHAIN))
if out_src.count(ANCHOR)  != 1: die('anchor damaged')
if out_src.count(RAWHEAD) != 1: die('raw head damaged')
if out_src.count(A_NEW)   != 1: die('A_NEW not applied exactly once')
if out_src.count(A_OLD)   != 0: die('A_OLD still present')
if out_src.count(SENT)    != 1: die('sentinel not unique')
if out_d2.count(B_NEW)    != 1: die('B_NEW not applied exactly once')
if out_src.count('ensureDefenseTables') != 1: die('ensureDefenseTables changed')
for g in GUARD:
    if g not in out_src: die('guard missing after: ' + g)

io.open(SRC, 'w', encoding='utf-8').write(out_src)
io.open(D2,  'w', encoding='utf-8').write(out_d2)
print('OK: applied (chain stays %d)' % chain2)
