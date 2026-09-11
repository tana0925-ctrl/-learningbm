#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __DEF_LOG_NOTRUNC_V1__ : 従来経路（クライアント申告）の log_json から .slice(0, 100000) を外す
#
# なぜ：リプレイの実測は 22人・50〜78ティックで 32〜65KB、480ティックで 67KB。
#       ステージ制で戦闘が伸びて 100,000 字を超えると、途中で切れた文字列が保存され、
#       読み出し側の JSON.parse が落ちてクラス全員がリプレイを見られなくなる。
# どうする：切り詰めない。サーバ経路（src/def_resolve.ts）と同じく、大きすぎるときだけ
#           諦めて 'null' を入れる。壊れた JSON は絶対に保存しない。
#
# fail-closed: 事前チェックに1つでも失敗したら src/index.tsx に一切触れずに exit 1
import sys, io

SRC = 'src/index.tsx'
SENT = '__DEF_LOG_NOTRUNC_V1__'   # 冪等性の番兵（検証条件とは別物）
BS = "app.get('/', async (c) => {"
BE = "app.get('/logout'"
EXPECT_CHAIN = 72                 # この改修では .replace() を1本も足さない

OLD = "  const logJson = JSON.stringify(body.log || null).slice(0, 100000)"
NEW = ("  // " + SENT + " 切り詰めると壊れた JSON を保存してしまい、クラス全員がリプレイを見られなくなる。\n"
       "  // サーバ経路と同じ上限。超えたときだけ諦めて 'null' を入れる（切れた文字列は保存しない）。\n"
       "  const _lnFull = JSON.stringify(body.log || null)\n"
       "  const logJson = (_lnFull && _lnFull.length <= 900000) ? _lnFull : 'null'")

GUARD = ['__DEF_SNAP_SPDSKILLS_V1__', '__DEF_RESOLVE_VERIFY_V1__', '__DEF_SERVER_RESOLVE_V1__',
         'defAutoAdvanceV1', 'defense_standing', 'defense_carry_lock',
         'const DEFENSE_BASE_HP = 380',
         'INSERT OR IGNORE INTO defense_results',
         'defServerResolve(c.env, st, classId, DEFENSE_ENEMIES)']


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


src = io.open(SRC, encoding='utf-8').read()

if SENT in src:
    print('ALREADY APPLIED (sentinel present) - no file touched')
    sys.exit(0)

if src.count(BS) != 1: die("app.get('/', async (c) => { が一意でない: %d" % src.count(BS))
if src.count(BE) != 1: die("app.get('/logout' が一意でない: %d" % src.count(BE))
st = src.find(BS); en = src.find(BE)
if en <= st: die('block bounds inverted')
chain = src[st:en].count('.replace(')
print('chain before = %d' % chain)
if chain != EXPECT_CHAIN: die('chain %d != %d' % (chain, EXPECT_CHAIN))

if src.count(OLD) != 1: die('切り詰めの行が一意でない: %d' % src.count(OLD))
if src.count('.slice(0, 100000)') != 1: die('.slice(0, 100000) が1件でない: %d' % src.count('.slice(0, 100000)'))
for g in GUARD:
    if g not in src: die('guard missing before: ' + g)
if src.count('ensureDefenseTables') != 1:
    die('ensureDefenseTables の出現が 1 件でない（呼び出しは0件のまま）')

out = src.replace(OLD, NEW, 1)

st2 = out.find(BS); en2 = out.find(BE)
chain2 = out[st2:en2].count('.replace(')
if chain2 != EXPECT_CHAIN: die('chain after %d != %d' % (chain2, EXPECT_CHAIN))
if out.count(SENT) != 1: die('番兵が1件でない: %d' % out.count(SENT))
if out.count('.slice(0, 100000)') != 0: die('切り詰めが残っている')
if out.count("const logJson = (_lnFull && _lnFull.length <= 900000) ? _lnFull : 'null'") != 1:
    die('置き換えに失敗')
if out.count('ensureDefenseTables') != 1: die('ensureDefenseTables が増減した')

io.open(SRC, 'w', encoding='utf-8').write(out)
print('APPLIED: chain=%d（変わらず）, log_json の切り詰めを外した' % chain2)
