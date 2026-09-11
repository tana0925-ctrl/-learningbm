#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __DEF2_SKIP_LOCAL_V1__ : makeResolve が「先に結果の有無を見て抜ける」ようにする（1箇所）
#
# なぜ：サーバ側は1クラス1回で済むようになったが、端末側は22台とも戦闘を回したままだった。
#       すでに結果があるなら、端末でローカル戦闘を回す意味がない（/api/defense/status は
#       結果が確定しているとき st.entries を返さないので、回しても空の戦闘になる）。
# どうする：st.result があれば buildBattle も POST もせず、リプレイ再生へ回す。
#
# fail-closed: 事前チェックに1つでも失敗したら public/defense2.js に一切触れずに exit 1
import sys, io

SRC = 'public/defense2.js'
SENT = '__DEF2_SKIP_LOCAL_V1__'   # 冪等性の番兵（検証条件とは別物）

ANCHOR = "        var built = buildBattle(st); var rep=built.rep;"
INS = ("        /* " + SENT + " すでに結果があるなら、端末で戦闘を回さずリプレイ再生に回す */\n"
       "        if(st.result){ if(typeof window.openDefense==='function'){ try{ window.openDefense(); }catch(e){} } return; }\n")

GUARD = ['function makeResolve(orig){', 'withFrozenStats(', 'window.autoBattleRT(',
         "jget('/api/defense/status')", "fetch('/api/defense/resolve'",
         'DEF2_STAGE0A_GCHOME_20260911', 'def2GetReplayData']


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


src = io.open(SRC, encoding='utf-8').read()

if SENT in src:
    print('ALREADY APPLIED (sentinel present) - no file touched')
    sys.exit(0)

if src.count(ANCHOR) != 1: die('挿入アンカーが一意でない: %d' % src.count(ANCHOR))
if src.count('function makeResolve(orig){') != 1: die('makeResolve が一意でない')
if src.count('autoBattleRT(') != src.count('window.autoBattleRT('):
    die('素の autoBattleRT( 呼び出しがある')
if src.count('withFrozenStats(') < 2: die('withFrozenStats が見当たらない')
for g in GUARD:
    if g not in src: die('guard missing before: ' + g)

# 挿入位置が makeResolve の中であること（別の buildBattle 呼び出しに当てない）
mr = src.find('function makeResolve(orig){')
ai = src.find(ANCHOR)
if ai < mr: die('アンカーが makeResolve より前にある')
if ai - mr > 2000: die('アンカーが makeResolve から離れすぎている: %d' % (ai - mr))

out = src.replace(ANCHOR, INS + ANCHOR, 1)

if out.count(SENT) != 1: die('番兵が1件でない: %d' % out.count(SENT))
if out.count('if(st.result){') != 1: die('先読みの分岐が1件でない')
if out.count(ANCHOR) != 1: die('アンカーが壊れた')
if out.count('autoBattleRT(') != out.count('window.autoBattleRT('):
    die('適用後に素の autoBattleRT( ができた')
if out.count('withFrozenStats(') != src.count('withFrozenStats('): die('withFrozenStats が増減した')
if len(out) <= len(src): die('ファイルが縮んだ')

# 先読みの分岐が、ローカル戦闘より前にあること
si = out.find('if(st.result){')
bi = out.find('var built = buildBattle(st);')
if not (si < bi): die('先読みが buildBattle より後ろにある')

io.open(SRC, 'w', encoding='utf-8').write(out)
print('APPLIED: makeResolve が結果ありなら即リプレイへ抜ける')
