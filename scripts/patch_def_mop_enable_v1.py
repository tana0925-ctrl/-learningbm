#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __DEF_MOP_ENABLE_V1__
# 防衛戦の解決だけ 掃討フェーズを有効にする（mopTicks: 120）。
#   - ためしうち / 友達バトル は この opts を通らないので 1 ビットも変わらない
#   - 有効化はここ 1 行だけ。エンジン側の既定は 0 のまま。
# さわるファイル: src/def_resolve.ts の 1 箇所だけ。
# fail-closed: 一致しなければ何も書かずに exit 1
import io, os, sys

TGT  = 'src/def_resolve.ts'
SENT = '__DEF_MOP_ENABLE_V1__'

OLD = ("      forts: false, tactics: true, contact: true, foeLaneMix: true\n"
       "    })")
NEW = ("      forts: false, tactics: true, contact: true, foeLaneMix: true,\n"
       "      // " + SENT + " 片方が全滅したあと、生き残りが相手の基地まで歩く時間（tick）。\n"
       "      // 0 だと歩く前に終わってしまい「基地に着いてないのに試合がおわる」になる。\n"
       "      mopTicks: 120\n"
       "    })")


def die(m):
    print('ABORT: ' + m)
    sys.exit(1)


if not os.path.exists(TGT):
    die('%s が無い' % TGT)
s = io.open(TGT, encoding='utf-8').read()

if SENT in s:
    if s.count('mopTicks: 120') != 1:
        die('番兵はあるが mopTicks が %d 件' % s.count('mopTicks: 120'))
    print('ALREADY APPLIED - no file touched')
    sys.exit(0)

if s.count('mopTicks') != 0:
    die('mopTicks がすでにある（%d 件）' % s.count('mopTicks'))
if s.count(OLD) != 1:
    die('アンカーが %d 件（1件でないと危険）' % s.count(OLD))
if s.count('const rep = defAutoBattleRT(specsA, specsB, {') != 1:
    die('defAutoBattleRT の呼び出しが 1 件でない')

out = s.replace(OLD, NEW, 1)

if out.count('mopTicks: 120') != 1:
    die('mopTicks が 1 件にならない')
if out.count(SENT) != 1:
    die('番兵が 1 件でない')
if out.count('const rep = defAutoBattleRT(specsA, specsB, {') != 1:
    die('呼び出しが壊れた')
if out.count("bases: true, lanes: true, laneCount: 3, seed: seed, program: true") != 1:
    die('ほかの opts が壊れた')

io.open(TGT, 'w', encoding='utf-8').write(out)
print('OK: %s に mopTicks: 120 を入れた' % TGT)
