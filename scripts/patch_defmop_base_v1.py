#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __DEFMOP_BASE_V1__
# 防衛戦：基地をこわして勝ったのに、終了理由が 'wipe'（全滅）のまま残る件を直す。
#
# なにが起きていたか（実測）
#   掃討フェーズ（__DEFMOP_V1__）の最後の一撃で敵の基地HPが 0 になると、
#   その直後の全滅チェックで _mopOn() が false（基地はもう落ちている）を返し、
#   基地チェックに進む前に break してしまう。→ reason は初期値の 'wipe' のまま。
#
# 直しかた
#   基地チェックを「全滅チェックより前」に移すだけ。
#   基地HPが 0 になるのは _cAttack が基地を殴ったときだけなので、
#   mopTicks=0（ためしうち・友達バトル）では 1 ビットも挙動が変わらない。
#   （node で 40 シードぶん、出力がバイト単位で同一であることを確認ずみ）
#
# さわるファイル: src/defmop_v1.ts の 1 箇所だけ。
# public/index.html / src/index.tsx / src/def_engine.ts には一切さわらない。
# fail-closed: 一致しなければ何も書かずに exit 1
import io, os, sys

TGT  = 'src/defmop_v1.ts'
SENT = '__DEFMOP_BASE_V1__'

OLD = ('const B_HIT = "if(CONTACT){ _cAttack(f); '
       'if(!alive(A).length||!alive(B).length){ /* __DEFMOP_V1__ */ if(!_mopOn()){ ended=true; break; } }"')

NEW = ('const B_HIT = "if(CONTACT){ _cAttack(f); '
       '/* __DEFMOP_BASE_V1__ 基地が落ちたら まず それを勝ちとして記録する。全滅の判定で上書きさせない。 */ '
       "if(baseHpA<=0){ baseHpA=0; winner='B'; reason='base'; ended=true; break; } "
       "if(baseHpB<=0){ baseHpB=0; winner='A'; reason='base'; ended=true; break; } "
       'if(!alive(A).length||!alive(B).length){ /* __DEFMOP_V1__ */ if(!_mopOn()){ ended=true; break; } }"')


def die(m):
    print('ABORT: ' + m)
    sys.exit(1)


if not os.path.exists(TGT):
    die('%s が無い' % TGT)
s = io.open(TGT, encoding='utf-8').read()

if SENT in s:
    if s.count(NEW) != 1:
        die('番兵はあるが中身が想定と違う')
    print('ALREADY APPLIED - no file touched')
    sys.exit(0)

if s.count(OLD) != 1:
    die('B_HIT の元の文字列が %d 件（1件でないと危険）' % s.count(OLD))
if s.count('__DEFMOP_V1__') < 3:
    die('__DEFMOP_V1__ の印が足りない')
if s.count("{ tag: 'M02_hit', a: A_HIT, b: B_HIT }") != 1:
    die('M02_hit の登録が 1 件でない')

out = s.replace(OLD, NEW, 1)

if out.count(SENT) != 1:
    die('番兵が 1 件にならない')
if out.count('const B_HIT = ') != 1:
    die('B_HIT の定義が 1 件でない')
if out.count("reason='base'") - s.count("reason='base'") != 2:
    die("reason='base' の増えかたが 2 件でない")
if out.count("{ tag: 'M01_decl', a: A_DECL, b: B_DECL }") != 1:
    die('M01 が壊れた')
if out.count("{ tag: 'M03_tail', a: A_TAIL, b: B_TAIL }") != 1:
    die('M03 が壊れた')

io.open(TGT, 'w', encoding='utf-8').write(out)
print('OK: %s に __DEFMOP_BASE_V1__ を適用' % TGT)
