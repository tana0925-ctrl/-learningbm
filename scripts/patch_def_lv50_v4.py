# -*- coding: utf-8 -*-
# DEF2_LV50_ENTRYFIX_V1 --- 出陣画面の ひとことが 出ていなかったのを なおす。
#
# DEF2_LV50_SAME_V1 で 足した あて先は
#   「てきの 見出し 👾 敵軍団（…」 だった。
# ところが チェーンの もっと 前で、その 見出しは
#   「👾 ステージ…／てき…たい」 に 書きかえられている。
# だから 私の あて先は もう 無く、ひとことが 出なかった。
#
# あて先を 書きかえられない ところまで みじかくする（見出しの 手前まで）。
# さわるのは src/index.tsx だけ。.replace チェーンは 85 の まま。
# 一つでも あてはまらなければ 何も 書かずに 止まる（fail-closed）。

import io
import sys

TSX = 'src/index.tsx'

MARK = 'DEF2_LV50_ENTRYFIX_V1'
BT = chr(96)
ALREADY = '>👾 ' + BT

SEG_OLD = '>👾 敵軍団（'
SEG_NEW = '>👾 '

CHAIN = 85


def die(msg):
    print(u'NG: ' + msg)
    sys.exit(1)


tsx = io.open(TSX, encoding='utf-8').read()

if ALREADY in tsx:
    print(u'すでに 適用ずみ。何も しない。')
    sys.exit(0)

if MARK in tsx:
    die(u'番兵だけ のこっている。人の目で 見てほしい。')

if 'DEF2_LV50_SAME_V1' not in tsx:
    die(u'さきに DEF2_LV50_SAME_V1 を 流してから。')

if tsx.count(SEG_OLD) != 2:
    die(u'あて先が %d 件（2件で ないと 流さない）' % tsx.count(SEG_OLD))

OLDC = u'      // DEF2_LV50_SAME_V1 出陣の 画面で、みんな おなじ ものさしだと つたえる'
NEWC = u'      // DEF2_LV50_SAME_V1 DEF2_LV50_ENTRYFIX_V1 出陣の 画面で、みんな おなじ ものさしだと つたえる（見出しが ステージ表示に 書きかえられた あとでも あたるよう、あて先を みじかくした）'

if tsx.count(OLDC) != 1:
    die(u'しるしの 行が %d 件（1件で ないと 流さない）' % tsx.count(OLDC))

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
before = tsx[i:j].count('.replace(')
if before != CHAIN:
    die(u'チェーンが %d 件（%d 件の はず）' % (before, CHAIN))

tsx = tsx.replace(SEG_OLD, SEG_NEW)
tsx = tsx.replace(OLDC, NEWC, 1)

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
after = tsx[i:j].count('.replace(')
if after != CHAIN:
    die(u'チェーンが %d 件に なった（%d 件の はず）' % (after, CHAIN))

if tsx.count(ALREADY) != 2:
    die(u'みじかい あて先が %d 件（2件の はず）' % tsx.count(ALREADY))
if tsx.count(SEG_OLD) != 0:
    die(u'ふるい あて先が のこっている')
if tsx.count(MARK) != 1:
    die(u'番兵が %d 件（1件の はず）' % tsx.count(MARK))

io.open(TSX, 'w', encoding='utf-8').write(tsx)
print(u'OK: チェーンは %d の まま' % after)
