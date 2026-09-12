# -*- coding: utf-8 -*-
# DEF_LV50_V2 --- ふるい ものさしで のこっている 出陣を、自動で 撮りなおす。
#
# DEF_LV50_V1 で、出陣の ときに 作る ひかえは レベル50・上限つき に なった。
# その しるしが dn:1。
# けれど まえに ためた ひかえは レベル100 などの ままで のこっている。
# サーバには 図鑑が ないので、サーバ側で 計算しなおすことは できない。
#
# そこで もとから ある 撮りなおしの みち（carry_over_stale）に のせる。
#   しるしの ない ひかえ  -> 撮りなおす
#   しるしの ある ひかえ  -> 撮りなおさない（レベルが 上がっても もう 関係ない）
# 児童の データは 消さない。画面を ひらいた ときに 上書きされるだけ。
#
# さわるのは src/index.tsx の サーバ側 1か所だけ。.replace チェーンは 84 の まま。
# 一つでも あてはまらなければ 何も 書かずに 止まる（fail-closed）。

import io
import sys

TSX = 'src/index.tsx'

MARK = '__DEF_LV50_V2__'
ALREADY = 'Number(out.my_entry.monster.dn)'

CHAIN = 84


def die(msg):
    print(u'NG: ' + msg)
    sys.exit(1)


tsx = io.open(TSX, encoding='utf-8').read()

if ALREADY in tsx:
    print(u'すでに 適用ずみ。何も しない。')
    sys.exit(0)

if MARK in tsx:
    die(u'番兵だけ のこっている。人の目で 見てほしい。')

if 'window.defNorm=function(b)' not in tsx:
    die(u'さきに DEF_LV50_V1 を 流してから。')

NL = chr(10)

OLD = (u'          if (Number(_dsRow.curlv || 0) > Number(_dsRow.lv || 0)) out.carry_over_stale = true' + NL
       + u'        }' + NL
       + u'      }' + NL
       + u'    } catch (_e) {}' + NL
       + u'  }' + NL)

NEW = (u'          // __DEF_LV50_V2__ ふるい ものさしの ときだけ 撮りなおす（レベルが 上がっても もう 撮りなおさない）' + NL
       + u'          if (!(_dsM && Number(_dsM.dn) === 1)) out.carry_over_stale = true' + NL
       + u'        }' + NL
       + u'      }' + NL
       + u'    } catch (_e) {}' + NL
       + u'  }' + NL
       + u'  // __DEF_LV50_V2__ ふるい ものさしで 出陣している子は、つぎに 画面を ひらいた ときに 自動で 撮りなおす（データは 消さない）' + NL
       + u'  try { if (out.my_entry && out.my_entry.monster && Number(out.my_entry.monster.dn) !== 1) out.carry_over_stale = true } catch (_e) {}' + NL)

if tsx.count(OLD) != 1:
    die(u'あて先が %d 件（1件で ないと 流さない）' % tsx.count(OLD))

if NEW in tsx:
    die(u'新しい 中みが すでに ある')

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
before = tsx[i:j].count('.replace(')
if before != CHAIN:
    die(u'チェーンが %d 件（%d 件の はず）' % (before, CHAIN))

tsx = tsx.replace(OLD, NEW, 1)

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
after = tsx[i:j].count('.replace(')
if after != CHAIN:
    die(u'チェーンが %d 件に なった（%d 件の はず）' % (after, CHAIN))

if tsx.count(MARK) != 2:
    die(u'番兵が %d 件（2件の はず）' % tsx.count(MARK))

if tsx.count('out.carry_over_stale') != 2:
    die(u'撮りなおしの 口が %d 件（2件の はず）' % tsx.count('out.carry_over_stale'))

io.open(TSX, 'w', encoding='utf-8').write(tsx)
print(u'OK: チェーンは %d の まま' % after)
