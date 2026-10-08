#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 図鑑で つながるはずの進化がつながっていない 14組39体を つなげる（表示だけ）
#
# データ（stage）は 絶対に触らない。
# stage は getStats の stageMultiplier に直接かかっていて、
# 1 を 2 や 3 に直すと 39体のステータスが変わってしまう。
# ガチャと 戦争の敵えらびでも使われている。
#
# 原因: nextId も evoLevel も 正しく入っているのに、
#       この39体は stage が ぜんぶ 1 のままなので、
#       図鑑の鎖づくりが「1の次が2でない」で切っていた。
#
# なおしかた: その判定に「ただし evoLevel が入っているなら つなぐ」を足すだけ。
#   ゲーム本体（tryEvolveById）は nextId と evoLevel だけを見て進化させている。
#   つまり この条件は 実際に進化するものと ぴったり同じになる。
#
# 全490体で 確かめたこと（本番の配信HTMLのデータで実測）:
#   - 鎖は 280本。変わるのは 14本だけ。ほかの266本は 1文字も変わらない
#   - 「条件を丸ごと外した場合」と 結果が完全に一致（ちがい0件）
#   - 新しくつながるのは この14組だけ。まちがってつながるものは 0件
#   - 入手方法の文（getObtainMethod）は stage も nextId も見ていないので 影響なし
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 167 であること
#   - あて先が ちょうど1件 であること
#   - EVOCHAIN_V1 が まだ入っていないこと
#   - DEXDUP_V1（さきに入れた重複止め）が 入っていること
#   - 入れたあと 増えた文字数が ぴったり合うこと
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 167

OLD = ("if (typeof curM.stage === 'number' && typeof nxM.stage === 'number'"
       " && nxM.stage !== curM.stage + 1) break;")

NEW = ("if (typeof curM.stage === 'number' && typeof nxM.stage === 'number'"
       " && nxM.stage !== curM.stage + 1"
       " && !(typeof curM.evoLevel === 'number' && curM.evoLevel > 0)) break;"
       " /* EVOCHAIN_V1 stageがそろっていなくても evoLevel があれば"
       " 本当に進化するので つなぐ。stage のデータは触らない */")


def die(msg):
    print('### 中止: ' + msg)
    sys.exit(1)


with open(SRC, encoding='utf-8', newline='') as f:
    src_before = f.read()

a = src_before.find("app.get('/',")
b = src_before.find("app.get('/logout'")
if a < 0 or b < 0 or b <= a:
    die('src/index.tsx の目印が見つからない')
chain = src_before.count('.replace(', a, b)
if chain != CHAIN_BEFORE:
    die('チェーン数が ' + str(chain) + ' 件。' + str(CHAIN_BEFORE) + ' 件のはず。')
print('チェーン数 ' + str(chain) + ' 件を確認')

with open(PUB, encoding='utf-8', newline='') as f:
    html = f.read()

before_len = len(html)

if 'DEXDUP_V1' not in html:
    die('DEXDUP_V1 が入っていない。先に重複止めを入れること。')
if 'EVOCHAIN_V1' in html:
    die('EVOCHAIN_V1 がすでに入っている。二重に入れない。')
if 'stageMultiplier' not in html:
    die('getStats の stageMultiplier が見つからない。別物を触っている恐れ。')

n = html.count(OLD)
if n != 1:
    die('あて先が ' + str(n) + ' 件。1件のはず。')

html = html.replace(OLD, NEW, 1)

if html.count('EVOCHAIN_V1') != 1:
    die('入れた印が ' + str(html.count('EVOCHAIN_V1')) + ' 個。1個のはず。')
if html.count(OLD) != 0:
    die('古い判定が残っている')
if len(html) - before_len != len(NEW) - len(OLD):
    die('増えた文字数が ' + str(len(html) - before_len)
        + '。' + str(len(NEW) - len(OLD)) + ' のはず。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)

print('public/index.html: ' + str(before_len) + ' -> ' + str(len(html)) + ' 文字')

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')

print('src/index.tsx は無変更。チェーン '
      + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: 図鑑の鎖だけ直した。MONSTERS の stage は1文字も触っていない。')
