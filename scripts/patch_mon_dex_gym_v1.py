#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# キャラの絵 第7便: 図鑑の中の「ジムリーダー」欄も 絵にする。
#
# 第2便で図鑑の4か所を差し替えたとき、範囲を狭くとって
# ジムリーダーの欄（id 400〜415 を並べる所）を外していた。
# その結果、同じ図鑑の中で 一覧は絵・ジムリーダー欄は絵文字 という
# 食い違いが起きていたので、ここも同じ形にそろえる。
#
# 絵が無い id（401 402 404 405 406 410 411 など）は これまでどおり絵文字。
# 未入手のキャラが ❓ になるところは変えない。
#
# 触るのは public/index.html の1か所だけ。図鑑の外（バトル等）は一切さわらない。
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 158 であること
#   - MON_IMG_V3（第5便）が入っていること
#   - MON_DEX_V2 が まだ入っていないこと
#   - あて先が ちょうど1件 であること
#   - 第2便の印(MON_DEX_V1)が5個のままであること
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 158

OLD = r"""                    <div class="text-2xl">${unlocked ? m.sprite : "❓"}</div>"""

NEW = (
    r"""                    <!-- MON_DEX_V2 ジムリーダー欄 絵があれば絵、無ければ絵文字 -->"""
    + chr(10) +
    r"""                    <div class="text-2xl">${unlocked ? ((typeof monSpriteHtml === 'function') ? monSpriteHtml(m.id, m.sprite) : m.sprite) : "❓"}</div>"""
)


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

if 'MON_IMG_V3' not in html:
    die('第5便(MON_IMG_V3)が入っていない')
if 'MON_DEX_V2' in html:
    die('MON_DEX_V2 がすでに入っている。二重に入れない。')

n = html.count(OLD)
if n != 1:
    die('あて先が ' + str(n) + ' 件。1件のはず。')

before_len = len(html)
html = html.replace(OLD, NEW, 1)

if html.count('MON_DEX_V2') != 1:
    die('入れた印が ' + str(html.count('MON_DEX_V2')) + ' 個。1個のはず。')
if html.count('MON_DEX_V1') != 5:
    die('第2便の印が ' + str(html.count('MON_DEX_V1')) + ' 個。5個のはず。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)

print('public/index.html: ' + str(before_len) + ' -> ' + str(len(html)) + ' 文字')

with open(SRC, encoding='utf-8', newline='') as f:
    src_after = f.read()
if src_after != src_before:
    die('src/index.tsx が変わってしまった')

print('src/index.tsx は無変更。チェーン ' + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: ジムリーダー欄も絵にした。')
