#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GYMIMG_V1  ジムのキャラを、絵文字からキャラ画像に差し替える。

  直すのは public/index.html の2か所（ジムの手持ち一覧。同じ行が2本ある）。
  .text-lg = 18px。王冠バッジ（crown）と title はそのまま。
  行は増やさない（差し込みは1行の中だけ）。
  色違いの金リング・クラス・付けかたの数が変わったら止まる。
  src/index.tsx は1バイトも触らない。
"""
import os
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
BT = chr(96)
D = chr(36)


def die(msg):
    print('::error::' + msg)
    sys.exit(1)


def chain_count(t):
    a = t.index("app.get('/'")
    b = t.index("app.get('/logout'")
    return t[a:b].count('.replace(')


with open(SRC, encoding='utf-8', newline='') as f:
    src_before = f.read()
want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want:
    die('CHAIN_BEFORE が渡されていません。')
now = chain_count(src_before)
if str(now) != want:
    die('チェーン数が合いません。実測 %d / 指定 %s。1バイトも書かずに止めました。' % (now, want))
print('チェーン数 %d 件を確認。' % now)

with open(PUB, encoding='utf-8', newline='') as f:
    html = f.read()

cr0 = html.count('\r')
lf0 = html.count('\n')
ring0 = html.count('shiny-ring')
cls0 = html.count('monShinyClass')
set0 = html.count('monShinySet')

if 'window.monSpriteHtml' not in html:
    die('monSpriteHtml の定義が見あたりません。')
if 'GYMIMG_V1' in html:
    die('GYMIMG_V1 がすでに入っています。')

OLD = ('                            return m ? ' + BT
       + '<div class="relative text-lg filter drop-shadow-sm cursor-help hover:scale-125 '
       + 'transition" title="' + D + '{m.name}">' + D + '{m.sprite}' + D + '{crown}</div>'
       + BT + " : '';\n")
NEW = OLD.replace(
    D + '{m.sprite}',
    D + "{/*GYMIMG_V1*/ (typeof monSpriteHtml === 'function') "
    "? monSpriteHtml(m.id, m.sprite) : m.sprite}")

n = html.count(OLD)
if n != 2:
    die('あて先が %d 件。2件のはず。1バイトも書かずに止めました。' % n)

html = html.replace(OLD, NEW)
print('差し替えた: ジムの手持ち一覧 2件')

if html.count('GYMIMG_V1') != 2:
    die('印が %d 個。2個のはず。' % html.count('GYMIMG_V1'))
if html.count('shiny-ring') != ring0 or html.count('monShinyClass') != cls0 or html.count('monShinySet') != set0:
    die('色違いの数が変わりました。')
if html.count('\r') != cr0 or html.count('\n') != lf0:
    die('改行の数が変わりました。')
if html.count('{crown}</div>') != 2:
    die('王冠バッジが消えました。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)
print('public/index.html: 改行はそのまま / 金リング %d / 色違いクラス %d'
      % (html.count('shiny-ring'), html.count('monShinyClass')))

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')
print('OK: ジムだけ差し替えた。')
