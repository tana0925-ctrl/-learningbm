#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DEFIMG_V1  防衛戦のキャラを、絵文字からキャラ画像に差し替える。

  直すのは public/index.html の2か所（どちらも1行の中だけ・行は増やさない）:
    1. 敵の一覧   .text-3xl = 30px
    2. ボス       .text-4xl = 36px

  ⚠️ 防衛戦の「戦績の一覧」は public/defense2.js が作っていて、
     そこの持ち物は {name, sprite, mon} だけで id を持っていない。
     id が無いと絵を引けないので、この便では触らない（絵文字のまま）。
     id を足すのは新しい作りになるので、別の相談にする。

  色違いの数（金リング・クラス・付けかた）が変わったら止まる。
  src/index.tsx は1バイトも触らない。
"""
import os
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
MARK = 'DEFIMG_V1'
TAG = '/*' + MARK + '*/ '


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
if MARK in html:
    die(MARK + ' がすでに入っています。')


def swap(cls, var, fallback):
    old = '<div class="' + cls + '">${' + var + '.sprite || ' + repr(fallback) + '}</div>'
    new = ('<div class="' + cls + '">${' + TAG
           + "(typeof monSpriteHtml === 'function') ? monSpriteHtml("
           + var + '.id, (' + var + '.sprite || ' + repr(fallback) + ')) : ('
           + var + '.sprite || ' + repr(fallback) + ')}</div>')
    return old, new


PAIRS = [
    swap('text-3xl', 'monster', '❓') + ('敵の一覧',),
    swap('text-4xl', 'bossMon', '\U0001F451') + ('ボス',),
]

for old, new, label in PAIRS:
    n = html.count(old)
    if n != 1:
        die('あて先「%s」が %d 件。1件のはず。1バイトも書かずに止めました。' % (label, n))

for old, new, label in PAIRS:
    html = html.replace(old, new, 1)
    print('差し替えた: ' + label)

if html.count(MARK) != 2:
    die('印が %d 個。2個のはず。' % html.count(MARK))
if html.count('shiny-ring') != ring0 or html.count('monShinyClass') != cls0 or html.count('monShinySet') != set0:
    die('色違いの数が変わりました。')
if html.count('\r') != cr0 or html.count('\n') != lf0:
    die('改行の数が変わりました。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)
print('public/index.html: 改行はそのまま / 金リング %d' % html.count('shiny-ring'))

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')
print('OK: 防衛戦だけ差し替えた。')
