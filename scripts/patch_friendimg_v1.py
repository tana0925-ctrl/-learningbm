#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FRIENDIMG_V1  友達3対3（グループ戦）のキャラを、絵文字からキャラ画像に差し替える。

  直すのは public/index.html の3か所（どれも1行の中だけ・行は増やさない）:
    1. field のユニット   .gc-sp = 30px
    2. 一覧のユニット     font-size:30px
    3. プログラムのタブ   .gc-ptab = 11px

  gc-hit / gc-strong / gc-ko / gc-dead のアニメと filter は
  入れ物（.gc-sp や .gc-unit）に効くので、中身が img でもそのまま残る。
  色違いの数（金リング・クラス・付けかた）が変わったら止まる。
  src/index.tsx は1バイトも触らない。
"""
import os
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
MARK = 'FRIENDIMG_V1'
C1 = "((typeof monSpriteHtml === 'function')?monSpriteHtml(m.id,m.sprite):m.sprite)"
C2 = "((typeof monSpriteHtml === 'function')?monSpriteHtml(m.id,(m.sprite||'')):(m.sprite||''))"
TAG = '/*' + MARK + '*/'


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

A1 = 'class="gc-sp">\'+m.sprite+'
A2 = 'line-height:1;">\'+m.sprite+'
A3 = "+(m.sprite||'')+_defEsc(m.name)+'</button>'"

PAIRS = [
    (A1, 'class="gc-sp">\'+' + TAG + C1 + '+', 'field のユニット'),
    (A2, 'line-height:1;">\'+' + TAG + C1 + '+', '一覧のユニット'),
    (A3, '+' + TAG + C2 + "+_defEsc(m.name)+'</button>'", 'プログラムのタブ'),
]

for old, new, label in PAIRS:
    n = html.count(old)
    if n != 1:
        die('あて先「%s」が %d 件。1件のはず。1バイトも書かずに止めました。' % (label, n))

for old, new, label in PAIRS:
    html = html.replace(old, new, 1)
    print('差し替えた: ' + label)

if html.count(MARK) != 3:
    die('印が %d 個。3個のはず。' % html.count(MARK))
if html.count('shiny-ring') != ring0 or html.count('monShinyClass') != cls0 or html.count('monShinySet') != set0:
    die('色違いの数が変わりました。')
if html.count('\r') != cr0 or html.count('\n') != lf0:
    die('改行の数が変わりました。')
for s in ['gc-hit', 'gc-strong', 'gc-ko', 'gc-dead', 'gcIdle']:
    if s not in html:
        die('演出「%s」が消えました。' % s)

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)
print('public/index.html: 改行はそのまま / 金リング %d / 色違いクラス %d'
      % (html.count('shiny-ring'), html.count('monShinyClass')))

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')
print('OK: 友達3対3だけ差し替えた。')
