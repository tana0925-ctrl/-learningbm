#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZOMBIMG_V1  ゾンビ（にゃんこビーム戦）のキャラを、絵文字からキャラ画像に差し替える。

  直すのは public/index.html の2か所（どちらも1行の中だけ・行は増やさない）:
    1. 出すキャラのボタン   .text-3xl = 30px （id がその場にあるのでそれを使う）
    2. 戦場のユニット       .war-sprite    （u.monsterId を使う）

  u.monsterId が null のもの（お城など）は monSpriteHtml が絵を作らず
  絵文字をそのまま返すので、今までどおりに出る。
  色違いの数が変わったら止まる。src/index.tsx は1バイトも触らない。
"""
import os
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
MARK = 'ZOMBIMG_V1'
TAG = '/*' + MARK + '*/ '
Q = '❓'


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

A_OLD = '<div class="war-sprite">${u.sprite}</div>'
A_NEW = ('<div class="war-sprite">${' + TAG
         + "(typeof monSpriteHtml === 'function') "
         + '? monSpriteHtml(u.monsterId, u.sprite) : u.sprite}</div>')

B_OLD = ('<div class="text-3xl leading-none">${escapeHtml(st.sprite||'
         + repr(Q) + ')}</div>')
B_NEW = ('<div class="text-3xl leading-none">${' + TAG
         + "(typeof monSpriteHtml === 'function') "
         + '? monSpriteHtml(id, (st.sprite||' + repr(Q) + ')) '
         + ': escapeHtml(st.sprite||' + repr(Q) + ')}</div>')

PAIRS = [(A_OLD, A_NEW, '戦場のユニット'), (B_OLD, B_NEW, '出すキャラのボタン')]

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
for s in ['war-unit', 'war-hp', 'war-spawning-enemy']:
    if s not in html:
        die('演出「%s」が消えました。' % s)

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)
print('public/index.html: 改行はそのまま / 金リング %d' % html.count('shiny-ring'))

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')
print('OK: ゾンビだけ差し替えた。')
