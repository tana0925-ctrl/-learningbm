#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BOXIMG_V1  ボックスのキャラを、絵文字からキャラ画像に差し替える。

  直すのは public/index.html の2か所:
    1. ボックスのマス（renderBox）   .text-lg = 18px
    2. 交換のボックスのマス          .text-lg = 18px

  色違いを壊さない:
    ・色違いの span（monShinyClass でクラスを付ける）と
      金リング span class="shiny-ring" は1文字も触らない。
      絵文字を入れていたところに、そのまま絵の HTML を入れるだけ。
    ・差し替えのあとに金リングとクラスの数を数えて確かめる。

  src/index.tsx は1バイトも触らない。チェーン数は確認だけ。
"""
import os
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CALL = "(typeof monSpriteHtml === 'function') ? monSpriteHtml(m.id, m.sprite) : m.sprite"


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
if 'BOXIMG_V1' in html:
    die('BOXIMG_V1 がすでに入っています。')
if ring0 < 1 or cls0 < 1:
    die('色違いの金リング(%d)かクラス(%d)が見あたりません。' % (ring0, cls0))

BT = chr(96)

A_OLD = (
    '                    slot.innerHTML = ' + BT + '<div class="text-lg leading-none">'
    "${entry.shiny ? '<span class=\"' + (window.monShinyClass ? "
    "window.monShinyClass(entry.monsterId) : 'shiny-mon') + '\">' + m.sprite + "
    "'</span>' : m.sprite}</div>${entry.shiny ? "
    "'<span class=\"shiny-ring\"></span>' : ''}"
    '<div class="text-[8px] font-bold truncate w-full text-center">${m.name}</div>'
    '<div class="text-[7px] text-gray-400">Lv.${entry.level}</div>' + BT + ';\n'
)
A_NEW = (
    '                    /* BOXIMG_V1 ボックスのマス: 絵があれば絵、無ければ絵文字 */\n'
    '                    const _bsp = ' + CALL + ';\n'
    + A_OLD.replace('+ m.sprite +', '+ _bsp +').replace(': m.sprite}', ': _bsp}')
)

B_OLD = (
    '      slot.innerHTML = \'<div class="text-lg leading-none">\' + m.sprite + '
    '\'</div><div class="text-[8px] font-bold truncate w-full text-center">\' + m.name + '
    '\'</div><div class="text-[7px] text-gray-400">Lv.\' + (entry.level||1) + \'</div>\';\n'
)
B_NEW = (
    '      /* BOXIMG_V1 交換のボックスのマス: 絵があれば絵、無ければ絵文字 */\n'
    '      var _bsp2 = ' + CALL + ';\n'
    + B_OLD.replace("+ m.sprite +", "+ _bsp2 +")
)

PAIRS = [(A_OLD, A_NEW, 'ボックスのマス'), (B_OLD, B_NEW, '交換のボックスのマス')]

for old, new, label in PAIRS:
    n = html.count(old)
    if n != 1:
        die('あて先「%s」が %d 件。1件のはず。1バイトも書かずに止めました。' % (label, n))

for old, new, label in PAIRS:
    html = html.replace(old, new, 1)
    print('差し替えた: ' + label)

if html.count('BOXIMG_V1') != 2:
    die('印が %d 個。2個のはず。' % html.count('BOXIMG_V1'))
if html.count('shiny-ring') != ring0:
    die('金リングが %d -> %d に変わりました。' % (ring0, html.count('shiny-ring')))
if html.count('monShinyClass') != cls0:
    die('色違いのクラスが %d -> %d に変わりました。' % (cls0, html.count('monShinyClass')))
if html.count('monShinySet') != set0:
    die('色違いの付けかたが %d -> %d に変わりました。' % (set0, html.count('monShinySet')))
if html.count('\r') != cr0:
    die('改行(CR)が %d -> %d に変わりました。' % (cr0, html.count('\r')))
if html.count('\n') != lf0 + 4:
    die('改行(LF)が %d -> %d。足すのは4本のはず。' % (lf0, html.count('\n')))
if html.count('_bsp +') != 1 or html.count(': _bsp}') != 1 or html.count('_bsp2 +') != 1:
    die('差し込んだ変数の使われ方がおかしい。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)
print('public/index.html: LF %d -> %d / 金リング %d / 色違いクラス %d'
      % (lf0, html.count('\n'), html.count('shiny-ring'), html.count('monShinyClass')))

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')
print('OK: ボックスだけ差し替えた。色違いの金リングとクラスはそのまま。')
