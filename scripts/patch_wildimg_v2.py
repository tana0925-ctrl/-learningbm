#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WILDIMG_V2  野生バトルの点滅を直す（絵文字には戻さない）。

  何が起きていたか:
    バトル中は setInterval(battleLoop, 100) で updateBattleDisplay() が
    0.1秒ごとに走る。WILDIMG_V1 はその中で毎回 innerHTML を書いていたので、
    1秒に10回 img を作り直していた。
    新しく作られた img は loading="lazy" / decoding="async" のぶん
    「まだ描かない」状態から始まるので、消えて出てをくりかえして点滅して見えた。
    ついでに float-dynamic や attacking-enemy のアニメも毎回いちからやり直しになっていた。

  直し方:
    中身（id と絵文字）が変わったときだけ書く。
    同じキャラが戦っているあいだ img は1個のまま。
    交代や進化で中身が変われば data-sp-key が変わるので、そのときだけ作り直す。
    作り直さないので lazy も decoding もアニメのやり直しも関係なくなる。

  おまけに直るもの:
    絵が無くて onerror で絵文字に落ちたあとも、もう書き直さないので
    「絵→絵文字→絵」の往復が起きない。

  色違い: monShinySet は入れ物の div にクラスを付けるので1文字も触らない。
          金リング・クラス・付けかたの数が変わったら止まる。
  src/index.tsx は1バイトも触らない。
  WILDIMG_V1 の印は消さずに残す（前の便が入っていることの目じるし）。
"""
import os
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'


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

if 'WILDIMG_V1' not in html:
    die('WILDIMG_V1 が入っていません。先に野生バトルの便を流すこと。')
if 'WILDIMG_V2' in html:
    die('WILDIMG_V2 がすでに入っています。')
if 'setInterval(battleLoop, 100)' not in html:
    die('バトルの時計仕掛けが見あたりません。作りが変わった可能性があります。')


def mk(indent, el_id, var, pre):
    i = ' ' * indent
    side = '・自分' if var == 'myMon' else '・相手'
    old = (
        i + '/* WILDIMG_V1 野生バトル' + side
        + ': 絵があれば絵、無ければ絵文字（色違いのクラスはこのすぐ下で付けます） */\n'
        + i + 'try {\n'
        + i + "    document.getElementById('" + el_id + "').innerHTML = "
        + "(typeof monSpriteHtml === 'function') ? monSpriteHtml(" + var + '.id, ' + var + '.sprite) '
        + ': String(' + var + ".sprite == null ? '' : " + var + '.sprite);\n'
        + i + '} catch (e) {\n'
        + i + "    document.getElementById('" + el_id + "').innerText = " + var + '.sprite;\n'
        + i + '}\n'
    )
    new = (
        i + '/* WILDIMG_V2（WILDIMG_V1 の直し）野生バトル' + side + ': 中身が変わったときだけ書く。\n'
        + i + '   バトル中はこの関数が 0.1秒ごとに走るので、毎回 innerHTML を書くと\n'
        + i + '   img を作り直してしまい、チカチカ点滅して見える。 */\n'
        + i + 'try {\n'
        + i + '    var ' + pre + "El = document.getElementById('" + el_id + "');\n"
        + i + '    var ' + pre + "Key = '" + pre + "' + String(" + var + ".id) + '|' + String("
        + var + '.sprite);\n'
        + i + '    if (' + pre + "El.getAttribute('data-sp-key') !== " + pre + 'Key) {\n'
        + i + '        ' + pre + "El.setAttribute('data-sp-key', " + pre + 'Key);\n'
        + i + '        ' + pre + 'El.innerHTML = '
        + "(typeof monSpriteHtml === 'function') ? monSpriteHtml(" + var + '.id, ' + var + '.sprite) '
        + ': String(' + var + ".sprite == null ? '' : " + var + '.sprite);\n'
        + i + '    }\n'
        + i + '} catch (e) {\n'
        + i + "    document.getElementById('" + el_id + "').innerText = " + var + '.sprite;\n'
        + i + '}\n'
    )
    return old, new


PAIRS = [
    mk(12, 'playerSpriteDisplay', 'myMon', '_wp') + ('自分がわ',),
    mk(16, 'enemySpriteDisplay', 'enemyMon', '_we') + ('相手がわ',),
]

for old, new, label in PAIRS:
    n = html.count(old)
    if n != 1:
        die('あて先「%s」が %d 件。1件のはず。1バイトも書かずに止めました。' % (label, n))

for old, new, label in PAIRS:
    html = html.replace(old, new, 1)
    print('直した: ' + label)

if html.count('WILDIMG_V2') != 2:
    die('印が %d 個。2個のはず。' % html.count('WILDIMG_V2'))
if html.count('WILDIMG_V1') != 2:
    die('WILDIMG_V1 の印が %d 個。2個のはず（残すこと）。' % html.count('WILDIMG_V1'))
if html.count("getAttribute('data-sp-key')") != 2:
    die('見張りが %d 個。2個のはず。' % html.count("getAttribute('data-sp-key')"))
if html.count('monSpriteHtml(myMon.id, myMon.sprite)') != 1:
    die('自分がわの呼び出しが1件ではありません。')
if html.count('monSpriteHtml(enemyMon.id, enemyMon.sprite)') != 1:
    die('相手がわの呼び出しが1件ではありません。')
for label, s in [('自分がわ', "document.getElementById('playerSpriteDisplay').innerText = myMon.sprite;"),
                 ('相手がわ', "document.getElementById('enemySpriteDisplay').innerText = enemyMon.sprite;")]:
    if html.count(s) != 1:
        die('落ち先（%s）が1件ではありません。' % label)
if html.count('shiny-ring') != ring0 or html.count('monShinyClass') != cls0 or html.count('monShinySet') != set0:
    die('色違いの数が変わりました。')
for s in ['float-dynamic', 'attacking-enemy', 'showWildBattleParticles', 'scaleX(-1)']:
    if s not in html:
        die('演出「%s」が消えました。' % s)
if html.count('\r') != cr0:
    die('改行(CR)が変わりました。')
if html.count('\n') != lf0 + 14:
    die('改行(LF)が %d -> %d。足すのは14本のはず。' % (lf0, html.count('\n')))

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)
print('public/index.html: LF %d -> %d / 金リング %d / 色違いクラス %d'
      % (lf0, html.count('\n'), html.count('shiny-ring'), html.count('monShinyClass')))

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')
print('OK: 野生バトルの点滅を直した。絵文字には戻していない。')
