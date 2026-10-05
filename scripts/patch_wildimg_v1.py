#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WILDIMG_V1  野生バトルのキャラを、絵文字からキャラ画像に差し替える。

  図鑑とガチャ結果で動いている monSpriteHtml を呼ぶだけ。新しい仕組みは作らない。

  触るのは public/index.html の2か所だけ（どちらもバトル画面の描画）:
    1. 自分がわ  #playerSpriteDisplay  （.player-sprite = 35px / 高さ600px以上で45px）
    2. 相手がわ  #enemySpriteDisplay   （.enemy-sprite  = 40px / 高さ600px以上で50px）

  色違いを壊さないための大事なところ:
    ・色違いは monShinySet(el, id, on) が「入れ物の div」に shiny-mon と svN を付ける
      やり方なので、中身を img にしても CSS の filter はそのまま効く。
    ・差し替えるのは innerText を入れる行だけ。そのすぐ下の色違いの try は
      1文字も触らない。順番も変えない（先に中身 → あとからクラス）。
    ・差し替えたあとに色違いの呼び出しが8件残っていることを数えて確かめる。

  演出を壊さないための大事なところ:
    ・ふわふわ浮く float-dynamic、被弾の damaged、攻撃の attacking-enemy、
      showAttackerMotion の transform、ボール投げの visibility は、
      どれも「入れ物の div」に効くので中身が img になっても残る。
    ・showWildBattleParticles は自前の絵文字の表を持っていて、
      スプライトの文字を読んでいない。だから img にしても粒は出る。
    ・.player-sprite の transform: scaleX(-1)（左右反転）も入れ物に効く。
      絵文字と同じように、画像も反転して向かい合う。

  自動でついてくるもの（monSpriteHtml の中）:
    ・loading="lazy" / decoding="async"
    ・画像が無いときに絵文字へ落ちる onerror="monImgFail(this)"
    ・list.js に id が無ければ img を作らず絵文字をそのまま返す

  ⚠️ src/index.tsx は1バイトも触らない。チェーン数は「増えていないこと」の確認だけ。
  ⚠️ public/index.html は手で編集しない。このスクリプト経由のみ。
  ⚠️ 改行は newline='' で読み書きして今あるものをそのまま保つ。
"""
import os
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'


def die(msg):
    print('::error::' + msg)
    sys.exit(1)


def chain_count(text):
    a = text.index("app.get('/'")
    b = text.index("app.get('/logout'")
    return text[a:b].count('.replace(')


# ---------------------------------------------------------------- 0. 事前確認
with open(SRC, encoding='utf-8', newline='') as f:
    src_before = f.read()

want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want:
    die('CHAIN_BEFORE が渡されていません。1バイトも書かずに止めました。')
now = chain_count(src_before)
if str(now) != want:
    die('チェーン数が合いません。実測 %d 件 / 指定 %s 件。'
        '他の便が流れた可能性があります。1バイトも書かずに止めました。' % (now, want))
print('チェーン数 %d 件を確認。' % now)

with open(PUB, encoding='utf-8', newline='') as f:
    html = f.read()

cr_before = html.count('\r')
lf_before = html.count('\n')

if 'MON_IMG_V1' not in html:
    die('受け皿（MON_IMG_V1）が入っていません。')
if 'window.monSpriteHtml' not in html:
    die('monSpriteHtml の定義が見あたりません。')
if 'WILDIMG_V1' in html:
    die('WILDIMG_V1 がすでに入っています。二重には入れません。')

shiny_before = html.count('monShinySet')
if shiny_before < 8:
    die('色違いの呼び出しが %d 件しかありません。先に色違いの便を確かめること。' % shiny_before)
if '.shiny-mon.sv1' not in html:
    die('色違いの色（.shiny-mon.sv1）が入っていません。')
ring_before = html.count('shiny-ring')
print('色違い: 呼び出し %d 件 / shiny-ring %d 件' % (shiny_before, ring_before))


def swap(indent, el_id, var):
    """innerText の1行を、絵があれば絵・無ければ絵文字に差し替える組を作る。"""
    i = ' ' * indent
    old = (i + "document.getElementById('" + el_id + "').innerText = " + var + ".sprite;\n")
    new = (
        i + "/* WILDIMG_V1 野生バトル" + ('・自分' if var == 'myMon' else '・相手')
        + ": 絵があれば絵、無ければ絵文字（色違いのクラスはこのすぐ下で付けます） */\n"
        + i + "try {\n"
        + i + "    document.getElementById('" + el_id + "').innerHTML = "
        + "(typeof monSpriteHtml === 'function') ? monSpriteHtml(" + var + ".id, " + var + ".sprite) "
        + ": String(" + var + ".sprite == null ? '' : " + var + ".sprite);\n"
        + i + "} catch (e) {\n"
        + i + "    document.getElementById('" + el_id + "').innerText = " + var + ".sprite;\n"
        + i + "}\n"
    )
    return old, new


PAIRS = [
    swap(12, 'playerSpriteDisplay', 'myMon') + ('自分がわ',),
    swap(16, 'enemySpriteDisplay', 'enemyMon') + ('相手がわ',),
]

for old, new, label in PAIRS:
    n = html.count(old)
    if n != 1:
        die('あて先「%s」が %d 件。1件のはず。1バイトも書かずに止めました。' % (label, n))

# ---------------------------------------------------------------- 1. 差し替え
before_len = len(html)
for old, new, label in PAIRS:
    html = html.replace(old, new, 1)
    print('差し替えた: ' + label)

# ---------------------------------------------------------------- 2. あと確認
if html.count('WILDIMG_V1') != 2:
    die('入れた印が %d 個。2個のはず。' % html.count('WILDIMG_V1'))
if html.count('monSpriteHtml(myMon.id, myMon.sprite)') != 1:
    die('自分がわの呼び出しが入っていません。')
if html.count('monSpriteHtml(enemyMon.id, enemyMon.sprite)') != 1:
    die('相手がわの呼び出しが入っていません。')
if html.count('monShinySet') != shiny_before:
    die('色違いの呼び出しが %d -> %d に変わりました。' % (shiny_before, html.count('monShinySet')))
if html.count('shiny-ring') != ring_before:
    die('色違いの金リング（shiny-ring）が %d -> %d に変わりました。' % (ring_before, html.count('shiny-ring')))
if '.shiny-mon.sv1' not in html:
    die('色違いの色（.shiny-mon.sv1）が消えました。')
for s in ['float-dynamic', 'attacking-enemy', 'showWildBattleParticles', 'showAttackerMotion',
          'scaleX(-1)']:
    if s not in html:
        die('演出「%s」が消えました。' % s)
if html.count('\r') != cr_before:
    die('改行(CR)の数が %d -> %d に変わりました。' % (cr_before, html.count('\r')))
if html.count('\n') != lf_before + 10:
    die('改行(LF)の数が %d -> %d。足すのは10本のはず。' % (lf_before, html.count('\n')))

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)

print('public/index.html: %d -> %d 文字（CR %d / LF %d -> %d）'
      % (before_len, len(html), html.count('\r'), lf_before, html.count('\n')))

with open(SRC, encoding='utf-8', newline='') as f:
    src_after = f.read()
if src_after != src_before:
    die('src/index.tsx が変わってしまった')
print('src/index.tsx は無変更。チェーン %d -> %d' % (now, chain_count(src_after)))
print('OK: 野生バトルだけ差し替えた。色違いのクラスも演出もそのまま。')
