#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GACHAIMG_V1  ガチャの結果画面のキャラを、絵文字からキャラ画像に差し替える。

  図鑑ですでに動いている仕組み（monSpriteHtml）をそのまま呼ぶだけ。新しくは作らない。

  触るのは public/index.html の2か所だけ:
    1. 1連の結果     #gachaResultSprite （親が text-8xl ＝ 96x96 で出る）
    2. 10連のまとめ  カードの絵         （親が text-4xl ＝ 36x36 で出る）

  触らないもの:
    ・秘伝の書（result.type === 'hiden'）とアイテム（result.type === 'item'）は
      キャラではないので絵文字のまま。残っていることを後で数えて確かめる。
    ・src/index.tsx は1バイトも触らない。チェーン数は「増えていないこと」の確認だけに使う。
    ・CSS も足さない。.mon-img{width:1em;height:1em} なので親の文字サイズで自動的に決まる。

  自動でついてくるもの（monSpriteHtml の中にある）:
    ・loading="lazy" / decoding="async"
    ・画像が無いときに絵文字へ落ちる onerror="monImgFail(this)"
    ・list.js に id が無ければ、そもそも img を作らず絵文字をそのまま返す

  演出:
    ・出現アニメ（animate-pop-count）とレア演出（drop-shadow）は親の要素のクラスなので、
      中身を img にしても残る。
    ・色違い（shiny-mon）はこの関数の中には出てこない（図鑑の詳細と戦闘側だけ）。
      shiny-mon は親に付ける filter なので、img になっても効く。

  改行:
    ・実測で LF のみ（CR=0 / LF=55531）。newline='' で読み書きして今ある改行をそのまま保つ。
    ・差し替えは行の中身だけで、改行を新しく作らない。

  書き方のきまり（9/26 に教師画面を2時間落とした件をくりかえさないため）:
    ・monSpriteHtml が返す HTML は二重引用符しか使わない。テンプレートリテラルの中に
      置いてもエスケープが1段落ちない。シングルクォートを入れないこと。
"""
import os
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'

Q = '❓'   # ❓ 10連のまとめで data が無いときの既定
SCROLL = '\U0001F4DC'   # 📜 秘伝の書


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
    die('受け皿（MON_IMG_V1）が入っていません。先に絵の便を流すこと。')
if 'MON_DEX_V1' not in html:
    die('図鑑の便（MON_DEX_V1）が入っていません。先に図鑑の便を流すこと。')
if 'GACHAIMG_V1' in html:
    die('GACHAIMG_V1 がすでに入っています。二重には入れません。')
if 'window.monSpriteHtml' not in html:
    die('monSpriteHtml の定義が見あたりません。')

# ---------------------------------------------------------------- 1. 差し替える組
PAIRS = []

# 1. 1連の結果（親が text-8xl ＝ 96x96）
PAIRS.append((
    "                const monster = result.data;\n"
    "                document.getElementById('gachaResultSprite').innerText = monster.sprite;\n",

    "                const monster = result.data;\n"
    "                /* GACHAIMG_V1 1連の結果: 絵があれば絵、無ければ絵文字 */\n"
    "                try {\n"
    "                    document.getElementById('gachaResultSprite').innerHTML = "
    "(typeof monSpriteHtml === 'function') ? monSpriteHtml(monster.id, monster.sprite) "
    ": String(monster.sprite == null ? '' : monster.sprite);\n"
    "                } catch (e) {\n"
    "                    document.getElementById('gachaResultSprite').innerText = monster.sprite;\n"
    "                }\n",

    '1連の結果',
))

# 2. 10連のまとめ（親が text-4xl ＝ 36x36）
#    sprite にそのまま HTML を入れる。入れ物（summary）の形は変えない。
#    同じキャラの重ねあわせは key（名前＋Lv）でやっているので、ここを変えても数は狂わない。
PAIRS.append((
    "                        sprite = r.data.sprite || '" + Q + "';\n",

    "                        /* GACHAIMG_V1 10連のまとめ: 絵があれば絵、無ければ絵文字 */\n"
    "                        sprite = ((typeof monSpriteHtml === 'function') "
    "? monSpriteHtml(r.data.id, (r.data.sprite || '" + Q + "')) "
    ": (r.data.sprite || '" + Q + "'));\n",

    '10連のまとめ',
))

for old, new, label in PAIRS:
    n = html.count(old)
    if n != 1:
        die('あて先「%s」が %d 件。1件のはず。1バイトも書かずに止めました。' % (label, n))

# 絵文字のまま残すところ（キャラではない）
KEEP = [
    ("秘伝の書",
     "document.getElementById('gachaResultSprite').innerText = result.sprite || '" + SCROLL + "';"),
    ("アイテム",
     "document.getElementById('gachaResultSprite').innerText = result.sprite;"),
]
for label, s in KEEP:
    n = html.count(s)
    if n != 1:
        die('絵文字のまま残すはずの「%s」が %d 件。1件のはず。' % (label, n))

# ---------------------------------------------------------------- 2. 差し替え
before_len = len(html)
for old, new, label in PAIRS:
    html = html.replace(old, new, 1)
    print('差し替えた: ' + label)

# ---------------------------------------------------------------- 3. あと確認
if html.count('GACHAIMG_V1') != 2:
    die('入れた印が %d 個。2個のはず。' % html.count('GACHAIMG_V1'))
if html.count("monSpriteHtml(monster.id, monster.sprite)") != 1:
    die('1連の呼び出しが入っていません。')
if html.count("monSpriteHtml(r.data.id, (r.data.sprite || '" + Q + "'))") != 1:
    die('10連の呼び出しが入っていません。')
for label, s in KEEP:
    if html.count(s) != 1:
        die('差し替えたあとに「%s」が %d 件になっています。' % (label, html.count(s)))
if html.count('\r') != cr_before:
    die('改行(CR)の数が %d -> %d に変わりました。' % (cr_before, html.count('\r')))
if html.count('\n') != lf_before + 6:
    die('改行(LF)の数が %d -> %d。足すのは6本のはず。' % (lf_before, html.count('\n')))

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)

print('public/index.html: %d -> %d 文字（CR %d / LF %d -> %d）'
      % (before_len, len(html), html.count('\r'), lf_before, html.count('\n')))

with open(SRC, encoding='utf-8', newline='') as f:
    src_after = f.read()
if src_after != src_before:
    die('src/index.tsx が変わってしまった')
print('src/index.tsx は無変更。チェーン %d -> %d' % (now, chain_count(src_after)))
print('OK: ガチャの結果画面だけ差し替えた。絵が1枚も無いうちは 今までどおり絵文字が出る。')
