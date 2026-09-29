#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# キャラの絵 第1便: 受け皿だけを作る。表示している場所は1か所も変えない。
#
# public/index.html の head に、次の3つを足すだけ。
#   1. <script src="/mon/list.js">  絵が用意できている id の一覧
#   2. MON_IMG_V1 の道具   絵があれば img、無ければ今までの絵文字を返す関数
#   3. MON_IMG_V1 の見た目 画像の大きさと、影を drop-shadow でつけるクラス
#
# どこからも呼んでいないので、これを入れても画面は1ミリも変わらない。
# 表示箇所の差し替えは第2便（図鑑だけ）から、場所ごとに分けて行う。
#
# 守り（どれか1つでも合わなければ、何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 158 であること
#   - public/index.html に あて先 が ちょうど1件 あること
#   - MON_IMG_V1 が まだ入っていないこと
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 158
ANCHOR = b'/* GLOBAL_MONSTERS */'
CLOSE = b'</script>'
MARK = b'MON_IMG_V1'

BLOCK = r'''
<script src="/mon/list.js"></script>
<script>/* MON_IMG_V1 キャラの絵の受け皿。絵があれば絵、無ければ絵文字。 */
(function(){
  var IDS = (window.MON_IMG_IDS && typeof window.MON_IMG_IDS === 'object') ? window.MON_IMG_IDS : {};
  function has(id){ var n = Number(id); return !!(n && IDS[n]); }
  function url(id){ return has(id) ? ('/mon/' + Number(id) + '.png') : null; }
  function esc(s){
    return String(s == null ? '' : s)
      .split('&').join('&amp;')
      .split('<').join('&lt;')
      .split('>').join('&gt;')
      .split('"').join('&quot;')
      .split("'").join('&#39;');
  }
  window.monHasImg = has;
  window.monImgUrl = url;
  window.monEsc = esc;
  /* HTMLに埋めるとき用。絵が無ければ、今までの絵文字をそのまま返す。 */
  window.monSpriteHtml = function(id, sprite, extraClass){
    var u = url(id);
    if (!u) return esc(sprite);
    return '<img src="' + u + '" alt="' + esc(sprite) + '" class="mon-img ' + esc(extraClass || '') + '" loading="lazy" decoding="async" draggable="false">';
  };
  /* canvas に描くとき用。まだ読めていなければ null（そのときは絵文字を描く）。 */
  var cache = {};
  window.monImgFor = function(id){
    var u = url(id);
    if (!u) return null;
    var n = Number(id);
    var im = cache[n];
    if (im === undefined) {
      im = new Image();
      im.decoding = 'async';
      im.onerror = function(){ cache[n] = null; };
      im.src = u;
      cache[n] = im;
      return null;
    }
    if (!im) return null;
    return (im.complete && im.naturalWidth > 0) ? im : null;
  };
  window.MON_IMG_READY = true;
})();
</script>
<style>/* MON_IMG_V1 */
.mon-img{ display:inline-block; width:1em; height:1em; object-fit:contain; vertical-align:-0.15em; }
.mon-img-shadow{ filter: drop-shadow(0 1px 2px rgba(0,0,0,0.45)); }
</style>
'''


def die(msg):
    print('### 中止: ' + msg)
    sys.exit(1)


with open(SRC, encoding='utf-8') as f:
    src_before = f.read()

a = src_before.find("app.get('/',")
b = src_before.find("app.get('/logout'")
if a < 0:
    die('src/index.tsx に 児童ページの入口が見つからない')
if b < 0 or b <= a:
    die('src/index.tsx に logout の入口が見つからない')

chain = src_before.count('.replace(', a, b)
if chain != CHAIN_BEFORE:
    die('チェーン数が ' + str(chain) + ' 件。' + str(CHAIN_BEFORE) + ' 件のはず。')
print('チェーン数 ' + str(chain) + ' 件を確認')

with open(PUB, 'rb') as f:
    data = f.read()

if data.count(MARK) != 0:
    die('MON_IMG_V1 がすでに入っている。二重に入れない。')

n_anchor = data.count(ANCHOR)
if n_anchor != 1:
    die('あて先が ' + str(n_anchor) + ' 件。1件のはず。')

i = data.find(ANCHOR)
j = data.find(CLOSE, i)
if j < 0:
    die('あて先のあとに script の終わりが無い')
if j - i > 300:
    die('あて先と script の終わりが ' + str(j - i) + ' 文字はなれている。想定外。')
j = j + len(CLOSE)

out = data[:j] + BLOCK.encode('utf-8') + data[j:]

with open(PUB, 'wb') as f:
    f.write(out)

print('public/index.html に受け皿を足した: ' + str(len(data)) + ' -> ' + str(len(out)) + ' バイト')

with open(SRC, encoding='utf-8') as f:
    src_after = f.read()
if src_after != src_before:
    die('src/index.tsx が変わってしまった')

print('src/index.tsx は無変更。チェーン ' + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: 受け皿だけ入れた。どこからも呼んでいないので、見た目は変わらない。')
