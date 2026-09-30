#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# キャラの絵 第5便: 絵が「読めなかったとき」だけ、その場で絵文字に戻す。
#
# なぜ必要か（2026-09-30 に実際に起きたこと）:
#   list.js に書いてあるのに PNG が無い id が70件あり、図鑑で70体が真っ白になった。
#   この直しが入っていれば、その70体は自動で絵文字に戻り、誰も困らなかった。
#   通信が途切れて1枚だけ落ちたときにも効く。
#
# だいじな点:
#   使うのは onerror。これは「読み込みに失敗したとき」だけ呼ばれる。
#   まだ読み込み中のあいだは呼ばれないので、
#   「一瞬 絵文字が出て あとから絵に変わる」チラつきは起きない。
#
#   失敗した id は一覧から外すので、同じ画面のほかの場所でも
#   もう読みに行かない（5.7MBの空振りを繰り返さない）。
#
# 触るのは public/index.html の monSpriteHtml だけ。表示箇所は一切さわらない。
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 158 であること
#   - MON_IMG_V2（第4便の直し）が入っていること
#   - MON_IMG_V3 が まだ入っていないこと
#   - あて先が ちょうど1件 であること
#   - 第2便の印(MON_DEX_V1)が5個のままであること
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 158

OLD = r"""  window.monSpriteHtml = function(id, sprite, extraClass){
    var u = url(id);
    if (!u) return esc(sprite);
    return '<img src="' + u + '" alt="' + esc(sprite) + '" class="mon-img ' + esc(extraClass || '') + '" loading="lazy" decoding="async" draggable="false">';
  };"""

NEW = r"""  /* MON_IMG_V3 読み込みに失敗したときだけ、その場で絵文字に戻す */
  window.monSpriteHtml = function(id, sprite, extraClass){
    var u = url(id);
    if (!u) return esc(sprite);
    return '<img src="' + u + '" alt="' + esc(sprite) + '" class="mon-img ' + esc(extraClass || '') + '" loading="lazy" decoding="async" draggable="false"'
      + ' data-mon-id="' + Number(id) + '" data-mon-emoji="' + esc(sprite) + '" onerror="monImgFail(this)">';
  };
  window.monImgFail = function(el){
    try {
      var n = Number(el.getAttribute('data-mon-id'));
      if (n > 0) { delete IDS[n]; }
      var sp = document.createElement('span');
      var cls = String(el.className || '').split('mon-img').join('').replace(/\s+/g, ' ').trim();
      if (cls) { sp.className = cls; }
      sp.textContent = el.getAttribute('data-mon-emoji') || '';
      if (el.parentNode) { el.parentNode.replaceChild(sp, el); }
    } catch (e) {}
  };"""


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

if 'MON_IMG_V2' not in html:
    die('第4便の直し(MON_IMG_V2)が入っていない')
if 'MON_IMG_V3' in html:
    die('MON_IMG_V3 がすでに入っている。二重に入れない。')

n = html.count(OLD)
if n != 1:
    die('あて先が ' + str(n) + ' 件。1件のはず。')

before_len = len(html)
html = html.replace(OLD, NEW, 1)

if html.count('MON_IMG_V3') != 1:
    die('入れた印が ' + str(html.count('MON_IMG_V3')) + ' 個。1個のはず。')
if html.count('MON_DEX_V1') != 5:
    die('第2便の印が ' + str(html.count('MON_DEX_V1')) + ' 個。5個のはず。')
if html.count('monImgFail') != 2:
    die('monImgFail が ' + str(html.count('monImgFail')) + ' 個。2個のはず。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)

print('public/index.html: ' + str(before_len) + ' -> ' + str(len(html)) + ' 文字')

with open(SRC, encoding='utf-8', newline='') as f:
    src_after = f.read()
if src_after != src_before:
    die('src/index.tsx が変わってしまった')

print('src/index.tsx は無変更。チェーン ' + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: 読み込みに失敗したときだけ 絵文字に戻るようにした。')
