#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# キャラの絵 第4便: 受け皿の直し。
#
# list.js が 配列 [1,2,3] で来ても 表 {1:1} で来ても
# 正しく読めるようにする。
#
# なぜ必要か（2026-09-30 に本番で見つけた不具合）:
#   第1便の受け皿は IDS[id] という引き方をしていた。
#   list.js が 配列 [1,2,...,144] だと、値は0番目から143番目の箱に入るので、
#   IDS[144] は存在せず id 144（カイザー）だけ絵が出なかった。
#   id 1〜143 が動いていたのは 配列の長さ と idの最大値 が
#   たまたま近かっただけの偶然。
#   次に 101〜488 の配列を渡されると、id 1〜343 を
#   「絵がある」と誤判定して 存在しない画像を読みに行き、
#   図鑑が総崩れになる。
#
# 直したあとは、どちらの形で来ても id の集合に読み替えてから使う。
#
# 触るのは public/index.html の受け皿の2行だけ。表示箇所は一切さわらない。
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 158 であること
#   - MON_IMG_V1（第1便の受け皿）が入っていること
#   - MON_IMG_V2 が まだ入っていないこと
#   - あて先が ちょうど1件 であること
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 158

OLD = (
    "  var IDS = (window.MON_IMG_IDS && typeof window.MON_IMG_IDS === 'object') "
    "? window.MON_IMG_IDS : {};\n"
    "  function has(id){ var n = Number(id); return !!(n && IDS[n]); }"
)

NEW = (
    "  /* MON_IMG_V2 一覧は 配列 [1,2,3] でも 表 {1:1} でも受け取れる */\n"
    "  var RAW = window.MON_IMG_IDS;\n"
    "  var IDS = {};\n"
    "  if (Object.prototype.toString.call(RAW) === '[object Array]') {\n"
    "    for (var _i = 0; _i < RAW.length; _i++) { var _v = Number(RAW[_i]); if (_v > 0) IDS[_v] = 1; }\n"
    "  } else if (RAW && typeof RAW === 'object') {\n"
    "    for (var _k in RAW) {\n"
    "      if (Object.prototype.hasOwnProperty.call(RAW, _k) && RAW[_k]) {\n"
    "        var _n = Number(_k); if (_n > 0) IDS[_n] = 1;\n"
    "      }\n"
    "    }\n"
    "  }\n"
    "  window.MON_IMG_IDS_MAP = IDS;\n"
    "  window.MON_IMG_COUNT = 0; for (var _c in IDS) { window.MON_IMG_COUNT++; }\n"
    "  function has(id){ var n = Number(id); return !!(n && IDS[n]); }"
)


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

if 'MON_IMG_V1' not in html:
    die('第1便の受け皿(MON_IMG_V1)が入っていない')
if 'MON_IMG_V2' in html:
    die('MON_IMG_V2 がすでに入っている。二重に入れない。')

n = html.count(OLD)
if n != 1:
    die('あて先が ' + str(n) + ' 件。1件のはず。')

before_len = len(html)
html = html.replace(OLD, NEW, 1)

if html.count('MON_IMG_V2') != 1:
    die('入れた印が ' + str(html.count('MON_IMG_V2')) + ' 個。1個のはず。')
if html.count('MON_DEX_V1') != 5:
    die('第2便の印が ' + str(html.count('MON_DEX_V1')) + ' 個。5個のはず。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)

print('public/index.html: ' + str(before_len) + ' -> ' + str(len(html)) + ' 文字')

with open(SRC, encoding='utf-8', newline='') as f:
    src_after = f.read()
if src_after != src_before:
    die('src/index.tsx が変わってしまった')

print('src/index.tsx は無変更。チェーン ' + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: 受け皿を直した。配列でも表でも読める。')
