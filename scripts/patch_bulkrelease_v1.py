#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ボックスに「まとめて にがす」を足す
#
# 中身は scripts/bulkrelease_v1.js。これを <script> で </body> の前に足すだけ。
# 既存の1体ずつの「にがす」には 一切さわらない。
# にがす処理そのものも 既存の releaseBoxMonster をそのまま呼ぶ（作り直さない）。
#
# 守るもの（チェックを出さない）: パーティ・つかっている子・その種類のさいごの1体
# ★がついている子は えらべる（確認画面で「★が◯体」と知らせる）
# コインなどは 出さない（いまと同じ）
# 1回に にがせるのは 20体まで。「ぜんぶえらぶ」は 入れない
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 167 であること
#   - scripts/bulkrelease_v1.js があって BULKRELEASE_V1 の印が入っていること
#   - その中に </script> が 入っていないこと
#   - public/index.html に </body> が ちょうど1件 であること
#   - BULKRELEASE_V1 が まだ入っていないこと
#   - 入れたあと 増えた文字数が 入れた分と ぴったり同じであること
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
JS = 'scripts/bulkrelease_v1.js'
CHAIN_BEFORE = 167
ANCHOR = '</body>'


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

try:
    with open(JS, encoding='utf-8', newline='') as f:
        js = f.read()
except IOError:
    die(JS + ' が無い')

if 'BULKRELEASE_V1' not in js:
    die(JS + ' に BULKRELEASE_V1 の印が無い')
if '</script' in js.lower():
    die(JS + ' に </script> が入っている。そのままでは埋められない。')
if len(js) < 3000:
    die(JS + ' が ' + str(len(js)) + ' 文字。短すぎる。')

BLOCK = '\n<script>\n' + js + '\n</script>\n'

with open(PUB, encoding='utf-8', newline='') as f:
    html = f.read()

before_len = len(html)

if 'BULKRELEASE_V1' in html:
    die('BULKRELEASE_V1 がすでに入っている。二重に入れない。')

n = html.count(ANCHOR)
if n != 1:
    die('あて先 </body> が ' + str(n) + ' 件。1件のはず。')

html = html.replace(ANCHOR, BLOCK + ANCHOR, 1)

if html.count('BULKRELEASE_V1') != 1:
    die('入れた印が ' + str(html.count('BULKRELEASE_V1')) + ' 個。1個のはず。')
if html.count(ANCHOR) != 1:
    die('</body> が増えてしまった')
if len(html) - before_len != len(BLOCK):
    die('増えた文字数が ' + str(len(html) - before_len)
        + '。' + str(len(BLOCK)) + ' のはず。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)

print('public/index.html: ' + str(before_len) + ' -> ' + str(len(html)) + ' 文字')

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')

print('src/index.tsx は無変更。チェーン '
      + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: ボックスに「まとめて にがす」を足した。1体ずつの にがす はそのまま。')
