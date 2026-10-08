#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 図鑑で 同じキャラが2回ならぶのを止める（表示だけ・データは1文字も触らない）
#
# No.1003 スッポンキング が2回出ている件。
# 原因は MONSTERS に id 1003 の別データが2件あること（1011 も同じ）。
# データを消すと、児童がすでに持っている 1003/1011 の
# ステータス・属性・技が変わってしまうので、データには触らない。
#
# やること: renderEvoLine を包んで、
#   「同じ並びを 同じ入れ物に 2回出さない」ようにするだけ。
#
# ・入れ物（グリッド）は 描き直すたびに createElement で作り直されるので、
#   印は毎回まっさらから始まる（実測で確認済み）
# ・999 阪神マン は『別々の入れ物』に2回出ている。これは わざとなので残す。
#   同じ入れ物の中だけを見るので 999 には影響しない（実測で確認済み）
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 167 であること
#   - あて先が ちょうど1件 であること
#   - DEXDUP_V1 が まだ入っていないこと（二重に入れない）
#   - 入れたあと DEXDUP_V1 が ちょうど1個 であること
#   - public/index.html の増えた文字数が 入れた分と ぴったり同じであること
#   - MON_IMG_V1 と MON_DEX_V1 が 残っていること
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 167

ANCHOR = 'function renderEvoLine(ids, container) {'

INSERT = """/* DEXDUP_V1 図鑑で同じ並びを同じ入れ物に2回出さない（データは触らない） */
        var __dexOrigEvoLine = renderEvoLine;
        renderEvoLine = function (ids, container) {
            try {
                if (container) {
                    if (!container.childElementCount) container.__dexKeys = null;
                    if (!container.__dexKeys) container.__dexKeys = Object.create(null);
                    var __dexKey = (ids || []).join('-');
                    if (container.__dexKeys[__dexKey]) return;
                    container.__dexKeys[__dexKey] = 1;
                }
            } catch (e) { }
            return __dexOrigEvoLine.apply(this, arguments);
        };

        """


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

before_len = len(html)

if 'MON_IMG_V1' not in html:
    die('MON_IMG_V1 が入っていない')
if 'MON_DEX_V1' not in html:
    die('MON_DEX_V1 が入っていない')
if 'DEXDUP_V1' in html:
    die('DEXDUP_V1 がすでに入っている。二重に入れない。')

n = html.count(ANCHOR)
if n != 1:
    die('あて先が ' + str(n) + ' 件。1件のはず。')

html = html.replace(ANCHOR, INSERT + ANCHOR, 1)

if html.count('DEXDUP_V1') != 1:
    die('入れた印が ' + str(html.count('DEXDUP_V1')) + ' 個。1個のはず。')
if len(html) - before_len != len(INSERT):
    die('増えた文字数が ' + str(len(html) - before_len)
        + '。' + str(len(INSERT)) + ' のはず。')
if html.count(ANCHOR) != 1:
    die('あて先が増えてしまった')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)

print('public/index.html: ' + str(before_len) + ' -> ' + str(len(html)) + ' 文字')

with open(SRC, encoding='utf-8', newline='') as f:
    if f.read() != src_before:
        die('src/index.tsx が変わってしまった')

print('src/index.tsx は無変更。チェーン '
      + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: 図鑑の重複表示だけを止めた。MONSTERS のデータは1文字も触っていない。')
