#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 第10便: パンの3体を 本物の進化にする
#
#   300 コパン → 301 クロワッサン → 302 キングパン
#
# いままで 3体とも nextId も evoLevel も無く、図鑑では進化のように
# 3体ならんで出るのに、301 と 302 には たどり着けなかった。
#
# お手本は スイーツの 323→324→325。実際のコードを読んで同じ形にそろえる。
#   323 ケケーキ   : evoLevel: 18,   nextId: 324,  stage: 1
#   324 ドドーナツ : evoLevel: 33,   nextId: 325,  stage: 2
#   325 プリリン   : evoLevel: null, nextId: null, stage: 3
#
# 直したあと:
#   300 コパン       : evoLevel: 18,   nextId: 301,  stage: 1
#   301 クロワッサン : evoLevel: 33,   nextId: 302,  stage: 2
#   302 キングパン   : evoLevel: null, nextId: null, stage: 3
#
# つよさは もともと 300 < 301 < 302 の順で、逆転は無い（確認ずみ）。
#   300: HP60  こうげき12 まもり10 すばやさ10
#   301: HP130 こうげき30 まもり25 すばやさ25
#   302: HP300 こうげき70 まもり60 すばやさ60
#
# いま持っている子（D1で確認ずみ・2026-10-01）:
#   児童A クロワッサンLv6 / キングパンLv100   → Lv6 < 33 なので進化しない
#   児童B コパンLv1                          → Lv1 < 18 なので進化しない
#   先生の管理用 300/301/302 すべてLv1        → 進化しない
#   つまり この変更で いきなり進化してしまう子は いない。
#
# 入手方法の文は さわらない。301/302 は もともと入っている
# 「進化かどうかを見る処理」が 自動で『進化（コパンがLv18で進化）』に変える。
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 158 であること
#   - 300/301/302 の行が それぞれ ちょうど1行 であること
#   - その3行が いまの形（evoLevel: null, nextId: null, stage: 1,）であること
#   - スイーツ 323/324/325 の行が 変わらないこと
#   - MON_BREAD_EVO_V1 が まだ入っていないこと
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 158
MARK = 'MON_BREAD_EVO_V1'

NOW = 'evoLevel: null, nextId: null, stage: 1,'
PLAN = [
    (300, 'コパン', 'evoLevel: 18, nextId: 301, stage: 1,'),
    (301, 'クロワッサン', 'evoLevel: 33, nextId: 302, stage: 2,'),
    (302, 'キングパン', 'evoLevel: null, nextId: null, stage: 3,'),
]
SWEETS = [
    (323, 'evoLevel: 18, nextId: 324, stage: 1,'),
    (324, 'evoLevel: 33, nextId: 325, stage: 2,'),
    (325, 'evoLevel: null, nextId: null, stage: 3,'),
]


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

if MARK in html:
    die(MARK + ' がすでに入っている。二重に入れない。')

lines = html.split(chr(10))


def find_line(mid, name):
    key = "id: " + str(mid) + ", name: '" + name + "'"
    hit = [k for k, l in enumerate(lines) if key in l]
    if len(hit) != 1:
        die(str(mid) + ' ' + name + ' の行が ' + str(len(hit)) + ' 行。1行のはず。')
    return hit[0]


# お手本（スイーツ）が想定どおりか先に確かめる
sweets_names = {323: 'ケケーキ', 324: 'ドドーナツ', 325: 'プリリン'}
sweets_before = {}
for mid, expect in SWEETS:
    k = find_line(mid, sweets_names[mid])
    if expect not in lines[k]:
        die('お手本 ' + str(mid) + ' が想定とちがう。期待: ' + expect)
    sweets_before[mid] = lines[k]
print('お手本（スイーツ 323/324/325）の形を確認')

for mid, name, new in PLAN:
    k = find_line(mid, name)
    if lines[k].count(NOW) != 1:
        die(str(mid) + ' ' + name + ' の行が いまの形ではない。期待: ' + NOW)
    lines[k] = lines[k].replace(NOW, new, 1)
    print(str(mid) + ' ' + name + ' → ' + new)

# スイーツが変わっていないこと
for mid, expect in SWEETS:
    k = find_line(mid, sweets_names[mid])
    if lines[k] != sweets_before[mid]:
        die('お手本のスイーツ ' + str(mid) + ' が変わってしまった')
print('スイーツ 323/324/325 は無変更')

# 入れた印（コメント）を パンの定義の直前に置く
k300 = find_line(300, 'コパン')
lines.insert(k300 - 1, '        /* ' + MARK + ' パンの3体を本物の進化にした（323/324/325と同じ形）。表示ではなくデータの修正。 */')

html = chr(10).join(lines)

if html.count(MARK) != 1:
    die('入れた印が ' + str(html.count(MARK)) + ' 個。1個のはず。')
for mk, n in [('MON_IMG_V1', 2), ('MON_IMG_V2', 1), ('MON_IMG_V3', 1),
              ('MON_DEX_V1', 5), ('MON_DEX_V2', 1), ('MON_OBT_V1', 1)]:
    if html.count(mk) != n:
        die('これまでの印 ' + mk + ' が ' + str(html.count(mk)) + ' 個。' + str(n) + ' 個のはず。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)
print('public/index.html を書きかえた')

with open(SRC, encoding='utf-8', newline='') as f:
    src_after = f.read()
if src_after != src_before:
    die('src/index.tsx が変わってしまった')

print('src/index.tsx は無変更。チェーン ' + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: パンの3体を進化でつないだ。')
