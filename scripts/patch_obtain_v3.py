#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 第12便: 923 コハヤ の入手方法を はっきりさせる
#
# 第9便では「小数の修行をやりこむと出会える」と ぼかしておいた。
# このキャラの desc にだけ「50問連続」と書いていなかったので、
# 数字を断定しなかったため。
#
# そのあと 実際の処理を見つけた（public/index.html）:
#
#   // === 隠しキャラ（小数×÷ 50問連続正解で仲間になる）===
#   const SECRET_DECIMAL_MONSTER_ID = 923;
#
#   if ((trainingMode === 'decimal' || trainingMode === 'decimal-muldiv')
#       && trainingCombo === 50) {
#     unlockDecimalSecretMonsterIfNeeded();
#   }
#
# ほかの12体と まったく同じ しくみ（trainingCombo === 50）だった。
# 単元は「小数×÷」。コメントと処理の両方が一致している。
#
# 表示だけを直す。ゲームのルールには一切さわらない。
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 158 であること
#   - あて先が ちょうど1行 であること
#   - 直したあとの文が ちょうど1つ であること
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 158

OLD = "if (id===923) return '小数の修行をやりこむと出会える（かくしキャラ）';"
NEW = "if (id===923) return '小数×÷を50問連続で正解する（かくしキャラ）';"


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

if NEW in html:
    die('すでに直っている。二重に入れない。')
if html.count(OLD) != 1:
    die('あて先が ' + str(html.count(OLD)) + ' 個。1個のはず。')

# 裏づけが本当にこのファイルにあることを ここでも確かめる
if 'SECRET_DECIMAL_MONSTER_ID = 923' not in html:
    die('SECRET_DECIMAL_MONSTER_ID = 923 が見つからない')
if 'unlockDecimalSecretMonsterIfNeeded' not in html:
    die('unlockDecimalSecretMonsterIfNeeded が見つからない')
if 'trainingCombo === 50' not in html:
    die('trainingCombo === 50 が見つからない')
print('裏づけ（923の定義・解放関数・50問連続の判定）を確認')

html = html.replace(OLD, NEW, 1)

if html.count(NEW) != 1:
    die('直したあとの文が ' + str(html.count(NEW)) + ' 個。1個のはず。')
for mk, n in [('MON_IMG_V1', 2), ('MON_IMG_V2', 1), ('MON_IMG_V3', 1),
              ('MON_DEX_V1', 5), ('MON_DEX_V2', 1), ('MON_OBT_V1', 1),
              ('MON_OBT_V2', 1), ('MON_BREAD_EVO_V1', 1)]:
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
print('OK: 923 コハヤ の入手方法を はっきりさせた。')
