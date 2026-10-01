#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 第11便: 防衛戦8体と世界編10体の「入手方法」を直す
#
# いまは18体とも「野生バトル（モンスタボールで捕まえる）」と出ている。
# どちらも サーバ（src/index.tsx）が配っているので、
# クライアント側に表が無く、既定の文に落ちていた。
#
# 裏取り（2つの出どころが一致していることを確認ずみ）:
#   防衛戦 src/index.tsx の DEFSTAGE_BONUS_MONSTERS
#          ステージ 3→1601 / 5→1602 / 7→1604 / 10→1605
#                  12→1611 / 15→1612 / 18→1613 / 21→1614
#          public/defstage_monsters.js と public/defboss_monsters.js の
#          先頭コメントにも同じステージ番号が書いてある。
#          クラスが はじめてクリアしたとき、在籍する全員に1体ずつ。
#   世界編 src/index.tsx の WORLD_STAGE_REWARDS
#          public/index.html の window.WORLD_REWARD_BY_STAGE と同じ表。
#
# 書き方:
#   防衛戦 1601/1602/1604/1605 は desc に【防衛戦 ステージN クリア げんてい】が
#          あるので、そこから番号を切り出す（写し間違いが起きない）。
#          1611〜1614 は desc に番号が無いので、確認した 12/15/18/21 を使う。
#   世界編 画面の表（WORLD_REWARD_BY_STAGE と WORLD_STAGES）をその場で引く。
#          表が変わっても文が自動でついてくる。
#          ステージの呼び名は 画面と同じ「国旗＋都市名」にそろえる
#          （例: 🇮🇳 デリー）。worldStageLabel() が同じ作り。
#
# 表示だけを直す。配る処理やゲームのルールには一切さわらない。
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 158 であること
#   - 第9便の印(MON_OBT_V1)が1個 入っていること
#   - MON_OBT_V2 が まだ入っていないこと
#   - 入れる場所（323の行）が ちょうど1行 であること
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 158
MARK = 'MON_OBT_V2'
ANCHOR = "if (id===323) return '野生バトルに勝ったあと、まれに出る「あやしいスイーツショップ」で手に入る';"

BLOCK = [
    "            /* MON_OBT_V2 防衛戦・世界編（どちらもサーバが配るので、ここで文を作る） */",
    "            if (id>=1601 && id<=1614) {",
    "              var _dfm = String(m.desc||'').match(/防衛戦\\s*ステージ\\s*(\\d+)/);",
    "              var _dfs = _dfm ? _dfm[1] : ({1611:'12',1612:'15',1613:'18',1614:'21'})[id];",
    "              if (_dfs) return '防衛戦のステージ' + _dfs + 'を クラスが はじめてクリアすると、クラス全員がもらえる';",
    "            }",
    "            if (id>=2101 && id<=2199) {",
    "              var _wr = (typeof window!=='undefined' && window.WORLD_REWARD_BY_STAGE) ? window.WORLD_REWARD_BY_STAGE : null;",
    "              var _wss = (typeof window!=='undefined' && window.WORLD_STAGES) ? window.WORLD_STAGES : null;",
    "              if (_wr) {",
    "                for (var _wk in _wr) {",
    "                  if (Number(_wr[_wk]) === id) {",
    "                    var _w1 = _wss ? _wss[Number(_wk)] : null;",
    "                    if (_w1 && _w1.city) return '世界編の「' + _w1.flag + ' ' + _w1.city + '」をクリアするともらえる';",
    "                    return '世界編のステージをクリアするともらえる';",
    "                  }",
    "                }",
    "              }",
    "            }",
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

if html.count('MON_OBT_V1') != 1:
    die('第9便の印(MON_OBT_V1)が ' + str(html.count('MON_OBT_V1')) + ' 個。1個のはず。')
if MARK in html:
    die(MARK + ' がすでに入っている。二重に入れない。')

lines = html.split(chr(10))
hit = [k for k, l in enumerate(lines) if ANCHOR in l]
if len(hit) != 1:
    die('入れる場所が ' + str(len(hit)) + ' 行。1行のはず。')
k = hit[0]
lines[k + 1:k + 1] = BLOCK
print('防衛戦・世界編の説明を入れた: ' + str(len(BLOCK)) + ' 行')

html = chr(10).join(lines)

if html.count(MARK) != 1:
    die('入れた印が ' + str(html.count(MARK)) + ' 個。1個のはず。')
for mk, n in [('MON_IMG_V1', 2), ('MON_IMG_V2', 1), ('MON_IMG_V3', 1),
              ('MON_DEX_V1', 5), ('MON_DEX_V2', 1), ('MON_OBT_V1', 1),
              ('MON_BREAD_EVO_V1', 1)]:
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
print('OK: 防衛戦・世界編の入手方法を直した。')
