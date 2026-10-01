#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 図鑑の「入手方法」の まちがいを直す（第9便）
#
# この欄は 子どもが 300コインの「入手のヒントメモ」を使って読む情報。
# そこに事実と違うことが書かれていた。
#
# (A) 夏フェスの説明が 無関係な7体に出ていた
#     夏フェスキャラは 957〜963 から 1501〜1507 へ id を付けかえたのに、
#     この関数の if(id===957)〜if(id===963) の7行だけ古いまま残っていた。
#     → 7行を消す。消すと 957/960/963 は下の新しい説明に、
#        958/959/961/962 は もとからある「進化」の説明に落ちる。
#
# (B) 野生に出ないキャラに「野生バトルで捕まえる」と出ていた
#     → 下の対応表で 正しい説明に差し替える。
#
# すべて 本番のコードで裏を取った（推測で書いた文は1つもない）:
#   50問連続の13体 … 各キャラの desc から単元名を切り出す
#   ラボの19体     … LAB_REVIVE_MONSTER_IDS と一致
#   999 阪神マン    … HANSHINMAN_REVIVE_UNLOCK_REQ（全修行100問以上・正解率90%以上）
#   1501〜1507     … _sf26CheckHidden と _SF26_STAMP_REWARDS の実際の条件
#   300 / 323      … 「謎のパン屋さん」「あやしいスイーツショップ」の画面
#
# 触らないもの（別途 報告ずみ）:
#   防衛戦8体・世界編10体 … 配っているのは src/index.tsx（サーバ側）。別便で直す。
#   301 クロワッサン / 302 キングパン … 入手経路が見つからない。ゲーム側の問題。
#
# 表示だけを直す。出現処理やゲームのルールには一切さわらない。

import re
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 158
MARK = 'MON_OBT_V1'

BLOCK = [
    "          /* MON_OBT_V1 入手方法の直し。図鑑の表示だけで、ゲームのルールは変えない。 */",
    "          try{",
    "            if (id===900||id===910||id===920||id===957||id===960||id===963||id===966||id===969||id===972||id===975||id===1511||id===1514) {",
    "              var _ob1 = String(m.desc||'').match(/^(.+?)を50問連続で正解/);",
    "              if (_ob1) return _ob1[1] + 'を50問連続で正解する（かくしキャラ）';",
    "            }",
    "            if (id===923) return '小数の修行をやりこむと出会える（かくしキャラ）';",
    "            if (id===999) return 'ラボで「かけら」を使って復活させる（すべての修行を100問以上・正解率90%以上で ひらく）';",
    "            if (id===926 || (id>=940 && id<=956)) return 'ラボで「かけら」を使って復活させる（かけらの数＝成功する%）';",
    "            if (id===1301) return '分数の修行で50問連続で正解する';",
    "            if (id===1302) return '分数の修行で70問連続で正解する';",
    "            if (id===1303) return '分数の修行で100問連続で正解する';",
    "            if (id===1501) return '夏フェスのスタンプカードが合計10日たまると仲間になる（夏限定）';",
    "            if (id===1502) return '夏フェスの縁日で合計3回あそぶと仲間になる（夏限定）';",
    "            if (id===1503) return '夏フェスのスタンプが合計6日ぶんたまると仲間になる（夏限定）';",
    "            if (id===1504) return '夏フェスの復習バトルで通算9回勝つと仲間になる（夏限定）';",
    "            if (id===1505) return 'クラスの花火が打ち上がったあと、夏フェス画面を見ると仲間になる（夏限定）';",
    "            if (id===1506) return '夏フェスのくじ引きで大当たりを引くと仲間になる（夏限定）';",
    "            if (id===1507) return '夏フェス期間中に合計300問正解すると仲間になる（夏限定）';",
    "            if (id===300) return '野生バトルに勝ったあと、まれに出る「謎のパン屋さん」から手に入る';",
    "            if (id===323) return '野生バトルに勝ったあと、まれに出る「あやしいスイーツショップ」で手に入る';",
    "          }catch(e){}",
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
    die('MON_OBT_V1 がすでに入っている。二重に入れない。')

if html.count('function getObtainMethod') != 1:
    die('getObtainMethod が ' + str(html.count('function getObtainMethod')) + ' 個。1個のはず。')

i = html.find('function getObtainMethod')
j = html.find(chr(10) + '        }', i)
if j < 0:
    die('getObtainMethod の終わりが見つからない')
j = j + 10
fn = html[i:j]
if 'var ob=(m.obtain' not in fn or 'WILD_AREA_POOLS' not in fn:
    die('取り出した関数の中身が想定とちがう')

lines = fn.split(chr(10))

pat = re.compile(r'^\s*if\(id===(95[789]|96[0-3])\)\s*return\s')
hits = [k for k, l in enumerate(lines) if pat.match(l)]
if len(hits) != 7:
    die('消す対象の行が ' + str(len(hits)) + ' 行。7行のはず。')
if hits != list(range(hits[0], hits[0] + 7)):
    die('消す対象の7行が連続していない')
ids_found = sorted([int(pat.match(lines[k]).group(1)) for k in hits])
if ids_found != [957, 958, 959, 960, 961, 962, 963]:
    die('消す対象の id が想定とちがう: ' + str(ids_found))
del lines[hits[0]:hits[0] + 7]
print('夏フェスの古い7行を消した: ' + str(ids_found))

obs = [k for k, l in enumerate(lines) if 'var ob=(m.obtain' in l]
if len(obs) != 1:
    die('入れる場所が ' + str(len(obs)) + ' か所。1か所のはず。')
k = obs[0]
if lines[k - 1].strip() != '}catch(e){}':
    die('入れる場所の直前が想定とちがう: ' + repr(lines[k - 1]))
lines[k:k] = BLOCK
print('新しい説明を入れた: ' + str(len(BLOCK)) + ' 行')

new_fn = chr(10).join(lines)
html = html[:i] + new_fn + html[j:]

if html.count(MARK) != 1:
    die('入れた印が ' + str(html.count(MARK)) + ' 個。1個のはず。')
for mk, n in [('MON_IMG_V1', 2), ('MON_IMG_V2', 1), ('MON_IMG_V3', 1), ('MON_DEX_V1', 5), ('MON_DEX_V2', 1)]:
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
print('OK: 入手方法の説明を直した。')
