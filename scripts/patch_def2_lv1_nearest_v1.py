# -*- coding: utf-8 -*-
# DEF2LV1NEAR_V1 --- レベル1に「近くの てきを こうげき」を 出す。お手本を 2つ ふやす。
#
# いままで: レベル1で えらべる うごきは 6つ だけ だった。
#           attackBase / returnBase / laneL / laneC / laneR / wait
#           このうち きちんと 勝てるのは 既定の attackBase だけ。
#           だから 子が プログラムを 書きかえても かちまけが ほとんど かわらない。
#           「何を 書いても おなじ」は むずかしさの 話ではなく、
#           勝てる ぶひんが レベル1に 無い という 話だった。
# これから: attackNearest を レベル1の ならびに 入れる。
#           名まえは ためしバトルで つかってきた ことば
#           「近くの てきを こうげき」に そろえる（D2T_JAFIX）。
#           カタログの ならびは こわさずに 写しを かえすので、
#           ぶひんの ならび・お手本の 日本語文・発火回数の ひょう・
#           ためしバトルの どこでも 英語の キーの ままには ならない。
#           お手本に「⚔ 近くの てきを たたく」（レベル1）と
#           「⚡ よわい てきを ねらう」（レベル2）を 足す。
#           もとの お手本 6つは 1つも 消さない。
#           aimWeak は レベル2の ままで よい。お手本で 存在を 知らせる。
#
# さわるのは public/defense2.js と、src/index.tsx の よみこみ番号 1か所 だけ。
# チェーンは 1件も ふやさない。
# 一つでも あてはまらなければ 何も 書かずに 止まる（fail-closed）。

import io
import sys

D2 = 'public/defense2.js'
TSX = 'src/index.tsx'

MARK = 'DEF2LV1NEAR_V1_MARK'              # 検証で 数える 番兵
ALREADY = 'function d2tJaFix(list) {'     # 冪等の 見わけ（検証条件とは 別もの）

VOLD = '/defense2.js' + '?v' + '=18'
VNEW = '/defense2.js' + '?v' + '=19'
CHAIN_WANT = 85


def die(msg):
    print(u'NG: ' + msg)
    sys.exit(1)


def chain_of(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


d2 = io.open(D2, encoding='utf-8').read()
tsx = io.open(TSX, encoding='utf-8').read()

if ALREADY in d2:
    print(u'すでに 適用ずみ。何も しない。')
    sys.exit(0)

if MARK in d2:
    die(u'番兵だけ のこっている。人の目で 見てほしい。')

if 'DEF2TPL_LEARN_V1_MARK' not in d2:
    die(u'さきに お手本の 学習サイクルが 要る')
if 'function d2tActJaFromCat(a){' not in d2:
    die(u'さきに 名まえを ひく ぶひんが 要る')
if 'D2T_JAFIX' in d2:
    die(u'おなじ 名まえの ぶひんが すでに ある')
if 'd2tJaFix' in d2:
    die(u'おなじ 名まえの はたらきが すでに ある')
OLD1 = u"""  var D2T_A1 = ['attackBase', 'returnBase', 'laneL', 'laneC', 'laneR', 'wait'];"""

NEW1 = u"""  /* DEF2LV1NEAR_V1_MARK
     レベル1に「近くの てきを こうげき」を 出す。
     レベル1で えらべる うごきは 6つ しか なくて、そのうち
     きちんと 勝てるのは 既定の attackBase だけ だった。
     だから プログラムを 書きかえても かちまけが ほとんど かわらない。
     名まえは ためしバトルで つかってきた ことばに そろえる（D2T_JAFIX）。 */
  var D2T_A1 = ['attackBase', 'returnBase', 'laneL', 'laneC', 'laneR', 'wait', 'attackNearest'];
  var D2T_JAFIX = { attackNearest: '近くの てきを こうげき' };"""

OLD2 = u"""  var D2T_A2 = D2T_A1.concat(['attackNearest', 'aimWeak',"""

NEW2 = u"""  var D2T_A2 = D2T_A1.concat(['aimWeak',"""

OLD3 = u"""  function tbActLabel(a){
    var i, ja = d2tActJaFromCat(a);"""

NEW3 = u"""  function tbActLabel(a){
    if (D2T_JAFIX[a]) return D2T_JAFIX[a];
    var i, ja = d2tActJaFromCat(a);"""

OLD4 = u"""  function d2tCatalogHook(full) {"""

NEW4 = u"""  /* DEF2LV1NEAR_V1 名まえを そろえる。もとの ならびは こわさずに 写しを かえす。 */
  function d2tJaFix(list) {
    var i, o, n, p, out = [];
    for (i = 0; i < (list || []).length; i++) {
      o = list[i];
      if (o && o.k && D2T_JAFIX[o.k]) {
        n = {};
        for (p in o) n[p] = o[p];
        n.l = D2T_JAFIX[o.k];
        out.push(n);
      } else {
        out.push(o);
      }
    }
    return out;
  }

  function d2tCatalogHook(full) {"""

OLD5 = u"""      var acts = d2tKeep(full.acts, okA, D2T_DROP_A, used.a);"""

NEW5 = u"""      var acts = d2tJaFix(d2tKeep(full.acts, okA, D2T_DROP_A, used.a));"""

OLD6 = u"""a: 'goPoint' }], els: [{ t: 'a', a: 'attackBase' }] }] }
  ];"""

NEW6 = u"""a: 'goPoint' }], els: [{ t: 'a', a: 'attackBase' }] }] },
    { name: '⚔ 近くの てきを たたく', lv: 1, prog: [{ t: 'a', a: 'attackNearest' }] },
    { name: '⚡ よわい てきを ねらう', lv: 2, prog: [{ t: 'a', a: 'aimWeak' }] }
  ];"""

PAIRS = [
    (u'レベル1の ならび', OLD1, NEW1),
    (u'レベル2の ならび', OLD2, NEW2),
    (u'名まえを ひく ところ', OLD3, NEW3),
    (u'ならびを しぼる ところ', OLD4, NEW4),
    (u'うごきの ならびに 名まえを あてる', OLD5, NEW5),
    (u'お手本の ならび', OLD6, NEW6),
]

for label, old, new in PAIRS:
    n = d2.count(old)
    if n != 1:
        die(u'あて先が %d 件（%s）。1件で ないと 流さない' % (n, label))
    if new in d2:
        die(u'新しい 中みが すでに ある（%s）' % label)

if tsx.count(VOLD) != 1:
    die(u'よみこみ番号 v18 が 1件で ない')
if tsx.count(VNEW) != 0:
    die(u'よみこみ番号 v19 が すでに ある')

chain_before = chain_of(tsx)
if chain_before != CHAIN_WANT:
    die(u'チェーンが %d 件（%d 件の はず）' % (chain_before, CHAIN_WANT))

for label, old, new in PAIRS:
    d2 = d2.replace(old, new, 1)

tsx = tsx.replace(VOLD, VNEW, 1)

chain_after = chain_of(tsx)
if chain_after != chain_before:
    die(u'チェーンが %d 件に なった（%d 件の ままで ないと だめ）' % (chain_after, chain_before))

ok = [True]


def chk(label, got, want):
    if got != want:
        print(u'NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


chk(u'こんかいの 番兵', d2.count(MARK), 1)
chk(u'名まえの さしかえ表', d2.count('D2T_JAFIX'), 6)
chk(u'名まえを そろえる はたらき', d2.count('function d2tJaFix(list) {'), 1)
chk(u'名まえを そろえる 呼び出し', d2.count('d2tJaFix('), 2)
chk(u'ためしバトルの 名まえ', d2.count('function tbActLabel(a){'), 1)
chk(u'ならびを しぼる ところ', d2.count('function d2tCatalogHook(full) {'), 1)
chk(u'attackNearest', d2.count('attackNearest'), 4)
chk(u'aimWeak', d2.count('aimWeak'), 5)
chk(u'aimWeakest は ふえていない', d2.count('aimWeakest'), 2)
chk(u'お手本の ならび', d2.count('D2T_TPL'), 8)
chk(u'新しい お手本 1', d2.count(u"{ name: '⚔ 近くの てきを たたく', lv: 1,"), 1)
chk(u'新しい お手本 2', d2.count(u"{ name: '⚡ よわい てきを ねらう', lv: 2,"), 1)
for _nm in (u'⚔ まっすぐ せめる', u'きちが あぶなくなったら もどる', u'HPが へったら まもる',
            u'まん中の みちを ゆく', u'ひだり5かい', u'きょてんを とりに いく'):
    chk(u'もとの お手本 ' + _nm, d2.count(_nm), 1)
chk(u'レベル1の ならび', d2.count(
    "var D2T_A1 = ['attackBase', 'returnBase', 'laneL', 'laneC', 'laneR', 'wait', 'attackNearest'];"), 1)
chk(u'外した うごきは そのまま', d2.count(
    "var D2T_DROP_A = ['attackFort', 'advanceFront', 'retreatBack', 'aimWeakest', 'defendFort', 'scatter'];"), 1)
chk(u'よみこみ番号 v19', tsx.count(VNEW), 1)
chk(u'ふるい よみこみ番号 v18', tsx.count(VOLD), 0)

if not ok[0]:
    die(u'書きこむ 前の 確かめで 止めた')

io.open(D2, 'w', encoding='utf-8').write(d2)
io.open(TSX, 'w', encoding='utf-8').write(tsx)
print(u'PATCH OK / chain %d -> %d' % (chain_before, chain_after))
