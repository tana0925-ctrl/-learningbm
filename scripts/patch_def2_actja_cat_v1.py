# -*- coding: utf-8 -*-
# DEF2ACTJA_CAT_V1 --- うごきの 名まえを キーの ままに しない。
#
# いままで: tbActLabel は defense2.js の 中の みじかい ならび（ACT と TB_ACTJA）
#           だけを 見ていた。そこに ない うごきは 英語の キーの まま 出ていた。
#           laneL / laneR / aimWeak / aimStrong と、きもちの うごき 6つ。
#           「🔁 ひだり5かい → みぎ5かい」の お手本を 読ませても laneL と 出る。
#           これでは 読む ための お手本に ならない。
# これから: じょうけんの d2tCondJa と おなじで、index.html の _pbCatalog() の
#           日本語を 先に つかう。見つからない ときだけ これまでの ならびに もどす。
#           ためしバトルの standStill は カタログに ないので もどり道が 要る。
#
# さわるのは public/defense2.js と、src/index.tsx の よみこみ番号 1か所 だけ。
# 一つでも あてはまらなければ 何も 書かずに 止まる（fail-closed）。

import io
import sys

D2 = 'public/defense2.js'
TSX = 'src/index.tsx'

MARK = 'DEF2ACTJA_CAT_V1_MARK'      # 検証で 数える 番兵
ALREADY = 'function d2tCatAll(){'   # 冪等の 見わけ（検証条件とは 別もの）


def die(msg):
    print(u'NG: ' + msg)
    sys.exit(1)


d2 = io.open(D2, encoding='utf-8').read()
tsx = io.open(TSX, encoding='utf-8').read()

if ALREADY in d2:
    print(u'すでに 適用ずみ。何も しない。')
    sys.exit(0)

if MARK in d2:
    die(u'番兵だけ のこっている。人の目で 見てほしい。')

if 'function d2tCondJa(n)' not in d2:
    die(u'さきに ツリーの しくみが 要る')
if 'DEF2TPL_LEARN_V1_MARK' not in d2:
    die(u'さきに お手本の 学習サイクルが 要る')
if 'd2tActJaFromCat' in d2:
    die(u'おなじ 名まえの ぶひんが すでに ある')

OLD = u"""  function tbActLabel(a){
    for(var i=0;i<ACT.length;i++){ if(ACT[i].v===a) return ACT[i].label; }
    return TB_ACTJA[a] || String(a);
  }"""

NEW = u"""  /* DEF2ACTJA_CAT_V1_MARK
     うごきの 名まえも、じょうけんと おなじで index.html の
     _pbCatalog() から もらう。ここを 見ていなかったので
     laneL・laneR・aimWeak・aimStrong と きもちの うごきが
     英語の キーの まま 画面に 出ていた。
     しぼりこみの さしこみ口は 名まえを ひく あいだだけ 外して
     すぐ もとに もどす。レベルで しぼられた ならびだと
     名まえが ひけない ことが あるから。
     カタログに ない ものは これまでの ならびに もどす。 */
  function d2tCatAll(){
    var cat = null, hk = null, on = false;
    if (typeof window._pbCatalog !== 'function') return null;
    try {
      hk = window._pbCatalogHook;
      on = true;
      window._pbCatalogHook = null;
      cat = window._pbCatalog();
    } catch (e) { cat = null; }
    if (on) { try { window._pbCatalogHook = hk; } catch (e2) {} }
    return cat;
  }

  function d2tActJaFromCat(a){
    var i, o, cat = d2tCatAll();
    if (cat && cat.acts) {
      for (i = 0; i < cat.acts.length; i++) {
        o = cat.acts[i];
        if (o && o.k === a && o.l) return o.l;
      }
    }
    return null;
  }

  function tbActLabel(a){
    var i, ja = d2tActJaFromCat(a);
    if (ja) return ja;
    for(i=0;i<ACT.length;i++){ if(ACT[i].v===a) return ACT[i].label; }
    return TB_ACTJA[a] || String(a);
  }"""

n = d2.count(OLD)
if n != 1:
    die(u'あて先が %d 件（1件で ないと 流さない）' % n)
if NEW in d2:
    die(u'新しい 中みが すでに ある')

if tsx.count('/defense2.js' + '?v' + '=13') != 1:
    die(u'よみこみ番号 v13 が 1件で ない')
if tsx.count('/defense2.js' + '?v' + '=14') != 0:
    die(u'よみこみ番号 v14 が すでに ある')

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
chain_before = tsx[i:j].count('.replace(')
if chain_before != 82:
    die(u'チェーンが %d 件（82 件の はず）' % chain_before)

d2 = d2.replace(OLD, NEW, 1)
tsx = tsx.replace('/defense2.js' + '?v' + '=13', '/defense2.js' + '?v' + '=14', 1)

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
chain_after = tsx[i:j].count('.replace(')
if chain_after != chain_before:
    die(u'チェーンが %d 件に なった（%d 件の ままで ないと だめ）' % (chain_after, chain_before))

if d2.count(MARK) != 1:
    die(u'番兵が 1件で ない')
if d2.count('function d2tCatAll(){') != 1:
    die(u'ぜんぶの ならびを もらう ぶひんが 1件で ない')
if d2.count('function d2tActJaFromCat(a){') != 1:
    die(u'名まえを ひく ぶひんが 1件で ない')
if d2.count('function tbActLabel(a){') != 1:
    die(u'tbActLabel が 1件で ない')
if d2.count('function d2tCondJa(n)') != 1:
    die(u'じょうけんの 名まえの ぶひんを こわした')

io.open(D2, 'w', encoding='utf-8').write(d2)
io.open(TSX, 'w', encoding='utf-8').write(tsx)
print(u'PATCH OK / chain %d -> %d' % (chain_before, chain_after))
