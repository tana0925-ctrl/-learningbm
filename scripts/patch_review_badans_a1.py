#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# REVIEW_BADANS_A1 : 復習に「選択肢の番号」を正解として出すのをやめる（応急処置A）
#
# ■ 何が起きていたか
#   recordWrongProblem() が、四択問題の正解を「選択肢のテキスト」ではなく
#   「選択肢の番号(0〜3)」のまま player.wrongQuestions に保存していた。
#   その保存値は、次の3か所でそのまま「正解」として児童に出る。
#     1. ステータス画面の復習リスト（上位5件）
#     2. 復習チャレンジ（10問）
#     3. 対戦の出題（_warPickFromWrongQuestions）
#   例) 「🌸 平安時代に力を持った貴族の一族は？」 → 正解：1
#   本番D1の実測: 児童22人 / 1,341件 / 60単元以上。
#   同じ問題が選択肢のシャッフルのたびに別の番号で保存されているので、
#   保存された番号には意味がない。
#
# ■ このパッチがすること（出さないだけ）
#   上の3か所が共有している絞り込み式に _revOK(x) を足して、
#   「番号のまま保存されたエントリ」を復習・対戦に出さないようにする。
#   D1には触らない。問題バンクにも触らない。保存データも書きかえない。
#   出題そのもの（修行モード）は一切変わらない。
#
# ■ _revOK が落とす条件（4つすべて満たすときだけ落とす）
#   - 保存された正解が 0〜3 の1文字
#   - 問題文に かな / カタカナ / 漢字 がある
#   - 問題文に □ が無い（虫食い算などの数値問題を守る）
#   - その単元が CURRICULUM で numpad / fraction ではない
#     分数の「約分後の分子は？」で正解が 1 のような正当なものを守るため。
#     本番D1の実測で、この条件で守られるのは 179件。
#
# ■ 触る範囲
#   public/index.html だけ。手では触らず、この台本で当てる。
#     (1) 共通の絞り込み式 3か所に _revOK(x) を足す
#     (2) </body> の直前に _revOK の定義ブロックを1つ入れる
#   src/index.tsx は1バイトも触らない。チェーン件数は
#   「流す直前に実測した値から変わっていないこと」の確認にだけ使う。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'

# 冪等性の番兵（これがあれば何もしない）
SENTINEL = '__REVIEW_BADANS_A1__'

# 3か所が共有している絞り込み式
OLD = 'x=>x && x.q && x.ans!=null && (x.count||0)>0'
# 足すぶん。_revOK が無ければ今までと同じ動き（フェイルオープン）
ADD = ' && (!window._revOK || window._revOK(x))'
NEW = OLD + ADD
EXPECT_SITES = 3

# 定義ブロックを入れる位置（ファイル中で1件だけ）
TAIL = '</body>'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"

# public/index.html で壊してはいけない目印（件数が変わったら中止）
KEEP_HTML = [
    'function startReviewChallenge',
    'function recordWrongProblem',
    'function _warPickFromWrongQuestions',
    'function _modeLabel',
    'const CURRICULUM',
    'window.monSpriteHtml',
    'monSpriteHtml(myMon.id, myMon.sprite)',
    'monSpriteHtml(enemyMon.id, enemyMon.sprite)',
    'monShinySet',
    'shiny-ring',
    'float-dynamic',
    'showWildBattleParticles',
]

BLOCK = """<script>
/* __REVIEW_BADANS_A1__ 四択の正解が選択肢番号のまま保存された復習エントリを出さない */
(function(){
  var MAP = null, MAPDONE = false;
  function buildMap(){
    var m = {}, n = 0;
    try {
      var C = window.CURRICULUM;
      if (!C) { return null; }
      for (var sk in C) {
        if (!Object.prototype.hasOwnProperty.call(C, sk)) { continue; }
        var g = C[sk] && C[sk].grades;
        if (!g) { continue; }
        for (var gk in g) {
          if (!Object.prototype.hasOwnProperty.call(g, gk)) { continue; }
          var us = g[gk] && g[gk].units;
          if (!us) { continue; }
          for (var i = 0; i < us.length; i++) {
            if (us[i] && us[i].id) { m[us[i].id] = us[i].input; n++; }
          }
        }
      }
    } catch (e) { return null; }
    return n > 0 ? m : null;
  }
  window._revOK = function(x){
    try {
      if (!x) { return false; }
      var a = String(x.ans == null ? '' : x.ans);
      if (!/^[0-3]$/.test(a)) { return true; }
      var q = String(x.q == null ? '' : x.q);
      if (q.indexOf('□') >= 0) { return true; }
      if (!/[ぁ-んァ-ヶ一-龥]/.test(q)) { return true; }
      if (!MAPDONE) { MAP = buildMap(); MAPDONE = true; }
      if (!MAP) { return true; }
      var inp = x.mode ? MAP[x.mode] : undefined;
      if (inp === 'numpad' || inp === 'fraction') { return true; }
      return false;
    } catch (e) { return true; }
  };
})();
</script>
"""


def die(msg):
    sys.stderr.write('FAIL: %s\n' % msg)
    sys.exit(1)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def want_chain():
    v = (os.environ.get('CHAIN_BEFORE') or '').strip()
    if not v.isdigit():
        die('CHAIN_BEFORE が数字で渡されていない: %r' % v)
    return int(v)


def main():
    expect_chain = want_chain()

    with open(HTML, encoding='utf-8', newline='') as fp:
        h = fp.read()
    with open(SRC, encoding='utf-8', newline='') as fp:
        s = fp.read()

    if SENTINEL in h:
        print('SKIP: 番兵 %s があるので何もしない' % SENTINEL)
        return

    # --- フェイルクローズ: 前提の確認 --------------------------------------
    if '\r' in h:
        die('public/index.html に CR がある（LFのはず）')
    if h.count(OLD) != EXPECT_SITES:
        die('絞り込み式が %d件（想定 %d件）' % (h.count(OLD), EXPECT_SITES))
    if h.count(NEW) != 0:
        die('すでに当たっている形が %d件ある' % h.count(NEW))
    if h.count(ADD) != 0:
        die('足すはずの文が既に %d件ある' % h.count(ADD))
    if h.count(TAIL) != 1:
        die('%s が %d件（想定 1件）' % (TAIL, h.count(TAIL)))
    if 'window._revOK' in h:
        die('_revOK が既にある')

    keep0 = {}
    for k in KEEP_HTML:
        n = h.count(k)
        if n < 1:
            die('目印が無い: %s' % k)
        keep0[k] = n

    # src/index.tsx は触らないが、チェーンの前提だけ確かめる
    if s.count(ROOT_ANCHOR) != 1:
        die('ルートのアンカーが一意でない: %d件' % s.count(ROOT_ANCHOR))
    n_chain = chain_count(s)
    if n_chain != expect_chain:
        die('チェーンが %d件（実測で渡された想定は %d件）' % (n_chain, expect_chain))
    # 配信チェーンがこの絞り込み式を足場に使っていたら、書きかえると壊れる
    if OLD in s:
        die('src/index.tsx が絞り込み式を足場に使っている（中止）')
    if SENTINEL in s:
        die('src/index.tsx に番兵がある（中止）')
    if '_revOK' in s:
        die('src/index.tsx に _revOK がある（中止）')

    n_script0 = h.count('<script')

    # --- 当てる -----------------------------------------------------------
    h2 = h.replace(OLD, NEW)
    if h2.count(NEW) != EXPECT_SITES:
        die('当てたあとの件数が %d件（想定 %d件）' % (h2.count(NEW), EXPECT_SITES))
    if h2.count(ADD) != EXPECT_SITES:
        die('足した文が %d件（想定 %d件）' % (h2.count(ADD), EXPECT_SITES))

    h3 = h2.replace(TAIL, BLOCK + TAIL, 1)
    if h3 == h2:
        die('定義ブロックの挿入に失敗した')

    # --- 当てたあとの確認 --------------------------------------------------
    if h3.count(SENTINEL) != 1:
        die('番兵が %d件（想定 1件）' % h3.count(SENTINEL))
    if h3.count('window._revOK =') != 1:
        die('_revOK の定義が %d件（想定 1件）' % h3.count('window._revOK ='))
    if h3.count(TAIL) != 1:
        die('%s が %d件になった' % (TAIL, h3.count(TAIL)))
    if h3.count('<script') != n_script0 + 1:
        die('script タグの増分が %d（想定 1）' % (h3.count('<script') - n_script0))
    want_len = len(h) + EXPECT_SITES * len(ADD) + len(BLOCK)
    if len(h3) != want_len:
        die('長さが %d（想定 %d）' % (len(h3), want_len))
    for k in KEEP_HTML:
        if h3.count(k) != keep0[k]:
            die('目印の件数が変わった: %s (%d -> %d)' % (k, keep0[k], h3.count(k)))
    if '\r' in h3:
        die('CR が入った')

    with open(HTML, 'w', encoding='utf-8', newline='') as fp:
        fp.write(h3)

    print('OK: 絞り込み %d か所 + 定義1件 / chain %d（据え置き）/ %d -> %d バイト相当'
          % (EXPECT_SITES, n_chain, len(h), len(h3)))


if __name__ == '__main__':
    main()
