#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_shiny_rate_v2.py --- 第2便: 色違いの出現率を学級向けに直す / ガチャでも色違いが出るようにする

これまで: 野生バトルで 1バトルごとに 1/100（SHINY_RATE）。遊ぶ量で差がつきすぎる。
         実測で 平均の子は年940戦・いちばん遊ぶ子は年4900戦 → 年9体と年49体になる。

これから:
 ・野生 … その日の「1〜3戦目のどれか」で1回だけ抽選。1/120。
          当たっても外れても その日はそれで終わり。どの子も年1〜2体にそろう。
 ・ガチャ … 1回ごとに 1/50。上限なし。引いた回数に比例して有利になる。
          実測（ボックスの uid が gacha_ の個体）で 年141回/37回/2回。
          → よく引く子で年2〜3体、合計（野生+ガチャ）で年4〜5体。
 ・限定ガチャ（10月など）も対象。getRandomMonster(stage=4) を通って
   applyGachaResultData に入るので、特別な分岐を足さなくても同じ確率で出る。
 ・強さは変えない。見た目と記録だけ。

ガチャの重複について:
 いまのガチャは、すでに持っているキャラが出たときボックスに個体を作らず
 EXPとメダルにしている。それだと図鑑がそろった子はガチャで色違いを取れない。
 → 色違いを引いたときだけ、重複でもボックスに個体を1つ作る（EXPとメダルはそのまま）。

さわるファイル:
 ・public/index.html … ガチャ3か所 + 新しい <script>（抽選の係）
 ・src/index.tsx     … 置換チェーンの「置き換える側」の文字列を1か所だけ書き換える
                       （.replace( の件数は増えない。167 のまま）

安全策:
 - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
 - 冪等: 目印 SENTINEL があれば何もしない
 - チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
 - 書いたあとにもチェーン件数が変わっていないことを確かめる
 - 改行コードは読み込んだまま保つ
 - DDL は流さない。D1 にも触らない
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')

SENTINEL = '/* SHINY_RATE_V2 */'


def fail(msg):
    print('NG 中止: ' + msg)
    sys.exit(1)


def must_be_one(text, needle, label):
    n = text.count(needle)
    if n != 1:
        fail('%s が %d 箇所（1箇所のはず）' % (label, n))


def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')


# ------------------------------------------------------------------
# 0) チェーン件数の照合（フェイルクローズ）
# ------------------------------------------------------------------
tsx = io.open(TSX, encoding='utf-8', newline='').read()
chain_before = root_replace_count(tsx)
want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want:
    fail('CHAIN_BEFORE が渡されていない')
if not want.isdigit():
    fail('CHAIN_BEFORE が数字でない: %r' % want)
if chain_before != int(want):
    fail('置換チェーンが %d 件（期待 %s 件）。ほかの便が入った可能性があるので中止'
         % (chain_before, want))
print('OK 置換チェーン: %d 件（期待どおり）' % chain_before)

html = io.open(HTML, encoding='utf-8', newline='').read()

if SENTINEL in html or SENTINEL in tsx:
    print('-- すでに適用済み（目印あり）。何もしません')
    sys.exit(0)

# 第1便が入っていること（.shiny-mon の見せ方がこの便の前提）
if '/* SHINY_BOX_DEX_V1 */' not in html:
    fail('第1便（SHINY_BOX_DEX_V1）がまだ入っていない')

# ------------------------------------------------------------------
# 1) アンカー
# ------------------------------------------------------------------
P1 = 'result.levelUpCount = 0;'
P2 = "try { createBoxEntry(monster.id, level, 'gacha'); } catch(e) {}"
P3 = "try{ logAcquire('ガチャ', monster.id, {isNew:false, note:'重複→EXP+'+gainExp}); }catch(e){}"
P4 = '</body>'
T1 = 'if (_shCap && Math.random() < SHINY_RATE) {'

must_be_one(html, P1, 'P1（ガチャ結果の下ごしらえ）')
must_be_one(html, P2, 'P2（ガチャ・新規のボックス追加）')
must_be_one(html, P3, 'P3（ガチャ・重複のログ）')
must_be_one(html, P4, 'P4（</body>）')
must_be_one(tsx,  T1, 'T1（チェーンの 野生の色違い判定・置き換える側）')

if T1 in html:
    fail('T1 が public/index.html にもある。鎖が空振りするので中止')
for lbl, s in (('P1', P1), ('P2', P2), ('P3', P3)):
    if s in tsx:
        fail('%s が src/index.tsx にもある。鎖が空振りするので中止' % lbl)
print('OK アンカー5種をすべて1箇所で確認。鎖との衝突なし')

# ------------------------------------------------------------------
# 2) ガチャ: 1回ごとに判定する
# ------------------------------------------------------------------
N1 = P1 + ' result.shiny = !!(window.__shinyGachaRoll && window.__shinyGachaRoll());'
html = html.replace(P1, N1, 1)

N2 = ("try { var _ge = createBoxEntry(monster.id, level, 'gacha'); "
      "if (result.shiny) { if (_ge) _ge.shiny = true; "
      "if (player.monsters[monster.id]) player.monsters[monster.id].shiny = true; "
      "if (window._shinyCaught) window._shinyCaught(monster.name); } } catch(e) {}")
html = html.replace(P2, N2, 1)

N3 = (P3 + " try { if (result.shiny) { var _gd = createBoxEntry(monster.id, level, 'gacha'); "
      "if (_gd) _gd.shiny = true; "
      "if (player.monsters[monster.id]) player.monsters[monster.id].shiny = true; "
      "if (window._shinyCaught) window._shinyCaught(monster.name); } } catch(e){}")
html = html.replace(P3, N3, 1)

# ------------------------------------------------------------------
# 3) 抽選の係を </body> の直前に足す
# ------------------------------------------------------------------
BLOCK = '<script>' + SENTINEL + """
(function(){
  /* 野生: 1日1回だけ。ガチャ: 1回ごと。ここだけ変えれば先生が調整できます。 */
  var WILD_RATE  = 1/120;
  var GACHA_RATE = 1/50;
  window.SHINY_WILD_RATE = WILD_RATE;
  window.SHINY_GACHA_RATE = GACHA_RATE;

  function dayKey(){
    var d = new Date();
    return d.getFullYear() + '-' + ('0'+(d.getMonth()+1)).slice(-2) + '-' + ('0'+d.getDate()).slice(-2);
  }

  /* 野生: その日の 1〜3戦目のどれか 1回だけ引く。
     当たっても外れても その日はそれで終わり。遊ぶ量で差がつかないようにするため。 */
  window.__shinyWildRoll = function(){
    try {
      if (typeof player === 'undefined' || !player) return false;
      var k = dayKey();
      var st = player.shinyDaily;
      if (!st || st.key !== k) {
        st = { key: k, at: 1 + Math.floor(Math.random()*3), n: 0, done: false };
        player.shinyDaily = st;
      }
      if (st.done) return false;
      st.n = (st.n || 0) + 1;
      if (st.n < st.at) return false;
      st.done = true;
      var hit = Math.random() < WILD_RATE;
      try { if (typeof saveData === 'function') saveData(); } catch (e) {}
      return hit;
    } catch (e) { return false; }
  };

  /* ガチャ: 1回ごとに判定。上限なし。限定キャラも同じ確率。 */
  window.__shinyGachaRoll = function(){
    var hit = false;
    try { hit = Math.random() < GACHA_RATE; } catch (e) { hit = false; }
    try {
      setTimeout(function(){
        var el = document.getElementById('gachaResultSprite');
        if (!el) return;
        if (hit) el.classList.add('shiny-mon'); else el.classList.remove('shiny-mon');
      }, 0);
    } catch (e) {}
    return hit;
  };
})();
</script>
</body>"""
html = html.replace(P4, BLOCK, 1)

# ------------------------------------------------------------------
# 4) 野生: チェーンの「置き換える側」だけ書き換える（件数は増やさない）
# ------------------------------------------------------------------
tsx = tsx.replace(T1, 'if (_shCap && window.__shinyWildRoll && window.__shinyWildRoll()) {', 1)

# ------------------------------------------------------------------
# 5) 最終確認
# ------------------------------------------------------------------
if html.count(SENTINEL) != 1:
    fail('目印が %d 個（1個のはず）' % html.count(SENTINEL))
if html.count('</body>') != 1:
    fail('</body> が %d 個（1個のはず）' % html.count('</body>'))
if T1 in tsx:
    fail('T1 が残っている')
chain_after = root_replace_count(tsx)
if chain_after != chain_before:
    fail('置換チェーンが %d -> %d に変わった（増やさないはず）' % (chain_before, chain_after))

io.open(HTML, 'w', encoding='utf-8', newline='').write(html)
io.open(TSX, 'w', encoding='utf-8', newline='').write(tsx)

print('OK 適用しました')
print('   - 野生: 1日1回だけ抽選 1/120（どの子も年1〜2体）')
print('   - ガチャ: 1回ごと 1/50（限定キャラもふくむ。重複でも色違いなら個体を作る）')
print('   置換チェーン: %d -> %d' % (chain_before, chain_after))
