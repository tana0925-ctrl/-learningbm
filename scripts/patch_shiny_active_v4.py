#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_shiny_active_v4.py --- 第4便: バトル中のすがたを「いま出している個体」で見る / 10連のまとめに色違いを出す

(1) バトル中の自分のすがた
    いまは player.monsters[id].shiny（種族単位）を見ているので、色違いを1体持っていると
    同じ種族の別個体を出してもバトル中は色違いに見える。
    → ボックスの個体から「その種族で、いま手持ち(isActive)にしている個体が色違いか」を見る。
    ★ player.party の持ち方（monsterId の配列）は変えない。
      変えると rt_rooms / battle_rooms の party_json、防衛戦の snapshot_json、
      トレード、友達対戦の合い言葉など、すでにD1に入っている形まで壊れるため。
      ボックスの個体を見るだけなら、保存してある形は一切変わらない。

(2) 10連ガチャのまとめ
    単発の結果画面は色が変わるのに、10連のまとめだけ色違いが分からなかった。
    → 同じ種族でも 色違いは別の札に分け、札を金色にして、絵に色違いの色をかける。

さわるのは public/index.html だけ。src/index.tsx は触らない（置換チェーンは増えない）。

別便との兼ね合い:
  GACHAIMG_V1（ガチャの絵を画像にする便）は、まだ流れていない。
  あちらは まとめの集計のところ（sprite を r.data から作る行）と
  単発の gachaResultSprite を書き換える。
  この便が使うアンカー7つは、あちらのスクリプトに1つも出てこないことを確かめてある。
  どちらを先に流しても、もう一方は動く。

安全策:
 - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
 - 冪等: 目印 SENTINEL があれば何もしない
 - チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
 - 第1〜3便が入っていることを確かめる
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')

SENTINEL = '/* SHINY_ACTIVE_V4 */'


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


tsx = io.open(TSX, encoding='utf-8', newline='').read()
chain_before = root_replace_count(tsx)
want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want or not want.isdigit():
    fail('CHAIN_BEFORE が渡されていない/数字でない: %r' % want)
if chain_before != int(want):
    fail('置換チェーンが %d 件（期待 %s 件）。ほかの便が入った可能性があるので中止'
         % (chain_before, want))
print('OK 置換チェーン: %d 件（期待どおり）' % chain_before)

html = io.open(HTML, encoding='utf-8', newline='').read()

if SENTINEL in html:
    print('-- すでに適用済み（目印あり）。何もしません')
    sys.exit(0)
for mark in ('/* SHINY_BOX_DEX_V1 */', '/* SHINY_RATE_V2 */', '/* SHINY_COLORS_V3 */'):
    if mark not in html:
        fail('%s が入っていない' % mark)

# ------------------------------------------------------------------
# アンカー
# ------------------------------------------------------------------
Q1 = 'var _psh = _pmid && player.monsters && player.monsters[_pmid] && player.monsters[_pmid].shiny;'
B1 = 'if (!summary[key]) {'
B2 = 'Object.values(summary).forEach(item => {'
B3 = '<div class="${bgColor} border-2 rounded-lg p-3 flex flex-col items-center justify-center">'
B4 = '<div class="text-4xl mb-1">${item.sprite}</div>'
B5 = '.shiny-mon.sv6{filter:sepia(0.8) saturate(3.4) hue-rotate(165deg) brightness(1.08);}'
B6 = '</body>'

for lbl, s in (('Q1',Q1),('B1',B1),('B2',B2),('B3',B3),('B4',B4),('B5',B5),('B6',B6)):
    must_be_one(html, s, lbl)
    if s != B6 and s in tsx:
        fail('%s が src/index.tsx にもある。鎖が空振りするので中止' % lbl)
print('OK アンカー7種をすべて1箇所で確認。鎖との衝突なし')

# ------------------------------------------------------------------
# (1) バトル中の自分のすがた
# ------------------------------------------------------------------
html = html.replace(Q1,
    'var _psh = window.__activeShiny ? window.__activeShiny(_pmid) : '
    '(_pmid && player.monsters && player.monsters[_pmid] && player.monsters[_pmid].shiny);', 1)

# ------------------------------------------------------------------
# (2) 10連のまとめ
# ------------------------------------------------------------------
html = html.replace(B1, "if (r.shiny) { key = String(key) + '__sh'; } if (!summary[key]) {", 1)

html = html.replace(B2,
    'Object.entries(summary).forEach(function(__e){ var __k = __e[0], item = __e[1]; '
    "item.shiny = /__sh$/.test(__k); "
    "item.monId = parseInt(String(__k).replace('__sh', ''), 10) || 0;", 1)

html = html.replace(B3,
    '<div class="${bgColor} border-2 rounded-lg p-3 flex flex-col items-center justify-center'
    "${item.shiny ? ' shiny-card' : ''}\">", 1)

html = html.replace(B4,
    '<div class="text-4xl mb-1">${item.shiny ? \'<span class="\' + '
    "(window.monShinyClass ? window.monShinyClass(item.monId) : 'shiny-mon') + '\">' + "
    "item.sprite + '</span>' : item.sprite}</div>", 1)

html = html.replace(B5, B5 + """
        /* SHINY_ACTIVE_V4 10連のまとめで 色違いの札 */
        .shiny-card{border-color:#f59e0b !important;background:#fffbeb !important;box-shadow:0 0 8px rgba(245,158,11,0.55);}""", 1)

# ------------------------------------------------------------------
# 係を </body> の直前に
# ------------------------------------------------------------------
BLOCK = '<script>' + SENTINEL + """
(function(){
  /* バトル中の自分のすがた: 種族ではなく「いま手持ちにしている個体」で見る。
     player.party の持ち方（monsterId の配列）は変えない。
     ボックスの個体が1つも見つからないときは、これまでどおり種族で見る。 */
  window.__activeShiny = function(id){
    try {
      if (!id) return false;
      if (typeof getAllBoxEntries === 'function') {
        var es = getAllBoxEntries() || [];
        var any = false, act = false;
        for (var i = 0; i < es.length; i++) {
          var e = es[i];
          if (!e || Number(e.monsterId) !== Number(id)) continue;
          any = true;
          if (e.isActive && e.shiny) act = true;
        }
        if (any) return act;
      }
      return !!(window.player && player.monsters && player.monsters[id] && player.monsters[id].shiny);
    } catch (err) { return false; }
  };
})();
</script>
</body>"""
html = html.replace(B6, BLOCK, 1)

# ------------------------------------------------------------------
# 最終確認
# ------------------------------------------------------------------
if html.count(SENTINEL) != 1:
    fail('目印が %d 個（1個のはず）' % html.count(SENTINEL))
if html.count('</body>') != 1:
    fail('</body> が %d 個（1個のはず）' % html.count('</body>'))
if html.count('shiny-card') != 2:
    fail('shiny-card が %d 個（CSSと札で2個のはず）' % html.count('shiny-card'))
if Q1 in html or B1 in html or B2 in html:
    fail('置換しきれていないアンカーがある')

io.open(HTML, 'w', encoding='utf-8', newline='').write(html)

tsx_after = io.open(TSX, encoding='utf-8', newline='').read()
if tsx_after != tsx:
    fail('src/index.tsx が変化している（この便は触らないはず）')

print('OK 適用しました')
print('   - バトル中: いま手持ちにしている個体が色違いのときだけ色が変わる')
print('   - 10連のまとめ: 色違いは別の札・金わく・キャラごとの色')
print('   置換チェーン: %d -> %d（増やしていない）' % (chain_before, root_replace_count(tsx_after)))
