#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_evo_show_v6.py --- 第6便: 進化の演出（音なし）

いままで:
  ・進化は完全に自動。tryEvolveById() が8か所から呼ばれる
  ・出るのは「進化！ ○○→○○」という名前だけの文字（学習の正解メッセージの中）
  ・友達対戦では alert() の中に1行まざるだけ
  ・残り6か所（ガチャ重複・起動時の救済・八百屋・イベント重複・ジム報酬ほか）は完全に無言
  ・進化前と進化後の姿はどちらも出ない。音・光・アニメはゼロ

これから:
  ・tryEvolveById() の中で、進化が成立した瞬間に待ち行列へ積む（1関数だけ直す）
    → 8か所すべてが自動で演出つきになる
    → while で一気に何段も進化しても、1段ずつ順番に見せられる
    → 「アプリを開いた瞬間に黙って進化していた」も、ちゃんと見える
  ・進化カード（1.6秒／タップで閉じる）
      前の姿が 0.6秒かけて白く飛ぶ → 新しい姿がポンと出る → ✨12個
      「しんか！」「○○ が ○○ に なった！」
  ・友達対戦の alert からは、進化の行だけ外す（alert 自体は触らない）
  ・音なし・暗転なし・長いカットインなし

V5（色違いの演出）の部品をそのまま流用する:
  .shinypop / .shinypop-in / .shinypop-ttl / .shinypop-name / .shinypop-hint
  window.__shinyFlash / window.__shinyBurst
  → V5 が入っていることを確かめてから当てる

さわるのは public/index.html だけ。src/index.tsx は触らない（置換チェーンは増えない）。

安全策:
 - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
   （※前の便で、自分が書き換えたあとの姿ではなく前の姿でアンカーを書いて失敗した。
     今回はすべて いまの main の実物から取って、存在を確かめてある）
 - 冪等: 目印 SENTINEL があれば何もしない
 - チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
 - 待ち行列は最大5件まで（起動時の救済でカードが延々と出ないように）
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')

SENTINEL = '/* EVO_SHOW_V6 */'


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
for mark in ('/* SHINY_SHOW_V5 */', '.shinypop-in{', 'window.__shinyBurst', 'window.__shinyFlash'):
    if mark not in html:
        fail('V5 の部品 %s が無い。先に第5便を当てること' % mark)

# ------------------------------------------------------------------
# アンカー（すべて いまの main の実物から取った）
# ------------------------------------------------------------------
E1 = ("                // 図鑑登録\n"
      "                if (!player.pokedex.includes(next.id)) player.pokedex.push(next.id);")
R  = "rewardMsg += `\\n✨ ${getMonster(beforeEvoId2).name} -> ${getMonster(afterEvoId2).name} 進化！`;"
LV = "lvlUpMsg += `✨ ${getMonster(beforeEvoId).name} -> ${getMonster(afterEvoId).name} 進化!\n`;"
CSSEND = '/* SHINY_SHOW_V5 ここまで */'
BODY = '</body>'

for lbl, sgl in (('E1', E1), ('R', R), ('LV', LV), ('CSSEND', CSSEND), ('BODY', BODY)):
    must_be_one(html, sgl, lbl)
    if lbl != 'BODY' and sgl in tsx:
        fail('%s が src/index.tsx にもある。鎖が空振りするので中止' % lbl)
print('OK アンカー5種をすべて1箇所で確認')

# ------------------------------------------------------------------
# 1) tryEvolveById の中で待ち行列に積む（ここだけで8か所ぶん効く）
# ------------------------------------------------------------------
html = html.replace(E1, E1 +
    "\n                try { if (window.__evoQueuePush) window.__evoQueuePush(id, next.id); } catch (e) {}", 1)

# ------------------------------------------------------------------
# 2) 友達対戦の alert から、進化の行だけ外す（alert 自体は触らない）
# ------------------------------------------------------------------
GONE = '/* EVO_SHOW_V6 進化はカードで出すので、alert の行からは外す */'
html = html.replace(R, GONE, 1)
html = html.replace(LV, GONE, 1)

# ------------------------------------------------------------------
# 3) CSS（V5 の最後に足す）
# ------------------------------------------------------------------
CSS = """/* EVO_SHOW_V6 進化のカード（音なし。V5の部品を流用） */
        .evo-stage{position:relative;height:78px;margin-bottom:6px;}
        .evo-stage > span{position:absolute;left:50%;top:50%;transform:translate(-50%,-50%);font-size:64px;line-height:1;}
        .evo-before{animation:evoFadeOut .62s ease-in forwards;}
        .evo-after{opacity:0;animation:evoPopIn .6s ease-out .55s forwards;}
        @keyframes evoFadeOut{0%{opacity:1;filter:brightness(1)}70%{opacity:1;filter:brightness(6) saturate(0)}100%{opacity:0;filter:brightness(9) saturate(0);transform:translate(-50%,-50%) scale(1.25)}}
        @keyframes evoPopIn{0%{opacity:0;transform:translate(-50%,-50%) scale(.6);filter:brightness(5)}60%{opacity:1;transform:translate(-50%,-50%) scale(1.14);filter:brightness(1.3)}100%{opacity:1;transform:translate(-50%,-50%) scale(1);filter:brightness(1)}}
        .evo-in .shinypop-ttl{color:#7c3aed;}
        """ + CSSEND
html = html.replace(CSSEND, CSS, 1)

# ------------------------------------------------------------------
# 4) カードの係
# ------------------------------------------------------------------
BLOCK = '<script>' + SENTINEL + """
(function(){
  var q = [], busy = false;
  function esc(s){ return String(s==null?'':s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;'); }
  function monOf(id){ try { return (typeof getMonster === 'function') ? getMonster(id) : null; } catch (e) { return null; } }
  function spriteOf(id){
    var m = monOf(id);
    if (!m) return '❓';
    try { return (typeof monSpriteHtml === 'function') ? monSpriteHtml(m.id, m.sprite) : esc(m.sprite); }
    catch (e) { return esc(m.sprite); }
  }
  function nameOf(id){ var m = monOf(id); return (m && m.name) ? m.name : '???'; }

  /* tryEvolveById の中から、進化1段ごとに呼ばれる */
  window.__evoQueuePush = function(beforeId, afterId){
    try {
      if (!beforeId || !afterId || Number(beforeId) === Number(afterId)) return;
      if (q.length >= 5) return;
      q.push([beforeId, afterId]);
      if (!busy) setTimeout(next, 500);
    } catch (e) {}
  };

  function next(){
    if (busy) return;
    var item = q.shift();
    if (!item) return;
    busy = true;
    show(item[0], item[1], function(){ busy = false; if (q.length) setTimeout(next, 160); });
  }

  function show(b, a, done){
    try {
      var box = document.getElementById('evoCard');
      if (!box) {
        box = document.createElement('div');
        box.id = 'evoCard';
        box.className = 'shinypop';
        document.body.appendChild(box);
      }
      box.innerHTML = '<div class="shinypop-in evo-in">'
        + '<div class="evo-stage"><span class="evo-before">' + spriteOf(b) + '</span>'
        + '<span class="evo-after">' + spriteOf(a) + '</span></div>'
        + '<div class="shinypop-ttl">しんか！</div>'
        + '<div class="shinypop-name">' + esc(nameOf(b)) + ' が ' + esc(nameOf(a)) + ' に なった！</div>'
        + '<div class="shinypop-hint">タップでとじる</div>'
        + '</div>';
      box.style.display = 'flex';
      try { if (window.__shinyFlash) window.__shinyFlash(); } catch (e) {}
      setTimeout(function(){ try { if (window.__shinyBurst) window.__shinyBurst(box.firstChild, 12); } catch (e) {} }, 520);
      var closed = false;
      function close(){
        if (closed) return;
        closed = true;
        try { box.style.display = 'none'; } catch (e) {}
        try { done(); } catch (e) {}
      }
      box.onclick = close;
      if (window.__evoTimer) clearTimeout(window.__evoTimer);
      window.__evoTimer = setTimeout(close, 1600);
    } catch (e) { try { done(); } catch (x) {} }
  }
})();
</script>
</body>"""
html = html.replace(BODY, BLOCK, 1)

# ------------------------------------------------------------------
# 最終確認
# ------------------------------------------------------------------
if html.count(SENTINEL) != 1:
    fail('目印が %d 個（1個のはず）' % html.count(SENTINEL))
if html.count('</body>') != 1:
    fail('</body> が %d 個（1個のはず）' % html.count('</body>'))
if html.count('window.__evoQueuePush') != 3:
    fail('__evoQueuePush が %d 個（呼び出し1 + 定義2 で3個のはず）' % html.count('window.__evoQueuePush'))
if R in html or LV in html:
    fail('友達対戦の進化の行が残っている')
if 'function tryEvolveById(' not in html:
    fail('tryEvolveById が消えている')

io.open(HTML, 'w', encoding='utf-8', newline='').write(html)

tsx_after = io.open(TSX, encoding='utf-8', newline='').read()
if tsx_after != tsx:
    fail('src/index.tsx が変化している（この便は触らないはず）')

print('OK 適用しました（音なし）')
print('   - tryEvolveById の中で待ち行列に積む（8か所ぶんが一度に演出つきに）')
print('   - 進化カード 1.6秒／タップで閉じる。前の姿が白く飛んで、新しい姿がポンと出る')
print('   - 友達対戦の alert からは進化の行だけ外した（alert 自体はそのまま）')
print('   置換チェーン: %d -> %d（増やしていない）' % (chain_before, root_replace_count(tsx_after)))
