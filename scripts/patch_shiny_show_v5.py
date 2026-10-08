#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_shiny_show_v5.py --- 第5便: 色違いの演出（音なし）

いままで:
  ・出会ったとき … 相手の絵の色が変わって、小さな ✨ が1つ付くだけ。気づかない子がいる
  ・捕まえたとき … 1.8秒後に OS の alert()。しかも通信が成功したときだけ出る
                   （.catch で握りつぶしていたので、圏外やサーバ不調だと無言だった）
  ・ガチャ      … 絵に色が付くだけ。メッセージは同じ alert()

これから:
  A 出会った瞬間（野生）
      画面が薄く白く光る → 相手の絵がポンと跳ねる → ✨ が8個舞う
      → 画面の上に「✨ いろちがい ✨」のリボン（2.6秒）
      そしてバトル中ずっと 金色の縁が残る（見逃しても分かるように）
  B 捕まえた瞬間
      alert() を廃止。画面中央にカード（色違いの絵・名前・✨12個）
      2.5秒で自動で消える／タップでも消える
      ★ 通信の成否に関係なく必ず出す。「第1号」だけ、返事が来てから出し直す
  C ガチャ
      単発 … 結果の絵に金の輪と ✨10個（カードは B と同じものが出る）
      10連 … 色違いの札だけ 1回ポンと跳ねる（CSSアニメ。JSなし）

  音は入れない（先生の判断）。長いカットイン・暗転・全画面アニメもやらない。
  どの演出も1秒前後で終わり、カードはタップで消せる。

さわるファイル:
  public/index.html … CSS 1か所 + ガチャ2か所 + 新しい <script>
  src/index.tsx     … 置換チェーンの「置き換える側」1か所 と SHINY_NEWS_JS 2か所
                      （.replace( の件数は増やさない。167 のまま）

さわらないもの:
  ・public/index.html の中の battle.enemyShiny = true の行
    （ここはチェーンの「探す側」の文字列。書き換えると鎖が空振りして
      夏休みの縛りが戻り、色違いが出なくなる）
  ・createParticles()（いままでの捕獲の演出）はそのまま

安全策:
 - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
 - 冪等: 目印 SENTINEL があれば何もしない
 - チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
 - 書いたあとにもチェーン件数が変わっていないことを確かめる
 - 第1〜4便が入っていることを確かめる
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')

SENTINEL = '/* SHINY_SHOW_V5 */'
GLOW = 'drop-shadow(0 0 6px rgba(251,191,36,.95))'


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

if SENTINEL in html or SENTINEL in tsx:
    print('-- すでに適用済み（目印あり）。何もしません')
    sys.exit(0)
for mark in ('/* SHINY_BOX_DEX_V1 */', '/* SHINY_RATE_V2 */',
             '/* SHINY_COLORS_V3 */', '/* SHINY_ACTIVE_V4 */'):
    if mark not in html:
        fail('%s が入っていない' % mark)

# ------------------------------------------------------------------
# アンカー
# ------------------------------------------------------------------
H1 = '.shiny-mon.sv6{filter:sepia(0.8) saturate(3.4) hue-rotate(165deg) brightness(1.08);}'
H2 = 'window.__shinyGachaRoll = function(mid){'
H4 = '</body>'

T1 = r"_sh0.shiny = true;\n                    }'"
N1 = 'window._shinyCaught = function(monName){'
N2 = 'setTimeout(function(){ try { alert(msg); } catch(e) {} }, 1800);'

for lbl, s in (('H1', H1), ('H2', H2), ('H4', H4)):
    must_be_one(html, s, lbl)
    if lbl != 'H4' and s in tsx:
        fail('%s が src/index.tsx にもある。中止' % lbl)
for lbl, s in (('T1', T1), ('N1', N1), ('N2', N2)):
    must_be_one(tsx, s, lbl)
    if s in html:
        fail('%s が public/index.html にもある。鎖が空振りするので中止' % lbl)
print('OK アンカー6種をすべて1箇所で確認')

# ------------------------------------------------------------------
# 1) CSS
# ------------------------------------------------------------------
CSS = H1 + """
        /* SHINY_SHOW_V5 ここから（音は入れない） */
        .shiny-mon{filter:hue-rotate(150deg) saturate(2.2) brightness(1.05) GLOW_;}
        .shiny-mon.sv1{filter:hue-rotate(170deg) saturate(2.2) brightness(1.05) GLOW_;}
        .shiny-mon.sv2{filter:hue-rotate(200deg) saturate(2.0) brightness(1.05) GLOW_;}
        .shiny-mon.sv3{filter:hue-rotate(240deg) saturate(2.1) brightness(1.05) GLOW_;}
        .shiny-mon.sv4{filter:hue-rotate(120deg) saturate(2.2) brightness(1.04) GLOW_;}
        .shiny-mon.sv5{filter:hue-rotate(130deg) saturate(2.2) brightness(1.04) GLOW_;}
        .shiny-mon.sv6{filter:sepia(0.8) saturate(3.4) hue-rotate(165deg) brightness(1.08) GLOW_;}
        .shiny-card{animation:shinypopBounce .55s ease-out 1;}
        .shiny-pop{animation:shinypopJump .55s ease-out 1;}
        @keyframes shinypopBounce{0%{transform:scale(.88)}55%{transform:scale(1.12)}100%{transform:scale(1)}}
        @keyframes shinypopJump{0%{transform:scale(1)}40%{transform:scale(1.18)}100%{transform:scale(1)}}
        .shiny-spark{position:fixed;z-index:99998;pointer-events:none;font-size:18px;line-height:1;animation:shinypopSpark .9s ease-out forwards;}
        @keyframes shinypopSpark{0%{opacity:0;transform:translate(-50%,-50%) scale(.4)}20%{opacity:1}100%{opacity:0;transform:translate(calc(-50% + var(--dx,0px)),calc(-50% + var(--dy,0px))) scale(1.15)}}
        .shiny-flash{position:fixed;top:0;right:0;bottom:0;left:0;z-index:99997;pointer-events:none;background:#fff;opacity:0;animation:shinypopFlash .6s ease-out forwards;}
        @keyframes shinypopFlash{0%{opacity:0}25%{opacity:.5}100%{opacity:0}}
        .shiny-ribbon{position:fixed;left:50%;top:14px;transform:translateX(-50%);z-index:99996;background:linear-gradient(90deg,#a21caf,#e879f9);color:#fff;font-weight:900;font-size:14px;padding:5px 16px;border-radius:999px;box-shadow:0 2px 10px rgba(0,0,0,.3);pointer-events:none;}
        .shinypop{position:fixed;top:0;right:0;bottom:0;left:0;z-index:99999;display:flex;align-items:center;justify-content:center;background:rgba(0,0,0,.25);}
        .shinypop-in{background:#fffbeb;border:3px solid #f59e0b;border-radius:20px;padding:18px 26px;text-align:center;box-shadow:0 8px 28px rgba(0,0,0,.35);animation:shinypopBounce .5s ease-out 1;max-width:86vw;}
        .shinypop-sp{font-size:64px;line-height:1;margin-bottom:6px;}
        .shinypop-ttl{font-weight:900;color:#a21caf;font-size:20px;}
        .shinypop-name{font-weight:900;color:#334155;font-size:16px;margin-top:4px;}
        .shinypop-first{margin-top:6px;font-size:13px;font-weight:900;color:#b45309;}
        .shinypop-hint{margin-top:8px;font-size:11px;color:#94a3b8;}
        /* SHINY_SHOW_V5 ここまで */""".replace('GLOW_', GLOW)
html = html.replace(H1, CSS, 1)

# ------------------------------------------------------------------
# 2) ガチャ（単発）
# ------------------------------------------------------------------
# 絵の色づけは第3便の monShinySet がすでにやっている（そこは触らない）。
# ここで足すのは ✨ の粒だけ。当たったかどうかは 40ms 後にクラスを見て判断する。
html = html.replace(H2,
    "window.__shinyGachaRoll = function(mid){ window.__shinyGachaMid = mid;"
    " try { setTimeout(function(){ var _ge = document.getElementById('gachaResultSprite');"
    " if (_ge && _ge.classList.contains('shiny-mon') && window.__shinyBurst) window.__shinyBurst(_ge, 10); }, 40); } catch(e) {}", 1)

# ------------------------------------------------------------------
# 3) 演出の係
# ------------------------------------------------------------------
BLOCK = '<script>' + SENTINEL + """
(function(){
  function esc(s){ return String(s==null?'':s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;'); }

  /* ✨ を何個か、その場から外へ飛ばす */
  window.__shinyBurst = function(el, n){
    try {
      if (!el) return;
      var r = el.getBoundingClientRect();
      if (!r.width && !r.height) return;
      var cx = r.left + r.width / 2, cy = r.top + r.height / 2;
      var marks = ['✨', '💫', '⭐', '✨'];
      var cnt = n || 8;
      for (var i = 0; i < cnt; i++) {
        var d = document.createElement('div');
        d.className = 'shiny-spark';
        d.textContent = marks[i % marks.length];
        var ang = (Math.PI * 2 * i) / cnt + Math.random() * 0.5;
        var dist = 30 + Math.random() * 28;
        d.style.left = cx + 'px';
        d.style.top = cy + 'px';
        d.style.setProperty('--dx', (Math.cos(ang) * dist) + 'px');
        d.style.setProperty('--dy', (Math.sin(ang) * dist) + 'px');
        document.body.appendChild(d);
        (function(e){ setTimeout(function(){ try { e.remove(); } catch (x) {} }, 950); })(d);
      }
    } catch (e) {}
  };

  /* 画面が薄く白く光る（0.6秒） */
  window.__shinyFlash = function(){
    try {
      var f = document.createElement('div');
      f.className = 'shiny-flash';
      document.body.appendChild(f);
      setTimeout(function(){ try { f.remove(); } catch (x) {} }, 650);
    } catch (e) {}
  };

  /* A: 出会った瞬間。チェーンの finishInitPvE から呼ばれる。
     相手の絵が出てからにしたいので 260ms 待つ。 */
  window.__shinyEncounter = function(){
    setTimeout(function(){
      try {
        window.__shinyFlash();
        var el = document.getElementById('enemySpriteDisplay');
        if (el) {
          el.classList.remove('shiny-pop');
          void el.offsetWidth;
          el.classList.add('shiny-pop');
          setTimeout(function(){ try { window.__shinyBurst(el, 8); } catch (x) {} }, 120);
        }
        var r = document.getElementById('shinyRibbon');
        if (!r) {
          r = document.createElement('div');
          r.id = 'shinyRibbon';
          r.className = 'shiny-ribbon';
          document.body.appendChild(r);
        }
        r.textContent = '✨ いろちがい ✨';
        r.style.display = '';
        if (window.__shinyRibbonTimer) clearTimeout(window.__shinyRibbonTimer);
        window.__shinyRibbonTimer = setTimeout(function(){ try { r.style.display = 'none'; } catch (x) {} }, 2600);
      } catch (e) {}
    }, 260);
  };

  /* B: 捕まえた瞬間。alert は使わない。通信の成否に関係なく出す。 */
  window.__shinyCard = function(name, isFirst){
    try {
      var box = document.getElementById('shinyPopCard');
      if (!box) {
        box = document.createElement('div');
        box.id = 'shinyPopCard';
        box.className = 'shinypop';
        box.onclick = function(){ try { box.style.display = 'none'; } catch (x) {} };
        document.body.appendChild(box);
      }
      var spriteHtml = '✨';
      try {
        var list = window.MONSTERS || [];
        for (var i = 0; i < list.length; i++) {
          if (list[i] && list[i].name === name) {
            var cls = window.monShinyClass ? window.monShinyClass(list[i].id) : 'shiny-mon';
            var inner = (typeof monSpriteHtml === 'function') ? monSpriteHtml(list[i].id, list[i].sprite) : esc(list[i].sprite);
            spriteHtml = '<span class="' + cls + '">' + inner + '</span>';
            break;
          }
        }
      } catch (x) {}
      var first = isFirst ? '<div class="shinypop-first">きみが いちばん最初に 見つけたよ！</div>' : '';
      box.innerHTML = '<div class="shinypop-in">'
        + '<div class="shinypop-sp">' + spriteHtml + '</div>'
        + '<div class="shinypop-ttl">✨ 色ちがいだ！ ✨</div>'
        + '<div class="shinypop-name">' + esc(name || 'モンスター') + ' を つかまえた！</div>'
        + first
        + '<div class="shinypop-hint">タップでとじる</div>'
        + '</div>';
      box.style.display = 'flex';
      if (window.__shinyCardTimer) clearTimeout(window.__shinyCardTimer);
      window.__shinyCardTimer = setTimeout(function(){ try { box.style.display = 'none'; } catch (x) {} }, 2500);
      setTimeout(function(){ try { window.__shinyBurst(box.firstChild, 12); } catch (x) {} }, 60);
    } catch (e) {}
  };
})();
</script>
</body>"""
html = html.replace(H4, BLOCK, 1)

# ------------------------------------------------------------------
# 4) src/index.tsx
# ------------------------------------------------------------------
tsx = tsx.replace(T1,
    r"_sh0.shiny = true;\n                        try { if (window.__shinyEncounter) window.__shinyEncounter(); } catch(e) {}\n                    }'", 1)

tsx = tsx.replace(N1,
    N1 + "\n    try { if (window.__shinyCard) window.__shinyCard(monName || '', false); } catch(e) {}", 1)

tsx = tsx.replace(N2,
    "if (j && j.isFirstDiscoverer) { try { if (window.__shinyCard) window.__shinyCard(monName || '', true); } catch(e) {} }", 1)

# ------------------------------------------------------------------
# 最終確認
# ------------------------------------------------------------------
if html.count(SENTINEL) != 1:
    fail('目印が %d 個（1個のはず）' % html.count(SENTINEL))
if html.count('</body>') != 1:
    fail('</body> が %d 個（1個のはず）' % html.count('</body>'))
if 'alert(msg)' in tsx:
    fail('alert が残っている')
if 'createParticles()' not in html:
    fail('createParticles が消えている（壊してはいけない）')
chain_after = root_replace_count(tsx)
if chain_after != chain_before:
    fail('置換チェーンが %d -> %d に変わった（増やさないはず）' % (chain_before, chain_after))

io.open(HTML, 'w', encoding='utf-8', newline='').write(html)
io.open(TSX, 'w', encoding='utf-8', newline='').write(tsx)

print('OK 適用しました（音なし）')
print('   A 出会った瞬間: 白い光 + 跳ね + ✨8 + リボン、バトル中は金の縁')
print('   B 捕まえた瞬間: alert 廃止。カード（2.5秒／タップで閉じる）。通信の成否によらず必ず出す')
print('   C ガチャ: 単発は金の輪と✨10、10連は色違いの札だけ跳ねる')
print('   置換チェーン: %d -> %d' % (chain_before, chain_after))
