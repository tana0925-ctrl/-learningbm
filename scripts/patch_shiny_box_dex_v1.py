#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_shiny_box_dex_v1.py --- 第1便: ボックスに色違いの印 / 図鑑の詳細をノーマル既定に / 捕獲の連打で複製されるのを止める

さわるのは public/index.html だけ。src/index.tsx は1文字も書き換えない。
（置換チェーンは増えない。CHAIN_BEFORE は「他の便と衝突していないか」のガードとして照合するだけ）

やること:

 1) ボックス(renderBox)の1マスに色違いの印を出す
    ・個体単位の entry.shiny で判定（種族単位の player.monsters[id].shiny は使わない）
    ・スプライトを .shiny-mon で包む（既存の hue-rotate + ✨ がそのまま効く）
    ・金色のリングを重ねる

 2) 図鑑の詳細(showDetail)をノーマル既定にする
    ・いまは持っていると色違いの姿に置き換わり、ノーマルが見られない
    ・しかも判定が player.monsters[id].shiny（種族単位）なので、1体捕まえると
      その種族の詳細が常に色違いになってしまう
    → ノーマルを既定にし、その種族の色違いの個体をボックスに持っている子だけに
      「✨ 色ちがいを見る」の切り替えボタンを出す（判定はボックスの個体）

 3) ボールの連打で同じ個体が複数できるのを止める
    実測: ある児童のボックスに monsterId=124 が
      1791165858626 / 1791165859461 / 1791165859642（1秒以内に3件）
    throwBall() に再入のガードが無く、onclick が唯一の呼び出し口なので、
    呼び出し口に 1.2秒のデバウンスを置く。throwBall() の中身は触らない。

安全策:
 - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
 - 冪等: 目印 SENTINEL があれば何もしない
 - src/index.tsx の置換チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
 - src/index.tsx は読むだけ（書き換えない）。前後で内容が同一であることも確認する
 - 改行コードは読み込んだまま保つ（newline='' で開く）
 - DDL は流さない。D1 にも触らない
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')

SENTINEL = '/* SHINY_BOX_DEX_V1 */'


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
tsx_before = io.open(TSX, encoding='utf-8', newline='').read()
chain_now = root_replace_count(tsx_before)
want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want:
    fail('CHAIN_BEFORE が渡されていない')
if not want.isdigit():
    fail('CHAIN_BEFORE が数字でない: %r' % want)
if chain_now != int(want):
    fail('置換チェーンが %d 件（期待 %s 件）。ほかの便が入った可能性があるので中止'
         % (chain_now, want))
print('OK 置換チェーン: %d 件（期待どおり）' % chain_now)

html = io.open(HTML, encoding='utf-8', newline='').read()

if SENTINEL in html:
    print('-- すでに適用済み（目印あり）。何もしません')
    sys.exit(0)

# ------------------------------------------------------------------
# 1) アンカーの存在確認（全部そろって初めて書く）
# ------------------------------------------------------------------
A_CSS = '.shiny-mon{filter:hue-rotate(150deg) saturate(2.2) brightness(1.05);position:relative;display:inline-block;}'
A_BOX = '<div class="text-lg leading-none">${m.sprite}</div>'
A_DEX = ("var _dsh = player.monsters && player.monsters[id] && player.monsters[id].shiny; "
         "if (_dsh) _dsp.classList.add('shiny-mon'); else _dsp.classList.remove('shiny-mon'); } catch(e){}")
A_LOCK = "try { __sp.classList.remove('shiny-mon'); } catch(e) {}"
A_BALL = 'onclick="throwBall()'
A_BODY = '</body>'

must_be_one(html, A_CSS,  'A_CSS（.shiny-mon のCSS）')
must_be_one(html, A_BOX,  'A_BOX（ボックス1マスのスプライト）')
must_be_one(html, A_DEX,  'A_DEX（図鑑詳細の色違い判定）')
must_be_one(html, A_LOCK, 'A_LOCK（未入手のときの色違い解除）')
must_be_one(html, A_BALL, 'A_BALL（ボールのボタン）')
must_be_one(html, A_BODY, 'A_BODY（</body>）')

# これらが src/index.tsx の置換チェーンに使われていないこと（使われていると鎖が空振りする）
for lbl, s in (('A_CSS', A_CSS), ('A_BOX', A_BOX), ('A_DEX', A_DEX),
               ('A_LOCK', A_LOCK), ('A_BALL', A_BALL)):
    if s in tsx_before:
        fail('%s が src/index.tsx にも出てくる。鎖が空振りするので中止' % lbl)
print('OK アンカー6種をすべて1箇所で確認。鎖との衝突なし')

# ------------------------------------------------------------------
# 2) CSS を足す
# ------------------------------------------------------------------
NEW_CSS = A_CSS + """
        /* SHINY_BOX_DEX_V1 ここから */
        #boxGrid > div{position:relative;}
        .shiny-ring{position:absolute;top:-2px;right:-2px;bottom:-2px;left:-2px;border:2px solid #f59e0b;border-radius:0.6rem;pointer-events:none;box-shadow:0 0 6px rgba(245,158,11,0.55);}
        #dexShinyToggle{margin:-4px 0 8px;text-align:center;}
        #dexShinyToggle button{font-size:11px;font-weight:800;padding:3px 12px;border-radius:999px;border:2px solid #e879f9;background:#fdf4ff;color:#a21caf;cursor:pointer;}
        #dexShinyToggle button.on{background:#a21caf;border-color:#a21caf;color:#fff;}
        /* SHINY_BOX_DEX_V1 ここまで */"""
html = html.replace(A_CSS, NEW_CSS, 1)

# ------------------------------------------------------------------
# 3) ボックスの1マス（テンプレートリテラルの中なので ' はそのまま使える）
# ------------------------------------------------------------------
NEW_BOX = ('<div class="text-lg leading-none">${entry.shiny ? \'<span class="shiny-mon">\' + m.sprite + \'</span>\' : m.sprite}</div>'
           '${entry.shiny ? \'<span class="shiny-ring"></span>\' : \'\'}')
html = html.replace(A_BOX, NEW_BOX, 1)

# ------------------------------------------------------------------
# 4) 図鑑の詳細: ノーマル既定 + 切り替えボタン
# ------------------------------------------------------------------
NEW_DEX = "_dsp.classList.remove('shiny-mon'); if (window.__dexShinyToggle) window.__dexShinyToggle(id, _dsp); } catch(e){}"
html = html.replace(A_DEX, NEW_DEX, 1)

NEW_LOCK = "try { __sp.classList.remove('shiny-mon'); if (window.__dexShinyToggle) window.__dexShinyToggle(0, __sp); } catch(e) {}"
html = html.replace(A_LOCK, NEW_LOCK, 1)

# ------------------------------------------------------------------
# 5) ボールの連打どめ（呼び出し口だけ差し替える）
# ------------------------------------------------------------------
html = html.replace(A_BALL, 'onclick="__throwBallOnce()', 1)

# ------------------------------------------------------------------
# 6) 新しい <script> を </body> の直前に足す
#    （src/index.tsx の鎖も '</body>' を足し場所に使うが、置換後も </body> は1個のままなので干渉しない）
# ------------------------------------------------------------------
BLOCK = """<script>""" + SENTINEL + """
(function(){
  /* その種族の色違いの個体を、自分のボックスに持っているか（個体単位で見る） */
  function hasShinyOf(id){
    try {
      if (typeof getAllBoxEntries !== 'function') return false;
      var es = getAllBoxEntries() || [];
      for (var i = 0; i < es.length; i++) {
        var e = es[i];
        if (e && e.shiny && Number(e.monsterId) === Number(id)) return true;
      }
    } catch (err) {}
    return false;
  }
  window.__hasShinyOf = hasShinyOf;

  /* 図鑑の詳細: ノーマルを既定にして、持っている子だけに切り替えボタンを出す */
  window.__dexShinyToggle = function(id, spriteEl){
    try {
      var box = document.getElementById('dexShinyToggle');
      if (!box) {
        box = document.createElement('div');
        box.id = 'dexShinyToggle';
      }
      var nameEl = document.getElementById('detailName');
      var anchor = nameEl || spriteEl;
      if (!anchor || !anchor.parentNode) return;
      if (box.parentNode !== anchor.parentNode || box.previousSibling !== anchor) {
        anchor.parentNode.insertBefore(box, anchor.nextSibling);
      }
      if (!id || !spriteEl || !hasShinyOf(id)) {
        box.innerHTML = '';
        box.style.display = 'none';
        return;
      }
      box.style.display = '';
      box.innerHTML = '<button type="button">✨ 色ちがいを見る</button>';
      var btn = box.getElementsByTagName('button')[0];
      if (!btn) return;
      btn.onclick = function(){
        var on = spriteEl.classList.toggle('shiny-mon');
        btn.className = on ? 'on' : '';
        btn.innerHTML = on
          ? 'ノーマルを見る'
          : '✨ 色ちがいを見る';
      };
    } catch (err) {}
  };

  /* ボールの連打どめ。1.2秒いないの2回目以降は捨てる。
     （実測: 同じモンスターが1秒いないに3体ボックスに入っていた） */
  window.__throwBallOnce = function(){
    try {
      var now = Date.now();
      if (window.__lastThrowTs && (now - window.__lastThrowTs) < 1200) return;
      window.__lastThrowTs = now;
    } catch (err) {}
    if (typeof throwBall === 'function') throwBall();
  };
})();
</script>
</body>"""
html = html.replace(A_BODY, BLOCK, 1)

# ------------------------------------------------------------------
# 7) 書き戻し前の最終確認
# ------------------------------------------------------------------
if html.count(SENTINEL) != 1:
    fail('目印が %d 個（1個のはず）' % html.count(SENTINEL))
if html.count('</body>') != 1:
    fail('</body> が %d 個（1個のはず）' % html.count('</body>'))
if 'onclick="throwBall()' in html:
    fail('ボールの呼び出し口が残っている')
if A_DEX in html or A_BOX in html:
    fail('置換しきれていないアンカーがある')

io.open(HTML, 'w', encoding='utf-8', newline='').write(html)

# src/index.tsx は読むだけ。念のため内容が変わっていないことを確かめる
tsx_after = io.open(TSX, encoding='utf-8', newline='').read()
if tsx_after != tsx_before:
    fail('src/index.tsx が変化している（このパッチは触らないはず）')

print('OK 適用しました')
print('   - ボックス: entry.shiny に .shiny-mon と金リング')
print('   - 図鑑詳細: ノーマル既定 + 「色ちがいを見る」切り替え（個体単位で判定）')
print('   - ボール: 1.2秒のデバウンス（連打で複製されるのを止める）')
print('   置換チェーン: %d -> %d（増やしていない）' % (chain_now, root_replace_count(tsx_after)))
