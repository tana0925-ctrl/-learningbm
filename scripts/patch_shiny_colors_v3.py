#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_shiny_colors_v3.py --- 第3便: 色違いの色を、キャラごとに決める

いままで: どのキャラも .shiny-mon で一律 hue-rotate(150deg)。
          もとから青いキャラは ほとんど変わらず、白や灰色のキャラは まったく変わらない。

これから: キャラの絵の色を読んで、6通りの型に割りふる。
          絵は1枚も増やさない。増えるのは小さな表 public/mon/shiny.js（数KB）だけ。

  sv1 … もとが赤系   → +170度（水色〜青へ）
  sv2 … もとが橙黄系 → +200度（青紫へ）
  sv3 … もとが緑系   → +240度（赤紫へ）
  sv4 … もとが水色青系 → +120度（橙赤へ）
  sv5 … もとが紫桃系 → +130度（黄緑へ）
  sv6 … 白・灰・黒など色みがうすいキャラ → sepia で染めてから回す
        （hue-rotate だけでは何も変わらないため）

やること:
 1) public/mon/*.png を1枚ずつ読み、透明でない画素の 色あい(hue)と あざやかさ(sat) を測る
 2) 型を決めて public/mon/shiny.js を書き出す（window.MON_SHINY_V と 係の関数2つ）
 3) public/index.html を7か所だけ直す
    ・/mon/shiny.js を読み込む
    ・.sv1〜.sv6 のCSSを足す
    ・色違いの見た目を当てている5か所を、キャラのidを渡す形にする
 4) src/index.tsx は触らない（置換チェーンは 167 のまま）

安全策:
 - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
 - 冪等: 目印 SENTINEL があれば何もしない
 - チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
 - 第1便・第2便が入っていることを確かめる
 - 絵が1枚も読めなかったら中止（空の表を配らない）
"""
import io, os, sys, json, colorsys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')
MON  = os.path.join(ROOT, 'public', 'mon')
OUT  = os.path.join(MON, 'shiny.js')

SENTINEL = '/* SHINY_COLORS_V3 */'


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
if '/* SHINY_BOX_DEX_V1 */' not in html:
    fail('第1便（SHINY_BOX_DEX_V1）が入っていない')
if '/* SHINY_RATE_V2 */' not in html:
    fail('第2便（SHINY_RATE_V2）が入っていない')

# ------------------------------------------------------------------
# 1) 絵の色を測る
# ------------------------------------------------------------------
try:
    from PIL import Image
except Exception as e:
    fail('Pillow が無い: %s' % e)

names = [n for n in os.listdir(MON) if n.endswith('.png') and n[:-4].isdigit()]
names.sort(key=lambda n: int(n[:-4]))
if len(names) < 100:
    fail('public/mon の png が %d 枚しかない（おかしい）' % len(names))

def variant_for(path):
    im = Image.open(path).convert('RGBA')
    im = im.resize((48, 48))
    px = im.load()
    sx = 0.0
    sy = 0.0
    vivid = 0
    opaque = 0
    for y in range(48):
        for x in range(48):
            r, g, b, a = px[x, y]
            if a < 128:
                continue
            opaque += 1
            hh, ll, ss = colorsys.rgb_to_hls(r/255.0, g/255.0, b/255.0)
            if ss < 0.25 or ll < 0.12 or ll > 0.93:
                continue
            vivid += 1
            ang = hh * 2.0 * 3.141592653589793
            import math
            sx += math.cos(ang)
            sy += math.sin(ang)
    if opaque == 0:
        return 6, 0.0, 0
    if vivid < max(20, opaque * 0.06):
        return 6, 0.0, vivid
    import math
    hue = (math.degrees(math.atan2(sy, sx)) + 360.0) % 360.0
    if   hue < 20 or hue >= 330: v = 1   # 赤
    elif hue < 70:               v = 2   # 橙・黄
    elif hue < 170:              v = 3   # 緑
    elif hue < 260:              v = 4   # 水色・青
    else:                        v = 5   # 紫・桃
    return v, hue, vivid

table = {}
counts = {1:0, 2:0, 3:0, 4:0, 5:0, 6:0}
for n in names:
    mid = int(n[:-4])
    try:
        v, hue, vivid = variant_for(os.path.join(MON, n))
    except Exception as e:
        print('   よめなかったので sv1 にする: %s (%s)' % (n, e))
        v = 1
    table[str(mid)] = v
    counts[v] = counts[v] + 1

if not table:
    fail('表が空になった')
print('OK %d 枚を見た。内わけ: %s' % (len(table), counts))

SHINY_JS = ('/* SHINY_COLORS_V3 キャラごとの色違いの型。public/mon/*.png から自動で作った表。 */\n'
            'window.MON_SHINY_V = ' + json.dumps(table, separators=(',', ':')) + ';\n'
            """window.monShinyClass = function(id){
  try { var v = window.MON_SHINY_V && window.MON_SHINY_V[String(Number(id))]; return v ? ('shiny-mon sv' + v) : 'shiny-mon'; }
  catch (e) { return 'shiny-mon'; }
};
window.monShinySet = function(el, id, on){
  if (!el) return;
  try {
    for (var i = 1; i <= 6; i++) { el.classList.remove('sv' + i); }
    if (!on) { el.classList.remove('shiny-mon'); return; }
    el.classList.add('shiny-mon');
    var v = window.MON_SHINY_V && window.MON_SHINY_V[String(Number(id))];
    if (v) el.classList.add('sv' + v);
  } catch (e) {}
};
""")
io.open(OUT, 'w', encoding='utf-8', newline='\n').write(SHINY_JS)
print('OK public/mon/shiny.js を書いた（%d バイト）' % len(SHINY_JS.encode('utf-8')))

# ------------------------------------------------------------------
# 2) public/index.html を7か所
# ------------------------------------------------------------------
A1 = '<script src="/mon/list.js"></script>'
A2 = '.shiny-mon{filter:hue-rotate(150deg) saturate(2.2) brightness(1.05);position:relative;display:inline-block;}'
A3 = 'entry.shiny ? \'<span class="shiny-mon">\' + m.sprite + \'</span>\' : m.sprite'
A4 = "var on = spriteEl.classList.toggle('shiny-mon');"
A5 = ("var _psh = _pmid && player.monsters && player.monsters[_pmid] && player.monsters[_pmid].shiny; "
      "if (_psh) _psd.classList.add('shiny-mon'); else _psd.classList.remove('shiny-mon');")
A6 = ("if (battle.enemyShiny || (enemyMon && enemyMon.shiny)) _esd.classList.add('shiny-mon'); "
      "else _esd.classList.remove('shiny-mon');")
A7 = 'result.shiny = !!(window.__shinyGachaRoll && window.__shinyGachaRoll());'
A8 = "if (hit) el.classList.add('shiny-mon'); else el.classList.remove('shiny-mon');"

for lbl, s in (('A1',A1),('A2',A2),('A3',A3),('A4',A4),('A5',A5),('A6',A6),('A7',A7),('A8',A8)):
    must_be_one(html, s, lbl)
    if s in tsx:
        fail('%s が src/index.tsx にもある。鎖が空振りするので中止' % lbl)
print('OK アンカー8種をすべて1箇所で確認。鎖との衝突なし')

html = html.replace(A1, A1 + '\n<script src="/mon/shiny.js"></script>', 1)

html = html.replace(A2, A2 + """
        /* SHINY_COLORS_V3 キャラごとの色。表は public/mon/shiny.js */
        .shiny-mon.sv1{filter:hue-rotate(170deg) saturate(2.2) brightness(1.05);}
        .shiny-mon.sv2{filter:hue-rotate(200deg) saturate(2.0) brightness(1.05);}
        .shiny-mon.sv3{filter:hue-rotate(240deg) saturate(2.1) brightness(1.05);}
        .shiny-mon.sv4{filter:hue-rotate(120deg) saturate(2.2) brightness(1.04);}
        .shiny-mon.sv5{filter:hue-rotate(130deg) saturate(2.2) brightness(1.04);}
        .shiny-mon.sv6{filter:sepia(0.8) saturate(3.4) hue-rotate(165deg) brightness(1.08);}""", 1)

html = html.replace(A3,
    "entry.shiny ? '<span class=\"' + (window.monShinyClass ? window.monShinyClass(entry.monsterId) : 'shiny-mon') + '\">' + m.sprite + '</span>' : m.sprite", 1)

html = html.replace(A4,
    "var on = !spriteEl.classList.contains('shiny-mon'); "
    "if (window.monShinySet) window.monShinySet(spriteEl, id, on); else spriteEl.classList.toggle('shiny-mon');", 1)

html = html.replace(A5,
    "var _psh = _pmid && player.monsters && player.monsters[_pmid] && player.monsters[_pmid].shiny; "
    "if (window.monShinySet) window.monShinySet(_psd, _pmid, !!_psh); "
    "else { if (_psh) _psd.classList.add('shiny-mon'); else _psd.classList.remove('shiny-mon'); }", 1)

html = html.replace(A6,
    "var _esh = !!(battle.enemyShiny || (enemyMon && enemyMon.shiny)); "
    "if (window.monShinySet) window.monShinySet(_esd, enemyMon && enemyMon.id, _esh); "
    "else { if (_esh) _esd.classList.add('shiny-mon'); else _esd.classList.remove('shiny-mon'); }", 1)

html = html.replace(A7,
    "result.shiny = !!(window.__shinyGachaRoll && window.__shinyGachaRoll(result.data && result.data.id));", 1)

html = html.replace(A8,
    "if (window.monShinySet) window.monShinySet(el, mid, hit); "
    "else { if (hit) el.classList.add('shiny-mon'); else el.classList.remove('shiny-mon'); }", 1)

# __shinyGachaRoll が id を受け取れるようにする
A9 = 'window.__shinyGachaRoll = function(){'
must_be_one(html, A9, 'A9（ガチャの抽選の係）')
html = html.replace(A9, 'window.__shinyGachaRoll = function(mid){', 1)

html = html.replace('/* SHINY_RATE_V2 */', '/* SHINY_RATE_V2 */' + SENTINEL, 1)

# ------------------------------------------------------------------
# 3) 最終確認
# ------------------------------------------------------------------
if html.count(SENTINEL) != 1:
    fail('目印が %d 個（1個のはず）' % html.count(SENTINEL))
if html.count('</body>') != 1:
    fail('</body> が %d 個（1個のはず）' % html.count('</body>'))
if html.count('<script src="/mon/shiny.js"></script>') != 1:
    fail('shiny.js の読み込みが %d 個' % html.count('<script src="/mon/shiny.js"></script>'))

io.open(HTML, 'w', encoding='utf-8', newline='').write(html)

tsx_after = io.open(TSX, encoding='utf-8', newline='').read()
if tsx_after != tsx:
    fail('src/index.tsx が変化している（この便は触らないはず）')

print('OK 適用しました')
print('   - public/mon/shiny.js を新規作成（%d 体ぶんの型）' % len(table))
print('   - .sv1〜.sv6 を追加。絵は1枚も増やしていない')
print('   置換チェーン: %d -> %d（増やしていない）' % (chain_before, root_replace_count(tsx_after)))
