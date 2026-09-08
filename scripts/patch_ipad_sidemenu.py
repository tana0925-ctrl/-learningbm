"""
iPad でサブメニュー（バトル／友達通信／システム）が見えない問題の修正。

症状: iPad でサイドバーの「バトル」「友達通信」を押すと、右に出るはずのサブメニューが
      表示されないが、その位置をタップすると「野生バトル」が始まる（＝見えないだけ）。

原因: サブメニューはサイドバー (.lbm-sidebar / overflow-y:auto) の中にある。
      既存コードは position:fixed にして切り落としを回避しているが、iOS Safari は
      overflow:auto の中の position:fixed を「描画だけ」その枠でクリップする。
      当たり判定は画面基準のままなので「見えないのにタップは効く」状態になる。
      （PC版 Chrome では fixed が枠を抜けるため問題が出ない）

修正: 開くときにメニュー要素を document.body 直下へ移し、クリップする親をなくす。
      あわせて画面の右端からはみ出さないよう左位置を丸め込む（スマホでも有効）。

方針: public/index.html（6.3MB）は直接触らず、src/index.tsx の .replace() チェーンに
      2件追加する。冪等（2回流しても安全）。適用前後で件数を照合する。
"""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')

MARK = 'IPAD_SIDEMENU_PORTAL'
CHAIN_START = '      let t = await a.text()\n'
CHAIN_END = '      _rootHtmlCache = t\n'


def fail(msg):
    print('NG: ' + msg, file=sys.stderr)
    sys.exit(1)


# ── 1) public/index.html 側のアンカーが「ちょうど1つ」あることを先に確かめる ──
# public/index.html は巨大なのでバイナリで読む（テキストモードだと改行が正規化される）
with open(HTML, 'rb') as f:
    html = f.read().decode('utf-8')

A_OLD = '\n'.join([
    "            var rect = btnEl.getBoundingClientRect();",
    "            m.style.position = 'fixed';",
    "            m.style.left = (rect.right + 4) + 'px';",
])
B_OLD = '\n'.join([
    "            var mRect = m.getBoundingClientRect();",
    "            var desiredTop = rect.bottom - mRect.height;",
])

for label, anchor in (('A', A_OLD), ('B', B_OLD)):
    n = html.count(anchor)
    if n != 1:
        fail('public/index.html のアンカー %s が %d 個（1個であるべき）' % (label, n))
print('OK : public/index.html のアンカー A / B はどちらも一意', file=sys.stderr)

# ── 2) src/index.tsx の .replace() チェーンに2件追加 ──
src = io.open(TSX, encoding='utf-8', newline='').read()

if MARK in src:
    print('SKIP: すでに適用ずみ（冪等）', file=sys.stderr)
    sys.exit(0)

if src.count(CHAIN_START) != 1:
    fail('index.tsx の chain 開始行が %d 個' % src.count(CHAIN_START))
if src.count(CHAIN_END) != 1:
    fail('index.tsx の chain 終了行が %d 個' % src.count(CHAIN_END))

chain_before = src[src.index(CHAIN_START):src.index(CHAIN_END)]
n_before = chain_before.count('.replace(')
if n_before != 23:
    fail('適用前の .replace() が %d 件（23件であるべき）' % n_before)
print('OK : 適用前の .replace() は 23 件', file=sys.stderr)

A_NEW = [
    "            /* IPAD_SIDEMENU_PORTAL: iOS Safari は overflow:auto の中の position:fixed を描画クリップするため、",
    "               サイドバーの中に置いたままだと iPad でサブメニューが見えない（タップは効く）。開くとき body 直下へ移す。 */",
    "            if (m.parentElement !== document.body) { document.body.appendChild(m); }",
    "            m.style.margin = '0';",
    "            var rect = btnEl.getBoundingClientRect();",
    "            m.style.position = 'fixed';",
    "            m.style.right = 'auto';",
    "            m.style.left = (rect.right + 8) + 'px';",
]
B_NEW = [
    "            var mRect = m.getBoundingClientRect();",
    "            /* IPAD_SIDEMENU_CLAMP: 画面の右端からはみ出さないように左位置を丸め込む（スマホのボトムナビでも有効） */",
    "            var _vwSM = document.documentElement.clientWidth || window.innerWidth;",
    "            var _dLeft = parseFloat(m.style.left) || 0;",
    "            if (_dLeft + mRect.width > _vwSM - 8) { _dLeft = _vwSM - 8 - mRect.width; }",
    "            if (_dLeft < 8) { _dLeft = 8; }",
    "            m.style.left = Math.round(_dLeft) + 'px';",
    "            var desiredTop = rect.bottom - mRect.height;",
]


def js_arr(lines):
    """Python の文字列リストを、TSX に書く ["a","b"].join("\\n") 形式にする"""
    parts = []
    for s in lines:
        if '"' in s or '\\' in s or '`' in s:
            fail('文字列に " か \\ か ` が含まれています: ' + s[:40])
        parts.append('"' + s + '"')
    return '[' + ','.join(parts) + '].join("\\n")'


INSERT = (
    '      // 📱 iPad: サイドバー(overflow:auto)の中の position:fixed が iOS Safari で描画クリップされ、\n'
    '      //    バトル／友達通信／システムのサブメニューが「見えないのにタップは効く」状態になる問題の修正。\n'
    '      //    開くときにメニューを body 直下へ移して、クリップする親をなくす。\n'
    '      t = t.replace(' + js_arr(A_OLD.split('\n')) + ', ' + js_arr(A_NEW) + ')\n'
    '      //    あわせて、画面の右端からはみ出さないよう左位置を丸め込む（スマホのボトムナビでも有効）。\n'
    '      t = t.replace(' + js_arr(B_OLD.split('\n')) + ', ' + js_arr(B_NEW) + ')\n'
)

src = src.replace(CHAIN_END, INSERT + CHAIN_END, 1)

# ── 3) 適用後の照合 ──
chain_after = src[src.index(CHAIN_START):src.index(CHAIN_END)]
n_after = chain_after.count('.replace(')
if n_after != 25:
    fail('適用後の .replace() が %d 件（25件であるべき）' % n_after)
if chain_after.count(MARK) != 1:
    fail('目印 %s が %d 個' % (MARK, chain_after.count(MARK)))
print('OK : 適用後の .replace() は 25 件（既存23件＋今回2件）', file=sys.stderr)

with io.open(TSX, 'w', encoding='utf-8', newline='') as f:
    f.write(src)

print('DONE: src/index.tsx に2件追加しました', file=sys.stderr)

