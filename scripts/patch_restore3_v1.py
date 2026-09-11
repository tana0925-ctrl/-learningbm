# scripts/patch_restore3_v1.py
# 到達不能になっていた3単元を児童のメニューへ復帰させる。
#
# 背景:
#   showSubjectModes() は先頭で _showSubjectModes_curriculum() に return するため、
#   旧10単元メニューは到達不能。旧10単元のうち
#     rounding / division / fraction-mixed / decimal / long-division / area / brackets
#   は CURRICULUM へ移行済みだが、
#     area-triangle / mushikuizan / numberline
#   の3つだけ取り残され、どこからも開けなくなっていた。
#
# 落とし穴:
#   _genTrainQ_curriculum は window[genName]() で出題関数を呼ぶ。
#   この3つの関数は window に公開されていないため、CURRICULUM に足すだけでは
#   window[...] が undefined になり generateDecimalProblem（小数）へフォールバックする。
#   → 「CURRICULUM 登録」と「window 公開」の2点セットが必須。
#
# やること（チェーンに5本追加、64 -> 69）:
#   1. 小3算数に 虫食い算・数直線 を追加
#   2. 小5算数に 三角形と平行四辺形の面積 を追加
#   3. 3つの出題関数を window に公開
#   4. MODE_LABELS の表示名を「三角形と平行四辺形の面積」に
#   5. 旧メニューの name も同じ表示名に
#
# IDは旧IDのまま（野生バトルの case 'area-triangle' 等がそのまま効くため）。
import sys, re, hashlib

SRC = 'src/index.tsx'
HTML = 'public/index.html'

SENTINEL = '__RESTORE3_V1__'          # 冪等性の番兵（src/index.tsx 側）
CHAIN_BEFORE = 64
CHAIN_ADD = 5
CHAIN_AFTER = CHAIN_BEFORE + CHAIN_ADD

ANCHOR_CHAIN = '      _rootHtmlCache = t\n'

NEW_NAME = '三角形と平行四辺形の面積'

# public/index.html 側のアンカー（すべて1件ちょうどであること）
ANCHORS = [
    ('小3の単元配列の末尾',   r"(\{id:'m3-weight',[^\n]*\})(\n    \]\},\n    4:\{label:)"),
    ('小5の単元配列の末尾',   r"(\{id:'m5-unit-qty',[^\n]*\})(\n    \]\},\n    6:\{label:)"),
    ('window公開ブロック',    r"(        window\.generateLongDivisionProblem = generateLongDivisionProblem;\n)"),
    ('MODE_LABELSの表示名',   r"(\n          'area-triangle':')[^']*(',)"),
    ('旧メニューの表示名',     r"(\{ mode: 'area-triangle', name: ')[^']*(')"),
]

# チェーンに差し込む行（そのまま src/index.tsx へ書かれる JavaScript）
CHAIN_LINES = [
    r'''      // __RESTORE3_V1__ 到達不能だった3単元をCURRICULUMへ復帰し、出題関数をwindowへ公開''',
    r'''      t = t.replace(/(\{id:'m3-weight',[^\n]*\})(\n    \]\},\n    4:\{label:)/, "$1,\n      {id:'mushikuizan',name:'虫食い算',icon:'🧩',color:'yellow',gen:'generateMushikuizanProblem',input:'numpad',desc:'□に入る数をもとめよう'},\n      {id:'numberline',name:'数直線',icon:'📏',color:'red',gen:'generateNumberLineProblem',input:'numpad',desc:'？に入る数をもとめよう'}$2")''',
    r'''      t = t.replace(/(\{id:'m5-unit-qty',[^\n]*\})(\n    \]\},\n    6:\{label:)/, "$1,\n      {id:'area-triangle',name:'三角形と平行四辺形の面積',icon:'📐',color:'blue',gen:'generateAreaTriangleProblem',input:'numpad',desc:'底辺×高さ(÷2)'}$2")''',
    r'''      t = t.replace(/(        window\.generateLongDivisionProblem = generateLongDivisionProblem;\n)/, "$1        window.generateAreaTriangleProblem = generateAreaTriangleProblem;\n        window.generateMushikuizanProblem = generateMushikuizanProblem;\n        window.generateNumberLineProblem = generateNumberLineProblem;\n")''',
    r'''      t = t.replace(/(\n          'area-triangle':')[^']*(',)/, "$1三角形と平行四辺形の面積$2")''',
    r'''      t = t.replace(/(\{ mode: 'area-triangle', name: ')[^']*(')/, "$1三角形と平行四辺形の面積$2")''',
]
BLOCK = '\n'.join(CHAIN_LINES) + '\n'

# 既存の修正の目印（src/index.tsx 内の件数が変わっていないこと）
MARKERS = {
    '__DRILLPARK_V1__': 1,
    '__PB_HASH_FIX__': 1,
    '__HANSHIN_ADV2_LOOKUP_V1__': 1,
    '__IDFIX_V1__': 1,
    '__RATIO6_GCD_FIX__': 1,
    '__R5_MEDAKA_HUMAN__': 1,
    '__S6WORLD_50__': 1,
    '__TEACHER_RECOVERY_V1__': 2,
    '__TEACHER_SCREEN_PREVIEW_V1__': 2,
}


def die(msg):
    print('[patch] NG: ' + msg)
    sys.exit(1)


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'")
    return s[i:j].count('.replace(')


def main():
    with open(HTML, 'r', encoding='utf-8') as f:
        html = f.read()
    with open(SRC, 'r', encoding='utf-8') as f:
        orig = f.read()
    print('[patch] src/index.tsx before sha256: ' + hashlib.sha256(orig.encode()).hexdigest())

    # --- 冪等性: 番兵があれば何もしない（番兵は検証条件とは別物） ---
    if SENTINEL in orig:
        print('[patch] already applied (idempotent). nothing to do.')
        return

    # --- 適用前チェック（1つでも外れたら src/index.tsx には一切触れない） ---
    for label, pat in ANCHORS:
        n = len(re.findall(pat, html))
        if n != 1:
            die('アンカー「%s」が %d 件（1件であるべき）' % (label, n))
    print('[patch] アンカー5本すべて1件ちょうど')

    if orig.count(ANCHOR_CHAIN) != 1:
        die('チェーンの差し込み位置が %d 件' % orig.count(ANCHOR_CHAIN))

    before = chain_count(orig)
    print('[patch] .replace() chain before: %d' % before)
    if before != CHAIN_BEFORE:
        die('.replace() チェーンが %d 件ではない（%d 件）' % (CHAIN_BEFORE, before))

    for m, want in MARKERS.items():
        got = orig.count(m)
        if got != want:
            die('既存の目印 %s が %d 件（%d 件であるべき）' % (m, got, want))
    print('[patch] 既存の目印 %d 種すべて想定どおり' % len(MARKERS))

    # --- 適用 ---
    out = orig.replace(ANCHOR_CHAIN, BLOCK + ANCHOR_CHAIN, 1)

    # 非破壊検証: 足したブロックを取り除けば完全に元へ戻ること
    if out.replace(BLOCK, '', 1) != orig:
        die('非破壊検証に失敗（元の内容が変わっている）')

    after = chain_count(out)
    print('[patch] .replace() chain after : %d' % after)
    if after != CHAIN_AFTER:
        die('.replace() チェーンが %d 件になっていない（%d 件）' % (CHAIN_AFTER, after))

    for m, want in MARKERS.items():
        if out.count(m) != want:
            die('適用後に既存の目印 %s の件数が変わった' % m)

    with open(SRC, 'w', encoding='utf-8') as f:
        f.write(out)
    print('[patch] src/index.tsx after  sha256: ' + hashlib.sha256(out.encode()).hexdigest())
    print('[patch] OK: applied (+%d bytes)' % (len(out) - len(orig)))


main()
