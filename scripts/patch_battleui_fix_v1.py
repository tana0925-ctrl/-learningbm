#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# BATTLEUI_FIX_V1 : 野生バトルのテンキーの崩れと、SVGが大きくなりすぎる件
#
# (ア) テンキーの段がずれる
#     .rpg-num-btn は height:100% を使っている。テンキーは
#     「grid grid-cols-3 gap-1 flex-1」で、行の高さが中身まかせになった瞬間に
#     ブラウザによって解釈が割れる書き方。Chrome では 1020x764 / 1020x636 /
#     1020x516 のどれでも崩れなかったが、iPad Safari で崩れたという報告がある。
#     行数を明示し、height:100% をやめて align-self:stretch で伸ばす。
#     エンジンに依存しない書き方になる。
#     .rpg-num-btn 本体は触らない（OKボタンなど他でも使われているため）。
#     #battleNumpadGrid の中のボタンだけに絞って上書きする。
#
# (イ) SVGが生成側の指定より大きく出る
#     #battleQuestion svg に max-height:150px !important が掛かっていて、
#     生成側がそれぞれ指定している値を全部打ち消していた。
#       九九   70px -> 実測109px（1.5倍に膨らむ）
#       虫食い算 120px / 数直線 130px / 面積 150px
#       三角形と平行四辺形の面積 160px -> 150px に切られていた（図が欠ける側）
#     !important を外すだけで、生成側の指定が効くようになる。
#     指定の無いSVGには、これまでどおり 150px が上限として効く。
#
# ■ 触る範囲
#   public/index.html の2か所だけ。手では触らず、この台本で当てる。
#   src/index.tsx は1バイトも触らない。チェーン件数は
#   「流す直前に実測した値から変わっていないこと」の確認にだけ使う。
#   D1 にも触らない。JavaScript は1行も変えない（CSSだけ）。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'

SENTINEL = '__BATTLEUI_FIX_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"

# (ア) テンキーの行を明示して height:100% をやめる
A_OLD = (
    "    box-shadow: 0 2px 0 #222;\n"
    "}\n"
    "\n"
    "        .rpg-num-btn.submit {"
)
A_NEW = (
    "    box-shadow: 0 2px 0 #222;\n"
    "}\n"
    "\n"
    "/* " + SENTINEL + " テンキーの段がずれないようにする（行数を明示し height:100% をやめる） */\n"
    "#battleNumpadGrid {\n"
    "    grid-template-rows: repeat(4, minmax(0, 1fr));\n"
    "}\n"
    "#battleNumpadGrid > .rpg-num-btn {\n"
    "    height: auto;\n"
    "    min-height: 0;\n"
    "    align-self: stretch;\n"
    "}\n"
    "\n"
    "        .rpg-num-btn.submit {"
)

# (イ) !important を外して、生成側の max-height を効かせる
B_OLD = "    max-height: 150px !important;\n    width: 100%;"
B_NEW = "    max-height: 150px;\n    width: 100%;"

# public/index.html で壊してはいけない目印（件数が変わったら中止）
KEEP_HTML = [
    '.rpg-num-btn.submit {',
    'id="battleNumpadGrid"',
    '#battleQuestion svg,',
    'grid grid-cols-3 gap-1 flex-1',
    '__REVIEW_BADANS_A1__',
    '__PVE_GRADE_LOCK_V1__',
    'WILDIMG_V2',
    'window.monSpriteHtml',
    'monShinySet',
    '二酸化炭素が発生',
]


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
    if h.count(A_OLD) != 1:
        die('(ア)の足場が %d件（想定 1件）' % h.count(A_OLD))
    if h.count(B_OLD) != 1:
        die('(イ)の足場が %d件（想定 1件）' % h.count(B_OLD))
    if '#battleNumpadGrid {' in h:
        die('#battleNumpadGrid のCSSが既にある（想定外）')
    if h.count('max-height: 150px !important') != 1:
        die('!important つきの max-height が %d件（想定 1件）'
            % h.count('max-height: 150px !important'))

    keep0 = {}
    for k in KEEP_HTML:
        n = h.count(k)
        if n < 1:
            die('目印が無い: %s' % k)
        keep0[k] = n

    # src/index.tsx は触らないが、チェーンと足場の前提だけ確かめる
    if s.count(ROOT_ANCHOR) != 1:
        die('ルートのアンカーが一意でない')
    n_chain = chain_count(s)
    if n_chain != expect_chain:
        die('チェーンが %d件（実測で渡された想定は %d件）' % (n_chain, expect_chain))
    for name, a in (('(ア)', A_OLD), ('(イ)', B_OLD)):
        if a in s:
            die('src/index.tsx が %s の足場を使っている（中止）' % name)
    if SENTINEL in s:
        die('src/index.tsx に番兵がある（中止）')

    # --- 当てる -----------------------------------------------------------
    h2 = h.replace(A_OLD, A_NEW, 1)
    if h2 == h:
        die('(ア)の置換に失敗した')
    h3 = h2.replace(B_OLD, B_NEW, 1)
    if h3 == h2:
        die('(イ)の置換に失敗した')

    # --- 当てたあとの確認 --------------------------------------------------
    if h3.count(SENTINEL) != 1:
        die('番兵が %d件（想定 1件）' % h3.count(SENTINEL))
    if h3.count('grid-template-rows: repeat(4, minmax(0, 1fr));') != 1:
        die('(ア)の本体が %d件（想定 1件）'
            % h3.count('grid-template-rows: repeat(4, minmax(0, 1fr));'))
    # 新しいCSS（#battleNumpadGrid > .rpg-num-btn）が '.rpg-num-btn {' を含むので1件ふえる
    if h3.count('.rpg-num-btn {') != h.count('.rpg-num-btn {') + 1:
        die('.rpg-num-btn のCSSが %d件（想定 %d件）'
            % (h3.count('.rpg-num-btn {'), h.count('.rpg-num-btn {') + 1))
    if h3.count('max-height: 150px !important') != 0:
        die('!important が残っている')
    if h3.count('max-height: 150px;') != h.count('max-height: 150px;') + 1:
        die('max-height: 150px の増分が想定と違う')
    want_len = len(h) + (len(A_NEW) - len(A_OLD)) + (len(B_NEW) - len(B_OLD))
    if len(h3) != want_len:
        die('長さが %d（想定 %d）' % (len(h3), want_len))
    for k in KEEP_HTML:
        if h3.count(k) != keep0[k]:
            die('目印の件数が変わった: %s (%d -> %d)' % (k, keep0[k], h3.count(k)))
    if '\r' in h3:
        die('CR が入った')

    with open(HTML, 'w', encoding='utf-8', newline='') as fp:
        fp.write(h3)

    print('OK: (ア)テンキー + (イ)SVG上限 / chain %d（据え置き）/ %d -> %d バイト相当'
          % (n_chain, len(h), len(h3)))


if __name__ == '__main__':
    main()
