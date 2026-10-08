#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# KUKU_UNIFY_V1 : 九九の問題の見た目を1つに統一する
#
# ■ 何が起きていたか
#   generateKukuProblem() が、1問ごとにサイコロを振って見た目を変えていた。
#       if (Math.random() < 0.2) {  -> 青い大きな数字の SVG（飾りつき）
#       それ以外                      -> 「6 × 5 = ?」のただの文字
#   400回まわして SVG 87回 / 文字 313回（約22%）。中身は同じ九九の問題で、
#   飾りが付くかどうかだけが変わる。同じバトルの中で見た目が2通りになるので、
#   先生から「統一したいね」と報告があった。
#
#   CURRICULUM 196単元 + レガシー11種を1単元300回ずつ調べた結果、
#   見た目が混ざるのは m2-kuku（九九）だけ。
#   虫食い算・数直線・分数・筆算・面積・三角形の面積は常に飾りつき、
#   残りは常に文字で、単元の中では揃っている。
#
# ■ このパッチがすること
#   九九を「いつも飾りつき」に寄せる（先生の希望）。
#   条件を外すだけ。SVG の中身も、文字版のコードも消さない。
#
# ■ 触る範囲
#   public/index.html の1か所だけ。手では触らず、この台本で当てる。
#   src/index.tsx は1バイトも触らない。チェーン件数は
#   「流す直前に実測した値から変わっていないこと」の確認にだけ使う。
#   D1 にも触らない。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'

SENTINEL = '__KUKU_UNIFY_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"

A_OLD = (
    "            // 20%の確率で視覚的な虫食い式を出す\n"
    "            if (Math.random() < 0.2) {"
)
A_NEW = (
    "            /* " + SENTINEL + " 九九はいつも飾りつき（SVG）で出す。\n"
    "               もとは 20%の確率で文字とSVGを切り替えていたので、\n"
    "               同じバトルの中で見た目が2通りになっていた。 */\n"
    "            if (true) {"
)

KEEP_HTML = [
    'function generateKukuProblem',
    'viewBox=\"0 0 400 100\"',
    'max-height:70px',
    '__BATTLEUI_FIX_V1__',
    '__REVIEW_BADANS_A1__',
    '__PVE_GRADE_LOCK_V1__',
    'WILDIMG_V2',
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

    if '\r' in h:
        die('public/index.html に CR がある（LFのはず）')
    if h.count(A_OLD) != 1:
        die('足場が %d件（想定 1件）' % h.count(A_OLD))
    if h.count('Math.random() < 0.2') != 1:
        die('20%%の分岐が %d件（想定 1件）' % h.count('Math.random() < 0.2'))

    keep0 = {}
    for k in KEEP_HTML:
        n = h.count(k)
        if n < 1:
            die('目印が無い: %s' % k)
        keep0[k] = n

    if s.count(ROOT_ANCHOR) != 1:
        die('ルートのアンカーが一意でない')
    n_chain = chain_count(s)
    if n_chain != expect_chain:
        die('チェーンが %d件（実測で渡された想定は %d件）' % (n_chain, expect_chain))
    if A_OLD in s:
        die('src/index.tsx が足場を使っている（中止）')
    if SENTINEL in s:
        die('src/index.tsx に番兵がある（中止）')

    h2 = h.replace(A_OLD, A_NEW, 1)
    if h2 == h:
        die('置換に失敗した')

    if h2.count(SENTINEL) != 1:
        die('番兵が %d件（想定 1件）' % h2.count(SENTINEL))
    if h2.count('Math.random() < 0.2') != 0:
        die('20%の分岐が残っている')
    if h2.count('            if (true) {') != 1:
        die('if (true) が %d件（想定 1件）' % h2.count('            if (true) {'))
    want_len = len(h) + (len(A_NEW) - len(A_OLD))
    if len(h2) != want_len:
        die('長さが %d（想定 %d）' % (len(h2), want_len))
    for k in KEEP_HTML:
        if h2.count(k) != keep0[k]:
            die('目印の件数が変わった: %s (%d -> %d)' % (k, keep0[k], h2.count(k)))
    if '\r' in h2:
        die('CR が入った')

    with open(HTML, 'w', encoding='utf-8', newline='') as fp:
        fp.write(h2)

    print('OK: 九九を飾りつきに統一 / chain %d（据え置き）/ %d -> %d バイト相当'
          % (n_chain, len(h), len(h2)))


if __name__ == '__main__':
    main()
