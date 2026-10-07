#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# PVE_GRADE_LOCK_V1 : 野生バトルの学年ボタンが「出てから消える」のをやめる
#
# ■ 何が起きていたか
#   野生バトルの学年セレクターは、3つのコードが同じボタン列を順番に触っている。
#     1. public/index.html の addPveGradeSelector() が 1〜7 を無条件で描く
#     2. g8core.js が「中2」を足す
#     3. g10core.js が 1.2秒後と2秒ごとのタイマーで、解禁されていない学年を消す
#   3 のコメントにも「index.htmlは1〜7を無条件生成」と書いてある。
#   つまり設計からして「全部出してから消す」。
#
#   2026-10-07 まで児童は全員6年生だったので baseGrade() が常に 6 になり、
#   消えるのは「中1」1個だけで目立たなかった。
#   同日に 3年生・4年生のアカウントが作られ、初めてこの経路が動いた。
#   3年生の画面では 4・5・6年生・中1・中2 の5個が 1.2秒後に消える。
#   先生の報告「ちかちかして123年だけでていた」と一致する。
#
# ■ このパッチがすること（2か所だけ）
#   (1) addPveGradeSelector() の中で、解禁されていない学年は最初から描かない。
#       window.__gradeUnlocked が無いときは今までどおり全部描く（フェイルオープン）。
#       g10core.js の消す側（enforceButtons）は安全網としてそのまま残す。
#   (2) 自分の学年が分かっているなら、最初に選ばれている学年をそれに合わせる。
#       既定は 4 なので、3年生の子は「4年生」が選ばれた状態から始まり、
#       あとから3年生に飛んで画面が描き直されていた。
#
# ■ 触る範囲
#   public/index.html だけ。手では触らず、この台本で当てる。
#   src/index.tsx は1バイトも触らない。チェーン件数は
#   「流す直前に実測した値から変わっていないこと」の確認にだけ使う。
#   D1 にも g8core/g9core/g10core にも触らない。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'

SENTINEL = '__PVE_GRADE_LOCK_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"

# (1) 解禁されていない学年は描かない
A1_OLD = (
    "[1, 2, 3, 4, 5, 6, 7].forEach(g => {\n"
    "      const btn = document.createElement('button');"
)
A1_NEW = (
    "[1, 2, 3, 4, 5, 6, 7].forEach(g => {\n"
    "      /* " + SENTINEL + " まだ解禁されていない学年は最初から出さない（出てから消えるのを防ぐ） */\n"
    "      if (g > 1 && window.__gradeUnlocked && !window.__gradeUnlocked(g)) return;\n"
    "      const btn = document.createElement('button');"
)

# (2) 最初に選ばれている学年を自分の学年に合わせる（一度だけ）
A2_OLD = (
    "function addPveGradeSelector() {\n"
    "    const existing = document.getElementById('pveGradeSelectorWrap');"
)
A2_NEW = (
    "function addPveGradeSelector() {\n"
    "    /* " + SENTINEL + " 自分の学年が分かったら、最初に選ばれている学年をそれに合わせる（一度だけ） */\n"
    "    try { if (!window.__pveGradeInit && Number(window.__userGrade) >= 1) {"
    " window.pveSelectedGrade = Number(window.__userGrade); window.__pveGradeInit = 1; } } catch (e) {}\n"
    "    const existing = document.getElementById('pveGradeSelectorWrap');"
)

# public/index.html で壊してはいけない目印（件数が変わったら中止）
KEEP_HTML = [
    'function addPveGradeSelector',
    'function renderPveDistrictSelectWithGrade',
    'function renderPveAreaSelectWithGrade',
    'pveGradeSelectorWrap',
    'pveSelectedGrade',
    'window.renderPvEDistrictSelect',
    'window.renderPvEAreaSelectForDistrict',
    '__REVIEW_BADANS_A1__',
    'window.monSpriteHtml',
    'monShinySet',
    'shiny-ring',
    'WILDIMG_V2',
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
    if h.count(A1_OLD) != 1:
        die('(1)の足場が %d件（想定 1件）' % h.count(A1_OLD))
    if h.count(A2_OLD) != 1:
        die('(2)の足場が %d件（想定 1件）' % h.count(A2_OLD))
    if '__gradeUnlocked' in h:
        die('public/index.html に __gradeUnlocked が既にある（想定外）')
    if '__pveGradeInit' in h:
        die('public/index.html に __pveGradeInit が既にある（想定外）')

    keep0 = {}
    for k in KEEP_HTML:
        n = h.count(k)
        if n < 1:
            die('目印が無い: %s' % k)
        keep0[k] = n

    # src/index.tsx は触らないが、チェーンと足場の前提だけ確かめる
    if s.count(ROOT_ANCHOR) != 1:
        die('ルートのアンカーが一意でない: %d件' % s.count(ROOT_ANCHOR))
    n_chain = chain_count(s)
    if n_chain != expect_chain:
        die('チェーンが %d件（実測で渡された想定は %d件）' % (n_chain, expect_chain))
    for name, a in (('(1)', A1_OLD), ('(2)', A2_OLD)):
        if a in s:
            die('src/index.tsx が %s の足場を使っている（中止）' % name)
    if SENTINEL in s:
        die('src/index.tsx に番兵がある（中止）')

    # --- 当てる -----------------------------------------------------------
    h2 = h.replace(A1_OLD, A1_NEW, 1)
    if h2 == h:
        die('(1)の置換に失敗した')
    h3 = h2.replace(A2_OLD, A2_NEW, 1)
    if h3 == h2:
        die('(2)の置換に失敗した')

    # --- 当てたあとの確認 --------------------------------------------------
    if h3.count(SENTINEL) != 2:
        die('番兵が %d件（想定 2件）' % h3.count(SENTINEL))
    if h3.count('!window.__gradeUnlocked(g)) return;') != 1:
        die('(1)の本体が %d件（想定 1件）' % h3.count('!window.__gradeUnlocked(g)) return;'))
    if h3.count('window.__pveGradeInit') != 2:
        die('(2)の本体が %d件（想定 2件）' % h3.count('window.__pveGradeInit'))
    if h3.count('[1, 2, 3, 4, 5, 6, 7].forEach') != 1:
        die('学年の配列が %d件になった' % h3.count('[1, 2, 3, 4, 5, 6, 7].forEach'))
    if h3.count('<script') != h.count('<script'):
        die('script タグの数が変わった')
    want_len = len(h) + (len(A1_NEW) - len(A1_OLD)) + (len(A2_NEW) - len(A2_OLD))
    if len(h3) != want_len:
        die('長さが %d（想定 %d）' % (len(h3), want_len))
    for k in KEEP_HTML:
        if h3.count(k) != keep0[k]:
            die('目印の件数が変わった: %s (%d -> %d)' % (k, keep0[k], h3.count(k)))
    if '\r' in h3:
        die('CR が入った')

    with open(HTML, 'w', encoding='utf-8', newline='') as fp:
        fp.write(h3)

    print('OK: 2か所 / chain %d（据え置き）/ %d -> %d バイト相当'
          % (n_chain, len(h), len(h3)))


if __name__ == '__main__':
    main()
