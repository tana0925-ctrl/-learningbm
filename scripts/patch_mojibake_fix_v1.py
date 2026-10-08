#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# MOJIBAKE_FIX_V1 : 児童に見える文字化け2か所を直す
#
# ■ 何が壊れていたか
#   配信HTMLに U+FFFD（文字化けの「■」）が11文字ある。
#   そのうち2か所は児童の画面に出る。
#
#   (A) 小6理科「大地のつくり」(r6-earth / genEarth6) の正解
#         「泡が出る（二酸化■ite素が発生）」   ← 「炭」が壊れている
#       四択ボタンには短い「泡が出る」だけが出るが、宿題のミニ問題で
#       正解を表示するときは fullOptions を使うので、この壊れた文字が出る。
#       同じファイル内の他の20か所以上では「二酸化炭素」は正しい。この1件だけの事故。
#
#   (B) 家庭学習の週のメニュー
#         otherEl.innerHTML = 'そ■■他：...'        ← 「の」が壊れている
#       先生が「その他」の課題を入れたときに児童の画面に出る。
#
#   残る8文字は JavaScript のコメントの中なので、誰にも見えず動作にも影響しない。
#     ・// 新しい下書きセッ■■■ョン（未開始）        3文字
#     ・// 週の振り返り■■金曜のみ）                 2文字
#     ・// 事前入力は提出済み以外は常に編集可（ス■■■ート後もOK）  3文字
#   コメントは触らない（直す必要がなく、触るほど巻き込みが増えるため）。
#
# ■ 触る範囲
#   public/index.html の2か所だけ。手では触らず、この台本で当てる。
#   src/index.tsx は1バイトも触らない。チェーン件数は
#   「流す直前に実測した値から変わっていないこと」の確認にだけ使う。
#   D1 にも触らない。問題バンクの他の問題にも触らない。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'

SENTINEL = '__MOJIBAKE_FIX_V1__'

FFFD = chr(0xFFFD)   # 文字化けの文字。ファイル自身には生の文字を置かない

# (A) 小6理科 大地のつくり：二酸化炭素
A_OLD = '（二酸化' + FFFD + 'ite素が発生）'
A_NEW = '（二酸化炭素が発生）'

# (B) 家庭学習 週のメニュー：その他
B_OLD = "'そ" + FFFD + FFFD + "他：<span"
B_NEW = "'その他：<span"

# 直す前の U+FFFD の総数（実測）
FFFD_BEFORE = 11
# (A) で1文字、(B) で2文字 減る
FFFD_AFTER = FFFD_BEFORE - 3

# public/index.html で壊してはいけない目印（件数が変わったら中止）
KEEP_HTML = [
    '石灰岩に塩酸をかけると',
    '泡が出る',
    'genEarth6',
    'otherEl.innerHTML',
    '__REVIEW_BADANS_A1__',
    '__PVE_GRADE_LOCK_V1__',
    'WILDIMG_V2',
    'window.monSpriteHtml',
    'monShinySet',
    'pveGradeSelectorWrap',
    'function startReviewChallenge',
]


def die(msg):
    sys.stderr.write('FAIL: %s\n' % msg)
    sys.exit(1)


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
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
    n_fffd = h.count(FFFD)
    if n_fffd != FFFD_BEFORE:
        die('U+FFFD が %d文字（想定 %d文字）。別のパッチが先に直した可能性がある'
            % (n_fffd, FFFD_BEFORE))
    if h.count(A_OLD) != 1:
        die('(A)の足場が %d件（想定 1件）' % h.count(A_OLD))
    if h.count(B_OLD) != 1:
        die('(B)の足場が %d件（想定 1件）' % h.count(B_OLD))
    # 直した形は別の正しい箇所にも既にある。件数を控えて「ちょうど1件ふえる」ことを見る。
    n_a_new0 = h.count('二酸化炭素が発生')
    n_b_new0 = h.count("'その他：<span")

    keep0 = {}
    for k in KEEP_HTML:
        n = h.count(k)
        if n < 1:
            die('目印が無い: %s' % k)
        keep0[k] = n

    # src/index.tsx は触らないが、チェーンと足場の前提だけ確かめる
    if s.count("app.get('/', async (c) => {") != 1:
        die('ルートのアンカーが一意でない')
    n_chain = chain_count(s)
    if n_chain != expect_chain:
        die('チェーンが %d件（実測で渡された想定は %d件）' % (n_chain, expect_chain))
    for name, a in (('(A)', A_OLD), ('(B)', B_OLD)):
        if a in s:
            die('src/index.tsx が %s の足場を使っている（中止）' % name)
    if FFFD in s:
        die('src/index.tsx にも U+FFFD がある（この便の範囲外・中止）')

    # --- 当てる -----------------------------------------------------------
    h2 = h.replace(A_OLD, A_NEW, 1)
    if h2 == h:
        die('(A)の置換に失敗した')
    h3 = h2.replace(B_OLD, B_NEW, 1)
    if h3 == h2:
        die('(B)の置換に失敗した')

    # --- 当てたあとの確認 --------------------------------------------------
    if h3.count(FFFD) != FFFD_AFTER:
        die('U+FFFD が %d文字（想定 %d文字）' % (h3.count(FFFD), FFFD_AFTER))
    if h3.count('二酸化炭素が発生') != n_a_new0 + 1:
        die('「二酸化炭素が発生」が %d件（想定 %d件）'
            % (h3.count('二酸化炭素が発生'), n_a_new0 + 1))
    if h3.count("'その他：<span") != n_b_new0 + 1:
        die('「その他：」が %d件（想定 %d件）'
            % (h3.count("'その他：<span"), n_b_new0 + 1))
    if h3.count(A_OLD) != 0 or h3.count(B_OLD) != 0:
        die('壊れた形が残っている')
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

    print('OK: 2か所 / U+FFFD %d -> %d 文字（残りはコメント内）/ chain %d（据え置き）/ %d -> %d バイト相当'
          % (FFFD_BEFORE, FFFD_AFTER, n_chain, len(h), len(h3)))


if __name__ == '__main__':
    main()
