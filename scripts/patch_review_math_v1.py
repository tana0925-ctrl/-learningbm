#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# REVIEW_MATH_V1 : 復習に出す前に計算式を検算する
#
# ■ 何が起きているか
#   先生の報告：「2足す10は⑤とすると不正解で正解は⑥とでる」
#   正確には  m6-frac-mul || 2+3=? || 6  という保存データ。
#   REVIEW_BADANS_A1（10/07）は「四択の番号が正解として保存されたもの」を
#   落とす作りで、条件に「問題文に日本語がある」を入れていた。
#   2+3=? には日本語が無いので、最初から対象外だった（当時そう報告している）。
#
# ■ このパッチがすること
#   _revOK の先頭に「計算式の検算」を足す。
#   たし算・ひき算・かけ算・わり算だけの単純な式を実際に計算し、
#   答えが合っていなければ復習に出さない。
#
#   検算しない（そのまま残す）もの：
#     ・問題文に日本語が入っている（「あまり」の連結仕様もここで除外される）
#     ・虫食い（□）や、式の途中に ？ があるもの
#     ・答えが数でないもの
#     ・筆算のように演算子が無いもの（例: 「4 348」）
#     ・かっこが入っているもの
#   小数の丸め誤差は 1e-9 で吸収する（0.01×50 など）。
#   「疑わしきは残す」。確実に合っていないと分かったときだけ落とす。
#
# ■ 本番データでの実測（D1は読み取りのみ）
#   復習リストのうち問題文に日本語が無い 166件をこの関数にかけた結果：
#     落とす .................. 2件（2+3=?→6、 2/3÷1/2=?→6）
#     合っていて残す ........ 小数・3項・全角記号を含むものを含めて全部
#     誤って落とすもの .... 0件
#
# ■ 触る範囲
#   public/index.html の1か所だけ。src/index.tsx は1バイトも触らない。
#   D1 にも触らない（保存データは書きかえず、「出さない」だけ）。
#   REVIEW_BADANS_A1 の判定はそのまま残す。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'

SENTINEL = '__REVIEW_MATH_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"

A_OLD = (
    "  window._revOK = function(x){\n"
    "    try {\n"
    "      if (!x) { return false; }\n"
)
A_NEW = (
    "  /* " + SENTINEL + " 計算式の検算。確実に合っていないと分かったときだけ true。\n"
    "     検算できないものは nullを返して、今までどおりの判定に渡す。 */\n"
    "  function _revMathBad(x) {\n"
    "    try {\n"
    "      var q = String((x && x.q) == null ? '' : x.q);\n"
    "      var a = String((x && x.ans) == null ? '' : x.ans).trim();\n"
    "      /* 日本語入りは式ではない（「あまり」の連結仕様もここで除外） */\n"
    "      if (/[぀-ゟ゠-ヿ一-鿿]/.test(q)) return null;\n"
    "      if (q.indexOf('□') >= 0) return null;\n"
    "      if (!/^-?[0-9]+(\\.[0-9]+)?$/.test(a)) return null;\n"
    "      var e = q.replace(/[\\s　]/g, '')\n"
    "               .replace(/[＋]/g, '+')\n"
    "               .replace(/[－−ー]/g, '-')\n"
    "               .replace(/[×✕✖]/g, '*')\n"
    "               .replace(/[÷]/g, '/')\n"
    "               .replace(/[＝]/g, '=');\n"
    "      e = e.replace(/=[?？]?$/, '').replace(/[?？]$/, '');\n"
    "      /* 数と四則だけの、かっこの無い式に限る */\n"
    "      if (!/^[0-9]+(\\.[0-9]+)?([+\\-*\\/][0-9]+(\\.[0-9]+)?){1,3}$/.test(e)) return null;\n"
    "      var v;\n"
    "      try { v = Function('\"use strict\";return (' + e + ')')(); } catch (e2) { return null; }\n"
    "      if (typeof v !== 'number' || !isFinite(v)) return null;\n"
    "      if (Math.abs(v - parseFloat(a)) < 1e-9) return null;   /* 合っている */\n"
    "      return true;                                           /* 合っていない */\n"
    "    } catch (e3) { return null; }\n"
    "  }\n"
    "  window._revMathBad = _revMathBad;\n"
    "\n"
    "  window._revOK = function(x){\n"
    "    try {\n"
    "      if (!x) { return false; }\n"
    "      if (_revMathBad(x) === true) { return false; }\n"
)

KEEP_HTML = [
    '__REVIEW_BADANS_A1__',
    'window._revOK = function',
    '__BATTLEUI_FIX_V1__',
    '__KUKU_UNIFY_V1__',
    '__REVIEW_BCD_V1__',
    '__PVE_GRADE_LOCK_V1__',
    'WILDIMG_V2',
    '二酸化炭素が発生',
    'function startReviewChallenge',
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
    if A_OLD in s:
        die('src/index.tsx が足場を配信チェーンで使っている（中止）')
    if '_revMathBad' in h:
        die('_revMathBad が既にある')

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
    if SENTINEL in s:
        die('src/index.tsx に番兵がある（中止）')

    h2 = h.replace(A_OLD, A_NEW, 1)
    if h2 == h:
        die('置換に失敗した')

    if h2.count(SENTINEL) != 1:
        die('番兵が %d件（想定 1件）' % h2.count(SENTINEL))
    if h2.count('function _revMathBad(x)') != 1:
        die('_revMathBad の定義が %d件（想定 1件）' % h2.count('function _revMathBad(x)'))
    if h2.count('if (_revMathBad(x) === true) { return false; }') != 1:
        die('_revMathBad の呼び出しが %d件（想定 1件）'
            % h2.count('if (_revMathBad(x) === true) { return false; }'))
    if h2.count('window._revOK = function') != 1:
        die('_revOK が %d件（想定 1件）' % h2.count('window._revOK = function'))
    if len(h2) != len(h) + (len(A_NEW) - len(A_OLD)):
        die('長さが想定と違う')
    for k in KEEP_HTML:
        if h2.count(k) != keep0[k]:
            die('目印の件数が変わった: %s (%d -> %d)' % (k, keep0[k], h2.count(k)))
    if '\r' in h2:
        die('CR が入った')

    with open(HTML, 'w', encoding='utf-8', newline='') as fp:
        fp.write(h2)

    print('OK: 検算を1か所追加 / chain %d（据え置き）/ %d -> %d バイト相当'
          % (n_chain, len(h), len(h2)))


if __name__ == '__main__':
    main()
