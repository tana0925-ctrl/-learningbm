#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# GRADE_RECENT_V1 : 学年の解禁に「直近」を足す＋進み具合を見せる
#
# ■ 何が問題だったか
#   解禁の条件は「1つ下の学年で合計100問正解かつ正答率80%以上」。
#   この正答率が「これまでの累計」なので、やり直しがきかない。
#   実測：累計 2037/3238 = 62.9% の児童は、80%に戻すには約3,000問を
#   ほぼ全問正解する必要があり、実質的な行き止まりになっていた。
#
# ■ このパッチがすること
#   (1) 累計 OR 直近のどちらかが条件を満たせば開く。
#       直近は trainingProgress[単元].recentAnswers（1単元あたり最大100件の正誤）を
#       その学年の全単元で合計する。新しく記録を貯める必要は無い
#       （D1の実測で 1,588件の単元記録すべてにあり、上限は100件）。
#       OR なので、いま開いている子が閉じることは構造的に起きない。
#       D1で児童28人分を変更前後で計算した結果：減る子 0人、新しく開く子 2人。
#   (2) 鍵のかかった「つぎの学年」を1つだけ、条件と進み具合つきで出す。
#       もとはコードのコメントに「事前告知UIなし」と書いてあり、
#       児童は上の学年があることすら気づけなかった。
#       同じアプリの世界編は「いま 12/47・ゾンビ 3/10」と出しているので、それに合わせる。
#
# ■ 触る範囲
#   public/g10core.js の2か所だけ。
#   public/index.html も src/index.tsx も触らない。
#   （g10core.js の script タグは配信チェーンが入れているので ?v= は上げられないが、
#    配信の cache-control は max-age=300 なので、遅くとも5分で入れ替わる）
#   g8core.js / g9core.js は触らない。D1 にも触らない。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

G10 = 'public/g10core.js'
HTML = 'public/index.html'
SRC = 'src/index.tsx'

SENTINEL = '__GRADE_RECENT_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"

A_OLD = (
    "  function gradeCleared(L) {\n"
    "    var s = gradeStats(L);\n"
    "    return (s.c >= NEED_CORRECT) && (s.t >= MIN_TOTAL) && ((s.c / s.t) >= NEED_ACC);\n"
    "  }"
)
A_NEW = (
    "  // " + SENTINEL + " 直近の成績。trainingProgress[単元].recentAnswers は\n"
    "  // 1単元あたり最大100件の正誤の記録（古いものから捨てられる）。\n"
    "  function recentStats(L) {\n"
    "    var c = 0, t = 0;\n"
    "    try {\n"
    "      var C = window.CURRICULUM; if (!C) return { c: 0, t: 0 };\n"
    "      var P = (typeof player !== 'undefined' && player) ? player : null;\n"
    "      if (!P) return { c: 0, t: 0 };\n"
    "      var tp = P.trainingProgress || {};\n"
    "      Object.keys(C).forEach(function (subj) {\n"
    "        var g = C[subj] && C[subj].grades && C[subj].grades[L];\n"
    "        if (!g || !g.units) return;\n"
    "        g.units.forEach(function (u) {\n"
    "          var pu = tp[u.id];\n"
    "          var ra = (pu && pu.recentAnswers && pu.recentAnswers.length) ? pu.recentAnswers : null;\n"
    "          if (!ra) return;\n"
    "          for (var i = 0; i < ra.length; i++) { t++; if (ra[i] === true) c++; }\n"
    "        });\n"
    "      });\n"
    "    } catch (e) {}\n"
    "    return { c: c, t: t };\n"
    "  }\n"
    "  G10.recentStats = recentStats;\n"
    "\n"
    "  // 累計 OR 直近。どちらかが条件を満たせば開く。\n"
    "  // 累計だけだと、昨年・昨月につまずいた子はどれだけがんばっても取り返せない。\n"
    "  // OR なので、いま開いている子が閉じることは起きない。\n"
    "  function gradeCleared(L) {\n"
    "    var s = gradeStats(L);\n"
    "    if ((s.c >= NEED_CORRECT) && (s.t >= MIN_TOTAL) && ((s.c / s.t) >= NEED_ACC)) return true;\n"
    "    var r = recentStats(L);\n"
    "    return (r.c >= NEED_CORRECT) && (r.t >= MIN_TOTAL) && ((r.c / r.t) >= NEED_ACC);\n"
    "  }"
)

B_OLD = (
    "      if (window.__gradeUnlocked(10)) addGrade10Button();\n"
    "    } catch (e) {}\n"
    "  }\n"
    "  G10.enforceButtons = enforceButtons;"
)
B_NEW = (
    "      if (window.__gradeUnlocked(10)) addGrade10Button();\n"
    "      addNextHint();\n"
    "    } catch (e) {}\n"
    "  }\n"
    "\n"
    "  // " + SENTINEL + " 鍵のかかった「つぎの学年」を1つだけ、進み具合つきで出す。\n"
    "  function addNextHint() {\n"
    "    try {\n"
    "      var wrap = document.getElementById('pveGradeSelectorWrap');\n"
    "      if (!wrap) return;\n"
    "      var old = document.getElementById('pveNextGradeHint');\n"
    "      if (old) old.remove();\n"
    "      var base = baseGrade();\n"
    "      var G = 0;\n"
    "      for (var g = base + 1; g <= 10; g++) { if (!window.__gradeUnlocked(g)) { G = g; break; } }\n"
    "      if (!G) return;\n"
    "      var L = G - 1;\n"
    "      var s = gradeStats(L), r = recentStats(L);\n"
    "      var c = Math.max(s.c, r.c);\n"
    "      var acc = 0;\n"
    "      if (s.t > 0) acc = Math.max(acc, s.c / s.t);\n"
    "      if (r.t > 0) acc = Math.max(acc, r.c / r.t);\n"
    "      var pct = Math.round(acc * 100);\n"
    "      var nm = LABEL[G] || (G + '年');\n"
    "      var msg;\n"
    "      if (c < NEED_CORRECT) {\n"
    "        msg = '\\u{1F512} ' + nm + 'は あと ' + (NEED_CORRECT - c) + '問 で ひらくよ（いま '\n"
    "            + c + '/' + NEED_CORRECT + '問・せいかい率 ' + pct + '%）';\n"
    "      } else if (acc < NEED_ACC) {\n"
    "        msg = '\\u{1F512} ' + nm + 'は せいかい率 8わり で ひらくよ（いま '\n"
    "            + pct + '%・' + NEED_CORRECT + '問は たっせい）';\n"
    "      } else {\n"
    "        msg = '\\u{1F513} ' + nm + 'が もうすぐ ひらくよ！';\n"
    "      }\n"
    "      var d = document.createElement('div');\n"
    "      d.id = 'pveNextGradeHint';\n"
    "      d.className = 'text-xs text-gray-600 text-center mt-1 px-2';\n"
    "      d.textContent = msg;\n"
    "      wrap.insertAdjacentElement('afterend', d);\n"
    "    } catch (e) {}\n"
    "  }\n"
    "  G10.enforceButtons = enforceButtons;"
)

KEEP_G10 = [
    'function gradeStats',
    'function baseGrade',
    'window.__gradeUnlocked',
    'G10.checkUnlock',
    'function enforceButtons',
    'function addGrade10Button',
    'NEED_CORRECT',
    'NEED_ACC',
    'LABEL',
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

    with open(G10, encoding='utf-8', newline='') as fp:
        g = fp.read()
    with open(SRC, encoding='utf-8', newline='') as fp:
        s = fp.read()

    if SENTINEL in g:
        print('SKIP: 番兵 %s があるので何もしない' % SENTINEL)
        return

    if g.count(A_OLD) != 1:
        die('(1)の足場が %d件（想定 1件）' % g.count(A_OLD))
    if g.count(B_OLD) != 1:
        die('(2)の足場が %d件（想定 1件）' % g.count(B_OLD))
    if 'recentStats' in g:
        die('recentStats が既にある')
    if 'pveNextGradeHint' in g:
        die('pveNextGradeHint が既にある')

    keep0 = {}
    for k in KEEP_G10:
        n = g.count(k)
        if n < 1:
            die('目印が無い: %s' % k)
        keep0[k] = n

    if s.count(ROOT_ANCHOR) != 1:
        die('ルートのアンカーが一意でない')
    n_chain = chain_count(s)
    if n_chain != expect_chain:
        die('チェーンが %d件（実測で渡された想定は %d件）' % (n_chain, expect_chain))
    for nm, a in (('(1)', A_OLD), ('(2)', B_OLD)):
        if a in s:
            die('src/index.tsx が %s の足場を使っている（中止）' % nm)

    g2 = g.replace(A_OLD, A_NEW, 1)
    if g2 == g:
        die('(1)の置換に失敗した')
    g3 = g2.replace(B_OLD, B_NEW, 1)
    if g3 == g2:
        die('(2)の置換に失敗した')

    if g3.count(SENTINEL) != 2:
        die('番兵が %d件（想定 2件）' % g3.count(SENTINEL))
    if g3.count('function recentStats(L)') != 1:
        die('recentStats が %d件（想定 1件）' % g3.count('function recentStats(L)'))
    if g3.count('function gradeCleared(L)') != 1:
        die('gradeCleared が %d件（想定 1件）' % g3.count('function gradeCleared(L)'))
    if g3.count('function addNextHint()') != 1:
        die('addNextHint が %d件（想定 1件）' % g3.count('function addNextHint()'))
    if g3.count('addNextHint();') != 1:
        die('addNextHint の呼び出しが %d件（想定 1件）' % g3.count('addNextHint();'))
    if g3.count('var r = recentStats(L);') != 1:
        die('OR判定が入っていない')
    want_len = len(g) + (len(A_NEW) - len(A_OLD)) + (len(B_NEW) - len(B_OLD))
    if len(g3) != want_len:
        die('長さが %d（想定 %d）' % (len(g3), want_len))
    for k in KEEP_G10:
        if g3.count(k) < keep0[k]:
            die('目印が減った: %s (%d -> %d)' % (k, keep0[k], g3.count(k)))

    with open(G10, 'w', encoding='utf-8', newline='') as fp:
        fp.write(g3)

    print('OK: g10core.js 2か所 / chain %d（据え置き）/ %d -> %d バイト'
          % (n_chain, len(g), len(g3)))


if __name__ == '__main__':
    main()
