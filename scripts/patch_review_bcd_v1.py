#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# REVIEW_BCD_V1 : favicon / 403の抑止 / 単元名の表示 / 復習に選択肢を残す
#
# (1) favicon
#     <link rel="icon"> が無く、全員の全アクセスで /favicon.ico が 404 になっていた。
#     ファイルを足さず、data URL の1行で済ませる。
#
# (2)(3) /api/student/ranking-rewards の 403
#     checkRankingRewards() と updateRewardBadge() が、ログイン状態に関係なく
#     DOMContentLoaded + 3.5秒 / + 4.2秒 のタイマーで必ず叩いていた。
#     ログイン前や、先生の admin では role が student でないので 403 になる。
#     サーバ側は正しく、児童のかけらは決済時にサーバで付与済み（D1で全員16人分突き合わせ済み）。
#     呼ぶ前に role を見る。児童のログイン前の分も消える。
#
# (4) 復習リストに選択肢を残す
#     四択の問題をまちがえたとき、選択肢はその場にあるのに捨てていた。
#     cur.opts に残しておけば、あとで復習を四択にできる（ダミーを作る必要がない）。
#     ※ 正解テキストを保存する側（B）は、src/index.tsx の配信チェーンが
#       すでに .replace() で入れ替えているので、ここでは触らない。
#       （その行はチェーンの足場なので、書きかえるとチェーンが外れる）
#
# (5) 単元名の表示
#     _modeLabel() は 8個の固定表しか知らず、CURRICULUM の196単元は
#     内部IDがそのまま出ていた（「m6-frac-mul」など）。CURRICULUM を先に引く。
#
# ■ 触る範囲
#   public/index.html の5か所だけ。手では触らず、この台本で当てる。
#   src/index.tsx は1バイトも触らない（配信チェーンを崩さない）。
#   5つの足場がどれも src/index.tsx に無いことを実測してあるが、台本でも確かめる。
#   D1 には触らない。
#
# 前提が1つでも崩れたら、ファイルに書かずに exit 1（フェイルクローズ）。

import os
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'

SENTINEL = '__REVIEW_BCD_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"

ICON = ('data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A%2F%2Fwww.w3.org%2F2000%2Fsvg%22'
        '%20viewBox%3D%220%200%2032%2032%22%3E%3Ctext%20y%3D%2226%22%20font-size%3D%2226%22'
        '%3E%F0%9F%8C%8F%3C%2Ftext%3E%3C%2Fsvg%3E')

EDITS = [
    # (1) favicon
    ('favicon',
     '<head>\n\n<script>/* GLOBAL_CLAMP */',
     '<head>\n<!-- ' + SENTINEL + ' タブのアイコン。ファイルを置かず data URL で済ませる -->\n'
     '<link rel="icon" href="' + ICON + '">\n\n<script>/* GLOBAL_CLAMP */'),

    # (2) ごほうびバッジ：児童でログイン済みのときだけ叩く
    ('badge',
     'window.updateRewardBadge=async function(){ try{ var n=0;',
     'window.updateRewardBadge=async function(){'
     ' if(window.__loggedInRole!==\'student\') return;'
     ' try{ var n=0;'),

    # (3) ごほうびのお知らせ：同じくログイン済みのときだけ
    ('checkRanking',
     "function checkRankingRewards(){\n  try{\n    fetch('/api/student/ranking-rewards')",
     "function checkRankingRewards(){\n"
     "  if(window.__loggedInRole!=='student') return;\n"
     "  try{\n    fetch('/api/student/ranking-rewards')"),

    # (4) まちがえた四択の選択肢を残す
    ('opts',
     '        cur.ans = ans;\n        player.wrongQuestions[key] = cur;',
     '        cur.ans = ans;\n'
     '        /* ' + SENTINEL + ' 四択の選択肢を残す（あとで復習を四択にできるように） */\n'
     '        try{ if(trainingQ && Array.isArray(trainingQ.options)'
     ' && trainingQ.options.length>=2){'
     ' cur.opts = trainingQ.options.slice(0,4).map(function(o){'
     ' return String(o==null?\'\':o); }); } }catch(e){}\n'
     '        player.wrongQuestions[key] = cur;'),

    # (5) 単元名を CURRICULUM から引く
    ('modeLabel',
     'function _modeLabel(mode){\n    const labels = {',
     'function _modeLabel(mode){\n'
     '    /* ' + SENTINEL + ' まず CURRICULUM から単元名を引く（196単元）。\n'
     '       下の固定表は8個しか無く、残りは内部IDがそのまま出ていた。 */\n'
     '    try {\n'
     '      var _C = window.CURRICULUM;\n'
     '      if (_C) {\n'
     '        for (var _sk in _C) {\n'
     '          var _gs = _C[_sk] && _C[_sk].grades; if (!_gs) continue;\n'
     '          for (var _gk in _gs) {\n'
     '            var _us = _gs[_gk] && _gs[_gk].units; if (!_us) continue;\n'
     '            for (var _i = 0; _i < _us.length; _i++) {\n'
     '              if (_us[_i] && _us[_i].id === mode && _us[_i].name) return _us[_i].name;\n'
     '            }\n'
     '          }\n'
     '        }\n'
     '      }\n'
     '    } catch (e) {}\n'
     '    const labels = {'),
]

KEEP_HTML = [
    'function recordWrongProblem',
    "const ans = (trainingQ && trainingQ.ans !== undefined) ? String(trainingQ.ans) : '';",
    'function checkRankingRewards',
    'window.updateRewardBadge',
    'function _modeLabel',
    '__KUKU_UNIFY_V1__',
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

    for name, old, new in EDITS:
        if h.count(old) != 1:
            die('%s の足場が %d件（想定 1件）' % (name, h.count(old)))
        if old in s:
            die('src/index.tsx が %s の足場を配信チェーンで使っている（中止）' % name)

    if 'rel="icon"' in h:
        die('favicon が既にある')
    if 'cur.opts' in h:
        die('cur.opts が既にある')
    if '__loggedInRole!==' in h:
        die('role の見張りが既にある')

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

    h2 = h
    delta = 0
    for name, old, new in EDITS:
        before = h2
        h2 = h2.replace(old, new, 1)
        if h2 == before:
            die('%s の置換に失敗した' % name)
        delta += len(new) - len(old)

    if h2.count(SENTINEL) != 3:
        die('番兵が %d件（想定 3件）' % h2.count(SENTINEL))
    if h2.count('rel="icon"') != 1:
        die('favicon が %d件（想定 1件）' % h2.count('rel="icon"'))
    if h2.count('__loggedInRole!==') != 2:
        die('role の見張りが %d件（想定 2件）' % h2.count('__loggedInRole!=='))
    if h2.count('cur.opts = trainingQ.options.slice(0,4)') != 1:
        die('選択肢の保存が %d件（想定 1件）'
            % h2.count('cur.opts = trainingQ.options.slice(0,4)'))
    if h2.count('_us[_i].id === mode') != 1:
        die('単元名の引きが %d件（想定 1件）' % h2.count('_us[_i].id === mode'))
    if len(h2) != len(h) + delta:
        die('長さが %d（想定 %d）' % (len(h2), len(h) + delta))
    for k in KEEP_HTML:
        if h2.count(k) != keep0[k]:
            die('目印の件数が変わった: %s (%d -> %d)' % (k, keep0[k], h2.count(k)))
    if '\r' in h2:
        die('CR が入った')

    with open(HTML, 'w', encoding='utf-8', newline='') as fp:
        fp.write(h2)

    print('OK: 5か所 / chain %d（据え置き）/ %d -> %d バイト相当'
          % (n_chain, len(h), len(h2)))


if __name__ == '__main__':
    main()
