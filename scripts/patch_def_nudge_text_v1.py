# -*- coding: utf-8 -*-
# DEF_NUDGE_TEXT_V1 : おさそいカードの 文を 事実に あわせる。
#   クラス全員が 出るように なったので、
#   「いちど とうろくすれば、つぎの日からは じどうで さんかできるよ」は もう ちがう。
#   とうろくの ねうちは いま「じぶんで えらんだ モンスターと プログラムで たたかえる」
#   「もらえるコインが ふえる」「ひょうしょうの たいしょうに なる」の3つ。
#   中身を かえたので、よみこみの ばんごうも 1つ すすめる。
#
# 1回流しても 2回流しても 同じ形（番兵 __DEF_NUDGE_TEXT_V1__）。
# 一致しないときは 何も書かずに 失敗で終わる（fail-closed）。

import io
import sys

NL = chr(10)
Q1 = chr(39)

JN_PATH = 'public/def_join_nudge.js'
INDEX_PATH = 'src/index.tsx'

SENTINEL = '__DEF_NUDGE_TEXT_V1__'

L2_OLD = '        ' + Q1 + 'きみのモンスターが 1ぴき ふえるだけで、クラスの まもる力が つよくなるんだ。' + Q1 + ' +'
L2_NEW = '        ' + Q1 + 'クラスの みんなは もう さんかしていて、きみの いちばん上の モンスターも 出ているよ。' + Q1 + ' +'

L3_OLD = '        ' + Q1 + 'いちど とうろくすれば、つぎの日からは じどうで さんかできるよ。' + Q1 + ' +'
L3_NEW = ('        ' + Q1 + 'とうろくすると、じぶんで えらんだ モンスターと プログラムで たたかえる。もらえるコインも ふえて、ひょうしょうにも 入れるよ。' + Q1 + ' +'
          + NL + '        /* ' + SENTINEL + ' クラス全員が 出るように なったので、文を 事実に あわせた */')

V_OLD = '/def_join_nudge.js?v=1'
V_NEW = '/def_join_nudge.js?v=2'


def read(path):
    return io.open(path, encoding='utf-8').read()


def write(path, text):
    io.open(path, 'w', encoding='utf-8', newline='').write(text)


def need_one(text, anchor, label):
    n = text.count(anchor)
    if n != 1:
        print('NG: %s のアンカーが %d 件（1 件でないので中止）' % (label, n))
        sys.exit(1)


def chain_count(text):
    i = text.index("app.get('/', async (c) => {")
    j = text.index("app.get('/logout'", i)
    return text[i:j].count('.replace(')


def main():
    jn = read(JN_PATH)
    s = read(INDEX_PATH)

    if SENTINEL in jn:
        print('すでに入っています（番兵 %s）。何もしません。' % SENTINEL)
        return

    need_one(jn, L2_OLD, 'おさそいの 2行目')
    need_one(jn, L3_OLD, 'おさそいの 3行目')
    need_one(s, V_OLD, 'よみこみの ばんごう')

    chain_before = chain_count(s)
    jn2 = jn.replace(L2_OLD, L2_NEW).replace(L3_OLD, L3_NEW)
    s2 = s.replace(V_OLD, V_NEW)
    chain_after = chain_count(s2)

    checks = [
        ('番兵', jn2.count(SENTINEL), 1),
        ('古い ことば', jn2.count('じどうで さんかできる'), 0),
        ('古い ことば2', jn2.count('1ぴき ふえるだけで'), 0),
        ('新しい ことば', jn2.count('もらえるコインも ふえて'), 1),
        ('新しい ことば2', jn2.count('もう さんかしていて'), 1),
        ('見出しは そのまま', jn2.count('ぼうえいせんに とうろくしよう'), 1),
        ('はじめの1文は そのまま', jn2.count('まいにち ひらかれているよ'), 1),
        ('ばんごう 2', s2.count(V_NEW), 1),
        ('ばんごう 1', s2.count(V_OLD), 0),
        ('よみこみの 道は そのまま', s2.count('def_join_nudge.js'), s.count('def_join_nudge.js')),
    ]
    bad = 0
    for label, got, want in checks:
        if got != want:
            print('NG: %s が %d 件（%d 件の予定）' % (label, got, want))
            bad += 1
    if bad:
        sys.exit(1)

    if chain_after != chain_before:
        print('NG: つなぎの数が %d から %d（ふえない予定）' % (chain_before, chain_after))
        sys.exit(1)

    write(JN_PATH, jn2)
    write(INDEX_PATH, s2)
    print('OK: 入れました。つなぎの数は %d のまま。' % chain_after)


main()
