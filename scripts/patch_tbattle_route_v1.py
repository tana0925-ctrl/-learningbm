# -*- coding: utf-8 -*-
# TBATTLE_ROUTE_V1
#
# public/ に置いた js は、そのままでは配信されない（404 になる）。
# src/index.tsx の `_g8files` の配列に名前を足すと、既存の for ループが
#   app.get('/' + ファイル名, ASSETS から読んで application/javascript で返す)
# を登録してくれる。その配列に tbattle.js と tbsub.js を足すだけ。
#
# 触るのは1行だけ。ハンドラは1つも書き足さない。
# app.get('/') の .replace( チェーンの本数が変わっていないことを、前後で数えて確かめる。
# 一致しなければ何も書かずに終了する（フェイルクローズ）。

import io
import sys

PATH = 'src/index.tsx'
OLD = "'hanshin_advice2.js']"
NEW = "'hanshin_advice2.js','tbattle.js','tbsub.js']"


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


def chain_of(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def main():
    raw = io.open(PATH, 'rb').read()
    if b'\r\n' in raw:
        die('src/index.tsx に CRLF が混ざっている。中止')
    s = raw.decode('utf-8')
    before_len = len(s)
    before_chain = chain_of(s)

    if "'tbattle.js'" in s and "'tbsub.js'" in s:
        print('すでに適用ずみ。何もしない')
        return

    for needle, want in (
        ("const _g8files = [", 1),
        (OLD, 1),
        ("'tbattle.js'", 0),
        ("'tbsub.js'", 0),
    ):
        got = s.count(needle)
        if got != want:
            die('アンカー %r が %d 件（期待 %d）' % (needle, got, want))

    out = s.replace(OLD, NEW)

    if len(out) - before_len != len(NEW) - len(OLD):
        die('差分の長さが合わない')
    after_chain = chain_of(out)
    if after_chain != before_chain:
        die('チェーンの本数が変わった（%d -> %d）' % (before_chain, after_chain))
    if out.count("'tbattle.js'") != 1 or out.count("'tbsub.js'") != 1:
        die('足した名前が1件ずつでない')

    with io.open(PATH, 'w', encoding='utf-8', newline='') as fp:
        fp.write(out)

    print('OK: chain=%d のまま、%d -> %d バイト' % (before_chain, before_len, len(out)))


if __name__ == '__main__':
    main()
