# -*- coding: utf-8 -*-
# TBATTLE_VER
#
# ターン制バトルの js を更新したときに、児童のブラウザが古いものを使い続けないように
# public/index.html の読み込み番号だけを上げる。
#   /tbsub.js?v=1   -> /tbsub.js?v=2
#   /tbattle.js?v=1 -> /tbattle.js?v=2
#
# 変えるのはこの2か所だけ。ほかの行は1文字も触らない。
# 一致しなければ何も書かずに終了する（フェイルクローズ）。
#
# 使い方: python3 scripts/patch_tbattle_ver.py <from> <to>

import io
import sys

PATH = 'public/index.html'
NAMES = ('tbsub.js', 'tbattle.js')


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


def main():
    if len(sys.argv) != 3:
        die('引数は <from> <to> の2つ')
    a, b = sys.argv[1], sys.argv[2]
    for v in (a, b):
        if not v.isdigit():
            die('番号は数字だけ: %r' % v)
    if a == b:
        die('from と to が同じ')

    raw = io.open(PATH, 'rb').read()
    if b'\r\n' in raw:
        die('public/index.html に CRLF が混ざっている。中止')
    html = raw.decode('utf-8')
    before = len(html)

    olds = ['/%s?v=%s' % (n, a) for n in NAMES]
    news = ['/%s?v=%s' % (n, b) for n in NAMES]

    done = 0
    for n in NAMES:
        if ('/%s?v=%s' % (n, b)) in html:
            done += 1
    if done == len(NAMES):
        print('すでに v=%s になっている。何もしない' % b)
        return

    for o in olds:
        c = html.count(o)
        if c != 1:
            die('%r が %d 件（期待 1）' % (o, c))
    for n in news:
        c = html.count(n)
        if c != 0:
            die('%r が すでに %d 件ある' % (n, c))

    out = html
    for o, n in zip(olds, news):
        out = out.replace(o, n)

    if len(out) - before != (len(b) - len(a)) * len(NAMES):
        die('差分の長さが合わない')
    for n in news:
        if out.count(n) != 1:
            die('%r が1件でない' % n)
    if out.count('TBATTLE_V1_MARK') != 1:
        die('目印が1件でない')

    with io.open(PATH, 'w', encoding='utf-8', newline='') as fp:
        fp.write(out)
    print('OK: v=%s -> v=%s（%d -> %d バイト）' % (a, b, before, len(out)))


if __name__ == '__main__':
    main()
