# -*- coding: utf-8 -*-
# TBATTLE_V1
#
# 児童ページ（public/index.html）に、ターン制バトル（オマケ）の script タグ2本を足すだけ。
# ほかの行は1文字も変えない。画面も入口も tbattle.js が実行時に自分で作る。
#
# public/index.html は 5.8MB・改行は LF。手で開いて編集しないこと。
# ここ以外から書き換えないこと。
#
# 一致しなければ何も書かずに終了する（フェイルクローズ）。

import io
import os
import sys

MARK = 'TBATTLE_V1_MARK'
PATH = 'public/index.html'
TAGS = (
    '\n<!-- ' + MARK + ' ターン制バトル（オマケ）。既存バトル7種には触っていません -->\n'
    '<script src="/tbsub.js?v=1"></script>\n'
    '<script src="/tbattle.js?v=1"></script>\n'
)


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


def main():
    for f in ('public/tbsub.js', 'public/tbattle.js'):
        if not os.path.exists(f):
            die(f + ' が無い。先にこの2本をコミットすること')

    raw = io.open(PATH, 'rb').read()
    if b'\r\n' in raw:
        die('public/index.html に CRLF が混ざっている。中止')
    html = raw.decode('utf-8')
    before = len(html)

    if MARK in html:
        print('すでに適用ずみ。何もしない')
        return

    checks = (
        ('</body>', 1),
        ('/tbattle.js', 0),
        ('/tbsub.js', 0),
        ('screen-tbattle', 0),
        (MARK, 0),
    )
    for needle, want in checks:
        got = html.count(needle)
        if got != want:
            die('アンカー %r が %d 件（期待 %d）' % (needle, got, want))
    print('アンカーはすべて期待どおり')

    i = html.rindex('</body>')
    out = html[:i] + TAGS + html[i:]

    if len(out) - before != len(TAGS):
        die('差分の長さが合わない（%d != %d）' % (len(out) - before, len(TAGS)))
    if out.count('</body>') != 1:
        die('</body> が1件でなくなった')
    if out.count('<script src="/tbattle.js?v=1"></script>') != 1:
        die('tbattle.js の読み込みが1件でない')

    with io.open(PATH, 'w', encoding='utf-8', newline='') as fp:
        fp.write(out)

    print('OK: %d -> %d バイト（+%d 文字）' % (before, len(out), len(TAGS)))


if __name__ == '__main__':
    main()
