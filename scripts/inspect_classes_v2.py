#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# INSPECT_CLASSES_V2 : 教師ダッシュボード ⑥クラス・名簿 の後半を読み出すだけ。
# ・src/index.tsx は 1バイトも書き換えない（読むだけ）。
# ・V1 で 820371〜831507 は読めたので、その続きを出す。

import sys

SRC = 'src/index.tsx'
ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"


def main():
    with open(SRC, encoding='utf-8', newline='') as fp:
        s = fp.read()

    print('LEN %d' % len(s))
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    print('CHAIN %d' % s[i:j].count('.replace('))

    base = s.index('function renderClasses')
    start = s.index('★逃げ道：必要人数を下げる', base)
    end = min(len(s), start + 13500)
    print('REGION %d .. %d (%d chars)' % (start, end, end - start))

    chunk = 700
    p = start
    while p < end:
        q = min(p + chunk, end)
        print('--- %d' % p)
        print(repr(s[p:q]))
        p = q

    print('DONE')


if __name__ == '__main__':
    main()
