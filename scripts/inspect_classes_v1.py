#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# INSPECT_CLASSES_V1 : 教師ダッシュボード ⑥クラス・名簿 の組み立てを読み出すだけ。
#
# ・src/index.tsx は 1バイトも書き換えない（読むだけ）。
# ・renderClasses() のクラス見出し行まわりを repr() で出す。
#   GitHub のウェブ画面では巨大行のため中身が見えないので、Actions のログで読む。
# ・grep -c は使わない（この台本は Python なので数え間違いは起きない）。

import sys

SRC = 'src/index.tsx'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"


def positions(s, k, limit=12):
    out = []
    p = -1
    while True:
        p = s.find(k, p + 1)
        if p < 0:
            break
        out.append(p)
        if len(out) >= limit:
            break
    return out


def main():
    with open(SRC, encoding='utf-8', newline='') as fp:
        s = fp.read()

    print('LEN %d' % len(s))
    print('LINES %d' % (s.count('\n') + 1))

    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    print('CHAIN %d' % s[i:j].count('.replace('))

    marks = [
        'function renderClasses',
        'justify-between mb-3',
        'mt-3 pt-3 border-t',
        'kht-banner',
        'kht-body',
        'kht-ctrl',
        'kht-pending',
        'border-red-200',
        'white-space',
        'flex-wrap',
        'tspOpenBtn',
        'qnFab',
        '__CLASSES_TIDY_V1__',
    ]
    for m in marks:
        print('MARK %-26s n=%-3d at=%s' % (m, s.count(m), positions(s, m)))

    base = s.index('function renderClasses')
    start = s.index('justify-between mb-3', base)
    # 削除ボタンの少しあとまで
    end = s.index('border-red-200', start) + 900
    start = max(0, start - 500)
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
