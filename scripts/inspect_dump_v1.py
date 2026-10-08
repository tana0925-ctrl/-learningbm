#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# INSPECT_DUMP_V1 : どのファイルでも「目印のまわり」を読み出すだけの道具。
#
# ・ファイルには1バイトも書かない（読むだけ）。
# ・GitHub のウェブ画面では巨大ファイルの中身が見えないので、Actions のログで読む。
# ・grep -c は使わない。
#
# 使い方（workflow_dispatch の入力）
#   file       : 読むファイル（例 public/index.html）
#   anchor     : 目印の文字列
#   occurrence : 何個目の目印か（1 から。既定 1）
#   before     : 目印の何文字前から出すか（既定 300）
#   after      : 目印の何文字後まで出すか（既定 4000）

import os
import sys

MAX_SPAN = 30000


def env(name, default=''):
    return (os.environ.get(name) or default).strip()


def main():
    path = env('IN_FILE')
    anchor = os.environ.get('IN_ANCHOR') or ''
    if not path or not anchor:
        sys.stderr.write('FAIL: file と anchor は必須\n')
        sys.exit(1)

    try:
        occ = max(1, int(env('IN_OCC', '1')))
    except ValueError:
        occ = 1
    try:
        before = max(0, int(env('IN_BEFORE', '300')))
    except ValueError:
        before = 300
    try:
        after = max(0, int(env('IN_AFTER', '4000')))
    except ValueError:
        after = 4000

    if before + after > MAX_SPAN:
        sys.stderr.write('FAIL: before+after が大きすぎる（上限 %d）\n' % MAX_SPAN)
        sys.exit(1)

    with open(path, encoding='utf-8', newline='') as fp:
        s = fp.read()

    total = s.count(anchor)
    print('FILE %s' % path)
    print('LEN %d' % len(s))
    print('ANCHOR_COUNT %d' % total)
    if total < occ:
        sys.stderr.write('FAIL: 目印が %d 件しかない（%d 個目を求められた）\n' % (total, occ))
        sys.exit(1)

    p = -1
    for _ in range(occ):
        p = s.find(anchor, p + 1)
    print('ANCHOR_AT %d' % p)

    start = max(0, p - before)
    end = min(len(s), p + len(anchor) + after)
    print('REGION %d .. %d (%d chars)' % (start, end, end - start))

    chunk = 700
    q = start
    while q < end:
        r = min(q + chunk, end)
        print('--- %d' % q)
        print(repr(s[q:r]))
        q = r

    print('DONE')


if __name__ == '__main__':
    main()
