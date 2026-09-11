# -*- coding: utf-8 -*-
"""DEF2TRY_STANDSTILL_V1

たたかいの エンジンに 「その場から うごかない」 を 1つだけ ふやす。

さわるファイルは public/index.html の 1つだけ。
めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。

なぜ いるのか:
  いまの エンジンには 「ぜんぜん 動かない」 ふるまいが ない。
  'wait'（その場で まつ）でも adv:0.5 で 半分 前に 出てしまう。
  ためしバトルの 「うごかない まと」 が 半分 動いてしまうと、
  子どもが 「じぶんの プログラムの せいか、あいての せいか」 を
  切りわけられない。それでは ためしバトルの ねうちが なくなる。
"""

import io
import sys

PATH = 'public/index.html'

# 冪等性の番兵（すでに流したかを 見るだけの しるし）
MARK = 'DEF2TRY_STANDSTILL_MARK'

# 一意であることを たしかめる めじるし
ANCHOR = "case 'wait': return {lane:null,adv:0.5,aggro:0.85};"

# ふやす1行（検証条件は この文字列のほうを 数える）
ADDED = "case 'standStill': return {lane:null,adv:0,aggro:0};"

NEW = ADDED + " /* " + MARK + " */ "


def main():
    src = io.open(PATH, encoding='utf-8', newline='').read()

    if MARK in src:
        print('すでに 入っています。なにも しません。')
        return 0

    if ADDED in src:
        print('NG: 番兵は ないのに 中身だけ ある。手で たしかめてください。')
        return 1

    n = src.count(ANCHOR)
    if n != 1:
        print('NG: めじるしが %d 件 みつかりました（1件でないと 流しません）' % n)
        return 1

    out = src.replace(ANCHOR, NEW + ANCHOR, 1)

    # 書きこむ前の 自己点検（どれか1つでも ちがえば 書かない）
    if out == src:
        print('NG: 書きかえが おきませんでした')
        return 1
    if len(out) - len(src) != len(NEW):
        print('NG: ふえた 文字数が あいません')
        return 1
    if out.count(ADDED) != 1:
        print('NG: ふやした 1行が %d 件です（1件で ないと だめ）' % out.count(ADDED))
        return 1
    if out.count(ANCHOR) != 1:
        print('NG: もとの めじるしが こわれました')
        return 1
    if out.count(MARK) != 1:
        print('NG: 番兵が %d 件です' % out.count(MARK))
        return 1

    io.open(PATH, 'w', encoding='utf-8', newline='').write(out)
    print('OK: standStill を 1つ ふやしました（+%d 文字）' % len(NEW))
    return 0


if __name__ == '__main__':
    sys.exit(main())
