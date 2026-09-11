# -*- coding: utf-8 -*-
"""DEF2TRY_STANDSTILL_GOAL_V1

「その場から うごかない」を、うごきを 決める ひょう（_cGoal）にも 足す。

なぜ もう1つ いるのか:
  さきに _pbBehavior に standStill を 足したが、
  ぶつかりあい（contact）の ときの 前後の うごきは _pbBehavior の adv では なく
  _cGoal(f) が act の 名前で 決めていた。
  _cGoal は 知らない 名前を ぜんぶ {adv:1} ＝「まっすぐ つっこむ」に していたので、
  standStill の あいてが つっこんで きていた。
  本番の 学習で ためした ところ、standStill の あいての ばしょが
  0.054 から 0.469 まで すすんで いた（実測）。これでは 的に ならない。

  ここを なおすと、standStill は 'wait' と おなじく
  いまの ばしょを たもつ（{adv:f.adv}）＝ ほんとうに うごかない、に なる。

さわるファイルは public/index.html の 1つだけ。
めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。
"""

import io
import sys

PATH = 'public/index.html'

# 冪等性の番兵（すでに流したかを 見るだけの しるし）
MARK = 'DEF2TRY_STANDSTILL_GOAL_MARK'

# 一意であることを たしかめる めじるし
ANCHOR = "if(act==='wait'||/^emote/.test(act)) return {adv:f.adv,ln:ln};"

# ふやす1行（検証条件は この文字列のほうを 数える）
ADDED = "if(act==='standStill') return {adv:f.adv,ln:ln};"

NEW = ADDED + " /* " + MARK + " */ "


def main():
    src = io.open(PATH, encoding='utf-8', newline='').read()

    if MARK in src:
        print('すでに 入っています。なにも しません。')
        return 0

    if ADDED in src:
        print('NG: 番兵は ないのに 中身だけ ある。手で たしかめてください。')
        return 1

    if 'DEF2TRY_STANDSTILL_MARK' not in src:
        print('NG: さきの standStill の パッチが 入っていません。')
        return 1

    n = src.count(ANCHOR)
    if n != 1:
        print('NG: めじるしが %d 件 みつかりました（1件でないと 流しません）' % n)
        return 1

    if src.count('function _cGoal(f){') != 1:
        print('NG: うごきの ひょうが 1つでは ありません')
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
        print('NG: ふやした 1行が %d 件です' % out.count(ADDED))
        return 1
    if out.count(ANCHOR) != 1:
        print('NG: もとの めじるしが こわれました')
        return 1
    if out.count(MARK) != 1:
        print('NG: 番兵が %d 件です' % out.count(MARK))
        return 1
    if out.count("case 'standStill': return {lane:null,adv:0,aggro:0};") != 1:
        print('NG: さきの パッチが こわれました')
        return 1

    io.open(PATH, 'w', encoding='utf-8', newline='').write(out)
    print('OK: うごきの ひょうにも standStill を 足しました（+%d 文字）' % len(NEW))
    return 0


if __name__ == '__main__':
    sys.exit(main())
