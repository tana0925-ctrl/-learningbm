# -*- coding: utf-8 -*-
"""DEF2TRY_NOWLABEL_V1

あたまの上の 「いま：」に standStill という 英語が そのまま 出ていた。
うごきの 名まえの ひょう（_GC_ACTSHORT）に 「うごかない」が
入っていなかったのが げんいん。名まえを 1つ 足すだけ。

さわるのは 1つだけ:
  public/index.html

めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。
"""

import io
import sys

H = 'public/index.html'

# 冪等性の番兵（すでに流したかを 見るだけの しるし）
MARK = 'DEF2TRY_NOWLABEL_V1_MARK'

A_OLD = ",wait:'まつ',emoteCheer:'おうえん📣'"
A_NEW = ",/* " + MARK + " */standStill:'うごかない',wait:'まつ',emoteCheer:'おうえん📣'"


def main():
    h = io.open(H, encoding='utf-8', newline='').read()

    if MARK in h:
        print('すでに 入っています。なにも しません。')
        return 0

    c = h.count(A_OLD)
    if c != 1:
        print('NG: めじるしが %d 件（1件で ないので 止めます）' % c)
        return 1
    if "standStill:'うごかない'" in h:
        print('NG: もう 名まえが あります')
        return 1

    h2 = h.replace(A_OLD, A_NEW, 1)

    if h2 == h:
        print('NG: 書きかえが おきませんでした')
        return 1
    if h2.count(MARK) != 1:
        print('NG: しるしの数が おかしい')
        return 1
    if h2.count("standStill:'うごかない'") != 1:
        print('NG: 足した数が おかしい')
        return 1
    if h2.count("wait:'まつ'") != 1:
        print('NG: まつ が こわれました')
        return 1
    if len(h2) - len(h) != len(A_NEW) - len(A_OLD):
        print('NG: ふえた 文字数が おかしい')
        return 1

    io.open(H, 'w', encoding='utf-8', newline='').write(h2)
    print('OK: 「いま：」の 名まえに うごかない を 足しました')
    return 0


if __name__ == '__main__':
    sys.exit(main())
