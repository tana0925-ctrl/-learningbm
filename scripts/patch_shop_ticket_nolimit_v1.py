# -*- coding: utf-8 -*-
# TBTICKET_NOLIMIT_V1
#
# ショップの「バトルチケット」の 1日5枚までの上限を はずす。
# さわるのは buyItem の中の `if (sold >= 5)` 3か所だけ。
#   1) gym_ticket / egg_ticket の 入口のチェック
#   2) gym_ticket を 買うところ
#   3) egg_ticket を 買うところ
# 強化チケットの `if (sold >= 3)`（2か所）には ぜったいに さわらない。
# 値段の計算にも 他の商品にも さわらない。
#
# 一致しなければ 何も書かずに終了する（フェイルクローズ）。

import io
import sys

PATH = 'public/index.html'
OLD = 'if (sold >= 5)'
NEW = 'if (false /* TBTICKET_NOLIMIT_V1 1日の上限なし */)'
WANT = 3
KEEP = 'if (sold >= 3)'
KEEP_WANT = 2


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


def main():
    raw = io.open(PATH, 'rb').read()
    if b'\r\n' in raw:
        die('public/index.html に CRLF が混ざっている。中止')
    html = raw.decode('utf-8')
    before = len(html)

    if 'TBTICKET_NOLIMIT_V1' in html:
        print('すでに適用ずみ。何もしない')
        return

    got = html.count(OLD)
    if got != WANT:
        die('%r が %d 件（期待 %d）' % (OLD, got, WANT))
    keep = html.count(KEEP)
    if keep != KEEP_WANT:
        die('さわってはいけない %r が %d 件（期待 %d）' % (KEEP, keep, KEEP_WANT))

    out = html.replace(OLD, NEW)

    if out.count(OLD) != 0:
        die('置きかえ残りがある')
    if out.count('TBTICKET_NOLIMIT_V1') != WANT:
        die('目印が %d 件（期待 %d）' % (out.count('TBTICKET_NOLIMIT_V1'), WANT))
    if out.count(KEEP) != KEEP_WANT:
        die('強化チケットの上限を こわしている')
    if len(out) - before != (len(NEW) - len(OLD)) * WANT:
        die('差分の長さが合わない')
    # 値段の表は さわっていないこと
    for s in ("{ id: 'gym_ticket', name: 'バトルチケット', price: 50",
              "player.gymTickets = (player.gymTickets || 0) + 1;"):
        if out.count(s) != html.count(s):
            die('さわってはいけない所が変わった: %r' % s[:40])

    with io.open(PATH, 'w', encoding='utf-8', newline='') as fp:
        fp.write(out)
    print('OK: %d -> %d バイト（%d か所）' % (before, len(out), WANT))


if __name__ == '__main__':
    main()
