# -*- coding: utf-8 -*-
"""DEF2TRY_V1

防衛戦の プログラム欄の すぐ下に 「ためしバトル」 を 足す。

さわるのは 2つだけ:
  public/defense2.js  … 中身を 足す
  src/index.tsx       … よみこみの v を 1つ 上げる（チェーンの数は 変えない）

中身の 本体は scripts/def2try_block_v1.js に 別ファイルで おいてある。
めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。
"""

import io
import sys

D2 = 'public/defense2.js'
IDX = 'src/index.tsx'
BLOCK_SRC = 'scripts/def2try_block_v1.js'

# 冪等性の番兵（すでに流したかを 見るだけの しるし）
MARK = 'DEF2TRY_V1_MARK'

A_FUNC = '  function install(){'
A_CALL = '    tryMountEditor();\n  }\n  install();'
A_CALL_NEW = '    tryMountEditor(); tryMountTryBattle();\n  }\n  install();'

V_OLD = '/defense2.js' + '?v' + '=6'
V_NEW = '/defense2.js' + '?v' + '=7'


def read(p):
    return io.open(p, encoding='utf-8', newline='').read()


def main():
    d = read(D2)
    s = read(IDX)
    block = read(BLOCK_SRC)

    if MARK in d:
        print('すでに 入っています。なにも しません。')
        return 0

    if MARK not in block:
        print('NG: 足す中身に 番兵が ありません')
        return 1

    for label, text, t, want in (
        ('install の宣言', A_FUNC, d, 1),
        ('install の呼び出し', A_CALL, d, 1),
        ('いまの よみこみ v', V_OLD, s, 1),
        ('つぎの よみこみ v', V_NEW, s, 0),
        ('ためしバトルの入口', 'function tryMountTryBattle()', d, 0),
    ):
        c = t.count(text)
        if c != want:
            print('NG: めじるし %s が %d 件（期待 %d）' % (label, c, want))
            return 1

    d2 = d.replace(A_FUNC, block + A_FUNC, 1)
    d2 = d2.replace(A_CALL, A_CALL_NEW, 1)
    s2 = s.replace(V_OLD, V_NEW, 1)

    # 書きこむ前の 自己点検（どれか1つでも ちがえば 書かない）
    if d2 == d or s2 == s:
        print('NG: 書きかえが おきませんでした')
        return 1
    if d2.count(MARK) != 1:
        print('NG: 番兵が %d 件' % d2.count(MARK))
        return 1
    if d2.count('function tryMountTryBattle()') != 1:
        print('NG: 入口が %d 件' % d2.count('function tryMountTryBattle()'))
        return 1
    if d2.count('tryMountEditor(); tryMountTryBattle();') != 1:
        print('NG: 呼び出しが %d 件' % d2.count('tryMountEditor(); tryMountTryBattle();'))
        return 1
    if d2.count('btn.parentNode.insertBefore(box, btn)') != 1:
        print('NG: プログラム欄の 組みこみが こわれた')
        return 1
    if s2.count(V_NEW) != 1 or s2.count(V_OLD) != 0:
        print('NG: よみこみの v が おかしい')
        return 1
    if len(s2) != len(s):
        print('NG: index.tsx の 長さが 変わった')
        return 1
    if '/api/defense/entry' in block or '/api/defense/resolve' in block:
        print('NG: 足す中身が 本番の 出入口に さわろうとしている')
        return 1
    if 'method' in block:
        print('NG: 足す中身に 送信の けはいが ある')
        return 1

    io.open(D2, 'w', encoding='utf-8', newline='').write(d2)
    io.open(IDX, 'w', encoding='utf-8', newline='').write(s2)
    print('OK: ためしバトルを 足しました（defense2.js +%d 文字 / index.tsx は v だけ）' % (len(d2) - len(d)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
