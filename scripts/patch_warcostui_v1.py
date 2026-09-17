#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
__WARCOSTUI_V1__

攻略モード：パワーが足りないときに「重さ」と「あと何秒で出せるか」を見せる。

なぜ:
  ⚡コストの数字は もともと出撃ボタンに出ている（黄色い丸バッジ）。
  再出撃の待ち秒数（待ち 12.3s）も もともと出ている。
  出ていなかったのは「パワーが足りないとき、あと何秒で出せるか」だけ。
  コスト上限を400にしたので、ここが見えないと ただ出せないだけの画面になる。

  ★は使わない。このアプリには すでに★がある（ガチャのレア度。201〜218が★6）。
  「強さの★」を足すと ★の意味が2つになって 子どもが混乱する。
  しかも阪神マンは★6ではないので「★6じゃないのに いちばん重い」という食い違いが起きる。
  なので「おもい／ふつう／かるい」の言葉で出す。

  しきい値: ⚡200以上=おもい（999/153/152の3体だけ）、⚡90以上=ふつう、それ未満=かるい。

さわるファイル: src/index.tsx だけ。
public/ と migrations/ は読むだけで、1バイトも書かない。
アンカーが合わなければ、1文字も書かずに中止する（fail-closed）。
"""

import io
import os
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'

MARK = '__WARCOSTUI_V1__'

INSERT_ANCHOR = '    // __WORLD_V1__ 3周目「世界編」第1段（あそべる箱だけ）。中身は src/world_v1.ts。'

HTML_ANCHORS = [
    "if(hint) hint.textContent = 'パワー不足';",
]

CHAIN_BEFORE = 110
CHAIN_AFTER = 111

BLOCK = r'''    // __WARCOSTUI_V1__ 攻略モード：パワー不足のときに「重さ」と「あと何秒で出せるか」を見せる。
    // ⚡コストの数字と 再出撃の待ち秒数は もともと出ている。足りないのは「あと何秒か」だけだった。
    // ★は使わない（ガチャのレア度★と まぎれるため）。おもい/ふつう/かるい の言葉で出す。
    // アンカーが無ければ console.error して飛ばす（throw するとチェーン全件が消えるため）。
    const _wcui0a = "if(hint) hint.textContent = 'パワー不足';"
    const _wcui0b = "if(hint) hint.textContent = ((cost>=200?'おもい':(cost>=90?'ふつう':'かるい')) + '・こたえると はやくなる'); if(text) text.textContent = ('⚡' + cost + '  あと' + Math.max(1, Math.ceil((cost - Number(ps.power||0)) / Math.max(0.1, Number(ps.baseRate||2)))) + '秒');"
    if (t.indexOf(_wcui0a) !== -1) { t = t.replace(_wcui0a, () => _wcui0b) } else { console.error('[__WARCOSTUI_V1__] anchor 0 not found') }

'''


def read(path):
    if not os.path.exists(path):
        print('NG: ファイルが無い:', path)
        sys.exit(1)
    return io.open(path, encoding='utf-8', newline='').read()


def chain_count(s):
    if s.count("app.get('/', async (c) => {") != 1:
        print('NG: 家の入口が 一意で ない')
        sys.exit(1)
    if s.count("app.get('/logout'") != 1:
        print('NG: 出口が 一意で ない')
        sys.exit(1)
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def check_html_anchors(h):
    ok = True
    for k, a in enumerate(HTML_ANCHORS):
        n = h.count(a)
        if n != 1:
            print('NG: public/index.html の アンカー', k, 'が', n, '個（1個のはず）')
            ok = False
        else:
            print('ok: アンカー', k, 'は 一意')
    return ok


def verify():
    s = read(TSX)
    h = read(HTML)
    ok = True
    if s.count(MARK) < 1:
        print('NG: 番兵', MARK, 'が 無い')
        ok = False
    if s.count('const _wcui0a = ') != 1 or s.count('const _wcui0b = ') != 1:
        print('NG: _wcui0a / _wcui0b が 一意で ない')
        ok = False
    if s.count('こたえると はやくなる') < 1:
        print('NG: あたらしい文言が 入っていない')
        ok = False
    if s.count('__WARCOST_V1__') < 1:
        print('NG: 先に入れた WARCOST_V1 が 消えている')
        ok = False
    n = chain_count(s)
    if n != CHAIN_AFTER:
        print('NG: いまの チェーンが', n, '（', CHAIN_AFTER, 'のはず）')
        ok = False
    else:
        print('チェーン =', n)
    if not check_html_anchors(h):
        ok = False
    if not ok:
        sys.exit(1)
    print('VERIFY OK')


def apply():
    s = read(TSX)
    h = read(HTML)

    if MARK in s:
        print('すでに 当てずみ（', MARK, 'が ある）。なにも しない。')
        return

    if s.count(INSERT_ANCHOR) != 1:
        print('NG: 差しこみ位置が 一意で ない（', s.count(INSERT_ANCHOR), '個）')
        sys.exit(1)

    if '__WARCOST_V1__' not in s:
        print('NG: 先に WARCOST_V1 が 入っていない。順番が ちがう。')
        sys.exit(1)

    n_before = chain_count(s)
    if n_before != CHAIN_BEFORE:
        print('NG: 直前の チェーンが', n_before, '（', CHAIN_BEFORE, 'のはず）')
        sys.exit(1)
    print('chain before =', n_before)

    if not check_html_anchors(h):
        print('NG: public/index.html の アンカーが 合わない。中止する。')
        sys.exit(1)

    for name in ('_wcui0a', '_wcui0b'):
        if name in s:
            print('NG: 変数名', name, 'が すでに 使われている')
            sys.exit(1)

    out = s.replace(INSERT_ANCHOR, BLOCK + INSERT_ANCHOR, 1)

    n_after = chain_count(out)
    if n_after != CHAIN_AFTER:
        print('NG: 当てたあとの チェーンが', n_after, '（', CHAIN_AFTER, 'のはず）')
        sys.exit(1)
    print('chain after =', n_after)

    added = out.count('\n') - s.count('\n')
    if added != BLOCK.count('\n'):
        print('NG: 増えた行数が', added, '（', BLOCK.count('\n'), 'のはず）')
        sys.exit(1)

    io.open(TSX, 'w', encoding='utf-8', newline='').write(out)
    print('WROTE', TSX)
    print('  chain', n_before, '->', n_after)


if __name__ == '__main__':
    if '--verify' in sys.argv:
        verify()
    else:
        apply()
