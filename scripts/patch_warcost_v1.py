#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
__WARCOST_V1__

攻略モードの「出撃コスト上限」と「再出撃の上限」をあげる。
あわせて「まちがえると出撃クールダウンが0に戻る」をやめる。

なぜ:
  攻略モードのコストは
      cost = clamp( (体力*0.55 + こうげき*4 + ぼうぎょ*0.8 + はやさ*0.5) / 6 , 30, 160)
  で決まる。ところが上限160で切られているため、
      阪神マン(999) 本来928 -> 160   (5.8ばいの値引き)
      タナカティーチャー(153) 840 -> 160
      なしひろし(152) 516 -> 160
      にゃんこ大先生(981) 171 -> 160 (ほぼ影響なし)
  の4体だけが安く出せている。373体中、残り369体はすでに式どおりの値段を
  払っているので、上限をあげても1も動かない（巻き添えゼロ）。

  再出撃の待ち時間も同じ理由で上限12秒に張り付いていたので30秒にする。

  さらに _warOnAnswered の不正解側が globalSpawnCd と slotCd を0に戻していた。
  まちがえるほど早く出撃できることになり、学習アプリとして逆なので、その2行を消す。

さわるファイル: src/index.tsx だけ。
public/ と migrations/ は読むだけで、1バイトも書かない。
アンカーが1つでも合わなければ、1文字も書かずに中止する（fail-closed）。
"""

import io
import os
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'

MARK = '__WARCOST_V1__'

# src/index.tsx の中で、この行の直前にブロックを差しこむ
INSERT_ANCHOR = '    // __WORLD_V1__ 3周目「世界編」第1段（あそべる箱だけ）。中身は src/world_v1.ts。'

# public/index.html の中で当てにいく3つのアンカー（当てるのは実行時。ここでは存在確認だけ）
HTML_ANCHORS = [
    'const move = 5 + clamp(spd,5,200)/14;  // ゆっくり行軍（にゃんこ風の「間」）\n'
    '    const cost = clamp(Math.round((hp*0.55 + atk*4 + def*0.8 + spd*0.5)/6), 30, 160);',
    'return clamp(sec, 2.5, 12);',
    '\n      warState.globalSpawnCd = 0;\n      warState.slotCd = [0,0,0];',
]

CHAIN_BEFORE = 106
CHAIN_AFTER = 109

BLOCK = r'''    // __WARCOST_V1__ 攻略モード：出撃コストの上限と 再出撃の上限を あげる。
    // コストは (体力*0.55 + こうげき*4 + ぼうぎょ*0.8 + はやさ*0.5)/6 で決まるのに 上限160で切られていた。
    // 373体のうち 上限160に当たるのは 999(本来928) / 153(840) / 152(516) / 981(171) の4体だけ。
    // 残り369体は すでに式どおりの値段なので この変更で 1も動かない（巻き添えゼロ）。
    // あわせて まちがえたときに 出撃クールダウンが 0に戻る（まちがえるほど早く出せる）のを やめる。
    // アンカーが無ければ console.error して飛ばす（throw するとチェーン全件が消えるため）。
    const _wcst0a = "const move = 5 + clamp(spd,5,200)/14;  // ゆっくり行軍（にゃんこ風の「間」）\n    const cost = clamp(Math.round((hp*0.55 + atk*4 + def*0.8 + spd*0.5)/6), 30, 160);"
    const _wcst0b = "const move = 5 + clamp(spd,5,200)/14;  // ゆっくり行軍（にゃんこ風の「間」）\n    const cost = clamp(Math.round((hp*0.55 + atk*4 + def*0.8 + spd*0.5)/6), 30, 400);"
    if (t.indexOf(_wcst0a) !== -1) { t = t.replace(_wcst0a, () => _wcst0b) } else { console.error('[__WARCOST_V1__] anchor 0 not found') }
    const _wcst1a = "return clamp(sec, 2.5, 12);"
    const _wcst1b = "return clamp(sec, 2.5, 30);"
    if (t.indexOf(_wcst1a) !== -1) { t = t.replace(_wcst1a, () => _wcst1b) } else { console.error('[__WARCOST_V1__] anchor 1 not found') }
    const _wcst2a = "\n      warState.globalSpawnCd = 0;\n      warState.slotCd = [0,0,0];"
    const _wcst2b = ""
    if (t.indexOf(_wcst2a) !== -1) { t = t.replace(_wcst2a, () => _wcst2b) } else { console.error('[__WARCOST_V1__] anchor 2 not found') }

'''


def read(path):
    if not os.path.exists(path):
        print('NG: ファイルが無い:', path)
        sys.exit(1)
    return io.open(path, encoding='utf-8', newline='').read()


def chain_count(s):
    """app.get('/') から app.get('/logout') までの .replace( の数を実測する"""
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
    if s.count('const _wcst0a = ') != 1 or s.count('const _wcst1a = ') != 1 or s.count('const _wcst2a = ') != 1:
        print('NG: _wcst0a / _wcst1a / _wcst2a が 一意で ない')
        ok = False
    if s.count('30, 400);') < 1:
        print('NG: 新しいコスト上限 400 が 入っていない')
        ok = False
    if s.count('return clamp(sec, 2.5, 30);') < 1:
        print('NG: 新しい再出撃上限 30 が 入っていない')
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

    # --- 先に ぜんぶ 確かめる。1つでもダメなら 1文字も 書かない ---
    if MARK in s:
        print('すでに 当てずみ（', MARK, 'が ある）。なにも しない。')
        return

    if s.count(INSERT_ANCHOR) != 1:
        print('NG: 差しこみ位置が 一意で ない（', s.count(INSERT_ANCHOR), '個）')
        sys.exit(1)

    n_before = chain_count(s)
    if n_before != CHAIN_BEFORE:
        print('NG: 直前の チェーンが', n_before, '（', CHAIN_BEFORE, 'のはず）')
        sys.exit(1)
    print('chain before =', n_before)

    if not check_html_anchors(h):
        print('NG: public/index.html の アンカーが 合わない。中止する。')
        sys.exit(1)

    for name in ('_wcst0a', '_wcst0b', '_wcst1a', '_wcst1b', '_wcst2a', '_wcst2b'):
        if name in s:
            print('NG: 変数名', name, 'が すでに 使われている')
            sys.exit(1)

    # --- ここから 書く ---
    out = s.replace(INSERT_ANCHOR, BLOCK + INSERT_ANCHOR, 1)

    if len(out) <= len(s):
        print('NG: 長さが 増えていない')
        sys.exit(1)

    n_after = chain_count(out)
    if n_after != CHAIN_AFTER:
        print('NG: 当てたあとの チェーンが', n_after, '（', CHAIN_AFTER, 'のはず）')
        sys.exit(1)
    print('chain after =', n_after)

    # 行は 足すだけ。消していないことを 確かめる
    added = out.count('\n') - s.count('\n')
    if added != BLOCK.count('\n'):
        print('NG: 増えた行数が', added, '（', BLOCK.count('\n'), 'のはず）')
        sys.exit(1)
    if s.replace(INSERT_ANCHOR, BLOCK + INSERT_ANCHOR, 1) != out:
        print('NG: 差しこみ結果が 合わない')
        sys.exit(1)

    io.open(TSX, 'w', encoding='utf-8', newline='').write(out)
    print('WROTE', TSX)
    print('  chain', n_before, '->', n_after)


if __name__ == '__main__':
    if '--verify' in sys.argv:
        verify()
    else:
        apply()
