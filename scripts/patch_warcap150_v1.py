#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
__WARCAP150_V1__

攻略モード：自動でたまる学習パワーは ⚡150 までにする。
正解でもらう分（+12 +コンボ×2）は、150を超えて積める。

なぜ:
  このアプリは学習アプリで、戦うパワーは「問題に答えること」で得るのが本来の形。
  ところが自動回復だけで、90秒に 180（2.0/秒の11人）〜450（5.0/秒の6人）たまる。
  5.0/秒の6人は、一問も答えずに 80秒で コスト400の阪神マンが出せる。
  答える子でも、パワーの2〜4割は自動回復。学習の輪が飾りになっていた。

  「速さ」ではなく「上限」を切る。理由は、速さを下げると答える子まで遅くなるため。

  この形だと:
    - ⚡150以下のキャラ（373体中365体）は、自動だけで いままでと まったく同じ間隔で出せる。
      2.0/秒なら 31秒ごと、5.0/秒なら 12秒ごと（コスト62の場合）。詰む道がない。
    - ⚡200超の3体（阪神マン400・タナカティーチャー400・なしひろし400）は、
      自動だけでは 絶対に届かない。答えるしかない。
    - 正解ぶんは 150を超えて積めるので、答える子の総量は いままでと ほぼ同じ。
    - 速さUP強化を 取り上げない（150まで戻る速さが上がる価値は残る）。

  数字ひとつ（150）を戻せば 元どおりになる。

さわるファイル: src/index.tsx だけ。
public/ と migrations/ は読むだけで、1バイトも書かない。
アンカーが合わなければ、1文字も書かずに中止する（fail-closed）。
"""

import io
import os
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'

MARK = '__WARCAP150_V1__'

INSERT_ANCHOR = '    // __WORLD_V1__ 3周目「世界編」第1段（あそべる箱だけ）。中身は src/world_v1.ts。'

HTML_ANCHORS = [
    'ps.power += ps.baseRate * getPowerMultiplier() * dt;',
]

CHAIN_BEFORE = 111
CHAIN_AFTER = 112

BLOCK = r'''    // __WARCAP150_V1__ 攻略モード：自動でたまる学習パワーは ⚡150 まで。
    // 正解でもらう分（+12 +コンボ×2）は 150を超えて積める（_warOnAnswered 側は さわらない）。
    // ⚡150以下のキャラは 自動だけで いままでと同じ間隔で出せる（たまる速さは 変えていない）。
    // ⚡200超の3体は 自動だけでは 届かない。答えるしかない。
    // アンカーが無ければ console.error して飛ばす（throw するとチェーン全件が消えるため）。
    const _wcap0a = "ps.power += ps.baseRate * getPowerMultiplier() * dt;"
    const _wcap0b = "const _wcAuto = Math.min(Number(ps.powerMax||200), 150); if(ps.power < _wcAuto){ ps.power = Math.min(_wcAuto, ps.power + ps.baseRate * getPowerMultiplier() * dt); }"
    if (t.indexOf(_wcap0a) !== -1) { t = t.replace(_wcap0a, () => _wcap0b) } else { console.error('[__WARCAP150_V1__] anchor 0 not found') }

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
    if s.count('const _wcap0a = ') != 1 or s.count('const _wcap0b = ') != 1:
        print('NG: _wcap0a / _wcap0b が 一意で ない')
        ok = False
    if s.count('_wcAuto') < 2:
        print('NG: _wcAuto が 入っていない')
        ok = False
    for name in ('__WARCOST_V1__', '__WARCOSTUI_V1__'):
        if name not in s:
            print('NG: 先に入れた', name, 'が 消えている')
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

    for name in ('__WARCOST_V1__', '__WARCOSTUI_V1__'):
        if name not in s:
            print('NG: 先に', name, 'が 入っていない。順番が ちがう。')
            sys.exit(1)

    n_before = chain_count(s)
    if n_before != CHAIN_BEFORE:
        print('NG: 直前の チェーンが', n_before, '（', CHAIN_BEFORE, 'のはず）')
        sys.exit(1)
    print('chain before =', n_before)

    if not check_html_anchors(h):
        print('NG: public/index.html の アンカーが 合わない。中止する。')
        sys.exit(1)

    for name in ('_wcap0a', '_wcap0b', '_wcAuto'):
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
