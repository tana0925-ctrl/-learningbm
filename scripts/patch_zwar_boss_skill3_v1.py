#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ZWAR_BOSS_SKILL3_V1
#
# 県ボス10体（ID 982〜991）は moves 配列を持っていない（持っているのは skills）。
# ところが戦闘コードは mon.moves[2] しか見ていないので、10体とも
# 3つ目のスキルが一度も発動していない。
#
# 直すこと（1件）:
#   ボスを出す warTrySpawnBoss の中だけ、moves が無いときに skills を見る。
#   雑魚敵やプレイヤー側のユニットの読み取りには一切触らない
#   （同じ形の行は他に4か所あるので、2行まとめのアンカーで ボスの1か所だけを指す）。
#
# public/index.html は手で触らない。src/index.tsx の app.get('/') の
# .replace() チェーンに1件足す形で当てる。
#
# 配信されるコード側では絶対に throw しない。
# アンカーが見つからなければ「適用せず console.error を出すだけ」。
#
# パッチを当てる側は fail-closed。前提が1つでも崩れたら1文字も書かずに exit 1。

import json
import os
import sys

NL = chr(10)

SRC = 'src/index.tsx'
HTML = 'public/index.html'

SENTINEL = '__ZWAR_BOSS_SKILL3_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
INSERT_AT = NL + '    _rootHtmlCache = t' + NL

# 流す直前に実測する値（ZWAR_CASTLE_STAND_V1 のあと）
CHAIN_BEFORE = 101
CHAIN_ADD = 1
CHAIN_AFTER = CHAIN_BEFORE + CHAIN_ADD

# ボスを出すところ「だけ」を指す2行のアンカー。
# （1行目の atkInterval の行は public/index.html に1件しかない）
A_OLD = NL.join([
    '  const atkInterval = clamp(1100 - (mon.spd||30)*6, 420, 1100);',
    '  const m3 = (mon && Array.isArray(mon.moves) && mon.moves[2]) ? mon.moves[2] : null;',
])
A_LEN = 149

A_NEW = NL.join([
    '  const atkInterval = clamp(1100 - (mon.spd||30)*6, 420, 1100);',
    '  // ' + SENTINEL + ' : 県ボスは moves を持たず skills を持っている。moves が無いときだけ skills を見る。',
    '  const m3 = (function(){',
    '    try{',
    '      var _mv = (mon && Array.isArray(mon.moves) && mon.moves.length) ? mon.moves : null;',
    '      var _sk = (!_mv && mon && Array.isArray(mon.skills) && mon.skills.length) ? mon.skills : null;',
    '      var _l = _mv || _sk;',
    '      return (_l && _l[2]) ? _l[2] : null;',
    "    }catch(e){ try{ console.error('[" + SENTINEL + "] skills fallback error', e); }catch(_e){} return null; }",
    '  })();',
])

# もとの形（moves だけを見る行）が公開HTMLに何件あるか。ボス以外の4か所は触らない。
M3_LINE = '  const m3 = (mon && Array.isArray(mon.moves) && mon.moves[2]) ? mon.moves[2] : null;'
M3_LINE_COUNT = 5

KEEP = [
    '__ZWAR_CASTLE_STAND_V1__',
    '__ZWAR_UNLOCK_V1__',
    '__DEFSTAGE_SENTINEL_V1__',
    '__DEF_MVP_V1__',
    'DEF2TRY_',
    'DEF2SEND_GUARD_V1_MARK',
    'DEF2TPL_LEARN_V1',
    'DEF_LV50_V1',
    'foeLaneMix',
    'DEF2TALLY_TREE_V2',
    '__DEFBOSS_V1',
    'defstage_monsters.js',
    'def_join_nudge.js',
    'HS_NEXT_RECALL_V1',
    '__S6WORLD_50__',
    '__H6MERGE_SRC_V1__',
    '__H6BANK_LIVE_V1__',
    '__H6U11_BOOST_V1__',
]

TEXT_EXT = ('.js', '.mjs', '.cjs', '.ts', '.tsx', '.html', '.css', '.json', '.txt', '.md')


def die(msg):
    sys.stderr.write('FAIL: ' + msg + NL)
    sys.exit(1)


def js(o):
    return json.dumps(o, ensure_ascii=False)


def read_corpus():
    buf = []
    for root in ('src', 'public'):
        if not os.path.isdir(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            for fn in sorted(filenames):
                if not fn.endswith(TEXT_EXT):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    with open(p, encoding='utf-8', errors='ignore') as fp:
                        buf.append(fp.read())
                except OSError:
                    pass
    return NL.join(buf)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def build_block():
    m = SENTINEL
    parts = [
        '',
        '    // ' + m + ' : 県ボスの3つ目のスキルを読めるようにする（ボスを出す1か所だけ）',
        '    const _zbs1 = ' + js(A_OLD),
        '    const _zbs2 = ' + js(A_NEW),
        "    if (t.indexOf(_zbs1) !== -1) { t = t.replace(_zbs1, _zbs2) } else { console.error('[" + m + "] anchor not found') }",
    ]
    return NL.join(parts)


def self_check():
    if len(A_OLD) != A_LEN:
        die('A_OLD の長さが %d（想定 %d）' % (len(A_OLD), A_LEN))
    if '$' in A_NEW:
        die('A_NEW に $ が含まれる')
    if '</' in A_NEW:
        die('A_NEW に </ が含まれる')
    if '.replace(' in A_NEW:
        die('A_NEW に .replace( が含まれる')
    if 'throw' in A_NEW:
        die('A_NEW に throw が含まれる')
    if A_OLD == A_NEW:
        die('置換前後が同じ')
    # 1行目は残し、2行目だけを書き換える形になっているか
    if not A_NEW.startswith('  const atkInterval = clamp(1100 - (mon.spd||30)*6, 420, 1100);'):
        die('A_NEW の1行目が変わっている')


def main():
    self_check()

    with open(SRC, encoding='utf-8') as fp:
        s = fp.read()
    with open(HTML, encoding='utf-8') as fp:
        h = fp.read()

    if SENTINEL in s:
        print('SKIP: 番兵 ' + SENTINEL + ' があるので何もしない')
        return

    if s.count(ROOT_ANCHOR) != 1:
        die('ルートのアンカーが一意でない: %d件' % s.count(ROOT_ANCHOR))
    if s.count(INSERT_AT) != 1:
        die('挿入位置が一意でない: %d件' % s.count(INSERT_AT))

    n = h.count(A_OLD)
    if n != 1:
        die('public/index.html の2行アンカーが %d件（想定 1件）' % n)
    if h.count(M3_LINE) != M3_LINE_COUNT:
        die('moves[2] を読む行が %d件（想定 %d件）。他の場所の形が変わっている' % (h.count(M3_LINE), M3_LINE_COUNT))
    if SENTINEL in h:
        die('public/index.html に番兵が混入している')
    if 'Array.isArray(mon.skills)' in h:
        die('public/index.html にすでに skills フォールバックの形がある')

    # ボスを出す関数の中にアンカーがあること（=ボスの1か所を指していること）
    fi = h.find('function warTrySpawnBoss()')
    if fi < 0:
        die('warTrySpawnBoss が見つからない')
    fj = h.find('function getEnemyTemplate(', fi)
    if fj < 0:
        die('warTrySpawnBoss の終わりが見つからない')
    if h.find(A_OLD) < fi or h.find(A_OLD) > fj:
        die('アンカーが warTrySpawnBoss の外にある')

    n0 = chain_count(s)
    if n0 != CHAIN_BEFORE:
        die('チェーンが %d件（想定 %d件）' % (n0, CHAIN_BEFORE))

    corpus = read_corpus()
    for k in KEEP:
        if k not in corpus:
            die('既存の目印が見つからない: ' + k)

    block = build_block()
    idx = s.index(INSERT_AT)
    s2 = s[:idx] + block + s[idx:]

    if len(s2) != len(s) + len(block):
        die('挿入で長さが合わない')
    if s2[:idx] != s[:idx]:
        die('挿入位置より前が変わっている')
    if s2[idx + len(block):] != s[idx:]:
        die('挿入位置より後が変わっている')

    n1 = chain_count(s2)
    if n1 != CHAIN_AFTER:
        die('挿入後のチェーンが %d件（想定 %d件）' % (n1, CHAIN_AFTER))

    if s2.count('_zbs1') != 3:
        die('_zbs1 が %d件（想定 3件）' % s2.count('_zbs1'))
    if s2.count('_zbs2') != 2:
        die('_zbs2 が %d件（想定 2件）' % s2.count('_zbs2'))
    if SENTINEL not in s2:
        die('番兵が入っていない')
    for k in KEEP:
        if s2.count(k) != s.count(k):
            die('既存の目印の数が変わった: ' + k)

    with open(SRC, 'w', encoding='utf-8') as fp:
        fp.write(s2)

    print('OK: chain %d -> %d' % (n0, n1))


if __name__ == '__main__':
    main()
