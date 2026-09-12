#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ZWAR_CASTLE_STAND_V1
#
# ゾンビ襲来（攻略モード）の「城の攻防」を にゃんこ大戦争ふうの山場にする。
#
# いまの困りごと:
#   敵の城に触れると 2〜3 斉射（3秒ほど）で落ちてしまい、
#   「ボスが出てから踏ん張る」時間がない。ボスのいる10県のうち
#   ほとんどで、ボスが出たときには城がもう残り半分を切っている。
#
# 直すこと（3件）:
#   A) ボスのいる県は、ボスの出かた（bossMode）を必ず 'castleHit' にする。
#      ＝「敵の城に触れた瞬間にボスが出る」。
#   B) ボスのいる県だけ、敵の城のHPを 20倍にする。
#      ボスのいない37県は今までどおり（誰もいない城を長く殴るだけになるため）。
#   C) 全47県で spawnStopWave を 0.2倍にする。
#      ＝敵の増援が止まるWAVEを早める。1戦が長すぎるのを短くする。
#
# public/index.html は手で触らない。src/index.tsx の app.get('/') の
# .replace() チェーンに3件足す形で当てる。
#
# 配信されるコード側では絶対に throw しない。
# アンカーが見つからなければ「適用せず console.error を出すだけ」。
# （チェーン全体が try/catch に包まれていて、throw すると
#   素の index.html が配信され、既存98件が全部消えてしまうため）
#
# パッチを当てる側は fail-closed。前提が1つでも崩れたら1文字も書かずに exit 1。

import json
import os
import sys

NL = chr(10)

SRC = 'src/index.tsx'
HTML = 'public/index.html'

# 冪等性の番兵（これがあれば何もしない）。検証条件には使わない。
SENTINEL = '__ZWAR_CASTLE_STAND_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
INSERT_AT = NL + '    _rootHtmlCache = t' + NL

# 流す直前に実測した値
CHAIN_BEFORE = 98
CHAIN_ADD = 3
CHAIN_AFTER = CHAIN_BEFORE + CHAIN_ADD

# --- A: ボスのいる県は「城に触れたらボス」にする ---
A_OLD = "  const bossMode = (i < 5) ? 'time' : ((i % 3 === 0) ? 'time' : (i % 3 === 1) ? 'wave' : 'castleHit');"
A_NEW = "  const bossMode = boss ? 'castleHit' : ((i < 5) ? 'time' : ((i % 3 === 0) ? 'time' : (i % 3 === 1) ? 'wave' : 'castleHit'));"
A_LEN = 102

# --- B: ボスのいる県だけ 敵城HP を 20倍 ---
B_OLD = '  const enemyCastleHpMax = Math.round(600 + i*28 + diff*140);'
B_NEW = NL.join([
    '  // ' + SENTINEL + ' : ボスがいる県だけ 敵の城を厚くする（ボスなし37県はそのまま）',
    '  const __zcsHasBoss = (function(){',
    '    try{',
    "      var _n = (typeof WAR_PREFS !== 'undefined' && WAR_PREFS && WAR_PREFS[i]) ? WAR_PREFS[i] : null;",
    "      return !!(_n && typeof WAR_PREF_BOSS !== 'undefined' && WAR_PREF_BOSS && WAR_PREF_BOSS[_n]);",
    "    }catch(e){ try{ console.error('[" + SENTINEL + "] boss lookup error', e); }catch(_e){} return false; }",
    '  })();',
    '  const enemyCastleHpMax = Math.round((600 + i*28 + diff*140) * (__zcsHasBoss ? 20 : 1));',
])
B_LEN = 61

# --- C: 増援が止まるWAVEを早める（全47県） ---
C_OLD = '  const spawnStopWave = 20 + i;'
C_NEW = '  const spawnStopWave = Math.max(1, Math.round((20 + i) * 0.2));'
C_LEN = 31

# 壊してはいけない既存の目印（src/ と public/ のどこかにあればよい）
KEEP = [
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
        '    // ' + m + ' : ゾンビ襲来の「城の攻防」を山場にする（A=城に触れたらボス / B=ボス県だけ城HP20倍 / C=増援を早く止める）',
        '    const _zcsA1 = ' + js(A_OLD),
        '    const _zcsA2 = ' + js(A_NEW),
        "    if (t.indexOf(_zcsA1) !== -1) { t = t.replace(_zcsA1, _zcsA2) } else { console.error('[" + m + "] anchor A not found') }",
        '    const _zcsB1 = ' + js(B_OLD),
        '    const _zcsB2 = ' + js(B_NEW),
        "    if (t.indexOf(_zcsB1) !== -1) { t = t.replace(_zcsB1, _zcsB2) } else { console.error('[" + m + "] anchor B not found') }",
        '    const _zcsC1 = ' + js(C_OLD),
        '    const _zcsC2 = ' + js(C_NEW),
        "    if (t.indexOf(_zcsC1) !== -1) { t = t.replace(_zcsC1, _zcsC2) } else { console.error('[" + m + "] anchor C not found') }",
    ]
    return NL.join(parts)


def self_check():
    for nm, v, want in [('A_OLD', A_OLD, A_LEN), ('B_OLD', B_OLD, B_LEN), ('C_OLD', C_OLD, C_LEN)]:
        if len(v) != want:
            die('%s の長さが %d（想定 %d）' % (nm, len(v), want))
    for nm, v in [('A_NEW', A_NEW), ('B_NEW', B_NEW), ('C_NEW', C_NEW)]:
        if '$' in v:
            die(nm + ' に $ が含まれる')
        if '</' in v:
            die(nm + ' に </ が含まれる')
        if '.replace(' in v:
            die(nm + ' に .replace( が含まれる')
        if 'throw' in v:
            die(nm + ' に throw が含まれる')
    # 置き換えたあとに元の並びが残っていないこと（=確かに書き換わる形か）
    if A_OLD == A_NEW or B_OLD == B_NEW or C_OLD == C_NEW:
        die('置換前後が同じ')


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

    for nm, v in [('A', A_OLD), ('B', B_OLD), ('C', C_OLD)]:
        n = h.count(v)
        if n != 1:
            die('public/index.html のアンカー ' + nm + ' が %d件（想定 1件）' % n)
    if SENTINEL in h:
        die('public/index.html に番兵が混入している')

    # すでに当たっていないこと（配信後の姿がHTMLに混ざっていないこと）
    for nm, v in [('A', A_NEW), ('B', '__zcsHasBoss'), ('C', C_NEW)]:
        if v in h:
            die('public/index.html に置換後の形 ' + nm + ' がすでにある')

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

    for nm in ('_zcsA1', '_zcsB1', '_zcsC1'):
        if s2.count(nm) != 3:
            die(nm + ' が %d件（想定 3件）' % s2.count(nm))
    for nm in ('_zcsA2', '_zcsB2', '_zcsC2'):
        if s2.count(nm) != 2:
            die(nm + ' が %d件（想定 2件）' % s2.count(nm))
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
