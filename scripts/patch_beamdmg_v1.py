#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# BEAMDMG_V1
#
# 攻略モードの ビーム②（威力）の のび方を なおす。
#
# しらべた こと:
#   player.beamDamageLevel は applyWarUpgradesToState() の 中で
#   warState.beamDamageRatio = BEAM_RATIO_BASE + (bdl-1)*BEAM_RATIO_PER_LEVEL
#   として ちゃんと つながっている（warApplyStage と resetWar から よばれる）。
#   つながっては いるが のびが 小さすぎる:
#     BEAM_RATIO_PER_LEVEL = 0.0004 -> 1レベルで もとの +0.333% しか のびない。
#     Lv1 0.12 -> Lv100 0.1596（1.33ばい）。チケット99まいで これだけ。
#
# そろえる 考え方（かってに 大きく しない）:
#   おなじ チケット1まい / 最大Lv100 の きょうかを ならべると
#     ビーム1 チャージ : 2 + 0.02/Lv   = 1レベル +1.000%  -> Lv100 1.99ばい
#     ビーム3 スタン   : 800 + 5/Lv    = 1レベル +0.625%  -> Lv100 1.62ばい
#     しろレベル       : +5HP/Lv       = 1レベル +0.833%  -> Lv100 1.83ばい
#     ビーム2 いりょく : 0.12+0.0004/Lv= 1レベル +0.333%  -> Lv100 1.33ばい  <- ここだけ 小さい
#   ビーム1 と おなじ きまり（1レベルで もとの +1%）に そろえる。
#     0.12 * 1% = 0.0012
#     Lv1 0.12（かわらない）-> Lv100 0.2388（1.99ばい = ビーム1 と おなじ）
#   Lv1 の つよさは 1ミリも かえない。のびる 分だけ なおす。
#
# public/index.html は 手で さわらない。src/index.tsx の app.get('/') の
# .replace() チェーンに 1本 足す形で 当てる。
#
# 配信される コード側では ぜったいに throw しない。
# あて先が 見つからなければ 当てずに console.error だけ。
#
# パッチを 当てる側は fail-closed。前提が ひとつでも 崩れたら 1文字も 書かずに exit 1。

import io
import json
import os
import re
import sys

NL = chr(10)

SRC = 'src/index.tsx'
HTML = 'public/index.html'

SENTINEL = '__BEAMDMG_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
INSERT_MARK = '_rootHtmlCache = t'

CHAIN_BEFORE = 97
CHAIN_ADD = 1
CHAIN_AFTER = CHAIN_BEFORE + CHAIN_ADD

OLD_LINE = 'const BEAM_RATIO_PER_LEVEL = 0.0004; // Lv100で約+0.0396'
NEW_LINE = 'const BEAM_RATIO_PER_LEVEL = 0.0012; // Lv100で約+0.1188'

KEEP = [
'__ZWEAK_V1__',
'__ZWAR_UNLOCK_V1__',
'startZombieWarFromPreview',
'__DEFSTAGE_SENTINEL_V1__',
'__DEF_MVP_V1__',
'DEF2TRY_',
'DEF2SEND_GUARD_V1_MARK',
'DEF2TPL_LEARN_V1',
'DEF2TALLY_TREE_V2',
'DEF_LV50_V1',
'foeLaneMix',
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

def read(p):
    return io.open(p, encoding='utf-8', newline='').read()

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
                    buf.append(io.open(p, encoding='utf-8', errors='ignore').read())
                except OSError:
                    pass
    return NL.join(buf)

def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')

def one(h, lit, label):
    ms = list(re.finditer(re.escape(lit), h))
    if len(ms) != 1:
        die('あて先 ' + label + ' が ' + str(len(ms)) + ' 件（1件のはず）')
    return ms[0]

def build_pairs(h):
    one(h, OLD_LINE, 'A')
    return [(OLD_LINE, NEW_LINE)]

def check_pairs(h, pairs):
    names = ['A']
    for k in range(len(pairs)):
        o = pairs[k][0]
        n = pairs[k][1]
        nm = names[k]
        if h.count(o) != 1:
            die('あて先 ' + nm + ' の文字列が public/index.html に ' + str(h.count(o)) + ' 件')
        if o == n:
            die('あて先 ' + nm + ' が 置きかえ前と 同じ')
        if h.count(n) != 0:
            die('置きかえ後 ' + nm + ' が すでに public/index.html に ある')
        for bad in ('$', '</', '.replace('):
            if bad in n:
                die('置きかえ後 ' + nm + ' に ' + bad + ' が ふくまれる')
            if bad in o:
                die('あて先 ' + nm + ' に ' + bad + ' が ふくまれる')
        if NL in o or NL in n:
            die('あて先 ' + nm + ' に 改行が ふくまれる')

def build_block(pairs):
    m = SENTINEL
    L = ['']
    L.append('  // ' + m + ' : ビーム2（いりょく）の のび方を ビーム1（チャージ）と そろえる')
    for k in range(len(pairs)):
        L.append('  const _bdm' + str(k) + 'a = ' + js(pairs[k][0]))
        L.append('  const _bdm' + str(k) + 'b = ' + js(pairs[k][1]))
    L.append('  const _bdmPairs = [' + ', '.join('[_bdm' + str(k) + 'a, _bdm' + str(k) + 'b]' for k in range(len(pairs))) + ']')
    L.append('  let _bdmOk = true')
    L.append('  for (let _bi = 0; _bi < _bdmPairs.length; _bi++) {')
    L.append('    const _ba = _bdmPairs[_bi][0]')
    L.append('    const _bf = t.indexOf(_ba)')
    L.append("    if (_bf === -1 || _bf !== t.lastIndexOf(_ba)) { _bdmOk = false; console.error('[" + m + "] anchor NG', _bi) }")
    L.append('  }')
    L.append('  if (_bdmOk) {')
    for k in range(len(pairs)):
        L.append('    t = t.replace(_bdm' + str(k) + 'a, _bdm' + str(k) + 'b)')
    L.append('  } else {')
    L.append("    console.error('[" + m + "] skipped: no change')")
    L.append('  }')
    return NL.join(L)

def js_literals(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return re.findall(r'"(?:[^"\\]|\\.)*"', s[i:j])

def apply():
    s = read(SRC)
    h = read(HTML)

    if SENTINEL in s:
        print('SKIP: 番兵 ' + SENTINEL + ' が あるので 何もしない')
        return
    if SENTINEL in h:
        die('public/index.html に 番兵が まぎれこんでいる')
    if chr(13) in h:
        die('public/index.html に CR が ある')
    if s.count(ROOT_ANCHOR) != 1:
        die('家の入口が ' + str(s.count(ROOT_ANCHOR)) + ' 件')
    if s.count(END_ANCHOR) != 1:
        die('出口が ' + str(s.count(END_ANCHOR)) + ' 件')
    if s.count(INSERT_MARK) != 1:
        die('入れる場所が ' + str(s.count(INSERT_MARK)) + ' 件')

    n0 = chain_count(s)
    if n0 != CHAIN_BEFORE:
        die('チェーンが ' + str(n0) + ' 件（' + str(CHAIN_BEFORE) + ' 件のはず）')

    corpus = read_corpus()
    miss = [k for k in KEEP if k not in corpus]
    if miss:
        die('のこすはずの 目印が ない: ' + ', '.join(miss))

    pairs = build_pairs(h)
    check_pairs(h, pairs)

    before_lits = {}
    for lit in js_literals(s):
        before_lits[lit] = before_lits.get(lit, 0) + 1

    block = build_block(pairs)
    idx = s.index(INSERT_MARK)
    ls = s.rfind(NL, 0, idx)
    if ls < 0:
        die('行あたまが 見つからない')

    s2 = s[:ls] + block + s[ls:]

    if len(s2) != len(s) + len(block):
        die('入れたあとの 長さが 合わない')
    if s2[:ls] != s[:ls]:
        die('入れた場所より 前が 変わっている')
    if s2[ls + len(block):] != s[ls:]:
        die('入れた場所より 後が 変わっている')

    n1 = chain_count(s2)
    if n1 != CHAIN_AFTER:
        die('入れたあとの チェーンが ' + str(n1) + ' 件（' + str(CHAIN_AFTER) + ' 件のはず）')

    after_lits = {}
    for lit in js_literals(s2):
        after_lits[lit] = after_lits.get(lit, 0) + 1
    for lit in before_lits:
        if after_lits.get(lit, 0) != before_lits[lit]:
            die('もとからある あて先文字列の数が 変わった: ' + lit[:60])

    if SENTINEL not in s2:
        die('番兵が 入っていない')
    for k in KEEP:
        if s2.count(k) != s.count(k):
            die('目印の数が 変わった: ' + k)

    io.open(SRC, 'w', encoding='utf-8', newline='').write(s2)
    print('OK: chain ' + str(n0) + ' -> ' + str(n1))
    print('OK: ' + OLD_LINE)
    print('OK: ' + NEW_LINE)

def verify():
    s = read(SRC)
    h = read(HTML)
    ok = [True]

    def chk(label, got, want):
        if got != want:
            print('NG: ' + label + ' が ' + str(got) + '（' + str(want) + ' のはず）')
            ok[0] = False
        else:
            print('ok: ' + label + ' = ' + str(got))

    chk('チェーン', chain_count(s), CHAIN_AFTER)
    chk('番兵', s.count(SENTINEL), 3)
    chk('public に 番兵', h.count(SENTINEL), 0)

    pairs = build_pairs(h)
    check_pairs(h, pairs)
    chk('src の あて先 A', s.count(js(pairs[0][0])), 1)
    chk('src の 置きかえ後 A', s.count(js(pairs[0][1])), 1)
    chk('public の あて先 A', h.count(pairs[0][0]), 1)
    chk('public の 置きかえ後 A', h.count(pairs[0][1]), 0)
    chk('replace の 本数', s.count('t = t.replace(_bdm'), 1)

    corpus = read_corpus()
    for k in KEEP:
        if k not in corpus:
            print('NG: 目印 ' + k + ' が 消えている')
            ok[0] = False

    if not ok[0]:
        sys.exit(1)
    print('VERIFY OK')

if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--verify':
        verify()
    else:
        apply()
