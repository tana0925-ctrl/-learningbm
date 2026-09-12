#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ZWEAK_V1
#
# ゾンビ襲来で なしひろし(152) / タナカティーチャー(153) / 阪神マン(999) が
# 完全に 出撃きんし（タップすると「こわい」とだけ 出る）になっていたのを やめる。
# かわりに ゾンビ襲来のときだけ 体力と こうげきを 0.2ばいに して 出せるようにする。
#
# - きんしの3箇所（見た目のグレーアウト / ボタンの文字 / 出撃のブロック）を なくす
# - getWarUnitStatsFromMonster の scale に 0.2 を かける（hp と atk だけが scale を使う）
# - ボタンの文字を 理由の分かる文に する（さいしょの描画と 毎フレームの更新の 両方）
#
# 通常モードには いっさい さわらない（zombieMode が false のとき かける数は 1）。
#
# public/index.html は 手で さわらない。src/index.tsx の app.get('/') の
# .replace() チェーンに 足す形で 当てる。
#
# 配信されるコード側では ぜったいに throw しない。
# あて先が ひとつでも 見つからなければ 5件とも 当てずに console.error だけ。
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

SENTINEL = '__ZWEAK_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
INSERT_MARK = '_rootHtmlCache = t'

CHAIN_BEFORE = 92
CHAIN_ADD = 5
CHAIN_AFTER = CHAIN_BEFORE + CHAIN_ADD

LABEL = 'ゾンビでは よわりモード'

ZMUL = ("(function(){ try{ var zw = (typeof warState !== 'undefined' && warState) ? warState"
        " : (typeof window !== 'undefined' ? window.warState : null);"
        " if (zw && zw.zombieMode && (id===152 || id===153 || id===999)) return 0.2;"
        " }catch(e){} return 1; })()")

ZHINT = ("((typeof warState !== 'undefined' && warState && warState.zombieMode"
         " && typeof id !== 'undefined' && (id===152 || id===153 || id===999))"
         " ? '" + LABEL + "' : 'タップで出陣')")

KEEP = [
    '__ZWAR_UNLOCK_V1__',
    'startZombieWarFromPreview',
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


def one(h, pat, label):
    ms = list(re.finditer(pat, h))
    if len(ms) != 1:
        die('あて先 ' + label + ' が ' + str(len(ms)) + ' 件（1件のはず）')
    return ms[0]


def build_pairs(h):
    mA = one(h, r"'opacity-60\s+grayscale\s+cursor-not-allowed'", 'A')
    a_old = mA.group(0)
    a_new = "'opacity-80'"

    mB = one(h, r"('こわい')(\s*:\s*)('タップで出陣')", 'B')
    b_old = mB.group(0)
    b_new = "'" + LABEL + "'" + mB.group(2) + mB.group(3)

    mC = one(h, r"(if\()(warState)(\s*&&\s*warState\.zombieMode\s*&&\s*\(id===152)", 'C')
    c_old = mC.group(0)
    c_new = mC.group(1) + 'false' + mC.group(3)

    mD = one(h, r"(const\s+scale\s*=\s*)(1\s*\+\s*Math\.min\(0\.8,\s*\(lv-1\)\*0\.03\))(\s*;)", 'D')
    d_old = mD.group(0)
    d_new = mD.group(1) + '(' + mD.group(2) + ') * ' + ZMUL + mD.group(3)

    mE = one(h, r"(if\(hint\)\s*hint\.textContent\s*=\s*)('タップで出陣')(;)", 'E')
    e_old = mE.group(0)
    e_new = mE.group(1) + ZHINT + mE.group(3)

    return [(a_old, a_new), (b_old, b_new), (c_old, c_new), (d_old, d_new), (e_old, e_new)]


def check_pairs(h, pairs):
    names = ['A', 'B', 'C', 'D', 'E']
    for k in range(len(pairs)):
        o = pairs[k][0]
        n = pairs[k][1]
        nm = names[k]
        if h.count(o) != 1:
            die('あて先 ' + nm + ' の文字列が public/index.html に ' + str(h.count(o)) + ' 件')
        if o == n:
            die('あて先 ' + nm + ' が 置きかえ前と 同じ')
        for bad in ('$', '</', '.replace('):
            if bad in n:
                die('置きかえ後 ' + nm + ' に ' + bad + ' が ふくまれる')
            if bad in o:
                die('あて先 ' + nm + ' に ' + bad + ' が ふくまれる')
        if NL in o or NL in n:
            die('あて先 ' + nm + ' に 改行が ふくまれる')
    for k in range(len(pairs)):
        for m in range(len(pairs)):
            if k != m and pairs[k][0] in pairs[m][0]:
                die('あて先どうしが 入れ子に なっている')


def build_block(pairs):
    m = SENTINEL
    L = ['']
    L.append('    // ' + m + ' : ゾンビ襲来では 出撃きんしを やめて 0.2ばいの よわりモードにする')
    for k in range(len(pairs)):
        L.append('    const _zwk' + str(k) + 'a = ' + js(pairs[k][0]))
        L.append('    const _zwk' + str(k) + 'b = ' + js(pairs[k][1]))
    L.append('    const _zwkPairs = [' + ', '.join('[_zwk' + str(k) + 'a, _zwk' + str(k) + 'b]' for k in range(len(pairs))) + ']')
    L.append('    let _zwkOk = true')
    L.append('    for (let _zi = 0; _zi < _zwkPairs.length; _zi++) {')
    L.append('      const _za = _zwkPairs[_zi][0]')
    L.append('      const _zf = t.indexOf(_za)')
    L.append("      if (_zf === -1 || _zf !== t.lastIndexOf(_za)) { _zwkOk = false; console.error('[" + m + "] anchor NG', _zi) }")
    L.append('    }')
    L.append('    if (_zwkOk) {')
    for k in range(len(pairs)):
        L.append('      t = t.replace(_zwk' + str(k) + 'a, _zwk' + str(k) + 'b)')
    L.append('    } else {')
    L.append("      console.error('[" + m + "] skipped: no change')")
    L.append('    }')
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
    for k in KEEP:
        if k not in corpus:
            die('のこすはずの 目印が ない: ' + k)

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
    print('OK: label = ' + LABEL)


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
    names = ['A', 'B', 'C', 'D', 'E']
    for k in range(len(pairs)):
        o = pairs[k][0]
        n = pairs[k][1]
        chk('src の あて先 ' + names[k], s.count(js(o)), 1)
        chk('src の 置きかえ後 ' + names[k], s.count(js(n)), 1)
        chk('public の あて先 ' + names[k], h.count(o), 1)
        chk('public の 置きかえ後 ' + names[k], h.count(n), 0)

    chk('replace の 本数', s.count('t = t.replace(_zwk'), 5)
    chk('よわりの かけ算', s.count('zw.zombieMode'), 1)

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
