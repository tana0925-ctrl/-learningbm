#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# ZWAR_UNLOCK_V1
#
# 攻略モード「ゾンビ襲来」の解禁判定を
#   「ステージを選ぶとき」 -> 「ゾンビ襲来を押すとき」
# へ移す。
#
# 直す不具合:
#   解禁判定が warState.zombieMode（＝前回戦ったときのモード）を見ていた。
#   モードはステージを選んだ 後 のプレビュー画面で決まるので、判定はいつも1戦ぶん古い。
#   - 通常モードで遊んだ直後 -> どの県でもゾンビで選べてしまう（順番飛ばし）
#   - ゾンビで遊んだ直後     -> 通常モードで遠い県が選べなくなる
#
# public/index.html は手で触らない。src/index.tsx の app.get('/') の
# .replace() チェーンに3件足す形で当てる。
#
# 配信されるコード側では絶対に throw しない。
# アンカーが見つからなければ「適用せず console.error を出すだけ」。
# （チェーン全体が try/catch に包まれていて、throw すると
#   素の index.html が配信され、既存89件が全部消えてしまうため）
#
# パッチを当てる側は fail-closed。前提が1つでも崩れたら1文字も書かずに exit 1。

import json
import sys

NL = chr(10)

SRC = 'src/index.tsx'
HTML = 'public/index.html'

# 冪等性の番兵（これがあれば何もしない）。検証条件には使わない。
SENTINEL = '__ZWAR_UNLOCK_V1__'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
INSERT_AT = NL + '    _rootHtmlCache = t' + NL

# 流す直前に実測した値
CHAIN_BEFORE = 89
CHAIN_ADD = 3
CHAIN_AFTER = CHAIN_BEFORE + CHAIN_ADD

# --- A: renderWarStageList の中（一覧の鍵） ---
A_OLD = NL.join([
    'let zUnlocked = 1;',
    '    if(isZombie){',
    '      let c = 0;',
    '      while(c < WAR_PREFS.length && zCleared[String(c)]) c++;',
    '      zUnlocked = clamp(c + 1, 1, WAR_PREFS.length);',
    '    }',
])
A_NEW = 'let zUnlocked = (progress.unlocked || 1);'
A_LEN = 174

# --- B: selectWarStage の中（選べるかどうか） ---
B_OLD = NL.join([
    'let maxUnlocked = (player.warProgress.unlocked||1);',
    '    try{',
    '      const isZombie = !!(window.warState && window.warState.zombieMode);',
    '      if(isZombie){',
    "        const z = (player.warProgress && player.warProgress.zombieCleared && typeof player.warProgress.zombieCleared==='object') ? player.warProgress.zombieCleared : {};",
    '        let c = 0;',
    '        while(c < WAR_PREFS.length && z[String(c)]) c++;',
    '        maxUnlocked = clamp(c + 1, 1, WAR_PREFS.length);',
    '      }',
    '    }catch(e){}',
])
B_NEW = 'let maxUnlocked = (player.warProgress.unlocked||1);'
B_LEN = 481

# --- C: ゾンビ襲来ボタン（ここで順番を見る） ---
C_ANCHOR = 'window.startZombieWarFromPreview = function() {'

C_PAYLOAD = NL + NL.join([
    '  // ' + SENTINEL + ' : ゾンビしゅうらいは じゅんばんに すすむ',
    '  try{',
    '    var _zc = (player && player.warProgress && player.warProgress.zombieCleared) || {};',
    "    var _zn = (typeof WAR_PREFS !== 'undefined' && WAR_PREFS && WAR_PREFS.length) ? WAR_PREFS.length : 47;",
    '    var _zi = 0;',
    '    while(_zi < _zn && _zc[String(_zi)]) _zi++;',
    '    var _zcur = (player && player.warProgress && player.warProgress.current) || 0;',
    '    if(_zcur > _zi){',
    "      var _zname = (typeof WAR_PREFS !== 'undefined' && WAR_PREFS && WAR_PREFS[_zi]) ? WAR_PREFS[_zi] : '';",
    "      alert('ゾンビしゅうらいは じゅんばんに すすむよ！' + String.fromCharCode(10) + 'つぎは ' + (_zi + 1) + 'ばんめの「' + _zname + '」から！');",
    '      return;',
    '    }',
    "  }catch(e){ try{ console.error('[" + SENTINEL + "] guard error', e); }catch(_e){} }",
])

# 壊してはいけない既存の目印
KEEP = [
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


def die(msg):
    sys.stderr.write('FAIL: ' + msg + NL)
    sys.exit(1)


def js(o):
    return json.dumps(o, ensure_ascii=False)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def build_block():
    m = SENTINEL
    parts = [
        '',
        '    // ' + m + ' : ゾンビ襲来の解禁判定をステージ選択からボタン側へ移す',
        '    const _zwA1 = ' + js(A_OLD),
        '    const _zwA2 = ' + js(A_NEW),
        "    if (t.indexOf(_zwA1) !== -1) { t = t.replace(_zwA1, _zwA2) } else { console.error('[" + m + "] anchor A not found') }",
        '    const _zwB1 = ' + js(B_OLD),
        '    const _zwB2 = ' + js(B_NEW),
        "    if (t.indexOf(_zwB1) !== -1) { t = t.replace(_zwB1, _zwB2) } else { console.error('[" + m + "] anchor B not found') }",
        '    const _zwC1 = ' + js(C_ANCHOR),
        '    const _zwC2 = ' + js(C_ANCHOR + C_PAYLOAD),
        "    if (t.indexOf(_zwC1) !== -1) { t = t.replace(_zwC1, _zwC2) } else { console.error('[" + m + "] anchor C not found') }",
    ]
    return NL.join(parts)


def self_check():
    if len(A_OLD) != A_LEN:
        die('A の長さが %d（想定 %d）' % (len(A_OLD), A_LEN))
    if len(B_OLD) != B_LEN:
        die('B の長さが %d（想定 %d）' % (len(B_OLD), B_LEN))
    for nm, v in [('A_NEW', A_NEW), ('B_NEW', B_NEW), ('C_PAYLOAD', C_PAYLOAD)]:
        if '$' in v:
            die(nm + ' に $ が含まれる')
        if '</' in v:
            die(nm + ' に </ が含まれる')
        if '.replace(' in v:
            die(nm + ' に .replace( が含まれる')


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

    for nm, v in [('A', A_OLD), ('B', B_OLD), ('C', C_ANCHOR)]:
        n = h.count(v)
        if n != 1:
            die('public/index.html のアンカー ' + nm + ' が %d件（想定 1件）' % n)
    if SENTINEL in h:
        die('public/index.html に番兵が混入している')

    n0 = chain_count(s)
    if n0 != CHAIN_BEFORE:
        die('チェーンが %d件（想定 %d件）' % (n0, CHAIN_BEFORE))

    for k in KEEP:
        if k not in s and k not in h:
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

    for nm in ('_zwA1', '_zwB1', '_zwC1'):
        if s2.count(nm) != 3:
            die(nm + ' が %d件（想定 3件）' % s2.count(nm))
    for nm in ('_zwA2', '_zwB2', '_zwC2'):
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
