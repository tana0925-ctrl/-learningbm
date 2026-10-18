#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# NEWCHARS_V1  クラスの子どもたちが考えた新キャラ7体を足す（ID 1701〜1707）。
#
#   1701 ミニドラゴン   ドラゴン  九九の野生（近場・奥地・最深部）ふつう
#   1702 ミッニ         ひこう    九九の野生（近場・奥地・最深部）ふつう／Lv18でミッキに進化
#   1703 ミッキ         ひこう    ミッニの進化でのみ入手（野生には出さない）
#   1704 リトルグリーン エスパー  九九の野生（奥地・最深部）レア
#   1705 もちいぬ       フェアリー 九九の野生（奥地・最深部）レア
#   1706 ちゅにごん     みず      九九の野生（最深部のみ）特別
#   1707 ドララくん     ノーマル  九九の野生（最深部のみ）特別
#
#   ・出やすさは WILD_AREA_POOLS.kuku の「くじの枚数」で変える（pickWildMonsterId は1バイトも変えない）。
#     エリア限定キャラは もともと野生バトルの10%で選ばれ、くじから1枚引かれる。
#       近場 : 5枚（既存3＋ふつう2）           → 新キャラ1体 約2%
#       奥地 : 12枚（既存3×2＋ふつう2×2＋レア2×1）→ ふつう約1.7%／レア約0.8%
#       最深部: 26枚（既存3×4＋ふつう2×4＋レア2×2＋特別2×1）→ ふつう約1.5%／レア約0.8%／特別約0.4%
#   ・図鑑の入手方法は既存の自動表示（WILD_AREA_POOLS を見て「算数（2年）「九九バトルフィールド」の野生バトル」と出す）に任せる。
#     そのため gacha:true も、図鑑文の【入手】も付けない。ミッキは nextId から「進化（ミッニがLv18で進化）」と出る。
#   ・交換は全員OK。交換禁止リスト（src/index.tsx の2か所）は触らない。
#   ・作者クレジットは今回は出さない。あとで足すときは各キャラの artBy に先生が決めたニックネームを入れる
#     （今はどこにも表示しない。子どもの実名は入れないこと）。
#
#   触るファイル: public/index.html（2か所）, public/mon/list.js（1か所）
#   src/index.tsx は1バイトも触らない（.replace() の対象行にも当たらない場所だけを選んだ）。
#   守り: あて先がちょうど1件でなければ、何も書かずに止まる。もう入っていれば何もしない。

import sys

PUB = 'public/index.html'
LIST = 'public/mon/list.js'
MARK = 'NEWCHARS_V1'


def die(msg):
    print('### 中止: ' + msg)
    sys.exit(1)


raw = open(PUB, 'rb').read()
nl = '\r\n' if b'\r\n' in raw[:200000] else '\n'
s = raw.decode('utf-8')

if MARK in s:
    print('すでに入っています。何もしません。')
    sys.exit(0)

ANCHOR = '// 野生出現テーブル（地方→エリア→深さ）'
OLD_KUKU = '    kuku:       { 1: [NW(5), NW(6), 1051],        2: [NW(7), NW(9), 1052],          3: [NW(10), NW(2), 1053] },'

for name, a in (('野生出現テーブルの見出し', ANCHOR), ('kuku の行', OLD_KUKU)):
    c = s.count(a)
    if c != 1:
        die(name + ' が ' + str(c) + ' 件（1件のはず）')

for i in range(1701, 1708):
    for pat in ('id: %d,' % i, 'id:%d,' % i, 'id: %d ' % i):
        if pat in s:
            die('id %d がすでに使われている（%s）' % (i, pat))

BLOCK = r"""
// === NEWCHARS_V1 クラスの子どもたちが考えた新キャラ（ID 1701〜1707） ===
// 入手: 算数2年「九九バトルフィールド」の野生（WILD_AREA_POOLS.kuku）。ミッキ(1703)はミッニの進化のみ。
// artBy: 作者クレジット用のニックネーム（いまは表示しない。子どもの実名は入れない）。
MONSTERS.push({
    id: 1701, name: 'ミニドラゴン', sprite: '🐲',
    hp: 145, atk: 38, def: 30, spd: 32, buff: 'attack', elementType: 'dragon',
    stage: 1, evoLevel: null, nextId: null, gacha: false, artBy: null,
    skills: [
        { name: 'ちびドラパンチ', type: 'normal', pow: 13, acc: 0.97, element: 'dragon', desc: '' },
        { name: 'トゲトゲしっぽ', type: 'heavy', pow: 28, acc: 0.72, element: 'dragon', desc: '' },
        { name: 'あいぼうボール', type: 'unique', pow: 14, acc: 0.9, effect: 'aoe', desc: '全体攻撃' }
    ],
    desc: 'まだ小さいドラゴン。背中のまるい友だちを守るときだけ、本気のほのおをはく。'
});
MONSTERS.push({
    id: 1702, name: 'ミッニ', sprite: '🐱',
    hp: 135, atk: 34, def: 24, spd: 42, buff: 'speed', elementType: 'flying',
    stage: 1, evoLevel: 18, nextId: 1703, gacha: false, artBy: null,
    skills: [
        { name: 'かぜねこダッシュ', type: 'normal', pow: 12, acc: 0.98, element: 'flying', desc: '' },
        { name: 'つむじ風キック', type: 'heavy', pow: 26, acc: 0.74, element: 'flying', desc: '' },
        { name: 'みどりのわっか', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_speed', desc: '自分のすばやさUP' }
    ],
    desc: '走ると 風の子が ついてくる。風を たくさん あつめると、まんまるの ミッキに なるらしい。'
});
MONSTERS.push({
    id: 1703, name: 'ミッキ', sprite: '🐻',
    hp: 250, atk: 62, def: 50, spd: 60, buff: 'speed', elementType: 'flying',
    stage: 2, evoLevel: null, nextId: null, gacha: false, artBy: null,
    skills: [
        { name: 'ころころかぜアタック', type: 'normal', pow: 15, acc: 0.97, element: 'flying', desc: '' },
        { name: 'まんまる突風', type: 'heavy', pow: 34, acc: 0.74, element: 'flying', desc: '' },
        { name: 'まんまるスマイル', type: 'unique', pow: 0, acc: 1.0, effect: 'heal_self', desc: '自分のHPを回復' }
    ],
    desc: 'おなかに 風をためて まんまるに なった。ふわっと うかんで、いつも にこにこ。'
});
MONSTERS.push({
    id: 1704, name: 'リトルグリーン', sprite: '🟢',
    hp: 175, atk: 44, def: 34, spd: 40, buff: 'lucky', elementType: 'psychic',
    stage: 1, evoLevel: null, nextId: null, gacha: false, artBy: null,
    skills: [
        { name: 'みどりのみつめビーム', type: 'normal', pow: 13, acc: 0.97, element: 'psychic', desc: '' },
        { name: 'アンテナでんぱ', type: 'unique', pow: 0, acc: 0.8, effect: 'stun', desc: '相手をしびれさせる' },
        { name: 'まるまるガード', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def', desc: '自分のぼうぎょUP' }
    ],
    desc: '3つの目で まえ・よこ・うしろを いっぺんに見る。小さいけれど、みどりの元気は だれにも負けない。'
});
MONSTERS.push({
    id: 1705, name: 'もちいぬ', sprite: '🐩',
    hp: 180, atk: 40, def: 40, spd: 38, buff: 'guard', elementType: 'fairy',
    stage: 1, evoLevel: null, nextId: null, gacha: false, artBy: null,
    skills: [
        { name: 'もふもふタックル', type: 'normal', pow: 12, acc: 0.98, element: 'fairy', desc: '' },
        { name: 'みかんころがし', type: 'heavy', pow: 27, acc: 0.74, desc: '' },
        { name: 'もちもちヒール', type: 'unique', pow: 0, acc: 1.0, effect: 'heal_self', desc: '自分のHPを回復' }
    ],
    desc: '頭の みかんは 落としたことがない。お正月が いちばん好き。'
});
MONSTERS.push({
    id: 1706, name: 'ちゅにごん', sprite: '🐬',
    hp: 220, atk: 52, def: 40, spd: 50, buff: 'speed', elementType: 'water',
    stage: 1, evoLevel: null, nextId: null, gacha: false, artBy: null,
    skills: [
        { name: 'ツノツノアタック', type: 'normal', pow: 14, acc: 0.97, element: 'water', desc: '' },
        { name: 'ほしくずスプラッシュ', type: 'unique', pow: 16, acc: 0.9, effect: 'aoe', element: 'water', desc: '全体攻撃' },
        { name: 'ひれウイング', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_speed', desc: '自分のすばやさUP' }
    ],
    desc: '星の夜にだけ 海から 顔を出す。まつ毛が 自まん。'
});
MONSTERS.push({
    id: 1707, name: 'ドララくん', sprite: '🐨',
    hp: 230, atk: 50, def: 44, spd: 46, buff: 'lucky', elementType: 'normal',
    stage: 1, evoLevel: null, nextId: null, gacha: false, artBy: null,
    skills: [
        { name: 'ユーカリパンチ', type: 'normal', pow: 14, acc: 0.97, desc: '' },
        { name: 'スターウェーブ', type: 'heavy', pow: 30, acc: 0.74, desc: '' },
        { name: 'おうえんフラッグ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_all', desc: '味方全体のこうげきUP' }
    ],
    desc: '旗を ふると みんなが 元気になる。自分が つかれていることに 気づかない。'
});
// === /NEWCHARS_V1 ===

"""

NEW_KUKU = ('    kuku:       { 1: [NW(5), NW(6), 1051, 1701, 1702],'
            ' 2: [NW(7), NW(7), NW(9), NW(9), 1052, 1052, 1701, 1701, 1702, 1702, 1704, 1705],'
            ' 3: [NW(10), NW(10), NW(10), NW(10), NW(2), NW(2), NW(2), NW(2), 1053, 1053, 1053, 1053,'
            ' 1701, 1701, 1701, 1701, 1702, 1702, 1702, 1702, 1704, 1704, 1705, 1705, 1706, 1707] },'
            ' // NEWCHARS_V1 くじの枚数で出やすさを調整（ふつう>レア>特別）')

block = BLOCK.replace('\n', nl)
s2 = s.replace(ANCHOR, block.lstrip(nl) + ANCHOR, 1)
s2 = s2.replace(OLD_KUKU, NEW_KUKU, 1)
if s2.count(MARK) < 3:
    die('置きかえの結果がおかしい')

lst = open(LIST, 'r', encoding='utf-8').read()
key = 'window.MON_IMG_IDS=['
if lst.count(key) != 1:
    die('list.js の MON_IMG_IDS が1件でない')
st = lst.index(key) + len(key)
en = lst.index(']', st)
ids = lst[st:en]
for i in range(1701, 1708):
    if (',%d,' % i) in (',' + ids.replace(' ', '') + ','):
        die('list.js にすでに %d がある' % i)
lst2 = lst[:en] + ',1701,1702,1703,1704,1705,1706,1707' + lst[en:]

open(PUB, 'wb').write(s2.encode('utf-8'))
open(LIST, 'w', encoding='utf-8', newline='').write(lst2)
print('OK: 新キャラ7体を追加（public/index.html 2か所・public/mon/list.js 1か所）。改行=' + ('CRLF' if nl == '\r\n' else 'LF'))
