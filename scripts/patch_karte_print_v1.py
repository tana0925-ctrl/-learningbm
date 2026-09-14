#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# KARTE_PRINT_V1 : 印刷カルテの3点修正（先生の決定ずみ）
#   (1) 週のようすの「先生から」手書き点線枠を廃止し、阪神マンの欄ひとつに統合。
#       あわせて teacher-ai.js の KARTE 指示文を阪神マンの口調に書きなおす。
#   (2) 連続記録を「今年度の話」と分かる文言にする（今年度の積み上げの中）。
#   (3) UNIT_JP に中学以降の34単元の日本語名を追加（_unitGrade は拡張しない）。
# fail-closed: アンカーが一意でなければ1文字も書かずに exit 1。
import sys, io

IDX = 'src/index.tsx'
TAI = 'public/teacher-ai.js'
CHAIN_EXPECT = 103


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


def read(p):
    with io.open(p, encoding='utf-8') as f:
        return f.read()


def write(p, s):
    with io.open(p, 'w', encoding='utf-8') as f:
        f.write(s)


def sub(s, old, new, label):
    n = s.count(old)
    if n != 1:
        die('アンカー[' + label + '] の出現数が ' + str(n) + '（1でなければ中止）')
    return s.replace(old, new)


def chain_count(s):
    a = s.find('let _rootHtmlCache')
    b = s.find('_rootHtmlCache = t', a + 1)
    if a < 0 or b < 0:
        die('app.get(/) の .replace() チェーン範囲が見つからない')
    return s[a:b].count('.replace(')


src = read(IDX)
tai = read(TAI)

n0 = chain_count(src)
print('CHAIN before = ' + str(n0))
if n0 != CHAIN_EXPECT:
    die('チェーン件数が ' + str(CHAIN_EXPECT) + ' ではない（実測 ' + str(n0) + '）')

# ---- (1) 週のようす内の手書き点線枠「先生から」を削除（阪神マン欄に一本化） ----
OLD_SENSEI = """_kH+='<div style="margin-top:9px;border:2px dashed #fcd34d;border-radius:10px;min-height:58px;padding:8px"><div style="font-size:10px;color:#b45309;font-weight:700">✏️ 先生から</div></div>';"""
src = sub(src, OLD_SENSEI, '', '先生から点線枠')

# ---- (2) 励まし文＝連続記録を今年度の話として書く ----
OLD_PRAISE = """var praise='よく がんばっているね！この調子で つづけていこう！'; if((ov.maxStreak||0)>=5) praise='なんと '+ov.maxStreak+'日も つづけて べんきょうできたね！すごい力だよ！'; else if((ov.totalSubmissions||0)>=10) praise='たくさん べんきょうを つづけているね！その努力は きっと力になるよ！';"""
NEW_PRAISE = """var praise='今年度の記録、ここにちゃんと残っとるで。'; if((ov.totalSubmissions||0)===0) praise='今週はまだ白紙やな。それはそれでええ。今日5分だけやるとしたら、何にする？'; else if((ov.maxStreak||0)>=5) praise='今年度でいちばん長かったのは '+ov.maxStreak+'日つづけたとき。これは今年度ぜんたいの記録やで。'; else if((ov.totalSubmissions||0)>=10) praise='今年度でここまで '+(ov.totalSubmissions||0)+'回。ようここまで積んだな。';"""
src = sub(src, OLD_PRAISE, NEW_PRAISE, '励まし文')

src = sub(src,
          "最長れんぞく '+(ov.maxStreak||0)+'日",
          "今年度の最長れんぞく '+(ov.maxStreak||0)+'日",
          '最長れんぞくの見出し')

# ---- (3) UNIT_JP に中学以降の34単元（_unitGrade は触らない） ----
UNITS = [
    ('e7-pron', '中1 代名詞・複数形'),
    ('e7-be', '中1 be動詞'),
    ('e7-verb', '中1 一般動詞'),
    ('e7-3tan', '中1 三単現のs'),
    ('e7-ing', '中1 現在進行形'),
    ('e8-past', '中2 過去形・過去進行形'),
    ('j7-yomi', '中1 漢字の読み'),
    ('j7-kaki', '中1 漢字の書き'),
    ('j7-goi', '中1 語彙(類義・対義・熟語)'),
    ('j7-kanyou', '中1 慣用句・ことわざ・故事成語'),
    ('j8-yomi', '中2 漢字の読み'),
    ('j8-kaki', '中2 漢字の書き'),
    ('j8-goi', '中2 語彙・熟語の構成'),
    ('j8-kanyou', '中2 慣用句・故事成語'),
    ('j9-yomi', '中3 漢字の読み'),
    ('j9-kaki', '中3 漢字の書き'),
    ('j9-goi', '中3 語彙(類義・対義・熟語)'),
    ('j9-kanyou', '中3 慣用句・ことわざ・故事成語'),
    ('m7-moji', '中1 文字と式'),
    ('m7-eq', '中1 1次方程式'),
    ('m8-zukei', '中2 図形の性質'),
    ('m9-tenkai', '中3 展開と因数分解'),
    ('m10-kakuritsu', '高1 確率'),
    ('r7-lsf', '中1 光・音・力'),
    ('r7-plant', '中1 植物の世界'),
    ('s7-worldmap', '中1 世界の姿'),
    ('s7-climate', '中1 世界の気候と宗教'),
    ('s7-civ', '中1 文明のおこり'),
    ('s7-asuka', '中1 飛鳥〜平安'),
    ('s8-japan', '中2 日本の姿'),
    ('s8-kamakura', '中2 鎌倉〜安土桃山'),
    ('s8-edo', '中2 江戸時代'),
    ('s9-history', '中3 歴史：明治維新〜現代'),
    ('s10-rekishi', '高1 歴史総合'),
]
if len(UNITS) != 34:
    die('UNITS の件数が34ではない: ' + str(len(UNITS)))

ANCHOR = 'window.UNIT_JP = {'
if src.count(ANCHOR) != 1:
    die('window.UNIT_JP = { が1箇所ではない: ' + str(src.count(ANCHOR)))
_i = src.index(ANCHOR)
_j = src.index(chr(10), _i)
_obj = src[_i:_j]
for k, v in UNITS:
    if ("'" + k + "'") in _obj:
        die('UNIT_JP に既存キーがある: ' + k)
    for ng in [chr(96), '$' + '{', "'", chr(92)]:
        if ng in v:
            die('値に使えない文字が入っている: ' + k)
add = ''.join(["'" + k + "':'" + v + "'," for k, v in UNITS])
src = sub(src, ANCHOR, ANCHOR + add, 'UNIT_JP 先頭')

# ---- (1b) teacher-ai.js : KARTE の指示文を阪神マンの口調に ----
A_OLD = "out.push('・=== [KARTE:...] === … 個人カルテ。①よいところ ②気になるところ ③次の一歩。子ども向け。');"
A_NEW = "out.push('・=== [KARTE:...] === … 阪神マンから本人へのひとこと。子ども向け。');"
tai = sub(tai, A_OLD, A_NEW, 'KARTE 見出し行')

B_OLD = "out.push('    ※個人カルテのきまり（大事）:');"
B_NEW = chr(10).join([
    "out.push('    ※阪神マンのひとこと（大事）:');",
    "      out.push('      - 書くのは先生ではなく「阪神マン」。関西弁の話しことばで、元気に、親しみをもって書く。');",
    "      out.push('        例：〜やったな／〜しとったな／〜ちゃう／〜やで／〜か？。ていねい語（です・ます）は使わない。');",
    "      out.push('        文体は、上の共通のきまりより この阪神マンのきまりを優先する。');",
    "      out.push('      - ①よいところ ②気になるところ ③次の一歩 のような番号の見出しは使わない。通信簿の形にしない。');",
    "      out.push('      - 3〜4文・150字以内。ひとかたまりの話しことばで書く。');",
    "      out.push('      - 本人が書いたことば（ふりかえり・きもちの理由・計画）があれば、かならず「 」でそのまま引用する。');",
    "      out.push('        例：金曜に「複雑な円の面積が求められた！」って、自分で書いとったで。');",
    "      out.push('      - できていないことは責めない。事実として返したうえで、それは別に悪いことちゃう、と受けとめる。');",
    "      out.push('      - 最後は指示ではなく、本人が決められる形で終わる。決めるのは本人。');",
    "      out.push('        終わり方は週のタイプで変える。毎回おなじ問いかけをくり返さない:');",
    "      out.push('        ・うまくいった週 … なぜうまくいったかを本人に言わせる（例：なんでうまいこといったか、自分では何やと思う？）');",
    "      out.push('        ・つまずいた週 … 責めずに選ばせる（例：立て直すなら、どっちからいく？）');",
    "      out.push('        ・記録がない週 … ハードルを下げて一つ選ばせる（例：5分だけやるとしたら、何にする？）');",
    "      out.push('        上の例文はそのまま使わず、その子の先週の中身に合わせて書きかえる。');",
])
tai = sub(tai, B_OLD, B_NEW, 'KARTE きまり先頭')

# ---- 書き込み前の自己検証 ----
for need in ['中1 文字と式', '中2 鎌倉〜安土桃山', '今年度の最長れんぞく', '今週はまだ白紙やな']:
    if need not in src:
        die('検証失敗（src）: ' + need)
if '✏️ 先生から' in src:
    die('検証失敗: 先生から の点線枠が残っている')
for need in ['関西弁', '阪神マン', '毎回おなじ問いかけをくり返さない']:
    if need not in tai:
        die('検証失敗（teacher-ai）: ' + need)
if '①よいところ ②気になるところ ③次の一歩。子ども向け' in tai:
    die('検証失敗: KARTE 見出しが通信簿のまま')

n1 = chain_count(src)
print('CHAIN after = ' + str(n1))
if n1 != CHAIN_EXPECT:
    die('チェーン件数が変化した: ' + str(n1))

write(IDX, src)
write(TAI, tai)
print('OK: src/index.tsx と public/teacher-ai.js に適用しました')
