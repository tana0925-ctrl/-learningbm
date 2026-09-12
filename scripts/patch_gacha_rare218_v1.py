# -*- coding: utf-8 -*-
# GACHA_RARE_DEX_METRICS_V1
# ガチャの ほつれを 3つ 直す。public/index.html の 決まった文字列を そっくり 入れかえるだけ。
# 1) レア枠の 抽選が id 201-215 で 止まっていたのを 201-218 に する。
#    216 フェニックス / 217 ドラゴン / 218 グリフォン が ようやく 出るようになる。
#    ★6 ぜんたいの 確率は rollGacha() の しきい値（ノーマル 0.25% / プレミアム 2%）のまま。
#    1体あたりが 15分の1 から 18分の1 に 薄まるだけ。しきい値には さわらない。
# 2) 図鑑の「入手方法」が id 400-415 までしか ジムリーダー と 言わなかったのを 419 まで に する。
#    416-419 は GYM_LEADER_IDS に 入っている ジムリーダー。gacha フラグには さわらない。
# 3) recordGacha() が 定義だけで 一度も 呼ばれていなかったので、引いた ところで 呼ぶ。
# 一致しなければ 1文字も 書かずに 止まる（fail-closed）。
import io
import os
import sys

HTML = 'public/index.html'
SRC = 'src/index.tsx'
MARK = 'GACHA_RARE_DEX_METRICS_V1'
ROOT_HEAD = "app.get('/', async (c) => {"
ROOT_TAIL = "app.get('/logout'"

NL = chr(10)
BS = chr(92)
WS = ' ' + chr(9) + chr(13) + chr(10)

OLD1 = 'if (stage === 4) candidates = MONSTERS.filter(m => m.id >= 201 && m.id <= 215);'
NEW1 = ('if (stage === 4) candidates = MONSTERS.filter(m => m.id >= 201 && m.id <= 218);'
        + ' /* ' + MARK + ' 216-218 も 抽選に 入れる。確率の しきい値は rollGacha のまま。 */')

OLD2 = "if(id>=400 && id<=415) return 'ジムリーダー（ジムバトル）';"
NEW2 = ("if(id>=400 && id<=419) return 'ジムリーダー（ジムバトル）';"
        + ' /* ' + MARK + ' 416-419 も GYM_LEADER_IDS の ジムリーダー。 */')

OLD3 = NL.join([
    '            const result = rollGacha(type);',
    '            applyGachaResultData(result);',
    '            saveData();'])
NEW3 = NL.join([
    '            const result = rollGacha(type);',
    '            applyGachaResultData(result);',
    '            try { recordGacha(type, result); } catch(e) {} /* ' + MARK + ' */',
    '            saveData();'])

OLD4 = NL.join([
    '                results.push(result);',
    '                applyGachaResultData(result);'])
NEW4 = NL.join([
    '                results.push(result);',
    '                applyGachaResultData(result);',
    '                try { recordGacha(type, result); } catch(e) {} /* ' + MARK + ' */'])

PAIRS = [
    ('レア枠 201-218', OLD1, NEW1),
    ('図鑑 ジム 400-419', OLD2, NEW2),
    ('1回ガチャの記録', OLD3, NEW3),
    ('10連ガチャの記録', OLD4, NEW4),
]

ESCMAP = {'n': chr(10), 't': chr(9), 'r': chr(13), 'b': chr(8), 'f': chr(12),
          'v': chr(11), '0': chr(0), BS: BS, "'": "'", '"': '"',
          chr(96): chr(96), '/': '/'}


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


def chain_string_targets(seg):
    # src/index.tsx の .replace( チェーンの あて先（文字どおりの 文字列）を 集める。
    # 読みとれない形が あったら None を返す（＝ 何も 書かずに 止まる）。
    key = '.replace('
    out = []
    i = 0
    while True:
        i = seg.find(key, i)
        if i < 0:
            break
        j = i + len(key)
        while j < len(seg) and seg[j] in WS:
            j = j + 1
        if j < len(seg) and (seg[j] == "'" or seg[j] == '"'):
            q = seg[j]
            j = j + 1
            buf = []
            closed = False
            while j < len(seg):
                c = seg[j]
                if c == BS:
                    if j + 1 >= len(seg):
                        return None
                    n = seg[j + 1]
                    if n == 'u':
                        try:
                            buf.append(chr(int(seg[j + 2:j + 6], 16)))
                        except Exception:
                            return None
                        j = j + 6
                        continue
                    if n == 'x':
                        try:
                            buf.append(chr(int(seg[j + 2:j + 4], 16)))
                        except Exception:
                            return None
                        j = j + 4
                        continue
                    if n not in ESCMAP:
                        return None
                    buf.append(ESCMAP[n])
                    j = j + 2
                    continue
                if c == q:
                    closed = True
                    break
                if c == chr(10):
                    return None
                buf.append(c)
                j = j + 1
            if not closed:
                return None
            t = ''.join(buf)
            if t:
                out.append(t)
        i = i + len(key)
    return out


def main():
    for p in (HTML, SRC):
        if not os.path.exists(p):
            die(p + ' が 無い')

    h = io.open(HTML, encoding='utf-8', newline='').read()
    s = io.open(SRC, encoding='utf-8', newline='').read()

    # 番兵：もう 当てずみなら 何も さわらない（何回 流しても 同じ）
    if MARK in h:
        print('すでに 当てずみ。ファイルには さわらない。')
        return

    if s.count(ROOT_HEAD) != 1 or s.count(ROOT_TAIL) != 1:
        die('src/index.tsx の 家の入口が 一意で ない')
    i = s.index(ROOT_HEAD)
    j = s.index(ROOT_TAIL, i)
    chain = s[i:j].count('.replace(')
    print('src/index.tsx の チェーン = ' + str(chain) + ' 件（この直しでは src には さわらない）')

    if h.count('function recordGacha(') != 1:
        die('recordGacha の 定義が 1件で ない')
    if h.count('function rollGacha(') != 1:
        die('rollGacha の 定義が 1件で ない')

    for label, old, new in PAIRS:
        n = h.count(old)
        if n != 1:
            die('あて先「' + label + '」が ' + str(n) + ' 件（期待 1）')
        if new in h:
            die('あて先「' + label + '」の 新しい形が すでに ある')

    out = h
    for label, old, new in PAIRS:
        out = out.replace(old, new, 1)

    # 配信チェーンの あて先が 1件も こわれないことを 確かめる
    targets = chain_string_targets(s[i:j])
    if targets is None:
        die('チェーンの あて先を 読みとれない')
    if len(targets) < 50:
        die('チェーンの あて先が ' + str(len(targets)) + ' 件しか 読めない（少なすぎる）')
    for t in targets:
        if h.count(t) != out.count(t):
            die('チェーンの あて先が こわれる（' + str(h.count(t)) + ' -> ' + str(out.count(t)) + '）')
    print('チェーンの あて先 ' + str(len(targets)) + ' 件は 数が 変わっていない')

    checks = [
        ('新しいレア枠', out.count('m.id >= 201 && m.id <= 218'), 1),
        ('古いレア枠が 消えた', out.count('m.id <= 215'), 0),
        ('新しいジム範囲', out.count('if(id>=400 && id<=419)'), 1),
        ('古いジム範囲が 消えた', out.count('id<=415'), 0),
        ('recordGacha の 呼び出し', out.count('recordGacha(type, result);'), 2),
        ('ノーマルの しきい値 0.9975', out.count('r < 0.9975'), 1),
        ('プレミアムの しきい値 0.98', out.count('r < 0.98)'), 1),
        ('GACHA_RARES', out.count('GACHA_RARES.forEach'), 1),
        ('GYM_LEADER_IDS', out.count('416,417,418,419]'), 1),
        ('gacha: true の 数は そのまま', out.count('gacha: true'), h.count('gacha: true')),
        ('gacha: false の 数は そのまま', out.count('gacha: false'), h.count('gacha: false')),
        ('印', out.count(MARK), 4),
    ]
    ng = False
    for label, got, want in checks:
        if got != want:
            print('NG: ' + label + ' が ' + str(got) + '（期待 ' + str(want) + '）')
            ng = True
    if ng:
        sys.exit(1)
    if len(out) <= len(h):
        die('中身が ふえていない')

    io.open(HTML, 'w', encoding='utf-8', newline='').write(out)
    print('OK: public/index.html の 4か所に 当てた。src/index.tsx は さわっていない。')


main()
