#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# BEAM 調査 v5（読むだけ）：たたかいの 中身と 対比較
import io
import re

NL = chr(10)
H = io.open('public/index.html', encoding='utf-8', errors='ignore', newline='').read()
HL = H.split(NL)

def grep(needle, width=240, limit=14):
    hits = [k for k, L in enumerate(HL) if needle in L]
    print('--- ' + needle + ' hits=' + str(len(hits)))
    for k in hits[:limit]:
        print('   ' + str(k + 1) + ': ' + HL[k].strip()[:width])

print('=== ユニットの こうげき まわり')
for w in ('atkCd', 'atkInterval', 'atkSpeed', 'u.atk', 'attackCd'):
    grep(w)

print('=== ステージの てき')
for w in ('enemyCastleHpMax:', 'playerCastleHpMax:', 'hpMul', 'atkMul'):
    grep(w, 240, 8)

print('=== てきの もとデータ（hp と atk が ならぶ ところ）')
pat = re.compile(r'hp\s*:\s*([0-9]+).{0,40}atk\s*:\s*([0-9]+)')
cnt = 0
hps = []
for k, L in enumerate(HL):
    m = pat.search(L)
    if m:
        cnt += 1
        hps.append(int(m.group(1)))
        if cnt <= 12:
            print('   ' + str(k + 1) + ': ' + L.strip()[:200])
print('   hp/atk ならぶ 行 =', cnt)
if hps:
    hps.sort()
    print('   hp min/中央/max =', hps[0], hps[len(hps)//2], hps[-1])

print('=== 対比較：段も 編成も 同じ、beamDamageLevel だけ かえる')
B = 0.12
for name, P in (('いま 0.0004', 0.0004), ('あん1 0.00075 スタンと そろえる', 0.00075), ('あん2 0.0012 チャージと そろえる', 0.0012)):
    r100 = B + 99 * P
    print('  ' + name + ' : Lv1=' + str(round(B, 5)) + ' / Lv100=' + str(round(r100, 5)) + ' / Lv100は Lv1の ' + str(round(r100 / B, 3)) + ' ばい')

print('=== ほかの きょうか（1レベルあたり 何% のびるか）')
print('  ビーム1 チャージ : 2 + 0.02/Lv  -> Lv100 3.98  (1.99ばい, 1レベル +1.000%)')
print('  ビーム2 いりょく : 0.12 + 0.0004/Lv -> Lv100 0.1596 (1.33ばい, 1レベル +0.333%)')
print('  ビーム3 スタン   : 800 + 5/Lv -> Lv100 1295ms (1.62ばい, 1レベル +0.625%)')
print('  しろレベル       : +5HP/Lv -> Lv100 +495 (もとHP600なら 1.83ばい, 1レベル +0.833%)')
print('  しゅつげき上限   : 7 + 1/かい -> 最大20 (2.86ばい, 13かい)')
print('  パワー上限       : 200 + 50/かい -> 700 (3.5ばい, 10かい)')
print('  パワー回復       : 2 + 0.3/かい -> 5 (2.5ばい, 10かい)')

print('=== 1はつの ビームで てきの 最大HPの 何%を けずるか')
for name, P in (('いま  ', 0.0004), ('あん1 ', 0.00075), ('あん2 ', 0.0012)):
    row = []
    for lv in (1, 26, 74, 94, 100):
        r = B + (lv - 1) * P
        row.append('Lv' + str(lv) + '=' + str(round(r * 100, 2)) + '%')
    print('  ' + name + ' : ' + ' / '.join(row))

print('=== ビームだけで てきを たおすのに 何ぱつ いるか')
for name, P in (('いま  ', 0.0004), ('あん1 ', 0.00075), ('あん2 ', 0.0012)):
    row = []
    for lv in (1, 74, 100):
        r = B + (lv - 1) * P
        n = 0
        hp = 1.0
        while hp > 0 and n < 999:
            hp -= r
            n += 1
        row.append('Lv' + str(lv) + '=' + str(n) + 'はつ')
    print('  ' + name + ' : ' + ' / '.join(row))
