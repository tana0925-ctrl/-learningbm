#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# BEAM 調査（読むだけ・何も書きかえない）
import io
import sys

NL = chr(10)

def load(p):
    try:
        return io.open(p, encoding='utf-8', errors='ignore', newline='').read()
    except OSError:
        return ''

H = load('public/index.html')
S = load('src/index.tsx')

def show(tag, text, needle, before=4, after=6, limit=12, width=300):
    lines = text.split(NL)
    hits = [k for k, L in enumerate(lines) if needle in L]
    print('=== ' + tag + ' / ' + needle + ' hits=' + str(len(hits)))
    for k in hits[:limit]:
        for m in range(max(0, k - before), min(len(lines), k + after + 1)):
            mark = '>>' if m == k else '  '
            print(mark + str(m + 1) + ': ' + lines[m].strip()[:width])
        print('    -----')

show('html', H, 'beamDamageRatio', 6, 8, 10, 320)
show('html', H, 'beamDamageLevel', 2, 3, 40, 240)
show('html', H, 'beamChargeLevel', 2, 3, 25, 240)
show('html', H, 'warDeployLimitUp', 2, 3, 25, 240)
show('html', H, 'warPowerSpeedUp', 2, 3, 20, 240)
show('html', H, 'warPowerCapUp', 2, 3, 20, 240)

print('=== counts')
for w in ('beamDamageRatio', 'beamDamageLevel', '0.12', 'beamChargeLevel', 'beamStunLevel'):
    print(w, H.count(w))

print('=== chain')
i = S.index("app.get('/', async (c) => {")
j = S.index("app.get('/logout'", i)
print('chain =', S[i:j].count('.replace('))
print('html len =', len(H))
