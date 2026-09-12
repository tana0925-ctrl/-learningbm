#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# BEAM 調査 v3（読むだけ / 本番は GET だけ）
import io
import urllib.request

NL = chr(10)

def load(p):
    try:
        return io.open(p, encoding='utf-8', errors='ignore', newline='').read()
    except OSError:
        return ''

H = load('public/index.html')

LIVE = ''
try:
    req = urllib.request.Request('https://learning-bm.pages.dev/', headers={'User-Agent': 'inspect-beam'})
    op = urllib.request.urlopen(req, timeout=90)
    LIVE = op.read().decode('utf-8', 'ignore')
    print('live status =', op.status)
except Exception as e:
    print('live fetch NG:', repr(e))

print('local len =', len(H), '/ live len =', len(LIVE), '/ diff =', len(LIVE) - len(H))

def grep(tag, text, needle, width=300, limit=20):
    lines = text.split(NL)
    hits = [k for k, L in enumerate(lines) if needle in L]
    print('--- ' + tag + ' / ' + needle + ' hits=' + str(len(hits)))
    for k in hits[:limit]:
        print('   ' + str(k + 1) + ': ' + lines[k].strip()[:width])

print('=== LIVE の ビーム まわり')
for w in ('BEAM_RATIO_BASE', 'BEAM_RATIO_PER_LEVEL', 'beamDamageRatio', 'getBeamDamageLevel',
          'Math.floor(maxHp * ratio)', 'applyWarUpgradesToState'):
    grep('live', LIVE, w, 300, 20)

def show(tag, text, needle, before=3, after=6, limit=6, width=260):
    lines = text.split(NL)
    hits = [k for k, L in enumerate(lines) if needle in L]
    print('=== ' + tag + ' / ' + needle + ' hits=' + str(len(hits)))
    for k in hits[:limit]:
        for m in range(max(0, k - before), min(len(lines), k + after + 1)):
            mark = '>>' if m == k else '  '
            print(mark + str(m + 1) + ': ' + lines[m].strip()[:width])
        print('    -----')

print('=== たたかい ひらく ところ（ローカル）')
show('html', H, '// apply upgrades (beam stats)', 14, 14, 3, 260)
show('html', H, 'beamCharge +=', 6, 6, 6, 260)
show('html', H, 'beamCharge =', 3, 3, 12, 260)
show('html', H, 'enemyHpMul', 3, 4, 10, 260)
show('html', H, 'function warSpawnEnemy', 3, 26, 2, 260)

print('=== ratio table (local consts)')
for lv in (1, 2, 5, 10, 20, 26, 43, 50, 74, 94, 100):
    r = 0.12 + (lv - 1) * 0.0004
    print('lv', lv, 'ratio', round(r, 6), 'dmg@hp200', max(1, int(200 * r)), 'dmg@hp1000', max(1, int(1000 * r)))
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# BEAM 調査 v2（読むだけ）
import io

NL = chr(10)

def load(p):
    try:
        return io.open(p, encoding='utf-8', errors='ignore', newline='').read()
    except OSError:
        return ''

H = load('public/index.html')
S = load('src/index.tsx')

def show(tag, text, needle, before=3, after=5, limit=12, width=300):
    lines = text.split(NL)
    hits = [k for k, L in enumerate(lines) if needle in L]
    print('=== ' + tag + ' / ' + needle + ' hits=' + str(len(hits)))
    for k in hits[:limit]:
        for m in range(max(0, k - before), min(len(lines), k + after + 1)):
            mark = '>>' if m == k else '  '
            print(mark + str(m + 1) + ': ' + lines[m].strip()[:width])
        print('    -----')

for w in ('BEAM_RATIO_BASE', 'BEAM_RATIO_PER_LEVEL', 'BEAM_RATE_BASE', 'BEAM_RATE_PER_LEVEL',
          'BEAM_STUN_BASE', 'BEAM_STUN_PER_LEVEL', 'UPGRADE_MAX_LEVEL'):
    show('html', H, w, 2, 2, 6, 240)

show('html', H, 'applyWarUpgradesToState', 2, 3, 25, 240)
show('html', H, 'function applyWarUpgradesToState', 2, 34, 3, 300)
show('html', H, 'const ratio = Number(warState.beamDamageRatio', 2, 46, 2, 300)
show('html', H, 'beamDamageRatio:0.12', 12, 4, 3, 300)

print('=== chain')
i = S.index("app.get('/', async (c) => {")
j = S.index("app.get('/logout'", i)
print('chain =', S[i:j].count('.replace('))
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
