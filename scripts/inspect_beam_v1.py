#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# BEAM 調査 v4（読むだけ / 本番は GET だけ）
import io
import re
import urllib.request

NL = chr(10)

def load(p):
    try:
        return io.open(p, encoding='utf-8', errors='ignore', newline='').read()
    except OSError:
        return ''

H = load('public/index.html')
HL = H.split(NL)

LIVE = ''
try:
    req = urllib.request.Request('https://learning-bm.pages.dev/', headers={'User-Agent': 'inspect-beam'})
    op = urllib.request.urlopen(req, timeout=90)
    LIVE = op.read().decode('utf-8', 'ignore')
    print('live status =', op.status)
except Exception as e:
    print('live fetch NG:', repr(e))
LL = LIVE.split(NL)
print('local len =', len(H), 'live len =', len(LIVE), 'diff =', len(LIVE) - len(H))

def owner(lines, idx):
    for k in range(idx, max(0, idx - 400), -1):
        s = lines[k]
        if re.match(r'^\s{0,6}(window\.[A-Za-z0-9_]+\s*=\s*(async\s*)?function|function\s+[A-Za-z0-9_]+)', s):
            return str(k + 1) + ': ' + s.strip()[:200]
    return '(みつからない)'

print('=== applyWarUpgradesToState を よぶ ところの もちぬし（local）')
for k, L in enumerate(HL):
    if 'applyWarUpgradesToState()' in L and 'function' not in L:
        print(str(k + 1) + ' <- ' + owner(HL, k))

print('=== おなじ（live）')
for k, L in enumerate(LL):
    if 'applyWarUpgradesToState()' in L and 'function' not in L:
        print(str(k + 1) + ' <- ' + owner(LL, k))

def dump(lines, a, b, tag):
    print('=== ' + tag + ' ' + str(a) + '-' + str(b))
    for m in range(a - 1, min(len(lines), b)):
        print(str(m + 1) + ': ' + lines[m].strip()[:240])

dump(HL, 42060, 42100, 'local たたかい リセット')
dump(HL, 38285, 38310, 'local ステージ えらぶ')

def grep(tag, text, needle, width=260, limit=12):
    lines = text.split(NL)
    hits = [k for k, L in enumerate(lines) if needle in L]
    print('--- ' + tag + ' / ' + needle + ' hits=' + str(len(hits)))
    for k in hits[:limit]:
        print('   ' + str(k + 1) + ': ' + lines[k].strip()[:width])

grep('local', H, 'CASTLE_HP_PER_LEVEL')
grep('local', H, 'warGetMaxUnits()')
grep('local', H, 'WAR_MAX_UNITS_MAX')

print('=== live の じっさいの しき（対比較：bdl だけ かえる）')
mb = re.search(r'const BEAM_RATIO_BASE = ([0-9.]+);', LIVE)
mp = re.search(r'const BEAM_RATIO_PER_LEVEL = ([0-9.]+);', LIVE)
md = re.search(r'const dmg = Math\.max\(1, Math\.floor\(maxHp \* ratio\)\);', LIVE)
print('live BASE =', mb.group(1) if mb else None, '/ PER =', mp.group(1) if mp else None, '/ dmg line =', bool(md))
if mb and mp:
    B = float(mb.group(1))
    P = float(mp.group(1))
    for hp in (120, 200, 400, 900, 2000):
        row = []
        for lv in (1, 26, 74, 94, 100):
            r = B + (lv - 1) * P
            row.append('Lv' + str(lv) + '=' + str(max(1, int(hp * r))))
        print('てきHP' + str(hp) + ' : ' + ' / '.join(row))
