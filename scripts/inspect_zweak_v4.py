#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# INSPECT_ZWEAK_V4
# updateSpawnButtonState の ヒント文の あて先を たしかめる。
# docs/zweak_probe_v3.txt にだけ 書く。

import io
import os
import re

NL = chr(10)
HTML = 'public/index.html'
OUT = 'docs/zweak_probe_v3.txt'

h = io.open(HTML, encoding='utf-8', newline='').read()
buf = []


def w(*a):
    buf.append(' '.join(str(x) for x in a))


PATS = [
    ('E_hint', "if\\(hint\\)\\s*hint\\.textContent\\s*=\\s*'タップで出陣';"),
    ('E_hint_loose', "hint\\.textContent\\s*=\\s*'タップで出陣'"),
    ('F_insert', "_rootHtmlCache = t"),
]
for name, pat in PATS:
    ms = list(re.finditer(pat, h))
    w('--- PAT', name, 'matches =', len(ms))
    for m in ms[:5]:
        w('   line =', h.count(NL, 0, m.start()) + 1, 'full =', repr(m.group(0)))

k = h.find('const move = 5 + clamp(spd,5,200)/14;')
w('=== tail of getWarUnitStatsFromMonster (pos ' + str(k) + ') ===')
w(repr(h[k:k + 1400]))

k2 = h.find("if(hint) hint.textContent = 'タップで出陣';")
w('=== around hint else-branch (pos ' + str(k2) + ') ===')
w(repr(h[max(0, k2 - 900):k2 + 200]))

w('INSPECT V4 DONE')

if not os.path.isdir('docs'):
    os.makedirs('docs')
io.open(OUT, 'w', encoding='utf-8', newline=NL).write(NL.join(buf) + NL)
print('wrote', OUT)
