#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# INSPECT_ZWEAK_V3
# あて先を 正規表現で さがして、実物の 文字列を そのまま 書き出す。
# docs/zweak_probe_v2.txt にだけ 書く。src/ public/ には さわらない。

import io
import os
import re

NL = chr(10)
SRC = 'src/index.tsx'
HTML = 'public/index.html'
OUT = 'docs/zweak_probe_v2.txt'

s = io.open(SRC, encoding='utf-8', newline='').read()
h = io.open(HTML, encoding='utf-8', newline='').read()

buf = []


def w(*a):
    buf.append(' '.join(str(x) for x in a))


ROOT = "app.get('/', async (c) => {"
END = "app.get('/logout'"
i = s.index(ROOT)
j = s.index(END, i)
w('CHAIN =', s[i:j].count('.replace('))

w('COUNT _rootHtmlCache in src =', s.count('_rootHtmlCache'))
p = 0
n = 0
while n < 8:
    k = s.find('_rootHtmlCache', p)
    if k < 0:
        break
    n += 1
    w('=== _rootHtmlCache #' + str(n) + ' line=' + str(s.count(NL, 0, k) + 1) + ' ===')
    w(repr(s[max(0, k - 300):k + 300]))
    p = k + 1

w('=== CHAIN TAIL (last 2500 chars before logout) ===')
w(repr(s[max(i, j - 2500):j]))

PATS = [
    ('A_class', "'opacity-60\\s+grayscale\\s+cursor-not-allowed'"),
    ('B_label', "'こわい'\\s*:\\s*'タップで出陣'"),
    ('C_guard', "if\\(warState\\s*&&\\s*warState\\.zombieMode\\s*&&\\s*\\(id===152"),
    ('D_scale', "(const\\s+scale\\s*=\\s*)(1\\s*\\+\\s*Math\\.min\\(0\\.8,\\s*\\(lv-1\\)\\*0\\.03\\))(\\s*;)"),
]
for name, pat in PATS:
    ms = list(re.finditer(pat, h))
    w('--- PAT', name, 'matches =', len(ms))
    for m in ms[:4]:
        w('   line =', h.count(NL, 0, m.start()) + 1)
        w('   full =', repr(m.group(0)))
        for gi in range(1, (m.re.groups or 0) + 1):
            w('   g' + str(gi) + ' =', repr(m.group(gi)))

w('INSPECT V3 DONE')

if not os.path.isdir('docs'):
    os.makedirs('docs')
io.open(OUT, 'w', encoding='utf-8', newline=NL).write(NL.join(buf) + NL)
print('wrote', OUT)
