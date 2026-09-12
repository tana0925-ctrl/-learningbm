#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# INSPECT_ZWEAK_V2
# しらべた結果を docs/zweak_probe_v1.txt に書き出すだけ。
# src/ public/ には いっさい さわらない。

import io
import os

NL = chr(10)
SRC = 'src/index.tsx'
HTML = 'public/index.html'
OUT = 'docs/zweak_probe_v1.txt'

s = io.open(SRC, encoding='utf-8', newline='').read()
h = io.open(HTML, encoding='utf-8', newline='').read()

buf = []


def w(*a):
    buf.append(' '.join(str(x) for x in a))


ROOT = "app.get('/', async (c) => {"
END = "app.get('/logout'"

w('LEN src =', len(s), ' html =', len(h))
w('root anchor count =', s.count(ROOT))
w('end anchor count =', s.count(END))
i = s.index(ROOT)
j = s.index(END, i)
w('CHAIN =', s[i:j].count('.replace('))
w('insert-at count =', s.count(NL + '  _rootHtmlCache = t' + NL))
w('CR in html =', (chr(13) in h))

KEYS = [
    'LIMITED_DAILY_IDS',
    'getWarUnitStatsFromMonster',
    'こわい',
    'zombieMode',
    'warState.zombieMode',
    '__ZWAR_UNLOCK_V1__',
    '__ZWEAK_V1__',
    'warUnitStats',
]
for k in KEYS:
    w('COUNT', k, 'src=', s.count(k), 'html=', h.count(k))


def dump(txt, key, before, after, label, limit=12):
    p = 0
    n = 0
    while n < limit:
        k = txt.find(key, p)
        if k < 0:
            break
        n += 1
        line = txt.count(NL, 0, k) + 1
        w('===== ' + label + ' #' + str(n) + ' pos=' + str(k) + ' line=' + str(line) + ' =====')
        w(repr(txt[max(0, k - before):k + after]))
        p = k + 1
    w('----- ' + label + ' shown = ' + str(n))


dump(h, 'LIMITED_DAILY_IDS', 400, 700, 'HTML LIMITED_DAILY_IDS', 12)
dump(h, 'getWarUnitStatsFromMonster', 80, 2200, 'HTML getWarUnitStatsFromMonster', 4)
dump(h, 'こわい', 600, 250, 'HTML KOWAI', 10)
dump(s, 'LIMITED_DAILY_IDS', 300, 500, 'SRC LIMITED_DAILY_IDS', 8)
dump(s, 'こわい', 300, 250, 'SRC KOWAI', 10)

w('INSPECT DONE')

if not os.path.isdir('docs'):
    os.makedirs('docs')
io.open(OUT, 'w', encoding='utf-8', newline=NL).write(NL.join(buf) + NL)
print('wrote', OUT, len(NL.join(buf)), 'chars')
