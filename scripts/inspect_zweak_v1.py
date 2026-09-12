#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# INSPECT_ZWEAK_V1
# 読み取りだけ。1文字も書かない。
# ゾンビ襲来の「出撃禁止」判定と getWarUnitStatsFromMonster の
# 正確なあて先を実測するための調査用。

import io

NL = chr(10)
SRC = 'src/index.tsx'
HTML = 'public/index.html'

s = io.open(SRC, encoding='utf-8', newline='').read()
h = io.open(HTML, encoding='utf-8', newline='').read()

ROOT = "app.get('/', async (c) => {"
END = "app.get('/logout'"

print('LEN src =', len(s), ' html =', len(h))
print('root anchor count =', s.count(ROOT))
print('end anchor count =', s.count(END))
i = s.index(ROOT)
j = s.index(END, i)
print('CHAIN =', s[i:j].count('.replace('))
print('insert-at count =', s.count(NL + '  _rootHtmlCache = t' + NL))
print('CR in html =', (chr(13) in h))

KEYS = [
    'LIMITED_DAILY_IDS',
    'getWarUnitStatsFromMonster',
    'こわい',
    'zombieMode',
    'warState.zombieMode',
    '__ZWAR_UNLOCK_V1__',
    '__ZWEAK_V1__',
]
for k in KEYS:
    print('COUNT', k, 'src=', s.count(k), 'html=', h.count(k))


def dump(txt, key, before, after, label, limit=12):
    p = 0
    n = 0
    while n < limit:
        k = txt.find(key, p)
        if k < 0:
            break
        n += 1
        line = txt.count(NL, 0, k) + 1
        print('===== ' + label + ' #' + str(n) + ' pos=' + str(k) + ' line=' + str(line) + ' =====')
        print(repr(txt[max(0, k - before):k + after]))
        p = k + 1
    print('----- ' + label + ' shown = ' + str(n))


dump(h, 'LIMITED_DAILY_IDS', 400, 600, 'HTML LIMITED_DAILY_IDS', 12)
dump(h, 'getWarUnitStatsFromMonster', 80, 2000, 'HTML getWarUnitStatsFromMonster', 4)
dump(h, 'こわい', 500, 200, 'HTML KOWAI', 10)
dump(s, 'LIMITED_DAILY_IDS', 300, 500, 'SRC LIMITED_DAILY_IDS', 8)
dump(s, 'こわい', 300, 200, 'SRC KOWAI', 10)

print('INSPECT DONE')
