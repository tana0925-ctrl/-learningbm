#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# INSPECT_CLASSES_V3 : 読み出すだけ（書き込みなし）。
#
#  (1) ⑥クラス・名簿の片づけで使う「足場」が1件ずつあるかを数える
#  (2) 右下の浮きボタン tspOpenBtn がどのファイルにあるかを探す
#  (3) 野生バトルの WILDIMG_V2 と、捕まえたときの演出まわりを出す
#
# ・どのファイルにも1バイトも書かない。
# ・grep -c は使わない。

import os
import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'

ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"

# (1) 片づけで使う足場（どれも1件であってほしい）
ANCHORS = [
    "btnGroup.className='flex items-center gap-2';",
    "header.appendChild(khtBox);",
    "header.appendChild(menusDivider);",
    "btnGroup.appendChild(delBtn);",
    "header.appendChild(btnGroup);",
    "card.appendChild(header);",
    "wrap.appendChild(card);",
    "khtBody.textContent = s;",
    "b.className = 'text-xs px-2 py-1 rounded font-bold border ' + cls;",
    "delBtn.textContent='削除';",
    "__CLASSES_TIDY_V1__",
]

# (3) 野生バトルで見たい目印
WILD_MARKS = [
    'WILDIMG_V2',
    'WILDIMG_V1',
    'battleLoop',
    'monSpriteHtml',
    'ゲットだぜ',
    'つかまえた',
    'ボール',
    'captureAnim',
    'wildSprite',
]


def read(path):
    with open(path, encoding='utf-8', newline='') as fp:
        return fp.read()


def positions(s, k, limit=14):
    out = []
    p = -1
    while True:
        p = s.find(k, p + 1)
        if p < 0:
            break
        out.append(p)
        if len(out) >= limit:
            break
    return out


def dump(s, start, end, label):
    start = max(0, start)
    end = min(len(s), end)
    print('===== %s : %d .. %d =====' % (label, start, end))
    chunk = 700
    p = start
    while p < end:
        q = min(p + chunk, end)
        print('--- %d' % p)
        print(repr(s[p:q]))
        p = q
    print('===== end %s =====' % label)


def main():
    s = read(SRC)
    print('SRC_LEN %d' % len(s))
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    print('CHAIN %d' % s[i:j].count('.replace('))

    print('')
    print('## (1) 片づけの足場')
    bad = 0
    for a in ANCHORS:
        n = s.count(a)
        flag = 'OK ' if (n == 1 or a == '__CLASSES_TIDY_V1__') else 'NG '
        if a == '__CLASSES_TIDY_V1__':
            flag = 'OK ' if n == 0 else 'NG '
        if flag == 'NG ':
            bad += 1
        print('%s n=%-3d %s' % (flag, n, a))
    print('ANCHOR_BAD %d' % bad)

    print('')
    print('## (2) tspOpenBtn をさがす')
    for name in sorted(os.listdir('public')):
        if not name.endswith('.js') and name != 'index.html':
            continue
        try:
            t = read(os.path.join('public', name))
        except Exception as e:
            print('  (読めない) %s %s' % (name, e))
            continue
        n = t.count('tspOpenBtn')
        if n:
            print('  %s : tspOpenBtn n=%d at=%s' % (name, n, positions(t, 'tspOpenBtn')))
            print('  %s : bottom-4 n=%d / qnFab n=%d' % (name, t.count('bottom-4'), t.count('qnFab')))
            dump(t, positions(t, 'tspOpenBtn')[0] - 400, positions(t, 'tspOpenBtn')[0] + 1400,
                 'tspOpenBtn in ' + name)

    print('')
    print('## (3) 野生バトル')
    h = read(PUB)
    print('PUB_LEN %d' % len(h))
    for m in WILD_MARKS:
        print('  MARK %-16s n=%-4d at=%s' % (m, h.count(m), positions(h, m)))

    p2 = positions(h, 'WILDIMG_V2')
    for idx, p in enumerate(p2[:2]):
        dump(h, p - 600, p + 2600, 'WILDIMG_V2 #%d' % (idx + 1))

    print('DONE')


if __name__ == '__main__':
    main()
