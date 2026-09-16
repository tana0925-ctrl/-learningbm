# -*- coding: utf-8 -*-
# KAHOOT_PRICE_V3_LEGACY
# v1 のとき 800 コインで買った子が、台帳にそのまま残っている（値段の記録が無い）。
# v2 の返金は「記録が無ければ 1500」で返してしまうので、実際に払った 800 で返すように直す。
# 台帳の中身には触らない。コードの既定値だけを直す。
import io
import sys

PATH = 'src/index.tsx'
SENTINEL = 'KHT_LEGACY_PRICE'

CONST_ANCHOR = 'const KHT_PRICE_NONE = 3000'
CONST_ADD = '\n// v1 のとき（2026-09-16）に 800 で買った子の台帳には値段が入っていない。\n// 返金はその子が実際に払った 800 で返す。\nconst KHT_LEGACY_PRICE = 800'

OLD = "    .map((b: any) => ({ u: String(b.u), c: Math.max(0, Math.floor(Number(b.c) || KHT_PRICE_MID)) }))"
NEW = "    .map((b: any) => ({ u: String(b.u), c: Math.max(0, Math.floor(Number(b.c) || KHT_LEGACY_PRICE)) }))"


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def main():
    s = io.open(PATH, encoding='utf-8').read()
    if SENTINEL in s:
        print('already applied: ' + SENTINEL)
        return 0
    before = chain_count(s)
    if s.count(CONST_ANCHOR) != 1:
        print('NG: 値段の定数のアンカーが 1 件でない')
        return 1
    if s.count(OLD) != 1:
        print('NG: 返金の行が 1 件でない')
        return 1
    t = s.replace(CONST_ANCHOR, CONST_ANCHOR + CONST_ADD)
    t = t.replace(OLD, NEW)
    ok = True
    if chain_count(t) != before:
        print('NG: チェーンが動いた')
        ok = False
    for label, want in (('const KHT_LEGACY_PRICE = 800', 1), ('|| KHT_LEGACY_PRICE)', 1), ('|| KHT_PRICE_MID)', 0)):
        if t.count(label) != want:
            print('NG: %s が %d 件（期待 %d）' % (label, t.count(label), want))
            ok = False
    for label in ('CREATE TABLE', 'ALTER TABLE', 'KHT_PRICE_STREAK = 500', 'KHT_PRICE_NONE = 3000'):
        if t.count(label) != s.count(label):
            print('NG: %s の数が動いた' % label)
            ok = False
    if t == s:
        print('NG: 中身が変わっていない')
        ok = False
    if not ok:
        print('NG: 自己点検に落ちたので書き込まない')
        return 1
    io.open(PATH, 'w', encoding='utf-8').write(t)
    print('OK: 返金の既定を 800 に直した（チェーン %d のまま）' % before)
    return 0


if __name__ == '__main__':
    sys.exit(main())
