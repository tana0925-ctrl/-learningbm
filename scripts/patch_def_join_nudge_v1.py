# -*- coding: utf-8 -*-
# DEF_JOIN_NUDGE_V1_PATCH
# 防衛戦に まだ一度も とうろくしていない子へのお知らせカードを配線する。
# 触るのは src/index.tsx だけ。public/index.html は手で編集しない。
# 足すのは「配る道（app.get）1本」と「読み込む replace 1本」だけ。
# アンカーが1件でなければ 1 文字も書かずに異常終了する（fail-closed）。
import io
import os
import sys

PATH = 'src/index.tsx'
ASSET = 'public/def_join_nudge.js'
SENTINEL = 'DEF_JOIN_NUDGE_V1_WIRED'

ROUTE_ANCHOR = "app.get('/defstage_monsters.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/defstage_monsters.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })"

ROUTE_ADD = "\n// " + SENTINEL + " 防衛戦のお知らせカードを配る道。student-karte.js とまったく同じ形。\napp.get('/def_join_nudge.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/def_join_nudge.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })"

INJECT_ANCHOR = "      t = t.replace('</body>', '<script src=\"/defstage_monsters.js?v=1\"></script></body>')"

INJECT_ADD = "\n      // 🏰 " + SENTINEL + " まだ とうろくしていない子にだけ出るお知らせカード。中身は public/def_join_nudge.js。\n      t = t.replace('</body>', '<script src=\"/def_join_nudge.js?v=1\"></script></body>')"

CHAIN_START = "app.get('/', async (c) => {"
CHAIN_END = "app.get('/logout'"


def chain_count(s):
    i = s.index(CHAIN_START)
    j = s.index(CHAIN_END, i)
    return s[i:j].count('.replace(')


def main():
    if not os.path.exists(ASSET):
        print('NG: ' + ASSET + ' が無い。先に置いてから流すこと')
        return 1

    s = io.open(PATH, encoding='utf-8').read()

    if SENTINEL in s:
        print('already applied: ' + SENTINEL + ' / 何もしない')
        return 0

    before = chain_count(s)
    if before != 76:
        print('NG: チェーンが %d 件（期待 76）' % before)
        return 1

    for label, text in (('配る道のアンカー', ROUTE_ANCHOR), ('読み込みのアンカー', INJECT_ANCHOR)):
        n = s.count(text)
        if n != 1:
            print('NG: %s が %d 件（期待 1）' % (label, n))
            return 1

    if "app.get('/def_join_nudge.js'" in s:
        print('NG: 同じ道がもうある')
        return 1

    t = s.replace(ROUTE_ANCHOR, ROUTE_ANCHOR + ROUTE_ADD)
    t = t.replace(INJECT_ANCHOR, INJECT_ANCHOR + INJECT_ADD)

    ok = True
    after = chain_count(t)
    if after != 77:
        print('NG: チェーンが %d 件（期待 77）' % after)
        ok = False
    for label, want in (
        ("app.get('/def_join_nudge.js'", 1),
        ('/def_join_nudge.js?v=1', 1),
        ("app.get('/student-karte.js'", 1),
        ("app.get('/defstage_monsters.js'", 1),
        ('/defstage_monsters.js?v=1', 1),
        ('/student-karte.js?v=1', 1),
        (SENTINEL, 2),
    ):
        got = t.count(label)
        if got != want:
            print('NG: %s が %d 件（期待 %d）' % (label, got, want))
            ok = False
    if t == s:
        print('NG: 中身が変わっていない')
        ok = False
    if not ok:
        print('NG: 自己点検に落ちたので書き込まない')
        return 1

    io.open(PATH, 'w', encoding='utf-8').write(t)
    print('OK: ' + PATH + ' を更新した（チェーン %d -> %d）' % (before, after))
    return 0


sys.exit(main())
