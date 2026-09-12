# -*- coding: utf-8 -*-
# HS_NEXT_RECALL_V1
# 家庭学習の「次、どうすると学びの天気が良くなる？」の入力の すぐ上に、
# まえに じぶんが 書いた「つぎにすること」を 直近3回ぶん 出すための 配線だけを 足す。
# 中身は public/hs_next_recall.js。public/index.html は 手で さわらない。
# 一致しなければ 1文字も 書かずに 止まる（fail-closed）。
import io
import os
import sys

SRC = 'src/index.tsx'
JS = 'public/hs_next_recall.js'
MARK = 'HS_NEXT_RECALL_V1_WIRED'

ROOT_HEAD = "app.get('/', async (c) => {"
ROOT_TAIL = "app.get('/logout'"

ANCHOR_ROUTE = "// DEF_JOIN_NUDGE_V1_WIRED"
ANCHOR_CHAIN = ".replace('</body>', '<script src=\"/shiny-news.js?v=1\"></script></body>')"

ROUTE_ADD = (
    "// HS_NEXT_RECALL_V1_WIRED まえの「つぎにすること」を配る道。def_join_nudge.js とまったく同じ形。\n"
    "app.get('/hs_next_recall.js', async (c) => { try { const a = await c.env.ASSETS?."
    "fetch(new Request(new URL('https://assets/hs_next_recall.js'))); if (a && a.status === 200) "
    "return new Response(await a.text(), { headers: { 'content-type': "
    "'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } "
    "catch (e) {} return c.text('not found', 404) })\n\n"
)

CHAIN_ADD = (
    "\n      // HS_NEXT_RECALL_V1_WIRED 入力の すぐ上に まえの「つぎにすること」を 出すだけ。"
    "中身は public/hs_next_recall.js。\n"
    "      t = t.replace('</body>', '<script src=\"/hs_next_recall.js?v=1\"></script></body>')"
)


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


def chain_count(text):
    i = text.index(ROOT_HEAD)
    j = text.index(ROOT_TAIL, i)
    return text[i:j].count('.replace(')


def main():
    if not os.path.exists(SRC):
        die('src/index.tsx が無い')
    if not os.path.exists(JS):
        die('public/hs_next_recall.js が無い（先に置いてください）')

    s = io.open(SRC, encoding='utf-8', newline='').read()

    # 番兵：もう配線ずみなら 何も さわらない（何回流しても 同じ結果）
    if MARK in s:
        print('すでに配線ずみ。ファイルには さわらない。')
        return

    if ROOT_HEAD not in s or ROOT_TAIL not in s:
        die('家の入口が 見つからない')

    for label, text in (('道の場所', ANCHOR_ROUTE), ('読み込みの場所', ANCHOR_CHAIN)):
        n = s.count(text)
        if n != 1:
            die('アンカー %s が %d 件（期待 1）' % (label, n))

    if "app.get('/hs_next_recall.js'" in s:
        die('同じ道が もうある')

    before = chain_count(s)

    out = s.replace(ANCHOR_ROUTE, ROUTE_ADD + ANCHOR_ROUTE, 1)
    out = out.replace(ANCHOR_CHAIN, ANCHOR_CHAIN + CHAIN_ADD, 1)

    after = chain_count(out)
    if after != before + 1:
        die('チェーンが %d から %d（期待 %d）' % (before, after, before + 1))
    if out.count("app.get('/hs_next_recall.js'") != 1:
        die('配る道が 1本に ならなかった')
    if out.count('/hs_next_recall.js?v=1') != 1:
        die('読み込みが 1件に ならなかった')
    if out.count(MARK) != 2:
        die('印が %d 件（期待 2）' % out.count(MARK))
    if len(out) <= len(s):
        die('中身が ふえていない')

    io.open(SRC, 'w', encoding='utf-8', newline='').write(out)
    print('OK: チェーン %d -> %d' % (before, after))


main()
