#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_analysis_v1b.py --- 分析タブ第1段階 追補

/teacher-ai.js が 404 になる件の修正。
Cloudflare Pages の _routes.json が public/ の新規ファイルを除外リストに入れないため、
リクエストが Worker に流れて 404 になっていた。
既存の defense2.js / g8*.js とまったく同じ作法で、ASSETS から返すルートを1本足す。
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

src = io.open(TSX, encoding='utf-8').read()
orig = src

SENTINEL = "app.get('/teacher-ai.js'"
ANCHOR = "let _rootHtmlCache: string | null = null"
NEW = ("app.get('/teacher-ai.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/teacher-ai.js'))); "
       "if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })\n")

if SENTINEL in src:
    print('⏭  すでに適用済み（スキップ）')
else:
    n = src.count(ANCHOR)
    if n != 1:
        print('❌ 中止: アンカーが %d 箇所（1箇所のはず）' % n)
        sys.exit(1)
    src = src.replace(ANCHOR, NEW + ANCHOR, 1)

def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

if root_replace_count(orig) != root_replace_count(src):
    print('❌ 中止: 置換チェーンの数が変わりました')
    sys.exit(1)
print('🔎 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx に /teacher-ai.js 配信ルートを追加しました')
else:
    print('… 変更なし')
