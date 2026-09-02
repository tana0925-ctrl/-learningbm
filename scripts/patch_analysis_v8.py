#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_analysis_v8.py --- 児童画面に /student-karte.js が入らなかった不具合の修正

v7 で入れた注入は、目印を
    <script src="/typeshoot.js"></script></body>
にしていた。ところが置換チェーンの「もっと前」の行が、すでに </body> の直前に
中学生向けスクリプト群を差し込んでいるため、この並びは本番では存在しなくなっていた。
（本番HTMLを取得して確認: student-karte.js のタグが1つも入っていなかった）

→ 目印を </body> だけにする。index.html 内に </body> は1つだけなので確実に当たる。
"""
import io, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
HTML = os.path.join(ROOT, 'public', 'index.html')

src = io.open(TSX, encoding='utf-8').read()
orig = src

def fail(msg):
    print('❌ 中止: ' + msg); sys.exit(1)

def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

BEFORE = root_replace_count(orig)

OLD = ("      t = t.replace('<script src=\"/typeshoot.js\"></script></body>', "
       "'<script src=\"/typeshoot.js\"></script><script src=\"/student-karte.js?v=1\"></script></body>')")
NEW = ("      t = t.replace('</body>', "
       "'<script src=\"/student-karte.js?v=1\"></script></body>')")

if NEW in src:
    print('⏭  目印の修正は適用済み（スキップ）')
elif src.count(OLD) == 1:
    src = src.replace(OLD, NEW, 1)
    print('✅ 目印を </body> に変更しました')
else:
    fail('v7 で入れた注入行が見つかりません（%d 箇所）' % src.count(OLD))

# ---------------- 検証 ----------------
after = root_replace_count(src)
if after != BEFORE:
    fail('置換チェーンの数が変わりました（%d → %d）' % (BEFORE, after))
print('🔎 置換チェーン: %d 件（変化なし）' % after)

if src.count('student-karte.js?v=1') != 1:
    fail('注入行が %d 箇所（1箇所のはず）' % src.count('student-karte.js?v=1'))

# 目印が本番HTMLに実在し、かつ1つだけであること
_h = io.open(HTML, encoding='utf-8', errors='replace').read()
if _h.count('</body>') != 1:
    fail('public/index.html の </body> が %d 個（1個のはず）' % _h.count('</body>'))
print('🔎 public/index.html の </body> は1つだけ → 確実に当たります')

# 既存の行も </body> を目印にしている（中学生向けスクリプト群）。
# それぞれ最初の </body> を置き換えて </body> を書き戻すので、順番によらず全部入る。
a = src.index("app.get('/', async (c) => {")
b = src.index("app.get('/logout'", a)
seg = src[a:b]
n_body = seg.count("'</body>'")
print('🔎 </body> を目印にしている行: %d 件（既存の2件＋今回の1件）' % n_body)
if n_body < 1:
    fail('</body> を目印にしている行がありません')

# チェーン全体を実際に回して、タグがちょうど1つ入ることを確かめる
html = io.open(HTML, encoding='utf-8', errors='replace').read()
sim = html
for pat in re.findall(r"t = t\.replace\('</body>', '([^']*)'\)", seg):
    sim = sim.replace('</body>', pat, 1)
if sim.count('student-karte.js?v=1') != 1:
    fail('チェーンを回した結果、student-karte.js のタグが %d 個（1個のはず）' % sim.count('student-karte.js?v=1'))
if sim.count('</body>') != 1:
    fail('チェーンを回した結果、</body> が %d 個（1個のはず）' % sim.count('</body>'))
print('🔎 置換チェーンを実際に回して確認: student-karte.js のタグがちょうど1つ入りました')

for must in ["app.get('/api/student/my-karte'", "app.post('/api/teacher/karte-share'",
             "app.get('/student-karte.js'", '/teacher-ai.js?v=5',
             '📅 今週のようす（', 'async function stuUnitAgg(']:
    if must not in src: fail('必須の要素が失われました: %s' % must)

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました')
else:
    print('… 変更なし')
