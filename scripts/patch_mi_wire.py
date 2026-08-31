#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
🧭 MIしらべ を src/index.tsx に配線する（4行だけ）。

src/index.tsx は 12,900行・900KB あり、web エディタでの全文編集は危険なので
既存の scripts/patch_*.py と同じやり方でパッチを当てる。

やること（すべて「1行の追記」。既存行の書き換えは一切しない）:
  1. import { registerMi } from './mi'          … 先頭の import の直後
  2. registerMi(app)                             … 末尾 export default app の直前
  3. 児童ゲーム画面の </body> 直前に MIしらべ の入口リンクを1本追記
     ※ app.get('/') の .replace() チェーンの既存行には触らない
  4. 教師ダッシュボードのヘッダに /teacher-mi へのリンクを1本追記

安全確認:
  - 適用前後で app.get('/') 内の .replace( の数を数え、既存分が消えていないこと
  - 既存の .replace( 行が1行も欠けていないこと
  - 何度実行しても二重適用されないこと（適用済みならスキップ）
"""
import io
import re
import sys

PATH = 'src/index.tsx'

ANCHOR_IMPORT = "import { getCookie, setCookie, deleteCookie } from 'hono/cookie'"
ADD_IMPORT = "\nimport { registerMi } from './mi'"

ANCHOR_EXPORT = "\nexport default app"
ADD_REGISTER = "\n// 🧭 MIしらべ（/mi, /teacher-mi, /api/mi/*, /api/teacher/mi/*）を登録\nregisterMi(app)\n"

ANCHOR_CACHE = "      _rootHtmlCache = t"
ADD_PILL = (
    "      // 🧭 MIしらべ への入口。既存の置換行には一切さわらず、</body> の直前に1本追記するだけ。\n"
    "      t = t.replace('</body>', '<a href=\"/mi\" style=\"position:fixed;left:8px;bottom:40px;"
    "z-index:2147483000;background:rgba(224,231,255,.97);color:#4338ca;border:1px solid #a5b4fc;"
    "border-radius:9999px;padding:5px 10px;font-size:11px;font-weight:bold;text-decoration:none;"
    "box-shadow:0 1px 3px rgba(0,0,0,.2)\" title=\"MIしらべ：いまの自分の「好き・とくい」を見てみよう\">"
    "🧭MIしらべ</a></body>')\n"
)

ANCHOR_TEACHER = ('<a href="/" class="text-sm px-3 py-1 rounded bg-emerald-100 hover:bg-emerald-200 '
                  'text-emerald-700 font-bold transition">🎮 ゲーム画面へ</a>')
ADD_TEACHER_LINK = ('<a href="/teacher-mi" class="text-sm px-3 py-1 rounded bg-indigo-100 '
                    'hover:bg-indigo-200 text-indigo-700 font-bold transition">🧭 MIしらべ</a>\n          ')

ROOT_BLOCK_RE = re.compile(r"app\.get\('/', async \(c\) => \{.*?_rootHtmlCache = t", re.S)


def root_block(src):
    m = ROOT_BLOCK_RE.search(src)
    if not m:
        sys.exit('FATAL: app.get(\'/\') のブロックが見つかりません。中止します。')
    return m.group(0)


def replace_lines(src):
    return [ln for ln in root_block(src).split('\n') if '.replace(' in ln]


def main():
    with io.open(PATH, encoding='utf-8', newline='') as f:
        src = f.read()

    before_block = root_block(src)
    before_count = before_block.count('.replace(')
    before_lines = replace_lines(src)
    print('適用前: app.get(\'/\') 内の .replace( = %d 件 / 該当行 %d 行' % (before_count, len(before_lines)))

    out = src
    applied = []

    # 1) import
    if "from './mi'" in out:
        print('  [skip] import は適用済み')
    else:
        if out.count(ANCHOR_IMPORT) != 1:
            sys.exit('FATAL: import のアンカーが %d 件（1件であるべき）' % out.count(ANCHOR_IMPORT))
        out = out.replace(ANCHOR_IMPORT, ANCHOR_IMPORT + ADD_IMPORT)
        applied.append('import registerMi')

    # 2) registerMi(app)
    if 'registerMi(app)' in out:
        print('  [skip] registerMi(app) は適用済み')
    else:
        if out.count(ANCHOR_EXPORT) != 1:
            sys.exit('FATAL: export default app のアンカーが %d 件（1件であるべき）' % out.count(ANCHOR_EXPORT))
        out = out.replace(ANCHOR_EXPORT, ADD_REGISTER + ANCHOR_EXPORT)
        applied.append('registerMi(app)')

    # 3) 児童ゲーム画面の入口リンク
    if 'href="/mi"' in out:
        print('  [skip] 児童側の入口リンクは適用済み')
    else:
        if out.count(ANCHOR_CACHE) != 1:
            sys.exit('FATAL: _rootHtmlCache のアンカーが %d 件（1件であるべき）' % out.count(ANCHOR_CACHE))
        out = out.replace(ANCHOR_CACHE, ADD_PILL + ANCHOR_CACHE)
        applied.append('児童ゲーム画面の入口リンク')

    # 4) 教師ダッシュボードのリンク
    if 'href="/teacher-mi"' in out:
        print('  [skip] 教師側のリンクは適用済み')
    else:
        if out.count(ANCHOR_TEACHER) != 1:
            sys.exit('FATAL: 教師ヘッダのアンカーが %d 件（1件であるべき）' % out.count(ANCHOR_TEACHER))
        out = out.replace(ANCHOR_TEACHER, ADD_TEACHER_LINK + ANCHOR_TEACHER)
        applied.append('教師ダッシュボードのリンク')

    # ---- 安全確認 ----
    after_count = root_block(out).count('.replace(')
    after_block = root_block(out)
    missing = [ln for ln in before_lines if ln not in after_block]
    print('適用後: app.get(\'/\') 内の .replace( = %d 件' % after_count)
    if missing:
        sys.exit('FATAL: 既存の .replace( 行が %d 行 失われました。中止します。' % len(missing))
    expected = before_count + (1 if '児童ゲーム画面の入口リンク' in applied else 0)
    if after_count != expected:
        sys.exit('FATAL: .replace( の件数が想定外（期待 %d / 実際 %d）。中止します。' % (expected, after_count))

    if out == src:
        print('変更はありません（すべて適用済み）。')
        return

    with io.open(PATH, 'w', encoding='utf-8', newline='') as f:
        f.write(out)
    print('適用しました: ' + '、'.join(applied))
    print('✅ 既存の置換マーカーはすべて無傷です。')


if __name__ == '__main__':
    main()
