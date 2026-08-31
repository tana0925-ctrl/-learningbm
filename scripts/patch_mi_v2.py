#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MIしらべ v2 パッチ（先生の指示3件をまとめて適用）

  1. 入口の移設
     - ゲーム画面 左下の常設ピル2本（🔒ひみつのしつもん / 🧭MIしらべ）を廃止
     - 🔒ひみつのしつもん → 「システム」メニューの中へ（PC版・モバイル版の両方）
     - 🧭MIしらべ         → 「ステータス」画面の中へ
     ※ ひみつのしつもん は入口の場所だけを移し、遷移先(/himitsu)も機能も変更しない
  2. MIしらべの冒頭に、導入の説明画面を追加
  3. 受検完了で特典コイン（JSTの月で1回まで・付与判定はすべてサーバー側）

対象ファイル: src/index.tsx / src/mi.tsx / public/mi.js
public/index.html（6.3MB・CRLF）には一切さわらない。注入は src/index.tsx の
app.get('/') の .replace() チェーンだけで行う。

編集は「既存の一意な文字列 → 置換後の文字列」の組でのみ行い、
適用前に必ず出現回数が1件であることを確認する。何度実行しても二重適用しない。
"""
import base64
import gzip
import io
import json
import re
import sys

EDITS_B64 = "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"

TSX = 'src/index.tsx'
HTML = 'public/index.html'
ROOT_BLOCK_RE = re.compile(r"app\.get\('/', async \(c\) => \{.*?_rootHtmlCache = t", re.S)

# 移設後に index.html 上でこう見えるはず、という期待値（空実行で確認する）
SYS_PC_ANCHOR = ('<button class="w-full px-4 py-3 text-sm font-bold text-gray-700 hover:bg-gray-50 '
                 'flex items-center gap-2 border-t border-slate-100" '
                 'onclick="trySetMode(\'report\'); closeSysMenu()"><span>📝</span>バグ報告・要望</button>')
SYS_SP_ANCHOR = ('<button class="w-full px-4 py-3 text-sm font-bold text-gray-700 hover:bg-gray-50 '
                 'flex items-center gap-2 border-t border-slate-100 whitespace-nowrap" '
                 'onclick="trySetMode(\'report\'); closeSysMenuMobile()"><span>📝</span>バグ報告・要望</button>')
STATUS_ANCHOR = '<div id="classMissionCard"'


def root_block(src):
    m = ROOT_BLOCK_RE.search(src)
    if not m:
        sys.exit("FATAL: app.get('/') のブロックが見つかりません。中止します。")
    return m.group(0)


def load(path):
    with io.open(path, encoding='utf-8', newline='') as f:
        return f.read()


def save(path, text):
    with io.open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(text)


def main():
    edits = json.loads(gzip.decompress(base64.b64decode(EDITS_B64)).decode('utf-8'))

    before_tsx = load(TSX)
    before_block = root_block(before_tsx)
    before_replace_lines = [l for l in before_block.split('\n') if '.replace(' in l]
    print("適用前: app.get('/') 内の .replace( = %d 件 / 該当行 %d 行"
          % (before_block.count('.replace('), len(before_replace_lines)))

    # すでに適用済みか（v2 の目印）
    cur_mi = load('src/mi.tsx')
    if 'miGrantMonthlyReward' in cur_mi and 'closeSysMenuMobile()"><span>🔒</span>' in before_tsx:
        print('  [skip] すでに適用済みです。')
        return

    # ---- 適用 ----
    bucket = {}
    for e in edits:
        bucket.setdefault(e['file'], []).append(e)
    results = {}
    for path, es in bucket.items():
        cur = load(path)
        for i, e in enumerate(es):
            n = cur.count(e['old'])
            if n != 1:
                sys.exit('FATAL: %s の編集 %d/%d のアンカーが %d 件（1件であるべき）。中止します。\n---\n%s\n---'
                         % (path, i + 1, len(es), n, e['old'][:300]))
            cur = cur.replace(e['old'], e['new'])
        results[path] = cur
        print('  %s: %d 箇所を編集' % (path, len(es)))

    out_tsx = results[TSX]

    # ---- 安全確認 1: 消したのはピル2行だけで、他の .replace( 行は無傷か ----
    after_block = root_block(out_tsx)
    pill_keys = ("t = t.replace('</body>', '<a href=\"/himitsu\"",
                 "t = t.replace('</body>', '<a href=\"/mi\"")
    survivors = [l for l in before_replace_lines if not any(k in l for k in pill_keys)]
    removed = [l for l in before_replace_lines if any(k in l for k in pill_keys)]
    if len(removed) != 2:
        sys.exit('FATAL: 削除対象のピルが %d 行（2行であるべき）。中止します。' % len(removed))
    missing = [l for l in survivors if l not in after_block]
    if missing:
        sys.exit('FATAL: 残すべき .replace( 行が %d 行 失われました。中止します。' % len(missing))
    after_count = after_block.count('.replace(')
    expected = before_block.count('.replace(') - 2 + 3
    print("適用後: app.get('/') 内の .replace( = %d 件（期待 %d 件・既存 %d 行は無傷）"
          % (after_count, expected, len(survivors)))
    if after_count != expected:
        sys.exit('FATAL: .replace( の件数が想定外。中止します。')

    # ---- 安全確認 2: index.html に置換を空実行して入口の数を数える ----
    html = load(HTML)
    lines = [l.strip() for l in after_block.split('\n') if l.strip().startswith('t = t.replace(`')]
    sim = html
    for l in lines:
        m = re.match(r'^t = t\.replace\(`(.*)`, `(.*)`\)$', l, re.S)
        if not m:
            sys.exit('FATAL: 追加した置換行を解釈できません: %s' % l[:120])
        a, b = m.group(1), m.group(2)
        if sim.count(a) != 1:
            sys.exit('FATAL: index.html 側のアンカーが %d 件（1件であるべき）: %s' % (sim.count(a), a[:120]))
        sim = sim.replace(a, b)
    n_him = sim.count("location.href='/himitsu'")
    n_mi = sim.count("location.href='/mi'")
    n_pill = sim.count('position:fixed;left:8px')
    print('置換シミュレーション: ひみつのしつもん入口 %d 件 / MIしらべ入口 %d 件 / 旧ピル %d 件'
          % (n_him, n_mi, n_pill))
    if n_him != 2 or n_mi != 1 or n_pill != 0:
        sys.exit('FATAL: 入口の数が想定外です。中止します。')
    if sim.count('\r\n') != html.count('\r\n'):
        sys.exit('FATAL: CRLF の数が変わりました（行末を壊しています）。中止します。')
    print('CRLF数: %d（変化なし）' % html.count('\r\n'))

    # ---- 安全確認 3: コイン付与まわりの必須要素 ----
    mi = results['src/mi.tsx']
    need = [('mi_rewards の PRIMARY KEY(user_id, month_key)', 'PRIMARY KEY (user_id, month_key)'),
            ('JSTの月キー', 'miJstMonthKey'),
            ('サーバー側の付与処理', 'miGrantMonthlyReward'),
            ('progress への加算台帳', '_miCoinsApplied')]
    for label, key in need:
        if key not in mi:
            sys.exit('FATAL: %s が見つかりません。中止します。' % label)
    if '_miCoinsApplied' not in out_tsx:
        sys.exit('FATAL: PUT /api/student/progress の補填ロジックがありません。中止します。')

    for path, text in results.items():
        save(path, text)
    print('✅ 入口の移設 / 導入画面 / 月1回の特典コイン を適用しました。')


if __name__ == '__main__':
    main()
