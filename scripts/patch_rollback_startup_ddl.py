#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_rollback_startup_ddl.py --- 緊急復旧: 起動時の索引作成をリクエスト経路から完全に外す

  症状: /api/teacher/classes, /api/teacher/all-students, /api/defense/status が 500。
       いずれも「先生のセッションは有効」なのに落ちている。
       共通しているのは「全リクエストが通るミドルウェア」だけ。

  今日そこに追加したのは CREATE INDEX 6本（v5の1本＋本日の5本）。
  try/catch で囲んではあるが、
    ・巨大な learning_results への CREATE INDEX が毎回タイムアウトし
    ・そのたびに D1 を掴んで、同じ isolate の他のクエリを巻き込む
  という筋が通る。索引は無くても動作するので、まるごと外して先に復旧させる。

  ★ このパッチは索引を「作らない」だけ。すでに出来ている索引は消しません（DROPしません）。
  ★ データには一切触れません。
"""
import io, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
src = io.open(TSX, encoding='utf-8').read()
orig = src

def fail(m):
    print('❌ 中止: ' + m); sys.exit(1)

START = "  // 📉 2026-09: 児童ごとの「直近N問」を索引で取れるようにする。"
END   = "  }\n  try {\n  const adminLoginId = c.env.ADMIN_LOGIN_ID || ''"

if START not in src:
    print('⏭  索引作成ブロックは既に外れています（スキップ）')
else:
    if src.count(START) != 1: fail('索引ブロックの目印が %d 個' % src.count(START))
    a = src.index(START)
    b = src.index(END, a)
    if b < 0: fail('索引ブロックの終わりが見つかりません')
    if src[b:b+4] != '  }\n': fail('索引ブロックの終端が想定と違います')
    block = src[a:b+4]   # catch を閉じる "  }\n" まで含める
    n_idx = block.count('CREATE INDEX')
    if n_idx != 6: fail('索引ブロックに CREATE INDEX が %d 本（6本のはず）' % n_idx)
    if 'ADMIN_LOGIN_ID' in block: fail('索引ブロックの範囲が広すぎます（admin判定が入っています）')
    if block.count('{') != block.count('}'): fail('索引ブロックの波かっこが釣り合っていません')
    note = ("  // 🚑 2026-09-03 復旧: ここにあった CREATE INDEX 6本を撤去した。\n"
            "  //   全リクエストが通る経路で巨大テーブルへの索引作成を await していたため、\n"
            "  //   /api/teacher/classes ・ /api/teacher/all-students ・ /api/defense/status など\n"
            "  //   複数のAPIが 500 になっていた（try/catch では止められない種類の巻き添え）。\n"
            "  //   索引が無くても動作は正しい（重いだけ）。索引を足すなら、リクエスト経路ではなく\n"
            "  //   マイグレーションか wrangler d1 execute で一度だけ流すこと（索引作成のSQL自体は書かない）。\n")
    src = src[:a] + note + src[b+4:]
    print('✅ CREATE INDEX 6本をリクエスト経路から撤去（%d文字）' % len(block))

# ---------------- 検証 ----------------
# 全リクエストが通る経路（起動時ミドルウェア）に CREATE INDEX が無いこと。
# ai_review_drafts の索引は「ひと往復」パネルのAPIでしか呼ばれない専用の ensure なので対象外。
_g0 = src.index('let _adminChecked = false')
_g1 = src.index('// -------------------- DB migration', _g0)
for _l in src[_g0:_g1].split('\n'):
    if 'CREATE INDEX' in _l and not _l.strip().startswith('//'):
        fail('起動時ミドルウェアに CREATE INDEX が残っています: ' + _l.strip()[:80])
for _bad in ['idx_class_members_class', 'idx_class_members_user', 'idx_contact_notes_class',
             'idx_messages_recipient', 'idx_messages_sender', 'idx_learning_results_user_time']:
    for _l in src.split('\n'):
        if _bad in _l and not _l.strip().startswith('//'):
            fail('撤去したはずの索引作成が残っています: ' + _bad)
print('🔎 全リクエスト経路で実行される CREATE INDEX は 0 本')

# ミドルウェアが必ず next() を呼ぶこと
i = src.index('let _adminChecked = false')
j = src.index('// -------------------- DB migration', i)
mid = src[i:j]
if mid.count('return next()') < 2: fail('ミドルウェアの next() が足りません')
for _l in mid.split('\n'):
    if 'CREATE INDEX' in _l and not _l.strip().startswith('//'): fail('ミドルウェアに CREATE INDEX が残っています')
if mid.count('{') != mid.count('}'): fail('ミドルウェアの波かっこが釣り合っていません')
print('🔎 起動時ミドルウェア: next() あり・索引作成なし・かっこ釣り合いOK')

for must in ["app.get('/api/teacher/classes'", "app.get('/api/teacher/all-students'",
             "app.get('/api/defense/status'", 'async function countMissionProgress(',
             'async function countMissionProgressRaw(', 'const MISSION_TTL_MS',
             'async function ensureMissionCacheTable(', 'let _adminChecked = false',
             'async function stuUnitAgg(', 'function fyStartYMD()',
             "app.get('/api/student/my-karte'", 'function downloadAllKartes']:
    if must not in src: fail('★残すはずのものが失われました: %s' % must)
print('🔎 ミッションのキャッシュ・カルテ・分析まわりはすべて残っています')

def root_replace_count(t):
    a = t.index("app.get('/', async (c) => {"); b = t.index("app.get('/logout'", a)
    return t[a:b].count('.replace(')
if root_replace_count(src) != root_replace_count(orig): fail('置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（変化なし）' % root_replace_count(src))

bal  = len(re.findall(r'<div\b', src))  - len(re.findall(r'</div>', src))
bal0 = len(re.findall(r'<div\b', orig)) - len(re.findall(r'</div>', orig))
if bal != bal0: fail('<div> の釣り合いが変わりました')
print('🔎 <div> の釣り合い: 変化なし')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
