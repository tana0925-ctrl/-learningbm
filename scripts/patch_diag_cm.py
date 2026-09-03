#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_diag_cm.py --- 500の中身を見るための一時的な診断口（あとで必ず消す）

  症状: class_members に触る3本だけが 500。users / teacher_accounts は正常。
  推測はやめて、D1 が返している生のエラー文を取る。

  GET /api/_diag/cm
      → class_members から1行だけ読み、成功なら {ok:true}、失敗なら {ok:false, err:"..."} を返す。
        データは返さない（件数のみ）。読み取りは1行。

  GET /api/_diag/cm?drop=1&t=fix20260903
      → 本日私が作った索引 2本だけを DROP する（idx_class_members_class / idx_class_members_user）。
        ・DROP INDEX はデータを一切消さない。索引が壊れている場合の唯一の直し方。
        ・他の索引・テーブルには触れない（名前を固定してある）。
        ・実行後にもう一度 class_members を1行読んで結果を返す。

  ★ 復旧が確認できたら、この診断口は削除する。
"""
import io, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
src = io.open(TSX, encoding='utf-8').read()
orig = src

def fail(m):
    print('❌ 中止: ' + m); sys.exit(1)

ANCHOR = "app.get('/api/auth/me', async (c) => {"
if src.count(ANCHOR) != 1:
    fail('/api/auth/me のアンカーが %d 個' % src.count(ANCHOR))

BLOCK = '''// 🩺 2026-09-03 一時的な診断口。復旧確認後に削除すること。
//    class_members に触るAPIだけが 500 になる原因を、推測ではなく D1 の生のエラー文で特定する。
//    児童・保護者の情報は一切返さない（件数と、エラー文だけ）。
app.get('/api/_diag/cm', async (c) => {
  const out: any = { ok: true, step: [] }
  if (c.req.query('drop') === '1' && c.req.query('t') === 'fix20260903') {
    for (const nm of ['idx_class_members_class', 'idx_class_members_user']) {
      try {
        await c.env.DB.prepare('DROP INDEX IF EXISTS ' + nm).run()
        out.step.push(nm + ': dropped')
      } catch (e: any) {
        out.step.push(nm + ': ' + (e?.message || String(e)))
      }
    }
  }
  try {
    const r = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM class_members').first<any>()
    out.cm = Number(r?.n || 0)
  } catch (e: any) {
    out.ok = false
    out.cm_error = (e?.name || 'Error') + ': ' + (e?.message || String(e))
    out.cm_cause = String((e as any)?.cause?.message || '')
  }
  try {
    await c.env.DB.prepare('SELECT id FROM classes LIMIT 1').first<any>()
    out.classes = 'ok'
  } catch (e: any) {
    out.classes = (e?.message || String(e))
  }
  return c.json(out)
})

'''

if 'api/_diag/cm' in src:
    print('⏭  診断口は追加ずみ（スキップ）')
else:
    src = src.replace(ANCHOR, BLOCK + ANCHOR, 1)
    print('✅ 診断口 /api/_diag/cm を追加しました（%d文字）' % len(BLOCK))

# ---------------- 検証 ----------------
if src.count("app.get('/api/_diag/cm'") != 1: fail('診断口が %d 個' % src.count("app.get('/api/_diag/cm'"))
if src.count(ANCHOR) != 1: fail('/api/auth/me が壊れました')
# 危険なSQLが「追加したブロックの中」に無いことを確認する（アプリ本体の DELETE は正常なもの）
for bad in ['DROP TABLE', 'DELETE FROM', 'UPDATE ', 'INSERT ']:
    if bad in BLOCK: fail('診断口に危険なSQLが入っています: %s' % bad)
n_drop = len(re.findall(r"DROP INDEX", src))
if n_drop != 1: fail('DROP INDEX の記述が %d 箇所（1箇所のはず）' % n_drop)
if "['idx_class_members_class', 'idx_class_members_user']" not in src:
    fail('DROP 対象の索引名が固定されていません')
print('🔎 DROP するのは名前を固定した索引2本だけ。DROP TABLE / DELETE は1つも無し')

for l in src.split('\n'):
    if 'CREATE INDEX' in l and not l.strip().startswith('//') and 'ai_review_drafts' not in l:
        fail('起動時の CREATE INDEX が復活しています')
print('🔎 起動時の CREATE INDEX は 0 本のまま')

for must in ["app.get('/api/teacher/classes'", "app.get('/api/teacher/all-students'",
             "app.get('/api/defense/status'", "app.get('/api/auth/me'",
             'let _adminChecked = false', 'async function countMissionProgress(']:
    if must not in src: fail('★残すはずのものが失われました: %s' % must)

def rc(t):
    a = t.index("app.get('/', async (c) => {"); b = t.index("app.get('/logout'", a)
    return t[a:b].count('.replace(')
if rc(src) != rc(orig): fail('置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（変化なし）' % rc(src))

bal  = len(re.findall(r'<div\b', src))  - len(re.findall(r'</div>', src))
bal0 = len(re.findall(r'<div\b', orig)) - len(re.findall(r'</div>', orig))
if bal != bal0: fail('<div> の釣り合いが変わりました')
print('🔎 <div> の釣り合い: 変化なし')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
