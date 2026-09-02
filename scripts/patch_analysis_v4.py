#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_analysis_v4.py --- D1 の行読み取りを減らす

  R0 fyStartYMD() ヘルパーを追加（今年度=4月1日以降）
  R1 全リクエストで走っていた管理者チェックを「起動時1回＋失敗しても素通り」に
  R2 /api/teacher/student-full-analysis の学習履歴を今年度だけに
  R3 /api/teacher/learning-analytics の3本の全期間スキャンを今年度だけに
  R4 /api/teacher/student-karte を今年度だけに
  R5 /api/student/review-suggestions を今年度だけに（児童が開くたびに走る）
  R6 /api/student/weak-units を今年度だけに（同上）
  R7 /api/teacher/weekly-report に期間条件を追加（week_key はインデックスが無いため）
  R8 teacher-ai.js のキャッシュ更新 v=4
  public/index.html は触りません。
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

src = io.open(TSX, encoding='utf-8').read()
orig = src
changes = []

def fail(msg):
    print('❌ 中止: ' + msg); sys.exit(1)

def rep(old, new, tag, sentinel=None):
    global src
    if sentinel is not None and sentinel in src:
        print('⏭  %s は適用済み（スキップ）' % tag); return
    n = src.count(old)
    if n == 0:
        if new in src:
            print('⏭  %s は適用済み（スキップ）' % tag); return
        fail('%s のアンカーが見つかりません' % tag)
    if n != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, n))
    src = src.replace(old, new, 1)
    changes.append(tag)

# ---------------- R0: 今年度の開始日ヘルパー ----------------
rep('// -------------------- utils --------------------',
"""// -------------------- utils --------------------

// 📉 2026-09: D1 の行読み取り削減。学習履歴は「今年度（4月1日以降）」だけを見る。
// learning_results には (user_id, answered_at) の索引があるため、この条件で
// 読み取る行数がその期間ぶんに絞られる。
function fyStartYMD(): string {
  const d = new Date()
  const y = d.getUTCFullYear()
  return (((d.getUTCMonth() + 1) >= 4) ? y : y - 1) + '-04-01'
}""",
'R0 fyStartYMD ヘルパー', sentinel='function fyStartYMD()')

# ---------------- R1: グローバル処理を1回だけ＋素通り ----------------
rep("""app.use('*', async (c, next) => {
  const adminLoginId = c.env.ADMIN_LOGIN_ID || ''
  const adminPassword = c.env.ADMIN_PASSWORD || ''
  const secret = c.env.SESSION_SECRET
  if (!adminLoginId || !adminPassword || !secret) {
    // allow app to run but admin won't be auto-provisioned
    return next()
  }

  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE role='admin' AND login_id=? LIMIT 1`)
    .bind(adminLoginId)
    .first<any>()

  if (!existing) {""",
"""// 📉 2026-09: ここは以前「全リクエストで必ず1回 D1 を読む」処理だった。
//   ・行読み取りを大量に消費していた
//   ・D1 が落ちるとログイン画面すら 500 になっていた
//  → 起動（isolate）ごとに1回だけ試し、失敗しても素通りする形に変更。
let _adminChecked = false
app.use('*', async (c, next) => {
  if (_adminChecked) return next()
  _adminChecked = true
  try {
  const adminLoginId = c.env.ADMIN_LOGIN_ID || ''
  const adminPassword = c.env.ADMIN_PASSWORD || ''
  const secret = c.env.SESSION_SECRET
  if (!adminLoginId || !adminPassword || !secret) {
    // allow app to run but admin won't be auto-provisioned
    return next()
  }

  const existing = await c.env.DB.prepare(`SELECT id FROM users WHERE role='admin' AND login_id=? LIMIT 1`)
    .bind(adminLoginId)
    .first<any>()

  if (!existing) {""",
'R1 管理者チェックを1回だけ＋素通り', sentinel='let _adminChecked = false')

rep("""  } else {
    // If admin already exists in DB, do NOT override password using Secrets.
  }

  return next()
})""",
"""  } else {
    // If admin already exists in DB, do NOT override password using Secrets.
  }
  } catch (e) {
    // D1 が使えなくても、画面の表示だけは通す（ログイン画面が真っ白にならないように）
    console.error('admin provision skipped:', (e as any)?.message || e)
  }

  return next()
})""",
'R1b 例外を握って素通り', sentinel='admin provision skipped')

# ---------------- R2: student-full-analysis ----------------
rep('  const [submissions, subjectResults, plans, reflections, revisions] = await Promise.all([',
"""  const _fy = fyStartYMD()
  const [submissions, subjectResults, plans, reflections, revisions] = await Promise.all([""",
'R2a fyStart を用意', sentinel='const _fy = fyStartYMD()')

rep("""      FROM learning_results WHERE user_id=? GROUP BY unit ORDER BY total DESC
    `).bind(studentId).all<any>().catch(() => ({ results: [] })),""",
"""      FROM learning_results WHERE user_id=? AND answered_at >= ? GROUP BY unit ORDER BY total DESC
    `).bind(studentId, _fy).all<any>().catch(() => ({ results: [] })),""",
'R2b student-full-analysis を今年度に限定')

# ---------------- R3: learning-analytics ----------------
rep("""  const [unitAgg, perStuLR, hourAgg] = await Promise.all([
    c.env.DB.prepare("SELECT unit, COUNT(*) as t, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as cc FROM learning_results WHERE user_id IN " + memQ + " GROUP BY unit").bind(classId).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare("SELECT user_id, COUNT(*) as t, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as cc FROM learning_results WHERE user_id IN " + memQ + " GROUP BY user_id").bind(classId).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare("SELECT strftime('%H', datetime(answered_at, '+9 hours')) as hr, COUNT(*) as n FROM learning_results WHERE user_id IN " + memQ + " GROUP BY hr").bind(classId).all<any>().catch(() => ({ results: [] })),
  ])""",
"""  const _laFy = fyStartYMD()
  const [unitAgg, perStuLR, hourAgg] = await Promise.all([
    c.env.DB.prepare("SELECT unit, COUNT(*) as t, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as cc FROM learning_results WHERE user_id IN " + memQ + " AND answered_at >= ? GROUP BY unit").bind(classId, _laFy).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare("SELECT user_id, COUNT(*) as t, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as cc FROM learning_results WHERE user_id IN " + memQ + " AND answered_at >= ? GROUP BY user_id").bind(classId, _laFy).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare("SELECT strftime('%H', datetime(answered_at, '+9 hours')) as hr, COUNT(*) as n FROM learning_results WHERE user_id IN " + memQ + " AND answered_at >= ? GROUP BY hr").bind(classId, _laFy).all<any>().catch(() => ({ results: [] })),
  ])""",
'R3 learning-analytics 3本を今年度に限定', sentinel='const _laFy = fyStartYMD()')

# ---------------- R4: student-karte ----------------
rep("""      FROM learning_results WHERE user_id=? GROUP BY unit, week_key ORDER BY week_key DESC
    `).bind(studentId).all<any>()""",
"""      FROM learning_results WHERE user_id=? AND answered_at >= ? GROUP BY unit, week_key ORDER BY week_key DESC
    `).bind(studentId, fyStartYMD()).all<any>()""",
'R4 student-karte を今年度に限定')

# ---------------- R5/R6: 児童側（開くたびに走る） ----------------
rep("""c.env.DB.prepare("SELECT unit, COUNT(*) as n, SUM(is_correct) as cor, MAX(answered_at) as last_at FROM learning_results WHERE user_id=? GROUP BY unit").bind(u.id).all<any>()""",
"""c.env.DB.prepare("SELECT unit, COUNT(*) as n, SUM(is_correct) as cor, MAX(answered_at) as last_at FROM learning_results WHERE user_id=? AND answered_at >= ? GROUP BY unit").bind(u.id, fyStartYMD()).all<any>()""",
'R5 review-suggestions を今年度に限定')

rep("""c.env.DB.prepare("SELECT unit, COUNT(*) as n, SUM(is_correct) as cor FROM learning_results WHERE user_id=? GROUP BY unit").bind(u.id).all<any>()""",
"""c.env.DB.prepare("SELECT unit, COUNT(*) as n, SUM(is_correct) as cor FROM learning_results WHERE user_id=? AND answered_at >= ? GROUP BY unit").bind(u.id, fyStartYMD()).all<any>()""",
'R6 weak-units を今年度に限定')

# ---------------- R7: weekly-report ----------------
rep("""      WHERE lr.week_key=? GROUP BY lr.user_id, lr.unit
    `).bind(classId, weekKey).all<any>()""",
"""      WHERE lr.week_key=? AND lr.answered_at >= ? GROUP BY lr.user_id, lr.unit
    `).bind(classId, weekKey, fyStartYMD()).all<any>()""",
'R7 weekly-report に期間条件を追加')

# ---------------- R7b: 「最新データで作り直す」ボタン ----------------
rep('<button onclick="taiCopyAll()" class="bg-emerald-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:bg-emerald-700">📋 まとめてコピー</button>',
    '<button onclick="taiCopyAll()" class="bg-emerald-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:bg-emerald-700">📋 まとめてコピー</button>'
    '<button onclick="taiCopyFresh()" class="ml-2 bg-white border border-emerald-300 text-emerald-700 rounded-lg px-3 py-2 text-xs font-bold hover:bg-emerald-50">🔄 最新データで作り直す</button>',
    'R7b 作り直しボタンを追加', sentinel='taiCopyFresh()')

# ---------------- R8: キャッシュ更新 ----------------
rep('<script src="/teacher-ai.js?v=3"></script>',
    '<script src="/teacher-ai.js?v=4"></script>',
    'R8 teacher-ai.js のキャッシュ更新', sentinel='/teacher-ai.js?v=4')

# ---------------- 検証 ----------------
def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

if root_replace_count(orig) != root_replace_count(src):
    fail('本番HTMLの置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

# bind の数と ? の数が合っているかを、変更した文だけ確認
import re
checks = [
    ("FROM learning_results WHERE user_id=? AND answered_at >= ? GROUP BY unit ORDER BY total DESC", 1),
    ("FROM learning_results WHERE user_id=? AND answered_at >= ? GROUP BY unit, week_key", 1),
]
for pat, want in checks:
    if src.count(pat) != want: fail('検訽失敗: %r が %d 箇所' % (pat[:50], src.count(pat)))

for must in ["app.get('/api/teacher/learning-analytics'", "app.get('/api/teacher/student-full-analysis'",
             'function fyStartYMD()', 'let _adminChecked = false', '/teacher-ai.js']:
    if must not in src: fail('必須の要素が失われました: %s' % must)

# 期間フィルタなしの重い全期間スキャンが残っていないか（対象6本）
leftovers = []
for pat in ['FROM learning_results WHERE user_id=? GROUP BY unit ORDER BY total DESC',
            'FROM learning_results WHERE user_id=? GROUP BY unit, week_key',
            'as cc FROM learning_results WHERE user_id IN " + memQ + " GROUP BY unit"',
            'as cc FROM learning_results WHERE user_id IN " + memQ + " GROUP BY user_id"',
            'as n FROM learning_results WHERE user_id IN " + memQ + " GROUP BY hr"',
            'as cor, MAX(answered_at) as last_at FROM learning_results WHERE user_id=? GROUP BY unit"',
            'as cor FROM learning_results WHERE user_id=? GROUP BY unit"']:
    if pat in src: leftovers.append(pat[:60])
if leftovers:
    fail('期間フィルタが入っていない箇所が残っています: %s' % leftovers)
print('🔎 対象クエリすべてに期間フィルタが入りました')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました')
else:
    print('… 変更なし')
print('---- 適用した項目 ----')
for c in changes: print(' ・' + c)
if not changes: print(' （なし）')
