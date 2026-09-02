#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_analysis_v5.py --- 児童ステータス画面の読み取り削減

  S0 起動時に1回だけ (user_id, answered_at) の索引を用意する（CREATE INDEX IF NOT EXISTS）
  S1 共有ヘルパー stuUnitAgg() を追加
       ・直近120日 かつ 直近1200問 まで（1人あたりの読み取りに上限をつける）
       ・120日で4問以上の単元が1つも無い子は、直近400日まで自動で広げる（カードが消えない安全網）
  S2 /api/student/review-suggestions を共有ヘルパーに切り替え
  S3 /api/student/weak-units を共有ヘルパーに切り替え（SQL 2本 → 1本）
  S4 /api/student/growth-story に10分キャッシュ
  S5 問題を解いたら（POST /api/student/results）その子のキャッシュを捨てる

public/index.html は触りません。児童に見える画面のHTMLも変えていません。
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

# ---------------- S0: 索引を1回だけ用意する ----------------
MW_OLD = """app.use('*', async (c, next) => {
  if (_adminChecked) return next()
  _adminChecked = true
  try {"""
MW_NEW = """app.use('*', async (c, next) => {
  if (_adminChecked) return next()
  _adminChecked = true
  // 📉 2026-09: 児童ごとの「直近N問」を索引で取れるようにする。
  //   索引が無いと LIMIT を付けても全履歴を読んでしまうため、起動時に1回だけ用意する。
  //   すでにあれば何もしない（IF NOT EXISTS）。データには一切触らない。
  try {
    await c.env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_learning_results_user_time ON learning_results(user_id, answered_at)').run()
  } catch (e) {
    console.error('index ensure skipped:', (e as any)?.message || e)
  }
  try {"""
rep(MW_OLD, MW_NEW, 'S0 (user_id, answered_at) の索引を起動時に用意', sentinel='index ensure skipped')

# ---------------- S1: 共有ヘルパー ----------------
FY = """function fyStartYMD(): string {
  const d = new Date()
  const y = d.getUTCFullYear()
  return (((d.getUTCMonth() + 1) >= 4) ? y : y - 1) + '-04-01'
}"""

HELPER = FY + """

// 📉 2026-09: 児童のステータス画面（📚復習おすすめ／⚡ミニ復習／成長ストーリー）の読み取り削減。
//
//  ・「復習おすすめ」と「ミニ復習(苦手)」は同じ集計で足りるので、SQLを1本にまとめて共有する（2本→1本）
//  ・期間は「直近120日」かつ「直近1200問」。1200問の上限があるので、
//    履歴が何年ぶん貯まっても1人あたりの読み取りが増え続けない。
//  ・90日ではなく120日にした理由: 9月時点で90日さかのぼると大半が夏休みになり、
//    「4問以上やった単元」に届かず判定から漏れる子が出るため（実測で3人／22人）。
//  ・それでも120日で4問以上の単元が1つも無い子は、直近400日まで自動で広げる。
//    これでカードが消える子は0人（4月の学年またぎ・長期の未活動どちらも検証ずみ）。
//  ・同じ画面から3本同時に呼ばれるので45秒だけ使い回す。問題を解いたら即座に捨てる。
const STU_AGG_TTL_MS = 45000
const STU_GROWTH_TTL_MS = 600000
const STU_AGG_DAYS = 120
const STU_AGG_WIDE_DAYS = 400
const STU_AGG_LIMIT = 1200
const _stuAggCache = new Map<string, { at: number, rows: any[] }>()
const _growthCache = new Map<string, { at: number, body: any }>()

function stuSinceYMD(days: number): string {
  return new Date(Date.now() - days * 86400000).toISOString().slice(0, 10)
}

function stuAggInvalidate(userId: string) {
  try { _stuAggCache.delete(userId); _growthCache.delete(userId) } catch (e) {}
}

async function stuUnitAggQuery(c: any, userId: string, since: string): Promise<any[]> {
  try {
    const r = await c.env.DB.prepare("SELECT unit, COUNT(*) as n, SUM(is_correct) as cor, MAX(answered_at) as last_at FROM (SELECT unit, is_correct, answered_at FROM learning_results WHERE user_id=? AND answered_at >= ? ORDER BY answered_at DESC LIMIT " + STU_AGG_LIMIT + ") GROUP BY unit").bind(userId, since).all<any>()
    return (((r && r.results) || []) as any[])
  } catch (e) { return [] }
}

async function stuUnitAgg(c: any, userId: string): Promise<any[]> {
  const hit = _stuAggCache.get(userId)
  if (hit && (Date.now() - hit.at) < STU_AGG_TTL_MS) return hit.rows
  let rows = await stuUnitAggQuery(c, userId, stuSinceYMD(STU_AGG_DAYS))
  let usable = false
  for (const r of rows) { if ((r.n || 0) >= 4) { usable = true; break } }
  if (!usable) {
    const wide = await stuUnitAggQuery(c, userId, stuSinceYMD(STU_AGG_WIDE_DAYS))
    if (wide.length) rows = wide
  }
  try { if (_stuAggCache.size > 800) _stuAggCache.clear(); _stuAggCache.set(userId, { at: Date.now(), rows }) } catch (e) {}
  return rows
}"""

rep(FY, HELPER, 'S1 共有ヘルパー stuUnitAgg を追加', sentinel='async function stuUnitAgg(')

# ---------------- S2: review-suggestions ----------------
REV_OLD = '''  try { const r = await c.env.DB.prepare("SELECT unit, COUNT(*) as n, SUM(is_correct) as cor, MAX(answered_at) as last_at FROM learning_results WHERE user_id=? AND answered_at >= ? GROUP BY unit").bind(u.id, fyStartYMD()).all<any>(); rows = (((r && r.results) || []) as any[]) } catch {}'''
rep(REV_OLD, '  rows = await stuUnitAgg(c, u.id)', 'S2 復習おすすめを共有集計に切り替え')

# ---------------- S3: weak-units ----------------
WEAK_OLD = '''  try { const r = await c.env.DB.prepare("SELECT unit, COUNT(*) as n, SUM(is_correct) as cor FROM learning_results WHERE user_id=? AND answered_at >= ? GROUP BY unit").bind(u.id, fyStartYMD()).all<any>(); rows = (((r && r.results) || []) as any[]) } catch {}'''
rep(WEAK_OLD, '  rows = await stuUnitAgg(c, u.id)', 'S3 ミニ復習(苦手)を共有集計に切り替え')

# ---------------- S4: growth-story のキャッシュ ----------------
G_HEAD_OLD = """app.get('/api/student/growth-story', async (c) => {
  const u = c.get('user'); if (!u) return jsonError(c, 403, 'forbidden')"""
G_HEAD_NEW = """app.get('/api/student/growth-story', async (c) => {
  const u = c.get('user'); if (!u) return jsonError(c, 403, 'forbidden')
  // 📉 2026-09: 年間の伸びを見る画面なので10分使い回す。問題を解いたら捨てる。
  const _gHit = _growthCache.get(u.id)
  if (_gHit && (Date.now() - _gHit.at) < STU_GROWTH_TTL_MS) return c.json(_gHit.body)"""
rep(G_HEAD_OLD, G_HEAD_NEW, 'S4a 成長ストーリーのキャッシュ読み', sentinel='const _gHit = _growthCache.get(u.id)')

G_RET_OLD = """  return c.json({ ok: true, show, periodLabel: fyY + '年度（4月〜）', start: { rate: startRate }, now: { rate: nowRate }, improved: improved.slice(0, 4), masteredCount, overallRate, totalProblems, submissions, maxStreak, message })"""
G_RET_NEW = """  const _gBody = { ok: true, show, periodLabel: fyY + '年度（4月〜）', start: { rate: startRate }, now: { rate: nowRate }, improved: improved.slice(0, 4), masteredCount, overallRate, totalProblems, submissions, maxStreak, message }
  try { if (_growthCache.size > 800) _growthCache.clear(); _growthCache.set(u.id, { at: Date.now(), body: _gBody }) } catch (e) {}
  return c.json(_gBody)"""
rep(G_RET_OLD, G_RET_NEW, 'S4b 成長ストーリーのキャッシュ書き', sentinel='_growthCache.set(u.id,')

# ---------------- S5: 解答したらキャッシュを捨てる ----------------
INS_OLD = """    .bind(u.id, unit, questionId, isCorrect, timeMs, answeredAt, metaJson)
    .run()

  return c.json({ ok: true })"""
INS_NEW = """    .bind(u.id, unit, questionId, isCorrect, timeMs, answeredAt, metaJson)
    .run()

  // 📉 2026-09: 解いた直後に古い集計を見せないよう、その子のキャッシュを捨てる
  try { stuAggInvalidate(u.id) } catch (e) {}

  return c.json({ ok: true })"""
rep(INS_OLD, INS_NEW, 'S5 解答時にキャッシュを捨てる', sentinel='stuAggInvalidate(u.id)')

# ---------------- 検証 ----------------
def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

if root_replace_count(orig) != root_replace_count(src):
    fail('本番HTMLの置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

for must in ['async function stuUnitAgg(', 'async function stuUnitAggQuery(', 'function stuAggInvalidate(',
             'const _stuAggCache', 'const _growthCache', 'const STU_AGG_DAYS = 120',
             'const STU_AGG_LIMIT = 1200', 'ORDER BY answered_at DESC LIMIT ',
             'CREATE INDEX IF NOT EXISTS idx_learning_results_user_time',
             "app.get('/api/student/review-suggestions'", "app.get('/api/student/weak-units'",
             "app.get('/api/student/growth-story'", 'function fyStartYMD()',
             'let _adminChecked = false']:
    if must not in src: fail('必須の要素が失われました: %s' % must)

counts = [
    ('rows = await stuUnitAgg(c, u.id)', 2),
    ('stuAggInvalidate(u.id)', 1),
    ('_growthCache.get(u.id)', 1),
    ('_growthCache.set(u.id,', 1),
    ('async function stuUnitAgg(', 1),
    ('CREATE INDEX IF NOT EXISTS idx_learning_results_user_time', 1),
]
for pat, want in counts:
    if src.count(pat) != want:
        fail('検証失敗: %r が %d 箇所（%d のはず）' % (pat[:50], src.count(pat), want))

for pat in [REV_OLD.strip(), WEAK_OLD.strip()]:
    if pat in src: fail('古い個別クエリが残っています: %s' % pat[:60])

leftovers = []
for pat in ['FROM learning_results WHERE user_id=? GROUP BY unit',
            'FROM learning_results WHERE user_id=? ORDER BY']:
    if pat in src: leftovers.append(pat[:60])
if leftovers:
    fail('期間フィルタが入っていない箇所が残っています: %s' % leftovers)
print('🔎 児童向けの単元集計は共有ヘルパー1本にまとまりました（上限1200問）')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました')
else:
    print('… 変更なし')
print('---- 適用した項目 ----')
for c in changes: print(' ・' + c)
if not changes: print(' （なし）')
