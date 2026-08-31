// ==================== 🧭 MIしらべ（マルチプルインテリジェンス自己認識チェック） ====================
// 児童: /mi （自分の結果だけが見える）／ 先生: /teacher-mi （requireTeacher の内側・未認証は401）
//
// 設計方針（index.tsx を極力さわらないため、この1ファイルに閉じている）:
//   - public/index.html には一切さわらない。src/index.tsx の .replace() チェーンにも手を入れない。
//   - 画面は独立ページ（/mi, /teacher-mi）＋外部JS（/mi.js, /teacher-mi.js）。
//     本体 index.html 内の変数（initGame のローカル const など）には一切依存しない。
//   - 既存テーブルへの破壊的変更なし。mi_* を runtime の CREATE TABLE IF NOT EXISTS で用意する。
//   - state_json には触らない（過去の last-write-wins によるデータ消失を避けるため別テーブル）。
//
// index.tsx 側の追加は
//   1) import { registerMi } from './mi'
//   2) registerMi(app)   ← ファイル末尾 export default app の直前
//   3) 児童ゲーム画面の </body> 直前に入口リンクを1本追加
//   4) 教師ダッシュボードのヘッダに /teacher-mi へのリンクを1本追加
// の4行だけ。

// 領域の並びは先生の配布用エクセルの「左から」の順。同点のときはこの順で上位になる。
export const MI_DOMAIN_ORDER = [
  { key: 'lang',   name: '言語・語学',   qs: [1, 9, 17, 25],  side: 'L' },
  { key: 'logic',  name: '論理・数学',   qs: [2, 10, 18, 26], side: 'L' },
  { key: 'nature', name: '自然・博物学', qs: [3, 11, 19, 27], side: 'L' },
  { key: 'intra',  name: '内省',         qs: [4, 12, 20, 28], side: 'L' },
  { key: 'visual', name: '視覚・空間',   qs: [5, 13, 21, 29], side: 'R' },
  { key: 'body',   name: '身体・運動',   qs: [6, 14, 22, 30], side: 'R' },
  { key: 'music',  name: '音楽・リズム', qs: [7, 15, 23, 31], side: 'R' },
  { key: 'inter',  name: '対人',         qs: [8, 16, 24, 32], side: 'R' }
]

// 各領域＝該当4問の合計（4〜16点）／左脳＝言語+論理+自然+内省、右脳＝視覚+身体+音楽+対人（各16〜64点）
export function miComputeScores(answers: any) {
  const a: any[] = Array.isArray(answers) ? answers : []
  const scores: Record<string, number> = {}
  let left = 0, right = 0
  for (const d of MI_DOMAIN_ORDER) {
    let s = 0
    for (const q of d.qs) {
      const v = Number(a[q - 1])
      if (v === 1 || v === 2 || v === 3 || v === 4) s += v
    }
    scores[d.key] = s
    if (d.side === 'L') left += s; else right += s
  }
  // 同点は領域の並び順（表の左から）が上位。安定ソートに頼らずインデックスを第2キーにする。
  const ranking = MI_DOMAIN_ORDER
    .map((d, i) => ({ key: d.key, name: d.name, score: scores[d.key], idx: i }))
    .sort((x, y) => (y.score - x.score) || (x.idx - y.idx))
  return { scores, left, right, ranking }
}

// 🎁 MIしらべの特典（月1回まで）。金額は先生の確認待ちのため、この1か所だけ直せばよいようにしている。
export const MI_REWARD_COINS = 100

// 月の判定は「日本時間(JST)の月」。既存の jstDayKey / date(answered_at,'+9 hours') と同じ基準。
export function miJstMonthKey(): string {
  return new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 7) // 例: '2026-08'
}

export function miNormalizeAnswers(raw: any) {
  const out: (number | null)[] = []
  for (let i = 0; i < 32; i++) {
    const v = Number(Array.isArray(raw) ? raw[i] : NaN)
    out.push((v === 1 || v === 2 || v === 3 || v === 4) ? v : null)
  }
  return out
}

// index.tsx の同名ヘルパーに合わせた最小実装（index.tsx をさわらずに済ませるため）
function miJsonError(c: any, status: number, message: string) {
  return c.json({ ok: false, error: message }, status)
}
function miRequireStudent(c: any) {
  const u = c.get('user')
  if (!u) return null
  // 既存の requireStudent と同様、admin/teacher もゲームを触れる
  if (u.role !== 'student' && u.role !== 'admin' && u.role !== 'teacher') return null
  return u
}
function miRequireTeacher(c: any) {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return null
  return u
}
const _miRl = new Map<string, { count: number, resetAt: number }>()
function miRateLimit(key: string, maxReqs: number, windowSec: number): boolean {
  const now = Date.now()
  let e = _miRl.get(key)
  if (!e || now > e.resetAt) { e = { count: 0, resetAt: now + windowSec * 1000 }; _miRl.set(key, e) }
  e.count++
  if (_miRl.size > 5000) { for (const [k, v] of _miRl) { if (now > v.resetAt) _miRl.delete(k) } }
  return e.count <= maxReqs
}

async function ensureMiTables(env: any) {
  try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS mi_results (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, class_id TEXT, answers_json TEXT NOT NULL, scores_json TEXT NOT NULL, left_total INTEGER DEFAULT 0, right_total INTEGER DEFAULT 0, taken_at TEXT NOT NULL)").run() } catch (_e) {}
  try { await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_mi_results_user ON mi_results(user_id, taken_at)").run() } catch (_e) {}
  try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS mi_drafts (user_id TEXT PRIMARY KEY, answers_json TEXT, updated_at TEXT)").run() } catch (_e) {}
  // 🎁 特典の受け取り台帳。PRIMARY KEY(user_id, month_key) で「同じ月に2回目」が
  //    構造的に INSERT できないようにする（アプリ側の判定ミスでは二重付与できない）。
  try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS mi_rewards (user_id TEXT NOT NULL, month_key TEXT NOT NULL, coins INTEGER NOT NULL DEFAULT 0, result_id TEXT, created_at TEXT, PRIMARY KEY (user_id, month_key))").run() } catch (_e) {}
  // 出席番号順に並べたいので、既存コード（report-card）と同じ防御的 ALTER（追加のみ・破壊なし）
  try { await env.DB.prepare('ALTER TABLE users ADD COLUMN roster_no INTEGER').run() } catch (_e) {}
}

function miRowToResult(r: any) {
  let sc: any = {}
  try { sc = JSON.parse(r.scores_json || '{}') } catch (_e) { sc = {} }
  let ans: any = null
  if (r.answers_json != null) { try { ans = JSON.parse(r.answers_json) } catch (_e) { ans = null } }
  return {
    id: r.id,
    takenAt: r.taken_at,
    scores: sc.scores || {},
    ranking: sc.ranking || [],
    left: Number(r.left_total || 0),
    right: Number(r.right_total || 0),
    answers: ans
  }
}

// 🎁 特典コインの付与。二重付与が構造的に起きないように、次の順番で行う。
//   1) mi_rewards に INSERT して「その月の枠」を先に確保する（PRIMARY KEY 衝突＝今月すでに受け取り済み）
//   2) 確保できたときだけ progress.state_json にサーバー側でコインを加算する
//      （既存の連絡帳コイン /api/student/contact-note/:id/read と同じ作法。
//        あわせて _miCoinsApplied を増やし、PUT /api/student/progress 側で
//        クライアントの全置換保存に負けないよう補填する）
//   3) コイン加算に失敗したら枠を解放して、次回リトライできるようにする
// クライアントからの申告（何コインもらった等）は一切受け取らない。金額はサーバーの定数だけ。
async function miGrantMonthlyReward(c: any, userId: string, resultId: string | null) {
  const monthKey = miJstMonthKey()
  const out: any = {
    monthKey, coins: MI_REWARD_COINS,
    granted: false, alreadyTakenThisMonth: false,
    reason: '', newCoins: null, miCoinsApplied: null
  }
  // 1) 月の枠を確保
  try {
    await c.env.DB.prepare(
      "INSERT INTO mi_rewards (user_id, month_key, coins, result_id, created_at) VALUES (?, ?, ?, ?, datetime('now'))"
    ).bind(userId, monthKey, MI_REWARD_COINS, resultId).run()
  } catch (_e) {
    out.alreadyTakenThisMonth = true
    out.reason = 'already_taken_this_month'
    return out
  }
  // 2) コインをサーバー側で加算
  let applied = false
  try {
    const prog = await c.env.DB.prepare('SELECT state_json FROM progress WHERE user_id=?').bind(userId).first()
    if (prog && (prog as any).state_json) {
      const state = JSON.parse((prog as any).state_json)
      state.coins = (Number(state.coins) || 0) + MI_REWARD_COINS
      state._miCoinsApplied = (Number(state._miCoinsApplied) || 0) + MI_REWARD_COINS
      await c.env.DB.prepare("UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?")
        .bind(JSON.stringify(state), userId).run()
      out.newCoins = state.coins
      out.miCoinsApplied = state._miCoinsApplied
      applied = true
    } else {
      out.reason = 'no_progress'
    }
  } catch (e: any) {
    out.reason = 'coin_apply_failed'
    console.error('[mi/reward] coin apply error:', e?.message || e)
  }
  // 3) 加算できなかったら枠を解放（コインを失わせない）
  if (!applied) {
    try {
      await c.env.DB.prepare('DELETE FROM mi_rewards WHERE user_id=? AND month_key=?').bind(userId, monthKey).run()
    } catch (_e) {}
    return out
  }
  out.granted = true
  return out
}

// 今月（JST）の受け取り状況。GET は副作用を持たせない。
async function miRewardStatus(c: any, userId: string) {
  const monthKey = miJstMonthKey()
  let taken = false, hasResultThisMonth = false
  try {
    const r = await c.env.DB.prepare('SELECT 1 as ok FROM mi_rewards WHERE user_id=? AND month_key=? LIMIT 1')
      .bind(userId, monthKey).first()
    taken = !!r
  } catch (_e) {}
  try {
    const r = await c.env.DB.prepare(
      "SELECT 1 as ok FROM mi_results WHERE user_id=? AND strftime('%Y-%m', datetime(taken_at, '+9 hours'))=? LIMIT 1"
    ).bind(userId, monthKey).first()
    hasResultThisMonth = !!r
  } catch (_e) {}
  return {
    monthKey, coins: MI_REWARD_COINS,
    takenThisMonth: taken,
    canClaim: hasResultThisMonth && !taken
  }
}

export function registerMi(app: any) {

  // ---- 児童：自分の下書き＋履歴（他の児童の結果は一切返さない） ----
  app.get('/api/mi/my', async (c: any) => {
    const u = miRequireStudent(c)
    if (!u) return miJsonError(c, 401, 'unauthorized')
    await ensureMiTables(c.env)
    let draft: any = null
    try {
      const d = await c.env.DB.prepare('SELECT answers_json, updated_at FROM mi_drafts WHERE user_id=? LIMIT 1').bind(u.id).first()
      if (d && d.answers_json) draft = { answers: JSON.parse(d.answers_json), updatedAt: d.updated_at }
    } catch (_e) { draft = null }
    let results: any[] = []
    try {
      const rows = await c.env.DB.prepare(
        'SELECT id, answers_json, scores_json, left_total, right_total, taken_at FROM mi_results WHERE user_id=? ORDER BY taken_at DESC, id DESC LIMIT 30'
      ).bind(u.id).all()
      results = ((rows && rows.results) || []).map(miRowToResult)
    } catch (_e) { results = [] }
    const reward = await miRewardStatus(c, u.id)
    return c.json({ ok: true, draft, results, reward })
  })

  // ---- 児童：下書き保存（途中で閉じても再開できる） ----
  app.put('/api/mi/draft', async (c: any) => {
    const u = miRequireStudent(c)
    if (!u) return miJsonError(c, 401, 'unauthorized')
    const body = await c.req.json().catch(() => null)
    if (!body) return miJsonError(c, 400, 'invalid_json')
    await ensureMiTables(c.env)
    const answers = miNormalizeAnswers(body.answers)
    try {
      await c.env.DB.prepare(
        `INSERT INTO mi_drafts (user_id, answers_json, updated_at) VALUES (?, ?, datetime('now'))
         ON CONFLICT(user_id) DO UPDATE SET answers_json=excluded.answers_json, updated_at=datetime('now')`
      ).bind(u.id, JSON.stringify(answers)).run()
    } catch (_e) { return miJsonError(c, 500, 'db_error') }
    return c.json({ ok: true })
  })

  // ---- 児童：提出（採点はサーバー側が正） ----
  app.post('/api/mi/submit', async (c: any) => {
    const u = miRequireStudent(c)
    if (!u) return miJsonError(c, 401, 'unauthorized')
    if (!miRateLimit('misubmit:' + u.id, 10, 300)) return miJsonError(c, 429, 'too_many_requests')
    const body = await c.req.json().catch(() => null)
    if (!body) return miJsonError(c, 400, 'invalid_json')
    const answers = miNormalizeAnswers(body.answers)
    for (let i = 0; i < 32; i++) if (answers[i] == null) return miJsonError(c, 400, 'incomplete_answers')
    await ensureMiTables(c.env)
    let classId: string | null = null
    try {
      const cm = await c.env.DB.prepare('SELECT class_id FROM class_members WHERE user_id=? LIMIT 1').bind(u.id).first()
      classId = cm ? cm.class_id : null
    } catch (_e) { classId = null }
    const calc = miComputeScores(answers)
    const id = crypto.randomUUID()
    const takenAt = new Date().toISOString().slice(0, 19).replace('T', ' ')
    try {
      await c.env.DB.prepare(
        'INSERT INTO mi_results (id, user_id, class_id, answers_json, scores_json, left_total, right_total, taken_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(id, u.id, classId, JSON.stringify(answers), JSON.stringify({ scores: calc.scores, ranking: calc.ranking }), calc.left, calc.right, takenAt).run()
    } catch (_e) { return miJsonError(c, 500, 'db_error') }
    try { await c.env.DB.prepare('DELETE FROM mi_drafts WHERE user_id=?').bind(u.id).run() } catch (_e) {}
    // 🎁 特典（月1回まで）。付与の可否はすべてサーバーが決める。
    const reward = await miGrantMonthlyReward(c, u.id, id)
    return c.json({
      ok: true,
      result: { id, takenAt, scores: calc.scores, ranking: calc.ranking, left: calc.left, right: calc.right, answers },
      reward
    })
  })

  // ---- 児童：特典の受け取り（提出時に付与できなかった場合のリトライ用） ----
  //      今月すでに受け取っていれば、何度叩いてもサーバーが弾く。
  app.post('/api/mi/reward/claim', async (c: any) => {
    const u = miRequireStudent(c)
    if (!u) return miJsonError(c, 401, 'unauthorized')
    if (!miRateLimit('mireward:' + u.id, 20, 300)) return miJsonError(c, 429, 'too_many_requests')
    await ensureMiTables(c.env)
    const monthKey = miJstMonthKey()
    // 今月ぶんの受検が無ければ付与しない
    let hasResult = false
    try {
      const r = await c.env.DB.prepare(
        "SELECT 1 as ok FROM mi_results WHERE user_id=? AND strftime('%Y-%m', datetime(taken_at, '+9 hours'))=? LIMIT 1"
      ).bind(u.id, monthKey).first()
      hasResult = !!r
    } catch (_e) {}
    if (!hasResult) return c.json({ ok: true, reward: { monthKey, coins: MI_REWARD_COINS, granted: false, alreadyTakenThisMonth: false, reason: 'no_result_this_month', newCoins: null, miCoinsApplied: null } })
    const reward = await miGrantMonthlyReward(c, u.id, null)
    return c.json({ ok: true, reward })
  })

  // ---- 先生：クラス一覧（8領域スコア＋未実施＋クラス平均） ----
  app.get('/api/teacher/mi/class/:classId', async (c: any) => {
    const u = miRequireTeacher(c)
    if (!u) return miJsonError(c, 401, 'unauthorized')
    const classId = c.req.param('classId')
    const cls = u.role === 'admin'
      ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=?').bind(classId).first()
      : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(classId, u.id).first()
    if (!cls) return miJsonError(c, 404, 'class not found')
    await ensureMiTables(c.env)
    const mem = await c.env.DB.prepare(
      'SELECT u.id as userId, u.login_id as loginId, u.name, u.roster_no as rosterNo FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=? ORDER BY u.roster_no IS NULL, u.roster_no, u.login_id'
    ).bind(classId).all()
    const members = (mem && mem.results) || []
    let rows: any[] = []
    try {
      const rs = await c.env.DB.prepare(
        `SELECT r.id, r.user_id, r.answers_json, r.scores_json, r.left_total, r.right_total, r.taken_at
         FROM mi_results r JOIN class_members cm ON cm.user_id = r.user_id
         WHERE cm.class_id=? ORDER BY r.taken_at ASC, r.id ASC`
      ).bind(classId).all()
      rows = (rs && rs.results) || []
    } catch (_e) { rows = [] }
    const byUser: Record<string, { count: number, latest: any }> = {}
    for (const r of rows) {
      const k = String(r.user_id)
      if (!byUser[k]) byUser[k] = { count: 0, latest: null }
      byUser[k].count++
      byUser[k].latest = miRowToResult(r) // ASC 順なので最後に入るものが最新
    }
    const students = (members as any[]).map((m: any) => ({
      userId: m.userId, loginId: m.loginId, name: m.name, rosterNo: m.rosterNo,
      count: byUser[m.userId] ? byUser[m.userId].count : 0,
      latest: byUser[m.userId] ? byUser[m.userId].latest : null
    }))
    const sum: Record<string, number> = {}
    for (const d of MI_DOMAIN_ORDER) sum[d.key] = 0
    let sumL = 0, sumR = 0, n = 0
    for (const s of students) {
      if (!s.latest) continue
      n++
      for (const d of MI_DOMAIN_ORDER) sum[d.key] += Number(s.latest.scores[d.key] || 0)
      sumL += Number(s.latest.left || 0); sumR += Number(s.latest.right || 0)
    }
    const average: Record<string, number> = {}
    for (const d of MI_DOMAIN_ORDER) average[d.key] = n ? Math.round(sum[d.key] / n * 10) / 10 : 0
    return c.json({
      ok: true, students, average,
      averageLeft: n ? Math.round(sumL / n * 10) / 10 : 0,
      averageRight: n ? Math.round(sumR / n * 10) / 10 : 0,
      doneCount: n, total: students.length
    })
  })

  // ---- 先生：個人の詳細（32問の生回答＋履歴） ----
  app.get('/api/teacher/mi/student/:userId', async (c: any) => {
    const u = miRequireTeacher(c)
    if (!u) return miJsonError(c, 401, 'unauthorized')
    const userId = c.req.param('userId')
    if (u.role !== 'admin') {
      const own = await c.env.DB.prepare(
        'SELECT 1 as ok FROM class_members cm JOIN classes cl ON cl.id=cm.class_id WHERE cm.user_id=? AND cl.teacher_id=? LIMIT 1'
      ).bind(userId, u.id).first()
      if (!own) return miJsonError(c, 403, 'forbidden')
    }
    await ensureMiTables(c.env)
    let attempts: any[] = []
    try {
      const rs = await c.env.DB.prepare(
        'SELECT id, answers_json, scores_json, left_total, right_total, taken_at FROM mi_results WHERE user_id=? ORDER BY taken_at DESC, id DESC LIMIT 50'
      ).bind(userId).all()
      attempts = ((rs && rs.results) || []).map(miRowToResult)
    } catch (_e) { attempts = [] }
    return c.json({ ok: true, attempts })
  })

  // ---- 児童ページ（タブレット前提のモバイルファースト） ----
  app.get('/mi', (c: any) => {
    return c.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"/>
  <title>MIしらべ</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="min-h-screen bg-slate-100 p-3">
    <div id="miApp" class="max-w-lg mx-auto"></div>
    <script src="/mi.js?v=1"></script>
  </body></html>`)
  })

  // ---- 先生ページ ----
  app.get('/teacher-mi', (c: any) => {
    return c.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>MIしらべ（先生用）</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="min-h-screen bg-emerald-50 p-4">
    <div id="miRoot" class="max-w-5xl mx-auto space-y-4">
      <div class="bg-white rounded-xl shadow p-4 flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 class="text-xl font-bold">🧭 MIしらべ（クラス一覧）</h1>
          <p class="text-xs text-slate-500">児童の「いまの自己認識」の記録です。タイプ分けや能力の判定ではありません。</p>
        </div>
        <div class="flex gap-2 items-center">
          <select id="miClassSel" class="border p-1.5 rounded text-sm bg-white"><option value="">クラスを選択…</option></select>
          <a href="/teacher" class="text-sm px-3 py-1 rounded bg-emerald-100 hover:bg-emerald-200 text-emerald-700 font-bold transition">← ダッシュボード</a>
        </div>
      </div>
      <div class="bg-white rounded-xl shadow p-4">
        <div id="miBody" class="text-sm text-slate-400">クラスを選んでください。</div>
      </div>
      <p class="text-[11px] text-slate-400 leading-relaxed">
        ※ 児童側の画面では「○○タイプ」といったラベル付けや、それにもとづく学習法の指示は行っていません。
        点数が低い領域を苦手・欠点として示すこともしていません。懇談や所見でお使いになる際も、その子の「いまの自己認識」としてお読みください。
      </p>
    </div>
    <script src="/teacher-mi.js?v=1"></script>
  </body></html>`)
  })

  // ---- 外部JSの配信（既存の g8*/g9*/g10* と同じ ASSETS 経由のやり方に合わせる） ----
  const _mifiles = ['mi.js', 'teacher-mi.js']
  for (const _f of _mifiles) {
    app.get('/' + _f, async (c: any) => {
      try {
        const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/' + _f)))
        if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } })
      } catch (e) {}
      return c.text('not found', 404)
    })
  }
}
