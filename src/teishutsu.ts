// ==================== 📮 TEISHUTSU_V1 提出状況のアドバイス（2026-10-27） ====================
//
// A. 家庭学習の提出状況（アプリの記録から自動）
//    ・子ども：今週（月〜日・週の振り返りの📊今週の記録と同じ数え方）に家庭学習を出した日数 → 阪神マンの一言（1日1回まで・責めない・比較しない）
//    ・カルテ：「今週の家庭学習：〇日」（画面・印刷）。数は wr2Facts と同じ（homework_submissions の day_key を月〜日で数える）。
// B. 学校の提出物（ドリル・ノート・プリントなど）
//    ・先生：📮 提出物チェック（作る → 名簿の格子で ✓／もう一度で取り消し・全員✓・未提出だけ・完了で畳む）
//    ・子ども：自分の「📮 まだの提出物」だけ（しめきりが近い順・出したら自動で消える・ほかの子の状況は返さない）
//    ・カルテには未提出の数を出さない（先生の個人ページでだけ見る）。コインは付けない。
// C. 提出・成果物のようす（事実だけ）… しめきりに対して出した日・教科ごと・ためやすい種類・家庭学習の曜日／時間帯・
//    写真や「成果物も提出あり」・学習時間・天気・先週決めたことの結果。今日のひと往復の材料と先生の個人ページに。
// D. テストの傾向（点数は使わない・返さない）… 観点（知識・技能／思考・判断・表現）の ◎○△ と、
//    テスト前1週間のアプリの取り組み（単元ごとの問題数）。データが無い子・教科では何も返さない（推測しない）。
//
// ⚠️ テーブルは migrations/0049_school_assignments.sql だけで作る。ここでは DDL を一切実行しない（2026-09-03 の障害）。
// ⚠️ 見るだけモード（VIEWAS_V1）では、子どもの経路は GET だけ。ここの子ども向けの道は読むだけ。
// ⚠️ D1 は主キー・索引の範囲読みだけ。learning_results は「本人・7日×最大6回・単元ごとの集計」でしか読まない。

const DAY = 86400000
const H9 = 9 * 3600000

function cut(x: any, n: number) { return Array.from(String(x == null ? '' : x).replace(/[\r\n\t]/g, ' ').replace(/[<>]/g, '').replace(/\s+/g, ' ').trim()).slice(0, n).join('') }
function isYmd(s: any) { return /^\d{4}-\d{2}-\d{2}$/.test(String(s || '')) }
export function tsYmdJ(ms: number) { return new Date(ms + H9).toISOString().slice(0, 10) }
export function tsDay830(ms: number) { return new Date(ms + H9 - 8.5 * 3600000).toISOString().slice(0, 10) }
function addDays(ymd: string, n: number) { return new Date(Date.parse(ymd + 'T00:00:00Z') + n * DAY).toISOString().slice(0, 10) }
function diffDays(a: string, b: string) { return Math.round((Date.parse(a + 'T00:00:00Z') - Date.parse(b + 'T00:00:00Z')) / DAY) }   // a - b
function isoMonday(wk: string): string {
  const m = String(wk).match(/^(\d{4})-W(\d{2})$/)
  if (!m) return ''
  const j4 = new Date(Date.UTC(Number(m[1]), 0, 4))
  const dw = j4.getUTCDay() || 7
  return new Date(j4.getTime() + ((1 - dw) + (Number(m[2]) - 1) * 7) * DAY).toISOString().slice(0, 10)
}
function rows(r: any): any[] { return ((r && r.results) || []) as any[] }

export const TS_SUBJECTS = ['国語', '算数', '理科', '社会', '外国語', '音楽', '図工', '家庭', '体育', '道徳', '総合', 'その他']
export const TS_KINDS: [string, RegExp][] = [['ドリル', /ドリル|スキル/], ['ノート', /ノート/], ['プリント', /プリント|ワークシート/], ['ワーク', /ワーク/], ['作文・日記', /作文|日記|感想/]]
export function tsKindOf(title: string) { for (const k of TS_KINDS) if (k[1].test(String(title || ''))) return k[0]; return 'その他' }
const MARKS = ['◎', '○', '△']
function mark(x: any) { let s = String(x || '').trim().replace('〇', '○').replace('◯', '○'); const AB: any = { A: '◎', 'Ａ': '◎', B: '○', 'Ｂ': '○', C: '△', 'Ｃ': '△' }; if (AB[s]) s = AB[s]; return MARKS.indexOf(s) >= 0 ? s : '' }   // SHINBUN_REVIEW_V1 成果物から 読んだ A・B・C も 同じに あつかう

// ── 家庭学習を出した日（月〜日・週の振り返りの📊と同じ数え方） ──
export async function tsHwWeek(env: any, userId: string, mon: string) {
  const sun = addDays(mon, 6)
  const days: string[] = []
  try {
    const r = await env.DB.prepare('SELECT day_key FROM homework_submissions WHERE user_id=? AND day_key >= ? AND day_key <= ? LIMIT 14').bind(userId, mon, sun).all()
    for (const x of rows(r)) { const dk = String(x.day_key || ''); if (dk && days.indexOf(dk) < 0) days.push(dk) }
  } catch (_e) {}
  days.sort()
  return { from: mon, to: sun, days: days.length, dayKeys: days }
}

// ── しめきり前（しめきりの日も含む）に出せた提出物の数（その週に ✓ がついたもの） ──
export async function tsOnTime(env: any, userId: string, from: string, to: string) {
  try {
    const r: any = await env.DB.prepare("SELECT COUNT(*) AS n FROM school_assignment_checks k JOIN school_assignments a ON a.id = k.assignment_id WHERE k.user_id=? AND k.checked_day >= ? AND k.checked_day <= ? AND a.deleted=0 AND a.due_date <> '' AND k.checked_day <= a.due_date").bind(userId, from, to).first()
    return Number((r && r.n) || 0)
  } catch (_e) { return 0 }
}

// ── 自分の まだの提出物（進行中・✓なし）。しめきりが近い順。 ──
export async function tsPending(env: any, userId: string, todayJ: string) {
  const out: any[] = []
  try {
    const r = await env.DB.prepare(`SELECT a.id, a.title, a.subject, a.due_date FROM class_members cm
        JOIN school_assignments a ON a.class_id = cm.class_id AND a.deleted = 0 AND a.done_at IS NULL
        LEFT JOIN school_assignment_checks k ON k.assignment_id = a.id AND k.user_id = cm.user_id
        WHERE cm.user_id = ? AND k.user_id IS NULL LIMIT 30`).bind(userId).all()
    for (const x of rows(r)) {
      const due = isYmd(x.due_date) ? String(x.due_date) : ''
      out.push({ id: String(x.id), title: String(x.title || ''), subject: String(x.subject || ''), dueDate: due, daysLeft: due ? diffDays(due, todayJ) : null })
    }
  } catch (_e) {}
  out.sort((a, b) => (a.daysLeft == null ? 9999 : a.daysLeft) - (b.daysLeft == null ? 9999 : b.daysLeft) || String(a.title).localeCompare(String(b.title), 'ja'))
  return out
}

// ── C. 提出・成果物のようす（事実だけ） ──
export async function tsHabits(env: any, userId: string, nowMs: number) {
  const todayJ = tsYmdJ(nowMs)
  const from60 = addDays(todayJ, -60), from28 = addDays(tsDay830(nowMs), -27)
  const school: any = { n: 0, before: 0, same: 0, after: 0, open: 0, openPast: 0, closedUnchecked: 0, lead: {} as Record<string, number>, bySubject: {} as Record<string, any>, kinds: {} as Record<string, any>, recent: [] as any[] }
  try {
    const r = await env.DB.prepare(`SELECT a.id, a.title, a.subject, a.due_date, a.created_at, a.done_at, k.checked_day FROM class_members cm
        JOIN school_assignments a ON a.class_id = cm.class_id AND a.deleted = 0 AND a.created_at >= ?
        LEFT JOIN school_assignment_checks k ON k.assignment_id = a.id AND k.user_id = cm.user_id
        WHERE cm.user_id = ? ORDER BY a.created_at DESC LIMIT 80`).bind(from60, userId).all()
    for (const x of rows(r)) {
      const due = isYmd(x.due_date) ? String(x.due_date) : ''
      const cd = isYmd(x.checked_day) ? String(x.checked_day) : ''
      const subj = String(x.subject || '') || '（教科なし）'
      const kind = tsKindOf(x.title)
      const S = school.bySubject[subj] || (school.bySubject[subj] = { n: 0, onTime: 0, late: 0, open: 0 })
      const K = school.kinds[kind] || (school.kinds[kind] = { n: 0, onTime: 0, late: 0, open: 0 })
      let st = ''
      if (cd) {
        if (due) {
          const d = diffDays(due, cd)   // しめきりの何日前に出したか
          school.n++; S.n++; K.n++
          if (d > 0) { school.before++; S.onTime++; K.onTime++; st = d === 1 ? '前の日' : d + '日前' }
          else if (d === 0) { school.same++; S.onTime++; K.onTime++; st = 'しめきりの日' }
          else { school.after++; S.late++; K.late++; st = 'しめきりの' + (-d) + '日あと' }
          const lk = d > 3 ? '4日以上前' : d >= 1 ? d + '日前' : d === 0 ? '当日' : 'あと'
          school.lead[lk] = (school.lead[lk] || 0) + 1
        } else st = '出した（しめきりなし）'
      } else if (x.done_at) { school.closedUnchecked++; st = '✓なしで完了' }
      else { school.open++; S.open++; K.open++; if (due && due < todayJ) school.openPast++; st = due && due < todayJ ? 'しめきりを過ぎて まだ' : 'これから' }
      if (school.recent.length < 12) school.recent.push({ title: cut(x.title, 30), subject: String(x.subject || ''), dueDate: due, checkedDay: cd, state: st })
    }
  } catch (_e) {}

  const hw: any = { n: 0, from: from28, dow: [0, 0, 0, 0, 0, 0, 0], band: { '朝（〜9時）': 0, '学校から帰ってすぐ（〜18時）': 0, '夕方〜夜（18〜21時）': 0, '21時より後': 0 }, photoDays: 0, physicalDays: 0, minPhoto: null, minNoPhoto: null, minAvg: null, weather: { sun: 0, cloud: 0, rain: 0 }, rest: 0 }
  try {
    const r = await env.DB.prepare('SELECT day_key, submitted_at, minutes, end_weather, has_physical, rest_day FROM homework_submissions WHERE user_id=? AND day_key >= ? ORDER BY day_key DESC LIMIT 40').bind(userId, from28).all()
    const subs = rows(r)
    const photo: Record<string, 1> = {}
    for (const t of ['homework_photos2', 'homework_photos']) {
      try { const pr = await env.DB.prepare(`SELECT DISTINCT day_key FROM ${t} WHERE user_id=? AND day_key >= ? LIMIT 40`).bind(userId, from28).all(); for (const p of rows(pr)) photo[String(p.day_key)] = 1 } catch (_e) {}
    }
    let mp = 0, np = 0, mn = 0, nn = 0, all = 0
    const seen: Record<string, 1> = {}
    for (const s of subs) {
      const dk = String(s.day_key || ''); if (!dk || seen[dk]) continue; seen[dk] = 1
      if (Number(s.rest_day)) { hw.rest++; continue }
      hw.n++
      const wd = new Date(dk + 'T00:00:00Z').getUTCDay(); hw.dow[wd]++
      const at = Number(s.submitted_at || 0)
      if (at > 0) {
        const h = new Date(at + H9).getUTCHours()
        const k = h < 9 ? '朝（〜9時）' : h < 18 ? '学校から帰ってすぐ（〜18時）' : h < 21 ? '夕方〜夜（18〜21時）' : '21時より後'
        hw.band[k]++
      }
      const m = Number(s.minutes || 0)
      all += m
      if (photo[dk]) { hw.photoDays++; mp += m; np++ } else { mn += m; nn++ }
      if (Number(s.has_physical)) hw.physicalDays++
      const w = String(s.end_weather || ''); if (hw.weather[w] != null) hw.weather[w]++
    }
    if (np >= 2 && nn >= 2) { hw.minPhoto = Math.round(mp / np); hw.minNoPhoto = Math.round(mn / nn) }
    if (hw.n) hw.minAvg = Math.round(all / hw.n)
  } catch (_e) {}

  const promise: any[] = []
  try {
    const r = await env.DB.prepare('SELECT week_key, promise_text, promise_result, promise_reason FROM week_ref2 WHERE user_id=? ORDER BY week_key DESC LIMIT 4').bind(userId).all()
    for (const x of rows(r)) if (x.promise_text || x.promise_result) promise.push({ weekKey: String(x.week_key), text: cut(x.promise_text, 60), result: String(x.promise_result || ''), reason: String(x.promise_reason || '') })
  } catch (_e) {}
  return { school, hw, promise }
}

// ── D. テストの傾向（点数は読まない・返さない） ──
export async function tsTests(env: any, userId: string) {
  const out: any[] = []
  let list: any[] = []
  try {
    const r = await env.DB.prepare('SELECT id, test_name, test_date, subject, eval_knowledge, eval_thinking, created_at FROM student_test_scores WHERE user_id=? ORDER BY id DESC LIMIT 12').bind(userId).all()
    list = rows(r).filter((x) => !/通知表|観点別評価/.test(String(x.test_name || '')) && (mark(x.eval_knowledge) || mark(x.eval_thinking))).slice(0, 6)
  } catch (_e) { list = [] }
  const qs = list.map((x) => {
    const td = isYmd(x.test_date) ? String(x.test_date) : ''
    const date = td || (isYmd(String(x.created_at || '').slice(0, 10)) ? String(x.created_at).slice(0, 10) : '')
    const item: any = { name: cut(x.test_name, 40), subject: String(x.subject || ''), date, dateFrom: td ? 'test' : 'import', k: mark(x.eval_knowledge), t: mark(x.eval_thinking), prep: [] as any[] }
    out.push(item)
    if (!date) return Promise.resolve()
    // テスト前1週間（日本時間の0:00 → UTC）
    const a = new Date(Date.parse(addDays(date, -7) + 'T00:00:00Z') - H9).toISOString()
    const b = new Date(Date.parse(addDays(date, 1) + 'T00:00:00Z') - H9).toISOString()
    return env.DB.prepare('SELECT unit, COUNT(*) AS n, SUM(is_correct) AS c FROM learning_results WHERE user_id=? AND answered_at >= ? AND answered_at < ? GROUP BY unit ORDER BY n DESC LIMIT 20').bind(userId, a, b).all()
      .then((r: any) => { item.prep = rows(r).map((p) => ({ unit: String(p.unit || ''), n: Number(p.n || 0), c: Number(p.c || 0) })) })
      .catch(() => {})
  })
  await Promise.all(qs)
  return out
}

// 先生の個人ページ・印刷カルテ・今日のひと往復のために、student-full-analysis に足す1かたまり
export async function tsPack(env: any, userId: string, karteMon: string, nowMs: number) {
  const todayJ = tsYmdJ(nowMs)
  const kw = isYmd(karteMon) ? await tsHwWeek(env, userId, karteMon) : null
  const kOn = kw ? await tsOnTime(env, userId, kw.from, kw.to) : 0
  const [habits, tests, pending] = await Promise.all([tsHabits(env, userId, nowMs), tsTests(env, userId), tsPending(env, userId, todayJ)])
  return { today: todayJ, karteWeek: kw ? { from: kw.from, to: kw.to, hwDays: kw.days, onTime: kOn } : null, habits, tests, pending }
}

type Deps = { weekRefAllowedKeys: (n?: number) => string[] }

export function registerTeishutsu(app: any, deps: Deps) {
  function curMon(nowMs: number) { const wk = deps.weekRefAllowedKeys(nowMs)[0]; return isoMonday(wk) }
  async function classOk(env: any, u: any, classId: string) {
    if (!classId) return false
    const r = u.role === 'admin'
      ? await env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first()
      : await env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first()
    return !!r
  }
  async function studentOk(env: any, u: any, sid: string) {
    if (!sid) return false
    const r = u.role === 'admin'
      ? await env.DB.prepare('SELECT 1 AS x FROM class_members WHERE user_id=? LIMIT 1').bind(sid).first()
      : await env.DB.prepare('SELECT 1 AS x FROM class_members cm JOIN classes cl ON cl.id=cm.class_id AND cl.teacher_id=? WHERE cm.user_id=? LIMIT 1').bind(u.id, sid).first()
    return !!r
  }
  async function itemOf(env: any, u: any, id: string) {
    if (!id) return null
    const a: any = await env.DB.prepare('SELECT * FROM school_assignments WHERE id=? AND deleted=0 LIMIT 1').bind(id).first()
    if (!a) return null
    return (await classOk(env, u, String(a.class_id))) ? a : null
  }
  function teacher(c: any) { const u = c.get('user'); return (u && (u.role === 'teacher' || u.role === 'admin')) ? u : null }

  // ───────── 子ども：自分の分だけ ─────────
  app.get('/api/student/teishutsu', async (c: any) => {
    const u = c.get('user')
    if (!u) return c.json({ ok: false, error: 'unauthorized' }, 401)
    if (u.role !== 'student') return c.json({ ok: false, error: 'forbidden' }, 403)
    const asked = String(c.req.query('userId') || c.req.query('studentId') || '')
    if (asked && asked !== String(u.id)) return c.json({ ok: false, error: 'forbidden' }, 403)
    const now = Date.now()
    const mon = curMon(now)
    const todayJ = tsYmdJ(now), d830 = tsDay830(now)
    const w = await tsHwWeek(c.env, u.id, mon)
    const pending = await tsPending(c.env, u.id, todayJ)
    const onTime = await tsOnTime(c.env, u.id, w.from, w.to)
    return c.json({ ok: true, today: todayJ, day830: d830, hw: { from: w.from, to: w.to, days: w.days, submittedToday: w.dayKeys.indexOf(d830) >= 0 }, onTimeWeek: onTime, pending: pending.slice(0, 8) })
  })

  // ───────── 先生：📮 提出物チェック ─────────
  app.get('/api/teacher/teishutsu', async (c: any) => {
    const u = teacher(c); if (!u) return c.json({ ok: false, error: 'forbidden' }, 403)
    const cid = String(c.req.query('classId') || '')
    if (!(await classOk(c.env, u, cid))) return c.json({ ok: false, error: 'class_not_found' }, 404)
    const env = c.env
    const rr = await env.DB.prepare('SELECT u.id AS userId, u.login_id AS loginId, u.name AS name, u.roster_no AS rosterNo FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=? ORDER BY (u.roster_no IS NULL), u.roster_no, u.name LIMIT 80').bind(cid).all()
    const roster = rows(rr).map((x) => ({ userId: String(x.userId), loginId: String(x.loginId || ''), name: String(x.name || ''), rosterNo: x.rosterNo == null ? null : Number(x.rosterNo) }))
    const ar = await env.DB.prepare('SELECT id, title, subject, due_date, created_at, done_at FROM school_assignments WHERE class_id=? AND deleted=0 AND done_at IS NULL ORDER BY created_at DESC LIMIT 40').bind(cid).all()
    const dr = await env.DB.prepare('SELECT id, title, subject, due_date, created_at, done_at FROM school_assignments WHERE class_id=? AND deleted=0 AND done_at IS NOT NULL ORDER BY done_at DESC LIMIT 15').bind(cid).all()
    const items = rows(ar).concat(rows(dr)).map((x) => ({ id: String(x.id), title: String(x.title || ''), subject: String(x.subject || ''), dueDate: String(x.due_date || ''), createdAt: String(x.created_at || ''), doneAt: x.done_at ? String(x.done_at) : '', checked: {} as Record<string, string> }))
    if (items.length) {
      const byId: Record<string, any> = {}; items.forEach((it) => { byId[it.id] = it })
      const kr = await env.DB.prepare(`SELECT assignment_id, user_id, checked_day FROM school_assignment_checks WHERE assignment_id IN (${items.map(() => '?').join(',')})`).bind(...items.map((x) => x.id)).all()
      for (const k of rows(kr)) { const it = byId[String(k.assignment_id)]; if (it) it.checked[String(k.user_id)] = String(k.checked_day || '') }
    }
    return c.json({ ok: true, classId: cid, today: tsYmdJ(Date.now()), roster, items, subjects: TS_SUBJECTS })
  })

  app.post('/api/teacher/teishutsu/create', async (c: any) => {
    const u = teacher(c); if (!u) return c.json({ ok: false, error: 'forbidden' }, 403)
    const b: any = await c.req.json().catch(() => null)
    if (!b) return c.json({ ok: false, error: 'invalid' }, 400)
    const cid = String(b.classId || '')
    if (!(await classOk(c.env, u, cid))) return c.json({ ok: false, error: 'class_not_found' }, 404)
    const title = cut(b.title, 40)
    if (!title) return c.json({ ok: false, error: 'title_required' }, 400)
    const subject = cut(b.subject, 10)
    const due = isYmd(b.dueDate) ? String(b.dueDate) : ''
    const id = (globalThis.crypto && (globalThis.crypto as any).randomUUID) ? (globalThis.crypto as any).randomUUID() : ('sa-' + Date.now() + '-' + Math.random().toString(36).slice(2))
    await c.env.DB.prepare("INSERT INTO school_assignments (id, class_id, title, subject, due_date, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))").bind(id, cid, title, subject, due, u.id).run()
    return c.json({ ok: true, id })
  })

  // ✓ をつける／取り消す（1人）・全員 ✓
  app.post('/api/teacher/teishutsu/check', async (c: any) => {
    const u = teacher(c); if (!u) return c.json({ ok: false, error: 'forbidden' }, 403)
    const b: any = await c.req.json().catch(() => null)
    if (!b) return c.json({ ok: false, error: 'invalid' }, 400)
    const a: any = await itemOf(c.env, u, String(b.id || ''))
    if (!a) return c.json({ ok: false, error: 'not_found' }, 404)
    const day = tsYmdJ(Date.now())
    if (b.all) {
      const r = await c.env.DB.prepare("INSERT OR IGNORE INTO school_assignment_checks (assignment_id, user_id, checked_at, checked_day, checked_by) SELECT ?, user_id, datetime('now'), ?, ? FROM class_members WHERE class_id=?").bind(a.id, day, u.id, a.class_id).run()
      return c.json({ ok: true, day, added: Number((r && r.meta && r.meta.changes) || 0) })
    }
    const sid = String(b.userId || '')
    const mem = await c.env.DB.prepare('SELECT 1 AS x FROM class_members WHERE class_id=? AND user_id=? LIMIT 1').bind(a.class_id, sid).first()
    if (!mem) return c.json({ ok: false, error: 'student_not_found' }, 404)
    if (b.on === false) {
      await c.env.DB.prepare('DELETE FROM school_assignment_checks WHERE assignment_id=? AND user_id=?').bind(a.id, sid).run()
      return c.json({ ok: true, on: false })
    }
    await c.env.DB.prepare("INSERT OR IGNORE INTO school_assignment_checks (assignment_id, user_id, checked_at, checked_day, checked_by) VALUES (?, ?, datetime('now'), ?, ?)").bind(a.id, sid, day, u.id).run()
    const k: any = await c.env.DB.prepare('SELECT checked_day FROM school_assignment_checks WHERE assignment_id=? AND user_id=? LIMIT 1').bind(a.id, sid).first()
    return c.json({ ok: true, on: true, day: (k && k.checked_day) || day })
  })

  // 完了（畳む）／もどす／けす／名前・しめきりを直す
  app.post('/api/teacher/teishutsu/update', async (c: any) => {
    const u = teacher(c); if (!u) return c.json({ ok: false, error: 'forbidden' }, 403)
    const b: any = await c.req.json().catch(() => null)
    if (!b) return c.json({ ok: false, error: 'invalid' }, 400)
    const a: any = await itemOf(c.env, u, String(b.id || ''))
    if (!a) return c.json({ ok: false, error: 'not_found' }, 404)
    if (b.deleted === true) { await c.env.DB.prepare('UPDATE school_assignments SET deleted=1 WHERE id=?').bind(a.id).run(); return c.json({ ok: true, deleted: true }) }
    if (b.done === true) await c.env.DB.prepare("UPDATE school_assignments SET done_at=datetime('now') WHERE id=?").bind(a.id).run()
    if (b.done === false) await c.env.DB.prepare('UPDATE school_assignments SET done_at=NULL WHERE id=?').bind(a.id).run()
    if (typeof b.title === 'string' && cut(b.title, 40)) await c.env.DB.prepare('UPDATE school_assignments SET title=? WHERE id=?').bind(cut(b.title, 40), a.id).run()
    if (typeof b.dueDate === 'string' && (b.dueDate === '' || isYmd(b.dueDate))) await c.env.DB.prepare('UPDATE school_assignments SET due_date=? WHERE id=?').bind(b.dueDate, a.id).run()
    if (typeof b.subject === 'string') await c.env.DB.prepare('UPDATE school_assignments SET subject=? WHERE id=?').bind(cut(b.subject, 10), a.id).run()
    return c.json({ ok: true })
  })

  // 先生：1人ぶん（個人ページ・振り返り一覧で小さく）。lite=1 のときはテストを読まない。
  app.get('/api/teacher/teishutsu/student', async (c: any) => {
    const u = teacher(c); if (!u) return c.json({ ok: false, error: 'forbidden' }, 403)
    const sid = String(c.req.query('studentId') || '')
    if (!(await studentOk(c.env, u, sid))) return c.json({ ok: false, error: 'student_not_found' }, 404)
    const now = Date.now()
    const habits = await tsHabits(c.env, sid, now)
    const pending = await tsPending(c.env, sid, tsYmdJ(now))
    const w = await tsHwWeek(c.env, sid, curMon(now))
    const tests = c.req.query('lite') ? null : await tsTests(c.env, sid)
    return c.json({ ok: true, today: tsYmdJ(now), habits, pending, week: { from: w.from, to: w.to, hwDays: w.days }, tests })
  })
}
