// ==================== 🔄 WEEKREF2_V1 週の振り返りを充実させる（2026-10-26） ====================
//
// 金曜に学校の授業中にみんなで振り返り、月曜にカルテを見ながら週の計画を立てる、の流れに足すもの。
//   1) 「先週決めたこと、どうだった？」… 先週の「次どうする？」「来週やってみたいこと」と今週の計画を見て、
//      できた／ちょっと／できなかった ＋ わけ（時間がなかった・わすれた・やり方が合わなかった・その他）。責めない言い方。
//   2) 今週の自分の記録 … 開いた日数・取り組んだ単元と正答の変化（先週→今週）・計画を書いた日のうち家庭学習を出した日。
//      事実だけ。ほかの子との比較・順位・点・パーセントは返さない。
//   3) 週ごとに変わる「考える問い」（学び方を考える問い・15こ をローテーション・任意）
//   4) 🏫 学校での学び … 教科（先生が ⑥授業メモ に「算数：比の利用」のように書いた行があれば、それを候補に）
//      ・わかったこと・もっと知りたいこと。
//   ・提出は いつもの週の振り返り（/api/student/weekly-reflection）と ひとまとめ。ここではコインを付けない（二重なし）。
//   ・先生：📋振り返り一覧・今日のひと往復の材料・カルテ（個人分析）に 1〜4 を渡す（読むのはクラス×週の索引だけ）。
//
// ⚠️ テーブルは migrations/0047_week_ref2.sql だけで作る。ここでは DDL を一切実行しない（2026-09-03 の障害）。
// ⚠️ D1 は主キー・索引の範囲読みだけ。learning_results は「本人・2週間・上限つき」でしか読まない。

export const WR2_LR_ROW_CAP = 1500
const DAY = 86400000

export const WR2_RESULTS: Record<string, string> = { done: 'できた', some: 'ちょっと', not: 'できなかった' }
export const WR2_REASONS: Record<string, string> = { time: '時間がなかった', forgot: 'わすれた', way: 'やり方が合わなかった', other: 'その他' }
export const WR2_SUBJECTS = ['国語', '算数', '理科', '社会', '外国語', '音楽', '図工', '家庭', '体育', '道徳', '総合', 'その他']

// 週ごとに変わる「考える問い」（学び方を考える問い）。選択肢＋自由記述・どれも任意。
export const WR2_QUESTIONS: { id: string, q: string, choices: string[] }[] = [
  { id: 'q01', q: 'どの やり方が よかった？', choices: ['くりかえし といた', 'まちがいを 見なおした', '図や 絵に かいた', '声に 出して 読んだ'] },
  { id: 'q02', q: 'つまずいたとき、どうした？', choices: ['ヒントを 見た', 'もう一度 読んだ', 'だれかに きいた', 'いったん 休んで また やった'] },
  { id: 'q03', q: 'だれかに 教えたり 教わったり した？', choices: ['教えた', '教わった', 'いっしょに 考えた', '今週は ひとりで やった'] },
  { id: 'q04', q: '集中できたのは どんなとき？', choices: ['時間を 決めたとき', 'しずかな 場所', 'すきな 単元のとき', 'だれかと いっしょのとき'] },
  { id: 'q05', q: '「わかった！」と 思ったのは どんなとき？', choices: ['とけたとき', '人に 説明できたとき', '前に ならったことと つながったとき', 'まちがいに 気づいたとき'] },
  { id: 'q06', q: 'まちがえた 問題、どうした？', choices: ['もう一度 といた', '答えを 見て たしかめた', 'ノートに 書いた', '次の 日に また やった'] },
  { id: 'q07', q: '学ぶ 時間は いつが よかった？', choices: ['朝', '学校から 帰って すぐ', '夜ごはんの 前', 'ねる 前'] },
  { id: 'q08', q: 'ちょっと むずかしいことに ちょうせん した？', choices: ['ちょうせん した', '少し ちょうせん した', '次は ちょうせん したい'] },
  { id: 'q09', q: '自分で 決めたことを つづける くふうは？', choices: ['メモに 書いた', '時間を 決めた', 'おうちの人に 言った', 'できたら しるしを つけた'] },
  { id: 'q10', q: '今週の 学びで、どこかで 使えそうなことは？', choices: ['友だちに 教えられる', '家で 使える', '次の 単元で 使える', 'これから 見つける'] },
  { id: 'q11', q: 'わからないとき、どこを 見た？', choices: ['教科書', 'ノート', 'アプリの ヒント', '友だちの 考え'] },
  { id: 'q12', q: '前の 自分と くらべて、かわったことは？', choices: ['とく はやさ', '集中する 時間', 'つづける 力', '自分で 決める 力'] },
  { id: 'q13', q: '学び方を 1つ 変えるなら？', choices: ['時間', '場所', '量', 'やる じゅんばん'] },
  { id: 'q14', q: '今週 いちばん がんばったと 思う ところは？', choices: ['はじめるまで', 'とちゅうで やめなかった', '見なおし', '新しいことに ちょうせん'] },
  { id: 'q15', q: '来週の 自分に ひとこと おくるなら？', choices: ['その ちょうしで', '1つずつ いこう', 'あせらず いこう', 'ちょうせん してみよう'] },
]
export function wr2QuestionFor(weekKey: string) {
  const m = String(weekKey || '').match(/^(\d{4})-W(\d{2})$/)
  const n = m ? (Number(m[1]) * 53 + Number(m[2])) : 0
  return WR2_QUESTIONS[n % WR2_QUESTIONS.length]
}

function cut(x: any, n: number) { return Array.from(String(x == null ? '' : x).replace(/[\r\n\t]/g, ' ').replace(/[<>]/g, '').replace(/\s+/g, ' ').trim()).slice(0, n).join('') }
function isWeek(s: any) { return /^\d{4}-W\d{2}$/.test(String(s || '')) }
export function wr2IsoKey(d: Date): string {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()))
  t.setUTCDate(t.getUTCDate() + 4 - (t.getUTCDay() || 7))
  const ys = new Date(Date.UTC(t.getUTCFullYear(), 0, 1))
  const wn = Math.ceil((((t.getTime() - ys.getTime()) / DAY) + 1) / 7)
  return `${t.getUTCFullYear()}-W${String(wn).padStart(2, '0')}`
}
export function wr2Monday(wk: string): Date | null {
  const m = String(wk).match(/^(\d{4})-W(\d{2})$/)
  if (!m) return null
  const j4 = new Date(Date.UTC(Number(m[1]), 0, 4))
  const dw = j4.getUTCDay() || 7
  return new Date(j4.getTime() + ((1 - dw) + (Number(m[2]) - 1) * 7) * DAY)
}
function ymd(d: Date) { return d.toISOString().slice(0, 10) }
export function wr2PrevWeek(wk: string) { const mo = wr2Monday(wk); return mo ? wr2IsoKey(new Date(mo.getTime() - 7 * DAY)) : '' }
// 「次：やり方を 変える（時間）　夜ごはんの前に」→ 先頭の「次：」をとる
function stripNext(s: any) { return String(s || '').replace(/^[\s　]*次[：:][\s　]*/, '').trim() }

// 計画の日（月〜金）の中身
const DAYS = ['mon', 'tue', 'wed', 'thu', 'fri']
const DAYS_JA = ['月', '火', '水', '木', '金']
export function wr2PlanDays(plansJson: any): { d: number, text: string }[] {
  let o: any = {}
  try { o = JSON.parse(String(plansJson || '{}')) || {} } catch (_e) { o = {} }
  const ks = Object.keys(o).filter((k) => k !== '_modified')
  const out: { d: number, text: string }[] = []
  for (let i = 0; i < 5; i++) {
    let v: any = o[DAYS[i]]
    if (v === undefined && ks[i] && DAYS.indexOf(ks[i]) < 0) v = o[ks[i]]
    const t = (v && typeof v === 'object') ? String(v.free || '') : String(v || '')
    const s = cut(t, 60)
    if (s && !/^(なし|休み|やすみ|ー|-)$/.test(s)) out.push({ d: i, text: s })
  }
  return out
}

// ⑥授業メモから、子どもに出してよい行だけをひろう（「算数：比の利用」「【理科】てこのはたらき」の形）。
//   ・この形の行だけ。ふつうのメモ（授業の気づき）は子どもの画面に出さない。
//   ・名前らしいことば（名簿の名前・さん・くん・ちゃん・先生）が入っている行は出さない。
export function wr2NoteTopics(bodies: string[], names: string[]) {
  const subjRe = '(国語|算数|理科|社会|外国語|英語|音楽|図工|図画工作|家庭|家庭科|体育|保健|道徳|総合|学活|書写)'
  const re1 = new RegExp('^[\\s　・*＊\\-]*[【［\\[(（]' + subjRe + '[】］\\])）][\\s　]*[：:｜|]?[\\s　]*(.{1,40})$')   // 【理科】てこのはたらき
  const re2 = new RegExp('^[\\s　・*＊\\-]*' + subjRe + '[\\s　]*[：:｜|][\\s　]*(.{1,40})$')                             // 算数：比の利用
  const nm = names.map((n) => String(n || '').replace(/[\s　]/g, '')).filter((n) => n.length >= 2)
  const out: { subj: string, theme: string }[] = []
  const seen: Record<string, 1> = {}
  for (const b of bodies) {
    for (const raw of String(b || '').split(/\r?\n/)) {
      const m = raw.trim().match(re1) || raw.trim().match(re2)
      if (!m) continue
      let subj = m[1]
      if (subj === '英語') subj = '外国語'
      if (subj === '図画工作') subj = '図工'
      if (subj === '家庭科') subj = '家庭'
      if (subj === '保健') subj = '体育'
      if (subj === '学活' || subj === '書写') subj = subj === '書写' ? '国語' : 'その他'
      const theme = cut(m[2].replace(/[。．.]+$/, ''), 30)
      if (!theme) continue
      const flat = theme.replace(/[\s　]/g, '')
      if (/(さん|くん|君|ちゃん|先生)/.test(flat)) continue
      if (nm.some((n) => flat.indexOf(n) >= 0)) continue
      const k = subj + '|' + theme
      if (seen[k]) continue
      seen[k] = 1
      out.push({ subj, theme })
      if (out.length >= 12) return out
    }
  }
  return out
}

// 今週の自分の記録（事実だけ）。本人・期間・上限つきで読む。
export async function wr2Facts(env: any, userId: string, wk: string, nowMs: number) {
  const mo = wr2Monday(wk) as Date
  const mon = ymd(mo), sun = ymd(new Date(mo.getTime() + 6 * DAY))
  const prevMon = new Date(mo.getTime() - 7 * DAY)
  // learning_results の answered_at は UTC の ISO。日本時間の月曜0:00 = 前の日の15:00Z
  const lrFrom = new Date(prevMon.getTime() - 9 * 3600000).toISOString()
  const lrMid = new Date(mo.getTime() - 9 * 3600000).toISOString()
  const lrTo = new Date(mo.getTime() + 7 * DAY - 9 * 3600000).toISOString()
  const today = ymd(new Date(nowMs + 9 * 3600000))
  const days: Record<string, 1> = {}
  try {
    const r = await env.DB.prepare('SELECT day_key FROM app_open_days WHERE user_id=? AND day_key >= ? AND day_key <= ? LIMIT 10').bind(userId, mon, sun).all()
    for (const x of (((r && r.results) || []) as any[])) days[String(x.day_key)] = 1
  } catch (_e) {}
  const hw: Record<string, 1> = {}
  try {
    const r = await env.DB.prepare('SELECT day_key FROM homework_submissions WHERE user_id=? AND day_key >= ? AND day_key <= ? LIMIT 14').bind(userId, mon, sun).all()
    for (const x of (((r && r.results) || []) as any[])) { const dk = String(x.day_key || ''); if (dk) { hw[dk] = 1; days[dk] = 1 } }
  } catch (_e) {}
  const units: { unit: string, n: number, c: number, prevC: number, prevN: number }[] = []
  let lrDays = 0
  try {
    const r = await env.DB.prepare('SELECT unit, SUM(CASE WHEN answered_at >= ? THEN 1 ELSE 0 END) AS n, SUM(CASE WHEN answered_at >= ? AND is_correct=1 THEN 1 ELSE 0 END) AS c, SUM(CASE WHEN answered_at < ? THEN 1 ELSE 0 END) AS pn, SUM(CASE WHEN answered_at < ? AND is_correct=1 THEN 1 ELSE 0 END) AS pc, COUNT(DISTINCT CASE WHEN answered_at >= ? THEN substr(answered_at,1,10) END) AS d FROM (SELECT unit, is_correct, answered_at FROM learning_results WHERE user_id=? AND answered_at >= ? AND answered_at < ? ORDER BY answered_at DESC LIMIT ?) GROUP BY unit LIMIT 60')
      .bind(lrMid, lrMid, lrMid, lrMid, lrMid, userId, lrFrom, lrTo, WR2_LR_ROW_CAP).all()
    for (const x of (((r && r.results) || []) as any[])) {
      const n = Number(x.n || 0)
      lrDays = Math.max(lrDays, Number(x.d || 0))
      if (!x.unit || n <= 0) continue
      units.push({ unit: String(x.unit), n, c: Number(x.c || 0), prevC: Number(x.pc || 0), prevN: Number(x.pn || 0) })
    }
  } catch (_e) {}
  units.sort((a, b) => b.n - a.n)
  // 計画を書いた日（今日まで）のうち、家庭学習を出した日
  let plan: { d: number, text: string }[] = []
  try {
    const p: any = await env.DB.prepare('SELECT plans_json FROM student_weekly_plans WHERE user_id=? AND week_key=? LIMIT 1').bind(userId, wk).first()
    plan = p ? wr2PlanDays(p.plans_json) : []
  } catch (_e) {}
  let planDays = 0, doneDays = 0
  for (const pd of plan) {
    const dk = ymd(new Date(mo.getTime() + pd.d * DAY))
    if (dk > today || (dk === today && !hw[dk])) continue   // 今日の分は、もう出してあるときだけ数える
    planDays++
    if (hw[dk]) doneDays++
  }
  return {
    openDays: Math.max(Object.keys(days).length, lrDays, nowMs >= mo.getTime() - 9 * 3600000 && today <= sun ? 1 : 0),
    hwDays: Object.keys(hw).length,
    units: units.slice(0, 3).map((u) => ({ unit: u.unit, c: u.c, n: u.n, prevC: u.prevC })),
    planDays, doneDays,
    plan: plan.map((p) => ({ day: DAYS_JA[p.d], text: p.text })),
  }
}

function rowView(r: any) {
  if (!r) return null
  let facts: any = null
  try { facts = r.facts_json ? JSON.parse(r.facts_json) : null } catch (_e) { facts = null }
  const q = WR2_QUESTIONS.filter((x) => x.id === r.q_id)[0] || null
  const ci = r.q_choice === '' || r.q_choice == null ? -1 : Number(r.q_choice)
  return {
    weekKey: String(r.week_key || ''),
    promise: (r.promise_text || r.promise_result) ? { text: r.promise_text || '', result: r.promise_result || '', resultJa: WR2_RESULTS[r.promise_result] || '', reason: r.promise_reason || '', reasonJa: WR2_REASONS[r.promise_reason] || '', note: r.promise_note || '' } : null,
    q: (q && (ci >= 0 || r.q_text)) ? { id: q.id, label: q.q, choiceJa: ci >= 0 ? (q.choices[ci] || '') : '', text: r.q_text || '' } : null,
    school: (r.school_subj || r.school_learned || r.school_more) ? { subj: r.school_subj || '', theme: r.school_theme || '', learned: r.school_learned || '', more: r.school_more || '' } : null,
    facts,
  }
}
export function wr2View(r: any) { return rowView(r) }

// 先生：クラス×週でまとめて読む（📋振り返り一覧・今日のひと往復の材料）。class_members → 主キー の索引だけ。
export async function wr2ForClass(env: any, classId: string, weeks: string[]) {
  const out: Record<string, any> = {}
  const ws = weeks.filter(isWeek).slice(0, 3)
  if (!classId || !ws.length) return out
  try {
    const r = await env.DB.prepare(`SELECT w.* FROM class_members cm JOIN week_ref2 w ON w.user_id = cm.user_id AND w.week_key IN (${ws.map(() => '?').join(',')}) WHERE cm.class_id = ?`).bind(...ws, classId).all()
    for (const x of (((r && r.results) || []) as any[])) out[String(x.user_id) + '|' + String(x.week_key)] = rowView(x)
  } catch (e) { console.error('WEEKREF2_V1 class', e) }
  return out
}

async function studentClass(env: any, userId: string): Promise<string> {
  try { const r: any = await env.DB.prepare('SELECT class_id FROM class_members WHERE user_id=? LIMIT 1').bind(userId).first(); return r ? String(r.class_id || '') : '' } catch (_e) { return '' }
}
async function promiseOf(env: any, userId: string, prevWk: string) {
  let next = '', nt: any = null
  try { const r: any = await env.DB.prepare('SELECT next_action FROM structured_reflections WHERE user_id=? AND week_key=? LIMIT 1').bind(userId, prevWk).first(); next = stripNext(r && r.next_action) } catch (_e) {}
  try { const r: any = await env.DB.prepare('SELECT unit_name, text FROM week_next_try WHERE user_id=? AND week_key=? LIMIT 1').bind(userId, prevWk).first(); if (r && (r.unit_name || r.text)) nt = { unitName: String(r.unit_name || ''), text: String(r.text || '') } } catch (_e) {}
  const parts: string[] = []
  if (next) parts.push(next)
  if (nt) { const s = (nt.unitName ? '「' + nt.unitName + '」' : '') + (nt.text || ''); if (s && parts.join('').indexOf(nt.text || '@@') < 0) parts.push(s) }
  return { next, nextTry: nt, text: cut(parts.join('／'), 80) }
}

export function registerWeekRef2(app: any, deps: { weekRefAllowedKeys: (n?: number) => string[] }) {
  function pickWeek(want: any) {
    const allowed = deps.weekRefAllowedKeys()
    return allowed.indexOf(String(want || '')) >= 0 ? String(want) : allowed[0]
  }
  function student(c: any) { const u = c.get('user'); return (u && u.role === 'student') ? u : null }

  // 児童：週の振り返りの材料（先週決めたこと・今週の計画・今週の記録・今週の問い・学校の候補・出したもの）
  app.get('/api/student/week-ref2', async (c: any) => {
    const u = c.get('user')
    if (!u) return c.json({ ok: false, error: 'unauthorized' }, 401)
    if (u.role !== 'student') return c.json({ ok: false, error: 'forbidden' }, 403)
    const asked = String(c.req.query('userId') || c.req.query('studentId') || '')
    if (asked && asked !== String(u.id)) return c.json({ ok: false, error: 'forbidden' }, 403)
    const now = Date.now()
    const wk = pickWeek(c.req.query('weekKey'))
    const pw = wr2PrevWeek(wk)
    const env = c.env
    const promise = await promiseOf(env, u.id, pw)
    const facts = await wr2Facts(env, u.id, wk, now)
    let mine: any = null, last: any = null
    try {
      const r = await env.DB.prepare('SELECT * FROM week_ref2 WHERE user_id=? AND week_key IN (?, ?)').bind(u.id, wk, pw).all()
      for (const x of (((r && r.results) || []) as any[])) { if (x.week_key === wk) mine = rowView(x); else last = rowView(x) }
    } catch (_e) {}
    // ⑥授業メモ（今週の分）から、教科：単元 の行だけ
    let topics: any[] = []
    const cid = await studentClass(env, u.id)
    if (cid) {
      try {
        const mo = wr2Monday(wk) as Date
        const r = await env.DB.prepare('SELECT body FROM teacher_class_notes WHERE class_id=? AND day_key >= ? AND day_key <= ? ORDER BY day_key DESC LIMIT 40').bind(cid, ymd(mo), ymd(new Date(mo.getTime() + 6 * DAY))).all()
        const bodies = (((r && r.results) || []) as any[]).map((x) => String(x.body || ''))
        if (bodies.length) {
          const nr = await env.DB.prepare('SELECT u.name AS name FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id = ? LIMIT 80').bind(cid).all()
          const names: string[] = []
          for (const x of (((nr && nr.results) || []) as any[])) { const n = String(x.name || ''); names.push(n); for (const p of n.split(/[\s　]+/)) names.push(p) }
          topics = wr2NoteTopics(bodies, names)
        }
      } catch (_e) {}
    }
    const q = wr2QuestionFor(wk)
    return c.json({
      ok: true, weekKey: wk, prevWeekKey: pw,
      promise: { text: promise.text, next: promise.next, nextTry: promise.nextTry }, plan: facts.plan,
      facts: { openDays: facts.openDays, hwDays: facts.hwDays, units: facts.units, planDays: facts.planDays, doneDays: facts.doneDays },
      question: q, subjects: WR2_SUBJECTS, topics, mine, last,
      results: WR2_RESULTS, reasons: WR2_REASONS,
    })
  })

  // 児童：出す（1人1週1行・上書き）。コインは付けない（コインは いつもの週の振り返りの台帳だけ）。
  app.post('/api/student/week-ref2', async (c: any) => {
    const u = c.get('user')
    if (!u) return c.json({ ok: false, error: 'unauthorized' }, 401)
    if (u.role !== 'student') return c.json({ ok: false, error: 'forbidden' }, 403)
    const body: any = await c.req.json().catch(() => null)
    if (!body) return c.json({ ok: false, error: 'invalid' }, 400)
    if (body.userId && String(body.userId) !== String(u.id)) return c.json({ ok: false, error: 'forbidden' }, 403)
    const wk = pickWeek(body.weekKey)
    const pw = wr2PrevWeek(wk)
    const p = body.promise || {}, qa = body.q || {}, sc = body.school || {}
    const result = WR2_RESULTS[String(p.result || '')] ? String(p.result) : ''
    const reason = (result && result !== 'done' && WR2_REASONS[String(p.reason || '')]) ? String(p.reason) : ''
    const q = wr2QuestionFor(wk)
    const ci = Number(qa.choice)
    const qChoice = (String(qa.id || '') === q.id && Number.isInteger(ci) && ci >= 0 && ci < q.choices.length) ? String(ci) : ''
    const qText = String(qa.id || '') === q.id ? cut(qa.text, 80) : ''
    const subj = WR2_SUBJECTS.indexOf(String(sc.subj || '')) >= 0 ? String(sc.subj) : ''
    const promise = await promiseOf(c.env, u.id, pw)
    const f = await wr2Facts(c.env, u.id, wk, Date.now())
    // 単元の名前は画面（CURRICULUM）から。表示用だけ（数は サーバーで数えたもの）
    const names = (body.unitNames && typeof body.unitNames === 'object') ? body.unitNames : {}
    const facts = { openDays: f.openDays, hwDays: f.hwDays, planDays: f.planDays, doneDays: f.doneDays, units: f.units.map((x) => ({ unit: x.unit, name: cut(names[x.unit], 20), c: x.c, prevC: x.prevC })) }
    await c.env.DB.prepare(`INSERT INTO week_ref2 (user_id, week_key, promise_text, promise_result, promise_reason, promise_note, q_id, q_choice, q_text, school_subj, school_theme, school_learned, school_more, facts_json, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
      ON CONFLICT(user_id, week_key) DO UPDATE SET promise_text=excluded.promise_text, promise_result=excluded.promise_result, promise_reason=excluded.promise_reason, promise_note=excluded.promise_note,
        q_id=excluded.q_id, q_choice=excluded.q_choice, q_text=excluded.q_text, school_subj=excluded.school_subj, school_theme=excluded.school_theme, school_learned=excluded.school_learned, school_more=excluded.school_more,
        facts_json=excluded.facts_json, updated_at=datetime('now')`)
      .bind(u.id, wk, promise.text, result, reason, cut(p.note, 60), (qChoice || qText) ? q.id : '', qChoice, qText, subj, subj ? cut(sc.theme, 30) : '', cut(sc.learned, 80), cut(sc.more, 60), JSON.stringify(facts).slice(0, 1500)).run()
    return c.json({ ok: true, weekKey: wk })
  })

  // 児童：前の自分とくらべる 用（自分の分だけ・16週）
  app.get('/api/student/week-ref2/history', async (c: any) => {
    const u = c.get('user')
    if (!u) return c.json({ ok: false, error: 'unauthorized' }, 401)
    if (u.role !== 'student') return c.json({ ok: false, error: 'forbidden' }, 403)
    const asked = String(c.req.query('userId') || c.req.query('studentId') || '')
    if (asked && asked !== String(u.id)) return c.json({ ok: false, error: 'forbidden' }, 403)
    const from = wr2IsoKey(new Date(Date.now() + 9 * 3600000 - 16 * 7 * DAY))
    let items: any[] = []
    try {
      const r = await c.env.DB.prepare('SELECT * FROM week_ref2 WHERE user_id=? AND week_key >= ? ORDER BY week_key DESC LIMIT 16').bind(u.id, from).all()
      items = (((r && r.results) || []) as any[]).map(rowView)
    } catch (_e) {}
    return c.json({ ok: true, items })
  })

  // 先生：1人ぶん（カルテ・個人分析で見る）。担任は自分のクラスの子だけ。
  app.get('/api/teacher/week-ref2', async (c: any) => {
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return c.json({ ok: false, error: 'forbidden' }, 403)
    const sid = String(c.req.query('studentId') || '')
    const own = u.role === 'admin'
      ? await c.env.DB.prepare('SELECT 1 AS x FROM class_members WHERE user_id=? LIMIT 1').bind(sid).first()
      : await c.env.DB.prepare('SELECT 1 AS x FROM class_members cm JOIN classes cl ON cl.id=cm.class_id AND cl.teacher_id=? WHERE cm.user_id=? LIMIT 1').bind(u.id, sid).first()
    if (!own) return c.json({ ok: false, error: 'student_not_found' }, 404)
    const n = Math.max(1, Math.min(8, Number(c.req.query('weeks')) || 4))
    let items: any[] = []
    try {
      const r = await c.env.DB.prepare('SELECT * FROM week_ref2 WHERE user_id=? ORDER BY week_key DESC LIMIT ?').bind(sid, n).all()
      items = (((r && r.results) || []) as any[]).map(rowView)
    } catch (_e) {}
    return c.json({ ok: true, items })
  })
}
