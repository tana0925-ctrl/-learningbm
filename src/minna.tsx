// ==================== 📋 振り返り一覧（先生）＋ 📖 みんなのふりかえり（子ども） MINNA_FURI_V1 ====================
//
// 先生:
//   ・📋振り返り一覧 … ロイロノートの提出箱のように、その日／その週の振り返りをクラス全員ぶんタイルで出す。
//     読むのは「その日／その週」の分だけ（class_members → (user_id, day_key|week_key) の索引。全件スキャンしない）。
//     返却は既存の API（/api/teacher/homework/:id/return・/api/teacher/reflection-comments）をそのまま使う。新しい付与経路は作らない。
//   ・みんなのふりかえり … 子どもが「のせてもいいよ」とした振り返りのうち、AI が選んだ掲載候補（⭐ 最大 MINNA_PICK_MAX 件／1回）を
//     先生が直して「採用」する。直した文面は minna_posts に別に保存し、元の振り返りは書きかえない。
//   ・採用された子には MINNA_ADOPT_COINS コイン（1つの振り返りにつき1回）。minna_rewards に素の INSERT が通ったときだけ足す。
//     予約→付与→失敗したら解放。coins と _minnaCoinsApplied を同じだけ動かす（PUT /api/student/progress の補填と矛盾しない）。
//     採用を取り消しても回収しない。もう一度採用しても台帳の主キーで二重にならない。
// 子ども:
//   ・同意（名前なし／名前あり／とりけし）。「のせないで」の選択肢は置かない（選ばなければのせない）。
//   ・同じクラスの子だけが読める。名前ありは名前だけ、名前なしは名前を出さない。順位・点数・いいねは出さない。
//   ・同意できるのは「いまの日／いまの週」の振り返りだけ（過去の振り返りは同意が無いので対象外）。とりけしはいつでも。
//
// ⚠️ テーブルは migrations/0045_minna_furi.sql だけで作る。ここでは DDL を一切実行しない（2026-09-03 の障害）。
// ⚠️ WHERE の列に関数をかけない（索引が死ぬ）。

export const MINNA_ADOPT_COINS = 300   // 採用されたときのコイン（ここだけ変えれば変わる）
export const MINNA_PICK_MAX = 5        // AI の掲載候補：1回（1日分／1週分）あたりの上限
const MINNA_BODY_MAX = 600

function jerr(c: any, status: number, message: string) { return c.json({ ok: false, error: message }, status) }
function isDay(s: any) { return /^\d{4}-\d{2}-\d{2}$/.test(String(s || '')) }
function isWeek(s: any) { return /^\d{4}-W\d{2}$/.test(String(s || '')) }
function cut(x: any, n: number) { return String(x == null ? '' : x).slice(0, n) }

export function minnaIsoWeek(d: Date): string {
  const t = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()))
  t.setUTCDate(t.getUTCDate() + 4 - (t.getUTCDay() || 7))
  const ys = new Date(Date.UTC(t.getUTCFullYear(), 0, 1))
  const wn = Math.ceil((((t.getTime() - ys.getTime()) / 86400000) + 1) / 7)
  return `${t.getUTCFullYear()}-W${String(wn).padStart(2, '0')}`
}
function ymd(d: Date) { return d.toISOString().slice(0, 10) }
function weekMonday(wk: string): Date | null {
  const m = String(wk).match(/^(\d{4})-W(\d{2})$/)
  if (!m) return null
  const j4 = new Date(Date.UTC(Number(m[1]), 0, 4))
  const dw = j4.getUTCDay() || 7
  return new Date(j4.getTime() + ((1 - dw) + (Number(m[2]) - 1) * 7) * 86400000)
}
// 子どもの画面と同じ数え方（日本時間・朝8:30前は前の日）と、カレンダーどおりの日。どちらも「いま」として認める。
export function minnaAllowedRefs(kind: string, nowMs?: number): string[] {
  const n = typeof nowMs === 'number' ? nowMs : Date.now()
  const a = new Date(n + 9 * 3600000 - 8.5 * 3600000)
  const b = new Date(n + 9 * 3600000)
  const xs = kind === 'week' ? [minnaIsoWeek(a), minnaIsoWeek(b)] : [ymd(a), ymd(b)]
  return xs[0] === xs[1] ? [xs[0]] : xs
}
function weekFri(plansJson: any): string {
  try {
    const o = JSON.parse(String(plansJson || '{}'))
    let v: any = o && o.fri
    if (v === undefined) { const ks = Object.keys(o || {}).filter((k) => k !== '_modified'); v = ks[4] ? o[ks[4]] : '' }
    return (v && typeof v === 'object') ? String(v.reflection || '') : ''
  } catch (_e) { return '' }
}
function newId() {
  const a = new Uint8Array(6)
  crypto.getRandomValues(a)
  let s = ''
  for (let i = 0; i < a.length; i++) s += 'abcdefghjkmnpqrstuvwxyz23456789'[a[i] % 31]
  return 'mf' + s
}

async function ownsClass(c: any, u: any, classId: string) {
  if (!classId) return null
  return u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first()
}
function teacherOf(c: any) {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return null
  return u
}
async function studentClass(c: any, userId: string): Promise<string> {
  const r: any = await c.env.DB.prepare('SELECT class_id FROM class_members WHERE user_id=? LIMIT 1').bind(userId).first()
  return r ? String(r.class_id || '') : ''
}

// 1つの振り返りにつき1回だけのコイン。予約→付与→失敗したら解放（WEEKREF_V1 の weekRefGrant と同じ作法）
export async function minnaGrant(env: any, userId: string, kind: string, refKey: string) {
  const out: any = { rewardedNow: false, coins: null, applied: null }
  let reserved = false
  try {
    await env.DB.prepare("INSERT INTO minna_rewards (user_id, kind, ref_key, coins, created_at) VALUES (?, ?, ?, ?, datetime('now'))").bind(userId, kind, refKey, MINNA_ADOPT_COINS).run()
    reserved = true
  } catch (_e) { reserved = false }
  if (!reserved) return out
  try {
    const r: any = await env.DB.prepare("UPDATE progress SET state_json = json_set(json_set(state_json, '$.coins', COALESCE(CAST(json_extract(state_json, '$.coins') AS INTEGER), 0) + ?), '$._minnaCoinsApplied', COALESCE(CAST(json_extract(state_json, '$._minnaCoinsApplied') AS INTEGER), 0) + ?), updated_at = datetime('now') WHERE user_id = ? AND json_valid(state_json)")
      .bind(MINNA_ADOPT_COINS, MINNA_ADOPT_COINS, userId).run()
    if (r && r.meta && Number(r.meta.changes) === 1) {
      out.rewardedNow = true
      const s2: any = await env.DB.prepare("SELECT CAST(json_extract(state_json, '$.coins') AS INTEGER) AS coins, CAST(json_extract(state_json, '$._minnaCoinsApplied') AS INTEGER) AS applied FROM progress WHERE user_id=?").bind(userId).first()
      if (s2) { out.coins = Number(s2.coins); out.applied = Number(s2.applied) }
    }
  } catch (e) { console.error('MINNA_FURI_V1 grant error', e) }
  if (!out.rewardedNow) {
    try { await env.DB.prepare('DELETE FROM minna_rewards WHERE user_id=? AND kind=? AND ref_key=?').bind(userId, kind, refKey).run() } catch (_e) {}
  }
  return out
}

// 振り返りがもう出してあるか（同意は「出した振り返り」にだけ付ける）
async function reflectionExists(c: any, userId: string, kind: string, ref: string) {
  if (kind === 'day') {
    const r = await c.env.DB.prepare('SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1').bind(userId, ref).first()
    return !!r
  }
  const s: any = await c.env.DB.prepare('SELECT free_text, good_point, improve_point FROM structured_reflections WHERE user_id=? AND week_key=? LIMIT 1').bind(userId, ref).first()
  if (s && String(s.free_text || '') + String(s.good_point || '') + String(s.improve_point || '')) return true
  const p: any = await c.env.DB.prepare('SELECT plans_json FROM student_weekly_plans WHERE user_id=? AND week_key=? LIMIT 1').bind(userId, ref).first()
  return !!(p && weekFri(p.plans_json).trim())
}

// 名前（ほかの子の名前）を「〇〇」にする。AI に渡す前と、AI候補の材料で使う。
function maskNames(text: string, names: string[]) {
  let t = String(text || '')
  for (const n of names) {
    const s = String(n || '').trim()
    if (s.length >= 2 && t.indexOf(s) >= 0) t = t.split(s).join('〇〇')
  }
  return t
}

export function registerMinna(app: any) {

  // ───────── 先生：📋振り返り一覧（その日／その週のぶんだけ） ─────────
  app.get('/api/teacher/teibako', async (c: any) => {
    const u = teacherOf(c)
    if (!u) return jerr(c, 403, 'forbidden')
    const classId = String(c.req.query('classId') || '')
    const cls: any = await ownsClass(c, u, classId)
    if (!cls) return jerr(c, 404, 'class_not_found')
    const mode = c.req.query('mode') === 'week' ? 'week' : 'day'
    const ref = String(c.req.query(mode === 'week' ? 'week' : 'date') || '')
    if (mode === 'day' ? !isDay(ref) : !isWeek(ref)) return jerr(c, 400, 'bad_ref')
    const DB = c.env.DB
    const rosterR: any = await DB.prepare('SELECT u.id AS id, u.name AS name, u.login_id AS loginId, u.roster_no AS rosterNo FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id = ?').bind(classId).all()
    const roster = ((rosterR && rosterR.results) || []) as any[]
    const items: Record<string, any> = {}
    const slot = (uid: string) => (items[uid] = items[uid] || { userId: uid })

    if (mode === 'day') {
      const r: any = await DB.prepare(`SELECT hs.id AS id, hs.user_id AS uid, hs.submitted_at AS submittedAt, hs.todo AS todo, hs.why AS why, hs.aim AS aim,
          hs.minutes AS minutes, hs.end_weather AS endWeather, hs.weather_reason AS weatherReason, hs.next_improve AS nextImprove,
          hs.rest_day AS restDay, hs.teacher_comment AS teacherComment, hs.returned_at AS returnedAt, hs.has_physical AS hasPhysical,
          hs.weekly_reflection AS weeklyReflection, hs.parent_comment AS parentComment, hs.work_photo_analysis AS photoAnalysis
        FROM class_members cm JOIN homework_submissions hs ON hs.user_id = cm.user_id AND hs.day_key = ? WHERE cm.class_id = ?`).bind(ref, classId).all()
      for (const row of (((r && r.results) || []) as any[])) {
        const s = slot(String(row.uid))
        Object.assign(s, {
          id: String(row.id), submittedAt: Number(row.submittedAt) || 0, todo: cut(row.todo, 500), why: cut(row.why, 500), aim: cut(row.aim, 500),
          minutes: Number(row.minutes) || 0, endWeather: cut(row.endWeather, 10), weatherReason: cut(row.weatherReason, 500), nextImprove: cut(row.nextImprove, 500),
          restDay: !!row.restDay, teacherComment: cut(row.teacherComment, 500), returnedAt: Number(row.returnedAt) || 0, hasPhysical: !!row.hasPhysical,
          weeklyReflection: cut(row.weeklyReflection, 1000), parentComment: cut(row.parentComment, 500), photoAnalysis: cut(row.photoAnalysis, 500), photoCount: 0,
        })
      }
      try {
        const p: any = await DB.prepare('SELECT p.user_id AS uid, COUNT(*) AS n FROM class_members cm JOIN homework_photos2 p ON p.user_id = cm.user_id AND p.day_key = ? WHERE cm.class_id = ? GROUP BY p.user_id').bind(ref, classId).all()
        for (const row of (((p && p.results) || []) as any[])) if (items[row.uid]) items[row.uid].photoCount = Number(row.n) || 0
      } catch (_e) {}
      try {
        const p0: any = await DB.prepare('SELECT p.user_id AS uid FROM class_members cm JOIN homework_photos p ON p.user_id = cm.user_id AND p.day_key = ? WHERE cm.class_id = ?').bind(ref, classId).all()
        for (const row of (((p0 && p0.results) || []) as any[])) if (items[row.uid] && !items[row.uid].photoCount) items[row.uid].photoCount = 1
      } catch (_e) {}
      try {   // 今日のひと往復の下書き（公開前。子どもには見えない）
        const d: any = await DB.prepare("SELECT id, target_id AS tid, ref_key AS rk, body FROM ai_review_drafts WHERE class_id = ? AND status = 'draft' AND kind = 'DAILY' AND teacher_id = ? LIMIT 400").bind(classId, u.id).all()
        const byHw: Record<string, any> = {}
        for (const row of (((d && d.results) || []) as any[])) byHw[String(row.rk)] = row
        for (const k of Object.keys(items)) { const x = items[k]; const dr = x.id && byHw[x.id]; if (dr) x.draft = { id: String(dr.id), body: cut(dr.body, 2000) } }
      } catch (_e) {}
    } else {
      const mon = weekMonday(ref) as Date
      const from = ymd(mon), to = ymd(new Date(mon.getTime() + 6 * 86400000))
      try {
        const r: any = await DB.prepare('SELECT swp.id AS id, swp.user_id AS uid, swp.plans_json AS pj, swp.updated_at AS ua, swp.reflection_comment AS rc, swp.reflection_returned_at AS ra FROM class_members cm JOIN student_weekly_plans swp ON swp.user_id = cm.user_id AND swp.week_key = ? WHERE cm.class_id = ?').bind(ref, classId).all()
        for (const row of (((r && r.results) || []) as any[])) {
          const s = slot(String(row.uid))
          s.planId = row.id; s.planReflection = cut(weekFri(row.pj), 800); s.teacherComment = cut(row.rc, 1000); s.returnedAt = Number(row.ra) || 0
          if (s.planReflection.trim()) s.submittedAt = Math.max(Number(s.submittedAt) || 0, Number(row.ua) || 0)
        }
      } catch (e) { console.error('MINNA teibako plans', e) }
      try {
        const r: any = await DB.prepare('SELECT sr.user_id AS uid, sr.concentration AS cc, sr.good_point AS gp, sr.improve_point AS ip, sr.next_action AS na, sr.free_text AS ft, sr.created_at AS ca FROM class_members cm JOIN structured_reflections sr ON sr.user_id = cm.user_id AND sr.week_key = ? WHERE cm.class_id = ?').bind(ref, classId).all()
        for (const row of (((r && r.results) || []) as any[])) {
          const s = slot(String(row.uid))
          Object.assign(s, { freeText: cut(row.ft, 800), goodPoint: cut(row.gp, 300), improvePoint: cut(row.ip, 300), nextAction: cut(row.na, 60), concentration: Number(row.cc) || 0 })
          s.submittedAt = Math.max(Number(s.submittedAt) || 0, Number(row.ca) || 0)
        }
      } catch (e) { console.error('MINNA teibako sr', e) }
      try {
        const r: any = await DB.prepare("SELECT hs.user_id AS uid, hs.day_key AS dk, hs.weekly_reflection AS wr FROM class_members cm JOIN homework_submissions hs ON hs.user_id = cm.user_id AND hs.day_key >= ? AND hs.day_key <= ? WHERE cm.class_id = ? AND hs.weekly_reflection <> ''").bind(from, to, classId).all()
        for (const row of (((r && r.results) || []) as any[])) {
          const s = slot(String(row.uid))
          if (s.star && String(s.star.dayKey) > String(row.dk)) continue
          s.star = { dayKey: String(row.dk), text: cut(row.wr, 800) }
        }
      } catch (_e) {}
      try {
        const r: any = await DB.prepare('SELECT nt.user_id AS uid, nt.unit_name AS nm, nt.text AS tx FROM class_members cm JOIN week_next_try nt ON nt.user_id = cm.user_id AND nt.week_key = ? WHERE cm.class_id = ?').bind(ref, classId).all()
        for (const row of (((r && r.results) || []) as any[])) { if (row.nm || row.tx) slot(String(row.uid)).nextTry = { unitName: cut(row.nm, 40), text: cut(row.tx, 60) } }
      } catch (_e) {}
      try {   // KANTAN_REF_V1 かんたんふりかえりの ◎○△（本人の見立て）
        const r: any = await DB.prepare('SELECT t.user_id AS uid, t.self_mark AS sm FROM class_members cm JOIN week_ref_taps t ON t.user_id = cm.user_id AND t.week_key = ? WHERE cm.class_id = ?').bind(ref, classId).all()
        const JA: any = { good: '◎よくできた', ok: '○まあまあ', more: '△もう少し' }
        for (const row of (((r && r.results) || []) as any[])) { if (JA[row.sm]) slot(String(row.uid)).kantan = JA[row.sm] }
      } catch (_e) {}
      try {
        const d: any = await DB.prepare("SELECT id, target_id AS tid, ref_key AS rk, body FROM ai_review_drafts WHERE class_id = ? AND status = 'draft' AND kind = 'REFLECT' AND teacher_id = ? LIMIT 400").bind(classId, u.id).all()
        for (const row of (((d && d.results) || []) as any[])) {
          if (!row.tid || (row.rk && String(row.rk) !== ref)) continue
          const s = items[String(row.tid)]
          if (s) s.draft = { id: String(row.id), body: cut(row.body, 2000) }
        }
      } catch (_e) {}
      // KANTAN_REF_V1 の保存形式（よかったこと欄の「◎ よくできた ／ なんで：…」）からも ◎○△ を読む
      for (const k of Object.keys(items)) {
        const s0 = items[k]
        if (s0.kantan) continue
        const m = String(s0.goodPoint || '').match(/^[\s　]*([◎○△])[\s　]*(よくできた|まあまあ|もう少し)?/)
        if (m) s0.kantan = m[1] + (m[2] || ({ '◎': 'よくできた', '○': 'まあまあ', '△': 'もう少し' } as any)[m[1]])
      }
      // 中身の無い週（計画だけの行など）は「未提出」あつかい
      for (const k of Object.keys(items)) {
        const s = items[k]
        s.submitted = !!(String(s.planReflection || '').trim() || String(s.freeText || '').trim() || String(s.goodPoint || '').trim() || String(s.improvePoint || '').trim())
      }
    }

    // みんなのふりかえり：同意・AI候補・採用
    try {
      const r: any = await DB.prepare("SELECT id, user_id AS uid, mode FROM minna_consents WHERE class_id = ? AND kind = ? AND ref_key = ?").bind(classId, mode, ref).all()
      const byId: Record<string, any> = {}
      for (const row of (((r && r.results) || []) as any[])) {
        if (!row.mode) continue
        const s = items[String(row.uid)]; if (!s) continue
        s.consent = { id: String(row.id), mode: String(row.mode) }
        byId[String(row.id)] = s
      }
      const p: any = await DB.prepare('SELECT consent_id AS cid, reason FROM minna_picks WHERE class_id = ? AND kind = ? AND ref_key = ?').bind(classId, mode, ref).all()
      for (const row of (((p && p.results) || []) as any[])) { const s = byId[String(row.cid)]; if (s) s.pick = { reason: cut(row.reason, 300) } }
      const q: any = await DB.prepare("SELECT consent_id AS cid, body, status FROM minna_posts WHERE class_id = ? AND status IN ('on','off') AND ref_key = ? AND kind = ?").bind(classId, ref, mode).all()
      for (const row of (((q && q.results) || []) as any[])) { const s = byId[String(row.cid)]; if (s) s.post = { body: cut(row.body, MINNA_BODY_MAX), on: row.status === 'on' } }
    } catch (e) { console.error('MINNA teibako consents', e) }

    return c.json({ ok: true, class: { id: cls.id, name: cls.name }, mode, ref, roster, items: Object.keys(items).map((k) => items[k]), pickMax: MINNA_PICK_MAX, adoptCoins: MINNA_ADOPT_COINS })
  })

  // 先生：開いたときの「前回のふりかえり」（1人・1件だけ）
  app.get('/api/teacher/teibako/prev', async (c: any) => {
    const u = teacherOf(c)
    if (!u) return jerr(c, 403, 'forbidden')
    const classId = String(c.req.query('classId') || '')
    const userId = String(c.req.query('userId') || '')
    if (!(await ownsClass(c, u, classId))) return jerr(c, 404, 'class_not_found')
    const mem = await c.env.DB.prepare('SELECT 1 AS x FROM class_members WHERE class_id=? AND user_id=? LIMIT 1').bind(classId, userId).first()
    if (!mem) return jerr(c, 404, 'not_found')
    const mode = c.req.query('mode') === 'week' ? 'week' : 'day'
    const ref = String(c.req.query('ref') || '')
    if (mode === 'day') {
      if (!isDay(ref)) return jerr(c, 400, 'bad_ref')
      const r: any = await c.env.DB.prepare('SELECT day_key AS dayKey, submitted_at AS submittedAt, end_weather AS endWeather, weather_reason AS weatherReason, next_improve AS nextImprove, todo, minutes FROM homework_submissions WHERE user_id=? AND day_key < ? ORDER BY day_key DESC LIMIT 1').bind(userId, ref).first()
      return c.json({ ok: true, prev: r || null })
    }
    if (!isWeek(ref)) return jerr(c, 400, 'bad_ref')
    const s: any = await c.env.DB.prepare('SELECT week_key AS weekKey, free_text AS freeText, good_point AS goodPoint, improve_point AS improvePoint, next_action AS nextAction, created_at AS createdAt FROM structured_reflections WHERE user_id=? AND week_key < ? ORDER BY week_key DESC LIMIT 1').bind(userId, ref).first()
    let planReflection = ''
    if (s) {
      try { const p: any = await c.env.DB.prepare('SELECT plans_json FROM student_weekly_plans WHERE user_id=? AND week_key=? LIMIT 1').bind(userId, s.weekKey).first(); planReflection = cut(weekFri(p && p.plans_json), 800) } catch (_e) {}
    }
    return c.json({ ok: true, prev: s ? Object.assign({}, s, { planReflection }) : null })
  })

  // 先生：採用（直した文面を別に保存）＋ コイン（1つの振り返りにつき1回）＋ お知らせ
  app.post('/api/teacher/minna/adopt', async (c: any) => {
    const u = teacherOf(c)
    if (!u) return jerr(c, 403, 'forbidden')
    const body = await c.req.json().catch(() => null)
    const cid = String((body && body.consentId) || '')
    const text = String((body && body.body) || '').replace(/\r/g, '').trim().slice(0, MINNA_BODY_MAX)
    if (!cid || !text) return jerr(c, 400, 'invalid')
    const cs: any = await c.env.DB.prepare('SELECT id, user_id, class_id, kind, ref_key, mode FROM minna_consents WHERE id=? LIMIT 1').bind(cid).first()
    if (!cs) return jerr(c, 404, 'not_found')
    if (!(await ownsClass(c, u, String(cs.class_id)))) return jerr(c, 404, 'not_found')
    const mem = await c.env.DB.prepare('SELECT 1 AS x FROM class_members WHERE class_id=? AND user_id=? LIMIT 1').bind(cs.class_id, cs.user_id).first()
    if (!mem) return jerr(c, 404, 'not_found')
    if (!cs.mode) return jerr(c, 400, 'no_consent')   // 同意していない（とりけした）振り返りは載せられない
    await c.env.DB.prepare("INSERT INTO minna_posts (consent_id, class_id, user_id, kind, ref_key, body, status, teacher_id, created_at, updated_at) VALUES (?,?,?,?,?,?,'on',?,datetime('now'),datetime('now')) ON CONFLICT(consent_id) DO UPDATE SET body=excluded.body, status='on', teacher_id=excluded.teacher_id, updated_at=datetime('now')")
      .bind(cs.id, cs.class_id, cs.user_id, cs.kind, cs.ref_key, text, u.id).run()
    const g = await minnaGrant(c.env, String(cs.user_id), String(cs.kind), String(cs.ref_key))
    if (g.rewardedNow) {
      try {
        await c.env.DB.prepare('INSERT INTO messages (id, class_id, sender_id, sender_role, recipient_id, body) VALUES (?,?,?,?,?,?)')
          .bind(crypto.randomUUID(), cs.class_id, u.id, 'teacher', cs.user_id, 'あなたのふりかえりが『みんなのふりかえり』にのったよ！＋' + MINNA_ADOPT_COINS + 'コイン').run()
      } catch (e) { console.error('MINNA notify failed', e) }
    }
    return c.json({ ok: true, rewardedNow: !!g.rewardedNow, coins: MINNA_ADOPT_COINS })
  })

  // 先生：採用の取り消し（コインは回収しない）
  app.post('/api/teacher/minna/unadopt', async (c: any) => {
    const u = teacherOf(c)
    if (!u) return jerr(c, 403, 'forbidden')
    const body = await c.req.json().catch(() => null)
    const cid = String((body && body.consentId) || '')
    const p: any = await c.env.DB.prepare('SELECT class_id FROM minna_posts WHERE consent_id=? LIMIT 1').bind(cid).first()
    if (!p || !(await ownsClass(c, u, String(p.class_id)))) return jerr(c, 404, 'not_found')
    await c.env.DB.prepare("UPDATE minna_posts SET status='off', updated_at=datetime('now') WHERE consent_id=?").bind(cid).run()
    return c.json({ ok: true })
  })

  // 先生：今日のひと往復に渡す「みんなのふりかえり候補」の材料（同意した振り返りだけ・名前はふせて振り返りIDだけ）
  //   最近7日（毎日）と今週・先週（週）。採用ずみは「もう載せた」として渡す。
  app.get('/api/teacher/minna/pick-source', async (c: any) => {
    const u = teacherOf(c)
    if (!u) return jerr(c, 403, 'forbidden')
    const classId = String(c.req.query('classId') || '')
    if (!(await ownsClass(c, u, classId))) return jerr(c, 404, 'class_not_found')
    const now = Date.now() + 9 * 3600000
    const days: string[] = []
    for (let i = 0; i < 7; i++) days.push(ymd(new Date(now - i * 86400000)))
    const w0 = minnaIsoWeek(new Date(now))
    const w1 = minnaIsoWeek(new Date(now - 7 * 86400000))
    const DB = c.env.DB
    const rosterR: any = await DB.prepare('SELECT u.name AS name FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id = ?').bind(classId).all()
    const names = (((rosterR && rosterR.results) || []) as any[]).map((r) => String(r.name || '')).filter((s) => s.length >= 2).sort((a, b) => b.length - a.length)
    const periods: Record<string, any> = {}
    const put = (kind: string, ref: string, it: any) => { const k = kind + '|' + ref; (periods[k] = periods[k] || { kind, ref, items: [] }).items.push(it) }
    const ph = days.map(() => '?').join(',')
    try {
      const r: any = await DB.prepare(`SELECT mc.id AS id, mc.user_id AS uid, mc.ref_key AS ref, hs.end_weather AS ew, hs.weather_reason AS wr, hs.next_improve AS ni, hs.todo AS todo, mp.status AS ps
        FROM minna_consents mc JOIN homework_submissions hs ON hs.user_id = mc.user_id AND hs.day_key = mc.ref_key
        LEFT JOIN minna_posts mp ON mp.consent_id = mc.id
        WHERE mc.class_id = ? AND mc.kind = 'day' AND mc.ref_key IN (${ph}) AND mc.mode <> ''`).bind(classId, ...days).all()
      for (const row of (((r && r.results) || []) as any[])) {
        const w = ({ sun: '☀️はれ', cloud: '☁️くもり', rain: '🌧️あめ' } as any)[String(row.ew)] || ''
        const t = [w ? '気分:' + w : '', row.todo ? 'やったこと:' + cut(row.todo, 120) : '', row.wr ? 'ふりかえり:' + cut(row.wr, 300) : '', row.ni ? 'つぎは:' + cut(row.ni, 200) : ''].filter(Boolean).join(' ／ ')
        put('day', String(row.ref), { id: String(row.id), uid: String(row.uid), text: maskNames(t, names), adopted: row.ps === 'on' })
      }
    } catch (e) { console.error('MINNA pick-source day', e) }
    try {
      const r: any = await DB.prepare(`SELECT mc.id AS id, mc.user_id AS uid, mc.ref_key AS ref, sr.free_text AS ft, sr.good_point AS gp, sr.improve_point AS ip, swp.plans_json AS pj, mp.status AS ps
        FROM minna_consents mc LEFT JOIN structured_reflections sr ON sr.user_id = mc.user_id AND sr.week_key = mc.ref_key
        LEFT JOIN student_weekly_plans swp ON swp.user_id = mc.user_id AND swp.week_key = mc.ref_key
        LEFT JOIN minna_posts mp ON mp.consent_id = mc.id
        WHERE mc.class_id = ? AND mc.kind = 'week' AND mc.ref_key IN (?, ?) AND mc.mode <> ''`).bind(classId, w0, w1).all()
      for (const row of (((r && r.results) || []) as any[])) {
        const fri = weekFri(row.pj)
        const main = String(row.ft || '').trim() || fri.trim()
        const t = [main ? cut(main, 500) : '', row.gp ? 'よかったこと:' + cut(row.gp, 200) : '', row.ip ? 'くふうしたいこと:' + cut(row.ip, 200) : ''].filter(Boolean).join(' ／ ')
        if (!t) continue
        put('week', String(row.ref), { id: String(row.id), uid: String(row.uid), text: maskNames(t, names), adopted: row.ps === 'on' })
      }
    } catch (e) { console.error('MINNA pick-source week', e) }
    // 子ども（uid）はAIに渡さない。同じ子ばかりにならないよう「同じ子」の目印だけ符号で付ける（その回かぎり）
    const alias: Record<string, string> = {}
    let n = 0
    const out = Object.keys(periods).sort().reverse().map((k) => {
      const p = periods[k]
      p.items = p.items.map((it: any) => { if (!alias[it.uid]) alias[it.uid] = 'K' + String(++n).padStart(2, '0'); return { id: it.id, who: alias[it.uid], text: it.text, adopted: it.adopted } })
      return p
    })
    return c.json({ ok: true, periods: out, pickMax: MINNA_PICK_MAX })
  })

  // 先生：AIの返事の [PICK:振り返りID] 理由 を取り込む。1回（kind+ref）あたり MINNA_PICK_MAX 件まで。こえた分は無視。
  //   その回の候補は、今回の取り込みで入れかえる（採用ずみの文面には触らない）。
  app.post('/api/teacher/minna/picks', async (c: any) => {
    const u = teacherOf(c)
    if (!u) return jerr(c, 403, 'forbidden')
    const body = await c.req.json().catch(() => null)
    const classId = String((body && body.classId) || '')
    if (!(await ownsClass(c, u, classId))) return jerr(c, 404, 'class_not_found')
    const list = Array.isArray(body && body.picks) ? body.picks.slice(0, 100) : []
    const seen: Record<string, 1> = {}
    const groups: Record<string, any[]> = {}
    const unknown: string[] = [], overLimit: string[] = []
    for (const p of list) {
      const id = String((p && p.id) || '').trim()
      if (!id || seen[id]) continue
      seen[id] = 1
      const cs: any = await c.env.DB.prepare("SELECT id, kind, ref_key FROM minna_consents WHERE id=? AND class_id=? AND mode <> '' LIMIT 1").bind(id, classId).first()
      if (!cs) { unknown.push(id); continue }
      const k = cs.kind + '|' + cs.ref_key
      ;(groups[k] = groups[k] || []).push({ id, kind: cs.kind, ref: cs.ref_key, reason: String((p && p.reason) || '').replace(/[\r\n]+/g, ' ').trim().slice(0, 300) })
    }
    let saved = 0
    for (const k of Object.keys(groups)) {
      const g = groups[k]
      await c.env.DB.prepare('DELETE FROM minna_picks WHERE class_id=? AND kind=? AND ref_key=?').bind(classId, g[0].kind, g[0].ref).run()
      for (let i = 0; i < g.length; i++) {
        if (i >= MINNA_PICK_MAX) { overLimit.push(g[i].id); continue }
        await c.env.DB.prepare("INSERT OR REPLACE INTO minna_picks (consent_id, class_id, kind, ref_key, reason, teacher_id, created_at) VALUES (?,?,?,?,?,?,datetime('now'))").bind(g[i].id, classId, g[i].kind, g[i].ref, g[i].reason, u.id).run()
        saved++
      }
    }
    return c.json({ ok: true, saved, unknown, overLimit, pickMax: MINNA_PICK_MAX })
  })

  // ───────── 子ども ─────────
  // 自分の同意（いまの日／いまの週）
  app.get('/api/student/minna/consent', async (c: any) => {
    const u = c.get('user')
    if (!u || u.role !== 'student') return jerr(c, 403, 'forbidden')
    const kind = c.req.query('kind') === 'week' ? 'week' : 'day'
    const ref = String(c.req.query('ref') || '')
    if (kind === 'day' ? !isDay(ref) : !isWeek(ref)) return jerr(c, 400, 'bad_ref')
    const r: any = await c.env.DB.prepare('SELECT mode FROM minna_consents WHERE user_id=? AND kind=? AND ref_key=? LIMIT 1').bind(u.id, kind, ref).first()
    return c.json({ ok: true, mode: r ? String(r.mode || '') : '' })
  })

  // 同意する／かえる／とりけす。同意できるのは「いま」の振り返りで、もう出してあるものだけ。とりけしはいつでも。
  app.post('/api/student/minna/consent', async (c: any) => {
    const u = c.get('user')
    if (!u || u.role !== 'student') return jerr(c, 403, 'forbidden')
    const body = await c.req.json().catch(() => null)
    const kind = (body && body.kind) === 'week' ? 'week' : 'day'
    const ref = String((body && body.ref) || '')
    const mode = (body && (body.mode === 'anon' || body.mode === 'named')) ? body.mode : ''
    if (kind === 'day' ? !isDay(ref) : !isWeek(ref)) return jerr(c, 400, 'bad_ref')
    const cur: any = await c.env.DB.prepare('SELECT id FROM minna_consents WHERE user_id=? AND kind=? AND ref_key=? LIMIT 1').bind(u.id, kind, ref).first()
    if (!mode) {
      if (cur) await c.env.DB.prepare("UPDATE minna_consents SET mode='', updated_at=datetime('now') WHERE id=?").bind(cur.id).run()
      return c.json({ ok: true, saved: true, mode: '' })
    }
    if (minnaAllowedRefs(kind).indexOf(ref) < 0) return c.json({ ok: true, saved: false, reason: 'not_now' })
    const classId = await studentClass(c, u.id)
    if (!classId) return c.json({ ok: true, saved: false, reason: 'no_class' })
    if (!(await reflectionExists(c, u.id, kind, ref))) return c.json({ ok: true, saved: false, reason: 'not_submitted' })
    if (cur) {
      await c.env.DB.prepare("UPDATE minna_consents SET mode=?, class_id=?, updated_at=datetime('now') WHERE id=?").bind(mode, classId, cur.id).run()
    } else {
      await c.env.DB.prepare("INSERT INTO minna_consents (id, user_id, class_id, kind, ref_key, mode, created_at, updated_at) VALUES (?,?,?,?,?,?,datetime('now'),datetime('now')) ON CONFLICT(user_id, kind, ref_key) DO UPDATE SET mode=excluded.mode, class_id=excluded.class_id, updated_at=datetime('now')")
        .bind(newId(), u.id, classId, kind, ref, mode).run()
    }
    return c.json({ ok: true, saved: true, mode })
  })

  // 自分の「のせてもいいよ」一覧（とりけし用）
  app.get('/api/student/minna/mine', async (c: any) => {
    const u = c.get('user')
    if (!u || u.role !== 'student') return jerr(c, 403, 'forbidden')
    const r: any = await c.env.DB.prepare("SELECT mc.kind AS kind, mc.ref_key AS ref, mc.mode AS mode, mp.status AS ps FROM minna_consents mc LEFT JOIN minna_posts mp ON mp.consent_id = mc.id WHERE mc.user_id = ? AND mc.mode <> '' ORDER BY mc.updated_at DESC LIMIT 30").bind(u.id).all()
    const items = (((r && r.results) || []) as any[]).map((x) => ({ kind: x.kind, ref: x.ref, mode: x.mode, posted: x.ps === 'on' }))
    return c.json({ ok: true, items })
  })

  // みんなのふりかえり（同じクラスの子だけ）。名前ありは名前だけ、名前なしは名前を出さない。だれの分かは返さない（自分の分だけ mine）。
  app.get('/api/student/minna/posts', async (c: any) => {
    const u = c.get('user')
    if (!u || u.role !== 'student') return jerr(c, 403, 'forbidden')
    const classId = await studentClass(c, u.id)
    if (!classId) return c.json({ ok: true, posts: [] })
    const r: any = await c.env.DB.prepare(`SELECT mp.kind AS kind, mp.ref_key AS ref, mp.body AS body, mp.user_id AS uid, mc.mode AS mode, us.name AS name, mp.updated_at AS at
      FROM minna_posts mp JOIN minna_consents mc ON mc.id = mp.consent_id AND mc.mode <> ''
      JOIN class_members cm ON cm.class_id = mp.class_id AND cm.user_id = mp.user_id
      LEFT JOIN users us ON us.id = mp.user_id
      WHERE mp.class_id = ? AND mp.status = 'on' ORDER BY mp.updated_at DESC LIMIT 200`).bind(classId).all()
    const posts = (((r && r.results) || []) as any[]).map((x) => {
      const wk = x.kind === 'week' ? String(x.ref) : minnaIsoWeek(new Date(String(x.ref) + 'T00:00:00Z'))
      return { kind: x.kind, ref: String(x.ref), weekKey: wk, body: cut(x.body, MINNA_BODY_MAX), name: x.mode === 'named' ? cut(x.name, 30) : '', mine: String(x.uid) === String(u.id) }
    })
    return c.json({ ok: true, posts })
  })
}
