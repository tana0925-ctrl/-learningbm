// ==================== 📸 PORTFOLIO_V1 成果物ポートフォリオ（先生だけ） ====================
//
// 先生のことば：「家庭学習の写真や、学校で撮ったノート・作品の写真を、子どもごとに1年ぶんためて見くらべたい。
//               子どもの画面には写真を一切出さない」
//
// しくみ:
//   ・目録（どの子・いつ・教科・メモ）は本体の D1（portfolio_items）。写真そのものは置き場（R2 か 写真専用 D1）。
//       置き場のえらび方：R2（env.PF）があれば R2 → なければ写真専用の D1（env.PFDB）→ どちらも無ければ保存しない。
//       ※ 本体の D1 には写真を入れない（容量を食わないため）。
//   ・家庭学習で子どもが付けた写真は、提出のときに自動で入る（クラスの設定で止められる）。
//       前からある家庭学習の写真は「とりこむ」ボタンで先生の端末が縮めてから入れる（もとの写真は消さない）。
//   ・写真を返す道は /api/teacher/portfolio/img/:id だけ。先生（担任は自分のクラスの子だけ）と管理者だけ。
//       写真のIDはランダム。URL が知られても、先生のログインが無ければ 403。
//       見るだけモード（viewas Cookie がある間）は先生でも写真を返さない（子どもの画面に出る事故を防ぐ）。
//   ・保存期間：はじめは「年度末まで」。年度末（3月〜）になったら先生に確認を出す。自動では消さない。
//
// ⚠️ ここでは DDL を一切実行しない（migrations/0050_portfolio.sql・migrations_pf/0001_pf_blobs.sql）。

export const PORTFOLIO_MARK = 'PORTFOLIO_V1'

const MAX_BYTES = 1_900_000      // D1 の1行の上限（2MB）より小さく
const MAX_THUMB = 200_000
const OK_MIME = /^image\/(jpeg|png|webp)$/

type Deps = {
  getCookie: (c: any, name: string) => string | undefined
}

function jerr(c: any, status: number, error: string) { return c.json({ ok: false, error }, status) }
function clean(s: any, n: number): string {
  const a = Array.from(String(s == null ? '' : s).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '').replace(/\r\n?/g, '\n').trim())
  return a.length > n ? a.slice(0, n).join('') : a.join('')
}
export function jstToday(atMs?: number): string {
  return new Date((atMs == null ? Date.now() : atMs) + 9 * 3600_000).toISOString().slice(0, 10)
}
export function fyOf(ymd: string): number {
  const y = Number(String(ymd).slice(0, 4)), m = Number(String(ymd).slice(5, 7))
  return m >= 4 ? y : y - 1
}
function isYmd(s: string) { return /^\d{4}-\d{2}-\d{2}$/.test(s) }
function newId() {
  try { return 'pf_' + (crypto as any).randomUUID().replace(/-/g, '') } catch (_e) {}
  const a = new Uint8Array(16); crypto.getRandomValues(a)
  return 'pf_' + Array.from(a).map((x) => x.toString(16).padStart(2, '0')).join('')
}

// ── 置き場 ─────────────────────────────────────────────
export function pfStoreKind(env: any): 'r2' | 'd1' | null {
  if (env && env.PF && typeof env.PF.put === 'function' && typeof env.PF.get === 'function') return 'r2'
  if (env && env.PFDB && typeof env.PFDB.prepare === 'function') return 'd1'
  return null
}
async function putObj(env: any, kind: string, key: string, bytes: Uint8Array, mime: string) {
  if (kind === 'r2') { await env.PF.put(key, bytes, { httpMetadata: { contentType: mime } }); return }
  await env.PFDB.prepare(
    `INSERT INTO pf_blobs (k, mime, bytes, byte_size) VALUES (?,?,?,?)
     ON CONFLICT(k) DO UPDATE SET mime=excluded.mime, bytes=excluded.bytes, byte_size=excluded.byte_size, created_at=datetime('now')`
  ).bind(key, mime, bytes, bytes.length).run()
}
async function getObj(env: any, kind: string, key: string): Promise<{ body: any, mime: string } | null> {
  if (kind === 'r2') {
    if (!env.PF) return null
    const o = await env.PF.get(key)
    if (!o) return null
    return { body: o.body, mime: (o.httpMetadata && o.httpMetadata.contentType) || 'image/jpeg' }
  }
  if (!env.PFDB) return null
  const r = await env.PFDB.prepare('SELECT mime, bytes FROM pf_blobs WHERE k=? LIMIT 1').bind(key).first()
  if (!r || !r.bytes) return null
  const raw: any = r.bytes
  return { body: (raw instanceof ArrayBuffer) ? raw : new Uint8Array(raw), mime: String(r.mime || 'image/jpeg') }
}
// 消せたら true（置き場が無い・失敗したら false。false のときは目録に「消した」を付けない）
async function delObj(env: any, kind: string, key: string): Promise<boolean> {
  if (!key) return true
  try {
    if (kind === 'r2') { if (!env.PF) return false; await env.PF.delete(key); return true }
    if (!env.PFDB) return false
    await env.PFDB.prepare('DELETE FROM pf_blobs WHERE k=?').bind(key).run()
    return true
  } catch (_e) { return false }
}
async function delItemObjs(env: any, it: any): Promise<boolean> {
  const a = await delObj(env, String(it.store), String(it.obj_key))
  const b = it.thumb_key ? await delObj(env, String(it.store), String(it.thumb_key)) : true
  return a && b
}

// ── だれが見てよいか ───────────────────────────────────
function teacherOf(c: any, d: Deps): any | null {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return null
  return u
}
// 見るだけモードの間は写真を返さない（先生のログインのままでも）
function viewAsOn(c: any, d: Deps): boolean {
  try { return !!d.getCookie(c, 'viewas') } catch (_e) { return false }
}
async function ownsClass(c: any, u: any, classId: string) {
  if (!classId) return null
  return u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first()
}
// その子が先生のクラスの子か。返すのはその子のクラスID（管理者は所属クラスのどれか）
async function classOfStudent(c: any, u: any, userId: string): Promise<string | null> {
  if (!userId) return null
  const r: any = u.role === 'admin'
    ? await c.env.DB.prepare(`SELECT cm.class_id AS cid FROM class_members cm JOIN users s ON s.id=cm.user_id AND s.role='student' WHERE cm.user_id=? LIMIT 1`).bind(userId).first()
    : await c.env.DB.prepare(`SELECT cm.class_id AS cid FROM class_members cm JOIN classes cl ON cl.id=cm.class_id AND cl.teacher_id=? JOIN users s ON s.id=cm.user_id AND s.role='student' WHERE cm.user_id=? LIMIT 1`).bind(u.id, userId).first()
  return r ? String(r.cid) : null
}
async function settingsOf(env: any, classId: string) {
  let s: any = null
  try { s = await env.DB.prepare('SELECT keep_mode, auto_hw, remind_snooze FROM portfolio_settings WHERE class_id=? LIMIT 1').bind(classId).first() } catch (_e) {}
  return {
    keepMode: s && s.keep_mode === 'keep' ? 'keep' : 'fy_end',
    autoHw: s ? Number(s.auto_hw) !== 0 : true,
    remindSnooze: s && s.remind_snooze ? String(s.remind_snooze) : '',
  }
}

// ── 家庭学習の提出から自動で入れる（analyze-photo から waitUntil で呼ぶ） ──
//   bytes は子どもの端末で縮めたもの（長辺1280px）。2MB 近いものは入れない（あとで「とりこむ」で入る）。
export async function pfFromHomework(env: any, userId: string, dayKey: string, idx: number, bytes: Uint8Array, mime: string): Promise<boolean> {
  try {
    const kind = pfStoreKind(env)
    if (!kind || !env.DB) return false
    if (!bytes || !bytes.length || bytes.length > MAX_BYTES) return false
    if (!OK_MIME.test(String(mime || ''))) return false
    if (!isYmd(dayKey)) return false
    const cm: any = await env.DB.prepare('SELECT class_id AS cid FROM class_members WHERE user_id=? LIMIT 1').bind(userId).first()
    const classId = cm ? String(cm.cid) : ''
    if (classId) { const st = await settingsOf(env, classId); if (!st.autoHw) return false }
    // 1まい目を出しなおした日は、その日の家庭学習の写真を入れかえる（家庭学習の写真の動きと同じ）
    const olds = idx === 0
      ? await env.DB.prepare(`SELECT id, store, obj_key, thumb_key FROM portfolio_items WHERE user_id=? AND src='hw' AND hw_day_key=?`).bind(userId, dayKey).all()
      : await env.DB.prepare(`SELECT id, store, obj_key, thumb_key FROM portfolio_items WHERE user_id=? AND src='hw' AND hw_day_key=? AND hw_idx=?`).bind(userId, dayKey, idx).all()
    for (const o of ((olds && olds.results) || []) as any[]) {
      if (!(await delItemObjs(env, o))) continue
      await env.DB.prepare('DELETE FROM portfolio_items WHERE id=?').bind(o.id).run()
    }
    const id = newId(), fy = fyOf(dayKey)
    const key = `pf/${fy}/${userId}/${id}.jpg`
    await putObj(env, kind, key, bytes, mime)
    await env.DB.prepare(
      `INSERT INTO portfolio_items (id, user_id, class_id, src, hw_day_key, hw_idx, taken_on, fy, subj, memo, store, obj_key, thumb_key, mime, byte_size, thumb_size, created_by)
       VALUES (?,?,?,'hw',?,?,?,?,'','',?,?,NULL,?,?,0,?)`
    ).bind(id, userId, classId || null, dayKey, idx, dayKey, fy, kind, key, mime, bytes.length, userId).run()
    return true
  } catch (e: any) {
    console.warn('[PORTFOLIO_V1] auto add skipped:', e && e.message || e)
    return false
  }
}

// 📓 PORTFOLIO_AI_V1 子どものカルテに出す「ノート・作品へのひとこと」（先生が公開した最新の1つ・45日以内）
export async function pfWorkNoteFor(env: any, userId: string): Promise<{ text: string, at: string } | null> {
  if (!userId) return null
  const r: any = await env.DB.prepare(
    `SELECT body, published_at AS at FROM ai_review_drafts
     WHERE target_id=? AND kind='WORK' AND status='published' AND published_at >= datetime('now','-45 days')
     ORDER BY published_at DESC LIMIT 1`
  ).bind(userId).first()
  if (!r || !String(r.body || '').trim()) return null
  return { text: String(r.body).slice(0, 600), at: String(r.at || '').slice(0, 10) }
}

const IMG_HEADERS = (mime: string) => {
  const h = new Headers()
  h.set('Content-Type', OK_MIME.test(mime) ? mime : 'image/jpeg')
  h.set('Cache-Control', 'private, no-store')   // 共用の端末に残さない
  h.set('Content-Security-Policy', "default-src 'none'; sandbox")
  h.set('Vary', 'Cookie')
  h.set('X-Content-Type-Options', 'nosniff')
  h.set('Cross-Origin-Resource-Policy', 'same-origin')
  return h
}

export function registerPortfolio(app: any, d: Deps) {
  // ガード：先生・管理者だけ／見るだけモード中は止める
  function guard(c: any): any {
    const u = teacherOf(c, d)
    if (!u) return { res: jerr(c, 403, 'forbidden') }
    if (viewAsOn(c, d)) return { res: jerr(c, 403, 'view_as_active') }
    return { u }
  }

  // クラス一覧＋子どもごとの枚数＋設定＋年度末の確認
  app.get('/api/teacher/portfolio/summary', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const u = g.u
    const clsRes = u.role === 'admin'
      ? await c.env.DB.prepare('SELECT id, name FROM classes ORDER BY created_at DESC LIMIT 300').all()
      : await c.env.DB.prepare('SELECT id, name FROM classes WHERE teacher_id=? ORDER BY created_at DESC').bind(u.id).all()
    const classes = ((clsRes && clsRes.results) || []) as any[]
    let classId = String(c.req.query('classId') || '')
    if (!classId && classes.length) classId = String(classes[0].id)
    if (!classes.some((x) => String(x.id) === classId)) return c.json({ ok: true, classes, classId: '', students: [], store: pfStoreKind(c.env) })
    const today = jstToday(), curFy = fyOf(today)
    const st = await settingsOf(c.env, classId)
    const rows = await c.env.DB.prepare(
      `SELECT s.id AS userId, s.login_id AS loginId, s.name AS name, s.roster_no AS rosterNo,
              (SELECT COUNT(*) FROM portfolio_items p WHERE p.user_id=s.id AND p.deleted_at IS NULL) AS n,
              (SELECT MAX(taken_on) FROM portfolio_items p WHERE p.user_id=s.id AND p.deleted_at IS NULL) AS lastOn
       FROM class_members cm JOIN users s ON s.id=cm.user_id AND s.role='student'
       WHERE cm.class_id=? ORDER BY COALESCE(s.roster_no, 999), s.login_id`
    ).bind(classId).all()
    const students = ((rows && rows.results) || []) as any[]
    // 年度末の確認：年度末まで のクラスで、3月に入った（その年度ぶん）か、前の年度のぶんが残っているとき
    let yearEnd: any = null
    if (st.keepMode === 'fy_end' && !(st.remindSnooze && st.remindSnooze >= today)) {
      const month = Number(today.slice(5, 7))
      const targetFy = month === 3 ? curFy : curFy - 1
      const r: any = await c.env.DB.prepare(
        `SELECT COUNT(*) AS n, COALESCE(SUM(p.byte_size + p.thumb_size),0) AS b, MIN(p.fy) AS minFy
         FROM portfolio_items p
         WHERE p.deleted_at IS NULL AND p.fy <= ? AND (p.class_id=? OR p.user_id IN (SELECT user_id FROM class_members WHERE class_id=?))`
      ).bind(targetFy, classId, classId).first()
      if (r && Number(r.n) > 0) yearEnd = { fy: Number(r.minFy), upToFy: targetFy, count: Number(r.n), bytes: Number(r.b) }
    }
    // まだ入っていない、前からある家庭学習の写真の数
    let legacy = 0
    try {
      const l2: any = await c.env.DB.prepare(
        `SELECT COUNT(*) AS n FROM homework_photos2 h JOIN class_members cm ON cm.user_id=h.user_id AND cm.class_id=?
         WHERE NOT EXISTS (SELECT 1 FROM portfolio_items p WHERE p.user_id=h.user_id AND p.src='hw' AND p.hw_day_key=h.day_key AND p.hw_idx=h.idx)`
      ).bind(classId).first()
      legacy += Number(l2 && l2.n) || 0
    } catch (_e) {}
    try {
      const l1: any = await c.env.DB.prepare(
        `SELECT COUNT(*) AS n FROM homework_photos h JOIN class_members cm ON cm.user_id=h.user_id AND cm.class_id=?
         WHERE NOT EXISTS (SELECT 1 FROM homework_photos2 h2 WHERE h2.user_id=h.user_id AND h2.day_key=h.day_key)
           AND NOT EXISTS (SELECT 1 FROM portfolio_items p WHERE p.user_id=h.user_id AND p.src='hw' AND p.hw_day_key=h.day_key AND p.hw_idx=0)`
      ).bind(classId).first()
      legacy += Number(l1 && l1.n) || 0
    } catch (_e) {}
    const tot: any = await c.env.DB.prepare(
      `SELECT COUNT(*) AS n, COALESCE(SUM(p.byte_size + p.thumb_size),0) AS b FROM portfolio_items p WHERE p.deleted_at IS NULL AND (p.class_id=? OR p.user_id IN (SELECT user_id FROM class_members WHERE class_id=?))`
    ).bind(classId, classId).first()
    return c.json({ ok: true, classes, classId, students, settings: st, yearEnd, legacy, today, fy: curFy,
      total: { count: Number(tot && tot.n) || 0, bytes: Number(tot && tot.b) || 0 }, store: pfStoreKind(c.env) })
  })

  // 1人ぶんの目録（写真は入っていない）
  app.get('/api/teacher/portfolio/items', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const userId = String(c.req.query('userId') || '')
    const cid = await classOfStudent(c, g.u, userId)
    if (!cid) return jerr(c, 404, 'student_not_found')
    let sql = `SELECT id, src, taken_on AS takenOn, fy, subj, memo, hw_day_key AS hwDayKey, (thumb_key IS NOT NULL AND thumb_key<>'') AS hasThumb, byte_size AS byteSize, created_at AS createdAt
               FROM portfolio_items WHERE user_id=? AND deleted_at IS NULL`
    const binds: any[] = [userId]
    const fy = Number(c.req.query('fy') || 0)
    if (fy > 2000) { sql += ' AND fy=?'; binds.push(fy) }
    sql += ' ORDER BY taken_on DESC, created_at DESC LIMIT 1000'
    const r = await c.env.DB.prepare(sql).bind(...binds).all()
    return c.json({ ok: true, items: ((r && r.results) || []) })
  })

  // 🤖 PORTFOLIO_AI_V1 成果物の分析：クラスの子ども・期間・教科で目録を（写真は入っていない）
  app.get('/api/teacher/portfolio/range', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const classId = String(c.req.query('classId') || '')
    if (!(await ownsClass(c, g.u, classId))) return jerr(c, 404, 'class_not_found')
    const from = String(c.req.query('from') || ''), to = String(c.req.query('to') || '')
    if (!isYmd(from) || !isYmd(to)) return jerr(c, 400, 'bad_range')
    const want = String(c.req.query('userIds') || '').split(',').map((x) => x.trim()).filter(Boolean).slice(0, 60)
    let sql = `SELECT p.id, p.user_id AS userId, p.src, p.taken_on AS takenOn, p.subj, p.memo, (p.thumb_key IS NOT NULL AND p.thumb_key<>'') AS hasThumb
               FROM portfolio_items p JOIN class_members cm ON cm.user_id=p.user_id AND cm.class_id=?
               WHERE p.deleted_at IS NULL AND p.taken_on >= ? AND p.taken_on <= ?`
    const binds: any[] = [classId, from, to]
    if (want.length) { sql += ` AND p.user_id IN (${want.map(() => '?').join(',')})`; binds.push(...want) }
    const subj = clean(c.req.query('subj'), 20)
    if (subj === '家庭学習') sql += ` AND p.src='hw' AND COALESCE(p.subj,'')=''`
    else if (subj) { sql += ' AND p.subj=?'; binds.push(subj) }
    sql += ' ORDER BY p.user_id, p.taken_on, p.created_at LIMIT 600'
    const r = await c.env.DB.prepare(sql).bind(...binds).all()
    return c.json({ ok: true, items: ((r && r.results) || []) })
  })

  // 📓 PORTFOLIO_AI_V1 紙のカルテ用：先生のクラスの子の「ノート・作品へのひとこと」（最新・45日以内）
  app.get('/api/teacher/portfolio/work-notes', async (c: any) => {
    const u = teacherOf(c, d)
    if (!u) return jerr(c, 403, 'forbidden')
    const sql = `SELECT d.target_id AS uid, d.body AS body, d.published_at AS at FROM ai_review_drafts d
                 WHERE d.kind='WORK' AND d.status='published' AND d.published_at >= datetime('now','-45 days')` +
      (u.role === 'admin' ? '' : ` AND d.class_id IN (SELECT id FROM classes WHERE teacher_id=?)`) +
      ` ORDER BY d.published_at DESC LIMIT 500`
    const r = u.role === 'admin' ? await c.env.DB.prepare(sql).all() : await c.env.DB.prepare(sql).bind(u.id).all()
    const byUser: Record<string, any> = {}
    for (const x of ((r && r.results) || []) as any[]) { const k = String(x.uid || ''); if (k && !byUser[k]) byUser[k] = { text: String(x.body || '').slice(0, 600), at: String(x.at || '').slice(0, 10) } }
    return c.json({ ok: true, byUser })
  })

  // 写真（先生だけ）。?t=1 で小さい版（あれば）
  app.get('/api/teacher/portfolio/img/:id', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const id = String(c.req.param('id') || '')
    if (!/^pf_[0-9a-f]{16,40}$/.test(id)) return jerr(c, 404, 'not_found')
    const it: any = await c.env.DB.prepare('SELECT user_id, store, obj_key, thumb_key, mime FROM portfolio_items WHERE id=? AND deleted_at IS NULL LIMIT 1').bind(id).first()
    if (!it) return jerr(c, 404, 'not_found')
    const cid = await classOfStudent(c, g.u, String(it.user_id))
    if (!cid) return jerr(c, 403, 'forbidden')
    const wantThumb = c.req.query('t') === '1' && it.thumb_key
    const o = await getObj(c.env, String(it.store), String(wantThumb ? it.thumb_key : it.obj_key))
    if (!o) return jerr(c, 404, 'not_found')
    return new Response(o.body, { headers: IMG_HEADERS(wantThumb ? 'image/jpeg' : String(o.mime || it.mime)) })
  })

  // 追加（1まいずつ。先生の端末で縮めてから送る）。src=hw は「前からある家庭学習の写真のとりこみ」
  app.post('/api/teacher/portfolio/upload', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const u = g.u
    const kind = pfStoreKind(c.env)
    if (!kind) return jerr(c, 503, 'store_not_ready')
    const fd = await c.req.formData().catch(() => null)
    if (!fd) return jerr(c, 400, 'invalid_form')
    const userId = String(fd.get('userId') || '')
    const cid = await classOfStudent(c, u, userId)
    if (!cid) return jerr(c, 404, 'student_not_found')
    const photo = fd.get('photo') as any
    if (!photo || typeof photo.arrayBuffer !== 'function' || !photo.size) return jerr(c, 400, 'photo_required')
    if (photo.size > MAX_BYTES) return jerr(c, 400, 'photo_too_large')
    const mime = String(photo.type || 'image/jpeg')
    if (!OK_MIME.test(mime)) return jerr(c, 400, 'bad_type')
    const bytes = new Uint8Array(await photo.arrayBuffer())
    const thumb = fd.get('thumb') as any
    let tb: Uint8Array | null = null
    if (thumb && typeof thumb.arrayBuffer === 'function' && thumb.size && thumb.size <= MAX_THUMB && OK_MIME.test(String(thumb.type || ''))) tb = new Uint8Array(await thumb.arrayBuffer())

    let src = String(fd.get('src') || 'teacher') === 'hw' ? 'hw' : 'teacher'
    let hwDay: string | null = null, hwIdx: number | null = null
    let takenOn = String(fd.get('takenOn') || '').slice(0, 10)
    if (src === 'hw') {
      hwDay = String(fd.get('hwDayKey') || '').slice(0, 10)
      hwIdx = Math.max(0, Math.min(9, Number(fd.get('hwIdx') || 0) | 0))
      if (!isYmd(hwDay)) return jerr(c, 400, 'bad_day')
      // 本当にその子のその日の家庭学習の写真があるか（うそのとりこみを入れない）
      let ok = false
      try { ok = !!(await c.env.DB.prepare('SELECT 1 FROM homework_photos2 WHERE user_id=? AND day_key=? AND idx=? LIMIT 1').bind(userId, hwDay, hwIdx).first()) } catch (_e) {}
      if (!ok && hwIdx === 0) { try { ok = !!(await c.env.DB.prepare('SELECT 1 FROM homework_photos WHERE user_id=? AND day_key=? LIMIT 1').bind(userId, hwDay).first()) } catch (_e) {} }
      if (!ok) return jerr(c, 404, 'hw_photo_not_found')
      const dup: any = await c.env.DB.prepare(`SELECT id FROM portfolio_items WHERE user_id=? AND src='hw' AND hw_day_key=? AND hw_idx=? LIMIT 1`).bind(userId, hwDay, hwIdx).first()
      if (dup) return c.json({ ok: true, skipped: true, id: dup.id })
      takenOn = hwDay
    }
    if (!isYmd(takenOn)) takenOn = jstToday()
    const id = newId(), fy = fyOf(takenOn)
    const key = `pf/${fy}/${userId}/${id}.jpg`
    const tkey = tb ? `pf/${fy}/${userId}/${id}_t.jpg` : null
    await putObj(c.env, kind, key, bytes, mime)
    if (tb && tkey) await putObj(c.env, kind, tkey, tb, 'image/jpeg')
    await c.env.DB.prepare(
      `INSERT INTO portfolio_items (id, user_id, class_id, src, hw_day_key, hw_idx, taken_on, fy, subj, memo, store, obj_key, thumb_key, mime, byte_size, thumb_size, created_by)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`
    ).bind(id, userId, cid, src, hwDay, hwIdx, takenOn, fy, clean(fd.get('subj'), 20), clean(fd.get('memo'), 200), kind, key, tkey, mime, bytes.length, tb ? tb.length : 0, u.id).run()
    return c.json({ ok: true, id })
  })

  // 教科・メモ・日付を直す
  app.post('/api/teacher/portfolio/update', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const b = await c.req.json().catch(() => null)
    if (!b || !b.id) return jerr(c, 400, 'invalid')
    const it: any = await c.env.DB.prepare('SELECT user_id, taken_on FROM portfolio_items WHERE id=? AND deleted_at IS NULL LIMIT 1').bind(String(b.id)).first()
    if (!it) return jerr(c, 404, 'not_found')
    if (!(await classOfStudent(c, g.u, String(it.user_id)))) return jerr(c, 403, 'forbidden')
    const takenOn = isYmd(String(b.takenOn || '')) ? String(b.takenOn) : String(it.taken_on)
    await c.env.DB.prepare('UPDATE portfolio_items SET subj=?, memo=?, taken_on=?, fy=? WHERE id=?')
      .bind(clean(b.subj, 20), clean(b.memo, 200), takenOn, fyOf(takenOn), String(b.id)).run()
    return c.json({ ok: true })
  })

  // 消す（先生だけ）。写真は消し、目録には「消した」印だけ残す
  app.post('/api/teacher/portfolio/delete', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const b = await c.req.json().catch(() => null)
    const ids = (b && Array.isArray(b.ids) ? b.ids : []).map((x: any) => String(x || '')).filter((x: string) => /^pf_[0-9a-f]{16,40}$/.test(x)).slice(0, 100)
    let n = 0
    for (const id of ids) {
      const it: any = await c.env.DB.prepare('SELECT user_id, store, obj_key, thumb_key FROM portfolio_items WHERE id=? AND deleted_at IS NULL LIMIT 1').bind(id).first()
      if (!it) continue
      if (!(await classOfStudent(c, g.u, String(it.user_id)))) continue
      if (!(await delItemObjs(c.env, it))) continue
      await c.env.DB.prepare("UPDATE portfolio_items SET deleted_at=datetime('now') WHERE id=?").bind(id).run()
      n++
    }
    return c.json({ ok: true, deleted: n })
  })

  // 設定（保存期間・家庭学習の自動とりこみ・年度末の確認をあとで）
  app.post('/api/teacher/portfolio/settings', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const b = await c.req.json().catch(() => null)
    const classId = String((b && b.classId) || '')
    if (!(await ownsClass(c, g.u, classId))) return jerr(c, 404, 'class_not_found')
    const cur = await settingsOf(c.env, classId)
    const keep = b.keepMode === 'keep' ? 'keep' : (b.keepMode === 'fy_end' ? 'fy_end' : cur.keepMode)
    const auto = (b.autoHw === undefined) ? (cur.autoHw ? 1 : 0) : (b.autoHw ? 1 : 0)
    let snooze = cur.remindSnooze
    if (b.snoozeDays) { const dd = Math.max(1, Math.min(60, Number(b.snoozeDays) | 0)); snooze = jstToday(Date.now() + dd * 86400_000) }
    await c.env.DB.prepare(
      `INSERT INTO portfolio_settings (class_id, keep_mode, auto_hw, remind_snooze, updated_by, updated_at) VALUES (?,?,?,?,?,datetime('now'))
       ON CONFLICT(class_id) DO UPDATE SET keep_mode=excluded.keep_mode, auto_hw=excluded.auto_hw, remind_snooze=excluded.remind_snooze, updated_by=excluded.updated_by, updated_at=excluded.updated_at`
    ).bind(classId, keep, auto, snooze || null, g.u.id).run()
    return c.json({ ok: true, settings: await settingsOf(c.env, classId) })
  })

  // 前からある家庭学習の写真のうち、まだ入っていないもの（先生の端末が縮めて upload src=hw で入れる）
  app.get('/api/teacher/portfolio/legacy', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const classId = String(c.req.query('classId') || '')
    if (!(await ownsClass(c, g.u, classId))) return jerr(c, 404, 'class_not_found')
    const out: any[] = []
    try {
      const r = await c.env.DB.prepare(
        `SELECT h.user_id AS userId, h.day_key AS dayKey, h.idx AS idx FROM homework_photos2 h JOIN class_members cm ON cm.user_id=h.user_id AND cm.class_id=?
         WHERE NOT EXISTS (SELECT 1 FROM portfolio_items p WHERE p.user_id=h.user_id AND p.src='hw' AND p.hw_day_key=h.day_key AND p.hw_idx=h.idx)
         ORDER BY h.day_key LIMIT 300`
      ).bind(classId).all()
      for (const x of ((r && r.results) || []) as any[]) out.push(x)
    } catch (_e) {}
    try {
      const r = await c.env.DB.prepare(
        `SELECT h.user_id AS userId, h.day_key AS dayKey, 0 AS idx FROM homework_photos h JOIN class_members cm ON cm.user_id=h.user_id AND cm.class_id=?
         WHERE NOT EXISTS (SELECT 1 FROM homework_photos2 h2 WHERE h2.user_id=h.user_id AND h2.day_key=h.day_key)
           AND NOT EXISTS (SELECT 1 FROM portfolio_items p WHERE p.user_id=h.user_id AND p.src='hw' AND p.hw_day_key=h.day_key AND p.hw_idx=0)
         ORDER BY h.day_key LIMIT 300`
      ).bind(classId).all()
      for (const x of ((r && r.results) || []) as any[]) out.push(x)
    } catch (_e) {}
    return c.json({ ok: true, items: out })
  })

  // 年度末：まとめて消す（先生が確認してから。1回に40まいずつ。画面が残りが0になるまで呼ぶ）
  app.post('/api/teacher/portfolio/year-end', async (c: any) => {
    const g = guard(c); if (g.res) return g.res
    const b = await c.req.json().catch(() => null)
    const classId = String((b && b.classId) || '')
    if (!(await ownsClass(c, g.u, classId))) return jerr(c, 404, 'class_not_found')
    const upToFy = Number(b && b.upToFy) | 0
    if (!(upToFy > 2000)) return jerr(c, 400, 'bad_fy')
    if (String((b && b.confirm) || '') !== 'けす') return jerr(c, 400, 'confirm_required')
    if (upToFy > fyOf(jstToday())) return jerr(c, 400, 'future_fy')
    const r = await c.env.DB.prepare(
      `SELECT p.id, p.store, p.obj_key, p.thumb_key FROM portfolio_items p
       WHERE p.deleted_at IS NULL AND p.fy <= ? AND (p.class_id=? OR p.user_id IN (SELECT user_id FROM class_members WHERE class_id=?)) LIMIT 40`
    ).bind(upToFy, classId, classId).all()
    let n = 0
    for (const it of ((r && r.results) || []) as any[]) {
      if (!(await delItemObjs(c.env, it))) continue
      await c.env.DB.prepare("UPDATE portfolio_items SET deleted_at=datetime('now') WHERE id=?").bind(it.id).run()
      n++
    }
    const left: any = await c.env.DB.prepare(
      `SELECT COUNT(*) AS n FROM portfolio_items p WHERE p.deleted_at IS NULL AND p.fy <= ? AND (p.class_id=? OR p.user_id IN (SELECT user_id FROM class_members WHERE class_id=?))`
    ).bind(upToFy, classId, classId).first()
    return c.json({ ok: true, deleted: n, left: Number(left && left.n) || 0 })
  })
}
