// ==================== 👀 子どもの画面に入る（見るだけ） VIEWAS_V1 ====================
//
// 先生の言葉：「子どもの画面がどうなってるか見たい。誰かの画面のコピーに入り込める感じで、全く同じ見方をしたい」
//
// しくみ:
//   ・先生（管理者・担任）が子どもを1人えらぶと、署名つきの「見るだけ」Cookie（viewas）を発行する。
//     先生のログイン（session Cookie）はそのまま残す。viewas は 60 分で切れる。
//   ・viewas があるあいだ、/api/* は「その子」として動く（/api/teacher/*・/api/admin/* だけは先生のまま）。
//     だから子どもの画面（ホーム・カルテ・家庭学習・振り返り・ゲーム…）が、その子の本物のデータでそのまま出る。
//   ・書きこみは2重に止める。
//       (1) サーバ：GET/HEAD 以外は、ハンドラを1つも通さずに {ok:true, viewOnly:true} を返す（保存・提出・コイン・既読・利用記録・ゲーム進行）。
//           GET のハンドラも、DB を「読むだけ」の包みに差しかえて動かす（SELECT 以外の SQL は実行せず、成功したふりだけ返す）。
//           → progress.state_json は、どの経路からも上書きされない。
//       (2) 画面：先頭に差しこむ小さなスクリプトが、fetch の GET 以外・sendBeacon・フォーム送信を止め、
//           localStorage / sessionStorage をその場かぎりのメモリに差しかえる（先生の端末にも何も残さない）。
//   ・誰が・いつ・誰の画面を見たかは view_as_log に残す（記録できなければ始めない＝fail closed）。
//   ・子どもの画面には何も足さない。帯とスクリプトは viewas Cookie が有効なときだけ差しこむ。
//
// ⚠️ テーブルは migrations/0046_view_as_log.sql だけで作る。ここでは DDL を一切実行しない。
// ⚠️ src/index.tsx の app.get('/') の .replace() チェーンには触らない（HTML の差しこみはこのミドルウェアで行う）。

import { VIEWAS_CLIENT_JS } from './viewas_client'

export const VIEWAS_COOKIE = 'viewas'
export const VIEWAS_MINUTES = 60
export const VIEWAS_MARK = 'VIEWAS_V1'

type Deps = {
  readSession: (secret: string, token: string) => Promise<any>
  makeSession: (secret: string, payload: any) => Promise<string>
  getCookie: (c: any, name: string) => string | undefined
  setCookie: (c: any, name: string, value: string, opt?: any) => void
  deleteCookie: (c: any, name: string, opt?: any) => void
}

function jerr(c: any, status: number, message: string) { return c.json({ ok: false, error: message }, status) }

// ── 読むだけの DB ──────────────────────────────────────────────
// SELECT（と書きこみ語を含まない WITH / EXPLAIN）だけ本物に通す。それ以外は実行しない。
export function viewAsIsReadSql(sql: string): boolean {
  let s = String(sql || '')
  // 先頭のコメントと空白を落とす
  for (let i = 0; i < 20; i++) {
    const t = s.replace(/^\s+/, '')
    if (t.startsWith('--')) { const n = t.indexOf('\n'); s = n < 0 ? '' : t.slice(n + 1); continue }
    if (t.startsWith('/*')) { const n = t.indexOf('*/'); s = n < 0 ? '' : t.slice(n + 2); continue }
    s = t
    break
  }
  const m = s.match(/^([A-Za-z]+)/)
  if (!m) return false
  const w = m[1].toUpperCase()
  const writes = /\b(INSERT|UPDATE|DELETE|REPLACE|UPSERT|CREATE|ALTER|DROP|ATTACH|DETACH|VACUUM|REINDEX|PRAGMA)\b/i
  if (w === 'SELECT') {
    // 1文目だけを見る。; のあとに別の文があれば通さない
    const semi = s.indexOf(';')
    if (semi >= 0 && s.slice(semi + 1).trim() !== '') return false
    return true
  }
  if (w === 'WITH' || w === 'EXPLAIN') return !writes.test(s) && (s.indexOf(';') < 0 || s.slice(s.indexOf(';') + 1).trim() === '')
  return false
}

function stubStmt(counter: { n: number }) {
  const meta = { changes: 0, last_row_id: 0, rows_read: 0, rows_written: 0, changed_db: false, duration: 0, viewOnly: true }
  const st: any = {
    __viewAsStub: true,
    bind() { return st },
    async run() { counter.n++; return { success: true, results: [], meta } },
    async all() { counter.n++; return { success: true, results: [], meta } },
    async first() { counter.n++; return null },
    async raw() { counter.n++; return [] },
  }
  return st
}

export function viewAsReadOnlyDB(db: any, counter: { n: number } = { n: 0 }): any {
  if (!db) return db
  const ro: any = {
    __viewAsReadOnly: true,
    prepare(sql: string) {
      if (viewAsIsReadSql(sql)) return db.prepare(sql)
      return stubStmt(counter)
    },
    async batch(stmts: any[]) {
      const out: any[] = []
      for (const s of (stmts || [])) {
        if (s && s.__viewAsStub) out.push(await s.run())
        else out.push(await s.all())
      }
      return out
    },
    async exec(_sql: string) { counter.n++; return { count: 0, duration: 0 } },
    async dump() { throw new Error('view_only') },
    withSession(...a: any[]) {
      try { return viewAsReadOnlyDB(db.withSession(...a), counter) } catch (_e) { return ro }
    },
  }
  return ro
}

function readOnlyBucket(b: any) {
  if (!b || typeof b !== 'object') return b
  return new Proxy(b, {
    get(t: any, k: any) {
      if (k === 'put' || k === 'delete' || k === 'createMultipartUpload' || k === 'resumeMultipartUpload') {
        return async () => null
      }
      const v = t[k]
      return typeof v === 'function' ? v.bind(t) : v
    },
  })
}

export function viewAsReadOnlyEnv(env: any, counter: { n: number }) {
  const ro = viewAsReadOnlyDB(env && env.DB, counter)
  return new Proxy(env || {}, {
    get(t: any, k: any) {
      if (k === 'DB') return ro
      const v = t[k]
      // R2 / KV など、put / delete を持つものは書きこめなくする（ASSETS・AI はそのまま）
      if (v && typeof v === 'object' && k !== 'ASSETS' && k !== 'AI' && (typeof v.put === 'function' || typeof v.delete === 'function')) {
        return readOnlyBucket(v)
      }
      return v
    },
  })
}

// ── Cookie ─────────────────────────────────────────────────────
const COOKIE_BASE = { httpOnly: true, secure: true, sameSite: 'Lax' as const, path: '/' }

async function teacherFromSession(c: any, d: Deps): Promise<any | null> {
  // /api/* では既存の認証ミドルウェアが user を入れている。ページの道では自分で読む。
  const u = c.get('user')
  if (u && u.id) return (u.role === 'teacher' || u.role === 'admin') ? u : null
  try {
    const tok = d.getCookie(c, 'session')
    const secret = c.env && c.env.SESSION_SECRET
    if (!tok || !secret) return null
    const s = await d.readSession(secret, tok)
    if (!s || !s.id) return null
    if (s.iat && (Math.floor(Date.now() / 1000) - s.iat) > 30 * 24 * 60 * 60) return null
    if (s.role !== 'teacher' && s.role !== 'admin') return null
    return { id: s.id, role: s.role, loginId: s.loginId, isActive: !!s.isActive }
  } catch (_e) { return null }
}

// 有効な viewas なら { teacher, va } を返す。署名・期限・先生の一致をすべて見る。
async function readViewAs(c: any, d: Deps): Promise<{ teacher: any, va: any } | null> {
  const tok = d.getCookie(c, VIEWAS_COOKIE)
  if (!tok) return null
  const secret = c.env && c.env.SESSION_SECRET
  if (!secret) return null
  let va: any = null
  try { va = await d.readSession(secret, tok) } catch (_e) { va = null }
  if (!va || va.k !== 'viewas' || !va.t || !va.s || !va.l) return null
  if (!(Number(va.exp) > Math.floor(Date.now() / 1000))) return null
  const teacher = await teacherFromSession(c, d)
  if (!teacher || String(teacher.id) !== String(va.t)) return null
  return { teacher, va }
}

async function endLog(env: any, logId: string) {
  try { await env.DB.prepare(`UPDATE view_as_log SET ended_at=datetime('now') WHERE id=? AND ended_at IS NULL`).bind(String(logId)).run() } catch (_e) {}
}
async function countBlocked(env: any, logId: string) {
  try { await env.DB.prepare(`UPDATE view_as_log SET blocked_count=blocked_count+1, last_seen_at=datetime('now') WHERE id=?`).bind(String(logId)).run() } catch (_e) {}
}

// 先生の画面に戻ったら「見る」を終わらせるページ
const TEACHER_PAGES = new Set(['/teacher', '/admin', '/teacher-mi', '/teacher-recovery', '/teacher-signup'])
// 帯を差しこまないページ（ログインまわり）
const NO_INJECT = new Set(['/login', '/signup', '/recover', '/logout'])

function safeJson(o: any) {
  return JSON.stringify(o).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029')
}

export function viewAsInjectHtml(html: string, cfg: any): string {
  const tag = '<script data-viewas="1">window.__VIEWAS__=' + safeJson(cfg) + ';' + VIEWAS_CLIENT_JS + '</script>'
  const m = html.match(/<head[^>]*>/i)
  if (m && m.index !== undefined) {
    const at = m.index + m[0].length
    return html.slice(0, at) + tag + html.slice(at)
  }
  return tag + html
}

// ── ミドルウェア（既存の認証ミドルウェアの直後に登録すること） ─────────────
export function installViewAs(app: any, d: Deps) {
  app.use('*', async (c: any, next: any) => {
    if (!d.getCookie(c, VIEWAS_COOKIE)) return next()
    const path = String(c.req.path || '/')
    const method = String(c.req.method || 'GET').toUpperCase()
    const isRead = method === 'GET' || method === 'HEAD' || method === 'OPTIONS'

    const r = await readViewAs(c, d)
    if (!r) {
      // 期限切れ・先生がちがう・署名がおかしい → Cookie を捨てて、ふつうに通す
      try { d.deleteCookie(c, VIEWAS_COOKIE, COOKIE_BASE) } catch (_e) {}
      if (path.startsWith('/api/') && !path.startsWith('/api/teacher/') && !path.startsWith('/api/admin/') && !isRead) {
        // 見るだけの画面から遅れて届いた書きこみも、先生のアカウントに入らないよう止める
        const t = await teacherFromSession(c, d)
        if (t) return c.json({ ok: true, viewOnly: true, ended: true })
      }
      return next()
    }
    const { va } = r

    // 先生のページに戻った → 終わり
    if (method === 'GET' && TEACHER_PAGES.has(path)) {
      await endLog(c.env, va.l)
      d.deleteCookie(c, VIEWAS_COOKIE, COOKIE_BASE)
      return next()
    }
    // 子どもの画面の「ログアウト」→ 先生はログアウトさせず、見るのを終えて先生の画面へ
    if (path === '/logout') {
      await endLog(c.env, va.l)
      d.deleteCookie(c, VIEWAS_COOKIE, COOKIE_BASE)
      return c.redirect('/teacher')
    }

    if (path.startsWith('/api/')) {
      // 先生・管理者の API は先生のまま（ほかのタブで開いている先生の画面がこわれないように）
      if (path.startsWith('/api/teacher/') || path.startsWith('/api/admin/')) return next()
      if (path === '/api/auth/logout') {
        await endLog(c.env, va.l)
        d.deleteCookie(c, VIEWAS_COOKIE, COOKIE_BASE)
        return c.json({ ok: true, viewOnly: true, ended: true })
      }
      if (!isRead) {
        await countBlocked(c.env, va.l)
        return c.json({ ok: true, viewOnly: true })
      }
      c.set('user', { id: String(va.s), role: 'student', loginId: String(va.n || ''), isActive: true })
      c.set('viewAs', { teacherId: String(va.t), logId: String(va.l) })
      const counter = { n: 0 }
      c.env = viewAsReadOnlyEnv(c.env, counter)
      await next()
      try { c.res.headers.set('cache-control', 'no-store') } catch (_e) {}
      return
    }

    // ページ（HTML）：子どもの画面に帯と見るだけスクリプトを差しこむ
    if (!isRead) return c.json({ ok: true, viewOnly: true })
    const roCounter = { n: 0 }
    c.env = viewAsReadOnlyEnv(c.env, roCounter)
    await next()
    if (NO_INJECT.has(path)) return
    try {
      const ct = String(c.res.headers.get('content-type') || '')
      if (ct.indexOf('text/html') < 0 || method !== 'GET') return
      const html = await c.res.text()
      const out = viewAsInjectHtml(html, { name: String(va.m || ''), until: Number(va.exp) * 1000 })
      const h = new Headers(c.res.headers)
      h.delete('content-length')
      h.set('cache-control', 'no-store')
      c.res = undefined
      c.res = new Response(out, { status: 200, headers: h })
    } catch (_e) {}
  })

  // ── 先生用 API ───────────────────────────────────────────────
  function needTeacher(c: any) {
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return null
    return u
  }

  // 子どもを選ぶための名簿（担任は自分のクラスだけ・管理者は全クラス）
  app.get('/api/teacher/view-as/roster', async (c: any) => {
    const u = needTeacher(c)
    if (!u) return jerr(c, 401, 'unauthorized')
    const cls = u.role === 'admin'
      ? await c.env.DB.prepare(`SELECT id, name, teacher_id AS teacherId FROM classes ORDER BY (teacher_id = ?) DESC, created_at DESC`).bind(u.id).all<any>()
      : await c.env.DB.prepare(`SELECT id, name, teacher_id AS teacherId FROM classes WHERE teacher_id=? ORDER BY created_at DESC`).bind(u.id).all<any>()
    const out: any[] = []
    for (const k of ((cls && cls.results) || [])) {
      const m = await c.env.DB.prepare(
        `SELECT u.id, u.name, u.grade FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=? AND u.role='student' ORDER BY u.name`
      ).bind(k.id).all<any>()
      out.push({ id: k.id, name: k.name, mine: String(k.teacherId) === String(u.id), members: (m && m.results) || [] })
    }
    return c.json({ ok: true, classes: out, minutes: VIEWAS_MINUTES })
  })

  // はじめる
  app.post('/api/teacher/view-as/start', async (c: any) => {
    const u = needTeacher(c)
    if (!u) return jerr(c, 401, 'unauthorized')
    const body = await c.req.json().catch(() => null)
    const sid = String((body && body.studentId) || '').slice(0, 80)
    if (!sid) return jerr(c, 400, 'studentId_required')
    const stu = await c.env.DB.prepare(`SELECT id, login_id AS loginId, name, role FROM users WHERE id=? LIMIT 1`).bind(sid).first<any>()
    if (!stu || stu.role !== 'student') return jerr(c, 404, 'student_not_found')
    // 担任は自分のクラスの子だけ。管理者はどの子でも。
    let classId = ''
    if (u.role === 'admin') {
      const m = await c.env.DB.prepare(`SELECT class_id AS classId FROM class_members WHERE user_id=? LIMIT 1`).bind(sid).first<any>()
      classId = m ? String(m.classId || '') : ''
    } else {
      const m = await c.env.DB.prepare(
        `SELECT cm.class_id AS classId FROM class_members cm JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id=? WHERE cm.user_id=? LIMIT 1`
      ).bind(u.id, sid).first<any>()
      if (!m) return jerr(c, 404, 'student_not_found')
      classId = String(m.classId || '')
    }
    // 前の「見る」が残っていたら閉じる
    const prev = await readViewAs(c, d)
    if (prev) await endLog(c.env, prev.va.l)

    const logId = crypto.randomUUID()
    try {
      await c.env.DB.prepare(
        `INSERT INTO view_as_log (id, teacher_id, teacher_role, student_id, class_id, started_at, last_seen_at) VALUES (?,?,?,?,?,datetime('now'),datetime('now'))`
      ).bind(logId, String(u.id), String(u.role), String(stu.id), classId).run()
    } catch (_e) {
      // 記録できないときは始めない
      return jerr(c, 503, 'log_unavailable')
    }
    const exp = Math.floor(Date.now() / 1000) + VIEWAS_MINUTES * 60
    const tok = await d.makeSession(c.env.SESSION_SECRET, {
      k: 'viewas', t: String(u.id), s: String(stu.id), n: String(stu.loginId || ''), m: String(stu.name || '').slice(0, 40), l: logId, exp,
    })
    d.setCookie(c, VIEWAS_COOKIE, tok, { ...COOKIE_BASE, maxAge: VIEWAS_MINUTES * 60 })
    return c.json({ ok: true, until: exp * 1000, name: String(stu.name || '') })
  })

  // おわる（Cookie がおかしくても必ず消す）
  app.post('/api/teacher/view-as/end', async (c: any) => {
    const u = needTeacher(c)
    const r = await readViewAs(c, d)
    if (r && u && String(r.va.t) === String(u.id)) await endLog(c.env, r.va.l)
    d.deleteCookie(c, VIEWAS_COOKIE, COOKIE_BASE)
    return c.json({ ok: true })
  })

  // いま見ているか（帯がときどき確かめる）
  app.get('/api/teacher/view-as/status', async (c: any) => {
    const u = needTeacher(c)
    if (!u) return c.json({ ok: true, active: false })
    const r = await readViewAs(c, d)
    if (!r) return c.json({ ok: true, active: false })
    return c.json({ ok: true, active: true, name: String(r.va.m || ''), until: Number(r.va.exp) * 1000 })
  })

  // 記録（誰が・いつ・誰の画面を見たか）
  app.get('/api/teacher/view-as/log', async (c: any) => {
    const u = needTeacher(c)
    if (!u) return jerr(c, 401, 'unauthorized')
    const sel = `SELECT l.id, l.teacher_id AS teacherId, l.teacher_role AS teacherRole, l.student_id AS studentId,
        l.started_at AS startedAt, l.ended_at AS endedAt, l.last_seen_at AS lastSeenAt, l.blocked_count AS blockedCount,
        COALESCE((SELECT name FROM teacher_accounts WHERE id=l.teacher_id), (SELECT name FROM users WHERE id=l.teacher_id), '') AS teacherName,
        COALESCE((SELECT name FROM users WHERE id=l.student_id), '') AS studentName
      FROM view_as_log l`
    try {
      const rows = u.role === 'admin'
        ? await c.env.DB.prepare(sel + ` ORDER BY l.started_at DESC LIMIT 50`).all<any>()
        : await c.env.DB.prepare(sel + ` WHERE l.teacher_id=? OR l.student_id IN (SELECT cm.user_id FROM class_members cm JOIN classes cl ON cl.id=cm.class_id WHERE cl.teacher_id=?) ORDER BY l.started_at DESC LIMIT 50`).bind(u.id, u.id).all<any>()
      return c.json({ ok: true, rows: (rows && rows.results) || [] })
    } catch (_e) {
      return c.json({ ok: true, rows: [], note: 'log_unavailable' })
    }
  })

  // 先生の画面のボタン（public/viewas-teacher.js）を配る道
  app.get('/viewas-teacher.js', async (c: any) => {
    try {
      const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/viewas-teacher.js')))
      if (a && a.status === 200) {
        return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } })
      }
    } catch (_e) {}
    return c.text('not found', 404)
  })
}
