import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'

type Bindings = {
  DB: D1Database
  SESSION_SECRET: string
  ADMIN_LOGIN_ID?: string
  ADMIN_PASSWORD?: string
}

type Variables = {
  user?: { id: string; role: 'student' | 'admin'; loginId: string; isActive: boolean }
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Global error handler (to avoid silent 500)
app.onError((err, c) => {
  console.error('Unhandled error:', err)
  const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err)
  return c.text(`Internal Error\n${msg}`, 500)
})

app.use('/api/*', cors())

// -------------------- utils --------------------

function jsonError(c: any, status: number, message: string) {
  return c.json({ ok: false, error: message }, status)
}

function b64uEncode(buf: ArrayBuffer) {
  const bytes = new Uint8Array(buf)
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function b64uDecodeToBytes(s: string) {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  const bin = atob(s)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

async function hmacSign(secret: string, data: string) {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data))
  return b64uEncode(sig)
}

async function hmacVerify(secret: string, data: string, sigB64u: string) {
  const enc = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  )
  return crypto.subtle.verify('HMAC', key, b64uDecodeToBytes(sigB64u), enc.encode(data))
}

function randomHex(bytes = 16) {
  const a = new Uint8Array(bytes)
  crypto.getRandomValues(a)
  return [...a].map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function pbkdf2Hash(password: string, saltHex: string, iterations = 100_000) {
  const enc = new TextEncoder()
  const salt = new Uint8Array(saltHex.match(/.{1,2}/g)!.map((x) => parseInt(x, 16)))
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations },
    keyMaterial,
    256
  )
  return b64uEncode(bits)
}

// session cookie: "v1.<payloadB64u>.<sigB64u>" where payload is JSON
async function makeSession(secret: string, payload: any) {
  const data = b64uEncode(new TextEncoder().encode(JSON.stringify(payload)))
  const sig = await hmacSign(secret, data)
  return `v1.${data}.${sig}`
}

async function readSession(secret: string, token: string) {
  const parts = token.split('.')
  if (parts.length !== 3 || parts[0] !== 'v1') return null
  const data = parts[1]
  const sig = parts[2]
  const ok = await hmacVerify(secret, data, sig)
  if (!ok) return null
  const json = new TextDecoder().decode(b64uDecodeToBytes(data))
  return JSON.parse(json)
}

// -------------------- ensure admin exists --------------------
app.use('*', async (c, next) => {
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

  if (!existing) {
    const id = crypto.randomUUID()
    const salt = randomHex(16)
    const hash = await pbkdf2Hash(adminPassword, salt)
    // admin is always active
    await c.env.DB.prepare(
      `INSERT INTO users (id, role, login_id, password_hash, password_salt, name, grade, class_name, is_active)
       VALUES (?, 'admin', ?, ?, ?, 'admin', 0, '-', 1)`
    )
      .bind(id, adminLoginId, hash, salt)
      .run()
  } else {
    // If admin already exists in DB, do NOT override password using Secrets.
  }

  return next()
})

// -------------------- auth middleware --------------------
app.use('/api/*', async (c, next) => {
  const token = getCookie(c, 'session')
  if (!token) return next()
  const secret = c.env.SESSION_SECRET
  if (!secret) return next()
  const sess = await readSession(secret, token)
  if (!sess?.id) return next()

  c.set('user', {
    id: sess.id,
    role: sess.role,
    loginId: sess.loginId,
    isActive: !!sess.isActive,
  })

  return next()
})

// -------------------- API: auth --------------------

app.post('/api/auth/signup', async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const loginId = String(body.loginId || '').trim()
  const password = String(body.password || '')
  const name = String(body.name || '').trim()
  const grade = Number(body.grade)
  const className = String(body.className || '').trim()

  if (!loginId || loginId.length < 3) return jsonError(c, 400, 'loginId_too_short')
  if (!password || password.length < 6) return jsonError(c, 400, 'password_too_short')
  if (!name) return jsonError(c, 400, 'name_required')
  if (!Number.isFinite(grade) || grade < 1 || grade > 12) return jsonError(c, 400, 'grade_invalid')
  if (!className) return jsonError(c, 400, 'class_required')

  const id = crypto.randomUUID()
  const salt = randomHex(16)
  const hash = await pbkdf2Hash(password, salt)

  try {
    await c.env.DB.prepare(
      `INSERT INTO users (id, role, login_id, password_hash, password_salt, name, grade, class_name, is_active)
       VALUES (?, 'student', ?, ?, ?, ?, ?, ?, 0)`
    )
      .bind(id, loginId, hash, salt, name, grade, className)
      .run()
  } catch (e: any) {
    // likely unique constraint
    return jsonError(c, 409, 'loginId_taken')
  }

  return c.json({ ok: true, status: 'ok' })
})

app.post('/api/auth/login', async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const loginId = String(body.loginId || '').trim()
  const password = String(body.password || '')
  if (!loginId || !password) return jsonError(c, 400, 'missing_credentials')

  const row = await c.env.DB.prepare(
    `SELECT id, role, login_id as loginId, password_hash as hash, password_salt as salt, is_active as isActive,
            must_change_password as mustChangePassword
     FROM users WHERE login_id = ? LIMIT 1`
  )
    .bind(loginId)
    .first<any>()

  if (!row) return jsonError(c, 401, 'invalid_credentials')

  const calc = await pbkdf2Hash(password, row.salt)
  if (calc !== row.hash) return jsonError(c, 401, 'invalid_credentials')

  // students must be approved
  if (row.role === 'student' && !row.isActive) {
    return jsonError(c, 403, 'pending_approval')
  }

  // Force password change if admin reset password
  if (row.role === 'student' && row.mustChangePassword) {
    // allow session but tell client
  }

  const token = await makeSession(c.env.SESSION_SECRET, {
    id: row.id,
    role: row.role,
    loginId: row.loginId,
    isActive: !!row.isActive,
  })

  setCookie(c, 'session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Lax',
    path: '/',
    maxAge: 60 * 60 * 24 * 30,
  })

  return c.json({ ok: true, role: row.role, mustChangePassword: !!row.mustChangePassword })
})

app.post('/api/auth/logout', async (c) => {
  // Cookie deletion must match attributes used when setting the cookie.
  // Some browsers keep a cookie if Path differs, so we clear a couple of common paths.
  const base = {
    secure: true,
    sameSite: 'Lax' as const,
    httpOnly: true,
  }

  deleteCookie(c, 'session', { ...base, path: '/' })
  deleteCookie(c, 'session', { ...base, path: '/api' })

  return c.json({ ok: true })
})

app.get('/api/auth/me', (c) => {
  const u = c.get('user')
  return c.json({ ok: true, user: u ?? null })
})

// -------------------- API: student --------------------

function requireStudent(c: any) {
  const u = c.get('user')
  if (!u) return null
  if (u.role !== 'student') return null
  return u
}

app.get('/api/student/progress', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const row = await c.env.DB.prepare(`SELECT state_json as stateJson, updated_at as updatedAt FROM progress WHERE user_id = ?`)
    .bind(u.id)
    .first<any>()

  return c.json({ ok: true, progress: row ? { stateJson: row.stateJson, updatedAt: row.updatedAt } : null })
})

app.put('/api/student/progress', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const stateJson = JSON.stringify(body.state ?? body)

  await c.env.DB.prepare(
    `INSERT INTO progress (user_id, state_json, updated_at)
     VALUES (?, ?, datetime('now'))
     ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json, updated_at=datetime('now')`
  )
    .bind(u.id, stateJson)
    .run()

  return c.json({ ok: true })
})

app.post('/api/student/results', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const unit = String(body.unit || '').trim()
  const questionId = body.questionId != null ? String(body.questionId) : null
  const isCorrect = body.isCorrect ? 1 : 0
  const timeMs = body.timeMs != null ? Number(body.timeMs) : null
  const answeredAt = body.answeredAt ? String(body.answeredAt) : null
  const metaJson = body.meta ? JSON.stringify(body.meta) : null

  if (!unit) return jsonError(c, 400, 'unit_required')

  await c.env.DB.prepare(
    `INSERT INTO learning_results (user_id, unit, question_id, is_correct, time_ms, answered_at, meta_json)
     VALUES (?, ?, ?, ?, ?, COALESCE(?, datetime('now')), ?)`
  )
    .bind(u.id, unit, questionId, isCorrect, timeMs, answeredAt, metaJson)
    .run()

  return c.json({ ok: true })
})

// -------------------- API: admin --------------------

function requireAdmin(c: any) {
  const u = c.get('user')
  if (!u) return null
  if (u.role !== 'admin') return null
  return u
}

app.get('/api/admin/pending', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const res = await c.env.DB.prepare(
    `SELECT id, login_id as loginId, name, grade, class_name as className, created_at as createdAt, disabled_reason as disabledReason
     FROM users WHERE role='student' AND is_active=0
     ORDER BY created_at DESC`
  ).all<any>()

  return c.json({ ok: true, users: res.results })
})

app.get('/api/admin/users', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const grade = c.req.query('grade')
  const className = c.req.query('class')

  const cond: string[] = [`role='student'`]
  const binds: any[] = []

  if (grade) {
    cond.push('grade = ?')
    binds.push(Number(grade))
  }
  if (className) {
    cond.push('class_name = ?')
    binds.push(String(className))
  }

  const sql = `SELECT id, login_id as loginId, name, grade, class_name as className, is_active as isActive, disabled_reason as disabledReason, created_at as createdAt
               FROM users WHERE ${cond.join(' AND ')} ORDER BY grade ASC, class_name ASC, name ASC`

  const res = await c.env.DB.prepare(sql).bind(...binds).all<any>()
  return c.json({ ok: true, users: res.results })
})

app.post('/api/admin/approve/:id', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const id = c.req.param('id')
  await c.env.DB.prepare(`UPDATE users SET is_active=1, disabled_reason=NULL WHERE id=? AND role='student'`).bind(id).run()
  return c.json({ ok: true })
})

app.post('/api/admin/disable/:id', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const id = c.req.param('id')
  const body = await c.req.json().catch(() => ({}))
  const reason = body?.reason ? String(body.reason).slice(0, 200) : null
  await c.env.DB
    .prepare(`UPDATE users SET is_active=0, disabled_reason=? WHERE id=? AND role='student'`)
    .bind(reason, id)
    .run()
  return c.json({ ok: true })
})

app.post('/api/admin/reset-password/:id', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const id = c.req.param('id')
  const temp = randomHex(4) // 8 hex chars
  const salt = randomHex(16)
  const hash = await pbkdf2Hash(temp, salt)

  await c.env.DB
    .prepare(
      `UPDATE users
       SET password_hash=?, password_salt=?, password_updated_at=datetime('now'), must_change_password=1
       WHERE id=? AND role='student'`
    )
    .bind(hash, salt, id)
    .run()

  return c.json({ ok: true, tempPassword: temp })
})

app.delete('/api/admin/delete/:id', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const id = c.req.param('id')

  // 安全確認: admin自身は削除不可
  if (id === u.id) return jsonError(c, 400, 'cannot_delete_self')

  // student のみ削除可（admin アカウントは削除不可）
  const target = await c.env.DB.prepare(`SELECT role FROM users WHERE id=? LIMIT 1`).bind(id).first<any>()
  if (!target) return jsonError(c, 404, 'user_not_found')
  if (target.role !== 'student') return jsonError(c, 400, 'cannot_delete_admin')

  // 関連データも削除
  await c.env.DB.prepare(`DELETE FROM progress WHERE user_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM learning_results WHERE user_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM battle_answers WHERE user_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM users WHERE id=? AND role='student'`).bind(id).run()

  return c.json({ ok: true })
})

app.post('/api/admin/change-password', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const oldPassword = String(body.oldPassword || '')
  const newPassword = String(body.newPassword || '')
  if (!oldPassword || !newPassword) return jsonError(c, 400, 'missing_fields')
  if (newPassword.length < 8) return jsonError(c, 400, 'new_password_too_short')

  const row = await c.env.DB.prepare(`SELECT id, password_hash as hash, password_salt as salt FROM users WHERE id=? AND role='admin' LIMIT 1`)
    .bind(u.id)
    .first<any>()
  if (!row) return jsonError(c, 404, 'admin_not_found')

  const calc = await pbkdf2Hash(oldPassword, row.salt)
  if (calc !== row.hash) return jsonError(c, 401, 'invalid_old_password')

  const salt = randomHex(16)
  const hash = await pbkdf2Hash(newPassword, salt)
  await c.env.DB
    .prepare(`UPDATE users SET password_hash=?, password_salt=?, password_updated_at=datetime('now'), must_change_password=0 WHERE id=?`)
    .bind(hash, salt, u.id)
    .run()

  return c.json({ ok: true })
})

app.get('/api/admin/results', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const limit = Math.min(500, Math.max(1, Number(c.req.query('limit') || 100)))
  const from = c.req.query('from') // ISO or YYYY-MM-DD
  const to = c.req.query('to')
  const grade = c.req.query('grade')
  const className = c.req.query('class')

  const cond: string[] = []
  const binds: any[] = []

  if (from) {
    cond.push('r.answered_at >= ?')
    binds.push(from)
  }
  if (to) {
    cond.push('r.answered_at <= ?')
    binds.push(to)
  }
  if (grade) {
    cond.push('u.grade = ?')
    binds.push(Number(grade))
  }
  if (className) {
    cond.push('u.class_name = ?')
    binds.push(String(className))
  }

  const where = cond.length ? `WHERE ${cond.join(' AND ')}` : ''

  const res = await c.env.DB.prepare(
    `SELECT r.id, r.answered_at as answeredAt, r.unit, r.question_id as questionId, r.is_correct as isCorrect, r.time_ms as timeMs,
            u.login_id as loginId, u.name, u.grade, u.class_name as className
     FROM learning_results r
     JOIN users u ON u.id = r.user_id
     ${where}
     ORDER BY r.answered_at DESC
     LIMIT ?`
  )
    .bind(...binds, limit)
    .all<any>()

  return c.json({ ok: true, results: res.results })
})

app.get('/api/admin/results.csv', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const from = c.req.query('from')
  const to = c.req.query('to')
  const grade = c.req.query('grade')
  const className = c.req.query('class')

  const cond: string[] = []
  const binds: any[] = []

  if (from) {
    cond.push('r.answered_at >= ?')
    binds.push(from)
  }
  if (to) {
    cond.push('r.answered_at <= ?')
    binds.push(to)
  }
  if (grade) {
    cond.push('u.grade = ?')
    binds.push(Number(grade))
  }
  if (className) {
    cond.push('u.class_name = ?')
    binds.push(String(className))
  }

  const where = cond.length ? `WHERE ${cond.join(' AND ')}` : ''

  const res = await c.env.DB.prepare(
    `SELECT r.answered_at as answeredAt, u.grade, u.class_name as className, u.name, u.login_id as loginId,
            r.unit, r.question_id as questionId, r.is_correct as isCorrect, r.time_ms as timeMs
     FROM learning_results r
     JOIN users u ON u.id = r.user_id
     ${where}
     ORDER BY r.answered_at DESC
     LIMIT 5000`
  )
    .bind(...binds)
    .all<any>()

  const header = ['answeredAt','grade','class','name','loginId','unit','questionId','isCorrect','timeMs']
  const escape = (v: any) => {
    const s = v == null ? '' : String(v)
    if (/[\n\r",]/.test(s)) return '"' + s.replace(/"/g, '""') + '"'
    return s
  }
  const lines = [header.join(',')]
  for (const r of res.results) {
    lines.push([
      r.answeredAt,
      r.grade,
      r.className,
      r.name,
      r.loginId,
      r.unit,
      r.questionId,
      r.isCorrect,
      r.timeMs,
    ].map(escape).join(','))
  }

  return new Response(lines.join('\n'), {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': 'attachment; filename="learning_results.csv"',
    },
  })
})

// -------------------- API: realtime battle --------------------

function requireAuth(c: any) {
  const u = c.get('user')
  if (!u) return null
  return u
}

function genRoomId() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  let id = ''
  const arr = new Uint8Array(6)
  crypto.getRandomValues(arr)
  for (let i = 0; i < 6; i++) id += chars[arr[i] % chars.length]
  return id
}

// ルーム作成
app.post('/api/battle/create', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const partyJson = JSON.stringify(body.party || [])
  const hostName = String(body.name || 'プレイヤー').slice(0, 20)
  const area = String(body.area || 'rounding').slice(0, 40)
  const battleMode = String(body.battleMode || 'normal').slice(0, 10)

  // 既存の waiting ルームがあれば削除
  await c.env.DB.prepare(`DELETE FROM battle_rooms WHERE host_user_id=? AND status='waiting'`)
    .bind(u.id).run()

  let roomId = genRoomId()
  // 重複チェック（稀だが念のため）
  for (let i = 0; i < 5; i++) {
    const ex = await c.env.DB.prepare(`SELECT id FROM battle_rooms WHERE id=?`).bind(roomId).first<any>()
    if (!ex) break
    roomId = genRoomId()
  }

  await c.env.DB.prepare(`
    INSERT INTO battle_rooms (id, host_user_id, host_name, host_party_json, area, battle_mode, status, host_hp, guest_hp, host_score, guest_score, question_index)
    VALUES (?, ?, ?, ?, ?, ?, 'waiting', 100, 100, 0, 0, 0)
  `).bind(roomId, u.id, hostName, partyJson, area, battleMode).run()

  return c.json({ ok: true, roomId })
})

// ルーム参加
app.post('/api/battle/join/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const roomId = c.req.param('roomId').toUpperCase()
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const guestName = String(body.name || 'プレイヤー').slice(0, 20)
  const partyJson = JSON.stringify(body.party || [])

  const room = await c.env.DB.prepare(`SELECT * FROM battle_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return jsonError(c, 404, 'room_not_found')
  if (room.status !== 'waiting') return jsonError(c, 409, 'room_not_available')
  if (room.host_user_id === u.id) return jsonError(c, 400, 'cannot_join_own_room')

  await c.env.DB.prepare(`
    UPDATE battle_rooms SET guest_user_id=?, guest_name=?, guest_party_json=?, status='ready', updated_at=datetime('now')
    WHERE id=? AND status='waiting'
  `).bind(u.id, guestName, partyJson, roomId).run()

  // ゲストにはホストのパーティ情報を返す
  return c.json({ ok: true, roomId, hostName: room.host_name, area: room.area, battleMode: room.battle_mode, hostParty: JSON.parse(room.host_party_json || '[]') })
})

// ルーム状態取得（ポーリング用）
app.get('/api/battle/room/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const roomId = c.req.param('roomId').toUpperCase()
  const room = await c.env.DB.prepare(`SELECT * FROM battle_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return jsonError(c, 404, 'room_not_found')

  // 参加者チェック
  const isHost = room.host_user_id === u.id
  const isGuest = room.guest_user_id === u.id
  if (!isHost && !isGuest) return jsonError(c, 403, 'not_a_participant')

  // 回答状況も取得
  const answers = await c.env.DB.prepare(`
    SELECT user_id, question_index, is_correct, answered_at FROM battle_answers
    WHERE room_id=? AND question_index=?
  `).bind(roomId, room.question_index).all<any>()

  const myRole = isHost ? 'host' : 'guest'
  const opponentId = isHost ? room.guest_user_id : room.host_user_id

  const myAnswer = answers.results.find((a: any) => a.user_id === u.id)
  const oppAnswer = answers.results.find((a: any) => a.user_id === opponentId)

  return c.json({
    ok: true,
    room: {
      id: room.id,
      status: room.status,
      area: room.area,
      hostName: room.host_name,
      guestName: room.guest_name,
      questionIndex: room.question_index,
      questionJson: room.current_question_json,
      hostScore: room.host_score,
      guestScore: room.guest_score,
      hostHp: room.host_hp,
      guestHp: room.guest_hp,
      winner: room.winner,
      myRole,
      myAnswer: myAnswer ? { isCorrect: !!myAnswer.is_correct } : null,
      oppAnswered: !!oppAnswer,
      oppCorrect: oppAnswer ? !!oppAnswer.is_correct : null,
      battleMode: room.battle_mode,
      // 自分のパーティは返さない。相手のパーティを返す
      opponentParty: isHost ? (room.guest_party_json ? JSON.parse(room.guest_party_json) : null) : (room.host_party_json ? JSON.parse(room.host_party_json) : null),
      opponentName: isHost ? room.guest_name : room.host_name,
    }
  })
})

// 問題をセット（ホストのみ、ready→playing時）
app.post('/api/battle/set-question/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const roomId = c.req.param('roomId').toUpperCase()
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const room = await c.env.DB.prepare(`SELECT * FROM battle_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return jsonError(c, 404, 'room_not_found')
  if (room.host_user_id !== u.id) return jsonError(c, 403, 'host_only')
  if (room.status !== 'ready' && room.status !== 'playing') return jsonError(c, 409, 'invalid_status')

  const questionJson = JSON.stringify(body.question)
  const questionIndex = Number(body.questionIndex ?? room.question_index)

  await c.env.DB.prepare(`
    UPDATE battle_rooms
    SET current_question_json=?, question_index=?, status='playing', updated_at=datetime('now')
    WHERE id=?
  `).bind(questionJson, questionIndex, roomId).run()

  return c.json({ ok: true })
})

// 回答を送信
app.post('/api/battle/answer/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const roomId = c.req.param('roomId').toUpperCase()
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const room = await c.env.DB.prepare(`SELECT * FROM battle_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return jsonError(c, 404, 'room_not_found')
  if (room.status !== 'playing') return jsonError(c, 409, 'not_playing')

  const isHost = room.host_user_id === u.id
  const isGuest = room.guest_user_id === u.id
  if (!isHost && !isGuest) return jsonError(c, 403, 'not_a_participant')

  const isCorrect = body.isCorrect ? 1 : 0
  const answer = String(body.answer || '').slice(0, 100)
  const questionIndex = room.question_index

  // 既に回答済みなら無視
  const existing = await c.env.DB.prepare(`
    SELECT id FROM battle_answers WHERE room_id=? AND user_id=? AND question_index=?
  `).bind(roomId, u.id, questionIndex).first<any>()
  if (existing) return c.json({ ok: true, alreadyAnswered: true })

  await c.env.DB.prepare(`
    INSERT INTO battle_answers (room_id, user_id, question_index, answer, is_correct)
    VALUES (?, ?, ?, ?, ?)
  `).bind(roomId, u.id, questionIndex, answer, isCorrect).run()

  // 両者回答済みかチェック → スコア更新
  const allAnswers = await c.env.DB.prepare(`
    SELECT user_id, is_correct FROM battle_answers WHERE room_id=? AND question_index=?
  `).bind(roomId, questionIndex).all<any>()

  const hostAns = allAnswers.results.find((a: any) => a.user_id === room.host_user_id)
  const guestAns = allAnswers.results.find((a: any) => a.user_id === room.guest_user_id)

  let newHostScore = room.host_score
  let newGuestScore = room.guest_score
  let newHostHp = room.host_hp
  let newGuestHp = room.guest_hp
  let bothAnswered = false
  let newStatus = room.status
  let winner = room.winner

  if (hostAns && guestAns) {
    bothAnswered = true
    const hostCorrect = !!hostAns.is_correct
    const guestCorrect = !!guestAns.is_correct

    if (hostCorrect && !guestCorrect) {
      newHostScore++
      newGuestHp = Math.max(0, newGuestHp - 20)
    } else if (!hostCorrect && guestCorrect) {
      newGuestScore++
      newHostHp = Math.max(0, newHostHp - 20)
    }
    // 両方正解/不正解の場合はHPダメージなし

    // 5問ごと or HPが0になったら終了
    const nextQIndex = questionIndex + 1
    const maxQuestions = 5
    if (newHostHp <= 0 || newGuestHp <= 0 || nextQIndex >= maxQuestions) {
      newStatus = 'finished'
      if (newHostScore > newGuestScore) winner = 'host'
      else if (newGuestScore > newHostScore) winner = 'guest'
      else winner = 'draw'
    }

    await c.env.DB.prepare(`
      UPDATE battle_rooms
      SET host_score=?, guest_score=?, host_hp=?, guest_hp=?, status=?, winner=?, updated_at=datetime('now')
      WHERE id=?
    `).bind(newHostScore, newGuestScore, newHostHp, newGuestHp, newStatus, winner, roomId).run()
  }

  return c.json({
    ok: true,
    bothAnswered,
    hostScore: newHostScore,
    guestScore: newGuestScore,
    hostHp: newHostHp,
    guestHp: newGuestHp,
    status: newStatus,
    winner,
  })
})

// ルーム終了・退出
app.post('/api/battle/leave/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const roomId = c.req.param('roomId').toUpperCase()
  const room = await c.env.DB.prepare(`SELECT * FROM battle_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return c.json({ ok: true })

  const isHost = room.host_user_id === u.id
  if (isHost) {
    // ホストが抜けたらルーム消滅
    await c.env.DB.prepare(`DELETE FROM battle_rooms WHERE id=?`).bind(roomId).run()
  } else {
    // ゲストが抜けたらwaiting状態に戻す
    await c.env.DB.prepare(`
      UPDATE battle_rooms SET guest_user_id=NULL, guest_name=NULL, guest_party_json=NULL,
      status='waiting', current_question_json=NULL, question_index=0,
      host_score=0, guest_score=0, host_hp=100, guest_hp=100, winner=NULL, updated_at=datetime('now')
      WHERE id=?
    `).bind(roomId).run()
  }
  return c.json({ ok: true })
})

// 古いルームの定期クリーンアップ（GETのついでに呼ぶ）
app.delete('/api/battle/cleanup', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  await c.env.DB.prepare(`
    DELETE FROM battle_rooms WHERE created_at < datetime('now', '-2 hours')
  `).run()
  return c.json({ ok: true })
})

// -------------------- API: rt (realtime friend battle v2) --------------------
// rt_rooms / rt_events テーブルを使った野生バトル/ジムバトル形式のリアルタイム対戦

// ルーム作成
app.post('/api/rt/create', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const hostName = String(body.name || 'プレイヤー').slice(0, 20)
  const partyJson = JSON.stringify(body.party || [])
  const area = String(body.area || 'rounding').slice(0, 40)
  const battleType = (body.battleType === 'gym') ? 'gym' : 'normal'

  // 既存 waiting ルームを削除
  await c.env.DB.prepare(`DELETE FROM rt_rooms WHERE host_user_id=? AND status='waiting'`).bind(u.id).run()

  let roomId = genRoomId()
  for (let i = 0; i < 5; i++) {
    const ex = await c.env.DB.prepare(`SELECT id FROM rt_rooms WHERE id=?`).bind(roomId).first<any>()
    if (!ex) break
    roomId = genRoomId()
  }

  await c.env.DB.prepare(`
    INSERT INTO rt_rooms (id, host_user_id, host_name, host_party_json, host_area, host_hp, host_ready, guest_hp, guest_ready, battle_type, status)
    VALUES (?, ?, ?, ?, ?, 100, 0, 100, 0, ?, 'waiting')
  `).bind(roomId, u.id, hostName, partyJson, area, battleType).run()

  return c.json({ ok: true, roomId })
})

// ルーム参加
app.post('/api/rt/join/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const roomId = c.req.param('roomId').toUpperCase()
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const guestName = String(body.name || 'プレイヤー').slice(0, 20)
  const partyJson = JSON.stringify(body.party || [])

  const room = await c.env.DB.prepare(`SELECT * FROM rt_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return jsonError(c, 404, 'room_not_found')
  if (room.status !== 'waiting') return jsonError(c, 409, 'room_not_available')
  if (room.host_user_id === u.id) return jsonError(c, 400, 'cannot_join_own_room')

  await c.env.DB.prepare(`
    UPDATE rt_rooms SET guest_user_id=?, guest_name=?, guest_party_json=?, status='ready', updated_at=datetime('now')
    WHERE id=? AND status='waiting'
  `).bind(u.id, guestName, partyJson, roomId).run()

  const hostParty = JSON.parse(room.host_party_json || '[]')
  return c.json({
    ok: true,
    roomId,
    hostName: room.host_name,
    area: room.host_area,
    battleType: room.battle_type,
    hostParty,
  })
})

// ルーム状態取得（ポーリング用）
app.get('/api/rt/room/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const roomId = c.req.param('roomId').toUpperCase()

  const room = await c.env.DB.prepare(`SELECT * FROM rt_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return jsonError(c, 404, 'room_not_found')

  const isHost = room.host_user_id === u.id
  const isGuest = room.guest_user_id === u.id
  if (!isHost && !isGuest) return jsonError(c, 403, 'not_a_participant')

  // 未読イベント（ポーリング用：相手からのダメージイベント）
  // クエリパラメータ after=lastEventId で差分取得
  const afterId = Number(c.req.query('after') || 0)
  const events = await c.env.DB.prepare(`
    SELECT id, user_id, event_type, value, monster_id, created_at FROM rt_events
    WHERE room_id=? AND id > ?
    ORDER BY id ASC LIMIT 50
  `).bind(roomId, afterId).all<any>()

  const myRole = isHost ? 'host' : 'guest'
  const opponentParty = isHost
    ? (room.guest_party_json ? JSON.parse(room.guest_party_json) : null)
    : JSON.parse(room.host_party_json || '[]')

  return c.json({
    ok: true,
    room: {
      id: room.id,
      status: room.status,
      battleType: room.battle_type,
      area: room.host_area,
      hostName: room.host_name,
      guestName: room.guest_name,
      hostHp: room.host_hp,
      guestHp: room.guest_hp,
      hostReady: !!room.host_ready,
      guestReady: !!room.guest_ready,
      winner: room.winner,
      myRole,
      opponentParty,
    },
    events: events.results,
  })
})

// Ready送信（両者がreadyになったらplaying開始）
app.post('/api/rt/ready/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const roomId = c.req.param('roomId').toUpperCase()

  const room = await c.env.DB.prepare(`SELECT * FROM rt_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return jsonError(c, 404, 'room_not_found')

  const isHost = room.host_user_id === u.id
  const isGuest = room.guest_user_id === u.id
  if (!isHost && !isGuest) return jsonError(c, 403, 'not_a_participant')

  if (isHost) {
    await c.env.DB.prepare(`UPDATE rt_rooms SET host_ready=1, updated_at=datetime('now') WHERE id=?`).bind(roomId).run()
  } else {
    await c.env.DB.prepare(`UPDATE rt_rooms SET guest_ready=1, updated_at=datetime('now') WHERE id=?`).bind(roomId).run()
  }

  // 両者 ready なら playing へ（status が 'ready' または 'waiting' でも対応）
  const updated = await c.env.DB.prepare(`SELECT * FROM rt_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (updated && updated.host_ready && updated.guest_ready && (updated.status === 'ready' || updated.status === 'waiting')) {
    await c.env.DB.prepare(`UPDATE rt_rooms SET status='playing', updated_at=datetime('now') WHERE id=?`).bind(roomId).run()
  }

  return c.json({ ok: true })
})

// ダメージイベント送信（正解時に相手HPを削る）
app.post('/api/rt/damage/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const roomId = c.req.param('roomId').toUpperCase()
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const room = await c.env.DB.prepare(`SELECT * FROM rt_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return jsonError(c, 404, 'room_not_found')
  if (room.status !== 'playing') return jsonError(c, 409, 'not_playing')

  const isHost = room.host_user_id === u.id
  const isGuest = room.guest_user_id === u.id
  if (!isHost && !isGuest) return jsonError(c, 403, 'not_a_participant')

  const damage = Math.max(0, Math.min(9999, Number(body.damage || 0)))
  const monsterId = Number(body.monsterId || 0)
  const eventType = String(body.eventType || 'damage').slice(0, 20) // 'damage'|'faint'|'win'|'lose'

  // イベント記録
  const result = await c.env.DB.prepare(`
    INSERT INTO rt_events (room_id, user_id, event_type, value, monster_id)
    VALUES (?, ?, ?, ?, ?)
  `).bind(roomId, u.id, eventType, damage, monsterId).run()

  const newEventId = (result.meta as any).last_row_id

  // HPを更新（送信者が攻撃 → 相手のHPを減らす）
  let newHostHp = room.host_hp
  let newGuestHp = room.guest_hp

  if (isHost) {
    newGuestHp = Math.max(0, newGuestHp - damage)
  } else {
    newHostHp = Math.max(0, newHostHp - damage)
  }

  let newStatus = room.status
  let winner = room.winner

  if (eventType === 'win') {
    newStatus = 'finished'
    winner = isHost ? 'host' : 'guest'
  } else if (eventType === 'draw') {
    newStatus = 'finished'
    winner = 'draw'
  }

  await c.env.DB.prepare(`
    UPDATE rt_rooms SET host_hp=?, guest_hp=?, status=?, winner=?, updated_at=datetime('now') WHERE id=?
  `).bind(newHostHp, newGuestHp, newStatus, winner, roomId).run()

  return c.json({ ok: true, eventId: newEventId, hostHp: newHostHp, guestHp: newGuestHp })
})

// ルーム退出
app.post('/api/rt/leave/:roomId', async (c) => {
  const u = requireAuth(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const roomId = c.req.param('roomId').toUpperCase()

  const room = await c.env.DB.prepare(`SELECT * FROM rt_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return c.json({ ok: true })

  const isHost = room.host_user_id === u.id
  if (isHost) {
    await c.env.DB.prepare(`DELETE FROM rt_rooms WHERE id=?`).bind(roomId).run()
  } else {
    // ゲストが抜けた → waiting に戻す
    await c.env.DB.prepare(`
      UPDATE rt_rooms SET guest_user_id=NULL, guest_name=NULL, guest_party_json=NULL,
      status='waiting', host_hp=100, guest_hp=100, host_ready=0, guest_ready=0, winner=NULL,
      updated_at=datetime('now') WHERE id=?
    `).bind(roomId).run()
  }
  return c.json({ ok: true })
})

// クリーンアップ
app.delete('/api/rt/cleanup', async (c) => {
  await c.env.DB.prepare(`DELETE FROM rt_rooms WHERE created_at < datetime('now', '-2 hours')`).run()
  await c.env.DB.prepare(`DELETE FROM rt_events WHERE created_at < datetime('now', '-2 hours')`).run()
  return c.json({ ok: true })
})

// -------------------- Pages (simple HTML endpoints) --------------------

// Serve the game HTML (built into dist/index.html as an asset)
app.get('/', async (c) => {
  // Avoid fetch('/') recursion when _routes includes "/*" and excludes "/index.html".
  // Serve the built HTML from the bundled asset in dist/index.html.
  // @ts-ignore - Cloudflare Pages provides a static assets binding.
  const asset = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/index.html')))
  if (asset) return asset
  return c.text('index.html not found', 404)
})


app.get('/logout', async (c) => {
  // GET endpoint for manual logout (admin can use URL directly)
  const base = {
    secure: true,
    sameSite: 'Lax' as const,
    httpOnly: true,
  }
  deleteCookie(c, 'session', { ...base, path: '/' })
  deleteCookie(c, 'session', { ...base, path: '/api' })
  return c.redirect('/login')
})

app.get('/login', (c) => {
  return c.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>教材ログイン（LearningBM）</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="min-h-screen bg-slate-100 p-4">
    <div class="max-w-md mx-auto bg-white rounded-xl shadow p-6">
      <h1 class="text-xl font-bold mb-1">教材ログイン</h1>
      <p class="text-xs text-slate-600 mb-4">学習記録のためにログインしてください。</p>
      <div class="space-y-3">
        <input id="loginId" class="w-full border p-2 rounded" placeholder="ログインID"/>
        <input id="password" type="password" class="w-full border p-2 rounded" placeholder="パスワード"/>
        <button id="btn" class="w-full bg-blue-600 text-white rounded p-2">ログイン</button>
        <p id="msg" class="text-sm text-red-600"></p>
        <a class="text-sm text-blue-700 underline" href="/signup">新規登録</a>
      </div>
    </div>
    <script>
      const msg = document.getElementById('msg');
      document.getElementById('btn').onclick = async () => {
        msg.textContent='';
        const loginId = document.getElementById('loginId').value.trim();
        const password = document.getElementById('password').value;
        const r = await fetch('/api/auth/login',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({loginId,password})});
        const j = await r.json().catch(()=>({}));
        if(!r.ok){
          const errMap = {
            invalid_credentials: 'IDまたはパスワードが間違っています',
            pending_approval: '承認待ちです。先生が承認するまでお待ちください',
            missing_credentials: 'IDとパスワードを入力してください',
          };
          msg.textContent = errMap[j.error] || (j.error || 'ログインに失敗しました');
          return;
        }
        location.href = '/';
      };
    </script>
  </body></html>`)
})

app.get('/signup', (c) => {
  return c.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>新規登録</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="min-h-screen bg-slate-100 p-4">
    <div class="max-w-md mx-auto bg-white rounded-xl shadow p-6">
      <h1 class="text-xl font-bold mb-4">児童 新規登録</h1>
      <div class="space-y-3">
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">名前</label>
          <input id="name" class="w-full border p-2 rounded" placeholder="例：山田 太郎"/>
        </div>
        <div class="flex gap-2">
          <div class="flex-1">
            <label class="text-sm font-bold text-gray-700 mb-1 block">学年</label>
            <select id="grade" class="w-full border p-2 rounded bg-white">
              <option value="">選択してください</option>
              <option value="1">1年</option>
              <option value="2">2年</option>
              <option value="3">3年</option>
              <option value="4">4年</option>
              <option value="5">5年</option>
              <option value="6">6年</option>
            </select>
          </div>
          <div class="flex-1">
            <label class="text-sm font-bold text-gray-700 mb-1 block">クラス</label>
            <input id="className" class="w-full border p-2 rounded" placeholder="例：1組 / A"/>
          </div>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">ログインID（自分で決める）</label>
          <input id="loginId" class="w-full border p-2 rounded" placeholder="半角英数字 3文字以上"/>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">パスワード</label>
          <input id="password" type="password" class="w-full border p-2 rounded" placeholder="6文字以上"/>
        </div>
        <button id="btn" class="w-full bg-green-600 text-white rounded p-2 font-bold">登録する</button>
        <p id="msg" class="text-sm"></p>
        <a class="text-sm text-blue-700 underline" href="/login">ログインへ</a>
      </div>
    </div>
    <script>
      const msg = document.getElementById('msg');
      const errMap = {
        loginId_too_short: 'ログインIDは3文字以上にしてください',
        loginId_taken: 'このログインIDはすでに使われています',
        password_too_short: 'パスワードは6文字以上にしてください',
        name_required: '名前を入力してください',
        grade_invalid: '学年を選択してください',
        class_required: 'クラスを入力してください',
        invalid_json: '入力内容に問題があります',
      };
      document.getElementById('btn').onclick = async () => {
        msg.textContent='';
        const gradeVal = document.getElementById('grade').value;
        const payload = {
          name: document.getElementById('name').value.trim(),
          grade: gradeVal ? Number(gradeVal) : NaN,
          className: document.getElementById('className').value.trim(),
          loginId: document.getElementById('loginId').value.trim(),
          password: document.getElementById('password').value,
        };
        // クライアント側バリデーション
        if(!payload.name){ msg.textContent='名前を入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!gradeVal){ msg.textContent='学年を選択してください'; msg.className='text-sm text-red-600'; return; }
        if(!payload.className){ msg.textContent='クラスを入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!payload.loginId || payload.loginId.length < 3){ msg.textContent='ログインIDは3文字以上にしてください'; msg.className='text-sm text-red-600'; return; }
        if(!payload.password || payload.password.length < 6){ msg.textContent='パスワードは6文字以上にしてください'; msg.className='text-sm text-red-600'; return; }

        document.getElementById('btn').disabled = true;
        const r = await fetch('/api/auth/signup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
        const j = await r.json().catch(()=>({}));
        if(!r.ok){
          msg.textContent = errMap[j.error] || (j.error || '登録に失敗しました');
          msg.className='text-sm text-red-600';
          document.getElementById('btn').disabled = false;
          return;
        }
        // 登録成功 → 承認待ちメッセージを表示してログイン画面へ
        msg.textContent = '登録しました！先生が承認するまでお待ちください。';
        msg.className='text-sm text-green-700';
        setTimeout(()=>{ location.href='/login'; }, 3000);
      };
    </script>
  </body></html>`)
})

app.get('/admin', (c) => {
  return c.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>学習記録 管理（LearningBM）</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="min-h-screen bg-slate-100 p-4">
    <div class="max-w-5xl mx-auto space-y-4">
      <div class="bg-white rounded-xl shadow p-6 flex items-center justify-between">
        <h1 class="text-xl font-bold">学習記録 管理</h1>
        <div class="flex items-center gap-3">
          <a href="/" class="text-sm px-3 py-1 rounded bg-indigo-100 hover:bg-indigo-200 text-indigo-700 font-bold transition">🌏 児童用ページへ</a>
          <button id="logout" class="text-sm px-3 py-1 rounded bg-gray-200 hover:bg-red-100 hover:text-red-700 text-gray-600 font-bold transition">ログアウト</button>
        </div>
      </div>

      <div class="grid md:grid-cols-2 gap-4">
        <div class="bg-white rounded-xl shadow p-6">
          <h2 class="font-bold mb-2">管理者パスワード変更</h2>
          <div class="space-y-2">
            <input id="oldAdminPw" type="password" class="w-full border p-2 rounded" placeholder="現在のパスワード" />
            <input id="newAdminPw" type="password" class="w-full border p-2 rounded" placeholder="新しいパスワード（8文字以上）" />
            <button id="changeAdminPwBtn" class="bg-indigo-600 text-white rounded px-3 py-2">変更</button>
            <p id="adminPwMsg" class="text-sm"></p>
          </div>
        </div>

        <div class="bg-white rounded-xl shadow p-6">
          <h2 class="font-bold mb-2">CSVエクスポート</h2>
          <div class="grid grid-cols-2 gap-2 text-sm">
            <input id="csvFrom" class="border p-2 rounded" placeholder="from (YYYY-MM-DD)" />
            <input id="csvTo" class="border p-2 rounded" placeholder="to (YYYY-MM-DD)" />
            <input id="csvGrade" class="border p-2 rounded" placeholder="学年(1-6)" />
            <input id="csvClass" class="border p-2 rounded" placeholder="クラス" />
          </div>
          <button id="csvBtn" class="mt-2 bg-emerald-600 text-white rounded px-3 py-2">CSVダウンロード</button>
        </div>
      </div>

      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">承認待ち / 停止中</h2>
        <div id="pending" class="space-y-2 text-sm"></div>
      </div>

      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">児童一覧</h2>
        <div class="flex flex-wrap gap-2 mb-2 text-sm">
          <input id="filterGrade" class="border p-2 rounded" placeholder="学年" />
          <input id="filterClass" class="border p-2 rounded" placeholder="クラス" />
          <button id="filterBtn" class="bg-slate-700 text-white rounded px-3">絞り込み</button>
          <button id="reloadBtn" class="bg-slate-200 rounded px-3">更新</button>
        </div>
        <div id="users" class="space-y-2 text-sm"></div>
      </div>

      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">直近の学習ログ</h2>
        <div id="results" class="space-y-2 text-sm"></div>
      </div>
    </div>

    <script>
      async function api(path, opt){
        const r = await fetch(path, opt);
        const isCsv = String(path||'').includes('.csv');
        if(isCsv) return r;
        const j = await r.json().catch(()=>({}));
        if(!r.ok) throw new Error(j.error || 'error');
        return j;
      }

      document.getElementById('logout').onclick = async () => {
        await fetch('/api/auth/logout',{method:'POST'});
        location.href='/login';
      };

      document.getElementById('changeAdminPwBtn').onclick = async () => {
        const msg = document.getElementById('adminPwMsg');
        msg.textContent='';
        try{
          const oldPassword = document.getElementById('oldAdminPw').value;
          const newPassword = document.getElementById('newAdminPw').value;
          await api('/api/admin/change-password',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({oldPassword,newPassword})});
          msg.textContent='変更しました';
          msg.className='text-sm text-green-700';
          document.getElementById('oldAdminPw').value='';
          document.getElementById('newAdminPw').value='';
        }catch(e){
          msg.textContent=String(e.message||e);
          msg.className='text-sm text-red-700';
        }
      };

      document.getElementById('csvBtn').onclick = async () => {
        const from = document.getElementById('csvFrom').value.trim();
        const to = document.getElementById('csvTo').value.trim();
        const grade = document.getElementById('csvGrade').value.trim();
        const cls = document.getElementById('csvClass').value.trim();
        const qs = new URLSearchParams();
        if(from) qs.set('from', from);
        if(to) qs.set('to', to);
        if(grade) qs.set('grade', grade);
        if(cls) qs.set('class', cls);
        location.href = '/api/admin/results.csv?' + qs.toString();
      };

      async function renderPending(){
        const p = await api('/api/admin/pending');
        const wrap = document.getElementById('pending');
        wrap.innerHTML='';
        if(!p.users.length){ wrap.textContent='承認待ち/停止中はありません'; return; }
        for(const u of p.users){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.textContent = u.grade + '年 ' + u.className + ' / ' + u.name + '（' + u.loginId + '）' + (u.disabledReason ? (' 停止理由: '+u.disabledReason) : '');
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2';

          const approve = document.createElement('button');
          approve.className='bg-blue-600 text-white rounded px-3 py-1';
          approve.textContent='承認/再開';
          approve.onclick = async ()=>{ await api('/api/admin/approve/'+u.id,{method:'POST'}); await loadAll(); };
          right.appendChild(approve);

          const disable = document.createElement('button');
          disable.className='bg-amber-600 text-white rounded px-3 py-1';
          disable.textContent='停止';
          disable.onclick = async ()=>{ const reason=prompt('停止理由(任意)'); await api('/api/admin/disable/'+u.id,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({reason})}); await loadAll(); };
          right.appendChild(disable);

          const reset = document.createElement('button');
          reset.className='bg-slate-800 text-white rounded px-3 py-1';
          reset.textContent='PWリセット';
          reset.onclick = async ()=>{ const r=await api('/api/admin/reset-password/'+u.id,{method:'POST'}); alert('仮パスワード: '+r.tempPassword+'\\n(次回ログインで変更させてください)'); };
          right.appendChild(reset);

          const del = document.createElement('button');
          del.className='bg-red-600 text-white rounded px-3 py-1';
          del.textContent='削除';
          del.onclick = async ()=>{
            if(!confirm(u.name+'（'+u.loginId+'）のアカウントを完全に削除しますか？\\n学習記録もすべて削除されます。この操作は取り消せません。')) return;
            await api('/api/admin/delete/'+u.id,{method:'DELETE'});
            await loadAll();
          };
          right.appendChild(del);

          div.appendChild(right);
          wrap.appendChild(div);
        }
      }

      async function renderUsers(){
        const grade = document.getElementById('filterGrade').value.trim();
        const cls = document.getElementById('filterClass').value.trim();
        const qs = new URLSearchParams();
        if(grade) qs.set('grade', grade);
        if(cls) qs.set('class', cls);
        const u = await api('/api/admin/users?' + qs.toString());
        const wrap = document.getElementById('users');
        wrap.innerHTML='';
        if(!u.users.length){ wrap.textContent='該当なし'; return; }
        for(const x of u.users){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.textContent = x.grade + '年 ' + x.className + ' / ' + x.name + '（' + x.loginId + '）' + (x.isActive? '' : ' [停止/未承認]');
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2';

          const toggle = document.createElement('button');
          toggle.className = x.isActive ? 'bg-amber-600 text-white rounded px-3 py-1' : 'bg-blue-600 text-white rounded px-3 py-1';
          toggle.textContent = x.isActive ? '停止' : '再開';
          toggle.onclick = async ()=>{
            if(x.isActive){ const reason=prompt('停止理由(任意)'); await api('/api/admin/disable/'+x.id,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({reason})}); }
            else { await api('/api/admin/approve/'+x.id,{method:'POST'}); }
            await loadAll();
          };
          right.appendChild(toggle);

          const reset = document.createElement('button');
          reset.className='bg-slate-800 text-white rounded px-3 py-1';
          reset.textContent='PWリセット';
          reset.onclick = async ()=>{ const r=await api('/api/admin/reset-password/'+x.id,{method:'POST'}); alert('仮パスワード: '+r.tempPassword+'\\n(次回ログインで変更させてください)'); };
          right.appendChild(reset);

          const del = document.createElement('button');
          del.className='bg-red-600 text-white rounded px-3 py-1';
          del.textContent='削除';
          del.onclick = async ()=>{
            if(!confirm(x.name+'（'+x.loginId+'）のアカウントを完全に削除しますか？\\n学習記録もすべて削除されます。この操作は取り消せません。')) return;
            await api('/api/admin/delete/'+x.id,{method:'DELETE'});
            await loadAll();
          };
          right.appendChild(del);

          div.appendChild(right);
          wrap.appendChild(div);
        }
      }

      async function renderResults(){
        const r = await api('/api/admin/results?limit=50');
        const rw = document.getElementById('results');
        rw.innerHTML='';
        if(!r.results.length){ rw.textContent='ログはまだありません'; return; }
        for(const x of r.results){
          const div = document.createElement('div');
          div.className='border rounded p-2';
          div.textContent = x.answeredAt + ' ' + x.grade + '年' + x.className + ' ' + x.name + '(' + x.loginId + ') unit=' + x.unit + ' q=' + (x.questionId ?? '') + ' correct=' + x.isCorrect + ' time=' + (x.timeMs ?? '');
          rw.appendChild(div);
        }
      }

      async function loadAll(){
        await renderPending();
        await renderUsers();
        await renderResults();
      }

      document.getElementById('filterBtn').onclick = loadAll;
      document.getElementById('reloadBtn').onclick = loadAll;

      // auth check
      (async ()=>{
        const me = await fetch('/api/auth/me');
        const j = await me.json().catch(()=>({}));
        if(!j.user || j.user.role!=='admin'){ location.href='/login'; return; }
        loadAll();
      })();
    </script>
  </body></html>`)
})

export default app
