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
  user?: { id: string; role: 'student' | 'admin' | 'teacher'; loginId: string; isActive: boolean }
}

const app = new Hono<{ Bindings: Bindings; Variables: Variables }>()

// Global error handler (to avoid silent 500)
app.onError((err, c) => {
  console.error('Unhandled error:', err)
  const msg = err instanceof Error ? `${err.name}: ${err.message}` : String(err)
  return c.text(`Internal Error\n${msg}`, 500)
})

// CORS: same-origin + pages.dev
app.use('/api/*', cors({
  origin: (origin) => {
    if (!origin) return '*'
    if (origin.endsWith('.pages.dev') || origin === 'http://localhost:8788' || origin === 'http://127.0.0.1:8788') return origin
    return null as any
  },
  credentials: true,
}))

// --- Simple in-memory rate limiter (per-isolate) ---
const _rl = new Map<string, { count: number; resetAt: number }>()
let _rlLastCleanup = 0
function rateLimit(key: string, maxReqs: number, windowSec: number): boolean {
  const now = Date.now()
  // Lazy cleanup: purge stale entries every 60s (instead of setInterval which is banned in global scope)
  if (now - _rlLastCleanup > 60_000) {
    _rlLastCleanup = now
    for (const [k, v] of _rl) { if (now > v.resetAt) _rl.delete(k) }
  }
  let entry = _rl.get(key)
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + windowSec * 1000 }
    _rl.set(key, entry)
  }
  entry.count++
  if (entry.count > maxReqs) return false // blocked
  return true // allowed
}

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

  // Session expiration: 30 days
  const SESSION_MAX_AGE = 30 * 24 * 60 * 60
  if (sess.iat && (Math.floor(Date.now() / 1000) - sess.iat) > SESSION_MAX_AGE) {
    deleteCookie(c, 'session', { path: '/' })
    return next() // expired, treat as unauthenticated
  }

  c.set('user', {
    id: sess.id,
    role: sess.role,
    loginId: sess.loginId,
    isActive: !!sess.isActive,
  })

  return next()
})

// -------------------- NGワードフィルター --------------------
const _NG_NAME_PATTERNS = [
  /[ちチﾁ][んンﾝ][こコﾞぽポ]/i, /[まマ][んンﾝ][こコ]/i, /[おオ][っッ][ぱパ][いイ]/i,
  /[ちチ][んンﾝ][ちチ][んンﾝ]/i, /[うウ][んンﾝ][こコ][ちチ]/i, /[うウ][んンﾝ][ちチ]/i,
  /[きキ][んンﾝ][たタ][まマ]/i, /[おオ][なナ][にニ]/i,
  /[しシ][ねネ]/, /[こコ][ろロ][すス]/, /死ね/, /殺す/, /殺/, /糞/, /クソ/,
  /ころす/, /しね[よ！]?$/, /ばか[やァ]?ろう/, /あほ/,
  /セックス/, /sex/i, /fuck/i, /shit/i, /dick/i, /pussy/i, /bitch/i,
  /エロ/, /えろ/, /ペニス/, /ヴァギナ/, /レイプ/,
  /うんこ/, /ウンコ/, /おしり/, /ケツ/
]
function isNgName(name: string): boolean {
  const s = (name || '').trim()
  return _NG_NAME_PATTERNS.some(r => r.test(s))
}

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
  if (isNgName(name)) return jsonError(c, 400, 'name_inappropriate')
  if (!Number.isFinite(grade) || grade < 1 || grade > 12) return jsonError(c, 400, 'grade_invalid')

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

  // まず users テーブルを検索
  let row = await c.env.DB.prepare(
    `SELECT id, role, login_id as loginId, password_hash as hash, password_salt as salt, is_active as isActive,
            must_change_password as mustChangePassword
     FROM users WHERE login_id = ? LIMIT 1`
  )
    .bind(loginId)
    .first<any>()

  // 見つからなければ teacher_accounts も検索
  if (!row) {
    const tRow = await c.env.DB.prepare(
      `SELECT id, 'teacher' as role, login_id as loginId, password_hash as hash, password_salt as salt,
              is_active as isActive, 0 as mustChangePassword
       FROM teacher_accounts WHERE login_id = ? LIMIT 1`
    ).bind(loginId).first<any>()
    if (tRow) row = tRow
  }

  if (!row) return jsonError(c, 401, 'invalid_credentials')

  const calc = await pbkdf2Hash(password, row.salt)
  if (calc !== row.hash) return jsonError(c, 401, 'invalid_credentials')

  // students/teachers must be approved
  if ((row.role === 'student' || row.role === 'teacher') && !row.isActive) {
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
    iat: Math.floor(Date.now() / 1000),
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

app.get('/api/auth/me', async (c) => {
  const u = c.get('user')
  if (!u) return c.json({ ok: true, user: null })
  if (u.role === 'teacher') {
    const row = await c.env.DB.prepare(`SELECT name, school FROM teacher_accounts WHERE id = ? LIMIT 1`).bind(u.id).first<any>()
    return c.json({ ok: true, user: { ...u, name: row?.name, school: row?.school, grade: null } })
  }
  // grade は DB から取得 + 4月1日自動進級チェック
  let grade: number | null = null
  try {
    const row = await c.env.DB.prepare(`SELECT grade, created_at FROM users WHERE id = ? LIMIT 1`).bind(u.id).first<any>()
    if (row) {
      grade = row.grade ?? null
      // 自動進級: 4月1日を過ぎていたら学年を上げる（最大6年）
      if (grade !== null && grade < 6 && u.role === 'student') {
        const now = new Date()
        const currentYear = now.getUTCFullYear()
        const currentMonth = now.getUTCMonth() + 1 // 1-12
        // 登録年度を推定: 4月以降なら今年度、3月以前なら前年度
        const createdAt = new Date(row.created_at)
        const createdYear = createdAt.getUTCFullYear()
        const createdMonth = createdAt.getUTCMonth() + 1
        const createdFiscalYear = createdMonth >= 4 ? createdYear : createdYear - 1
        const currentFiscalYear = currentMonth >= 4 ? currentYear : currentYear - 1
        const yearsPassed = currentFiscalYear - createdFiscalYear
        if (yearsPassed > 0) {
          const newGrade = Math.min(6, (row.grade as number) + yearsPassed)
          if (newGrade !== row.grade) {
            await c.env.DB.prepare(`UPDATE users SET grade=? WHERE id=?`).bind(newGrade, u.id).run()
            grade = newGrade
          }
        }
      }
    }
  } catch(e) {}
  return c.json({ ok: true, user: { ...u, grade } })
})

// -------------------- API: student --------------------

function requireStudent(c: any) {
  const u = c.get('user')
  if (!u) return null
  // admin and teacher can also play the game
  if (u.role !== 'student' && u.role !== 'admin' && u.role !== 'teacher') return null
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

  // 教師はteacher_accountsテーブルにいるためprogress(FK→users)には保存不可
  // 教師・超大サイズは正常終了で返す（ゲームは続けられる）
  if (u.role === 'teacher') return c.json({ ok: true })
  if (stateJson.length > 1_000_000) return c.json({ ok: true })

  try {
    await c.env.DB.prepare(
      `INSERT INTO progress (user_id, state_json, updated_at)
       VALUES (?, ?, datetime('now'))
       ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json, updated_at=datetime('now')`
    )
      .bind(u.id, stateJson)
      .run()
  } catch (e: any) {
    console.error('[progress] DB error:', e?.message || e)
    return jsonError(c, 500, 'db_error')
  }

  // ランキング統計を非同期で更新
  try {
    const userRow = await c.env.DB.prepare(`SELECT name, grade FROM users WHERE id=? LIMIT 1`).bind(u.id).first<any>()
    const stats = extractRankingStats(stateJson, userRow?.name || '')
    const grade = Number(userRow?.grade || 0)
    const weekStart = getCurrentWeekStart()

    // 既存データを取得：週が変わったらベースラインを現在の累計値でリセット
    const existing = await c.env.DB.prepare(
      `SELECT week_start, correct_count, total_level, battle_power, pokedex_count, wild_win_streak, ranking_points FROM ranking_stats WHERE user_id=? LIMIT 1`
    ).bind(u.id).first<any>()

    let baseCorrect = 0, baseLevel = 0, basePower = 0, baseDex = 0, baseStreak = 0, baseRkPts = 0
    if (existing && existing.week_start === weekStart) {
      // 同じ週 → ベースラインは既存のまま（UPDATEで変わらない）
      // ここでは新規INSERT時のみ使うのでダミー
    } else if (existing) {
      // 週が変わった → 前回の累計値を新しいベースラインに
      baseCorrect = Number(existing.correct_count || 0)
      baseLevel = Number(existing.total_level || 0)
      basePower = Number(existing.battle_power || 0)
      baseDex = Number(existing.pokedex_count || 0)
      baseStreak = Number(existing.wild_win_streak || 0)
      baseRkPts = Number(existing.ranking_points || 0)
    }

    if (!existing) {
      // 初回挿入：ベースラインは現在の値（週間スコアは0からスタート）
      await c.env.DB.prepare(
        `INSERT INTO ranking_stats (user_id, display_name, total_level, monster_count, correct_count, ranking_points,
           grade, battle_power, pokedex_count, wild_win_streak,
           week_start, week_base_correct_count, week_base_total_level, week_base_battle_power, week_base_pokedex_count, week_base_wild_win_streak, week_base_ranking_points,
           updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))`
      ).bind(
        u.id, stats.displayName, stats.totalLevel, stats.monsterCount, stats.correctCount, stats.rankingPoints,
        grade, stats.battlePower, stats.pokedexCount, stats.wildWinStreak,
        weekStart, stats.correctCount, stats.totalLevel, stats.battlePower, stats.pokedexCount, stats.wildWinStreak, stats.rankingPoints
      ).run()
    } else if (existing.week_start !== weekStart) {
      // 週が変わった → ベースラインを更新
      await c.env.DB.prepare(
        `UPDATE ranking_stats SET
           display_name=?, total_level=?, monster_count=?, correct_count=?, ranking_points=?,
           grade=?, battle_power=?, pokedex_count=?, wild_win_streak=?,
           week_start=?, week_base_correct_count=?, week_base_total_level=?, week_base_battle_power=?, week_base_pokedex_count=?, week_base_wild_win_streak=?, week_base_ranking_points=?,
           updated_at=datetime('now')
         WHERE user_id=?`
      ).bind(
        stats.displayName, stats.totalLevel, stats.monsterCount, stats.correctCount, stats.rankingPoints,
        grade, stats.battlePower, stats.pokedexCount, stats.wildWinStreak,
        weekStart, baseCorrect, baseLevel, basePower, baseDex, baseStreak, baseRkPts,
        u.id
      ).run()
    } else {
      // 同じ週 → 累計値のみ更新、ベースラインはそのまま
      await c.env.DB.prepare(
        `UPDATE ranking_stats SET
           display_name=?, total_level=?, monster_count=?, correct_count=?, ranking_points=?,
           grade=?, battle_power=?, pokedex_count=?, wild_win_streak=?,
           updated_at=datetime('now')
         WHERE user_id=?`
      ).bind(
        stats.displayName, stats.totalLevel, stats.monsterCount, stats.correctCount, stats.rankingPoints,
        grade, stats.battlePower, stats.pokedexCount, stats.wildWinStreak,
        u.id
      ).run()
    }
  } catch { /* ランキング更新エラーは無視 */ }

  return c.json({ ok: true })
})

app.post('/api/student/results', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  if (!rateLimit(`results:${u.id}`, 30, 60)) return jsonError(c, 429, 'too_many_requests')

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

// -------------------- ranking stats helper --------------------

function extractRankingStats(stateJson: string, fallbackName: string) {
  try {
    const obj = JSON.parse(stateJson)
    const s = obj.state || obj
    const playerLevel = Number(s.level || 1)
    const monsters: Record<string, any> = s.monsters || {}
    const monsterCount = Object.keys(monsters).length
    const sumMonsterLevels = Object.values(monsters).reduce((sum: number, m: any) => sum + Number(m?.level || 1), 0)
    const totalLevel = playerLevel + sumMonsterLevels
    const tp: Record<string, any> = s.trainingProgress || {}
    const correctCount = Object.values(tp).reduce((sum: number, t: any) => sum + Number(t?.correctCount ?? t?.count ?? 0), 0)
    // v2: 学年補正済みランキングポイント（rankingPointsが無い場合はcorrectCountにフォールバック）
    const rankingPoints = Object.values(tp).reduce((sum: number, t: any) => {
      if (t?.rankingPoints != null) return sum + Number(t.rankingPoints)
      return sum + Number(t?.correctCount ?? t?.count ?? 0)
    }, 0)
    // v2: battle_power, pokedex_count, wild_win_streak
    const party: number[] = Array.isArray(s.party) ? s.party : []
    let battlePower = 0
    for (const mid of party) {
      const m = monsters[String(mid)]
      if (m) {
        const lv = Number(m.level || 1)
        const atk = Number(m.atk || 0)
        const def = Number(m.def || 0)
        const hp = Number(m.hp || 0)
        const spd = Number(m.spd || 0)
        battlePower += atk + def + hp + spd
      }
    }
    const pokedexCount = Array.isArray(s.pokedex) ? s.pokedex.length : 0
    const maxObj: any = s.max || (s.M && s.M.max) || {}
    const wildWinStreak = Number(maxObj.winStreak || 0)
    return {
      displayName: String(s.name || fallbackName).slice(0, 30),
      totalLevel, monsterCount, correctCount, rankingPoints,
      battlePower, pokedexCount, wildWinStreak
    }
  } catch {
    return { displayName: fallbackName, totalLevel: 0, monsterCount: 0, correctCount: 0, rankingPoints: 0, battlePower: 0, pokedexCount: 0, wildWinStreak: 0 }
  }
}

// 現在の週の開始日（月曜日）をYYYY-MM-DD形式で返す
function getCurrentWeekStart(): string {
  const now = new Date()
  const day = now.getUTCDay() // 0=Sun, 1=Mon, ..., 6=Sat
  const diff = day === 0 ? 6 : day - 1 // Monday=0
  const monday = new Date(now)
  monday.setUTCDate(now.getUTCDate() - diff)
  return monday.toISOString().slice(0, 10)
}

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

// -------------------- API: admin (教師・ランキング設定) --------------------

app.get('/api/admin/pending-teachers', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const res = await c.env.DB.prepare(
    `SELECT id, login_id as loginId, name, school, created_at as createdAt FROM teacher_accounts WHERE is_active=0 ORDER BY created_at DESC`
  ).all<any>()
  return c.json({ ok: true, teachers: res.results })
})

app.post('/api/admin/approve-teacher/:id', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  await c.env.DB.prepare(`UPDATE teacher_accounts SET is_active=1 WHERE id=?`).bind(c.req.param('id')).run()
  return c.json({ ok: true })
})

app.delete('/api/admin/reject-teacher/:id', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  await c.env.DB.prepare(`DELETE FROM teacher_accounts WHERE id=? AND is_active=0`).bind(c.req.param('id')).run()
  return c.json({ ok: true })
})

app.get('/api/admin/settings', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const rows = await c.env.DB.prepare(`SELECT key, value FROM admin_settings`).all<any>()
  const settings: Record<string, string> = {}
  for (const r of rows.results) settings[r.key] = r.value
  return c.json({ ok: true, settings })
})

app.put('/api/admin/settings', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  for (const [key, val] of Object.entries(body)) {
    if (typeof val !== 'string') continue
    await c.env.DB.prepare(
      `INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
       ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')`
    ).bind(key, val).run()
  }
  return c.json({ ok: true })
})

// -------------------- API: admin - grade management --------------------

app.put('/api/admin/user-grade', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'admin' && u.role !== 'teacher')) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const userId = String(body.userId || '')
  const newGrade = Number(body.grade)
  if (!userId || !Number.isFinite(newGrade) || newGrade < 1 || newGrade > 6) {
    return jsonError(c, 400, 'invalid_grade')
  }
  await c.env.DB.prepare(`UPDATE users SET grade=? WHERE id=? AND role='student'`).bind(newGrade, userId).run()
  return c.json({ ok: true })
})

// -------------------- API: teacher --------------------

function requireTeacher(c: any) {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return null
  return u
}

function genClassCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  let code = ''
  const arr = new Uint8Array(6)
  crypto.getRandomValues(arr)
  for (let i = 0; i < 6; i++) code += chars[arr[i] % chars.length]
  return code
}

// 教師サインアップ
app.post('/api/auth/teacher-signup', async (c) => {
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const loginId = String(body.loginId || '').trim()
  const password = String(body.password || '')
  const name = String(body.name || '').trim()
  const school = String(body.school || '').trim()
  if (!loginId || loginId.length < 3) return jsonError(c, 400, 'loginId_too_short')
  if (!password || password.length < 6) return jsonError(c, 400, 'password_too_short')
  if (!name) return jsonError(c, 400, 'name_required')
  const id = crypto.randomUUID()
  const salt = randomHex(16)
  const hash = await pbkdf2Hash(password, salt)
  try {
    await c.env.DB.prepare(
      `INSERT INTO teacher_accounts (id, login_id, password_hash, password_salt, name, school) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(id, loginId, hash, salt, name, school).run()
  } catch {
    return jsonError(c, 409, 'loginId_taken')
  }
  return c.json({ ok: true })
})

// クラス作成
app.post('/api/teacher/class', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const name = String(body.name || '').trim()
  if (!name) return jsonError(c, 400, 'name_required')
  let classCode = genClassCode()
  for (let i = 0; i < 5; i++) {
    const ex = await c.env.DB.prepare(`SELECT id FROM classes WHERE class_code=? LIMIT 1`).bind(classCode).first<any>()
    if (!ex) break
    classCode = genClassCode()
  }
  const id = crypto.randomUUID()
  await c.env.DB.prepare(`INSERT INTO classes (id, class_code, name, teacher_id) VALUES (?, ?, ?, ?)`).bind(id, classCode, name, u.id).run()
  return c.json({ ok: true, classId: id, classCode })
})

// クラス一覧
app.get('/api/teacher/classes', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  // 管理者は全クラスを閲覧可能
  const isAdmin = u.role === 'admin'
  const res = isAdmin
    ? await c.env.DB.prepare(
        `SELECT c.id, c.class_code as classCode, c.name, c.ranking_enabled as rankingEnabled, c.homework_enabled as homeworkEnabled, c.contact_enabled as contactEnabled, c.created_at as createdAt, t.name as teacherName
         FROM classes c LEFT JOIN teacher_accounts t ON t.id = c.teacher_id ORDER BY c.created_at DESC`
      ).all<any>()
    : await c.env.DB.prepare(
        `SELECT id, class_code as classCode, name, ranking_enabled as rankingEnabled, homework_enabled as homeworkEnabled, contact_enabled as contactEnabled, created_at as createdAt FROM classes WHERE teacher_id=? ORDER BY created_at DESC`
      ).bind(u.id).all<any>()
  return c.json({ ok: true, classes: res.results })
})

// クラス削除
app.delete('/api/teacher/class/:classId', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  await c.env.DB.prepare(`DELETE FROM class_members WHERE class_id=?`).bind(classId).run()
  if (u.role === 'admin') {
    await c.env.DB.prepare(`DELETE FROM classes WHERE id=?`).bind(classId).run()
  } else {
    await c.env.DB.prepare(`DELETE FROM classes WHERE id=? AND teacher_id=?`).bind(classId, u.id).run()
  }
  return c.json({ ok: true })
})

// 家庭学習ON/OFFトグル
app.put('/api/teacher/class/:classId/homework-toggle', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const body = await c.req.json().catch(() => null)
  const enabled = body?.enabled ? 1 : 0
  const result = u.role === 'admin'
    ? await c.env.DB.prepare(`UPDATE classes SET homework_enabled=? WHERE id=?`).bind(enabled, classId).run()
    : await c.env.DB.prepare(`UPDATE classes SET homework_enabled=? WHERE id=? AND teacher_id=?`).bind(enabled, classId, u.id).run()
  if (!result.meta?.changes) return jsonError(c, 404, 'class_not_found')
  return c.json({ ok: true, homeworkEnabled: enabled })
})

// 連絡帳ON/OFFトグル
app.put('/api/teacher/class/:classId/contact-toggle', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const body = await c.req.json().catch(() => null)
  const enabled = body?.enabled ? 1 : 0
  const result = u.role === 'admin'
    ? await c.env.DB.prepare(`UPDATE classes SET contact_enabled=? WHERE id=?`).bind(enabled, classId).run()
    : await c.env.DB.prepare(`UPDATE classes SET contact_enabled=? WHERE id=? AND teacher_id=?`).bind(enabled, classId, u.id).run()
  if (!result.meta?.changes) return jsonError(c, 404, 'class_not_found')
  return c.json({ ok: true, contactEnabled: enabled })
})

// ランキング参加ON/OFFトグル
app.put('/api/teacher/class/:classId/ranking-toggle', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const body = await c.req.json().catch(() => null)
  const enabled = body?.enabled ? 1 : 0
  const result = u.role === 'admin'
    ? await c.env.DB.prepare(`UPDATE classes SET ranking_enabled=? WHERE id=?`).bind(enabled, classId).run()
    : await c.env.DB.prepare(`UPDATE classes SET ranking_enabled=? WHERE id=? AND teacher_id=?`).bind(enabled, classId, u.id).run()
  if (!result.meta?.changes) return jsonError(c, 404, 'class_not_found')
  return c.json({ ok: true, rankingEnabled: enabled })
})

// クラス詳細（メンバー＋ランキング）
app.get('/api/teacher/class/:classId/ranking', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  // 自分のクラスか確認（管理者は全クラスアクセス可能）
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare(`SELECT id, name, class_code as classCode FROM classes WHERE id=? LIMIT 1`).bind(classId).first<any>()
    : await c.env.DB.prepare(`SELECT id, name, class_code as classCode FROM classes WHERE id=? AND teacher_id=? LIMIT 1`).bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const res = await c.env.DB.prepare(`
    SELECT u.id, u.name, u.grade, u.class_name as className,
           COALESCE(rs.total_level, 0) as totalLevel,
           COALESCE(rs.monster_count, 0) as monsterCount,
           COALESCE(rs.correct_count, 0) as correctCount,
           COALESCE(rs.updated_at, '') as updatedAt
    FROM class_members cm
    JOIN users u ON u.id = cm.user_id
    LEFT JOIN ranking_stats rs ON rs.user_id = cm.user_id
    WHERE cm.class_id = ?
    ORDER BY rs.total_level DESC, rs.correct_count DESC
  `).bind(classId).all<any>()
  return c.json({ ok: true, class: cls, members: res.results })
})

// -------------------- API: teacher (学習分析) --------------------
app.get('/api/teacher/class/:classId/unit-analytics', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare(`SELECT id, name FROM classes WHERE id=? LIMIT 1`).bind(classId).first<any>()
    : await c.env.DB.prepare(`SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1`).bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  const members = await c.env.DB.prepare(`
    SELECT u.id, u.name, u.grade, p.state_json as stateJson
    FROM class_members cm
    JOIN users u ON u.id = cm.user_id
    LEFT JOIN progress p ON p.user_id = cm.user_id
    WHERE cm.class_id = ?
    ORDER BY u.name
  `).bind(classId).all<any>()

  const studentData: any[] = []
  const allUnits = new Map<string, { name: string, subject: string }>()

  for (const m of members.results) {
    let byUnit: any = {}
    let bySubject: any = {}
    let learnStreak = 0
    try {
      if (m.stateJson) {
        const state = JSON.parse(m.stateJson)
        byUnit = state?.metrics?.learn?.byUnit || {}
        bySubject = state?.metrics?.learn?.bySubject || {}
        const daily: any = state?.metrics?.daily || {}
        const activeDays = Object.keys(daily).filter((k: string) => (daily[k]?.training || 0) >= 1).sort()
        let streak = 0
        for (let i = activeDays.length - 1; i >= 0; i--) {
          const dayDate = new Date(activeDays[i] + 'T00:00:00+09:00')
          const diff = Math.round((Date.now() - dayDate.getTime()) / 86400000)
          if (diff === activeDays.length - 1 - i) streak++
          else break
        }
        learnStreak = streak
      }
    } catch {}

    Object.keys(byUnit).forEach((mode: string) => {
      const u2 = byUnit[mode]
      if (!allUnits.has(mode) && u2.unitName) {
        allUnits.set(mode, { name: u2.unitName, subject: u2.subjectName || '' })
      }
    })

    studentData.push({ id: m.id, name: m.name || '', grade: m.grade || '', byUnit, bySubject, learnStreak })
  }

  const unitKeys: string[] = []
  allUnits.forEach((_, mode) => {
    if (studentData.some(s => (s.byUnit[mode]?.total || 0) >= 5)) unitKeys.push(mode)
  })

  const unitSummary = unitKeys.map(mode => {
    const info = allUnits.get(mode)!
    const students = studentData.filter(s => (s.byUnit[mode]?.total || 0) >= 5)
    const totalAcc = students.reduce((sum: number, s: any) => {
      const u2 = s.byUnit[mode]
      return sum + (u2.total ? u2.correct / u2.total : 0)
    }, 0)
    const classAvg = students.length > 0 ? Math.round(totalAcc / students.length * 100) : null
    return { mode, name: info.name, subject: info.subject, classAvg, studentCount: students.length }
  }).sort((a: any, b: any) => (a.classAvg ?? 101) - (b.classAvg ?? 101))

  return c.json({
    ok: true, class: cls, unitSummary,
    unitInfo: Object.fromEntries(allUnits),
    students: studentData.map((s: any) => ({
      id: s.id, name: s.name, grade: s.grade, learnStreak: s.learnStreak,
      bySubject: Object.fromEntries(
        Object.entries(s.bySubject).map(([k, v]: [string, any]) => [k, {
          total: v.total || 0, correct: v.correct || 0,
          acc: v.total ? Math.round(v.correct / v.total * 100) : 0
        }])
      ),
      units: Object.fromEntries(
        unitKeys.map((mode: string) => {
          const u2 = s.byUnit[mode]
          if (!u2 || (u2.total || 0) < 5) return [mode, null]
          return [mode, { total: u2.total, correct: u2.correct, acc: Math.round(u2.correct / u2.total * 100) }]
        })
      )
    }))
  })
})

// -------------------- API: student (クラス参加) --------------------

app.post('/api/student/join-class', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const code = String(body.classCode || '').trim().toUpperCase()
  if (!code) return jsonError(c, 400, 'code_required')
  const cls = await c.env.DB.prepare(`SELECT id, name FROM classes WHERE class_code=? LIMIT 1`).bind(code).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  // 既存メンバーシップを確認（同じクラスへの重複参加を防ぐ）
  const existing = await c.env.DB.prepare(`SELECT 1 FROM class_members WHERE user_id=? AND class_id=? LIMIT 1`).bind(u.id, cls.id).first<any>()
  if (!existing) {
    // 他クラスから退会してから参加
    await c.env.DB.prepare(`DELETE FROM class_members WHERE user_id=?`).bind(u.id).run()
    await c.env.DB.prepare(`INSERT INTO class_members (user_id, class_id) VALUES (?, ?)`).bind(u.id, cls.id).run()
  }
  return c.json({ ok: true, className: cls.name })
})

app.get('/api/student/class-info', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const row = await c.env.DB.prepare(`
    SELECT c.id, c.name, c.class_code as classCode, cm.joined_at as joinedAt,
           c.homework_enabled as homeworkEnabled, c.contact_enabled as contactEnabled
    FROM class_members cm JOIN classes c ON c.id = cm.class_id
    WHERE cm.user_id = ? LIMIT 1
  `).bind(u.id).first<any>()
  return c.json({ ok: true, class: row || null })
})

app.post('/api/student/leave-class', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  await c.env.DB.prepare(`DELETE FROM class_members WHERE user_id=?`).bind(u.id).run()
  return c.json({ ok: true })
})

// -------------------- API: ranking --------------------

app.get('/api/ranking', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')

  const scopeRow = await c.env.DB.prepare(`SELECT value FROM admin_settings WHERE key='ranking_scope' LIMIT 1`).first<any>()
  const enabledRow = await c.env.DB.prepare(`SELECT value FROM admin_settings WHERE key='ranking_enabled' LIMIT 1`).first<any>()
  const scope = scopeRow?.value || 'class'
  const enabled = enabledRow?.value !== '0'

  if (!enabled || scope === 'hidden') return c.json({ ok: true, ranking: [], scope, enabled: false, hidden: true })

  // v2: type=overall|grade|power|correct|pokedex|wild  period=cumulative|weekly  grade=1-6
  const type = c.req.query('type') || 'overall'
  const period = c.req.query('period') || 'cumulative'
  const filterGrade = Number(c.req.query('grade') || 0)
  const weekStart = getCurrentWeekStart()

  // ソート列とSELECT列を決定
  let orderCol = 'rs.total_level'
  let extraSelect = ''
  switch (type) {
    case 'overall': orderCol = 'rs.total_level'; break
    case 'power': orderCol = 'rs.battle_power'; break
    case 'correct': orderCol = 'rs.ranking_points'; break
    case 'pokedex': orderCol = 'rs.pokedex_count'; break
    case 'wild': orderCol = 'rs.wild_win_streak'; break
    case 'grade': orderCol = 'rs.ranking_points'; break
  }

  // 週間の場合は差分で並べ替え
  if (period === 'weekly') {
    switch (type) {
      case 'overall': extraSelect = ', (rs.total_level - rs.week_base_total_level) as weeklyScore'; orderCol = 'weeklyScore'; break
      case 'power': extraSelect = ', (rs.battle_power - rs.week_base_battle_power) as weeklyScore'; orderCol = 'weeklyScore'; break
      case 'correct': case 'grade': extraSelect = ', (rs.ranking_points - rs.week_base_ranking_points) as weeklyScore'; orderCol = 'weeklyScore'; break
      case 'pokedex': extraSelect = ', (rs.pokedex_count - rs.week_base_pokedex_count) as weeklyScore'; orderCol = 'weeklyScore'; break
      case 'wild': extraSelect = ', (rs.wild_win_streak - rs.week_base_wild_win_streak) as weeklyScore'; orderCol = 'weeklyScore'; break
    }
  }

  // 学年フィルタ
  const gradeFilter = (type === 'grade' && filterGrade >= 1 && filterGrade <= 6)
    ? ` AND rs.grade = ${filterGrade}` : ''

  // 週間の場合は同じ週のデータのみ
  const weekFilter = (period === 'weekly') ? ` AND rs.week_start = '${weekStart}'` : ''

  let sql = ''
  const binds: any[] = []

  const selectCols = `rs.user_id as userId, rs.display_name as displayName,
    rs.total_level as totalLevel, rs.monster_count as monsterCount, rs.correct_count as correctCount,
    rs.ranking_points as rankingPoints,
    rs.grade, rs.battle_power as battlePower, rs.pokedex_count as pokedexCount, rs.wild_win_streak as wildWinStreak
    ${extraSelect}`

  if (scope === 'global' || u.role === 'admin') {
    sql = `SELECT ${selectCols}
           FROM ranking_stats rs
           JOIN users u ON u.id = rs.user_id AND u.is_active=1
           JOIN class_members cm ON cm.user_id = rs.user_id
           JOIN classes cl ON cl.id = cm.class_id AND cl.ranking_enabled = 1
           WHERE 1=1 ${gradeFilter} ${weekFilter}
           ORDER BY ${orderCol} DESC, rs.correct_count DESC LIMIT 100`
  } else if (scope === 'class') {
    const classRow = await c.env.DB.prepare(
      `SELECT cm.class_id, cl.ranking_enabled FROM class_members cm JOIN classes cl ON cl.id=cm.class_id WHERE cm.user_id=? LIMIT 1`
    ).bind(u.id).first<any>()
    if (!classRow) return c.json({ ok: true, ranking: [], scope, enabled, message: 'no_class' })
    if (!classRow.ranking_enabled) return c.json({ ok: true, ranking: [], scope, enabled, message: 'ranking_not_allowed' })
    sql = `SELECT ${selectCols}
           FROM ranking_stats rs
           JOIN class_members cm ON cm.user_id = rs.user_id AND cm.class_id = ?
           JOIN users u ON u.id = rs.user_id AND u.is_active=1
           WHERE 1=1 ${gradeFilter} ${weekFilter}
           ORDER BY ${orderCol} DESC, rs.correct_count DESC LIMIT 100`
    binds.push(classRow.class_id)
  } else {
    return c.json({ ok: true, ranking: [], scope, enabled: false, hidden: true })
  }

  const res = await c.env.DB.prepare(sql).bind(...binds).all<any>()
  const ranking = res.results.map((r: any, i: number) => ({ ...r, rank: i + 1, isMe: r.userId === u.id }))
  return c.json({ ok: true, ranking, scope, enabled, type, period })
})

// -------------------- API: homework (家庭学習提出) --------------------

function genHwId() {
  const a = new Uint8Array(16)
  crypto.getRandomValues(a)
  return [...a].map(b => b.toString(16).padStart(2, '0')).join('')
}

// 生徒：シートをDBに提出（報酬はまだ付与しない）
app.post('/api/homework/submit', async (c) => {
  const u = c.get('user')
  if (!u || u.role !== 'student') return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const dayKey = String(body.dayKey || '').slice(0, 10)
  if (!dayKey) return jsonError(c, 400, 'day_key_required')

  // 同じ日に既に提出済みならエラー
  const existing = await c.env.DB.prepare(
    `SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1`
  ).bind(u.id, dayKey).first<any>()
  if (existing) return c.json({ ok: true, alreadySubmitted: true, id: existing.id })

  // クラスの担任を自動設定
  const classRow = await c.env.DB.prepare(
    `SELECT c.teacher_id FROM class_members cm JOIN classes c ON c.id=cm.class_id WHERE cm.user_id=? LIMIT 1`
  ).bind(u.id).first<any>()
  const teacherId = classRow?.teacher_id || null

  const id = genHwId()
  await c.env.DB.prepare(`
    INSERT INTO homework_submissions
      (id, user_id, day_key, submitted_at, todo, why, aim, minutes, end_weather,
       weather_reason, next_improve, rest_day, streak_after,
       reward_kind, reward_coins, reward_shards, bonus_coins, bonus_shards, teacher_id,
       self_study_plan, weekly_plan, weekly_reflection)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
  `).bind(
    id, u.id, dayKey, Date.now(),
    String(body.todo || '').slice(0, 500),
    String(body.why || '').slice(0, 500),
    String(body.aim || '').slice(0, 500),
    Number(body.minutes || 0),
    String(body.endWeather || 'sun'),
    String(body.weatherReason || '').slice(0, 500),
    String(body.nextImprove || '').slice(0, 500),
    body.restDay ? 1 : 0,
    Number(body.streakAfter || 0),
    String(body.rewardKind || 'coin'),
    Number(body.rewardCoins || 0),
    Number(body.rewardShards || 0),
    Number(body.bonusCoins || 0),
    Number(body.bonusShards || 0),
    teacherId,
    String(body.selfStudyPlan || '').slice(0, 500),
    String(body.weeklyPlan || '').slice(0, 1000),
    String(body.weeklyReflection || '').slice(0, 1000)
  ).run()

  return c.json({ ok: true, id })
})

// 生徒：提出済みシートの内容を修正して再提出（報酬変更なし）
app.put('/api/homework/submit', async (c) => {
  const u = c.get('user')
  if (!u || u.role !== 'student') return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const dayKey = String(body.dayKey || '').slice(0, 10)
  if (!dayKey) return jsonError(c, 400, 'day_key_required')

  const result = await c.env.DB.prepare(`
    UPDATE homework_submissions
    SET todo=?, why=?, aim=?, minutes=?, end_weather=?, weather_reason=?, next_improve=?,
        self_study_plan=?, weekly_plan=?, weekly_reflection=?,
        updated_at=?
    WHERE user_id=? AND day_key=?
  `).bind(
    String(body.todo || '').slice(0, 500),
    String(body.why || '').slice(0, 500),
    String(body.aim || '').slice(0, 500),
    Number(body.minutes || 0),
    String(body.endWeather || 'sun'),
    String(body.weatherReason || '').slice(0, 500),
    String(body.nextImprove || '').slice(0, 500),
    String(body.selfStudyPlan || '').slice(0, 500),
    String(body.weeklyPlan || '').slice(0, 1000),
    String(body.weeklyReflection || '').slice(0, 1000),
    Date.now(),
    u.id, dayKey
  ).run()

  if (!result.meta?.changes) return jsonError(c, 404, 'not_found')
  return c.json({ ok: true })
})

// 生徒：自分の提出履歴を取得
app.get('/api/homework/my', async (c) => {
  const u = c.get('user')
  if (!u || u.role !== 'student') return jsonError(c, 403, 'forbidden')
  const res = await c.env.DB.prepare(`
    SELECT id, day_key as dayKey, submitted_at as submittedAt, rest_day as restDay,
           teacher_comment as teacherComment, has_physical as hasPhysical,
           returned_at as returnedAt, reward_claimed as rewardClaimed,
           reward_kind as rewardKind, reward_coins as rewardCoins, reward_shards as rewardShards,
           bonus_coins as bonusCoins, bonus_shards as bonusShards
    FROM homework_submissions WHERE user_id=? ORDER BY submitted_at DESC LIMIT 30
  `).bind(u.id).all<any>()
  return c.json({ ok: true, submissions: res.results })
})

// 生徒：返却済み報酬を受け取る
app.post('/api/homework/:id/claim', async (c) => {
  const u = c.get('user')
  if (!u || u.role !== 'student') return jsonError(c, 403, 'forbidden')
  const hwId = c.req.param('id')
  const row = await c.env.DB.prepare(`
    SELECT * FROM homework_submissions WHERE id=? AND user_id=? LIMIT 1
  `).bind(hwId, u.id).first<any>()
  if (!row) return jsonError(c, 404, 'not_found')
  if (!row.returned_at) return jsonError(c, 400, 'not_returned_yet')
  if (row.reward_claimed) return jsonError(c, 400, 'already_claimed')

  // 報酬計算：成果物なし→50%、あり→100%
  const rate = row.has_physical ? 1.0 : 0.5
  const coins = Math.floor((Number(row.reward_coins || 0) + Number(row.bonus_coins || 0)) * rate)
  const shards = Math.floor((Number(row.reward_shards || 0) + Number(row.bonus_shards || 0)) * rate)
  const rewardKind = String(row.reward_kind || 'coin')

  // 受け取り済みにマーク
  await c.env.DB.prepare(`
    UPDATE homework_submissions SET reward_claimed=1, reward_claimed_at=? WHERE id=?
  `).bind(Date.now(), hwId).run()

  return c.json({ ok: true, coins, shards, rewardKind, hasPhysical: !!row.has_physical })
})

// 教師：クラスの提出一覧を取得
app.get('/api/teacher/homework', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.query('classId')

  let sql = `
    SELECT hs.id, hs.day_key as dayKey, hs.submitted_at as submittedAt,
           hs.todo, hs.why, hs.aim, hs.minutes,
           hs.end_weather as endWeather, hs.weather_reason as weatherReason, hs.next_improve as nextImprove,
           hs.rest_day as restDay, hs.reward_kind as rewardKind,
           hs.reward_coins as rewardCoins, hs.reward_shards as rewardShards,
           hs.bonus_coins as bonusCoins, hs.bonus_shards as bonusShards,
           hs.teacher_comment as teacherComment, hs.has_physical as hasPhysical,
           hs.returned_at as returnedAt, hs.reward_claimed as rewardClaimed,
           u.id as userId, u.name as studentName, u.grade, u.class_name as className
    FROM homework_submissions hs
    JOIN users u ON u.id = hs.user_id
    JOIN class_members cm ON cm.user_id = hs.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
  `
  const binds: any[] = [u.id]
  if (classId) { sql += ` AND cl.id = ?`; binds.push(classId) }
  sql += ` ORDER BY hs.submitted_at DESC LIMIT 100`

  const res = await c.env.DB.prepare(sql).bind(...binds).all<any>()
  return c.json({ ok: true, submissions: res.results })
})

// 教師：返却（コメント＋成果物フラグ）
app.post('/api/teacher/homework/:id/return', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const hwId = c.req.param('id')
  const body = await c.req.json<any>().catch(() => ({}))

  // 自分のクラスの生徒の提出のみ操作可
  const row = await c.env.DB.prepare(`
    SELECT hs.id FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE hs.id = ? LIMIT 1
  `).bind(u.id, hwId).first<any>()
  if (!row) return jsonError(c, 404, 'not_found')

  await c.env.DB.prepare(`
    UPDATE homework_submissions
    SET teacher_id=?, teacher_comment=?, has_physical=?, returned_at=?
    WHERE id=?
  `).bind(
    u.id,
    String(body.comment || '').slice(0, 500),
    body.hasPhysical ? 1 : 0,
    Date.now(),
    hwId
  ).run()

  return c.json({ ok: true })
})

// -------------------- API: 先生メニュー (class weekly menu) --------------------

// 今週のキーを返す (ISO week: YYYY-Wnn)
function getWeekKey(date?: Date): string {
  const d = date || new Date()
  const tmp = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()))
  tmp.setUTCDate(tmp.getUTCDate() + 4 - (tmp.getUTCDay() || 7))
  const yearStart = new Date(Date.UTC(tmp.getUTCFullYear(), 0, 1))
  const weekNo = Math.ceil((((tmp.getTime() - yearStart.getTime()) / 86400000) + 1) / 7)
  return `${tmp.getUTCFullYear()}-W${String(weekNo).padStart(2, '0')}`
}

// 教師：今週の先生メニューを設定
app.post('/api/teacher/class/:classId/weekly-menu', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.param('classId')

  // 自分のクラスか確認（管理者は全クラスOK）
  const isAdmin = u.role === 'admin'
  const cls = isAdmin
    ? await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? LIMIT 1`).bind(classId).first<any>()
    : await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1`).bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  const body = await c.req.json<any>().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const weekKey = String(body.weekKey || getWeekKey()).slice(0, 8)
  const kanjiPage = String(body.kanjiPage || '').slice(0, 100)
  const keisanPage = String(body.keisanPage || '').slice(0, 100)
  const otherTasks = String(body.otherTasks || '').slice(0, 500)

  await c.env.DB.prepare(`
    INSERT INTO class_weekly_menu (class_id, week_key, kanji_page, keisan_page, other_tasks, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(class_id, week_key) DO UPDATE SET
      kanji_page=excluded.kanji_page, keisan_page=excluded.keisan_page,
      other_tasks=excluded.other_tasks, updated_at=excluded.updated_at
  `).bind(classId, weekKey, kanjiPage, keisanPage, otherTasks, Date.now()).run()

  return c.json({ ok: true, weekKey })
})

// 教師：先生メニュー一覧を取得
app.get('/api/teacher/class/:classId/weekly-menu', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.param('classId')

  const isAdmin = u.role === 'admin'
  const cls = isAdmin
    ? await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? LIMIT 1`).bind(classId).first<any>()
    : await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1`).bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  const weekKey = c.req.query('weekKey') || getWeekKey()
  const row = await c.env.DB.prepare(
    `SELECT * FROM class_weekly_menu WHERE class_id=? AND week_key=? LIMIT 1`
  ).bind(classId, weekKey).first<any>()

  return c.json({ ok: true, menu: row || null, weekKey })
})

// 生徒：自分のクラスの今週の先生メニューを取得
app.get('/api/student/weekly-menu', async (c) => {
  const u = c.get('user')
  if (!u || u.role !== 'student') return jsonError(c, 403, 'forbidden')

  const weekKey = c.req.query('weekKey') || getWeekKey()

  const row = await c.env.DB.prepare(`
    SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
           cwm.other_tasks as otherTasks, cwm.week_key as weekKey
    FROM class_weekly_menu cwm
    JOIN class_members cm ON cm.class_id = cwm.class_id
    WHERE cm.user_id = ? AND cwm.week_key = ?
    LIMIT 1
  `).bind(u.id, weekKey).first<any>()

  return c.json({ ok: true, menu: row || null, weekKey })
})

// 生徒：提出データに週間計画・振り返りを含める（既存submitのPUT拡張）
// → 既存の PUT /api/homework/submit に self_study_plan, weekly_plan, weekly_reflection を追加

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

// -------------------- API: trade (合言葉交換) --------------------

function genTradeCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
  let code = ''
  for (let i = 0; i < 6; i++) code += chars[Math.floor(Math.random() * chars.length)]
  return code
}

// コード発行：自分のモンスターを登録して交換コードを作る
app.post('/api/trade/offer', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json<any>().catch(() => null)
  if (!body?.monster) return jsonError(c, 400, 'monster_required')

  // 既存の有効なオファーがあればキャンセル
  await c.env.DB.prepare(
    `UPDATE trade_offers SET status='cancelled' WHERE from_user_id=? AND status='pending'`
  ).bind(u.id).run()

  const id = crypto.randomUUID()
  let code = genTradeCode()
  // コード衝突チェック（3回まで）
  for (let i = 0; i < 3; i++) {
    const existing = await c.env.DB.prepare(
      `SELECT id FROM trade_offers WHERE code=? AND status='pending' AND expires_at > ?`
    ).bind(code, Date.now()).first()
    if (!existing) break
    code = genTradeCode()
  }

  const now = Date.now()
  const expires = now + 24 * 60 * 60 * 1000 // 24時間

  await c.env.DB.prepare(`
    INSERT INTO trade_offers (id, code, from_user_id, from_user_name, from_monster_json, status, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)
  `).bind(id, code, u.id, u.name || u.username || 'プレイヤー', JSON.stringify(body.monster), now, expires).run()

  return c.json({ ok: true, code, expiresAt: expires })
})

// コード照会：相手のコードを入力して内容を確認する
app.get('/api/trade/offer/:code', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  const code = c.req.param('code').toUpperCase()

  const offer = await c.env.DB.prepare(
    `SELECT * FROM trade_offers WHERE code=? AND status='pending' AND expires_at > ?`
  ).bind(code, Date.now()).first<any>()

  if (!offer) return jsonError(c, 404, 'offer_not_found')
  if (offer.from_user_id === u.id) return jsonError(c, 400, 'cannot_trade_with_yourself')

  return c.json({
    ok: true,
    offer: {
      id: offer.id,
      code: offer.code,
      fromUserName: offer.from_user_name,
      fromMonster: JSON.parse(offer.from_monster_json),
      expiresAt: offer.expires_at,
    }
  })
})

// 交換実行：両者のstateを更新してモンスターを入れ替える
app.post('/api/trade/complete', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json<any>().catch(() => null)
  if (!body?.code || !body?.monster) return jsonError(c, 400, 'code_and_monster_required')

  const code = String(body.code).toUpperCase()
  const offer = await c.env.DB.prepare(
    `SELECT * FROM trade_offers WHERE code=? AND status='pending' AND expires_at > ?`
  ).bind(code, Date.now()).first<any>()

  if (!offer) return jsonError(c, 404, 'offer_not_found')
  if (offer.from_user_id === u.id) return jsonError(c, 400, 'cannot_trade_with_yourself')

  const fromMonster = JSON.parse(offer.from_monster_json)
  const toMonster = body.monster

  // 申請者(from)のstateを取得してモンスターを入れ替え
  const fromProgress = await c.env.DB.prepare(
    `SELECT state_json FROM progress WHERE user_id=?`
  ).bind(offer.from_user_id).first<any>()

  if (!fromProgress) return jsonError(c, 404, 'from_user_progress_not_found')

  let fromState: any
  try { fromState = JSON.parse(fromProgress.state_json) } catch { return jsonError(c, 500, 'state_parse_error') }

  // 受諾者(to)のstateを取得
  const toProgress = await c.env.DB.prepare(
    `SELECT state_json FROM progress WHERE user_id=?`
  ).bind(u.id).first<any>()

  if (!toProgress) return jsonError(c, 404, 'to_user_progress_not_found')

  let toState: any
  try { toState = JSON.parse(toProgress.state_json) } catch { return jsonError(c, 500, 'state_parse_error') }

  // player.boxes は boxes[boxIdx][slotIdx] の2次元配列
  // fromMonsterをfromStateのboxesから探して削除し、toMonsterを追加
  if (!Array.isArray(fromState.boxes)) return jsonError(c, 400, 'from_box_invalid')
  let fromBoxI = -1, fromSlotI = -1
  outer1: for (let bi = 0; bi < fromState.boxes.length; bi++) {
    const box = fromState.boxes[bi]
    if (!Array.isArray(box)) continue
    for (let si = 0; si < box.length; si++) {
      const b = box[si]
      if (b && (b.uid === fromMonster.uid || (b.monsterId === fromMonster.monsterId && b.level === fromMonster.level))) {
        fromBoxI = bi; fromSlotI = si; break outer1
      }
    }
  }
  if (fromBoxI === -1) return jsonError(c, 400, 'from_monster_not_in_box')
  fromState.boxes[fromBoxI][fromSlotI] = null

  // toMonsterをtoStateのboxesから探して削除し、fromMonsterを追加
  if (!Array.isArray(toState.boxes)) return jsonError(c, 400, 'to_box_invalid')
  let toBoxI = -1, toSlotI = -1
  outer2: for (let bi = 0; bi < toState.boxes.length; bi++) {
    const box = toState.boxes[bi]
    if (!Array.isArray(box)) continue
    for (let si = 0; si < box.length; si++) {
      const b = box[si]
      if (b && (b.uid === toMonster.uid || (b.monsterId === toMonster.monsterId && b.level === toMonster.level))) {
        toBoxI = bi; toSlotI = si; break outer2
      }
    }
  }
  if (toBoxI === -1) return jsonError(c, 400, 'to_monster_not_in_box')
  toState.boxes[toBoxI][toSlotI] = null

  // 空きスロットに相手のモンスターを入れる
  const placeInBoxes = (boxes: any[][], monster: any) => {
    for (let bi = 0; bi < boxes.length; bi++) {
      if (!Array.isArray(boxes[bi])) boxes[bi] = []
      for (let si = 0; si < 100; si++) {
        if (!boxes[bi][si]) { boxes[bi][si] = { ...monster, tradedAt: Date.now() }; return }
      }
    }
    // 全スロット埋まっていたらbox0の末尾に追加
    boxes[0].push({ ...monster, tradedAt: Date.now() })
  }
  placeInBoxes(fromState.boxes, toMonster)
  placeInBoxes(toState.boxes, fromMonster)

  // 両者のstateを保存
  await c.env.DB.prepare(
    `UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?`
  ).bind(JSON.stringify(fromState), offer.from_user_id).run()

  await c.env.DB.prepare(
    `UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?`
  ).bind(JSON.stringify(toState), u.id).run()

  // オファーをcompletedに
  await c.env.DB.prepare(
    `UPDATE trade_offers SET status='completed', to_user_id=?, to_monster_json=?, completed_at=? WHERE id=?`
  ).bind(u.id, JSON.stringify(toMonster), Date.now(), offer.id).run()

  return c.json({
    ok: true,
    received: fromMonster,
    sent: toMonster,
    fromUserName: offer.from_user_name,
  })
})

// 自分の発行中オファーをキャンセル
app.delete('/api/trade/offer', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  await c.env.DB.prepare(
    `UPDATE trade_offers SET status='cancelled' WHERE from_user_id=? AND status='pending'`
  ).bind(u.id).run()
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
  const battleType = (body.battleType === 'egg') ? 'egg' : (body.battleType === 'gym') ? 'gym' : 'normal'

  // 既存 waiting ルームを削除
  await c.env.DB.prepare(`DELETE FROM rt_rooms WHERE host_user_id=? AND status='waiting'`).bind(u.id).run()

  const customCode = body.code ? String(body.code).toUpperCase().replace(/[^A-Z0-9]/g, '') : ''
  let roomId = customCode.length >= 4 ? customCode : genRoomId()
  if (!customCode.length) {
    for (let i = 0; i < 5; i++) {
      const ex = await c.env.DB.prepare(`SELECT id FROM rt_rooms WHERE id=?`).bind(roomId).first<any>()
      if (!ex) break
      roomId = genRoomId()
    }
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
    UPDATE rt_rooms SET guest_user_id=?, guest_name=?, guest_party_json=?, guest_ready=1, status='ready', updated_at=datetime('now')
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
    SELECT id, user_id, event_type, value, monster_id, meta_json, created_at FROM rt_events
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
  if (!rateLimit(`rtdmg:${u.id}`, 20, 10)) return jsonError(c, 429, 'too_many_requests')
  const roomId = c.req.param('roomId').toUpperCase()
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')

  const room = await c.env.DB.prepare(`SELECT * FROM rt_rooms WHERE id=? LIMIT 1`).bind(roomId).first<any>()
  if (!room) return jsonError(c, 404, 'room_not_found')
  if (room.status !== 'playing') return jsonError(c, 409, 'not_playing')

  const isHost = room.host_user_id === u.id
  const isGuest = room.guest_user_id === u.id
  if (!isHost && !isGuest) return jsonError(c, 403, 'not_a_participant')

  const damage = Math.max(0, Math.min(500, Number(body.damage || 0)))
  if (!Number.isFinite(damage)) return jsonError(c, 400, 'invalid_damage')
  const monsterId = Math.max(0, Math.min(9999, Math.floor(Number(body.monsterId || 0))))
  const metaJson = body.meta ? JSON.stringify(body.meta).slice(0, 500) : null
  const validEvents = ['damage', 'faint', 'win', 'lose']
  const eventType = validEvents.includes(String(body.eventType)) ? String(body.eventType) : 'damage'

  // イベント記録
  const result = await c.env.DB.prepare(`
    INSERT INTO rt_events (room_id, user_id, event_type, value, monster_id, meta_json)
    VALUES (?, ?, ?, ?, ?, ?)
  `).bind(roomId, u.id, eventType, damage, monsterId, metaJson).run()

  const newEventId = (result.meta as any).last_row_id

  // HPを更新（送信者が攻撃 → 相手のHPを減らす）
  let newHostHp = room.host_hp
  let newGuestHp = room.guest_hp

  if (eventType === 'self_damage') {
    // ジムバトル: AIが自分の城を攻撃 → 送信者自身のHPを減らす
    if (isHost) { newHostHp = Math.max(0, newHostHp - damage) }
    else { newGuestHp = Math.max(0, newGuestHp - damage) }
  } else {
    // 通常バトル: 自分が相手を攻撃 → 相手のHPを減らす
    if (isHost) { newGuestHp = Math.max(0, newGuestHp - damage) }
    else { newHostHp = Math.max(0, newHostHp - damage) }
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

// -------------------- Reports --------------------

// Submit a report (any logged-in user)
app.post('/api/report', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')

  const body = await c.req.json().catch(() => null)
  if (!body?.body || typeof body.body !== 'string' || body.body.trim().length === 0) {
    return jsonError(c, 400, 'body_required')
  }
  const category = ['bug', 'request', 'other'].includes(body.category) ? body.category : 'bug'
  const text = body.body.trim().slice(0, 1000)

  // Get display name
  const acct = await c.env.DB.prepare(`SELECT name FROM users WHERE id=?`).bind(u.id).first<any>()
  const displayName = acct?.name || u.loginId || 'unknown'

  const id = crypto.randomUUID()
  await c.env.DB.prepare(
    `INSERT INTO reports (id, account_id, display_name, category, body) VALUES (?, ?, ?, ?, ?)`
  ).bind(id, u.id, displayName, category, text).run()

  return c.json({ ok: true, id })
})

// Get my reports (logged-in user)
app.get('/api/report/my', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')

  const rows = await c.env.DB.prepare(
    `SELECT id, category, body, status, admin_note as adminNote, created_at as createdAt
     FROM reports WHERE account_id=? ORDER BY created_at DESC LIMIT 20`
  ).bind(u.id).all<any>()

  return c.json({ ok: true, reports: rows.results })
})

// Admin/Teacher: get all reports
app.get('/api/admin/reports', async (c) => {
  const u = requireAdmin(c) || requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const status = c.req.query('status') || 'all'
  let sql = `SELECT id, account_id as accountId, display_name as displayName, category, body, status, admin_note as adminNote, created_at as createdAt, updated_at as updatedAt FROM reports`
  const params: string[] = []
  if (status !== 'all') {
    sql += ` WHERE status=?`
    params.push(status)
  }
  sql += ` ORDER BY created_at DESC LIMIT 100`

  const stmt = params.length > 0
    ? c.env.DB.prepare(sql).bind(...params)
    : c.env.DB.prepare(sql)
  const rows = await stmt.all<any>()

  return c.json({ ok: true, reports: rows.results })
})

// Admin/Teacher: update report status/note
app.put('/api/admin/report/:id', async (c) => {
  const u = requireAdmin(c) || requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  const reportId = c.req.param('id')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_body')

  const validStatuses = ['open', 'in_progress', 'resolved', 'closed']
  const updates: string[] = []
  const vals: string[] = []

  if (body.status && validStatuses.includes(body.status)) {
    updates.push('status=?')
    vals.push(body.status)
  }
  if (typeof body.adminNote === 'string') {
    updates.push('admin_note=?')
    vals.push(body.adminNote.slice(0, 500))
  }
  if (updates.length === 0) return jsonError(c, 400, 'nothing_to_update')

  updates.push("updated_at=datetime('now')")
  vals.push(reportId)

  await c.env.DB.prepare(
    `UPDATE reports SET ${updates.join(', ')} WHERE id=?`
  ).bind(...vals).run()

  return c.json({ ok: true })
})

// Admin/Teacher: delete report
app.delete('/api/admin/report/:id', async (c) => {
  const u = requireAdmin(c) || requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')

  await c.env.DB.prepare(`DELETE FROM reports WHERE id=?`).bind(c.req.param('id')).run()
  return c.json({ ok: true })
})

// -------------------- API: おしらせ (announcements) --------------------

// 管理者のみ: おしらせ作成
app.post('/api/teacher/announcement', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const title = String(body.title || '').trim()
  const text = String(body.body || '').trim()
  const classId = body.classId || null  // null = 全体向け
  if (!title || !text) return jsonError(c, 400, 'title_and_body_required')
  const id = crypto.randomUUID()
  await c.env.DB.prepare(
    `INSERT INTO announcements (id, class_id, teacher_id, title, body) VALUES (?,?,?,?,?)`
  ).bind(id, classId, u.id, title, text).run()
  return c.json({ ok: true, id })
})

// 管理者のみ: おしらせ一覧
app.get('/api/teacher/announcements', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const res = await c.env.DB.prepare(
    `SELECT a.id, a.class_id as classId, a.title, a.body, a.created_at as createdAt, c.name as className
     FROM announcements a LEFT JOIN classes c ON c.id = a.class_id
     ORDER BY a.created_at DESC LIMIT 50`
  ).all<any>()
  return c.json({ ok: true, announcements: res.results })
})

// 管理者のみ: おしらせ削除
app.delete('/api/teacher/announcement/:id', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const annId = c.req.param('id')
  await c.env.DB.prepare(`DELETE FROM announcement_reads WHERE announcement_id=?`).bind(annId).run()
  await c.env.DB.prepare(`DELETE FROM announcements WHERE id=?`).bind(annId).run()
  return c.json({ ok: true })
})

// 生徒: 自分のクラス向け + 全体向けのおしらせ取得
app.get('/api/student/announcements', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  // 自分のクラスIDを取得
  const cm = await c.env.DB.prepare(`SELECT class_id FROM class_members WHERE user_id=? LIMIT 1`).bind(u.id).first<any>()
  const classId = cm?.class_id || null
  // 全体向け(class_id IS NULL) + 自分のクラス向け
  let res
  if (classId) {
    res = await c.env.DB.prepare(
      `SELECT a.id, a.title, a.body, a.created_at as createdAt, a.class_id as classId,
              ar.read_at as readAt
       FROM announcements a
       LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
       WHERE a.class_id IS NULL OR a.class_id = ?
       ORDER BY a.created_at DESC LIMIT 30`
    ).bind(u.id, classId).all<any>()
  } else {
    // クラス未参加 → 全体向けのみ
    res = await c.env.DB.prepare(
      `SELECT a.id, a.title, a.body, a.created_at as createdAt, a.class_id as classId,
              ar.read_at as readAt
       FROM announcements a
       LEFT JOIN announcement_reads ar ON ar.announcement_id = a.id AND ar.user_id = ?
       WHERE a.class_id IS NULL
       ORDER BY a.created_at DESC LIMIT 30`
    ).bind(u.id).all<any>()
  }
  return c.json({ ok: true, announcements: res.results })
})

// 生徒: おしらせ既読マーク
app.post('/api/student/announcement/:id/read', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  const annId = c.req.param('id')
  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO announcement_reads (user_id, announcement_id) VALUES (?,?)`
  ).bind(u.id, annId).run()
  return c.json({ ok: true })
})

// -------------------- API: 連絡帳 (contact notes) --------------------

// 教師: 連絡帳を書く
app.post('/api/teacher/contact-note', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const classId = String(body.classId || '').trim()
  const text = String(body.body || '').trim()
  const dayKey = String(body.dayKey || '').trim()
  const rewardDeadline = body.rewardDeadline || null
  const rewardCoins = Number(body.rewardCoins) || 5
  if (!classId || !text || !dayKey) return jsonError(c, 400, 'classId_body_dayKey_required')
  // classIdが自分のクラスか確認（管理者も含む全員）
  const cls = await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1`).bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 403, 'not_your_class')
  const id = crypto.randomUUID()
  await c.env.DB.prepare(
    `INSERT INTO contact_notes (id, class_id, teacher_id, day_key, body, reward_deadline, reward_coins) VALUES (?,?,?,?,?,?,?)`
  ).bind(id, classId, u.id, dayKey, text, rewardDeadline, rewardCoins).run()
  return c.json({ ok: true, id })
})

// 教師: 連絡帳一覧（自分のクラス）
app.get('/api/teacher/contact-notes', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.query('classId') || ''
  const isAdmin = u.role === 'admin'
  let res
  if (classId) {
    res = await c.env.DB.prepare(
      `SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
       FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
       WHERE cn.class_id = ? ${isAdmin ? '' : 'AND cn.teacher_id = ?'}
       ORDER BY cn.created_at DESC LIMIT 30`
    ).bind(...(isAdmin ? [classId] : [classId, u.id])).all<any>()
  } else {
    res = isAdmin
      ? await c.env.DB.prepare(
          `SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
           FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
           ORDER BY cn.created_at DESC LIMIT 30`
        ).all<any>()
      : await c.env.DB.prepare(
          `SELECT cn.id, cn.class_id as classId, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt, c.name as className
           FROM contact_notes cn LEFT JOIN classes c ON c.id = cn.class_id
           WHERE cn.teacher_id = ?
           ORDER BY cn.created_at DESC LIMIT 30`
        ).bind(u.id).all<any>()
  }
  return c.json({ ok: true, notes: res.results })
})

// 教師: 連絡帳削除
app.delete('/api/teacher/contact-note/:id', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const noteId = c.req.param('id')
  await c.env.DB.prepare(`DELETE FROM contact_note_reads WHERE note_id=?`).bind(noteId).run()
  if (u.role === 'admin') {
    await c.env.DB.prepare(`DELETE FROM contact_notes WHERE id=?`).bind(noteId).run()
  } else {
    await c.env.DB.prepare(`DELETE FROM contact_notes WHERE id=? AND teacher_id=?`).bind(noteId, u.id).run()
  }
  return c.json({ ok: true })
})

// 教師: 連絡帳の既読状況
app.get('/api/teacher/contact-note/:id/reads', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const noteId = c.req.param('id')
  const res = await c.env.DB.prepare(
    `SELECT cnr.user_id as userId, cnr.read_at as readAt, cnr.reward_claimed as rewardClaimed, u.name as studentName
     FROM contact_note_reads cnr JOIN users u ON u.id = cnr.user_id
     WHERE cnr.note_id = ? ORDER BY cnr.read_at ASC`
  ).bind(noteId).all<any>()
  return c.json({ ok: true, reads: res.results })
})

// 生徒（＋教師/管理者のプレビュー用）: 自分のクラスの連絡帳を取得
app.get('/api/student/contact-notes', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  let classId: string | null = null
  // 教師・管理者はclass_membersではなくclassesテーブルから自分のクラスを取得
  if (u.role === 'teacher' || u.role === 'admin') {
    const clsRow = u.role === 'admin'
      ? await c.env.DB.prepare(`SELECT id FROM classes ORDER BY created_at DESC LIMIT 1`).first<any>()
      : await c.env.DB.prepare(`SELECT id FROM classes WHERE teacher_id=? ORDER BY created_at DESC LIMIT 1`).bind(u.id).first<any>()
    classId = clsRow?.id || null
  } else {
    const cm = await c.env.DB.prepare(`SELECT class_id FROM class_members WHERE user_id=? LIMIT 1`).bind(u.id).first<any>()
    classId = cm?.class_id || null
  }
  if (!classId) return c.json({ ok: true, notes: [] })
  const res = await c.env.DB.prepare(
    `SELECT cn.id, cn.day_key as dayKey, cn.body, cn.reward_deadline as rewardDeadline, cn.reward_coins as rewardCoins, cn.created_at as createdAt,
            cnr.read_at as readAt, cnr.reward_claimed as rewardClaimed
     FROM contact_notes cn
     LEFT JOIN contact_note_reads cnr ON cnr.note_id = cn.id AND cnr.user_id = ?
     WHERE cn.class_id = ?
     ORDER BY cn.created_at DESC LIMIT 50`
  ).bind(u.id, classId).all<any>()
  return c.json({ ok: true, notes: res.results })
})

// 生徒: 連絡帳を読んだ（既読+報酬）
app.post('/api/student/contact-note/:id/read', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  const noteId = c.req.param('id')
  // 既に読んでいるか確認
  const existing = await c.env.DB.prepare(`SELECT reward_claimed FROM contact_note_reads WHERE user_id=? AND note_id=? LIMIT 1`).bind(u.id, noteId).first<any>()
  if (existing) return c.json({ ok: true, alreadyRead: true, reward: 0 })
  // 連絡帳情報を取得
  const note = await c.env.DB.prepare(`SELECT reward_deadline, reward_coins FROM contact_notes WHERE id=? LIMIT 1`).bind(noteId).first<any>()
  if (!note) return jsonError(c, 404, 'not_found')
  const now = new Date().toISOString()
  let reward = 0
  let rewardClaimed = 0
  // 締切内なら報酬あり
  if (note.reward_deadline) {
    if (now <= note.reward_deadline) {
      reward = note.reward_coins || 5
      rewardClaimed = 1
    }
  } else {
    // 締切なしなら常に報酬あり
    reward = note.reward_coins || 5
    rewardClaimed = 1
  }
  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO contact_note_reads (user_id, note_id, reward_claimed) VALUES (?,?,?)`
  ).bind(u.id, noteId, rewardClaimed).run()
  return c.json({ ok: true, reward, rewardClaimed: !!rewardClaimed })
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
        <a class="text-sm text-blue-700 underline" href="/signup">児童 新規登録</a>
        <span class="text-sm text-slate-400 mx-1">｜</span>
        <a class="text-sm text-emerald-700 underline" href="/teacher-signup">教師 アカウント申請</a>
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
            pending_approval: '承認待ちです。管理者の承認をお待ちください',
            missing_credentials: 'IDとパスワードを入力してください',
          };
          msg.textContent = errMap[j.error] || (j.error || 'ログインに失敗しました');
          return;
        }
        const me = await fetch('/api/auth/me').then(r=>r.json()).catch(()=>({}));
        if(me.user && me.user.role === 'teacher') { location.href = '/teacher'; }
        else { location.href = '/'; }
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
        name_inappropriate: 'その名前は使えません',
        grade_invalid: '学年を選択してください',
        invalid_json: '入力内容に問題があります',
      };
      document.getElementById('btn').onclick = async () => {
        msg.textContent='';
        const gradeVal = document.getElementById('grade').value;
        const payload = {
          name: document.getElementById('name').value.trim(),
          grade: gradeVal ? Number(gradeVal) : NaN,
          loginId: document.getElementById('loginId').value.trim(),
          password: document.getElementById('password').value,
        };
        // クライアント側バリデーション
        if(!payload.name){ msg.textContent='名前を入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!gradeVal){ msg.textContent='学年を選択してください'; msg.className='text-sm text-red-600'; return; }
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

      <!-- 教師承認 -->
      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">🍎 教師アカウント承認</h2>
        <div id="pendingTeachers" class="space-y-2 text-sm"></div>
      </div>

      <!-- ランキング設定 -->
      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-3">🏆 ランキング設定</h2>
        <div class="space-y-3 text-sm">
          <div class="flex items-center gap-3">
            <span class="font-bold">表示範囲：</span>
            <label class="flex items-center gap-1"><input type="radio" name="rankScope" value="global"/> 全体</label>
            <label class="flex items-center gap-1"><input type="radio" name="rankScope" value="class"/> クラス内のみ</label>
            <label class="flex items-center gap-1"><input type="radio" name="rankScope" value="hidden"/> 非表示</label>
          </div>
          <div class="flex items-center gap-3">
            <span class="font-bold">ランキング機能：</span>
            <label class="flex items-center gap-1"><input type="radio" name="rankEnabled" value="1"/> 有効</label>
            <label class="flex items-center gap-1"><input type="radio" name="rankEnabled" value="0"/> 無効</label>
          </div>
          <button id="saveRankingBtn" class="bg-indigo-600 text-white rounded px-3 py-2">設定を保存</button>
          <p id="rankingMsg" class="text-sm"></p>
        </div>
      </div>

      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">承認待ち / 停止中 児童</h2>
        <div id="pending" class="space-y-2 text-sm"></div>
      </div>

      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">児童一覧</h2>
        <div class="flex flex-wrap gap-2 mb-2 text-sm">
          <input id="filterGrade" class="border p-2 rounded" placeholder="学年" />
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

      async function renderPendingTeachers(){
        const wrap = document.getElementById('pendingTeachers');
        let data;
        try{ data = await api('/api/admin/pending-teachers'); }
        catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; return; }
        wrap.innerHTML='';
        if(!data.teachers.length){ wrap.textContent='承認待ちの教師はいません'; return; }
        for(const t of data.teachers){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.textContent = t.name + '（' + t.loginId + '）' + (t.school ? ' ' + t.school : '');
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2';
          const approve = document.createElement('button');
          approve.className='bg-emerald-600 text-white rounded px-3 py-1';
          approve.textContent='承認';
          approve.onclick = async ()=>{ await api('/api/admin/approve-teacher/'+t.id,{method:'POST'}); await renderPendingTeachers(); };
          right.appendChild(approve);
          const reject = document.createElement('button');
          reject.className='bg-red-600 text-white rounded px-3 py-1';
          reject.textContent='却下';
          reject.onclick = async ()=>{
            if(!confirm(t.name + 'の申請を却下・削除しますか？')){ return; }
            await api('/api/admin/reject-teacher/'+t.id,{method:'DELETE'}); await renderPendingTeachers();
          };
          right.appendChild(reject);
          div.appendChild(right);
          wrap.appendChild(div);
        }
      }

      async function loadRankingSettings(){
        try{
          const d = await api('/api/admin/settings');
          const scope = d.settings.ranking_scope || 'class';
          const enabled = d.settings.ranking_enabled !== '0';
          document.querySelectorAll('[name="rankScope"]').forEach(r=>{ r.checked = (r.value === scope); });
          document.querySelectorAll('[name="rankEnabled"]').forEach(r=>{ r.checked = (r.value === (enabled?'1':'0')); });
        }catch(e){ console.error('settings load error', e); }
      }

      document.getElementById('saveRankingBtn').onclick = async () => {
        const msg = document.getElementById('rankingMsg');
        msg.textContent=''; msg.className='text-sm';
        const scope = [...document.querySelectorAll('[name="rankScope"]')].find(r=>r.checked)?.value;
        const enabled = [...document.querySelectorAll('[name="rankEnabled"]')].find(r=>r.checked)?.value;
        try{
          await api('/api/admin/settings',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({ranking_scope:scope,ranking_enabled:enabled})});
          msg.textContent='保存しました'; msg.className='text-sm text-green-700';
        }catch(e){ msg.textContent=String(e.message||e); msg.className='text-sm text-red-600'; }
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
        const qs = new URLSearchParams();
        if(grade) qs.set('grade', grade);
        const u = await api('/api/admin/users?' + qs.toString());
        const wrap = document.getElementById('users');
        wrap.innerHTML='';
        if(!u.users.length){ wrap.textContent='該当なし'; return; }
        for(const x of u.users){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.textContent = x.grade + '年 / ' + x.name + '（' + x.loginId + '）' + (x.isActive? '' : ' [停止/未承認]');
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2 flex-wrap';

          const gradeBtn = document.createElement('button');
          gradeBtn.className='bg-indigo-600 text-white rounded px-3 py-1';
          gradeBtn.textContent='学年変更';
          gradeBtn.onclick = async ()=>{
            const g = prompt(x.name + ' の学年を入力（1〜6）', x.grade);
            if(!g) return;
            const n = Number(g);
            if(!Number.isInteger(n)||n<1||n>6){ alert('1〜6の数字を入力してください'); return; }
            await api('/api/admin/user-grade',{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({userId:x.id,grade:n})});
            await loadAll();
          };
          right.appendChild(gradeBtn);

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
        await renderPendingTeachers();
        await loadRankingSettings();
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

// -------------------- Page: teacher signup --------------------
app.get('/teacher-signup', (c) => {
  return c.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>教師 アカウント申請</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="min-h-screen bg-emerald-50 p-4">
    <div class="max-w-md mx-auto bg-white rounded-xl shadow p-6">
      <h1 class="text-xl font-bold mb-1">教師 アカウント申請</h1>
      <p class="text-xs text-slate-500 mb-4">申請後、管理者が承認するとログインできるようになります。</p>
      <div class="space-y-3">
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">お名前</label>
          <input id="name" class="w-full border p-2 rounded" placeholder="例：田中 健一"/>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">学校名</label>
          <input id="school" class="w-full border p-2 rounded" placeholder="例：〇〇市立△△小学校"/>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">ログインID（自分で決める）</label>
          <input id="loginId" class="w-full border p-2 rounded" placeholder="半角英数字 3文字以上"/>
        </div>
        <div>
          <label class="text-sm font-bold text-gray-700 mb-1 block">パスワード</label>
          <input id="password" type="password" class="w-full border p-2 rounded" placeholder="6文字以上"/>
        </div>
        <button id="btn" class="w-full bg-emerald-600 text-white rounded p-2 font-bold">申請する</button>
        <p id="msg" class="text-sm"></p>
        <a class="text-sm text-blue-700 underline" href="/login">← ログインへ戻る</a>
      </div>
    </div>
    <script>
      const msg = document.getElementById('msg');
      document.getElementById('btn').onclick = async () => {
        msg.textContent=''; msg.className='text-sm';
        const name = document.getElementById('name').value.trim();
        const school = document.getElementById('school').value.trim();
        const loginId = document.getElementById('loginId').value.trim();
        const password = document.getElementById('password').value;
        if(!name){ msg.textContent='お名前を入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!loginId || loginId.length < 3){ msg.textContent='ログインIDは3文字以上にしてください'; msg.className='text-sm text-red-600'; return; }
        if(!password || password.length < 6){ msg.textContent='パスワードは6文字以上にしてください'; msg.className='text-sm text-red-600'; return; }
        document.getElementById('btn').disabled = true;
        const r = await fetch('/api/auth/teacher-signup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name,school,loginId,password})});
        const j = await r.json().catch(()=>({}));
        if(!r.ok){
          const errMap = { loginId_too_short:'IDは3文字以上', loginId_taken:'このIDはすでに使われています', password_too_short:'パスワードは6文字以上', name_required:'名前を入力してください' };
          msg.textContent = errMap[j.error] || (j.error || '申請に失敗しました');
          msg.className='text-sm text-red-600';
          document.getElementById('btn').disabled = false;
          return;
        }
        msg.textContent = '申請しました！管理者の承認をお待ちください。';
        msg.className='text-sm text-green-700';
        setTimeout(()=>{ location.href='/login'; }, 3000);
      };
    </script>
  </body></html>`)
})

// -------------------- Page: teacher dashboard --------------------
app.get('/teacher', (c) => {
  return c.html(`<!doctype html><html lang="ja"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>教師ダッシュボード</title><script src="https://cdn.tailwindcss.com"></script></head>
  <body class="min-h-screen bg-emerald-50 p-4">
    <div class="max-w-4xl mx-auto space-y-4">
      <div class="bg-white rounded-xl shadow p-4 flex items-center justify-between">
        <div>
          <h1 class="text-xl font-bold">教師ダッシュボード</h1>
          <p id="teacherInfo" class="text-sm text-slate-500"></p>
        </div>
        <div class="flex gap-2 items-center">
          <a href="/" class="text-sm px-3 py-1 rounded bg-emerald-100 hover:bg-emerald-200 text-emerald-700 font-bold transition">🎮 ゲーム画面へ</a>
          <button id="logout" class="text-sm px-3 py-1 rounded bg-gray-200 hover:bg-red-100 hover:text-red-700 text-gray-600 font-bold transition">ログアウト</button>
        </div>
      </div>

      <!-- クラス作成 -->
      <div class="bg-white rounded-xl shadow p-4">
        <h2 class="font-bold mb-3">クラス作成</h2>
        <div class="flex gap-2">
          <input id="newClassName" class="flex-1 border p-2 rounded" placeholder="クラス名（例：4年1組）"/>
          <button id="createClassBtn" class="bg-emerald-600 text-white rounded px-4 py-2 font-bold">作成</button>
        </div>
        <p id="createMsg" class="text-sm mt-1"></p>
      </div>

      <!-- タブナビ -->
      <div class="bg-white rounded-xl shadow p-1 flex gap-1">
        <button id="tabClasses" class="flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white" onclick="switchTab('classes')">📚 クラス管理</button>
        <button id="tabContact" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('contact')">📓 連絡帳</button>
        <button id="tabAnnouncements" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('announcements')">📢 おしらせ</button>
        <button id="tabHomework" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('homework')">📬 家庭学習</button>
        <button id="tabReports" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('reports')">📝 報告</button>
        <button id="tabAnalytics" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('analytics')">📊 学習分析</button>
      </div>

      <!-- クラス一覧タブ -->
      <div id="tabPaneClasses" class="space-y-4">
        <div id="classList" class="space-y-4"></div>
      </div>

      <!-- 学習分析タブ -->
      <div id="tabPaneAnalytics" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <div class="flex gap-2 mb-3 flex-wrap items-center">
            <select id="analyticsClassFilter" class="border p-2 rounded text-sm bg-white">
              <option value="">クラスを選択...</option>
            </select>
            <button onclick="loadUnitAnalytics()" class="bg-purple-600 text-white rounded px-3 py-2 text-sm font-bold">📊 分析を表示</button>
            <span class="text-xs text-slate-400">※5問以上やった単元を表示します</span>
          </div>
          <div id="analyticsContent"></div>
        </div>
      </div>

      <!-- 家庭学習提出一覧タブ -->
      <div id="tabPaneHomework" class="hidden space-y-3">
        <!-- 先生メニュー（週の課題設定） -->
        <div class="bg-green-50 border border-green-200 rounded-xl p-4 space-y-3">
          <div class="font-bold text-sm text-green-800">📋 先生メニュー（今週の課題）</div>
          <div class="text-xs text-green-700 mb-2">クラス全体に出す漢字スキル・計算スキルのページ指示を設定します。生徒の家庭学習シートに表示されます。</div>
          <div class="flex gap-2 items-center flex-wrap">
            <select id="menuClassFilter" class="border p-2 rounded text-sm bg-white"></select>
            <span id="menuWeekLabel" class="text-xs text-slate-500 font-bold"></span>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-3 gap-2">
            <div>
              <label class="text-xs font-bold text-green-800">漢字スキル</label>
              <input id="menuKanjiPage" class="w-full border border-green-300 rounded-lg p-2 text-sm" placeholder="例：p.20まで"/>
            </div>
            <div>
              <label class="text-xs font-bold text-green-800">計算スキル</label>
              <input id="menuKeisanPage" class="w-full border border-green-300 rounded-lg p-2 text-sm" placeholder="例：p.15まで"/>
            </div>
            <div>
              <label class="text-xs font-bold text-green-800">その他</label>
              <input id="menuOtherTasks" class="w-full border border-green-300 rounded-lg p-2 text-sm" placeholder="例：音読3回"/>
            </div>
          </div>
          <div class="flex gap-2 items-center">
            <button onclick="saveWeeklyMenu()" class="bg-green-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">💾 保存</button>
            <span id="menuSaveMsg" class="text-xs text-green-700"></span>
          </div>
        </div>

        <!-- Gemini連携パネル -->
        <div class="bg-amber-50 border border-amber-200 rounded-xl p-3 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="font-bold text-sm text-amber-800">🤖 Geminiで一括コメント返却</div>
            <button onclick="toggleGemPrompt()" class="text-xs text-amber-700 underline hover:no-underline">📝 Gem設定用プロンプトを表示</button>
          </div>
          <!-- Gemプロンプト表示エリア（初期非表示） -->
          <div id="gemPromptArea" class="hidden bg-white border border-amber-300 rounded-lg p-3 space-y-2">
            <div class="text-xs font-bold text-amber-800">Gemini の「Gem」に以下をシステムプロンプトとして設定してください</div>
            <pre id="gemPromptText" class="text-xs text-slate-700 whitespace-pre-wrap bg-slate-50 rounded p-2 border select-all">あなたは小学校の担任の先生の代わりにコメントを書くアシスタントです。

【ルール】
- 児童の「今日の振り返り」と「過去の振り返り」を読む
- 各児童への温かく具体的な先生コメントを30文字以内で考える
- その子の成長・課題・継続している努力を踏まえた個別最適な内容にする
- 必ずJSON形式だけで返答する（他のテキストは一切不要）

【返答形式】
{"comments":["コメント1","コメント2","コメント3",...]}

貼り付けられたテキストを読んだら、上記形式で即座に返答してください。</pre>
            <button onclick="copyGemPrompt()" class="bg-amber-500 text-white rounded px-3 py-1 text-xs font-bold">📋 このプロンプトをコピー</button>
            <div id="gemPromptCopyMsg" class="text-xs text-emerald-600"></div>
          </div>
          <div class="flex items-center gap-3 flex-wrap">
            <span class="text-xs text-amber-700 font-bold">① </span>
            <button onclick="copyReflections()" class="bg-amber-500 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">📋 振り返りをコピー</button>
            <span class="text-xs text-amber-600">→ GeminiのGemに貼り付けてコメントを生成 →</span>
          </div>
          <div class="space-y-1">
            <div class="text-xs font-bold text-amber-700">② Geminiの返答をここに貼り付け</div>
            <textarea id="aiPasteArea" rows="4" class="w-full border border-amber-300 rounded-lg p-2 text-xs bg-white focus:outline-none focus:border-amber-500" placeholder='{"comments":["よく頑張りました！","毎日続けてえらいね",...]}&#10;または番号付きリスト形式でもOK'></textarea>
          </div>
          <button onclick="pasteAndBulkReturn()" class="w-full bg-emerald-600 text-white rounded-lg px-4 py-2.5 text-sm font-bold shadow hover:opacity-90">✅ ③ 貼り付けて一括返却</button>
          <div id="aiGenMsg" class="text-xs text-amber-700 min-h-[16px]"></div>
        </div>
        <div class="bg-white rounded-xl shadow p-4">
          <div class="flex gap-2 mb-3 flex-wrap items-center">
            <select id="hwClassFilter" class="border p-2 rounded text-sm bg-white"></select>
            <select id="hwStatusFilter" class="border p-2 rounded text-sm bg-white">
              <option value="">すべて</option>
              <option value="unreturned">未返却</option>
              <option value="returned">返却済み</option>
            </select>
            <button onclick="loadHomework()" class="bg-emerald-600 text-white rounded px-3 py-1 text-sm font-bold">絞り込み</button>
            <button onclick="loadHomework()" class="bg-slate-200 rounded px-3 py-1 text-sm">更新</button>
            <button onclick="bulkReturnNoComment()" class="ml-auto bg-blue-500 text-white rounded-lg px-4 py-1.5 text-sm font-bold shadow hover:opacity-90">✅ 未返却をまとめて返却（コメントなし）</button>
          </div>
          <div id="hwList" class="space-y-3 text-sm"></div>
        </div>
      </div>

      <!-- 連絡帳タブ -->
      <div id="tabPaneContact" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">連絡帳を書く</h3>
          <div class="space-y-2">
            <select id="cnClassFilter" class="border p-2 rounded text-sm bg-white w-full"></select>
            <div class="flex gap-2">
              <div class="flex-1">
                <label class="text-xs font-bold text-gray-600">日付</label>
                <input id="cnDayKey" type="date" class="w-full border p-2 rounded text-sm"/>
              </div>
              <div class="flex-1">
                <label class="text-xs font-bold text-gray-600">報酬締切（任意）</label>
                <input id="cnDeadline" type="datetime-local" class="w-full border p-2 rounded text-sm"/>
              </div>
              <div class="w-20">
                <label class="text-xs font-bold text-gray-600">報酬コイン</label>
                <input id="cnCoins" type="number" value="5" min="0" max="100" class="w-full border p-2 rounded text-sm"/>
              </div>
            </div>
            <textarea id="cnBody" class="w-full border p-2 rounded text-sm" rows="4" placeholder="明日の持ち物や連絡事項を入力..."></textarea>
            <button onclick="sendContactNote()" class="bg-blue-500 hover:bg-blue-600 text-white rounded px-4 py-2 font-bold text-sm">📓 送信</button>
            <p id="cnMsg" class="text-sm"></p>
          </div>
        </div>
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">送信済み連絡帳</h3>
          <div id="cnList" class="space-y-3 text-sm"></div>
        </div>
      </div>

      <!-- おしらせタブ -->
      <div id="tabPaneAnnouncements" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">おしらせ作成</h3>
          <div class="space-y-2">
            <select id="annClassFilter" class="border p-2 rounded text-sm bg-white w-full">
              <option value="">全体（クラス関係なく全員）</option>
            </select>
            <input id="annTitle" class="w-full border p-2 rounded text-sm" placeholder="タイトル（例：イベント開催！）"/>
            <textarea id="annBody" class="w-full border p-2 rounded text-sm" rows="4" placeholder="内容を入力..."></textarea>
            <button id="annSendBtn" onclick="sendAnnouncement()" class="bg-orange-500 hover:bg-orange-600 text-white rounded px-4 py-2 font-bold text-sm">📢 送信</button>
            <p id="annMsg" class="text-sm"></p>
          </div>
        </div>
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">送信済みおしらせ</h3>
          <div id="annList" class="space-y-3 text-sm"></div>
        </div>
      </div>

      <!-- 報告一覧タブ -->
      <div id="tabPaneReports" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <div class="flex gap-2 mb-3 flex-wrap items-center">
            <select id="rptStatusFilter" class="border p-2 rounded text-sm bg-white">
              <option value="all">すべて</option>
              <option value="open">📬 受付中</option>
              <option value="in_progress">🔧 対応中</option>
              <option value="resolved">✅ 解決済み</option>
              <option value="closed">🗂️ 終了</option>
            </select>
            <button onclick="loadAdminReports()" class="bg-gray-600 text-white rounded px-3 py-1 text-sm font-bold">絞り込み</button>
            <span id="rptCount" class="text-xs text-gray-500 ml-auto"></span>
          </div>
          <div id="adminReportList" class="space-y-3 text-sm"></div>
        </div>
      </div>
    </div>

    <script>
      async function api(path, opt){
        const r = await fetch(path, opt);
        const j = await r.json().catch(()=>({}));
        if(!r.ok) throw new Error(j.error || 'error');
        return j;
      }

      function escH(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

      function switchTab(tab){
        ['classes','contact','announcements','homework','reports','analytics'].forEach(function(t){
          var pane = document.getElementById('tabPane' + t.charAt(0).toUpperCase() + t.slice(1));
          if(pane) pane.classList.toggle('hidden', tab !== t);
          var btn = document.getElementById('tab' + t.charAt(0).toUpperCase() + t.slice(1));
          if(btn) btn.className = tab===t
            ? 'flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white'
            : 'flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100';
        });
        if(tab === 'homework') { loadHomework(); loadWeeklyMenu(); }
        if(tab === 'reports') loadAdminReports();
        if(tab === 'announcements') loadAnnouncements();
        if(tab === 'contact') loadContactNotes();
      }

      async function loadUnitAnalytics(){
        const wrap = document.getElementById('analyticsContent');
        const classId = document.getElementById('analyticsClassFilter').value;
        if(!classId){ wrap.innerHTML='<p class="text-slate-400 text-sm">クラスを選択してください</p>'; return; }
        wrap.innerHTML='<p class="text-slate-400 text-sm">読み込み中... ⏳</p>';
        let data;
        try{ data = await api('/api/teacher/class/'+encodeURIComponent(classId)+'/unit-analytics'); }
        catch(e){ wrap.innerHTML='<p class="text-red-600 text-sm">読み込みエラー: '+escH(String(e.message||e))+'</p>'; return; }

        const students = data.students || [];
        const unitSummary = data.unitSummary || [];
        if(!students.length){ wrap.innerHTML='<p class="text-slate-400 text-sm">まだ生徒がいません</p>'; return; }

        // 教科別色
        const subjColor = {math:'bg-blue-100 text-blue-800', jp:'bg-pink-100 text-pink-800', soc:'bg-green-100 text-green-800', science:'bg-yellow-100 text-yellow-800'};
        const subjName = {math:'算数', jp:'国語', soc:'社会', science:'理科'};

        // ① クラス全体の教科別平均
        let html = '<div class="mb-4"><h3 class="font-bold text-slate-700 mb-2">📊 クラス全体 教科別正解率</h3>';
        html += '<div class="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">';
        ['math','jp','soc','science'].forEach(subj=>{
          const rows = students.filter(s=>s.bySubject[subj] && s.bySubject[subj].total >= 10);
          if(!rows.length){ html += '<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">'+escH(subjName[subj]||subj)+'</div><div class="font-bold text-slate-400">データなし</div></div>'; return; }
          const avg = Math.round(rows.reduce((s,r)=>s+(r.bySubject[subj].acc||0),0)/rows.length);
          const color = avg>=80?'text-green-600':avg>=60?'text-yellow-600':'text-red-600';
          html += '<div class="rounded-lg border p-3 text-center"><div class="text-xs font-bold text-slate-500">'+escH(subjName[subj]||subj)+'</div>'
            +'<div class="text-2xl font-black '+color+'">'+avg+'%</div>'
            +'<div class="text-xs text-slate-400">'+rows.length+'人分</div></div>';
        });
        html += '</div></div>';

        // ② 単元別クラス平均（苦手順）
        if(unitSummary.length > 0){
          html += '<div class="mb-4"><h3 class="font-bold text-slate-700 mb-2">⚠️ 単元別クラス平均（苦手順）</h3>';
          html += '<div class="overflow-x-auto"><table class="w-full text-xs border-collapse">';
          html += '<thead><tr class="bg-slate-50"><th class="border px-2 py-1 text-left">教科</th><th class="border px-2 py-1 text-left">単元名</th><th class="border px-2 py-1 text-right">クラス平均</th><th class="border px-2 py-1 text-right">人数</th></tr></thead><tbody>';
          unitSummary.slice(0,15).forEach((u,i)=>{
            const avg = u.classAvg;
            const bar = avg!=null ? Math.round(avg) : null;
            const color = avg==null?'text-slate-400':avg>=80?'text-green-600':avg>=60?'text-yellow-600':'text-red-600 font-black';
            html += '<tr class="'+(i%2===0?'':'bg-slate-50')+'">'
              +'<td class="border px-2 py-1">'+escH(u.subject||'')+'</td>'
              +'<td class="border px-2 py-1 font-bold">'+escH(u.name||u.mode)+'</td>'
              +'<td class="border px-2 py-1 text-right '+color+'">'+(avg!=null?avg+'%':'−')+'</td>'
              +'<td class="border px-2 py-1 text-right">'+u.studentCount+'</td></tr>';
          });
          html += '</tbody></table></div></div>';
        }

        // ③ 生徒別一覧
        html += '<div><h3 class="font-bold text-slate-700 mb-2">👤 生徒別 学習状況</h3>';
        html += '<div class="overflow-x-auto"><table class="w-full text-xs border-collapse">';
        html += '<thead><tr class="bg-slate-50">'
          +'<th class="border px-2 py-1 text-left sticky left-0 bg-slate-50">名前</th>'
          +'<th class="border px-2 py-1 text-center">🔥連続</th>'
          +'<th class="border px-2 py-1 text-center">算数</th>'
          +'<th class="border px-2 py-1 text-center">国語</th>'
          +'<th class="border px-2 py-1 text-center">社会</th>'
          +'<th class="border px-2 py-1 text-center">理科</th>'
          +'</tr></thead><tbody>';
        students.forEach((s,i)=>{
          const row = '<tr class="'+(i%2===0?'':'bg-slate-50')+'">'
            +'<td class="border px-2 py-1 font-bold sticky left-0 '+(i%2===0?'bg-white':'bg-slate-50')+'">'+escH(s.name)+'</td>'
            +'<td class="border px-2 py-1 text-center">'+(s.learnStreak>0?'🔥'+s.learnStreak:'−')+'</td>'
            +['math','jp','soc','science'].map(subj=>{
              const d = s.bySubject[subj];
              if(!d||d.total<5) return '<td class="border px-2 py-1 text-center text-slate-300">−</td>';
              const c = d.acc>=80?'text-green-600':d.acc>=60?'text-yellow-600':'text-red-600 font-black';
              return '<td class="border px-2 py-1 text-center '+c+'">'+d.acc+'%<span class="text-slate-300 ml-0.5 text-[10px]">('+d.total+')</span></td>';
            }).join('')
            +'</tr>';
          html += row;
        });
        html += '</tbody></table></div>';
        html += '<p class="text-xs text-slate-400 mt-1">括弧内は解答数。5問未満は「−」表示。</p></div>';

        wrap.innerHTML = html;
      }

      document.getElementById('logout').onclick = async () => {
        await fetch('/api/auth/logout',{method:'POST'});
        location.href='/login';
      };

      document.getElementById('createClassBtn').onclick = async () => {
        const msg = document.getElementById('createMsg');
        msg.textContent=''; msg.className='text-sm';
        const name = document.getElementById('newClassName').value.trim();
        if(!name){ msg.textContent='クラス名を入力してください'; msg.className='text-sm text-red-600'; return; }
        try{
          await api('/api/teacher/class',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name})});
          document.getElementById('newClassName').value='';
          msg.textContent='クラスを作成しました';
          msg.className='text-sm text-green-700';
          await renderClasses();
        }catch(e){
          msg.textContent=String(e.message||e);
          msg.className='text-sm text-red-600';
        }
      };

      async function renderClasses(){
        const wrap = document.getElementById('classList');
        wrap.innerHTML='<p class="text-sm text-slate-400">読み込み中...</p>';
        let data;
        try{ data = await api('/api/teacher/classes'); }
        catch(e){ wrap.innerHTML='<p class="text-sm text-red-600">読み込みエラー</p>'; return; }
        wrap.innerHTML='';
        if(!data.classes.length){ wrap.innerHTML='<p class="text-sm text-slate-400 bg-white rounded-xl shadow p-4">クラスはまだありません。上から作成してください。</p>'; return; }

        // クラスフィルター選択肢を更新
        const sel = document.getElementById('hwClassFilter');
        sel.innerHTML = '<option value="">全クラス</option>';
        data.classes.forEach(c => { sel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
        // 学習分析タブのクラスフィルターも更新
        const analyticsSel = document.getElementById('analyticsClassFilter');
        if(analyticsSel){
          analyticsSel.innerHTML = '<option value="">クラスを選択...</option>';
          data.classes.forEach(c => { analyticsSel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
        }

        for(const cls of data.classes){
          const card = document.createElement('div');
          card.className='bg-white rounded-xl shadow p-4';
          const header = document.createElement('div');
          header.className='flex items-center justify-between mb-3';
          const title = document.createElement('div');
          title.innerHTML = '<span class="font-bold text-lg">' + escH(cls.name) + '</span>'
            + ' <span class="text-sm text-slate-400 ml-2 select-all font-mono bg-slate-100 px-2 py-0.5 rounded">参加コード: ' + escH(cls.classCode) + '</span>'
            + ' <span class="text-xs text-slate-400 ml-2">生徒数: ' + cls.memberCount + '人</span>';
          header.appendChild(title);
          const btnGroup = document.createElement('div');
          btnGroup.className='flex items-center gap-2';
          // ランキング参加トグルボタン
          const rankBtn = document.createElement('button');
          const isEnabled = !!cls.rankingEnabled;
          rankBtn.className = isEnabled
            ? 'text-xs px-2 py-1 rounded font-bold bg-emerald-100 text-emerald-700 border border-emerald-300 hover:bg-emerald-200'
            : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
          rankBtn.textContent = isEnabled ? '🏆 ランキング参加中' : '🏆 ランキング不参加';
          rankBtn.title = isEnabled ? 'クリックでランキング参加を停止' : 'クリックでランキング参加を許可';
          rankBtn.onclick = async ()=>{
            const newVal = !rankBtn.dataset.enabled;
            rankBtn.dataset.enabled = newVal ? '1' : '';
            try{
              await api('/api/teacher/class/'+cls.id+'/ranking-toggle',{
                method:'PUT', headers:{'content-type':'application/json'},
                body: JSON.stringify({enabled: newVal})
              });
              rankBtn.className = newVal
                ? 'text-xs px-2 py-1 rounded font-bold bg-emerald-100 text-emerald-700 border border-emerald-300 hover:bg-emerald-200'
                : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
              rankBtn.textContent = newVal ? '🏆 ランキング参加中' : '🏆 ランキング不参加';
              rankBtn.title = newVal ? 'クリックでランキング参加を停止' : 'クリックでランキング参加を許可';
            } catch(e){ alert(String(e.message||e)); }
          };
          rankBtn.dataset.enabled = isEnabled ? '1' : '';
          btnGroup.appendChild(rankBtn);
          // 家庭学習ON/OFFトグルボタン
          const hwBtn = document.createElement('button');
          const hwEnabled = cls.homeworkEnabled !== 0 && cls.homeworkEnabled !== '0';
          hwBtn.className = hwEnabled
            ? 'text-xs px-2 py-1 rounded font-bold bg-blue-100 text-blue-700 border border-blue-300 hover:bg-blue-200'
            : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
          hwBtn.textContent = hwEnabled ? '📝 家庭学習ON' : '📝 家庭学習OFF';
          hwBtn.title = hwEnabled ? 'クリックで家庭学習を非表示にする' : 'クリックで家庭学習を表示する';
          hwBtn.dataset.enabled = hwEnabled ? '1' : '';
          hwBtn.onclick = async ()=>{
            const newVal = !hwBtn.dataset.enabled;
            hwBtn.dataset.enabled = newVal ? '1' : '';
            try{
              await api('/api/teacher/class/'+cls.id+'/homework-toggle',{
                method:'PUT', headers:{'content-type':'application/json'},
                body: JSON.stringify({enabled: newVal})
              });
              hwBtn.className = newVal
                ? 'text-xs px-2 py-1 rounded font-bold bg-blue-100 text-blue-700 border border-blue-300 hover:bg-blue-200'
                : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
              hwBtn.textContent = newVal ? '📝 家庭学習ON' : '📝 家庭学習OFF';
              hwBtn.title = newVal ? 'クリックで家庭学習を非表示にする' : 'クリックで家庭学習を表示する';
            } catch(e){ alert(String(e.message||e)); }
          };
          btnGroup.appendChild(hwBtn);
          // 連絡帳ON/OFFトグルボタン
          const ctBtn = document.createElement('button');
          const ctEnabled = cls.contactEnabled !== 0 && cls.contactEnabled !== '0';
          ctBtn.className = ctEnabled
            ? 'text-xs px-2 py-1 rounded font-bold bg-cyan-100 text-cyan-700 border border-cyan-300 hover:bg-cyan-200'
            : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
          ctBtn.textContent = ctEnabled ? '📓 連絡帳ON' : '📓 連絡帳OFF';
          ctBtn.title = ctEnabled ? 'クリックで連絡帳を非表示にする' : 'クリックで連絡帳を表示する';
          ctBtn.dataset.enabled = ctEnabled ? '1' : '';
          ctBtn.onclick = async ()=>{
            const newVal = !ctBtn.dataset.enabled;
            ctBtn.dataset.enabled = newVal ? '1' : '';
            try{
              await api('/api/teacher/class/'+cls.id+'/contact-toggle',{
                method:'PUT', headers:{'content-type':'application/json'},
                body: JSON.stringify({enabled: newVal})
              });
              ctBtn.className = newVal
                ? 'text-xs px-2 py-1 rounded font-bold bg-cyan-100 text-cyan-700 border border-cyan-300 hover:bg-cyan-200'
                : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-500 border border-slate-300 hover:bg-slate-200';
              ctBtn.textContent = newVal ? '📓 連絡帳ON' : '📓 連絡帳OFF';
              ctBtn.title = newVal ? 'クリックで連絡帳を非表示にする' : 'クリックで連絡帳を表示する';
            } catch(e){ alert(String(e.message||e)); }
          };
          btnGroup.appendChild(ctBtn);
          const delBtn = document.createElement('button');
          delBtn.className='text-xs text-red-500 hover:text-red-700 border border-red-200 rounded px-2 py-1';
          delBtn.textContent='削除';
          delBtn.onclick = async ()=>{
            if(!confirm(cls.name + ' を削除しますか？\\n生徒のクラス参加も解除されます。')){ return; }
            try{ await api('/api/teacher/class/'+cls.id,{method:'DELETE'}); await renderClasses(); }
            catch(e){ alert(String(e.message||e)); }
          };
          btnGroup.appendChild(delBtn);
          header.appendChild(btnGroup);
          card.appendChild(header);

          const rankDiv = document.createElement('div');
          rankDiv.innerHTML='<p class="text-xs text-slate-400">ランキングを読み込み中...</p>';
          card.appendChild(rankDiv);
          wrap.appendChild(card);

          api('/api/teacher/class/'+cls.id+'/ranking').then(rd=>{
            if(!rd.members.length){ rankDiv.innerHTML='<p class="text-xs text-slate-400">まだ生徒がいません</p>'; return; }
            let html = '<div class="overflow-x-auto"><table class="w-full text-xs border-collapse"><thead><tr class="bg-slate-50">'
              + '<th class="border px-2 py-1 text-left">順位</th><th class="border px-2 py-1 text-left">名前</th>'
              + '<th class="border px-2 py-1 text-right">総合Lv</th><th class="border px-2 py-1 text-right">モンスター数</th><th class="border px-2 py-1 text-right">正解数</th>'
              + '</tr></thead><tbody>';
            rd.members.forEach((m,i)=>{
              html += '<tr class="'+(i%2===0?'bg-white':'bg-slate-50')+'">'
                +'<td class="border px-2 py-1 text-center font-bold">'+(i+1)+'</td>'
                +'<td class="border px-2 py-1">'+escH(m.displayName||m.userId)+'</td>'
                +'<td class="border px-2 py-1 text-right">'+(m.totalLevel||0)+'</td>'
                +'<td class="border px-2 py-1 text-right">'+(m.monsterCount||0)+'</td>'
                +'<td class="border px-2 py-1 text-right">'+(m.correctCount||0)+'</td></tr>';
            });
            html += '</tbody></table></div>';
            rankDiv.innerHTML = html;
          }).catch(()=>{ rankDiv.innerHTML='<p class="text-xs text-red-400">ランキング取得エラー</p>'; });
        }
      }

      // 家庭学習提出一覧
      // ISO週番号キーを返す
      function getWeekKeyLocal(date){
        var d = date || new Date();
        var tmp = new Date(Date.UTC(d.getFullYear(), d.getMonth(), d.getDate()));
        tmp.setUTCDate(tmp.getUTCDate() + 4 - (tmp.getUTCDay() || 7));
        var yearStart = new Date(Date.UTC(tmp.getUTCFullYear(), 0, 1));
        var weekNo = Math.ceil((((tmp.getTime() - yearStart.getTime()) / 86400000) + 1) / 7);
        return tmp.getUTCFullYear() + '-W' + String(weekNo).padStart(2, '0');
      }

      async function loadWeeklyMenu(){
        try{
          var classFilter = document.getElementById('menuClassFilter');
          var weekLabel = document.getElementById('menuWeekLabel');
          var wk = getWeekKeyLocal(new Date());
          if(weekLabel) weekLabel.textContent = '今週: ' + wk;

          // クラス一覧をメニューフィルターにも反映
          if(classFilter && classFilter.options.length <= 1){
            var cdata = await api('/api/teacher/classes');
            var classes = (cdata && cdata.classes) || [];
            classFilter.innerHTML = '';
            classes.forEach(function(cls){
              var opt = document.createElement('option');
              opt.value = cls.id;
              opt.textContent = cls.name;
              classFilter.appendChild(opt);
            });
          }

          var classId = classFilter ? classFilter.value : '';
          if(!classId) return;

          var data = await api('/api/teacher/class/' + encodeURIComponent(classId) + '/weekly-menu?weekKey=' + encodeURIComponent(wk));
          var menu = (data && data.menu) || {};
          document.getElementById('menuKanjiPage').value = menu.kanji_page || menu.kanjiPage || '';
          document.getElementById('menuKeisanPage').value = menu.keisan_page || menu.keisanPage || '';
          document.getElementById('menuOtherTasks').value = menu.other_tasks || menu.otherTasks || '';
        }catch(e){ console.warn('loadWeeklyMenu error:', e); }
      }

      async function saveWeeklyMenu(){
        var msg = document.getElementById('menuSaveMsg');
        try{
          var classId = document.getElementById('menuClassFilter').value;
          if(!classId){ if(msg) msg.textContent = 'クラスを選択してください'; return; }
          var wk = getWeekKeyLocal(new Date());
          var body = {
            weekKey: wk,
            kanjiPage: document.getElementById('menuKanjiPage').value || '',
            keisanPage: document.getElementById('menuKeisanPage').value || '',
            otherTasks: document.getElementById('menuOtherTasks').value || '',
          };
          await api('/api/teacher/class/' + encodeURIComponent(classId) + '/weekly-menu', {
            method: 'POST',
            headers: {'content-type':'application/json'},
            body: JSON.stringify(body),
          });
          if(msg) msg.textContent = '✅ 保存しました（' + wk + '）';
          setTimeout(function(){ if(msg) msg.textContent = ''; }, 3000);
        }catch(e){
          if(msg) msg.textContent = '⚠️ 保存に失敗しました';
        }
      }

      async function loadHomework(){
        const wrap = document.getElementById('hwList');
        wrap.innerHTML='<p class="text-slate-400">読み込み中...</p>';
        const classId = document.getElementById('hwClassFilter').value;
        const status = document.getElementById('hwStatusFilter').value;
        let qs = classId ? '?classId='+encodeURIComponent(classId) : '';
        let data;
        try{ data = await api('/api/teacher/homework'+qs); }
        catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; return; }
        let list = data.submissions || [];
        if(status === 'unreturned') list = list.filter(s => !s.returnedAt);
        if(status === 'returned')   list = list.filter(s => !!s.returnedAt);
        if(!list.length){ wrap.innerHTML='<p class="text-slate-400">提出がありません</p>'; return; }
        wrap.innerHTML='';
        for(const s of list){
          const card = document.createElement('div');
          const returned = !!s.returnedAt;
          card.className='border rounded-xl p-3 space-y-2 ' + (returned ? 'bg-slate-50' : 'bg-yellow-50 border-yellow-300');
          card.dataset.hwId = s.id;
          card.dataset.hwUserId = s.userId||'';
          card.dataset.hwName = s.studentName||'';
          card.dataset.hwDayKey = s.dayKey||'';
          const weatherEmoji = {sun:'☀️', cloud:'☁️', rain:'🌧️'}[s.endWeather] || '😊';
          const physicalBadge = s.hasPhysical
            ? '<span class="bg-yellow-200 text-yellow-800 text-xs px-1 rounded">成果物あり⭐</span>'
            : '';
          const returnedBadge = returned
            ? '<span class="bg-green-100 text-green-700 text-xs px-1 rounded">返却済み</span>'
            : '<span class="bg-red-100 text-red-600 text-xs px-1 rounded font-bold">未返却</span>';

          card.innerHTML = '<div class="flex items-center justify-between flex-wrap gap-1">'
            + '<div class="font-bold">' + escH(s.studentName||'') + ' <span class="text-xs text-slate-400 font-normal">'+escH(s.grade+'年'+s.className)+'</span></div>'
            + '<div class="flex gap-1 items-center text-xs">' + returnedBadge + physicalBadge + '<span class="text-slate-400">'+escH(s.dayKey)+'</span></div>'
            + '</div>'
            + '<div class="text-xs space-y-0.5 text-slate-700">'
            + '<div><b>今日やること：</b>'+escH(s.todo)+'</div>'
            + '<div><b>なんで：</b>'+escH(s.why)+'</div>'
            + '<div><b>めあて：</b>'+escH(s.aim)+'</div>'
            + '<div><b>'+s.minutes+'分</b> 学習 / 学びの天気: '+weatherEmoji+'</div>'
            + (s.weatherReason ? '<div><b>天気の理由：</b>'+escH(s.weatherReason)+'</div>' : '')
            + (s.nextImprove  ? '<div><b>次にするには：</b>'+escH(s.nextImprove)+'</div>' : '')
            + '</div>';

          if(!returned){
            // 返却フォーム
            const formDiv = document.createElement('div');
            formDiv.className='space-y-2 border-t pt-2';
            formDiv.innerHTML = '<div class="text-xs font-bold text-slate-600">先生コメント（任意）</div>'
              + '<textarea class="w-full border rounded p-2 text-xs" rows="2" placeholder="よく頑張りました！など" id="hwComment_'+s.id+'"></textarea>'
              + '<label class="flex items-center gap-2 text-xs cursor-pointer"><input type="checkbox" id="hwPhysical_'+s.id+'"/> <span>成果物（ノートなど）も提出あり ⭐</span></label>'
              + '<button class="bg-emerald-600 text-white rounded px-3 py-1 text-xs font-bold" onclick="returnHomework(&#39;'+escH(s.id)+'&#39;, this)">✅ 返却する</button>';
            card.appendChild(formDiv);
          } else if(s.teacherComment) {
            const commentDiv = document.createElement('div');
            commentDiv.className='text-xs text-emerald-700 bg-emerald-50 rounded p-2 border border-emerald-200';
            commentDiv.textContent = '💬 ' + s.teacherComment;
            card.appendChild(commentDiv);
          }
          wrap.appendChild(card);
        }
      }

      async function returnHomework(id, btn){
        btn.disabled = true;
        const comment = (document.getElementById('hwComment_'+id)||{}).value || '';
        const hasPhysical = (document.getElementById('hwPhysical_'+id)||{}).checked || false;
        try{
          await api('/api/teacher/homework/'+id+'/return',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({comment,hasPhysical})});
          await loadHomework();
        }catch(e){
          btn.disabled=false;
          alert('エラー: '+String(e.message||e));
        }
      }

      async function copyReflections(){
        const msgEl = document.getElementById('aiGenMsg');
        msgEl.textContent='⏳ 履歴を取得中...';

        // 全提出データを取得（返却済み含む）
        const classId = document.getElementById('hwClassFilter').value;
        var qs = classId ? '?classId='+encodeURIComponent(classId) : '';
        var allData;
        try{ allData = await api('/api/teacher/homework'+qs); }
        catch(e){ msgEl.textContent='❌ データ取得失敗: '+String(e.message||e); return; }
        var all = allData.submissions||[];

        // userId → 過去の返却済み提出（最新3件）にグループ化
        var history = {};
        for(var i=0;i<all.length;i++){
          var s = all[i];
          if(!s.returnedAt) continue; // 返却済みのみ過去履歴に使う
          if(!history[s.userId]) history[s.userId]=[];
          history[s.userId].push(s);
        }
        // 各ユーザーの履歴を日付降順にソートして最新3件に絞る
        Object.keys(history).forEach(function(uid){
          history[uid].sort(function(a,b){ return (b.submittedAt||0)-(a.submittedAt||0); });
          history[uid]=history[uid].slice(0,5);
        });

        // 未返却カードを収集
        var cards = document.querySelectorAll('#hwList [data-hw-id]');
        var items = [];
        var idx = 1;
        for(var ci=0;ci<cards.length;ci++){
          var card = cards[ci];
          var id = card.dataset.hwId;
          if(!document.getElementById('hwComment_'+id)) continue;
          // 対応する提出データをallから探す
          var sub = null;
          for(var si=0;si<all.length;si++){ if(all[si].id===id){ sub=all[si]; break; } }
          if(!sub) continue;
          var w = {sun:'☀晴れ',cloud:'☁くもり',rain:'☂あめ'}[sub.endWeather]||'';
          var today = idx+'. 【'+sub.studentName+'】（'+sub.dayKey+'）';
          today += '\\n  やったこと: '+(sub.todo||'―');
          today += '\\n  なんで: '+(sub.why||'―');
          today += '\\n  めあて: '+(sub.aim||'―');
          today += '\\n  学習時間: '+(sub.minutes||0)+'分 / 学びの天気: '+w;
          today += '\\n  振り返り: '+(sub.weatherReason||'―');
          today += '\\n  次どうする: '+(sub.nextImprove||'―');
          var hist = history[sub.userId]||[];
          if(hist.length){
            today += '\\n  ── 過去の振り返り（参考）──';
            for(var hi=0;hi<hist.length;hi++){
              var h = hist[hi];
              var hw = {sun:'☀',cloud:'☁',rain:'☂'}[h.endWeather]||'';
              today += '\\n    ['+h.dayKey+']';
              today += '\\n      やること: '+(h.todo||'―');
              today += '\\n      理由: '+(h.why||'―');
              today += '\\n      めあて: '+(h.aim||'―');
              today += '\\n      時間: '+(h.minutes||0)+'分';
              today += '\\n      天気: '+hw+' 「'+(h.weatherReason||'―')+'」';
              today += '\\n      次どうする: '+(h.nextImprove||'―');
            }
          }
          items.push(today);
          idx++;
        }
        if(!items.length){ msgEl.textContent='未返却の提出がありません'; return; }

        var nl = String.fromCharCode(10);
        var header = '小学校の担任の先生として、以下の児童の家庭学習の振り返りを読み、各児童への個別最適なコメントを30文字以内で考えてください。'+nl
          +'過去の振り返りも参考にして、その子の成長や課題に合わせてください。'+nl
          +'必ずJSON形式だけで返答してください（番号は不要）：{"comments":["コメント1","コメント2",...]}'+nl+nl
          +'=== 児童の振り返り ==='+nl;
        var text = header + items.join(nl+nl);

        navigator.clipboard.writeText(text).then(function(){
          msgEl.textContent='✅ '+items.length+'件（過去履歴付き）をコピーしました！GeminiのGemに貼り付けてください。';
        }).catch(function(){
          var ta = document.createElement('textarea');
          ta.value=text; ta.style.position='fixed'; ta.style.opacity='0';
          document.body.appendChild(ta); ta.select(); document.execCommand('copy');
          document.body.removeChild(ta);
          msgEl.textContent='✅ '+items.length+'件コピーしました！';
        });
      }

      function toggleGemPrompt(){
        var el = document.getElementById('gemPromptArea');
        if(el) el.classList.toggle('hidden');
      }
      function copyGemPrompt(){
        var el = document.getElementById('gemPromptText');
        var msg = document.getElementById('gemPromptCopyMsg');
        if(!el) return;
        navigator.clipboard.writeText(el.textContent||'').then(function(){
          msg.textContent='✅ コピーしました！Geminiの「Gem」→「システムプロンプト」に貼り付けてください';
        }).catch(function(){
          var ta=document.createElement('textarea');
          ta.value=el.textContent||''; ta.style.position='fixed'; ta.style.opacity='0';
          document.body.appendChild(ta); ta.select(); document.execCommand('copy');
          document.body.removeChild(ta);
          msg.textContent='✅ コピーしました！';
        });
      }

      async function bulkReturnNoComment(){
        const cards = document.querySelectorAll('#hwList [data-hw-id]');
        const targets = [];
        for(var i=0;i<cards.length;i++){
          var id = cards[i].dataset.hwId;
          var commentEl = document.getElementById('hwComment_'+id);
          if(!commentEl) continue; // 返却済みはスキップ
          var comment = commentEl.value||'';
          targets.push({id:id, comment:comment});
        }
        if(!targets.length){ alert('未返却の提出がありません'); return; }
        if(!confirm(targets.length+'件まとめて返却します。よろしいですか？')) return;
        var ok=0, ng=0;
        for(var ti=0;ti<targets.length;ti++){
          try{
            await api('/api/teacher/homework/'+targets[ti].id+'/return',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({comment:targets[ti].comment,hasPhysical:false})});
            ok++;
          }catch(e){ ng++; }
        }
        alert((ng===0?'✅ ':('⚠️ '+ng+'件失敗 / '))+ok+'件返却しました！');
        await loadHomework();
      }

      async function pasteAndBulkReturn(){
        const msgEl = document.getElementById('aiGenMsg');
        const raw = (document.getElementById('aiPasteArea')||{value:''}).value||'';
        if(!raw.trim()){ msgEl.textContent='⚠️ Geminiのコメントをテキストエリアにペーストしてからボタンを押してください'; return; }

        // コメント解析（JSON形式 or 番号付きリスト）
        let comments = [];
        try{
          const start = raw.indexOf('{'); const end = raw.lastIndexOf('}');
          if(start>=0 && end>start){ const j = JSON.parse(raw.slice(start, end+1)); comments = j.comments||[]; }
        }catch(_){}
        if(!comments.length){
          var nl = String.fromCharCode(10);
          comments = raw.split(nl).map(function(l){ return l.replace(/^[0-9]+[.)] */,'').trim(); }).filter(function(l){ return l.length>0; });
        }
        if(!comments.length){ msgEl.textContent='⚠️ コメントを解析できませんでした。JSON形式または番号付きリストで貼り付けてください'; return; }

        // 未返却の提出を収集
        const cards = document.querySelectorAll('#hwList [data-hw-id]');
        const targets = [];
        for(const card of cards){
          const id = card.dataset.hwId;
          if(!document.getElementById('hwComment_'+id)) continue; // 返却済みはスキップ
          targets.push(id);
        }
        if(!targets.length){ msgEl.textContent='未返却の提出がありません'; return; }
        if(!confirm(targets.length+'件まとめて返却します。よろしいですか？')) return;

        msgEl.textContent='⏳ 返却中...';
        let ok=0, ng=0;
        for(let i=0;i<targets.length;i++){
          const id = targets[i];
          const comment = (i < comments.length) ? comments[i] : '';
          try{
            await api('/api/teacher/homework/'+id+'/return',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({comment:comment,hasPhysical:false})});
            ok++;
          }catch(e){ ng++; }
        }
        document.getElementById('aiPasteArea').value='';
        msgEl.textContent=(ng===0?'✅ ':('⚠️ '+ng+'件失敗 / '))+ok+'件返却しました！';
        await loadHomework();
      }

      // 報告一覧
      async function loadAdminReports(){
        const wrap = document.getElementById('adminReportList');
        const countEl = document.getElementById('rptCount');
        wrap.innerHTML='<p class="text-slate-400">読み込み中...</p>';
        const status = document.getElementById('rptStatusFilter').value;
        try {
          const data = await api('/api/admin/reports?status='+encodeURIComponent(status));
          const list = data.reports || [];
          if(countEl) countEl.textContent = list.length + '件';
          if(!list.length){ wrap.innerHTML='<p class="text-slate-400">報告はありません</p>'; return; }
          var catLabels = {bug:'🐛 バグ', request:'💡 要望', other:'💬 その他'};
          var statusLabels = {open:'📬 受付中', in_progress:'🔧 対応中', resolved:'✅ 解決済み', closed:'🗂️ 終了'};
          wrap.innerHTML='';
          list.forEach(function(r){
            var card = document.createElement('div');
            card.className = 'border rounded-xl p-3 space-y-2 ' + (r.status==='open' ? 'bg-yellow-50 border-yellow-300' : 'bg-white');
            card.innerHTML = '<div class="flex items-center justify-between flex-wrap gap-1">'
              + '<div class="font-bold text-sm">' + escH(r.displayName) + ' <span class="text-xs text-slate-400 font-normal">'+(catLabels[r.category]||r.category)+'</span></div>'
              + '<div class="flex gap-1 items-center text-xs"><span class="px-2 py-0.5 rounded-full bg-gray-100">'+(statusLabels[r.status]||r.status)+'</span><span class="text-slate-400">'+escH(r.createdAt)+'</span></div>'
              + '</div>'
              + '<div class="text-sm text-slate-700">'+escH(r.body)+'</div>'
              + (r.adminNote ? '<div class="text-xs bg-emerald-50 border border-emerald-200 rounded p-2 text-emerald-800">💬 返信: '+escH(r.adminNote)+'</div>' : '')
              + '<div class="flex gap-2 items-center flex-wrap">'
              + '<select class="border p-1 rounded text-xs" id="rptSt_'+r.id+'">'
              + '<option value="open"'+(r.status==='open'?' selected':'')+'>受付中</option>'
              + '<option value="in_progress"'+(r.status==='in_progress'?' selected':'')+'>対応中</option>'
              + '<option value="resolved"'+(r.status==='resolved'?' selected':'')+'>解決済み</option>'
              + '<option value="closed"'+(r.status==='closed'?' selected':'')+'>終了</option>'
              + '</select>'
              + '<input class="border p-1 rounded text-xs flex-1" id="rptNote_'+r.id+'" placeholder="返信メモ" value="'+escH(r.adminNote)+'" />'
              + '<button class="bg-emerald-600 text-white rounded px-2 py-1 text-xs font-bold" onclick="updateReport(&#39;'+r.id+'&#39;)">更新</button>'
              + '<button class="bg-red-100 text-red-600 rounded px-2 py-1 text-xs" onclick="deleteReport(&#39;'+r.id+'&#39;)">削除</button>'
              + '</div>';
            wrap.appendChild(card);
          });
        } catch(e) {
          wrap.innerHTML='<p class="text-red-600">読み込みエラー: '+escH(String(e.message||e))+'</p>';
        }
      }

      async function updateReport(id){
        var st = document.getElementById('rptSt_'+id).value;
        var note = document.getElementById('rptNote_'+id).value;
        try{
          await api('/api/admin/report/'+id,{method:'PUT',headers:{'content-type':'application/json'},body:JSON.stringify({status:st,adminNote:note})});
          loadAdminReports();
        }catch(e){ alert('更新エラー: '+String(e.message||e)); }
      }

      async function deleteReport(id){
        if(!confirm('この報告を削除しますか？')) return;
        try{
          await api('/api/admin/report/'+id,{method:'DELETE'});
          loadAdminReports();
        }catch(e){ alert('削除エラー: '+String(e.message||e)); }
      }

      // ===== 連絡帳機能 =====
      async function loadContactNotes(){
        // クラスセレクター更新
        try{
          var clsData = await api('/api/teacher/classes');
          var sel = document.getElementById('cnClassFilter');
          sel.innerHTML = '';
          (clsData.classes||[]).forEach(function(c,i){ sel.innerHTML += '<option value="'+escH(c.id)+'"'+(i===0?' selected':'')+'>'+escH(c.name)+'</option>'; });
        }catch(e){}
        // 今日の日付をデフォルトに
        var today = new Date();
        var tmrw = new Date(today); tmrw.setDate(tmrw.getDate()+1);
        var dk = document.getElementById('cnDayKey');
        if(dk && !dk.value) dk.value = tmrw.toISOString().slice(0,10);
        // 一覧
        var wrap = document.getElementById('cnList');
        wrap.innerHTML = '<p class="text-slate-400 text-xs">読み込み中...</p>';
        try{
          var classId = document.getElementById('cnClassFilter').value||'';
          var data = await api('/api/teacher/contact-notes?classId='+encodeURIComponent(classId));
          wrap.innerHTML = '';
          if(!data.notes.length){ wrap.innerHTML='<p class="text-xs text-slate-400">まだ連絡がありません</p>'; return; }
          for(var i=0;i<data.notes.length;i++){
            var n = data.notes[i];
            var card = document.createElement('div');
            card.className = 'border rounded-lg p-3 bg-blue-50 border-blue-200';
            var deadlineStr = n.rewardDeadline ? '<span class="text-xs text-orange-600">報酬締切: '+escH(n.rewardDeadline).slice(0,16)+'</span>' : '';
            card.innerHTML = '<div class="flex items-center justify-between mb-1">'
              + '<div class="font-bold text-sm">'+escH(n.dayKey)+' <span class="text-xs text-slate-400">'+escH(n.className||'')+'</span></div>'
              + '<div class="flex items-center gap-2">'
              + '<span class="text-xs bg-blue-100 text-blue-700 px-1 rounded">💰 '+n.rewardCoins+'コイン</span>'
              + deadlineStr
              + '<button class="text-xs text-slate-500 underline" onclick="viewContactReads(&#39;'+escH(n.id)+'&#39;)">既読状況</button>'
              + '<button class="text-xs text-red-400 hover:text-red-600" onclick="deleteContactNote(&#39;'+escH(n.id)+'&#39;)">削除</button>'
              + '</div></div>'
              + '<div class="text-xs text-slate-700 whitespace-pre-wrap">'+escH(n.body)+'</div>'
              + '<div class="hidden text-xs mt-2 border-t pt-2" id="cnReads_'+escH(n.id)+'"></div>';
            wrap.appendChild(card);
          }
        }catch(e){ wrap.innerHTML='<p class="text-xs text-red-600">読み込みエラー</p>'; }
      }

      async function sendContactNote(){
        var msg = document.getElementById('cnMsg');
        msg.textContent=''; msg.className='text-sm';
        var classId = document.getElementById('cnClassFilter').value;
        var dayKey = document.getElementById('cnDayKey').value;
        var body = document.getElementById('cnBody').value.trim();
        var deadline = document.getElementById('cnDeadline').value || null;
        var coins = parseInt(document.getElementById('cnCoins').value) || 5;
        if(!classId){ msg.textContent='クラスを選択してください'; msg.className='text-sm text-red-600'; return; }
        if(!dayKey){ msg.textContent='日付を入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!body){ msg.textContent='連絡内容を入力してください'; msg.className='text-sm text-red-600'; return; }
        var rewardDeadline = deadline ? new Date(deadline).toISOString() : null;
        try{
          await api('/api/teacher/contact-note',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({classId:classId,dayKey:dayKey,body:body,rewardDeadline:rewardDeadline,rewardCoins:coins})});
          msg.textContent='送信しました！'; msg.className='text-sm text-green-700';
          document.getElementById('cnBody').value='';
          loadContactNotes();
        }catch(e){ msg.textContent='送信エラー: '+String(e.message||e); msg.className='text-sm text-red-600'; }
      }

      async function deleteContactNote(id){
        if(!confirm('この連絡を削除しますか？')) return;
        try{
          await api('/api/teacher/contact-note/'+id,{method:'DELETE'});
          loadContactNotes();
        }catch(e){ alert('削除エラー: '+String(e.message||e)); }
      }

      async function viewContactReads(id){
        var wrap = document.getElementById('cnReads_'+id);
        if(!wrap) return;
        if(!wrap.classList.contains('hidden')){ wrap.classList.add('hidden'); return; }
        wrap.classList.remove('hidden');
        wrap.innerHTML = '<span class="text-slate-400">読み込み中...</span>';
        try{
          var data = await api('/api/teacher/contact-note/'+id+'/reads');
          if(!data.reads.length){ wrap.innerHTML='<span class="text-slate-400">まだ誰も読んでいません</span>'; return; }
          var html = '<div class="font-bold mb-1">既読: '+data.reads.length+'人</div>';
          data.reads.forEach(function(r){
            var reward = r.rewardClaimed ? '<span class="text-green-600">💰</span>' : '<span class="text-slate-400">-</span>';
            html += '<div class="flex gap-2 items-center">'
              + '<span>'+escH(r.studentName)+'</span>'
              + '<span class="text-xs text-slate-400">'+escH((r.readAt||'').slice(0,16))+'</span>'
              + reward + '</div>';
          });
          wrap.innerHTML = html;
        }catch(e){ wrap.innerHTML='<span class="text-red-500">エラー</span>'; }
      }

      // ===== おしらせ機能 =====
      async function loadAnnouncements(){
        // クラスセレクター更新
        try{
          var clsData = await api('/api/teacher/classes');
          var sel = document.getElementById('annClassFilter');
          sel.innerHTML = '<option value="">全体（クラス関係なく全員）</option>';
          (clsData.classes||[]).forEach(function(c){ sel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
        }catch(e){}
        // 送信済み一覧
        var wrap = document.getElementById('annList');
        wrap.innerHTML = '<p class="text-slate-400 text-xs">読み込み中...</p>';
        try{
          var data = await api('/api/teacher/announcements');
          wrap.innerHTML = '';
          if(!data.announcements.length){ wrap.innerHTML='<p class="text-xs text-slate-400">まだおしらせがありません</p>'; return; }
          data.announcements.forEach(function(a){
            var card = document.createElement('div');
            card.className = 'border rounded-lg p-3 bg-orange-50 border-orange-200';
            var target = a.classId ? escH(a.className||'クラス') : '<span class="text-orange-600 font-bold">全体</span>';
            card.innerHTML = '<div class="flex items-center justify-between mb-1">'
              + '<div class="font-bold text-sm">'+escH(a.title)+'</div>'
              + '<div class="flex items-center gap-2">'
              + '<span class="text-xs text-slate-400">'+escH(a.createdAt||'').slice(0,10)+'</span>'
              + '<span class="text-xs bg-orange-100 text-orange-700 px-1 rounded">'+target+'</span>'
              + '</div></div>'
              + '<div class="text-xs text-slate-700 whitespace-pre-wrap">'+escH(a.body)+'</div>'
              + '<button class="text-xs text-red-400 hover:text-red-600 mt-1" onclick="deleteAnnouncement(&#39;'+escH(a.id)+'&#39;)">削除</button>';
            wrap.appendChild(card);
          });
        }catch(e){ wrap.innerHTML='<p class="text-xs text-red-600">読み込みエラー</p>'; }
      }

      async function sendAnnouncement(){
        var msg = document.getElementById('annMsg');
        msg.textContent=''; msg.className='text-sm';
        var title = document.getElementById('annTitle').value.trim();
        var body = document.getElementById('annBody').value.trim();
        var classId = document.getElementById('annClassFilter').value || null;
        if(!title){ msg.textContent='タイトルを入力してください'; msg.className='text-sm text-red-600'; return; }
        if(!body){ msg.textContent='内容を入力してください'; msg.className='text-sm text-red-600'; return; }
        try{
          await api('/api/teacher/announcement',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({title:title,body:body,classId:classId})});
          msg.textContent='送信しました！'; msg.className='text-sm text-green-700';
          document.getElementById('annTitle').value='';
          document.getElementById('annBody').value='';
          loadAnnouncements();
        }catch(e){ msg.textContent='送信エラー: '+String(e.message||e); msg.className='text-sm text-red-600'; }
      }

      async function deleteAnnouncement(id){
        if(!confirm('このおしらせを削除しますか？')) return;
        try{
          await api('/api/teacher/announcement/'+id,{method:'DELETE'});
          loadAnnouncements();
        }catch(e){ alert('削除エラー: '+String(e.message||e)); }
      }

      (async ()=>{
        const me = await fetch('/api/auth/me').then(r=>r.json()).catch(()=>({}));
        if(!me.user || (me.user.role !== 'teacher' && me.user.role !== 'admin')){ location.href='/login'; return; }
        document.getElementById('teacherInfo').textContent = me.user.name + '（' + (me.user.school||'') + '）';
        // おしらせタブは管理者のみ表示
        if(me.user.role !== 'admin'){
          var annTab = document.getElementById('tabAnnouncements');
          if(annTab) annTab.style.display = 'none';
          var annPane = document.getElementById('tabPaneAnnouncements');
          if(annPane) annPane.style.display = 'none';
        }
        await renderClasses();
      })();
    </script>
  </body></html>`)
})

export default app
