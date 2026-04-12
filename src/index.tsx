import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'

type Bindings = {
  DB: D1Database
  SESSION_SECRET: string
  ADMIN_LOGIN_ID?: string
  ADMIN_PASSWORD?: string
  AI: any
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

// Gemini API キーローテーション（交互使用＋429フェイルオーバー）
let _geminiKeyIndex = 0
function getGeminiKeys(env: any): string[] {
  const keys: string[] = []
  if (env.GEMINI_API_KEY) keys.push(env.GEMINI_API_KEY)
  if (env.GEMINI_API_KEY_2) keys.push(env.GEMINI_API_KEY_2)
  return keys
}

async function callGemini(env: any, body: any, model = 'gemini-2.5-flash'): Promise<{ ok: boolean, text: string, source: string }> {
  const keys = getGeminiKeys(env)
  if (!keys.length) return { ok: false, text: '', source: 'no_key' }

  // ラウンドロビン: リクエストごとに交互に使う
  const startIdx = _geminiKeyIndex % keys.length
  _geminiKeyIndex++

  for (let attempt = 0; attempt < keys.length; attempt++) {
    const keyIdx = (startIdx + attempt) % keys.length
    const key = keys[keyIdx]
    try {
      const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${key}`
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (res.ok) {
        const json: any = await res.json()
        const text = json?.candidates?.[0]?.content?.parts?.[0]?.text || ''
        return { ok: true, text, source: 'gemini_key' + (keyIdx + 1) }
      }
      if (res.status === 429) {
        console.log(`Gemini key${keyIdx + 1} got 429, trying next key...`)
        continue // 次のキーを試す
      }
      // 429以外のエラーはそのまま失敗
      console.error(`Gemini key${keyIdx + 1} error: ${res.status}`)
      return { ok: false, text: '', source: 'gemini_error_' + res.status }
    } catch (e: any) {
      console.error(`Gemini key${keyIdx + 1} fetch error:`, e?.message || e)
      continue
    }
  }
  return { ok: false, text: '', source: 'all_keys_exhausted' }
}

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

// -------------------- DB migration (add columns if missing) --------------------
let _dbMigrated = false
app.use('*', async (c, next) => {
  if (!_dbMigrated) {
    _dbMigrated = true
    try { await c.env.DB.exec(`ALTER TABLE homework_submissions ADD COLUMN work_photo_key TEXT DEFAULT ''`) } catch (_) {}
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

  // 最終ログイン時刻を記録
  if (row.role === 'teacher') {
    await c.env.DB.prepare(`UPDATE teacher_accounts SET last_login_at=datetime('now') WHERE id=?`).bind(row.id).run()
  } else {
    await c.env.DB.prepare(`UPDATE users SET last_login_at=datetime('now') WHERE id=?`).bind(row.id).run()
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
  // 最終アクティブ日時を更新（fire-and-forget）
  c.env.DB.prepare(`UPDATE users SET last_login_at=datetime('now') WHERE id=?`).bind(u.id).run().catch(() => {})

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
    // クライアント側で計算されたキャッシュ値を優先使用
    const battlePower = Number(s._cachedBattlePower || 0)
    const pokedexCount = Array.isArray(s.pokedex) ? s.pokedex.length : 0
    const maxObj: any = s.max || (s.M && s.M.max) || {}
    const wildWinStreak = Number(maxObj.winStreak || s._cachedWildWinStreak || 0)
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

  const sql = `SELECT id, login_id as loginId, name, grade, class_name as className, is_active as isActive, disabled_reason as disabledReason, created_at as createdAt, last_login_at as lastLoginAt
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

app.get('/api/admin/teachers', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const res = await c.env.DB.prepare(
    `SELECT id, login_id as loginId, name, school, is_active as isActive, last_login_at as lastLoginAt, created_at as createdAt
     FROM teacher_accounts ORDER BY created_at DESC`
  ).all<any>()
  return c.json({ ok: true, teachers: res.results })
})

app.post('/api/admin/teacher-reset-password/:id', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const id = c.req.param('id')
  const tempPassword = randomHex(4)
  const salt = randomHex(16)
  const hash = await pbkdf2Hash(tempPassword, salt)
  await c.env.DB.prepare(`UPDATE teacher_accounts SET password_hash=?, password_salt=? WHERE id=?`).bind(hash, salt, id).run()
  return c.json({ ok: true, tempPassword })
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

// -------------------- API: admin - class management --------------------

app.get('/api/admin/classes', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const res = await c.env.DB.prepare(
    `SELECT c.id, c.class_code as classCode, c.name, c.created_at as createdAt, COALESCE(t.name, u.name) as teacherName,
     (SELECT COUNT(*) FROM class_members cm WHERE cm.class_id = c.id) as memberCount
     FROM classes c LEFT JOIN teacher_accounts t ON t.id = c.teacher_id LEFT JOIN users u ON u.id = c.teacher_id ORDER BY c.created_at DESC`
  ).all<any>()
  return c.json({ ok: true, classes: res.results })
})

app.get('/api/admin/class/:classId/members', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const cls = await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const rows = await c.env.DB.prepare(
    `SELECT u.id as userId, u.login_id as loginId, u.name, u.grade, u.class_name as className, cm.joined_at as joinedAt
     FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=? ORDER BY u.grade ASC, u.name ASC`
  ).bind(classId).all<any>()
  return c.json({ ok: true, members: rows.results })
})

app.post('/api/admin/class/:classId/add-member', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const userId = String(body.userId || '').trim()
  if (!userId) return jsonError(c, 400, 'userId_required')
  const cls = await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const student = await c.env.DB.prepare(`SELECT id, name FROM users WHERE id=? AND role='student' LIMIT 1`).bind(userId).first<any>()
  if (!student) return jsonError(c, 404, 'student_not_found')
  const existing = await c.env.DB.prepare('SELECT 1 FROM class_members WHERE user_id=? AND class_id=? LIMIT 1').bind(userId, classId).first<any>()
  if (existing) return c.json({ ok: true, already: true, className: cls.name })
  await c.env.DB.prepare('DELETE FROM class_members WHERE user_id=?').bind(userId).run()
  await c.env.DB.prepare('INSERT INTO class_members (user_id, class_id) VALUES (?, ?)').bind(userId, classId).run()
  return c.json({ ok: true, className: cls.name, studentName: student.name })
})

app.post('/api/admin/class/:classId/add-members-bulk', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const body = await c.req.json().catch(() => null)
  if (!body || !Array.isArray(body.userIds) || body.userIds.length === 0) return jsonError(c, 400, 'userIds_required')
  const cls = await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  let added = 0
  let skipped = 0
  for (const uid of body.userIds) {
    const userId = String(uid).trim()
    if (!userId) continue
    const student = await c.env.DB.prepare(`SELECT id FROM users WHERE id=? AND role='student' LIMIT 1`).bind(userId).first<any>()
    if (!student) { skipped++; continue }
    const existing = await c.env.DB.prepare('SELECT 1 FROM class_members WHERE user_id=? AND class_id=? LIMIT 1').bind(userId, classId).first<any>()
    if (existing) { skipped++; continue }
    await c.env.DB.prepare('DELETE FROM class_members WHERE user_id=?').bind(userId).run()
    await c.env.DB.prepare('INSERT INTO class_members (user_id, class_id) VALUES (?, ?)').bind(userId, classId).run()
    added++
  }
  return c.json({ ok: true, added, skipped })
})

app.delete('/api/admin/class/:classId/remove-member/:userId', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const userId = c.req.param('userId')
  await c.env.DB.prepare('DELETE FROM class_members WHERE user_id=? AND class_id=?').bind(userId, classId).run()
  return c.json({ ok: true })
})

app.get('/api/admin/unassigned-students', async (c) => {
  const u = requireAdmin(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const res = await c.env.DB.prepare(
    `SELECT u.id, u.login_id as loginId, u.name, u.grade, u.class_name as className
     FROM users u
     WHERE u.role='student' AND u.is_active=1
       AND u.id NOT IN (SELECT cm.user_id FROM class_members cm)
     ORDER BY u.grade ASC, u.class_name ASC, u.name ASC`
  ).all<any>()
  return c.json({ ok: true, students: res.results })
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
  const res = await c.env.DB.prepare(
        `SELECT id, class_code as classCode, name, ranking_enabled as rankingEnabled, homework_enabled as homeworkEnabled, contact_enabled as contactEnabled, menus_enabled as menusEnabled, created_at as createdAt,
         (SELECT COUNT(*) FROM class_members cm WHERE cm.class_id = classes.id) as memberCount
         FROM classes WHERE teacher_id=? ORDER BY created_at DESC`
    ).bind(u.id).all<any>()
  return c.json({ ok: true, classes: res.results })
})

// クラスのメンバー一覧
app.get('/api/teacher/class/:classId/members', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const cls = await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class not found')
  const rows = await c.env.DB.prepare(
    'SELECT u.id as userId, u.name FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=? ORDER BY u.name'
  ).bind(classId).all<any>()
  return c.json({ ok: true, members: rows.results })
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

// メニュー表示ON/OFFトグル（一括）
app.put('/api/teacher/class/:classId/menus-toggle', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const body = await c.req.json().catch(() => null)
  const menusEnabled = body?.menusEnabled ? JSON.stringify(body.menusEnabled) : '{}'
  const result = u.role === 'admin'
    ? await c.env.DB.prepare(`UPDATE classes SET menus_enabled=? WHERE id=?`).bind(menusEnabled, classId).run()
    : await c.env.DB.prepare(`UPDATE classes SET menus_enabled=? WHERE id=? AND teacher_id=?`).bind(menusEnabled, classId, u.id).run()
  if (!result.meta?.changes) return jsonError(c, 404, 'class_not_found')
  return c.json({ ok: true, menusEnabled: JSON.parse(menusEnabled) })
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


// -------------------- API: teacher アクティビティ --------------------
app.get('/api/teacher/class/:classId/activity', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  // クラスメンバー取得
  const members = await c.env.DB.prepare(
    `SELECT u.id, u.name, u.last_login_at as lastLoginAt
     FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id = ?`
  ).bind(classId).all<any>()

  // 今日の学習結果（UTC基準で当日）
  const todayResults = await c.env.DB.prepare(
    `SELECT r.user_id as userId, r.is_correct as isCorrect
     FROM learning_results r
     JOIN class_members cm ON cm.user_id = r.user_id AND cm.class_id = ?
     WHERE r.answered_at >= datetime('now', '-24 hours')`
  ).bind(classId).all<any>()

  const activeToday = new Set(todayResults.results.map((r: any) => r.userId))
  const totalProblems = todayResults.results.length
  const correctCount = todayResults.results.filter((r: any) => r.isCorrect).length
  const accuracy = totalProblems > 0 ? Math.round(correctCount / totalProblems * 100) : null

  // 最近の活動ログ（直近50件）
  const recentLog = await c.env.DB.prepare(
    `SELECT r.answered_at as answeredAt, r.unit, r.is_correct as isCorrect, r.time_ms as timeMs,
            u.name, u.login_id as loginId
     FROM learning_results r
     JOIN class_members cm ON cm.user_id = r.user_id AND cm.class_id = ?
     JOIN users u ON u.id = r.user_id
     ORDER BY r.answered_at DESC LIMIT 50`
  ).bind(classId).all<any>()

  // 7日以上学習していない生徒
  const inactive = members.results.filter((m: any) => {
    if (!m.lastLoginAt) return true
    const last = new Date(m.lastLoginAt + 'Z')
    return (Date.now() - last.getTime()) > 7 * 86400000
  }).map((m: any) => ({ id: m.id, name: m.name, lastLoginAt: m.lastLoginAt }))

  return c.json({
    ok: true, class: cls,
    summary: {
      memberCount: members.results.length,
      activeToday: activeToday.size,
      totalProblems,
      accuracy
    },
    recentLog: recentLog.results,
    inactive
  })
})

// -------------------- API: teacher AI分析 --------------------
app.get('/api/teacher/class-ai-analysis', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.query('classId')
  if (!classId) return jsonError(c, 400, 'classId required')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const members = await c.env.DB.prepare(`
    SELECT u.id, u.name, p.state_json
    FROM class_members cm JOIN users u ON u.id = cm.user_id
    LEFT JOIN progress p ON p.user_id = cm.user_id
    WHERE cm.class_id = ?
  `).bind(classId).all<any>()
  const weekKey = c.req.query('weekKey') || ''
  let hw: any = { results: [] }, plans: any = { results: [] }, refs: any = { results: [] }
  try { hw = await c.env.DB.prepare('SELECT user_id, subject, minutes, created_at FROM homework_logs WHERE class_id = ? AND week_key = ?').bind(classId, weekKey).all<any>() } catch {}
  try { plans = await c.env.DB.prepare('SELECT user_id, goal_text, plan_text, revision_count FROM weekly_plans WHERE class_id = ? AND week_key = ?').bind(classId, weekKey).all<any>() } catch {}
  try { refs = await c.env.DB.prepare('SELECT user_id, reflection_text, concentration, achievement FROM weekly_reflections WHERE class_id = ? AND week_key = ?').bind(classId, weekKey).all<any>() } catch {}
  const studentSummaries = members.results.map((m: any) => {
    const myHw = hw.results.filter((h: any) => h.user_id === m.id)
    const myPlan = plans.results.find((p: any) => p.user_id === m.id)
    const myRef = refs.results.find((r: any) => r.user_id === m.id)
    let learnData: Record<string, any> = {}
    try {
      if (m.state_json) {
        const state = JSON.parse(m.state_json)
        const bySubject = state?.metrics?.learn?.bySubject || {}
        learnData = Object.fromEntries(Object.entries(bySubject).map(([k, v]: [string, any]) => [k, { total: v.total || 0, correct: v.correct || 0, acc: v.total ? Math.round(v.correct / v.total * 100) : 0 }]))
      }
    } catch {}
    return {
      name: m.name,
      homework: { count: myHw.length, totalMinutes: myHw.reduce((s: number, h: any) => s + (h.minutes || 0), 0), subjects: myHw.map((h: any) => h.subject) },
      plan: myPlan ? { goal: myPlan.goal_text, plan: myPlan.plan_text, revisions: myPlan.revision_count } : null,
      reflection: myRef ? { text: myRef.reflection_text, concentration: myRef.concentration, achievement: myRef.achievement } : null,
      learning: learnData
    }
  })
  const prompt = [
    'あなたは小学校の教師を支援するAIアシスタントです。以下は' + cls.name + 'の今週（' + weekKey + '）の学習データです。',
    'クラス人数: ' + members.results.length + '人',
    '',
    '【児童別データ】',
    ...studentSummaries.map((s: any) => {
      let txt = '■ ' + s.name + ': 家庭学習' + s.homework.count + '回(' + s.homework.totalMinutes + '分)'
      if (s.plan) txt += ', 計画あり(修正' + s.plan.revisions + '回)'
      if (s.reflection) txt += ', ふりかえりあり(集中度' + s.reflection.concentration + ')'
      if (Object.keys(s.learning).length > 0) {
        txt += ', 教科別正答率: ' + Object.entries(s.learning).map(([k, v]: [string, any]) => k + v.acc + '%').join('/')
      }
      return txt
    }),
    '',
    '以下の観点で分析してください：',
    '1. 家庭学習の傾向: クラス全体の提出状況、学習時間の傾向',
    '2. 困りごとの検出: 学習量が少ない・正答率が低い・未提出の児童を特定',
    '3. 自己調整の力: 計画→実行→ふりかえりのサイクルができている児童、支援が必要な児童',
    '4. 具体的なアドバイス: 教師として来週どんな声かけや支援をすべきか',
    '',
    '日本語で、箇条書きではなく教師に語りかけるような文章で回答してください。'
  ].join('\n')
  // Gemini APIで分析
  try {
    let analysisText = ''
    const gRes = await callGemini(c.env, {
      system_instruction: { parts: [{ text: 'あなたは小学校の教師を支援する教育AIアシスタントです。データに基づいて具体的・実践的な分析をしてください。日本語で回答してください。' }] },
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.5, maxOutputTokens: 2048 },
    })
    if (gRes.ok) {
      analysisText = gRes.text
    }
    // フォールバック
    if (!analysisText) {
      const aiResult: any = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
        messages: [{ role: 'user', content: prompt }],
        max_tokens: 1024
      })
      analysisText = aiResult.response || aiResult.result || ''
    }
    return c.json({ ok: true, analysis: analysisText })
  } catch (e: any) {
    return c.json({ ok: false, error: e.message || 'AI error' }, 500)
  }
})

// 個人カルテAPI: 児童1人の詳細分析
app.get('/api/teacher/student-karte', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const studentId = c.req.query('studentId')
  if (!studentId) return jsonError(c, 400, 'studentId required')

  // 権限チェック: この先生のクラスの児童か
  const member = u.role === 'admin'
    ? await c.env.DB.prepare(`SELECT u.id, u.name FROM users u WHERE u.id=?`).bind(studentId).first<any>()
    : await c.env.DB.prepare(`
        SELECT u.id, u.name FROM users u
        JOIN class_members cm ON cm.user_id = u.id
        JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
        WHERE u.id = ?
      `).bind(u.id, studentId).first<any>()
  if (!member) return jsonError(c, 404, 'student_not_found')

  // 過去60日分の提出データ
  let submissions: any = { results: [] }
  try {
    submissions = await c.env.DB.prepare(`
      SELECT day_key, todo, minutes, end_weather, weather_reason, teacher_comment, aim, next_improve, work_photo_analysis, submitted_at
      FROM homework_submissions WHERE user_id=? ORDER BY day_key DESC LIMIT 60
    `).bind(studentId).all<any>()
  } catch {}

  // 教科別成績（全期間）
  let subjectResults: any = { results: [] }
  try {
    subjectResults = await c.env.DB.prepare(`
      SELECT unit, week_key, COUNT(*) as total, SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END) as correct_count
      FROM learning_results WHERE user_id=? GROUP BY unit, week_key ORDER BY week_key DESC
    `).bind(studentId).all<any>()
  } catch {}

  // 計画修正履歴
  let revisions: any = { results: [] }
  try {
    revisions = await c.env.DB.prepare(`
      SELECT week_key, revision_number, reason, created_at FROM plan_revisions WHERE user_id=? ORDER BY created_at DESC LIMIT 20
    `).bind(studentId).all<any>()
  } catch {}

  // 週間計画
  let plans: any = { results: [] }
  try {
    plans = await c.env.DB.prepare(`
      SELECT week_key, plans_json, revision_count, plan_approved FROM student_weekly_plans WHERE user_id=? ORDER BY week_key DESC LIMIT 8
    `).bind(studentId).all<any>()
  } catch {}

  // 構造化振り返り
  let reflections: any = { results: [] }
  try {
    reflections = await c.env.DB.prepare(`
      SELECT week_key, concentration, good_point, improve_point, next_action FROM structured_reflections WHERE user_id=? ORDER BY week_key DESC LIMIT 8
    `).bind(studentId).all<any>()
  } catch {}

  const subs = submissions.results || []
  // 統計計算
  const totalDays = subs.length
  const avgMin = totalDays ? Math.round(subs.reduce((a: number, s: any) => a + (s.minutes || 0), 0) / totalDays) : 0
  const weathers = subs.map((s: any) => s.end_weather).filter(Boolean)
  const sunRate = weathers.length ? Math.round(weathers.filter((w: string) => w === 'sun').length / weathers.length * 100) : 0

  // 週ごとの提出数・学習時間の推移
  const weeklyStats: Record<string, { count: number, totalMin: number }> = {}
  for (const s of subs) {
    const wk = s.day_key ? s.day_key.slice(0, 7) : 'unknown'
    if (!weeklyStats[wk]) weeklyStats[wk] = { count: 0, totalMin: 0 }
    weeklyStats[wk].count++
    weeklyStats[wk].totalMin += (s.minutes || 0)
  }

  // 教科別の得意/苦手
  const subjectMap: Record<string, { total: number, correct: number }> = {}
  for (const r of (subjectResults.results || [])) {
    if (!subjectMap[r.unit]) subjectMap[r.unit] = { total: 0, correct: 0 }
    subjectMap[r.unit].total += r.total
    subjectMap[r.unit].correct += r.correct_count
  }
  const subjectAnalysis = Object.entries(subjectMap).map(([unit, v]) => ({
    unit, total: v.total, correct: v.correct, rate: v.total ? Math.round(v.correct / v.total * 100) : 0
  })).sort((a, b) => b.total - a.total)

  // Gemini AIで個人分析
  let aiAdvice = ''
  if (totalDays > 0) {
    try {
      const recentSubs = subs.slice(0, 15).map((s: any) =>
        `[${s.day_key}] ${s.todo||''}(${s.minutes||0}分) 天気:${s.end_weather||'?'} めあて:${s.aim||'-'} 振返り:${s.weather_reason||'-'}${s.work_photo_analysis ? ' 📷:'+s.work_photo_analysis : ''}`
      ).join('\n')
      const subjectTxt = subjectAnalysis.map(s => `${s.unit}: 正答率${s.rate}%(${s.total}問)`).join(', ')
      const revTxt = (revisions.results || []).slice(0, 5).map((r: any) => `[${r.week_key}] ${r.reason || '理由なし'}`).join(', ')
      const refTxt = (reflections.results || []).slice(0, 3).map((r: any) => `[${r.week_key}] 集中${r.concentration} 良:${r.good_point||'-'} 改:${r.improve_point||'-'} 次:${r.next_action||'-'}`).join('\n')

      const kartePrompt = `以下は「${member.name}」さん（小学生）の学習データです。担任の先生への報告として分析してください。

＜基本統計＞
提出回数: ${totalDays}回 / 平均学習時間: ${avgMin}分 / 満足度(☀️率): ${sunRate}%

＜教科別成績＞
${subjectTxt || 'データなし'}

＜直近の学習記録＞
${recentSubs || 'データなし'}

＜計画修正履歴＞
${revTxt || 'なし'}

＜構造化振り返り＞
${refTxt || 'なし'}

以下の4つの観点で分析してください（各100文字程度）：
1. 📊 学習の傾向: 学習時間・提出頻度・教科の偏りなど
2. 💪 強みと成長: この子の良いところ、伸びているところ
3. 🔍 気になる点: 支援が必要そうなところ、注意すべき変化
4. 💬 おすすめの声かけ: 具体的な声かけ例を2-3個

必ずJSON形式で返答:
{"trend":"...","strength":"...","concern":"...","advice":"..."}`

      const gRes = await callGemini(c.env, {
        contents: [{ role: 'user', parts: [{ text: kartePrompt }] }],
        generationConfig: { temperature: 0.5, maxOutputTokens: 1024 },
      })
      if (gRes.ok) {
        const rawText = gRes.text
        const jsonMatch = rawText.match(/\{[\s\S]*\}/)
        if (jsonMatch) {
          aiAdvice = jsonMatch[0]
        }
      }
    } catch (e: any) {
      console.error('Karte AI error:', e?.message || e)
    }
  }

  return c.json({
    ok: true,
    student: { id: member.id, name: member.name },
    stats: { totalDays, avgMin, sunRate, weeklyStats },
    subjects: subjectAnalysis,
    recentSubmissions: subs.slice(0, 20),
    revisions: revisions.results || [],
    plans: plans.results || [],
    reflections: reflections.results || [],
    aiAdvice,
  })
})

// 週報レポートAPI: クラス全体の1週間まとめ
app.get('/api/teacher/weekly-report', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.query('classId')
  if (!classId) return jsonError(c, 400, 'classId required')
  const weekKey = c.req.query('weekKey') || getWeekKey()
  const prevWeekKey = getPrevWeekKey(weekKey)

  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=?').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  // 児童一覧
  const members = await c.env.DB.prepare(`
    SELECT u.id, u.name FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=?
  `).bind(classId).all<any>()
  const memberList = members.results || []

  // 今週の提出データ
  let thisWeekHW: any = { results: [] }
  try {
    thisWeekHW = await c.env.DB.prepare(`
      SELECT hs.user_id, hs.day_key, hs.minutes, hs.end_weather, hs.todo, hs.aim, hs.weather_reason, hs.work_photo_analysis
      FROM homework_submissions hs JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
      WHERE hs.week_key=? ORDER BY hs.day_key
    `).bind(classId, weekKey).all<any>()
  } catch {}

  // 先週の提出データ（比較用）
  let prevWeekHW: any = { results: [] }
  try {
    prevWeekHW = await c.env.DB.prepare(`
      SELECT hs.user_id, COUNT(*) as cnt, SUM(hs.minutes) as totalMin
      FROM homework_submissions hs JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
      WHERE hs.week_key=? GROUP BY hs.user_id
    `).bind(classId, prevWeekKey).all<any>()
  } catch {}

  // 教科別成績
  let thisResults: any = { results: [] }
  try {
    thisResults = await c.env.DB.prepare(`
      SELECT lr.user_id, lr.unit, COUNT(*) as total, SUM(CASE WHEN lr.correct=1 THEN 1 ELSE 0 END) as correct_count
      FROM learning_results lr JOIN class_members cm ON cm.user_id = lr.user_id AND cm.class_id=?
      WHERE lr.week_key=? GROUP BY lr.user_id, lr.unit
    `).bind(classId, weekKey).all<any>()
  } catch {}

  // 計画データ
  let plansData: any = { results: [] }
  try {
    plansData = await c.env.DB.prepare(`
      SELECT user_id, revision_count FROM student_weekly_plans WHERE week_key=? AND user_id IN (SELECT user_id FROM class_members WHERE class_id=?)
    `).bind(weekKey, classId).all<any>()
  } catch {}

  // データ集約
  const hwList = thisWeekHW.results || []
  const prevMap: Record<string, any> = {}
  for (const r of (prevWeekHW.results || [])) prevMap[r.user_id] = r

  const studentSummaries = memberList.map((m: any) => {
    const myHW = hwList.filter((h: any) => h.user_id === m.id)
    const prevW = prevMap[m.id]
    const myResults = (thisResults.results || []).filter((r: any) => r.user_id === m.id)
    const myPlan = (plansData.results || []).find((p: any) => p.user_id === m.id)
    const totalMin = myHW.reduce((a: number, h: any) => a + (h.minutes || 0), 0)
    const weathers = myHW.map((h: any) => h.end_weather).filter(Boolean)
    const sunRate = weathers.length ? Math.round(weathers.filter((w: string) => w === 'sun').length / weathers.length * 100) : 0
    const subjects = myResults.map((r: any) => `${r.unit}:${r.total > 0 ? Math.round(r.correct_count / r.total * 100) : 0}%`).join(',')
    return {
      name: m.name,
      thisWeek: { count: myHW.length, totalMin, sunRate },
      prevWeek: prevW ? { count: prevW.cnt, totalMin: prevW.totalMin } : null,
      subjects,
      revisions: myPlan?.revision_count || 0,
    }
  })

  // クラス全体統計
  const classStats = {
    totalStudents: memberList.length,
    submittedStudents: new Set(hwList.map((h: any) => h.user_id)).size,
    totalSubmissions: hwList.length,
    avgMinPerStudent: memberList.length ? Math.round(hwList.reduce((a: number, h: any) => a + (h.minutes || 0), 0) / memberList.length) : 0,
    avgSunRate: (() => {
      const allW = hwList.map((h: any) => h.end_weather).filter(Boolean)
      return allW.length ? Math.round(allW.filter((w: string) => w === 'sun').length / allW.length * 100) : 0
    })(),
  }

  // Gemini AIで週報生成
  let reportText = ''
  try {
    const studentLines = studentSummaries.map((s, i) => {
      let line = `${i+1}. ${s.name}: 提出${s.thisWeek.count}回(${s.thisWeek.totalMin}分) 満足度${s.thisWeek.sunRate}%`
      if (s.prevWeek) line += ` [先週:${s.prevWeek.count}回/${s.prevWeek.totalMin}分]`
      if (s.subjects) line += ` 教科:${s.subjects}`
      if (s.revisions > 0) line += ` 計画修正${s.revisions}回`
      return line
    }).join('\n')

    const reportPrompt = `あなたは小学校の担任教師の週報作成を手伝うAIアシスタントです。
以下のデータから「${cls.name}」クラスの週報（${weekKey}）を作成してください。

＜クラス統計＞
在籍: ${classStats.totalStudents}人 / 提出者: ${classStats.submittedStudents}人 / 総提出: ${classStats.totalSubmissions}回
1人あたり平均学習時間: ${classStats.avgMinPerStudent}分 / クラス全体の満足度: ${classStats.avgSunRate}%

＜児童別データ＞
${studentLines}

以下の構成で週報を作成してください：
1. 📊 今週の概況（クラス全体の提出率・学習時間・先週との比較）
2. ⭐ 今週のMVP（特に頑張った児童3人と理由）
3. 🔍 気になる児童（未提出・学習時間減少・満足度低下の児童）
4. 📈 教科別の傾向（正答率が低い教科、よく取り組まれている教科）
5. 💡 来週に向けて（教師へのアドバイス・声かけのポイント）

温かく前向きなトーンで、先生が保護者や管理職に共有できるクオリティで書いてください。`

    const gRes = await callGemini(c.env, {
      contents: [{ role: 'user', parts: [{ text: reportPrompt }] }],
      generationConfig: { temperature: 0.5, maxOutputTokens: 2048 },
    })
    if (gRes.ok) {
      reportText = gRes.text
    }
  } catch (e: any) {
    console.error('Weekly report AI error:', e?.message || e)
  }

  return c.json({
    ok: true,
    weekKey,
    className: cls.name,
    classStats,
    studentSummaries,
    reportText,
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
           c.homework_enabled as homeworkEnabled, c.contact_enabled as contactEnabled, c.menus_enabled as menusEnabled
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
      case 'correct': case 'grade': extraSelect = ', ROUND(rs.ranking_points - rs.week_base_ranking_points, 1) as weeklyScore'; orderCol = 'weeklyScore'; break
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
  // 最終アクティブ日時を更新（fire-and-forget）
  c.env.DB.prepare(`UPDATE users SET last_login_at=datetime('now') WHERE id=?`).bind(u.id).run().catch(() => {})
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
       self_study_plan, weekly_plan, weekly_reflection, work_photo_analysis)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
    String(body.weeklyReflection || '').slice(0, 1000),
    String(body.workPhotoAnalysis || '').slice(0, 500)
  ).run()

  return c.json({ ok: true, id })
})

// 生徒：成果物写真をAIで分析してテキスト化→DB保存
app.post('/api/homework/analyze-photo', async (c) => {
  try {
    const u = c.get('user')
    if (!u) return jsonError(c, 403, 'forbidden')

    const formData = await c.req.formData().catch(() => null)
    if (!formData) return jsonError(c, 400, 'invalid_form_data')

    const dayKey = String(formData.get('dayKey') || '').slice(0, 10)
    if (!dayKey) return jsonError(c, 400, 'day_key_required')

    const photo = formData.get('photo') as File | null
    if (!photo || !photo.size) return jsonError(c, 400, 'photo_required')
    if (photo.size > 5 * 1024 * 1024) return jsonError(c, 400, 'photo_too_large_max_5mb')

    let analysisText = ''
    const imageBytes = new Uint8Array(await photo.arrayBuffer())
    const mimeType = photo.type || 'image/jpeg'

    // R2に写真を保存（R2バインディングがある場合のみ）
    const ext = mimeType === 'image/png' ? 'png' : 'jpg'
    const photoKey = `photos/${u.id}/${dayKey}.${ext}`
    try {
      if (c.env.PHOTOS) {
        await c.env.PHOTOS.put(photoKey, imageBytes, {
          httpMetadata: { contentType: mimeType },
        })
      }
      // DBにキーを記録
      const existing0 = await c.env.DB.prepare(
        `SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1`
      ).bind(u.id, dayKey).first<any>()
      if (existing0) {
        await c.env.DB.prepare(
          `UPDATE homework_submissions SET work_photo_key=? WHERE id=?`
        ).bind(photoKey, existing0.id).run()
      }
    } catch (r2err: any) {
      console.error('R2 photo save error:', r2err?.message || r2err)
    }

    try {
      let binary = ''
      for (let i = 0; i < imageBytes.length; i += 8192) {
        binary += String.fromCharCode(...imageBytes.subarray(i, Math.min(i + 8192, imageBytes.length)))
      }
      const base64 = btoa(binary)

      const photoPrompt = `あなたは小学校の先生です。児童が提出した家庭学習の写真を見て、内容を分析してください。

80〜120文字で簡潔に書いてください:
- 教科・学習内容（何の勉強か）
- 学習の量や丁寧さ
- 良い点を1つ

温かい言葉で。名前や挨拶は不要。`

      // Gemini 2.5 Flash で画像分析
      let geminiDone = false
      try {
        const gRes = await callGemini(c.env, {
          contents: [{ role: 'user', parts: [
            { inline_data: { mime_type: mimeType, data: base64 } },
            { text: photoPrompt }
          ] }],
          generationConfig: { temperature: 0.3, maxOutputTokens: 300 },
        })
        if (gRes.ok) {
          const text = gRes.text
          if (text.trim()) {
            analysisText = text.trim().slice(0, 500)
            geminiDone = true
          }
        }
      } catch (ge: any) {
        console.error('Gemini photo analysis error:', ge?.message || ge)
      }

      // フォールバック: Cloudflare AI (Gemma 4 26B)
      if (!geminiDone) {
        try {
          const dataUri = `data:${mimeType};base64,${base64}`
          const aiRes: any = await c.env.AI.run('@cf/google/gemma-4-26b-a4b-it', {
            messages: [{
              role: 'user',
              content: [
                { type: 'image_url', image_url: { url: dataUri } },
                { type: 'text', text: photoPrompt }
              ]
            }],
            max_tokens: 300,
          })
          analysisText = String(aiRes.response || '').trim().slice(0, 500)
        } catch (cfErr: any) {
          console.error('CF AI photo fallback error:', cfErr?.message || cfErr)
        }
      }
    } catch (e: any) {
      console.error('AI photo analysis error:', e)
      analysisText = ''
    }

    // AI分析が失敗してもOKを返す（写真自体は提出時に保存される）
    if (analysisText) {
      try {
        const existing = await c.env.DB.prepare(
          `SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1`
        ).bind(u.id, dayKey).first<any>()
        if (existing) {
          await c.env.DB.prepare(
            `UPDATE homework_submissions SET work_photo_analysis=? WHERE id=?`
          ).bind(analysisText, existing.id).run()
        }
      } catch (_) {}
    }

    return c.json({ ok: true, analysis: analysisText || '', saved: !!analysisText })
  } catch (e: any) {
    console.error('analyze-photo error:', e)
    return c.json({ ok: true, analysis: '', saved: false })
  }
})

// 写真を取得（先生 or 本人のみ）
app.get('/api/photo/:userId/:dayKey', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 403, 'forbidden')
  const targetUserId = c.req.param('userId')
  const dayKey = c.req.param('dayKey')

  // 本人 or 先生のみ
  if (u.role === 'student' && u.id !== targetUserId) return jsonError(c, 403, 'forbidden')
  if (u.role === 'teacher') {
    const isMine = await c.env.DB.prepare(
      `SELECT 1 FROM class_members cm JOIN classes cl ON cl.id=cm.class_id AND cl.teacher_id=? WHERE cm.user_id=? LIMIT 1`
    ).bind(u.id, targetUserId).first<any>()
    if (!isMine) return jsonError(c, 403, 'forbidden')
  }

  // DBからキー取得 or フォールバックでキー推測
  const row = await c.env.DB.prepare(
    `SELECT work_photo_key FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1`
  ).bind(targetUserId, dayKey).first<any>()

  let photoKey = row?.work_photo_key || ''
  if (!photoKey) {
    // 旧データ用フォールバック：jpgとpngを試す
    photoKey = `photos/${targetUserId}/${dayKey}.jpg`
  }

  if (!c.env.PHOTOS) return jsonError(c, 404, 'photo_storage_not_configured')
  try {
    let obj = await c.env.PHOTOS.get(photoKey)
    if (!obj && photoKey.endsWith('.jpg')) {
      obj = await c.env.PHOTOS.get(photoKey.replace('.jpg', '.png'))
    }
    if (!obj) return jsonError(c, 404, 'photo_not_found')
    const headers = new Headers()
    headers.set('Content-Type', obj.httpMetadata?.contentType || 'image/jpeg')
    headers.set('Cache-Control', 'private, max-age=3600')
    return new Response(obj.body, { headers })
  } catch (e: any) {
    return jsonError(c, 500, 'photo_error')
  }
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
           hs.weekly_plan as weeklyPlan, hs.weekly_reflection as weeklyReflection,
           hs.self_study_plan as selfStudyPlan,
           hs.work_photo_analysis as workPhotoAnalysis,
           hs.work_photo_key as workPhotoKey,
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

// AIで一括コメント生成（家庭学習の日々の振り返り）
app.post('/api/teacher/homework-ai-comments', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body?.classId) return jsonError(c, 400, 'classId required')

  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(body.classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(body.classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  const subs = await c.env.DB.prepare(`
    SELECT hs.id, hs.user_id, hs.todo, hs.why, hs.aim, hs.minutes, hs.end_weather,
           hs.weather_reason, hs.next_improve, hs.weekly_reflection, hs.day_key, u.name,
           hs.work_photo_analysis
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id = ?
    JOIN users u ON u.id = hs.user_id
    WHERE hs.returned_at IS NULL
    ORDER BY u.name, hs.day_key DESC
  `).bind(body.classId).all<any>()

  if (!subs.results?.length) return c.json({ ok: true, comments: [] })

  const userIds = [...new Set(subs.results.map((s: any) => s.user_id))]
  const historyMap: Record<string, any[]> = {}
  for (const uid of userIds) {
    try {
      const hist = await c.env.DB.prepare(`
        SELECT day_key, todo, minutes, end_weather, weather_reason, teacher_comment, aim, next_improve, work_photo_analysis
        FROM homework_submissions WHERE user_id=? AND returned_at IS NOT NULL
        ORDER BY day_key DESC LIMIT 30
      `).bind(uid).all<any>()
      historyMap[uid] = hist.results || []
    } catch { historyMap[uid] = [] }
  }

  // Gemini API で一括コメント生成
  const lines = subs.results.map((s: any, i: number) => {
    const hist = historyMap[s.user_id] || []
    const subjects = hist.map((h: any) => h.todo).filter(Boolean)
    const uniqueSubjects = [...new Set(subjects)].slice(0, 5)
    const avgMin = hist.length ? Math.round(hist.reduce((a: number, h: any) => a + (h.minutes || 0), 0) / hist.length) : 0
    const totalDays = hist.length
    // 天気（学びの満足度）の傾向
    const weathers = hist.map((h: any) => h.end_weather).filter(Boolean)
    const sunCount = weathers.filter((w: string) => w === 'sun').length
    // 学習時間の推移（最近5回 vs それ以前）
    const recent5 = hist.slice(0, 5)
    const older = hist.slice(5)
    const recent5Avg = recent5.length ? Math.round(recent5.reduce((a: number, h: any) => a + (h.minutes || 0), 0) / recent5.length) : 0
    const olderAvg = older.length ? Math.round(older.reduce((a: number, h: any) => a + (h.minutes || 0), 0) / older.length) : 0
    const trend = recent5Avg > olderAvg + 5 ? '↑増加傾向' : recent5Avg < olderAvg - 5 ? '↓減少傾向' : '→安定'
    // 直近の記録（詳細）
    const recentHist = hist.slice(0, 10).map((h: any) =>
      `[${h.day_key}] ${h.todo||''}(${h.minutes||0}分) 天気:${h.end_weather||'?'} めあて:${h.aim||'-'} 振り返り:${h.weather_reason||'-'}${h.work_photo_analysis ? ' 📷:'+h.work_photo_analysis : ''}${h.teacher_comment ? ' 先生:'+h.teacher_comment : ''}`
    ).join('\n    ')
    const photoLine = s.work_photo_analysis ? `\n  成果物の様子: ${s.work_photo_analysis}` : ''
    return `${i+1}. 【${s.name}】(${s.day_key})
  ＜今日の学習＞
  やったこと: ${s.todo || '未記入'}
  なんで: ${s.why || '未記入'}
  めあて: ${s.aim || '未記入'}
  学習時間: ${s.minutes || 0}分
  振り返り(天気): ${s.end_weather || '?'} 理由: ${s.weather_reason || '未記入'}
  次どうする: ${s.next_improve || '未記入'}${photoLine}
  ＜過去の傾向（${totalDays}回分）＞
  平均学習時間: ${avgMin}分 / 最近の傾向: ${trend}（直近5回平均${recent5Avg}分 vs 以前${olderAvg}分）
  よくやる教科: ${uniqueSubjects.join('・') || 'データなし'}
  学びの天気☀️率: ${weathers.length ? Math.round(sunCount/weathers.length*100) : 0}%
  ＜直近の記録＞
    ${recentHist || 'まだ記録なし'}`
  }).join('\n\n')

  const systemPrompt = `あなたは小学校の担任の先生の代わりにコメントを書くアシスタントです。
【ルール】
- 児童の「今日の振り返り」と「過去30回分の振り返り・傾向」を読む
- 各児童への温かく具体的な先生コメントを40文字以内で考える
- 以下の観点を踏まえて、その子だけに向けた個別最適なコメントにする:
  ・賞賛: 今日の頑張り、継続している努力、成長を具体的に褒める
  ・アドバイス: めあてや振り返りの内容から、次につながるヒントを一言添える
  ・成長の気づき: 過去と比べて学習時間が増えた、新しい教科に挑戦した等
- 過去の先生コメントと重複しない新鮮な内容にする
- 過去データがまだない児童には、今日の取り組みだけを褒める
- 必ずJSON形式だけで返答する（他のテキストは一切不要）
【返答形式】
{"comments":["コメント1","コメント2","コメント3",...]}
貼り付けられたテキストを読んだら、上記形式で即座に返答してください。`

  // Gemini API → 失敗時は Cloudflare Workers AI にフォールバック
  const geminiKey = c.env.GEMINI_API_KEY || ''
  let parsed: string[] = []
  let aiSource = 'gemini'

  if (geminiKey) {
    try {
      const resp = await callGemini(c.env, {
        system_instruction: { parts: [{ text: systemPrompt }] },
        contents: [{ parts: [{ text: lines }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 2000 }
      })
      if (resp.ok) {
        const text = resp.text
        if (text) {
          try {
            const jsonMatch = text.match(/\{[\s\S]*\}/)
            if (jsonMatch) parsed = JSON.parse(jsonMatch[0]).comments || []
          } catch {
            parsed = text.split('\n').filter((l: string) => l.match(/^\d+[\.\)]/)).map((l: string) => l.replace(/^\d+[\.\)]\s*/, '').trim())
          }
        }
      } else {
        console.warn('[Gemini] API error - falling back to Cloudflare AI')
        aiSource = 'cloudflare-fallback'
      }
    } catch (e: any) {
      console.warn('[Gemini] Error:', e.message, '- falling back to Cloudflare AI')
      aiSource = 'cloudflare-fallback'
    }
  } else {
    aiSource = 'cloudflare-no-key'
  }

  // フォールバック: Cloudflare Workers AI（1児童ずつ個別生成）
  if (!parsed.length && aiSource !== 'gemini') {
    for (const s of subs.results) {
      const hist = historyMap[s.user_id] || []
      const avgMin = hist.length ? Math.round(hist.reduce((a: number, h: any) => a + (h.minutes || 0), 0) / hist.length) : 0
      let ud = `学習: ${s.todo || '未記入'}, ${s.minutes || 0}分(平均${avgMin}分), 振り返り: ${s.weather_reason || '未記入'}`
      if (s.work_photo_analysis) ud += `, 成果物: ${s.work_photo_analysis}`
      try {
        const aiRes: any = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct', {
          messages: [
            { role: 'system', content: 'あなたは小学校の先生です。児童の家庭学習に対するコメントを1つだけ出力。30文字以内。温かく褒める。名前不要。コメントだけ出力。' },
            { role: 'user', content: ud }
          ],
          max_tokens: 80,
        })
        let t = (aiRes.response || '').trim().replace(/^["「『【]+|["」』】]+$/g, '').replace(/^\d+[\.\)]\s*/, '').replace(/^コメント[:：]\s*/,'').trim()
        parsed.push(t.slice(0, 60))
      } catch { parsed.push('') }
    }
  }

  const comments = subs.results.map((s: any, i: number) => ({
    id: s.id, name: s.name, dayKey: s.day_key, comment: (parsed[i] || '').replace(/^["「]+|["」]+$/g, '').slice(0, 60)
  }))
  return c.json({ ok: true, comments, _source: aiSource })
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

function getPrevWeekKey(weekKey) {
  const m = weekKey.match(/^(\d{4})-W(\d{2})$/);
  if (!m) return weekKey;
  let y = parseInt(m[1]), w = parseInt(m[2]);
  w--;
  if (w < 1) { y--; w = 52; }
  return y + '-W' + String(w).padStart(2, '0');
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
  const tests = String(body.tests || '').slice(0, 500)
  // 有効な曜日（デフォルト: 月〜金）
  const validDays = ['mon','tue','wed','thu','fri']
  const activeDays = Array.isArray(body.activeDays)
    ? body.activeDays.filter((d: string) => validDays.includes(d))
    : validDays
  const activeDaysJson = JSON.stringify(activeDays)

  await c.env.DB.prepare(`
    INSERT INTO class_weekly_menu (class_id, week_key, kanji_page, keisan_page, other_tasks, tests, active_days, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(class_id, week_key) DO UPDATE SET
      kanji_page=excluded.kanji_page, keisan_page=excluded.keisan_page,
      other_tasks=excluded.other_tasks, tests=excluded.tests, active_days=excluded.active_days, updated_at=excluded.updated_at
  `).bind(classId, weekKey, kanjiPage, keisanPage, otherTasks, tests, activeDaysJson, Date.now()).run()

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

// 生徒（または管理者・教師）：自分のクラスの今週の先生メニューを取得
app.get('/api/student/weekly-menu', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 403, 'forbidden')

  const weekKey = c.req.query('weekKey') || getWeekKey()
  const classIdParam = c.req.query('classId') || ''

  // 生徒はclass_members経由、teacher/adminはclasses経由（またはclassIdパラメータ）で検索
  let row: any = null
  if (u.role === 'teacher' || u.role === 'admin') {
    if (classIdParam) {
      row = await c.env.DB.prepare(`
        SELECT kanji_page as kanjiPage, keisan_page as keisanPage,
               other_tasks as otherTasks, tests, week_key as weekKey, active_days as activeDays
        FROM class_weekly_menu WHERE class_id = ? AND week_key = ? LIMIT 1
      `).bind(classIdParam, weekKey).first<any>()
    } else {
      // classId未指定時は教師の最初のクラスを使用
      row = await c.env.DB.prepare(`
        SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
               cwm.other_tasks as otherTasks, cwm.tests as tests, cwm.week_key as weekKey,
               cwm.active_days as activeDays
        FROM class_weekly_menu cwm
        JOIN classes cls ON cls.id = cwm.class_id
        WHERE cls.teacher_id = ? AND cwm.week_key = ?
        LIMIT 1
      `).bind(u.id, weekKey).first<any>()
    }
  } else {
    row = await c.env.DB.prepare(`
      SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
             cwm.other_tasks as otherTasks, cwm.tests as tests, cwm.week_key as weekKey,
             cwm.active_days as activeDays
      FROM class_weekly_menu cwm
      JOIN class_members cm ON cm.class_id = cwm.class_id
      WHERE cm.user_id = ? AND cwm.week_key = ?
      LIMIT 1
    `).bind(u.id, weekKey).first<any>()
  }

  // 今週のメニューが未配信の場合、前週のメニューをフォールバックで返す
  if (!row) {
    const prevWk = getPrevWeekKey(weekKey)
    let prevRow: any = null
    if (u.role === 'teacher' || u.role === 'admin') {
      if (classIdParam) {
        prevRow = await c.env.DB.prepare(`
          SELECT kanji_page as kanjiPage, keisan_page as keisanPage,
                 other_tasks as otherTasks, tests, week_key as weekKey, active_days as activeDays
          FROM class_weekly_menu WHERE class_id = ? AND week_key = ? LIMIT 1
        `).bind(classIdParam, prevWk).first<any>()
      } else {
        prevRow = await c.env.DB.prepare(`
          SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
                 cwm.other_tasks as otherTasks, cwm.tests as tests, cwm.week_key as weekKey,
                 cwm.active_days as activeDays
          FROM class_weekly_menu cwm
          JOIN classes cls ON cls.id = cwm.class_id
          WHERE cls.teacher_id = ? AND cwm.week_key = ?
          LIMIT 1
        `).bind(u.id, prevWk).first<any>()
      }
    } else {
      prevRow = await c.env.DB.prepare(`
        SELECT cwm.kanji_page as kanjiPage, cwm.keisan_page as keisanPage,
               cwm.other_tasks as otherTasks, cwm.tests as tests, cwm.week_key as weekKey,
               cwm.active_days as activeDays
        FROM class_weekly_menu cwm
        JOIN class_members cm ON cm.class_id = cwm.class_id
        WHERE cm.user_id = ? AND cwm.week_key = ?
        LIMIT 1
      `).bind(u.id, prevWk).first<any>()
    }
    return c.json({ ok: true, menu: prevRow || null, weekKey, published: false, fallbackWeek: prevRow ? prevWk : null })
  }

  return c.json({ ok: true, menu: row, weekKey, published: true })
})

// 生徒：計画・振り返りの承認状況を取得
app.get('/api/student/weekly-plan-status', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 403, 'forbidden')
  const weekKey = c.req.query('weekKey') || getWeekKey()
  const row = await c.env.DB.prepare(`
    SELECT plan_approved as planApproved, plan_reward_coins as planRewardCoins,
           reflection_comment as reflectionComment, reflection_returned_at as reflectionReturnedAt,
           reflection_reward_coins as reflectionRewardCoins
    FROM student_weekly_plans WHERE user_id=? AND week_key=?
  `).bind(u.id, weekKey).first<any>()
  return c.json({ ok: true, status: row || null })
})

// 生徒：週間計画を提出（修正履歴付き・自己調整記録）
app.post('/api/student/weekly-plan', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body || !body.weekKey || !body.plans) return jsonError(c, 400, 'invalid')

  const weekKey = String(body.weekKey).slice(0, 10)
  const plansJson = JSON.stringify(body.plans).slice(0, 5000)
  const reason = String(body.reason || '').slice(0, 200)
  const now = Date.now()

  // 既存の計画があるか確認（修正履歴を残すため）
  const existing = await c.env.DB.prepare(
    `SELECT id, plans_json, revision_count FROM student_weekly_plans WHERE user_id=? AND week_key=?`
  ).bind(u.id, weekKey).first<any>()

  if (existing && existing.plans_json && existing.plans_json !== plansJson) {
    // 修正履歴を保存（自己調整の記録）
    const revNum = (existing.revision_count || 0) + 1
    await c.env.DB.prepare(`
      INSERT INTO plan_revisions (plan_id, user_id, week_key, revision_number, before_json, after_json, reason, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(existing.id, u.id, weekKey, revNum, existing.plans_json, plansJson, reason, now).run()

    await c.env.DB.prepare(
      `UPDATE student_weekly_plans SET plans_json=?, updated_at=?, revision_count=? WHERE id=?`
    ).bind(plansJson, now, revNum, existing.id).run()
  } else {
    await c.env.DB.prepare(`
      INSERT INTO student_weekly_plans (user_id, week_key, plans_json, updated_at, revision_count)
      VALUES (?, ?, ?, ?, 0)
      ON CONFLICT(user_id, week_key) DO UPDATE SET plans_json=excluded.plans_json, updated_at=excluded.updated_at
    `).bind(u.id, weekKey, plansJson, now).run()
  }

  return c.json({ ok: true })
})

// 生徒：構造化ふりかえりを提出
app.post('/api/student/weekly-reflection', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body || !body.weekKey) return jsonError(c, 400, 'invalid')

  const weekKey = String(body.weekKey).slice(0, 10)
  const concentration = Math.min(3, Math.max(1, Number(body.concentration) || 2))
  const goodPoint = String(body.goodPoint || '').slice(0, 300)
  const improvePoint = String(body.improvePoint || '').slice(0, 300)
  const nextAction = String(body.nextAction || '').slice(0, 50)
  const freeText = String(body.freeText || '').slice(0, 500)
  const now = Date.now()

  await c.env.DB.prepare(`
    INSERT INTO structured_reflections (user_id, week_key, concentration, good_point, improve_point, next_action, free_text, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(user_id, week_key) DO UPDATE SET
      concentration=excluded.concentration, good_point=excluded.good_point,
      improve_point=excluded.improve_point, next_action=excluded.next_action,
      free_text=excluded.free_text, created_at=excluded.created_at
  `).bind(u.id, weekKey, concentration, goodPoint, improvePoint, nextAction, freeText, now).run()

  return c.json({ ok: true })
})

// 生徒：自分の構造化ふりかえりを取得
app.get('/api/student/weekly-reflection', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 403, 'forbidden')
  const weekKey = c.req.query('weekKey') || getWeekKey()

  const row = await c.env.DB.prepare(`
    SELECT concentration, good_point as goodPoint, improve_point as improvePoint,
           next_action as nextAction, free_text as freeText, created_at as createdAt
    FROM structured_reflections WHERE user_id=? AND week_key=?
  `).bind(u.id, weekKey).first<any>()

  return c.json({ ok: true, reflection: row || null })
})

// 生徒：自分の学習ダッシュボード（成長の見える化）
app.get('/api/student/dashboard', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 403, 'forbidden')
  const weekKey = getWeekKey()
  const prevWeekKey = getPrevWeekKey(weekKey)

  // 1) 今週・先週の宿題提出データ
  const thisWeekHW = await c.env.DB.prepare(`
    SELECT COUNT(*) as cnt, COALESCE(SUM(minutes),0) as totalMin, COALESCE(AVG(minutes),0) as avgMin
    FROM homework_submissions WHERE user_id=? AND week_key=?
  `).bind(u.id, weekKey).first<any>()
  const prevWeekHW = await c.env.DB.prepare(`
    SELECT COUNT(*) as cnt, COALESCE(SUM(minutes),0) as totalMin, COALESCE(AVG(minutes),0) as avgMin
    FROM homework_submissions WHERE user_id=? AND week_key=?
  `).bind(u.id, prevWeekKey).first<any>()

  // 2) 教科別正答率（今週 vs 先週）
  const thisWeekResults = await c.env.DB.prepare(`
    SELECT unit, COUNT(*) as total,
           SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END) as correct_count
    FROM learning_results WHERE user_id=? AND week_key=?
    GROUP BY unit
  `).bind(u.id, weekKey).all<any>()
  const prevWeekResults = await c.env.DB.prepare(`
    SELECT unit, COUNT(*) as total,
           SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END) as correct_count
    FROM learning_results WHERE user_id=? AND week_key=?
    GROUP BY unit
  `).bind(u.id, prevWeekKey).all<any>()

  // 3) ストリーク
  const streakRow = await c.env.DB.prepare(`
    SELECT streak_after as streak FROM homework_submissions
    WHERE user_id=? ORDER BY submitted_at DESC LIMIT 1
  `).bind(u.id).first<any>()

  // 4) 自己調整スコア算出
  const planRow = await c.env.DB.prepare(`
    SELECT revision_count, plan_approved FROM student_weekly_plans WHERE user_id=? AND week_key=?
  `).bind(u.id, weekKey).first<any>()
  const reflectionRow = await c.env.DB.prepare(`
    SELECT concentration, good_point, improve_point, next_action FROM structured_reflections WHERE user_id=? AND week_key=?
  `).bind(u.id, weekKey).first<any>()

  // 修正理由の質もチェック
  const revisions = await c.env.DB.prepare(`
    SELECT reason FROM plan_revisions WHERE user_id=? AND week_key=?
  `).bind(u.id, weekKey).all<any>()

  // スコア計算
  let selfRegScore = 0
  // 計画力: 計画を立てたか (+2)
  if (planRow) selfRegScore += 2
  // 実行力: 提出回数/5曜日 (+3 max)
  const execRate = Math.min(1, (thisWeekHW?.cnt || 0) / 5)
  selfRegScore += Math.round(execRate * 3)
  // 調整力: 理由付き修正 (+2/回, max +6)
  const reasonedRevs = (revisions.results || []).filter((r: any) => r.reason && r.reason.length > 0).length
  selfRegScore += Math.min(6, reasonedRevs * 2)
  // 内省力: ふりかえりの充実度 (+3 max)
  if (reflectionRow) {
    let refScore = 0
    if (reflectionRow.good_point && reflectionRow.good_point.length >= 5) refScore += 1
    if (reflectionRow.improve_point && reflectionRow.improve_point.length >= 5) refScore += 1
    if (reflectionRow.next_action) refScore += 1
    selfRegScore += refScore
  }

  // 5) 自動フィードバックメッセージ生成
  const feedback = generateFeedback({
    streak: streakRow?.streak || 0,
    thisWeekMin: thisWeekHW?.totalMin || 0,
    prevWeekMin: prevWeekHW?.totalMin || 0,
    thisWeekCount: thisWeekHW?.cnt || 0,
    thisWeekResults: thisWeekResults.results || [],
    prevWeekResults: prevWeekResults.results || [],
    selfRegScore,
    revisionCount: planRow?.revision_count || 0,
  })

  return c.json({
    ok: true,
    weekKey,
    homework: {
      thisWeek: { count: thisWeekHW?.cnt || 0, totalMin: thisWeekHW?.totalMin || 0, avgMin: Math.round(thisWeekHW?.avgMin || 0) },
      prevWeek: { count: prevWeekHW?.cnt || 0, totalMin: prevWeekHW?.totalMin || 0, avgMin: Math.round(prevWeekHW?.avgMin || 0) },
    },
    results: {
      thisWeek: (thisWeekResults.results || []).map((r: any) => ({ unit: r.unit, rate: r.total > 0 ? Math.round(r.correct_count / r.total * 100) : 0, total: r.total })),
      prevWeek: (prevWeekResults.results || []).map((r: any) => ({ unit: r.unit, rate: r.total > 0 ? Math.round(r.correct_count / r.total * 100) : 0, total: r.total })),
    },
    streak: streakRow?.streak || 0,
    selfRegulation: {
      score: selfRegScore,
      maxScore: 14,
      planMade: !!planRow,
      revisionCount: planRow?.revision_count || 0,
      reflectionDone: !!reflectionRow,
    },
    feedback,
  })
})

// 自動フィードバックメッセージ生成ロジック
function generateFeedback(data: {
  streak: number, thisWeekMin: number, prevWeekMin: number, thisWeekCount: number,
  thisWeekResults: any[], prevWeekResults: any[], selfRegScore: number, revisionCount: number,
}): string[] {
  const msgs: string[] = []

  // ストリーク
  if (data.streak >= 14) msgs.push('🔥 ' + data.streak + '日連続提出！すごい継続力だね！この調子！')
  else if (data.streak >= 7) msgs.push('⭐ 1週間連続で提出できたね！がんばってるね！')
  else if (data.streak >= 3) msgs.push('👍 ' + data.streak + '日連続！いいリズムだよ！')

  // 学習時間の変化
  if (data.prevWeekMin > 0 && data.thisWeekMin > 0) {
    const diff = data.thisWeekMin - data.prevWeekMin
    const pct = Math.round(diff / data.prevWeekMin * 100)
    if (pct >= 20) msgs.push('📈 先週より学習時間が' + pct + '%アップ！がんばりが見えるよ！')
    else if (pct <= -20 && data.thisWeekCount >= 3) msgs.push('💪 今週は少し時間が短めだけど、ちゃんと取り組めてるね！')
  }

  // 教科別の成長
  const prevMap: Record<string, number> = {}
  for (const r of data.prevWeekResults) prevMap[r.unit] = r.total > 0 ? Math.round(r.correct_count / r.total * 100) : 0
  for (const r of data.thisWeekResults) {
    const thisRate = r.total > 0 ? Math.round(r.correct_count / r.total * 100) : 0
    const prevRate = prevMap[r.unit] || 0
    if (thisRate >= prevRate + 15 && r.total >= 3) {
      msgs.push('🎯 ' + r.unit + 'の正答率が先週より' + (thisRate - prevRate) + '%アップ！力がついてきたね！')
    }
    if (thisRate < 50 && r.total >= 5) {
      msgs.push('📝 ' + r.unit + 'はもう少し練習してみよう。コツコツやれば必ず伸びるよ！')
    }
  }

  // 自己調整
  if (data.revisionCount >= 2) msgs.push('🔄 計画を' + data.revisionCount + '回見直せたね！自分で考えて調整できるのはすごいことだよ！')
  else if (data.revisionCount === 1) msgs.push('🔄 計画を見直して修正できたね！これが「自分で学ぶ力」だよ！')

  if (data.selfRegScore >= 10) msgs.push('🏆 自己調整スコアが' + data.selfRegScore + '点！自分の学びをしっかりコントロールできてるね！')

  // デフォルト
  if (msgs.length === 0) msgs.push('🌟 今週も家庭学習をがんばろう！少しずつで大丈夫だよ！')

  return msgs.slice(0, 4) // 最大4つに絞る
}

// 先生：クラス全体の分析ダッシュボード
app.get('/api/teacher/class-analytics', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.query('classId')
  if (!classId) return jsonError(c, 400, 'classId required')
  const weekKey = c.req.query('weekKey') || getWeekKey()
  const prevWeekKey = getPrevWeekKey(weekKey)

  // 権限チェック
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? LIMIT 1`).bind(classId).first<any>()
    : await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? AND teacher_id=?`).bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  // 児童一覧
  const members = await c.env.DB.prepare(`
    SELECT u.id, u.name, u.grade, u.class_name as className
    FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=?
    ORDER BY u.grade, u.class_name, u.name
  `).bind(classId).all<any>()

  // 提出率ヒートマップ用（曜日×児童）
  let hwData: any = { results: [] }, prevHwData: any = { results: [] }
  try {
    hwData = await c.env.DB.prepare(`
    SELECT hs.user_id, hs.submitted_at, hs.minutes
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
    WHERE hs.week_key=?
  `).bind(classId, weekKey).all<any>()
  } catch {}

  // 先週の提出データ（変化検知用）
  try {
    prevHwData = await c.env.DB.prepare(`
    SELECT hs.user_id, COUNT(*) as cnt, SUM(hs.minutes) as totalMin
    FROM homework_submissions hs
    JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
    WHERE hs.week_key=?
    GROUP BY hs.user_id
  `).bind(classId, prevWeekKey).all<any>()
  } catch {}

  // 自己調整データ
  const planData = await c.env.DB.prepare(`
    SELECT swp.user_id, swp.revision_count, swp.plan_approved
    FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id AND cm.class_id=?
    WHERE swp.week_key=?
  `).bind(classId, weekKey).all<any>()

  const refData = await c.env.DB.prepare(`
    SELECT sr.user_id, sr.concentration, sr.good_point, sr.improve_point, sr.next_action
    FROM structured_reflections sr
    JOIN class_members cm ON cm.user_id = sr.user_id AND cm.class_id=?
    WHERE sr.week_key=?
  `).bind(classId, weekKey).all<any>()

  // 「気になる児童」アラート生成
  const prevHwMap: Record<string, any> = {}
  for (const r of prevHwData.results || []) prevHwMap[r.user_id] = r

  const thisHwByUser: Record<string, { cnt: number, totalMin: number }> = {}
  for (const r of (hwData.results || [])) {
    if (!thisHwByUser[r.user_id]) thisHwByUser[r.user_id] = { cnt: 0, totalMin: 0 }
    thisHwByUser[r.user_id].cnt++
    thisHwByUser[r.user_id].totalMin += (r.minutes || 0)
  }

  const alerts: { userId: string, name: string, type: string, detail: string }[] = []
  for (const m of (members.results || [])) {
    const thisW = thisHwByUser[m.id]
    const prevW = prevHwMap[m.id]
    // 提出が減った
    if (prevW && prevW.cnt >= 3 && (!thisW || thisW.cnt <= 1)) {
      alerts.push({ userId: m.id, name: m.name, type: 'submission_drop', detail: '先週'+prevW.cnt+'回→今週'+(thisW?.cnt||0)+'回に減少' })
    }
    // 学習時間が大幅減
    if (prevW && prevW.totalMin >= 60 && thisW && thisW.totalMin < prevW.totalMin * 0.5) {
      alerts.push({ userId: m.id, name: m.name, type: 'time_drop', detail: '学習時間が先週の半分以下' })
    }
    // 今週ゼロ提出
    if (!thisW && (members.results || []).length > 0) {
      alerts.push({ userId: m.id, name: m.name, type: 'no_submission', detail: '今週まだ提出なし' })
    }
  }

  return c.json({
    ok: true, weekKey,
    members: members.results,
    homework: hwData.results,
    plans: planData.results,
    reflections: refData.results,
    alerts,
  })
})

// 先生：自動フィードバック候補の一括生成
app.get('/api/teacher/auto-feedback', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.query('classId')
  if (!classId) return jsonError(c, 400, 'classId required')
  const weekKey = c.req.query('weekKey') || getWeekKey()
  const prevWeekKey = getPrevWeekKey(weekKey)

  // 権限チェック
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? LIMIT 1`).bind(classId).first<any>()
    : await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? AND teacher_id=?`).bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  // 児童一覧
  const members = await c.env.DB.prepare(`
    SELECT u.id, u.name FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=?
  `).bind(classId).all<any>()

  const feedbackList: { userId: string, name: string, messages: string[] }[] = []

  // 各児童のデータを収集
  const studentDataList: { userId: string, name: string, thisHW: any, prevHW: any, streak: number, thisResults: any[], prevResults: any[], revisionCount: number }[] = []

  for (const m of (members.results || [])) {
    let thisHW: any = { cnt: 0, totalMin: 0 }
    let prevHW: any = { cnt: 0, totalMin: 0 }
    try { thisHW = await c.env.DB.prepare(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(minutes),0) as totalMin FROM homework_submissions WHERE user_id=? AND week_key=?
    `).bind(m.id, weekKey).first<any>() || thisHW } catch {}
    try { prevHW = await c.env.DB.prepare(`
      SELECT COUNT(*) as cnt, COALESCE(SUM(minutes),0) as totalMin FROM homework_submissions WHERE user_id=? AND week_key=?
    `).bind(m.id, prevWeekKey).first<any>() || prevHW } catch {}
    let streakRow: any = null
    try { streakRow = await c.env.DB.prepare(`
      SELECT streak_after as streak FROM homework_submissions WHERE user_id=? ORDER BY submitted_at DESC LIMIT 1
    `).bind(m.id).first<any>() } catch {}
    let thisResults: any = { results: [] }
    try { thisResults = await c.env.DB.prepare(`
      SELECT unit, COUNT(*) as total, SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END) as correct_count
      FROM learning_results WHERE user_id=? AND week_key=? GROUP BY unit
    `).bind(m.id, weekKey).all<any>() } catch {}
    let prevResults: any = { results: [] }
    try { prevResults = await c.env.DB.prepare(`
      SELECT unit, COUNT(*) as total, SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END) as correct_count
      FROM learning_results WHERE user_id=? AND week_key=? GROUP BY unit
    `).bind(m.id, prevWeekKey).all<any>() } catch {}
    let planRow: any = null
    try { planRow = await c.env.DB.prepare(`
      SELECT revision_count FROM student_weekly_plans WHERE user_id=? AND week_key=?
    `).bind(m.id, weekKey).first<any>() } catch {}

    // 過去30日分の提出データも取得
    let recentHistory: any = { results: [] }
    try { recentHistory = await c.env.DB.prepare(`
      SELECT day_key, todo, minutes, end_weather, weather_reason, teacher_comment, aim, next_improve
      FROM homework_submissions WHERE user_id=? AND returned_at IS NOT NULL
      ORDER BY day_key DESC LIMIT 30
    `).bind(m.id).all<any>() } catch {}

    studentDataList.push({
      userId: m.id, name: m.name,
      thisHW, prevHW,
      streak: streakRow?.streak || 0,
      thisResults: thisResults.results || [],
      prevResults: prevResults.results || [],
      revisionCount: planRow?.revision_count || 0,
    })

    // Gemini用のデータに過去履歴も含める
    ;(studentDataList[studentDataList.length - 1] as any).recentHistory = recentHistory.results || []
  }

  // Gemini APIで一括フィードバック生成
  let geminiSuccess = false
  const geminiKey = (c.env as any).GEMINI_API_KEY
  if (geminiKey && studentDataList.length > 0) {
    try {
      const lines = studentDataList.map((s, i) => {
        const thisR = s.thisResults.map((r: any) => `${r.unit}:正答率${r.total > 0 ? Math.round(r.correct_count / r.total * 100) : 0}%(${r.total}問)`).join(', ')
        const prevR = s.prevResults.map((r: any) => `${r.unit}:正答率${r.total > 0 ? Math.round(r.correct_count / r.total * 100) : 0}%(${r.total}問)`).join(', ')
        const history = ((s as any).recentHistory || []).slice(0, 5).map((h: any) =>
          `${h.day_key}: ${h.todo || ''}(${h.minutes}分) 天気:${h.end_weather || '?'} めあて:${h.aim || ''} 次:${h.next_improve || ''}`
        ).join(' / ')
        return `${i + 1}. 【${s.name}】
＜今週＞ 提出${s.thisHW?.cnt || 0}回, 合計${s.thisHW?.totalMin || 0}分
＜先週＞ 提出${s.prevHW?.cnt || 0}回, 合計${s.prevHW?.totalMin || 0}分
連続提出: ${s.streak}日
計画見直し回数: ${s.revisionCount}回
今週の教科別: ${thisR || 'なし'}
先週の教科別: ${prevR || 'なし'}
直近の記録: ${history || 'なし'}`
      }).join('\n\n')

      const systemPrompt = `あなたは小学校の担任の先生の代わりに、週次フィードバックを書くアシスタントです。
【ルール】
- 各児童の今週と先週のデータ、連続提出日数、教科別成績、直近の記録を読む
- 各児童に対して、1〜4個の温かくて具体的なフィードバックメッセージを生成する
- 賞賛・アドバイス・成長の気づきを踏まえた個別最適なメッセージにする
- 各メッセージは絵文字1つ＋50文字以内
- 先週との比較で具体的な変化に言及する
- データがない児童には「今週もがんばろう！」系の励ましを1つだけ
- 必ずJSON形式だけで返答: {"feedback":[["メッセージ1","メッセージ2"],["メッセージ1"],...]}
  （外側の配列は児童順、内側の配列は各児童のメッセージ群）`

      const gRes = await callGemini(c.env, {
        system_instruction: { parts: [{ text: systemPrompt }] },
        contents: [{ role: 'user', parts: [{ text: `以下の児童データに基づいて週次フィードバックを生成してください。\n\n${lines}` }] }],
        generationConfig: { temperature: 0.7, maxOutputTokens: 2048 },
      })

      if (gRes.ok) {
        const rawText = gRes.text
        const jsonMatch = rawText.match(/\{[\s\S]*"feedback"[\s\S]*\}/)
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0])
          if (parsed.feedback && Array.isArray(parsed.feedback) && parsed.feedback.length === studentDataList.length) {
            for (let i = 0; i < studentDataList.length; i++) {
              const msgs = Array.isArray(parsed.feedback[i]) ? parsed.feedback[i].filter((m: any) => typeof m === 'string' && m.length > 0) : []
              feedbackList.push({ userId: studentDataList[i].userId, name: studentDataList[i].name, messages: msgs.length > 0 ? msgs : ['🌟 今週もがんばろう！'] })
            }
            geminiSuccess = true
          }
        }
      }
    } catch (e: any) {
      console.error('Gemini weekly feedback error:', e?.message || e)
    }
  }

  // フォールバック: ルールベースのgenerateFeedback
  if (!geminiSuccess) {
    for (const s of studentDataList) {
      const msgs = generateFeedback({
        streak: s.streak,
        thisWeekMin: s.thisHW?.totalMin || 0, prevWeekMin: s.prevHW?.totalMin || 0,
        thisWeekCount: s.thisHW?.cnt || 0,
        thisWeekResults: s.thisResults, prevWeekResults: s.prevResults,
        selfRegScore: 0, revisionCount: s.revisionCount,
      })
      feedbackList.push({ userId: s.userId, name: s.name, messages: msgs })
    }
  }

  return c.json({ ok: true, feedbackList, weekKey, aiSource: geminiSuccess ? 'gemini' : 'rule' })
})

// 先生：特定の生徒の計画修正履歴を取得
app.get('/api/teacher/weekly-plan/:id/revisions', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const planId = c.req.param('id')

  const plan = await c.env.DB.prepare(`
    SELECT swp.user_id, swp.week_key FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.id = ?
  `).bind(u.id, planId).first<any>()
  if (!plan) return jsonError(c, 404, 'not_found')

  const rows = await c.env.DB.prepare(`
    SELECT id, revision_number as revisionNumber, before_json as beforeJson, after_json as afterJson,
           reason, created_at as createdAt
    FROM plan_revisions WHERE plan_id=? ORDER BY revision_number DESC
  `).bind(planId).all<any>()

  return c.json({ ok: true, revisions: rows.results })
})

// 先生：クラスの生徒の週間計画を取得
app.get('/api/teacher/weekly-plans', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.query('classId')
  const weekKey = c.req.query('weekKey') || getWeekKey()

  let sql = `
    SELECT swp.id, swp.plans_json as plansJson, swp.updated_at as updatedAt, swp.week_key as weekKey,
           swp.plan_approved as planApproved, swp.plan_approved_at as planApprovedAt,
           swp.reflection_comment as reflectionComment, swp.reflection_returned_at as reflectionReturnedAt,
           swp.revision_count as revisionCount,
           u.id as userId, u.name as studentName, u.grade, u.class_name as className
    FROM student_weekly_plans swp
    JOIN users u ON u.id = swp.user_id
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.week_key = ?
  `
  const binds: any[] = [u.id, weekKey]
  if (classId) { sql += ` AND cl.id = ?`; binds.push(classId) }
  sql += ` ORDER BY u.grade, u.class_name, u.name`

  const res = await c.env.DB.prepare(sql).bind(...binds).all<any>()
  return c.json({ ok: true, plans: res.results, weekKey })
})

// 先生：計画を承認（OKを出す）→ 生徒にコイン付与
app.post('/api/teacher/weekly-plan/:id/approve', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const planId = c.req.param('id')

  // 承認対象を取得＋権限チェック
  const row = await c.env.DB.prepare(`
    SELECT swp.*, cm.class_id FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.id = ?
  `).bind(u.id, planId).first<any>()
  if (!row) return jsonError(c, 404, 'not_found')
  if (row.plan_approved) return jsonError(c, 400, 'already_approved')

  const coins = 300, shards = 5
  await c.env.DB.prepare(
    `UPDATE student_weekly_plans SET plan_approved=1, plan_approved_at=?, plan_reward_coins=? WHERE id=?`
  ).bind(Date.now(), coins, planId).run()

  return c.json({ ok: true, coins, shards })
})

// 先生：振り返りにコメント付きで返却 → 生徒にコイン付与
app.post('/api/teacher/weekly-plan/:id/return-reflection', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const planId = c.req.param('id')
  const body = await c.req.json<any>().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid')
  const comment = String(body.comment || '').slice(0, 500)

  const row = await c.env.DB.prepare(`
    SELECT swp.*, cm.class_id FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE swp.id = ?
  `).bind(u.id, planId).first<any>()
  if (!row) return jsonError(c, 404, 'not_found')
  if (row.reflection_returned_at) return jsonError(c, 400, 'already_returned')

  const coins = 300, shards = 5
  await c.env.DB.prepare(
    `UPDATE student_weekly_plans SET reflection_comment=?, reflection_returned_at=?, reflection_reward_coins=? WHERE id=?`
  ).bind(comment, Date.now(), coins, planId).run()

  return c.json({ ok: true, coins, shards })
})

// AI計画チェック：生徒の週間計画を評価し問題点をフラグ
app.post('/api/teacher/ai-plan-check', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body?.classId) return jsonError(c, 400, 'classId required')

  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(body.classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(body.classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  const weekKey = body.weekKey || getWeekKey()
  const plans = await c.env.DB.prepare(`
    SELECT swp.id, swp.plans_json, swp.revision_count, swp.plan_approved,
           u.id as userId, u.name, u.grade, u.class_name
    FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id AND cm.class_id = ?
    JOIN users u ON u.id = swp.user_id
    WHERE swp.week_key = ?
    ORDER BY u.name
  `).bind(body.classId, weekKey).all<any>()

  if (!plans.results?.length) return c.json({ ok: true, results: [], message: 'まだ計画が提出されていません' })

  const dayLabels = ['月', '火', '水', '木', '金']
  const lines = plans.results.map((p: any, i: number) => {
    let parsed: any = {}
    try { parsed = JSON.parse(p.plans_json || '{}') } catch (_) {}
    const keys = Object.keys(parsed).filter((k: string) => k !== '_modified')
    const dayPlans = keys.slice(0, 5).map((k: string, di: number) => {
      const val = parsed[k]
      const text = typeof val === 'object' ? (val.free || '') : (val || '')
      return `${dayLabels[di] || '?'}：${text || '（空欄）'}`
    }).join('　/　')
    return `${i + 1}. 【${p.name}】${dayPlans}${p.revision_count > 0 ? `　（${p.revision_count}回修正済）` : ''}`
  }).join('\n')

  const prompt = `あなたは小学校の先生のアシスタントです。以下は児童が提出した今週の家庭学習計画です。

各児童の計画を評価し、以下の観点で問題がある場合にフラグを立ててください：
- 「勉強する」「がんばる」など具体性がない曖昧な計画
- 毎日同じ内容でバリエーションがない
- 空欄が多い（やる気の低下の可能性）
- 非現実的な量や内容
- 教科の偏り（例：毎日算数だけ）

必ず以下のJSON形式だけで返答してください：
{"results":[{"name":"児童名","level":"ok|caution|warning","comment":"短い評価コメント（20文字以内）"},...]}"

level の意味：
- "ok" = 問題なし（具体的で良い計画）
- "caution" = 少し気になる点あり（声かけ推奨）
- "warning" = 要注意（計画の立て直しが必要）

【児童の計画一覧】
${lines}`

  try {
    const gemResult = await callGemini(c.env, {
      contents: [{ role: 'user', parts: [{ text: prompt }] }],
      generationConfig: { temperature: 0.3, maxOutputTokens: 2048 }
    })

    if (gemResult.ok) {
      let parsed: any = null
      try {
        const jsonMatch = gemResult.text.match(/\{[\s\S]*\}/)
        if (jsonMatch) parsed = JSON.parse(jsonMatch[0])
      } catch (_) {}
      if (parsed?.results) {
        return c.json({ ok: true, results: parsed.results, source: gemResult.source })
      }
    }

    // Gemini失敗時：ルールベースの簡易チェック
    const ruleResults = plans.results.map((p: any) => {
      let parsed: any = {}
      try { parsed = JSON.parse(p.plans_json || '{}') } catch (_) {}
      const keys = Object.keys(parsed).filter((k: string) => k !== '_modified')
      const texts = keys.slice(0, 5).map((k: string) => {
        const val = parsed[k]
        return typeof val === 'object' ? (val.free || '') : (val || '')
      })
      const emptyCount = texts.filter((t: string) => !t.trim()).length
      const vague = texts.filter((t: string) => /^(勉強|がんばる|べんきょう|頑張る|やる)$/i.test(t.trim())).length
      const unique = new Set(texts.filter((t: string) => t.trim())).size

      let level = 'ok', comment = '問題なし'
      if (emptyCount >= 3) { level = 'warning'; comment = '空欄が多い（' + emptyCount + '日分）' }
      else if (vague >= 2) { level = 'caution'; comment = '具体性が不足' }
      else if (unique <= 1 && emptyCount < 3) { level = 'caution'; comment = '毎日同じ内容' }
      return { name: p.name, level, comment }
    })
    return c.json({ ok: true, results: ruleResults, source: 'rule-based' })
  } catch (e: any) {
    return jsonError(c, 500, 'ai_error: ' + (e.message || ''))
  }
})

// AIで一括コメント生成（週の振り返り）
app.post('/api/teacher/weekly-ai-comments', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body?.classId) return jsonError(c, 400, 'classId required')

  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(body.classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(body.classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  const weekKey = body.weekKey || getWeekKey()
  const plans = await c.env.DB.prepare(`
    SELECT swp.id, swp.user_id, swp.weekly_reflection, u.name
    FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id AND cm.class_id = ?
    JOIN users u ON u.id = swp.user_id
    WHERE swp.week_key = ? AND swp.reflection_returned_at IS NULL AND swp.weekly_reflection IS NOT NULL
  `).bind(body.classId, weekKey).all<any>()

  if (!plans.results?.length) return c.json({ ok: true, comments: [] })

  const lines = plans.results.map((p: any, i: number) =>
    `${i+1}. 【${p.name}】\n  振り返り: ${p.weekly_reflection || '未記入'}`
  ).join('\n\n')

  const systemPrompt = `あなたは小学校の担任の先生の代わりにコメントを書くアシスタントです。
【ルール】
- 児童の1週間の振り返りを読む
- 各児童への温かく具体的な先生コメントを30文字以内で考える
- その子の成長や努力を踏まえた内容にする
- 必ずJSON形式だけで返答する（他のテキストは一切不要）
【返答形式】
{"comments":["コメント1","コメント2","コメント3",...]}
貼り付けられたテキストを読んだら、上記形式で即座に返答してください。`

  try {
    const resp = await callGemini(c.env, {
      system_instruction: { parts: [{ text: systemPrompt }] },
      contents: [{ parts: [{ text: lines }] }],
      generationConfig: { temperature: 0.7, maxOutputTokens: 2000 }
    })
    if (!resp.ok) return jsonError(c, 500, 'Gemini API error')

    const text = resp.text

    let parsed: string[] = []
    try {
      const jsonMatch = text.match(/\{[\s\S]*\}/)
      if (jsonMatch) parsed = JSON.parse(jsonMatch[0]).comments || []
    } catch {
      parsed = text.split('\n').filter((l: string) => l.match(/^\d+[\.\)]/)).map((l: string) => l.replace(/^\d+[\.\)]\s*/, '').trim())
    }

    const comments = plans.results.map((p: any, i: number) => ({
      id: p.id, name: p.name, comment: (parsed[i] || '').replace(/^["「]+|["」]+$/g, '').slice(0, 60)
    }))
    return c.json({ ok: true, comments })
  } catch (e: any) {
    return jsonError(c, 500, 'Gemini API error: ' + (e.message || String(e)))
  }
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
  const validEvents = ['damage', 'faint', 'win', 'lose', 'self_damage', 'gym_ready', 'egg_battle']
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


// -------------------- Messages (teacher <-> student) --------------------

// Teacher: send message to a student
app.post('/api/teacher/message', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const { classId, studentId, body, image } = await c.req.json<any>()
  if (!classId || !studentId || !body?.trim()) return jsonError(c, 400, 'classId, studentId, body required')
  // Verify teacher owns this class and student is a member
  const cls = await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 403, 'not your class')
  const member = await c.env.DB.prepare('SELECT user_id FROM class_members WHERE class_id=? AND user_id=?').bind(classId, studentId).first<any>()
  if (!member) return jsonError(c, 400, 'student not in class')
  const id = crypto.randomUUID()
  await c.env.DB.prepare(
    'INSERT INTO messages (id, class_id, sender_id, sender_role, recipient_id, body, image) VALUES (?,?,?,?,?,?,?)'
  ).bind(id, classId, u.id, 'teacher', studentId, body.trim(), image || null).run()
  return c.json({ ok: true, id })
})

// Teacher: get messages for a class (sent & received)
app.get('/api/teacher/messages', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.query('classId') || ''
  const studentId = c.req.query('studentId') || ''
  if (!classId) return jsonError(c, 400, 'classId required')
  const cls = await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 403, 'not your class')
  // Cleanup: null out images older than 14 days
  await c.env.DB.prepare(`UPDATE messages SET image=NULL WHERE image IS NOT NULL AND created_at < datetime('now','-14 days')`).run()
  let query = `SELECT m.id, m.sender_id as senderId, m.sender_role as senderRole, m.recipient_id as recipientId, m.body, m.image, m.read_at as readAt, m.created_at as createdAt,
     CASE WHEN m.sender_role='student' THEN u.name ELSE '(先生)' END as senderName,
     CASE WHEN m.sender_role='teacher' THEN u2.name ELSE NULL END as recipientName
     FROM messages m
     LEFT JOIN users u ON m.sender_id = u.id
     LEFT JOIN users u2 ON m.recipient_id = u2.id
     WHERE m.class_id=?`
  const params: string[] = [classId]
  if (studentId) {
    query += ` AND (m.sender_id=? OR m.recipient_id=?)`
    params.push(studentId, studentId)
  }
  query += ` ORDER BY m.created_at DESC LIMIT 100`
  const stmt = c.env.DB.prepare(query)
  const rows = await (params.length === 1 ? stmt.bind(params[0]) : stmt.bind(params[0], params[1], params[2])).all()
  return c.json({ ok: true, messages: rows.results })
})

















// Teacher: mark message as read
app.post('/api/teacher/message/:id/read', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  await c.env.DB.prepare(`UPDATE messages SET read_at=datetime('now') WHERE id=? AND recipient_id=? AND read_at IS NULL`).bind(c.req.param('id'), u.id).run()
  return c.json({ ok: true })
})

// Teacher: get unread count
app.get('/api/teacher/messages/unread-count', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const row = await c.env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM messages WHERE recipient_id=? AND read_at IS NULL'
  ).bind(u.id).first<any>()
  return c.json({ ok: true, count: row?.cnt || 0 })
})

// Student: send message to class teacher
app.post('/api/student/message', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const { body, image } = await c.req.json<any>()
  if (!body?.trim() && !image) return jsonError(c, 400, 'body or image required')
  // Find student's class and teacher
  const membership = await c.env.DB.prepare(
    'SELECT cm.class_id, c.teacher_id FROM class_members cm JOIN classes c ON cm.class_id=c.id WHERE cm.user_id=?'
  ).bind(u.id).first<any>()
  if (!membership) return jsonError(c, 400, 'no class joined')
  const id = crypto.randomUUID()
  await c.env.DB.prepare(
    'INSERT INTO messages (id, class_id, sender_id, sender_role, recipient_id, body, image) VALUES (?,?,?,?,?,?,?)'
  ).bind(id, membership.class_id, u.id, 'student', membership.teacher_id, (body||'').trim() || '(画像)', image || null).run()
  return c.json({ ok: true, id })
})

// Student: get my messages (sent & received)
app.get('/api/student/messages', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const rows = await c.env.DB.prepare(
    `SELECT id, sender_id as senderId, sender_role as senderRole, recipient_id as recipientId, body, image, read_at as readAt, created_at as createdAt
     FROM messages WHERE sender_id=? OR recipient_id=?
     ORDER BY created_at DESC LIMIT 50`
  ).bind(u.id, u.id).all()
  return c.json({ ok: true, messages: rows.results })
})

// Student: mark message as read
app.post('/api/student/message/:id/read', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  await c.env.DB.prepare(`UPDATE messages SET read_at=datetime('now') WHERE id=? AND recipient_id=? AND read_at IS NULL`).bind(c.req.param('id'), u.id).run()
  return c.json({ ok: true })
})

// Student: get unread count
app.get('/api/student/messages/unread-count', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const row = await c.env.DB.prepare(
    'SELECT COUNT(*) as cnt FROM messages WHERE recipient_id=? AND read_at IS NULL'
  ).bind(u.id).first<any>()
  return c.json({ ok: true, count: row?.cnt || 0 })
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
  const u = requireAdmin(c)
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
  const u = requireAdmin(c)
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
  const u = requireAdmin(c)
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
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? LIMIT 1`).bind(classId).first<any>()
    : await c.env.DB.prepare(`SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1`).bind(classId, u.id).first<any>()
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
    const clsRow = await c.env.DB.prepare(`SELECT id FROM classes WHERE teacher_id=? ORDER BY created_at DESC LIMIT 1`).bind(u.id).first<any>()
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

      <!-- 教師一覧 -->
      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-2">👩‍🏫 教師一覧</h2>
        <div id="teacherList" class="space-y-2 text-sm"></div>
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

      <!-- クラス管理 -->
      <div class="bg-white rounded-xl shadow p-6">
        <h2 class="font-bold mb-3">📚 クラス管理（児童追加・削除）</h2>
        <div id="classManagement">
          <div class="flex gap-2 mb-3">
            <button id="loadClassesBtn" class="bg-indigo-600 text-white rounded px-3 py-2 text-sm">クラス一覧を読み込む</button>
          </div>
          <div id="classList" class="space-y-3 text-sm"></div>
          <div id="classDetail" class="mt-4 hidden">
            <div class="border-2 border-indigo-200 rounded-lg p-4">
              <div class="flex items-center justify-between mb-3">
                <h3 id="classDetailName" class="font-bold text-lg"></h3>
                <button id="closeClassDetail" class="text-gray-400 hover:text-gray-700 text-xl">&times;</button>
              </div>
              <p id="classDetailInfo" class="text-gray-600 mb-3"></p>
              <div class="grid md:grid-cols-2 gap-4">
                <div>
                  <h4 class="font-bold mb-2">現在のメンバー</h4>
                  <div id="classMemberList" class="space-y-1 max-h-60 overflow-y-auto"></div>
                </div>
                <div>
                  <h4 class="font-bold mb-2">児童を追加</h4>
                  <div class="space-y-2">
                    <div class="flex gap-2">
                      <select id="addStudentGradeFilter" class="border p-1 rounded text-sm">
                        <option value="">全学年</option>
                        <option value="1">1年</option><option value="2">2年</option><option value="3">3年</option>
                        <option value="4">4年</option><option value="5">5年</option><option value="6">6年</option>
                      </select>
                      <button id="loadUnassignedBtn" class="bg-slate-600 text-white rounded px-2 py-1 text-xs">未所属を表示</button>
                      <button id="loadAllStudentsBtn" class="bg-slate-400 text-white rounded px-2 py-1 text-xs">全児童を表示</button>
                    </div>
                    <div id="addStudentList" class="space-y-1 max-h-60 overflow-y-auto"></div>
                    <button id="bulkAddBtn" class="bg-emerald-600 text-white rounded px-3 py-1 text-sm hidden">チェック済みを一括追加</button>
                  </div>
                </div>
              </div>
              <p id="classActionMsg" class="text-sm mt-2"></p>
            </div>
          </div>
        </div>
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

      function fmtLogin(dt){
        if(!dt) return '未ログイン';
        const d = new Date(dt + 'Z');
        return d.getFullYear() + '/' + String(d.getMonth()+1).padStart(2,'0') + '/' + String(d.getDate()).padStart(2,'0')
          + ' ' + String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');
      }

      async function renderTeachers(){
        const wrap = document.getElementById('teacherList');
        let data;
        try{ data = await api('/api/admin/teachers'); }
        catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; return; }
        wrap.innerHTML='';
        if(!data.teachers.length){ wrap.textContent='教師がいません'; return; }
        for(const t of data.teachers){
          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2';
          const left = document.createElement('div');
          left.innerHTML = '<span class="font-bold">' + t.name + '</span>'
            + ' <span class="text-gray-500 select-all">ID: ' + t.loginId + '</span>'
            + (t.school ? ' <span class="text-xs text-gray-400">' + t.school + '</span>' : '')
            + ' <span class="text-xs text-blue-600 ml-1">最終ログイン: ' + fmtLogin(t.lastLoginAt) + '</span>';
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2';
          const reset = document.createElement('button');
          reset.className='bg-slate-800 text-white rounded px-3 py-1';
          reset.textContent='PWリセット';
          reset.onclick = async ()=>{
            if(!confirm(t.name + 'のパスワードをリセットしますか？')){ return; }
            const r = await api('/api/admin/teacher-reset-password/'+t.id,{method:'POST'});
            alert('仮パスワード: '+r.tempPassword+'\\n本人に伝えてください');
          };
          right.appendChild(reset);
          div.appendChild(right);
          wrap.appendChild(div);
        }
      }

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
          left.innerHTML = x.grade + '年 / ' + x.name + '（' + x.loginId + '）' + (x.isActive? '' : ' <span class="text-red-500">[停止/未承認]</span>')
            + ' <span class="text-xs text-blue-600">最終ログイン: ' + fmtLogin(x.lastLoginAt) + '</span>';
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

// ========== クラス管理 ==========
      let currentClassId = null;

      document.getElementById('loadClassesBtn').onclick = renderClassList;

      async function renderClassList(){
        const wrap = document.getElementById('classList');
        wrap.innerHTML='<p class="text-gray-400">読み込み中...</p>';
        try{
          const d = await api('/api/admin/classes');
          wrap.innerHTML='';
          if(!d.classes.length){ wrap.textContent='クラスがまだありません'; return; }
          for(const cls of d.classes){
            const div = document.createElement('div');
            div.className='flex items-center justify-between border rounded p-2 hover:bg-indigo-50 cursor-pointer';
            const left = document.createElement('div');
            left.innerHTML = '<span class="font-bold">' + cls.name + '</span> <span class="text-gray-500">(' + cls.classCode + ')</span>' +
              ' <span class="text-xs text-gray-400">' + (cls.teacherName || '教師不明') + '</span>' +
              ' <span class="bg-indigo-100 text-indigo-700 rounded px-2 py-0.5 text-xs ml-1">' + cls.memberCount + '人</span>';
            div.appendChild(left);
            const btn = document.createElement('button');
            btn.className='bg-indigo-600 text-white rounded px-3 py-1 text-xs';
            btn.textContent='管理';
            btn.onclick = (e)=>{ e.stopPropagation(); openClassDetail(cls.id, cls.name, cls.classCode, cls.teacherName); };
            div.appendChild(btn);
            div.onclick = ()=>{ openClassDetail(cls.id, cls.name, cls.classCode, cls.teacherName); };
            wrap.appendChild(div);
          }
        }catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; }
      }

      async function openClassDetail(classId, name, code, teacher){
        currentClassId = classId;
        document.getElementById('classDetail').classList.remove('hidden');
        document.getElementById('classDetailName').textContent = name + '（' + code + '）';
        document.getElementById('classDetailInfo').textContent = '教師: ' + (teacher || '不明');
        document.getElementById('classActionMsg').textContent = '';
        document.getElementById('addStudentList').innerHTML = '';
        document.getElementById('bulkAddBtn').classList.add('hidden');
        await renderClassMembers(classId);
      }

      document.getElementById('closeClassDetail').onclick = ()=>{
        document.getElementById('classDetail').classList.add('hidden');
        currentClassId = null;
      };

      async function renderClassMembers(classId){
        const wrap = document.getElementById('classMemberList');
        wrap.innerHTML='<p class="text-gray-400">読み込み中...</p>';
        try{
          const d = await api('/api/admin/class/' + classId + '/members');
          wrap.innerHTML='';
          if(!d.members.length){ wrap.textContent='メンバーなし'; return; }
          for(const m of d.members){
            const div = document.createElement('div');
            div.className='flex items-center justify-between border rounded px-2 py-1';
            const left = document.createElement('span');
            left.textContent = m.grade + '年 ' + m.name + '（' + m.loginId + '）';
            div.appendChild(left);
            const rm = document.createElement('button');
            rm.className='bg-red-500 text-white rounded px-2 py-0.5 text-xs hover:bg-red-700';
            rm.textContent='外す';
            rm.onclick = async ()=>{
              if(!confirm(m.name + 'をこのクラスから外しますか？')) return;
              await api('/api/admin/class/' + classId + '/remove-member/' + m.userId, {method:'DELETE'});
              await renderClassMembers(classId);
              showClassMsg('text-green-700', m.name + 'をクラスから外しました');
            };
            div.appendChild(rm);
            wrap.appendChild(div);
          }
        }catch(e){ wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>'; }
      }

      document.getElementById('loadUnassignedBtn').onclick = async ()=>{
        if(!currentClassId) return;
        const wrap = document.getElementById('addStudentList');
        wrap.innerHTML='<p class="text-gray-400">読み込み中...</p>';
        try{
          const d = await api('/api/admin/unassigned-students');
          renderAddStudentList(d.students);
        }catch(e){ wrap.innerHTML='<p class="text-red-600">エラー</p>'; }
      };

      document.getElementById('loadAllStudentsBtn').onclick = async ()=>{
        if(!currentClassId) return;
        const wrap = document.getElementById('addStudentList');
        wrap.innerHTML='<p class="text-gray-400">読み込み中...</p>';
        try{
          const d = await api('/api/admin/users');
          renderAddStudentList(d.users.filter(u => u.isActive));
        }catch(e){ wrap.innerHTML='<p class="text-red-600">エラー</p>'; }
      };

      function renderAddStudentList(students){
        const gradeFilter = document.getElementById('addStudentGradeFilter').value;
        const filtered = gradeFilter ? students.filter(s => String(s.grade) === gradeFilter) : students;
        const wrap = document.getElementById('addStudentList');
        wrap.innerHTML='';
        if(!filtered.length){ wrap.textContent='該当する児童がいません'; document.getElementById('bulkAddBtn').classList.add('hidden'); return; }
        const checkboxes = [];
        for(const s of filtered){
          const div = document.createElement('div');
          div.className='flex items-center gap-2 border rounded px-2 py-1';
          const cb = document.createElement('input');
          cb.type='checkbox'; cb.value=s.id; cb.className='accent-emerald-600';
          checkboxes.push(cb);
          div.appendChild(cb);
          const label = document.createElement('span');
          label.textContent = s.grade + '年 ' + (s.className || '') + ' ' + s.name + '（' + s.loginId + '）';
          label.className='flex-1 cursor-pointer';
          label.onclick = ()=>{ cb.checked = !cb.checked; };
          div.appendChild(label);
          const addOne = document.createElement('button');
          addOne.className='bg-emerald-500 text-white rounded px-2 py-0.5 text-xs';
          addOne.textContent='追加';
          addOne.onclick = async ()=>{
            await api('/api/admin/class/' + currentClassId + '/add-member', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({userId:s.id})});
            await renderClassMembers(currentClassId);
            showClassMsg('text-green-700', s.name + 'を追加しました');
            div.remove();
          };
          div.appendChild(addOne);
          wrap.appendChild(div);
        }
        const bulkBtn = document.getElementById('bulkAddBtn');
        bulkBtn.classList.remove('hidden');
        bulkBtn.onclick = async ()=>{
          const ids = checkboxes.filter(c=>c.checked).map(c=>c.value);
          if(!ids.length){ alert('追加する児童を選んでください'); return; }
          if(!confirm(ids.length + '人をこのクラスに追加しますか？')) return;
          const r = await api('/api/admin/class/' + currentClassId + '/add-members-bulk', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({userIds:ids})});
          await renderClassMembers(currentClassId);
          showClassMsg('text-green-700', r.added + '人を追加しました（スキップ: ' + r.skipped + '人）');
          document.getElementById('loadUnassignedBtn').click();
        };
      }

      document.getElementById('addStudentGradeFilter').onchange = ()=>{
        document.getElementById('addStudentList').innerHTML='';
        document.getElementById('bulkAddBtn').classList.add('hidden');
      };

      function showClassMsg(cls, text){
        const msg = document.getElementById('classActionMsg');
        msg.textContent = text;
        msg.className = 'text-sm mt-2 ' + cls;
        setTimeout(()=>{ msg.textContent=''; }, 3000);
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
        await renderTeachers();
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

      <!-- 今日の学習状況 -->
      <div class="bg-white rounded-xl shadow p-4">
        <div class="flex items-center justify-between mb-3">
          <h2 class="font-bold">📈 今日の学習状況</h2>
          <select id="activityClassFilter" class="border p-1 rounded text-sm bg-white">
            <option value="">クラスを選択...</option>
          </select>
        </div>
        <div id="activitySummary" class="text-sm text-slate-400">クラスを選択してください</div>
      </div>

      <!-- タブナビ -->
      <div class="bg-white rounded-xl shadow p-1 flex gap-1">
        <button id="tabClasses" class="flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white" onclick="switchTab('classes')">📚 クラス管理</button>
        <button id="tabContact" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('contact')">📓 連絡帳</button>
        <button id="tabAnnouncements" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('announcements')">📢 おしらせ</button>
        <button id="tabHomework" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('homework')">📬 家庭学習</button>
        <button id="tabAnalytics" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('analytics')">📊 分析</button>
        <button id="tabMail" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('mail')">💬 質問チャット</button>
      </div>

      <!-- クラス一覧タブ -->
      <div id="tabPaneClasses" class="space-y-4">
        <div id="classList" class="space-y-4"></div>
      </div>

      <!-- 分析タブ（統合） -->
      <div id="tabPaneAnalytics" class="hidden space-y-3">
        <!-- サブタブナビ -->
        <div class="bg-white rounded-xl shadow p-2 flex items-center gap-1 overflow-x-auto">
          <button id="anSubTab_subject" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-purple-500 text-white" onclick="switchAnalyticsSubTab('subject')">
            <span class="bg-white text-purple-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">1</span> 教科の成績
          </button>
          <button id="anSubTab_homework" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchAnalyticsSubTab('homework')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">2</span> 家庭学習
          </button>
          <button id="anSubTab_ai" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchAnalyticsSubTab('ai')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">3</span> AI分析
          </button>
        </div>
        <!-- 共通クラス選択 -->
        <div class="bg-white rounded-xl shadow p-3 flex gap-2 items-center flex-wrap">
          <span class="text-sm font-bold text-slate-600">クラス:</span>
          <select id="analyticsClassFilter" class="border p-2 rounded text-sm bg-white"></select>
        </div>

        <!-- サブタブ①: 教科の成績 -->
        <div id="anPane_subject" class="space-y-3">
          <div class="bg-purple-50 border border-purple-200 rounded-xl p-4">
            <div class="flex items-center justify-between flex-wrap gap-2 mb-3">
              <div class="font-bold text-sm text-purple-800">📊 教科別・単元別の正解率</div>
              <button onclick="loadUnitAnalytics()" class="bg-purple-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">📊 分析を表示</button>
            </div>
            <div id="analyticsContent"><p class="text-xs text-slate-400">クラスを選んで「分析を表示」を押してください</p></div>
          </div>
          <!-- 非アクティブ生徒の警告 -->
          <div id="inactiveStudentsCard" class="bg-orange-50 border border-orange-200 rounded-xl p-4 hidden">
            <h3 class="font-bold text-orange-600 mb-2">⚠️ しばらく学習していない生徒</h3>
            <p class="text-xs text-slate-400 mb-2">7日以上ログインがありません</p>
            <div id="inactiveStudentsList" class="space-y-1 text-sm"></div>
          </div>
          <!-- 最近の活動ログ -->
          <div id="recentActivityCard" class="bg-white rounded-xl shadow p-4 hidden">
            <h3 class="font-bold text-slate-700 mb-2">📋 最近の活動ログ</h3>
            <div id="recentActivityLog" class="space-y-1 text-sm max-h-96 overflow-y-auto"></div>
          </div>
        </div>

        <!-- サブタブ②: 家庭学習 -->
        <div id="anPane_homework" class="hidden space-y-3">
          <div class="bg-indigo-50 border border-indigo-200 rounded-xl p-4 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="font-bold text-sm text-indigo-800">📝 今週の家庭学習ダッシュボード</div>
              <button onclick="loadClassAnalytics()" class="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">📊 分析</button>
            </div>
            <div id="classAnalyticsContent" class="space-y-3">
              <p class="text-xs text-slate-400">「分析」を押してください</p>
            </div>
          </div>
        </div>

        <!-- サブタブ③: AI分析 -->
        <div id="anPane_ai" class="hidden space-y-3">
          <!-- AIクラス分析 -->
          <div class="bg-gradient-to-br from-purple-50 to-indigo-50 border border-purple-200 rounded-xl p-4 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="font-bold text-sm text-purple-800">🤖 AIクラス分析</div>
              <button onclick="loadAIAnalysis()" class="bg-purple-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-purple-700" id="btnAIAnalysis">✨ AIで分析</button>
            </div>
            <p class="text-xs text-purple-600">教科の成績＋家庭学習＋自己調整のデータをAIが総合的に分析し、声かけアドバイスを生成します。</p>
            <div id="aiAnalysisContent" class="text-sm text-slate-600">
              <p class="text-xs text-slate-400">クラスを選んで「AIで分析」を押してください</p>
            </div>
          </div>

          <!-- 週報レポート -->
          <div class="bg-gradient-to-br from-green-50 to-emerald-50 border border-green-200 rounded-xl p-4 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="font-bold text-sm text-green-800">📋 週報レポート</div>
              <button onclick="loadWeeklyReport()" class="bg-green-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-green-700" id="btnWeeklyReport">📝 週報を生成</button>
            </div>
            <p class="text-xs text-green-600">今週の学習状況をまとめた週報をAIが自動生成します。管理職や保護者への報告にも使えます。</p>
            <div id="weeklyReportContent" class="text-sm text-slate-600">
              <p class="text-xs text-slate-400">クラスを選んで「週報を生成」を押してください</p>
            </div>
          </div>

          <!-- 個人カルテ -->
          <div class="bg-gradient-to-br from-amber-50 to-orange-50 border border-amber-200 rounded-xl p-4 space-y-3">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="font-bold text-sm text-amber-800">👤 個人カルテ</div>
            </div>
            <p class="text-xs text-amber-600">児童の名前をクリックすると、AIによる個人分析が表示されます。</p>
            <div id="karteStudentList" class="flex flex-wrap gap-2">
              <p class="text-xs text-slate-400">クラスを選んで「AIで分析」または「週報を生成」を押すと、ここに児童一覧が表示されます</p>
            </div>
          </div>

          <!-- 提出ヒートマップ -->
          <div class="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
            <div class="font-bold text-sm text-slate-700">🗓️ 提出ヒートマップ（今週）</div>
            <div id="heatmapContent" class="overflow-x-auto">
              <p class="text-xs text-slate-400">分析データが読み込まれると自動で表示されます</p>
            </div>
          </div>
        </div>

        <!-- 個人カルテ詳細パネル（オーバーレイ） -->
        <div id="studentKartePanel" class="hidden bg-white rounded-xl shadow-lg p-4 space-y-3 border-2 border-purple-300">
          <div class="flex items-center justify-between">
            <div class="font-bold text-lg text-purple-800" id="karteStudentName"></div>
            <button onclick="document.getElementById('studentKartePanel').classList.add('hidden')" class="text-slate-400 hover:text-slate-700 text-xl font-bold">✕</button>
          </div>
          <div id="karteContent"></div>
        </div>
      </div>

      <!-- 家庭学習提出一覧タブ -->
      <div id="tabPaneHomework" class="hidden space-y-3">
        <!-- ステップ風サブタブナビゲーション -->
        <div class="bg-white rounded-xl shadow p-2 flex items-center gap-1 overflow-x-auto">
          <button id="hwSubTab_menu" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-green-500 text-white" onclick="switchHomeworkSubTab('menu')">
            <span class="bg-white text-green-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">1</span> 先生メニュー
          </button>
          <button id="hwSubTab_plan" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchHomeworkSubTab('plan')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">2</span> 今週の計画
          </button>
          <button id="hwSubTab_daily" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchHomeworkSubTab('daily')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">3</span> 毎日の振り返り
          </button>
          <button id="hwSubTab_weekly" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchHomeworkSubTab('weekly')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">4</span> 今週の振り返り
          </button>
        </div>

        <!-- サブタブ①: 先生メニュー -->
        <div id="hwPane_menu" class="space-y-3">
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
          <div>
            <label class="text-xs font-bold text-green-800">📝 今週のテスト</label>
            <input id="menuTests" class="w-full border border-green-300 rounded-lg p-2 text-sm" placeholder="例：金曜 漢字50問テスト"/>
          </div>
          <div>
            <label class="text-xs font-bold text-green-800 block mb-1">📅 今週の家庭学習がある曜日</label>
            <div class="flex gap-3 flex-wrap">
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayMon" value="mon" checked class="accent-green-600"> 月</label>
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayTue" value="tue" checked class="accent-green-600"> 火</label>
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayWed" value="wed" checked class="accent-green-600"> 水</label>
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayThu" value="thu" checked class="accent-green-600"> 木</label>
              <label class="inline-flex items-center gap-1 text-sm"><input type="checkbox" id="menuDayFri" value="fri" checked class="accent-green-600"> 金</label>
            </div>
            <p class="text-xs text-green-600 mt-1">祝日や行事がある日はチェックを外してください</p>
          </div>
          <div class="flex gap-2 items-center">
            <button onclick="saveWeeklyMenu()" class="bg-green-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">📤 送信</button>
            <span id="menuSaveMsg" class="text-xs text-green-700"></span>
          </div>
        </div>

        </div>
        <!-- サブタブ②: 今週の計画 -->
        <div id="hwPane_plan" class="hidden space-y-3">
        <!-- 生徒の今週の計画 -->
        <div class="bg-blue-50 border border-blue-200 rounded-xl p-3 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="font-bold text-sm text-blue-800">📝 生徒の今週の計画</div>
            <button onclick="loadStudentPlans()" class="bg-blue-600 text-white rounded-lg px-3 py-1 text-xs font-bold shadow hover:opacity-90">🔄 読み込む</button>
            <button onclick="aiPlanCheck()" class="bg-red-500 text-white rounded-lg px-3 py-1 text-xs font-bold shadow hover:opacity-90" id="aiPlanCheckBtn">🤖 AI計画チェック</button>
          </div>
          <div id="aiPlanCheckResult" class="hidden bg-white border border-red-200 rounded-lg p-2 space-y-1"></div>
          <div id="studentPlansList" class="space-y-2 text-sm text-slate-700">
            <p class="text-xs text-slate-400">「読み込む」を押すと表示されます</p>
          </div>
          <!-- 振り返り一括AI返却 -->
          <div id="bulkRefPanel" class="hidden border-t border-blue-200 pt-3 space-y-3">
            <!-- アプリ内AI -->
            <div class="bg-emerald-50 border border-emerald-200 rounded-lg p-2 space-y-2">
              <div class="font-bold text-xs text-emerald-800">🤖 AIで一括コメント生成</div>
              <button onclick="generateWeeklyAIComments()" class="bg-emerald-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90" id="weeklyAiGenBtn">🤖 AIコメント一括生成</button>
              <div id="weeklyAiGenMsg" class="text-xs text-emerald-700"></div>
            </div>
            <!-- 手動Gemini（折りたたみ） -->
            <details class="bg-purple-50 border border-purple-200 rounded-lg">
              <summary class="cursor-pointer p-2 text-xs font-bold text-purple-800 select-none">📋 Geminiでも手動で返却できます</summary>
              <div class="px-2 pb-2 space-y-2">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="text-xs text-slate-500">①</span>
                  <button onclick="copyWeeklyReflections()" class="bg-purple-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">📋 振り返りをコピー</button>
                  <span class="text-xs text-slate-400">→ GeminiのGemに貼り付けてコメントを生成 →</span>
                </div>
                <div class="text-xs text-slate-500">② Geminiの返答をここに貼り付け</div>
                <textarea id="bulkRefComments" class="w-full border border-purple-300 rounded-lg p-2 text-xs" rows="3" placeholder='{"comments":["よく頑張りました！","毎日続けてえらいね",...]}&#10;または番号付きリスト形式でもOK'></textarea>
                <button onclick="bulkReturnReflections()" class="bg-purple-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">✅ 貼り付けて一括返却</button>
                <div id="bulkRefMsg" class="text-xs text-purple-700"></div>
              </div>
            </details>
          </div>
        </div>

        </div>
        <!-- サブタブ③: 毎日の振り返り -->
        <div id="hwPane_daily" class="hidden space-y-3">
        <!-- アプリ内AIコメント生成パネル -->
        <div class="bg-emerald-50 border border-emerald-200 rounded-xl p-3 space-y-2">
          <div class="font-bold text-sm text-emerald-800">🤖 AIで一括コメント生成</div>
          <div class="text-xs text-emerald-600">ボタンを押すと内蔵AIが未返却の家庭学習にコメントを自動生成し、各コメント欄に反映します。確認・修正してから返却できます。</div>
          <button onclick="generateHWAIComments()" class="bg-emerald-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90" id="hwAiGenBtn">🤖 AIコメント一括生成</button>
          <div id="hwAiGenMsg" class="text-xs text-emerald-700 min-h-[16px]"></div>
        </div>

        <!-- Gemini連携パネル（折りたたみ） -->
        <details class="bg-amber-50 border border-amber-200 rounded-xl">
          <summary class="cursor-pointer p-3 text-sm font-bold text-amber-800 select-none">📋 Geminiでも手動で返却できます</summary>
          <div class="px-3 pb-3 space-y-3">
            <button onclick="toggleGemPrompt()" class="text-xs text-amber-700 underline hover:no-underline">📝 Gem設定用プロンプトを表示</button>
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
        </details>
        <!-- 毎日の宿題一覧（日次返却） -->
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

        <!-- サブタブ④: 今週の振り返り -->
        <div id="hwPane_weekly" class="hidden space-y-3">
        <!-- 自動フィードバック（週間） -->
        <div class="bg-yellow-50 border border-yellow-200 rounded-xl p-4 space-y-3">
          <div class="flex items-center justify-between flex-wrap gap-2">
            <div class="font-bold text-sm text-yellow-800">💡 今週の自動フィードバック</div>
            <div class="flex gap-2 items-center">
              <select id="fbClassFilter" class="border p-1.5 rounded text-sm bg-white">
                <option value="">クラスを選択...</option>
              </select>
              <button onclick="loadAutoFeedback()" class="bg-yellow-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">🔄 生成</button>
            </div>
          </div>
          <p class="text-xs text-yellow-700">1週間の提出回数・学習時間・計画修正などから、児童ごとの声かけ候補を自動生成します。コメントは編集してから送信できます。</p>
          <div id="autoFeedbackList" class="space-y-2 text-sm">
            <p class="text-xs text-slate-400">クラスを選んで「生成」を押してください</p>
          </div>
        </div>
        </div>
      </div>


      <!-- (クラス分析は分析タブに統合済み) -->

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

    </div>

      <!-- メールタブ -->      <div id="tabPaneMail" class="hidden">        <div id="mailStudentListView">          <div class="flex gap-2 mb-3 items-center">            <select id="mailClassFilter" class="border p-2 rounded text-sm bg-white font-bold"></select>          </div>          <div id="mailStudentCards" class="space-y-1"></div>        </div>        <div id="mailChatView" class="hidden" style="height:70vh;display:none;">          <div class="flex items-center gap-3 bg-gradient-to-r from-teal-500 to-teal-600 text-white px-4 py-3 rounded-t-xl">            <button onclick="closeMailChat()" class="text-white font-bold text-lg">←</button>            <span id="mailChatName" class="font-bold"></span>          </div>          <div id="mailChatMessages" class="overflow-y-auto p-3 space-y-2 bg-[#e2efe9]" style="height:calc(70vh - 110px);"></div>          <div id="mailImagePreview" class="hidden px-2 pt-2 bg-white border-t"><div class="relative inline-block"><img id="mailImageThumb" class="h-16 rounded"/><button onclick="clearMailImage()" class="absolute -top-1 -right-1 bg-red-500 text-white rounded-full w-5 h-5 text-xs flex items-center justify-center">✕</button></div></div>          <div class="flex gap-2 items-end bg-white border-t p-2 rounded-b-xl">            <input type="file" id="mailImageInput" accept="image/*" class="hidden" onchange="handleMailImage(this)"/>            <button onclick="document.getElementById('mailImageInput').click()" class="w-10 h-10 flex items-center justify-center rounded-full bg-slate-200 text-slate-600 font-bold shadow hover:bg-slate-300 flex-shrink-0" title="画像を添付">📷</button>            <textarea id="mailBody" class="flex-1 border border-slate-300 rounded-2xl px-3 py-2 text-sm resize-none focus:border-teal-500 focus:outline-none" rows="1" placeholder="メッセージを入力..." oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,80)+'px'"></textarea>            <button onclick="sendTeacherMail()" class="w-10 h-10 flex items-center justify-center rounded-full bg-teal-500 text-white font-bold shadow hover:opacity-90 flex-shrink-0">▶</button>          </div>          <p id="mailMsg" class="text-xs text-center py-1"></p>        </div>      </div>
    <script>
      async function api(path, opt){
        const r = await fetch(path, opt);
        const j = await r.json().catch(()=>({}));
        if(!r.ok) throw new Error(j.error || 'error');
        return j;
      }

      function escH(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

      function switchTab(tab){
        ['classes','contact','announcements','homework','analytics','mail'].forEach(function(t){
          var pane = document.getElementById('tabPane' + t.charAt(0).toUpperCase() + t.slice(1));
          if(pane) pane.classList.toggle('hidden', tab !== t);
          var btn = document.getElementById('tab' + t.charAt(0).toUpperCase() + t.slice(1));
          if(btn) btn.className = tab===t
            ? 'flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white'
            : 'flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100';
        });
        if(tab === 'homework') { loadWeeklyMenu(); switchHomeworkSubTab('menu'); }
        if(tab === 'analytics') { initAnalyticsFilters(); switchAnalyticsSubTab('subject'); }
        if(tab === 'announcements') loadAnnouncements();
        if(tab === 'contact') loadContactNotes();
        if(tab === 'mail'){ loadTeacherMail(); if(_mailListPollTimer) clearInterval(_mailListPollTimer); _mailListPollTimer = setInterval(function(){ loadMailStudentList(); }, 10000); } else { if(_mailPollTimer){ clearInterval(_mailPollTimer); _mailPollTimer=null; } if(_mailListPollTimer){ clearInterval(_mailListPollTimer); _mailListPollTimer=null; } }
      }

      // --- 家庭学習サブタブ切り替え ---
      function switchHomeworkSubTab(sub){
        const tabs = ['menu','plan','daily','weekly'];
        const colors = {menu:'green',plan:'blue',daily:'emerald',weekly:'yellow'};
        tabs.forEach(function(t){
          var pane = document.getElementById('hwPane_' + t);
          if(pane) pane.classList.toggle('hidden', sub !== t);
          var btn = document.getElementById('hwSubTab_' + t);
          if(!btn) return;
          var c = colors[t] || 'slate';
          if(sub === t){
            btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-'+c+'-500 text-white';
            var num = btn.querySelector('span');
            if(num) num.className = 'bg-white text-'+c+'-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
          } else {
            btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100';
            var num = btn.querySelector('span');
            if(num) num.className = 'bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
          }
        });
        if(sub === 'daily') loadHomework();
        if(sub === 'plan') loadStudentPlans();
        if(sub === 'weekly'){ initNewTabFilters(); }
      }

      // --- アクティビティ（今日の学習状況）---
      async function loadActivitySummary(){
        const classId = document.getElementById('activityClassFilter').value;
        const wrap = document.getElementById('activitySummary');
        if(!classId){ wrap.innerHTML='<span class="text-slate-400">クラスを選択してください</span>'; return; }
        wrap.innerHTML='<span class="text-slate-400">読み込み中...</span>';
        let data;
        try{ data = await api('/api/teacher/class/'+encodeURIComponent(classId)+'/activity'); }
        catch(e){ wrap.innerHTML='<span class="text-red-600">読み込みエラー</span>'; return; }
        const s = data.summary;
        wrap.innerHTML =
          '<div class="grid grid-cols-2 sm:grid-cols-4 gap-3">'
          +'<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">取り組んだ生徒</div><div class="text-2xl font-black text-emerald-600">'+s.activeToday+'<span class="text-sm font-normal text-slate-400"> / '+s.memberCount+'人</span></div></div>'
          +'<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">解いた問題数</div><div class="text-2xl font-black text-blue-600">'+s.totalProblems+'<span class="text-sm font-normal text-slate-400">問</span></div></div>'
          +'<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">正答率</div><div class="text-2xl font-black '+(s.accuracy===null?'text-slate-400':s.accuracy>=80?'text-green-600':s.accuracy>=60?'text-yellow-600':'text-red-600')+'">'+(s.accuracy!==null?s.accuracy+'%':'−')+'</div></div>'
          +'<div class="rounded-lg border p-3 text-center"><div class="text-xs text-slate-400">未学習（7日+）</div><div class="text-2xl font-black '+(data.inactive.length>0?'text-orange-600':'text-slate-400')+'">'+data.inactive.length+'<span class="text-sm font-normal text-slate-400">人</span></div></div>'
          +'</div>';

        // 非アクティブ生徒を学習分析タブにも反映
        const inactiveCard = document.getElementById('inactiveStudentsCard');
        const inactiveList = document.getElementById('inactiveStudentsList');
        if(data.inactive.length > 0){
          inactiveCard.classList.remove('hidden');
          inactiveList.innerHTML = data.inactive.map(function(st){
            var lastTxt = st.lastLoginAt ? fmtLoginT(st.lastLoginAt) : '一度もログインなし';
            return '<div class="flex items-center justify-between border rounded px-3 py-1.5">'
              +'<span class="font-bold">'+escH(st.name)+'</span>'
              +'<span class="text-xs text-slate-400">最終: '+lastTxt+'</span></div>';
          }).join('');
        } else {
          inactiveCard.classList.add('hidden');
        }

        // 最近の活動ログを学習分析タブに反映
        var logCard = document.getElementById('recentActivityCard');
        var logWrap = document.getElementById('recentActivityLog');
        if(data.recentLog.length > 0){
          logCard.classList.remove('hidden');
          var unitNames = {decimal:'小数', fraction:'分数', integer:'整数', kanji_read:'漢字読み', kanji_write:'漢字書き', social:'社会', science:'理科'};
          logWrap.innerHTML = data.recentLog.map(function(r){
            var dt = r.answeredAt ? fmtLoginT(r.answeredAt) : '';
            var unitLabel = r.unit ? (r.unit.split(':')[0]) : '';
            unitLabel = unitNames[unitLabel] || unitLabel;
            var mark = r.isCorrect ? '<span class="text-green-600 font-bold">○</span>' : '<span class="text-red-500 font-bold">×</span>';
            return '<div class="flex items-center gap-2 border-b py-1 text-xs">'
              +'<span class="text-slate-400 w-32 shrink-0">'+dt+'</span>'
              +'<span class="font-bold w-20 shrink-0">'+escH(r.name)+'</span>'
              +'<span class="text-slate-500 w-16 shrink-0">'+escH(unitLabel)+'</span>'
              +mark
              +(r.timeMs ? '<span class="text-slate-400 ml-1">'+Math.round(r.timeMs/1000)+'秒</span>' : '')
              +'</div>';
          }).join('');
        } else {
          logCard.classList.add('hidden');
        }
      }

      function fmtLoginT(dt){
        if(!dt) return '';
        var d = new Date(dt.indexOf('Z') >= 0 ? dt : dt + 'Z');
        return d.getFullYear() + '/' + String(d.getMonth()+1).padStart(2,'0') + '/' + String(d.getDate()).padStart(2,'0')
          + ' ' + String(d.getHours()).padStart(2,'0') + ':' + String(d.getMinutes()).padStart(2,'0');
      }

      document.getElementById('activityClassFilter').onchange = function(){ loadActivitySummary(); };

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
            +'<td class="border px-2 py-1 font-bold sticky left-0 '+(i%2===0?'bg-white':'bg-slate-50')+'"><a href="javascript:void(0)" onclick="showStudentKarte(&#39;'+escH(s.id)+'&#39;,&#39;'+escH(s.name)+'&#39;)" class="text-purple-600 hover:underline cursor-pointer">'+escH(s.name)+'</a></td>'
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

      // --- 分析サブタブ切り替え ---
      function switchAnalyticsSubTab(sub){
        var tabs = ['subject','homework','ai'];
        var colors = {subject:'purple',homework:'indigo',ai:'purple'};
        tabs.forEach(function(t){
          var pane = document.getElementById('anPane_' + t);
          if(pane) pane.classList.toggle('hidden', sub !== t);
          var btn = document.getElementById('anSubTab_' + t);
          if(!btn) return;
          var c = colors[t] || 'slate';
          if(sub === t){
            btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-'+c+'-500 text-white';
            var num = btn.querySelector('span');
            if(num) num.className = 'bg-white text-'+c+'-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
          } else {
            btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100';
            var num = btn.querySelector('span');
            if(num) num.className = 'bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
          }
        });
      }

      async function initAnalyticsFilters(){
        try{
          var cdata = await api('/api/teacher/classes');
          var classes = (cdata && cdata.classes) || [];
          var el = document.getElementById('analyticsClassFilter');
          if(el && el.options.length <= 1){
            el.innerHTML = '';
            classes.forEach(function(cls){
              var opt = document.createElement('option');
              opt.value = cls.id;
              opt.textContent = cls.name;
              el.appendChild(opt);
            });
          }
        }catch(_){}
      }

      // --- 個人カルテ ---
      async function showStudentKarte(studentId, studentName){
        var panel = document.getElementById('studentKartePanel');
        var content = document.getElementById('karteContent');
        document.getElementById('karteStudentName').textContent = studentName + ' さんのカルテ';
        panel.classList.remove('hidden');
        content.innerHTML = '<p class="text-slate-400 text-sm animate-pulse">読み込み中...</p>';
        var classId = document.getElementById('analyticsClassFilter').value;
        try{
          var weekKey = typeof getWeekKeyLocal === 'function' ? getWeekKeyLocal() : '';
          var unitData = await api('/api/teacher/class/' + encodeURIComponent(classId) + '/unit-analytics');
          var caData = await api('/api/teacher/class-analytics?classId=' + encodeURIComponent(classId) + '&weekKey=' + encodeURIComponent(weekKey));
          var student = (unitData.students||[]).find(function(s){ return s.id === studentId; });
          var hwAll = (caData.homework||[]).filter(function(h){ return h.user_id === studentId; });
          var plan = (caData.plans||[]).find(function(p){ return p.user_id === studentId; });
          var ref = (caData.reflections||[]).find(function(r){ return r.user_id === studentId; });
          var subjName = {math:'算数', jp:'国語', soc:'社会', science:'理科'};
          var html = '';

          // 教科別成績
          html += '<div class="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">';
          ['math','jp','soc','science'].forEach(function(subj){
            var d = student && student.bySubject[subj];
            if(!d || d.total < 5){
              html += '<div class="rounded-lg border p-2 text-center"><div class="text-xs text-slate-400">'+(subjName[subj]||subj)+'</div><div class="text-lg font-bold text-slate-300">−</div></div>';
            } else {
              var c = d.acc>=80?'text-green-600':d.acc>=60?'text-yellow-600':'text-red-600';
              html += '<div class="rounded-lg border p-2 text-center"><div class="text-xs font-bold text-slate-500">'+(subjName[subj]||subj)+'</div><div class="text-xl font-black '+c+'">'+d.acc+'%</div><div class="text-[10px] text-slate-400">'+d.total+'問</div></div>';
            }
          });
          html += '</div>';

          // 連続学習
          if(student && student.learnStreak > 0){
            html += '<div class="bg-orange-50 border border-orange-200 rounded-lg p-2 mb-3 text-sm">🔥 連続学習 <b>'+student.learnStreak+'日</b></div>';
          }

          // 家庭学習状況
          html += '<div class="bg-blue-50 border border-blue-200 rounded-lg p-3 mb-3 space-y-1">';
          html += '<div class="font-bold text-xs text-blue-800">📝 今週の家庭学習</div>';
          if(hwAll.length > 0){
            var totalMin = hwAll.reduce(function(s,h){ return s + (h.minutes||0); }, 0);
            html += '<div class="text-sm">提出 <b>'+hwAll.length+'回</b> / 合計 <b>'+totalMin+'分</b></div>';
            html += '<div class="flex gap-1 flex-wrap">';
            hwAll.forEach(function(h){
              html += '<span class="bg-blue-100 text-blue-700 px-1.5 py-0.5 rounded text-[10px]">'+escH(h.subject||'')+(h.minutes?(' '+h.minutes+'分'):'')+'</span>';
            });
            html += '</div>';
          } else {
            html += '<div class="text-xs text-slate-400">今週の提出はまだありません</div>';
          }
          html += '</div>';

          // 計画・ふりかえり
          html += '<div class="bg-purple-50 border border-purple-200 rounded-lg p-3 space-y-1">';
          html += '<div class="font-bold text-xs text-purple-800">🔄 自己調整</div>';
          if(plan){
            html += '<div class="text-xs"><b>計画:</b> '+escH(plan.plan_text||plan.goal_text||'(内容なし)')+'</div>';
            if(plan.revision_count > 0) html += '<div class="text-xs text-orange-600">🔄 計画修正 '+plan.revision_count+'回</div>';
          } else {
            html += '<div class="text-xs text-slate-400">計画の提出なし</div>';
          }
          if(ref){
            html += '<div class="text-xs"><b>ふりかえり:</b> '+escH(ref.reflection_text||'(内容なし)')+'</div>';
            if(ref.concentration) html += '<div class="text-xs">集中度: '+('★'.repeat(ref.concentration))+'</div>';
          } else {
            html += '<div class="text-xs text-slate-400">ふりかえりなし</div>';
          }
          html += '</div>';

          content.innerHTML = html;
          panel.scrollIntoView({behavior:'smooth', block:'nearest'});
        }catch(e){
          content.innerHTML = '<p class="text-red-500 text-sm">読み込みエラー: '+escH(String(e.message||e))+'</p>';
        }
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

        // クラスフィルター選択肢を更新（全セレクトで最初のクラスを自動選択）
        const defaultClassId = data.classes.length > 0 ? data.classes[0].id : '';
        const sel = document.getElementById('hwClassFilter');
        sel.innerHTML = '<option value="">全クラス</option>';
        data.classes.forEach(c => { sel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
        if(defaultClassId) sel.value = defaultClassId;
        // 学習分析タブのクラスフィルターも更新
        const analyticsSel = document.getElementById('analyticsClassFilter');
        if(analyticsSel){
          analyticsSel.innerHTML = '';
          data.classes.forEach(c => { analyticsSel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
          if(defaultClassId) analyticsSel.value = defaultClassId;
        }
        // アクティビティ（今日の学習状況）のクラスフィルターも更新
        const actSel = document.getElementById('activityClassFilter');
        if(actSel){
          const prevVal = actSel.value;
          actSel.innerHTML = '';
          data.classes.forEach(c => { actSel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
          if(prevVal){ actSel.value = prevVal; }
          else if(defaultClassId){ actSel.value = defaultClassId; }
          loadActivitySummary();
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

          // ====== 全メニュー表示トグル ======
          const menusDivider = document.createElement('div');
          menusDivider.className = 'mt-3 pt-3 border-t border-slate-200';
          menusDivider.innerHTML = '<div class="text-xs font-bold text-slate-600 mb-2"> メニュー表示設定</div>';
          const menusGrid = document.createElement('div');
          menusGrid.className = 'flex flex-wrap gap-1';

          const currentMenus = cls.menusEnabled ? (typeof cls.menusEnabled === 'string' ? JSON.parse(cls.menusEnabled) : cls.menusEnabled) : {};

          const allMenuItems = [
            {key:'status', label:'ステータス', color:'emerald'},
            {key:'training', label:'️修行', color:'blue'},
            {key:'mail', label:'質問', color:'purple'},
            {key:'battle', label:'⚔️バトル', color:'red'},
            {key:'friend', label:'欄友達通信', color:'violet'},
            {key:'shop', label:'ショップ', color:'orange'},
            {key:'lab', label:'ラボ', color:'teal'},
            {key:'pokedex', label:'図鑑', color:'slate'},
            {key:'box', label:'ボックス', color:'cyan'},
          ];

          allMenuItems.forEach(function(item){
            const isOn = currentMenus[item.key] !== false && currentMenus[item.key] !== 0;
            const mbtn = document.createElement('button');
            mbtn.className = isOn
              ? 'text-xs px-2 py-1 rounded font-bold bg-'+item.color+'-100 text-'+item.color+'-700 border border-'+item.color+'-300'
              : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-400 border border-slate-200 line-through';
            mbtn.textContent = item.label;
            mbtn.dataset.menuKey = item.key;
            mbtn.dataset.on = isOn ? '1' : '';
            mbtn.onclick = async function(){
              const wasOn = !!mbtn.dataset.on;
              mbtn.dataset.on = wasOn ? '' : '1';
              currentMenus[item.key] = !wasOn;
              mbtn.className = !wasOn
                ? 'text-xs px-2 py-1 rounded font-bold bg-'+item.color+'-100 text-'+item.color+'-700 border border-'+item.color+'-300'
                : 'text-xs px-2 py-1 rounded font-bold bg-slate-100 text-slate-400 border border-slate-200 line-through';
              try{
                await api('/api/teacher/class/'+cls.id+'/menus-toggle',{
                  method:'PUT', headers:{'content-type':'application/json'},
                  body: JSON.stringify({menusEnabled: currentMenus})
                });
              }catch(e){ alert(String(e.message||e)); }
            };
            menusGrid.appendChild(mbtn);
          });

          menusDivider.appendChild(menusGrid);
          header.appendChild(menusDivider);


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
                +'<td class="border px-2 py-1">'+escH(m.name||m.id)+'</td>'
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
          document.getElementById('menuTests').value = menu.tests || '';
          // 曜日チェックボックスの復元
          var activeDays = [];
          try{ activeDays = JSON.parse(menu.active_days || menu.activeDays || '["mon","tue","wed","thu","fri"]'); }catch(e){ activeDays = ['mon','tue','wed','thu','fri']; }
          ['mon','tue','wed','thu','fri'].forEach(function(d){
            var cb = document.getElementById('menuDay' + d.charAt(0).toUpperCase() + d.slice(1));
            if(cb) cb.checked = activeDays.indexOf(d) >= 0;
          });
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
            tests: document.getElementById('menuTests').value || '',
            activeDays: ['mon','tue','wed','thu','fri'].filter(function(d){
              var cb = document.getElementById('menuDay' + d.charAt(0).toUpperCase() + d.slice(1));
              return cb && cb.checked;
            }),
          };
          await api('/api/teacher/class/' + encodeURIComponent(classId) + '/weekly-menu', {
            method: 'POST',
            headers: {'content-type':'application/json'},
            body: JSON.stringify(body),
          });
          if(msg) msg.textContent = '✅ 送信しました（' + wk + '）';
          setTimeout(function(){ if(msg) msg.textContent = ''; }, 3000);
        }catch(e){
          if(msg) msg.textContent = '⚠️ 送信に失敗しました';
        }
      }

      async function loadStudentPlans(){
        const wrap = document.getElementById('studentPlansList');
        if(!wrap) return;
        wrap.innerHTML='<p class="text-slate-400">読み込み中...</p>';
        const classId = document.getElementById('hwClassFilter')?.value || '';
        const wk = getWeekKeyLocal();
        let qs = '?weekKey='+encodeURIComponent(wk);
        if(classId) qs += '&classId='+encodeURIComponent(classId);
        try{
          const data = await api('/api/teacher/weekly-plans'+qs);
          const plans = data.plans || [];
          if(!plans.length){ wrap.innerHTML='<p class="text-slate-400">まだ計画が提出されていません</p>'; return; }
          const dayLabels = ['月','火','水','木','金'];
          wrap.innerHTML = '';
          window._weeklyRefData = []; // 一括用データ
          for(const p of plans){
            let parsed = {};
            try{ parsed = JSON.parse(p.plansJson || '{}'); }catch(_){}
            const modified = parsed._modified || {};
            const card = document.createElement('div');
            card.className = 'border rounded-lg p-2 bg-white space-y-1';

            // ヘッダー + 承認バッジ + 修正回数バッジ
            const approvedBadge = p.planApproved
              ? '<span class="bg-green-100 text-green-700 text-xs px-1.5 rounded font-bold">✅ 承認済(+300coin+5かけら)</span>'
              : '';
            const revBadge = (p.revisionCount && p.revisionCount > 0)
              ? '<span class="bg-orange-100 text-orange-700 text-xs px-1.5 rounded font-bold cursor-pointer" onclick="showRevisions('+p.id+',\\''+escH(p.studentName)+'\\')">🔄 '+p.revisionCount+'回修正（自己調整）</span>'
              : '';
            let html = '<div class="flex items-center justify-between flex-wrap gap-1">'
              + '<div class="font-bold text-sm">'+escH(p.studentName)+' <span class="text-xs text-slate-400 font-normal">'+escH(p.grade+'年'+p.className)+'</span> '+approvedBadge+' '+revBadge+'</div>'
              + '<div class="text-[10px] text-slate-400">'+new Date(p.updatedAt).toLocaleString('ja-JP',{month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit'})+'</div>'
              + '</div>';

            // 5曜日グリッド
            html += '<div class="grid grid-cols-5 gap-1 text-xs">';
            const keys = Object.keys(parsed).filter(k => k !== '_modified');
            for(let i = 0; i < 5; i++){
              const k = keys[i] || '';
              const val = k ? parsed[k] : '';
              const planText = typeof val === 'object' ? (val.free || '') : (val || '');
              const isMod = k && modified[k];
              html += '<div class="border rounded p-1 '+(isMod ? 'bg-orange-50 border-orange-200' : 'bg-slate-50 border-slate-200')+'">'
                + '<div class="font-bold text-center '+(i===0?'text-green-700':i===4?'text-orange-700':'text-slate-600')+'">'+dayLabels[i]+'</div>'
                + '<div class="text-[11px] text-slate-700 break-words">'+(planText ? escH(planText) : '<span class="text-slate-300">—</span>')+'</div>'
                + (isMod ? '<div class="text-[9px] text-orange-500 text-center">✎変更</div>' : '')
                + '</div>';
            }
            html += '</div>';

            // 計画承認ボタン（未承認の場合のみ）
            if(!p.planApproved){
              html += '<div class="flex justify-end"><button class="bg-green-600 text-white rounded px-3 py-1 text-xs font-bold hover:opacity-90" onclick="approvePlan('+p.id+',this)">✅ 計画OK (+300coin+5かけら)</button></div>';
            }

            // 金曜の振り返り
            const friKey = keys[4] || '';
            const friVal = friKey ? parsed[friKey] : '';
            const reflection = typeof friVal === 'object' ? (friVal.reflection || '') : '';
            if(reflection){
              html += '<div class="text-xs mt-1 p-1.5 bg-orange-50 rounded border border-orange-200 space-y-1">'
                + '<div><span class="font-bold text-orange-700">🔄 振り返り：</span>'+escH(reflection)+'</div>';
              if(p.reflectionReturnedAt){
                html += '<div class="text-emerald-700 bg-emerald-50 rounded p-1 border border-emerald-200">💬 '+escH(p.reflectionComment)+' <span class="text-[10px] text-slate-400">(返却済+300coin+5かけら)</span></div>';
              } else {
                window._weeklyRefData.push({ id: p.id, name: p.studentName, reflection: reflection });
                html += '<div class="flex items-center gap-1">'
                  + '<textarea id="refComment_'+p.id+'" class="flex-1 border rounded p-1.5 text-xs" rows="1" placeholder="コメント（一括AIも可）"></textarea>'
                  + '<button class="bg-orange-500 text-white rounded px-2 py-1 text-[11px] font-bold hover:opacity-90 shrink-0" onclick="returnReflection('+p.id+',this)">返却</button>'
                  + '</div>';
              }
              html += '</div>';
            }

            card.innerHTML = html;
            wrap.appendChild(card);
          }
          // 一括パネル表示
          const bulkPanel = document.getElementById('bulkRefPanel');
          if(bulkPanel) bulkPanel.classList.toggle('hidden', window._weeklyRefData.length === 0);
        }catch(e){
          wrap.innerHTML='<p class="text-red-600">読み込みエラー</p>';
        }
      }

      function copyWeeklyReflections(){
        const data = window._weeklyRefData || [];
        if(!data.length){ alert('未返却の振り返りがありません'); return; }
        let text = '以下は小学生の今週の家庭学習の振り返りです。それぞれに温かく励ましつつ具体的に褒める短いコメント（1〜2文）を書いてください。\\nJSON形式 {"comments":["コメント1","コメント2",...]} で返してください。\\n\\n';
        data.forEach(function(d, i){
          text += (i+1) + '. ' + d.name + '「' + d.reflection + '」\\n';
        });
        navigator.clipboard.writeText(text).then(function(){
          alert('📋 '+data.length+'人分の振り返りをコピーしました！\\nGemini等に貼り付けてコメントを生成してください。');
        }).catch(function(){
          prompt('コピーに失敗しました。手動でコピーしてください:', text);
        });
      }

      async function bulkReturnReflections(){
        const data = window._weeklyRefData || [];
        if(!data.length){ alert('未返却の振り返りがありません'); return; }
        const raw = (document.getElementById('bulkRefComments') || {}).value || '';
        const msg = document.getElementById('bulkRefMsg');

        // パース：JSON or 番号付きリスト
        let comments = [];
        try{
          const parsed = JSON.parse(raw);
          comments = parsed.comments || parsed;
        }catch(_){
          // 番号付きリスト形式をパース
          comments = raw.split(/\\n/).map(function(line){
            return line.replace(/^\d+[\.\)：:]\s*/, '').trim();
          }).filter(function(l){ return l.length > 0; });
        }

        if(comments.length < data.length){
          if(msg) msg.textContent = '⚠️ コメント数('+comments.length+')が振り返り数('+data.length+')より少ないです';
          return;
        }

        if(msg) msg.textContent = '返却中...';
        let ok = 0, fail = 0;
        for(let i = 0; i < data.length; i++){
          try{
            await api('/api/teacher/weekly-plan/'+data[i].id+'/return-reflection', {
              method:'POST', headers:{'content-type':'application/json'},
              body: JSON.stringify({ comment: comments[i] || '' })
            });
            ok++;
          }catch(e){ fail++; }
        }
        if(msg) msg.textContent = '✅ '+ok+'人に返却完了' + (fail ? ' ('+fail+'人失敗)' : '');
        await loadStudentPlans();
      }

      async function aiPlanCheck(){
        var btn = document.getElementById('aiPlanCheckBtn');
        var wrap = document.getElementById('aiPlanCheckResult');
        if(!wrap) return;
        var classId = document.getElementById('hwClassFilter') ? document.getElementById('hwClassFilter').value : '';
        if(!classId){ alert('クラスを選択してください'); return; }
        btn.disabled = true; btn.textContent = '🤖 チェック中...';
        wrap.classList.remove('hidden');
        wrap.innerHTML = '<p class="text-xs text-slate-400">AIが計画を分析しています...</p>';
        try{
          var wk = getWeekKeyLocal();
          var res = await api('/api/teacher/ai-plan-check', {
            method:'POST', headers:{'content-type':'application/json'},
            body: JSON.stringify({classId: classId, weekKey: wk})
          });
          var results = res.results || [];
          if(!results.length){
            wrap.innerHTML = '<p class="text-xs text-slate-400">計画がまだ提出されていません</p>';
            return;
          }
          var warnCount = results.filter(function(r){ return r.level === 'warning'; }).length;
          var cautionCount = results.filter(function(r){ return r.level === 'caution'; }).length;
          var okCount = results.filter(function(r){ return r.level === 'ok'; }).length;

          var html = '<div class="flex items-center gap-2 flex-wrap mb-1">'
            + '<span class="font-bold text-sm text-red-700">🤖 AI計画チェック結果</span>'
            + '<span class="text-xs bg-green-100 text-green-700 px-1.5 rounded font-bold">' + okCount + '人OK</span>'
            + (cautionCount ? '<span class="text-xs bg-yellow-100 text-yellow-700 px-1.5 rounded font-bold">' + cautionCount + '人注意</span>' : '')
            + (warnCount ? '<span class="text-xs bg-red-100 text-red-700 px-1.5 rounded font-bold">' + warnCount + '人要注意</span>' : '')
            + '<span class="text-[10px] text-slate-400">(' + (res.source || 'AI') + ')</span>'
            + '</div>';

          // 要注意と注意を先に表示
          var sorted = results.slice().sort(function(a,b){
            var order = {warning:0, caution:1, ok:2};
            return (order[a.level]||2) - (order[b.level]||2);
          });
          for(var i = 0; i < sorted.length; i++){
            var r = sorted[i];
            var bgClass = r.level === 'warning' ? 'bg-red-50 border-red-300' : r.level === 'caution' ? 'bg-yellow-50 border-yellow-300' : 'bg-green-50 border-green-200';
            var icon = r.level === 'warning' ? '🚨' : r.level === 'caution' ? '⚠️' : '✅';
            var textClass = r.level === 'warning' ? 'text-red-700' : r.level === 'caution' ? 'text-yellow-700' : 'text-green-700';
            html += '<div class="flex items-center gap-2 px-2 py-1 rounded border ' + bgClass + ' text-xs">'
              + '<span>' + icon + '</span>'
              + '<span class="font-bold">' + escH(r.name) + '</span>'
              + '<span class="' + textClass + '">' + escH(r.comment) + '</span>'
              + '</div>';
          }
          wrap.innerHTML = html;
        }catch(e){
          wrap.innerHTML = '<p class="text-xs text-red-600">エラー: ' + escH(String(e.message||e)) + '</p>';
        }finally{
          btn.disabled = false; btn.textContent = '🤖 AI計画チェック';
        }
      }

      async function approvePlan(planId, btn){
        btn.disabled = true;
        try{
          await api('/api/teacher/weekly-plan/'+planId+'/approve', {method:'POST',headers:{'content-type':'application/json'},body:'{}'});
          await loadStudentPlans();
        }catch(e){ btn.disabled=false; alert('エラー: '+String(e.message||e)); }
      }

      async function returnReflection(planId, btn){
        btn.disabled = true;
        const comment = (document.getElementById('refComment_'+planId)||{}).value || '';
        if(!comment.trim()){ alert('コメントを入力してください'); btn.disabled=false; return; }
        try{
          await api('/api/teacher/weekly-plan/'+planId+'/return-reflection', {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({comment})});
          await loadStudentPlans();
wrap.innerHTML = '';
          for(const item of list){
            const card = document.createElement('div');
            card.className = 'border rounded-lg p-2 bg-white space-y-1';
            let html = '<div class="font-bold text-sm text-slate-700">'+escH(item.name)+'</div>';
            html += '<div class="space-y-0.5">';
            for(const msg of item.messages){
              html += '<div class="text-xs text-slate-600 bg-yellow-50 rounded p-1.5 border border-yellow-100">'+escH(msg)+'</div>';
            }
            html += '</div>';
            // 編集可能なテキストエリア + 送信ボタン
            html += '<div class="flex gap-1 items-end mt-1">';
            html += '<textarea class="flex-1 border rounded p-1.5 text-xs" rows="2" id="fbMsg_'+item.userId+'" placeholder="コメントを編集...">'+escH(item.messages.join(' '))+'</textarea>';
            html += '<button class="bg-emerald-600 text-white rounded px-2 py-1.5 text-[11px] font-bold hover:opacity-90 shrink-0" onclick="sendFeedback(\\''+item.userId+'\\',this)">💬 送信</button>';
            html += '</div>';
            card.innerHTML = html;
            wrap.appendChild(card);
          }
        }catch(e){
          wrap.innerHTML='<p class="text-red-600">エラー: '+escH(String(e.message||e))+'</p>';
        }
      }

          async function loadAutoFeedback(){
            const wrap = document.getElementById('autoFeedbackList');
            if(!wrap) return;
            const classId = document.getElementById('fbClassFilter')?.value;
            if(!classId){ alert('クラスを選択してください'); return; }
            wrap.innerHTML = '<p class="text-xs text-slate-400">生成中...</p>';
            try{
              const data = await api('/api/teacher/auto-feedback?classId='+encodeURIComponent(classId)+'&weekKey='+encodeURIComponent(getWeekKeyLocal()));
              const list = data.feedbackList || [];
              if(!list.length){ wrap.innerHTML = '<p class="text-xs text-slate-400">データがありません</p>'; return; }
              wrap.innerHTML = '';
              for(const item of list){
                const card = document.createElement('div');
                card.className = 'border rounded-lg p-2 bg-white space-y-1 mb-2';
                const hdr = document.createElement('div');
                hdr.className = 'font-bold text-sm text-slate-700';
                hdr.textContent = item.name;
                card.appendChild(hdr);
                const ta = document.createElement('textarea');
                ta.id = 'fbMsg_' + item.userId;
                ta.className = 'w-full border rounded p-1.5 text-xs mt-1';
                ta.rows = 2;
                ta.value = item.messages.join(' ');
                const btn = document.createElement('button');
                btn.className = 'mt-1 bg-emerald-600 text-white rounded px-3 py-1.5 text-xs font-bold w-full';
                btn.textContent = '送信';
                const uid = item.userId;
                btn.onclick = function(){ sendFeedback(uid, btn); };
                card.appendChild(ta);
                card.appendChild(btn);
                wrap.appendChild(card);
              }
            }catch(e){
              wrap.innerHTML = '<p class="text-red-600">エラー: ' + escH(String(e.message||e)) + '</p>';
            }
          }

      async function sendFeedback(userId, btn){
        btn.disabled = true;
        const msg = (document.getElementById('fbMsg_'+userId)||{}).value || '';
        if(!msg.trim()){ alert('メッセージを入力してください'); btn.disabled=false; return; }
        try{
          await api('/api/teacher/message', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({studentId:userId, content:msg})});
          btn.textContent='✅ 送信済';
          btn.className='bg-slate-300 text-slate-500 rounded px-2 py-1.5 text-[11px] font-bold shrink-0';
        }catch(e){ btn.disabled=false; alert('送信エラー: '+String(e.message||e)); }
      }

      // ===== クラス分析ダッシュボード =====
      async function loadClassAnalytics(){
        const wrap = document.getElementById('classAnalyticsContent');
        if(!wrap) return;
        const classId = document.getElementById('analyticsClassFilter')?.value;
        if(!classId){ alert('クラスを選択してください'); return; }
        wrap.innerHTML='<p class="text-slate-400">分析中...</p>';
        try{
          const data = await api('/api/teacher/class-analytics?classId='+encodeURIComponent(classId)+'&weekKey='+encodeURIComponent(getWeekKeyLocal()));
          let html = '';

          // 1) 気になる児童アラート
          const alerts = data.alerts || [];
          if(alerts.length > 0){
            html += '<div class="bg-red-50 border border-red-200 rounded-lg p-3 space-y-1">';
            html += '<div class="font-bold text-sm text-red-800">⚠️ 気になる児童 ('+alerts.length+'人)</div>';
            for(const a of alerts){
              const icon = a.type==='no_submission' ? '🔴' : a.type==='submission_drop' ? '🟡' : '🟠';
              html += '<div class="text-xs text-red-700">'+icon+' <b>'+escH(a.name)+'</b>: '+escH(a.detail)+'</div>';
            }
            html += '</div>';
          } else {
            html += '<div class="bg-green-50 border border-green-200 rounded-lg p-3"><div class="text-sm text-green-700">✅ 特に気になる児童はいません</div></div>';
          }

          // 2) 提出状況サマリー
          const members = data.members || [];
          const hwData = data.homework || [];
          const hwByUser = {};
          for(const h of hwData){ if(!hwByUser[h.user_id]) hwByUser[h.user_id]={cnt:0,totalMin:0}; hwByUser[h.user_id].cnt++; hwByUser[h.user_id].totalMin+=(h.minutes||0); }
          const submitted = Object.keys(hwByUser).length;
          const total = members.length;
          const rate = total > 0 ? Math.round(submitted/total*100) : 0;

          html += '<div class="bg-white border rounded-lg p-3 space-y-2">';
          html += '<div class="font-bold text-sm text-slate-700">📊 今週の提出状況</div>';
          html += '<div class="flex gap-4 text-center">';
          html += '<div><div class="text-2xl font-bold text-emerald-600">'+rate+'%</div><div class="text-[10px] text-slate-500">提出率</div></div>';
          html += '<div><div class="text-2xl font-bold text-blue-600">'+submitted+'/'+total+'</div><div class="text-[10px] text-slate-500">提出人数</div></div>';
          html += '</div>';

          // ミニヒートマップ（提出回数をバーで表示）
          html += '<div class="space-y-0.5 mt-2">';
          for(const m of members){
            const hw = hwByUser[m.id] || {cnt:0, totalMin:0};
            const barW = Math.min(100, hw.cnt * 20); // 5回=100%
            const color = hw.cnt >= 4 ? 'bg-emerald-500' : hw.cnt >= 2 ? 'bg-yellow-500' : hw.cnt > 0 ? 'bg-orange-400' : 'bg-red-300';
            html += '<div class="flex items-center gap-1 text-[11px]">';
            html += '<div class="w-16 truncate text-slate-600">'+escH(m.name)+'</div>';
            html += '<div class="flex-1 bg-slate-100 rounded-full h-3 overflow-hidden"><div class="h-full rounded-full '+color+'" style="width:'+barW+'%"></div></div>';
            html += '<div class="w-10 text-right text-slate-500">'+hw.cnt+'回</div>';
            html += '<div class="w-14 text-right text-slate-400">'+(hw.totalMin||0)+'分</div>';
            html += '</div>';
          }
          html += '</div></div>';

          // 3) 自己調整スコア分布
          const plans = data.plans || [];
          const reflections = data.reflections || [];
          const planMap = {}; for(const p of plans) planMap[p.user_id] = p;
          const refMap = {}; for(const r of reflections) refMap[r.user_id] = r;

          html += '<div class="bg-white border rounded-lg p-3 space-y-2">';
          html += '<div class="font-bold text-sm text-slate-700">🔄 自己調整の状況</div>';
          const planCount = plans.length;
          const refCount = reflections.length;
          const revisionStudents = plans.filter(function(p){ return p.revision_count > 0; }).length;
          html += '<div class="flex gap-4 text-center text-xs">';
          html += '<div><div class="text-lg font-bold text-blue-600">'+planCount+'/'+total+'</div><div class="text-slate-500">計画提出</div></div>';
          html += '<div><div class="text-lg font-bold text-orange-600">'+revisionStudents+'</div><div class="text-slate-500">計画修正した人</div></div>';
          html += '<div><div class="text-lg font-bold text-purple-600">'+refCount+'/'+total+'</div><div class="text-slate-500">ふりかえり</div></div>';
          html += '</div>';

          // 児童別の自己調整状況
          html += '<div class="space-y-0.5 mt-2">';
          for(const m of members){
            const p = planMap[m.id];
            const r = refMap[m.id];
            const badges = [];
            if(p) badges.push('<span class="bg-blue-100 text-blue-700 px-1 rounded text-[9px]">📝計画</span>');
            if(p && p.revision_count > 0) badges.push('<span class="bg-orange-100 text-orange-700 px-1 rounded text-[9px]">🔄修正'+p.revision_count+'回</span>');
            if(r) badges.push('<span class="bg-purple-100 text-purple-700 px-1 rounded text-[9px]">💭ふりかえり</span>');
            if(r && r.concentration) badges.push('<span class="bg-yellow-100 text-yellow-700 px-1 rounded text-[9px]">集中'+('★'.repeat(r.concentration))+'</span>');
            html += '<div class="flex items-center gap-1 text-[11px]">';
            html += '<div class="w-16 truncate text-slate-600">'+escH(m.name)+'</div>';
            html += '<div class="flex gap-0.5 flex-wrap">'+(badges.length > 0 ? badges.join(' ') : '<span class="text-slate-300 text-[9px]">—</span>')+'</div>';
            html += '</div>';
          }
          html += '</div></div>';

          wrap.innerHTML = html;
        }catch(e){
          wrap.innerHTML='<p class="text-red-600">エラー: '+escH(String(e.message||e))+'</p>';
        }
      }

      // 週報レポート生成（loadAIAnalysisは上で再定義済み）
      async function loadWeeklyReport(){
        const classId = document.getElementById('analyticsClassFilter').value;
        if(!classId){ document.getElementById('weeklyReportContent').innerHTML='<p class="text-xs text-red-500">クラスを選択してください</p>'; return; }
        const btn = document.getElementById('btnWeeklyReport');
        btn.disabled = true; btn.textContent = '生成中...';
        document.getElementById('weeklyReportContent').innerHTML='<p class="text-xs text-green-500 animate-pulse">📝 週報を作成しています...</p>';
        try {
          const weekKey = typeof getWeekKeyLocal === 'function' ? getWeekKeyLocal() : '';
          const res = await fetch('/api/teacher/weekly-report?classId=' + classId + '&weekKey=' + weekKey);
          const data = await res.json();
          if(data.ok){
            // 統計カード
            const s = data.classStats || {};
            let html = '<div class="grid grid-cols-2 gap-2 mb-3">';
            html += '<div class="bg-white rounded-lg p-2 text-center border"><div class="text-lg font-black text-blue-600">'+s.submittedStudents+'/'+s.totalStudents+'</div><div class="text-[10px] text-slate-500">提出者数</div></div>';
            html += '<div class="bg-white rounded-lg p-2 text-center border"><div class="text-lg font-black text-green-600">'+s.totalSubmissions+'</div><div class="text-[10px] text-slate-500">総提出回数</div></div>';
            html += '<div class="bg-white rounded-lg p-2 text-center border"><div class="text-lg font-black text-purple-600">'+s.avgMinPerStudent+'分</div><div class="text-[10px] text-slate-500">1人あたり平均</div></div>';
            html += '<div class="bg-white rounded-lg p-2 text-center border"><div class="text-lg font-black text-amber-600">'+s.avgSunRate+'%</div><div class="text-[10px] text-slate-500">満足度(☀️率)</div></div>';
            html += '</div>';
            // AI週報本文
            if(data.reportText){
              const formatted = data.reportText.split(String.fromCharCode(10)).join('<br>');
              html += '<div class="bg-white rounded-lg p-3 text-sm leading-relaxed text-slate-700 border">'+formatted+'</div>';
            }
            document.getElementById('weeklyReportContent').innerHTML = html;
            // 児童一覧を個人カルテエリアに表示
            updateKarteStudentList(data.studentSummaries || [], classId);
          } else {
            document.getElementById('weeklyReportContent').innerHTML='<p class="text-xs text-red-500">生成に失敗: '+(data.error||'unknown')+'</p>';
          }
        } catch(e) {
          document.getElementById('weeklyReportContent').innerHTML='<p class="text-xs text-red-500">エラー: '+e.message+'</p>';
        } finally {
          btn.disabled = false; btn.textContent = '📝 週報を生成';
        }
      }

      // 個人カルテの児童一覧を更新
      function updateKarteStudentList(students, classId){
        const wrap = document.getElementById('karteStudentList');
        if(!wrap) return;
        if(!students.length){ wrap.innerHTML='<p class="text-xs text-slate-400">児童データがありません</p>'; return; }
        wrap.innerHTML = '';
        // ヒートマップ用データも保持
        window._lastStudentSummaries = students;
        window._lastAnalyticsClassId = classId;
        for(const s of students){
          const btn = document.createElement('button');
          btn.className = 'px-3 py-1.5 rounded-lg text-xs font-bold border border-amber-300 bg-amber-50 hover:bg-amber-100 text-amber-800 transition';
          btn.textContent = '👤 ' + s.name;
          btn.onclick = function(){ openStudentKarte(s.userId || s.name, s.name); };
          wrap.appendChild(btn);
        }
        // ヒートマップも描画
        renderHeatmap(students);
      }

      // 提出ヒートマップ描画
      function renderHeatmap(students){
        const wrap = document.getElementById('heatmapContent');
        if(!wrap) return;
        const days = ['月','火','水','木','金'];
        let html = '<table class="w-full text-xs"><thead><tr><th class="text-left p-1 text-slate-500">名前</th>';
        days.forEach(function(d){ html += '<th class="p-1 text-center text-slate-500">'+d+'</th>'; });
        html += '</tr></thead><tbody>';
        for(const s of students){
          html += '<tr>';
          html += '<td class="p-1 font-bold text-slate-700 whitespace-nowrap cursor-pointer hover:text-purple-600" onclick="openStudentKarte(&#39;'+escH(s.userId||s.name)+'&#39;,&#39;'+escH(s.name)+'&#39;)">' + escH(s.name) + '</td>';
          const cnt = s.thisWeek ? s.thisWeek.count : 0;
          // 曜日ごとの提出は簡易表示（提出回数に応じて色分け）
          for(let d=0; d<5; d++){
            const submitted = d < cnt;
            const color = submitted ? 'bg-green-400' : 'bg-slate-100';
            html += '<td class="p-1 text-center"><div class="w-6 h-6 rounded '+color+' mx-auto flex items-center justify-center">'+(submitted?'✓':'')+'</div></td>';
          }
          html += '</tr>';
        }
        html += '</tbody></table>';
        wrap.innerHTML = html;
      }

      // 個人カルテを開く
      async function openStudentKarte(studentId, studentName){
        const panel = document.getElementById('studentKartePanel');
        const nameEl = document.getElementById('karteStudentName');
        const contentEl = document.getElementById('karteContent');
        panel.classList.remove('hidden');
        nameEl.textContent = '👤 ' + studentName + ' のカルテ';
        contentEl.innerHTML = '<p class="text-xs text-purple-500 animate-pulse">🤖 AIが分析中...</p>';
        // スクロール
        panel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        try {
          const res = await fetch('/api/teacher/student-karte?studentId=' + encodeURIComponent(studentId));
          const data = await res.json();
          if(!data.ok){ contentEl.innerHTML = '<p class="text-red-500 text-xs">取得エラー</p>'; return; }
          let html = '';
          // 基本統計
          const st = data.stats || {};
          html += '<div class="grid grid-cols-3 gap-2 mb-3">';
          html += '<div class="bg-blue-50 rounded-lg p-2 text-center"><div class="text-lg font-black text-blue-600">'+st.totalDays+'</div><div class="text-[10px] text-slate-500">提出回数</div></div>';
          html += '<div class="bg-green-50 rounded-lg p-2 text-center"><div class="text-lg font-black text-green-600">'+st.avgMin+'分</div><div class="text-[10px] text-slate-500">平均学習時間</div></div>';
          html += '<div class="bg-amber-50 rounded-lg p-2 text-center"><div class="text-lg font-black text-amber-600">'+st.sunRate+'%</div><div class="text-[10px] text-slate-500">満足度</div></div>';
          html += '</div>';
          // 教科別成績
          if(data.subjects && data.subjects.length > 0){
            html += '<div class="mb-3"><div class="font-bold text-xs text-slate-600 mb-1">📊 教科別成績</div><div class="space-y-1">';
            for(const sub of data.subjects){
              const w = Math.max(sub.rate, 5);
              const color = sub.rate >= 80 ? 'bg-green-400' : sub.rate >= 60 ? 'bg-yellow-400' : 'bg-red-400';
              html += '<div class="flex items-center gap-2"><span class="text-xs w-16 text-slate-600 font-bold truncate">'+escH(sub.unit)+'</span>';
              html += '<div class="flex-1 bg-slate-100 rounded-full h-4"><div class="'+color+' rounded-full h-4 text-[10px] text-white flex items-center justify-center font-bold" style="width:'+w+'%">'+sub.rate+'%</div></div>';
              html += '<span class="text-[10px] text-slate-400">'+sub.total+'問</span></div>';
            }
            html += '</div></div>';
          }
          // 計画修正履歴
          if(data.revisions && data.revisions.length > 0){
            html += '<div class="mb-3"><div class="font-bold text-xs text-slate-600 mb-1">🔄 計画修正履歴</div><div class="space-y-1">';
            for(const r of data.revisions.slice(0, 5)){
              html += '<div class="text-xs bg-slate-50 rounded p-1.5 border"><span class="font-bold text-slate-500">['+escH(r.week_key)+']</span> '+escH(r.reason || '理由なし')+'</div>';
            }
            html += '</div></div>';
          }
          // AI分析
          if(data.aiAdvice){
            try{
              const advice = JSON.parse(data.aiAdvice);
              html += '<div class="space-y-2">';
              if(advice.trend) html += '<div class="bg-blue-50 rounded-lg p-2.5 border border-blue-200"><div class="font-bold text-xs text-blue-700 mb-1">📊 学習の傾向</div><div class="text-xs text-slate-700">'+escH(advice.trend)+'</div></div>';
              if(advice.strength) html += '<div class="bg-green-50 rounded-lg p-2.5 border border-green-200"><div class="font-bold text-xs text-green-700 mb-1">💪 強みと成長</div><div class="text-xs text-slate-700">'+escH(advice.strength)+'</div></div>';
              if(advice.concern) html += '<div class="bg-orange-50 rounded-lg p-2.5 border border-orange-200"><div class="font-bold text-xs text-orange-700 mb-1">🔍 気になる点</div><div class="text-xs text-slate-700">'+escH(advice.concern)+'</div></div>';
              if(advice.advice) html += '<div class="bg-purple-50 rounded-lg p-2.5 border border-purple-200"><div class="font-bold text-xs text-purple-700 mb-1">💬 おすすめの声かけ</div><div class="text-xs text-slate-700">'+escH(advice.advice)+'</div></div>';
              html += '</div>';
            }catch(_){
              html += '<div class="bg-purple-50 rounded-lg p-2.5 border text-xs text-slate-700">'+escH(data.aiAdvice)+'</div>';
            }
          }
          // 直近の学習記録
          if(data.recentSubmissions && data.recentSubmissions.length > 0){
            html += '<div class="mt-3"><div class="font-bold text-xs text-slate-600 mb-1">📝 直近の学習記録</div><div class="space-y-1 max-h-48 overflow-y-auto">';
            for(const s of data.recentSubmissions.slice(0, 10)){
              const wIcon = s.end_weather === 'sun' ? '☀️' : s.end_weather === 'cloud' ? '☁️' : s.end_weather === 'rain' ? '🌧️' : '❓';
              html += '<div class="text-xs bg-white rounded p-1.5 border flex items-center gap-1">';
              html += '<span class="font-bold text-slate-500">'+escH(s.day_key||'')+'</span> ';
              html += wIcon+' ';
              html += '<span class="text-slate-600">'+escH(s.todo||'')+'</span> ';
              html += '<span class="text-slate-400">('+( s.minutes||0)+'分)</span>';
              html += '</div>';
            }
            html += '</div></div>';
          }
          contentEl.innerHTML = html;
        } catch(e) {
          contentEl.innerHTML = '<p class="text-red-500 text-xs">エラー: '+e.message+'</p>';
        }
      }

      // AIクラス分析（Gemini対応＋児童リスト・ヒートマップ連動）
      async function loadAIAnalysis(){
        const classId = document.getElementById('analyticsClassFilter').value;
        if(!classId){ document.getElementById('aiAnalysisContent').innerHTML='<p class="text-xs text-red-500">クラスを選択してください</p>'; return; }
        const btn = document.getElementById('btnAIAnalysis');
        btn.disabled = true; btn.textContent = '分析中...';
        document.getElementById('aiAnalysisContent').innerHTML='<p class="text-xs text-purple-500 animate-pulse">🤖 AIがデータを分析しています...</p>';
        try {
          const weekKey = typeof getWeekKeyLocal === 'function' ? getWeekKeyLocal() : '';
          // AI分析と同時にclass-analyticsも取得して児童一覧・ヒートマップに使う
          const [aiRes, caRes] = await Promise.all([
            fetch('/api/teacher/class-ai-analysis?classId=' + classId + '&weekKey=' + weekKey),
            fetch('/api/teacher/class-analytics?classId=' + classId + '&weekKey=' + weekKey).then(r=>r.json()).catch(()=>null)
          ]);
          const data = await aiRes.json();
          if(data.ok && data.analysis){
            const formatted = data.analysis.split(String.fromCharCode(10)).join('<br>');
            document.getElementById('aiAnalysisContent').innerHTML = '<div class="bg-white rounded-lg p-3 text-sm leading-relaxed text-slate-700 border">' + formatted + '</div>';
          } else {
            document.getElementById('aiAnalysisContent').innerHTML = '<p class="text-xs text-red-500">分析に失敗: ' + (data.error || 'unknown') + '</p>';
          }
          // 児童一覧更新
          if(caRes && caRes.ok && caRes.members){
            const studentList = caRes.members.map(function(m){
              const hwByUser = {};
              (caRes.homework || []).forEach(function(h){ if(h.user_id===m.id){ if(!hwByUser[m.id]) hwByUser[m.id]={count:0}; hwByUser[m.id].count++; } });
              return { userId: m.id, name: m.name, thisWeek: { count: hwByUser[m.id] ? hwByUser[m.id].count : 0, totalMin: 0, sunRate: 0 } };
            });
            updateKarteStudentList(studentList, classId);
          }
        } catch(e) {
          document.getElementById('aiAnalysisContent').innerHTML = '<p class="text-xs text-red-500">エラー: ' + e.message + '</p>';
        } finally {
          btn.disabled = false; btn.textContent = '✨ AIで分析';
        }
      }

      // フィルター初期化
      async function initNewTabFilters(){
        try{
          const cdata = await api('/api/teacher/classes');
          const classes= (cdata && cdata.classes) || [];
          ['fbClassFilter'].forEach(function(filterId){
            const el = document.getElementById(filterId);
            if(el && el.options.length <= 1){
              el.innerHTML = '';
              classes.forEach(function(cls){
                var opt = document.createElement('option');
                opt.value = cls.id;
                opt.textContent = cls.name;
                el.appendChild(opt);
              });
            }
          });
        }catch(_){}
      }
      // 初期化時にフィルターを設定
      setTimeout(initNewTabFilters, 500);

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
            + (s.selfStudyPlan ? '<div class="mt-1 p-1.5 bg-blue-50 rounded border border-blue-200"><b>📖 自主学習：</b>'+escH(s.selfStudyPlan)+'</div>' : '')
            + (s.weeklyPlan ? '<div class="mt-1 p-1.5 bg-purple-50 rounded border border-purple-200"><b>📝 週の計画：</b>'+escH(s.weeklyPlan)+'</div>' : '')
            + (s.weeklyReflection ? '<div class="mt-1 p-1.5 bg-amber-50 rounded border border-amber-200"><b>🔄 週の振り返り：</b>'+escH(s.weeklyReflection)+'</div>' : '')
            + (s.workPhotoAnalysis ? '<div class="mt-1 p-1.5 bg-cyan-50 rounded border border-cyan-200"><b>📷 成果物（AI分析）：</b>'+escH(s.workPhotoAnalysis)+'</div>' : '')
            + (s.workPhotoKey ? '<div class="mt-1"><img src="/api/photo/'+encodeURIComponent(s.userId)+'/'+encodeURIComponent(s.dayKey)+'" class="rounded-lg border border-slate-200 max-h-48 cursor-pointer hover:opacity-90" onclick="this.classList.toggle(&#39;max-h-48&#39;);this.classList.toggle(&#39;max-h-none&#39;)" loading="lazy" alt="成果物写真"/></div>' : '')
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

      async function generateHWAIComments(){
        var btn = document.getElementById('hwAiGenBtn');
        var msg = document.getElementById('hwAiGenMsg');
        var classId = document.getElementById('hwClassFilter').value;
        if(!classId){ alert('クラスを選択してください'); return; }
        btn.disabled=true; btn.textContent='⏳ AI生成中...';
        msg.textContent='AIがコメントを生成しています…少しお待ちください';
        try{
          var r = await api('/api/teacher/homework-ai-comments',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({classId:classId})});
          console.log('[AI-COMMENT-RESPONSE]', JSON.stringify(r));
          if(!r.comments || !r.comments.length){ msg.textContent='未返却の提出がありません'; return; }
          var filled = 0;
          for(var i=0;i<r.comments.length;i++){
            var c = r.comments[i];
            var ta = document.getElementById('hwComment_'+c.id);
            if(ta){ ta.value = c.comment; filled++; }
          }
          msg.textContent='✅ '+filled+'件のコメントを生成しました！内容を確認して「未返却をまとめて返却」で返却してください。';
        }catch(e){
          msg.textContent='❌ エラー: '+String(e.message||e);
        }finally{
          btn.disabled=false; btn.textContent='🤖 AIコメント一括生成';
        }
      }

      async function generateWeeklyAIComments(){
        var btn = document.getElementById('weeklyAiGenBtn');
        var msg = document.getElementById('weeklyAiGenMsg');
        var data = window._weeklyRefData || [];
        if(!data.length){ alert('未返却の振り返りがありません'); return; }
        var classId = (document.getElementById('wpClassSel')||{}).value || (document.getElementById('hwClassFilter')||{}).value;
        if(!classId){ alert('クラスを選択してください'); return; }
        btn.disabled=true; btn.textContent='⏳ AI生成中...';
        msg.textContent='AIがコメントを生成しています…';
        try{
          var r = await api('/api/teacher/weekly-ai-comments',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({classId:classId})});
          if(!r.comments || !r.comments.length){ msg.textContent='未返却の振り返りがありません'; return; }
          var ta = document.getElementById('bulkRefComments');
          if(ta){
            var json = JSON.stringify({comments: r.comments.map(function(c){ return c.comment; })});
            ta.value = json;
          }
          msg.textContent='✅ '+r.comments.length+'件のコメントを生成しました！「貼り付けて一括返却」で返却してください。';
        }catch(e){
          msg.textContent='❌ エラー: '+String(e.message||e);
        }finally{
          btn.disabled=false; btn.textContent='🤖 AIコメント一括生成';
        }
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

      // ===== メール機能 =====
      function _utcToJST(utcStr){
        if(!utcStr) return {date:'',time:''};
        var d = new Date(utcStr.replace(' ','T')+'Z');
        var jp = new Date(d.getTime() + 9*60*60*1000);
        var mm = String(jp.getUTCMonth()+1).padStart(2,'0');
        var dd = String(jp.getUTCDate()).padStart(2,'0');
        var hh = String(jp.getUTCHours()).padStart(2,'0');
        var mi = String(jp.getUTCMinutes()).padStart(2,'0');
        return {date: jp.getUTCFullYear()+'-'+mm+'-'+dd, time: hh+':'+mi};
      }
      var _mailCurrentStudent = null;
      var _mailCurrentClass = null;

      var _mailPollTimer = null;
      var _mailListPollTimer = null;

      async function loadTeacherMail(){
        try{
          var clsData = await api('/api/teacher/classes');
          var sel = document.getElementById('mailClassFilter');
          var cur = sel.value;
          sel.innerHTML = '';
          (clsData.classes||[]).forEach(function(c,i){ sel.innerHTML += '<option value="'+escH(c.id)+'"'+(c.id===cur||(!cur&&i===0)?' selected':'')+'>'+escH(c.name)+'</option>'; });
          sel.onchange = function(){ loadMailStudentList(); };
          _mailCurrentClass = sel.value;
          loadMailStudentList();
        }catch(e){}
      }

      async function loadMailStudentList(){
        var classId = document.getElementById('mailClassFilter').value;
        _mailCurrentClass = classId;
        var wrap = document.getElementById('mailStudentCards');
        wrap.innerHTML = '<p class="text-slate-400 text-sm">読み込み中...</p>';
        if(!classId) return;
        try{
          var data = await api('/api/teacher/class/'+encodeURIComponent(classId)+'/members');
          var members = data.members || [];
          if(!members.length){ wrap.innerHTML='<p class="text-slate-400 text-sm">生徒がいません</p>'; return; }
          var unreadData = await api('/api/teacher/messages?classId='+encodeURIComponent(classId));
          var msgs = unreadData.messages || [];
          var unreadMap = {};
          var lastMsgMap = {};
          msgs.forEach(function(m){
            var sid = m.senderRole==='student' ? m.senderId : m.recipientId;
            if(!lastMsgMap[sid]) lastMsgMap[sid] = m;
            if(m.senderRole==='student' && !m.readAt){ unreadMap[sid] = (unreadMap[sid]||0) + 1; }
          });
          wrap.innerHTML='';
          // 未読がある生徒を上に、次に最新メッセージがある生徒、最後にメッセージなし
          members.sort(function(a,b){
            var ua = unreadMap[a.userId] || 0;
            var ub = unreadMap[b.userId] || 0;
            if(ua !== ub) return ub - ua; // 未読多い順
            var la = lastMsgMap[a.userId];
            var lb = lastMsgMap[b.userId];
            if(la && !lb) return -1;
            if(!la && lb) return 1;
            if(la && lb) return la.createdAt > lb.createdAt ? -1 : 1; // 新しい順
            return 0;
          });
          members.forEach(function(m){
            var card = document.createElement('div');
            var unread = unreadMap[m.userId] || 0;
            var lastMsg = lastMsgMap[m.userId];
            var preview = lastMsg ? lastMsg.body.slice(0,30) : 'メッセージなし';
            var time = lastMsg ? _utcToJST(lastMsg.createdAt).time : '';
            card.className = 'flex items-center gap-3 bg-white rounded-xl p-3 shadow-sm cursor-pointer hover:bg-slate-50 border' + (unread ? ' border-orange-300' : ' border-slate-100');
            card.innerHTML = '<div class="w-10 h-10 rounded-full bg-teal-100 flex items-center justify-center text-teal-700 font-bold text-sm flex-shrink-0">'+escH(m.name.slice(0,1))+'</div>'
              + '<div class="flex-1 min-w-0"><div class="flex justify-between items-center"><span class="font-bold text-sm">'+escH(m.name)+'</span><span class="text-[10px] text-slate-400">'+escH(time)+'</span></div><div class="text-xs text-slate-500 truncate">'+escH(preview)+'</div></div>'
              + (unread ? '<span class="bg-red-500 text-white text-[10px] rounded-full min-w-[18px] h-[18px] flex items-center justify-center font-bold">'+unread+'</span>' : '');
            card.onclick = (function(s){ return function(){ openMailChat(s.userId, s.name); }; })({userId:m.userId,name:m.name});
            wrap.appendChild(card);
          });
        }catch(e){ wrap.innerHTML='<p class="text-red-500 text-sm">読み込みエラー</p>'; }
      }

      function openMailChat(studentId, studentName){
        _mailCurrentStudent = studentId;
        document.getElementById('mailChatName').textContent = studentName + 'さん';
        document.getElementById('mailStudentListView').style.display='none';
        var cv = document.getElementById('mailChatView');
        cv.classList.remove('hidden'); cv.style.display='';
        loadMailChat();
        if(_mailPollTimer) clearInterval(_mailPollTimer);
        _mailPollTimer = setInterval(function(){ loadMailChat(true); }, 5000);
      }

      function closeMailChat(){
        if(_mailPollTimer){ clearInterval(_mailPollTimer); _mailPollTimer = null; }
        _mailCurrentStudent = null;
        document.getElementById('mailStudentListView').style.display='';
        document.getElementById('mailChatView').style.display='none';
        loadMailStudentList();
      }

      async function loadMailChat(silent){
        var wrap = document.getElementById('mailChatMessages');
        if(!silent) wrap.innerHTML = '<p class="text-sm text-slate-400 text-center">読み込み中...</p>';
        if(!_mailCurrentClass || !_mailCurrentStudent) return;
        try{
          var data = await api('/api/teacher/messages?classId='+encodeURIComponent(_mailCurrentClass)+'&studentId='+encodeURIComponent(_mailCurrentStudent));
          var list = data.messages || [];
          if(!list.length){ wrap.innerHTML='<p class="text-sm text-slate-400 text-center py-4">まだメッセージはありません</p>'; return; }
          // 生徒からの未読メッセージを自動で既読にする
          var unreadIds = [];
          list.forEach(function(m){ if(m.senderRole==='student' && !m.readAt) unreadIds.push(m.id); });
          if(unreadIds.length > 0){
            Promise.all(unreadIds.map(function(mid){ return api('/api/teacher/message/'+mid+'/read',{method:'POST'}); }))
              .then(function(){ if(!silent) loadMailChat(true); });
          }
          wrap.innerHTML='';
          var prevDate='';
          list.slice().reverse().forEach(function(m){
            var isFromMe = m.senderRole === 'teacher';
            var jst = _utcToJST(m.createdAt);
            var dt = jst.date;
            if(dt !== prevDate){
              wrap.insertAdjacentHTML('beforeend','<div class="text-center my-2"><span class="bg-black/10 text-slate-600 text-[10px] rounded-full px-3 py-0.5">'+escH(dt)+'</span></div>');
              prevDate = dt;
            }
            var row = document.createElement('div');
            row.className = 'flex ' + (isFromMe ? 'justify-end' : 'justify-start') + ' mb-1';
            var bubble = document.createElement('div');
            bubble.className = 'max-w-[75%]';
            var nameTag = '';
            if(!isFromMe){ nameTag = '<div class="text-[10px] text-slate-500 mb-0.5 ml-1">'+escH(m.senderName||'生徒')+'</div>'; }
            var time = escH(jst.time);
            var readMark = '';
            if(isFromMe && m.readAt){ readMark = '<span class="text-[10px] text-teal-600">既読</span> '; }
            var msgDiv = document.createElement('div');
            if(isFromMe){
              msgDiv.className = 'rounded-2xl rounded-br-sm px-3 py-2 text-sm shadow-sm bg-teal-500 text-white';
            } else {
              msgDiv.className = 'rounded-2xl rounded-bl-sm px-3 py-2 text-sm shadow-sm bg-white';
            }
            if(m.image){ var img=document.createElement('img'); img.src=m.image; img.className='rounded-lg max-w-full max-h-[200px] mb-1 cursor-pointer'; img.onclick=function(){window.open(m.image,'_blank');}; msgDiv.appendChild(img); }
            if(m.body && m.body!=='(画像)'){ var txt=document.createElement('span'); txt.textContent=m.body; msgDiv.appendChild(txt); } else if(!m.image){ msgDiv.textContent=m.body; }
            bubble.insertAdjacentHTML('beforeend', nameTag);
            bubble.appendChild(msgDiv);
            bubble.insertAdjacentHTML('beforeend', '<div class="flex items-end gap-1 mt-0.5 '+(isFromMe?'justify-end mr-1':'ml-1')+'"><span class="text-[10px] text-slate-400">'+readMark+time+'</span></div>');
            if(!isFromMe && !m.readAt){
              msgDiv.onclick = (function(mid){ return async function(){
                await api('/api/teacher/message/'+mid+'/read',{method:'POST'});
                loadMailChat();
              }; })(m.id);
              msgDiv.style.cursor='pointer';
              msgDiv.title='クリックで既読';
            }
            row.appendChild(bubble);
            wrap.appendChild(row);
          });
          wrap.scrollTop = wrap.scrollHeight;
        }catch(e){ wrap.innerHTML='<p class="text-red-500 text-sm text-center">読み込みエラー</p>'; }
      }

      var _mailImageData = null;
      function handleMailImage(input){
        var file = input.files[0]; if(!file) return;
        var reader = new FileReader();
        reader.onload = function(e){
          var img = new Image();
          img.onload = function(){
            var canvas = document.createElement('canvas');
            var maxW = 800, w = img.width, h = img.height;
            if(w > maxW){ h = Math.round(h * maxW / w); w = maxW; }
            canvas.width = w; canvas.height = h;
            canvas.getContext('2d').drawImage(img, 0, 0, w, h);
            _mailImageData = canvas.toDataURL('image/jpeg', 0.6);
            document.getElementById('mailImageThumb').src = _mailImageData;
            document.getElementById('mailImagePreview').classList.remove('hidden');
          };
          img.src = e.target.result;
        };
        reader.readAsDataURL(file);
        input.value = '';
      }
      function clearMailImage(){ _mailImageData = null; document.getElementById('mailImagePreview').classList.add('hidden'); }
      async function sendTeacherMail(){
        if(!_mailCurrentStudent){ return; }
        var body = document.getElementById('mailBody').value.trim();
        var msg = document.getElementById('mailMsg');
        if(!body && !_mailImageData){ msg.textContent='メッセージを入力してください'; msg.className='text-xs text-center py-1 text-red-600'; return; }
        try{
          await api('/api/teacher/message',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({classId:_mailCurrentClass,studentId:_mailCurrentStudent,body:body||'(画像)',image:_mailImageData||undefined})});
          msg.textContent=''; document.getElementById('mailBody').value=''; clearMailImage();
          loadMailChat();
        }catch(e){ msg.textContent='送信エラー'; msg.className='text-xs text-center py-1 text-red-600'; }
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
        // 締切のデフォルトを今日の20:00に
        var dlEl = document.getElementById('cnDeadline');
        if(dlEl && !dlEl.value){
          var y = today.getFullYear(), m = String(today.getMonth()+1).padStart(2,'0'), d = String(today.getDate()).padStart(2,'0');
          dlEl.value = y+'-'+m+'-'+d+'T20:00';
        }
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
