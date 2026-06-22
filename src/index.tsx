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

async function callGemini(env: any, body: any, model = 'gemini-3.5-flash'): Promise<{ ok: boolean, text: string, source: string }> {
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
      const _ac = new AbortController(); const _to = setTimeout(() => _ac.abort(), 30000)
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        signal: _ac.signal,
      }).finally(() => clearTimeout(_to))
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

  // 連絡帳コインの上書き消失を防ぐ：サーバが付与済みの連絡帳コインをクライアントが知らない場合は補填
  let saveJson = stateJson
  try {
    const _cur = await c.env.DB.prepare(`SELECT state_json FROM progress WHERE user_id=?`).bind(u.id).first<any>()
    if (_cur?.state_json) {
      const _srv = JSON.parse(_cur.state_json)
      const _srvApplied = Number(_srv._contactCoinsApplied) || 0
      const _inc: any = body.state ?? body
      const _cliApplied = Number(_inc._contactCoinsApplied) || 0
      if (_srvApplied > _cliApplied) {
        _inc.coins = (Number(_inc.coins) || 0) + (_srvApplied - _cliApplied)
        _inc._contactCoinsApplied = _srvApplied
        saveJson = JSON.stringify(_inc)
      }
    }
  } catch { /* 補填失敗時はそのまま保存 */ }

  try {
    await c.env.DB.prepare(
      `INSERT INTO progress (user_id, state_json, updated_at)
       VALUES (?, ?, datetime('now'))
       ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json, updated_at=datetime('now')`
    )
      .bind(u.id, saveJson)
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
    await c.env.DB.prepare(`UPDATE ranking_stats SET typeshoot_score=? WHERE user_id=?`).bind(Number(stats.typeShootScore || 0), u.id).run()
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
    const typeShootScore = Number(s._cachedTypeShootScore || 0)
    const pokedexCount = Array.isArray(s.pokedex) ? s.pokedex.length : 0
    const maxObj: any = (s.metrics && s.metrics.max) || s.max || (s.M && s.M.max) || {}
    const wildWinStreak = Number(maxObj.winStreak || s._cachedWildWinStreak || 0)
    return {
      displayName: String(s.name || fallbackName).slice(0, 30),
      totalLevel, monsterCount, correctCount, rankingPoints,
      battlePower, pokedexCount, wildWinStreak, typeShootScore
    }
  } catch {
    return { displayName: fallbackName, totalLevel: 0, monsterCount: 0, correctCount: 0, rankingPoints: 0, battlePower: 0, pokedexCount: 0, wildWinStreak: 0, typeShootScore: 0 }
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

// -------------------- API: fest status (public for logged-in users) --------------------

app.get('/api/fest/status', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  try {
    const rows = await c.env.DB.prepare(
      `SELECT key, value FROM admin_settings WHERE key IN ('fraction_fest_active','decimal_fest_active')`
    ).all<any>()
    const result: Record<string, boolean> = { fraction_fest_active: false, decimal_fest_active: false }
    for (const r of rows.results) {
      result[r.key] = r.value === '1'
    }
    return c.json({ ok: true, ...result })
  } catch(e) {
    return c.json({ ok: true, fraction_fest_active: false, decimal_fest_active: false })
  }
})

app.put('/api/admin/fest-toggle', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'admin' && u.role !== 'teacher')) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body || !body.fest) return jsonError(c, 400, 'invalid_json')
  const key = body.fest === 'fraction' ? 'fraction_fest_active' : body.fest === 'decimal' ? 'decimal_fest_active' : null
  if (!key) return jsonError(c, 400, 'invalid_fest')
  const active = body.active ? '1' : '0'
  await c.env.DB.prepare(
    `INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))
     ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=datetime('now')`
  ).bind(key, active).run()
  return c.json({ ok: true, [key]: body.active ? true : false })
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
// 先生の担当クラスの全児童（CSV書き出し用）
app.get('/api/teacher/all-students', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const res = await c.env.DB.prepare(`
    SELECT DISTINCT u.id as userId, u.login_id as loginId, u.name, u.grade, u.class_name as className
    FROM users u
    JOIN class_members cm ON cm.user_id = u.id
    JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    WHERE u.role = 'student'
    ORDER BY u.grade, u.class_name, u.login_id
  `).bind(u.id).all<any>()
  return c.json({ ok: true, students: res.results })
})

// 先生の担当クラスの全児童の名前をクラウドから消去（匿名化）
app.post('/api/teacher/anonymize-names', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json<any>().catch(() => ({}))
  if (body?.confirm !== 'YES_ANONYMIZE') return jsonError(c, 400, 'confirm_required')
  // 担当クラスの児童のnameを login_id に置き換える（空にはしない、表示識別のため）
  const res = await c.env.DB.prepare(`
    UPDATE users SET name = login_id
    WHERE role = 'student' AND id IN (
      SELECT DISTINCT cm.user_id FROM class_members cm
      JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
    )
  `).bind(u.id).run()
  return c.json({ ok: true, updated: res.meta?.changes || 0 })
})

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
    'SELECT u.id as userId, u.login_id as loginId, u.name FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=? ORDER BY u.name'
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
    SELECT u.id, u.login_id as loginId, u.name, u.grade, u.class_name as className,
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
    SELECT u.id, u.login_id as loginId, u.name, u.grade, p.state_json as stateJson
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

    studentData.push({ id: m.id, loginId: m.loginId || '', name: m.name || '', grade: m.grade || '', byUnit, bySubject, learnStreak })
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
      id: s.id, loginId: s.loginId, name: s.name, grade: s.grade, learnStreak: s.learnStreak,
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
    `SELECT u.id, u.login_id as loginId, u.name, u.last_login_at as lastLoginAt
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
  }).map((m: any) => ({ id: m.id, loginId: m.loginId, name: m.name, lastLoginAt: m.lastLoginAt }))

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
    // フォールバック（タイムアウト付き・失敗しても500にしない）
    if (!analysisText) {
      try {
        const aiResult: any = await Promise.race([
          c.env.AI.run('@cf/meta/llama-3.1-8b-instruct-fast', {
            messages: [{ role: 'user', content: prompt }],
            max_tokens: 1024
          }),
          new Promise((_, rej) => setTimeout(() => rej(new Error('workers_ai_timeout')), 20000))
        ])
        analysisText = aiResult.response || aiResult.result || ''
      } catch (fe: any) {
        console.error('class-ai fallback failed:', fe?.message || fe)
      }
    }
    if (!analysisText) {
      return c.json({ ok: false, error: 'AI分析を生成できませんでした。少し時間をおいて再度お試しください。（管理者の方へ：解消しない場合は GEMINI_API_KEY の有効期限切れの可能性があります）' })
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
      SELECT unit, week_key, COUNT(*) as total, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as correct_count
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

// 個人全期間分析API
app.get('/api/teacher/student-full-analysis', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const studentId = c.req.query('studentId')
  if (!studentId) return jsonError(c, 400, 'studentId required')

  const member = u.role === 'admin'
    ? await c.env.DB.prepare(`SELECT u.id, u.name, u.login_id, u.grade FROM users u WHERE u.id=?`).bind(studentId).first<any>()
    : await c.env.DB.prepare(`
        SELECT u.id, u.name, u.login_id, u.grade FROM users u
        JOIN class_members cm ON cm.user_id = u.id
        JOIN classes cl ON cl.id = cm.class_id AND cl.teacher_id = ?
        WHERE u.id = ?
      `).bind(u.id, studentId).first<any>()
  if (!member) return jsonError(c, 404, 'student_not_found')

  const [submissions, subjectResults, plans, reflections, revisions] = await Promise.all([
    c.env.DB.prepare(`
      SELECT day_key, todo, minutes, end_weather, weather_reason, teacher_comment, aim,
             next_improve, submitted_at, returned_at, streak_after, rest_day, has_physical
      FROM homework_submissions WHERE user_id=? ORDER BY day_key DESC
    `).bind(studentId).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare(`
      SELECT unit, COUNT(*) as total, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as correct_count
      FROM learning_results WHERE user_id=? GROUP BY unit ORDER BY total DESC
    `).bind(studentId).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare(`
      SELECT week_key, plans_json, revision_count, plan_approved, plan_reward_coins,
             reflection_comment, reflection_returned_at, reflection_reward_coins
      FROM student_weekly_plans WHERE user_id=? ORDER BY week_key DESC
    `).bind(studentId).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare(`
      SELECT week_key, concentration, good_point, improve_point, next_action, free_text, created_at
      FROM structured_reflections WHERE user_id=? ORDER BY week_key DESC
    `).bind(studentId).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare(`
      SELECT week_key, revision_number, reason, created_at
      FROM plan_revisions WHERE user_id=? ORDER BY created_at DESC
    `).bind(studentId).all<any>().catch(() => ({ results: [] })),
  ])

  const subs = submissions.results || []
  const totalSubmissions = subs.length
  const firstDate = subs.length > 0 ? subs[subs.length - 1].day_key : null
  const lastDate = subs.length > 0 ? subs[0].day_key : null
  const totalMinutes = subs.reduce((a: number, s: any) => a + (s.minutes || 0), 0)
  const avgMinutes = totalSubmissions > 0 ? Math.round(totalMinutes / totalSubmissions) : 0
  const weathers = subs.map((s: any) => s.end_weather).filter(Boolean)
  const sunCount = weathers.filter((w: string) => w === 'sun').length
  const cloudCount = weathers.filter((w: string) => w === 'cloud').length
  const rainCount = weathers.filter((w: string) => w === 'rain').length
  const sunRate = weathers.length ? Math.round(sunCount / weathers.length * 100) : 0

  // ストリーク計算
  const dayKeys = [...new Set(subs.map((s: any) => s.day_key).filter(Boolean))].sort()
  let currentStreak = 0
  let maxStreak = 0
  const streaksList: { start: string, end: string, length: number }[] = []
  if (dayKeys.length > 0) {
    let sStart = dayKeys[0], sLen = 1, prev = dayKeys[0]
    for (let i = 1; i < dayKeys.length; i++) {
      const diff = Math.round((new Date(dayKeys[i]).getTime() - new Date(prev).getTime()) / 86400000)
      if (diff === 1) { sLen++ }
      else if (diff > 1) {
        streaksList.push({ start: sStart, end: prev, length: sLen })
        if (sLen > maxStreak) maxStreak = sLen
        sStart = dayKeys[i]; sLen = 1
      }
      prev = dayKeys[i]
    }
    streaksList.push({ start: sStart, end: prev, length: sLen })
    if (sLen > maxStreak) maxStreak = sLen
    const daysSinceLast = Math.round((Date.now() - new Date(dayKeys[dayKeys.length - 1]).getTime()) / 86400000)
    if (daysSinceLast <= 1) currentStreak = streaksList[streaksList.length - 1].length
  }

  // 月別トレンド
  const mMap: Record<string, { count: number, totalMin: number, sun: number, weatherTotal: number }> = {}
  for (const s of subs) {
    if (!s.day_key) continue
    const m = s.day_key.slice(0, 7)
    if (!mMap[m]) mMap[m] = { count: 0, totalMin: 0, sun: 0, weatherTotal: 0 }
    mMap[m].count++
    mMap[m].totalMin += (s.minutes || 0)
    if (s.end_weather) { mMap[m].weatherTotal++; if (s.end_weather === 'sun') mMap[m].sun++ }
  }
  const monthlyTrends = Object.entries(mMap)
    .map(([month, v]) => ({ month, count: v.count, avgMin: v.count ? Math.round(v.totalMin / v.count) : 0, sunRate: v.weatherTotal ? Math.round(v.sun / v.weatherTotal * 100) : 0 }))
    .sort((a, b) => a.month.localeCompare(b.month))

  // カレンダー
  const calendar: Record<string, { minutes: number, weather: string }> = {}
  for (const s of subs) {
    if (s.day_key) calendar[s.day_key] = { minutes: s.minutes || 0, weather: s.end_weather || '' }
  }

  // 教科分析
  const subjectAnalysis = (subjectResults.results || []).map((r: any) => ({
    unit: r.unit, total: r.total, correct: r.correct_count, rate: r.total ? Math.round(r.correct_count / r.total * 100) : 0
  }))

  const allPlans = plans.results || []
  const approvedPlans = allPlans.filter((p: any) => p.plan_approved)
  const allRefs = reflections.results || []
  const returnedSubs = subs.filter((s: any) => s.returned_at)
  let aiComment2 = ''
  try { const _air = await c.env.DB.prepare(`SELECT comment FROM student_ai_comments WHERE user_id=? LIMIT 1`).bind(studentId).first<any>(); aiComment2 = (_air && _air.comment) || '' } catch {}
  let testScores: any[] = []
  try { const _tsr = await c.env.DB.prepare(`SELECT id, test_name, test_date, subject, max_score, score, comment FROM student_test_scores WHERE user_id=? ORDER BY (test_date IS NULL OR test_date=''), test_date DESC, id DESC`).bind(studentId).all<any>(); testScores = (((_tsr && _tsr.results) || []) as any[]).map((r: any) => ({ id: r.id, testName: r.test_name, testDate: r.test_date, subject: r.subject, maxScore: r.max_score, score: r.score, comment: r.comment, pct: (r.max_score ? Math.round(r.score / r.max_score * 100) : null) })) } catch {}

  let records: any[] = []
  try { const _rr = await c.env.DB.prepare(`SELECT id, type, title, body, reflection, eval_rank, eval_comment, subject, unit, day_key, created_at FROM student_records WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC`).bind(studentId).all<any>(); records = (((_rr && _rr.results) || []) as any[]).map((r: any) => ({ id: r.id, type: r.type, title: r.title, body: r.body, reflection: r.reflection, evalRank: r.eval_rank, evalComment: r.eval_comment, subject: r.subject, unit: r.unit, dayKey: r.day_key, createdAt: r.created_at })) } catch {}
  let teacherNotes: any[] = []
  try { const _tnr = await c.env.DB.prepare(`SELECT day_key, body, show_in_karte FROM teacher_student_notes WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC`).bind(studentId).all<any>(); teacherNotes = (((_tnr && _tnr.results) || []) as any[]).map((r: any) => ({ dayKey: r.day_key, body: r.body, showInKarte: !!r.show_in_karte })) } catch {}
  return c.json({
    ok: true,
    student: { id: member.id, name: member.name, loginId: member.login_id, grade: member.grade },
    overview: {
      totalSubmissions, firstDate, lastDate, totalMinutes, avgMinutes,
      sunRate, sunCount, cloudCount, rainCount, currentStreak, maxStreak,
      returnRate: totalSubmissions > 0 ? Math.round(returnedSubs.length / totalSubmissions * 100) : 0,
      planCompletionRate: allPlans.length > 0 ? Math.round(approvedPlans.length / allPlans.length * 100) : 0,
      totalPlans: allPlans.length, totalReflections: allRefs.length,
      totalRevisions: (revisions.results || []).length,
    },
    monthlyTrends, calendar, subjects: subjectAnalysis,
    streaks: streaksList.sort((a, b) => b.length - a.length).slice(0, 10),
    plans: allPlans.map((p: any) => ({ weekKey: p.week_key, revisionCount: p.revision_count || 0, approved: !!p.plan_approved })),
    reflections: allRefs.map((r: any) => ({ weekKey: r.week_key, concentration: r.concentration, goodPoint: r.good_point, improvePoint: r.improve_point, nextAction: r.next_action })),
    revisions: (revisions.results || []).slice(0, 30),
    recentSubmissions: subs.slice(0, 15),
    aiComment: aiComment2,
    testScores,
    records,
    teacherNotes,
  })
})

// 児童AIコメントの一括保存API
app.post('/api/teacher/student-ai-comments', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json().catch(() => null)
  if (!body || !Array.isArray(body.comments)) return jsonError(c, 400, 'invalid')
  let allowed: Set<string> | null = null
  if (u.role === 'teacher') {
    const rows = await c.env.DB.prepare(`SELECT cm.user_id as uid FROM class_members cm JOIN classes cl ON cl.id=cm.class_id AND cl.teacher_id=?`).bind(u.id).all<any>()
    allowed = new Set((rows.results || []).map((r: any) => String(r.uid)))
  }
  let saved = 0
  for (const it of body.comments) {
    const sid = String((it && it.studentId) || '')
    if (!sid) continue
    if (allowed && !allowed.has(sid)) continue
    await c.env.DB.prepare(`INSERT INTO student_ai_comments (user_id, comment, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(user_id) DO UPDATE SET comment=excluded.comment, updated_at=datetime('now')`).bind(sid, String(it.comment || '')).run()
    saved++
  }
  return c.json({ ok: true, saved })
})


// ===== テスト結果の取り込みAPI（外部AIの出力を貼り付け→パース→保存・集計値は再利用可能） =====
function _tsNorm(s){ return String(s==null?'':s).replace(/[Ａ-Ｚａ-ｚ０-９]/g,function(ch){return String.fromCharCode(ch.charCodeAt(0)-65248);}).replace(/[ 　]/g,'').toLowerCase(); }
function _tsHalf(s){ return String(s==null?'':s).replace(/[０-９]/g,function(ch){return String.fromCharCode(ch.charCodeAt(0)-65248);}); }
function _tsKeepNum(s){ return _tsHalf(s).replace(/[^0-9]/g,''); }
function _tsParseText(text){
  var NL=String.fromCharCode(10);
  var lines=String(text||'').split(NL);
  var testName='', testDate='', subject='', maxScore=100;
  var rows=[];
  for(var i=0;i<lines.length;i++){
    var line=String(lines[i]==null?'':lines[i]).trim();
    if(!line) continue;
    var hasColon=(line.indexOf(':')>=0)||(line.indexOf('：')>=0);
    var hasComma=(line.indexOf(',')>=0)||(line.indexOf('，')>=0)||(line.indexOf('、')>=0);
    if(!hasColon && !hasComma) continue;
    if(hasColon && !hasComma){
      var ci=line.indexOf('：'); if(ci<0) ci=line.indexOf(':');
      var k=line.slice(0,ci).replace(/[ 　]/g,'');
      var v=line.slice(ci+1).trim();
      if(k.indexOf('テスト名')>=0||k.indexOf('名称')>=0||k.indexOf('タイトル')>=0){ testName=v; }
      else if(k.indexOf('実施日')>=0||k.indexOf('日付')>=0||k.indexOf('日時')>=0){ testDate=_tsHalf(v).split('年').join('-').split('月').join('-').split('日').join('').split('/').join('-').split('.').join('-').trim(); if(testDate.charAt(testDate.length-1)==='-') testDate=testDate.slice(0,-1); }
      else if(k.indexOf('教科')>=0||k.indexOf('科目')>=0){ subject=v; }
      else if(k.indexOf('満点')>=0||k.indexOf('配点')>=0){ var mn=parseInt(_tsKeepNum(v),10); if(!isNaN(mn)&&mn>0) maxScore=mn; }
      continue;
    }
    var norm=line.split('，').join(',').split('、').join(',');
    var parts=norm.split(',');
    if(parts.length<2) continue;
    var nm=String(parts[0]).trim();
    var scoreStr=_tsKeepNum(parts[1]);
    if(!nm||scoreStr==='') continue;
    var sc=parseInt(scoreStr,10);
    if(isNaN(sc)) continue;
    var cm=parts.slice(2).join(',').trim();
    rows.push({rawName:nm, score:sc, comment:cm});
  }
  return { testName:testName, testDate:testDate, subject:subject, maxScore:maxScore, rows:rows };
}
app.post('/api/teacher/test-scores/parse', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json().catch(() => null)
  if (!body || typeof body.text !== 'string') return jsonError(c, 400, 'invalid')
  const classId = String(body.classId || '')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const roster = (((await c.env.DB.prepare('SELECT u.id, u.login_id as loginId, u.name FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=?').bind(classId).all<any>()).results) || [])
  const idx: Record<string, string> = {}
  for (const m of roster as any[]) { if (m.name) idx[_tsNorm(m.name)] = m.id; if (m.loginId) idx[_tsNorm(m.loginId)] = m.id }
  const parsed = _tsParseText(body.text)
  const rows = parsed.rows.map((r: any) => {
    const key = _tsNorm(r.rawName)
    let uid: string | null = idx[key] || null
    if (!uid) { for (const m of roster as any[]) { const nn = _tsNorm(m.name); if (nn && (nn.indexOf(key) >= 0 || key.indexOf(nn) >= 0)) { uid = m.id; break } } }
    const mm = uid ? (roster as any[]).find((x: any) => x.id === uid) : null
    return { rawName: r.rawName, score: r.score, comment: r.comment, matchedUserId: uid, matchedName: mm ? mm.name : null }
  })
  return c.json({ ok: true, header: { testName: parsed.testName, testDate: parsed.testDate, subject: parsed.subject, maxScore: parsed.maxScore }, rows, roster: (roster as any[]).map((m: any) => ({ userId: m.id, name: m.name, loginId: m.loginId })) })
})
app.post('/api/teacher/test-scores/save', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json().catch(() => null)
  if (!body || !Array.isArray(body.rows)) return jsonError(c, 400, 'invalid')
  const classId = String(body.classId || '')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const mem = (((await c.env.DB.prepare('SELECT user_id as uid FROM class_members WHERE class_id=?').bind(classId).all<any>()).results) || [])
  const allowed = new Set((mem as any[]).map((r: any) => String(r.uid)))
  try { await c.env.DB.prepare("CREATE TABLE IF NOT EXISTS student_test_scores (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, test_name TEXT, test_date TEXT, subject TEXT, max_score INTEGER DEFAULT 100, score INTEGER, comment TEXT, created_by TEXT, created_at TEXT)").run() } catch {}
  const testName = String(body.testName || '').slice(0, 120)
  const testDate = String(body.testDate || '').slice(0, 40)
  const subject = String(body.subject || '').slice(0, 40)
  const maxScore = Math.max(1, parseInt(String(body.maxScore || 100), 10) || 100)
  const nowIso = new Date().toISOString()
  let saved = 0
  for (const it of body.rows) {
    const uid = String((it && it.userId) || '')
    if (!uid || !allowed.has(uid)) continue
    const sc = parseInt(String(it && it.score), 10)
    if (isNaN(sc)) continue
    await c.env.DB.prepare('INSERT INTO student_test_scores (user_id, test_name, test_date, subject, max_score, score, comment, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?)').bind(uid, testName, testDate, subject, maxScore, sc, String((it && it.comment) || ''), u.id, nowIso).run()
    saved++
  }
  return c.json({ ok: true, saved })
})

// ===== 学習の記録（ポートフォリオ）取り込みAPI =====
function _recNorm(s){ return String(s==null?'':s).replace(/[Ａ-Ｚａ-ｚ０-９]/g,function(ch){return String.fromCharCode(ch.charCodeAt(0)-65248);}).replace(/[ 　]/g,'').toLowerCase(); }
function _recHalfDate(v){ var s=String(v==null?'':v).replace(/[０-９]/g,function(ch){return String.fromCharCode(ch.charCodeAt(0)-65248);}); s=s.split('年').join('-').split('月').join('-').split('日').join('').split('/').join('-').split('.').join('-').trim(); if(s.charAt(s.length-1)==='-') s=s.slice(0,-1); return s; }
function _recNormRank(v){ var s=String(v==null?'':v); if(s.indexOf('◎')>=0) return '◎'; if(s.indexOf('○')>=0||s.indexOf('〇')>=0) return '○'; if(s.indexOf('△')>=0) return '△'; var t=s.toUpperCase(); if(t.indexOf('A')>=0) return '◎'; if(t.indexOf('B')>=0) return '○'; if(t.indexOf('C')>=0) return '△'; return ''; }
function _recParseText(text){
  var NL=String.fromCharCode(10);
  var lines=String(text||'').split(NL);
  var blocks=[]; var cur=null; var sec=null;
  for(var i=0;i<lines.length;i++){
    var rawLine=String(lines[i]==null?'':lines[i]);
    var line=rawLine.trim();
    var mk=line.match(/^===\s*\[([^\]]*)\]\s*(.*?)\s*===$/);
    if(mk){ if(cur) blocks.push(cur); cur={ idRaw:String(mk[1]||'').trim(), nameRaw:String(mk[2]||'').trim(), title:'', day:'', subject:'', unit:'', body:'', reflection:'', evalRank:'', evalComment:'' }; sec=null; continue; }
    if(!cur) continue;
    var ci=line.indexOf('：'); if(ci<0) ci=line.indexOf(':');
    var handled=false;
    if(ci>=0&&ci<=14){
      var k=line.slice(0,ci).replace(/[ 　]/g,'');
      var v=line.slice(ci+1).trim();
      if(k.indexOf('タイトル')>=0||k.indexOf('題名')>=0){ cur.title=v; sec=null; handled=true; }
      else if(k.indexOf('日付')>=0||k.indexOf('日時')>=0||k.indexOf('実施日')>=0){ cur.day=_recHalfDate(v); sec=null; handled=true; }
      else if(k.indexOf('教科')>=0||k.indexOf('科目')>=0){ cur.subject=v; sec=null; handled=true; }
      else if(k.indexOf('単元')>=0){ cur.unit=v; sec=null; handled=true; }
      else if(k.indexOf('評価コメント')>=0||k.indexOf('評価メモ')>=0){ cur.evalComment=v; sec='evalComment'; handled=true; }
      else if(k.indexOf('評価')>=0){ cur.evalRank=_recNormRank(v); sec=null; handled=true; }
      else if(k.indexOf('振り返り')>=0||k.indexOf('ふりかえり')>=0){ sec='reflection'; if(v){ cur.reflection+=v; } handled=true; }
      else if(k.indexOf('本文')>=0||k.indexOf('内容')>=0||k.indexOf('成果物')>=0){ sec='body'; if(v){ cur.body+=v; } handled=true; }
    }
    if(handled) continue;
    if(sec==='body'){ cur.body += (cur.body?NL:'') + rawLine; }
    else if(sec==='reflection'){ cur.reflection += (cur.reflection?NL:'') + rawLine; }
    else if(sec==='evalComment'){ cur.evalComment += (cur.evalComment?NL:'') + rawLine; }
  }
  if(cur) blocks.push(cur);
  for(var b=0;b<blocks.length;b++){ blocks[b].body=String(blocks[b].body||'').replace(/\s+$/,''); blocks[b].reflection=String(blocks[b].reflection||'').replace(/\s+$/,''); blocks[b].evalComment=String(blocks[b].evalComment||'').replace(/\s+$/,''); }
  return blocks;
}
app.post('/api/teacher/records/parse', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json().catch(() => null)
  if (!body || typeof body.text !== 'string') return jsonError(c, 400, 'invalid')
  const classId = String(body.classId || '')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const roster = (((await c.env.DB.prepare('SELECT u.id, u.login_id as loginId, u.name FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=?').bind(classId).all<any>()).results) || [])
  const idx: Record<string, string> = {}
  for (const m of roster as any[]) { if (m.name) idx[_recNorm(m.name)] = m.id; if (m.loginId) idx[_recNorm(m.loginId)] = m.id }
  const blocks = _recParseText(body.text)
  const rows = blocks.map((bk: any) => {
    const keyId = _recNorm(bk.idRaw); const keyNm = _recNorm(bk.nameRaw)
    let uid: string | null = idx[keyId] || idx[keyNm] || null
    if (!uid && keyNm) { for (const m of roster as any[]) { const nn = _recNorm(m.name); if (nn && (nn.indexOf(keyNm) >= 0 || keyNm.indexOf(nn) >= 0)) { uid = m.id; break } } }
    const mm = uid ? (roster as any[]).find((x: any) => x.id === uid) : null
    return { idRaw: bk.idRaw, nameRaw: bk.nameRaw, title: bk.title, day: bk.day, subject: bk.subject, unit: bk.unit, body: bk.body, reflection: bk.reflection, evalRank: bk.evalRank, evalComment: bk.evalComment, matchedUserId: uid, matchedName: mm ? mm.name : null }
  })
  return c.json({ ok: true, rows, roster: (roster as any[]).map((m: any) => ({ userId: m.id, name: m.name, loginId: m.loginId })) })
})
app.post('/api/teacher/records/save', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json().catch(() => null)
  if (!body || !Array.isArray(body.rows)) return jsonError(c, 400, 'invalid')
  const classId = String(body.classId || '')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const mem = (((await c.env.DB.prepare('SELECT user_id as uid FROM class_members WHERE class_id=?').bind(classId).all<any>()).results) || [])
  const allowed = new Set((mem as any[]).map((r: any) => String(r.uid)))
  try { await c.env.DB.prepare("CREATE TABLE IF NOT EXISTS student_records (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, class_id TEXT, type TEXT, title TEXT, body TEXT, subject TEXT, unit TEXT, day_key TEXT, created_by TEXT, created_at TEXT)").run() } catch {}
  try { await c.env.DB.prepare("ALTER TABLE student_records ADD COLUMN reflection TEXT").run() } catch {}
  try { await c.env.DB.prepare("ALTER TABLE student_records ADD COLUMN eval_rank TEXT").run() } catch {}
  try { await c.env.DB.prepare("ALTER TABLE student_records ADD COLUMN eval_comment TEXT").run() } catch {}
  const allowTypes = new Set(['report', 'reflect', 'other'])
  let rtype = String(body.type || 'report'); if (!allowTypes.has(rtype)) rtype = 'other'
  const nowIso = new Date().toISOString()
  let saved = 0
  for (const it of body.rows) {
    const uid = String((it && it.userId) || '')
    if (!uid || !allowed.has(uid)) continue
    const title = String((it && it.title) || '').slice(0, 200)
    const bodyTxt = String((it && it.body) || '').slice(0, 8000)
    const reflection = String((it && it.reflection) || '').slice(0, 8000)
    const evalRankRaw = String((it && it.evalRank) || '').trim(); const _ranks = new Set(['◎','○','△']); const evalRank = _ranks.has(evalRankRaw) ? evalRankRaw : ''
    const evalComment = String((it && it.evalComment) || '').slice(0, 2000)
    if (!title && !bodyTxt && !reflection && !evalRank && !evalComment) continue
    const subj = String((it && it.subject) || '').slice(0, 40)
    const unit = String((it && it.unit) || '').slice(0, 80)
    const day = String((it && it.day) || '').slice(0, 40)
    await c.env.DB.prepare('INSERT INTO student_records (user_id, class_id, type, title, body, reflection, eval_rank, eval_comment, subject, unit, day_key, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(uid, classId, rtype, title, bodyTxt, reflection, evalRank, evalComment, subj, unit, day, u.id, nowIso).run()
    saved++
  }
  return c.json({ ok: true, saved })
})
// ===== 授業メモAPI（クラス全体メモ＋児童ごとメモ・教師は自分のクラスのみ） =====
app.get('/api/teacher/class-notes', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = String(c.req.query('classId') || '')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  let notes: any[] = []
  try { const r = await c.env.DB.prepare("SELECT day_key, body FROM teacher_class_notes WHERE class_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC").bind(classId).all<any>(); notes = (((r && r.results) || []) as any[]).map((x: any) => ({ dayKey: x.day_key, body: x.body })) } catch {}
  const roster = (((await c.env.DB.prepare('SELECT u.id as userId, u.login_id as loginId, u.name FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=? ORDER BY u.name').bind(classId).all<any>()).results) || [])
  return c.json({ ok: true, notes, roster })
})
app.post('/api/teacher/class-notes', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid')
  const classId = String(body.classId || '')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const txt = String(body.body || '').slice(0, 2000)
  if (!txt.trim()) return jsonError(c, 400, 'empty')
  try { await c.env.DB.prepare("CREATE TABLE IF NOT EXISTS teacher_class_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, class_id TEXT NOT NULL, day_key TEXT, body TEXT, created_by TEXT, created_at TEXT)").run() } catch {}
  await c.env.DB.prepare('INSERT INTO teacher_class_notes (class_id, day_key, body, created_by, created_at) VALUES (?,?,?,?,?)').bind(classId, String(body.dayKey || '').slice(0, 40), txt, u.id, new Date().toISOString()).run()
  return c.json({ ok: true })
})
app.get('/api/teacher/student-notes', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const studentId = String(c.req.query('studentId') || '')
  const allowed = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM users WHERE id=? LIMIT 1').bind(studentId).first<any>()
    : await c.env.DB.prepare('SELECT u.id FROM users u JOIN class_members cm ON cm.user_id=u.id JOIN classes cl ON cl.id=cm.class_id AND cl.teacher_id=? WHERE u.id=? LIMIT 1').bind(u.id, studentId).first<any>()
  if (!allowed) return jsonError(c, 404, 'student_not_found')
  let notes: any[] = []
  try { const r = await c.env.DB.prepare("SELECT day_key, body, show_in_karte FROM teacher_student_notes WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC").bind(studentId).all<any>(); notes = (((r && r.results) || []) as any[]).map((x: any) => ({ dayKey: x.day_key, body: x.body, showInKarte: !!x.show_in_karte })) } catch {}
  return c.json({ ok: true, notes })
})
app.post('/api/teacher/student-notes', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid')
  const studentId = String(body.studentId || '')
  const mem = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT cm.class_id as classId FROM class_members cm WHERE cm.user_id=? LIMIT 1').bind(studentId).first<any>()
    : await c.env.DB.prepare('SELECT cm.class_id as classId FROM class_members cm JOIN classes cl ON cl.id=cm.class_id AND cl.teacher_id=? WHERE cm.user_id=? LIMIT 1').bind(u.id, studentId).first<any>()
  if (!mem) return jsonError(c, 404, 'student_not_found')
  const txt = String(body.body || '').slice(0, 2000)
  if (!txt.trim()) return jsonError(c, 400, 'empty')
  try { await c.env.DB.prepare("CREATE TABLE IF NOT EXISTS teacher_student_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, class_id TEXT, day_key TEXT, body TEXT, show_in_karte INTEGER DEFAULT 0, created_by TEXT, created_at TEXT)").run() } catch {}
  const showK = (body.showInKarte === 1 || body.showInKarte === true || body.showInKarte === '1') ? 1 : 0
  await c.env.DB.prepare('INSERT INTO teacher_student_notes (user_id, class_id, day_key, body, show_in_karte, created_by, created_at) VALUES (?,?,?,?,?,?,?)').bind(studentId, String(mem.classId || ''), String(body.dayKey || '').slice(0, 40), txt, showK, u.id, new Date().toISOString()).run()
  return c.json({ ok: true })
})

// ===== 復習おすすめAPI（忘れかけ単元の検出・児童本人のみ） =====
app.get('/api/student/review-suggestions', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  let grade: number | null = null
  try { const gr = await c.env.DB.prepare('SELECT grade FROM users WHERE id=? LIMIT 1').bind(u.id).first<any>(); grade = gr ? gr.grade : null } catch {}
  let rows: any[] = []
  try { const r = await c.env.DB.prepare("SELECT unit, COUNT(*) as n, SUM(is_correct) as cor, MAX(answered_at) as last_at FROM learning_results WHERE user_id=? GROUP BY unit").bind(u.id).all<any>(); rows = (((r && r.results) || []) as any[]) } catch {}
  const now = Date.now(); const dayMs = 86400000
  const ug = (id: string) => { id = String(id || ''); const c0 = id.charAt(0); if ((c0 === 'm' || c0 === 'j' || c0 === 'r' || c0 === 's') && id.charAt(2) === '-') { const dch = id.charAt(1); if (dch >= '1' && dch <= '6') return parseInt(dch, 10) } return null }
  const thr = (acc: number) => acc >= 0.9 ? 21 : acc >= 0.8 ? 14 : acc >= 0.6 ? 7 : 4
  const items: any[] = []
  for (const row of rows) {
    const n = row.n || 0; if (n < 4) continue
    const acc = n ? (row.cor || 0) / n : 0
    const last = row.last_at ? Date.parse(row.last_at) : 0; if (!last) continue
    const daysSince = Math.floor((now - last) / dayMs); const th = thr(acc)
    if (daysSince <= th) continue
    const gu = ug(row.unit); const launchable = gu != null
    const isReview = (grade != null && gu != null) ? (gu < grade) : false
    const isSame = (grade != null && gu != null) ? (gu === grade) : false
    items.push({ unit: row.unit, acc: Math.round(acc * 100), daysSince, threshold: th, gradeOfUnit: gu, isReview, isSame, launchable })
  }
  items.sort((a, b) => { if (a.isSame !== b.isSame) return a.isSame ? -1 : 1; if (a.isReview !== b.isReview) return a.isReview ? 1 : -1; return (b.daysSince / b.threshold) - (a.daysSince / a.threshold) })
  return c.json({ ok: true, grade, suggestions: items.slice(0, 8) })
})

app.get('/api/student/weak-units', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  let grade: number | null = null
  try { const gr = await c.env.DB.prepare('SELECT grade FROM users WHERE id=? LIMIT 1').bind(u.id).first<any>(); grade = gr ? gr.grade : null } catch {}
  let rows: any[] = []
  try { const r = await c.env.DB.prepare("SELECT unit, COUNT(*) as n, SUM(is_correct) as cor FROM learning_results WHERE user_id=? GROUP BY unit").bind(u.id).all<any>(); rows = (((r && r.results) || []) as any[]) } catch {}
  const ug = (id: string) => { id = String(id || ''); const c0 = id.charAt(0); if ((c0 === 'm' || c0 === 'j' || c0 === 'r' || c0 === 's') && id.charAt(2) === '-') { const dch = id.charAt(1); if (dch >= '1' && dch <= '6') return parseInt(dch, 10) } return null }
  const items: any[] = []
  for (const row of rows) {
    const n = row.n || 0; if (n < 4) continue
    const acc = n ? Math.round((row.cor || 0) / n * 100) : 0
    if (acc >= 80) continue
    const gu = ug(row.unit); const launchable = gu != null
    const isReview = (grade != null && gu != null) ? (gu < grade) : false
    const isSame = (grade != null && gu != null) ? (gu === grade) : false
    items.push({ unit: row.unit, acc, n, gradeOfUnit: gu, isReview, isSame, launchable })
  }
  items.sort((a, b) => { if (a.isSame !== b.isSame) return a.isSame ? -1 : 1; if (a.isReview !== b.isReview) return a.isReview ? 1 : -1; return a.acc - b.acc })
  return c.json({ ok: true, grade, weak: items.slice(0, 8) })
})

app.get('/api/teacher/early-alerts', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.query('classId')
  if (!classId) return jsonError(c, 400, 'classId required')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  let members: any = { results: [] }
  try { members = await c.env.DB.prepare('SELECT u.id, u.name, u.login_id FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=?').bind(classId).all<any>() } catch {}
  const nameMap: Record<string, any> = {}
  for (const m of (members.results || [])) nameMap[String(m.id)] = { name: m.name, loginId: m.login_id }
  let rows: any = { results: [] }
  try { rows = await c.env.DB.prepare("SELECT lr.user_id as uid, lr.unit as unit, lr.is_correct as ic, lr.answered_at as at FROM learning_results lr JOIN class_members cm ON cm.user_id=lr.user_id WHERE cm.class_id=? AND lr.answered_at >= datetime('now','-180 days') ORDER BY lr.user_id, lr.unit, lr.answered_at").bind(classId).all<any>() } catch {}
  const groups: Record<string, number[]> = {}
  for (const r of (rows.results || [])) {
    const k = String(r.uid) + '|' + String(r.unit)
    if (!groups[k]) groups[k] = []
    groups[k].push(r.ic ? 1 : 0)
  }
  const acc = (arr: number[]) => arr.length ? Math.round(arr.reduce((s, x) => s + x, 0) / arr.length * 100) : 0
  const alerts: any[] = []
  const unitAgg: Record<string, { t: number, c: number, good: number, mid: number, low: number }> = {}
  for (const k of Object.keys(groups)) {
    const arr = groups[k]
    const total = arr.length
    const sep = k.indexOf('|')
    const uid = k.slice(0, sep); const unit = k.slice(sep + 1)
    const a = acc(arr)
    if (total >= 4) {
      if (!unitAgg[unit]) unitAgg[unit] = { t: 0, c: 0, good: 0, mid: 0, low: 0 }
      unitAgg[unit].t += total
      unitAgg[unit].c += arr.reduce((s, x) => s + x, 0)
      if (a >= 80) unitAgg[unit].good++; else if (a >= 60) unitAgg[unit].mid++; else unitAgg[unit].low++
    }
    const signals: string[] = []
    if (total >= 4) {
      const last3 = arr.slice(-3)
      if (last3.length === 3 && last3[0] === 0 && last3[1] === 0 && last3[2] === 0) signals.push('consec')
    }
    if (total >= 8) {
      const half = Math.floor(total / 2)
      const ea = acc(arr.slice(0, half)); const ra = acc(arr.slice(half))
      if (ea - ra >= 15) signals.push('drop')
      if (ea >= 80 && ra < 70) signals.push('regress')
    }
    if (signals.length) {
      const half = Math.floor(total / 2)
      const ra = total >= 8 ? acc(arr.slice(half)) : null
      const nm = nameMap[uid] || {}
      alerts.push({ studentId: uid, name: nm.name || '', loginId: nm.loginId || '', unit, signals, acc: a, recentAcc: ra, total })
    }
  }
  alerts.sort((x, y) => (y.signals.length - x.signals.length) || (x.acc - y.acc))
  const mastery = Object.keys(unitAgg).map(unit => {
    const g = unitAgg[unit]
    const classAcc = g.t ? Math.round(g.c / g.t * 100) : 0
    const tier = classAcc >= 80 ? 'good' : (classAcc >= 60 ? 'mid' : 'low')
    return { unit, classAcc, tier, n: g.good + g.mid + g.low, counts: { good: g.good, mid: g.mid, low: g.low } }
  }).filter(m => m.n >= 1).sort((a, b) => a.classAcc - b.classAcc).slice(0, 14)
  return c.json({ ok: true, alerts: alerts.slice(0, 40), mastery })
})

// ===== ラーニングアナリティクスAPI（クラス学習履歴の本格分析・集計値は再利用可能） =====
app.get('/api/teacher/learning-analytics', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.query('classId')
  if (!classId) return jsonError(c, 400, 'classId required')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const members = (((await c.env.DB.prepare('SELECT u.id, u.login_id as loginId, u.name FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=?').bind(classId).all<any>()).results) || [])
  const total = members.length
  const memQ = '(SELECT user_id FROM class_members WHERE class_id=?)'
  const subs = (((await c.env.DB.prepare('SELECT user_id, day_key, minutes, end_weather, weather_reason, submitted_at FROM homework_submissions WHERE user_id IN ' + memQ + ' ORDER BY day_key').bind(classId).all<any>()).results) || [])
  const [unitAgg, perStuLR, hourAgg] = await Promise.all([
    c.env.DB.prepare("SELECT unit, COUNT(*) as t, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as cc FROM learning_results WHERE user_id IN " + memQ + " GROUP BY unit").bind(classId).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare("SELECT user_id, COUNT(*) as t, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as cc FROM learning_results WHERE user_id IN " + memQ + " GROUP BY user_id").bind(classId).all<any>().catch(() => ({ results: [] })),
    c.env.DB.prepare("SELECT strftime('%H', datetime(answered_at, '+9 hours')) as hr, COUNT(*) as n FROM learning_results WHERE user_id IN " + memQ + " GROUP BY hr").bind(classId).all<any>().catch(() => ({ results: [] })),
  ])
  const dayMs = 86400000
  const todayMs = Date.now()
  const dkMs = (dk: string) => new Date(dk + 'T00:00:00Z').getTime()
  const isoWeek = (dk: string) => { const d = new Date(dk + 'T00:00:00Z'); const wd = (d.getUTCDay() + 6) % 7; d.setUTCDate(d.getUTCDate() - wd); return d.toISOString().slice(0, 10) }
  // Area1 continuity
  const byStu: Record<string, string[]> = {}
  for (const s of subs) { if (!s.day_key) continue; (byStu[s.user_id] = byStu[s.user_id] || []).push(s.day_key) }
  const perStudent = members.map((m: any) => {
    const days = Array.from(new Set(byStu[m.id] || [])).sort()
    let maxStreak = 0, run = 0, prev = ''
    for (const dk of days) { if (prev && Math.round((dkMs(dk) - dkMs(prev)) / dayMs) === 1) run++; else run = 1; if (run > maxStreak) maxStreak = run; prev = dk }
    let currentStreak = 0
    if (days.length) { const since = Math.round((todayMs - dkMs(days[days.length - 1])) / dayMs); if (since <= 1) currentStreak = run }
    const recent7 = days.filter(dk => (todayMs - dkMs(dk)) <= 7 * dayMs).length
    const prev7 = days.filter(dk => { const a = todayMs - dkMs(dk); return a > 7 * dayMs && a <= 14 * dayMs }).length
    const dropping = (prev7 >= 2 && recent7 <= Math.floor(prev7 / 2)) || (prev7 >= 3 && recent7 === 0)
    return { userId: m.id, name: m.name, loginId: m.loginId, submissions: days.length, currentStreak, maxStreak, recent7, prev7, dropping }
  })
  const droppingStudents = perStudent.filter((p: any) => p.dropping).map((p: any) => ({ userId: p.userId, name: p.name, loginId: p.loginId, recent7: p.recent7, prev7: p.prev7 }))
  const wkSet: Record<string, Set<string>> = {}
  for (const s of subs) { if (!s.day_key) continue; const w = isoWeek(s.day_key); (wkSet[w] = wkSet[w] || new Set()).add(s.user_id) }
  const weeklyRate = Object.keys(wkSet).sort().slice(-10).map(w => ({ week: w, submitted: wkSet[w].size, total, rate: total ? Math.round(wkSet[w].size / total * 100) : 0 }))
  // Area2 subjects
  const perUnit = ((unitAgg.results || []) as any[]).map(r => ({ unit: r.unit, total: r.t, correct: r.cc, rate: r.t ? Math.round(r.cc / r.t * 100) : 0 })).sort((a, b) => b.total - a.total)
  const strong = perUnit.filter(x => x.total >= 20).sort((a, b) => b.rate - a.rate).slice(0, 5)
  const weak = perUnit.filter(x => x.total >= 20).sort((a, b) => a.rate - b.rate).slice(0, 5)
  const buckets = [0, 0, 0, 0, 0, 0]
  const bIdx = (r: number) => r >= 90 ? 5 : r >= 80 ? 4 : r >= 70 ? 3 : r >= 60 ? 2 : r >= 40 ? 1 : 0
  for (const r of (perStuLR.results || []) as any[]) { if (r.t >= 10) buckets[bIdx(Math.round(r.cc / r.t * 100))]++ }
  const distribution = [{ label: '0-39%', count: buckets[0] }, { label: '40-59%', count: buckets[1] }, { label: '60-69%', count: buckets[2] }, { label: '70-79%', count: buckets[3] }, { label: '80-89%', count: buckets[4] }, { label: '90-100%', count: buckets[5] }]
  // Area3 time
  const hourHistogram = Array.from({ length: 24 }, (_, h) => ({ hour: h, count: 0 }))
  for (const r of (hourAgg.results || []) as any[]) { const h = parseInt(r.hr, 10); if (h >= 0 && h < 24) hourHistogram[h].count = r.n }
  const dows = ['日', '月', '火', '水', '木', '金', '土']
  const wdCount = [0, 0, 0, 0, 0, 0, 0], wdMin = [0, 0, 0, 0, 0, 0, 0]
  for (const s of subs) { if (!s.day_key) continue; const d = new Date(s.day_key + 'T00:00:00Z').getUTCDay(); wdCount[d]++; wdMin[d] += (s.minutes || 0) }
  const weekdayHistogram = dows.map((nm, i) => ({ dow: nm, count: wdCount[i], avgMin: wdCount[i] ? Math.round(wdMin[i] / wdCount[i]) : 0 }))
  const wkMin: Record<string, number> = {}
  for (const s of subs) { if (!s.day_key) continue; const w = isoWeek(s.day_key); wkMin[w] = (wkMin[w] || 0) + (s.minutes || 0) }
  const weeklyMinutes = Object.keys(wkMin).sort().slice(-10).map(w => ({ week: w, avgMinPerStudent: total ? Math.round(wkMin[w] / total) : 0 }))
  const totMin = subs.reduce((a: number, s: any) => a + (s.minutes || 0), 0)
  const avgMinPerSubmission = subs.length ? Math.round(totMin / subs.length) : 0
  // Area4 satisfaction
  let sun = 0, cloud = 0, rain = 0
  for (const s of subs) { if (s.end_weather === 'sun') sun++; else if (s.end_weather === 'cloud') cloud++; else if (s.end_weather === 'rain') rain++ }
  const wkW: Record<string, any> = {}
  for (const s of subs) { if (!s.day_key || !s.end_weather) continue; const w = isoWeek(s.day_key); const o = wkW[w] = wkW[w] || { sun: 0, cloud: 0, rain: 0 }; if (s.end_weather === 'sun') o.sun++; else if (s.end_weather === 'cloud') o.cloud++; else if (s.end_weather === 'rain') o.rain++ }
  const satWeekly = Object.keys(wkW).sort().slice(-10).map(w => { const o = wkW[w]; const t = o.sun + o.cloud + o.rain; return { week: w, sun: o.sun, cloud: o.cloud, rain: o.rain, sunRate: t ? Math.round(o.sun / t * 100) : 0 } })
  const stop = new Set(['今日', 'こと', 'できた', 'できました', 'すること', 'した', 'やる', 'やった', '勉強', 'から', 'ので', 'けど', 'けれど', 'ちょっと', 'もっと', 'みたい', 'なので', 'ため', 'たから', 'おわった', '終わった', 'できて', 'これ', 'それ', 'です', 'ます', 'して', 'いる', 'ある', 'なる', 'ない', 'よう', 'たい', 'たくさん', 'すごく', 'とても', 'まあ', 'まだ', 'もう', 'また'])
  const freq: Record<string, number> = {}
  for (const s of subs) {
    const tx = String(s.weather_reason || '')
    if (!tx) continue
    const toks = tx.split(/[^぀-ヿ一-鿿]+/)
    for (const tk of toks) { if (tk.length >= 2 && tk.length <= 6 && !stop.has(tk)) freq[tk] = (freq[tk] || 0) + 1 }
  }
  const keywords = Object.keys(freq).map(w => ({ word: w, count: freq[w] })).sort((a, b) => b.count - a.count).slice(0, 20)
  // Area5 relation
  const minByStu: Record<string, number> = {}, wByStu: Record<string, any> = {}
  for (const s of subs) { minByStu[s.user_id] = (minByStu[s.user_id] || 0) + (s.minutes || 0); const o = wByStu[s.user_id] = wByStu[s.user_id] || { sun: 0, n: 0 }; if (s.end_weather) { o.n++; if (s.end_weather === 'sun') o.sun++ } }
  const lrByStu: Record<string, any> = {}
  for (const r of (perStuLR.results || []) as any[]) lrByStu[r.user_id] = r
  const scatter = members.map((m: any) => { const lr = lrByStu[m.id]; const w = wByStu[m.id]; return { name: m.name, problems: lr ? lr.t : 0, minutes: minByStu[m.id] || 0, rate: (lr && lr.t) ? Math.round(lr.cc / lr.t * 100) : null, sunRate: (w && w.n) ? Math.round(w.sun / w.n * 100) : null } }).filter((x: any) => x.problems > 0 || x.minutes > 0)
  const pts = scatter.filter((x: any) => x.rate != null && x.problems > 0)
  let corr = null as number | null
  if (pts.length >= 3) {
    const n = pts.length; const xs = pts.map((p: any) => p.problems), ys = pts.map((p: any) => p.rate)
    const mx = xs.reduce((a: number, b: number) => a + b, 0) / n, my = ys.reduce((a: number, b: number) => a + b, 0) / n
    let sxy = 0, sxx = 0, syy = 0
    for (let i = 0; i < n; i++) { const dx = xs[i] - mx, dy = ys[i] - my; sxy += dx * dy; sxx += dx * dx; syy += dy * dy }
    corr = (sxx > 0 && syy > 0) ? Math.round(sxy / Math.sqrt(sxx * syy) * 100) / 100 : null
  }
  let testsBySubject: any[] = []
  try { const _tsa = await c.env.DB.prepare("SELECT subject, COUNT(*) as n, AVG(CASE WHEN max_score>0 THEN score*100.0/max_score ELSE NULL END) as avgpct FROM student_test_scores WHERE user_id IN " + memQ + " GROUP BY subject").bind(classId).all<any>(); testsBySubject = (((_tsa && _tsa.results) || []) as any[]).map((r: any) => ({ subject: r.subject || '(教科なし)', count: r.n, avgPct: (r.avgpct != null ? Math.round(r.avgpct) : null) })) } catch {}
  return c.json({
    ok: true, classId, className: cls.name, studentCount: total, generatedAt: new Date().toISOString(),
    continuity: { perStudent, droppingStudents, weeklyRate },
    subjects: { perUnit, strong, weak, distribution },
    time: { hourHistogram, weekdayHistogram, weeklyMinutes, avgMinPerSubmission },
    satisfaction: { overall: { sun, cloud, rain }, weekly: satWeekly, keywords },
    relation: { scatter, correlation: corr },
    tests: { bySubject: testsBySubject },
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
    SELECT u.id, u.login_id as loginId, u.name FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=?
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
      SELECT lr.user_id, lr.unit, COUNT(*) as total, SUM(CASE WHEN lr.is_correct=1 THEN 1 ELSE 0 END) as correct_count
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
      userId: m.id,
      loginId: m.loginId,
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
    case 'typeshoot': orderCol = 'rs.typeshoot_score'; break
  }

  // 週間の場合は差分で並べ替え
  if (period === 'weekly') {
    switch (type) {
      case 'overall': extraSelect = ', (rs.total_level - rs.week_base_total_level) as weeklyScore'; orderCol = 'weeklyScore'; break
      case 'power': extraSelect = ', (rs.battle_power - rs.week_base_battle_power) as weeklyScore'; orderCol = 'weeklyScore'; break
      case 'correct': case 'grade': extraSelect = ', ROUND(rs.ranking_points - rs.week_base_ranking_points, 1) as weeklyScore'; orderCol = 'weeklyScore'; break
      case 'pokedex': extraSelect = ', (rs.pokedex_count - rs.week_base_pokedex_count) as weeklyScore'; orderCol = 'weeklyScore'; break
      case 'wild': extraSelect = ', (rs.wild_win_streak - rs.week_base_wild_win_streak) as weeklyScore'; orderCol = 'weeklyScore'; break
      case 'typeshoot': extraSelect = ', rs.typeshoot_score as weeklyScore'; orderCol = 'weeklyScore'; break
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
    rs.grade, rs.battle_power as battlePower, rs.pokedex_count as pokedexCount, rs.wild_win_streak as wildWinStreak, rs.typeshoot_score as typeShootScore
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
       self_study_plan, weekly_plan, weekly_reflection, work_photo_analysis, parent_comment)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
    String(body.workPhotoAnalysis || '').slice(0, 500),
    String(body.parentComment || '').slice(0, 500)
  ).run()

  // ── 提出即コイン：クライアント側で即付与するため、サーバーはclaimed済みにマーク ──
  // （実際のコイン付与はクライアントのhsGrantRewardsで行う。
  //   progress.state_jsonは二重付与防止のため触らない）
  try {
    await c.env.DB.prepare(`UPDATE homework_submissions SET reward_claimed=1, reward_claimed_at=? WHERE id=?`).bind(Date.now(), id).run()
  } catch (e) { console.error('instant reward mark error:', e) }

  return c.json({ ok: true, id, instantReward: true })
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

    // D1のhomework_photosテーブルにBLOBとして写真を保存（R2の代わり）
    const ext = mimeType === 'image/png' ? 'png' : 'jpg'
    const photoKey = `photos/${u.id}/${dayKey}.${ext}` // work_photo_key用マーカー（teacher dashboardの<img>表示条件）
    try {
      await c.env.DB.prepare(
        `INSERT INTO homework_photos (user_id, day_key, mime_type, bytes, byte_size)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(user_id, day_key) DO UPDATE SET
           mime_type=excluded.mime_type, bytes=excluded.bytes, byte_size=excluded.byte_size, created_at=datetime('now')`
      ).bind(u.id, dayKey, mimeType, imageBytes, imageBytes.length).run()
      // homework_submissions にもキーマーカーを記録
      const existing0 = await c.env.DB.prepare(
        `SELECT id FROM homework_submissions WHERE user_id=? AND day_key=? LIMIT 1`
      ).bind(u.id, dayKey).first<any>()
      if (existing0) {
        await c.env.DB.prepare(
          `UPDATE homework_submissions SET work_photo_key=? WHERE id=?`
        ).bind(photoKey, existing0.id).run()
      }
    } catch (dbErr: any) {
      console.error('D1 photo save error:', dbErr?.message || dbErr)
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

    // Lazy cleanup: 180日経過した写真をバックグラウンドで削除
    try { (c as any).executionCtx?.waitUntil?.(cleanupOldPhotos(c)) } catch {}
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

  // D1のhomework_photosからBLOBを取得（R2の代わり）
  try {
    const row = await c.env.DB.prepare(
      `SELECT mime_type, bytes FROM homework_photos WHERE user_id=? AND day_key=? LIMIT 1`
    ).bind(targetUserId, dayKey).first<any>()
    if (!row?.bytes) return jsonError(c, 404, 'photo_not_found')
    const headers = new Headers()
    headers.set('Content-Type', row.mime_type || 'image/jpeg')
    headers.set('Cache-Control', 'private, max-age=3600')
    return new Response(row.bytes as ArrayBuffer, { headers })
  } catch (e: any) {
    console.error('photo fetch error:', e?.message || e)
    return jsonError(c, 500, 'photo_error')
  }
})

// ----- 写真クリーンアップ: 180日経過したBLOBを削除（AI分析テキストは残す） -----
async function cleanupOldPhotos(c: any) {
  try {
    // work_photo_keyマーカーを先にクリア（壊れた画像アイコンを防ぐ）
    await c.env.DB.prepare(
      `UPDATE homework_submissions SET work_photo_key=''
       WHERE work_photo_key != ''
       AND user_id || '/' || day_key IN (
         SELECT user_id || '/' || day_key FROM homework_photos
         WHERE created_at < datetime('now', '-180 days')
       )`
    ).run()
    const result = await c.env.DB.prepare(
      `DELETE FROM homework_photos WHERE created_at < datetime('now', '-180 days')`
    ).run()
    if (result.meta?.changes) {
      console.log('[cleanupOldPhotos] deleted ' + result.meta.changes + ' photos older than 180 days')
    }
  } catch (e: any) {
    console.error('[cleanupOldPhotos] error:', e?.message || e)
  }
}

// 教師・管理者から手動でクリーンアップ実行
app.post('/api/admin/cleanup-old-photos', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'admin' && u.role !== 'teacher')) return jsonError(c, 403, 'forbidden')
  await cleanupOldPhotos(c)
  const stats = await c.env.DB.prepare(
    `SELECT COUNT(*) as count, COALESCE(SUM(byte_size),0) as totalBytes FROM homework_photos`
  ).first<any>()
  return c.json({ ok: true, remaining: { count: stats?.count || 0, totalBytes: stats?.totalBytes || 0 } })
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
           hs.parent_comment as parentComment,
           u.id as userId, u.login_id as loginId, u.name as studentName, u.grade, u.class_name as className
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

  // ── 先生ボーナス：返却時に自動でコインを付与 ──
  const TEACHER_BONUS = 150
  const PHYSICAL_BONUS = 100  // 成果物ありなら追加
  try {
    const sub = await c.env.DB.prepare(`SELECT user_id FROM homework_submissions WHERE id=?`).bind(hwId).first<any>()
    if (sub?.user_id) {
      const bonusAmount = TEACHER_BONUS + (body.hasPhysical ? PHYSICAL_BONUS : 0)
      const prog = await c.env.DB.prepare(`SELECT state_json FROM progress WHERE user_id=?`).bind(sub.user_id).first<any>()
      if (prog?.state_json) {
        const state = JSON.parse(prog.state_json)
        state.coins = (Number(state.coins) || 0) + bonusAmount
        await c.env.DB.prepare(`UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?`).bind(JSON.stringify(state), sub.user_id).run()
      }
    }
  } catch (e) { console.error('teacher bonus error:', e) }

  return c.json({ ok: true })
})

// AIで一括コメント生成（家庭学習の日々の振り返り）
app.post('/api/teacher/homework-ai-comments', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body?.classId) return jsonError(c, 400, 'classId required')

  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, teacher_id FROM classes WHERE id=? LIMIT 1').bind(body.classId).first<any>()
    : await c.env.DB.prepare('SELECT id, teacher_id FROM classes WHERE id=? AND teacher_id=?').bind(body.classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const teacherId = cls.teacher_id || u.id

  const subs = await c.env.DB.prepare(`
    SELECT hs.id, hs.user_id, hs.todo, hs.why, hs.aim, hs.minutes, hs.end_weather,
           hs.weather_reason, hs.next_improve, hs.weekly_reflection, hs.day_key, u.name, u.grade,
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
    return `${i+1}. 【${s.name}】${s.grade ? s.grade + '年生 ' : ''}(${s.day_key})
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

  // この先生（teacherId）の過去コメントをランダムに最大15件取得 → AIに口調を学習させる Few-shot examples
  let styleExamples = ''
  try {
    const ex = await c.env.DB.prepare(`
      SELECT DISTINCT TRIM(teacher_comment) AS comment
      FROM homework_submissions
      WHERE teacher_id = ?
        AND teacher_comment IS NOT NULL
        AND LENGTH(TRIM(teacher_comment)) BETWEEN 15 AND 200
      ORDER BY RANDOM() LIMIT 15
    `).bind(teacherId).all<any>()
    if (ex.results?.length) {
      styleExamples = ex.results.map((r: any) => '- 「' + r.comment + '」').join('\n')
    }
  } catch (e: any) {
    console.warn('[homework-ai-comments] style examples fetch error:', e?.message || e)
  }

  const examplesBlock = styleExamples
    ? `\n【この先生の実際のコメント例 — 必ずこの口調・テンポ・語尾を真似してください】\n${styleExamples}\n`
    : ''

  const systemPrompt = `あなたは小学校の担任の先生として、児童一人ひとりの家庭学習にコメントを書きます。
${examplesBlock}
【絶対に守るルール】
- 上記の実例と**同じ口調・語尾・テンポ・文末記号（！や〜ね、句点）**で書く
- 2〜3文、40〜100文字程度（内容が濃いほど良い）
- 児童が書いた**具体的な言葉を必ず引用**する（例：「公式集を使った」「スマホ遠ざけた」「机を片付けた」など）
- 過去の傾向データ（学習時間の変化、天気率、よくやる教科）にも触れる
- 児童の発達段階に合わせる（低学年=ひらがな多め、高学年=学習内容に踏み込む）

【コメントの作り方】
1. まず児童の記述から**一番印象的な部分**を見つけて触れる
2. 次に**過去との比較**（学習時間が増えた、新しい教科に挑戦した、連続提出が続いてる等）を加える
3. 最後に**応援や共感**で締める（ただし「がんばったね」だけで終わらない）

【絶対にやらないこと】
- 「〜ましょう」「〜してみよう」など指導的・命令調の語尾
- 「次の授業で」「先生は」のような学校目線の言い回し
- 「すごい」「がんばったね」「えらいね」だけで終わる中身のないコメント
- 全員に似たような文面を書く（一人ひとり違う内容にする）
- 児童の記述に触れない一般論

【観察のヒント】
- めあてと振り返りに一貫性があるか → あれば「めあて通りにできたんだね」と認める
- 自己評価の天気☀️🌤️☁️🌧️と振り返り内容にギャップがあれば、優しく寄り添う
- 学習時間の増減・新しい教科への挑戦は積極的に拾う
- 振り返りに「できなかった」「むずかしかった」が出てきたら、否定せず「そこに気づけるのがすごい」と返す
- 成果物の写真分析がある場合は、その内容にも具体的に触れる

【返答形式】
{"comments":["コメント1","コメント2",...]}
必ずこのJSONだけ。説明文・前置き・コードブロック不要。`

  // Gemini API → 失敗時は Cloudflare Workers AI にフォールバック
  const geminiKey = c.env.GEMINI_API_KEY || ''
  let parsed: string[] = []
  let aiSource = 'gemini'

  if (geminiKey) {
    try {
      const resp = await callGemini(c.env, {
        system_instruction: { parts: [{ text: systemPrompt }] },
        contents: [{ parts: [{ text: lines }] }],
        generationConfig: { temperature: 0.85, maxOutputTokens: 5000 }
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
      let ud = `${s.grade ? s.grade + '年生 / ' : ''}学習: ${s.todo || '未記入'}, ${s.minutes || 0}分(平均${avgMin}分), 振り返り: ${s.weather_reason || '未記入'}`
      if (s.work_photo_analysis) ud += `, 成果物: ${s.work_photo_analysis}`
      try {
        const aiRes: any = await c.env.AI.run('@cf/meta/llama-3.1-8b-instruct-fast', {
          messages: [
            { role: 'system', content: 'あなたは小学校の担任の先生です。児童の家庭学習に温かく具体的なコメントを1つだけ出力。50〜100文字。児童が書いた「やったこと」「めあて」「振り返り」の具体的な言葉を引用して触れる。学習時間の変化にも言及する。「すごいね」「がんばったね」だけのコメントは絶対NG。名前不要。コメントだけ出力。' },
            { role: 'user', content: ud }
          ],
          max_tokens: 150,
        })
        let t = (aiRes.response || '').trim().replace(/^["「『【]+|["」』】]+$/g, '').replace(/^\d+[\.\)]\s*/, '').replace(/^コメント[:：]\s*/,'').trim()
        parsed.push(t.slice(0, 120))
      } catch { parsed.push('') }
    }
  }

  const comments = subs.results.map((s: any, i: number) => ({
    id: s.id, name: s.name, dayKey: s.day_key, comment: (parsed[i] || '').replace(/^["「]+|["」]+$/g, '').slice(0, 120)
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

function getNextWeekKey(weekKey) {
  const m = weekKey.match(/^(\d{4})-W(\d{2})$/);
  if (!m) return weekKey;
  let y = parseInt(m[1]), w = parseInt(m[2]);
  w++;
  if (w > 52) { y++; w = 1; }
  return y + '-W' + String(w).padStart(2, '0');
}

// weekKeyから月曜日のDateを取得
function getMondayFromWeekKey(weekKey: string): Date {
  const m = weekKey.match(/^(\d{4})-W(\d{2})$/);
  if (!m) return new Date();
  const year = parseInt(m[1]);
  const week = parseInt(m[2]);
  // ISO: 1月4日は必ずW01に含まれる
  const jan4 = new Date(Date.UTC(year, 0, 4));
  const dayOfWeek = jan4.getUTCDay() || 7; // 月=1 ... 日=7
  const monday = new Date(jan4);
  monday.setUTCDate(jan4.getUTCDate() - dayOfWeek + 1 + (week - 1) * 7);
  return monday;
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
           SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as correct_count
    FROM learning_results WHERE user_id=? AND week_key=?
    GROUP BY unit
  `).bind(u.id, weekKey).all<any>()
  const prevWeekResults = await c.env.DB.prepare(`
    SELECT unit, COUNT(*) as total,
           SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as correct_count
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
    SELECT u.id, u.login_id as loginId, u.name, u.grade, u.class_name as className
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

  // 振り返りデータ: student_weekly_plansのplans_json内にreflectionが含まれるものを取得
  const refData = await c.env.DB.prepare(`
    SELECT swp.user_id, swp.plans_json
    FROM student_weekly_plans swp
    JOIN class_members cm ON cm.user_id = swp.user_id AND cm.class_id=?
    WHERE swp.week_key=? AND swp.plans_json LIKE '%"reflection"%'
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

  const alerts: { userId: string, loginId: string, name: string, type: string, detail: string }[] = []
  for (const m of (members.results || [])) {
    const thisW = thisHwByUser[m.id]
    const prevW = prevHwMap[m.id]
    // 提出が減った
    if (prevW && prevW.cnt >= 3 && (!thisW || thisW.cnt <= 1)) {
      alerts.push({ userId: m.id, loginId: m.loginId, name: m.name, type: 'submission_drop', detail: '先週'+prevW.cnt+'回→今週'+(thisW?.cnt||0)+'回に減少' })
    }
    // 学習時間が大幅減
    if (prevW && prevW.totalMin >= 60 && thisW && thisW.totalMin < prevW.totalMin * 0.5) {
      alerts.push({ userId: m.id, loginId: m.loginId, name: m.name, type: 'time_drop', detail: '学習時間が先週の半分以下' })
    }
    // 今週ゼロ提出
    if (!thisW && (members.results || []).length > 0) {
      alerts.push({ userId: m.id, loginId: m.loginId, name: m.name, type: 'no_submission', detail: '今週まだ提出なし' })
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

// ======== 提出状況ダッシュボード ========
app.get('/api/teacher/class/:classId/submission-dashboard', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.param('classId')
  const weekKey = c.req.query('weekKey') || getWeekKey()

  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id, name FROM classes WHERE id=? AND teacher_id=?').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')

  // 児童一覧
  const members = await c.env.DB.prepare(`
    SELECT u.id, u.login_id as loginId, u.name
    FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id=?
    ORDER BY u.name
  `).bind(classId).all<any>()

  // 週の月曜日〜日曜日の日付範囲を計算
  const monday = getMondayFromWeekKey(weekKey)
  const sunday = new Date(monday)
  sunday.setUTCDate(monday.getUTCDate() + 6)
  const mondayStr = monday.toISOString().split('T')[0]
  const sundayStr = sunday.toISOString().split('T')[0]

  // 今週の毎日の振り返り（日別）
  let dailySubs: any = { results: [] }
  try {
    dailySubs = await c.env.DB.prepare(`
      SELECT hs.user_id, hs.day_key, hs.minutes, hs.end_weather, hs.returned_at, hs.teacher_comment
      FROM homework_submissions hs
      JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
      WHERE hs.day_key >= ? AND hs.day_key <= ? ORDER BY hs.day_key
    `).bind(classId, mondayStr, sundayStr).all<any>()
  } catch {}

  // 先週の提出データ（比較用）
  const prevWeekKey = getPrevWeekKey(weekKey)
  const prevMonday = getMondayFromWeekKey(prevWeekKey)
  const prevSunday = new Date(prevMonday)
  prevSunday.setUTCDate(prevMonday.getUTCDate() + 6)
  const prevMondayStr = prevMonday.toISOString().split('T')[0]
  const prevSundayStr = prevSunday.toISOString().split('T')[0]
  let prevSubs: any = { results: [] }
  try {
    prevSubs = await c.env.DB.prepare(`
      SELECT hs.user_id, COUNT(*) as cnt
      FROM homework_submissions hs
      JOIN class_members cm ON cm.user_id = hs.user_id AND cm.class_id=?
      WHERE hs.day_key >= ? AND hs.day_key <= ? GROUP BY hs.user_id
    `).bind(classId, prevMondayStr, prevSundayStr).all<any>()
  } catch {}

  // 今週の計画
  let plans: any = { results: [] }
  try {
    plans = await c.env.DB.prepare(`
      SELECT user_id, revision_count, plan_approved, updated_at
      FROM student_weekly_plans
      WHERE week_key=? AND user_id IN (SELECT user_id FROM class_members WHERE class_id=?)
    `).bind(weekKey, classId).all<any>()
  } catch {}

  // 今週の振り返り: student_weekly_plansのplans_json内にreflectionが含まれるもの
  let reflections: any = { results: [] }
  try {
    reflections = await c.env.DB.prepare(`
      SELECT user_id, plans_json
      FROM student_weekly_plans
      WHERE week_key=? AND user_id IN (SELECT user_id FROM class_members WHERE class_id=?)
      AND plans_json LIKE '%"reflection"%'
    `).bind(weekKey, classId).all<any>()
  } catch {}

  // 家庭学習がある曜日
  let menu: any = null
  try {
    menu = await c.env.DB.prepare(
      'SELECT active_days FROM class_weekly_menu WHERE class_id=? AND week_key=? LIMIT 1'
    ).bind(classId, weekKey).first<any>()
  } catch {}

  // JST基準の今日
  const jstNow = new Date(Date.now() + 9 * 3600000)
  const realToday = jstNow.toISOString().split('T')[0]
  const fridayDate = new Date(monday)
  fridayDate.setUTCDate(monday.getUTCDate() + 4)
  const fridayStr = fridayDate.toISOString().split('T')[0]
  // 過去の週を見ているときは、todayKeyをその週の金曜日にする
  const todayKey = realToday > fridayStr ? fridayStr : realToday

  // 指定週の月〜金の日付を計算（weekKeyから算出）
  let activeDays = ['mon','tue','wed','thu','fri']
  try { if (menu?.active_days) activeDays = JSON.parse(menu.active_days) } catch {}
  // monday is already computed above
  const weekDays: { date: string; dayName: string; label: string; isActive: boolean; isPast: boolean }[] = []
  const dayNames = ['mon', 'tue', 'wed', 'thu', 'fri']
  const dayLabels = ['月', '火', '水', '木', '金']
  for (let i = 0; i < 5; i++) {
    const d = new Date(monday)
    d.setUTCDate(d.getUTCDate() + i)
    const dateStr = d.toISOString().split('T')[0]
    weekDays.push({
      date: dateStr,
      dayName: dayNames[i],
      label: dayLabels[i],
      isActive: activeDays.includes(dayNames[i]),
      isPast: dateStr <= todayKey,
    })
  }

  return c.json({
    ok: true, weekKey, todayKey,
    className: cls.name,
    members: members.results,
    dailySubmissions: dailySubs.results,
    prevWeekSubmissions: prevSubs.results,
    plans: plans.results,
    reflections: reflections.results,
    weekDays, activeDays,
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
      SELECT unit, COUNT(*) as total, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as correct_count
      FROM learning_results WHERE user_id=? AND week_key=? GROUP BY unit
    `).bind(m.id, weekKey).all<any>() } catch {}
    let prevResults: any = { results: [] }
    try { prevResults = await c.env.DB.prepare(`
      SELECT unit, COUNT(*) as total, SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END) as correct_count
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
           u.id as userId, u.login_id as loginId, u.name as studentName, u.grade, u.class_name as className
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
  const battleType = (body.battleType === 'egg') ? 'egg' : (body.battleType === 'gym') ? 'gym' : (body.battleType === 'shoot') ? 'shoot' : 'normal'

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
  const validEvents = ['damage', 'faint', 'win', 'lose', 'draw', 'self_damage', 'gym_ready', 'egg_battle']
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
  } else if (eventType === 'lose') {
    newStatus = 'finished'
    winner = isHost ? 'guest' : 'host'
  } else if (eventType === 'draw') {
    newStatus = 'finished'
    winner = 'draw'
  }

  // HPが0になったら自動で試合終了＋勝者確定（勝敗が宙ぶらりんになる不具合の修正）
  if (newStatus !== 'finished') {
    if (newHostHp <= 0 && newGuestHp <= 0) {
      newStatus = 'finished'; winner = 'draw'
    } else if (newGuestHp <= 0) {
      newStatus = 'finished'; winner = 'host'
    } else if (newHostHp <= 0) {
      newStatus = 'finished'; winner = 'guest'
    }
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
    `SELECT cnr.user_id as userId, cnr.read_at as readAt, cnr.reward_claimed as rewardClaimed, u.login_id as loginId, u.name as studentName
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
  let newCoinTotal: number | null = null
  let contactApplied: number | null = null
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
  // ★ コインをサーバー側で progress.state_json に直接加算（クライアント保存ミスでも消えないように）
  if (reward > 0) {
    let coinApplyOk = false
    try {
      const prog = await c.env.DB.prepare(`SELECT state_json FROM progress WHERE user_id=?`).bind(u.id).first<any>()
      if (prog?.state_json) {
        const state = JSON.parse(prog.state_json)
        state.coins = (Number(state.coins) || 0) + reward
        state._contactCoinsApplied = (Number(state._contactCoinsApplied) || 0) + reward
        newCoinTotal = state.coins
        contactApplied = state._contactCoinsApplied
        await c.env.DB.prepare(
          `UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?`
        ).bind(JSON.stringify(state), u.id).run()
        coinApplyOk = true
      } else {
        // progressがまだ無い児童はクライアント側加算に任せる（従来動作）
        coinApplyOk = true
      }
    } catch (e: any) {
      console.error('[contact-note/read] coin apply error:', e?.message || e)
    }
    if (!coinApplyOk) {
      // コイン加算に失敗 → 既読記録を残さずリトライ可能にする（コインを失わせない）
      return jsonError(c, 500, 'coin_apply_failed')
    }
  }
  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO contact_note_reads (user_id, note_id, reward_claimed) VALUES (?,?,?)`
  ).bind(u.id, noteId, rewardClaimed).run()
  return c.json({ ok: true, reward, rewardClaimed: !!rewardClaimed, newCoins: newCoinTotal, contactCoinsApplied: contactApplied })
})

// -------------------- API: クラス共同ミッション (class missions) --------------------

// ミッション期間中のクラス合計正解数を集計
async function countMissionProgress(c: any, classId: string, startAt: string, endAt: string | null): Promise<number> {
  let sql = `SELECT COUNT(*) AS cnt FROM learning_results lr
    JOIN class_members cm ON cm.user_id = lr.user_id AND cm.class_id = ?
    WHERE lr.is_correct = 1 AND lr.answered_at >= ?`
  const binds: any[] = [classId, startAt]
  if (endAt) { sql += ` AND lr.answered_at <= ?`; binds.push(endAt) }
  const row = await c.env.DB.prepare(sql).bind(...binds).first<any>()
  return Number(row?.cnt || 0)
}

// 教師: クラスミッションを作成
app.post('/api/teacher/class-mission', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const body = await c.req.json<any>().catch(() => null)
  if (!body?.classId) return jsonError(c, 400, 'classId required')
  const goalCorrect = Math.max(1, Number(body.goalCorrect) || 0)
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(body.classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(body.classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const id = crypto.randomUUID()
  const title = String(body.title || 'クラスミッション').slice(0, 60)
  const rewardCoins = Math.max(0, Number(body.rewardCoins) || 0)
  const rewardShards = Math.max(0, Number(body.rewardShards) || 0)
  const endAt = body.endAt ? (String(body.endAt).slice(0, 10) + ' 23:59:59') : null
  await c.env.DB.prepare(
    `INSERT INTO class_missions (id, class_id, title, goal_correct, reward_coins, reward_shards, end_at, created_by) VALUES (?,?,?,?,?,?,?,?)`
  ).bind(id, body.classId, title, goalCorrect, rewardCoins, rewardShards, endAt, u.id).run()
  return c.json({ ok: true, id })
})

// 教師: クラスミッション一覧（進捗つき）
app.get('/api/teacher/class-missions', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const classId = c.req.query('classId')
  if (!classId) return jsonError(c, 400, 'classId required')
  const rows = await c.env.DB.prepare(
    `SELECT id, title, goal_correct AS goalCorrect, reward_coins AS rewardCoins, reward_shards AS rewardShards,
            start_at AS startAt, end_at AS endAt, auto_generated AS autoGenerated, created_at AS createdAt
     FROM class_missions WHERE class_id=? ORDER BY created_at DESC LIMIT 30`
  ).bind(classId).all<any>()
  const missions: any[] = []
  for (const m of (rows.results || [])) {
    const progress = await countMissionProgress(c, classId, m.startAt, m.endAt)
    missions.push({ ...m, progress, achieved: progress >= m.goalCorrect })
  }
  return c.json({ ok: true, missions })
})

// 教師: クラスミッション削除
app.delete('/api/teacher/class-mission/:id', async (c) => {
  const u = c.get('user')
  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')
  const id = c.req.param('id')
  if (u.role !== 'admin') {
    const owned = await c.env.DB.prepare(
      `SELECT cm.id FROM class_missions cm JOIN classes cl ON cl.id=cm.class_id WHERE cm.id=? AND cl.teacher_id=?`
    ).bind(id, u.id).first<any>()
    if (!owned) return jsonError(c, 404, 'not_found')
  }
  await c.env.DB.prepare(`DELETE FROM class_mission_claims WHERE mission_id=?`).bind(id).run()
  await c.env.DB.prepare(`DELETE FROM class_missions WHERE id=?`).bind(id).run()
  return c.json({ ok: true })
})

// 児童: 自分のクラスの進行中ミッション＋進捗を取得
app.get('/api/student/class-mission', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  // 生徒はclass_members、教師はclasses.teacher_idで所属クラスを取得
  let cm = await c.env.DB.prepare(`SELECT class_id FROM class_members WHERE user_id=? LIMIT 1`).bind(u.id).first<any>()
  if (!cm && (u.role === 'teacher' || u.role === 'admin')) {
    cm = await c.env.DB.prepare(`SELECT id AS class_id FROM classes WHERE teacher_id=? LIMIT 1`).bind(u.id).first<any>()
  }
  if (!cm) return c.json({ ok: true, mission: null })

  // まず進行中のミッションを探す
  let m = await c.env.DB.prepare(
    `SELECT id, title, goal_correct AS goalCorrect, reward_coins AS rewardCoins, reward_shards AS rewardShards,
            start_at AS startAt, end_at AS endAt
     FROM class_missions WHERE class_id=? AND (end_at IS NULL OR end_at >= datetime('now'))
     ORDER BY created_at DESC LIMIT 1`
  ).bind(cm.class_id).first<any>()

  // 進行中がなければ、締切済みでも達成済み＆未受取のミッションを探す（報酬受け取り猶予）
  if (!m) {
    const latest = await c.env.DB.prepare(
      `SELECT id, title, goal_correct AS goalCorrect, reward_coins AS rewardCoins, reward_shards AS rewardShards,
              start_at AS startAt, end_at AS endAt
       FROM class_missions WHERE class_id=?
       ORDER BY created_at DESC LIMIT 1`
    ).bind(cm.class_id).first<any>()
    if (latest) {
      const prog = await countMissionProgress(c, cm.class_id, latest.startAt, latest.endAt)
      const alreadyClaimed = await c.env.DB.prepare(`SELECT 1 FROM class_mission_claims WHERE mission_id=? AND user_id=? LIMIT 1`).bind(latest.id, u.id).first<any>()
      if (prog >= latest.goalCorrect && !alreadyClaimed) {
        m = latest // 達成済み＆未受取 → 表示する
      }
    }
  }

  if (!m) return c.json({ ok: true, mission: null })
  const progress = await countMissionProgress(c, cm.class_id, m.startAt, m.endAt)
  const claimed = await c.env.DB.prepare(`SELECT 1 FROM class_mission_claims WHERE mission_id=? AND user_id=? LIMIT 1`).bind(m.id, u.id).first<any>()
  return c.json({ ok: true, mission: { ...m, progress, achieved: progress >= m.goalCorrect, claimed: !!claimed } })
})

// 児童: ミッション達成報酬を受け取る（コイン＋かけらをサーバー側で加算）
app.post('/api/student/class-mission/:id/claim', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  const missionId = c.req.param('id')
  const already = await c.env.DB.prepare(`SELECT 1 FROM class_mission_claims WHERE mission_id=? AND user_id=? LIMIT 1`).bind(missionId, u.id).first<any>()
  if (already) return c.json({ ok: true, alreadyClaimed: true, rewardCoins: 0, rewardShards: 0 })
  const m = await c.env.DB.prepare(
    `SELECT class_id, goal_correct, reward_coins, reward_shards, start_at, end_at FROM class_missions WHERE id=? LIMIT 1`
  ).bind(missionId).first<any>()
  if (!m) return jsonError(c, 404, 'mission_not_found')
  // 生徒はclass_members、教師はclasses.teacher_idで所属を確認
  let member = await c.env.DB.prepare(`SELECT 1 FROM class_members WHERE class_id=? AND user_id=? LIMIT 1`).bind(m.class_id, u.id).first<any>()
  if (!member && (u.role === 'teacher' || u.role === 'admin')) {
    member = await c.env.DB.prepare(`SELECT 1 FROM classes WHERE id=? AND teacher_id=? LIMIT 1`).bind(m.class_id, u.id).first<any>()
  }
  if (!member) return jsonError(c, 403, 'not_class_member')
  const progress = await countMissionProgress(c, m.class_id, m.start_at, m.end_at)
  if (progress < m.goal_correct) return jsonError(c, 400, 'not_achieved')
  const rewardCoins = Number(m.reward_coins) || 0
  const rewardShards = Number(m.reward_shards) || 0
  let applyOk = false
  try {
    const prog = await c.env.DB.prepare(`SELECT state_json FROM progress WHERE user_id=?`).bind(u.id).first<any>()
    if (prog?.state_json) {
      const state = JSON.parse(prog.state_json)
      state.coins = (Number(state.coins) || 0) + rewardCoins
      if (rewardShards > 0) {
        if (!state.lab || typeof state.lab !== 'object') state.lab = { shards: 0, use: {} }
        state.lab.shards = (Number(state.lab.shards) || 0) + rewardShards
      }
      await c.env.DB.prepare(`UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?`).bind(JSON.stringify(state), u.id).run()
      applyOk = true
    } else {
      applyOk = true
    }
  } catch (e: any) {
    console.error('[class-mission/claim] reward apply error:', e?.message || e)
  }
  if (!applyOk) return jsonError(c, 500, 'reward_apply_failed')
  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO class_mission_claims (mission_id, user_id, reward_coins, reward_shards) VALUES (?,?,?,?)`
  ).bind(missionId, u.id, rewardCoins, rewardShards).run()
  return c.json({ ok: true, rewardCoins, rewardShards })
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
          <label class="text-sm font-bold text-gray-700 mb-1 block">ニックネーム</label>
          <input id="name" class="w-full border p-2 rounded" placeholder="例：ひろ、たろう、りんご"/>
          <p class="text-xs text-red-600 mt-1">⚠️ 本名（フルネーム）は書かないでください</p>
          <p class="text-xs text-gray-500 mt-0.5">好きなニックネームでOK！あとから変更もできます</p>
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
        name_required: 'ニックネームを入力してください',
        name_inappropriate: 'そのニックネームは使えません',
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
        if(!payload.name){ msg.textContent='ニックネームを入力してください'; msg.className='text-sm text-red-600'; return; }
        // 本名っぽい入力（漢字2文字以上が連続）を警告
        if(/[\u4e00-\u9fa5]{2,}\s*[\u4e00-\u9fa5]{2,}/.test(payload.name)){
          if(!confirm('本名（フルネーム）のように見えます。\\n本当にこれをニックネームにしますか？\\n\\n※ プライバシー保護のため、ニックネームの使用をおすすめします。')){
            return;
          }
        }
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
        <div class="flex flex-wrap gap-2 mb-2 text-sm items-center">
          <input id="filterGrade" class="border p-2 rounded w-16" placeholder="学年" />
          <select id="sortOrder" class="border p-2 rounded" onchange="renderUsers(true)">
            <option value="default">名前順（デフォルト）</option>
            <option value="login_asc">ログイン古い順</option>
            <option value="login_desc">ログイン新しい順</option>
            <option value="nologin">未ログイン優先</option>
          </select>
          <label class="flex items-center gap-1 cursor-pointer bg-red-50 border border-red-200 rounded px-2 py-1">
            <input type="checkbox" id="filterInactive" onchange="renderUsers(true)" />
            <span class="text-red-600 font-bold">2ヶ月未活動のみ</span>
          </label>
          <button id="filterBtn" class="bg-slate-700 text-white rounded px-3 py-2">絞り込み</button>
          <button id="reloadBtn" class="bg-slate-200 rounded px-3 py-2">更新</button>
        </div>
        <div id="userCount" class="text-xs text-gray-500 mb-1"></div>
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

      var _cachedUsers = [];
      async function renderUsers(useCache){
        const grade = document.getElementById('filterGrade').value.trim();
        if(!useCache){
          const qs = new URLSearchParams();
          if(grade) qs.set('grade', grade);
          const u = await api('/api/admin/users?' + qs.toString());
          _cachedUsers = u.users || [];
        }
        var users = _cachedUsers.slice();

        // --- フィルター: 2ヶ月未活動のみ ---
        var filterInactive = document.getElementById('filterInactive').checked;
        var now = Date.now();
        var twoMonthsMs = 60 * 24 * 60 * 60 * 1000; // 60日
        if(filterInactive){
          users = users.filter(function(x){
            if(!x.lastLoginAt) return true; // 未ログイン = 未活動
            var d = new Date(x.lastLoginAt + 'Z');
            return (now - d.getTime()) > twoMonthsMs;
          });
        }

        // --- ソート ---
        var sort = document.getElementById('sortOrder').value;
        if(sort === 'login_asc'){
          users.sort(function(a,b){
            if(!a.lastLoginAt && !b.lastLoginAt) return 0;
            if(!a.lastLoginAt) return -1;
            if(!b.lastLoginAt) return 1;
            return a.lastLoginAt < b.lastLoginAt ? -1 : 1;
          });
        } else if(sort === 'login_desc'){
          users.sort(function(a,b){
            if(!a.lastLoginAt && !b.lastLoginAt) return 0;
            if(!a.lastLoginAt) return 1;
            if(!b.lastLoginAt) return -1;
            return a.lastLoginAt > b.lastLoginAt ? -1 : 1;
          });
        } else if(sort === 'nologin'){
          users.sort(function(a,b){
            var aNo = !a.lastLoginAt ? 0 : 1;
            var bNo = !b.lastLoginAt ? 0 : 1;
            if(aNo !== bNo) return aNo - bNo;
            return (a.name||'').localeCompare(b.name||'');
          });
        }
        // default は API のまま（名前順）

        const wrap = document.getElementById('users');
        const countEl = document.getElementById('userCount');
        wrap.innerHTML='';
        countEl.textContent = '表示: ' + users.length + '件' + (_cachedUsers.length !== users.length ? ' / 全' + _cachedUsers.length + '件' : '');
        if(!users.length){ wrap.textContent='該当なし'; return; }
        for(const x of users){
          // 未活動判定
          var isInactive = false;
          var inactiveLabel = '';
          if(!x.lastLoginAt){
            isInactive = true; inactiveLabel = '⚠ 未ログイン';
          } else {
            var lastD = new Date(x.lastLoginAt + 'Z');
            var daysSince = Math.floor((now - lastD.getTime()) / (24*60*60*1000));
            if(daysSince >= 60){
              isInactive = true; inactiveLabel = '⚠ ' + daysSince + '日間未活動';
            }
          }

          const div = document.createElement('div');
          div.className='flex flex-col md:flex-row md:items-center md:justify-between border rounded p-2 gap-2'
            + (isInactive ? ' bg-red-50 border-red-300' : '');
          const left = document.createElement('div');
          left.innerHTML = x.grade + '年 / ' + x.name + '（' + x.loginId + '）' + (x.isActive? '' : ' <span class="text-red-500">[停止/未承認]</span>')
            + ' <span class="text-xs text-blue-600">最終ログイン: ' + fmtLogin(x.lastLoginAt) + '</span>'
            + (isInactive ? ' <span class="text-xs font-bold text-red-600 ml-1">' + inactiveLabel + '</span>' : '');
          div.appendChild(left);
          const right = document.createElement('div');
          right.className='flex gap-2 flex-shrink-0';

          const toggle = document.createElement('button');
          toggle.className = x.isActive ? 'bg-amber-600 text-white rounded px-3 py-1 text-sm' : 'bg-blue-600 text-white rounded px-3 py-1 text-sm';
          toggle.textContent = x.isActive ? '停止' : '承認/再開';
          toggle.onclick = async ()=>{
            if(x.isActive){
              const reason = prompt('停止理由(任意)');
              await api('/api/admin/disable/'+x.id,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({reason})});
            } else {
              await api('/api/admin/approve/'+x.id,{method:'POST'});
            }
            await loadAll();
          };
          right.appendChild(toggle);

          const reset = document.createElement('button');
          reset.className='bg-slate-800 text-white rounded px-3 py-1 text-sm';
          reset.textContent='PWリセット';
          reset.onclick = async ()=>{ const r=await api('/api/admin/reset-password/'+x.id,{method:'POST'}); alert('仮パスワード: '+r.tempPassword+'\\n(次回ログインで変更させてください)'); };
          right.appendChild(reset);

          const del = document.createElement('button');
          del.className='bg-red-600 text-white rounded px-3 py-1 text-sm';
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

      <!-- イベント管理 -->
      <div class="bg-white rounded-xl shadow p-4">
        <h2 class="font-bold mb-3">🎉 イベント管理</h2>
        <div class="flex flex-wrap gap-3" id="festToggles">
          <button id="festFractionBtn" onclick="toggleFest('fraction')" class="px-4 py-2 rounded-lg font-bold text-sm border-2 transition bg-slate-100 text-slate-500 border-slate-300">🍰 分数フェス OFF</button>
          <button id="festDecimalBtn" onclick="toggleFest('decimal')" class="px-4 py-2 rounded-lg font-bold text-sm border-2 transition bg-slate-100 text-slate-500 border-slate-300">💧 小数フェス OFF</button>
        </div>
        <p class="text-xs text-slate-400 mt-2">ONにすると生徒の修行画面にフェス表示が出て、かけらがドロップするようになります。</p>
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
        <button id="tabMissions" class="flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100" onclick="switchTab('missions')">🎯 ミッション</button>
      </div>

      <!-- クラス一覧タブ -->
      <div id="tabPaneClasses" class="space-y-4">
        <div id="classList" class="space-y-4"></div>
      </div>

      <!-- 分析タブ（統合） -->
      <div id="tabPaneAnalytics" class="hidden space-y-3">
        <!-- サブタブナビ -->
        <div class="bg-white rounded-xl shadow p-2 flex items-center gap-1 overflow-x-auto">
          <button id="anSubTab_overview" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-indigo-500 text-white" onclick="switchAnalyticsSubTab('overview')">
            <span class="bg-white text-indigo-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">1</span> クラス全体
          </button>
          <button id="anSubTab_subject" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchAnalyticsSubTab('subject')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">2</span> 教科の定着
          </button>
          <button id="anSubTab_homework" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchAnalyticsSubTab('homework')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">3</span> 家庭学習
          </button>
          <button id="anSubTab_ai" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchAnalyticsSubTab('ai')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">4</span> AI分析・個人
          </button>
          <button id="anSubTab_tests" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchAnalyticsSubTab('tests')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">5</span> テスト取り込み
          </button>
          <button id="anSubTab_notes" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchAnalyticsSubTab('notes')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">6</span> 授業メモ
          </button>
        </div>
        <!-- 共通クラス選択 -->
        <div class="bg-white rounded-xl shadow p-3 flex gap-2 items-center flex-wrap">
          <span class="text-sm font-bold text-slate-600">クラス:</span>
          <select id="analyticsClassFilter" class="border p-2 rounded text-sm bg-white"></select>
        </div>

        <!-- サブタブ①: クラス全体（ラーニングアナリティクス） -->
        <div id="anPane_overview" class="space-y-3">
          <div class="bg-gradient-to-br from-rose-50 to-orange-50 border border-rose-200 rounded-xl p-4 space-y-3" id="earlyAlertCard"><div class="flex items-center justify-between flex-wrap gap-2"><div class="font-bold text-sm text-rose-800">⚠️ 早期対応リスト ＋ 習熟ライン</div><button onclick="loadEarlyAlerts()" id="btnEarlyAlerts" class="bg-rose-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-rose-700">🔍 つまずきをチェック</button></div><p class="text-xs text-rose-600">「3回連続まちがい」「正答率の急落」「できていた単元の低下」を検出。単元の定着ライン（定着／あと一歩／要サポート）も色分け表示します。タップでその子の分析へ。</p><div id="earlyAlertContent" class="text-sm text-slate-600"><p class="text-xs text-slate-400">クラスを選んで「つまずきをチェック」を押してください</p></div></div>
          <div class="bg-white rounded-xl shadow p-4">
            <div class="flex items-center gap-2 flex-wrap mb-3">
              <h3 class="font-bold text-slate-700">📈 ラーニングアナリティクス</h3>
              <select id="laClassSelect" class="border p-1.5 rounded text-sm bg-white font-bold"></select>
              <button onclick="loadLearnAnalytics()" class="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:opacity-90">分析する</button>
            </div>
            <div id="laContent"><p class="text-xs text-slate-400">クラスを選んで「分析する」を押してください</p></div>
          </div>
        </div>

        <!-- サブタブ②: 教科の定着 -->
        <div id="anPane_subject" class="hidden space-y-3">
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

          <!-- 全員分まとめAI分析 -->
          <div class="bg-gradient-to-br from-violet-50 to-fuchsia-50 border border-violet-200 rounded-xl p-4 space-y-3">
            <div class="font-bold text-sm text-violet-800">🤖 全員分のAI分析（一括）</div>
            <p class="text-xs text-violet-600">①「まとめてコピー」→ ChatGPT/Geminiに貼り付け → ②AIの結果を下に貼って「保存」。各児童の個人分析・カルテに反映されます。</p>
            <div class="flex flex-wrap gap-2">
              <button onclick="copyAllAiText()" class="bg-emerald-600 text-white rounded-lg px-3 py-2 text-xs font-bold hover:bg-emerald-700">📋 全員分のAI分析用テキストをまとめてコピー</button>
              <button onclick="downloadAllKartes()" class="bg-rose-600 text-white rounded-lg px-3 py-2 text-xs font-bold hover:bg-rose-700">📄 全員分のカルテをまとめてダウンロード（印刷）</button>
            </div>
            <span id="allAiStatus" class="text-xs text-violet-700 font-bold block"></span>
            <textarea id="allAiPaste" rows="5" placeholder="ここにAIの出力を全部貼り付けてください（=== [児童ID] ... === の目印ごとに自動でふり分けます）" class="w-full text-xs border border-violet-300 rounded-lg p-2"></textarea>
            <div><button onclick="saveAllAiComments()" class="bg-violet-600 text-white rounded-lg px-3 py-2 text-xs font-bold hover:bg-violet-700">💾 AIの結果をまとめて保存</button></div>
          </div>

          <!-- 提出ヒートマップ -->
          <div class="bg-white border border-slate-200 rounded-xl p-4 space-y-3">
            <div class="font-bold text-sm text-slate-700">🗓️ 提出ヒートマップ（今週）</div>
            <div id="heatmapContent" class="overflow-x-auto">
              <p class="text-xs text-slate-400">分析データが読み込まれると自動で表示されます</p>
            </div>
          </div>
        </div>

        <!-- サブタブ⑤: テスト結果の取り込み -->
        <div id="anPane_tests" class="hidden space-y-3">
          <div class="bg-white rounded-xl shadow p-4">
            <div class="font-bold text-slate-700 mb-1">📝 テスト結果の取り込み</div>
            <div class="text-xs text-slate-500 mb-2">ロイロやテストのPDFは外部AI（ChatGPT・Gemini・Claude）に読み取らせ、決まった形式で書き出した結果をここに貼り付けて取り込みます。保存先は「クラス全体」で選んだクラスです。</div>
            <div class="flex items-center gap-2 flex-wrap mb-2">
              <button onclick="copyTestPrompt()" class="bg-emerald-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-emerald-700">📋 AI用プロンプトをコピー</button>
              <span id="tsPromptStatus" class="text-xs text-emerald-600 font-bold"></span>
            </div>
            <textarea id="tsPaste" rows="7" class="w-full border rounded-lg p-2 text-xs" placeholder="AIが書き出した結果をここに貼り付け（テスト名: / 実施日: / 教科: / 満点: / --- / 名前, 点数 …）"></textarea>
            <div class="flex items-center gap-2 mt-2">
              <button onclick="parseTestScores()" class="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:opacity-90">🔍 読み取り</button>
              <span id="tsParseStatus" class="text-xs text-slate-500"></span>
            </div>
            <div id="tsPreview" class="mt-3"></div>
          </div>
          <div class="bg-white rounded-xl shadow p-4">
            <div class="font-bold text-slate-700 mb-1">📚 記録の取り込み（まとめ・振り返り・その他）</div>
            <div class="text-xs text-slate-500 mb-2">ロイロ等の「調べたこと・レポート・振り返り」を外部AIに決まった形式で書き出させ、ここに貼り付けて児童ごとに保存します。保存先は上の「クラス」で選んだクラスです。</div>
            <div class="flex items-center gap-2 flex-wrap mb-2">
              <span class="text-xs font-bold text-slate-600">種類:</span>
              <select id="recType" class="border p-1.5 rounded text-xs bg-white">
                <option value="report">まとめ・レポート（調べたこと）</option>
                <option value="reflect">振り返り</option>
                <option value="other">その他</option>
              </select>
              <button onclick="copyRecordPrompt()" class="bg-emerald-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-emerald-700">📋 AI用プロンプトをコピー</button>
              <span id="recPromptStatus" class="text-xs text-emerald-600 font-bold"></span>
            </div>
            <textarea id="recPaste" rows="8" class="w-full border rounded-lg p-2 text-xs" placeholder="AIが書き出した結果をここに貼り付け（=== [児童ID] 名前 === / タイトル: / 日付: / 教科: / 単元: / 本文: …）"></textarea>
            <div class="flex items-center gap-2 mt-2">
              <button onclick="parseRecords()" class="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:opacity-90">🔍 読み取り</button>
              <span id="recParseStatus" class="text-xs text-slate-500"></span>
            </div>
            <div id="recPreview" class="mt-3"></div>
          </div>
        </div>

        <!-- サブタブ⑥: 授業メモ -->
        <div id="anPane_notes" class="hidden space-y-3">
          <div class="bg-white rounded-xl shadow p-4">
            <div class="flex items-center gap-2 flex-wrap mb-2">
              <div class="font-bold text-slate-700">🏫 クラス全体メモ</div>
              <button onclick="loadNotes()" class="bg-slate-200 text-slate-700 rounded-lg px-2 py-1 text-xs font-bold hover:bg-slate-300">🔄 読み込む</button>
            </div>
            <div class="text-xs text-slate-500 mb-2">上の「クラス」で選んだクラスの、その日の授業の気づきを記録します。</div>
            <div class="flex flex-col gap-2">
              <input id="cnoteDate" type="date" class="border rounded p-1.5 text-xs w-40">
              <textarea id="cnoteBody" rows="3" class="w-full border rounded-lg p-2 text-xs" placeholder="例：今日は発表が活発だった。グループ活動の声かけを工夫したい。"></textarea>
              <div class="flex items-center gap-2"><button onclick="saveClassNote()" class="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:opacity-90">💾 クラスメモを保存</button><span id="cnoteStatus" class="text-xs text-indigo-600 font-bold"></span></div>
            </div>
            <div id="cnoteList" class="mt-3 space-y-1"></div>
          </div>
          <div class="bg-white rounded-xl shadow p-4">
            <div class="font-bold text-slate-700 mb-1">👤 児童ごとメモ</div>
            <div class="text-xs text-slate-500 mb-2">児童を選んで、授業中の様子をサッと一言。チェックを入れたメモだけ「子ども向けカルテPDF」に載ります（既定はオフ＝先生だけが見る）。</div>
            <div class="flex flex-col gap-2">
              <select id="snoteStudent" class="border rounded p-1.5 text-xs bg-white" onchange="loadStudentNotesTab()"></select>
              <input id="snoteDate" type="date" class="border rounded p-1.5 text-xs w-40">
              <input id="snoteBody" class="w-full border rounded-lg p-2 text-xs" placeholder="例：発表でしっかり説明できた">
              <label class="flex items-center gap-1 text-xs text-slate-600"><input id="snoteKarte" type="checkbox"> カルテ（子ども向け）にも載せる</label>
              <div class="flex items-center gap-2"><button onclick="saveStudentNoteTab()" class="bg-teal-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-teal-700">💾 児童メモを保存</button><span id="snoteStatus" class="text-xs text-teal-600 font-bold"></span></div>
            </div>
            <div id="snoteList" class="mt-3 space-y-1"></div>
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

        <!-- 個人全期間分析オーバーレイ -->
        <div id="studentFullAnalysisOverlay" class="hidden" style="position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,0.5);overflow-y:auto;">
          <div style="max-width:800px;margin:20px auto;background:white;border-radius:16px;padding:20px;min-height:calc(100vh - 40px);">
            <div class="flex items-center justify-between mb-4">
              <div class="font-bold text-xl text-indigo-800" id="fullAnalysisStudentName"></div>
              <button onclick="closeStudentFullAnalysis()" class="bg-slate-200 hover:bg-slate-300 rounded-full w-8 h-8 flex items-center justify-center text-slate-600 font-bold text-lg">✕</button>
            </div>
            <div id="fullAnalysisContent">
              <p class="text-indigo-500 animate-pulse text-sm">📊 データを取得中...</p>
            </div>
          </div>
        </div>
      </div>

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
          <button id="hwSubTab_dashboard" class="flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100" onclick="switchHomeworkSubTab('dashboard')">
            <span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">📊</span> 提出状況
          </button>
        </div>

        <!-- サブタブ: 提出状況ダッシュボード -->
        <div id="hwPane_dashboard" class="hidden space-y-3">
          <div class="bg-white rounded-xl shadow p-4">
            <div class="flex gap-2 mb-3 flex-wrap items-center">
              <select id="dashClassFilter" class="border p-2 rounded text-sm bg-white font-bold"></select>
              <button onclick="loadSubmissionDashboard()" class="bg-indigo-600 text-white rounded-lg px-4 py-2 text-sm font-bold shadow hover:opacity-90">📊 提出状況を表示</button>
              <span id="dashWeekLabel" class="text-xs text-slate-500 ml-auto"></span>
            </div>
            <!-- 週ナビゲーション -->
            <div id="dashWeekNav" class="hidden flex items-center gap-2 mb-3 flex-wrap bg-gradient-to-r from-indigo-50 to-purple-50 rounded-lg p-2">
              <button onclick="dashWeekPrev()" class="bg-white border border-indigo-200 rounded-lg px-3 py-1.5 text-sm font-bold text-indigo-600 hover:bg-indigo-100 shadow-sm">◀ 前の週</button>
              <select id="dashWeekSelector" onchange="dashWeekJump(this.value)" class="border border-indigo-200 rounded-lg px-2 py-1.5 text-sm font-bold bg-white text-indigo-700 max-w-[180px]"></select>
              <button onclick="dashWeekNext()" class="bg-white border border-indigo-200 rounded-lg px-3 py-1.5 text-sm font-bold text-indigo-600 hover:bg-indigo-100 shadow-sm">次の週 ▶</button>
              <button onclick="dashWeekToday()" class="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-sm font-bold shadow hover:opacity-90 ml-auto">📅 今週</button>
            </div>
            <div id="dashboardContent">
              <p class="text-xs text-slate-400">クラスを選んで「提出状況を表示」を押してください</p>
            </div>
          </div>
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

        <!-- 名簿管理（プライバシー保護） -->
        <div class="bg-rose-50 border border-rose-200 rounded-xl p-4 space-y-3">
          <div class="font-bold text-sm text-rose-800">🔒 名簿管理（プライバシー保護）</div>
          <div class="text-xs text-rose-700 leading-relaxed">
            児童の実名をクラウドに保存せず、先生のPCの中だけで管理する仕組みです。<br>
            ① 「名簿CSVダウンロード」で現在の児童リストを取得 → ②必要なら実名に編集 → ③「名簿CSVアップロード」で先生のブラウザに保存。<br>
            <span class="font-bold">④最後に「クラウド側の名前を空にする」を押すと完全匿名化されます。</span>
          </div>
          <div class="flex gap-2 items-center flex-wrap">
            <button onclick="downloadStudentCSV()" class="bg-rose-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">📥 ① 現在の名簿をCSVダウンロード</button>
            <label class="bg-rose-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90 cursor-pointer">
              📤 ③ 名簿CSVアップロード
              <input type="file" accept=".csv" onchange="uploadStudentCSV(event)" class="hidden"/>
            </label>
            <button onclick="anonymizeCloudNames()" class="bg-red-700 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">🔒 ④ クラウド側の名前を空にする</button>
            <button onclick="clearStudentCSV()" class="bg-slate-400 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">🗑 名簿リセット（このブラウザのみ）</button>
          </div>
          <div id="csvStatusMsg" class="text-xs text-rose-700 font-bold"></div>
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
          <!-- サマリーバー -->
          <div id="hwSummaryBar" class="hidden mb-3 p-3 bg-gradient-to-r from-blue-50 to-emerald-50 rounded-lg border border-blue-200 text-sm"></div>
          <!-- 未提出者リスト -->
          <div id="hwUnsubmittedList" class="hidden mb-3 p-3 bg-orange-50 rounded-lg border border-orange-200 text-sm"></div>
          <!-- 日付タブ -->
          <div id="hwDateTabs" class="flex gap-1 mb-3 flex-wrap hidden"></div>
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

      <!-- ミッションタブ -->
      <div id="tabPaneMissions" class="hidden space-y-3">
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">🎯 クラス共同ミッションを作る</h3>
          <p class="text-xs text-slate-500 mb-2">クラス全員の正解数を合計して目標に挑戦！達成すると全員がコイン＋かけらをもらえます。</p>
          <div class="space-y-2">
            <select id="cmClassFilter" class="border p-2 rounded text-sm bg-white w-full" onchange="loadClassMissions()"></select>
            <input id="cmTitle" type="text" placeholder="ミッション名（例：みんなで1000問正解！）" class="w-full border p-2 rounded text-sm"/>
            <div class="flex gap-2">
              <div class="flex-1"><label class="text-xs font-bold text-gray-600">目標正解数</label><input id="cmGoal" type="number" value="1000" min="1" class="w-full border p-2 rounded text-sm"/></div>
              <div class="flex-1"><label class="text-xs font-bold text-gray-600">締切（任意）</label><input id="cmEnd" type="date" class="w-full border p-2 rounded text-sm"/></div>
            </div>
            <div class="flex gap-2">
              <div class="flex-1"><label class="text-xs font-bold text-gray-600">ごほうび：コイン</label><input id="cmCoins" type="number" value="500" min="0" class="w-full border p-2 rounded text-sm"/></div>
              <div class="flex-1"><label class="text-xs font-bold text-gray-600">ごほうび：かけら</label><input id="cmShards" type="number" value="5" min="0" class="w-full border p-2 rounded text-sm"/></div>
            </div>
            <button onclick="sendClassMission()" class="bg-purple-600 hover:bg-purple-700 text-white rounded px-4 py-2 font-bold text-sm">🎯 ミッション開始</button>
            <p id="cmMsg" class="text-sm"></p>
          </div>
        </div>
        <div class="bg-white rounded-xl shadow p-4">
          <h3 class="font-bold mb-3">ミッション一覧・進捗</h3>
          <div id="cmList"></div>
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

    </div>

      <!-- メールタブ -->      <div id="tabPaneMail" class="hidden">        <div id="mailStudentListView">          <div class="flex gap-2 mb-3 items-center">            <select id="mailClassFilter" class="border p-2 rounded text-sm bg-white font-bold"></select>          </div>          <div id="mailStudentCards" class="space-y-1"></div>        </div>        <div id="mailChatView" class="hidden" style="height:70vh;display:none;">          <div class="flex items-center gap-3 bg-gradient-to-r from-teal-500 to-teal-600 text-white px-4 py-3 rounded-t-xl">            <button onclick="closeMailChat()" class="text-white font-bold text-lg">←</button>            <span id="mailChatName" class="font-bold"></span>          </div>          <div id="mailChatMessages" class="overflow-y-auto p-3 space-y-2 bg-[#e2efe9]" style="height:calc(70vh - 110px);"></div>          <div id="mailImagePreview" class="hidden px-2 pt-2 bg-white border-t"><div class="relative inline-block"><img id="mailImageThumb" class="h-16 rounded"/><button onclick="clearMailImage()" class="absolute -top-1 -right-1 bg-red-500 text-white rounded-full w-5 h-5 text-xs flex items-center justify-center">✕</button></div></div>          <div class="flex gap-2 items-end bg-white border-t p-2 rounded-b-xl">            <input type="file" id="mailImageInput" accept="image/*" class="hidden" onchange="handleMailImage(this)"/>            <button onclick="document.getElementById('mailImageInput').click()" class="w-10 h-10 flex items-center justify-center rounded-full bg-slate-200 text-slate-600 font-bold shadow hover:bg-slate-300 flex-shrink-0" title="画像を添付">📷</button>            <textarea id="mailBody" class="flex-1 border border-slate-300 rounded-2xl px-3 py-2 text-sm resize-none focus:border-teal-500 focus:outline-none" rows="1" placeholder="メッセージを入力..." oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,80)+'px'"></textarea>            <button onclick="sendTeacherMail()" class="w-10 h-10 flex items-center justify-center rounded-full bg-teal-500 text-white font-bold shadow hover:opacity-90 flex-shrink-0">▶</button>          </div>          <p id="mailMsg" class="text-xs text-center py-1"></p>        </div>      </div>
    <script>
      async function api(path, opt){
        const r = await fetch(path, opt);
        const j = await r.json().catch(()=>({}));
        if(!r.ok) throw new Error(j.error || 'error');
        return j;
      }

      // ===== フェストグル =====
      var _festState = { fraction_fest_active: false, decimal_fest_active: false };
      async function loadFestStatus(){
        try{
          var d = await api('/api/fest/status');
          _festState = { fraction_fest_active: !!d.fraction_fest_active, decimal_fest_active: !!d.decimal_fest_active };
        }catch(e){}
        updateFestButtons();
      }
      function updateFestButtons(){
        var fb = document.getElementById('festFractionBtn');
        var db = document.getElementById('festDecimalBtn');
        if(fb){
          if(_festState.fraction_fest_active){
            fb.className='px-4 py-2 rounded-lg font-bold text-sm border-2 transition bg-teal-100 text-teal-700 border-teal-400 shadow';
            fb.textContent='🍰 分数フェス ON';
          } else {
            fb.className='px-4 py-2 rounded-lg font-bold text-sm border-2 transition bg-slate-100 text-slate-500 border-slate-300';
            fb.textContent='🍰 分数フェス OFF';
          }
        }
        if(db){
          if(_festState.decimal_fest_active){
            db.className='px-4 py-2 rounded-lg font-bold text-sm border-2 transition bg-sky-100 text-sky-700 border-sky-400 shadow';
            db.textContent='💧 小数フェス ON';
          } else {
            db.className='px-4 py-2 rounded-lg font-bold text-sm border-2 transition bg-slate-100 text-slate-500 border-slate-300';
            db.textContent='💧 小数フェス OFF';
          }
        }
      }
      async function toggleFest(type){
        var key = type === 'fraction' ? 'fraction_fest_active' : 'decimal_fest_active';
        var newVal = !_festState[key];
        try{
          await api('/api/admin/fest-toggle',{
            method:'PUT', headers:{'content-type':'application/json'},
            body: JSON.stringify({fest: type, active: newVal})
          });
          _festState[key] = newVal;
          updateFestButtons();
        }catch(e){ alert('エラー: ' + String(e.message||e)); }
      }
      loadFestStatus();

      function escH(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;'); }

      // ===== 名簿マッピング（localStorage）=====
      function getStudentNameMap(){
        try { return JSON.parse(localStorage.getItem('studentNameMap') || '{}'); } catch(_) { return {}; }
      }
      function setStudentNameMap(map){
        try { localStorage.setItem('studentNameMap', JSON.stringify(map||{})); } catch(_) {}
      }
      function resolveStudentName(loginId, fallback){
        var map = getStudentNameMap();
        if(loginId && map[loginId]) return map[loginId];
        return fallback || loginId || '';
      }
      async function downloadStudentCSV(){
        try {
          var data = await api('/api/teacher/all-students');
          var rows = [['ログインID','実名','学年','クラス']];
          var map = getStudentNameMap();
          (data.students || []).forEach(function(s){
            var realName = map[s.loginId] || s.name || '';
            rows.push([s.loginId, realName, s.grade || '', s.className || '']);
          });
          var csv = rows.map(function(r){
            return r.map(function(c){ return '"' + String(c).replace(/"/g,'""') + '"'; }).join(',');
          }).join('\\n');
          var blob = new Blob(['\ufeff'+csv], {type:'text/csv;charset=utf-8'});
          var a = document.createElement('a');
          a.href = URL.createObjectURL(blob);
          a.download = '名簿_' + new Date().toISOString().slice(0,10) + '.csv';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          var msg = document.getElementById('csvStatusMsg');
          if(msg) msg.textContent = '✅ 名簿CSVをダウンロードしました（' + ((data.students||[]).length) + '名）';
        } catch(e){
          alert('エラー: ' + String(e.message||e));
        }
      }
      function parseCSV(text){
        // シンプルなCSVパーサ（ダブルクォート対応）
        var rows = [];
        var row = [];
        var cur = '';
        var inQuote = false;
        for(var i=0; i<text.length; i++){
          var ch = text[i];
          if(inQuote){
            if(ch === '"'){
              if(text[i+1] === '"'){ cur += '"'; i++; }
              else { inQuote = false; }
            } else { cur += ch; }
          } else {
            if(ch === '"'){ inQuote = true; }
            else if(ch === ','){ row.push(cur); cur = ''; }
            else if(ch === '\\n' || ch === '\\r'){
              if(ch === '\\r' && text[i+1] === '\\n') i++;
              row.push(cur); cur = '';
              rows.push(row); row = [];
            } else { cur += ch; }
          }
        }
        if(cur !== '' || row.length > 0){ row.push(cur); rows.push(row); }
        return rows;
      }
      async function uploadStudentCSV(ev){
        try {
          var file = ev.target.files[0];
          if(!file) return;
          var text = await file.text();
          // BOM除去
          if(text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
          var rows = parseCSV(text);
          if(rows.length < 2){ alert('CSVにデータがありません'); return; }
          var header = rows[0].map(function(h){ return String(h).trim(); });
          var idxLogin = header.indexOf('ログインID');
          var idxName = header.indexOf('実名');
          if(idxLogin < 0) idxLogin = 0;
          if(idxName < 0) idxName = 1;
          var map = {};
          var count = 0;
          for(var i=1; i<rows.length; i++){
            var r = rows[i];
            if(!r || r.length === 0) continue;
            var loginId = String(r[idxLogin]||'').trim();
            var realName = String(r[idxName]||'').trim();
            if(loginId && realName){ map[loginId] = realName; count++; }
          }
          setStudentNameMap(map);
          ev.target.value = '';
          var msg = document.getElementById('csvStatusMsg');
          if(msg) msg.textContent = '✅ 名簿を読み込みました（' + count + '名）。このブラウザにのみ保存されます。';
          // 画面を更新
          if(typeof loadClasses === 'function') loadClasses();
        } catch(e){
          alert('エラー: ' + String(e.message||e));
        }
      }
      async function anonymizeCloudNames(){
        if(!confirm('【最終確認】\\nクラウド側に保存されている児童の名前をすべて空にします。\\n（ログインIDと同じ値に置き換わります）\\n\\n※ 先生のブラウザの名簿CSVがあれば、これまで通り実名で表示されます。\\n※ この操作は取り消せません。\\n\\n続けますか？')) return;
        if(!confirm('もう一度確認します。\\n本当にクラウド側の名前をすべて匿名化しますか？')) return;
        try {
          var r = await api('/api/teacher/anonymize-names', {
            method:'POST',
            headers:{'Content-Type':'application/json'},
            body: JSON.stringify({ confirm: 'YES_ANONYMIZE' })
          });
          var msg = document.getElementById('csvStatusMsg');
          if(msg) msg.textContent = '🔒 匿名化完了（' + (r.updated||0) + '名の名前を空にしました）';
          alert('匿名化しました。');
          if(typeof loadClasses === 'function') loadClasses();
        } catch(e){
          alert('エラー: ' + String(e.message||e));
        }
      }
      function clearStudentCSV(){
        if(!confirm('このブラウザに保存されている名簿マッピングを削除します。\\n（クラウド側のデータには影響しません）\\nよろしいですか？')) return;
        setStudentNameMap({});
        var msg = document.getElementById('csvStatusMsg');
        if(msg) msg.textContent = '🗑 名簿マッピングを削除しました';
        if(typeof loadClasses === 'function') loadClasses();
      }

      function switchTab(tab){
        ['classes','contact','announcements','homework','analytics','mail','missions'].forEach(function(t){
          var pane = document.getElementById('tabPane' + t.charAt(0).toUpperCase() + t.slice(1));
          if(pane) pane.classList.toggle('hidden', tab !== t);
          var btn = document.getElementById('tab' + t.charAt(0).toUpperCase() + t.slice(1));
          if(btn) btn.className = tab===t
            ? 'flex-1 py-2 rounded-lg text-sm font-bold bg-emerald-600 text-white'
            : 'flex-1 py-2 rounded-lg text-sm font-bold text-slate-600 hover:bg-slate-100';
        });
        if(tab === 'homework') { loadWeeklyMenu(); switchHomeworkSubTab('menu'); }
        if(tab === 'analytics') { initAnalyticsFilters(); initLearnAnalytics(); switchAnalyticsSubTab('overview'); }
        if(tab === 'announcements') loadAnnouncements();
        if(tab === 'contact') loadContactNotes();
        if(tab === 'missions') loadClassMissions();
        if(tab === 'mail'){ loadTeacherMail(); if(_mailListPollTimer) clearInterval(_mailListPollTimer); _mailListPollTimer = setInterval(function(){ loadMailStudentList(); }, 10000); } else { if(_mailPollTimer){ clearInterval(_mailPollTimer); _mailPollTimer=null; } if(_mailListPollTimer){ clearInterval(_mailListPollTimer); _mailListPollTimer=null; } }
      }

      // --- 家庭学習サブタブ切り替え ---
      function switchHomeworkSubTab(sub){
        const tabs = ['dashboard','menu','plan','daily','weekly'];
        const colors = {dashboard:'indigo',menu:'green',plan:'blue',daily:'emerald',weekly:'yellow'};
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
        if(sub === 'dashboard') loadSubmissionDashboard();
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
              +'<span class="font-bold">'+escH(resolveStudentName(st.loginId, st.name))+'</span>'
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
              +'<span class="font-bold w-20 shrink-0">'+escH(resolveStudentName(r.loginId, r.name))+'</span>'
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
            +'<td class="border px-2 py-1 font-bold sticky left-0 '+(i%2===0?'bg-white':'bg-slate-50')+'"><a href="javascript:void(0)" onclick="showStudentKarte(&#39;'+escH(s.id)+'&#39;,&#39;'+escH(resolveStudentName(s.loginId, s.name))+'&#39;)" class="text-purple-600 hover:underline cursor-pointer">'+escH(resolveStudentName(s.loginId, s.name))+'</a></td>'
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
        var tabs = ['overview','subject','homework','ai','tests','notes'];
        var colors = {overview:'indigo',subject:'purple',homework:'indigo',ai:'purple',tests:'rose',notes:'teal'};
        if(sub==='notes' && typeof initNotesTab==='function') initNotesTab();
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
        // 提出状況ダッシュボードのクラスフィルターも更新
        const dashSel = document.getElementById('dashClassFilter');
        if(dashSel){
          dashSel.innerHTML = '';
          data.classes.forEach(c => { dashSel.innerHTML += '<option value="'+escH(c.id)+'">'+escH(c.name)+'</option>'; });
          if(defaultClassId) dashSel.value = defaultClassId;
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
                +'<td class="border px-2 py-1">'+escH(resolveStudentName(m.loginId, m.name||m.id))+'</td>'
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
            const __pName = resolveStudentName(p.loginId, p.studentName);
            const revBadge = (p.revisionCount && p.revisionCount > 0)
              ? '<span class="bg-orange-100 text-orange-700 text-xs px-1.5 rounded font-bold cursor-pointer" onclick="showRevisions('+p.id+',\\''+escH(__pName)+'\\')">🔄 '+p.revisionCount+'回修正（自己調整）</span>'
              : '';
            let html = '<div class="flex items-center justify-between flex-wrap gap-1">'
              + '<div class="font-bold text-sm">'+escH(__pName)+' <span class="text-xs text-slate-400 font-normal">'+escH(p.grade+'年'+p.className)+'</span> '+approvedBadge+' '+revBadge+'</div>'
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
                window._weeklyRefData.push({ id: p.id, name: __pName, reflection: reflection });
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
              + '<span class="font-bold">' + escH(resolveStudentName(r.name, r.name)) + '</span>'
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
              html += '<div class="text-xs text-red-700">'+icon+' <b>'+escH(resolveStudentName(a.loginId, a.name))+'</b>: '+escH(a.detail)+'</div>';
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
            html += '<div class="w-16 truncate text-slate-600">'+escH(resolveStudentName(m.loginId, m.name))+'</div>';
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
            html += '<div class="w-16 truncate text-slate-600">'+escH(resolveStudentName(m.loginId, m.name))+'</div>';
            html += '<div class="flex gap-0.5 flex-wrap">'+(badges.length > 0 ? badges.join(' ') : '<span class="text-slate-300 text-[9px]">—</span>')+'</div>';
            html += '</div>';
          }
          html += '</div></div>';

          wrap.innerHTML = html;
        }catch(e){
          wrap.innerHTML='<p class="text-red-600">エラー: '+escH(String(e.message||e))+'</p>';
        }
      }

      // ===== 提出状況ダッシュボード =====
      var _dashCurrentWeek = '';
      var _dashWeekOptions = [];

      // 週キーヘルパー
      function _dashPrevWeek(wk){
        var m = wk.match(/^(\\d{4})-W(\\d{2})$/);
        if(!m) return wk;
        var y = parseInt(m[1]), w = parseInt(m[2]);
        w--; if(w<1){y--; w=52;}
        return y+'-W'+String(w).padStart(2,'0');
      }
      function _dashNextWeek(wk){
        var m = wk.match(/^(\\d{4})-W(\\d{2})$/);
        if(!m) return wk;
        var y = parseInt(m[1]), w = parseInt(m[2]);
        w++; if(w>52){y++; w=1;}
        return y+'-W'+String(w).padStart(2,'0');
      }
      // weekKeyから月曜日の日付文字列を取得
      function _weekKeyToMonday(wk){
        var m = wk.match(/^(\\d{4})-W(\\d{2})$/);
        if(!m) return '';
        var year = parseInt(m[1]), week = parseInt(m[2]);
        var jan4 = new Date(Date.UTC(year,0,4));
        var dow = jan4.getUTCDay() || 7;
        var mon = new Date(jan4);
        mon.setUTCDate(jan4.getUTCDate() - dow + 1 + (week-1)*7);
        var fri = new Date(mon);
        fri.setUTCDate(mon.getUTCDate()+4);
        return (mon.getUTCMonth()+1)+'/'+mon.getUTCDate()+'~'+(fri.getUTCMonth()+1)+'/'+fri.getUTCDate();
      }

      function _initWeekSelector(){
        var sel = document.getElementById('dashWeekSelector');
        if(!sel) return;
        var cur = getWeekKeyLocal();
        var options = [];
        var wk = cur;
        for(var i=0; i<52; i++){
          options.push(wk);
          wk = _dashPrevWeek(wk);
        }
        _dashWeekOptions = options;
        sel.innerHTML = '';
        for(var j=0; j<options.length; j++){
          var o = document.createElement('option');
          o.value = options[j];
          var label = options[j] + ' (' + _weekKeyToMonday(options[j]) + ')';
          if(j===0) label += ' <- now';
          o.textContent = label;
          sel.appendChild(o);
        }
        if(!_dashCurrentWeek) _dashCurrentWeek = cur;
        sel.value = _dashCurrentWeek;
        document.getElementById('dashWeekNav').classList.remove('hidden');
      }

      function dashWeekPrev(){
        _dashCurrentWeek = _dashPrevWeek(_dashCurrentWeek || getWeekKeyLocal());
        var sel = document.getElementById('dashWeekSelector');
        if(sel) sel.value = _dashCurrentWeek;
        loadSubmissionDashboard(_dashCurrentWeek);
      }
      function dashWeekNext(){
        var cur = getWeekKeyLocal();
        var next = _dashNextWeek(_dashCurrentWeek || cur);
        if(next > cur) return;
        _dashCurrentWeek = next;
        var sel = document.getElementById('dashWeekSelector');
        if(sel) sel.value = _dashCurrentWeek;
        loadSubmissionDashboard(_dashCurrentWeek);
      }
      function dashWeekJump(wk){
        _dashCurrentWeek = wk;
        loadSubmissionDashboard(wk);
      }
      function dashWeekToday(){
        _dashCurrentWeek = getWeekKeyLocal();
        var sel = document.getElementById('dashWeekSelector');
        if(sel) sel.value = _dashCurrentWeek;
        loadSubmissionDashboard(_dashCurrentWeek);
      }

      async function loadSubmissionDashboard(selectedWeek){
        const wrap = document.getElementById('dashboardContent');
        if(!wrap) return;
        const classId = document.getElementById('dashClassFilter')?.value;
        if(!classId){ alert('クラスを選択してください'); return; }
        wrap.innerHTML='<p class="text-indigo-500 text-sm animate-pulse">📊 提出状況を取得中...</p>';
        _initWeekSelector();
        try{
          const wk = selectedWeek || _dashCurrentWeek || getWeekKeyLocal();
          _dashCurrentWeek = wk;
          var sel = document.getElementById('dashWeekSelector');
          if(sel) sel.value = wk;
          const data = await api('/api/teacher/class/'+encodeURIComponent(classId)+'/submission-dashboard?weekKey='+encodeURIComponent(wk));
          const members = data.members || [];
          const daily = data.dailySubmissions || [];
          const prevSubs = data.prevWeekSubmissions || [];
          const plans = data.plans || [];
          const reflections = data.reflections || [];
          const weekDays = data.weekDays || [];
          const todayKey = data.todayKey || '';
          const weekKey = data.weekKey || wk;

          // ヘルパー: user_idで日別提出をマップ化
          const dailyByUser = {};
          for(const d of daily){
            if(!dailyByUser[d.user_id]) dailyByUser[d.user_id] = {};
            dailyByUser[d.user_id][d.day_key] = d;
          }
          // 先週提出マップ
          const prevByUser = {};
          for(const p of prevSubs) prevByUser[p.user_id] = p.cnt || 0;
          // 計画マップ
          const planByUser = {};
          for(const p of plans) planByUser[p.user_id] = p;
          // 振り返りマップ
          const refByUser = {};
          for(const r of reflections) refByUser[r.user_id] = r;

          // 過去の曜日だけフィルタ (isActive && isPast)
          const pastActiveDays = weekDays.filter(function(d){ return d.isActive && d.isPast; });
          const activeDayDates = pastActiveDays.map(function(d){ return d.date; });

          // ===== 集計 =====
          // 今日の提出
          const todaySubmitters = daily.filter(function(d){ return d.day_key === todayKey; });
          const todayRate = members.length > 0 ? Math.round(todaySubmitters.length / members.length * 100) : 0;
          // 今日の未提出者
          const todaySubmitterIds = {};
          for(const s of todaySubmitters) todaySubmitterIds[s.user_id] = true;
          const todayMissing = members.filter(function(m){ return !todaySubmitterIds[m.id]; });
          // 週の各日ごと提出数
          const totalPossible = members.length * activeDayDates.length;
          const totalActual = daily.filter(function(d){ return activeDayDates.indexOf(d.day_key) >= 0; }).length;
          const weekDailyRate = totalPossible > 0 ? Math.round(totalActual / totalPossible * 100) : 0;
          // 計画提出率
          const planCount = plans.length;
          const planRate = members.length > 0 ? Math.round(planCount / members.length * 100) : 0;
          const planMissing = members.filter(function(m){ return !planByUser[m.id]; });
          // 振り返り提出率
          const refCount = reflections.length;
          const refRate = members.length > 0 ? Math.round(refCount / members.length * 100) : 0;
          const refMissing = members.filter(function(m){ return !refByUser[m.id]; });
          // 先週比
          var prevTotal = 0; for(var uid in prevByUser) prevTotal += prevByUser[uid];
          var prevTotalVal = 0; for(var uid2 in prevByUser) prevTotalVal += prevByUser[uid2];
          const weekDiff = totalActual - prevTotalVal;
          const weekDiffLabel = weekDiff > 0 ? '+'+weekDiff : String(weekDiff);

          // 週ラベル
          var dashWeekEl = document.getElementById('dashWeekLabel');
          if(dashWeekEl) dashWeekEl.textContent = '📅 ' + weekKey + '（' + escH(data.className||'') + '）';

          var html = '';

          // ====== サマリーカード ======
          html += '<div class="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-4">';
          // 今日の提出率
          var todayColor = todayRate >= 80 ? 'text-emerald-600' : todayRate >= 50 ? 'text-yellow-600' : 'text-red-600';
          html += '<div class="bg-white rounded-xl border-2 border-indigo-100 p-3 text-center">';
          html += '<div class="text-3xl font-black '+todayColor+'">'+todayRate+'<span class="text-lg">%</span></div>';
          html += '<div class="text-[10px] text-slate-500 font-bold">📝 今日の振り返り提出率</div>';
          html += '<div class="text-[10px] text-slate-400">'+todaySubmitters.length+'/'+members.length+'人</div>';
          html += '</div>';
          // 今週の日別提出率
          var weekDailyColor = weekDailyRate >= 80 ? 'text-emerald-600' : weekDailyRate >= 50 ? 'text-yellow-600' : 'text-red-600';
          html += '<div class="bg-white rounded-xl border-2 border-blue-100 p-3 text-center">';
          html += '<div class="text-3xl font-black '+weekDailyColor+'">'+weekDailyRate+'<span class="text-lg">%</span></div>';
          html += '<div class="text-[10px] text-slate-500 font-bold">📊 今週の日別提出率</div>';
          html += '<div class="text-[10px] text-slate-400">'+totalActual+'/'+totalPossible+'件</div>';
          html += '</div>';
          // 計画提出率
          var planColor = planRate >= 80 ? 'text-emerald-600' : planRate >= 50 ? 'text-yellow-600' : 'text-red-600';
          html += '<div class="bg-white rounded-xl border-2 border-purple-100 p-3 text-center">';
          html += '<div class="text-3xl font-black '+planColor+'">'+planRate+'<span class="text-lg">%</span></div>';
          html += '<div class="text-[10px] text-slate-500 font-bold">📋 今週の計画提出率</div>';
          html += '<div class="text-[10px] text-slate-400">'+planCount+'/'+members.length+'人</div>';
          html += '</div>';
          // 振り返り提出率
          var refColor = refRate >= 80 ? 'text-emerald-600' : refRate >= 50 ? 'text-yellow-600' : 'text-red-600';
          html += '<div class="bg-white rounded-xl border-2 border-orange-100 p-3 text-center">';
          html += '<div class="text-3xl font-black '+refColor+'">'+refRate+'<span class="text-lg">%</span></div>';
          html += '<div class="text-[10px] text-slate-500 font-bold">💭 週の振り返り提出率</div>';
          html += '<div class="text-[10px] text-slate-400">'+refCount+'/'+members.length+'人</div>';
          html += '</div>';
          html += '</div>';

          // ====== 先週比カード ======
          html += '<div class="bg-gradient-to-r '+(weekDiff>=0?'from-green-50 to-emerald-50 border-green-200':'from-red-50 to-orange-50 border-red-200')+' border rounded-xl p-3 mb-4 flex items-center gap-3">';
          html += '<div class="text-2xl">'+(weekDiff>=0?'📈':'📉')+'</div>';
          html += '<div><div class="font-bold text-sm '+(weekDiff>=0?'text-green-700':'text-red-700')+'">先週比: '+weekDiffLabel+'件</div>';
          html += '<div class="text-[10px] text-slate-500">今週 '+totalActual+'件 / 先週 '+prevTotalVal+'件（日別提出数の合計）</div>';
          html += '</div></div>';

          // ====== 未提出者アラート ======
          if(todayMissing.length > 0){
            html += '<div class="bg-red-50 border border-red-200 rounded-xl p-3 mb-4">';
            html += '<div class="font-bold text-sm text-red-700 mb-2">🔴 今日の振り返り未提出者（'+todayMissing.length+'人）</div>';
            html += '<div class="flex flex-wrap gap-1">';
            for(var ti=0;ti<todayMissing.length;ti++){
              var tm = todayMissing[ti];
              html += '<span class="bg-red-100 text-red-800 px-2 py-0.5 rounded-full text-xs font-bold">'+escH(resolveStudentName(tm.loginId, tm.name))+'</span>';
            }
            html += '</div></div>';
          }
          if(planMissing.length > 0){
            html += '<div class="bg-purple-50 border border-purple-200 rounded-xl p-3 mb-4">';
            html += '<div class="font-bold text-sm text-purple-700 mb-2">📋 計画未提出者（'+planMissing.length+'人）</div>';
            html += '<div class="flex flex-wrap gap-1">';
            for(var pi=0;pi<planMissing.length;pi++){
              var pm = planMissing[pi];
              html += '<span class="bg-purple-100 text-purple-800 px-2 py-0.5 rounded-full text-xs font-bold">'+escH(resolveStudentName(pm.loginId, pm.name))+'</span>';
            }
            html += '</div></div>';
          }
          if(refMissing.length > 0){
            html += '<div class="bg-orange-50 border border-orange-200 rounded-xl p-3 mb-4">';
            html += '<div class="font-bold text-sm text-orange-700 mb-2">💭 週の振り返り未提出者（'+refMissing.length+'人）</div>';
            html += '<div class="flex flex-wrap gap-1">';
            for(var ri=0;ri<refMissing.length;ri++){
              var rm = refMissing[ri];
              html += '<span class="bg-orange-100 text-orange-800 px-2 py-0.5 rounded-full text-xs font-bold">'+escH(resolveStudentName(rm.loginId, rm.name))+'</span>';
            }
            html += '</div></div>';
          }

          // ====== 日別提出マトリックス ======
          html += '<div class="bg-white rounded-xl border p-3 mb-4 overflow-x-auto">';
          html += '<div class="font-bold text-sm text-slate-700 mb-2">📅 日別提出マトリックス</div>';
          html += '<table class="w-full text-xs border-collapse">';
          html += '<thead><tr><th class="text-left p-1.5 text-slate-500 border-b sticky left-0 bg-white z-10 min-w-[80px]">児童名</th>';
          for(var wi=0;wi<weekDays.length;wi++){
            var wd = weekDays[wi];
            var thClass = wd.date === todayKey ? 'bg-indigo-50 text-indigo-700 font-black' : 'text-slate-500';
            var activeLabel = wd.isActive ? '' : '<br><span class="text-[8px] text-slate-300">(休)</span>';
            html += '<th class="p-1.5 text-center border-b '+thClass+'">'+wd.label+activeLabel+'</th>';
          }
          html += '<th class="p-1.5 text-center border-b text-slate-500">計画</th>';
          html += '<th class="p-1.5 text-center border-b text-slate-500">振返り</th>';
          html += '<th class="p-1.5 text-center border-b text-slate-500">提出数</th>';
          html += '</tr></thead><tbody>';

          for(var mi=0;mi<members.length;mi++){
            var m = members[mi];
            var userDays = dailyByUser[m.id] || {};
            var userSubmitCount = 0;
            html += '<tr class="'+(mi%2===0?'bg-white':'bg-slate-50')+' hover:bg-indigo-50">';
            html += '<td class="p-1.5 font-bold text-slate-700 border-b whitespace-nowrap sticky left-0 '+(mi%2===0?'bg-white':'bg-slate-50')+'">';
            html += '<span class="cursor-pointer hover:text-indigo-600 hover:underline" onclick="openStudentFullAnalysis(&#39;'+escH(m.id)+'&#39;,&#39;'+escH(resolveStudentName(m.loginId, m.name))+'&#39;)">'+escH(resolveStudentName(m.loginId, m.name))+'</span>';
            html += '</td>';
            for(var di=0;di<weekDays.length;di++){
              var day = weekDays[di];
              var sub = userDays[day.date];
              var cellHtml = '';
              var cellClass = 'p-1.5 text-center border-b ';
              if(day.date === todayKey) cellClass += 'bg-indigo-50 ';
              if(!day.isActive){
                cellHtml = '<span class="text-slate-200">-</span>';
                cellClass += 'bg-slate-50 ';
              } else if(sub){
                userSubmitCount++;
                var wIcon = sub.end_weather==='sun'?'☀️':sub.end_weather==='cloud'?'☁️':sub.end_weather==='rain'?'🌧️':'✅';
                var retIcon = sub.returned_at ? '<span class="text-[8px] text-green-500">✓返</span>' : (sub.teacher_comment ? '<span class="text-[8px] text-blue-500">💬</span>' : '');
                cellHtml = '<div class="leading-tight">'+wIcon+'<div class="text-[9px] text-slate-400">'+( sub.minutes||0)+'分</div>'+retIcon+'</div>';
                cellClass += 'bg-green-50 ';
              } else if(day.isPast){
                cellHtml = '<span class="text-red-400 font-bold">✗</span>';
                cellClass += 'bg-red-50 ';
              } else {
                cellHtml = '<span class="text-slate-200">-</span>';
              }
              html += '<td class="'+cellClass+'">'+cellHtml+'</td>';
            }
            // 計画
            var plan = planByUser[m.id];
            if(plan){
              var approvedBadge = plan.plan_approved ? '✅' : '📝';
              var revBadge = plan.revision_count > 0 ? '<div class="text-[8px] text-orange-500">修正'+plan.revision_count+'回</div>' : '';
              html += '<td class="p-1.5 text-center border-b bg-blue-50">'+approvedBadge+revBadge+'</td>';
            } else {
              html += '<td class="p-1.5 text-center border-b bg-red-50"><span class="text-red-400 font-bold">✗</span></td>';
            }
            // 振り返り
            var ref = refByUser[m.id];
            if(ref){
              var concBadge = ref.concentration ? '★'.repeat(Math.min(ref.concentration,5)) : '✅';
              html += '<td class="p-1.5 text-center border-b bg-purple-50"><span class="text-[10px]">'+concBadge+'</span></td>';
            } else {
              html += '<td class="p-1.5 text-center border-b bg-red-50"><span class="text-red-400 font-bold">✗</span></td>';
            }
            // 提出数
            var submitBarW = activeDayDates.length > 0 ? Math.round(userSubmitCount / activeDayDates.length * 100) : 0;
            var submitColor = submitBarW >= 80 ? 'bg-emerald-400' : submitBarW >= 50 ? 'bg-yellow-400' : 'bg-red-400';
            html += '<td class="p-1.5 border-b"><div class="flex items-center gap-1"><div class="w-12 bg-slate-100 rounded-full h-3 overflow-hidden"><div class="'+submitColor+' h-full rounded-full" style="width:'+submitBarW+'%"></div></div><span class="text-[10px] font-bold text-slate-600">'+userSubmitCount+'/'+activeDayDates.length+'</span></div></td>';
            html += '</tr>';
          }
          html += '</tbody></table></div>';

          // ====== 返却状況 ======
          var returnedCount = 0;
          var unreturned = [];
          for(var si=0;si<daily.length;si++){
            if(daily[si].day_key === todayKey){
              if(daily[si].returned_at) returnedCount++;
              else unreturned.push(daily[si]);
            }
          }
          if(todaySubmitters.length > 0){
            html += '<div class="bg-blue-50 border border-blue-200 rounded-xl p-3 mb-4">';
            html += '<div class="font-bold text-sm text-blue-700 mb-1">🔄 今日の返却状況</div>';
            html += '<div class="flex gap-4 items-center">';
            html += '<div class="text-lg font-black text-blue-600">'+returnedCount+'/'+todaySubmitters.length+'</div>';
            html += '<div class="text-xs text-slate-500">返却済み</div>';
            if(unreturned.length > 0){
              html += '<div class="text-xs text-orange-600 font-bold">未返却: '+unreturned.length+'件</div>';
            } else {
              html += '<div class="text-xs text-green-600 font-bold">✅ 全件返却済み</div>';
            }
            html += '</div></div>';
          }

          // ====== 個人別サマリー(折りたたみ) ======
          html += '<details class="bg-white rounded-xl border p-3">';
          html += '<summary class="font-bold text-sm text-slate-700 cursor-pointer">👤 個人別サマリー（クリックで展開）</summary>';
          html += '<div class="mt-3 space-y-2">';
          for(var si2=0;si2<members.length;si2++){
            var student = members[si2];
            var sName = resolveStudentName(student.loginId, student.name);
            var sDays = dailyByUser[student.id] || {};
            var sCount = 0;
            var sTotalMin = 0;
            for(var dk in sDays){ sCount++; sTotalMin += (sDays[dk].minutes||0); }
            var sPlan = planByUser[student.id];
            var sRef = refByUser[student.id];
            var sPrev = prevByUser[student.id] || 0;
            var sDiff = sCount - sPrev;
            var diffIcon = sDiff > 0 ? '📈+'+sDiff : sDiff < 0 ? '📉'+sDiff : '→';
            var statusBadges = [];
            if(!sPlan) statusBadges.push('<span class="bg-red-100 text-red-700 px-1 rounded text-[9px]">計画✗</span>');
            if(!sRef) statusBadges.push('<span class="bg-orange-100 text-orange-700 px-1 rounded text-[9px]">振返り✗</span>');
            if(sCount === 0 && activeDayDates.length > 0) statusBadges.push('<span class="bg-red-200 text-red-800 px-1 rounded text-[9px] font-bold">未提出</span>');
            html += '<div class="flex items-center gap-2 text-xs p-2 rounded-lg '+(sCount===0&&activeDayDates.length>0?'bg-red-50 border border-red-200':'bg-slate-50 border')+'">';
            html += '<div class="font-bold text-slate-700 w-20 truncate cursor-pointer hover:text-indigo-600" onclick="openStudentFullAnalysis(&#39;'+escH(student.id)+'&#39;,&#39;'+escH(sName)+'&#39;)">'+escH(sName)+'</div>';
            html += '<div class="text-slate-500">提出'+sCount+'回</div>';
            html += '<div class="text-slate-500">計'+sTotalMin+'分</div>';
            html += '<div class="text-slate-400">'+diffIcon+'</div>';
            html += '<div class="flex gap-0.5 flex-wrap">'+statusBadges.join('')+'</div>';
            html += '<button onclick="openStudentFullAnalysis(&#39;'+escH(student.id)+'&#39;,&#39;'+escH(sName)+'&#39;)" class="text-[9px] bg-indigo-100 text-indigo-700 px-1.5 py-0.5 rounded font-bold hover:bg-indigo-200 ml-auto">📊詳細</button>';
            html += '</div>';
          }
          html += '</div></details>';

          wrap.innerHTML = html;
        }catch(e){
          wrap.innerHTML='<p class="text-red-600 text-sm">エラー: '+escH(String(e.message||e))+'</p>';
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
          btn.className = 'px-3 py-1.5 rounded-lg text-xs font-bold border border-indigo-300 bg-indigo-50 hover:bg-indigo-100 text-indigo-800 transition';
          const __n = resolveStudentName(s.loginId, s.name);
          btn.textContent = '📊 ' + __n;
          btn.onclick = (function(id, name){ return function(){ openStudentFullAnalysis(id, name); }; })(s.userId || s.name, __n);
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
          var __hName = resolveStudentName(s.loginId, s.name);
          html += '<td class="p-1 font-bold text-slate-700 whitespace-nowrap cursor-pointer hover:text-indigo-600" onclick="openStudentFullAnalysis(&#39;'+escH(s.userId||s.name)+'&#39;,&#39;'+escH(__hName)+'&#39;)">' + escH(__hName) + '</td>';
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

            // 個人全期間分析を開く
      async function openStudentFullAnalysis(studentId, studentName){
        var overlay = document.getElementById('studentFullAnalysisOverlay');
        if (overlay && overlay.parentElement !== document.body) document.body.appendChild(overlay);
        var nameEl = document.getElementById('fullAnalysisStudentName');
        var contentEl = document.getElementById('fullAnalysisContent');
        overlay.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
        nameEl.textContent = '📊 ' + studentName + ' の個人分析';
        contentEl.innerHTML = '<p class="text-indigo-500 animate-pulse text-sm">📊 全期間のデータを取得中...</p>';
        overlay.scrollTop = 0;
        try {
          var res = await fetch('/api/teacher/student-full-analysis?studentId=' + encodeURIComponent(studentId));
          var data = await res.json();
          if(!data.ok){ contentEl.innerHTML = '<p class="text-red-500 text-sm">データの取得に失敗しました</p>'; return; }
          var html = '';
          var ov = data.overview || {};

          // === 概要統計カード ===
          html += '<div class="grid grid-cols-3 sm:grid-cols-6 gap-2 mb-4">';
          html += _faStatCard('📝', ov.totalSubmissions, '提出回数', 'blue');
          html += _faStatCard('⏱️', ov.avgMinutes+'分', '平均学習時間', 'green');
          html += _faStatCard('☀️', ov.sunRate+'%', '満足度', 'amber');
          html += _faStatCard('🔥', ov.currentStreak+'日', '現在の連続', 'red');
          html += _faStatCard('🏆', ov.maxStreak+'日', '最長連続', 'purple');
          html += _faStatCard('📋', ov.totalPlans, '計画提出数', 'indigo');
          html += '</div>';

          // 期間情報
          if(ov.firstDate){
            html += '<div class="bg-slate-50 rounded-lg p-2 mb-4 text-xs text-slate-500 flex gap-4 flex-wrap">';
            html += '<span>📅 初回: '+escH(ov.firstDate)+'</span>';
            html += '<span>📅 最終: '+escH(ov.lastDate)+'</span>';
            html += '<span>⏱️ 合計: '+ov.totalMinutes+'分 ('+Math.round(ov.totalMinutes/60)+'時間)</span>';
            html += '<span>🔄 返却率: '+ov.returnRate+'%</span>';
            html += '<span>✅ 計画承認率: '+ov.planCompletionRate+'%</span>';
            html += '</div>';
          }

          // === 月別提出推移 ===
          if(data.monthlyTrends && data.monthlyTrends.length > 0){
            html += '<div class="bg-white rounded-xl border p-4 mb-4">';
            html += '<div class="font-bold text-sm text-slate-700 mb-3">📊 月別提出回数の推移</div>';
            var maxCount = Math.max.apply(null, data.monthlyTrends.map(function(t){return t.count;}));
            html += '<div class="flex items-end gap-1 overflow-x-auto pb-1" style="height:140px">';
            for(var ti=0; ti<data.monthlyTrends.length; ti++){
              var t = data.monthlyTrends[ti];
              var hPct = maxCount > 0 ? Math.max(Math.round(t.count / maxCount * 100), 5) : 5;
              var barColor = t.sunRate >= 70 ? 'bg-green-400' : t.sunRate >= 40 ? 'bg-yellow-400' : 'bg-blue-400';
              html += '<div class="flex flex-col items-center justify-end min-w-[36px]" style="height:100%">';
              html += '<div class="text-[9px] text-slate-500 mb-1">'+t.count+'</div>';
              html += '<div class="w-7 '+barColor+' rounded-t" style="height:'+hPct+'%"></div>';
              html += '<div class="text-[8px] text-slate-400 mt-1 whitespace-nowrap">'+t.month.slice(5)+'月</div>';
              html += '</div>';
            }
            html += '</div>';
            html += '<div class="flex gap-3 mt-2 text-[9px] text-slate-400"><span>🟢 満足度70%+ 🟡 40-69% 🔵 39%以下</span></div>';
            html += '</div>';
          }

          // === 提出カレンダー（直近6ヶ月） ===
          if(data.calendar && Object.keys(data.calendar).length > 0){
            html += '<div class="bg-white rounded-xl border p-4 mb-4">';
            html += '<div class="font-bold text-sm text-slate-700 mb-3">🗓️ 提出カレンダー（直近6ヶ月）</div>';
            html += _renderFullCalendar(data.calendar);
            html += '</div>';
          }

          // === 学習満足度の分布 ===
          html += '<div class="bg-white rounded-xl border p-4 mb-4">';
          html += '<div class="font-bold text-sm text-slate-700 mb-3">🌤️ 学習満足度の分布</div>';
          var totalW = (ov.sunCount||0)+(ov.cloudCount||0)+(ov.rainCount||0);
          if(totalW > 0){
            var sunW = Math.round(ov.sunCount/totalW*100);
            var cloudW = Math.round(ov.cloudCount/totalW*100);
            var rainW = Math.round(ov.rainCount/totalW*100);
            html += '<div class="flex items-center gap-2 mb-2">';
            html += '<div class="flex-1 h-6 rounded-full overflow-hidden flex">';
            if(sunW>0) html += '<div class="bg-amber-400 h-full" style="width:'+sunW+'%"></div>';
            if(cloudW>0) html += '<div class="bg-slate-300 h-full" style="width:'+cloudW+'%"></div>';
            if(rainW>0) html += '<div class="bg-blue-400 h-full" style="width:'+rainW+'%"></div>';
            html += '</div></div>';
            html += '<div class="flex gap-4 text-xs text-slate-600">';
            html += '<span>☀️ '+ov.sunCount+'回 ('+sunW+'%)</span>';
            html += '<span>☁️ '+ov.cloudCount+'回 ('+cloudW+'%)</span>';
            html += '<span>🌧️ '+ov.rainCount+'回 ('+rainW+'%)</span>';
            html += '</div>';
          } else {
            html += '<p class="text-xs text-slate-400">データなし</p>';
          }
          html += '</div>';

          // === 教科別成績 ===
          if(data.subjects && data.subjects.length > 0){
            html += '<div class="bg-white rounded-xl border p-4 mb-4">';
            html += '<div class="font-bold text-sm text-slate-700 mb-3">📚 教科別成績</div>';
            var _sg2=(data.student&&data.student.grade)||null;
            html += '<div class="space-y-2">';
            for(var si=0; si<data.subjects.length; si++){
              var sub = data.subjects[si];
              var sColor = sub.rate >= 80 ? 'bg-green-400' : sub.rate >= 60 ? 'bg-yellow-400' : 'bg-red-400';
              html += '<div class="flex items-center gap-2">';
              html += '<span class="text-xs w-20 text-slate-600 font-bold truncate">'+escH(_unitJa(sub.unit))+'</span>';
              html += '<div class="flex-1 bg-slate-100 rounded-full h-5"><div class="'+sColor+' rounded-full h-5 text-[10px] text-white flex items-center justify-center font-bold" style="width:'+Math.max(sub.rate,5)+'%">'+sub.rate+'%</div></div>';
              var _gc=_gradeClass(_sg2,_unitGrade(sub.unit)); var _gb=_gc==='review'?' <span class="text-[8px] bg-sky-100 text-sky-700 px-1 rounded">復習</span>':_gc==='ahead'?' <span class="text-[8px] bg-violet-100 text-violet-700 px-1 rounded">先取り</span>':''; html += '<span class="text-[10px] text-slate-400 w-12 text-right">'+sub.total+'問</span>'+_gb;
              html += '</div>';
            }
            html += '</div></div>';
          }

          // === 連続提出記録 ===
          if(data.streaks && data.streaks.length > 0){
            html += '<div class="bg-white rounded-xl border p-4 mb-4">';
            html += '<div class="font-bold text-sm text-slate-700 mb-3">🔥 連続提出記録 TOP5</div>';
            html += '<div class="space-y-1">';
            var medals = ['🥇','🥈','🥉','4️⃣','5️⃣'];
            for(var ski=0; ski<Math.min(data.streaks.length,5); ski++){
              var sk = data.streaks[ski];
              html += '<div class="flex items-center gap-2 text-xs bg-slate-50 rounded-lg p-2">';
              html += '<span class="text-base">'+(medals[ski]||'')+'</span>';
              html += '<span class="font-black text-indigo-600 text-lg">'+sk.length+'日</span>';
              html += '<span class="text-slate-400">'+escH(sk.start)+' → '+escH(sk.end)+'</span>';
              html += '</div>';
            }
            html += '</div></div>';
          }

          // === 計画・振り返り履歴 ===
          if((data.plans && data.plans.length > 0)||(data.reflections && data.reflections.length > 0)){
            html += '<div class="bg-white rounded-xl border p-4 mb-4">';
            html += '<div class="font-bold text-sm text-slate-700 mb-3">📋 計画・振り返り履歴</div>';
            var allWeeks = {};
            if(data.plans) for(var pi=0;pi<data.plans.length;pi++) allWeeks[data.plans[pi].weekKey]=true;
            if(data.reflections) for(var ri=0;ri<data.reflections.length;ri++) allWeeks[data.reflections[ri].weekKey]=true;
            var sortedWeeks = Object.keys(allWeeks).sort().reverse();
            html += '<div class="space-y-1 max-h-64 overflow-y-auto">';
            for(var wi=0; wi<sortedWeeks.length; wi++){
              var wk = sortedWeeks[wi];
              var plan = null; var ref = null;
              if(data.plans) for(var pj=0;pj<data.plans.length;pj++){ if(data.plans[pj].weekKey===wk){plan=data.plans[pj];break;} }
              if(data.reflections) for(var rj=0;rj<data.reflections.length;rj++){ if(data.reflections[rj].weekKey===wk){ref=data.reflections[rj];break;} }
              html += '<div class="flex items-center gap-2 text-xs p-2 bg-slate-50 rounded-lg border flex-wrap">';
              html += '<span class="font-bold text-slate-500 w-20">'+escH(wk)+'</span>';
              if(plan){
                html += plan.approved ? '<span class="bg-green-100 text-green-700 px-1.5 rounded text-[9px]">✅承認</span>' : '<span class="bg-yellow-100 text-yellow-700 px-1.5 rounded text-[9px]">📝提出</span>';
                if(plan.revisionCount>0) html += '<span class="bg-orange-100 text-orange-700 px-1 rounded text-[9px]">修正'+plan.revisionCount+'回</span>';
              } else {
                html += '<span class="bg-red-100 text-red-700 px-1.5 rounded text-[9px]">計画✗</span>';
              }
              if(ref){
                var stars = '';
                for(var ci=0;ci<Math.min(ref.concentration||0,3);ci++) stars+='★';
                html += '<span class="bg-purple-100 text-purple-700 px-1.5 rounded text-[9px]">振返り 集中'+stars+'</span>';
              } else {
                html += '<span class="bg-red-100 text-red-700 px-1.5 rounded text-[9px]">振返り✗</span>';
              }
              html += '</div>';
            }
            html += '</div></div>';
          }

          // === 先生の記録（授業メモ） ===
          html += '<div class="bg-white rounded-xl border p-4 mb-4">';
          html += '<div class="font-bold text-sm text-slate-700 mb-2">📝 先生の記録</div>';
          if(data.teacherNotes && data.teacherNotes.length){
            html += '<div class="space-y-1 max-h-48 overflow-y-auto mb-3">';
            for(var tni=0; tni<data.teacherNotes.length; tni++){
              var tnn = data.teacherNotes[tni];
              var kbadge = tnn.showInKarte ? '<span class="text-[8px] bg-rose-100 text-rose-700 px-1 rounded ml-1">カルテ掲載</span>' : '';
              html += '<div class="text-xs bg-slate-50 rounded p-1.5 border"><span class="text-slate-400">'+escH(tnn.dayKey||'')+'</span> '+escH(tnn.body||'')+kbadge+'</div>';
            }
            html += '</div>';
          } else { html += '<div class="text-xs text-slate-400 mb-3">まだ記録はありません</div>'; }
          html += '<div class="flex flex-col gap-1 bg-slate-50 rounded-lg p-2">';
          html += '<input id="faNoteDate" type="date" class="border rounded p-1 text-xs w-40" value="'+escH(new Date().toISOString().slice(0,10))+'">';
          html += '<input id="faNoteBody" class="border rounded p-1 text-xs" placeholder="例：発表でしっかり説明できた">';
          html += '<label class="flex items-center gap-1 text-[11px] text-slate-600"><input id="faNoteKarte" type="checkbox"> カルテ（子ども向け）にも載せる</label>';
          html += '<div class="flex items-center gap-2"><button onclick="saveQuickStudentNote()" class="bg-teal-600 text-white rounded-lg px-3 py-1 text-xs font-bold hover:bg-teal-700">💾 メモを保存</button><span id="faNoteStatus" class="text-xs text-teal-600 font-bold"></span></div>';
          html += '</div>';
          html += '</div>';

          // === 学習の記録（ポートフォリオ） ===
          (function(){
            var pf=[];
            var tss=data.testScores||[];
            for(var ti=0; ti<tss.length; ti++){ var t2=tss[ti]; pf.push({kind:'test', day:(t2.testDate||''), subject:(t2.subject||''), unit:'', title:(t2.testName||''), score:t2.score, maxScore:t2.maxScore, pct:t2.pct, body:''}); }
            var rcs=data.records||[];
            for(var ri=0; ri<rcs.length; ri++){ var rc=rcs[ri]; pf.push({kind:(rc.type||'other'), day:(rc.dayKey||''), subject:(rc.subject||''), unit:(rc.unit||''), title:(rc.title||''), body:(rc.body||'')}); }
            if(pf.length>0){
              pf.sort(function(a,b){ var x=String(a.day||''); var y=String(b.day||''); if(x===y) return 0; if(!x) return 1; if(!y) return -1; return x<y?1:-1; });
              var meta=function(k){ if(k==='test') return {icon:'📝',label:'テスト',cls:'bg-blue-100 text-blue-700',bar:'border-blue-300'}; if(k==='report') return {icon:'🔍',label:'まとめ',cls:'bg-green-100 text-green-700',bar:'border-green-300'}; if(k==='reflect') return {icon:'🪞',label:'振り返り',cls:'bg-amber-100 text-amber-700',bar:'border-amber-300'}; return {icon:'📌',label:'その他',cls:'bg-slate-100 text-slate-600',bar:'border-slate-300'}; };
              html += '<div class="bg-white rounded-xl border p-4 mb-4">';
              html += '<div class="font-bold text-sm text-slate-700 mb-3">📚 学習の記録（ポートフォリオ） <span class="text-[10px] text-slate-400 font-normal">'+pf.length+'件</span></div>';
              html += '<div class="space-y-2 max-h-96 overflow-y-auto">';
              for(var pi=0; pi<pf.length; pi++){
                var it=pf[pi]; var mt=meta(it.kind);
                html += '<div class="border-l-4 '+mt.bar+' bg-slate-50 rounded p-2">';
                html += '<div class="flex items-center gap-1 flex-wrap text-xs">';
                html += '<span class="text-slate-400">'+escH(it.day||'(日付なし)')+'</span>';
                html += '<span class="text-[10px] '+mt.cls+' px-1.5 rounded font-bold">'+mt.icon+' '+mt.label+'</span>';
                html += (it.subject ? '<span class="text-[10px] bg-indigo-100 text-indigo-700 px-1 rounded">'+escH(it.subject)+'</span>' : '');
                html += (it.unit ? '<span class="text-[10px] text-slate-500">'+escH(it.unit)+'</span>' : '');
                html += '<span class="text-slate-700 font-bold flex-1 truncate">'+escH(it.title||'(無題)')+'</span>';
                if(it.kind==='test'){ var tp=(it.pct==null)?'':(' ('+it.pct+'%)'); html += '<span class="font-bold text-slate-700 whitespace-nowrap">'+(it.score==null?'-':it.score)+' / '+(it.maxScore||100)+tp+'</span>'; }
                html += '</div>';
                if(it.body && it.body.trim()){ html += '<div class="mt-1 text-xs text-slate-600 whitespace-pre-wrap border-t border-slate-200 pt-1">'+escH(it.body)+'</div>'; }
                html += '</div>';
              }
              html += '</div></div>';
            }
          })();

          // === 直近の学習記録 ===
          if(data.recentSubmissions && data.recentSubmissions.length > 0){
            html += '<div class="bg-white rounded-xl border p-4 mb-4">';
            html += '<div class="font-bold text-sm text-slate-700 mb-3">📝 直近の学習記録</div>';
            html += '<div class="space-y-1 max-h-64 overflow-y-auto">';
            for(var rsi=0; rsi<data.recentSubmissions.length; rsi++){
              var rs = data.recentSubmissions[rsi];
              var wIcon = rs.end_weather==='sun'?'☀️':rs.end_weather==='cloud'?'☁️':rs.end_weather==='rain'?'🌧️':'❓';
              var retBadge = rs.returned_at ? '<span class="text-[8px] text-green-500 ml-1">✓返却</span>' : '';
              html += '<div class="text-xs bg-slate-50 rounded p-1.5 border flex items-center gap-1">';
              html += '<span class="font-bold text-slate-500">'+escH(rs.day_key||'')+'</span> ';
              html += wIcon+' ';
              html += '<span class="text-slate-600 flex-1 truncate">'+escH(rs.todo||'')+'</span> ';
              html += '<span class="text-slate-400">('+( rs.minutes||0)+'分)</span>';
              html += retBadge;
              html += '</div>';
            }
            html += '</div></div>';
          }

          // === AIカルテボタン ===
          window._faData = data; window._faName = studentName; window._faId = studentId; try{ html += _kHowToLearn(data); }catch(_khl){}
          if(data.aiComment){ html += '<div class="bg-violet-50 rounded-xl border border-violet-200 p-4 mb-4"><div class="font-bold text-sm text-violet-800 mb-2">🤖 阪神マンからのアドバイス</div><div class="text-xs text-slate-700" style="white-space:pre-wrap">'+escH(data.aiComment)+'</div></div>'; }
          html += '<div class="bg-white rounded-xl border p-4 mb-4 mt-4">';
          html += '<div class="font-bold text-sm text-slate-700 mb-2">🤖 外部AI（ChatGPT・Geminiなど）で分析</div>';
          html += '<label class="flex items-center gap-2 text-xs text-slate-600 mb-2"><input type="checkbox" id="faIncludeName" checked> 児童名を含める</label>';
          html += '<div class="flex items-center gap-2 flex-wrap">';
          html += '<button onclick="copyAiAnalysisText()" class="bg-emerald-600 text-white rounded-lg px-4 py-2 text-sm font-bold hover:bg-emerald-700">📋 AI分析用テキストをコピー</button>';
          html += '<button onclick="downloadKartePdf()" class="bg-rose-600 text-white rounded-lg px-4 py-2 text-sm font-bold hover:bg-rose-700">📄 カルテをPDFでダウンロード</button>';
          html += '<span id="faCopyStatus" class="text-xs text-emerald-600 font-bold"></span>';
          html += '</div>';
          html += '<div class="text-[10px] text-slate-400 mt-2">コピーしてChatGPTやGeminiに貼り付けると、先生向けの分析コメントが作れます</div>';
          html += '</div>';
          html += '<div class="text-center mt-4">';
          html += '<button onclick="closeStudentFullAnalysis();openStudentKarte(&#39;'+escH(studentId)+'&#39;,&#39;'+escH(studentName)+'&#39;)" class="bg-purple-600 text-white rounded-lg px-4 py-2 text-sm font-bold hover:bg-purple-700">🤖 AIカルテを表示</button>';
          html += '</div>';

          contentEl.innerHTML = html;
        } catch(e) {
          contentEl.innerHTML = '<p class="text-red-500 text-sm">エラー: '+escH(String(e.message||e))+'</p>';
        }
      }

      function _buildAiAnalysisText(){
        var data = window._faData || {}; var ov = data.overview || {};
        var includeName = true; var cb = document.getElementById('faIncludeName'); if(cb) includeName = !!cb.checked;
        var name = includeName ? (window._faName || '児童') : '（匿名児童）';
        var NL = String.fromCharCode(10); var L = [];
        L.push('あなたはアプリの修行エリアにいる関西弁の応援キャラ「阪神マン」です。以下の児童の家庭学習データをもとに、①ええところ（取り組みの良い点）②気になるところ③おすすめの学習・声かけ、を関西弁で、子どもが読んで前向きになれるようにやさしくまとめてください。学年に合わせて声かけを変えること：【下の学年の復習】は「ようがんばって復習できたな！次はいまの学年の◯◯に進もか」、【いまの学年（学年相当）】は出来をしっかりほめる、【先取り（上の学年）】は「まだ習ってへんのにスゴいやん！」と認める。おすすめは具体的に——単元名・つまずきやすいポイント・次の一歩（何を何分やるか）まで書く。下の学年が未定着なら「まず◯年の◯◯を復習→いまの学年へ」と段階で示す。やりすぎず、先生がそのまま児童に渡せる文章にしてください。');
        L.push('');
        L.push('■ 児童: ' + name);
        var _sg3=(data.student&&data.student.grade)||null; if(_sg3) L.push('■ 学年: ' + _sg3 + '年生（各単元の「対象学年」は教科別に明記。対象学年が本人より下＝復習、同じ＝学年相当、上＝先取り）');
        L.push('');
        L.push('【基本統計】');
        L.push('・提出回数: ' + (ov.totalSubmissions||0) + '回');
        L.push('・平均学習時間: ' + (ov.avgMinutes||0) + '分');
        L.push('・学習満足度（☀️の割合）: ' + (ov.sunRate||0) + '%');
        L.push('・現在の連続提出: ' + (ov.currentStreak||0) + '日 / 最長連続: ' + (ov.maxStreak||0) + '日');
        if(ov.firstDate) L.push('・記録期間: ' + ov.firstDate + ' 〜 ' + ov.lastDate);
        if(ov.totalMinutes!=null) L.push('・合計学習時間: ' + ov.totalMinutes + '分（約' + Math.round((ov.totalMinutes||0)/60) + '時間）');
        if(ov.returnRate!=null) L.push('・先生からの返却率: ' + ov.returnRate + '%');
        if(ov.planCompletionRate!=null) L.push('・計画の承認率: ' + ov.planCompletionRate + '%');
        var tw = (ov.sunCount||0)+(ov.cloudCount||0)+(ov.rainCount||0);
        if(tw>0) L.push('・満足度の内訳: ☀️' + (ov.sunCount||0) + '回 / ☁️' + (ov.cloudCount||0) + '回 / 🌧️' + (ov.rainCount||0) + '回');
        if(data.monthlyTrends && data.monthlyTrends.length){ L.push(''); L.push('【月別の提出回数の推移】'); for(var i=0;i<data.monthlyTrends.length;i++){ var t=data.monthlyTrends[i]; L.push('・' + t.month + ': ' + t.count + '回（満足度' + (t.sunRate!=null?t.sunRate+'%':'-') + '・平均' + (t.avgMin||0) + '分）'); } }
        if(data.subjects && data.subjects.length){ var _sg4=(data.student&&data.student.grade)||null; L.push(''); L.push('【教科別の正答率（取り組み量の多い順／対象学年つき）】'); for(var j=0;j<data.subjects.length;j++){ var su=data.subjects[j]; var _ug=_unitGrade(su.unit); var _lab=_gradeLabel(_gradeClass(_sg4,_ug))||'対象学年不明'; L.push('・' + _unitJa(su.unit) + '（' + (_ug?('対象'+_ug+'年・'):'') + _lab + '）: 正答率' + su.rate + '%（' + su.total + '問）'); } }
        if(data.teacherNotes && data.teacherNotes.length){ L.push(''); L.push('【先生の観察メモ（授業中の様子・教師向け）】'); for(var tn=0;tn<Math.min(data.teacherNotes.length,15);tn++){ var nt=data.teacherNotes[tn]; L.push('・'+(nt.dayKey||'')+' '+(nt.body||'')); } } if(data.streaks && data.streaks.length){ L.push(''); L.push('【連続提出の記録（上位）】'); for(var k=0;k<Math.min(data.streaks.length,3);k++){ var sk=data.streaks[k]; L.push('・' + sk.length + '日連続（' + sk.start + ' 〜 ' + sk.end + '）'); } }
        if(data.reflections && data.reflections.length){ L.push(''); L.push('【最近のふりかえり（本人の記録）】'); for(var m=0;m<Math.min(data.reflections.length,5);m++){ var rf=data.reflections[m]; var ps=[]; if(rf.concentration!=null) ps.push('集中度' + rf.concentration + '/3'); if(rf.goodPoint) ps.push('よかった点:' + rf.goodPoint); if(rf.improvePoint) ps.push('直したい点:' + rf.improvePoint); if(rf.nextAction) ps.push('次の目標:' + rf.nextAction); L.push('・[' + (rf.weekKey||'') + '] ' + (ps.length?ps.join(' / '):'記録あり')); } }
        if(data.recentSubmissions && data.recentSubmissions.length){ L.push(''); L.push('【直近の学習記録】'); for(var n=0;n<Math.min(data.recentSubmissions.length,12);n++){ var rs=data.recentSubmissions[n]; var w = rs.end_weather==='sun'?'☀️':rs.end_weather==='cloud'?'☁️':rs.end_weather==='rain'?'🌧️':'❓'; var line='・' + (rs.day_key||'') + ' ' + w + ' ' + (rs.todo||'') + '（' + (rs.minutes||0) + '分）'; if(rs.weather_reason) line += ' ふりかえり:' + rs.weather_reason; L.push(line); } }
        L.push('');
        L.push('※先生がそのまま使えるよう、具体的でやさしい言葉でお願いします。');
        return L.join(NL);
      }
      function _faFallbackCopy(txt){ try{ var ta=document.createElement('textarea'); ta.value=txt; ta.style.position='fixed'; ta.style.left='-9999px'; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); }catch(e){} }
      function copyAiAnalysisText(){
        var s=document.getElementById('faCopyStatus');
        try{ var txt=_buildAiAnalysisText(); var done=function(){ if(s){ s.textContent='✓ コピーしました'; setTimeout(function(){ s.textContent=''; },3000); } };
          if(navigator.clipboard && navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done, function(){ _faFallbackCopy(txt); done(); }); }
          else { _faFallbackCopy(txt); done(); }
        }catch(e){ if(s) s.textContent='コピー失敗'; }
      }
      window.UNIT_JP = {'kuku':'九九','m3-divR':'わり算(あまりあり)','s6-hist':'歴史(6年)','m6-speed':'速さ(6年)','area':'面積','brackets':'計算の順序','conjunction':'つなぎ言葉','decimal':'小数(×÷)','division':'わり算(暗算)','fraction-mixed':'分数','idiom':'慣用句','j1-kanji':'かんじ(1年80字)','j2-kanji':'漢字(2年160字)','j3-kanji':'漢字(3年)','j3-kotowaza':'ことわざ','j3-romaji':'ローマ字','j4-kanji':'漢字(4年)','j5-homoph':'同音異義語','j5-kanji':'漢字(5年)','j5-keigo':'敬語','j6-bunpo':'文法まとめ','j6-classic':'古典','j6-kanji':'漢字(6年)','long-division':'筆算(わり算)','m1-3num':'3つのかずのけいさん','m1-add-cy':'たしざん(くり上がり)','m1-add-no':'たしざん(くり上がりなし)','m1-sub-bo':'ひきざん(くり下がり)','m1-sub-no':'ひきざん(くり下がりなし)','m2-add2':'たし算(2けた)','m2-kuku':'九九','m2-length':'長さ(cm, mm)','m2-sub2':'ひき算(2けた)','m3-div0':'わり算(あまりなし)','m3-large':'大きい数の位','m3-mul1':'かけ算(2けた×1けた)','m3-weight':'重さ(g, kg)','m5-avg':'平均','m5-dec-div':'小数÷小数','m5-dec-mul':'小数×小数','m5-frac-eq':'約分と通分','m5-percent':'割合(百分率)','m5-polygon':'多角形の角','m5-speed':'速さ','m5-unit-qty':'単位量あたり','m5-volume':'体積','m6-circle':'円の面積','m6-expression':'文字と式','m6-frac-dec':'小数と分数','m6-frac-div':'分数÷分数','m6-frac-int':'分数×÷整数','m6-frac-mixed':'帯分数の計算','m6-frac-mul':'分数×分数','m6-frac-triple':'分数3つの計算','m6-proportion':'比例と反比例','m6-ratio':'比','r3-insect':'こん虫の体','r3-light':'光の性質','r3-magnet':'じしゃく','r5-dissolve':'もののとけ方','r5-flow':'流れる水のはたらき','r5-human':'人のたんじょう','r5-magnet2':'電磁石','r5-medaka':'メダカのたんじょう','r5-pendulum':'ふりこ','r5-plant':'植物の発芽と成長','r5-weather':'天気の変化','r6-aqueous':'水溶液の性質','r6-body':'体のつくり(発展)','r6-combust':'ものの燃え方','r6-earth':'大地のつくり','r6-electric':'電気の利用','r6-environment':'生物と地球環境','r6-lever':'てこのはたらき','r6-moon':'月と太陽','r6-plant':'植物のつくりとはたらき','rounding':'がい数','s3-map':'地図記号','s4-disaster':'自然災害からくらしを守る','s4-garbage':'ごみのしょりと利用','s4-inuyama':'犬山祭り','s4-minamichita':'南知多町','s4-toyohashi':'豊橋市','s4-water':'水はどこから','s5-agri':'農業','s5-disaster':'自然災害を防ぐ','s5-env':'国土と環境','s5-fishery':'水産業','s5-forest':'森林とわたしたちの生活','s5-industry':'工業','s5-info':'情報と産業','s5-land':'国土の地形と気候','s6-hist-u1':'縄文〜古墳','s6-hist-u10':'戦争と人々','s6-hist-u11':'新しい日本へ','s6-hist-u2':'天皇の国づくり','s6-hist-u3':'貴族のくらし','s6-hist-u4':'武士の世の中へ','s6-hist-u5':'室町文化','s6-hist-u6':'天下統一','s6-hist-u7':'江戸の政治','s6-hist-u8':'町人文化','s6-hist-u9':'明治の国づくり','s6-politics':'政治','s6-world':'世界の国々','science-airwater':'空気と水','science-body':'人の体のつくり','science-electric':'電池のはたらき','science-heat':'もののあたたまり方','science-moonstars':'月と星','science-rainwater':'雨水のゆくえ','science-seasons':'季節と生き物','science-temperature-volume':'ものの温度と体積','science-water-change':'すがたを変える水','science-weather':'天気と気温','social':'都道府県','social-nagoyasouth':'名古屋南部の開発','social-seto':'瀬戸のやきもの','yoji':'四字熟語'};
      function _unitJa(id){ return (window.UNIT_JP && window.UNIT_JP[id]) || id; }
      function _subjectArea(id){ var m={'rounding':'math','division':'math','decimal':'math','area':'math','brackets':'math','long-division':'math','fraction-mixed':'math','idiom':'jp','conjunction':'jp','kanji':'jp','social':'soc'}; if(m[id]) return m[id]; var c=(id||'').charAt(0); if(c==='m') return 'math'; if(c==='j') return 'jp'; if(c==='s') return 'soc'; if(c==='r') return 'sci'; return ''; }
      function _unitGrade(id){ id=String(id||''); var M={'kuku':2,'division':3,'long-division':4,'decimal':5,'rounding':4,'area':4,'brackets':4,'fraction-mixed':5,'conjunction':3,'idiom':4,'yoji':5,'social':4,'social-nagoyasouth':3,'social-seto':3,'science-airwater':4,'science-seasons':4,'science-moonstars':4,'science-rainwater':4,'science-temperature-volume':4,'science-water-change':4,'science-weather':4,'science-electric':4,'science-body':4,'science-heat':4}; if(M[id]!=null) return M[id]; var c0=id.charAt(0); if((c0==='m'||c0==='j'||c0==='r'||c0==='s') && id.charAt(2)==='-'){ var dg=id.charAt(1); if(dg>='1'&&dg<='6') return parseInt(dg,10); } return null; }
      function _gradeClass(sg, ug){ if(sg==null||ug==null) return 'unknown'; if(ug===sg) return 'same'; if(ug<sg) return 'review'; return 'ahead'; }
      function _gradeLabel(cl){ return cl==='review'?'復習':cl==='same'?'学年相当':cl==='ahead'?'先取り':''; }
      function _kStudyTip(id){ var T={'j5-keigo':'尊敬語とけんじょう語の取りちがえが多いところ。「先生が言う→おっしゃる」など短い言いかえを声に出して、1日3つ練習しよう。','rounding':'「上から2けた」「百の位まで」など、どこで四捨五入するか先に印をつけてから計算しよう。','idiom':'本やニュースで出会った慣用句を、意味と例文をセットで1日1つためていこう。','conjunction':'「だから・でも・それで」で2つの文をつなぐ練習。教科書の文を1つ選んで言いかえてみよう。','long-division':'たてる→かける→ひく→おろす の4手順を声に出しながら1段ずつ。位をそろえて書くとミスが減るよ。','fraction-mixed':'帯分数と仮分数の行き来でつまずきやすい。図に分けて大きさをイメージしてから計算しよう。','area':'公式の暗記よりも「たて×よこ」の意味から。複雑な形は四角に分けて足し引きしよう。','m6-circle':'半径×半径×3.14。直径と半径の取りちがえが定番ミス。まず図に半径を書きこんでから式を立てよう。','m6-frac-div':'分数のわり算は「ひっくり返してかける」。約分のし忘れに注意。1問だけ図でなぜそうなるか確かめると定着するよ。','m6-frac-mul':'計算の前に約分するとラクで正確。帯分数は仮分数に直してから。','m6-ratio':'比は「何対何」をジュースと水などの具体物でイメージ。比の値とのちがいを1問ずつ確認しよう。','m6-proportion':'片方が2倍で他方も2倍なら比例、半分なら反比例。表に書いて確かめよう。','m6-expression':'xやaに具体的な数を入れて確かめる練習から。文章を式にする所をゆっくり。','m5-speed':'速さ＝道のり÷時間。「は・じ・き」の図で求めるものを指でかくして確認。分と時間の単位変換に注意。','m5-percent':'まず「もとにする量」を見つけるのが第一歩。0.01＝1%の対応を表で確認しよう。','m5-dec-div':'小数のわり算は小数点の移動がカギ。わる数を整数にした分だけ、わられる数も同じだけ動かそう。','m5-frac-eq':'約分・通分は分母の最小公倍数がカギ。九九を使って素早く見つけよう。','m5-unit-qty':'「1あたりの量」をそろえて比べる。どちらが1あたりか言葉で確認してから計算しよう。','j6-kanji':'読みと書きを分け、まちがえた字だけ集中的に。部首の意味とセットで覚えると忘れにくいよ。','j6-bunpo':'主語・述語・修飾語を色分けして、文の組み立てを見える化しよう。','s6-world':'国旗・位置・特徴をセットで。白地図に色をぬりながら覚えると定着するよ。','s6-politics':'国会・内閣・裁判所の役割をニュースと結びつけ、図にしてつながりを覚えよう。'}; if(T[id]) return T[id]; var a=_subjectArea(id); if(a==='math') return 'まちがえた問題をもう一度ときなおし、どこで間違えたかを言葉で説明してみよう。'; if(a==='jp') return '声に出して読んだり、まちがえた所だけノートに書いたりして おぼえよう。'; if(a==='soc') return '地図や年表・絵とむすびつけて、おはなしのように流れで おぼえよう。'; if(a==='sci') return '身のまわりの出来事とむすびつけ、「なぜ？」を1つ考えてみよう。'; return 'まちがえた問題を見直して、もう一度チャレンジしてみよう。'; }
      function _kHBar(items, color){
        if(!items||!items.length) return '<div style="font-size:11px;color:#94a3b8;padding:4px 8px">データなし</div>';
        var n=items.length, rowH=24, W=520, labelW=150, barX=labelW+6, barMaxW=W-barX-92, H=n*rowH+4;
        var s='<svg width="'+W+'" height="'+H+'" viewBox="0 0 '+W+' '+H+'" xmlns="http://www.w3.org/2000/svg" style="max-width:100%">';
        for(var i=0;i<n;i++){ var it=items[i]; var rate=Math.max(0,Math.min(100,it.rate||0)); var y=i*rowH+rowH/2; var bw=Math.max(barMaxW*rate/100,2);
          var lab=String(it.label||''); if(lab.length>12) lab=lab.slice(0,11)+'…';
          s+='<text x="'+labelW+'" y="'+(y+4)+'" font-size="11" font-weight="700" fill="#334155" text-anchor="end">'+lab+'</text>';
          s+='<rect x="'+barX+'" y="'+(y-8)+'" width="'+barMaxW+'" height="16" rx="8" fill="#f1f5f9"/>';
          s+='<rect x="'+barX+'" y="'+(y-8)+'" width="'+bw.toFixed(1)+'" height="16" rx="8" fill="'+color+'"/>';
          s+='<text x="'+(barX+barMaxW+5)+'" y="'+(y+4)+'" font-size="10" font-weight="700" fill="'+color+'" text-anchor="start">'+rate+'%（'+(it.total||0)+'問）</text>';
        }
        s+='</svg>'; return s;
      }
      function _kRadar(vals){
        var cx=120, cy=92, R=56, n=vals.length;
        var ang=function(i){ return (-90 + i*(360/n)) * Math.PI/180; };
        var pt=function(i,r){ var a=ang(i); return [(cx+r*Math.cos(a)), (cy+r*Math.sin(a))]; };
        var s='<svg width="240" height="190" viewBox="0 0 240 190" xmlns="http://www.w3.org/2000/svg">';
        var rings=[0.25,0.5,0.75,1];
        for(var g=0;g<rings.length;g++){ var pts=''; for(var i=0;i<n;i++){ var p=pt(i,R*rings[g]); pts+=(i?' ':'')+p[0].toFixed(1)+','+p[1].toFixed(1); } s+='<polygon points="'+pts+'" fill="none" stroke="#e2e8f0" stroke-width="1"/>'; }
        for(var i=0;i<n;i++){ var p=pt(i,R); s+='<line x1="'+cx+'" y1="'+cy+'" x2="'+p[0].toFixed(1)+'" y2="'+p[1].toFixed(1)+'" stroke="#e2e8f0" stroke-width="1"/>'; }
        var dp=''; for(var i=0;i<n;i++){ var v=Math.max(0,Math.min(100,vals[i].value||0)); var p=pt(i,R*v/100); dp+=(i?' ':'')+p[0].toFixed(1)+','+p[1].toFixed(1); }
        s+='<polygon points="'+dp+'" fill="#6366f1" fill-opacity="0.35" stroke="#4f46e5" stroke-width="2"/>';
        for(var i=0;i<n;i++){ var v=Math.max(0,Math.min(100,vals[i].value||0)); var p=pt(i,R*v/100); s+='<circle cx="'+p[0].toFixed(1)+'" cy="'+p[1].toFixed(1)+'" r="3" fill="#4f46e5"/>'; }
        for(var i=0;i<n;i++){ var p=pt(i,R+10); var anc=(i===0||i===2)?'middle':(i===1?'start':'end'); var lab=vals[i].noData?(vals[i].label+' データなし'):(vals[i].label+' '+Math.round(vals[i].value)+'%'); s+='<text x="'+p[0].toFixed(1)+'" y="'+(p[1]+3).toFixed(1)+'" font-size="10" font-weight="700" fill="#334155" text-anchor="'+anc+'">'+lab+'</text>'; }
        s+='</svg>'; return s;
      }
      function _kBars(items){
        if(!items||!items.length) return '<div style="font-size:11px;color:#94a3b8;padding:30px 10px">データなし</div>';
        var n=items.length, W=Math.max(n*40,150), H=170, pad=24;
        var max=1; for(var i=0;i<n;i++){ if((items[i].value||0)>max) max=items[i].value; }
        var s='<svg width="'+W+'" height="'+H+'" viewBox="0 0 '+W+' '+H+'" xmlns="http://www.w3.org/2000/svg">';
        var slot=(W-2*pad)/n, bw=Math.min(28,slot*0.62);
        for(var i=0;i<n;i++){ var v=items[i].value||0; var bh=Math.round((H-40)*v/max); var x=pad+i*slot+(slot-bw)/2; var y=H-22-bh;
          s+='<rect x="'+x.toFixed(1)+'" y="'+y.toFixed(1)+'" width="'+bw.toFixed(1)+'" height="'+Math.max(bh,1)+'" rx="3" fill="#22c55e"/>';
          s+='<text x="'+(x+bw/2).toFixed(1)+'" y="'+(y-3).toFixed(1)+'" font-size="10" font-weight="700" fill="#16a34a" text-anchor="middle">'+v+'</text>';
          s+='<text x="'+(x+bw/2).toFixed(1)+'" y="'+(H-6)+'" font-size="9" fill="#94a3b8" text-anchor="middle">'+String(items[i].label)+'</text>';
        }
        s+='</svg>'; return s;
      }
      function _kDonut(sun,cloud,rain){
        var t=(sun||0)+(cloud||0)+(rain||0); if(!t) return '<div style="font-size:11px;color:#94a3b8;padding:30px 10px">データなし</div>';
        var cx=70,cy=66,R=46,sw=20,C=2*Math.PI*R;
        var segs=[{v:sun||0,c:'#fbbf24'},{v:cloud||0,c:'#cbd5e1'},{v:rain||0,c:'#60a5fa'}];
        var s='<svg width="140" height="158" viewBox="0 0 140 158" xmlns="http://www.w3.org/2000/svg">';
        s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+R+'" fill="none" stroke="#f1f5f9" stroke-width="'+sw+'"/>';
        var off=0;
        for(var i=0;i<segs.length;i++){ if(segs[i].v<=0) continue; var frac=segs[i].v/t; var len=frac*C;
          s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+R+'" fill="none" stroke="'+segs[i].c+'" stroke-width="'+sw+'" stroke-dasharray="'+len.toFixed(2)+' '+(C-len).toFixed(2)+'" stroke-dashoffset="'+(-off).toFixed(2)+'" transform="rotate(-90 '+cx+' '+cy+')"/>';
          off+=len;
        }
        var sp=Math.round((sun||0)/t*100);
        s+='<text x="'+cx+'" y="'+(cy-1)+'" font-size="18" font-weight="900" fill="#f59e0b" text-anchor="middle">'+sp+'%</text>';
        s+='<text x="'+cx+'" y="'+(cy+13)+'" font-size="8" fill="#94a3b8" text-anchor="middle">☀の割合</text>';
        s+='<text x="70" y="150" font-size="10" fill="#475569" text-anchor="middle">☀'+(sun||0)+'  ☁'+(cloud||0)+'  ☂'+(rain||0)+'</text>';
        s+='</svg>'; return s;
      }
      function _kHowToLearn(d){ d=d||{}; var ov=d.overview||{}; var sg=(d.student&&d.student.grade)||null; var subj=(d.subjects||[]).slice(); var esc=function(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }; var cl=function(u){ return _gradeClass(sg,_unitGrade(u)); }; var review=subj.filter(function(s){return cl(s.unit)==='review'&&s.total>=10;}).sort(function(a,b){return a.rate-b.rate;}); var reviewWeak=review.filter(function(s){return s.rate<70;}).slice(0,3); var grow=subj.filter(function(s){return s.rate<70&&s.total>=5&&cl(s.unit)==='same';}).sort(function(a,b){return a.rate-b.rate;}); if(!grow.length){ grow=subj.filter(function(s){return s.rate<70&&s.total>=5&&cl(s.unit)!=='review';}).sort(function(a,b){return a.rate-b.rate;}); } grow=grow.slice(0,3); var good=subj.filter(function(s){return s.rate>=80&&s.total>=20&&cl(s.unit)==='same';}).sort(function(a,b){return b.rate-a.rate;}); var uL=function(s){ var g=_unitGrade(s.unit); return (g?g+'年 ':'')+_unitJa(s.unit); }; var methodFor=function(u){ var a=_subjectArea(u); if(a==='math') return '1日3〜5問ずつ、まちがえた問題はやり方を声に出してもう一度'; if(a==='jp') return '音読と漢字を毎日5分、まちがえた言葉はノートに書き出す'; if(a==='soc') return '用語を声に出して説明し、ミニクイズで確かめる'; if(a==='sci') return '図や実験を思い出しながら、用語をクイズで確かめる'; return '少しずつ毎日、まちがい直しを大切に'; }; var spacingFor=function(r){ return (r>=60)?'1回10分 × 週2〜3回、日をあけて（分散学習）':'1回10分を3日つづけて → 数日あけてもう1回'; }; var one=''; if(reviewWeak.length){ var t0=reviewWeak[0]; one='まず土台から。<b>'+esc(uL(t0))+'</b>（いま '+t0.rate+'%）を復習しよう。'+esc(methodFor(t0.unit))+'。'; } else if(grow.length){ var g0=grow[0]; one='<b>'+esc(_unitJa(g0.unit))+'</b>（いまの学年・'+g0.rate+'%）をもう一度ていねいに。'+esc(methodFor(g0.unit))+'。'; } else if(good.length){ one='いまの学年はバッチリ！<b>'+esc(_unitJa(good[0].unit))+'</b>をさらに伸ばすか、上の学年の先取りに挑戦してみよう。'; } else { one='今のペースで、毎日つづけることを大切に。続けることが一番の力だよ。'; } var pool=reviewWeak.concat(grow).slice(0,4); var revList=[]; for(var i=0;i<pool.length;i++){ var p=pool[i]; revList.push('<li style="margin:4px 0"><b>'+esc(uL(p))+'</b>（'+p.rate+'%）… '+esc(spacingFor(p.rate))+'。'+esc(methodFor(p.unit))+'</li>'); } var voices=[]; if((ov.maxStreak||0)>=5) voices.push('毎日つづけられる力がすごいね。続けられること自体が、もう立派な才能だよ。'); voices.push('「できた／できない」より「どうやってできたか」を一緒に話そう。やり方に目を向けると次に活きるよ。'); if(reviewWeak.length) voices.push('むずかしい所に挑戦できたね。まちがいは「のびるチャンス」。直せたら100点と同じだよ。'); else voices.push('ここまでよく積み上げたね。次の一歩を自分で選べたら、もっと強くなるよ。'); voices=voices.slice(0,3); var plans=(d.plans||[]); var refs=(d.reflections||[]); var hasGoal=plans.length>0; var hasDo=(ov.totalSubmissions||0)>0; var hasReflect=refs.filter(function(r){return r.nextAction||r.goodPoint||r.improvePoint;}).length>0; var loopMsg=''; if(!hasGoal){ loopMsg='まず「今週はこれをやる」と一つ決めてから始めると、ぐっと続けやすくなるよ。'; } else if(!hasReflect){ loopMsg='目標→実行はできている。ふりかえりに「次はこうする」を一言足すと、サイクルが回り出すよ。'; } else { loopMsg='目標→実行→ふりかえりがしっかり回っている。この習慣こそ、一番の学ぶ力だよ。'; } var bdg=function(on,txt){ return '<span style="display:inline-block;font-size:11px;padding:2px 8px;border-radius:10px;margin:0 4px 4px 0;'+(on?'background:#dcfce7;color:#15803d':'background:#f1f5f9;color:#94a3b8')+'">'+(on?'✓ ':'')+txt+'</span>'; }; var H=[]; H.push('<div style="border:2px solid #c7d2fe;border-radius:14px;padding:12px 14px;margin-bottom:11px;background:#eef2ff">'); H.push('<div style="font-weight:800;font-size:16px;color:#4338ca;margin-bottom:8px">📚 どう学ぶといいか（おうちでの学び方）</div>'); H.push('<div style="background:#fff;border-radius:10px;padding:9px 12px;margin-bottom:8px"><div style="font-weight:800;color:#4338ca;font-size:13px">🎯 今週の一手（これだけでOK）</div><div style="margin-top:3px;color:#334155">'+one+'</div></div>'); if(revList.length){ H.push('<div style="margin-bottom:8px"><div style="font-weight:800;color:#0369a1;font-size:13px">🔁 復習する単元とやり方（分散学習）</div><ul style="margin:4px 0;padding-left:20px;color:#334155">'+revList.join('')+'</ul></div>'); } H.push('<div><div style="font-weight:800;color:#b45309;font-size:13px">🔄 目標 → 実行 → ふりかえり のループ</div><div style="margin:5px 0">'+bdg(hasGoal,'目標を立てる')+bdg(hasDo,'実行する')+bdg(hasReflect,'ふりかえる')+'</div><div style="color:#7c2d12">'+esc(loopMsg)+'</div></div>'); H.push('</div>'); return H.join(''); }
      function _buildKarteHtml(){ var d=window._faData||{}; var ov=d.overview||{}; var name=window._faName||'あなた'; var esc=function(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }; var subjects=(d.subjects||[]).slice(); var _sg=(d.student&&d.student.grade)||null; var _cl=function(u){return _gradeClass(_sg,_unitGrade(u));}; var good=subjects.filter(function(s){return s.rate>=80&&s.total>=20&&_cl(s.unit)==='same';}).sort(function(a,b){return (b.rate-a.rate)||(b.total-a.total);}).slice(0,5); if(!good.length){ good=subjects.filter(function(s){return s.rate>=80&&s.total>=20&&_cl(s.unit)!=='review';}).sort(function(a,b){return (b.rate-a.rate)||(b.total-a.total);}).slice(0,5); } var _rev=subjects.filter(function(s){return _cl(s.unit)==='review'&&s.total>=10;}).sort(function(a,b){return a.rate-b.rate;}); var reviewGood=_rev.filter(function(s){return s.rate>=80;}).slice(0,3); var reviewWeak=_rev.filter(function(s){return s.rate<70;}).slice(0,3); var ahead=subjects.filter(function(s){return _cl(s.unit)==='ahead'&&s.rate>=70&&s.total>=10;}).sort(function(a,b){return (b.rate-a.rate);}).slice(0,3); var grow=subjects.filter(function(s){return s.rate<70&&s.total>=5&&_cl(s.unit)==='same';}).sort(function(a,b){return a.rate-b.rate;}).slice(0,3); if(!grow.length){ grow=subjects.filter(function(s){return s.rate<70&&s.total>=5&&_cl(s.unit)!=='review';}).sort(function(a,b){return a.rate-b.rate;}).slice(0,3); } var period=(ov.firstDate? (ov.firstDate+' 〜 '+ov.lastDate) : ''); var hours=Math.round((ov.totalMinutes||0)/60); var praise='よく がんばっているね！この調子で つづけていこう！'; if((ov.maxStreak||0)>=5) praise='なんと '+ov.maxStreak+'日も つづけて べんきょうできたね！すごい力だよ！'; else if((ov.totalSubmissions||0)>=10) praise='たくさん べんきょうを つづけているね！その努力は きっと力になるよ！'; var H=[]; H.push('<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>家庭学習カルテ</title>'); H.push('<style>'); H.push('@page{size:A4;margin:12mm;} *{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact;}'); H.push('body{font-family:"Hiragino Maru Gothic ProN","Hiragino Sans","Yu Gothic","Meiryo",sans-serif;color:#334155;margin:0;font-size:13px;line-height:1.6;}'); H.push('.wrap{max-width:186mm;margin:0 auto;}'); H.push('.head{text-align:center;background:linear-gradient(135deg,#fef3c7,#fde68a);border-radius:16px;padding:14px;margin-bottom:12px;}'); H.push('.head h1{margin:0;font-size:24px;color:#b45309;} .head .nm{font-size:18px;font-weight:800;color:#92400e;margin-top:4px;} .head .pd{font-size:12px;color:#a16207;margin-top:2px;}'); H.push('.sec{border:2px solid #e2e8f0;border-radius:14px;padding:12px 14px;margin-bottom:11px;} .sec h2{margin:0 0 8px;font-size:16px;}'); H.push('.chips{display:flex;flex-wrap:wrap;gap:8px;} .chip{background:#eff6ff;border-radius:10px;padding:8px 12px;text-align:center;flex:1;min-width:84px;} .chip .v{font-size:20px;font-weight:900;color:#2563eb;} .chip .l{font-size:10px;color:#64748b;}'); H.push('.msg{background:#ecfdf5;border-radius:10px;padding:9px 12px;margin-top:9px;color:#047857;font-weight:700;}'); H.push('.good .b{font-weight:800;color:#16a34a;} .grow .it{background:#fff7ed;border-radius:10px;padding:8px 11px;margin:6px 0;} .grow .t{font-weight:800;color:#ea580c;} .grow .tip{font-size:12px;color:#7c2d12;margin-top:2px;}'); H.push('.refl{font-size:12px;color:#475569;} .refl li{margin:3px 0;} .note{border:2px dashed #cbd5e1;border-radius:12px;min-height:70px;padding:10px;} ul{margin:4px 0;padding-left:20px;} .foot{text-align:center;font-size:10px;color:#cbd5e1;margin-top:6px;}'); H.push('</style></head><body><div class="wrap">'); H.push('<div class="head"><h1>📒 家庭学習カルテ</h1><div class="nm">'+esc(name)+' さん'+(_sg?'（'+_sg+'年生）':'')+'</div>'+(period?'<div class="pd">'+esc(period)+'</div>':'')+'</div>'); H.push('<div class="sec"><h2>🌟 がんばりの記録</h2><div class="chips">'); H.push('<div class="chip"><div class="v">'+(ov.totalSubmissions||0)+'</div><div class="l">提出回数</div></div>'); H.push('<div class="chip"><div class="v">'+hours+'時間</div><div class="l">合計学習時間</div></div>'); H.push('<div class="chip"><div class="v">'+(ov.avgMinutes||0)+'分</div><div class="l">1日の平均</div></div>'); H.push('<div class="chip"><div class="v">'+(ov.maxStreak||0)+'日</div><div class="l">最長れんぞく</div></div>'); H.push('<div class="chip"><div class="v">'+(ov.sunRate||0)+'%</div><div class="l">きもち☀️</div></div>'); H.push('</div><div class="msg">'+praise+'</div></div>'); var _areas=[{key:'jp',label:'国語'},{key:'math',label:'算数'},{key:'sci',label:'理科'},{key:'soc',label:'社会'}]; var _agg=function(arr){ var tot=0,cor=0; for(var ai=0;ai<arr.length;ai++){ var it=arr[ai]; var cc=(typeof it.correct==='number')?it.correct:Math.round((it.rate||0)/100*(it.total||0)); tot+=(it.total||0); cor+=cc; } return tot? Math.round(cor/tot*100):null; }; var _radar=_areas.map(function(a){ var same=subjects.filter(function(s){ return _subjectArea(s.unit)===a.key && _cl(s.unit)==='same'; }); var all=subjects.filter(function(s){ return _subjectArea(s.unit)===a.key; }); var v=_agg(same); var nd=false; if(v==null){ v=_agg(all); } if(v==null){ v=0; nd=true; } return {label:a.label, value:v, noData:nd}; }); var _mt=(d.monthlyTrends||[]).slice(-6); var _barItems=_mt.map(function(m){ return {label:String(m.month||'').slice(5), value:m.count||0}; }); H.push('<div class="sec"><h2>📊 学習の見える化</h2><div style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-start;justify-content:space-around">'); H.push('<div style="text-align:center"><div style="font-size:11px;font-weight:700;color:#475569;margin-bottom:2px">教科の定着（いまの学年）</div>'+_kRadar(_radar)+'</div>'); H.push('<div style="text-align:center"><div style="font-size:11px;font-weight:700;color:#475569;margin-bottom:2px">月ごとの提出回数</div>'+_kBars(_barItems)+'</div>'); H.push('<div style="text-align:center"><div style="font-size:11px;font-weight:700;color:#475569;margin-bottom:2px">きもちの割合</div>'+_kDonut(ov.sunCount,ov.cloudCount,ov.rainCount)+'</div>'); H.push('</div>'); var goodBars=good.map(function(s){return {label:_unitJa(s.unit),rate:s.rate,total:s.total};}); var growBars=grow.map(function(s){return {label:_unitJa(s.unit),rate:s.rate,total:s.total};}); var revBars=reviewWeak.map(function(s){var rg=_unitGrade(s.unit); return {label:(rg?rg+'年 ':'')+_unitJa(s.unit),rate:s.rate,total:s.total};}); H.push('<div style="margin-top:8px;border-top:1px dashed #e2e8f0;padding-top:6px">'); H.push('<div style="font-weight:800;color:#16a34a;font-size:12px;margin-bottom:2px">💪 とくいな単元（いまの学年）</div>'+_kHBar(goodBars,'#22c55e')); H.push('<div style="font-weight:800;color:#ea580c;font-size:12px;margin:6px 0 2px">🌱 これから伸ばす単元（いまの学年）</div>'+_kHBar(growBars,'#f97316')); if(revBars.length){ H.push('<div style="font-weight:800;color:#0369a1;font-size:12px;margin:6px 0 2px">🔁 下の学年の復習（まずここから）</div>'+_kHBar(revBars,'#3b82f6')); } H.push('</div>'); H.push('</div>'); H.push(_kHowToLearn(d)); H.push('<div class="sec good"><h2>💪 とくいな教科'+(_sg?'（いまの学年）':'')+'</h2>'); if(good.length){ H.push('<ul>'); for(var i=0;i<good.length;i++){ var g=good[i]; H.push('<li><span class="b">'+esc(_unitJa(g.unit))+'</span> … 正答率 '+g.rate+'%（'+g.total+'問）よくできているね！</li>'); } H.push('</ul>'); } else { H.push('<p>これから とくいな教科を ふやしていこう！</p>'); } if(reviewGood.length){ var _rg=[]; for(var rgi=0;rgi<reviewGood.length;rgi++){ var _rgu=reviewGood[rgi]; var _rgg=_unitGrade(_rgu.unit); _rg.push((_rgg?_rgg+'年 ':'')+esc(_unitJa(_rgu.unit))+'('+_rgu.rate+'%)'); } H.push('<div style="margin-top:8px;font-size:12px;color:#0369a1;font-weight:700">🔁 下の学年の復習もバッチリ … '+_rg.join('、')+'</div>'); } if(ahead.length){ var _ag=[]; for(var agi=0;agi<ahead.length;agi++){ var _agu=ahead[agi]; var _agg=_unitGrade(_agu.unit); _ag.push((_agg?_agg+'年 ':'')+esc(_unitJa(_agu.unit))+'('+_agu.rate+'%)'); } H.push('<div style="margin-top:6px;font-size:12px;color:#7c3aed;font-weight:700">🚀 先取りもチャレンジ … '+_ag.join('、')+'</div>'); } H.push('</div>'); H.push('<div class="sec grow"><h2>🌱 これから もっと のびるところ</h2>'); if(grow.length){ for(var j=0;j<grow.length;j++){ var w=grow[j]; H.push('<div class="it"><div class="t">'+esc(_unitJa(w.unit))+'（いまの学年・正答率 '+w.rate+'%）</div><div class="tip">👉 '+esc(_kStudyTip(w.unit))+'</div></div>'); } } else { H.push('<p>いまの学年の単元は よくできています。すばらしい！</p>'); } if(reviewWeak.length){ H.push('<div style="margin-top:8px;border-top:1px dashed #e2e8f0;padding-top:8px"><div style="font-weight:800;color:#b45309;font-size:13px">📥 まずは下の学年の復習から（土台づくり）</div>'); for(var rw=0;rw<reviewWeak.length;rw++){ var _rwu=reviewWeak[rw]; var _rwg=_unitGrade(_rwu.unit); H.push('<div class="it"><div class="t">'+(_rwg?_rwg+'年 ':'')+esc(_unitJa(_rwu.unit))+'（いま '+_rwu.rate+'%）</div><div class="tip">👉 まず'+(_rwg?_rwg+'年の':'')+esc(_unitJa(_rwu.unit))+'を復習して、できるようになってから いまの学年へ進もう。'+esc(_kStudyTip(_rwu.unit))+'</div></div>'); } H.push('</div>'); } H.push('</div>'); var refs=(d.recentSubmissions||[]).filter(function(s){return s.weather_reason;}).slice(0,3); if(refs.length){ H.push('<div class="sec"><h2>📝 さいきんの ふりかえり</h2><ul class="refl">'); for(var k=0;k<refs.length;k++){ var r=refs[k]; var w2=r.end_weather==='sun'?'☀️':r.end_weather==='cloud'?'☁️':r.end_weather==='rain'?'🌧️':''; H.push('<li>'+esc(r.day_key||'')+' '+w2+' '+esc(r.weather_reason)+'</li>'); } H.push('</ul></div>'); } var tsc=(d.testScores||[]); if(tsc.length){ H.push('<div class="sec"><h2>📝 テストの記録</h2><ul>'); for(var ti=0;ti<tsc.length;ti++){ var tt=tsc[ti]; var tp=(tt.pct==null)?'':('（'+tt.pct+'%）'); H.push('<li>'+esc(tt.testDate||'')+' '+esc(tt.subject||'')+' '+esc(tt.testName||'')+' … '+(tt.score==null?'-':tt.score)+'/'+(tt.maxScore||100)+'点'+tp+'</li>'); } H.push('</ul></div>'); } var _tn=(d.teacherNotes||[]).filter(function(n){return n.showInKarte;}); if(_tn.length){ H.push('<div class="sec"><h2>📝 先生からの記録</h2><ul>'); for(var ni=0;ni<_tn.length;ni++){ var nn=_tn[ni]; H.push('<li>'+esc(nn.dayKey||'')+' '+esc(nn.body||'')+'</li>'); } H.push('</ul></div>'); } if(d.aiComment){ H.push('<div class="sec"><h2>🤖 阪神マンからのアドバイス</h2><div style="font-size:12px;color:#475569;white-space:pre-wrap">'+esc(d.aiComment)+'</div></div>'); }  H.push('<div class="foot">LearningBM ／ 家庭学習カルテ</div>'); H.push('</div></body></html>'); return H.join(''); }
      function downloadKartePdf(){ try{ var html=_buildKarteHtml(); var w=window.open('','_blank'); if(!w){ alert('ポップアップがブロックされました。このサイトのポップアップを許可してください。'); return; } w.document.open(); w.document.write(html); w.document.close(); setTimeout(function(){ try{ w.focus(); w.print(); }catch(e){} }, 500); }catch(e){ alert('カルテの作成に失敗しました: '+e.message); } }
      function _aiBodyLines(data){ var ov=data.overview||{}; var _sg5=(data.student&&data.student.grade)||null; var L=[]; if(_sg5) L.push('【学年】'+_sg5+'年生'); L.push('【基本統計】'); L.push('・提出回数: '+(ov.totalSubmissions||0)+'回'); L.push('・平均学習時間: '+(ov.avgMinutes||0)+'分'); L.push('・学習満足度（☀️の割合）: '+(ov.sunRate||0)+'%'); L.push('・現在の連続提出: '+(ov.currentStreak||0)+'日 / 最長連続: '+(ov.maxStreak||0)+'日'); if(ov.firstDate) L.push('・記録期間: '+ov.firstDate+' 〜 '+ov.lastDate); if(ov.totalMinutes!=null) L.push('・合計学習時間: '+ov.totalMinutes+'分（約'+Math.round((ov.totalMinutes||0)/60)+'時間）'); if(ov.returnRate!=null) L.push('・先生からの返却率: '+ov.returnRate+'%'); var tw=(ov.sunCount||0)+(ov.cloudCount||0)+(ov.rainCount||0); if(tw>0) L.push('・満足度の内訳: ☀️'+(ov.sunCount||0)+'回 / ☁️'+(ov.cloudCount||0)+'回 / 🌧️'+(ov.rainCount||0)+'回'); if(data.subjects&&data.subjects.length){ var _sg6=(data.student&&data.student.grade)||null; L.push(''); L.push('【教科別の正答率（取り組み量の多い順／対象学年つき）】'); for(var j=0;j<data.subjects.length;j++){ var su=data.subjects[j]; var _ug6=_unitGrade(su.unit); var _lab6=_gradeLabel(_gradeClass(_sg6,_ug6))||'対象学年不明'; L.push('・'+_unitJa(su.unit)+'（'+(_ug6?('対象'+_ug6+'年・'):'')+_lab6+'）: 正答率'+su.rate+'%（'+su.total+'問）'); } } if(data.teacherNotes&&data.teacherNotes.length){ L.push(''); L.push('【先生の観察メモ（授業中の様子・教師向け）】'); for(var tn=0;tn<Math.min(data.teacherNotes.length,15);tn++){ var nt=data.teacherNotes[tn]; L.push('・'+(nt.dayKey||'')+' '+(nt.body||'')); } } if(data.streaks&&data.streaks.length){ L.push(''); L.push('【連続提出の記録（上位）】'); for(var k=0;k<Math.min(data.streaks.length,3);k++){ L.push('・'+data.streaks[k].length+'日連続'); } } if(data.recentSubmissions&&data.recentSubmissions.length){ L.push(''); L.push('【直近の学習記録】'); for(var n=0;n<Math.min(data.recentSubmissions.length,10);n++){ var rs=data.recentSubmissions[n]; var w=rs.end_weather==='sun'?'☀️':rs.end_weather==='cloud'?'☁️':rs.end_weather==='rain'?'🌧️':'❓'; var line='・'+(rs.day_key||'')+' '+w+' '+(rs.todo||'')+'（'+(rs.minutes||0)+'分）'; if(rs.weather_reason) line+=' ふりかえり:'+rs.weather_reason; L.push(line); } } return L; }
      function _normId(s){ return String(s==null?'':s).replace(/[Ａ-Ｚａ-ｚ０-９]/g,function(c){return String.fromCharCode(c.charCodeAt(0)-65248);}).replace(/[\\s　]/g,'').toLowerCase(); }
      function _parseAiBlocks(raw){ var lines=String(raw||'').split(/\\r?\\n/); var blocks=[]; var cur=null; var re=/^[\\s　]*[=＝]{2,}[\\s　]*[\\[［]\\s*([^\\]］]+?)\\s*[\\]］]/; for(var i=0;i<lines.length;i++){ var m=lines[i].match(re); if(m){ if(cur) blocks.push(cur); cur={id:m[1],lines:[]}; } else if(cur){ cur.lines.push(lines[i]); } } if(cur) blocks.push(cur); return blocks.map(function(b){ return {id:b.id, body:b.lines.join(String.fromCharCode(10)).replace(/^\\s+|\\s+$/g,'')}; }); }
      async function copyAllAiText(){ var students=window._lastStudentSummaries||[]; var status=document.getElementById('allAiStatus'); if(!students.length){ if(status) status.textContent='先に「AIで分析」か「週報を生成」を押して児童一覧を表示してください'; return; } if(status) status.textContent='データを集めています...(0/'+students.length+')'; var NL=String.fromCharCode(10); var L=[]; L.push('以下は同じクラスの複数の児童の家庭学習データです。あなたは関西弁の応援キャラ「阪神マン」です。各児童ごとに、「=== [児童ID] 名前 ===」の目印の行を そのまま変えずに残し、その下に ①ええところ（取り組みの良い点）②気になるところ ③おすすめの学習・声かけ を、関西弁で子どもを励ますようにやさしく書いてください。各児童の【学年】と各単元の【対象学年】を見て声かけを変えること：下の学年の復習は「復習できたな！次はいまの学年へ」、学年相当はしっかりほめる、先取り（上の学年）は「まだ習ってへんのにスゴいやん！」。おすすめは単元名・つまずきポイント・次の一歩を具体的に。児童IDと目印は絶対に変更しないでください。やりすぎず、先生がそのまま使える範囲で。'); L.push(''); for(var i=0;i<students.length;i++){ var s=students[i]; var nm=(typeof resolveStudentName==='function')?resolveStudentName(s.loginId,s.name):(s.name||''); var id=s.loginId||s.userId||s.name; L.push('=== ['+id+'] '+nm+' ==='); try{ var res=await fetch('/api/teacher/student-full-analysis?studentId='+encodeURIComponent(s.userId||s.name)); var data=await res.json(); if(data&&data.ok){ L=L.concat(_aiBodyLines(data)); } else { L.push('(データの取得に失敗しました)'); } }catch(e){ L.push('(エラー: '+e.message+')'); } L.push(''); if(status) status.textContent='データを集めています...('+(i+1)+'/'+students.length+')'; } var txt=L.join(NL); var done=function(){ if(status) status.textContent='✓ '+students.length+'人分をコピーしました。AIに貼り付けてください'; }; if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done,function(){ _faFallbackCopy(txt); done(); }); } else { _faFallbackCopy(txt); done(); } }
      async function saveAllAiComments(){ var ta=document.getElementById('allAiPaste'); var raw=ta?ta.value:''; var status=document.getElementById('allAiStatus'); if(!raw||!raw.trim()){ if(status) status.textContent='AIの結果を貼り付けてください'; return; } var students=window._lastStudentSummaries||[]; var map={}; for(var i=0;i<students.length;i++){ var s=students[i]; if(s.loginId) map[_normId(s.loginId)]=s.userId; if(s.userId) map[_normId(s.userId)]=s.userId; if(s.name) map[_normId(s.name)]=s.userId; } var blocks=_parseAiBlocks(raw); var comments=[]; var unmatched=[]; for(var b=0;b<blocks.length;b++){ var uid=map[_normId(blocks[b].id)]; if(uid&&blocks[b].body){ comments.push({studentId:uid,comment:blocks[b].body}); } else { unmatched.push(blocks[b].id); } } if(!comments.length){ if(status) status.textContent='目印 === [児童ID] === が見つかりませんでした（'+blocks.length+'ブロック検出）'; return; } if(status) status.textContent='保存中...'; try{ var res=await fetch('/api/teacher/student-ai-comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({comments:comments})}); var d=await res.json(); if(d&&d.ok){ if(status) status.textContent='✓ '+d.saved+'人分を保存しました'+(unmatched.length?'（未一致: '+unmatched.join(', ')+'）':''); } else { if(status) status.textContent='保存に失敗しました'; } }catch(e){ if(status) status.textContent='エラー: '+e.message; } }
      async function downloadAllKartes(){ var students=window._lastStudentSummaries||[]; var status=document.getElementById('allAiStatus'); if(!students.length){ if(status) status.textContent='先に児童一覧を表示してください'; return; } if(status) status.textContent='カルテを作成中...(0/'+students.length+')'; var savedD=window._faData, savedN=window._faName; var docs=[]; for(var i=0;i<students.length;i++){ var s=students[i]; var nm=(typeof resolveStudentName==='function')?resolveStudentName(s.loginId,s.name):(s.name||''); try{ var res=await fetch('/api/teacher/student-full-analysis?studentId='+encodeURIComponent(s.userId||s.name)); var data=await res.json(); if(data&&data.ok){ window._faData=data; window._faName=nm; docs.push(_buildKarteHtml()); } }catch(e){} if(status) status.textContent='カルテを作成中...('+(i+1)+'/'+students.length+')'; } window._faData=savedD; window._faName=savedN; if(!docs.length){ if(status) status.textContent='データがありませんでした'; return; } var style=''; var sm=docs[0].match(/<style>[\\s\\S]*?<\\/style>/); if(sm) style=sm[0]; var bodies=docs.map(function(doc){ var m=doc.match(/<body>([\\s\\S]*?)<\\/body>/); return '<div style="page-break-after:always">'+(m?m[1]:'')+'</div>'; }); var html='<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>家庭学習カルテ（全員分）</title>'+style+'</head><body>'+bodies.join('')+'</body></html>'; var w=window.open('','_blank'); if(!w){ if(status) status.textContent='ポップアップを許可してください'; return; } w.document.open(); w.document.write(html); w.document.close(); setTimeout(function(){ try{ w.focus(); w.print(); }catch(e){} }, 800); if(status) status.textContent='✓ '+docs.length+'人分のカルテを開きました'; }
      function initLearnAnalytics(){ var sel=document.getElementById('laClassSelect'); if(!sel || sel.getAttribute('data-init')) return; fetch('/api/teacher/classes').then(function(r){return r.json();}).then(function(d){ if(d&&d.ok&&d.classes&&d.classes.length){ sel.innerHTML=''; for(var i=0;i<d.classes.length;i++){ var o=document.createElement('option'); o.value=d.classes[i].id; o.textContent=d.classes[i].name; sel.appendChild(o); } sel.setAttribute('data-init','1'); } }).catch(function(e){}); }
      function loadLearnAnalytics(){ var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:''; var el=document.getElementById('laContent'); if(!cid){ el.innerHTML='<p class="text-xs text-slate-400">クラスを選んでください</p>'; return; } el.innerHTML='<p class="text-xs text-indigo-500 animate-pulse">📈 学習データを集計しています...</p>'; fetch('/api/teacher/learning-analytics?classId='+encodeURIComponent(cid)).then(function(r){return r.json();}).then(function(d){ if(!d.ok){ el.innerHTML='<p class="text-xs text-red-500">取得エラー</p>'; return; } window._laData=d; el.innerHTML=_laRender(d); }).catch(function(e){ el.innerHTML='<p class="text-xs text-red-500">エラー: '+e.message+'</p>'; }); }
      function _laCard(title, inner){ return '<div class="bg-white rounded-xl border border-slate-200 p-4 mb-3"><div class="font-bold text-sm text-slate-700 mb-2">'+title+'</div>'+inner+'</div>'; }
      function _laVBars(items, getV, getLabel, color){ var max=1,i; for(i=0;i<items.length;i++){ var v=getV(items[i]); if(v>max)max=v; } var h='<div class="flex items-end gap-1 overflow-x-auto pb-1" style="height:130px">'; for(i=0;i<items.length;i++){ var v=getV(items[i]); var pct=Math.max(Math.round(v/max*100),2); h+='<div class="flex flex-col items-center justify-end min-w-[26px]" style="height:100%"><div class="text-[8px] text-slate-500 mb-0.5">'+v+'</div><div class="w-5 rounded-t" style="height:'+pct+'%;background:'+color+'"></div><div class="text-[8px] text-slate-400 mt-1 whitespace-nowrap">'+escH(String(getLabel(items[i])))+'</div></div>'; } h+='</div>'; return h; }
      function _laHBars(items, getV, getLabel, color, suffix){ var max=1,i; for(i=0;i<items.length;i++){ var v=getV(items[i]); if(v>max)max=v; } var h='<div class="space-y-1">'; for(i=0;i<items.length;i++){ var v=getV(items[i]); var pct=Math.max(Math.round(v/max*100),4); h+='<div class="flex items-center gap-2"><span class="text-xs w-24 truncate text-slate-600 font-bold">'+escH(String(getLabel(items[i])))+'</span><div class="flex-1 bg-slate-100 rounded-full h-4"><div class="h-4 rounded-full text-[10px] text-white flex items-center justify-end pr-1 font-bold" style="width:'+pct+'%;background:'+color+'">'+v+(suffix||'')+'</div></div></div>'; } h+='</div>'; return h; }
      function _laLine(points, getV, getLabel, color, suffix){ var n=points.length; if(!n) return '<p class="text-xs text-slate-400">データなし</p>'; var W=Math.max(n*46,220), H=130, pad=22, i; var max=1; for(i=0;i<n;i++){ var v=getV(points[i]); if(v>max)max=v; } var xs=function(i){ return pad+(n>1? i*(W-2*pad)/(n-1):(W-2*pad)/2); }; var ys=function(v){ return H-pad-(v/max)*(H-2*pad); }; var poly='',circ='',lbl=''; for(i=0;i<n;i++){ var v=getV(points[i]); var x=xs(i),y=ys(v); poly+=(i?' ':'')+x.toFixed(0)+','+y.toFixed(0); circ+='<circle cx="'+x.toFixed(0)+'" cy="'+y.toFixed(0)+'" r="3" fill="'+color+'"/><text x="'+x.toFixed(0)+'" y="'+(y-6).toFixed(0)+'" font-size="9" text-anchor="middle" fill="#475569">'+v+(suffix||'')+'</text>'; lbl+='<text x="'+x.toFixed(0)+'" y="'+(H-4)+'" font-size="8" text-anchor="middle" fill="#94a3b8">'+escH(String(getLabel(points[i])))+'</text>'; } return '<div style="overflow-x:auto"><svg width="'+W+'" height="'+H+'" viewBox="0 0 '+W+' '+H+'"><polyline points="'+poly+'" fill="none" stroke="'+color+'" stroke-width="2"/>'+circ+lbl+'</svg></div>'; }
      function _laScatter(pts){ var p=[],i; for(i=0;i<pts.length;i++){ if(pts[i].rate!=null && pts[i].problems>0) p.push(pts[i]); } if(!p.length) return '<p class="text-xs text-slate-400">データなし</p>'; var W=360,H=240,pad=36; var maxX=1; for(i=0;i<p.length;i++){ if(p[i].problems>maxX)maxX=p[i].problems; } var X=function(v){ return pad+v/maxX*(W-2*pad); }; var Y=function(v){ return H-pad-v/100*(H-2*pad); }; var dots=''; for(i=0;i<p.length;i++){ dots+='<circle cx="'+X(p[i].problems).toFixed(0)+'" cy="'+Y(p[i].rate).toFixed(0)+'" r="4" fill="#6366f1" opacity="0.7"><title>'+escH(p[i].name)+' / '+p[i].problems+'問 / 正答率'+p[i].rate+'%</title></circle>'; } var ax='<line x1="'+pad+'" y1="'+(H-pad)+'" x2="'+(W-pad)+'" y2="'+(H-pad)+'" stroke="#cbd5e1"/><line x1="'+pad+'" y1="'+pad+'" x2="'+pad+'" y2="'+(H-pad)+'" stroke="#cbd5e1"/><text x="'+(W/2)+'" y="'+(H-6)+'" font-size="9" text-anchor="middle" fill="#94a3b8">取り組んだ問題数 →</text><text x="11" y="'+(H/2)+'" font-size="9" text-anchor="middle" fill="#94a3b8" transform="rotate(-90 11 '+(H/2)+')">正答率% →</text>'; return '<div style="overflow-x:auto"><svg width="'+W+'" height="'+H+'" viewBox="0 0 '+W+' '+H+'">'+ax+dots+'</svg></div>'; }
      function _laWeather(o){ var t=(o.sun||0)+(o.cloud||0)+(o.rain||0); if(!t) return '<p class="text-xs text-slate-400">データなし</p>'; var sw=Math.round(o.sun/t*100),cw=Math.round(o.cloud/t*100),rw=Math.round(o.rain/t*100); return '<div class="flex h-6 rounded-full overflow-hidden border border-slate-200">'+(sw>0?'<div style="width:'+sw+'%;background:#fbbf24"></div>':'')+(cw>0?'<div style="width:'+cw+'%;background:#cbd5e1"></div>':'')+(rw>0?'<div style="width:'+rw+'%;background:#60a5fa"></div>':'')+'</div><div class="flex gap-3 text-xs text-slate-600 mt-1"><span>☀️ '+o.sun+'回('+sw+'%)</span><span>☁️ '+o.cloud+'回('+cw+'%)</span><span>🌧️ '+o.rain+'回('+rw+'%)</span></div>'; }
      function _laRender(d){ var h=''; var i;
        h+='<div class="text-xs text-slate-500 mb-2">クラス: <b>'+escH(d.className)+'</b> ／ '+d.studentCount+'人 ／ 集計: '+escH((d.generatedAt||'').slice(0,10))+'</div>';
        var c=d.continuity||{};
        var drop='';
        if(c.droppingStudents&&c.droppingStudents.length){ drop='<div class="bg-amber-50 border border-amber-200 rounded-lg p-2 mb-2"><div class="text-xs font-bold text-amber-700 mb-1">⚠ 離れ気味アラート（直近7日が前の7日より大きく減少）</div><div class="text-xs text-amber-800">'; for(i=0;i<c.droppingStudents.length;i++){ var ds=c.droppingStudents[i]; drop+=escH(resolveStudentName(ds.loginId,ds.name))+'（前7日'+ds.prev7+'→直近'+ds.recent7+'回） '; } drop+='</div></div>'; } else { drop='<div class="text-xs text-green-600 mb-2">✅ 直近で大きく落ちている児童はいません</div>'; }
        var cont = drop + '<div class="text-xs font-bold text-slate-500 mb-1">クラスの週別 提出率</div>' + _laLine(c.weeklyRate||[], function(x){return x.rate;}, function(x){return (x.week||'').slice(5);}, '#10b981', '%');
        cont += '<div class="text-xs font-bold text-slate-500 mt-3 mb-1">児童ごとの提出回数・最長連続</div><div class="max-h-48 overflow-y-auto"><table class="w-full text-xs"><thead><tr class="text-slate-400"><th class="text-left p-1">児童</th><th class="p-1">提出</th><th class="p-1">最長連続</th><th class="p-1">直近7日</th></tr></thead><tbody>';
        var ps=(c.perStudent||[]).slice().sort(function(a,b){return b.submissions-a.submissions;});
        for(i=0;i<ps.length;i++){ var p=ps[i]; cont+='<tr class="'+(p.dropping?'bg-amber-50':'')+'"><td class="p-1 font-bold text-slate-700">'+escH(resolveStudentName(p.loginId,p.name))+'</td><td class="p-1 text-center">'+p.submissions+'</td><td class="p-1 text-center">'+p.maxStreak+'日</td><td class="p-1 text-center">'+p.recent7+'</td></tr>'; }
        cont+='</tbody></table></div>';
        h+=_laCard('① 継続・つまずきの早期発見', cont);
        var sj=d.subjects||{};
        var sub='';
        if(sj.strong&&sj.strong.length){ sub+='<div class="text-xs font-bold text-green-600 mb-1">💪 クラスの得意（正答率・20問以上）</div>'+_laHBars(sj.strong, function(x){return x.rate;}, function(x){return _unitJa(x.unit);}, '#16a34a', '%'); }
        if(sj.weak&&sj.weak.length){ sub+='<div class="text-xs font-bold text-rose-600 mt-3 mb-1">🌱 クラスの苦手（正答率・20問以上）</div>'+_laHBars(sj.weak, function(x){return x.rate;}, function(x){return _unitJa(x.unit);}, '#f43f5e', '%'); }
        sub+='<div class="text-xs font-bold text-slate-500 mt-3 mb-1">正答率の分布（児童数・10問以上の児童）</div>'+_laVBars(sj.distribution||[], function(x){return x.count;}, function(x){return x.label;}, '#6366f1');
        h+=_laCard('② 教科ごとの定着度', sub);
        var tm=d.time||{};
        var tim='<div class="text-xs font-bold text-slate-500 mb-1">学習している時間帯（問題を解いた時刻・JST）</div>'+_laVBars(tm.hourHistogram||[], function(x){return x.count;}, function(x){return x.hour;}, '#0ea5e9');
        tim+='<div class="text-xs font-bold text-slate-500 mt-3 mb-1">曜日別の提出回数</div>'+_laVBars(tm.weekdayHistogram||[], function(x){return x.count;}, function(x){return x.dow;}, '#f59e0b');
        tim+='<div class="text-xs font-bold text-slate-500 mt-3 mb-1">1人あたり週の学習時間（分）</div>'+_laLine(tm.weeklyMinutes||[], function(x){return x.avgMinPerStudent;}, function(x){return (x.week||'').slice(5);}, '#8b5cf6', '分');
        tim+='<div class="text-xs text-slate-500 mt-2">1回あたり平均学習時間: <b>'+(tm.avgMinPerSubmission||0)+'分</b></div>';
        h+=_laCard('③ 時間帯・学習時間', tim);
        var st=d.satisfaction||{};
        var sat='<div class="text-xs font-bold text-slate-500 mb-1">満足度の全体割合</div>'+_laWeather(st.overall||{sun:0,cloud:0,rain:0});
        sat+='<div class="text-xs font-bold text-slate-500 mt-3 mb-1">週別の☀️率の推移</div>'+_laLine(st.weekly||[], function(x){return x.sunRate;}, function(x){return (x.week||'').slice(5);}, '#fbbf24', '%');
        if(st.keywords&&st.keywords.length){ sat+='<div class="text-xs font-bold text-slate-500 mt-3 mb-1">振り返りのよく出る言葉</div><div class="flex flex-wrap gap-1">'; for(i=0;i<st.keywords.length;i++){ var kw=st.keywords[i]; var sz=10+Math.min(kw.count,12); sat+='<span class="bg-slate-100 rounded-full px-2 py-0.5 text-slate-700" style="font-size:'+sz+'px">'+escH(kw.word)+'<span class="text-slate-400 text-[9px]"> '+kw.count+'</span></span>'; } sat+='</div>'; }
        h+=_laCard('④ 満足度・振り返りの傾向', sat);
        var rl=d.relation||{};
        var rel='<div class="text-xs text-slate-500 mb-1">点ひとつが児童1人（横: 取り組んだ問題数、縦: 正答率）</div>'+_laScatter(rl.scatter||[]);
        if(rl.correlation!=null){ var cr=rl.correlation; var msg = cr>=0.4?'取り組み量が多い子ほど正答率が高い傾向（正の相関）':cr<=-0.4?'負の相関':'はっきりした相関は見られません'; rel+='<div class="text-xs text-slate-600 mt-1">相関係数: <b>'+cr+'</b> … '+msg+'</div>'; }
        h+=_laCard('⑤ 取り組み量と成績の関係', rel);
        var tg=(d.tests&&d.tests.bySubject)||[];
        if(tg.length){ var tgh='<div class="text-xs text-slate-500 mb-1">取り込んだテストの教科別 平均得点率</div>'+_laHBars(tg, function(x){return x.avgPct||0;}, function(x){return x.subject+'（'+x.count+'回）';}, '#e11d48', '%'); h+=_laCard('📝 テスト結果（教科別の平均）', tgh); }
        return h;
      }
      function _tsDispName(rm){ return (typeof resolveStudentName==='function')?resolveStudentName(rm.loginId, rm.name):(rm.name||rm.loginId||''); }
      function _tsRematch(d){
        var roster=d.roster||[]; var idx={};
        for(var j=0;j<roster.length;j++){ var rm=roster[j]; var dn=_tsDispName(rm); if(dn) idx[_normId(dn)]=rm; if(rm.name) idx[_normId(rm.name)]=rm; if(rm.loginId) idx[_normId(rm.loginId)]=rm; }
        for(var i=0;i<d.rows.length;i++){ var r=d.rows[i]; var key=_normId(r.rawName||''); var hit=idx[key]||null;
          if(!hit){ for(var k=0;k<roster.length;k++){ var rm2=roster[k]; var dn2=_normId(_tsDispName(rm2)); if(dn2 && (dn2.indexOf(key)>=0||key.indexOf(dn2)>=0)){ hit=rm2; break; } } }
          r.matchedUserId = hit? hit.userId : null; r.matchedName = hit? _tsDispName(hit) : null;
        }
      }
      function _notesClassId(){ var sel=document.getElementById('analyticsClassFilter'); return sel?sel.value:''; }
      function _todayStr(){ return new Date().toISOString().slice(0,10); }
      function initNotesTab(){ var cd=document.getElementById('cnoteDate'); if(cd && !cd.value) cd.value=_todayStr(); var sd=document.getElementById('snoteDate'); if(sd && !sd.value) sd.value=_todayStr(); if(_notesClassId()) loadNotes(); }
      function loadNotes(){
        var cid=_notesClassId(); if(!cid) return;
        fetch('/api/teacher/class-notes?classId='+encodeURIComponent(cid)).then(function(r){return r.json();}).then(function(d){
          if(!d||!d.ok) return;
          window._notesRoster=d.roster||[];
          var sel=document.getElementById('snoteStudent');
          if(sel){ var cur=sel.value; var h='<option value="">児童を選ぶ…</option>'; for(var i=0;i<window._notesRoster.length;i++){ var rm=window._notesRoster[i]; var dn=(typeof resolveStudentName==='function')?resolveStudentName(rm.loginId,rm.name):(rm.name||rm.loginId); h+='<option value="'+escH(rm.userId)+'">'+escH(dn)+'</option>'; } sel.innerHTML=h; if(cur) sel.value=cur; }
          var list=document.getElementById('cnoteList');
          if(list){ var notes=d.notes||[]; if(!notes.length){ list.innerHTML='<div class="text-xs text-slate-400">まだクラスメモはありません</div>'; } else { var s=''; for(var j=0;j<notes.length;j++){ var n=notes[j]; s+='<div class="text-xs bg-slate-50 rounded p-1.5 border"><span class="text-slate-400">'+escH(n.dayKey||'')+'</span> '+escH(n.body||'')+'</div>'; } list.innerHTML=s; } }
        }).catch(function(e){});
      }
      function saveClassNote(){
        var cid=_notesClassId(); var st=document.getElementById('cnoteStatus');
        if(!cid){ if(st) st.textContent='上でクラスを選んでください'; return; }
        var dk=(document.getElementById('cnoteDate')||{}).value||''; var body=(document.getElementById('cnoteBody')||{}).value||'';
        if(!body||!body.trim()){ if(st) st.textContent='メモを入力してください'; return; }
        if(st) st.textContent='保存中...';
        fetch('/api/teacher/class-notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid, dayKey:dk, body:body})}).then(function(r){return r.json();}).then(function(d){
          if(d&&d.ok){ if(st) st.textContent='✓ 保存しました'; var b=document.getElementById('cnoteBody'); if(b) b.value=''; loadNotes(); } else { if(st) st.textContent='保存に失敗しました'; }
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function loadStudentNotesTab(){
        var sid=(document.getElementById('snoteStudent')||{}).value||''; var list=document.getElementById('snoteList');
        if(!sid){ if(list) list.innerHTML=''; return; }
        fetch('/api/teacher/student-notes?studentId='+encodeURIComponent(sid)).then(function(r){return r.json();}).then(function(d){
          if(!d||!d.ok||!list) return;
          var notes=d.notes||[]; if(!notes.length){ list.innerHTML='<div class="text-xs text-slate-400">この児童のメモはまだありません</div>'; return; }
          var s=''; for(var i=0;i<notes.length;i++){ var n=notes[i]; var kb=n.showInKarte?'<span class="text-[8px] bg-rose-100 text-rose-700 px-1 rounded ml-1">カルテ掲載</span>':''; s+='<div class="text-xs bg-slate-50 rounded p-1.5 border"><span class="text-slate-400">'+escH(n.dayKey||'')+'</span> '+escH(n.body||'')+kb+'</div>'; } list.innerHTML=s;
        }).catch(function(e){});
      }
      function saveStudentNoteTab(){
        var sid=(document.getElementById('snoteStudent')||{}).value||''; var st=document.getElementById('snoteStatus');
        if(!sid){ if(st) st.textContent='児童を選んでください'; return; }
        var dk=(document.getElementById('snoteDate')||{}).value||''; var body=(document.getElementById('snoteBody')||{}).value||''; var kt=(document.getElementById('snoteKarte')||{}).checked?1:0;
        if(!body||!body.trim()){ if(st) st.textContent='メモを入力してください'; return; }
        if(st) st.textContent='保存中...';
        fetch('/api/teacher/student-notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({studentId:sid, dayKey:dk, body:body, showInKarte:kt})}).then(function(r){return r.json();}).then(function(d){
          if(d&&d.ok){ if(st) st.textContent='✓ 保存しました'; var b=document.getElementById('snoteBody'); if(b) b.value=''; var ck=document.getElementById('snoteKarte'); if(ck) ck.checked=false; loadStudentNotesTab(); } else { if(st) st.textContent='保存に失敗しました'; }
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function saveQuickStudentNote(){
        var sid=window._faId; if(!sid) return; var st=document.getElementById('faNoteStatus');
        var dk=(document.getElementById('faNoteDate')||{}).value||''; var body=(document.getElementById('faNoteBody')||{}).value||''; var kt=(document.getElementById('faNoteKarte')||{}).checked?1:0;
        if(!body||!body.trim()){ if(st) st.textContent='メモを入力してください'; return; }
        if(st) st.textContent='保存中...';
        fetch('/api/teacher/student-notes',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({studentId:sid, dayKey:dk, body:body, showInKarte:kt})}).then(function(r){return r.json();}).then(function(d){
          if(d&&d.ok){ if(st) st.textContent='✓ 保存しました'; openStudentFullAnalysis(window._faId, window._faName); } else { if(st) st.textContent='保存に失敗しました'; }
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function _recTypeLabel(t){ if(t==='reflect') return '振り返り'; if(t==='other') return 'その他'; return 'まとめ・レポート'; }
      function copyRecordPrompt(){
        var NL=String.fromCharCode(10);
        var sel=document.getElementById('recType'); var t=sel?sel.value:'report';
        var label=_recTypeLabel(t);
        var L=[];
        L.push('あなたは小学校の先生のアシスタントです。アップロードした（または貼り付けた）児童の'+label+'のPDF・画像から、児童ごとに内容を読み取り、次の「出力形式」だけを、コードブロックに入れずそのまま出力してください。前置きや説明は書かないでください。');
        L.push('');
        L.push('【出力形式】児童ごとに次のブロックをくり返す。');
        L.push('=== [児童ID] 名前 ===');
        L.push('タイトル: （'+label+'のタイトル。なければ内容を短く要約）');
        L.push('日付: （YYYY-MM-DD。わからなければ空欄）');
        L.push('教科: （国語・算数・理科・社会 など。なければ空欄）');
        L.push('単元: （わかれば。なければ空欄）');
        L.push('本文:');
        L.push('（児童が書いた文章をそのまま。複数行でよい）');
        L.push('');
        L.push('【ルール】児童IDは名簿のログインID。わからなければ [名前] のように名前を入れる。1人ずつ「=== [..] .. ===」で区切る。本文は「本文:」の次の行からブロックの終わり（次の===）まで。要約や講評を勝手に足さず、児童の記述を尊重する。読み取れない児童は飛ばしてよい。');
        var txt=L.join(NL);
        var st=document.getElementById('recPromptStatus');
        var done=function(){ if(st) st.textContent='✓ コピーしました。AIに貼り付けてください'; };
        if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done,function(){ _faFallbackCopy(txt); done(); }); } else { _faFallbackCopy(txt); done(); }
      }
      function parseRecords(){
        var ta=document.getElementById('recPaste'); var raw=ta?ta.value:'';
        var st=document.getElementById('recParseStatus');
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';
        if(!cid){ if(st) st.textContent='先に「クラス」を選んでください'; return; }
        if(!raw||!raw.trim()){ if(st) st.textContent='AIの出力を貼り付けてください'; return; }
        if(st) st.textContent='読み取り中...';
        fetch('/api/teacher/records/parse',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid,text:raw})}).then(function(r){return r.json();}).then(function(d){
          if(!d||!d.ok){ if(st) st.textContent='読み取りに失敗しました（クラス権限などを確認）'; return; }
          window._recParsed=d;
          if(st) st.textContent='✓ '+d.rows.length+'件を読み取りました。内容を確認して保存してください';
          _recRenderPreview(d);
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function _recRenderPreview(d){
        var el=document.getElementById('recPreview'); if(!el) return;
        var roster=d.roster||[];
        var opts=function(selId){ var s='<option value="">（未割り当て）</option>'; for(var j=0;j<roster.length;j++){ var rm=roster[j]; s+='<option value="'+escH(rm.userId)+'"'+(rm.userId===selId?' selected':'')+'>'+escH(_tsDispName(rm))+'</option>'; } return s; };
        var unmatched=0; var h='';
        h+='<div class="space-y-2 max-h-96 overflow-y-auto">';
        for(var i=0;i<d.rows.length;i++){
          var r=d.rows[i]; var warn=!r.matchedUserId; if(warn) unmatched++;
          h+='<div class="border rounded-lg p-2 '+(warn?'bg-amber-50':'bg-slate-50')+'">';
          h+='<div class="flex items-center gap-1 flex-wrap mb-1">';
          h+='<span class="text-[10px] text-slate-400">読取: '+escH(r.idRaw||'')+' '+escH(r.nameRaw||'')+(warn?' <span class="text-amber-600">⚠未マッチ</span>':'')+'</span>';
          h+='<select id="recRow_'+i+'_user" class="border rounded p-1 text-xs">'+opts(r.matchedUserId)+'</select>';
          h+='</div>';
          h+='<div class="grid grid-cols-3 gap-1 mb-1">';
          h+='<input id="recRow_'+i+'_title" class="border rounded p-1 text-xs col-span-2" placeholder="タイトル" value="'+escH(r.title||'')+'">';
          h+='<input id="recRow_'+i+'_day" class="border rounded p-1 text-xs" placeholder="YYYY-MM-DD" value="'+escH(r.day||'')+'">';
          h+='<input id="recRow_'+i+'_subject" class="border rounded p-1 text-xs" placeholder="教科" value="'+escH(r.subject||'')+'">';
          h+='<input id="recRow_'+i+'_unit" class="border rounded p-1 text-xs col-span-2" placeholder="単元（任意）" value="'+escH(r.unit||'')+'">';
          h+='</div>';
          h+='<textarea id="recRow_'+i+'_body" rows="3" class="w-full border rounded p-1 text-xs" placeholder="本文">'+escH(r.body||'')+'</textarea>';
          h+='</div>';
        }
        h+='</div>';
        h+='<div class="flex items-center gap-2 mt-2"><button onclick="saveRecords()" class="bg-rose-600 text-white rounded-lg px-4 py-2 text-sm font-bold hover:bg-rose-700">💾 保存</button>';
        h+='<span id="recSaveStatus" class="text-xs font-bold text-amber-600">'+(unmatched?('未マッチ '+unmatched+'件は児童を選ぶと保存されます'):'')+'</span></div>';
        el.innerHTML=h;
      }
      function saveRecords(){
        var d=window._recParsed; if(!d) return;
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';
        var tsel=document.getElementById('recType'); var rtype=tsel?tsel.value:'report';
        var st=document.getElementById('recSaveStatus');
        var gv=function(id){ var e=document.getElementById(id); return e?e.value:''; };
        var rows=[]; var skipped=0;
        for(var i=0;i<d.rows.length;i++){
          var uid=gv('recRow_'+i+'_user');
          var title=gv('recRow_'+i+'_title'); var bodyTxt=gv('recRow_'+i+'_body');
          if(!uid){ skipped++; continue; }
          if((!title||!title.trim())&&(!bodyTxt||!bodyTxt.trim())){ skipped++; continue; }
          rows.push({userId:uid, title:title, body:bodyTxt, subject:gv('recRow_'+i+'_subject'), unit:gv('recRow_'+i+'_unit'), day:gv('recRow_'+i+'_day')});
        }
        if(!rows.length){ if(st) st.textContent='保存できる行がありません（児童の割り当てと内容を確認）'; return; }
        if(st) st.textContent='保存中...';
        fetch('/api/teacher/records/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid, type:rtype, rows:rows})}).then(function(r){return r.json();}).then(function(res){
          if(res&&res.ok){ if(st) st.textContent='✓ '+res.saved+'人分を保存しました'+(skipped?('（未保存 '+skipped+'件）'):'')+'。個人分析のポートフォリオに反映されます'; }
          else { if(st) st.textContent='保存に失敗しました'; }
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function copyTestPrompt(){
        var NL=String.fromCharCode(10);
        var L=[];
        L.push('あなたは小学校のテストの採点結果を整理するアシスタントです。アップロードした（または貼り付けた）テストの画像・PDFから、児童ごとの点数を読み取り、次の「出力形式」だけを、コードブロックに入れずそのまま出力してください。前置きや説明は書かないでください。');
        L.push('');
        L.push('【出力形式】');
        L.push('テスト名: （テストの名前）');
        L.push('実施日: （YYYY-MM-DD。わからなければ空欄）');
        L.push('教科: （国語・算数・理科・社会・英語 など）');
        L.push('満点: （数字。わからなければ100）');
        L.push('---');
        L.push('児童名, 点数');
        L.push('児童名, 点数');
        L.push('');
        L.push('【ルール】名前と点数はカンマ（,）で区切る。1行に1人。点数は数字のみ。満点は必ず「満点:」の行に入れる（不明なら100）。児童名はできるだけ名簿の表記に合わせる。読み取れない児童は飛ばしてよい。合計や平均などの余計な行は入れない。');
        var txt=L.join(NL);
        var st=document.getElementById('tsPromptStatus');
        var done=function(){ if(st) st.textContent='✓ コピーしました。AIに貼り付けてください'; };
        if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done,function(){ _faFallbackCopy(txt); done(); }); } else { _faFallbackCopy(txt); done(); }
      }
      function parseTestScores(){
        var ta=document.getElementById('tsPaste'); var raw=ta?ta.value:'';
        var st=document.getElementById('tsParseStatus');
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';
        if(!cid){ if(st) st.textContent='先に「クラス全体」でクラスを選んでください'; return; }
        if(!raw||!raw.trim()){ if(st) st.textContent='AIの出力を貼り付けてください'; return; }
        if(st) st.textContent='読み取り中...';
        fetch('/api/teacher/test-scores/parse',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid,text:raw})}).then(function(r){return r.json();}).then(function(d){
          if(!d||!d.ok){ if(st) st.textContent='読み取りに失敗しました（クラス権限などを確認）'; return; }
          _tsRematch(d);
          window._tsParsed=d;
          if(st) st.textContent='✓ '+d.rows.length+'件を読み取りました。内容を確認して保存してください';
          _tsRenderPreview(d);
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function _tsRenderPreview(d){
        var el=document.getElementById('tsPreview'); if(!el) return;
        var roster=d.roster||[]; var hd=d.header||{};
        var opts=function(selId){ var s='<option value="">（未割り当て）</option>'; for(var j=0;j<roster.length;j++){ var rm=roster[j]; s+='<option value="'+escH(rm.userId)+'"'+(rm.userId===selId?' selected':'')+'>'+escH(_tsDispName(rm))+'</option>'; } return s; };
        var h='';
        h+='<div class="bg-slate-50 rounded-lg border p-3 mb-2"><div class="grid grid-cols-2 gap-2 text-xs">';
        h+='<label class="flex flex-col text-slate-500">テスト名<input id="tsHdrName" class="border rounded p-1 mt-0.5 text-slate-700" value="'+escH(hd.testName||'')+'"></label>';
        h+='<label class="flex flex-col text-slate-500">実施日<input id="tsHdrDate" class="border rounded p-1 mt-0.5 text-slate-700" value="'+escH(hd.testDate||'')+'" placeholder="YYYY-MM-DD"></label>';
        h+='<label class="flex flex-col text-slate-500">教科<input id="tsHdrSubject" class="border rounded p-1 mt-0.5 text-slate-700" value="'+escH(hd.subject||'')+'"></label>';
        h+='<label class="flex flex-col text-slate-500">満点<input id="tsHdrMax" type="number" class="border rounded p-1 mt-0.5 text-slate-700" value="'+escH(String(hd.maxScore||100))+'"></label>';
        h+='</div></div>';
        var unmatched=0;
        h+='<div class="max-h-72 overflow-y-auto"><table class="w-full text-xs"><thead><tr class="text-slate-400"><th class="text-left p-1">読み取った名前</th><th class="text-left p-1">割り当てる児童</th><th class="p-1">点数</th></tr></thead><tbody>';
        for(var i=0;i<d.rows.length;i++){
          var r=d.rows[i]; var warn=!r.matchedUserId; if(warn) unmatched++;
          h+='<tr class="'+(warn?'bg-amber-50':'')+'">';
          h+='<td class="p-1 font-bold text-slate-700">'+escH(r.rawName||'')+(warn?' <span class="text-[9px] text-amber-600">⚠未マッチ</span>':'')+'</td>';
          h+='<td class="p-1"><select id="tsRow_'+i+'_user" class="border rounded p-1 w-full">'+opts(r.matchedUserId)+'</select></td>';
          h+='<td class="p-1 text-center"><input id="tsRow_'+i+'_score" type="number" class="border rounded p-1 w-16 text-center" value="'+escH(String(r.score==null?'':r.score))+'"><span class="text-slate-400"> / '+escH(String(hd.maxScore||100))+'</span></td>';
          h+='</tr>';
        }
        h+='</tbody></table></div>';
        h+='<div class="flex items-center gap-2 mt-2"><button onclick="saveTestScores()" class="bg-rose-600 text-white rounded-lg px-4 py-2 text-sm font-bold hover:bg-rose-700">💾 保存</button>';
        h+='<span id="tsSaveStatus" class="text-xs font-bold text-amber-600">'+(unmatched?('未マッチ '+unmatched+'件は児童を選ぶと保存されます'):'')+'</span></div>';
        el.innerHTML=h;
      }
      function saveTestScores(){
        var d=window._tsParsed; if(!d) return;
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';
        var st=document.getElementById('tsSaveStatus');
        var gv=function(id){ var e=document.getElementById(id); return e?e.value:''; };
        var testName=gv('tsHdrName'), testDate=gv('tsHdrDate'), subject=gv('tsHdrSubject'), maxScore=gv('tsHdrMax')||'100';
        var rows=[]; var skipped=0;
        for(var i=0;i<d.rows.length;i++){
          var uid=gv('tsRow_'+i+'_user'); var score=gv('tsRow_'+i+'_score');
          if(!uid){ skipped++; continue; }
          if(score===''||score==null){ skipped++; continue; }
          rows.push({userId:uid, score:parseInt(score,10), comment:(d.rows[i].comment||'')});
        }
        if(!rows.length){ if(st) st.textContent='保存できる行がありません（児童の割り当てと点数を確認）'; return; }
        if(st) st.textContent='保存中...';
        fetch('/api/teacher/test-scores/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid, testName:testName, testDate:testDate, subject:subject, maxScore:(parseInt(maxScore,10)||100), rows:rows})}).then(function(r){return r.json();}).then(function(res){
          if(res&&res.ok){ if(st) st.textContent='✓ '+res.saved+'人分を保存しました'+(skipped?('（未保存 '+skipped+'件）'):'')+'。個人分析・カルテ・アナリティクスに反映されます'; }
          else { if(st) st.textContent='保存に失敗しました'; }
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function _faStatCard(icon, value, label, color){
        return '<div class="bg-'+color+'-50 rounded-lg p-2 text-center"><div class="text-lg font-black text-'+color+'-600">'+icon+' '+value+'</div><div class="text-[9px] text-slate-500">'+label+'</div></div>';
      }

      function closeStudentFullAnalysis(){
        document.getElementById('studentFullAnalysisOverlay').classList.add('hidden');
        document.body.style.overflow = '';
      }

      function _renderFullCalendar(calendar){
        var today = new Date();
        var startDate = new Date(today);
        startDate.setMonth(startDate.getMonth() - 5);
        startDate.setDate(1);
        var html = '<div class="overflow-x-auto"><div class="inline-flex gap-[2px]">';
        var d = new Date(startDate);
        var weekData = [];
        var curWeek = [];
        var lastWeekNum = -1;
        while(d <= today){
          var key = d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');
          var dow = (d.getDay()+6)%7;
          var weekNum = Math.floor((d.getTime()-startDate.getTime())/(7*86400000));
          if(weekNum !== lastWeekNum && curWeek.length > 0){
            weekData.push(curWeek);
            curWeek = [];
          }
          lastWeekNum = weekNum;
          curWeek.push({date:key, dow:dow, data:calendar[key]||null});
          d.setDate(d.getDate()+1);
        }
        if(curWeek.length > 0) weekData.push(curWeek);
        for(var wi=0; wi<weekData.length; wi++){
          var week = weekData[wi];
          html += '<div class="flex flex-col gap-[2px]">';
          var firstDow = week[0].dow;
          for(var fi=0;fi<firstDow;fi++) html += '<div class="w-3 h-3"></div>';
          for(var di=0;di<week.length;di++){
            var day = week[di];
            var color = 'bg-slate-100';
            var title = day.date+': 未提出';
            if(day.data){
              var min = day.data.minutes||0;
              if(min>=60) color='bg-green-600';
              else if(min>=40) color='bg-green-500';
              else if(min>=20) color='bg-green-400';
              else color='bg-green-300';
              var wName = day.data.weather==='sun'?'☀️':day.data.weather==='cloud'?'☁️':'🌧️';
              title = day.date+': '+min+'分 '+wName;
            }
            html += '<div class="w-3 h-3 rounded-sm '+color+'" title="'+escH(title)+'"></div>';
          }
          html += '</div>';
        }
        html += '</div>';
        // 月ラベル
        html += '<div class="flex gap-1 mt-1 text-[8px] text-slate-400 pl-1">';
        var shownMonths = {};
        var d2 = new Date(startDate);
        while(d2 <= today){
          var mKey = d2.getFullYear()+'-'+String(d2.getMonth()+1).padStart(2,'0');
          if(!shownMonths[mKey]){
            shownMonths[mKey] = true;
            html += '<span class="mr-4">'+(d2.getMonth()+1)+'月</span>';
          }
          d2.setMonth(d2.getMonth()+1);
        }
        html += '</div>';
        html += '<div class="flex items-center gap-1 mt-1 text-[9px] text-slate-400">';
        html += '<span>少</span><div class="w-3 h-3 rounded-sm bg-slate-100"></div><div class="w-3 h-3 rounded-sm bg-green-300"></div><div class="w-3 h-3 rounded-sm bg-green-400"></div><div class="w-3 h-3 rounded-sm bg-green-500"></div><div class="w-3 h-3 rounded-sm bg-green-600"></div><span>多(60分+)</span>';
        html += '</div></div>';
        return html;
      }


      function _eaEsc(s){ return String(s==null?'':s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;'); }
      function _eaUnitName(u){ try{ return (typeof _unitJa==='function')?_unitJa(u):u; }catch(e){ return u; } }
      async function loadEarlyAlerts(){
        var sel=document.getElementById('laClassSelect')||document.getElementById('analyticsClassFilter');
        var classId=sel?sel.value:'';
        var box=document.getElementById('earlyAlertContent');
        if(!classId){ if(box) box.innerHTML='<p class="text-xs text-red-500">クラスを選択してください</p>'; return; }
        var btn=document.getElementById('btnEarlyAlerts'); if(btn){ btn.disabled=true; btn.textContent='チェック中...'; }
        if(box) box.innerHTML='<p class="text-xs text-rose-500 animate-pulse">🔍 つまずきの兆候をさがしています...</p>';
        try{
          var res=await fetch('/api/teacher/early-alerts?classId='+encodeURIComponent(classId));
          var d=await res.json();
          if(!d||!d.ok){ if(box) box.innerHTML='<p class="text-xs text-red-500">取得に失敗しました'+(d&&d.error?'：'+_eaEsc(d.error):'')+'</p>'; return; }
          var html='';
          var mastery=d.mastery||[];
          html+='<div class="mb-3"><div class="font-bold text-xs text-slate-700 mb-1">📶 習熟ライン（単元ごと・クラス平均）</div>';
          if(mastery.length){ html+='<div class="space-y-1">';
            for(var i=0;i<mastery.length;i++){ var mu=mastery[i];
              var tcol=mu.tier==='good'?'#16a34a':(mu.tier==='mid'?'#f59e0b':'#dc2626');
              var tlab=mu.tier==='good'?'定着':(mu.tier==='mid'?'あと一歩':'要サポート');
              var w=Math.max(mu.classAcc,4);
              html+='<div class="flex items-center gap-2"><span class="text-xs font-bold text-slate-600" style="width:7rem;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+_eaEsc(_eaUnitName(mu.unit))+'</span>';
              html+='<div class="flex-1 bg-slate-100 rounded-full h-4"><div style="width:'+w+'%;background:'+tcol+'" class="rounded-full h-4 text-white flex items-center justify-center font-bold"><span style="font-size:10px">'+mu.classAcc+'%</span></div></div>';
              html+='<span class="font-bold" style="font-size:10px;color:'+tcol+'">'+tlab+'</span>';
              html+='<span class="text-slate-400 whitespace-nowrap" style="font-size:10px">🟢'+(mu.counts?mu.counts.good:0)+' 🟡'+(mu.counts?mu.counts.mid:0)+' 🔴'+(mu.counts?mu.counts.low:0)+'</span></div>';
            } html+='</div>';
          } else { html+='<p class="text-xs text-slate-400">まだ十分なデータがありません。</p>'; }
          html+='</div>';
          var alerts=d.alerts||[];
          html+='<div><div class="font-bold text-xs text-rose-700 mb-1">⚠️ 早期対応リスト（'+alerts.length+'件）</div>';
          if(alerts.length){ html+='<div class="space-y-2">';
            for(var a=0;a<alerts.length;a++){ var al=alerts[a];
              var nm=(typeof resolveStudentName==='function')?resolveStudentName(al.loginId,al.name):(al.name||'');
              var badges='';
              for(var b=0;b<(al.signals||[]).length;b++){ var sg=al.signals[b];
                var bc=sg==='consec'?'background:#fee2e2;color:#b91c1c':(sg==='drop'?'background:#ffedd5;color:#c2410c':'background:#fef9c3;color:#a16207');
                var bl=sg==='consec'?'3回連続まちがい':(sg==='drop'?'急落':'できていたのに低下');
                badges+='<span style="font-size:10px;padding:1px 7px;border-radius:8px;margin-right:4px;'+bc+'">'+bl+'</span>';
              }
              html+='<div onclick="openStudentFullAnalysis(&#39;'+al.studentId+'&#39;,&#39;'+_eaEsc(nm)+'&#39;)" class="bg-white rounded-lg border border-rose-200 p-2 cursor-pointer hover:bg-rose-50">';
              html+='<div class="flex items-center justify-between gap-2"><div class="font-bold text-sm text-slate-800">'+_eaEsc(nm)+'</div><div class="text-slate-400" style="font-size:10px">タップで分析 ▶</div></div>';
              html+='<div class="text-xs text-slate-600" style="margin-top:2px">'+_eaEsc(_eaUnitName(al.unit))+'（正答率 '+al.acc+'%'+(al.recentAcc!=null?' ／ 直近 '+al.recentAcc+'%':'')+'）</div>';
              html+='<div style="margin-top:4px">'+badges+'</div></div>';
            } html+='</div>';
          } else { html+='<p class="text-xs text-emerald-600">いまは大きなつまずきの兆候はありません 🎉</p>'; }
          html+='</div>';
          if(box) box.innerHTML=html;
        } catch(e){ if(box) box.innerHTML='<p class="text-xs text-red-500">エラー：'+_eaEsc(e.message)+'</p>'; }
        finally{ if(btn){ btn.disabled=false; btn.textContent='🔍 つまずきをチェック'; } }
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

      var _hwDateFilter = ''; // '' = all, 'today', 'yesterday', 'older'
      function hwSetDateFilter(f){ _hwDateFilter = f; hwApplyDateFilter(); }
      function hwApplyDateFilter(){
        var tabs = document.querySelectorAll('#hwDateTabs button');
        tabs.forEach(function(t){ t.className = t.dataset.filter === _hwDateFilter
          ? 'px-3 py-1 rounded-full text-sm font-bold bg-emerald-600 text-white shadow'
          : 'px-3 py-1 rounded-full text-sm bg-slate-100 text-slate-600 hover:bg-slate-200'; });
        var cards = document.querySelectorAll('#hwList [data-hw-day-key]');
        cards.forEach(function(c){
          if(!_hwDateFilter){ c.classList.remove('hidden'); return; }
          c.classList.toggle('hidden', c.dataset.hwDayKey !== _hwDateFilter);
        });
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

        // --- 日付グループ計算 ---
        var now = new Date();
        if(now.getHours() < 4) now.setDate(now.getDate()-1);
        var todayKey = now.getFullYear()+'-'+String(now.getMonth()+1).padStart(2,'0')+'-'+String(now.getDate()).padStart(2,'0');
        var yd = new Date(now); yd.setDate(yd.getDate()-1);
        var yesterdayKey = yd.getFullYear()+'-'+String(yd.getMonth()+1).padStart(2,'0')+'-'+String(yd.getDate()).padStart(2,'0');

        // --- サマリー & 未提出者 ---
        var summaryBar = document.getElementById('hwSummaryBar');
        var unsubList = document.getElementById('hwUnsubmittedList');
        if(classId){
          try{
            var mData = await api('/api/teacher/class/'+encodeURIComponent(classId)+'/members');
            var members = (mData && mData.members) || [];
            var todaySubs = list.filter(function(s){ return s.dayKey === todayKey; });
            var submittedIds = new Set(todaySubs.map(function(s){ return s.userId; }));
            var unreturned = todaySubs.filter(function(s){ return !s.returnedAt; }).length;
            if(summaryBar){
              var sumParts = todayKey.split('-');
              var sumLabel = parseInt(sumParts[1])+'/'+parseInt(sumParts[2]);
              summaryBar.innerHTML = '<div class="flex gap-4 items-center flex-wrap">'
                + '<span class="font-bold text-blue-700">📊 今日 ('+sumLabel+')</span>'
                + '<span>提出 <b class="text-lg text-emerald-700">'+submittedIds.size+'</b> / '+members.length+'人</span>'
                + '<span>未返却 <b class="text-lg '+(unreturned>0?'text-red-600':'text-slate-400')+'">'+unreturned+'</b>件</span>'
                + '</div>';
              summaryBar.classList.remove('hidden');
            }
            var unsubMembers = members.filter(function(m){ return !submittedIds.has(m.userId); });
            if(unsubList){
              if(unsubMembers.length > 0 && unsubMembers.length < members.length){
                var names = unsubMembers.map(function(m){ return escH(resolveStudentName(m.loginId, m.name)); }).join('、');
                unsubList.innerHTML = '<span class="font-bold text-orange-700">📋 今日の未提出 ('+unsubMembers.length+'人)：</span> '+names;
                unsubList.classList.remove('hidden');
              } else if(unsubMembers.length === 0){
                unsubList.innerHTML = '<span class="font-bold text-emerald-700">🎉 全員提出済み！</span>';
                unsubList.classList.remove('hidden');
              } else { unsubList.classList.add('hidden'); }
            }
          }catch(e){ /* ignore */ }
        } else {
          if(summaryBar) summaryBar.classList.add('hidden');
          if(unsubList) unsubList.classList.add('hidden');
        }

        // --- 日付タブ ---
        var dateTabs = document.getElementById('hwDateTabs');
        var dayCounts = {today:0, yesterday:0, older:0};
        list.forEach(function(s){
          if(s.dayKey === todayKey) dayCounts.today++;
          else if(s.dayKey === yesterdayKey) dayCounts.yesterday++;
          else dayCounts.older++;
        });
        if(dateTabs && list.length > 0){
          dateTabs.innerHTML = '';
          // 日付ごとに集計
          var dayMap = {};
          list.forEach(function(s){ dayMap[s.dayKey] = (dayMap[s.dayKey]||0) + 1; });
          var dayKeys = Object.keys(dayMap).sort().reverse(); // 新しい順
          var dayTabs = [{label:'すべて ('+list.length+')', filter:''}];
          dayKeys.forEach(function(dk){
            var parts = dk.split('-');
            var label = parseInt(parts[1])+'/'+parseInt(parts[2]) + ' ('+dayMap[dk]+')';
            dayTabs.push({label:label, filter:dk});
          });
          dayTabs.forEach(function(tab){
            var btn = document.createElement('button');
            btn.textContent = tab.label;
            btn.dataset.filter = tab.filter;
            btn.className = String(tab.filter) === String(_hwDateFilter)
              ? 'px-3 py-1 rounded-full text-sm font-bold bg-emerald-600 text-white shadow'
              : 'px-3 py-1 rounded-full text-sm bg-slate-100 text-slate-600 hover:bg-slate-200';
            btn.onclick = function(){ hwSetDateFilter(tab.filter); };
            dateTabs.appendChild(btn);
          });
          dateTabs.classList.remove('hidden');
        } else if(dateTabs){ dateTabs.classList.add('hidden'); }

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
          const __sName = resolveStudentName(s.loginId, s.studentName);
          card.dataset.hwName = __sName||'';
          card.dataset.hwDayKey = s.dayKey||'';
          card.dataset.hwDateGroup = s.dayKey === todayKey ? 'today' : s.dayKey === yesterdayKey ? 'yesterday' : 'older';
          if(_hwDateFilter && (s.dayKey||'') !== _hwDateFilter) card.classList.add('hidden');
          const weatherEmoji = {sun:'☀️', cloud:'☁️', rain:'🌧️'}[s.endWeather] || '😊';
          const physicalBadge = s.hasPhysical
            ? '<span class="bg-yellow-200 text-yellow-800 text-xs px-1 rounded">成果物あり⭐</span>'
            : '';
          const returnedBadge = returned
            ? '<span class="bg-green-100 text-green-700 text-xs px-1 rounded">返却済み</span>'
            : '<span class="bg-red-100 text-red-600 text-xs px-1 rounded font-bold">未返却</span>';

          card.innerHTML = '<div class="flex items-center justify-between flex-wrap gap-1">'
            + '<div class="font-bold">' + escH(__sName||'') + ' <span class="text-xs text-slate-400 font-normal">'+escH(s.grade+'年'+s.className)+'</span></div>'
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
            + (s.parentComment ? '<div class="mt-1 p-1.5 bg-pink-50 rounded border border-pink-200"><b>🏠 サポーターから：</b>'+escH(s.parentComment)+'</div>' : '')
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
          var today = idx+'. 【'+resolveStudentName(sub.loginId, sub.studentName)+'】（'+sub.dayKey+'）';
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
            var __mName = resolveStudentName(m.loginId, m.name);
            card.innerHTML = '<div class="w-10 h-10 rounded-full bg-teal-100 flex items-center justify-center text-teal-700 font-bold text-sm flex-shrink-0">'+escH(__mName.slice(0,1))+'</div>'
              + '<div class="flex-1 min-w-0"><div class="flex justify-between items-center"><span class="font-bold text-sm">'+escH(__mName)+'</span><span class="text-[10px] text-slate-400">'+escH(time)+'</span></div><div class="text-xs text-slate-500 truncate">'+escH(preview)+'</div></div>'
              + (unread ? '<span class="bg-red-500 text-white text-[10px] rounded-full min-w-[18px] h-[18px] flex items-center justify-center font-bold">'+unread+'</span>' : '');
            card.onclick = (function(s){ return function(){ openMailChat(s.userId, s.name); }; })({userId:m.userId,name:__mName});
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
      async function loadClassMissions(){
        try{
          var clsData = await api('/api/teacher/classes');
          var sel = document.getElementById('cmClassFilter');
          if(sel && !sel.options.length){
            (clsData.classes||[]).forEach(function(c,i){ sel.innerHTML += '<option value="'+escH(c.id)+'"'+(i===0?' selected':'')+'>'+escH(c.name)+'</option>'; });
          }
        }catch(e){}
        var wrap = document.getElementById('cmList');
        wrap.innerHTML = '<p class="text-slate-400 text-xs">読み込み中...</p>';
        try{
          var classId = document.getElementById('cmClassFilter').value||'';
          var data = await api('/api/teacher/class-missions?classId='+encodeURIComponent(classId));
          wrap.innerHTML = '';
          if(!data.missions.length){ wrap.innerHTML='<p class="text-xs text-slate-400">まだミッションがありません</p>'; return; }
          for(var i=0;i<data.missions.length;i++){
            var m = data.missions[i];
            var pct = Math.min(100, Math.round(m.progress / m.goalCorrect * 100));
            var card = document.createElement('div');
            card.className = 'border rounded-lg p-3 mb-2 ' + (m.achieved ? 'bg-green-50 border-green-300' : 'bg-purple-50 border-purple-200');
            card.innerHTML = '<div class="flex items-center justify-between mb-1">'
              + '<div class="font-bold text-sm">'+escH(m.title)+(m.achieved?' <span class="text-green-600">✅達成！</span>':'')+'</div>'
              + '<button class="text-xs text-red-400 hover:text-red-600" onclick="deleteClassMission(&#39;'+escH(m.id)+'&#39;)">削除</button>'
              + '</div>'
              + '<div class="text-xs text-slate-600 mb-1">クラス全員で <b>'+m.progress+'</b> / '+m.goalCorrect+' 問正解（'+pct+'%）</div>'
              + '<div class="w-full bg-slate-200 rounded-full h-3 overflow-hidden"><div class="h-3 '+(m.achieved?'bg-green-500':'bg-purple-500')+'" style="width:'+pct+'%"></div></div>'
              + '<div class="text-xs text-slate-500 mt-1">ごほうび: 💰'+m.rewardCoins+'コイン / 🔹'+m.rewardShards+'かけら'+(m.endAt?' ・締切 '+escH(String(m.endAt).slice(0,10)):'')+'</div>';
            wrap.appendChild(card);
          }
        }catch(e){ wrap.innerHTML='<p class="text-xs text-red-600">読み込みエラー</p>'; }
      }

      async function sendClassMission(){
        var msg = document.getElementById('cmMsg');
        msg.textContent=''; msg.className='text-sm';
        var classId = document.getElementById('cmClassFilter').value;
        var title = document.getElementById('cmTitle').value.trim() || 'クラスミッション';
        var goal = parseInt(document.getElementById('cmGoal').value) || 0;
        var coins = parseInt(document.getElementById('cmCoins').value) || 0;
        var shards = parseInt(document.getElementById('cmShards').value) || 0;
        var endAt = document.getElementById('cmEnd').value || null;
        if(!classId){ msg.textContent='クラスを選択してください'; msg.className='text-sm text-red-600'; return; }
        if(goal < 1){ msg.textContent='目標正解数を入力してください'; msg.className='text-sm text-red-600'; return; }
        try{
          await api('/api/teacher/class-mission',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({classId:classId,title:title,goalCorrect:goal,rewardCoins:coins,rewardShards:shards,endAt:endAt})});
          msg.textContent='ミッションを開始しました！'; msg.className='text-sm text-green-700';
          document.getElementById('cmTitle').value='';
          loadClassMissions();
        }catch(e){ msg.textContent='エラー: '+String(e.message||e); msg.className='text-sm text-red-600'; }
      }

      async function deleteClassMission(id){
        if(!confirm('このミッションを削除しますか？')) return;
        try{
          await api('/api/teacher/class-mission/'+id,{method:'DELETE'});
          loadClassMissions();
        }catch(e){ alert('削除エラー: '+String(e.message||e)); }
      }

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
              + '<span>'+escH(resolveStudentName(r.loginId, r.studentName))+'</span>'
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
