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

  return c.json({ ok: true, status: 'pending_approval' })
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
        if(!r.ok){ msg.textContent = j.error || 'error'; return; }
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
        <input id="name" class="w-full border p-2 rounded" placeholder="名前"/>
        <input id="grade" class="w-full border p-2 rounded" placeholder="学年（例: 5）"/>
        <input id="className" class="w-full border p-2 rounded" placeholder="クラス（例: 2組 / A）"/>
        <input id="loginId" class="w-full border p-2 rounded" placeholder="ログインID（自由）"/>
        <input id="password" type="password" class="w-full border p-2 rounded" placeholder="パスワード（6文字以上）"/>
        <button id="btn" class="w-full bg-green-600 text-white rounded p-2">登録</button>
        <p id="msg" class="text-sm"></p>
        <a class="text-sm text-blue-700 underline" href="/login">ログインへ</a>
      </div>
    </div>
    <script>
      const msg = document.getElementById('msg');
      document.getElementById('btn').onclick = async () => {
        msg.textContent='';
        const payload = {
          name: document.getElementById('name').value.trim(),
          grade: Number(document.getElementById('grade').value),
          className: document.getElementById('className').value.trim(),
          loginId: document.getElementById('loginId').value.trim(),
          password: document.getElementById('password').value,
        };
        const r = await fetch('/api/auth/signup',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(payload)});
        const j = await r.json().catch(()=>({}));
        if(!r.ok){ msg.textContent = (j.error || 'error'); msg.className='text-sm text-red-600'; return; }
        msg.textContent = '登録しました。管理者の承認後にログインできます。';
        msg.className='text-sm text-green-700';
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
        <button id="logout" class="text-sm underline">ログアウト</button>
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
