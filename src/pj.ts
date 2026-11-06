// ⚾⚽ __PJ_V1__ 先生PJ「野球・サッカー人気アップ」— スカウト券・チーム・契約・図鑑（サーバ権威）
//   ・クラスごとの ON/OFF（pj_class）。はじめは OFF。OFF のクラスの子には 何も 出さない。
//   ・先生（teacher/admin）は いつでも「ためしモード」で さわれる（ためし用コイン・日を進める）。本物のコインは うごかない。
//   ・選手データは リポジトリに 平文で 置かない。public/pjd/*.bin は 暗号化してあり、鍵は D1（pj_meta.catkey）にだけ ある。
//     先生が はじめて ひらいたときに 1まいずつ ほどいて pj_players に 入れる（1回の リクエストは 小さく）。
//   ・子どもに わたすのは じぶんの 選手の データだけ。ぜんぶを まとめて 出す 道は 作らない。
//   ・きまり：スカウト券 1日3まいまで（200→300→400）、学校の日だけ。チーム30人まで。契約は 学校の日で20日。
//     かぶったら 契約が10日のびる。20日たつと 引退して 図鑑に「殿堂入り」で のこる。
// @ts-nocheck
/* eslint-disable */

type Deps = {
  coinStmt: (env: any, userId: string, delta: number) => any
  classRest: (env: any, classId: string) => Promise<any>
  isRest: (dk: string, extra: any) => boolean
  addDay: (dk: string, n: number) => string
  ownsClass: (c: any, u: any, classId: string) => Promise<any>
  weekKey: () => string
}

const PRICES = [200, 300, 400]
const TEAM_MAX = 30
const CONTRACT = 20
const DUP_EXT = 10
const TEST_COINS = 3000

function jstToday(): string { return new Date(Date.now() + 9 * 3600 * 1000).toISOString().slice(0, 10) }
function err(c: any, s: number, e: string, extra?: any) { return c.json(Object.assign({ ok: false, error: e }, extra || {}), s) }

let _ready = false
async function ensure(env: any) {
  if (_ready) return
  const q = [
    "CREATE TABLE IF NOT EXISTS pj_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS pj_players (k TEXT PRIMARY KEY, s TEXT NOT NULL, j TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS idx_pj_players_s ON pj_players(s)",
    "CREATE TABLE IF NOT EXISTS pj_class (class_id TEXT PRIMARY KEY, enabled INTEGER NOT NULL DEFAULT 0, updated_at TEXT)",
    "CREATE TABLE IF NOT EXISTS pj_user (user_id TEXT PRIMARY KEY, st TEXT NOT NULL, ver INTEGER NOT NULL DEFAULT 1, updated_at TEXT)"
  ]
  for (const s of q) { try { await env.DB.prepare(s).run() } catch (_e) {} }
  _ready = true
}

async function manifest(env: any) {
  try {
    const r = await env.ASSETS.fetch(new Request('https://assets/pjd/m.json'))
    if (r && r.status === 200) return await r.json()
  } catch (_e) {}
  return null
}
async function catVer(env: any) {
  try { const r = await env.DB.prepare("SELECT v FROM pj_meta WHERE k='catver'").first(); return r ? String(r.v) : '' } catch (_e) { return '' }
}

function hexBytes(h: string) { const a = new Uint8Array(h.length / 2); for (let i = 0; i < a.length; i++) a[i] = parseInt(h.substr(i * 2, 2), 16); return a }

async function importPart(env: any, part: number) {
  const m = await manifest(env)
  if (!m) return { ok: false, error: 'no_manifest' }
  if (!(part >= 0 && part < m.parts)) return { ok: false, error: 'part' }
  const kr = await env.DB.prepare("SELECT v FROM pj_meta WHERE k='catkey'").first()
  if (!kr) return { ok: false, error: 'no_key' }
  const res = await env.ASSETS.fetch(new Request('https://assets/pjd/p' + String(part).padStart(2, '0') + '.bin'))
  if (!res || res.status !== 200) return { ok: false, error: 'no_part' }
  const buf = new Uint8Array(await res.arrayBuffer())
  const key = await crypto.subtle.importKey('raw', hexBytes(String(kr.v)), { name: 'AES-GCM' }, false, ['decrypt'])
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12))
  const txt = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).text()
  const rows = JSON.parse(txt)
  const stmts = []
  for (let i = 0; i < rows.length; i += 30) {
    const g = rows.slice(i, i + 30)
    const vals = g.map(() => '(?,?,?)').join(',')
    const args = []
    g.forEach((r) => { args.push(String(r.k), String(r.s), JSON.stringify(r.j)) })
    stmts.push(env.DB.prepare('INSERT OR REPLACE INTO pj_players (k,s,j) VALUES ' + vals).bind(...args))
  }
  await env.DB.batch(stmts)
  if (part === m.parts - 1) await env.DB.prepare("INSERT OR REPLACE INTO pj_meta (k,v) VALUES ('catver', ?)").bind(String(m.v)).run()
  return { ok: true, part, parts: m.parts, rows: rows.length }
}

async function players(env: any, keys: string[]) {
  const out: any = {}
  const ks = Array.from(new Set(keys.filter(Boolean).map(String)))
  for (let i = 0; i < ks.length; i += 90) {
    const g = ks.slice(i, i + 90)
    try {
      const r = await env.DB.prepare('SELECT k, s, j FROM pj_players WHERE k IN (' + g.map(() => '?').join(',') + ')').bind(...g).all()
      for (const x of ((r && r.results) || [])) { try { out[x.k] = Object.assign({ s: x.s }, JSON.parse(String(x.j))) } catch (_e) {} }
    } catch (_e) {}
  }
  return out
}

// ---- だれが 使うか ----
async function who(c: any, d: any) {
  const u = c.get('user')
  if (!u) return { error: 'login' }
  if (u.role === 'teacher' || u.role === 'admin') return { u, test: true, classId: '' }
  if (u.role !== 'student') return { error: 'forbidden' }
  const m = await c.env.DB.prepare('SELECT class_id AS cid FROM class_members WHERE user_id=? LIMIT 1').bind(String(u.id)).first()
  if (!m || !m.cid) return { error: 'off' }   // クラスに 入っていない子には 出さない
  const p = await c.env.DB.prepare('SELECT enabled FROM pj_class WHERE class_id=?').bind(String(m.cid)).first()
  if (!p || Number(p.enabled) !== 1) return { error: 'off' }
  // 今週の 学習計画が 承認された子だけ つかえる（PJ_PLANGATE_V1）
  let plan = false
  try { const q = await c.env.DB.prepare('SELECT plan_approved AS a FROM student_weekly_plans WHERE user_id=? AND week_key=? LIMIT 1').bind(String(u.id), d.weekKey()).first(); plan = !!(q && Number(q.a) === 1) } catch (_e) { plan = false }
  return { u, test: false, classId: String(m.cid), plan }
}

function blank() { return { ro: [], zk: {}, by: { d: '', n: 0 }, pd: null, nw: [], tc: TEST_COINS, off: 0 } }

async function load(env: any, uid: string) {
  const r = await env.DB.prepare('SELECT st, ver FROM pj_user WHERE user_id=?').bind(String(uid)).first()
  if (!r) return { st: blank(), ver: 0 }
  let st = null
  try { st = JSON.parse(String(r.st)) } catch (_e) { st = null }
  st = Object.assign(blank(), st || {})
  return { st, ver: Number(r.ver) || 1 }
}
async function save(env: any, uid: string, st: any, ver: number) {
  const js = JSON.stringify(st)
  if (!ver) {
    try { await env.DB.prepare("INSERT INTO pj_user (user_id, st, ver, updated_at) VALUES (?, ?, 1, datetime('now'))").bind(String(uid), js).run(); return true } catch (_e) { return false }
  }
  const r = await env.DB.prepare("UPDATE pj_user SET st=?, ver=ver+1, updated_at=datetime('now') WHERE user_id=? AND ver=?").bind(js, String(uid), ver).run()
  return !!(r && r.meta && Number(r.meta.changes) === 1)
}

export function installPj(app: any, d: Deps) {
  // その子の「きょう」と 休みの日
  async function dayCtx(c: any, w: any, st: any) {
    let today = jstToday()
    if (w.test && st.off) today = d.addDay(today, Number(st.off) || 0)
    const rest = w.classId ? await d.classRest(c.env, w.classId) : {}
    const school = (dk: string) => !d.isRest(dk, rest)
    return { today, school }
  }
  function used(start: string, today: string, school: any) {
    let n = 0, dk = start
    for (let i = 0; i < 400 && dk <= today; i++) { if (school(dk)) n++; dk = d.addDay(dk, 1) }
    return n
  }
  function leftOf(r: any, ctx: any) { return CONTRACT + (Number(r.e) || 0) - Math.max(0, used(r.s, ctx.today, ctx.school) - 1) }

  // 引退の しょり（20日 たった 選手を 殿堂へ）
  function retire(st: any, ctx: any) {
    let ch = false
    const keep = []
    for (const r of st.ro) {
      if (leftOf(r, ctx) <= 0) {
        const z = st.zk[r.k] || (st.zk[r.k] = { n: 1, f: r.s })
        z.h = 1
        st.nw.push({ k: r.k, d: ctx.today, days: CONTRACT + (Number(r.e) || 0) })
        ch = true
      } else keep.push(r)
    }
    st.ro = keep
    if (st.nw.length > 20) st.nw = st.nw.slice(-20)
    return ch
  }

  async function coinsOf(c: any, w: any, st: any) {
    if (w.test) return Number(st.tc) || 0
    try { const r = await c.env.DB.prepare("SELECT CAST(json_extract(state_json,'$.coins') AS INTEGER) AS c FROM progress WHERE user_id=?").bind(String(w.u.id)).first(); return Number(r && r.c) || 0 } catch (_e) { return 0 }
  }

  async function view(c: any, w: any, st: any, ctx: any, extra?: any) {
    const bought = st.by && st.by.d === ctx.today ? Number(st.by.n) || 0 : 0
    const keys = st.ro.map((r: any) => r.k).concat(st.pd ? [st.pd] : [], st.nw.map((n: any) => n.k), extra && extra.k ? [extra.k] : [])
    const pl = await players(c.env, keys)
    let total = 0
    try { const t = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM pj_players').first(); total = Number(t && t.n) || 0 } catch (_e) {}
    return Object.assign({
      ok: true, test: !!w.test, today: ctx.today, school: ctx.school(ctx.today),
      coins: await coinsOf(c, w, st), bought, max: PRICES.length, price: bought < PRICES.length ? PRICES[bought] : null,
      teamMax: TEAM_MAX, roster: st.ro.map((r: any) => ({ k: r.k, left: leftOf(r, ctx) })).sort((a: any, b: any) => a.left - b.left),
      pending: st.pd, news: st.nw, zukan: Object.keys(st.zk).length, zb: Object.keys(st.zk).filter((k) => k[0] === 'b').length, total, players: pl
    }, extra || {})
  }

  async function begin(c: any) {
    await ensure(c.env)
    const w = await who(c, d)
    if (w.error) return { res: err(c, w.error === 'login' ? 401 : 403, w.error) }
    if (!w.test && !w.plan) return { res: err(c, 403, 'plan') }
    const m = await manifest(c.env)
    if (m && (await catVer(c.env)) !== String(m.v)) return { res: c.json({ ok: false, error: 'import', test: !!w.test, parts: m.parts }) }
    const L = await load(c.env, w.u.id)
    const ctx = await dayCtx(c, w, L.st)
    return { w, st: L.st, ver: L.ver, ctx }
  }

  // 子どもの アプリに 入口を 出すか（OFF なら 何も 出さない）
  app.get('/api/pj/status', async (c: any) => {
    await ensure(c.env)
    const w = await who(c, d)
    return c.json({ ok: true, on: !w.error, plan: !!(w.test || w.plan) })
  })

  app.get('/api/pj/state', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    if (retire(b.st, b.ctx)) await save(c.env, b.w.u.id, b.st, b.ver)
    return c.json(await view(c, b.w, b.st, b.ctx))
  })

  // スカウト券を 買って 1回 ひく
  app.post('/api/pj/scout', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const { w, st, ctx } = b
    retire(st, ctx)
    if (!ctx.school(ctx.today)) return err(c, 409, 'rest_day')
    if (st.pd) return err(c, 409, 'pending')
    const bought = st.by && st.by.d === ctx.today ? Number(st.by.n) || 0 : 0
    if (bought >= PRICES.length) return err(c, 409, 'limit')
    const price = PRICES[bought]
    // どちらを ひくか えらべる（PJ_SPORT_V1）。えらばなければ はんぶんずつ
    const body0 = await c.req.json().catch(() => ({}))
    const sport = body0 && (body0.sport === 'bb' || body0.sport === 'sc') ? body0.sport : (Math.random() < 0.5 ? 'bb' : 'sc')
    const pr = await c.env.DB.prepare('SELECT k FROM pj_players WHERE s=? ORDER BY RANDOM() LIMIT 1').bind(sport).first()
    if (!pr) return err(c, 503, 'no_players')
    // お金を 先に 引く（足りなければ ここで 止まる）
    if (w.test) {
      if ((Number(st.tc) || 0) < price) return err(c, 402, 'coins')
      st.tc = (Number(st.tc) || 0) - price
    } else {
      const r = await d.coinStmt(c.env, w.u.id, -price).run()
      if (!(r && r.meta && Number(r.meta.changes) === 1)) return err(c, 402, 'coins')
    }
    const k = String(pr.k)
    st.by = { d: ctx.today, n: bought + 1 }
    const z = st.zk[k]
    st.zk[k] = { n: (z ? Number(z.n) || 0 : 0) + 1, f: z ? z.f : ctx.today }
    if (z && z.h) st.zk[k].h = 1
    let kind = 'new'
    const mine = st.ro.find((r: any) => r.k === k)
    if (mine) { mine.e = (Number(mine.e) || 0) + DUP_EXT; kind = 'dup' }
    // チームは 野球・サッカー それぞれ 30人まで（PJ_SPORTMODE_V1）
    else if (st.ro.filter((r: any) => (r.k[0] === 'b') === (k[0] === 'b')).length < TEAM_MAX) { st.ro.push({ k, s: ctx.today, e: 0 }); kind = z ? 'back' : 'new' }
    else { st.pd = k; kind = 'full' }
    const okSave = await save(c.env, w.u.id, st, b.ver)
    if (!okSave) {
      if (!w.test) { try { await d.coinStmt(c.env, w.u.id, price).run() } catch (_e) {} }   // 保存できなければ 返す
      return err(c, 409, 'busy')
    }
    let spent = null
    if (!w.test) { try { const s = await c.env.DB.prepare("SELECT CAST(json_extract(state_json,'$._serverSpentCoins') AS INTEGER) AS v FROM progress WHERE user_id=?").bind(String(w.u.id)).first(); spent = Number(s && s.v) || 0 } catch (_e) {} }
    return c.json(await view(c, w, st, ctx, { pull: { k, kind, first: !z }, serverSpentCoins: spent }))
  })

  // チームが いっぱいの ときに：だれかを 自由契約にして 入れる／見送る
  app.post('/api/pj/keep', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const { w, st, ctx } = b
    const body = await c.req.json().catch(() => ({}))
    if (!st.pd) return err(c, 409, 'none')
    if (body && body.release) {
      const i = st.ro.findIndex((r: any) => r.k === String(body.release) && (r.k[0] === 'b') === (String(st.pd)[0] === 'b'))
      if (i < 0) return err(c, 400, 'release')
      st.ro.splice(i, 1)
      st.ro.push({ k: st.pd, s: ctx.today, e: 0 })
    }
    st.pd = null
    if (!(await save(c.env, w.u.id, st, b.ver))) return err(c, 409, 'busy')
    return c.json(await view(c, w, st, ctx))
  })

  // 自由契約（チームから 外す。図鑑には のこる）
  app.post('/api/pj/release', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const { w, st, ctx } = b
    const body = await c.req.json().catch(() => ({}))
    const i = st.ro.findIndex((r: any) => r.k === String(body && body.k))
    if (i < 0) return err(c, 400, 'k')
    st.ro.splice(i, 1)
    if (!(await save(c.env, w.u.id, st, b.ver))) return err(c, 409, 'busy')
    return c.json(await view(c, w, st, ctx))
  })

  app.post('/api/pj/news-seen', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    b.st.nw = []
    await save(c.env, b.w.u.id, b.st, b.ver)
    return c.json({ ok: true })
  })

  // 図鑑：60人ずつ（重くしない）
  app.get('/api/pj/zukan', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const sport = c.req.query('s') === 'sc' ? 'sc' : (c.req.query('s') === 'bb' ? 'bb' : '')
    const page = Math.max(0, Math.floor(Number(c.req.query('p') || 0)))
    let ks = Object.keys(b.st.zk)
    ks.sort((a, x) => String(b.st.zk[x].f || '').localeCompare(String(b.st.zk[a].f || '')) || a.localeCompare(x))
    if (sport) ks = ks.filter((k) => sport === 'bb' ? k[0] === 'b' : k[0] !== 'b')
    const slice = ks.slice(page * 60, page * 60 + 60)
    const pl = await players(c.env, slice)
    const inTeam: any = {}; b.st.ro.forEach((r: any) => { inTeam[r.k] = 1 })
    return c.json({ ok: true, count: ks.length, page, more: ks.length > page * 60 + 60, items: slice.map((k) => ({ k, n: b.st.zk[k].n, f: b.st.zk[k].f, h: !!b.st.zk[k].h, team: !!inTeam[k], p: pl[k] || null })) })
  })

  // 元の 選手名鑑（手作りアプリの 野球・サッカー）を ひらく じゅんび（PJ_MEIKAN_V1）
  //   ・ページは 暗号化して 置いてあり、ここで 鍵と「その子が 持っている 選手」だけを わたす。
  app.get('/api/pj/meikan', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const kr = await c.env.DB.prepare("SELECT v FROM pj_meta WHERE k='gkey'").first()
    let ver: any = {}
    try { const r = await c.env.ASSETS.fetch(new Request('https://assets/pjd/g.json')); if (r && r.status === 200) ver = await r.json() } catch (_e) {}
    const ks = Object.keys(b.st.zk)
    const bb = ks.filter((k) => k[0] === 'b').map((k) => Number(k.slice(1))).filter((n) => n >= 0)
    const scK = ks.filter((k) => k[0] !== 'b')
    const pl = await players(c.env, scK)
    const sc = scK.map((k) => pl[k] && pl[k].mk).filter(Boolean)
    return c.json({ ok: true, key: kr ? String(kr.v) : '', v: ver, bb, sc })
  })
  app.get('/api/pj/game/:f', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const f = c.req.param('f') === 'sc' ? 'sc' : 'bb'
    const r = await c.env.ASSETS.fetch(new Request('https://assets/pjd/g' + f + '.bin'))
    if (!r || r.status !== 200) return err(c, 404, 'no_game')
    return new Response(r.body, { headers: { 'content-type': 'application/octet-stream', 'cache-control': 'private, max-age=2592000' } })
  })

  // 先生の ためしモード（ためし用コインと 日付だけ。本物は うごかない）
  app.post('/api/pj/test', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    if (!b.w.test) return err(c, 403, 'teacher_only')
    const body = await c.req.json().catch(() => ({}))
    const st = b.st
    if (body.act === 'day') st.off = (Number(st.off) || 0) + Math.max(1, Math.min(30, Math.floor(Number(body.n) || 1)))
    else if (body.act === 'coins') st.tc = (Number(st.tc) || 0) + 1000
    else if (body.act === 'reset') { const n = blank(); Object.keys(st).forEach((k) => delete st[k]); Object.assign(st, n) }
    else return err(c, 400, 'act')
    if (!(await save(c.env, b.w.u.id, st, b.ver))) return err(c, 409, 'busy')
    const ctx = await dayCtx(c, b.w, st)
    retire(st, ctx); await save(c.env, b.w.u.id, st, b.ver + 1)
    return c.json(await view(c, b.w, st, ctx))
  })

  // 選手データを D1 に 入れる（先生だけ。1回に 1まい）
  app.post('/api/pj/admin/import', async (c: any) => {
    await ensure(c.env)
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return err(c, 403, 'forbidden')
    const body = await c.req.json().catch(() => ({}))
    try { return c.json(await importPart(c.env, Math.floor(Number(body.part)))) } catch (e) { return err(c, 500, 'import_failed', { detail: String(e && e.message || e).slice(0, 200) }) }
  })

  // クラスの ON/OFF（先生）
  app.get('/api/teacher/pj/class/:classId', async (c: any) => {
    await ensure(c.env)
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return err(c, 403, 'forbidden')
    const cid = c.req.param('classId')
    if (!(await d.ownsClass(c, u, cid))) return err(c, 404, 'class')
    const r = await c.env.DB.prepare('SELECT enabled FROM pj_class WHERE class_id=?').bind(cid).first()
    return c.json({ ok: true, enabled: !!(r && Number(r.enabled) === 1) })
  })
  app.put('/api/teacher/pj/class/:classId', async (c: any) => {
    await ensure(c.env)
    const u = c.get('user')
    if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return err(c, 403, 'forbidden')
    const cid = c.req.param('classId')
    if (!(await d.ownsClass(c, u, cid))) return err(c, 404, 'class')
    const body = await c.req.json().catch(() => ({}))
    const en = body && body.enabled ? 1 : 0
    await c.env.DB.prepare("INSERT INTO pj_class (class_id, enabled, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(class_id) DO UPDATE SET enabled=excluded.enabled, updated_at=excluded.updated_at").bind(cid, en).run()
    return c.json({ ok: true, enabled: !!en })
  })
}
