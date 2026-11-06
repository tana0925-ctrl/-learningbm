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
  weekKey: (offsetDays?: number) => string
  weekOf: (dk: string) => string
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

// 監督の データ（PJ_MGR_V1）。小さいので、ひつようなら その場で 入れる
let _mgOk = ''
async function ensureMgr(env: any) {
  try {
    const r = await env.ASSETS.fetch(new Request('https://assets/pjd/mg.json'))
    if (!r || r.status !== 200) return
    const m = await r.json()
    if (_mgOk === m.v) return
    const cur = await env.DB.prepare("SELECT v FROM pj_meta WHERE k='mgver'").first()
    if (cur && String(cur.v) === String(m.v)) { _mgOk = m.v; return }
    const kr = await env.DB.prepare("SELECT v FROM pj_meta WHERE k='catkey'").first()
    if (!kr) return
    const res = await env.ASSETS.fetch(new Request('https://assets/pjd/mg.bin'))
    const buf = new Uint8Array(await res.arrayBuffer())
    const key = await crypto.subtle.importKey('raw', hexBytes(String(kr.v)), { name: 'AES-GCM' }, false, ['decrypt'])
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12))
    const rows = JSON.parse(await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream('gzip'))).text())
    const stmts = []
    for (let i = 0; i < rows.length; i += 30) {
      const g = rows.slice(i, i + 30), args = []
      g.forEach((x) => { args.push(String(x.k), String(x.s), JSON.stringify(x.j)) })
      stmts.push(env.DB.prepare('INSERT OR REPLACE INTO pj_players (k,s,j) VALUES ' + g.map(() => '(?,?,?)').join(',')).bind(...args))
    }
    await env.DB.batch(stmts)
    await env.DB.prepare("INSERT OR REPLACE INTO pj_meta (k,v) VALUES ('mgver', ?)").bind(String(m.v)).run()
    _mgOk = m.v
  } catch (_e) {}
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
  // 先週 か 今週、どちらかの 学習計画が 承認された子が つかえる（PJ_PLANGATE_V3：先週 がんばった子は 月曜から、今週 早く 出した子は 承認された その時から）
  let plan = false
  try { const q = await c.env.DB.prepare('SELECT 1 AS a FROM student_weekly_plans WHERE user_id=? AND week_key IN (?, ?) AND plan_approved=1 LIMIT 1').bind(String(u.id), d.weekKey(-7), d.weekKey(0)).first(); plan = !!q } catch (_e) { plan = false }
  // 承認された 週（契約の 日数を 数えるのに つかう：つかえない 週は 日数を へらさない＝PJ_PAUSE_CONTRACT_V1）
  let apw: string[] = []
  try { const r = await c.env.DB.prepare('SELECT week_key AS w FROM student_weekly_plans WHERE user_id=? AND plan_approved=1').bind(String(u.id)).all(); apw = ((r && r.results) || []).map((x: any) => String(x.w)) } catch (_e) { apw = [] }
  return { u, test: false, classId: String(m.cid), plan, apw }
}

function blank() { return { ro: [], zk: {}, by: { d: '', n: 0 }, pd: null, nw: [], tc: TEST_COINS, off: 0, mg: {}, cm: {} } }

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

// 📋 オーダー（PJ_ORDER_V1）：野球＝スタメン9（打順・守備）＋先発2・中継ぎ3・抑え1・控え野手3／サッカー＝フォーメーション＋11人＋ベンチ5
const BB_POS = ['C', '1B', '2B', '3B', 'SS', 'LF', 'CF', 'RF', 'DH']
const SC_FORMS = ['4-4-2', '4-3-3', '4-2-3-1', '3-5-2', '3-4-2-1']
const LIM: any = { SP: 2, RP: 3, CL: 1, BN: 3, B: 5 }
function cleanOrder(st: any) {
  const have: any = {}; (st.ro || []).forEach((r: any) => { have[r.k] = 1 })
  const od = st.od || {}, out: any = {}
  const bb = od.bb || {}, used: any = {}
  const ok = (k: any, b: boolean) => typeof k === 'string' && have[k] && (k[0] === 'b') === b && !used[k] && (used[k] = 1)
  out.bb = { L: (bb.L || []).filter((x: any) => x && BB_POS.indexOf(x.p) >= 0 && ok(x.k, true)).slice(0, 9) }
  ;['SP', 'RP', 'CL', 'BN'].forEach((g) => { out.bb[g] = (bb[g] || []).filter((k: any) => ok(k, true)).slice(0, LIM[g]) })
  const sc = od.sc || {}
  out.sc = { f: SC_FORMS.indexOf(sc.f) >= 0 ? sc.f : '4-3-3', L: (sc.L || []).slice(0, 11).map((k: any) => (k && ok(k, false)) ? k : null), B: (sc.B || []).filter((k: any) => ok(k, false)).slice(0, LIM.B) }
  return out
}

// 🏷 チーム名（PJ_TEAMNAME_V1）：ことばを 2つ えらんで くみあわせる（自由入力は しない＝本名・からかいが 入らない）
const TN_A = ['ひかり', 'かぜ', 'そら', 'ほのお', 'いなずま', 'にじ', 'ほし', 'たいよう', 'つき', 'うみ', 'もり', 'さくら', 'ゆき', 'あおぞら', 'みらい', 'ゆうき', 'きぼう', 'はやぶさ', 'サンダー', 'スター', 'ブレイブ', 'ミラクル', 'ドリーム', 'ロケット', 'ギャラクシー', 'ゴールデン', 'スーパー', 'ファイヤー', 'アクア', 'シャイン']
const TN_B: any = {
  bb: ['イーグルス', 'タイガース', 'ドラゴンズ', 'スターズ', 'ホークス', 'ライオンズ', 'マリンズ', 'ベアーズ', 'ファルコンズ', 'ウェーブズ', 'サンダーズ', 'フェニックス', 'ジャガーズ', 'パイレーツ', 'ブルース', 'ファイターズ'],
  sc: ['FC', 'ユナイテッド', 'シティ', 'ローヴァーズ', 'ワンダラーズ', 'アスレチック', 'レンジャーズ', 'ウィングス', 'ヴィクトリー', 'ドリームズ', 'スターズ', 'ファイターズ', 'SC', 'ユース']
}
function tnName(sp: string, v: any) {
  if (!Array.isArray(v)) return ''
  const a = TN_A[Number(v[0])], b = (TN_B[sp] || [])[Number(v[1])]
  if (!a || !b) return ''
  return b === 'FC' || b === 'SC' ? b + a : a + b
}

export function installPj(app: any, d: Deps) {
  // 練習試合が できるか（家庭学習の「学習日」＝朝8:30 区切り。先生の ためしモードは いつでも）
  async function practiceInfo(c: any, w: any, st: any, ctx: any) {
    const day = new Date(Date.now() + 30 * 60 * 1000).toISOString().slice(0, 10)
    if (w.test) return { can: true, hw: true, used: false, day, test: true }
    let hw = false
    try { const r = await c.env.DB.prepare('SELECT 1 AS x FROM homework_submissions WHERE user_id=? AND day_key=? AND COALESCE(rest_day,0)=0 LIMIT 1').bind(String(w.u.id), day).first(); hw = !!r } catch (_e) { hw = false }
    const used = !!(st.pr && st.pr.d === day && Number(st.pr.n) >= 1)
    return { can: hw && !used, hw, used, day }
  }

  // その子の「きょう」と 休みの日
  async function dayCtx(c: any, w: any, st: any) {
    let today = jstToday()
    if (w.test && st.off) today = d.addDay(today, Number(st.off) || 0)
    const rest = w.classId ? await d.classRest(c.env, w.classId) : {}
    // 子どもは「先週か今週の 計画が 承認された 週」の 学校の日だけ 数える（つかえない 週は 契約が へらない）
    const ap: any = {}; (w.apw || []).forEach((x: string) => { ap[x] = 1 })
    const okWeek: any = {}
    const allowed = (dk: string) => { if (w.test) return true; const wk = d.weekOf(dk); if (!(wk in okWeek)) okWeek[wk] = !!(ap[wk] || ap[d.weekOf(d.addDay(dk, -7))]); return okWeek[wk] }
    const school = (dk: string) => !d.isRest(dk, rest) && allowed(dk)
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
    const cm = st.cm || {}
    const keys = st.ro.map((r: any) => r.k).concat(st.pd ? [st.pd] : [], st.nw.map((n: any) => n.k), extra && extra.k ? [extra.k] : [], extra && extra.pull && extra.pull.k ? [extra.pull.k] : [], cm.bb ? [cm.bb] : [], cm.sc ? [cm.sc] : [])
    const pl = await players(c.env, keys)
    let total = 0
    try { const t = await c.env.DB.prepare('SELECT COUNT(*) AS n FROM pj_players WHERE s IN (\'bb\',\'sc\')').first(); total = Number(t && t.n) || 0 } catch (_e) {}
    return Object.assign({
      ok: true, test: !!w.test, today: ctx.today, school: ctx.school(ctx.today),
      coins: await coinsOf(c, w, st), bought, max: PRICES.length, price: bought < PRICES.length ? PRICES[bought] : null,
      teamMax: TEAM_MAX, roster: st.ro.map((r: any) => ({ k: r.k, left: leftOf(r, ctx) })).sort((a: any, b: any) => a.left - b.left),
      teamName: { bb: tnName('bb', (st.tn || {}).bb), sc: tnName('sc', (st.tn || {}).sc) }, tnOpts: { a: TN_A, bb: TN_B.bb, sc: TN_B.sc }, tnSel: st.tn || {},
      order: cleanOrder(st), starterGot: st.sg || {}, practice: await practiceInfo(c, w, st, ctx),
      mgr: { bb: cm.bb || null, sc: cm.sc || null }, mgN: { bb: Object.keys(st.mg || {}).filter((k) => k.indexOf('mb:') === 0).length, sc: Object.keys(st.mg || {}).filter((k) => k.indexOf('ms:') === 0).length },
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
    await ensureMgr(c.env)
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
    // ポジションを えらんで ひける（PJ_POS_V1）。えらばなければ だれでも
    const POS: any = {
      bb: { P: ['投手'], C: ['捕手'], IF: ['一塁手', '二塁手', '三塁手', '遊撃手'], OF: ['外野手'] },
      sc: { GK: ['ゴールキーパー'], DF: ['センターバック', 'サイドバック'], MF: ['守備的MF', '攻撃的MF'], FW: ['ウイング', 'センターフォワード'] }
    }
    const want = POS[sport] && body0 && POS[sport][String(body0.pos || '')]
    // 🎩 監督（引退しない・どんどん ふえる）。まだ いない 監督から ひく
    if (body0 && body0.pos === 'MG') {
      st.mg = st.mg || {}; st.cm = st.cm || {}
      const pre = sport === 'bb' ? 'mb:' : 'ms:'
      const have = Object.keys(st.mg).filter((x) => x.indexOf(pre) === 0)
      let mr = null
      if (have.length) {
        const hv = have.slice(0, 600)
        mr = await c.env.DB.prepare('SELECT k FROM pj_players WHERE s=? AND k NOT IN (' + hv.map(() => '?').join(',') + ') ORDER BY RANDOM() LIMIT 1').bind(sport + 'm', ...hv).first()
      }
      if (!mr) mr = await c.env.DB.prepare('SELECT k FROM pj_players WHERE s=? ORDER BY RANDOM() LIMIT 1').bind(sport + 'm').first()
      if (!mr) return err(c, 503, 'no_players')
      if (w.test) {
        if ((Number(st.tc) || 0) < price) return err(c, 402, 'coins')
        st.tc = (Number(st.tc) || 0) - price
      } else {
        const r = await d.coinStmt(c.env, w.u.id, -price).run()
        if (!(r && r.meta && Number(r.meta.changes) === 1)) return err(c, 402, 'coins')
      }
      const mk = String(mr.k), dupM = !!st.mg[mk]
      st.by = { d: ctx.today, n: bought + 1 }
      st.mg[mk] = { f: dupM ? st.mg[mk].f : ctx.today }
      if (!st.cm[sport]) st.cm[sport] = mk
      if (!(await save(c.env, w.u.id, st, b.ver))) {
        if (!w.test) { try { await d.coinStmt(c.env, w.u.id, price).run() } catch (_e) {} }
        return err(c, 409, 'busy')
      }
      return c.json(await view(c, w, st, ctx, { pull: { k: mk, kind: dupM ? 'mgr_dup' : 'mgr', first: !dupM } }))
    }
    let pr = null
    if (want) {
      const cond = want.map(() => "json_extract(j,'$.pos') LIKE ?").join(' OR ')
      pr = await c.env.DB.prepare('SELECT k FROM pj_players WHERE s=? AND (' + cond + ') ORDER BY RANDOM() LIMIT 1').bind(sport, ...want.map((w: string) => '%' + w + '%')).first()
    } else pr = await c.env.DB.prepare('SELECT k FROM pj_players WHERE s=? ORDER BY RANDOM() LIMIT 1').bind(sport).first()
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

  // 監督：持っている 監督の 一覧と、つかう 監督を きめる
  app.get('/api/pj/managers', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const sp = c.req.query('s') === 'sc' ? 'sc' : 'bb', pre = sp === 'bb' ? 'mb:' : 'ms:'
    const ks = Object.keys(b.st.mg || {}).filter((k) => k.indexOf(pre) === 0)
    const pl = await players(c.env, ks)
    return c.json({ ok: true, cur: (b.st.cm || {})[sp] || null, items: ks.map((k) => ({ k, p: pl[k] || null })) })
  })
  app.post('/api/pj/manager', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const body = await c.req.json().catch(() => ({}))
    const k = String(body && body.k || ''), sp = k.indexOf('mb:') === 0 ? 'bb' : (k.indexOf('ms:') === 0 ? 'sc' : '')
    if (!sp || !(b.st.mg || {})[k]) return err(c, 400, 'k')
    b.st.cm = b.st.cm || {}; b.st.cm[sp] = k
    if (!(await save(c.env, b.w.u.id, b.st, b.ver))) return err(c, 409, 'busy')
    return c.json(await view(c, b.w, b.st, b.ctx))
  })

  app.post('/api/pj/order', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const body = await c.req.json().catch(() => ({}))
    const sp = body && body.sport === 'sc' ? 'sc' : 'bb'
    b.st.od = b.st.od || {}
    b.st.od[sp] = body && body.od && typeof body.od === 'object' ? body.od : {}
    b.st.od = cleanOrder(b.st)
    if (!(await save(c.env, b.w.u.id, b.st, b.ver))) return err(c, 409, 'busy')
    return c.json(await view(c, b.w, b.st, b.ctx))
  })

  // 🎁 さいしょの 選手（PJ_STARTER_V1）：はじめて その スポーツを ひらいたら、弱めの 選手 15人と 監督 1人
  const STARTER: any = {
    bb: [['投手', '先発', 2], ['投手', '中継ぎ', 2], ['投手', '抑え', 1], ['捕手', '', 1], ['一塁手', '', 1], ['二塁手', '', 1], ['三塁手', '', 1], ['遊撃手', '', 1], ['外野手', '', 3], ['', '', 2]],
    sc: [['ゴールキーパー', '', 2], ['センターバック', '', 3], ['サイドバック', '', 2], ['守備的MF', '', 2], ['攻撃的MF', '', 2], ['ウイング', '', 2], ['センターフォワード', '', 2]]
  }
  function weakScore(j: any) { const a = (j && j.ab) || {}; let t = 0; Object.keys(a).forEach((k) => { t += Number(a[k]) || 0 }); return t }
  app.post('/api/pj/starter', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const body = await c.req.json().catch(() => ({}))
    const sp = body && body.sport === 'sc' ? 'sc' : 'bb'
    const st = b.st, ctx = b.ctx
    st.sg = st.sg || {}
    if (st.sg[sp]) return c.json(await view(c, b.w, st, ctx))
    const got: string[] = [], seen: any = {}
    st.ro.forEach((r: any) => { seen[r.k] = 1 })
    for (const [pos, role, n] of STARTER[sp]) {
      let q = 'SELECT k, j FROM pj_players WHERE s=? AND json_extract(j,\'$.st\')=1', args: any[] = [sp]
      if (pos) { q += " AND json_extract(j,'$.pos') LIKE ?"; args.push('%' + pos + '%') }
      if (role) { q += " AND json_extract(j,'$.pos') LIKE ?"; args.push('%' + role + '%') }
      if (sp === 'bb' && !pos) q += " AND json_extract(j,'$.pos') NOT LIKE '投手%'"
      const r = await c.env.DB.prepare(q + ' ORDER BY RANDOM() LIMIT 24').bind(...args).all()
      const cand = ((r && r.results) || []).map((x: any) => ({ k: String(x.k), sc: weakScore(JSON.parse(String(x.j))) })).filter((x: any) => !seen[x.k]).sort((x: any, y: any) => x.sc - y.sc)
      cand.slice(0, Math.max(n, Math.ceil(cand.length / 2))).sort(() => Math.random() - 0.5).slice(0, n).forEach((x: any) => { seen[x.k] = 1; got.push(x.k) })
    }
    got.forEach((k) => {
      if (st.ro.filter((r: any) => (r.k[0] === 'b') === (sp === 'bb')).length >= TEAM_MAX) return
      st.ro.push({ k, s: ctx.today, e: 0 })
      const z = st.zk[k]; st.zk[k] = { n: (z ? Number(z.n) || 0 : 0) + 1, f: z ? z.f : ctx.today }
    })
    st.mg = st.mg || {}; st.cm = st.cm || {}
    if (!st.cm[sp]) {
      const m = await c.env.DB.prepare('SELECT k FROM pj_players WHERE s=? ORDER BY RANDOM() LIMIT 1').bind(sp + 'm').first()
      if (m) { st.mg[String(m.k)] = { f: ctx.today }; st.cm[sp] = String(m.k) }
    }
    st.sg[sp] = ctx.today
    if (!(await save(c.env, b.w.u.id, st, b.ver))) return err(c, 409, 'busy')
    return c.json(await view(c, b.w, st, ctx, { starter: { sport: sp, n: got.length } }))
  })

  // 🤖 CPUの チーム（練習試合の あいて）：ポジションが そろうように ★1〜2の 選手から
  app.get('/api/pj/cpu-team', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const sp = c.req.query('s') === 'sc' ? 'sc' : 'bb'
    const lv = ['weak', 'mid', 'strong'].indexOf(String(c.req.query('lv'))) >= 0 ? String(c.req.query('lv')) : 'mid'
    const r = await cpuRoster(c.env, sp, lv)
    return c.json(Object.assign({ ok: true, coach: await cpuCoach(c.env, sp) }, r))
  })

  // 🏟 練習試合（PJ_PRACTICE_V1）：その日に 家庭学習を 出した子だけ、1日 1回
  app.post('/api/pj/practice/use', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const p = await practiceInfo(c, b.w, b.st, b.ctx)
    if (!p.can) return err(c, 403, p.hw ? 'practice_used' : 'practice_hw')
    if (!b.w.test) { b.st.pr = { d: p.day, n: 1 }; if (!(await save(c.env, b.w.u.id, b.st, b.ver))) return err(c, 409, 'busy') }
    return c.json({ ok: true })
  })

  app.post('/api/pj/teamname', async (c: any) => {
    const b = await begin(c); if (b.res) return b.res
    const body = await c.req.json().catch(() => ({}))
    const sp = body && body.sport === 'sc' ? 'sc' : 'bb', v = [Math.floor(Number(body && body.a)), Math.floor(Number(body && body.b))]
    if (!tnName(sp, v)) return err(c, 400, 'name')
    b.st.tn = b.st.tn || {}; b.st.tn[sp] = v
    if (!(await save(c.env, b.w.u.id, b.st, b.ver))) return err(c, 409, 'busy')
    return c.json(await view(c, b.w, b.st, b.ctx))
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

  // ===================== 🏆 リーグ戦（PJ_LEAGUE_V1） =====================
  //  ・野球と サッカーは べつべつ。両方でも 片方でも 参加できる。参加したい子だけ。
  //  ・1週間（月〜金の 学校の日）。6チームずつの グループ（足りない ぶんは CPU）。1日 1試合、12:40 に 試合。
  //  ・試合は「たね（seed）」と その日の オーダー（12:40 の 時点で こおらせる）で きまる → だれが 見ても 同じ 試合。
  //  ・結果は 見た人の 画面（元の ゲームの 計算）で 出して サーバに 1回だけ のこす。
  //  ・見られるのは その日に 家庭学習を 出した子だけ、同じ 試合は 2回まで。結果だけなら だれでも 見られる。
  const LG_TIME = '12:40', LG_BUILD = '12:30', LG_SIZE = 6
  function nowHM() { const d = new Date(Date.now() + 9 * 3600 * 1000); return String(d.getUTCHours()).padStart(2, '0') + ':' + String(d.getUTCMinutes()).padStart(2, '0') }
  function mondayOf(dk: string) { const w = new Date(dk + 'T00:00:00Z').getUTCDay(); return d.addDay(dk, w === 0 ? -6 : 1 - w) }
  function lgCid(w: any) { return w.test ? 'T:' + w.u.id : w.classId }
  function seedOf(...xs: any[]) { let h = 2166136261; for (const ch of xs.join('|')) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619) } return h >>> 0 }
  async function ensureLg(env: any) {
    for (const q of ["CREATE TABLE IF NOT EXISTS pj_league (cid TEXT NOT NULL, wk TEXT NOT NULL, sp TEXT NOT NULL, j TEXT NOT NULL, ver INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (cid, wk, sp))",
      "CREATE TABLE IF NOT EXISTS pj_lentry (cid TEXT NOT NULL, wk TEXT NOT NULL, sp TEXT NOT NULL, uid TEXT NOT NULL, created_at TEXT, PRIMARY KEY (cid, wk, sp, uid))"]) { try { await env.DB.prepare(q).run() } catch (_e) {} }
  }
  async function lgLoad(env: any, cid: string, wk: string, sp: string) {
    const r = await env.DB.prepare('SELECT j, ver FROM pj_league WHERE cid=? AND wk=? AND sp=?').bind(cid, wk, sp).first()
    if (!r) return null
    try { return { L: JSON.parse(String(r.j)), ver: Number(r.ver) } } catch (_e) { return null }
  }
  async function lgSave(env: any, cid: string, wk: string, sp: string, L: any, ver: number) {
    if (!ver) { try { await env.DB.prepare('INSERT INTO pj_league (cid, wk, sp, j, ver) VALUES (?,?,?,?,1)').bind(cid, wk, sp, JSON.stringify(L)).run(); return true } catch (_e) { return false } }
    const r = await env.DB.prepare('UPDATE pj_league SET j=?, ver=ver+1 WHERE cid=? AND wk=? AND sp=? AND ver=?').bind(JSON.stringify(L), cid, wk, sp, ver).run()
    return !!(r && r.meta && Number(r.meta.changes) === 1)
  }
  // 名前（子どもの 本名は 出さない）：チーム名は「〇〇の 名前を つかわない」きまった 名前
  const TN = { bb: ['イーグルス', 'タイガース', 'ドラゴンズ', 'スターズ', 'ホークス', 'ライオンズ', 'マリンズ', 'ベアーズ', 'ファルコンズ', 'ウェーブズ', 'サンダーズ', 'フェニックス'], sc: ['FCブルー', 'FCレッド', 'ユナイテッド', 'シティ', 'ローヴァーズ', 'ワンダラーズ', 'アスレチック', 'レンジャーズ', 'FCグリーン', 'スターズFC', 'ウィングス', 'ヴィクトリー'] }
  // lv: weak＝★1の 中でも 弱め／mid＝★1〜2／strong＝★2〜3（練習試合の つよさ）
  async function cpuRoster(env: any, sp: string, lv?: string) {
    const ST = lv === 'strong' ? "CAST(json_extract(j,'$.st') AS INTEGER) >= 2" : lv === 'weak' ? "CAST(json_extract(j,'$.st') AS INTEGER) = 1" : "CAST(json_extract(j,'$.st') AS INTEGER) <= 2"
    const pickK = (rows: any[], seen: any) => { const c = rows.filter((x: any) => !seen[x.k]); if (lv === 'weak') c.sort((a: any, b: any) => weakScore(JSON.parse(String(a.j))) - weakScore(JSON.parse(String(b.j)))); return c[0] || null }
    if (sp === 'bb') {
      const want: any[] = [['捕手'], ['一塁手'], ['二塁手'], ['三塁手'], ['遊撃手'], ['外野手'], ['外野手'], ['外野手'], [''], [''], [''], [''], ['投手', '先発'], ['投手', '先発'], ['投手', '中継ぎ'], ['投手', '中継ぎ'], ['投手', '中継ぎ'], ['投手', '抑え']]
      const ids: any[] = [], seen: any = {}
      for (const w of want) {
        let q = "SELECT k, j FROM pj_players WHERE s='bb' AND " + ST, args: any[] = []
        if (w[0]) { q += " AND json_extract(j,'$.pos') LIKE ?"; args.push('%' + w[0] + '%') }
        if (w[1]) { q += " AND json_extract(j,'$.pos') LIKE ?"; args.push('%' + w[1] + '%') }
        if (w[0] !== '投手') q += " AND json_extract(j,'$.pos') NOT LIKE '投手%'"
        const r = await env.DB.prepare(q + ' ORDER BY RANDOM() LIMIT 12').bind(...args).all()
        const x = pickK((r && r.results) || [], seen), k = x ? String(x.k) : null
        if (k) seen[k] = 1
        ids.push(k ? Number(k.slice(1)) : null)
      }
      return { ids, order: [0, 1, 2, 3, 4, 5, 6, 7, 8] }
    }
    const roles: any[] = [['ゴールキーパー'], ['サイドバック'], ['センターバック'], ['センターバック'], ['サイドバック'], ['守備的MF'], ['攻撃的MF'], ['守備的MF'], ['ウイング'], ['センターフォワード'], ['ウイング'], [''], [''], [''], [''], ['']]
    const out: any[] = [], seen: any = {}
    for (const w of roles) {
      let q = "SELECT k, j FROM pj_players WHERE s='sc' AND " + ST, args: any[] = []
      if (w[0]) { q += " AND json_extract(j,'$.pos') = ?"; args.push(w[0]) } else q += " AND json_extract(j,'$.pos') <> 'ゴールキーパー'"
      const r = await env.DB.prepare(q + ' ORDER BY RANDOM() LIMIT 12').bind(...args).all()
      const x = pickK((r && r.results) || [], seen)
      if (x) { seen[x.k] = 1; try { out.push(String(JSON.parse(String(x.j)).mk || '').slice(1) || null) } catch (_e) { out.push(null) } } else out.push(null)
    }
    return { f: '4-3-3', L: out.slice(0, 11), B: out.slice(11).filter(Boolean) }
  }
  async function cpuCoach(env: any, sp: string) { const m = await env.DB.prepare('SELECT j FROM pj_players WHERE s=? ORDER BY RANDOM() LIMIT 1').bind(sp + 'm').first(); try { return m ? String(JSON.parse(String(m.j)).n) : '' } catch (_e) { return '' } }
  function schedule(n: number) {
    // 円の まわし方（6チーム → 5回戦 × 3試合）
    const t = Array.from({ length: n }, (_, i) => i), R: any[] = []
    for (let r = 0; r < n - 1; r++) { const m: any[] = []; for (let i = 0; i < n / 2; i++) m.push(r % 2 ? [t[n - 1 - i], t[i]] : [t[i], t[n - 1 - i]]); R.push(m); t.splice(1, 0, t.pop()) }
    return R
  }
  async function weekDays(c: any, w: any, wk: string) {
    const rest = w.classId ? await d.classRest(c.env, w.classId) : {}
    const out: string[] = []
    for (let i = 0; i < 5; i++) { const dk = d.addDay(wk, i); if (!d.isRest(dk, rest)) out.push(dk) }
    return out
  }
  async function buildLeague(c: any, w: any, cid: string, wk: string, sp: string) {
    const er = await c.env.DB.prepare('SELECT uid FROM pj_lentry WHERE cid=? AND wk=? AND sp=? ORDER BY created_at, uid').bind(cid, wk, sp).all()
    let uids = ((er && er.results) || []).map((x: any) => String(x.uid))
    if (!uids.length) return null
    const seed = seedOf(cid, wk, sp)
    uids = uids.map((u: string, i: number) => ({ u, r: seedOf(seed, u, i) })).sort((a: any, b: any) => a.r - b.r).map((x: any) => x.u)
    const ng = Math.ceil(uids.length / LG_SIZE), groups: any[] = []
    const names = (TN as any)[sp].slice()
    let ni = 0
    for (let g = 0; g < ng; g++) {
      const mem = uids.filter((_: any, i: number) => i % ng === g)
      const teams: any[] = []
      for (const u of mem) { let nm = ''; try { const L0 = await load(c.env, u); nm = tnName(sp, (L0.st.tn || {})[sp]) } catch (_e) {} if (!nm) nm = names[(ni++) % names.length]; let k = 2, base = nm; while (teams.some((t: any) => t.name === nm)) nm = base + '②③④⑤⑥'.charAt(k++ - 2); teams.push({ uid: u, name: nm }) }
      while (teams.length < LG_SIZE) teams.push({ cpu: 1, name: 'CPU ' + names[(ni++) % names.length], roster: await cpuRoster(c.env, sp), coach: await cpuCoach(c.env, sp) })
      groups.push({ teams })
    }
    const days = await weekDays(c, w, wk)
    const sch = schedule(LG_SIZE), matches: any[] = []
    groups.forEach((g: any, gi: number) => sch.forEach((round: any, r: number) => { if (r >= days.length) return; round.forEach((p: any, m: number) => matches.push({ id: 'g' + gi + 'r' + r + 'm' + m, g: gi, r, a: p[0], b: p[1], day: days[r], seed: seedOf(seed, gi, r, m) & 2147483647 })) }))
    return { sp, wk, groups, matches, days, snap: {}, res: {}, t: LG_TIME }
  }
  function played(L: any, m: any, ctx: any, w: any) { if (m.day < ctx.today) return true; if (m.day > ctx.today) return false; return w.test || nowHM() >= L.t }
  // その日の オーダーを こおらせる（子どもの オーダーが たりなければ サーバで おまかせ）
  async function lineupOf(c: any, sp: string, uid: string) {
    const L0 = await load(c.env, uid)
    const st = L0.st, od = cleanOrder(st)[sp] || {}
    const coach = st.cm && st.cm[sp] ? String(st.cm[sp]).slice(3) : ''
    const keys = st.ro.map((r: any) => r.k).filter((k: string) => (k[0] === 'b') === (sp === 'bb'))
    const P = await players(c.env, keys)
    const isP = (k: string) => /^投手/.test((P[k] && P[k].pos) || '')
    const score = (k: string) => { const a = (P[k] && P[k].ab) || {}; let s = 0; Object.keys(a).forEach((x) => { s += Number(a[x]) || 0 }); return s + ((P[k] && P[k].st) || 1) * 30 }
    const used: any = {}
    const best = (f: any) => { const k = keys.filter((x: string) => !used[x] && P[x] && f(x)).sort((a: string, b: string) => score(b) - score(a))[0]; if (k) used[k] = 1; return k || null }
    if (sp === 'bb') {
      const POS = ['C', '1B', '2B', '3B', 'SS', 'LF', 'CF', 'RF', 'DH'], RE: any = { C: /捕手/, '1B': /一塁手/, '2B': /二塁手/, '3B': /三塁手/, SS: /遊撃手/, LF: /外野手/, CF: /外野手/, RF: /外野手/, DH: null }
      const field: any = {}; (od.L || []).forEach((x: any) => { field[x.p] = x.k; used[x.k] = 1 })
      const grp: any = {}; ['SP', 'RP', 'CL', 'BN'].forEach((g) => { grp[g] = (od[g] || []).slice(); grp[g].forEach((k: string) => { used[k] = 1 }) })
      POS.forEach((p) => { if (!field[p]) field[p] = best((k: string) => !isP(k) && (!RE[p] || RE[p].test(P[k].pos))) || best((k: string) => !isP(k)) })
      while (grp.SP.length < 2) { const k = best((x: string) => isP(x) && /先発/.test(P[x].pos)) || best(isP); if (!k) break; grp.SP.push(k) }
      if (!grp.CL.length) { const k = best((x: string) => isP(x) && /抑え/.test(P[x].pos)) || best(isP); if (k) grp.CL.push(k) }
      while (grp.RP.length < 3) { const k = best(isP); if (!k) break; grp.RP.push(k) }
      while (grp.BN.length < 3) { const k = best((x: string) => !isP(x)); if (!k) break; grp.BN.push(k) }
      if (grp.SP.length === 1) grp.SP.push(grp.SP[0])
      const num = (k: any) => k ? Number(String(k).slice(1)) : null
      const ids = POS.map((p) => num(field[p])).concat([0, 1, 2].map((i) => num(grp.BN[i])), [0, 1].map((i) => num(grp.SP[i])), [0, 1, 2].map((i) => num(grp.RP[i])), [num(grp.CL[0])])
      const ord = (od.L || []).length === 9 ? od.L.map((x: any) => POS.indexOf(x.p)) : [0, 1, 2, 3, 4, 5, 6, 7, 8]
      return { ids, order: ord, coach }
    }
    const F: any = { '4-4-2': ['GK', 'D', 'D', 'D', 'D', 'M', 'M', 'M', 'M', 'F', 'F'], '4-3-3': ['GK', 'D', 'D', 'D', 'D', 'M', 'M', 'M', 'F', 'F', 'F'], '4-2-3-1': ['GK', 'D', 'D', 'D', 'D', 'M', 'M', 'F', 'M', 'F', 'F'], '3-5-2': ['GK', 'D', 'D', 'D', 'D', 'M', 'M', 'M', 'D', 'F', 'F'], '3-4-2-1': ['GK', 'D', 'D', 'D', 'D', 'M', 'M', 'D', 'M', 'M', 'F'] }
    const f = F[od.f] ? od.f : '4-3-3', L = (od.L || []).slice(0, 11), B = (od.B || []).slice()
    L.forEach((k: any) => { if (k) used[k] = 1 }); B.forEach((k: any) => { used[k] = 1 })
    const G: any = { GK: /ゴールキーパー/, D: /センターバック|サイドバック/, M: /守備的MF|攻撃的MF/, F: /ウイング|センターフォワード/ }
    F[f].forEach((r: string, i: number) => { if (!L[i]) L[i] = best((k: string) => G[r].test(P[k].pos)) || (r === 'GK' ? null : best((k: string) => !G.GK.test(P[k].pos))) })
    while (B.length < 5) { const k = best(() => true); if (!k) break; B.push(k) }
    const mk = (k: any) => k && P[k] && P[k].mk ? String(P[k].mk).slice(1) : null
    return { f, L: L.map(mk), B: B.map(mk).filter(Boolean), coach }
  }
  async function freeze(c: any, w: any, L: any, ctx: any) {
    let ch = false
    for (const m of L.matches) {
      if (!played(L, m, ctx, w) || L.snap[m.r + ':' + m.g]) continue
      const g = L.groups[m.g], snap: any[] = []
      for (const t of g.teams) snap.push(t.cpu ? Object.assign({}, t.roster, { coach: t.coach }) : await lineupOf(c, L.sp, t.uid))
      L.snap[m.r + ':' + m.g] = snap; ch = true
    }
    return ch
  }
  function standings(L: any, gi: number) {
    const g = L.groups[gi], T = g.teams.map((t: any, i: number) => ({ i, name: t.name, cpu: !!t.cpu, w: 0, l: 0, dr: 0, gf: 0, ga: 0, pt: 0 }))
    L.matches.filter((m: any) => m.g === gi && L.res[m.id]).forEach((m: any) => {
      const [x, y] = L.res[m.id], A = T[m.a], B = T[m.b]
      A.gf += x; A.ga += y; B.gf += y; B.ga += x
      if (x > y) { A.w++; B.l++; A.pt += 3 } else if (x < y) { B.w++; A.l++; B.pt += 3 } else { A.dr++; B.dr++; A.pt++; B.pt++ }
    })
    return T.sort((a: any, b: any) => b.pt - a.pt || (b.gf - b.ga) - (a.gf - a.ga) || b.gf - a.gf || a.i - b.i)
  }
  async function lgCtx(c: any) {
    await ensureLg(c.env)
    const b = await begin(c); if (b.res) return b
    const sp = (c.req.query('s') || '') === 'sc' ? 'sc' : 'bb'
    return Object.assign(b, { sp, cid: lgCid(b.w), wk: mondayOf(b.ctx.today) })
  }
  async function lgView(c: any, b: any, sp: string) {
    const { w, ctx, cid, wk } = b
    let row = await lgLoad(c.env, cid, wk, sp)
    const buildOk = w.test || ctx.today > wk || nowHM() >= LG_BUILD
    if (!row && buildOk) {
      const L = await buildLeague(c, w, cid, wk, sp)
      if (L) { await lgSave(c.env, cid, wk, sp, L, 0); row = await lgLoad(c.env, cid, wk, sp) }
    }
    const nwk = d.addDay(wk, 7)
    const ent = await c.env.DB.prepare('SELECT wk FROM pj_lentry WHERE cid=? AND sp=? AND uid=? AND wk IN (?,?)').bind(cid, sp, String(w.u.id), wk, nwk).all()
    const myE: any = {}; ((ent && ent.results) || []).forEach((x: any) => { myE[x.wk] = 1 })
    const out: any = { ok: true, sp, wk, today: ctx.today, now: nowHM(), time: LG_TIME, entryThis: !!myE[wk], entryNext: !!myE[nwk], canEnterThis: !row && !buildOk, test: !!w.test, league: null }
    if (!row) return out
    const L = row.L
    if (await freeze(c, w, L, ctx)) { if (await lgSave(c.env, cid, wk, sp, L, row.ver)) row.ver++ }
    const gi = L.groups.findIndex((g: any) => g.teams.some((t: any) => t.uid === String(w.u.id)))
    if (gi < 0) { out.league = { joined: false, groups: L.groups.length }; return out }
    const me = L.groups[gi].teams.findIndex((t: any) => t.uid === String(w.u.id))
    const views = ((b.st.lv || {})[wk] || {})
    out.league = {
      joined: true, g: gi, groups: L.groups.length, me, teams: L.groups[gi].teams.map((t: any) => ({ name: t.name, cpu: !!t.cpu })),
      days: L.days, table: standings(L, gi),
      matches: L.matches.filter((m: any) => m.g === gi).map((m: any) => ({ id: m.id, r: m.r, a: m.a, b: m.b, day: m.day, done: played(L, m, ctx, w), res: L.res[m.id] || null, frozen: !!L.snap[m.r + ':' + m.g], views: Number(views[sp + ':' + m.id]) || 0 }))
    }
    return out
  }
  app.get('/api/pj/league', async (c: any) => {
    const b = await lgCtx(c); if (b.res) return b.res
    return c.json(await lgView(c, b, b.sp))
  })
  app.post('/api/pj/league/enter', async (c: any) => {
    await ensureLg(c.env)
    const b = await begin(c); if (b.res) return b.res
    const body = await c.req.json().catch(() => ({}))
    const sp = body && body.sport === 'sc' ? 'sc' : 'bb', cid = lgCid(b.w), wk0 = mondayOf(b.ctx.today)
    const wk = body && body.week === 'this' ? wk0 : d.addDay(wk0, 7)
    if (body && body.week === 'this') { const row = await lgLoad(c.env, cid, wk0, sp); if (row || (!b.w.test && (b.ctx.today > wk0 || nowHM() >= LG_BUILD))) return err(c, 409, 'closed') }
    if (body && body.on === false) await c.env.DB.prepare('DELETE FROM pj_lentry WHERE cid=? AND wk=? AND sp=? AND uid=?').bind(cid, wk, sp, String(b.w.u.id)).run()
    else await c.env.DB.prepare("INSERT OR IGNORE INTO pj_lentry (cid, wk, sp, uid, created_at) VALUES (?,?,?,?,datetime('now'))").bind(cid, wk, sp, String(b.w.u.id)).run()
    return c.json(await lgView(c, Object.assign(b, { cid, wk: wk0 }), sp))
  })
  // 試合の じゅんび（計算 または 観戦）：両チームの こおらせた オーダーと たねを わたす
  async function fixture(c: any, b: any, sp: string, mid: string) {
    const row = await lgLoad(c.env, b.cid, b.wk, sp)
    if (!row) return null
    const L = row.L, m = L.matches.find((x: any) => x.id === mid)
    if (!m || !played(L, m, b.ctx, b.w)) return null
    if (await freeze(c, b.w, L, b.ctx)) await lgSave(c.env, b.cid, b.wk, sp, L, row.ver)
    const snap = L.snap[m.r + ':' + m.g]; if (!snap) return null
    const g = L.groups[m.g]
    return { id: m.id, r: m.r, seed: m.seed, names: [g.teams[m.a].name, g.teams[m.b].name], A: snap[m.a], B: snap[m.b], res: L.res[m.id] || null }
  }
  app.post('/api/pj/league/fixture', async (c: any) => {
    const b = await lgCtx(c); if (b.res) return b.res
    const body = await c.req.json().catch(() => ({}))
    const sp = body && body.sport === 'sc' ? 'sc' : 'bb'
    const fx = await fixture(c, b, sp, String(body && body.mid || ''))
    if (!fx) return err(c, 409, 'not_ready')
    if (body && body.watch) {
      const day = (L0: any) => L0
      const pr = await practiceInfo(c, b.w, b.st, b.ctx)
      const m = (await lgLoad(c.env, b.cid, b.wk, sp)).L.matches.find((x: any) => x.id === fx.id)
      if (!b.w.test) {
        if (m.day !== b.ctx.today) return err(c, 403, 'not_today')
        if (!pr.hw) return err(c, 403, 'practice_hw')
      }
      b.st.lv = b.st.lv || {}; Object.keys(b.st.lv).forEach((k) => { if (k < d.addDay(b.wk, -14)) delete b.st.lv[k] })
      const v = b.st.lv[b.wk] = b.st.lv[b.wk] || {}, key = sp + ':' + fx.id
      if (!b.w.test && (Number(v[key]) || 0) >= 2) return err(c, 403, 'watch_limit')
      v[key] = (Number(v[key]) || 0) + 1
      if (!(await save(c.env, b.w.u.id, b.st, b.ver))) return err(c, 409, 'busy')
      void day
    }
    return c.json(Object.assign({ ok: true }, fx))
  })
  app.post('/api/pj/league/result', async (c: any) => {
    const b = await lgCtx(c); if (b.res) return b.res
    const body = await c.req.json().catch(() => ({}))
    const sp = body && body.sport === 'sc' ? 'sc' : 'bb'
    const sc = body && Array.isArray(body.sc) ? body.sc.map((x: any) => Math.max(0, Math.min(99, Math.floor(Number(x) || 0)))) : null
    if (!sc || sc.length !== 2) return err(c, 400, 'sc')
    for (let i = 0; i < 3; i++) {
      const row = await lgLoad(c.env, b.cid, b.wk, sp); if (!row) return err(c, 404, 'league')
      const L = row.L, m = L.matches.find((x: any) => x.id === String(body.mid || ''))
      if (!m || !played(L, m, b.ctx, b.w) || !L.snap[m.r + ':' + m.g]) return err(c, 409, 'not_ready')
      if (L.res[m.id]) return c.json({ ok: true, res: L.res[m.id] })
      L.res[m.id] = sc
      if (await lgSave(c.env, b.cid, b.wk, sp, L, row.ver)) return c.json({ ok: true, res: sc })
    }
    return err(c, 409, 'busy')
  })
  // 先生の ためし：今週の テストリーグを 作りなおす（先生 ＋ CPU 5）
  app.post('/api/pj/league/test-reset', async (c: any) => {
    const b = await lgCtx(c); if (b.res) return b.res
    if (!b.w.test) return err(c, 403, 'teacher_only')
    const body = await c.req.json().catch(() => ({}))
    const sp = body && body.sport === 'sc' ? 'sc' : 'bb'
    await c.env.DB.prepare('DELETE FROM pj_league WHERE cid=? AND sp=?').bind(b.cid, sp).run()
    await c.env.DB.prepare("INSERT OR IGNORE INTO pj_lentry (cid, wk, sp, uid, created_at) VALUES (?,?,?,?,datetime('now'))").bind(b.cid, b.wk, sp, String(b.w.u.id)).run()
    return c.json(await lgView(c, b, sp))
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
