# -*- coding: utf-8 -*-
# KAHOOT_TICKET_V1_PATCH
# 🎫 カフート券：クラスのみんながそろって初めて発動する協力の商品を、ショップに足す。
#
# 触るのは src/index.tsx だけ。public/index.html は手で編集しない。
# 足すのは
#   1) 配る道（app.get('/kahoot_ticket.js')）1本
#   2) 読み込む replace 1本（チェーン 104 -> 105）
#   3) サーバAPI（/api/shop/kahoot/* と /api/teacher/class/:classId/kahoot*）
#   4) 先生画面のクラスカードに出すパネル
# だけ。新しいテーブルは作らない（CREATE TABLE の数が increase しないことも点検する）。
#
# アンカーが1件でなければ 1 文字も書かずに異常終了する（fail-closed）。
import io
import os
import sys

PATH = 'src/index.tsx'
ASSET = 'public/kahoot_ticket.js'
SENTINEL = 'KAHOOT_TICKET_V1'

#   チェーン件数は「流す直前の実測値」を入れること。
#   9/14 は 103 だったが、9/14 14:49 の e8e96ec4 で 104 に増えた。
#   9/16 10:07 に main を実測して 105（別セッションの __WORLD_V1__ で 1 本増えた）。足すのは 1 本なので 106 になる。
CHAIN_BEFORE = 105
CHAIN_AFTER = 106

# ---- アンカー（すべて現物で 1 件であることを確認済み） -------------------------
ROUTE_ANCHOR = "app.get('/sticker.js', (c) => {"
INJECT_ANCHOR = "t = t.replace('</body>', '<script src=\"/def_join_nudge.js?v=2\"></script></body>')"
API_ANCHOR = "// -------------------- Messages (teacher <-> student) --------------------"
TEACHER_ANCHOR = "          btnGroup.appendChild(stkBtn);"
HEADER_DECL = "const header = document.createElement('div');"


# ---- 1) 配る道 ----------------------------------------------------------------
ROUTE_ADD = r'''// KAHOOT_TICKET_V1 🎫 カフート券のショップUIを配る道。student-karte.js とまったく同じ形。
app.get('/kahoot_ticket.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/kahoot_ticket.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })

'''

# ---- 2) 読み込み（チェーンに 1 本だけ足す） ------------------------------------
#   チェーンは try{...}catch{ 素のHTML } で包まれていて検証が無い。
#   ここで throw するとチェーン全件が黙って捨てられるので、
#   アンカーが無いときは throw せず console.error して skip する。
INJECT_ADD = r'''
      // KAHOOT_TICKET_V1 🎫 カフート券のショップUI。見つからなければ足さずに進む（throw しない）。
      if (t.indexOf('</body>') >= 0) { t = t.replace('</body>', '<script src="/kahoot_ticket.js?v=1"></script></body>') } else console.error('KAHOOT_TICKET_V1: </body> が無いので読み込みを足さずに進む')'''


# ---- 3) サーバAPI --------------------------------------------------------------
SERVER_ADD = r'''// ══════════════════════════════════════════════════════════════════════════
// KAHOOT_TICKET_V1 🎫 カフート券
//   クラスのみんながそろって初めて発動する、協力の商品。
//
// 【どこに置くか】
//   新しいテーブルは作らない。
//     ・リクエストパスで DDL（テーブルを作る文）は打たない。
//     ・migrations は d1_migrations を見るかぎり 0005 までしか適用されていない
//       （0006〜0035 は未適用のまま）ので、migrations/ に足しても本番には作られない。
//   そこで、クラスごとの状態は admin_settings の 1 行に JSON で置く。
//     key   = 'kahoot_v1:<classId>'
//     value = { v, round, enabled, need, openedAt, dueAt, buyers:[{u,p,at}], owed:[], history:[] }
//   同時アクセスは defense_decision_at とまったく同じ CAS で 1 本に絞る。
//     「value が、読んだときのままの行だけ」書き換わる → changes === 1 のときだけ成立。
//
// 【コイン】
//   引くのはサーバだけ。クライアントの数字は一切見ない。
//   引くときは必ず _serverSpentCoins を同じ UPDATE で増やす。
//   これが無いと、児童の端末からの全置換保存で 800 コインが戻ってしまう
//   （progress の保存は _srvSpent > _cliSpent のときだけ差分を引く仕組みのため）。
//
// 【子どもに見せないもの】★いちばん大事★
//   買った人数、まだ買っていない子、名前。
//   /api/shop/kahoot/current が返すのは 0〜5 の段階ゲージだけで、人数は送らない。
//   1 段が数人ぶんなので、だれか 1 人が買ってもふつうはゲージが動かない。
//   「今わたしが買ったら増えた＝さっき買ったのは◯◯くん」というつきとめ方を塞ぐため。
// ══════════════════════════════════════════════════════════════════════════
const KHT_PRICE = 800
const KHT_DAYS = 14
const KHT_DAY_MS = 86400000

function khtKey(classId: string): string { return 'kahoot_v1:' + String(classId) }

function khtFresh(nowMs: number): any {
  return { v: 1, round: 1, enabled: 0, need: null, openedAt: new Date(nowMs).toISOString(), dueAt: new Date(nowMs + KHT_DAYS * KHT_DAY_MS).toISOString(), buyers: [], owed: [], history: [] }
}

function khtNorm(st: any, nowMs: number): any {
  const f = khtFresh(nowMs)
  if (!st || typeof st !== 'object') return f
  st.v = 1
  st.round = Math.max(1, Math.floor(Number(st.round) || 1))
  st.enabled = st.enabled ? 1 : 0
  st.need = (st.need === null || st.need === undefined) ? null : Math.max(1, Math.floor(Number(st.need) || 1))
  if (typeof st.openedAt !== 'string') st.openedAt = f.openedAt
  if (typeof st.dueAt !== 'string') st.dueAt = f.dueAt
  if (!Array.isArray(st.buyers)) st.buyers = []
  if (!Array.isArray(st.owed)) st.owed = []
  if (!Array.isArray(st.history)) st.history = []
  st.buyers = st.buyers.filter((b: any) => b && typeof b.u === 'string' && b.u).slice(0, 200)
  return st
}

async function khtLoad(env: any, classId: string): Promise<any> {
  let raw = ''
  try {
    const row = await env.DB.prepare('SELECT value FROM admin_settings WHERE key = ? LIMIT 1').bind(khtKey(classId)).first<any>()
    if (row && typeof row.value === 'string') raw = row.value
  } catch (_e) { return { raw: '', st: khtFresh(Date.now()) } }
  let st: any = null
  if (raw) { try { st = JSON.parse(raw) } catch (_e) { st = null } }
  return { raw: raw, st: khtNorm(st, Date.now()) }
}

// 「読んだときの value のままの行だけ」書き換える文。batch に入れて使う。
function khtCasStmt(env: any, classId: string, oldRaw: string, st: any): any {
  return env.DB.prepare("INSERT INTO admin_settings (key, value, updated_at) VALUES (?, ?, datetime('now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = datetime('now') WHERE admin_settings.value = ?").bind(khtKey(classId), JSON.stringify(st), String(oldRaw))
}

async function khtCas(env: any, classId: string, oldRaw: string, st: any): Promise<boolean> {
  try {
    const r = await khtCasStmt(env, classId, oldRaw, st).run()
    return !!(r && r.meta && Number(r.meta.changes || 0) === 1)
  } catch (_e) { return false }
}

// コインを動かす文。delta が - なら購入、+ なら返金。
// _serverSpentCoins は必ず反対向きに同じ額だけ動かす。
// 「動かしたあとコインがマイナスにならない」を WHERE で確かめるので、
// 足りない子から引いてしまう事故は起きない。
function khtCoinStmt(env: any, userId: string, delta: number): any {
  const d = Math.trunc(Number(delta) || 0)
  return env.DB.prepare("UPDATE progress SET state_json = json_set(json_set(state_json, '$.coins', COALESCE(CAST(json_extract(state_json, '$.coins') AS INTEGER), 0) + ?), '$._serverSpentCoins', COALESCE(CAST(json_extract(state_json, '$._serverSpentCoins') AS INTEGER), 0) - ?), updated_at = datetime('now') WHERE user_id = ? AND json_valid(state_json) AND COALESCE(CAST(json_extract(state_json, '$.coins') AS INTEGER), 0) + ? >= 0").bind(d, d, String(userId), d)
}

function khtPaid(st: any): number { return ((st && st.buyers) || []).filter((b: any) => b && Number(b.p) === 1).length }

async function khtSize(env: any, classId: string): Promise<number> {
  try {
    const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM class_members WHERE class_id = ?').bind(String(classId)).first<any>()
    return Math.max(0, Math.floor(Number(r && r.n) || 0))
  } catch (_e) { return 0 }
}

// 既定は「クラス全員」。先生が下げたときはその数（ただしクラス人数が上限）。
function khtNeed(st: any, size: number): number {
  const base = size > 0 ? size : 1
  if (!st || st.need === null || st.need === undefined) return base
  const n = Math.floor(Number(st.need) || 0)
  if (!(n > 0)) return base
  return Math.max(1, Math.min(base, n))
}

// 0〜5 の段階。1 段が数人ぶんなので、1 人買っただけではふつう動かない。
function khtGauge(paid: number, need: number): number {
  if (!(need > 0) || paid <= 0) return 0
  if (paid >= need) return 5
  const r = paid / need
  if (r < 0.34) return 1
  if (r < 0.67) return 2
  if (r < 0.9) return 3
  return 4
}

async function khtCoinsOf(env: any, userId: string): Promise<number | null> {
  try {
    const r = await env.DB.prepare("SELECT COALESCE(CAST(json_extract(state_json, '$.coins') AS INTEGER), 0) AS coins FROM progress WHERE user_id = ? LIMIT 1").bind(String(userId)).first<any>()
    if (!r) return null
    return Math.max(0, Math.floor(Number(r.coins) || 0))
  } catch (_e) { return null }
}

async function khtClassOf(env: any, userId: string): Promise<string> {
  try {
    const r = await env.DB.prepare('SELECT class_id FROM class_members WHERE user_id = ? LIMIT 1').bind(String(userId)).first<any>()
    return r && r.class_id ? String(r.class_id) : ''
  } catch (_e) { return '' }
}

async function khtTeacherOwns(c: any, u: any, classId: string): Promise<boolean> {
  if (u && u.role === 'admin') return true
  try {
    const r = await c.env.DB.prepare('SELECT 1 AS x FROM classes WHERE id = ? AND teacher_id = ? LIMIT 1').bind(String(classId), String(u.id)).first<any>()
    return !!r
  } catch (_e) { return false }
}

// 回を終わらせる。refund=true なら買った子ぜんいんに 800 を返す。
// 台帳のリセットと返金は 1 つの batch（＝1 トランザクション）で動かす。
// 返せなかった子は owed に積んで、先生の画面に「まだ返せていない」として出す。
// ここで自動の再挑戦はしない（二重に返すほうが事故として重いため）。
async function khtSettleRound(env: any, classId: string, st: any, raw: string, why: string, refund: boolean): Promise<any> {
  const buyers: any[] = ((st.buyers || []).filter((b: any) => b && Number(b.p) === 1)).map((b: any) => String(b.u))
  const next = JSON.parse(JSON.stringify(st))
  next.history = (next.history || []).slice(-9)
  next.history.push({ round: next.round, at: new Date().toISOString(), why: String(why), paid: buyers.length })
  next.round = Math.max(1, Math.floor(Number(next.round) || 1)) + 1
  next.buyers = []
  next.openedAt = new Date().toISOString()
  next.dueAt = new Date(Date.now() + KHT_DAYS * KHT_DAY_MS).toISOString()
  const stmts: any[] = [khtCasStmt(env, classId, raw, next)]
  if (refund) { for (const uid of buyers) { stmts.push(khtCoinStmt(env, String(uid), KHT_PRICE)) } }
  let rs: any = null
  try { rs = await env.DB.batch(stmts) } catch (_e) { return { ok: false, reason: 'batch_failed' } }
  const casOk = !!(rs && rs[0] && rs[0].meta && Number(rs[0].meta.changes || 0) === 1)
  if (!casOk) return { ok: false, reason: 'race' }
  const failed: any[] = []
  if (refund) {
    for (let i = 0; i < buyers.length; i++) {
      const r = rs[i + 1]
      if (!(r && r.meta && Number(r.meta.changes || 0) === 1)) failed.push(String(buyers[i]))
    }
  }
  if (failed.length) {
    const cur = await khtLoad(env, classId)
    const back = JSON.parse(JSON.stringify(cur.st))
    back.owed = (back.owed || []).concat(failed.map((uid: any) => ({ u: String(uid), amount: KHT_PRICE, at: new Date().toISOString() }))).slice(0, 200)
    await khtCas(env, classId, cur.raw, back)
  }
  return { ok: true, refunded: refund ? (buyers.length - failed.length) : 0, failed: failed.length }
}

// 子ども向け：今の様子。人数は返さない（ゲージだけ）。ここでは書き込みをしない。
app.get('/api/shop/kahoot/current', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = await khtClassOf(c.env, u.id)
  if (!classId) return c.json({ ok: true, enabled: false, price: KHT_PRICE, bought: false, gauge: 0, gaugeMax: 5, reached: false, daysLeft: null, round: 0 })
  const loaded = await khtLoad(c.env, classId)
  const st = loaded.st
  const size = await khtSize(c.env, classId)
  const need = khtNeed(st, size)
  const paid = khtPaid(st)
  const mine = (st.buyers || []).some((b: any) => String(b.u) === String(u.id) && Number(b.p) === 1)
  let daysLeft: number | null = null
  try { const d = Math.ceil((Date.parse(st.dueAt) - Date.now()) / KHT_DAY_MS); daysLeft = isFinite(d) ? Math.max(0, d) : null } catch (_e) { daysLeft = null }
  return c.json({ ok: true, enabled: !!st.enabled, price: KHT_PRICE, bought: mine, gauge: khtGauge(paid, need), gaugeMax: 5, reached: paid >= need, daysLeft: daysLeft, round: st.round })
})

// 子ども向け：買う。
//   ① 期限ぎれならまず精算（返金して回をやり直す）
//   ② コインが足りるか先に読む（ここで弾けば、下の差し戻しはほとんど起きない）
//   ③ 台帳の CAS とコインの引き算を 1 つの batch（＝1 トランザクション）で動かす
//   ④ 枠だけ取れてコインが動かなかったときは、枠を解放して 1 枚も引かずに終わる
app.post('/api/shop/kahoot/buy', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = await khtClassOf(c.env, u.id)
  if (!classId) return jsonError(c, 403, 'no_class')
  const size = await khtSize(c.env, classId)
  for (let attempt = 0; attempt < 4; attempt++) {
    const loaded = await khtLoad(c.env, classId)
    const st = loaded.st
    if (!st.enabled) return jsonError(c, 403, 'kahoot_disabled')
    const need = khtNeed(st, size)
    const due = Date.parse(st.dueAt)
    if (isFinite(due) && Date.now() > due && khtPaid(st) < need) {
      await khtSettleRound(c.env, classId, st, loaded.raw, 'expired', true)
      continue
    }
    if (khtPaid(st) >= need) return jsonError(c, 409, 'already_reached')
    if ((st.buyers || []).some((b: any) => String(b.u) === String(u.id))) return jsonError(c, 409, 'already_bought')
    const have = await khtCoinsOf(c.env, u.id)
    if (have === null) return jsonError(c, 409, 'no_progress')
    if (have < KHT_PRICE) return jsonError(c, 402, 'not_enough_coins')
    const next = JSON.parse(JSON.stringify(st))
    next.buyers.push({ u: String(u.id), p: 1, at: new Date().toISOString() })
    let casOk = false
    let coinOk = false
    try {
      const rs = await c.env.DB.batch([khtCasStmt(c.env, classId, loaded.raw, next), khtCoinStmt(c.env, u.id, -KHT_PRICE)])
      casOk = !!(rs && rs[0] && rs[0].meta && Number(rs[0].meta.changes || 0) === 1)
      coinOk = !!(rs && rs[1] && rs[1].meta && Number(rs[1].meta.changes || 0) === 1)
    } catch (_e) { casOk = false; coinOk = false }
    if (!casOk) continue
    if (!coinOk) {
      const cur = await khtLoad(c.env, classId)
      const back = JSON.parse(JSON.stringify(cur.st))
      back.buyers = (back.buyers || []).filter((b: any) => String(b.u) !== String(u.id))
      await khtCas(c.env, classId, cur.raw, back)
      return jsonError(c, 402, 'not_enough_coins')
    }
    const paid2 = khtPaid(next)
    const coins = await khtCoinsOf(c.env, u.id)
    return c.json({ ok: true, price: KHT_PRICE, coins: coins, bought: true, gauge: khtGauge(paid2, need), gaugeMax: 5, reached: paid2 >= need })
  }
  return jsonError(c, 503, 'busy_retry')
})

// 先生向け：進み具合。ここでは名前を返さない（人数だけ）。
app.get('/api/teacher/class/:classId/kahoot', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  if (!(await khtTeacherOwns(c, u, classId))) return jsonError(c, 404, 'class_not_found')
  let loaded = await khtLoad(c.env, classId)
  const size = await khtSize(c.env, classId)
  const need0 = khtNeed(loaded.st, size)
  const due0 = Date.parse(loaded.st.dueAt)
  if (isFinite(due0) && Date.now() > due0 && khtPaid(loaded.st) < need0) {
    await khtSettleRound(c.env, classId, loaded.st, loaded.raw, 'expired', true)
    loaded = await khtLoad(c.env, classId)
  }
  const st = loaded.st
  const need = khtNeed(st, size)
  const paid = khtPaid(st)
  let short = 0
  try {
    const rows = await c.env.DB.prepare("SELECT cm.user_id AS uid, COALESCE(CAST(json_extract(p.state_json, '$.coins') AS INTEGER), 0) AS coins FROM class_members cm LEFT JOIN progress p ON p.user_id = cm.user_id WHERE cm.class_id = ? LIMIT 200").bind(String(classId)).all<any>()
    const bought: any = {}
    for (const b of (st.buyers || [])) { if (Number(b.p) === 1) bought[String(b.u)] = 1 }
    short = ((rows && rows.results) || []).filter((r: any) => !bought[String(r.uid)] && (Number(r.coins) || 0) < KHT_PRICE).length
  } catch (_e) { short = 0 }
  let daysLeft: number | null = null
  try { const d = Math.ceil((Date.parse(st.dueAt) - Date.now()) / KHT_DAY_MS); daysLeft = isFinite(d) ? d : null } catch (_e) { daysLeft = null }
  return c.json({ ok: true, enabled: !!st.enabled, price: KHT_PRICE, round: st.round, size: size, need: need, needRaw: (st.need === null || st.need === undefined) ? null : st.need, paid: paid, reached: paid >= need, dueAt: st.dueAt, daysLeft: daysLeft, shortOfCoins: short, owed: (st.owed || []).length })
})

// 先生向け：まだ買っていない子の名前。先生が「まだの子をみる」を押したときだけ呼ばれる。
// ★この一覧を、子どもに見える画面に出す導線は作らないこと★
app.get('/api/teacher/class/:classId/kahoot/pending', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  if (!(await khtTeacherOwns(c, u, classId))) return jsonError(c, 404, 'class_not_found')
  const loaded = await khtLoad(c.env, classId)
  const bought: any = {}
  for (const b of (loaded.st.buyers || [])) { if (Number(b.p) === 1) bought[String(b.u)] = 1 }
  let list: any[] = []
  try {
    const rows = await c.env.DB.prepare("SELECT cm.user_id AS uid, us.name AS name, COALESCE(CAST(json_extract(p.state_json, '$.coins') AS INTEGER), 0) AS coins FROM class_members cm JOIN users us ON us.id = cm.user_id LEFT JOIN progress p ON p.user_id = cm.user_id WHERE cm.class_id = ? LIMIT 200").bind(String(classId)).all<any>()
    list = ((rows && rows.results) || [])
      .filter((r: any) => !bought[String(r.uid)])
      .map((r: any) => ({ name: String(r.name || ''), coins: Math.max(0, Math.floor(Number(r.coins) || 0)), canAfford: (Number(r.coins) || 0) >= KHT_PRICE }))
      .sort((a: any, b: any) => a.coins - b.coins)
  } catch (_e) { list = [] }
  return c.json({ ok: true, price: KHT_PRICE, pending: list })
})

// 先生向け：ON/OFF と 必要人数 と 期限のばし。
app.put('/api/teacher/class/:classId/kahoot', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  if (!(await khtTeacherOwns(c, u, classId))) return jsonError(c, 404, 'class_not_found')
  const body = await c.req.json().catch(() => null)
  if (!body) return jsonError(c, 400, 'invalid_json')
  const size = await khtSize(c.env, classId)
  for (let attempt = 0; attempt < 4; attempt++) {
    const loaded = await khtLoad(c.env, classId)
    const next = JSON.parse(JSON.stringify(loaded.st))
    if (typeof body.enabled !== 'undefined') next.enabled = body.enabled ? 1 : 0
    if (typeof body.need !== 'undefined') {
      if (body.need === null || body.need === 'all') next.need = null
      else {
        const n = Math.floor(Number(body.need) || 0)
        if (!(n > 0)) return jsonError(c, 400, 'bad_need')
        next.need = Math.max(1, Math.min(size > 0 ? size : 1, n))
      }
    }
    if (typeof body.days !== 'undefined') {
      const d = Math.floor(Number(body.days) || 0)
      if (d > 0 && d <= 120) next.dueAt = new Date(Date.now() + d * KHT_DAY_MS).toISOString()
    }
    if (await khtCas(c.env, classId, loaded.raw, next)) {
      const need = khtNeed(next, size)
      return c.json({ ok: true, enabled: !!next.enabled, need: need, paid: khtPaid(next), reached: khtPaid(next) >= need, dueAt: next.dueAt })
    }
  }
  return jsonError(c, 503, 'busy_retry')
})

// 先生向け：「やったよ」。券を使い切って、回を 1 つ進める（また売れるようになる）。
// 発動したのでコインは動かさない。
app.post('/api/teacher/class/:classId/kahoot/done', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  if (!(await khtTeacherOwns(c, u, classId))) return jsonError(c, 404, 'class_not_found')
  for (let attempt = 0; attempt < 4; attempt++) {
    const loaded = await khtLoad(c.env, classId)
    const r = await khtSettleRound(c.env, classId, loaded.st, loaded.raw, 'done', false)
    if (r.ok) return c.json({ ok: true })
    if (r.reason !== 'race') return jsonError(c, 500, String(r.reason || 'failed'))
  }
  return jsonError(c, 503, 'busy_retry')
})

// 先生向け：「みんなに返す」。今の回の買った子ぜんいんに 800 を返して、回をやり直す。
app.post('/api/teacher/class/:classId/kahoot/refund', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  if (!(await khtTeacherOwns(c, u, classId))) return jsonError(c, 404, 'class_not_found')
  for (let attempt = 0; attempt < 4; attempt++) {
    const loaded = await khtLoad(c.env, classId)
    const r = await khtSettleRound(c.env, classId, loaded.st, loaded.raw, 'refund', true)
    if (r.ok) return c.json({ ok: true, refunded: r.refunded, failed: r.failed })
    if (r.reason !== 'race') return jsonError(c, 500, String(r.reason || 'failed'))
  }
  return jsonError(c, 503, 'busy_retry')
})


'''


# ---- 4) 先生画面のパネル -------------------------------------------------------
#   ここは c.html(`...`) の中＝テンプレートリテラルの中なので、
#   ・バッククォートと ${ は 1 文字も書かない
#   ・改行を入れたい所は \\n と二重に書く（既存の anonymizeCloudNames と同じ作法）
TEACHER_ADD = r'''

          // ══════ KAHOOT_TICKET_V1 🎫 カフート券 ══════
          //   ここに出すのは「人数」まで。
          //   まだ買っていない子の名前は、下の「まだの子をみる」を押したときだけ取りに行く。
          //   ★この一覧は、子どもに見える画面には絶対に出さないこと★
          const khtBox = document.createElement('div');
          khtBox.className = 'mt-3 pt-3 border-t border-slate-200';
          khtBox.innerHTML = '<div class="text-xs font-bold text-slate-600 mb-2">🎫 カフート券</div>'
            + '<div class="kht-banner"></div>'
            + '<div class="kht-body text-xs text-slate-500">よみこみ中…</div>'
            + '<div class="kht-ctrl flex flex-wrap gap-1 items-center mt-2"></div>'
            + '<div class="kht-pending text-xs mt-2"></div>';
          header.appendChild(khtBox);

          const khtBanner = khtBox.querySelector('.kht-banner');
          const khtBody = khtBox.querySelector('.kht-body');
          const khtCtrl = khtBox.querySelector('.kht-ctrl');
          const khtPend = khtBox.querySelector('.kht-pending');
          let khtState = null;

          const khtBtn = function(label, cls){
            const b = document.createElement('button');
            b.className = 'text-xs px-2 py-1 rounded font-bold border ' + cls;
            b.textContent = label;
            return b;
          };

          const khtRender = function(){
            const d = khtState;
            if(!d){ khtBody.textContent = 'よみこめませんでした'; return; }
            // 先生への知らせ：そろったらここに大きく出る
            if(d.reached){
              khtBanner.innerHTML = '<div style="background:#dcfce7;border:2px solid #16a34a;color:#166534;'
                + 'border-radius:10px;padding:8px 10px;font-weight:800;font-size:13px;margin-bottom:6px">'
                + '🎉 カフート券が そろいました（' + d.paid + ' / ' + d.need + '人）。今日か明日、カフートをやってください。</div>';
            } else {
              khtBanner.innerHTML = '';
            }
            let s = d.enabled ? 'ショップに出ています' : 'ショップに出ていません';
            s += '｜' + d.paid + ' / ' + d.need + ' 人';
            s += (d.needRaw === null) ? '（クラス全員）' : '（先生が ' + d.need + ' 人に下げています）';
            s += '｜1枚 ' + d.price + 'コイン';
            if(typeof d.daysLeft === 'number'){ s += '｜のこり ' + d.daysLeft + '日で自動返金'; }
            khtBody.textContent = s;

            khtPend.innerHTML = '';
            if(d.shortOfCoins > 0 && !d.reached){
              const w = document.createElement('div');
              w.className = 'text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-1 mt-1';
              w.textContent = '⚠ ' + d.price + 'コインに とどいていない子が ' + d.shortOfCoins + '人 います。必要人数を下げると、その子たちを待たずに発動できます。';
              khtPend.appendChild(w);
            }
            if(d.owed > 0){
              const w2 = document.createElement('div');
              w2.className = 'text-xs text-red-700 bg-red-50 border border-red-200 rounded px-2 py-1 mt-1';
              w2.textContent = '⚠ まだ返せていないコインが ' + d.owed + '件 あります。';
              khtPend.appendChild(w2);
            }

            khtCtrl.innerHTML = '';

            const onBtn = khtBtn(d.enabled ? '🎫 カフート券ON' : '🎫 カフート券OFF',
              d.enabled ? 'bg-purple-100 text-purple-700 border-purple-300 hover:bg-purple-200'
                        : 'bg-slate-100 text-slate-500 border-slate-300 hover:bg-slate-200');
            onBtn.title = d.enabled ? 'クリックでこのクラスのショップから隠す' : 'クリックでこのクラスのショップに出す';
            onBtn.onclick = async () => {
              try{ await api('/api/teacher/class/' + cls.id + '/kahoot', { method:'PUT', headers:{'content-type':'application/json'}, body: JSON.stringify({ enabled: !d.enabled }) }); await khtLoadState(); }
              catch(e){ alert(String(e.message||e)); }
            };
            khtCtrl.appendChild(onBtn);

            const sel = document.createElement('select');
            sel.className = 'text-xs px-2 py-1 rounded font-bold border bg-white border-slate-300';
            const optAll = document.createElement('option');
            optAll.value = 'all'; optAll.textContent = '必要人数: クラス全員';
            sel.appendChild(optAll);
            for(let i = d.size; i >= 1; i--){
              const o = document.createElement('option');
              o.value = String(i); o.textContent = '必要人数: ' + i + '人';
              sel.appendChild(o);
            }
            sel.value = (d.needRaw === null) ? 'all' : String(d.needRaw);
            sel.title = 'どうしても そろわないときに下げてください。下げたことは子どもの画面には出ません。';
            sel.onchange = async () => {
              try{ await api('/api/teacher/class/' + cls.id + '/kahoot', { method:'PUT', headers:{'content-type':'application/json'}, body: JSON.stringify({ need: sel.value === 'all' ? null : Number(sel.value) }) }); await khtLoadState(); }
              catch(e){ alert(String(e.message||e)); }
            };
            khtCtrl.appendChild(sel);

            const doneBtn = khtBtn('✅ カフートをやった（リセット）',
              d.reached ? 'bg-green-100 text-green-700 border-green-300 hover:bg-green-200'
                        : 'bg-slate-100 text-slate-400 border-slate-200');
            doneBtn.disabled = !d.reached;
            doneBtn.title = 'カフートをやったら押してください。券は使い切りになり、また売り出せます。';
            doneBtn.onclick = async () => {
              if(!confirm('カフートを やりましたか？\\n押すと券は使い切りになり、また売り出せるようになります。\\n（コインは返しません）')) return;
              try{ await api('/api/teacher/class/' + cls.id + '/kahoot/done', { method:'POST' }); await khtLoadState(); }
              catch(e){ alert(String(e.message||e)); }
            };
            khtCtrl.appendChild(doneBtn);

            const refBtn = khtBtn('↩ みんなにコインを返す', 'bg-orange-50 text-orange-700 border-orange-300 hover:bg-orange-100');
            refBtn.title = 'そろわないまま終わりにするとき。買った子ぜんいんに ' + d.price + 'コインを返して、はじめからにします。';
            refBtn.onclick = async () => {
              if(!confirm('買った子 ' + d.paid + '人 ぜんいんに ' + d.price + 'コインを返して、はじめからにします。よろしいですか？')) return;
              try{ const r = await api('/api/teacher/class/' + cls.id + '/kahoot/refund', { method:'POST' }); alert(r.refunded + '人に返しました。'); await khtLoadState(); }
              catch(e){ alert(String(e.message||e)); }
            };
            khtCtrl.appendChild(refBtn);

            const pendBtn = khtBtn('▶ まだの子をみる（子どもに見せないでください）', 'bg-white text-slate-600 border-slate-300 hover:bg-slate-50');
            pendBtn.onclick = async () => {
              try{
                const r = await api('/api/teacher/class/' + cls.id + '/kahoot/pending');
                const box = document.createElement('div');
                box.className = 'text-xs text-slate-700 bg-slate-50 border border-slate-200 rounded px-2 py-1 mt-1';
                if(!r.pending.length){ box.textContent = 'まだの子は いません。'; }
                else {
                  box.innerHTML = '<div class="font-bold mb-1">まだ買っていない子（' + r.pending.length + '人）</div>'
                    + r.pending.map(function(x){
                        return '<div>' + (x.canAfford ? '・' : '⚠ ') + x.name + '（' + x.coins + 'コイン' + (x.canAfford ? '' : ' ／ たりない') + '）</div>';
                      }).join('');
                }
                pendBtn.remove();
                khtPend.appendChild(box);
              } catch(e){ alert(String(e.message||e)); }
            };
            khtCtrl.appendChild(pendBtn);
          };

          const khtLoadState = async function(){
            try{ khtState = await api('/api/teacher/class/' + cls.id + '/kahoot'); }
            catch(e){ khtState = null; }
            khtRender();
          };
          khtLoadState();
'''


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def main():
    if not os.path.exists(ASSET):
        print('NG: ' + ASSET + ' が無い。先に置いてから流すこと')
        return 1

    s = io.open(PATH, encoding='utf-8').read()

    if SENTINEL in s:
        print('already applied: ' + SENTINEL + ' / 何もしない')
        return 0

    before = chain_count(s)
    if before != CHAIN_BEFORE:
        print('NG: チェーンが %d 件（期待 %d）' % (before, CHAIN_BEFORE))
        return 1

    for label, text in (
        ('配る道のアンカー', ROUTE_ANCHOR),
        ('読み込みのアンカー', INJECT_ANCHOR),
        ('APIのアンカー', API_ANCHOR),
        ('先生画面のアンカー', TEACHER_ANCHOR),
        ('先生画面の header', HEADER_DECL),
    ):
        n = s.count(text)
        if n != 1:
            print('NG: %s が %d 件（期待 1）' % (label, n))
            return 1

    if s.index(HEADER_DECL) > s.index(TEACHER_ANCHOR):
        print('NG: header の宣言よりも前に足そうとしている')
        return 1

    for label in ("app.get('/kahoot_ticket.js'", '/api/shop/kahoot/', 'kahoot_v1:', 'khtCasStmt', 'KHT_PRICE'):
        if label in s:
            print('NG: ' + label + ' がもうある')
            return 1

    # 先生画面はテンプレートリテラルの中。バッククォート・${・単独の \ を入れたら壊れる。
    if '`' in TEACHER_ADD or '${' in TEACHER_ADD:
        print('NG: 先生画面の追加にバッククォートか ${ が入っている')
        return 1
    if TEACHER_ADD.replace('\\\\', '').count('\\') != 0:
        print('NG: 先生画面の追加に 二重になっていない \\ が入っている')
        return 1

    t = s.replace(ROUTE_ANCHOR, ROUTE_ADD + ROUTE_ANCHOR)
    t = t.replace(INJECT_ANCHOR, INJECT_ANCHOR + INJECT_ADD)
    t = t.replace(API_ANCHOR, SERVER_ADD + API_ANCHOR)
    t = t.replace(TEACHER_ANCHOR, TEACHER_ANCHOR + TEACHER_ADD)

    ok = True
    after = chain_count(t)
    if after != CHAIN_AFTER:
        print('NG: チェーンが %d 件（期待 %d）' % (after, CHAIN_AFTER))
        ok = False

    def chk(label, got, want):
        if got != want:
            print('NG: %s が %d 件（期待 %d）' % (label, got, want))
            return False
        return True

    # 新しく足したもの
    for label, want in (
        ("app.get('/kahoot_ticket.js'", 1),
        ('/kahoot_ticket.js?v=1', 1),
        ("app.get('/api/shop/kahoot/current'", 1),
        ("app.post('/api/shop/kahoot/buy'", 1),
        ("app.get('/api/teacher/class/:classId/kahoot'", 1),
        ("app.get('/api/teacher/class/:classId/kahoot/pending'", 1),
        ("app.put('/api/teacher/class/:classId/kahoot'", 1),
        ("app.post('/api/teacher/class/:classId/kahoot/done'", 1),
        ("app.post('/api/teacher/class/:classId/kahoot/refund'", 1),
        ('header.appendChild(khtBox);', 1),
    ):
        ok = chk(label, t.count(label), want) and ok

    # 壊してはいけない既存のもの（数が動いていないこと）
    for label in (
        "app.get('/sticker.js'",
        "app.post('/api/shop/sticker/buy'",
        "app.get('/def_join_nudge.js'",
        '/def_join_nudge.js?v=2',
        'DEF_JOIN_NUDGE_V1_WIRED',
        "app.get('/', async (c) => {",
        "app.get('/logout'",
        API_ANCHOR,
        TEACHER_ANCHOR,
        HEADER_DECL,
        'defStageMakeLedger',
        'applyDefStageGrants',
    ):
        ok = chk('（既存）' + label, t.count(label), s.count(label)) and ok

    # DDL を 1 つも増やしていないこと
    ok = chk('CREATE TABLE', t.count('CREATE TABLE'), s.count('CREATE TABLE')) and ok
    ok = chk('ALTER TABLE', t.count('ALTER TABLE'), s.count('ALTER TABLE')) and ok

    # _serverSpentCoins は「既存 + 今回足したぶん」ちょうど
    ok = chk('_serverSpentCoins', t.count('_serverSpentCoins'),
             s.count('_serverSpentCoins') + SERVER_ADD.count('_serverSpentCoins')) and ok

    if t == s:
        print('NG: 中身が変わっていない')
        ok = False

    if not ok:
        print('NG: 自己点検に落ちたので書き込まない')
        return 1

    io.open(PATH, 'w', encoding='utf-8').write(t)
    print('OK: ' + PATH + ' を更新した（チェーン %d -> %d）' % (before, after))
    return 0


if __name__ == '__main__':
    sys.exit(main())
