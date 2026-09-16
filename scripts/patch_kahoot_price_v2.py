# -*- coding: utf-8 -*-
# KAHOOT_PRICE_V2
# 🎫 カフート券の値段を3段階にして、「クラス全員」の数え方を直す。
#
# 変えるところ
#   1) 値段：3登校日れんぞく 500 ／ 提出はあるが連続3日未満 1500 ／ 直近5登校日に提出なし 3000
#      判定は「買うとき」に、サーバでその場で計算する。
#      連続の数え方は public/index.html の hsCalcRequiredStreak と同じ
#      （土日祝はとばす／平日を抜かしたら切れる／休みの日の提出は数えない）。
#      homework_submissions.streak_after は使わない。あれは端末が提出時に計算した
#      スナップショットで、実測すると 14人中4人がズレていた
#      （金→月→火と3日つづけた子の保存値が 1 になっていた）。
#   2) 「クラス全員」を users.role='student' AND is_active=1 の子だけにする。
#      class_members には admin が1行まざっており、素で数えると必要人数に届かず
#      「永久にそろわない券」になっていた。
#   3) 買った値段を台帳に記録する。返金はその子が払った額をそのまま返す。
#   4) 子どもの画面：安くなった子には理由を出す。高い子には理由を書かない。
#      ただし「あと◯日つづけると500コインになるよ」は全員に出す（行き止まりにしない）。
#
# チェーンは1本も増減しない（配信の replace には触らない）。
# アンカーは v1 のパッチスクリプトを import して、その場の文字列そのものを使う。
# 1件でなければ 1 文字も書かずに異常終了する（fail-closed）。
import importlib.util
import io
import os
import sys

PATH = 'src/index.tsx'
ASSET = 'public/kahoot_ticket.js'
V1 = 'scripts/patch_kahoot_ticket_v1.py'
SENTINEL = 'KAHOOT_PRICE_V2'


def load_v1():
    spec = importlib.util.spec_from_file_location('kht_v1', V1)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


# ══════════════════════════════════════════════════════════════════════════
# 新しいサーバ側のかたまり（v1 の SERVER_ADD を丸ごと置きかえる）
# ══════════════════════════════════════════════════════════════════════════
NEW_SERVER = r'''// ══════════════════════════════════════════════════════════════════════════
// KAHOOT_TICKET_V1 / KAHOOT_PRICE_V2 🎫 カフート券
//   クラスのみんながそろって初めて発動する、協力の商品。
//
// 【どこに置くか】
//   新しいテーブルは作らない。
//     ・リクエストパスで DDL（テーブルを作る文）は打たない。
//     ・migrations は d1_migrations を見るかぎり 0005 までしか適用されていない
//       （0006〜0035 は未適用のまま）ので、migrations/ に足しても本番には作られない。
//   クラスごとの状態は admin_settings の 1 行（key = 'kahoot_v1:<classId>'）に JSON で置く。
//   同時アクセスは defense_decision_at とまったく同じ CAS で 1 本に絞る。
//
// 【値段】買うときにサーバで決める。クライアントの申告は一切見ない。
//     ・家庭学習が 3 登校日いじょう れんぞく  →  500
//     ・提出はあるが れんぞく 3 日みまん      → 1500
//     ・直近 5 登校日に 1 回も提出がない      → 3000
//   れんぞくの数え方は public/index.html の hsCalcRequiredStreak と同じにする。
//   （土日祝はとばす／平日を抜かしたら切れる／休みの日の提出は数えない）
//   homework_submissions.streak_after は使わない。あれは端末が提出時に計算した
//   スナップショットで、6年2組の実測では 14 人中 4 人がズレていた。
//   金→月→火と 3 日つづけた子の保存値が 1 になっていた（＝安くならない事故）。
//
// 【クラス全員】class_members には admin などが混ざっている。
//   users.role='student' AND is_active=1 の子だけを数える。
//   素で数えると、買えない行のぶんだけ必要人数に届かず
//   「22人ぜんいん買ったのにゲージが最後の1段だけ埋まらない」= 永久にそろわない券になる。
//
// 【子どもに見せないもの】★いちばん大事★
//   買った人数、まだ買っていない子、名前。返すのは 0〜5 の段階ゲージだけ。
//   値段の理由は「安くなった子」にだけ出す。高い子に理由は書かない。
//   ただし「あと◯日で500」はぜんいんに出す（行き止まりにしないため）。
// ══════════════════════════════════════════════════════════════════════════
const KHT_PRICE_STREAK = 500
const KHT_PRICE_MID = 1500
const KHT_PRICE_NONE = 3000
const KHT_STREAK_NEED = 3
const KHT_RECENT_DAYS = 5
const KHT_DAYS = 14
const KHT_DAY_MS = 86400000

// 2026年の祝日。public/index.html の hsDefaultHolidays2026 と同じ並び。
// 外部APIは使わない（黙って止まるので）。学校独自の休みは先生が足せる（既定は空）。
const KHT_HOLIDAYS = ['2026-01-01','2026-01-12','2026-02-11','2026-02-23','2026-03-20','2026-04-29','2026-05-03','2026-05-04','2026-05-05','2026-05-06','2026-07-20','2026-08-11','2026-09-21','2026-09-22','2026-09-23','2026-10-12','2026-11-03','2026-11-23']

function khtKey(classId: string): string { return 'kahoot_v1:' + String(classId) }

function khtFresh(nowMs: number): any {
  return { v: 2, round: 1, enabled: 0, need: null, openedAt: new Date(nowMs).toISOString(), dueAt: new Date(nowMs + KHT_DAYS * KHT_DAY_MS).toISOString(), buyers: [], owed: [], history: [], extraHolidays: [] }
}

function khtNorm(st: any, nowMs: number): any {
  const f = khtFresh(nowMs)
  if (!st || typeof st !== 'object') return f
  st.v = 2
  st.round = Math.max(1, Math.floor(Number(st.round) || 1))
  st.enabled = st.enabled ? 1 : 0
  st.need = (st.need === null || st.need === undefined) ? null : Math.max(1, Math.floor(Number(st.need) || 1))
  if (typeof st.openedAt !== 'string') st.openedAt = f.openedAt
  if (typeof st.dueAt !== 'string') st.dueAt = f.dueAt
  if (!Array.isArray(st.buyers)) st.buyers = []
  if (!Array.isArray(st.owed)) st.owed = []
  if (!Array.isArray(st.history)) st.history = []
  if (!Array.isArray(st.extraHolidays)) st.extraHolidays = []
  st.buyers = st.buyers.filter((b: any) => b && typeof b.u === 'string' && b.u).slice(0, 200)
  st.extraHolidays = st.extraHolidays.filter((d: any) => typeof d === 'string' && /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(d)).slice(0, 200)
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
// これが無いと、児童の端末からの全置換保存でコインが戻ってしまう。
// 「動かしたあとコインがマイナスにならない」を WHERE で確かめる。
function khtCoinStmt(env: any, userId: string, delta: number): any {
  const d = Math.trunc(Number(delta) || 0)
  return env.DB.prepare("UPDATE progress SET state_json = json_set(json_set(state_json, '$.coins', COALESCE(CAST(json_extract(state_json, '$.coins') AS INTEGER), 0) + ?), '$._serverSpentCoins', COALESCE(CAST(json_extract(state_json, '$._serverSpentCoins') AS INTEGER), 0) - ?), updated_at = datetime('now') WHERE user_id = ? AND json_valid(state_json) AND COALESCE(CAST(json_extract(state_json, '$.coins') AS INTEGER), 0) + ? >= 0").bind(d, d, String(userId), d)
}

function khtPaid(st: any): number { return ((st && st.buyers) || []).filter((b: any) => b && Number(b.p) === 1).length }

// ★クラス全員＝在籍している児童だけ。admin や先生の行は数えない。
async function khtSize(env: any, classId: string): Promise<number> {
  try {
    const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM class_members cm JOIN users u ON u.id = cm.user_id WHERE cm.class_id = ? AND u.role = 'student' AND u.is_active = 1").bind(String(classId)).first<any>()
    return Math.max(0, Math.floor(Number(r && r.n) || 0))
  } catch (_e) { return 0 }
}

function khtNeed(st: any, size: number): number {
  const base = size > 0 ? size : 1
  if (!st || st.need === null || st.need === undefined) return base
  const n = Math.floor(Number(st.need) || 0)
  if (!(n > 0)) return base
  return Math.max(1, Math.min(base, n))
}

function khtGauge(paid: number, need: number): number {
  if (!(need > 0) || paid <= 0) return 0
  if (paid >= need) return 5
  const r = paid / need
  if (r < 0.34) return 1
  if (r < 0.67) return 2
  if (r < 0.9) return 3
  return 4
}

// ── 日付のみち（サーバの時間帯に左右されないよう UTC で組み立てる）──
function khtParseDay(k: string): number {
  const p = String(k).split('-')
  return Date.UTC(Number(p[0]), Number(p[1]) - 1, Number(p[2]))
}
function khtFmtDay(ms: number): string { return new Date(ms).toISOString().slice(0, 10) }
function khtAddDay(k: string, n: number): string { return khtFmtDay(khtParseDay(k) + n * KHT_DAY_MS) }
// 8時半リセットの「今日キー」。クライアントの hsGetDayKey830（ローカル時刻 −8時間30分）と同じ日になる。
// 日本時間は UTC+9 なので、UTC に 30 分足した日の日付を取ればよい。
function khtTodayKey(nowMs: number): string { return khtFmtDay(nowMs + 30 * 60 * 1000) }

function khtExtraMap(st: any): any {
  const m: any = {}
  const list = (st && Array.isArray(st.extraHolidays)) ? st.extraHolidays : []
  for (const d of list) { if (typeof d === 'string' && d) m[d] = 1 }
  return m
}

// 休みの日＝土日・祝日・先生が足した学校独自の休み。
function khtIsRest(k: string, extra: any): boolean {
  const w = new Date(khtParseDay(k)).getUTCDay()
  if (w === 0 || w === 6) return true
  if (KHT_HOLIDAYS.indexOf(k) >= 0) return true
  return !!(extra && extra[k])
}

async function khtDays(env: any, userId: string, fromKey: string, toKey: string): Promise<any> {
  const m: any = {}
  try {
    const rows = await env.DB.prepare('SELECT DISTINCT day_key FROM homework_submissions WHERE user_id = ? AND day_key >= ? AND day_key <= ? LIMIT 400').bind(String(userId), fromKey, toKey).all<any>()
    for (const r of ((rows && rows.results) || [])) { if (r && r.day_key) m[String(r.day_key)] = 1 }
  } catch (_e) { return {} }
  return m
}

// public/index.html の hsCalcRequiredStreak と同じ数え方。
function khtStreak(days: any, todayKey: string, extra: any): number {
  let k = todayKey
  let s = 0
  for (let i = 0; i < 400; i++) {
    if (khtIsRest(k, extra)) { k = khtAddDay(k, -1); continue }
    if (days[k]) { s++; k = khtAddDay(k, -1); continue }
    break
  }
  return s
}

// 直近 n 登校日（今日をふくむ）に 1 回でも提出があるか。
function khtRecent(days: any, todayKey: string, extra: any, n: number): boolean {
  let k = todayKey
  let seen = 0
  for (let i = 0; i < 400 && seen < n; i++) {
    if (!khtIsRest(k, extra)) { seen++; if (days[k]) return true }
    k = khtAddDay(k, -1)
  }
  return false
}

function khtPriceOf(streak: number, recent: boolean): number {
  if (streak >= KHT_STREAK_NEED) return KHT_PRICE_STREAK
  if (recent) return KHT_PRICE_MID
  return KHT_PRICE_NONE
}

// その子の「いまの値段」と「500まであと何日」。
async function khtQuote(env: any, userId: string, st: any): Promise<any> {
  const todayKey = khtTodayKey(Date.now())
  const days = await khtDays(env, userId, khtAddDay(todayKey, -70), todayKey)
  const extra = khtExtraMap(st)
  const streak = khtStreak(days, todayKey, extra)
  const recent = khtRecent(days, todayKey, extra, KHT_RECENT_DAYS)
  const price = khtPriceOf(streak, recent)
  return { price: price, streak: streak, toGo: Math.max(0, KHT_STREAK_NEED - streak), cheap: price === KHT_PRICE_STREAK }
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

// 回を終わらせる。refund=true なら買った子それぞれに「その子が払った額」を返す。
// 台帳のリセットと返金は 1 つの batch（＝1 トランザクション）で動かす。
// 返せなかった子は owed に積む。自動の再挑戦はしない（二重に返すほうが事故として重い）。
async function khtSettleRound(env: any, classId: string, st: any, raw: string, why: string, refund: boolean): Promise<any> {
  const buyers: any[] = ((st.buyers || []).filter((b: any) => b && Number(b.p) === 1))
    .map((b: any) => ({ u: String(b.u), c: Math.max(0, Math.floor(Number(b.c) || KHT_PRICE_MID)) }))
  const next = JSON.parse(JSON.stringify(st))
  next.history = (next.history || []).slice(-9)
  next.history.push({ round: next.round, at: new Date().toISOString(), why: String(why), paid: buyers.length })
  next.round = Math.max(1, Math.floor(Number(next.round) || 1)) + 1
  next.buyers = []
  next.openedAt = new Date().toISOString()
  next.dueAt = new Date(Date.now() + KHT_DAYS * KHT_DAY_MS).toISOString()
  const stmts: any[] = [khtCasStmt(env, classId, raw, next)]
  if (refund) { for (const b of buyers) { stmts.push(khtCoinStmt(env, b.u, b.c)) } }
  let rs: any = null
  try { rs = await env.DB.batch(stmts) } catch (_e) { return { ok: false, reason: 'batch_failed' } }
  const casOk = !!(rs && rs[0] && rs[0].meta && Number(rs[0].meta.changes || 0) === 1)
  if (!casOk) return { ok: false, reason: 'race' }
  const failed: any[] = []
  if (refund) {
    for (let i = 0; i < buyers.length; i++) {
      const r = rs[i + 1]
      if (!(r && r.meta && Number(r.meta.changes || 0) === 1)) failed.push(buyers[i])
    }
  }
  if (failed.length) {
    const cur = await khtLoad(env, classId)
    const back = JSON.parse(JSON.stringify(cur.st))
    back.owed = (back.owed || []).concat(failed.map((b: any) => ({ u: String(b.u), amount: b.c, at: new Date().toISOString() }))).slice(0, 200)
    await khtCas(env, classId, cur.raw, back)
  }
  return { ok: true, refunded: refund ? (buyers.length - failed.length) : 0, failed: failed.length }
}

// 子ども向け：今の様子。人数は返さない（ゲージだけ）。ここでは書き込みをしない。
app.get('/api/shop/kahoot/current', async (c) => {
  const u = requireStudent(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = await khtClassOf(c.env, u.id)
  if (!classId) return c.json({ ok: true, enabled: false, price: KHT_PRICE_NONE, cheapPrice: KHT_PRICE_STREAK, streak: 0, toGo: KHT_STREAK_NEED, cheap: false, bought: false, gauge: 0, gaugeMax: 5, reached: false, daysLeft: null, round: 0 })
  const loaded = await khtLoad(c.env, classId)
  const st = loaded.st
  const size = await khtSize(c.env, classId)
  const q = await khtQuote(c.env, u.id, st)
  const mine = (st.buyers || []).some((b: any) => String(b.u) === String(u.id) && Number(b.p) === 1)
  let daysLeft: number | null = null
  try { const dd = Math.ceil((Date.parse(st.dueAt) - Date.now()) / KHT_DAY_MS); daysLeft = isFinite(dd) ? Math.max(0, dd) : null } catch (_e) { daysLeft = null }
  const nd = khtNeed(st, size)
  const pd = khtPaid(st)
  return c.json({ ok: true, enabled: !!st.enabled, price: q.price, cheapPrice: KHT_PRICE_STREAK, streak: q.streak, toGo: q.toGo, cheap: q.cheap, bought: mine, gauge: khtGauge(pd, nd), gaugeMax: 5, reached: pd >= nd, daysLeft: daysLeft, round: st.round })
})

// 子ども向け：買う。値段はここでサーバが決める。
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
    const q = await khtQuote(c.env, u.id, st)
    const price = q.price
    const p0 = await c.env.DB.prepare("SELECT COALESCE(CAST(json_extract(state_json, '$.coins') AS INTEGER), 0) AS coins FROM progress WHERE user_id = ? LIMIT 1").bind(String(u.id)).first<any>()
    if (!p0) return jsonError(c, 409, 'no_progress')
    if ((Number(p0.coins) || 0) < price) return jsonError(c, 402, 'not_enough_coins')
    const next = JSON.parse(JSON.stringify(st))
    next.buyers.push({ u: String(u.id), p: 1, at: new Date().toISOString(), c: price })
    let casOk = false
    let coinOk = false
    try {
      const rs = await c.env.DB.batch([khtCasStmt(c.env, classId, loaded.raw, next), khtCoinStmt(c.env, u.id, -price)])
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
    const p1 = await c.env.DB.prepare("SELECT COALESCE(CAST(json_extract(state_json, '$.coins') AS INTEGER), 0) AS coins FROM progress WHERE user_id = ? LIMIT 1").bind(String(u.id)).first<any>()
    return c.json({ ok: true, price: price, cheap: q.cheap, streak: q.streak, coins: p1 ? Number(p1.coins) : null, bought: true, gauge: khtGauge(paid2, need), gaugeMax: 5, reached: paid2 >= need })
  }
  return jsonError(c, 503, 'busy_retry')
})

// 先生向け：進み具合。人数だけ。名前はここでは返さない。
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
  const extra = khtExtraMap(st)
  const todayKey = khtTodayKey(Date.now())
  const fromKey = khtAddDay(todayKey, -70)
  // 値段ごとの人数と、自分の値段を払えない子の人数。名前は出さない。
  let t500 = 0, t1500 = 0, t3000 = 0, cannot = 0
  try {
    const mem = await c.env.DB.prepare("SELECT cm.user_id AS uid, COALESCE(CAST(json_extract(p.state_json, '$.coins') AS INTEGER), 0) AS coins FROM class_members cm JOIN users u2 ON u2.id = cm.user_id LEFT JOIN progress p ON p.user_id = cm.user_id WHERE cm.class_id = ? AND u2.role = 'student' AND u2.is_active = 1 LIMIT 200").bind(String(classId)).all<any>()
    const subs = await c.env.DB.prepare('SELECT h.user_id AS uid, h.day_key AS dk FROM homework_submissions h JOIN class_members cm ON cm.user_id = h.user_id WHERE cm.class_id = ? AND h.day_key >= ? LIMIT 4000').bind(String(classId), fromKey).all<any>()
    const byUser: any = {}
    for (const r of ((subs && subs.results) || [])) {
      const k = String(r.uid)
      if (!byUser[k]) byUser[k] = {}
      byUser[k][String(r.dk)] = 1
    }
    const bought: any = {}
    for (const b of (st.buyers || [])) { if (Number(b.p) === 1) bought[String(b.u)] = 1 }
    for (const m of ((mem && mem.results) || [])) {
      const uid = String(m.uid)
      const days = byUser[uid] || {}
      const price = khtPriceOf(khtStreak(days, todayKey, extra), khtRecent(days, todayKey, extra, KHT_RECENT_DAYS))
      if (price === KHT_PRICE_STREAK) t500++
      else if (price === KHT_PRICE_MID) t1500++
      else t3000++
      if (!bought[uid] && (Number(m.coins) || 0) < price) cannot++
    }
  } catch (_e) { t500 = 0; t1500 = 0; t3000 = 0; cannot = 0 }
  let daysLeft: number | null = null
  try { const dd = Math.ceil((Date.parse(st.dueAt) - Date.now()) / KHT_DAY_MS); daysLeft = isFinite(dd) ? dd : null } catch (_e) { daysLeft = null }
  return c.json({ ok: true, enabled: !!st.enabled, round: st.round, size: size, need: need, needRaw: (st.need === null || st.need === undefined) ? null : st.need, paid: paid, reached: paid >= need, dueAt: st.dueAt, daysLeft: daysLeft, tier500: t500, tier1500: t1500, tier3000: t3000, cannotAfford: cannot, owed: (st.owed || []).length, extraHolidays: (st.extraHolidays || []) })
})

// 先生向け：まだ買っていない子の名前。先生が押したときだけ呼ばれる。
// ★この一覧を、子どもに見える画面に出す導線は作らないこと★
app.get('/api/teacher/class/:classId/kahoot/pending', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  if (!(await khtTeacherOwns(c, u, classId))) return jsonError(c, 404, 'class_not_found')
  const loaded = await khtLoad(c.env, classId)
  const st = loaded.st
  const extra = khtExtraMap(st)
  const todayKey = khtTodayKey(Date.now())
  const fromKey = khtAddDay(todayKey, -70)
  const bought: any = {}
  for (const b of (st.buyers || [])) { if (Number(b.p) === 1) bought[String(b.u)] = 1 }
  let list: any[] = []
  try {
    const mem = await c.env.DB.prepare("SELECT cm.user_id AS uid, u2.name AS name, COALESCE(CAST(json_extract(p.state_json, '$.coins') AS INTEGER), 0) AS coins FROM class_members cm JOIN users u2 ON u2.id = cm.user_id LEFT JOIN progress p ON p.user_id = cm.user_id WHERE cm.class_id = ? AND u2.role = 'student' AND u2.is_active = 1 LIMIT 200").bind(String(classId)).all<any>()
    const subs = await c.env.DB.prepare('SELECT h.user_id AS uid, h.day_key AS dk FROM homework_submissions h JOIN class_members cm ON cm.user_id = h.user_id WHERE cm.class_id = ? AND h.day_key >= ? LIMIT 4000').bind(String(classId), fromKey).all<any>()
    const byUser: any = {}
    for (const r of ((subs && subs.results) || [])) {
      const k = String(r.uid)
      if (!byUser[k]) byUser[k] = {}
      byUser[k][String(r.dk)] = 1
    }
    for (const m of ((mem && mem.results) || [])) {
      const uid = String(m.uid)
      if (bought[uid]) continue
      const days = byUser[uid] || {}
      const price = khtPriceOf(khtStreak(days, todayKey, extra), khtRecent(days, todayKey, extra, KHT_RECENT_DAYS))
      const coins = Math.max(0, Math.floor(Number(m.coins) || 0))
      list.push({ name: String(m.name || ''), coins: coins, price: price, canAfford: coins >= price })
    }
    list.sort((a: any, b: any) => (a.coins - a.price) - (b.coins - b.price))
  } catch (_e) { list = [] }
  return c.json({ ok: true, pending: list })
})

// 先生向け：ON/OFF・必要人数・期限のばし・学校独自の休みの追加。
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
    if (typeof body.addHoliday === 'string' && /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(body.addHoliday)) {
      if ((next.extraHolidays || []).indexOf(body.addHoliday) < 0) next.extraHolidays = (next.extraHolidays || []).concat([body.addHoliday]).slice(0, 200)
    }
    if (typeof body.removeHoliday === 'string') {
      next.extraHolidays = (next.extraHolidays || []).filter((d: any) => String(d) !== String(body.removeHoliday))
    }
    if (await khtCas(c.env, classId, loaded.raw, next)) {
      return c.json({ ok: true, enabled: !!next.enabled, need: khtNeed(next, size), extraHolidays: next.extraHolidays })
    }
  }
  return jsonError(c, 503, 'busy_retry')
})

// 先生向け：「やったよ」。券を使い切って、回を 1 つ進める。コインは動かさない。
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

// 先生向け：「みんなに返す」。買った子それぞれに、その子が払った額を返す。
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


# ══════════════════════════════════════════════════════════════════════════
# 新しい先生画面（v1 の TEACHER_ADD を丸ごと置きかえる）
#   c.html(`...`) の中＝テンプレートリテラルの中なので
#   ・バッククォートと ${ は 1 文字も書かない
#   ・改行は \\n と二重に書く
# ══════════════════════════════════════════════════════════════════════════
NEW_TEACHER = r'''

          // ══════ KAHOOT_TICKET_V1 / KAHOOT_PRICE_V2 🎫 カフート券 ══════
          //   ここに出すのは「人数」まで。名前は押したときだけ別の道で取りに行く。
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
            if(d.reached){
              khtBanner.innerHTML = '<div style="background:#dcfce7;border:2px solid #16a34a;color:#166534;'
                + 'border-radius:10px;padding:8px 10px;font-weight:800;font-size:13px;margin-bottom:6px">'
                + '🎉 カフート券が そろいました（' + d.paid + ' / ' + d.need + '人）。今日か明日、カフートをやってください。</div>';
            } else {
              khtBanner.innerHTML = '';
            }
            let s = d.enabled ? 'ショップに出ています' : 'ショップに出ていません';
            s += '｜' + d.paid + ' / ' + d.need + ' 人';
            s += (d.needRaw === null) ? '（クラス全員＝児童' + d.size + '人）' : '（先生が ' + d.need + ' 人に下げています）';
            s += '｜いまの値段：500円が' + d.tier500 + '人／1500円が' + d.tier1500 + '人／3000円が' + d.tier3000 + '人';
            if(typeof d.daysLeft === 'number'){ s += '｜のこり ' + d.daysLeft + '日で自動返金'; }
            khtBody.textContent = s;

            khtPend.innerHTML = '';
            if(d.cannotAfford > 0 && !d.reached){
              const w = document.createElement('div');
              w.className = 'text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded px-2 py-1 mt-1';
              w.textContent = '⚠ いまの自分の値段を払えない子が ' + d.cannotAfford + '人 います。'
                + '家庭学習を3日つづければ500円になりますが、どうしても届かないときは必要人数を下げてください。';
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
            onBtn.onclick = async () => {
              try{ await api('/api/teacher/class/' + cls.id + '/kahoot', { method:'PUT', headers:{'content-type':'application/json'}, body: JSON.stringify({ enabled: !d.enabled }) }); await khtLoadState(); }
              catch(e){ alert(String(e.message||e)); }
            };
            khtCtrl.appendChild(onBtn);

            // ★逃げ道：必要人数を下げる。目立つ色にしておく。
            const sel = document.createElement('select');
            sel.className = 'text-xs px-2 py-1 rounded font-bold border bg-amber-50 border-amber-400 text-amber-800';
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
            doneBtn.onclick = async () => {
              if(!confirm('カフートを やりましたか？\\n押すと券は使い切りになり、また売り出せるようになります。\\n（コインは返しません）')) return;
              try{ await api('/api/teacher/class/' + cls.id + '/kahoot/done', { method:'POST' }); await khtLoadState(); }
              catch(e){ alert(String(e.message||e)); }
            };
            khtCtrl.appendChild(doneBtn);

            const refBtn = khtBtn('↩ みんなにコインを返す', 'bg-orange-50 text-orange-700 border-orange-300 hover:bg-orange-100');
            refBtn.title = '買った子には、その子が払った額をそのまま返します。';
            refBtn.onclick = async () => {
              if(!confirm('買った子 ' + d.paid + '人 に、それぞれが払った額を返して、はじめからにします。よろしいですか？')) return;
              try{ const r = await api('/api/teacher/class/' + cls.id + '/kahoot/refund', { method:'POST' }); alert(r.refunded + '人に返しました。'); await khtLoadState(); }
              catch(e){ alert(String(e.message||e)); }
            };
            khtCtrl.appendChild(refBtn);

            // 学校独自の休み（開校記念日・学年閉鎖など）。国の祝日は既に入っている。
            const holBtn = khtBtn('📅 学校の休みを足す（' + (d.extraHolidays ? d.extraHolidays.length : 0) + '日）',
              'bg-white text-slate-600 border-slate-300 hover:bg-slate-50');
            holBtn.title = 'ここで足した日は「休みの日」として連続の判定からのぞかれます。国の祝日と土日は足さなくても入っています。';
            holBtn.onclick = async () => {
              const cur = (d.extraHolidays || []).join(', ') || 'なし';
              const v = prompt('学校独自の休みを 1 日ぶん足します（例 2026-10-05）。\\nいま登録されている日：' + cur + '\\n\\n消したいときは、その日付をそのまま入れてください。', '');
              if(!v) return;
              const day = String(v).trim();
              const already = (d.extraHolidays || []).indexOf(day) >= 0;
              try{
                await api('/api/teacher/class/' + cls.id + '/kahoot', { method:'PUT', headers:{'content-type':'application/json'},
                  body: JSON.stringify(already ? { removeHoliday: day } : { addHoliday: day }) });
                await khtLoadState();
              } catch(e){ alert(String(e.message||e)); }
            };
            khtCtrl.appendChild(holBtn);

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
                        return '<div>' + (x.canAfford ? '・' : '⚠ ') + x.name + '（' + x.coins + 'コイン／いまの値段 ' + x.price + '）</div>';
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


# ══════════════════════════════════════════════════════════════════════════
# 子どもに配る JS（public/kahoot_ticket.js を丸ごと書き出す）
# ══════════════════════════════════════════════════════════════════════════
NEW_ASSET = r'''/* ===================================================================
   kahoot_ticket.js : 「カフート券」ショップUI（サーバー権威）
   - index.html 無編集。sticker.js とまったく同じ形で配信・注入する。
   - ★いちばん大事な約束★
     子どもの画面には「何人が買ったか」も「だれが買っていないか」も出さない。
     サーバが返すのは 0〜5 の段階ゲージだけで、人数はそもそも送られてこない。
   - ★値段の見せ方★
     安くなった子には理由を出す（「家庭学習を3日つづけたから500コイン！」）。
     高い子には理由を書かない。ふつうの値段として出すだけ。
     ただし「あと◯日つづけると500コインになるよ」はぜんいんに出す。
     高い数字だけ見せて終わると、そこで動くのをやめてしまうから。
   =================================================================== */
(function(global){
  'use strict';

  var S = { loaded:false, enabled:false, bought:false, gauge:0, reached:false, daysLeft:null,
            price:1500, cheapPrice:500, streak:0, toGo:3, cheap:false };
  var _busy = false;

  function curP(){ try{ if(typeof player!=='undefined' && player) return player; }catch(e){} return global.player || null; }

  function jpost(path){
    return fetch(path, { method:'POST', headers:{'content-type':'application/json'}, credentials:'same-origin' })
      .then(function(r){ return r.json().then(function(j){ j=j||{}; j.__status=r.status; return j; }).catch(function(){ return {ok:false,__status:r.status}; }); })
      .catch(function(){ return {ok:false,__status:0}; });
  }
  function jget(path){
    return fetch(path, { credentials:'same-origin' })
      .then(function(r){ return r.json().then(function(j){ j=j||{}; j.__status=r.status; return j; }).catch(function(){ return {ok:false,__status:r.status}; }); })
      .catch(function(){ return {ok:false,__status:0}; });
  }

  function applyCoins(newCoins){
    if(typeof newCoins !== 'number' || !isFinite(newCoins)) return;
    var p = curP();
    if(p){ try{ p.coins = newCoins; }catch(e){} }
    try{ if(typeof updateStatusView==='function') updateStatusView(); }catch(e){}
    ['coinCount','trainingCoinCount','coins','newCoins'].forEach(function(id){
      var el=document.getElementById(id); if(el){ try{ el.innerText = newCoins; }catch(e){} }
    });
    try{ if(typeof renderShopItems==='function') renderShopItems(); }catch(e){}
  }

  var LABELS = [
    'まだ はじまったばかり',
    'あつまってきたよ',
    'はんぶんくらい',
    'だいぶ そろってきた',
    'あと ちょっと！',
    'ぜんいん そろったよ！'
  ];
  function gaugeHtml(g, reached){
    var i, on, h = '<div style="display:flex;gap:3px;margin-top:7px">';
    for(i=1;i<=5;i++){
      on = (i<=g);
      h += '<div style="flex:1;height:9px;border-radius:5px;background:'+(on?(reached?'#22c55e':'#f97316'):'#e5e7eb')+'"></div>';
    }
    return h + '</div>';
  }

  function removeCard(){ var c0=document.getElementById('kahootShopCard'); if(c0&&c0.parentNode) c0.parentNode.removeChild(c0); }

  function refreshState(){
    return jget('/api/shop/kahoot/current').then(function(res){
      if(res && res.ok){
        S.loaded = true;
        S.enabled = !!res.enabled;
        S.bought = !!res.bought;
        S.gauge = Math.max(0, Math.min(5, Math.floor(Number(res.gauge)||0)));
        S.reached = !!res.reached;
        S.daysLeft = (typeof res.daysLeft === 'number') ? res.daysLeft : null;
        if(typeof res.price === 'number') S.price = res.price;
        if(typeof res.cheapPrice === 'number') S.cheapPrice = res.cheapPrice;
        if(typeof res.streak === 'number') S.streak = res.streak;
        if(typeof res.toGo === 'number') S.toGo = res.toGo;
        S.cheap = !!res.cheap;
      }
      ensureCard();
      updateCard();
      return res;
    });
  }

  function updateCard(){
    var card = document.getElementById('kahootShopCard'); if(!card) return;
    var g = card.querySelector('.kht-gauge');
    var lbl = card.querySelector('.kht-label');
    var cta = card.querySelector('.kht-cta');
    var note = card.querySelector('.kht-note');
    var why = card.querySelector('.kht-why');
    var tag = card.querySelector('.kht-price');
    if(g) g.innerHTML = gaugeHtml(S.gauge, S.reached);
    if(lbl) lbl.textContent = LABELS[S.reached ? 5 : S.gauge] || LABELS[0];
    if(tag) tag.textContent = '💰 ' + S.price + ' コイン';

    /* 値段の理由：安くなった子にだけ。高い子には「なぜ高いか」を書かない。
       かわりに「どうすれば安くなるか」はぜんいんに出す。 */
    if(why){
      if(S.cheap){
        why.style.display = '';
        why.style.background = '#dcfce7';
        why.style.color = '#166534';
        why.textContent = '🔥 家庭学習を ' + S.streak + '日 つづけたから ' + S.cheapPrice + 'コイン！';
      } else if(!S.bought){
        why.style.display = '';
        why.style.background = '#eff6ff';
        why.style.color = '#1d4ed8';
        why.textContent = '💡 家庭学習を あと' + S.toGo + '日 つづけると ' + S.cheapPrice + 'コインに なるよ';
      } else {
        why.style.display = 'none';
      }
    }

    if(cta){
      if(S.reached){
        cta.textContent = '🎉 そろったよ！ 先生からの おしらせを まってね';
        cta.style.background = '#16a34a';
      } else if(S.bought){
        cta.textContent = '✅ こうにゅう ずみ｜みんなを まっているよ';
        cta.style.background = '#0ea5e9';
      } else {
        cta.textContent = '🎫 ' + S.price + 'コインで こうにゅう';
        cta.style.background = S.cheap ? '#16a34a' : '#7c3aed';
      }
    }
    if(note){
      if(S.reached){
        note.textContent = 'クラスのみんなが そろいました。';
      } else if(S.daysLeft !== null){
        note.textContent = 'そろわないまま ' + S.daysLeft + '日 たつと、コインは ぜんいんに もどってきます。';
      } else {
        note.textContent = 'そろわなかったときは、コインは もどってきます。';
      }
    }
  }

  function doBuy(){
    if(_busy) return;
    if(S.bought || S.reached){ return; }
    var p = curP();
    var have = p ? (Number(p.coins)||0) : null;
    if(have !== null && have < S.price){
      alert('コインが たりないよ（' + S.price + 'コイン ひつよう）\n家庭学習を あと' + S.toGo + '日 つづけると ' + S.cheapPrice + 'コインに なるよ。');
      return;
    }
    if(!confirm('カフート券を ' + S.price + 'コインで かいますか？\n\nクラスの みんなが そろうと、先生が カフートを やってくれます。\nそろわなかったときは、コインは もどってきます。')) return;
    _busy = true;
    jpost('/api/shop/kahoot/buy').then(function(res){
      _busy = false;
      if(res && res.ok){
        if(typeof res.coins === 'number') applyCoins(res.coins);
        S.bought = true;
        if(typeof res.gauge === 'number') S.gauge = res.gauge;
        S.reached = !!res.reached;
        updateCard();
        alert('カフート券を かいました！\nクラスの みんなが そろうのを まとう。');
        refreshState();
        return;
      }
      var r = (res && res.error) || (res && res.reason) || '';
      if(r === 'not_enough_coins') alert('コインが たりないよ（' + S.price + 'コイン ひつよう）');
      else if(r === 'already_bought') { S.bought = true; updateCard(); alert('もう かってあるよ。'); }
      else if(r === 'already_reached') { S.reached = true; updateCard(); alert('もう ぜんいん そろっているよ！'); }
      else if(r === 'kahoot_disabled') { S.enabled = false; ensureCard(); }
      else if(r === 'busy_retry') alert('こんでいます。すこし まって、もういちど おしてね。');
      else alert('うまく いきませんでした。もういちど ためしてね。');
      refreshState();
    });
  }

  function ensureCard(){
    var container = document.getElementById('shopItemsContainer');
    if(!container) return;
    if(!S.loaded) return;
    if(!S.enabled && !S.bought){ removeCard(); return; }
    if(document.getElementById('kahootShopCard')) return;

    var card = document.createElement('button');
    card.id = 'kahootShopCard';
    card.className = 'rounded-xl p-4 shadow-sm border border-purple-300 text-left flex flex-col gap-1 relative';
    card.style.cssText = 'background:#faf5ff;';
    card.innerHTML = ''
      + '<div class="flex items-center gap-3">'
      + '  <div class="text-3xl">🎫</div>'
      + '  <div class="flex-1"><div class="font-bold text-base">カフート券</div>'
      + '  <div class="text-xs text-gray-600">クラスの ぜんいんが そろうと、先生が カフートを やってくれる券。</div></div>'
      + '</div>'
      + '<div class="kht-price mt-1 bg-purple-100 text-purple-800 text-xs px-2 py-1 rounded-full w-fit"></div>'
      + '<div class="kht-why" style="font-size:11px;font-weight:700;border-radius:8px;padding:5px 8px;margin-top:5px"></div>'
      + '<div class="kht-gauge"></div>'
      + '<div class="kht-label" style="font-size:12px;color:#6b21a8;font-weight:700;margin-top:4px"></div>'
      + '<div class="kht-note" style="font-size:11px;color:#6b7280;margin-top:2px"></div>'
      + '<div class="kht-cta" style="margin-top:8px;color:#fff;background:#7c3aed;border-radius:10px;padding:8px 10px;font-weight:800;font-size:13px;text-align:center"></div>';
    card.addEventListener('click', function(ev){ ev.preventDefault(); ev.stopPropagation(); doBuy(); });
    container.appendChild(card);
    updateCard();
  }

  function start(){
    var container = document.getElementById('shopItemsContainer');
    if(!container){ setTimeout(start, 800); return; }
    try{ var mo = new MutationObserver(function(){ ensureCard(); }); mo.observe(container, {childList:true}); }catch(e){}
    refreshState();
    setInterval(function(){ ensureCard(); }, 1500);
    setInterval(function(){ refreshState(); }, 30000);
  }
  if(document.readyState !== 'loading') start();
  else document.addEventListener('DOMContentLoaded', start);

  global.__kahootRefresh = refreshState;
})(typeof window!=='undefined'?window:globalThis);
'''


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def main():
    if not os.path.exists(V1):
        print('NG: ' + V1 + ' が無い')
        return 1
    v1 = load_v1()
    old_server = v1.SERVER_ADD
    old_teacher = v1.TEACHER_ADD

    s = io.open(PATH, encoding='utf-8').read()

    if SENTINEL in s:
        print('already applied: ' + SENTINEL + ' / 何もしない')
        return 0

    before = chain_count(s)

    # v1 のかたまりがそのままの形で 1 件だけあること
    for label, text in (('v1のサーバ部', old_server), ('v1の先生画面', old_teacher)):
        n = s.count(text)
        if n != 1:
            print('NG: %s が %d 件（期待 1）' % (label, n))
            return 1

    # 先生画面はテンプレートリテラルの中。壊す文字を入れない。
    if '`' in NEW_TEACHER or '${' in NEW_TEACHER:
        print('NG: 先生画面の追加にバッククォートか ${ が入っている')
        return 1
    if NEW_TEACHER.replace('\\\\', '').count('\\') != 0:
        print('NG: 先生画面の追加に 二重になっていない \\ が入っている')
        return 1

    t = s.replace(old_server, NEW_SERVER)
    t = t.replace(old_teacher, NEW_TEACHER)

    ok = True

    def chk(label, got, want):
        if got != want:
            print('NG: %s が %s（期待 %s）' % (label, got, want))
            return False
        return True

    # チェーンは 1 本も増減していないこと
    after = chain_count(t)
    ok = chk('チェーン件数', after, before) and ok

    # 新しい値段が入っていること
    for label, want in (
        ('KHT_PRICE_STREAK = 500', 1),
        ('KHT_PRICE_MID = 1500', 1),
        ('KHT_PRICE_NONE = 3000', 1),
        ('KHT_STREAK_NEED = 3', 1),
        ('KHT_RECENT_DAYS = 5', 1),
        ('KAHOOT_PRICE_V2', 2),
        ('function khtStreak(', 1),
        ('function khtRecent(', 1),
        ('function khtPriceOf(', 1),
        ('async function khtQuote(', 1),
    ):
        ok = chk(label, t.count(label), want) and ok

    # 古い 800 円の作りが残っていないこと
    for label in ('const KHT_PRICE =', 'price: KHT_PRICE,'):
        ok = chk('（消えているべき）' + label, t.count(label), 0) and ok

    # クラス全員は児童だけ
    ok = chk('児童だけを数える', t.count("u.role = 'student' AND u.is_active = 1"), 1) and ok
    ok = chk('児童だけを数える2', t.count("u2.role = 'student' AND u2.is_active = 1"), 2) and ok

    # 道が 1 本ずつあること
    for label in (
        "app.get('/api/shop/kahoot/current'",
        "app.post('/api/shop/kahoot/buy'",
        "app.get('/api/teacher/class/:classId/kahoot'",
        "app.get('/api/teacher/class/:classId/kahoot/pending'",
        "app.put('/api/teacher/class/:classId/kahoot'",
        "app.post('/api/teacher/class/:classId/kahoot/done'",
        "app.post('/api/teacher/class/:classId/kahoot/refund'",
        'header.appendChild(khtBox);',
    ):
        ok = chk(label, t.count(label), 1) and ok

    # 壊してはいけない既存のもの（数が動いていないこと）
    for label in (
        "app.get('/sticker.js'",
        "app.post('/api/shop/sticker/buy'",
        "app.get('/def_join_nudge.js'",
        "app.get('/kahoot_ticket.js'",
        '/kahoot_ticket.js?v=1',
        "app.get('/', async (c) => {",
        "app.get('/logout'",
        'defStageMakeLedger',
        'applyDefStageGrants',
        'CREATE TABLE',
        'ALTER TABLE',
    ):
        ok = chk('（既存）' + label, t.count(label), s.count(label)) and ok

    # コインはサーバで確定する道が残っていること
    ok = chk('コイン台帳の道', t.count("'$._serverSpentCoins'"), 2) and ok

    # 子ども向けの返り値に人数が入っていないこと
    cur = t[t.index("app.get('/api/shop/kahoot/current'"):t.index("app.post('/api/shop/kahoot/buy'")]
    for bad in ('paid:', 'need:', 'pending', 'notPaid', 'buyers:', 'tier500', 'cannotAfford'):
        if bad in cur:
            print('NG: 子ども向けの返り値に %s が入っている' % bad)
            ok = False

    if t == s:
        print('NG: 中身が変わっていない')
        ok = False

    if not ok:
        print('NG: 自己点検に落ちたので書き込まない')
        return 1

    io.open(PATH, 'w', encoding='utf-8').write(t)
    io.open(ASSET, 'w', encoding='utf-8').write(NEW_ASSET)
    print('OK: %s と %s を更新した（チェーン %d のまま）' % (PATH, ASSET, after))
    return 0


if __name__ == '__main__':
    sys.exit(main())
