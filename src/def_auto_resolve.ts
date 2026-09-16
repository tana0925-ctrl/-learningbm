// __DEF_AUTO_RESOLVE_V1__ 先生が 画面を ひらいていなくても 12:30 に 決戦が おきるようにする。
//
// 2026-09-14 / 09-15 / 09-16 と 3日つづけて 12:30 に はじまりませんでした。
// D1 の 時刻から わかったこと（2026-09-16 しらべ）:
//   09-15 12:41:52 … 持ちこし＋全員じどう出陣だけが 走った（defense_carry_lock と
//                    defense_entries 18件）。これは /api/defense/status でも
//                    /api/teacher/defense/start でも 起きる。結果は 1文字も 書かれていない。
//   09-15 13:34:56 … ここで はじめて defense_results が 書かれた（53分あと）。
// 先生の画面の 20秒タイマーは、
//   ・_defTsFired を たたく前に 立てるので 1回でも しくじると そのページでは 二度と たたかない
//   ・タブが うしろに まわると 1分に1回まで しぼられ、PCが スリープすると 止まる
//   ・そもそも /teacher を ひらいていないと 存在しない
// ので、「先生が 正しく さわれば 動く」に たよるのは もう やめます。
//
// ここで やること
//   1) だれの 端末も 要らない 入口 GET/POST /api/defense/auto-resolve を つくる。
//      GitHub Actions の 時計から 12:25〜12:55 のあいだ 5分おきに たたく。
//      ・決戦時刻の 前なら 何もしない（not_yet）
//      ・もう 結果が あるなら 何もしない（already）
//      ・勝敗が 決められないなら 1文字も 書かない（fail-closed）
//      ログインは 要りません。この口が できるのは「決戦時刻を すぎた 未判定の回を
//      1回だけ 決着させる」ことだけで、それは もともと 起きるべきことです。
//   2) 児童の /api/defense/status からも 決着まで 済ませる（案B）。
//      2分に 1台だけ（darBucketLock）なので、22台で 戦闘計算が 走ることは ありません。
//   3) 先生の画面が「昨日 動かなかった」ことに 気づけるように
//      GET /api/teacher/defense/health を つくる。
//
// 勝敗の 決め方（defServerResolve）と 持ちこしの SQL は
// src/index.tsx / src/def_teacher_start.ts の ものを そのまま 写しています。
// 片方だけ 変えないこと。児童の 戦闘エンジン（def_engine / def_resolve / def_stage / def_dex）
// には 1文字も さわっていません。
// @ts-nocheck
/* eslint-disable */

let DAR: any = null

function darDeps() { return DAR }

// 先生の うけもちクラス。2つ以上 あるときは いちばん古い 1つ。
async function darClassId(env: any, teacherId: any) {
  try {
    const r = await env.DB.prepare("SELECT id FROM classes WHERE teacher_id=? ORDER BY created_at ASC LIMIT 1").bind(String(teacherId)).first()
    return (r && r.id) ? String(r.id) : ''
  } catch (_e) { return '' }
}

async function darEntryCountRaw(env: any, eventKey: any, classId: any) {
  try {
    const r = await env.DB.prepare("SELECT COUNT(*) AS c FROM defense_entries WHERE event_key=? AND class_id=? LIMIT 1").bind(String(eventKey), String(classId)).first()
    const n = Number(r && r.c)
    return Number.isFinite(n) ? Math.floor(n) : 0
  } catch (_e) { return 0 }
}

// 重い 戦闘計算を 2分に 1回だけに しぼる 見はり。
// defense_carry_lock を 借りるが、class_id に '#auto<番号>' を つけた にせの鍵なので
// 本物の (event_key, class_id) とは ぶつからない。読む側も ここ以外に いない。
async function darBucketLock(env: any, eventKey: any, classId: any, decisionAt: any) {
  let bucket = 0
  try {
    const t = Date.parse(String(decisionAt))
    if (Number.isFinite(t)) bucket = Math.floor((Date.now() - t) / 120000)
  } catch (_e) {}
  if (!Number.isFinite(bucket) || bucket < 0) bucket = 0
  const key = String(classId) + '#auto' + String(bucket)
  try {
    const r = await env.DB.prepare("INSERT INTO defense_carry_lock (event_key, class_id, done_at) VALUES (?,?,datetime('now')) ON CONFLICT(event_key, class_id) DO NOTHING").bind(String(eventKey), key).run()
    return !!(r && r.meta && Number(r.meta.changes || 0) > 0)
  } catch (_e) { return false }
}

// 持ちこし＋クラス全員の じどう出陣。クラスで 1回だけ 走る（defense_carry_lock）。
// src/index.tsx の /api/defense/status と src/def_teacher_start.ts の 同じ かたまり。
async function darMaterialize(env: any, eventKey: any, classId: any) {
  const d = darDeps()
  if (!d) return false
  try {
    const lock = await env.DB.prepare("INSERT INTO defense_carry_lock (event_key, class_id, done_at) VALUES (?,?,datetime('now')) ON CONFLICT(event_key, class_id) DO NOTHING").bind(eventKey, classId).run()
    if (!lock || !lock.meta || Number(lock.meta.changes || 0) <= 0) return false
    try {
      const all = await env.DB.prepare("SELECT ds.user_id AS uid, ds.snapshot_json AS mj, ds.strategy AS strat, json_extract(p.state_json, '$.monsters.\"' || ds.monster_id || '\".level') AS curlv FROM defense_standing ds JOIN class_members cm ON cm.user_id = ds.user_id LEFT JOIN progress p ON p.user_id = ds.user_id WHERE cm.class_id=? LIMIT 200").bind(classId).all()
      const rows = ((all && all.results) || []).filter((r: any) => r && r.mj && r.curlv != null && d.defCarrySnapOk(r.mj))
      if (rows.length) {
        const ins = env.DB.prepare("INSERT INTO defense_entries (event_key, user_id, class_id, monster_json, strategy, created_at) VALUES (?,?,?,?,?,datetime('now')) ON CONFLICT(event_key, user_id) DO NOTHING")
        await env.DB.batch(rows.map((r: any) => ins.bind(eventKey, String(r.uid), classId, String(r.mj), String(r.strat || 'balance'))))
      }
    } catch (_e) {}
    try {
      const aj = await env.DB.prepare("SELECT cm.user_id AS uid, json_extract(p.state_json, '$.party[0]') AS pid FROM class_members cm LEFT JOIN progress p ON p.user_id = cm.user_id WHERE cm.class_id=? AND cm.user_id NOT IN (SELECT user_id FROM defense_entries WHERE event_key=? AND class_id=?) LIMIT 200").bind(classId, eventKey, classId).all()
      const ajRows: any[] = []
      for (const r of ((aj && aj.results) || [])) {
        const m = d.defDexEntry(r && r.pid)
        if (!m || !d.defEntryOk(m)) continue
        m.auto = 1
        const uid = String((r && r.uid) || '')
        if (!uid) continue
        ajRows.push({ uid: uid, mj: JSON.stringify(m) })
      }
      if (ajRows.length) {
        const ins2 = env.DB.prepare("INSERT INTO defense_entries (event_key, user_id, class_id, monster_json, strategy, created_at) VALUES (?,?,?,?,?,datetime('now')) ON CONFLICT(event_key, user_id) DO NOTHING")
        await env.DB.batch(ajRows.map((r: any) => ins2.bind(eventKey, r.uid, classId, r.mj, 'balance')))
      }
    } catch (_e) {}
    return true
  } catch (_e) { return false }
}

// 勝敗を 決めて 書く。決められないときは 1文字も 書かない（fail-closed）。
// src/def_teacher_start.ts の tsResolve と 同じ。
async function darResolve(env: any, st: any, classId: any) {
  const d = darDeps()
  if (!d) return { undecidable: true, entries: 0 }
  const done = await env.DB.prepare("SELECT 1 AS x FROM defense_results WHERE event_key=? AND class_id=? LIMIT 1").bind(st.eventKey, classId).first()
  if (done) return { already: true }
  let stage = 1
  try {
    const r = await env.DB.prepare("SELECT stage FROM defense_stage WHERE class_id = ? LIMIT 1").bind(classId).first()
    const n = Number(r && r.stage)
    if (Number.isFinite(n) && n >= 1) stage = Math.floor(n)
  } catch (_e) {}
  const enemies = d.defBossApply(d.defStageEnemies(d.DEFENSE_ENEMIES, stage, await d.defEntryCount(env, st.eventKey, classId)), stage)
  const srv = await d.defServerResolve(env, st, classId, enemies)
  if (!srv) return { undecidable: true, entries: await darEntryCountRaw(env, st.eventKey, classId) }
  const lock = await env.DB.prepare("INSERT OR IGNORE INTO defense_results (event_key, class_id, result, log_json, base_hp_end, resolved_at) VALUES (?,?,?,?,?,datetime('now'))").bind(st.eventKey, classId, srv.result, srv.logJson, srv.baseHpEnd).run()
  if (!lock || !lock.meta || Number(lock.meta.changes || 0) === 0) return { already: true }
  try { await d.defMvpMakeLedger(env, st.eventKey, classId, srv.mvpLedger) } catch (_e) {}
  if (srv.result === 'win') {
    try {
      await env.DB.prepare("INSERT OR IGNORE INTO defense_stage (class_id, stage, updated_at) VALUES (?, 1, datetime('now'))").bind(classId).run()
      const up = await env.DB.prepare("UPDATE defense_stage SET stage = stage + 1, updated_at = datetime('now') WHERE class_id = ? AND stage = ?").bind(classId, stage).run()
      if (up && up.meta && Number(up.meta.changes || 0) === 1) await d.defStageMakeLedger(env, classId, stage)
    } catch (_e) {}
    try {
      const es = await env.DB.prepare("SELECT user_id, json_extract(monster_json, '$.auto') AS au FROM defense_entries WHERE event_key=? AND class_id=?").bind(st.eventKey, classId).all()
      const rw = env.DB.prepare("INSERT OR IGNORE INTO defense_rewards (event_key, class_id, user_id, coins, seen, created_at) VALUES (?,?,?,?,0,datetime('now'))")
      const list = ((es && es.results) || []).map((r: any) => rw.bind(st.eventKey, classId, String(r.user_id), (Number(r.au) === 1 ? d.DEFENSE_WIN_COINS : d.DEFENSE_WIN_COINS + d.DEFENSE_ENTRY_BONUS_COINS)))
      if (list.length) await env.DB.batch(list)
    } catch (_e) {}
  }
  return { resolved: true, result: srv.result, base_hp_end: srv.baseHpEnd, entries: srv.entries }
}

// __DEF_AUTO_GUARD_V1__ クラスの 人数。
async function darMemberCount(env: any, classId: any) {
  try {
    const r = await env.DB.prepare("SELECT COUNT(*) AS c FROM class_members WHERE class_id=? LIMIT 1").bind(String(classId)).first()
    const n = Number(r && r.c)
    return Number.isFinite(n) ? Math.floor(n) : 0
  } catch (_e) { return 0 }
}

// __DEF_AUTO_GUARD_V1__ 出陣が できあがっているか。
// 自分で 作ったなら もちろん OK（同じ通信の中で 順番に 走っている）。
// ほかの 通信が 作ったなら、それが 終わるだけの 時間（5秒）が たっていること。
async function darRosterReady(env: any, eventKey: any, classId: any, wonLock: any) {
  if (wonLock) return true
  try {
    const r = await env.DB.prepare("SELECT 1 AS x FROM defense_carry_lock WHERE event_key=? AND class_id=? AND done_at <= datetime('now','-5 seconds') LIMIT 1").bind(String(eventKey), String(classId)).first()
    return !!r
  } catch (_e) { return false }
}

// __DEF_AUTO_GUARD_V1__ 人数が あまりに 少ないときは 判定しない。
// 「時間どおりに 2人で 負ける」より「おくれて みんなで 勝つ」ほうが いい。
async function darTooFew(env: any, eventKey: any, classId: any) {
  const n = await darEntryCountRaw(env, eventKey, classId)
  const m = await darMemberCount(env, classId)
  return { few: (m >= 5 && n < 3), entries: n, members: m }
}

// 児童の /api/defense/status から よぶ 入口（案B）。
// 2分に 1台だけ 通す。しくじっても 児童の画面を 止めない。
export async function defAutoResolveHook(env: any, st: any, classId: any) {
  try {
    if (!DAR || !st || !st.eventKey || !classId) return false
    if (!(st.decisionAt && Date.now() >= Date.parse(st.decisionAt))) return false
    const done = await env.DB.prepare("SELECT 1 AS x FROM defense_results WHERE event_key=? AND class_id=? LIMIT 1").bind(String(st.eventKey), String(classId)).first()
    if (done) return false
    // __DEF_AUTO_GUARD_V1__ 先に 出陣を つくる。できあがる前なら 判定しない。
    const won = await darMaterialize(env, st.eventKey, classId)
    if (!(await darRosterReady(env, st.eventKey, classId, won))) return false
    const few = await darTooFew(env, st.eventKey, classId)
    if (few.few) return false
    const got = await darBucketLock(env, st.eventKey, classId, st.decisionAt)
    if (!got) return false
    const r = await darResolve(env, st, classId)
    return !!(r && r.resolved)
  } catch (_e) { return false }
}

export function registerDefAutoResolve(app: any, deps: any) {
  DAR = deps
  const requireTeacher = deps.requireTeacher
  const jsonError = deps.jsonError
  const defenseSettings = deps.defenseSettings

  // だれの 端末も 要らない 入口。時刻を すぎた 未判定の回を 1回だけ 決着させる。
  async function darRunAll(env: any) {
    const out: any = { ok: true, ran: false, server_now: new Date().toISOString(), event_key: '', decision_at: '', classes: [] }
    let st: any = null
    try { st = await defenseSettings(env) } catch (_e) { st = null }
    if (!st) { out.reason = 'no_settings'; return out }
    out.event_key = st.eventKey || ''
    out.decision_at = st.decisionAt || ''
    if (!st.active) { out.reason = 'inactive'; return out }
    if (!st.eventKey) { out.reason = 'no_event'; return out }
    if (!(st.decisionAt && Date.now() >= Date.parse(st.decisionAt))) { out.reason = 'not_yet'; return out }
    let ids: string[] = []
    try {
      const r = await env.DB.prepare("SELECT DISTINCT class_id AS cid FROM class_members LIMIT 20").all()
      ids = ((r && r.results) || []).map((x: any) => String((x && x.cid) || '')).filter((x: string) => !!x)
    } catch (_e) { ids = [] }
    for (const cid of ids) {
      try {
        const done = await env.DB.prepare("SELECT 1 AS x FROM defense_results WHERE event_key=? AND class_id=? LIMIT 1").bind(st.eventKey, cid).first()
        if (done) { out.classes.push({ class_id: cid, already: true }); continue }
        // __DEF_AUTO_GUARD_V1__ 先に 出陣を つくる。できあがる前や 人数が 少なすぎるときは 待つ。
        const won = await darMaterialize(env, st.eventKey, cid)
        if (!(await darRosterReady(env, st.eventKey, cid, won))) { out.classes.push({ class_id: cid, skipped: 'roster_not_ready' }); continue }
        const few = await darTooFew(env, st.eventKey, cid)
        if (few.few) { out.classes.push({ class_id: cid, skipped: 'too_few', entries: few.entries, members: few.members }); continue }
        const got = await darBucketLock(env, st.eventKey, cid, st.decisionAt)
        if (!got) { out.classes.push({ class_id: cid, skipped: 'busy' }); continue }
        const r = await darResolve(env, st, cid)
        if (r && r.resolved) { out.ran = true; out.classes.push({ class_id: cid, resolved: true, result: r.result, base_hp_end: r.base_hp_end, entries: r.entries }) }
        else if (r && r.already) out.classes.push({ class_id: cid, already: true })
        else out.classes.push({ class_id: cid, undecidable: true, entries: (r && r.entries) || 0 })
      } catch (_e) {
        out.classes.push({ class_id: cid, error: true })
      }
    }
    return out
  }

  app.get('/api/defense/auto-resolve', async (c: any) => { return c.json(await darRunAll(c.env)) })
  app.post('/api/defense/auto-resolve', async (c: any) => { return c.json(await darRunAll(c.env)) })

  // 先生むけ「動かなかったことに 気づく」ための 口（読むだけ）。
  app.get('/api/teacher/defense/health', async (c: any) => {
    const u = requireTeacher(c)
    if (!u) return jsonError(c, 401, 'unauthorized')
    const out: any = { ok: true, class_id: '', recent: [], today: null, server_now: new Date().toISOString() }
    const classId = await darClassId(c.env, u.id)
    out.class_id = classId
    if (!classId) return c.json(out)
    try {
      const rs = await c.env.DB.prepare("SELECT event_key, resolved_at FROM defense_results WHERE class_id=? ORDER BY resolved_at DESC LIMIT 5").bind(classId).all()
      for (const r of ((rs && rs.results) || [])) {
        const sched = Date.parse(String((r && r.event_key) || ''))
        const got = Date.parse(String((r && r.resolved_at) || '').replace(' ', 'T') + 'Z')
        const late = (Number.isFinite(sched) && Number.isFinite(got)) ? Math.round((got - sched) / 60000) : null
        out.recent.push({ event_key: r.event_key, resolved_at: r.resolved_at, late_minutes: late })
      }
    } catch (_e) {}
    try {
      const st = await defenseSettings(c.env)
      if (st && st.active && st.eventKey && st.decisionAt) {
        const done = await c.env.DB.prepare("SELECT 1 AS x FROM defense_results WHERE event_key=? AND class_id=? LIMIT 1").bind(st.eventKey, classId).first()
        const t = Date.parse(st.decisionAt)
        out.today = {
          event_key: st.eventKey,
          decision_at: st.decisionAt,
          resolved: !!done,
          overdue_minutes: (!done && Number.isFinite(t) && Date.now() > t) ? Math.round((Date.now() - t) / 60000) : 0
        }
      }
    } catch (_e) {}
    return c.json(out)
  })
}
