// __DEF_TEACHER_START_V1__ 先生の画面から その場で 決戦を はじめる。
//
// 2026-09-14（初日の本番）に 12:30 の 防衛戦が はじまらず、14:05 に なってしまった
// ふぐあいの 直しです。
//
// 何が おきていたか
//   これまで 決戦を 起こせるのは、児童の画面の 赤い「決戦をはじめる！」ボタン
//   （public/index.html → window._defStartResolve → public/defense2.js →
//    POST /api/defense/resolve）だけでした。
//   先生は class_members に 入っていないため、/api/defense/status は no_class で
//   すぐ 打ち切られます。先生が 何回 画面を ひらいても 1ミリも 進みません。
//   給食の 12:30 に iPad が 1台も ひらいていない日は、だれも 決戦を 起こせません。
//   じっさい 2026-09-14 は 12:30〜14:01 のあいだ 児童の アクセスが 1件も ありませんでした。
//
// ここで やること
//   1) 先生 → クラス は classes.teacher_id から ひく（class_members は 使わない）。
//   2) 児童側 status と 同じ「持ちこし＋クラス全員の じどう出陣」を 先に 走らせる。
//      ここを ぬくと 22人ではなく 7人で 戦ってしまう。
//   3) 勝敗は サーバの defServerResolve で 決める。
//      決められないときは 1文字も 書かない（fail-closed）。
//   4) 書きこみは INSERT OR IGNORE の 冪等ロックだけ。
//      すでに 結果が ある回は ぜったいに 走らせない。
//
// 児童側の みちすじ（/api/defense/status と /api/defense/resolve）には さわっていない。
// SQL は src/index.tsx の 同じ処理を 写したもの。片方だけ 変えないこと。
// @ts-nocheck
/* eslint-disable */

export function registerDefTeacherStart(app: any, deps: any) {
  const requireTeacher = deps.requireTeacher
  const jsonError = deps.jsonError
  const defenseSettings = deps.defenseSettings
  const defServerResolve = deps.defServerResolve
  const defEntryOk = deps.defEntryOk
  const defDexEntry = deps.defDexEntry
  const defCarrySnapOk = deps.defCarrySnapOk
  const defStageEnemies = deps.defStageEnemies
  const defBossApply = deps.defBossApply
  const DEFENSE_ENEMIES = deps.DEFENSE_ENEMIES
  const defEntryCount = deps.defEntryCount
  const defMvpMakeLedger = deps.defMvpMakeLedger
  const defStageMakeLedger = deps.defStageMakeLedger
  const DEFENSE_WIN_COINS = deps.DEFENSE_WIN_COINS
  const DEFENSE_ENTRY_BONUS_COINS = deps.DEFENSE_ENTRY_BONUS_COINS

  // 先生の うけもちクラス。2つ以上 あるときは いちばん古い 1つ。
  async function tsClassId(env: any, teacherId: any) {
    try {
      const r = await env.DB.prepare("SELECT id FROM classes WHERE teacher_id=? ORDER BY created_at ASC LIMIT 1").bind(String(teacherId)).first()
      return (r && r.id) ? String(r.id) : ''
    } catch (_e) { return '' }
  }

  // 見せるための 出陣人数。defEntryCount は 0人のとき 8 を 返すので、そのままは 使わない。
  async function tsEntryCount(env: any, eventKey: any, classId: any) {
    try {
      const r = await env.DB.prepare("SELECT COUNT(*) AS c FROM defense_entries WHERE event_key=? AND class_id=? LIMIT 1").bind(String(eventKey), String(classId)).first()
      const n = Number(r && r.c)
      return Number.isFinite(n) ? Math.floor(n) : 0
    } catch (_e) { return 0 }
  }

  // 持ちこし＋クラス全員の じどう出陣。クラスで 1回だけ 走る（defense_carry_lock）。
  // 児童側 /api/defense/status の 同じ かたまりと そろえてある。
  async function tsMaterialize(env: any, eventKey: any, classId: any) {
    try {
      const lock = await env.DB.prepare("INSERT INTO defense_carry_lock (event_key, class_id, done_at) VALUES (?,?,datetime('now')) ON CONFLICT(event_key, class_id) DO NOTHING").bind(eventKey, classId).run()
      if (!lock || !lock.meta || Number(lock.meta.changes || 0) <= 0) return false
      try {
        const all = await env.DB.prepare("SELECT ds.user_id AS uid, ds.snapshot_json AS mj, ds.strategy AS strat, json_extract(p.state_json, '$.monsters.\"' || ds.monster_id || '\".level') AS curlv FROM defense_standing ds JOIN class_members cm ON cm.user_id = ds.user_id LEFT JOIN progress p ON p.user_id = ds.user_id WHERE cm.class_id=? LIMIT 200").bind(classId).all()
        const rows = ((all && all.results) || []).filter((r: any) => r && r.mj && r.curlv != null && defCarrySnapOk(r.mj))
        if (rows.length) {
          const ins = env.DB.prepare("INSERT INTO defense_entries (event_key, user_id, class_id, monster_json, strategy, created_at) VALUES (?,?,?,?,?,datetime('now')) ON CONFLICT(event_key, user_id) DO NOTHING")
          await env.DB.batch(rows.map((r: any) => ins.bind(eventKey, String(r.uid), classId, String(r.mj), String(r.strat || 'balance'))))
        }
      } catch (_e) {}
      try {
        const aj = await env.DB.prepare("SELECT cm.user_id AS uid, json_extract(p.state_json, '$.party[0]') AS pid FROM class_members cm LEFT JOIN progress p ON p.user_id = cm.user_id WHERE cm.class_id=? AND cm.user_id NOT IN (SELECT user_id FROM defense_entries WHERE event_key=? AND class_id=?) LIMIT 200").bind(classId, eventKey, classId).all()
        const ajRows: any[] = []
        for (const r of ((aj && aj.results) || [])) {
          const m = defDexEntry(r && r.pid)
          if (!m || !defEntryOk(m)) continue
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

  // 勝敗を 決めて 書く。児童側 /api/defense/resolve の サーバ経路と 同じ。
  // ちがうのは「クライアントの申告に 落ちない」ところだけ。
  // 先生の画面には 申告する 戦闘結果が 無いので、決められないときは 何も 書かない。
  async function tsResolve(env: any, st: any, classId: any) {
    const done = await env.DB.prepare("SELECT 1 AS x FROM defense_results WHERE event_key=? AND class_id=? LIMIT 1").bind(st.eventKey, classId).first()
    if (done) return { already: true }
    let stage = 1
    try {
      const r = await env.DB.prepare("SELECT stage FROM defense_stage WHERE class_id = ? LIMIT 1").bind(classId).first()
      const n = Number(r && r.stage)
      if (Number.isFinite(n) && n >= 1) stage = Math.floor(n)
    } catch (_e) {}
    const enemies = defBossApply(defStageEnemies(DEFENSE_ENEMIES, stage, await defEntryCount(env, st.eventKey, classId)), stage)
    const srv = await defServerResolve(env, st, classId, enemies)
    if (!srv) return { undecidable: true, entries: await tsEntryCount(env, st.eventKey, classId) }
    const lock = await env.DB.prepare("INSERT OR IGNORE INTO defense_results (event_key, class_id, result, log_json, base_hp_end, resolved_at) VALUES (?,?,?,?,?,datetime('now'))").bind(st.eventKey, classId, srv.result, srv.logJson, srv.baseHpEnd).run()
    if (!lock || !lock.meta || Number(lock.meta.changes || 0) === 0) return { already: true }
    try { await defMvpMakeLedger(env, st.eventKey, classId, srv.mvpLedger) } catch (_e) {}
    if (srv.result === 'win') {
      try {
        await env.DB.prepare("INSERT OR IGNORE INTO defense_stage (class_id, stage, updated_at) VALUES (?, 1, datetime('now'))").bind(classId).run()
        const up = await env.DB.prepare("UPDATE defense_stage SET stage = stage + 1, updated_at = datetime('now') WHERE class_id = ? AND stage = ?").bind(classId, stage).run()
        if (up && up.meta && Number(up.meta.changes || 0) === 1) await defStageMakeLedger(env, classId, stage)
      } catch (_e) {}
      try {
        const es = await env.DB.prepare("SELECT user_id, json_extract(monster_json, '$.auto') AS au FROM defense_entries WHERE event_key=? AND class_id=?").bind(st.eventKey, classId).all()
        const rw = env.DB.prepare("INSERT OR IGNORE INTO defense_rewards (event_key, class_id, user_id, coins, seen, created_at) VALUES (?,?,?,?,0,datetime('now'))")
        const list = ((es && es.results) || []).map((r: any) => rw.bind(st.eventKey, classId, String(r.user_id), (Number(r.au) === 1 ? DEFENSE_WIN_COINS : DEFENSE_WIN_COINS + DEFENSE_ENTRY_BONUS_COINS)))
        if (list.length) await env.DB.batch(list)
      } catch (_e) {}
    }
    return { resolved: true, result: srv.result, base_hp_end: srv.baseHpEnd, entries: srv.entries }
  }

  // 先生の画面むけ ようす（読むだけ）。
  // class_members を 見ないので、先生でも ほんとうの 開催じょうきょうが 見える。
  // （/api/defense/status は クラス未所属を no_class で 打ち切るときに active を false に
  //   上書きするため、先生の画面の ランプが 開催中でも「OFF」に 見えていた。）
  app.get('/api/teacher/defense/state', async (c: any) => {
    const u = requireTeacher(c)
    if (!u) return jsonError(c, 401, 'unauthorized')
    const st = await defenseSettings(c.env)
    const classId = await tsClassId(c.env, u.id)
    const out: any = {
      ok: true,
      active: !!st.active,
      decision_at: st.decisionAt || '',
      event_key: st.eventKey || '',
      class_id: classId,
      decided: !!(st.decisionAt && Date.now() >= Date.parse(st.decisionAt)),
      resolved: false,
      result: null,
      base_hp_end: null,
      resolved_at: null,
      entries: 0,
      server_now: new Date().toISOString()
    }
    if (!classId) return c.json(out)
    try {
      const r = await c.env.DB.prepare("SELECT result, base_hp_end, resolved_at FROM defense_results WHERE event_key=? AND class_id=? LIMIT 1").bind(st.eventKey, classId).first()
      if (r) {
        out.resolved = true
        out.result = r.result
        out.base_hp_end = Number(r.base_hp_end || 0)
        out.resolved_at = r.resolved_at
      }
    } catch (_e) {}
    out.entries = await tsEntryCount(c.env, st.eventKey, classId)
    return c.json(out)
  })

  // 先生の画面から 決戦を はじめる。
  // 先生が 12:30 に 画面を ひらいていれば、児童の 端末が 1台も なくても ここで 決着する。
  app.post('/api/teacher/defense/start', async (c: any) => {
    const u = requireTeacher(c)
    if (!u) return jsonError(c, 401, 'unauthorized')
    const st = await defenseSettings(c.env)
    if (!st.eventKey) return c.json({ ok: true, started: false, reason: 'no_event' })
    if (!st.active) return c.json({ ok: true, started: false, reason: 'inactive' })
    if (!(st.decisionAt && Date.now() >= Date.parse(st.decisionAt))) {
      return c.json({ ok: true, started: false, reason: 'not_yet', decision_at: st.decisionAt })
    }
    const classId = await tsClassId(c.env, u.id)
    if (!classId) return c.json({ ok: true, started: false, reason: 'no_class' })
    // すでに 結果が ある回は ここで 打ち切る（その日の 結果を ぜったいに こわさない）。
    const before = await c.env.DB.prepare("SELECT 1 AS x FROM defense_results WHERE event_key=? AND class_id=? LIMIT 1").bind(st.eventKey, classId).first()
    if (before) return c.json({ ok: true, started: false, already: true })
    await tsMaterialize(c.env, st.eventKey, classId)
    const r = await tsResolve(c.env, st, classId)
    if (r && r.already) return c.json({ ok: true, started: false, already: true })
    if (r && r.undecidable) return c.json({ ok: true, started: false, reason: 'undecidable', entries: r.entries })
    return c.json({ ok: true, started: true, result: r.result, base_hp_end: r.base_hp_end, entries: r.entries })
  })
}
