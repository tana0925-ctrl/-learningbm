// __DEF_REVIEW_V1__ 防衛戦の「ふりかえり」— いちばん新しい 決戦を 見て、その子に「つぎの 作戦」の ヒントを 出す。
//   ・読むだけ。D1 には 1文字も 書かない。
//   ・その子 じぶんの ことと、クラス ぜんたいの ことだけ。ほかの子の 名前や くらべっこは 出さない。
//   ・％や じゅんいは 出さない（数は「てきに あたえた ダメージ」「たおした てきの 数」など じぶん・クラスの 事実だけ）。
// @ts-nocheck
/* eslint-disable */

function walk(prog, fn) {
  if (!Array.isArray(prog)) return
  for (const s of prog) {
    if (!s || typeof s !== 'object') continue
    fn(s)
    walk(s.body, fn); walk(s.els, fn)
  }
}

const STARTER = JSON.stringify([{ t: 'if', c: 'allyBaseBelow', cn: 40, body: [{ t: 'a', a: 'returnBase' }], els: [{ t: 'a', a: 'attackBase' }] }])

export function defReviewProgInfo(prog) {
  const info = { blocks: 0, empty: true, allyBaseBelow: false, selfHpBelow: false, lane: false, returnBase: false, ifs: 0 }
  walk(prog, function (s) {
    info.blocks++
    if (s.t === 'if') info.ifs++
    if (s.c === 'allyBaseBelow') info.allyBaseBelow = true
    if (s.c === 'selfHpBelow') info.selfHpBelow = true
    if (s.a === 'laneL' || s.a === 'laneC' || s.a === 'laneR') info.lane = true
    if (s.a === 'returnBase') info.returnBase = true
  })
  info.empty = info.blocks === 0
  // さいしょの すがた（defense2.js の D2T_START）の まま か
  try { info.starter = JSON.stringify(prog) === STARTER } catch (_e) { info.starter = false }
  return info
}

// replay と 自分の 番号から、じぶん・クラスの ようすを 出す。
export function defReviewFacts(log, idx) {
  const R = (log && log.replay) || {}
  const E = Array.isArray(R.events) ? R.events : []
  const ticks = Number(R.ticks) || 0
  const baseMax = Number(R.baseMax) || 0
  let last = null
  for (let i = E.length - 1; i >= 0; i--) { if (E[i] && Array.isArray(E[i].hpB)) { last = E[i]; break } }
  const foesTotal = Array.isArray(log && log.enemy_squad) ? log.enemy_squad.length : (last ? last.hpB.length : 0)
  const foesDown = last ? last.hpB.filter(function (h) { return Number(h) <= 0 }).length : 0
  let fallT = null, firstBaseHit = null
  for (const e of E) {
    if (!e) continue
    if (fallT == null && idx >= 0 && Array.isArray(e.hpA) && e.hpA[idx] != null && Number(e.hpA[idx]) <= 0) fallT = Number(e.t)
    if (firstBaseHit == null && e.bA != null && baseMax && Number(e.bA) < baseMax) firstBaseHit = Number(e.t)
  }
  const c = (log && Array.isArray(log.contrib) && idx >= 0) ? log.contrib[idx] : null
  return {
    ticks: ticks, baseMax: baseMax,
    myBaseEnd: R.baseHpA != null ? Math.max(0, Math.floor(Number(R.baseHpA))) : null,
    enemyBaseEnd: R.baseHpB != null ? Math.max(0, Math.floor(Number(R.baseHpB))) : null,
    foesTotal: foesTotal, foesDown: foesDown,
    firstBaseHit: firstBaseHit,
    me: c ? { dealt: Number(c.dealt) || 0, alive: !!c.alive, auto: !!c.auto, mon: String(c.mon || ''), sprite: String(c.sprite || '') } : null,
    fallFrac: (fallT != null && ticks > 0) ? Math.min(1, fallT / ticks) : null
  }
}

// ヒントを えらぶ（多くて 2つ）。文は 子ども むけ。
export function defReviewTips(result, f, pi, sameStreak) {
  const tips = []
  const me = f.me || {}
  const lost = result !== 'win'
  const baseBroken = lost && f.myBaseEnd === 0
  if (me.auto) tips.push({ icon: '🙋', text: 'こんかいは「おまかせ出陣」だったよ。じぶんで モンスターと プログラムを えらんで 出陣すると、コインも ふえるよ。' })
  if (pi.empty) tips.push({ icon: '🧩', text: 'プログラムが まだ からっぽ。まずは おてほんの「🛡 きちが あぶなくなったら もどる」を 入れてみよう。', tpl: 1 })
  if (baseBroken && !pi.empty && !pi.allyBaseBelow) tips.push({ icon: '🏰', text: 'みかたの きちが こわされたよ。「もし みかたの基地が危ない なら → みかたの基地をまもる」を 入れると、もどって まもれるかも。', tpl: 1 })
  if (f.fallFrac != null && f.fallFrac < 0.4 && !pi.selfHpBelow) tips.push({ icon: '💧', text: 'はやめに たおれちゃった。「もし 自分のHPが少ない なら → みかたの基地をまもる」で さがると、ながく たたかえるよ。', tpl: 2 })
  if (pi.starter && !me.auto) tips.push({ icon: '✏️', text: 'プログラムが さいしょの おてほんの ままだよ。「もし」の 中みを 1つ かえたり、ブロックを 1つ 足したりして、きみだけの 作戦に してみよう。' })
  if (sameStreak >= 3 && !me.auto && !pi.starter) tips.push({ icon: '🔁', text: 'このプログラムで ' + sameStreak + '回 つづけて たたかったよ。1つだけ かえて、ためしバトルで くらべてみよう。' })
  if (lost && !pi.empty && !pi.lane && tips.length < 2) tips.push({ icon: '🛣', text: 'みちを えらぶ ブロック（ひだり・まん中・みぎ）を つかうと、てきが 来る みちで まちぶせ できるよ。' })
  if (!lost && tips.length < 2) tips.push({ icon: '🎉', text: 'かったね！ つぎは てきが 少し つよくなるよ。かった プログラムの どこが よかったか 考えて、もう1つ くふうを 足してみよう。' })
  if (!tips.length) tips.push({ icon: '🧪', text: 'ためしバトルで、ちがう プログラムを いくつか ためしてみよう。どれが ながく のこれるかな？' })
  return tips.slice(0, 2)
}

export async function defReview(env, userId, classId) {
  if (!userId || !classId) return { ok: true, none: true }
  const rr = await env.DB.prepare("SELECT event_key, result, log_json FROM defense_results WHERE class_id = ? ORDER BY resolved_at DESC LIMIT 1").bind(String(classId)).first()
  if (!rr) return { ok: true, none: true }
  let log = null
  try { log = JSON.parse(String(rr.log_json)) } catch (_e) { return { ok: true, none: true } }
  const ek = String(rr.event_key)
  // サーバの 決め方（def_resolve.ts）と 同じ ならびで 自分の 番号を さがす
  const us = await env.DB.prepare("SELECT user_id AS uid FROM defense_entries WHERE event_key=? AND class_id=? ORDER BY created_at ASC, user_id ASC LIMIT 200").bind(ek, String(classId)).all()
  const ids = ((us && us.results) || []).map(function (r) { return String(r.uid) })
  let idx = ids.indexOf(String(userId))
  if (!log || !Array.isArray(log.contrib) || ids.length !== log.contrib.length) idx = -1
  const f = defReviewFacts(log, idx)
  // 自分の プログラムと、おなじ プログラムが 何回 つづいたか（その回 から さかのぼる）
  let prog = null, sameStreak = 0
  try {
    const hs = await env.DB.prepare("SELECT event_key AS ek, json_extract(monster_json, '$.prog') AS pg, json_extract(monster_json, '$.auto') AS au FROM defense_entries WHERE user_id = ? AND class_id = ? AND event_key <= ? ORDER BY event_key DESC LIMIT 15").bind(String(userId), String(classId), ek).all()
    const rows = (hs && hs.results) || []
    if (rows.length && String(rows[0].ek) === ek) {
      try { prog = rows[0].pg ? JSON.parse(String(rows[0].pg)) : null } catch (_e) { prog = null }
      const key = String(rows[0].pg || '')
      for (const r of rows) { if (String(r.pg || '') === key) sameStreak++; else break }
    }
  } catch (_e) {}
  if (idx < 0 && !prog) return { ok: true, none: true, event_key: ek }
  const pi = defReviewProgInfo(prog)
  return {
    ok: true, event_key: ek, result: String(rr.result),
    facts: { foesTotal: f.foesTotal, foesDown: f.foesDown, baseMax: f.baseMax, myBaseEnd: f.myBaseEnd, enemyBaseEnd: f.enemyBaseEnd },
    me: f.me ? { mon: f.me.mon, sprite: f.me.sprite, dealt: f.me.dealt, alive: f.me.alive, auto: f.me.auto, fall: f.fallFrac == null ? null : (f.fallFrac < 0.34 ? 'early' : (f.fallFrac < 0.67 ? 'mid' : 'late')) } : null,
    prog: { blocks: pi.blocks, empty: pi.empty, same: sameStreak },
    tips: defReviewTips(String(rr.result), f, pi, sameStreak)
  }
}
