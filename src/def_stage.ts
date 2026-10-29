// DEF_STAGE_V2 ステージに応じて敵を強くする純関数だけを置くファイル。
// 敵の体数は絶対に増やさない（エンジンは毎tick全員×全員を見るので体数はCPUに二乗で効く）。
// ステージ1の素は src/index.tsx の DEFENSE_ENEMIES。ここでは受け取るだけで、元の配列には触らない。
// @ts-nocheck
/* eslint-disable */

export const DEF_STAGE_MAX = 30

// 1 〜 DEF_STAGE_MAX に丸める。壊れた値は 1 とみなす。
export function defStageClamp(stage) {
  const n = Math.floor(Number(stage))
  if (!Number.isFinite(n) || n < 1) return 1
  return n > DEF_STAGE_MAX ? DEF_STAGE_MAX : n
}

// base（ステージ1の素）のコピーに倍率をかけた新しい配列を返す。base は書き換えない。
//   DEF_STAGE_V3_CURVE 倍率は u（0〜1）で効かせる。上の段ほど急に強くなる。
//   いちばん下の段は u が 0 なので素のまま（spd も足さない）。
//   hp       いちばん上で 26 倍
//   atk      いちばん上で 20 倍
//   def      いちばん上で 7 倍
//   skillPow いちばん上で 19 倍
//   spd      10 から 240 まで（速いほど手数が増える）
export function defStageEnemies(base, stage, n) {
  if (!Array.isArray(base)) return []
  const k = defStageClamp(stage) - 1
  // DEF_STAGE_V5 __DEFSTAGE_30_V1__ __DEFSTAGE_N_V1__ 段の強さは 段だけで きまる。
  //   クラス全員が 出るので 人数は ほぼ 一定。人数で わりつけると 友だちを さそうほど
  //   てきが 強くなり「みんなで やれば 勝てる」と 逆に なる。n は 受け取るが つかわない。
  //   u は 1段 1.12 倍きざみ。表を やめて 式に したので 段を いくつ ふやしても つづく。
  //   ステージ1 は u = 0（素のまま）。2 で 0.24、10 で 約0.59、30 で 約5.73。
  //   てきの はやさ も 段で 少しずつ 上げる（1 は 10 のまま、2 で 40、8 いこう 70）。
  //   はやさが 10 のままだと よこの道の てきが 基地に とどかず、
  //   みんなを 1つの道に あつめるだけが いつも 最善に なってしまう。
  const _dsSpd = (k <= 0) ? 10 : Math.min(70, 35 + 5 * k)
  // __DEFSTAGE_SOFT_V1__ 1.12倍の かけ算だと 子どもの そだち（たし算）が おいつけない。
  //   ステージ20 までは 今までと おなじ。21 から上は 1段 1.04倍に ゆるめる（24 で u 約2.16、30 で 約2.73）。
  const u = (k <= 0) ? 0 : (k <= 19 ? 0.24 * Math.pow(1.12, k - 1) : 0.24 * Math.pow(1.12, 18) * Math.pow(1.04, k - 19))
  return base.map(function (e) {
    const o = {}
    for (const p in e) o[p] = e[p]
    o.hp = Math.round(Number(e.hp || 0) * (1 + 25 * u))
    o.atk = Math.round(Number(e.atk || 0) * (1 + 19 * u))
    o.def = Math.round(Number(e.def || 0) * (1 + 6 * u))
    o.skillPow = Math.round(Number(e.skillPow || 10) * (1 + 18 * u))
    o.spd = _dsSpd
    return o
  })
}


// __DEFSTAGE_DOWN_V1__ 負けたとき：いまの ステージに なってから 3回 つづけて 負けたら 1つ 下げる。
//   defense_stage.updated_at（上がった/下がった時刻）より あとの 負けを かぞえる。勝つと updated_at が
//   かわるので「つづけて」に なる。下げたら updated_at も かわるので また 3回から かぞえなおし。
//   読んだ ステージを 条件に 入れて（楽観ロック）、同じ 負けで 2回 下げない。ステージ1より 下げない。
export const DEF_STAGE_DOWN_AFTER = 3
export async function defStageDownIfLosing(env, classId, stage) {
  try {
    const s = Math.floor(Number(stage))
    if (!classId || !Number.isFinite(s) || s <= 1) return false
    const r = await env.DB.prepare("SELECT COUNT(*) AS c FROM defense_results WHERE class_id = ? AND result = 'lose' AND resolved_at > (SELECT updated_at FROM defense_stage WHERE class_id = ?)").bind(String(classId), String(classId)).first()
    const n = Number(r && r.c)
    if (!Number.isFinite(n) || n < DEF_STAGE_DOWN_AFTER) return false
    const dn = await env.DB.prepare("UPDATE defense_stage SET stage = stage - 1, updated_at = datetime('now') WHERE class_id = ? AND stage = ?").bind(String(classId), s).run()
    return !!(dn && dn.meta && Number(dn.meta.changes || 0) === 1)
  } catch (_e) { return false }
}
