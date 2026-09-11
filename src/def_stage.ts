// DEF_STAGE_V2 ステージに応じて敵を強くする純関数だけを置くファイル。
// 敵の体数は絶対に増やさない（エンジンは毎tick全員×全員を見るので体数はCPUに二乗で効く）。
// ステージ1の素は src/index.tsx の DEFENSE_ENEMIES。ここでは受け取るだけで、元の配列には触らない。
// @ts-nocheck
/* eslint-disable */

export const DEF_STAGE_MAX = 10

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
export function defStageEnemies(base, stage) {
  if (!Array.isArray(base)) return []
  const k = defStageClamp(stage) - 1
  const u = Math.pow(k / (DEF_STAGE_MAX - 1), 2.2)
  return base.map(function (e) {
    const o = {}
    for (const p in e) o[p] = e[p]
    o.hp = Math.round(Number(e.hp || 0) * (1 + 25 * u))
    o.atk = Math.round(Number(e.atk || 0) * (1 + 19 * u))
    o.def = Math.round(Number(e.def || 0) * (1 + 6 * u))
    o.skillPow = Math.round(Number(e.skillPow || 10) * (1 + 18 * u))
    if (k > 0) o.spd = Math.round(10 + 230 * u)
    return o
  })
}

