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
//   hp  x (1 + 0.25 x (stage - 1))
//   atk x (1 + 0.12 x (stage - 1))
//   def + 2 x (stage - 1)
export function defStageEnemies(base, stage) {
  if (!Array.isArray(base)) return []
  const k = defStageClamp(stage) - 1
  return base.map(function (e) {
    const o = {}
    for (const p in e) o[p] = e[p]
    o.hp = Math.round(Number(e.hp || 0) * (1 + 0.25 * k))
    o.atk = Math.round(Number(e.atk || 0) * (1 + 0.12 * k))
    o.def = Number(e.def || 0) + 2 * k
    return o
  })
}

