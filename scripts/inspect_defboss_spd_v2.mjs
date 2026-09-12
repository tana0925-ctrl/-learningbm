// __DEFBOSS_SPD_MEASURE_V2__ 読むだけの しらべもの。1文字も 書きこまない。
//   本番の エンジン（src/def_engine.ts）・段の式（src/def_stage.ts）・図鑑（src/def_dex.ts）を
//   そのまま 使って 勝率を かぞえる。src/index.tsx からは 敵の素 と ボスの表 を
//   読みとるだけ（手で 書き写さない）。
//
//   環境変数
//     N       … 1マスあたりの 試行回数（既定 100）
//     PART    … all（既定）／ main（A だけ）／ probe（B・C・D だけ）
//     ROSTER  … top（既定・図鑑で いちばん つよい 22体）／ mid ／ rand
//
//   アンカーが 合わなければ 1件も 測らずに exit 1（fail-closed）。
import fs from 'node:fs'
import { defAutoBattleRT } from '../src/def_engine'
import { defStageEnemies } from '../src/def_stage'
import { defDexEntry, DEF_DEX_COUNT } from '../src/def_dex'

const N = Math.max(1, Math.min(2000, parseInt(process.env.N || '100', 10) || 100))
const PART = String(process.env.PART || 'all')
const ROSTER_MODE = String(process.env.ROSTER || 'top')

function die(msg) {
  console.error('NG: ' + msg)
  process.exit(1)
}

const SRC = fs.readFileSync('src/index.tsx', 'utf8')
const STG = fs.readFileSync('src/def_stage.ts', 'utf8')
const RSV = fs.readFileSync('src/def_resolve.ts', 'utf8')
const D2 = fs.readFileSync('public/defense2.js', 'utf8')

function once(label, text, hay) {
  const c = hay.split(text).length - 1
  if (c !== 1) die('アンカー ' + label + ' が ' + c + ' 件（1件でないと 進めない）')
}

function atLeast(label, text, hay, want) {
  const c = hay.split(text).length - 1
  if (c < want) die('アンカー ' + label + ' が ' + c + ' 件（' + want + ' 件いじょう ほしい）')
}

function literal(marker, closer, label) {
  once(label + 'のしるし', marker, SRC)
  const i = SRC.indexOf(marker)
  const open = i + marker.length - 1
  const j = SRC.indexOf('\n' + closer, open)
  if (j < 0) die(label + ' の とじかっこが 見つからない')
  return SRC.slice(open, j + 1 + closer.length)
}

const ENEMY_LIT = literal('const DEFENSE_ENEMIES = [', ']', '敵の素')
const BOSS_LIT = literal('const DEFBOSS_FACE: any = {', '}', 'ボスの表')

let DEFENSE_ENEMIES, DEFBOSS_FACE
try {
  DEFENSE_ENEMIES = eval('(' + ENEMY_LIT + ')')
  DEFBOSS_FACE = eval('(' + BOSS_LIT + ')')
} catch (e) {
  die('敵の素／ボスの表 を 読みとれなかった: ' + e.message)
}

if (!Array.isArray(DEFENSE_ENEMIES) || DEFENSE_ENEMIES.length !== 8) die('敵は 8体でないと 進めない')
const LAST = DEFENSE_ENEMIES[DEFENSE_ENEMIES.length - 1]
if (LAST.name !== 'まおう' || LAST.hp !== 520 || LAST.atk !== 60 || LAST.def !== 24) die('まおうの素の値が ちがう')
once('基地HP 380', 'DEFENSE_BASE_HP = 380', SRC)
once('敵の spd 上限 70', 'Math.min(70, 35 + 5 * k)', STG)
once('本番の opts（前半）', 'bases: true, lanes: true, laneCount: 3, seed: seed, program: true', RSV)
once('本番の opts（後半）', 'forts: false, tactics: true, contact: true, foeLaneMix: true', RSV)

const BKEYS = Object.keys(DEFBOSS_FACE)
if (BKEYS.join(',') !== '12,15,18,21') die('ボスの段が 12,15,18,21 でない（' + BKEYS.join(',') + '）')
for (const k of BKEYS) {
  if (Number(DEFBOSS_FACE[k].spdMul) !== 1.15) die('段' + k + ' の spdMul が 1.15 でない')
}
for (const k of ['12', '15', '18']) {
  if (Number(DEFBOSS_FACE[k].hpMul) !== 1.3) die('段' + k + ' の hpMul が 1.3 でない')
}
if (Number(DEFBOSS_FACE['21'].hpMul) !== 1) die('段21 の hpMul が 1 でない')
atLeast('spd の番兵', '__DEFBOSS_SPD_V1__', SRC, 2)

for (const [label, t] of [
  ['hpMul の読み', 'const mul = Number(b.hpMul) || 1'],
  ['hp のかけ算', 'const hp = Math.round(Number(last.hp || 0) * mul)'],
  ['spdMul の読み', 'const smul = Number(b.spdMul)'],
  ['spd のかけ算', 'const spd = Math.round(Number(last.spd || 0) * smul)'],
  ['最後の1体だけ さしかえ', 'out[out.length - 1] = o']
]) once(label, t, SRC)

for (const [label, t] of [
  ['⚔ まっすぐ', "{ t: 'a', a: 'attackBase' }"],
  ['⚔ ちかく', "{ t: 'a', a: 'attackNearest' }"],
  ['🛡 きち', "c: 'allyBaseBelow', cn: 40"],
  ['💧 HP', "c: 'selfHpBelow', cn: 35"],
  ['🛣 まん中', "{ t: 'a', a: 'laneC' }"]
]) atLeast('お手本 ' + label, t, D2, 1)

console.log('アンカー OK / 敵 8体 / ボス 4体 / spdMul 1.15 / spd上限 70 / N=' + N + ' / PART=' + PART + ' / ROSTER=' + ROSTER_MODE)

function bossApply(squad, stage, table) {
  if (!Array.isArray(squad) || !squad.length) return squad
  const n = Math.floor(Number(stage))
  if (!Number.isFinite(n)) return squad
  const b = table[String(n)]
  if (!b) return squad
  const out = squad.slice()
  const last = out[out.length - 1]
  if (!last) return squad
  const o = {}
  for (const p in last) o[p] = last[p]
  o.name = String(b.name)
  o.sprite = String(b.sprite)
  const mul = Number(b.hpMul) || 1
  const hp = Math.round(Number(last.hp || 0) * mul)
  o.hp = (Number.isFinite(hp) && hp > 0) ? hp : Math.floor(Number(last.hp || 0))
  const smul = Number(b.spdMul)
  if (Number.isFinite(smul) && smul > 0) {
    const spd = Math.round(Number(last.spd || 0) * smul)
    if (Number.isFinite(spd) && spd > 0) o.spd = spd
  }
  o.boss = true
  out[out.length - 1] = o
  return out
}

const NO_SPD = {}
for (const k of BKEYS) {
  const o = {}
  for (const p in DEFBOSS_FACE[k]) if (p !== 'spdMul') o[p] = DEFBOSS_FACE[k][p]
  NO_SPD[k] = o
}

const NA = 22
function power(m) { return Number(m.hp) + 10 * Number(m.atk) + 6 * Number(m.def) + 4 * Number(m.spd) }
function mkRoster(seed) {
  const all = []
  for (let id = 1; id <= DEF_DEX_COUNT; id++) { const m = defDexEntry(id); if (m) all.push(m) }
  if (all.length < NA) die('図鑑が 読めない（' + all.length + '体）')
  const sorted = all.slice().sort((a, b) => power(b) - power(a))
  if (ROSTER_MODE === 'top') return sorted.slice(0, NA)
  if (ROSTER_MODE === 'mid') return sorted.slice(Math.floor(all.length * 0.25), Math.floor(all.length * 0.25) + NA)
  let x = seed >>> 0 || 1
  const r = () => { x ^= x << 13; x >>>= 0; x ^= x >> 17; x ^= x << 5; x >>>= 0; return x / 4294967296 }
  const list = []
  let guard = 0
  while (list.length < NA && guard++ < 20000) {
    const m = defDexEntry(1 + Math.floor(r() * DEF_DEX_COUNT))
    if (m) list.push(m)
  }
  if (list.length !== NA) die('名簿が ' + list.length + '人')
  return list
}
const ROSTER = mkRoster(20260914)
console.log('名簿 22体（図鑑 レベル50）: ' + ROSTER.map(m => m.id).join(','))
console.log('  つよさの めやす hp/atk/def/spd の へいきん: ' +
  Math.round(ROSTER.reduce((s, m) => s + m.hp, 0) / NA) + ' / ' +
  Math.round(ROSTER.reduce((s, m) => s + m.atk, 0) / NA) + ' / ' +
  Math.round(ROSTER.reduce((s, m) => s + m.def, 0) / NA) + ' / ' +
  Math.round(ROSTER.reduce((s, m) => s + m.spd, 0) / NA))

const SPECS_A = ROSTER.map(m => ({
  level: Number(m.level || 1),
  strategy: 'balance',
  raw: {
    name: m.name, sprite: m.sprite,
    hp: Number(m.hp), atk: Number(m.atk), def: Number(m.def), spd: Number(m.spd),
    buff: m.buff, skillPow: m.skillPow, elementType: m.elementType, skills: m.skills
  }
}))

const PROG_B = [{ c: 'always', a: 'attackBase' }]
const P_DEFAULT = [{ t: 'a', a: 'attackBase' }]
const P_NEAR = [{ t: 'a', a: 'attackNearest' }]
const P_SHIELD = [{ t: 'if', c: 'allyBaseBelow', cn: 40, body: [{ t: 'a', a: 'returnBase' }], els: [{ t: 'a', a: 'attackBase' }] }]
const P_DROP = [{ t: 'if', c: 'selfHpBelow', cn: 35, body: [{ t: 'a', a: 'returnBase' }], els: [{ t: 'a', a: 'attackBase' }] }]
const P_LANEC = [{ t: 'a', a: 'laneC' }]
const pHp = (cn) => [{ t: 'if', c: 'selfHpBelow', cn: cn, body: [{ t: 'a', a: 'returnBase' }], els: [{ t: 'a', a: 'attackBase' }] }]
const pBase = (cn) => [{ t: 'if', c: 'allyBaseBelow', cn: cn, body: [{ t: 'a', a: 'returnBase' }], els: [{ t: 'a', a: 'attackBase' }] }]

function seedOf(i) { return (2654435761 * (i + 1)) >>> 0 }

function one(stage, prog, table, seed) {
  const squad = bossApply(defStageEnemies(DEFENSE_ENEMIES, stage, NA), stage, table)
  const specsB = squad.map(en => ({
    raw: {
      name: en.name, sprite: en.sprite, hp: en.hp, atk: en.atk, def: en.def, spd: en.spd,
      buff: en.buff, skillPow: en.skillPow, elementType: en.elementType, skills: en.skills
    },
    strategy: 'attack'
  }))
  const rep = defAutoBattleRT(SPECS_A, specsB, {
    bases: true, lanes: true, laneCount: 3, seed: seed, program: true,
    programsA: SPECS_A.map(() => prog), programB: PROG_B,
    forts: false, tactics: true, contact: true, foeLaneMix: true
  })
  if (!rep || (rep.winner !== 'A' && rep.winner !== 'B')) die('エンジンが 勝敗を 返さなかった（段' + stage + '）')
  if (rep.baseHpA == null || !Number.isFinite(Number(rep.baseHpA))) die('基地HP が 返ってこない（段' + stage + '）')
  return { win: rep.winner === 'A', base: Number(rep.baseHpA), ticks: Number(rep.ticks) }
}

function cell(stage, prog, table) {
  let w = 0, baseHit = 0, baseZero = 0, mid = 0
  const sig = []
  for (let i = 0; i < N; i++) {
    const r = one(stage, prog, table, seedOf(i))
    if (r.win) w++
    if (r.base < 380) baseHit++
    if (r.base <= 0) baseZero++
    if (r.base > 0 && r.base < 380) mid++
    sig.push((r.win ? 'W' : 'L') + r.base + '/' + r.ticks)
  }
  return { win: w, pct: Math.round(w * 1000 / N) / 10, baseHit, baseZero, mid, sig: sig.join('|') }
}

const STAGES = [12, 15, 18, 21]
const t0 = Date.now()

if (PART === 'all' || PART === 'main') {
  console.log('')
  console.log('===== A) ボスの spd ×1.15 あり／なし（n=' + NA + '人・各 ' + N + '回）=====')
  console.log('段\tspd\t既定 勝ち\t⚔ちかく 勝ち\tさ')
  for (const st of STAGES) {
    for (const [tag, tbl] of [['なし(1.00)', NO_SPD], ['×1.15', DEFBOSS_FACE]]) {
      const a = cell(st, P_DEFAULT, tbl)
      const b = cell(st, P_NEAR, tbl)
      console.log(st + '\t' + tag + '\t' + a.win + '/' + N + ' (' + a.pct + '%)\t' +
        b.win + '/' + N + ' (' + b.pct + '%)\t' + (Math.round((b.pct - a.pct) * 10) / 10) + 'pt')
    }
  }
  console.log('（メモ）ボスの spd: 段8いじょうは 素が 70、×1.15 で ' + Math.round(70 * 1.15) + '。ほかの 7体は 70 のまま。')
}

if (PART === 'all' || PART === 'probe') {
  console.log('')
  console.log('===== B) お手本ごとの 勝ち数（いまの 本番・各 ' + N + '回）=====')
  const NAMES = [
    ['既定 ⚔まっすぐ', P_DEFAULT],
    ['⚔ ちかく', P_NEAR],
    ['🛡 きち<40', P_SHIELD],
    ['💧 HP<35', P_DROP],
    ['🛣 まん中', P_LANEC]
  ]
  const base = {}
  console.log('段\t' + NAMES.map(x => x[0]).join('\t'))
  for (const st of STAGES) {
    const row = []
    for (let z = 0; z < NAMES.length; z++) {
      const c = cell(st, NAMES[z][1], DEFBOSS_FACE)
      if (z === 0) { base[st] = c; row.push(c.win + '/' + N); continue }
      row.push(c.win + '/' + N + (c.sig === base[st].sig ? ' [既定と 完全同一]' : ' [ちがう戦あり]'))
    }
    console.log(st + '\t' + row.join('\t'))
  }

  console.log('')
  console.log('===== D) 基地は そもそも「あぶない」状態に なるのか（既定・各 ' + N + '回）=====')
  console.log('段\t勝ち\t基地に 傷\t基地 0\t0でも 満タンでもない戦（＝🛡が 効きうる戦）\t負け方(基地0 / 全滅)')
  for (const st of [1, 3, 6, 9, 12, 15, 18, 21]) {
    const c = cell(st, P_DEFAULT, DEFBOSS_FACE)
    console.log(st + '\t' + c.win + '/' + N + '\t' + c.baseHit + '\t' + c.baseZero + '\t' + c.mid + '\t' + c.baseZero + ' / ' + (N - c.win - c.baseZero))
  }
  console.log('（メモ）敵1体の こうげき力（段べつ・素 60 の まおう）: ' +
    [12, 15, 18, 21].map(st => st + '段=' + defStageEnemies(DEFENSE_ENEMIES, st, NA)[7].atk).join(' / ') +
    '。基地HP は 380。')

  console.log('')
  console.log('===== C) しきい値を 上げると 生き返るか =====')
  console.log('（💧 selfHpBelow）段\t35(いま)\t50\t70\t90\t101(いつも真)')
  for (const st of STAGES) {
    console.log(st + '\t' + [35, 50, 70, 90, 101].map(cn => cell(st, pHp(cn), DEFBOSS_FACE).win + '/' + N).join('\t'))
  }
  console.log('（🛡 allyBaseBelow）段\t40(いま)\t70\t90\t101(いつも真)')
  for (const st of STAGES) {
    console.log(st + '\t' + [40, 70, 90, 101].map(cn => cell(st, pBase(cn), DEFBOSS_FACE).win + '/' + N).join('\t'))
  }
  console.log('※ 101 は「いつも 真」。ここが 既定と 変わるなら、if の しくみ じたいは 動いている。')
}

console.log('')
console.log('かかった時間: ' + Math.round((Date.now() - t0) / 1000) + ' 秒')
console.log('OK: 読むだけで おわり。1つも 書きこんでいない。')
