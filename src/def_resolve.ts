// __DEF_SERVER_RESOLVE_V1__ 自動生成ファイル（scripts/patch_def_server_resolve_v1.py）。手で編集しないこと。
// @ts-nocheck
/* eslint-disable */
import { defAutoBattleRT } from './def_engine'

const DEF_DEFAULT_PROG = [{ c: 'always', a: 'attackBase' }]

// public/defense2.js から機械的に抜き出した computeMVP（手で書き写していない）
function computeMVP(rep, entrants){
    try{
      var A = rep.teams && rep.teams.A ? rep.teams.A : []; var best=null;
      A.forEach(function(f,i){
        var dealt = (f.dmgDealt!=null)? f.dmgDealt : ((f.atk||0)*(f.alive?2:1));
        var ent = entrants && entrants[i] ? entrants[i] : null;
        var score = dealt + (f.alive?50:0);
        if(!best || score>best.score){ best={score:score, name:(ent&&ent.name)||f.name, sprite:f.sprite, mon:f.name}; }
      });
      return best;
    }catch(e){ return null; }
  }

// event_key から seed を作る（resolve の照合が使っているものと同じ式）
function defFnv(x) {
  const s = String(x == null ? '' : x)
  let h = 2166136261 >>> 0
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) }
  return h >>> 0
}
export function defSeedFromKey(k) { return ((defFnv(k) ^ 0x9e3779b9) >>> 0) }

// 番人：1件でも spd / skills を欠いていたら null を返す。
// 劣化した条件（spd=10 固定・こうげき1本）で勝敗が確定することを原理的に起こさないため。
export function defEntryOk(m) {
  if (!m || typeof m !== 'object') return false
  if (!Number.isFinite(Number(m.spd)) || Number(m.spd) <= 0) return false
  if (!Array.isArray(m.skills) || m.skills.length === 0) return false
  if (!Number.isFinite(Number(m.hp)) || Number(m.hp) <= 0) return false
  if (!Number.isFinite(Number(m.atk)) || !Number.isFinite(Number(m.def))) return false
  if (m.elementType == null) return false
  return true
}

// __DEF_MVP_V1__ 部門べつの ベスト3。
//   せめ  ＝ あたえたダメージ ÷ 自分のこうげき力（自分のモンスターの力を 何回ぶん はたらかせたか）
//   まもり ＝ うけたダメージ ÷ 自分のたいりょく（どれだけの わりあいを たえたか）
//   ねばり ＝ たおれた tick ÷ さいごの tick（さいごまで のこれば 満点）
// どれも 生の数字ではなく 自分の力で わった値なので、レベルの差が そのまま順位にならない。
// 部門が成り立つのは「0でない子が3人以上」かつ「値が2種類以上」のときだけ。
// 成り立たない部門は その日は出さない（みんな同じ値なのに順位をつける＝うその表彰は しない）。
const DEF_MVP_CATS = [
  { key: 'seme',   label: 'はたらいた かず' },
  { key: 'nebari', label: 'のこった じかん' },
  { key: 'mamori', label: 'たえた わりあい' }
]
// 1位40／2位30／3位20。同点は全員入賞。金額はここだけで決める。
const DEF_MVP_COINS = [0, 40, 30, 20]
const DEF_MVP_MIN_ENTRIES = 3

function defMvpRound(v) { return Math.round((Number(v) || 0) * 1000000) / 1000000 }

function defMvpRank(vals) {
  const nz = vals.filter(function (v) { return v > 0 }).length
  const uniq = []
  for (const v of vals) { if (uniq.indexOf(v) < 0) uniq.push(v) }
  if (nz < 3 || uniq.length < 2) return null
  const top = uniq.slice().sort(function (a, b) { return b - a }).slice(0, 3)
  return vals.map(function (v) {
    const p = top.indexOf(v)
    return (v > 0 && p >= 0) ? (p + 1) : 0
  })
}

function defMvpAwards(rep, ents) {
  try {
    const A = (rep && rep.teams && rep.teams.A) ? rep.teams.A : []
    const n = ents.length
    // 並びがずれていたら何も出さない（だれの きろくか 分からなくなるため）。
    if (!n || A.length !== n) return null
    const evs = (rep && rep.events) ? rep.events : []
    const last = Math.max(1, Math.floor(Number(rep.ticks) || 0))
    const dealt = [], taken = [], fell = []
    for (let i = 0; i < n; i++) { dealt.push(0); taken.push(0); fell.push(null) }
    for (const e of evs) {
      if (!e) continue
      const d = Math.max(0, Math.round(Number(e.dmg) || 0))
      if (e.side === 'A' && !e.miss) {
        const i = Math.floor(Number(e.ai))
        if (Number.isFinite(i) && i >= 0 && i < n) dealt[i] += d
      } else if (e.side === 'B') {
        const i = Math.floor(Number(e.ti))
        if (Number.isFinite(i) && i >= 0 && i < n) {
          taken[i] += d
          if (e.dead && fell[i] === null) fell[i] = Math.max(0, Math.floor(Number(e.t) || 0))
        }
      }
    }
    const vals = { seme: [], mamori: [], nebari: [] }
    for (let i = 0; i < n; i++) {
      const atk = Math.max(1, Number(A[i] && A[i].atk) || 1)
      const mhp = Math.max(1, Number(A[i] && A[i].maxHp) || 1)
      vals.seme.push(defMvpRound(dealt[i] / atk))
      vals.mamori.push(defMvpRound(taken[i] / mhp))
      vals.nebari.push(defMvpRound((fell[i] === null ? last : fell[i]) / last))
    }
    const few = (n < DEF_MVP_MIN_ENTRIES)
    const cats = [], ledger = []
    for (const cat of DEF_MVP_CATS) {
      const v = vals[cat.key]
      const places = few ? null : defMvpRank(v)
      const top = []
      for (let i = 0; i < n; i++) {
        const place = places ? places[i] : 0
        const coins = (place >= 1 && place <= 3) ? DEF_MVP_COINS[place] : 0
        ledger.push({ uid: ents[i].uid, category: cat.key, place: place, coins: coins, value: v[i], ok: places ? 1 : 0 })
        if (coins > 0) top.push({ place: place, name: ents[i].nm, sprite: (ents[i].m && ents[i].m.sprite) || '', mon: (ents[i].m && ents[i].m.name) || '', value: v[i], coins: coins })
      }
      top.sort(function (a, b) { return a.place - b.place })
      cats.push({ key: cat.key, label: cat.label, ok: places ? true : false, top: top })
    }
    return {
      awards: { v: 1, ticks: last, cats: cats },
      ledger: ledger,
      dealt: dealt,
      alive: fell.map(function (x) { return x === null })
    }
  } catch (_e) { return null }
}

export async function defServerResolve(env, st, classId, enemies) {
  try {
    if (!st || !st.eventKey || !classId) return null
    if (!Array.isArray(enemies) || !enemies.length) return null
    const rows = await env.DB.prepare(
      "SELECT de.monster_json AS mj, de.strategy AS sg, u.name AS nm, de.user_id AS uid FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC LIMIT 200"
    ).bind(String(st.eventKey), String(classId)).all()
    const list = (rows && rows.results) || []
    if (!list.length) return null
    const ents = []
    for (const r of list) {
      let m = null
      try { m = JSON.parse(String(r.mj)) } catch (_e) { return null }
      if (!defEntryOk(m)) return null
      ents.push({ m: m, nm: String(r.nm || ''), sg: String(r.sg || ''), uid: String(r.uid || '') })
    }
    const specsA = ents.map(function (e) {
      return {
        level: Number(e.m.level || 1),
        strategy: e.m.strategy || e.sg || 'balance',
        raw: {
          name: e.m.name, sprite: e.m.sprite,
          hp: Number(e.m.hp), atk: Number(e.m.atk), def: Number(e.m.def), spd: Number(e.m.spd),
          buff: e.m.buff, skillPow: e.m.skillPow,
          elementType: e.m.elementType, skills: e.m.skills
        }
      }
    })
    const programsA = ents.map(function (e) {
      return (Array.isArray(e.m.prog) && e.m.prog.length) ? e.m.prog : DEF_DEFAULT_PROG
    })
    const specsB = enemies.map(function (en) {
      return { raw: { name: en.name, sprite: en.sprite, hp: en.hp, atk: en.atk, def: en.def, buff: en.buff, skillPow: en.skillPow, elementType: en.elementType, skills: en.skills }, strategy: 'attack' }
    })
    const seed = defSeedFromKey(st.eventKey)
    const rep = defAutoBattleRT(specsA, specsB, {
      bases: true, lanes: true, laneCount: 3, seed: seed, program: true,
      programsA: programsA, programB: DEF_DEFAULT_PROG,
      forts: false, tactics: true, contact: true
    })
    if (!rep || (rep.winner !== 'A' && rep.winner !== 'B')) return null
    if (rep.baseHpA == null || !Number.isFinite(Number(rep.baseHpA))) return null
    const result = (rep.winner === 'A') ? 'win' : 'lose'
    const baseHpEnd = Math.max(0, Math.floor(Number(rep.baseHpA)))
    // __DEF_MVP_V1__ 部門べつの きろく。events から そのまま かぞえる。
    let _mv: any = null
    try { _mv = defMvpAwards(rep, ents) } catch (_e) { _mv = null }
    const _mvA0 = (rep.teams && rep.teams.A) ? rep.teams.A : []
    // __DEF_MVP_V1__ もとの計算は f.dmgDealt / f.alive を見ていたが、どちらも teams には入っていない。
    //                events からかぞえた ほんとうの数字を入れてから えらぶ。
    const _mvRep = (_mv && _mv.dealt) ? { teams: { A: _mvA0.map(function (f: any, i: number) {
      const o: any = {}
      for (const p in f) o[p] = f[p]
      o.dmgDealt = _mv.dealt[i]
      o.alive = !!_mv.alive[i]
      return o
    }) } } : rep
    let mvp = null
    try { mvp = computeMVP(_mvRep, ents.map(function (e) { return { name: e.nm } })) } catch (_e) { mvp = null }
    const teamA = (rep.teams && rep.teams.A) ? rep.teams.A : []
    const log = {
      v: 2, seed: seed, enemy_squad: enemies,
      entrants: ents.map(function (e) {
        return { name: e.nm, sprite: e.m.sprite || '', mon: e.m.name || '', prog: e.m.prog || null }
      }),
      mvp: mvp,
      awards: (_mv && _mv.awards) ? _mv.awards : null,
      contrib: teamA.map(function (f, i) {
        // __DEF_MVP_V1__ dealt は events から かぞえた あたえたダメージ。alive は たおれた記録が無いこと。
        const dealt = (_mv && _mv.dealt) ? _mv.dealt[i] : 0
        const live = (_mv && _mv.alive) ? !!_mv.alive[i] : false
        const e = ents[i] || { m: {}, nm: null }
        return {
          name: e.nm || f.name,
          sprite: (e.m && e.m.sprite) || f.sprite || '',
          mon: (e.m && e.m.name) || f.name,
          dealt: Math.round(dealt || 0), alive: live
        }
      }),
      enemyTotalHp: enemies.reduce(function (s, en) { return s + (en.hp || 0) }, 0),
      replay: rep,
      server: true
    }
    const logJson = JSON.stringify(log)
    // 切り詰めると壊れた JSON を保存してしまうので、大きすぎたら諦めて今まで通りに流す
    if (!logJson || logJson.length > 900000) return null
    return { result: result, baseHpEnd: baseHpEnd, logJson: logJson, seed: seed, entries: ents.length, mvpLedger: (_mv && _mv.ledger) ? _mv.ledger : null }
  } catch (_e) {
    return null
  }
}
