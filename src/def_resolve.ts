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
function defEntryOk(m) {
  if (!m || typeof m !== 'object') return false
  if (!Number.isFinite(Number(m.spd)) || Number(m.spd) <= 0) return false
  if (!Array.isArray(m.skills) || m.skills.length === 0) return false
  if (!Number.isFinite(Number(m.hp)) || Number(m.hp) <= 0) return false
  if (!Number.isFinite(Number(m.atk)) || !Number.isFinite(Number(m.def))) return false
  if (m.elementType == null) return false
  return true
}

export async function defServerResolve(env, st, classId, enemies) {
  try {
    if (!st || !st.eventKey || !classId) return null
    if (!Array.isArray(enemies) || !enemies.length) return null
    const rows = await env.DB.prepare(
      "SELECT de.monster_json AS mj, de.strategy AS sg, u.name AS nm FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC LIMIT 200"
    ).bind(String(st.eventKey), String(classId)).all()
    const list = (rows && rows.results) || []
    if (!list.length) return null
    const ents = []
    for (const r of list) {
      let m = null
      try { m = JSON.parse(String(r.mj)) } catch (_e) { return null }
      if (!defEntryOk(m)) return null
      ents.push({ m: m, nm: String(r.nm || ''), sg: String(r.sg || '') })
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
    let mvp = null
    try { mvp = computeMVP(rep, ents.map(function (e) { return { name: e.nm } })) } catch (_e) { mvp = null }
    const teamA = (rep.teams && rep.teams.A) ? rep.teams.A : []
    const log = {
      v: 2, seed: seed, enemy_squad: enemies,
      entrants: ents.map(function (e) {
        return { name: e.nm, sprite: e.m.sprite || '', mon: e.m.name || '', prog: e.m.prog || null }
      }),
      mvp: mvp,
      contrib: teamA.map(function (f, i) {
        const dealt = (f.dmgDealt != null) ? f.dmgDealt : ((f.atk || 0) * (f.alive ? 2 : 1))
        const e = ents[i] || { m: {}, nm: null }
        return {
          name: e.nm || f.name,
          sprite: (e.m && e.m.sprite) || f.sprite || '',
          mon: (e.m && e.m.name) || f.name,
          dealt: Math.round(dealt || 0), alive: !!f.alive
        }
      }),
      enemyTotalHp: enemies.reduce(function (s, en) { return s + (en.hp || 0) }, 0),
      replay: rep,
      server: true
    }
    const logJson = JSON.stringify(log)
    // 切り詰めると壊れた JSON を保存してしまうので、大きすぎたら諦めて今まで通りに流す
    if (!logJson || logJson.length > 900000) return null
    return { result: result, baseHpEnd: baseHpEnd, logJson: logJson, seed: seed, entries: ents.length }
  } catch (_e) {
    return null
  }
}
