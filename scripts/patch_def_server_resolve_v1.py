#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __DEF_SERVER_RESOLVE_V1__
# 防衛戦の勝敗をサーバで確定させる。
#   - そのイベントの全エントリが spd と skills を持っているときだけサーバ計算（番人・fail-closed）
#   - 1件でも欠けていたら、これまで通りクライアントの申告で流す（__DEF_RESOLVE_VERIFY_V1__ の4本はそのまま）
#   - すでに結果があるなら計算を起こさずに already を返す（1クラス1回）
#   - .replace() のチェーンは 72 件のまま。public/index.html / public/defense2.js は書き換えない
#   - DDL は一切実行しない
import sys, io, os, re, hashlib

SRC  = 'src/index.tsx'
D2   = 'public/defense2.js'
ENG  = 'src/def_engine.ts'
OUT  = 'src/def_resolve.ts'
SENT = '__DEF_SERVER_RESOLVE_V1__'

BS = "app.get('/', async (c) => {"
BE = "app.get('/logout'"
EXPECT_CHAIN = 72

IMP_ANCHOR = "import { defAutoBattleRT, defTestRoster, DEF_ENGINE_SIG, DEF_ENGINE_BYTES } from './def_engine'"
IMP_NEW = (IMP_ANCHOR + "\n"
           "import { defServerResolve } from './def_resolve'")

INS_ANCHOR = "  const result = (String(body.result) === 'win') ? 'win' : 'lose'"

GUARD = ['__DEF_SNAP_SPDSKILLS_V1__', '__DEF_RESOLVE_VERIFY_V1__', '__AB_RAW_ELEM_SKILLS_V1__',
         '__DEF_SERVER_ENGINE_V1__', 'defAutoAdvanceV1', 'defense_standing', 'defense_carry_lock',
         'const DEFENSE_BASE_HP = 380',
         "'log_seed_mismatch'", "'log_replay_missing'", "'log_result_mismatch'",
         "'log_base_hp_mismatch'", 'retry: true', 'Number(_dvLog.v) === 2',
         'Number.isFinite(Number(_dvRep.baseHpA))']

INS_BLOCK = """  // __DEF_SERVER_RESOLVE_V1__ 勝敗はサーバで決める。
  // すでに結果があるなら、ここで打ち切る（戦闘を起こさない＝1クラス1回）。
  const _srvDone = await c.env.DB.prepare("SELECT 1 AS x FROM defense_results WHERE event_key=? AND class_id=? LIMIT 1").bind(st.eventKey, classId).first<any>()
  if (_srvDone) return c.json({ ok: true, already: true })
  // 全エントリが spd と skills を持っているときだけサーバで計算する。
  // 1件でも欠けていたら null が返る＝これまで通りクライアントの申告で流す（fail-closed）。
  const _srv = await defServerResolve(c.env, st, classId, DEFENSE_ENEMIES)
  if (_srv) {
    const _srvLock = await c.env.DB.prepare("INSERT OR IGNORE INTO defense_results (event_key, class_id, result, log_json, base_hp_end, resolved_at) VALUES (?,?,?,?,?,datetime('now'))").bind(st.eventKey, classId, _srv.result, _srv.logJson, _srv.baseHpEnd).run()
    if (!_srvLock.meta || _srvLock.meta.changes === 0) return c.json({ ok: true, already: true })
    if (_srv.result === 'win') {
      try {
        const _srvEs = await c.env.DB.prepare("SELECT user_id FROM defense_entries WHERE event_key=? AND class_id=?").bind(st.eventKey, classId).all<any>()
        for (const _srvR of ((_srvEs && _srvEs.results) || [])) {
          await c.env.DB.prepare("INSERT OR IGNORE INTO defense_rewards (event_key, class_id, user_id, coins, seen, created_at) VALUES (?,?,?,?,0,datetime('now'))").bind(st.eventKey, classId, String(_srvR.user_id), DEFENSE_WIN_COINS).run()
        }
      } catch (_e) {}
    }
    return c.json({ ok: true, resolved: true, result: _srv.result, server: true })
  }
"""


def die(msg):
    print('ABORT: ' + msg)
    sys.exit(1)


def scan_block(H, start, where):
    i = H.find('{', start)
    if i < 0:
        die('%s: opening brace not found' % where)
    d = 0
    j = i
    inS = None
    n = len(H)
    while j < n:
        c = H[j]
        if inS:
            if c == '\\':
                j += 2
                continue
            if c == inS:
                inS = None
            j += 1
            continue
        if c == '"' or c == "'" or c == '\u0060':
            inS = c
            j += 1
            continue
        if c == '{':
            d += 1
        elif c == '}':
            d -= 1
            if d == 0:
                return H[start:j + 1]
        j += 1
    die('%s: brace scan ran off the end' % where)


# ---------------- 読み込み ----------------
for p in (SRC, D2, ENG):
    if not os.path.exists(p):
        die('%s が無い' % p)

src = io.open(SRC, encoding='utf-8').read()
d2 = io.open(D2, encoding='utf-8').read()

if SENT in src and os.path.exists(OUT):
    print('ALREADY APPLIED (sentinel present) - no file touched')
    sys.exit(0)
if SENT in src or os.path.exists(OUT):
    die('中途半端に適用されている（番兵と %s が食い違う）' % OUT)

# ---------------- 事前チェック（1つでも落ちたら書かない） ----------------
if src.count(BS) != 1:
    die("app.get('/') アンカーが %d 件" % src.count(BS))
if src.count(BE) != 1:
    die("app.get('/logout') が %d 件" % src.count(BE))
st = src.find(BS)
en = src.find(BE)
if not (0 <= st < en):
    die('チェーン範囲が取れない')
chain = src[st:en].count('.replace(')
print('chain before = %d' % chain)
if chain != EXPECT_CHAIN:
    die('chain %d != %d' % (chain, EXPECT_CHAIN))

if src.count(IMP_ANCHOR) != 1:
    die('import アンカーが %d 件' % src.count(IMP_ANCHOR))
if src.count(INS_ANCHOR) != 1:
    die('挿入アンカーが %d 件（1件でないと危険）' % src.count(INS_ANCHOR))
if src.count('defServerResolve') != 0:
    die('defServerResolve がすでにある')
if src.count("app.post('/api/defense/resolve', async (c) => {") != 1:
    die('resolve ルートが 1 件でない')
if src.count('ensureDefenseTables') != 1:
    die('ensureDefenseTables の出現が %d 件（呼び出しは0件のまま）' % src.count('ensureDefenseTables'))
for g in GUARD:
    if g not in src:
        die('guard missing before: ' + g)
if d2.count('function computeMVP(') != 1:
    die('public/defense2.js の computeMVP が 1 件でない')

# ---------------- computeMVP を defense2.js から機械的に抜き出す ----------------
mvp = scan_block(d2, d2.index('function computeMVP('), 'computeMVP')
if not mvp.endswith('}'):
    die('computeMVP の末尾が } ではない')
if not (200 <= len(mvp) <= 4000):
    die('computeMVP のサイズが想定外（%d）' % len(mvp))
print('computeMVP = %d chars' % len(mvp))

# ---------------- src/def_resolve.ts を書く ----------------
ts = []
ts.append('// ' + SENT + ' 自動生成ファイル（scripts/patch_def_server_resolve_v1.py）。手で編集しないこと。')
ts.append('// @ts-nocheck')
ts.append('/* eslint-disable */')
ts.append("import { defAutoBattleRT } from './def_engine'")
ts.append('')
ts.append("const DEF_DEFAULT_PROG = [{ c: 'always', a: 'attackBase' }]")
ts.append('')
ts.append('// public/defense2.js から機械的に抜き出した computeMVP（手で書き写していない）')
ts.append(mvp)
ts.append('')
ts.append('// event_key から seed を作る（resolve の照合が使っているものと同じ式）')
ts.append('function defFnv(x) {')
ts.append("  const s = String(x == null ? '' : x)")
ts.append('  let h = 2166136261 >>> 0')
ts.append('  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619) }')
ts.append('  return h >>> 0')
ts.append('}')
ts.append('export function defSeedFromKey(k) { return ((defFnv(k) ^ 0x9e3779b9) >>> 0) }')
ts.append('')
ts.append('// 番人：1件でも spd / skills を欠いていたら null を返す。')
ts.append('// 劣化した条件（spd=10 固定・こうげき1本）で勝敗が確定することを原理的に起こさないため。')
ts.append('function defEntryOk(m) {')
ts.append("  if (!m || typeof m !== 'object') return false")
ts.append('  if (!Number.isFinite(Number(m.spd)) || Number(m.spd) <= 0) return false')
ts.append('  if (!Array.isArray(m.skills) || m.skills.length === 0) return false')
ts.append('  if (!Number.isFinite(Number(m.hp)) || Number(m.hp) <= 0) return false')
ts.append('  if (!Number.isFinite(Number(m.atk)) || !Number.isFinite(Number(m.def))) return false')
ts.append('  if (m.elementType == null) return false')
ts.append('  return true')
ts.append('}')
ts.append('')
ts.append('export async function defServerResolve(env, st, classId, enemies) {')
ts.append('  try {')
ts.append('    if (!st || !st.eventKey || !classId) return null')
ts.append('    if (!Array.isArray(enemies) || !enemies.length) return null')
ts.append('    const rows = await env.DB.prepare(')
ts.append('      "SELECT de.monster_json AS mj, de.strategy AS sg, u.name AS nm FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC LIMIT 200"')
ts.append('    ).bind(String(st.eventKey), String(classId)).all()')
ts.append('    const list = (rows && rows.results) || []')
ts.append('    if (!list.length) return null')
ts.append('    const ents = []')
ts.append('    for (const r of list) {')
ts.append('      let m = null')
ts.append('      try { m = JSON.parse(String(r.mj)) } catch (_e) { return null }')
ts.append('      if (!defEntryOk(m)) return null')
ts.append("      ents.push({ m: m, nm: String(r.nm || ''), sg: String(r.sg || '') })")
ts.append('    }')
ts.append('    const specsA = ents.map(function (e) {')
ts.append('      return {')
ts.append('        level: Number(e.m.level || 1),')
ts.append("        strategy: e.m.strategy || e.sg || 'balance',")
ts.append('        raw: {')
ts.append('          name: e.m.name, sprite: e.m.sprite,')
ts.append('          hp: Number(e.m.hp), atk: Number(e.m.atk), def: Number(e.m.def), spd: Number(e.m.spd),')
ts.append('          buff: e.m.buff, skillPow: e.m.skillPow,')
ts.append('          elementType: e.m.elementType, skills: e.m.skills')
ts.append('        }')
ts.append('      }')
ts.append('    })')
ts.append('    const programsA = ents.map(function (e) {')
ts.append('      return (Array.isArray(e.m.prog) && e.m.prog.length) ? e.m.prog : DEF_DEFAULT_PROG')
ts.append('    })')
ts.append('    const specsB = enemies.map(function (en) {')
ts.append('      return { raw: { name: en.name, sprite: en.sprite, hp: en.hp, atk: en.atk, def: en.def, buff: en.buff, skillPow: en.skillPow, elementType: en.elementType, skills: en.skills }, strategy: \'attack\' }')
ts.append('    })')
ts.append('    const seed = defSeedFromKey(st.eventKey)')
ts.append('    const rep = defAutoBattleRT(specsA, specsB, {')
ts.append('      bases: true, lanes: true, laneCount: 3, seed: seed, program: true,')
ts.append('      programsA: programsA, programB: DEF_DEFAULT_PROG,')
ts.append('      forts: false, tactics: true, contact: true')
ts.append('    })')
ts.append("    if (!rep || (rep.winner !== 'A' && rep.winner !== 'B')) return null")
ts.append('    if (rep.baseHpA == null || !Number.isFinite(Number(rep.baseHpA))) return null')
ts.append("    const result = (rep.winner === 'A') ? 'win' : 'lose'")
ts.append('    const baseHpEnd = Math.max(0, Math.floor(Number(rep.baseHpA)))')
ts.append('    let mvp = null')
ts.append('    try { mvp = computeMVP(rep, ents.map(function (e) { return { name: e.nm } })) } catch (_e) { mvp = null }')
ts.append('    const teamA = (rep.teams && rep.teams.A) ? rep.teams.A : []')
ts.append('    const log = {')
ts.append('      v: 2, seed: seed, enemy_squad: enemies,')
ts.append('      entrants: ents.map(function (e) {')
ts.append("        return { name: e.nm, sprite: e.m.sprite || '', mon: e.m.name || '', prog: e.m.prog || null }")
ts.append('      }),')
ts.append('      mvp: mvp,')
ts.append('      contrib: teamA.map(function (f, i) {')
ts.append('        const dealt = (f.dmgDealt != null) ? f.dmgDealt : ((f.atk || 0) * (f.alive ? 2 : 1))')
ts.append('        const e = ents[i] || { m: {}, nm: null }')
ts.append('        return {')
ts.append('          name: e.nm || f.name,')
ts.append("          sprite: (e.m && e.m.sprite) || f.sprite || '',")
ts.append('          mon: (e.m && e.m.name) || f.name,')
ts.append('          dealt: Math.round(dealt || 0), alive: !!f.alive')
ts.append('        }')
ts.append('      }),')
ts.append('      enemyTotalHp: enemies.reduce(function (s, en) { return s + (en.hp || 0) }, 0),')
ts.append('      replay: rep,')
ts.append('      server: true')
ts.append('    }')
ts.append('    const logJson = JSON.stringify(log)')
ts.append('    // 切り詰めると壊れた JSON を保存してしまうので、大きすぎたら諦めて今まで通りに流す')
ts.append('    if (!logJson || logJson.length > 900000) return null')
ts.append('    return { result: result, baseHpEnd: baseHpEnd, logJson: logJson, seed: seed, entries: ents.length }')
ts.append('  } catch (_e) {')
ts.append('    return null')
ts.append('  }')
ts.append('}')
ts.append('')
out_ts = '\n'.join(ts)

# ---------------- src/index.tsx を書き換える ----------------
out_src = src.replace(IMP_ANCHOR, IMP_NEW, 1)
out_src = out_src.replace(INS_ANCHOR, INS_BLOCK + INS_ANCHOR, 1)

# ---------------- 適用後チェック（番兵とは別の条件で見る） ----------------
st2 = out_src.find(BS)
en2 = out_src.find(BE)
chain2 = out_src[st2:en2].count('.replace(')
print('chain after  = %d' % chain2)
if chain2 != EXPECT_CHAIN:
    die('chain が変わった: %d != %d' % (chain2, EXPECT_CHAIN))
if out_src.count("from './def_resolve'") != 1:
    die('import が 1 件でない')
if out_src.count('defServerResolve(c.env, st, classId, DEFENSE_ENEMIES)') != 1:
    die('呼び出しが 1 件でない')
if out_src.count(INS_ANCHOR) != 1:
    die('挿入アンカーが壊れた')
if out_src.count('ensureDefenseTables') != 1:
    die('ensureDefenseTables が変わった')
if out_src.count('CREATE TABLE') != src.count('CREATE TABLE'):
    die('CREATE TABLE の数が変わった')
for g in GUARD:
    if g not in out_src:
        die('guard missing after: ' + g)
if out_src.count(SENT) < 1:
    die('番兵が無い')
if out_ts.count('function computeMVP(') != 1:
    die('def_resolve.ts の computeMVP が 1 件でない')
if out_ts.count('export async function defServerResolve(') != 1:
    die('def_resolve.ts の defServerResolve が 1 件でない')
for k in ['Number(m.spd)', 'Array.isArray(m.skills)', 'm.skills.length === 0']:
    if k not in out_ts:
        die('番人の条件が欠けている: ' + k)

io.open(OUT, 'w', encoding='utf-8').write(out_ts)
io.open(SRC, 'w', encoding='utf-8').write(out_src)
print('OK: applied (chain stays %d, def_resolve.ts %d chars)' % (chain2, len(out_ts)))
