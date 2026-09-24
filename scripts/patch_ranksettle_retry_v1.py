# -*- coding: utf-8 -*-
# RANKSETTLE_RETRY_V1 (2026-09-24)
#   週次ランキング報酬の確定 settleClassWeek を、途中で落ちても配り直せる形にする。
#     ・もとは INSERT OR IGNORE で「配り終えた」印を先に立ててから配っていた。
#       配っている途中で処理が打ち切られると、その週は二度と配られない。
#       2026-09-07 の週は実際に1人目で止まり、4人ぶん32かけらが未付与になった。
#     ・印を「作業中(RUN <ISO>)」と「完了(日時だけ)」の二段にして、
#       最後まで配り終えたときだけ「完了」にする。落ちた作業中の印は
#       10分後に次の保存が引き継ぎ、足りないぶんだけ配り直す。
#     ・かけらを progress に足せなかったときは、入れた台帳の行を消して
#       次の配り直しでやり直せるようにする（class-mission/:id/claim と同じ作法）。
#     ・先生用アカウント(role='admin')を順位から外す。
#   昔の settled_at 行は 'RUN ' が付いていないので「完了」扱い＝過去の週は動かさない。
#   児童の画面（配信チェーン）は1件も増減しない。増減していたら止まる。
#   progress の全体上書きは従来どおり settleClassWeek の中だけ。列や表は足さない（DDL なし）。
import json
import os
import sys

SRC = 'src/index.tsx'


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if not raw.isdigit():
    print('NG: CHAIN_BEFORE が数字でない（渡された値: %r）' % raw)
    sys.exit(1)
CHAIN_BEFORE = int(raw)

src = open(SRC, encoding='utf-8').read()
before = chain_count(src)
print('チェーン = %d' % before)
if before != CHAIN_BEFORE:
    print('NG: チェーンが %d 件。実測した %d と合わないので止めます。' % (before, CHAIN_BEFORE))
    sys.exit(1)

for marker in ['RANKSETTLE_RETRY_V1', 'markDone', 'insertedTypes']:
    if marker in src:
        print('NG: すでに適用済みのようです（%s）' % marker)
        sys.exit(1)

EDITS = json.loads(r"""[{"tag": "S1_settle_retry", "old": "async function settleClassWeek(env: any, classId: string, weekKey: string) {\n  if (!classId || !weekKey) return\n  const lock = await env.DB.prepare(\"INSERT OR IGNORE INTO ranking_settlement (week_key, class_id, settled_at) VALUES (?,?,datetime('now'))\").bind(weekKey, classId).run()\n  if (!lock.meta || lock.meta.changes === 0) return\n  const rows = await env.DB.prepare(\"SELECT ws.user_id as uid, ws.correct_pt as cpt, ws.pokedex as dex, ws.typeshoot as ts, ws.wild as wd FROM ranking_weekly_scores ws JOIN class_members cm ON cm.user_id=ws.user_id AND cm.class_id=? JOIN users u ON u.id=ws.user_id AND u.is_active=1 WHERE ws.week_key=?\").bind(classId, weekKey).all<any>()\n  const list = ((rows && rows.results) || []) as any[]\n  if (!list.length) return\n  const SHARDS: Record<number, number> = { 1: 10, 2: 6, 3: 3 }\n  const typeDefs: Array<{ type: string, get: (r: any) => number }> = [\n    { type: 'correct', get: (r) => Number(r.cpt || 0) },\n    { type: 'pokedex', get: (r) => Number(r.dex || 0) },\n    { type: 'typeshoot', get: (r) => Number(r.ts || 0) },\n    { type: 'wild', get: (r) => Number(r.wd || 0) },\n  ]\n  const awards: Record<string, Array<{ type: string, rank: number, shards: number }>> = {}\n  for (const td of typeDefs) {\n    const sorted = list.filter((r) => td.get(r) > 0).sort((a, b) => td.get(b) - td.get(a))\n    for (let i = 0; i < Math.min(3, sorted.length); i++) {\n      const uid = String(sorted[i].uid)\n      const rank = i + 1\n      if (!awards[uid]) awards[uid] = []\n      awards[uid].push({ type: td.type, rank, shards: SHARDS[rank] })\n    }\n  }\n  for (const uid of Object.keys(awards)) {\n    const kept = awards[uid].sort((a, b) => b.shards - a.shards).slice(0, 2)\n    let total = 0\n    for (const a of kept) {\n      const ins = await env.DB.prepare(\"INSERT OR IGNORE INTO ranking_rewards (week_key, class_id, type, user_id, rank, shards, seen, created_at) VALUES (?,?,?,?,?,?,0,datetime('now'))\").bind(weekKey, classId, a.type, uid, a.rank, a.shards).run()\n      if (ins.meta && ins.meta.changes > 0) total += a.shards\n    }\n    if (total > 0) {\n      try {\n        const prog = await env.DB.prepare(\"SELECT state_json FROM progress WHERE user_id=?\").bind(uid).first<any>()\n        if (prog && prog.state_json) {\n          const state = JSON.parse(prog.state_json)\n          if (!state.lab || typeof state.lab !== 'object') state.lab = { shards: 0, use: {} }\n          state.lab.shards = (Number(state.lab.shards) || 0) + total\n          state._rankShardsApplied = (Number(state._rankShardsApplied) || 0) + total\n          try { if (state.decimalFest) state.decimalFest.totalShards = state.lab.shards } catch (_e) {}\n          try { if (state.fractionFest) state.fractionFest.totalShards = state.lab.shards } catch (_e) {}\n          await env.DB.prepare(\"UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?\").bind(JSON.stringify(state), uid).run()\n        }\n      } catch (_e) {}\n    }\n  }\n}\n", "new": "async function settleClassWeek(env: any, classId: string, weekKey: string) {\n  if (!classId || !weekKey) return\n  // ══════ RANKSETTLE_RETRY_V1 (2026-09-24) 途中で落ちても配り直せるようにする ══════\n  //  もとは「配り終えた印を先に立ててから配る」順だったので、配っている\n  //  途中で処理が打ち切られると、その週は二度と配られなかった。\n  //  2026-09-07 の週は実際に1人目で止まり、4人ぶん32かけらが未付与のまま残った。\n  //  そこで印を二段にする：\n  //    ・作業中 … settled_at が 'RUN <ISO日時>'\n  //    ・完了   … settled_at が datetime('now')（従来どおりの日時だけ）\n  //  最後まで配り終えたときだけ「完了」にする。途中で落ちた「作業中」の印は\n  //  10分たてば次の保存が引き継いで、足りないぶんだけ配り直す。\n  //  配り直しても二重付与にならないのは、台帳 ranking_rewards が主キーで守られ、\n  //  INSERT が成功した行のぶんしか足さないから（homework_claims と同じ作法）。\n  //  昔の行は 'RUN ' が付いていないので「完了」とみなす＝過去の週は動かさない。\n  let claimed = ''\n  try {\n    const cur = await env.DB.prepare(\"SELECT settled_at FROM ranking_settlement WHERE week_key=? AND class_id=? LIMIT 1\").bind(weekKey, classId).first<any>()\n    if (!cur) {\n      claimed = 'RUN ' + new Date().toISOString()\n      const ins = await env.DB.prepare(\"INSERT OR IGNORE INTO ranking_settlement (week_key, class_id, settled_at) VALUES (?,?,?)\").bind(weekKey, classId, claimed).run()\n      if (!ins.meta || ins.meta.changes === 0) return\n    } else {\n      const was = String(cur.settled_at || '')\n      if (was.indexOf('RUN ') !== 0) return\n      const startedMs = Date.parse(was.slice(4))\n      if (!(startedMs > 0) || (Date.now() - startedMs) < 600000) return\n      claimed = 'RUN ' + new Date().toISOString()\n      const took = await env.DB.prepare(\"UPDATE ranking_settlement SET settled_at=? WHERE week_key=? AND class_id=? AND settled_at=?\").bind(claimed, weekKey, classId, was).run()\n      if (!took.meta || took.meta.changes === 0) return\n    }\n  } catch (_e) { return }\n  const markDone = async () => {\n    try { await env.DB.prepare(\"UPDATE ranking_settlement SET settled_at=datetime('now') WHERE week_key=? AND class_id=? AND settled_at=?\").bind(weekKey, classId, claimed).run() } catch (_e) {}\n  }\n  const rows = await env.DB.prepare(\"SELECT ws.user_id as uid, ws.correct_pt as cpt, ws.pokedex as dex, ws.typeshoot as ts, ws.wild as wd FROM ranking_weekly_scores ws JOIN class_members cm ON cm.user_id=ws.user_id AND cm.class_id=? JOIN users u ON u.id=ws.user_id AND u.is_active=1 AND u.role='student' WHERE ws.week_key=?\").bind(classId, weekKey).all<any>()\n  const list = ((rows && rows.results) || []) as any[]\n  if (!list.length) { await markDone(); return }\n  const SHARDS: Record<number, number> = { 1: 10, 2: 6, 3: 3 }\n  const typeDefs: Array<{ type: string, get: (r: any) => number }> = [\n    { type: 'correct', get: (r) => Number(r.cpt || 0) },\n    { type: 'pokedex', get: (r) => Number(r.dex || 0) },\n    { type: 'typeshoot', get: (r) => Number(r.ts || 0) },\n    { type: 'wild', get: (r) => Number(r.wd || 0) },\n  ]\n  const awards: Record<string, Array<{ type: string, rank: number, shards: number }>> = {}\n  for (const td of typeDefs) {\n    const sorted = list.filter((r) => td.get(r) > 0).sort((a, b) => td.get(b) - td.get(a))\n    for (let i = 0; i < Math.min(3, sorted.length); i++) {\n      const uid = String(sorted[i].uid)\n      const rank = i + 1\n      if (!awards[uid]) awards[uid] = []\n      awards[uid].push({ type: td.type, rank, shards: SHARDS[rank] })\n    }\n  }\n  let anyFailed = false\n  for (const uid of Object.keys(awards)) {\n    const kept = awards[uid].sort((a, b) => b.shards - a.shards).slice(0, 2)\n    let total = 0\n    const insertedTypes: string[] = []\n    for (const a of kept) {\n      const ins = await env.DB.prepare(\"INSERT OR IGNORE INTO ranking_rewards (week_key, class_id, type, user_id, rank, shards, seen, created_at) VALUES (?,?,?,?,?,?,0,datetime('now'))\").bind(weekKey, classId, a.type, uid, a.rank, a.shards).run()\n      if (ins.meta && ins.meta.changes > 0) { total += a.shards; insertedTypes.push(a.type) }\n    }\n    if (total > 0) {\n      // 加算できたかどうかを必ず見る。できていなければ台帳の行を消して、\n      // 次の配り直しでやり直せるようにする（class-mission/:id/claim と同じ作法）。\n      let applyOk = false\n      try {\n        const prog = await env.DB.prepare(\"SELECT state_json FROM progress WHERE user_id=?\").bind(uid).first<any>()\n        if (prog && prog.state_json) {\n          const state = JSON.parse(prog.state_json)\n          if (!state.lab || typeof state.lab !== 'object') state.lab = { shards: 0, use: {} }\n          state.lab.shards = (Number(state.lab.shards) || 0) + total\n          state._rankShardsApplied = (Number(state._rankShardsApplied) || 0) + total\n          try { if (state.decimalFest) state.decimalFest.totalShards = state.lab.shards } catch (_e) {}\n          try { if (state.fractionFest) state.fractionFest.totalShards = state.lab.shards } catch (_e) {}\n          const upd = await env.DB.prepare(\"UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?\").bind(JSON.stringify(state), uid).run()\n          applyOk = !!(upd.meta && upd.meta.changes > 0)\n        } else {\n          // まだセーブが無い子。足す先が無いだけなので台帳はそのままでよい。\n          applyOk = true\n        }\n      } catch (_e) {\n        console.error('[rank-settle] shard apply error', uid)\n        applyOk = false\n      }\n      if (!applyOk) {\n        anyFailed = true\n        for (const t of insertedTypes) {\n          try { await env.DB.prepare(\"DELETE FROM ranking_rewards WHERE week_key=? AND class_id=? AND type=? AND user_id=?\").bind(weekKey, classId, t, uid).run() } catch (_e) {}\n        }\n      }\n    }\n  }\n  // 1人でも配れなかったら「完了」にしない。印は作業中(RUN)のまま残り、\n  // 10分後の保存が引き継いで、足りないぶんだけ配り直す。\n  if (!anyFailed) await markDone()\n}\n"}]""")

bad = False
for e in EDITS:
    n = src.count(e['old'])
    print('%-20s アンカー %d 件' % (e['tag'], n))
    if n != 1:
        print('NG: %s のアンカーが %d か所（1件でないので止めます）' % (e['tag'], n))
        bad = True
if bad:
    sys.exit(1)

out = src
for e in EDITS:
    out = out.replace(e['old'], e['new'], 1)

after = chain_count(out)
print('適用後のチェーン = %d' % after)
if after != CHAIN_BEFORE:
    print('NG: チェーンが変わりました（%d -> %d）' % (before, after))
    sys.exit(1)

need = json.loads(r"""{"RANKSETTLE_RETRY_V1": 1, "u.role='student'": 2, "DELETE FROM ranking_rewards": 1, "markDone": 3, "insertedTypes": 3, "ranking_settlement": 5, "ranking_rewards": 7, "_rankShardsApplied": 5, "settleClassWeek": 2, "INSERT OR IGNORE INTO ranking_rewards": 1, "SELECT settled_at FROM ranking_settlement": 1}""")
for k in sorted(need):
    want = need[k]
    got = out.count(k)
    print('適用後 %-42s %d 件（期待 %d）' % (k, got, want))
    if got != want:
        print('NG: %r の件数が期待と違います' % k)
        bad = True

# 危険な作り込みが紛れていないこと
for k in ['ALTER TABLE', 'DROP TABLE', 'DELETE FROM progress', 'DELETE FROM users']:
    if out.count(k) != src.count(k):
        print('NG: %r の件数が変わりました（%d -> %d）' % (k, src.count(k), out.count(k)))
        bad = True

for k in ['cannot_trade_special', 'genElectric6', 'if (m.uncapturable) continue;', '__WORLD_V3__', 'WARMIX', '_hash']:
    if out.count(k) < 1:
        print('NG: 安全マーカー %r が消えました' % k)
        bad = True
if bad:
    sys.exit(1)

open(SRC, 'w', encoding='utf-8', newline='').write(out)
print('OK: %d -> %d バイト（%+d）' % (len(src), len(out), len(out) - len(src)))
