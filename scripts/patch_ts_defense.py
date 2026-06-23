import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip'); continue
        if old not in data:
            print('ANCHOR NOT FOUND',repr(old[:60])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old),repr(old[:40])); sys.exit(1)
        data=data.replace(old,new); print('ok',repr(old[:30]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

NEW_FUNCS = r'''

// -------------------- 週次ランキング報酬（かけら・JST月〜金17:00〆） --------------------
function rewardWeekInfo(now: Date): { curOpenWeek: string | null, lastClosedWeek: string } {
  const ms = now.getTime()
  const jst = new Date(ms + 9 * 3600 * 1000)
  const dow = jst.getUTCDay()
  const diff = dow === 0 ? 6 : dow - 1
  const monJst = new Date(jst)
  monJst.setUTCDate(jst.getUTCDate() - diff)
  monJst.setUTCHours(0, 0, 0, 0)
  const thisMonKey = monJst.toISOString().slice(0, 10)
  const realMonMs = monJst.getTime() - 9 * 3600 * 1000
  const fri17Ms = realMonMs + 4 * 86400000 + 17 * 3600000
  const prevMonKey = new Date(monJst.getTime() - 7 * 86400000).toISOString().slice(0, 10)
  const curOpenWeek = (ms >= realMonMs && ms < fri17Ms) ? thisMonKey : null
  const lastClosedWeek = (ms >= fri17Ms) ? thisMonKey : prevMonKey
  return { curOpenWeek, lastClosedWeek }
}

async function ensureRankingRewardTables(env: any) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS ranking_reward_base (user_id TEXT PRIMARY KEY, week_key TEXT, base_rp REAL DEFAULT 0, base_dex INTEGER DEFAULT 0, base_ts INTEGER DEFAULT 0, base_wild INTEGER DEFAULT 0)").run().catch(() => {})
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS ranking_weekly_scores (user_id TEXT NOT NULL, week_key TEXT NOT NULL, correct_pt REAL DEFAULT 0, pokedex INTEGER DEFAULT 0, typeshoot INTEGER DEFAULT 0, wild INTEGER DEFAULT 0, updated_at TEXT, PRIMARY KEY(user_id, week_key))").run().catch(() => {})
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS ranking_settlement (week_key TEXT NOT NULL, class_id TEXT NOT NULL, settled_at TEXT, PRIMARY KEY(week_key, class_id))").run().catch(() => {})
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS ranking_rewards (week_key TEXT NOT NULL, class_id TEXT NOT NULL, type TEXT NOT NULL, user_id TEXT NOT NULL, rank INTEGER, shards INTEGER, seen INTEGER DEFAULT 0, created_at TEXT, PRIMARY KEY(week_key, class_id, type, user_id))").run().catch(() => {})
}

async function settleClassWeek(env: any, classId: string, weekKey: string) {
  if (!classId || !weekKey) return
  const lock = await env.DB.prepare("INSERT OR IGNORE INTO ranking_settlement (week_key, class_id, settled_at) VALUES (?,?,datetime('now'))").bind(weekKey, classId).run()
  if (!lock.meta || lock.meta.changes === 0) return
  const rows = await env.DB.prepare("SELECT ws.user_id as uid, ws.correct_pt as cpt, ws.pokedex as dex, ws.typeshoot as ts, ws.wild as wd FROM ranking_weekly_scores ws JOIN class_members cm ON cm.user_id=ws.user_id AND cm.class_id=? JOIN users u ON u.id=ws.user_id AND u.is_active=1 WHERE ws.week_key=?").bind(classId, weekKey).all<any>()
  const list = ((rows && rows.results) || []) as any[]
  if (!list.length) return
  const SHARDS: Record<number, number> = { 1: 10, 2: 6, 3: 3 }
  const typeDefs: Array<{ type: string, get: (r: any) => number }> = [
    { type: 'correct', get: (r) => Number(r.cpt || 0) },
    { type: 'pokedex', get: (r) => Number(r.dex || 0) },
    { type: 'typeshoot', get: (r) => Number(r.ts || 0) },
    { type: 'wild', get: (r) => Number(r.wd || 0) },
  ]
  const awards: Record<string, Array<{ type: string, rank: number, shards: number }>> = {}
  for (const td of typeDefs) {
    const sorted = list.filter((r) => td.get(r) > 0).sort((a, b) => td.get(b) - td.get(a))
    for (let i = 0; i < Math.min(3, sorted.length); i++) {
      const uid = String(sorted[i].uid)
      const rank = i + 1
      if (!awards[uid]) awards[uid] = []
      awards[uid].push({ type: td.type, rank, shards: SHARDS[rank] })
    }
  }
  for (const uid of Object.keys(awards)) {
    const kept = awards[uid].sort((a, b) => b.shards - a.shards).slice(0, 2)
    let total = 0
    for (const a of kept) {
      const ins = await env.DB.prepare("INSERT OR IGNORE INTO ranking_rewards (week_key, class_id, type, user_id, rank, shards, seen, created_at) VALUES (?,?,?,?,?,?,0,datetime('now'))").bind(weekKey, classId, a.type, uid, a.rank, a.shards).run()
      if (ins.meta && ins.meta.changes > 0) total += a.shards
    }
    if (total > 0) {
      try {
        const prog = await env.DB.prepare("SELECT state_json FROM progress WHERE user_id=?").bind(uid).first<any>()
        if (prog && prog.state_json) {
          const state = JSON.parse(prog.state_json)
          if (!state.lab || typeof state.lab !== 'object') state.lab = { shards: 0, use: {} }
          state.lab.shards = (Number(state.lab.shards) || 0) + total
          state._rankShardsApplied = (Number(state._rankShardsApplied) || 0) + total
          try { if (state.decimalFest) state.decimalFest.totalShards = state.lab.shards } catch (_e) {}
          try { if (state.fractionFest) state.fractionFest.totalShards = state.lab.shards } catch (_e) {}
          await env.DB.prepare("UPDATE progress SET state_json=?, updated_at=datetime('now') WHERE user_id=?").bind(JSON.stringify(state), uid).run()
        }
      } catch (_e) {}
    }
  }
}

async function updateWeeklyAndSettle(env: any, userId: string, stats: any) {
  await ensureRankingRewardTables(env)
  const info = rewardWeekInfo(new Date())
  const rp = Number(stats.rankingPoints || 0)
  const dex = Number(stats.pokedexCount || 0)
  const ts = Number(stats.typeShootScore || 0)
  const wild = Number(stats.wildWinStreak || 0)
  const base = await env.DB.prepare("SELECT week_key, base_rp, base_dex, base_ts, base_wild FROM ranking_reward_base WHERE user_id=? LIMIT 1").bind(userId).first<any>()
  if (info.curOpenWeek) {
    if (!base) {
      await env.DB.prepare("INSERT OR IGNORE INTO ranking_reward_base (user_id, week_key, base_rp, base_dex, base_ts, base_wild) VALUES (?,?,?,?,?,?)").bind(userId, info.curOpenWeek, rp, dex, ts, wild).run()
    } else if (base.week_key !== info.curOpenWeek) {
      await env.DB.prepare("UPDATE ranking_reward_base SET week_key=?, base_rp=?, base_dex=?, base_ts=?, base_wild=? WHERE user_id=?").bind(info.curOpenWeek, rp, dex, ts, wild, userId).run()
    } else {
      const cPt = Math.max(0, rp - Number(base.base_rp || 0))
      const cDex = Math.max(0, dex - Number(base.base_dex || 0))
      const cTs = Math.max(0, ts - Number(base.base_ts || 0))
      const cWild = Math.max(0, wild - Number(base.base_wild || 0))
      await env.DB.prepare("INSERT INTO ranking_weekly_scores (user_id, week_key, correct_pt, pokedex, typeshoot, wild, updated_at) VALUES (?,?,?,?,?,?,datetime('now')) ON CONFLICT(user_id, week_key) DO UPDATE SET correct_pt=excluded.correct_pt, pokedex=excluded.pokedex, typeshoot=excluded.typeshoot, wild=excluded.wild, updated_at=datetime('now')").bind(userId, info.curOpenWeek, cPt, cDex, cTs, cWild).run()
    }
  }
  try {
    const classes = await env.DB.prepare("SELECT class_id FROM class_members WHERE user_id=?").bind(userId).all<any>()
    for (const cr of ((classes && classes.results) || [])) {
      await settleClassWeek(env, String(cr.class_id), info.lastClosedWeek)
    }
  } catch (_e) {}
}
'''

NEW_ENDPOINTS = r'''app.get('/api/student/ranking-rewards', async (c) => {
  const u = c.get('user')
  if (!u || u.role !== 'student') return jsonError(c, 403, 'forbidden')
  try { await ensureRankingRewardTables(c.env) } catch {}
  const labelMap: Record<string, string> = { correct: '正解ポイント', pokedex: 'ずかん（今週ふやした数）', typeshoot: 'タイプシュート', wild: 'やせいバトル（連勝）' }
  let rows: any = { results: [] }
  try { rows = await c.env.DB.prepare("SELECT week_key as weekKey, type, rank, shards FROM ranking_rewards WHERE user_id=? AND seen=0 ORDER BY shards DESC").bind(u.id).all<any>() } catch {}
  const list = (((rows && rows.results) || []) as any[]).map((r) => ({ weekKey: r.weekKey, type: r.type, label: labelMap[r.type] || r.type, rank: r.rank, shards: r.shards }))
  return c.json({ ok: true, rewards: list })
})

app.post('/api/student/ranking-rewards/seen', async (c) => {
  const u = c.get('user')
  if (!u || u.role !== 'student') return jsonError(c, 403, 'forbidden')
  try { await c.env.DB.prepare("UPDATE ranking_rewards SET seen=1 WHERE user_id=? AND seen=0").bind(u.id).run() } catch {}
  return c.json({ ok: true })
})

'''

GETCWS_OLD = '''function getCurrentWeekStart(): string {
  const now = new Date()
  const day = now.getUTCDay() // 0=Sun, 1=Mon, ..., 6=Sat
  const diff = day === 0 ? 6 : day - 1 // Monday=0
  const monday = new Date(now)
  monday.setUTCDate(now.getUTCDate() - diff)
  return monday.toISOString().slice(0, 10)
}'''

TS_OLD = "    await c.env.DB.prepare(`UPDATE ranking_stats SET typeshoot_score=? WHERE user_id=?`).bind(Number(stats.typeShootScore || 0), u.id).run()"
TS_NEW = TS_OLD + "\n    try { await updateWeeklyAndSettle(c.env, u.id, stats) } catch {}"

RECON_OLD = '''      if (_srvApplied > _cliApplied) {
        _inc.coins = (Number(_inc.coins) || 0) + (_srvApplied - _cliApplied)
        _inc._contactCoinsApplied = _srvApplied
        saveJson = JSON.stringify(_inc)
      }'''
RECON_NEW = RECON_OLD + '''
      const _srvRk = Number(_srv._rankShardsApplied) || 0
      const _cliRk = Number(_inc._rankShardsApplied) || 0
      if (_srvRk > _cliRk) {
        if (!_inc.lab || typeof _inc.lab !== 'object') _inc.lab = { shards: 0, use: {} }
        _inc.lab.shards = (Number(_inc.lab.shards) || 0) + (_srvRk - _cliRk)
        _inc._rankShardsApplied = _srvRk
        try { if (_inc.decimalFest) _inc.decimalFest.totalShards = _inc.lab.shards } catch (_e) {}
        try { if (_inc.fractionFest) _inc.fractionFest.totalShards = _inc.lab.shards } catch (_e) {}
        saveJson = JSON.stringify(_inc)
      }'''

EP_OLD = "// 生徒：週間計画を提出（修正履歴付き・自己調整記録）\napp.post('/api/student/weekly-plan', async (c) => {"
EP_NEW = NEW_ENDPOINTS + EP_OLD

SRC_EDITS = [
    (GETCWS_OLD, GETCWS_OLD + "\n" + NEW_FUNCS),
    (TS_OLD, TS_NEW),
    (RECON_OLD, RECON_NEW),
    (EP_OLD, EP_NEW),
]

# ---- client (public/index.html, CRLF) ----
CLIENT_FN = r'''function checkRankingRewards(){
  try{
    fetch('/api/student/ranking-rewards').then(function(r){return r.json();}).then(function(d){
      if(!d||!d.ok||!d.rewards||!d.rewards.length) return;
      var html='';
      for(var i=0;i<d.rewards.length;i++){ var rw=d.rewards[i]; html+='<div style="margin:6px 0;font-size:15px;color:#374151;">🏆 今週『'+rw.label+'』で'+rw.rank+'位！ かけら+'+rw.shards+' GET</div>'; }
      var ov=document.createElement('div');
      ov.style.cssText='position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(0,0,0,0.5);z-index:99999;display:flex;align-items:center;justify-content:center;padding:16px;';
      ov.innerHTML='<div style="background:#fff;border-radius:16px;padding:20px;max-width:92%;text-align:center;box-shadow:0 8px 30px rgba(0,0,0,0.3);"><div style="font-size:20px;font-weight:bold;color:#d97706;margin-bottom:8px;">🎉 今週のランキングごほうび</div>'+html+'<div style="font-size:12px;color:#9ca3af;margin:10px 0;">かけらはもう入っているよ！</div><button id="rkRwOk" style="background:#10b981;color:#fff;border:none;border-radius:10px;padding:10px 28px;font-weight:bold;font-size:15px;cursor:pointer;">やったー！</button></div>';
      document.body.appendChild(ov);
      var btn=document.getElementById('rkRwOk');
      if(btn){ btn.onclick=function(){ try{ document.body.removeChild(ov); }catch(_e){} try{ fetch('/api/student/ranking-rewards/seen',{method:'POST'}); }catch(_e2){} }; }
    }).catch(function(){});
  }catch(e){}
}
'''

FN_ANCHOR = "            try{ ensureMetrics(); setInterval(tickPlaytime, 30000); }catch(e){}"
FN_NEW = CLIENT_FN + "\n" + FN_ANCHOR
CALL_ANCHOR = "console.log('DOMContentLoaded event fired');"
CALL_NEW = CALL_ANCHOR + "\n            try { setTimeout(function(){ if(typeof checkRankingRewards==='function'){ checkRankingRewards(); } }, 3500); } catch(_e){}"

PUB_EDITS_RAW = [
    (FN_ANCHOR, FN_NEW),
    (CALL_ANCHOR, CALL_NEW),
]
PUB_EDITS = [(o.replace('\n','\r\n'), n.replace('\n','\r\n')) for (o,n) in PUB_EDITS_RAW]

patch_file('src/index.tsx', SRC_EDITS)
patch_file('public/index.html', PUB_EDITS)
print('DONE RANK')
