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
            print('NOT UNIQUE',data.count(old)); sys.exit(1)
        data=data.replace(old,new); print('ok',repr(old[:30]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ('  `).bind(u.id, weekKey, concentration, goodPoint, improvePoint, nextAction, freeText, now).run()\n\n  return c.json({ ok: true })\n})',
     '  `).bind(u.id, weekKey, concentration, goodPoint, improvePoint, nextAction, freeText, now).run()\n\n  // === 毎日のふりかえり提出で「かけら」付与（1日1回・冪等・内容ありが条件）===\n  let reflectionShards: any = { awarded: 0, base: 0, bonus: 0, streak: 0, newTotal: null, alreadyAwarded: false, eligible: false }\n  try {\n    const hasContent = !!(goodPoint.trim() || improvePoint.trim() || nextAction.trim() || freeText.trim())\n    reflectionShards.eligible = hasContent\n    if (hasContent) {\n      await c.env.DB.prepare("CREATE TABLE IF NOT EXISTS daily_reflection_rewards (user_id TEXT NOT NULL, day_key TEXT NOT NULL, shards INTEGER NOT NULL DEFAULT 0, base INTEGER DEFAULT 0, bonus INTEGER DEFAULT 0, created_at TEXT, PRIMARY KEY(user_id, day_key))").run().catch(() => {})\n      const dayKey = String(body.dayKey || weekKey).slice(0, 10)\n      const exists = await c.env.DB.prepare("SELECT shards FROM daily_reflection_rewards WHERE user_id=? AND day_key=? LIMIT 1").bind(u.id, dayKey).first<any>()\n      if (exists) {\n        reflectionShards.alreadyAwarded = true\n      } else {\n        const _dms = (d: string) => new Date(d + \'T00:00:00Z\').getTime()\n        let streak = 1\n        for (let k = 1; k <= 30; k++) {\n          const prev = new Date(_dms(dayKey) - k * 86400000).toISOString().slice(0, 10)\n          const pr = await c.env.DB.prepare("SELECT 1 FROM daily_reflection_rewards WHERE user_id=? AND day_key=? LIMIT 1").bind(u.id, prev).first<any>()\n          if (pr) { streak++ } else { break }\n        }\n        const base = 1\n        const bonus = (streak % 5 === 0) ? 1 : 0\n        const total = base + bonus\n        const ins = await c.env.DB.prepare("INSERT OR IGNORE INTO daily_reflection_rewards (user_id, day_key, shards, base, bonus, created_at) VALUES (?,?,?,?,?,datetime(\'now\'))").bind(u.id, dayKey, total, base, bonus).run()\n        if (ins.meta && ins.meta.changes === 1) {\n          let newTotal: number | null = null\n          try {\n            const prog = await c.env.DB.prepare("SELECT state_json FROM progress WHERE user_id=?").bind(u.id).first<any>()\n            if (prog && prog.state_json) {\n              const state = JSON.parse(prog.state_json)\n              if (!state.lab || typeof state.lab !== \'object\') state.lab = { shards: 0, use: {} }\n              state.lab.shards = (Number(state.lab.shards) || 0) + total\n              try { if (state.decimalFest) state.decimalFest.totalShards = state.lab.shards } catch (_e) {}\n              try { if (state.fractionFest) state.fractionFest.totalShards = state.lab.shards } catch (_e) {}\n              newTotal = state.lab.shards\n              await c.env.DB.prepare("UPDATE progress SET state_json=?, updated_at=datetime(\'now\') WHERE user_id=?").bind(JSON.stringify(state), u.id).run()\n            }\n          } catch (_e) {}\n          reflectionShards = { awarded: total, base, bonus, streak, newTotal, alreadyAwarded: false, eligible: true }\n        } else {\n          reflectionShards.alreadyAwarded = true\n        }\n      }\n    }\n  } catch (_e) {}\n  return c.json({ ok: true, reflectionShards })\n})'),
]
PUB_EDITS = [
    ("    hwSavePlanForWeek(weekKey, plan);\n\n    const msg = document.getElementById('hwReflectionMsg');",
     "    hwSavePlanForWeek(weekKey, plan);\n\n    // 毎日のふりかえり提出 → かけら付与（サーバ冪等・1日1回・内容ありが条件）\n    try{\n      if(reflection && reflection.length>0){\n        fetch('/api/student/weekly-reflection',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({ weekKey: weekKey, dayKey: todayKey, freeText: reflection })})\n          .then(function(rr){ return rr.json(); })\n          .then(function(rj){\n            try{\n              var rs = rj && rj.reflectionShards;\n              if(rs && rs.awarded>0){\n                if(typeof labAddShards==='function') labAddShards(rs.awarded);\n                try{ var _se=document.getElementById('labShardCount'); if(_se && typeof labGetShards==='function') _se.textContent=String(labGetShards()); }catch(_e){}\n                try{ if(typeof saveData==='function') saveData(); }catch(_e){}\n                var _rm=document.getElementById('hwReflectionMsg');\n                if(_rm){ _rm.textContent='\\uD83D\\uDFE6 \\u304B\\u3051\\u3089 +'+rs.awarded+' \\u3082\\u3089\\u3048\\u305F\\uFF01'+((rs.bonus>0)?'\\uFF08\\u308C\\u3093\\u305E\\u304F\\u30DC\\u30FC\\u30CA\\u30B9 +'+rs.bonus+'\\uFF09':''); setTimeout(function(){ try{ if(_rm) _rm.textContent=''; }catch(_e){} }, 5000); }\n              }\n            }catch(_e){}\n          }).catch(function(){});\n      }\n    }catch(_e){}\n\n    const msg = document.getElementById('hwReflectionMsg');"),
]

patch_file('src/index.tsx', SRC_EDITS)
patch_file('public/index.html', PUB_EDITS)
print('DONE SHARD')
