import sys
def patch_file(path, edits, label):
    data=open(path,'rb').read().decode('utf-8')
    for old,new,g in edits:
        if new in data and old not in data:
            print('skip '+g, file=sys.stderr); continue
        c=data.count(old)
        if c!=1:
            print('ANCHOR x'+str(c)+' '+g, file=sys.stderr); sys.exit(1)
        data=data.replace(old,new,1)
    open(path,'wb').write(data.encode('utf-8'))
    print('['+label+'] ok', file=sys.stderr)
SRV=[
  ('  let newCoinTotal: number | null = null','  let newCoinTotal: number | null = null\n  let contactApplied: number | null = null','A'),
  ('        state.coins = (Number(state.coins) || 0) + reward\n        newCoinTotal = state.coins','        state.coins = (Number(state.coins) || 0) + reward\n        state._contactCoinsApplied = (Number(state._contactCoinsApplied) || 0) + reward\n        newCoinTotal = state.coins\n        contactApplied = state._contactCoinsApplied','B'),
  ('  return c.json({ ok: true, reward, rewardClaimed: !!rewardClaimed, newCoins: newCoinTotal })','  return c.json({ ok: true, reward, rewardClaimed: !!rewardClaimed, newCoins: newCoinTotal, contactCoinsApplied: contactApplied })','C'),
  ("  if (stateJson.length > 1_000_000) return c.json({ ok: true })\n\n  try {\n    await c.env.DB.prepare(\n      `INSERT INTO progress (user_id, state_json, updated_at)\n       VALUES (?, ?, datetime('now'))\n       ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json, updated_at=datetime('now')`\n    )\n      .bind(u.id, stateJson)\n      .run()","  if (stateJson.length > 1_000_000) return c.json({ ok: true })\n\n  // 連絡帳コインの上書き消失を防ぐ：サーバが付与済みの連絡帳コインをクライアントが知らない場合は補填\n  let saveJson = stateJson\n  try {\n    const _cur = await c.env.DB.prepare(`SELECT state_json FROM progress WHERE user_id=?`).bind(u.id).first<any>()\n    if (_cur?.state_json) {\n      const _srv = JSON.parse(_cur.state_json)\n      const _srvApplied = Number(_srv._contactCoinsApplied) || 0\n      const _inc: any = body.state ?? body\n      const _cliApplied = Number(_inc._contactCoinsApplied) || 0\n      if (_srvApplied > _cliApplied) {\n        _inc.coins = (Number(_inc.coins) || 0) + (_srvApplied - _cliApplied)\n        _inc._contactCoinsApplied = _srvApplied\n        saveJson = JSON.stringify(_inc)\n      }\n    }\n  } catch { /* 補填失敗時はそのまま保存 */ }\n\n  try {\n    await c.env.DB.prepare(\n      `INSERT INTO progress (user_id, state_json, updated_at)\n       VALUES (?, ?, datetime('now'))\n       ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json, updated_at=datetime('now')`\n    )\n      .bind(u.id, saveJson)\n      .run()",'D'),
]
CLI=[
  ('                    player.coins = (typeof res.newCoins === "number") ? res.newCoins : ((player.coins||0) + res.reward);','                    player.coins = (typeof res.newCoins === "number") ? res.newCoins : ((player.coins||0) + res.reward);\r\n                    if(typeof res.contactCoinsApplied === "number") player._contactCoinsApplied = res.contactCoinsApplied;','E'),
]
patch_file('src/index.tsx', SRV, 'index.tsx')
patch_file('public/index.html', CLI, 'index.html')
print('DONE', file=sys.stderr)
