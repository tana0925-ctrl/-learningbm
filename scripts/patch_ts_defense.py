import sys
def patch_file(path, edits, label):
    data=open(path,'rb').read().decode('utf-8')
    for old,new,guard in edits:
        if guard and guard in data:
            print(f'[{label}] skip (already): {guard[:30]}', file=sys.stderr); continue
        c=data.count(old)
        if c!=1:
            print(f'[{label}] ANCHOR NOT UNIQUE ({c}): {old[:50]!r}', file=sys.stderr); sys.exit(1)
        data=data.replace(old,new,1)
    open(path,'wb').write(data.encode('utf-8'))
    print(f'[{label}] patched', file=sys.stderr)

# ---- index.html (CRLF) ----
patch_file('public/index.html', [
 # 1) disable fraud zero-reset
 ('                if (delta >= 101) {\r\n                    applyOldCoinFraudPenalty();\r\n                }',
  '                if (false && delta >= 101) { /* 不正リセット無効化：正規学習でも1日101枚超で誤発動していたため */\r\n                    applyOldCoinFraudPenalty();\r\n                }',
  'false && delta >= 101'),
 # 2) client adopts server total to avoid overwrite revert
 ('                    player.coins = (player.coins||0) + res.reward;\r\n                    try{if(typeof player.oldCoinDailyStart!="undefined") player.oldCoinDailyStart=(player.coins||0);}catch(e){}',
  '                    player.coins = (typeof res.newCoins === "number") ? res.newCoins : ((player.coins||0) + res.reward);\r\n                    try{if(typeof player.oldCoinDailyStart!="undefined") player.oldCoinDailyStart=(player.coins||0);}catch(e){}',
  'typeof res.newCoins === "number"'),
], 'index.html')

# ---- src/index.tsx (LF) ----
patch_file('src/index.tsx', [
 ('  let reward = 0\n  let rewardClaimed = 0',
  '  let reward = 0\n  let rewardClaimed = 0\n  let newCoinTotal: number | null = null',
  'let newCoinTotal'),
 ('        state.coins = (Number(state.coins) || 0) + reward\n        await c.env.DB.prepare(',
  '        state.coins = (Number(state.coins) || 0) + reward\n        newCoinTotal = state.coins\n        await c.env.DB.prepare(',
  'newCoinTotal = state.coins'),
 ('  return c.json({ ok: true, reward, rewardClaimed: !!rewardClaimed })',
  '  return c.json({ ok: true, reward, rewardClaimed: !!rewardClaimed, newCoins: newCoinTotal })',
  'newCoins: newCoinTotal'),
], 'src/index.tsx')
print('DONE', file=sys.stderr)
