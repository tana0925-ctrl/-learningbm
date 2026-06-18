import sys
LF=chr(10); CR=chr(13); CRLF=CR+LF
def patch_file(path, edits, label):
    data=open(path,'rb').read().decode('utf-8')
    for old,new,guard in edits:
        if guard and guard in data:
            print('['+label+'] skip', file=sys.stderr); continue
        c=data.count(old)
        if c!=1:
            print('['+label+'] ANCHOR x'+str(c)+': '+repr(old[:55]), file=sys.stderr); sys.exit(1)
        data=data.replace(old,new,1)
    open(path,'wb').write(data.encode('utf-8'))
    print('['+label+'] ok', file=sys.stderr)

# ===== public/typeshoot.js (LF) =====
patch_file('public/typeshoot.js', [
 ("enemyType:'normal', baseType:'normal' };",
  "enemyType:'normal', baseType:'normal', score:0 };", "baseType:'normal', score:0"),
 ('''        '<div id="tsStage" style="font-weight:800;font-size:16px;color:#fbbf24">ステージ 1</div>' +''',
  '''        '<div id="tsStage" style="font-weight:800;font-size:16px;color:#fbbf24">ステージ 1</div>' +
        '<div id="tsScore" style="font-weight:800;font-size:14px;color:#86efac">スコア 0</div>' +''', 'id="tsScore"'),
 ("  function updateStageLabel() { if (el('tsStage')) el('tsStage').textContent = 'ステージ ' + S.stage; }",
  "  function updateStageLabel() { if (el('tsStage')) el('tsStage').textContent = 'ステージ ' + S.stage; }"+LF+"  function updateScore() { if (el('tsScore')) el('tsScore').textContent = 'スコア ' + (S.score || 0); }", 'function updateScore'),
 ("    var dmg = Math.round(18 * eff.f);",
  "    var dmg = Math.round(18 * eff.f);"+LF+"    S.score = (S.score || 0) + Math.round(10 * eff.f) + (S.combo || 0); updateScore();", 'S.score = (S.score || 0) + Math.round(10'),
 ("if (di >= 0) rm(di, done); fxBurst(dx, dyy, '💥'); fxFloat(dx, dyy, 'ナイス！', '#93c5fd'); S.combo++;",
  "if (di >= 0) rm(di, done); fxBurst(dx, dyy, '💥'); fxFloat(dx, dyy, 'ナイス！', '#93c5fd'); S.score = (S.score || 0) + 15 + (S.combo || 0); updateScore(); S.combo++;", "+ 15 + (S.combo || 0); updateScore(); S.combo++;"),
 ("    stageBanner('ステージ ' + S.stage);",
  "    S.score = (S.score || 0) + 100; updateScore();"+LF+"    stageBanner('ステージ ' + S.stage);", '+ 100; updateScore();'),
 ("S.combo = 0; S.missiles = []; S.last = 0;",
  "S.combo = 0; S.missiles = []; S.last = 0; S.score = 0;", 'S.last = 0; S.score = 0;'),
 ("    setMode('attack'); setBars(); setWord(); updateStageLabel();",
  "    setMode('attack'); setBars(); setWord(); updateStageLabel(); updateScore();", 'updateStageLabel(); updateScore();'),
 ('''    var reward = 0; /* if (win) giveReward(reward); */
    var r = el('tsResult');
    r.innerHTML = '<div style="font-size:56px">🎌</div>' +
      '<div style="font-size:26px;font-weight:800;color:#fbbf24">ステージ ' + S.stage + ' まで とうたつ！</div>' +''',
  '''    var reward = 0; /* if (win) giveReward(reward); */
    var best = S.score || 0; var isNewBest = false;
    try { var _p = window.getPlayer && window.getPlayer(); if (_p) { var prevBest = Number(_p._cachedTypeShootScore || 0); isNewBest = (S.score || 0) > prevBest; best = Math.max(prevBest, S.score || 0); _p._cachedTypeShootScore = best; if (window.saveData) window.saveData(); } } catch (e) {}
    var r = el('tsResult');
    r.innerHTML = '<div style="font-size:56px">🎌</div>' +
      '<div style="font-size:26px;font-weight:800;color:#fbbf24">ステージ ' + S.stage + ' まで とうたつ！</div>' +
      '<div style="font-size:30px;font-weight:900;color:#86efac;margin-top:8px">スコア ' + (S.score || 0) + '</div>' +
      '<div style="font-size:13px;color:#94a3b8;margin-top:2px">' + (isNewBest ? '🎉 ベスト更新！' : 'ベスト ' + best) + '</div>' +''',
  '_cachedTypeShootScore = best'),
], 'typeshoot.js')

# ===== src/index.tsx (LF) =====
patch_file('src/index.tsx', [
 ('    const battlePower = Number(s._cachedBattlePower || 0)',
  '    const battlePower = Number(s._cachedBattlePower || 0)'+LF+'    const typeShootScore = Number(s._cachedTypeShootScore || 0)', 'const typeShootScore = Number'),
 ('      battlePower, pokedexCount, wildWinStreak'+LF+'    }',
  '      battlePower, pokedexCount, wildWinStreak, typeShootScore'+LF+'    }', 'wildWinStreak, typeShootScore'),
 ('rankingPoints: 0, battlePower: 0, pokedexCount: 0, wildWinStreak: 0 }',
  'rankingPoints: 0, battlePower: 0, pokedexCount: 0, wildWinStreak: 0, typeShootScore: 0 }', 'wildWinStreak: 0, typeShootScore: 0'),
 ('      ).run()'+LF+'    }'+LF+'  } catch { /* ランキング更新エラーは無視 */ }',
  '      ).run()'+LF+'    }'+LF+'    await c.env.DB.prepare(`UPDATE ranking_stats SET typeshoot_score=? WHERE user_id=?`).bind(Number(stats.typeShootScore || 0), u.id).run()'+LF+'  } catch { /* ランキング更新エラーは無視 */ }', 'SET typeshoot_score=? WHERE'),
 ("    case 'grade': orderCol = 'rs.ranking_points'; break"+LF+"  }",
  "    case 'grade': orderCol = 'rs.ranking_points'; break"+LF+"    case 'typeshoot': orderCol = 'rs.typeshoot_score'; break"+LF+"  }", "case 'typeshoot': orderCol = 'rs.typeshoot_score'"),
 ("      case 'wild': extraSelect = ', (rs.wild_win_streak - rs.week_base_wild_win_streak) as weeklyScore'; orderCol = 'weeklyScore'; break",
  "      case 'wild': extraSelect = ', (rs.wild_win_streak - rs.week_base_wild_win_streak) as weeklyScore'; orderCol = 'weeklyScore'; break"+LF+"      case 'typeshoot': extraSelect = ', rs.typeshoot_score as weeklyScore'; orderCol = 'weeklyScore'; break", "case 'typeshoot': extraSelect = ', rs.typeshoot_score"),
 ('rs.wild_win_streak as wildWinStreak'+LF+'    ${extraSelect}',
  'rs.wild_win_streak as wildWinStreak, rs.typeshoot_score as typeShootScore'+LF+'    ${extraSelect}', 'rs.typeshoot_score as typeShootScore'),
], 'index.tsx')

# ===== public/index.html (CRLF) =====
patch_file('public/index.html', [
 ('''      <button class="rk-tab" data-rktype="wild" onclick="rkSwitchType('wild')">野生バトル</button>''',
  '''      <button class="rk-tab" data-rktype="wild" onclick="rkSwitchType('wild')">野生バトル</button>'''+CRLF+'''      <button class="rk-tab" data-rktype="typeshoot" onclick="rkSwitchType('typeshoot')">⌨タイプシュート</button>''', 'data-rktype="typeshoot"'),
 ("  var labels = {overall:'総合Lv', grade:'正解pt', power:'戦闘力', correct:'正解pt', pokedex:'図鑑数', wild:'最大連勝'};",
  "  var labels = {overall:'総合Lv', grade:'正解pt', power:'戦闘力', correct:'正解pt', pokedex:'図鑑数', wild:'最大連勝', typeshoot:'タイプシュート'};", "typeshoot:'タイプシュート'"),
 ("    case 'wild': return r.wildWinStreak || 0;",
  "    case 'wild': return r.wildWinStreak || 0;"+CRLF+"    case 'typeshoot': return r.typeShootScore || 0;", "case 'typeshoot': return r.typeShootScore"),
], 'index.html')
print('DONE', file=sys.stderr)
