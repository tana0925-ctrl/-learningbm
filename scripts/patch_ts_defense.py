# typeshoot.js: 防御を「飛んでくる敵の弾の文字を打って撃ち落とす」方式(v0.3)に変更する
# 既存の野生バトル等には影響しない（typeshoot.js内のみ）。報酬無効化は維持。
import sys
p = 'public/typeshoot.js'
s = open(p, encoding='utf-8').read()

if 'spawnEnemyWord' in s:
    print('already v0.3 defense, skip')
    sys.exit(0)

old_cpu = "  function cpuFire() { if (!S.open || S.ended || !S.ready) return; spawnMissile('down', '\U0001F4A7'); }"
new_cpu = (
"  function spawnEnemyWord() {\n"
"    var f = el('tsField'); if (!f || !S.ready) return;\n"
"    var w = WORDS[Math.floor(Math.random() * WORDS.length)];\n"
"    var pats = romaPatterns(w);\n"
"    var box = document.createElement('div');\n"
"    var x = 14 + Math.random() * Math.max(10, (f.clientWidth - 110));\n"
"    box.style.cssText = 'position:absolute;left:' + x + 'px;top:18px;background:#7f1d1d;border:2px solid #fca5a5;border-radius:8px;padding:2px 8px;text-align:center;min-width:48px';\n"
"    box.innerHTML = '<div style=\"font-size:16px;font-weight:800;color:#fff;letter-spacing:1px\">' + w + '</div><div style=\"font-size:11px;color:#fecaca;letter-spacing:1px\">' + pats[0] + '</div>';\n"
"    f.appendChild(box);\n"
"    S.missiles.push({ node: box, dir: 'down', y: 18, word: w, pats: pats });\n"
"  }\n"
"  function cpuFire() { if (!S.open || S.ended || !S.ready) return; spawnEnemyWord(); }"
)
assert s.count(old_cpu) == 1, ('cpu', s.count(old_cpu))
s = s.replace(old_cpu, new_cpu, 1)

combo_disp = "if (el('tsCombo')) el('tsCombo').textContent = S.combo >= 2 ? ('コンボ ×' + S.combo + '！') : '';"
old_block = (
"      var t = S.typed + e.key.toLowerCase();\n"
"      if (isPrefix(t, S.pats)) {\n"
"        S.typed = t; renderTyped();\n"
"        if (isComplete(S.typed, S.pats)) {\n"
"          S.combo++;\n"
"          " + combo_disp + "\n"
"          if (S.mode === 'attack') spawnMissile('up', getMyMonster().sprite);\n"
"          else interceptNearest();\n"
"          setWord();\n"
"        }\n"
"      } else {\n"
"        S.combo = 0; if (el('tsCombo')) el('tsCombo').textContent = '';\n"
"        var tw = el('tsTyped'); if (tw) { tw.style.color = '#ef4444'; setTimeout(function () { if (tw) tw.style.color = '#a78bfa'; }, 200); }\n"
"      }"
)
new_block = (
"      var t = S.typed + e.key.toLowerCase();\n"
"      if (S.mode === 'attack') {\n"
"        if (isPrefix(t, S.pats)) {\n"
"          S.typed = t; renderTyped();\n"
"          if (isComplete(S.typed, S.pats)) {\n"
"            S.combo++; " + combo_disp + "\n"
"            spawnMissile('up', getMyMonster().sprite); setWord();\n"
"          }\n"
"        } else {\n"
"          S.combo = 0; if (el('tsCombo')) el('tsCombo').textContent = '';\n"
"          var tw = el('tsTyped'); if (tw) { tw.style.color = '#ef4444'; setTimeout(function () { if (tw) tw.style.color = '#a78bfa'; }, 200); }\n"
"        }\n"
"      } else {\n"
"        var cands = [];\n"
"        for (var ci = 0; ci < S.missiles.length; ci++) { var cm = S.missiles[ci]; if (cm.dir === 'down' && cm.pats && isPrefix(t, cm.pats)) cands.push(cm); }\n"
"        if (cands.length) {\n"
"          S.typed = t; renderTyped();\n"
"          var done = null, dy = -1;\n"
"          for (var cj = 0; cj < cands.length; cj++) { if (isComplete(t, cands[cj].pats) && cands[cj].y > dy) { dy = cands[cj].y; done = cands[cj]; } }\n"
"          if (done) { var di = S.missiles.indexOf(done); if (di >= 0) rm(di, done); S.combo++; " + combo_disp + " S.typed = ''; renderTyped(); }\n"
"        } else {\n"
"          S.combo = 0; if (el('tsCombo')) el('tsCombo').textContent = '';\n"
"          var tw2 = el('tsTyped'); if (tw2) { tw2.style.color = '#ef4444'; setTimeout(function () { if (tw2) tw2.style.color = '#a78bfa'; }, 200); }\n"
"        }\n"
"      }"
)
assert s.count(old_block) == 1, ('block', s.count(old_block))
s = s.replace(old_block, new_block, 1)

s = s.replace('しさく版 v0.2', 'しさく版 v0.3', 1)
s = s.replace('[TypeShoot v0.2] loaded', '[TypeShoot v0.3 defense] loaded', 1)

open(p, 'w', encoding='utf-8').write(s)
print('patched typeshoot.js to v0.3 defense')
