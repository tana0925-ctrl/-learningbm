/* タイプシュート 試作版 v0.2（1ステージ）
 * 追加: 手持ちキャラ反映 / ⚔こうげき・🛡ぼうぎょ切替 / 3・2・1カウントダウン
 * 独立モード。既存のバトルには干渉しない。
 */
(function () {
  'use strict';

  var ROMA = {
    'あ':['a'],'い':['i'],'う':['u'],'え':['e'],'お':['o'],
    'か':['ka'],'き':['ki'],'く':['ku'],'け':['ke'],'こ':['ko'],
    'さ':['sa'],'し':['shi','si'],'す':['su'],'せ':['se'],'そ':['so'],
    'た':['ta'],'ち':['chi','ti'],'つ':['tsu','tu'],'て':['te'],'と':['to'],
    'な':['na'],'に':['ni'],'ぬ':['nu'],'ね':['ne'],'の':['no'],
    'は':['ha'],'ひ':['hi'],'ふ':['fu','hu'],'へ':['he'],'ほ':['ho'],
    'ま':['ma'],'み':['mi'],'む':['mu'],'め':['me'],'も':['mo'],
    'や':['ya'],'ゆ':['yu'],'よ':['yo'],
    'ら':['ra'],'り':['ri'],'る':['ru'],'れ':['re'],'ろ':['ro'],
    'わ':['wa'],'を':['wo','o'],'ん':['nn','n'],
    'が':['ga'],'ぎ':['gi'],'ぐ':['gu'],'げ':['ge'],'ご':['go'],
    'ざ':['za'],'じ':['ji','zi'],'ず':['zu'],'ぜ':['ze'],'ぞ':['zo'],
    'だ':['da'],'ぢ':['di'],'づ':['du'],'で':['de'],'ど':['do'],
    'ば':['ba'],'び':['bi'],'ぶ':['bu'],'べ':['be'],'ぼ':['bo'],
    'ぱ':['pa'],'ぴ':['pi'],'ぷ':['pu'],'ぺ':['pe'],'ぽ':['po'],'ー':['-']
  };
  function romaPatterns(word) {
    var sets = [];
    for (var i = 0; i < word.length; i++) { var k = ROMA[word[i]]; if (!k) return [word]; sets.push(k); }
    var out = [''];
    for (var s = 0; s < sets.length; s++) {
      var next = [];
      for (var a = 0; a < out.length; a++) for (var b = 0; b < sets[s].length; b++) next.push(out[a] + sets[s][b]);
      out = next; if (out.length > 64) out = out.slice(0, 64);
    }
    return out;
  }
  function isPrefix(t, p) { for (var i = 0; i < p.length; i++) if (p[i].indexOf(t) === 0) return true; return false; }
  function isComplete(t, p) { for (var i = 0; i < p.length; i++) if (p[i] === t) return true; return false; }

  var WORDS = ['ねこ','いぬ','とり','うさぎ','きりん','ぱんだ','さかな','からす',
    'りんご','みかん','ばなな','すいか','とまと','ぶどう',
    'えんぴつ','つくえ','はさみ','ともだち','せんせい','たいいく','ひまわり'];

  var S = { open:false, ready:false, word:'', pats:[], typed:'', myHp:100, cpuHp:100, combo:0,
    mode:'attack', raf:null, missiles:[], cpuTimer:null, ended:false, last:0 };

  function getMyMonster() {
    try {
      var p = window.getPlayer && window.getPlayer();
      var id = p && p.party && p.party[0];
      if (id && typeof id === 'object') id = id.i || id.id;
      if (id != null && window.getMonster) { var m = window.getMonster(id); if (m) return { sprite: m.sprite || '⭐' }; }
    } catch (e) {}
    return { sprite: '⭐' };
  }
  function giveReward(coins) {
    try { if (window.hsGrantRewards) { window.hsGrantRewards({ kind:'coin', coins:coins, shards:0 }, { coins:0, shards:0 }); return; } } catch (e) {}
    try { var p = window.getPlayer && window.getPlayer(); if (p) p.coins = (p.coins || 0) + coins; if (window.saveData) window.saveData(); } catch (e) {}
  }

  var el = function (id) { return document.getElementById(id); };

  function build() {
    if (el('tsOverlay')) return;
    var o = document.createElement('div');
    o.id = 'tsOverlay';
    o.style.cssText = 'position:fixed;inset:0;z-index:100000;background:#0b1220;color:#f1f5f9;display:none;flex-direction:column;font-family:system-ui,sans-serif;overflow:hidden';
    o.innerHTML =
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:#0f172a">' +
        '<div style="font-weight:700;color:#a78bfa">⌨ タイプシュート（しさく版 v0.2）</div>' +
        '<button id="tsClose" style="background:#334155;color:#fff;border:none;border-radius:8px;padding:6px 12px;font-weight:700;cursor:pointer">とじる</button>' +
      '</div>' +
      '<div style="padding:8px 14px"><div style="font-size:12px;color:#94a3b8">あいて の きち</div>' +
        '<div style="background:#1e293b;border-radius:8px;height:14px;overflow:hidden;margin-top:3px"><div id="tsCpuBar" style="height:14px;background:#ef4444;width:100%;transition:width .3s"></div></div></div>' +
      '<div id="tsField" style="position:relative;flex:1;margin:4px 14px;border-radius:12px;background:#111a2e;overflow:hidden">' +
        '<div style="position:absolute;top:8px;left:0;right:0;text-align:center;font-size:30px">🏯</div>' +
        '<div style="position:absolute;bottom:8px;left:0;right:0;text-align:center;font-size:30px">🛡️</div>' +
        '<div id="tsCount" style="position:absolute;inset:0;display:none;align-items:center;justify-content:center;font-size:80px;font-weight:900;color:#fbbf24"></div>' +
      '</div>' +
      '<div style="padding:6px 14px"><div style="font-size:12px;color:#94a3b8">じぶん の きち</div>' +
        '<div style="background:#1e293b;border-radius:8px;height:14px;overflow:hidden;margin-top:3px"><div id="tsMyBar" style="height:14px;background:#4ade80;width:100%;transition:width .3s"></div></div></div>' +
      '<div style="display:flex;gap:8px;justify-content:center;padding:8px 14px 0">' +
        '<button id="tsAtkBtn" style="border:none;border-radius:10px;padding:8px 18px;font-weight:800;cursor:pointer">⚔ こうげき</button>' +
        '<button id="tsDefBtn" style="border:none;border-radius:10px;padding:8px 18px;font-weight:800;cursor:pointer">🛡 ぼうぎょ</button>' +
        '<span style="align-self:center;font-size:11px;color:#64748b">（スペースキーで切替）</span>' +
      '</div>' +
      '<div style="padding:8px 14px 20px;text-align:center;background:#0f172a">' +
        '<div id="tsWord" style="font-size:34px;font-weight:800;letter-spacing:4px">ねこ</div>' +
        '<div id="tsTyped" style="font-size:20px;color:#a78bfa;min-height:26px;letter-spacing:2px;margin-top:4px">_</div>' +
        '<div id="tsHint" style="font-size:13px;color:#64748b;margin-top:2px">れい：neko</div>' +
        '<div id="tsCombo" style="font-size:13px;color:#fbbf24;margin-top:6px;height:18px"></div>' +
      '</div>' +
      '<div id="tsResult" style="display:none;position:absolute;inset:0;background:rgba(2,6,23,.92);flex-direction:column;align-items:center;justify-content:center;text-align:center"></div>';
    document.body.appendChild(o);
    el('tsClose').onclick = closeGame;
    el('tsAtkBtn').onclick = function () { setMode('attack'); };
    el('tsDefBtn').onclick = function () { setMode('defense'); };
  }

  function setMode(m) {
    S.mode = m;
    var a = el('tsAtkBtn'), d = el('tsDefBtn');
    if (a && d) {
      a.style.background = m === 'attack' ? '#ef4444' : '#1e293b';
      a.style.color = m === 'attack' ? '#fff' : '#94a3b8';
      a.style.outline = m === 'attack' ? '3px solid #fca5a5' : 'none';
      d.style.background = m === 'defense' ? '#3b82f6' : '#1e293b';
      d.style.color = m === 'defense' ? '#fff' : '#94a3b8';
      d.style.outline = m === 'defense' ? '3px solid #93c5fd' : 'none';
    }
  }

  function setWord() {
    S.word = WORDS[Math.floor(Math.random() * WORDS.length)];
    S.pats = romaPatterns(S.word); S.typed = '';
    if (el('tsWord')) el('tsWord').textContent = S.word;
    if (el('tsHint')) el('tsHint').textContent = 'れい：' + S.pats[0];
    renderTyped();
  }
  function renderTyped() { if (el('tsTyped')) el('tsTyped').textContent = S.typed || '_'; }
  function setBars() {
    if (el('tsCpuBar')) el('tsCpuBar').style.width = Math.max(0, S.cpuHp) + '%';
    if (el('tsMyBar')) el('tsMyBar').style.width = Math.max(0, S.myHp) + '%';
  }

  function spawnMissile(dir, emoji) {
    var f = el('tsField'); if (!f) return;
    var m = document.createElement('div');
    var x = 20 + Math.random() * (f.clientWidth - 60);
    var startY = dir === 'up' ? f.clientHeight - 50 : 20;
    m.textContent = emoji;
    m.style.cssText = 'position:absolute;font-size:24px;left:' + x + 'px;top:' + startY + 'px';
    f.appendChild(m);
    S.missiles.push({ node: m, dir: dir, y: startY });
  }
  function interceptNearest() {
    var best = -1, bestY = -1;
    for (var i = 0; i < S.missiles.length; i++) { if (S.missiles[i].dir === 'down' && S.missiles[i].y > bestY) { bestY = S.missiles[i].y; best = i; } }
    if (best >= 0) { try { S.missiles[best].node.remove(); } catch (e) {} S.missiles.splice(best, 1); return true; }
    return false;
  }
  function loop(ts) {
    if (!S.open || S.ended) return;
    if (!S.last) S.last = ts;
    var dt = Math.min(50, ts - S.last); S.last = ts;
    var f = el('tsField'); var fh = f ? f.clientHeight : 400;
    for (var i = S.missiles.length - 1; i >= 0; i--) {
      var mo = S.missiles[i]; var speed = 0.12 * dt;
      mo.y += mo.dir === 'up' ? -speed : speed;
      mo.node.style.top = mo.y + 'px';
      if (mo.dir === 'up' && mo.y <= 26) { hitCpu(); rm(i, mo); }
      else if (mo.dir === 'down' && mo.y >= fh - 40) { hitMe(); rm(i, mo); }
    }
    S.raf = requestAnimationFrame(loop);
  }
  function rm(i, mo) { try { mo.node.remove(); } catch (e) {} S.missiles.splice(i, 1); }
  function hitCpu() { S.cpuHp = Math.max(0, S.cpuHp - 18); setBars(); if (S.cpuHp <= 0) finish(true); }
  function hitMe() { S.myHp = Math.max(0, S.myHp - 15); setBars(); flash(); if (S.myHp <= 0) finish(false); }
  function flash() { var f = el('tsField'); if (f) { f.style.boxShadow = 'inset 0 0 0 3px #ef4444'; setTimeout(function () { if (f) f.style.boxShadow = 'none'; }, 150); } }
  function cpuFire() { if (!S.open || S.ended || !S.ready) return; spawnMissile('down', '💧'); }

  function onKey(e) {
    if (!S.open || S.ended || !S.ready) return;
    if (e.key === 'Escape') { e.preventDefault(); closeGame(); return; }
    if (e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); setMode(S.mode === 'attack' ? 'defense' : 'attack'); return; }
    if (e.key === 'Backspace') { e.preventDefault(); S.typed = S.typed.slice(0, -1); renderTyped(); return; }
    if (e.key && e.key.length === 1 && /[a-zA-Z\-]/.test(e.key)) {
      e.preventDefault();
      var t = S.typed + e.key.toLowerCase();
      if (isPrefix(t, S.pats)) {
        S.typed = t; renderTyped();
        if (isComplete(S.typed, S.pats)) {
          S.combo++;
          if (el('tsCombo')) el('tsCombo').textContent = S.combo >= 2 ? ('コンボ ×' + S.combo + '！') : '';
          if (S.mode === 'attack') spawnMissile('up', getMyMonster().sprite);
          else interceptNearest();
          setWord();
        }
      } else {
        S.combo = 0; if (el('tsCombo')) el('tsCombo').textContent = '';
        var tw = el('tsTyped'); if (tw) { tw.style.color = '#ef4444'; setTimeout(function () { if (tw) tw.style.color = '#a78bfa'; }, 200); }
      }
    }
  }

  function startGame() {
    build();
    S.open = true; S.ended = false; S.ready = false; S.myHp = 100; S.cpuHp = 100; S.combo = 0; S.missiles = []; S.last = 0;
    el('tsOverlay').style.display = 'flex';
    el('tsResult').style.display = 'none';
    setMode('attack'); setBars(); setWord();
    if (el('tsCombo')) el('tsCombo').textContent = '';
    document.addEventListener('keydown', onKey, true);
    S.raf = requestAnimationFrame(loop);
    countdown(3);
  }
  function countdown(n) {
    var c = el('tsCount'); if (!c) { begin(); return; }
    c.style.display = 'flex';
    if (n > 0) { c.textContent = String(n); setTimeout(function () { countdown(n - 1); }, 700); }
    else { c.textContent = 'スタート！'; c.style.fontSize = '52px'; setTimeout(function () { c.style.display = 'none'; c.style.fontSize = '80px'; begin(); }, 600); }
  }
  function begin() {
    if (!S.open || S.ended) return;
    S.ready = true;
    if (S.cpuTimer) clearInterval(S.cpuTimer);
    S.cpuTimer = setInterval(cpuFire, 5500);
  }
  function stopLoops() {
    if (S.cpuTimer) { clearInterval(S.cpuTimer); S.cpuTimer = null; }
    if (S.raf) { cancelAnimationFrame(S.raf); S.raf = null; }
    document.removeEventListener('keydown', onKey, true);
  }
  function finish(win) {
    if (S.ended) return; S.ended = true; S.ready = false; stopLoops();
    var reward = win ? 30 : 0; if (win) giveReward(reward);
    var r = el('tsResult');
    r.innerHTML = '<div style="font-size:56px">' + (win ? '🏆' : '💧') + '</div>' +
      '<div style="font-size:28px;font-weight:800;color:' + (win ? '#4ade80' : '#f87171') + '">' + (win ? 'クリア！' : 'まけ…') + '</div>' +
      (win ? '<div style="margin-top:6px;color:#fbbf24">+' + reward + 'コイン</div>' : '') +
      '<div style="margin-top:18px;display:flex;gap:10px">' +
        '<button id="tsRetry" style="background:#6d28d9;color:#fff;border:none;border-radius:10px;padding:10px 18px;font-weight:700;cursor:pointer">もういちど</button>' +
        '<button id="tsBack" style="background:#334155;color:#fff;border:none;border-radius:10px;padding:10px 18px;font-weight:700;cursor:pointer">やめる</button>' +
      '</div>';
    r.style.display = 'flex';
    el('tsRetry').onclick = startGame; el('tsBack').onclick = closeGame;
  }
  function closeGame() {
    S.open = false; S.ready = false; stopLoops();
    for (var i = 0; i < S.missiles.length; i++) { try { S.missiles[i].node.remove(); } catch (e) {} }
    S.missiles = [];
    if (el('tsOverlay')) el('tsOverlay').style.display = 'none';
  }

  function injectButton() {
    if (el('tsLaunchBtn')) return;
    var b = document.createElement('button');
    b.id = 'tsLaunchBtn'; b.textContent = '⌨ タイプシュート';
    b.style.cssText = 'position:fixed;right:12px;bottom:74px;z-index:99998;background:#6d28d9;color:#fff;border:none;border-radius:22px;padding:9px 14px;font-weight:700;font-size:13px;box-shadow:0 3px 12px rgba(0,0,0,.4);cursor:pointer';
    b.onclick = startGame;
    document.body.appendChild(b);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', injectButton);
  else injectButton();
  setTimeout(injectButton, 2000);
  console.log('[TypeShoot v0.2] loaded');
})();
