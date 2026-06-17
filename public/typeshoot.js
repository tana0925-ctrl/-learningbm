/* タイプシュート v0.4（エンドレス）
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

  var TIERS = [
    ['あり','いか','いぬ','うし','うま','かに','かば','かめ','くま','さい','さる','せみ','ぞう','たい','たこ','ちば','つき','とら','とり','なら','にじ','ねこ','はち','ぶた','へび','ほし','やぎ','りす','わに','いちご','いるか','うさぎ','えいご','からす','きつね','きりん','くじら','こあら','こくご','さかな','さくら','すいか','ずこう','たぬき','だんご','つくえ','つくし','とまと','ながの','なごや','はさみ','ばなな','ぱんだ','ひみこ','びわこ','ぶどう','ぷりん','ぺりー','みかん','めだか','めろん','もみじ','りんご'],
    ['あさがお','あじさい','えんぴつ','おおさか','おきなわ','おにぎり','おんがく','かごしま','かみなり','かもしか','からあげ','くまもと','くろねこ','ぐらたん','こうえん','こうもり','こすもす','さいたま','さんすう','ざびえる','しまうま','せんせい','せんだい','せんべい','たいいく','たいやき','たいよう','たべもの','たんぽぽ','てつぼう','ともだち','どーなつ','ながぐつ','ながさき','にいがた','ひこうき','ひまわり','ひろしま','ふくおか','ふくろう','ふじさん','ぺんぎん','ほしぞら','やきそば','らいおん'],
    ['あかとんぼ','ありがとう','おべんとう','おむらいす','かぶとむし','こんにちは','さようなら','せんぷうき','たからもの','たまごやき','だんごむし','つだうめこ','なつやすみ','はりねずみ','はんばーぐ','みずたまり'],
    ['うんどうかい','おだのぶなが','たいようけい','だてまさむね','どうぶつえん','のぐちひでよ'],
    ['あけちみつひで','いしだみつなり','いとうひろぶみ','さなだゆきむら','たけだしんげん','ひらがげんない','ふくざわゆきち','みやもとむさし','むらさきしきぶ','うえすぎけんしん','おおくぼとしみち','さいごうたかもり','たいらのきよもり','とくがわいえやす','とよとみひでよし','すがわらのみちざね','ふじわらのみちなが','みなもとのよりとも']
  ];
  function pickWord(stage) {
    var maxT = Math.min(4, Math.floor((stage - 1) / 3));
    var minT = Math.max(0, maxT - 1);
    var t = minT + Math.floor(Math.random() * (maxT - minT + 1));
    var arr = TIERS[t];
    return arr[Math.floor(Math.random() * arr.length)];
  }
  function stageSpeed(stage) { return Math.min(0.18, 0.06 + 0.004 * (stage - 1)); }
  function stageInterval(stage) { return Math.max(2000, 5500 - 220 * (stage - 1)); }
  function stageCpuHpMax(stage) { return Math.min(400, 100 + 15 * (stage - 1)); }

  var S = { open:false, ready:false, word:'', pats:[], typed:'', myHp:100, cpuHp:100, cpuHpMax:100, stage:1, combo:0,
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
        '<div style="font-weight:700;color:#a78bfa">⌨ タイプシュート</div>' +
        '<div id="tsStage" style="font-weight:800;font-size:16px;color:#fbbf24">ステージ 1</div>' +
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
    if (!document.getElementById('tsFxStyle')) {
      var st = document.createElement('style'); st.id = 'tsFxStyle';
      st.textContent = '@keyframes tsPop{0%{transform:scale(.3);opacity:1}100%{transform:scale(1.9);opacity:0}}@keyframes tsShake{0%,100%{transform:translateX(0)}25%{transform:translateX(-7px)}75%{transform:translateX(7px)}}@keyframes tsRise{0%{transform:translateY(0);opacity:1}100%{transform:translateY(-44px) scale(1.25);opacity:0}}@keyframes tsClearIn{0%{transform:scale(.2) rotate(-12deg);opacity:0}55%{transform:scale(1.15) rotate(5deg);opacity:1}100%{transform:scale(1) rotate(0);opacity:1}}@keyframes tsConfetti{0%{transform:translateY(0) rotate(0);opacity:1}100%{transform:translateY(250px) rotate(560deg);opacity:0}}';
      document.head.appendChild(st);
    }
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
    S.word = pickWord(S.stage);
    S.pats = romaPatterns(S.word); S.typed = '';
    if (el('tsWord')) el('tsWord').textContent = S.word;
    if (el('tsHint')) el('tsHint').textContent = 'れい：' + S.pats[0];
    renderTyped();
  }
  function renderTyped() { if (el('tsTyped')) el('tsTyped').textContent = S.typed || '_'; }
  function setBars() {
    if (el('tsCpuBar')) el('tsCpuBar').style.width = Math.max(0, S.cpuHp / (S.cpuHpMax || 100) * 100) + '%';
    if (el('tsMyBar')) el('tsMyBar').style.width = Math.max(0, S.myHp) + '%';
  }
  function updateStageLabel() { if (el('tsStage')) el('tsStage').textContent = 'ステージ ' + S.stage; }
  function stageBanner(text) {
    var c = el('tsCount'); if (!c) return;
    c.style.fontSize = '40px'; c.textContent = text; c.style.display = 'flex';
    setTimeout(function () { if (c) { c.style.display = 'none'; c.style.fontSize = '80px'; } }, 900);
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
      var mo = S.missiles[i]; var speed = stageSpeed(S.stage) * dt;
      mo.y += mo.dir === 'up' ? -speed : speed;
      mo.node.style.top = mo.y + 'px';
      if (mo.dir === 'up' && mo.y <= 26) { hitCpu(); rm(i, mo); }
      else if (mo.dir === 'down' && mo.y >= fh - 40) { hitMe(); rm(i, mo); }
    }
    S.raf = requestAnimationFrame(loop);
  }
  function rm(i, mo) { try { mo.node.remove(); } catch (e) {} S.missiles.splice(i, 1); }
  function hitCpu() { S.cpuHp = Math.max(0, S.cpuHp - 18); setBars(); fxBar('tsCpuBar', '#fde047'); var f = el('tsField'); if (f) fxBurst(f.clientWidth / 2 - 14, 2, '💥'); if (S.cpuHp <= 0) nextStage(); }
  function nextStage() {
    fxClear(S.stage);
    S.stage++;
    S.myHp = Math.min(100, S.myHp + 20);
    S.cpuHpMax = stageCpuHpMax(S.stage);
    S.cpuHp = S.cpuHpMax;
    for (var i = S.missiles.length - 1; i >= 0; i--) { try { S.missiles[i].node.remove(); } catch (e) {} }
    S.missiles = [];
    S.typed = ''; renderTyped(); setBars(); updateStageLabel();
    if (S.cpuTimer) clearInterval(S.cpuTimer);
    S.cpuTimer = setInterval(cpuFire, stageInterval(S.stage));
    stageBanner('ステージ ' + S.stage);
    setWord();
  }
  function hitMe() { S.myHp = Math.max(0, S.myHp - 15); setBars(); flash(); fxBar('tsMyBar', '#fca5a5'); var f = el('tsField'); if (f) { fxBurst(f.clientWidth / 2 - 14, f.clientHeight - 58, '💥'); fxShake(f); } if (S.myHp <= 0) finish(false); }
  function flash() { var f = el('tsField'); if (f) { f.style.boxShadow = 'inset 0 0 0 3px #ef4444'; setTimeout(function () { if (f) f.style.boxShadow = 'none'; }, 150); } }
  function fxBurst(x, y, emoji, color) {
    var f = el('tsField'); if (!f) return;
    var s = document.createElement('div'); s.textContent = emoji;
    s.style.cssText = 'position:absolute;left:' + x + 'px;top:' + y + 'px;font-size:28px;pointer-events:none;z-index:6;animation:tsPop .5s ease-out forwards';
    if (color) s.style.color = color;
    f.appendChild(s); setTimeout(function () { try { s.remove(); } catch (e) {} }, 520);
  }
  function fxFloat(x, y, text, color) {
    var f = el('tsField'); if (!f) return;
    var s = document.createElement('div'); s.textContent = text;
    s.style.cssText = 'position:absolute;left:' + x + 'px;top:' + y + 'px;font-size:16px;font-weight:800;color:' + (color || '#fbbf24') + ';pointer-events:none;z-index:7;text-shadow:0 1px 3px #000;animation:tsRise .7s ease-out forwards';
    f.appendChild(s); setTimeout(function () { try { s.remove(); } catch (e) {} }, 720);
  }
  function fxShake(node) { if (!node) return; node.style.animation = 'tsShake .3s'; setTimeout(function () { if (node) node.style.animation = ''; }, 320); }
  function fxBar(id, color) { var b = el(id); if (!b) return; var prev = b.style.background; b.style.background = color; setTimeout(function () { if (b) b.style.background = prev; }, 180); }
  function fxClear(stageNum) {
    var f = el('tsField'); if (!f) return;
    var w = f.clientWidth;
    var banner = document.createElement('div');
    banner.textContent = 'ステージ ' + stageNum + ' クリア！';
    banner.style.cssText = 'position:absolute;left:0;right:0;top:36%;text-align:center;font-size:34px;font-weight:900;color:#fde047;text-shadow:0 2px 6px #000;pointer-events:none;z-index:9;animation:tsClearIn .5s ease-out';
    f.appendChild(banner);
    var emo = ['🎉','⭐','🎊','✨','🏅','💫'];
    for (var i = 0; i < 18; i++) {
      var c = document.createElement('div'); c.textContent = emo[i % emo.length];
      c.style.cssText = 'position:absolute;left:' + (Math.random() * w) + 'px;top:-12px;font-size:' + (16 + Math.random() * 16) + 'px;pointer-events:none;z-index:8;animation:tsConfetti ' + (0.9 + Math.random() * 0.9) + 's ease-in forwards';
      f.appendChild(c);
      (function (node) { setTimeout(function () { try { node.remove(); } catch (e) {} }, 2000); })(c);
    }
    setTimeout(function () { try { banner.remove(); } catch (e) {} }, 1100);
  }
  function spawnEnemyWord() {
    var f = el('tsField'); if (!f || !S.ready) return;
    var w = pickWord(S.stage);
    var pats = romaPatterns(w);
    var box = document.createElement('div');
    var x = 14 + Math.random() * Math.max(10, (f.clientWidth - 110));
    box.style.cssText = 'position:absolute;left:' + x + 'px;top:18px;background:#7f1d1d;border:2px solid #fca5a5;border-radius:8px;padding:2px 8px;text-align:center;min-width:48px';
    box.innerHTML = '<div style="font-size:16px;font-weight:800;color:#fff;letter-spacing:1px">' + w + '</div><div style="font-size:11px;color:#fecaca;letter-spacing:1px">' + pats[0] + '</div>';
    f.appendChild(box);
    S.missiles.push({ node: box, dir: 'down', y: 18, word: w, pats: pats });
  }
  function cpuFire() { if (!S.open || S.ended || !S.ready) return; spawnEnemyWord(); }

  function onKey(e) {
    if (!S.open || S.ended || !S.ready) return;
    if (e.key === 'Escape') { e.preventDefault(); closeGame(); return; }
    if (e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); setMode(S.mode === 'attack' ? 'defense' : 'attack'); return; }
    if (e.key === 'Backspace') { e.preventDefault(); S.typed = S.typed.slice(0, -1); renderTyped(); return; }
    if (e.key && e.key.length === 1 && /[a-zA-Z\-]/.test(e.key)) {
      e.preventDefault();
      var t = S.typed + e.key.toLowerCase();
      if (S.mode === 'attack') {
        if (isPrefix(t, S.pats)) {
          S.typed = t; renderTyped();
          if (isComplete(S.typed, S.pats)) {
            S.combo++; if (el('tsCombo')) el('tsCombo').textContent = S.combo >= 2 ? ('コンボ ×' + S.combo + '！') : '';
            spawnMissile('up', getMyMonster().sprite); setWord();
          }
        } else {
          S.combo = 0; if (el('tsCombo')) el('tsCombo').textContent = '';
          var tw = el('tsTyped'); if (tw) { tw.style.color = '#ef4444'; setTimeout(function () { if (tw) tw.style.color = '#a78bfa'; }, 200); }
        }
      } else {
        var cands = [];
        for (var ci = 0; ci < S.missiles.length; ci++) { var cm = S.missiles[ci]; if (cm.dir === 'down' && cm.pats && isPrefix(t, cm.pats)) cands.push(cm); }
        if (cands.length) {
          S.typed = t; renderTyped();
          var done = null, dy = -1;
          for (var cj = 0; cj < cands.length; cj++) { if (isComplete(t, cands[cj].pats) && cands[cj].y > dy) { dy = cands[cj].y; done = cands[cj]; } }
          if (done) { var dx = parseFloat(done.node.style.left) || 0; var dyy = done.y || 0; var di = S.missiles.indexOf(done); if (di >= 0) rm(di, done); fxBurst(dx, dyy, '💥'); fxFloat(dx, dyy, 'ナイス！', '#93c5fd'); S.combo++; if (el('tsCombo')) el('tsCombo').textContent = S.combo >= 2 ? ('コンボ ×' + S.combo + '！') : ''; S.typed = ''; renderTyped(); }
        } else {
          S.combo = 0; if (el('tsCombo')) el('tsCombo').textContent = '';
          var tw2 = el('tsTyped'); if (tw2) { tw2.style.color = '#ef4444'; setTimeout(function () { if (tw2) tw2.style.color = '#a78bfa'; }, 200); }
        }
      }
    }
  }

  function startGame() {
    build();
    S.open = true; S.ended = false; S.ready = false; S.myHp = 100; S.stage = 1; S.cpuHpMax = stageCpuHpMax(1); S.cpuHp = S.cpuHpMax; S.combo = 0; S.missiles = []; S.last = 0;
    el('tsOverlay').style.display = 'flex';
    el('tsResult').style.display = 'none';
    setMode('attack'); setBars(); setWord(); updateStageLabel();
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
    S.cpuTimer = setInterval(cpuFire, stageInterval(S.stage));
  }
  function stopLoops() {
    if (S.cpuTimer) { clearInterval(S.cpuTimer); S.cpuTimer = null; }
    if (S.raf) { cancelAnimationFrame(S.raf); S.raf = null; }
    document.removeEventListener('keydown', onKey, true);
  }
  function finish(win) {
    if (S.ended) return; S.ended = true; S.ready = false; stopLoops();
    // typeshootは作成途中のため、クリア報酬は一旦なし（giveRewardは呼ばない）
    var reward = 0; /* if (win) giveReward(reward); */
    var r = el('tsResult');
    r.innerHTML = '<div style="font-size:56px">🎌</div>' +
      '<div style="font-size:26px;font-weight:800;color:#fbbf24">ステージ ' + S.stage + ' まで とうたつ！</div>' +
      '<div style="font-size:14px;color:#94a3b8;margin-top:6px">よく がんばったね！</div>' +
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
  console.log('[TypeShoot v0.4 endless] loaded');
})();
