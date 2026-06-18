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
  var YOON = { 'きゃ':['kya'],'きゅ':['kyu'],'きょ':['kyo'],'しゃ':['sha','sya'],'しゅ':['shu','syu'],'しょ':['sho','syo'],'ちゃ':['cha','tya'],'ちゅ':['chu','tyu'],'ちょ':['cho','tyo'],'にゃ':['nya'],'にゅ':['nyu'],'にょ':['nyo'],'ひゃ':['hya'],'ひゅ':['hyu'],'ひょ':['hyo'],'みゃ':['mya'],'みゅ':['myu'],'みょ':['myo'],'りゃ':['rya'],'りゅ':['ryu'],'りょ':['ryo'],'ぎゃ':['gya'],'ぎゅ':['gyu'],'ぎょ':['gyo'],'じゃ':['ja','zya','jya'],'じゅ':['ju','zyu','jyu'],'じょ':['jo','zyo','jyo'],'びゃ':['bya'],'びゅ':['byu'],'びょ':['byo'],'ぴゃ':['pya'],'ぴゅ':['pyu'],'ぴょ':['pyo'],'ぢゃ':['ja','dya'],'ぢゅ':['ju','dyu'],'ぢょ':['jo','dyo'] };
  function romaPatterns(word) {
    var sets = []; var i = 0; var dbl = false;
    while (i < word.length) {
      var c = word[i], c2 = word[i + 1];
      if (c === 'っ') { dbl = true; i++; continue; }
      var opts;
      if (c2 && YOON[c + c2]) { opts = YOON[c + c2].slice(); i += 2; }
      else if (ROMA[c]) { opts = ROMA[c].slice(); i += 1; }
      else { return [word]; }
      if (dbl) { opts = opts.map(function (o) { return /^[aiueo]/.test(o) ? o : o[0] + o; }); dbl = false; }
      sets.push(opts);
    }
    var out = [''];
    for (var s = 0; s < sets.length; s++) {
      var next = [];
      for (var a = 0; a < out.length; a++) for (var b = 0; b < sets[s].length; b++) next.push(out[a] + sets[s][b]);
      out = next; if (out.length > 256) out = out.slice(0, 256);
    }
    return out;
  }
  function isPrefix(t, p) { for (var i = 0; i < p.length; i++) if (p[i].indexOf(t) === 0) return true; return false; }
  function isComplete(t, p) { for (var i = 0; i < p.length; i++) if (p[i] === t) return true; return false; }

  var TIERS = [
    ['あり','いか','いぬ','うし','うま','かに','かば','かめ','ぎふ','くま','さい','さる','せみ','ぞう','たい','たこ','ちば','つき','とら','とり','なら','にじ','ねこ','はち','ぶた','へび','ほし','やぎ','りす','わに','いちご','いるか','うさぎ','えいご','からす','きつね','きりん','くじら','こあら','こくご','さかな','さくら','すいか','ずこう','たぬき','だんご','つくえ','つくし','とちぎ','とまと','ながの','なごや','はさみ','ばなな','ぱんだ','ひみこ','ひょう','びわこ','ぶどう','ぷりん','ぺりー','みかん','めだか','めろん','もみじ','りんご'],
    ['あさがお','あじさい','えんぴつ','おおさか','おきなわ','おにぎり','おんがく','かごしま','かみなり','かもしか','からあげ','がっこう','がんじん','きょうと','きんぎょ','くまもと','くろねこ','ぐらたん','こうえん','こうもり','こすもす','さいたま','さっぽろ','さんすう','ざびえる','しまうま','せんせい','せんだい','せんべい','たいいく','たいやき','たいよう','たべもの','たんぽぽ','てつぼう','ともだち','どーなつ','ながぐつ','ながさき','にいがた','ひこうき','ひまわり','ひょうご','ひろしま','ふくおか','ふくろう','ふじさん','ぺんぎん','ほしぞら','やきそば','らいおん'],
    ['あかとんぼ','ありがとう','おべんとう','おむらいす','かぶとむし','こんにちは','こんにゃく','さようなら','しゅくだい','しょくぱん','じゅぎょう','せんぷうき','たからもの','たまごやき','だんごむし','ちょうちょ','つだうめこ','とうきょう','なつやすみ','はりねずみ','はんばーぐ','みずたまり','りゅうぐう'],
    ['うんどうかい','おだのぶなが','きどたかよし','きゅうしゅう','きゅうしょく','ぎゅうにゅう','たいようけい','だてまさむね','ちゃわんむし','どうぶつえん','のぐちひでよ'],
    ['あけちみつひで','いしだみつなり','いとうひろぶみ','いのうただたか','いわくらともみ','かつかいしゅう','かのうえいとく','さなだゆきむら','すぎたげんぱく','すぎはらちうね','せんのりきゅう','たけだしんげん','なつめそうせき','ひぐちいちよう','ひらがげんない','ふくざわゆきち','まつおばしょう','みやもとむさし','むらさきしきぶ','あしかがたかうじ','あしかがよしまさ','あしかがよしみつ','いたがきたいすけ','うえすぎけんしん','うたがわひろしげ','おおくぼとしみち','おおくましげのぶ','かつしかほくさい','きたがわうたまろ','さいごうたかもり','さかもとりょうま','しょうとくたいし','しょうむてんのう','せいしょうなごん','たいらのきよもり','とくがわいえみつ','とくがわいえやす','とくがわよしむね','とよとみひでよし','もとおりのりなが','すがわらのみちざね','なかとみのかまたり','ふじわらのみちなが','ほうじょうときむね','みなもとのよしつね','みなもとのよりとも','きたざとしばさぶろう','ちかまつもんざえもん','なかのおおえのおうじ']
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
    mode:'attack', raf:null, missiles:[], cpuTimer:null, ended:false, last:0, party:[], activeIdx:0, enemy:null, enemyParty:[], enemyIdx:0, enemyType:'normal', baseType:'normal', score:0 };

  var TYPE_JA = { normal:'ノーマル', fire:'ほのお', water:'みず', grass:'くさ', electric:'でんき', flying:'ひこう', rock:'いわ', ground:'じめん', ice:'こおり', fighting:'かくとう', psychic:'エスパー', dark:'あく', steel:'はがね', fairy:'フェアリー', ghost:'ゴースト', bug:'むし', poison:'どく', dragon:'ドラゴン' };
  var TYPE_COLOR = { normal:'#9ca3af', fire:'#ef4444', water:'#3b82f6', grass:'#22c55e', electric:'#eab308', flying:'#60a5fa', rock:'#a16207', ground:'#b45309', ice:'#22d3ee', fighting:'#b91c1c', psychic:'#ec4899', dark:'#374151', steel:'#64748b', fairy:'#f472b6', ghost:'#7c3aed', bug:'#84cc16', poison:'#a21caf', dragon:'#4338ca' };
  function typeBadge(elm, prefix) { var col = TYPE_COLOR[elm] || '#9ca3af'; return '<span style="display:inline-block;background:' + col + ';color:#fff;font-size:13px;font-weight:800;padding:2px 11px;border-radius:11px;box-shadow:0 1px 3px rgba(0,0,0,.45)">' + (prefix || '') + typeJa(elm) + '</span>'; }
  function typeJa(t) { return TYPE_JA[t] || t || '？'; }
  var ENEMY_POOL = null;
  function buildEnemyPool() {
    if (ENEMY_POOL) return; ENEMY_POOL = {};
    try {
      var s = window.MONSTERS; if (!s) return;
      var arr = Array.isArray(s) ? s : Object.keys(s).map(function (k) { return s[k]; });
      for (var i = 0; i < arr.length; i++) { var m = arr[i]; if (m && m.elementType && m.sprite) { (ENEMY_POOL[m.elementType] = ENEMY_POOL[m.elementType] || []).push({ sprite: m.sprite, name: m.name || '', el: m.elementType }); } }
    } catch (e) {}
  }
  var ENEMY_CYCLE = ['grass','fire','water','electric','flying','rock','ice','ground','fighting','psychic','dark','steel','fairy','ghost','bug','poison','dragon','normal'];
  function setEnemy(stage) {
    buildEnemyPool();
    var want = ENEMY_CYCLE[(stage - 1) % ENEMY_CYCLE.length];
    function pick(type) { var pool = (ENEMY_POOL && ENEMY_POOL[type]) || []; return pool.length ? pool[Math.floor(Math.random() * pool.length)] : null; }
    var leader = pick(want) || { sprite: '🏯', name: 'きち', el: 'normal' };
    S.enemyParty = [{ sprite: leader.sprite, name: leader.name, el: leader.el }];
    for (var k = 0; k < 2; k++) { var m2 = pick(ENEMY_CYCLE[Math.floor(Math.random() * ENEMY_CYCLE.length)]); if (m2) S.enemyParty.push({ sprite: m2.sprite, name: m2.name, el: m2.el }); }
    S.enemyIdx = 0; S.enemyType = leader.el; S.enemy = S.enemyParty[0];
    var cc = el('tsCpuChar'); if (cc) cc.textContent = leader.sprite;
    var ei = el('tsEnemyInfo'); if (ei) ei.textContent = '／ ' + (leader.name ? leader.name + ' ' : '') + typeJa(leader.el) + '（せんとう）';
    var ct = el('tsCpuType'); if (ct) ct.innerHTML = typeBadge(leader.el, 'きちタイプ：');
    if (S.party && S.party.length) renderParty();
  }
  function loadParty() {
    S.party = []; var seen = {};
    function pushMon(rawId) { var id = Number(rawId); if (!isFinite(id) || seen[id]) return; var m = window.getMonster && window.getMonster(id); if (m) { seen[id] = 1; S.party.push({ id: id, sprite: m.sprite || '⭐', name: m.name || '', el: m.elementType || 'normal' }); } }
    try {
      var p = window.getPlayer && window.getPlayer();
      var ids = (p && p.party && p.party.length) ? p.party : [];
      for (var i = 0; i < ids.length && S.party.length < 3; i++) { var e = ids[i]; if (e && typeof e === 'object') e = e.i || e.id || e.mid; pushMon(e); }
      if (S.party.length < 3 && p && p.monsters) { var owned = Object.keys(p.monsters); for (var j = 0; j < owned.length && S.party.length < 3; j++) pushMon(owned[j]); }
    } catch (e) {}
    if (!S.party.length) S.party = [{ sprite: '⭐', name: 'スター', el: 'normal' }];
    S.activeIdx = 0; renderParty(); var mc = el('tsMyChar'); if (mc && S.party[0]) mc.textContent = S.party[0].sprite; var mt = el('tsMyType'); if (mt && S.party[0]) mt.innerHTML = typeBadge(S.party[0].el, 'こうげき：'); S.baseType = S.party[0] ? S.party[0].el : 'normal'; var bi = el('tsMyBaseInfo'); if (bi) bi.textContent = '／ きちタイプ ' + typeJa(S.baseType);
  }
  function activeMon() { return S.party && S.party[S.activeIdx]; }
  function renderParty() {
    var c = el('tsParty'); if (!c) return; c.innerHTML = '';
    var lab = document.createElement('span'); lab.textContent = 'じゅんばん：'; lab.style.cssText = 'align-self:center;font-size:11px;color:#64748b';
    c.appendChild(lab);
    for (var i = 0; i < S.party.length; i++) {
      var m = S.party[i]; var tip = '';
      var ef = effFactor(m.el, S.enemyType); if (ef.f >= 2) tip = '◎'; else if (ef.f <= 0.5) tip = '▽';
      var b = document.createElement('span');
      b.textContent = (i === S.activeIdx ? '▶' : (i + 1) + '.') + m.sprite + typeJa(m.el) + tip;
      b.style.cssText = 'border-radius:10px;padding:5px 9px;font-size:13px;font-weight:800;' + (i === S.activeIdx ? 'background:#f59e0b;color:#1f2937;outline:2px solid #fcd34d' : 'background:#1e293b;color:#cbd5e1');
      c.appendChild(b);
    }
  }
  function setActive(i) { if (i < 0 || i >= S.party.length) return; S.activeIdx = i; renderParty(); var mc = el('tsMyChar'); if (mc && S.party[i]) mc.textContent = S.party[i].sprite; var mt = el('tsMyType'); if (mt && S.party[i]) mt.innerHTML = typeBadge(S.party[i].el, 'こうげき：'); }
  function rotateParty() { if (S.party.length) setActive((S.activeIdx + 1) % S.party.length); }
  function rotateEnemy() { if (!S.enemyParty.length) return; S.enemyIdx = (S.enemyIdx + 1) % S.enemyParty.length; var cc = el('tsCpuChar'); if (cc) cc.textContent = S.enemyParty[S.enemyIdx].sprite; }
  function effFactor(at, dt) {
    var mult = 1; try { mult = window.getElementTypeMultiplier(at, [dt]); } catch (e) { mult = 1; }
    if (mult > 1.05) return { f: 2.0, label: 'こうかバツグン！', color: '#fca5a5' };
    if (mult === 0) return { f: 0.4, label: 'こうかなし…', color: '#94a3b8' };
    if (mult < 0.95) return { f: 0.5, label: 'いまひとつ', color: '#93c5fd' };
    return { f: 1.0, label: '', color: '#fde047' };
  }
  function getMyMonster() { var a = activeMon(); return { sprite: a ? a.sprite : '⭐' }; }
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
        '<div id="tsScore" style="font-weight:800;font-size:14px;color:#86efac">スコア 0</div>' +
        '<button id="tsClose" style="background:#334155;color:#fff;border:none;border-radius:8px;padding:6px 12px;font-weight:700;cursor:pointer">とじる</button>' +
      '</div>' +
      '<div style="padding:8px 14px"><div style="font-size:12px;color:#94a3b8">あいて の きち<span id="tsEnemyInfo" style="color:#fca5a5;font-weight:700"></span></div>' +
        '<div style="background:#1e293b;border-radius:8px;height:14px;overflow:hidden;margin-top:3px"><div id="tsCpuBar" style="height:14px;background:#ef4444;width:100%;transition:width .3s"></div></div></div>' +
      '<div id="tsField" style="position:relative;flex:1;margin:4px 14px;border-radius:12px;background:#111a2e;overflow:hidden">' +
        '<div id="tsCpuChar" style="position:absolute;top:8px;left:0;right:0;text-align:center;font-size:34px">🏯</div>' +
        '<div id="tsCpuType" style="position:absolute;top:52px;left:0;right:0;text-align:center"></div>' +
        '<div id="tsMyType" style="position:absolute;bottom:52px;left:0;right:0;text-align:center"></div>' +
        '<div id="tsMyChar" style="position:absolute;bottom:8px;left:0;right:0;text-align:center;font-size:34px">🛡️</div>' +
        '<div id="tsCount" style="position:absolute;inset:0;display:none;align-items:center;justify-content:center;font-size:80px;font-weight:900;color:#fbbf24"></div>' +
      '</div>' +
      '<div style="padding:6px 14px"><div style="font-size:12px;color:#94a3b8">じぶん の きち<span id="tsMyBaseInfo" style="color:#86efac;font-weight:700"></span></div>' +
        '<div style="background:#1e293b;border-radius:8px;height:14px;overflow:hidden;margin-top:3px"><div id="tsMyBar" style="height:14px;background:#4ade80;width:100%;transition:width .3s"></div></div></div>' +
      '<div style="display:flex;gap:8px;justify-content:center;padding:8px 14px 0">' +
        '<button id="tsAtkBtn" style="border:none;border-radius:10px;padding:8px 18px;font-weight:800;cursor:pointer">⚔ こうげき</button>' +
        '<button id="tsDefBtn" style="border:none;border-radius:10px;padding:8px 18px;font-weight:800;cursor:pointer">🛡 ぼうぎょ</button>' +
        '<span style="align-self:center;font-size:11px;color:#64748b">（スペースで こうげき／ぼうぎょ　キャラは順番に交代）</span>' +
      '</div>' +
      '<div id="tsParty" style="display:flex;gap:6px;justify-content:center;padding:6px 14px 0;flex-wrap:wrap"></div>' +
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
  function updateScore() { if (el('tsScore')) el('tsScore').textContent = 'スコア ' + (S.score || 0); }
  function stageBanner(text) {
    var c = el('tsCount'); if (!c) return;
    c.style.fontSize = '40px'; c.textContent = text; c.style.display = 'flex';
    setTimeout(function () { if (c) { c.style.display = 'none'; c.style.fontSize = '80px'; } }, 900);
  }

  function spawnMissile(dir, emoji, atkType) {
    var f = el('tsField'); if (!f) return;
    var m = document.createElement('div');
    var x = 20 + Math.random() * (f.clientWidth - 60);
    var startY = dir === 'up' ? f.clientHeight - 50 : 20;
    m.textContent = emoji;
    m.style.cssText = 'position:absolute;font-size:26px;left:' + x + 'px;top:' + startY + 'px';
    f.appendChild(m);
    S.missiles.push({ node: m, dir: dir, y: startY, atkType: atkType });
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
      if (mo.dir === 'up' && mo.y <= 26) { hitCpu(mo); rm(i, mo); }
      else if (mo.dir === 'down' && mo.y >= fh - 40) { hitMe(mo); rm(i, mo); }
    }
    S.raf = requestAnimationFrame(loop);
  }
  function rm(i, mo) { try { mo.node.remove(); } catch (e) {} S.missiles.splice(i, 1); }
  function hitCpu(mo) {
    var at = (mo && mo.atkType) || (activeMon() && activeMon().el) || 'normal';
    var dt = S.enemyType || 'normal';
    var eff = effFactor(at, dt);
    var dmg = Math.round(18 * eff.f);
    S.score = (S.score || 0) + Math.round(10 * eff.f) + (S.combo || 0); updateScore();
    S.cpuHp = Math.max(0, S.cpuHp - dmg); setBars(); fxBar('tsCpuBar', '#fde047');
    var f = el('tsField'); if (f) { fxBurst(f.clientWidth / 2 - 14, 2, '💥'); if (eff.label) fxFloat(f.clientWidth / 2 - 40, 18, eff.label, eff.color); }
    if (S.cpuHp <= 0) nextStage();
  }
  function nextStage() {
    fxClear(S.stage);
    S.stage++;
    S.myHp = Math.min(100, S.myHp + 20);
    S.cpuHpMax = stageCpuHpMax(S.stage);
    S.cpuHp = S.cpuHpMax;
    setEnemy(S.stage);
    for (var i = S.missiles.length - 1; i >= 0; i--) { try { S.missiles[i].node.remove(); } catch (e) {} }
    S.missiles = [];
    S.typed = ''; renderTyped(); setBars(); updateStageLabel();
    if (S.cpuTimer) clearInterval(S.cpuTimer);
    S.cpuTimer = setInterval(cpuFire, stageInterval(S.stage));
    S.score = (S.score || 0) + 100; updateScore();
    stageBanner('ステージ ' + S.stage);
    setWord();
  }
  function hitMe(mo) { var ie = (mo && mo.inEff) || 1; var mult = ie >= 2 ? 1.5 : (ie <= 0.5 ? 0.6 : 1); var dmg = Math.round(15 * mult); S.myHp = Math.max(0, S.myHp - dmg); setBars(); flash(); fxBar('tsMyBar', '#fca5a5'); var f = el('tsField'); if (f) { fxBurst(f.clientWidth / 2 - 14, f.clientHeight - 58, '💥'); fxShake(f); } if (S.myHp <= 0) finish(false); }
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
    var atkEl = (S.enemyParty[S.enemyIdx] && S.enemyParty[S.enemyIdx].el) || S.enemyType || 'normal';
    var eff = effFactor(atkEl, S.baseType);
    var col = TYPE_COLOR[atkEl] || '#9ca3af';
    var border = eff.f >= 2 ? '#f87171' : '#fca5a5';
    var box = document.createElement('div');
    var x = 14 + Math.random() * Math.max(10, (f.clientWidth - 110));
    box.style.cssText = 'position:absolute;left:' + x + 'px;top:18px;background:#7f1d1d;border:2px solid ' + border + ';border-radius:8px;padding:2px 8px;text-align:center;min-width:52px' + (eff.f >= 2 ? ';box-shadow:0 0 9px #f87171' : '');
    var tag = eff.f >= 2 ? '<div style="font-size:10px;font-weight:800;color:#fecaca">⚠ばつぐん</div>' : (eff.f <= 0.5 ? '<div style="font-size:10px;color:#bfdbfe">いまひとつ</div>' : '');
    box.innerHTML = '<div style="font-size:10px;font-weight:800;color:#fff;background:' + col + ';border-radius:7px;padding:0 6px;display:inline-block;margin-bottom:1px">' + typeJa(atkEl) + '</div>' + tag + '<div style="font-size:16px;font-weight:800;color:#fff;letter-spacing:1px">' + w + '</div><div style="font-size:11px;color:#fecaca;letter-spacing:1px">' + pats[0] + '</div>';
    f.appendChild(box);
    S.missiles.push({ node: box, dir: 'down', y: 18, word: w, pats: pats, inEff: eff.f, atkEl: atkEl });
  }
  function cpuFire() { if (!S.open || S.ended || !S.ready) return; spawnEnemyWord(); rotateEnemy(); }

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
            var am = activeMon(); spawnMissile('up', am ? am.sprite : '⭐', am ? am.el : 'normal'); rotateParty(); setWord();
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
          if (done) { var dx = parseFloat(done.node.style.left) || 0; var dyy = done.y || 0; var di = S.missiles.indexOf(done); if (di >= 0) rm(di, done); fxBurst(dx, dyy, '💥'); fxFloat(dx, dyy, 'ナイス！', '#93c5fd'); S.score = (S.score || 0) + 15 + (S.combo || 0); updateScore(); S.combo++; if (el('tsCombo')) el('tsCombo').textContent = S.combo >= 2 ? ('コンボ ×' + S.combo + '！') : ''; S.typed = ''; renderTyped(); }
        } else {
          S.combo = 0; if (el('tsCombo')) el('tsCombo').textContent = '';
          var tw2 = el('tsTyped'); if (tw2) { tw2.style.color = '#ef4444'; setTimeout(function () { if (tw2) tw2.style.color = '#a78bfa'; }, 200); }
        }
      }
    }
  }

  function startGame() {
    build();
    S.open = true; S.ended = false; S.ready = false; S.myHp = 100; S.stage = 1; S.cpuHpMax = stageCpuHpMax(1); S.cpuHp = S.cpuHpMax; S.combo = 0; S.missiles = []; S.last = 0; S.score = 0;
    el('tsOverlay').style.display = 'flex';
    buildEnemyPool(); loadParty(); setEnemy(1);
    el('tsResult').style.display = 'none';
    setMode('attack'); setBars(); setWord(); updateStageLabel(); updateScore();
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
    var best = S.score || 0; var isNewBest = false;
    try { var _p = window.getPlayer && window.getPlayer(); if (_p) { var prevBest = Number(_p._cachedTypeShootScore || 0); isNewBest = (S.score || 0) > prevBest; best = Math.max(prevBest, S.score || 0); _p._cachedTypeShootScore = best; if (window.saveData) window.saveData(); } } catch (e) {}
    var r = el('tsResult');
    r.innerHTML = '<div style="font-size:56px">🎌</div>' +
      '<div style="font-size:26px;font-weight:800;color:#fbbf24">ステージ ' + S.stage + ' まで とうたつ！</div>' +
      '<div style="font-size:30px;font-weight:900;color:#86efac;margin-top:8px">スコア ' + (S.score || 0) + '</div>' +
      '<div style="font-size:13px;color:#94a3b8;margin-top:2px">' + (isNewBest ? '🎉 ベスト更新！' : 'ベスト ' + best) + '</div>' +
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
  /* ===== ともだち対戦（タイプシュート VS） 最小版 ===== */
  var V = null;
  function vMyMon() {
    try {
      var p = window.getPlayer && window.getPlayer();
      var id = p && p.party && p.party[0];
      if (id && typeof id === 'object') id = id.i || id.id;
      id = Number(id);
      var m = isFinite(id) && window.getMonster ? window.getMonster(id) : null;
      if (m) return { sprite: m.sprite || '⭐', el: m.elementType || 'normal' };
    } catch (e) {}
    return { sprite: '⭐', el: 'normal' };
  }
  function vBuild() {
    if (el('tsvOverlay')) return;
    var o = document.createElement('div');
    o.id = 'tsvOverlay';
    o.style.cssText = 'position:fixed;inset:0;z-index:100001;background:#0b1220;color:#f1f5f9;display:none;flex-direction:column;font-family:system-ui,sans-serif;overflow:hidden';
    o.innerHTML =
      '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;background:#0f172a">' +
        '<div style="font-weight:700;color:#a78bfa">⚔ タイプシュート たいせん</div>' +
        '<div id="tsvInfo" style="font-size:13px;color:#fbbf24"></div>' +
        '<button id="tsvClose" style="background:#334155;color:#fff;border:none;border-radius:8px;padding:6px 12px;font-weight:700;cursor:pointer">やめる</button>' +
      '</div>' +
      '<div style="padding:8px 14px"><div style="font-size:12px;color:#94a3b8">あいて <span id="tsvOppName"></span> の きち</div>' +
        '<div style="background:#1e293b;border-radius:8px;height:14px;overflow:hidden;margin-top:3px"><div id="tsvOppBar" style="height:14px;background:#ef4444;width:100%;transition:width .3s"></div></div></div>' +
      '<div id="tsvField" style="position:relative;flex:1;margin:4px 14px;border-radius:12px;background:#111a2e;overflow:hidden">' +
        '<div style="position:absolute;top:8px;left:0;right:0;text-align:center;font-size:30px">🏯</div>' +
        '<div id="tsvMyChar" style="position:absolute;bottom:8px;left:0;right:0;text-align:center;font-size:30px">🙂</div>' +
        '<div id="tsvCount" style="position:absolute;inset:0;display:none;align-items:center;justify-content:center;font-size:80px;font-weight:900;color:#fbbf24"></div>' +
      '</div>' +
      '<div style="padding:6px 14px"><div style="font-size:12px;color:#94a3b8">じぶん の きち</div>' +
        '<div style="background:#1e293b;border-radius:8px;height:14px;overflow:hidden;margin-top:3px"><div id="tsvMyBar" style="height:14px;background:#4ade80;width:100%;transition:width .3s"></div></div></div>' +
      '<div style="display:flex;gap:8px;justify-content:center;padding:8px 14px 0">' +
        '<button id="tsvAtkBtn" style="border:none;border-radius:10px;padding:8px 18px;font-weight:800;cursor:pointer">⚔ こうげき</button>' +
        '<button id="tsvDefBtn" style="border:none;border-radius:10px;padding:8px 18px;font-weight:800;cursor:pointer">🛡 ぼうぎょ</button>' +
        '<span style="align-self:center;font-size:11px;color:#64748b">（スペースで切替）</span>' +
      '</div>' +
      '<div style="padding:8px 14px 18px;text-align:center;background:#0f172a">' +
        '<div id="tsvWord" style="font-size:32px;font-weight:800;letter-spacing:4px">ねこ</div>' +
        '<div id="tsvTyped" style="font-size:20px;color:#a78bfa;min-height:26px;letter-spacing:2px;margin-top:4px">_</div>' +
        '<div id="tsvHint" style="font-size:13px;color:#64748b;margin-top:2px"></div>' +
      '</div>' +
      '<div id="tsvResult" style="display:none;position:absolute;inset:0;background:rgba(2,6,23,.92);flex-direction:column;align-items:center;justify-content:center;text-align:center"></div>';
    document.body.appendChild(o);
    el('tsvClose').onclick = vClose;
    el('tsvAtkBtn').onclick = function () { vSetMode('attack'); };
    el('tsvDefBtn').onclick = function () { vSetMode('defense'); };
  }
  function vSetMode(m) {
    V.mode = m;
    var a = el('tsvAtkBtn'), d = el('tsvDefBtn');
    if (a && d) {
      a.style.background = m === 'attack' ? '#ef4444' : '#1e293b'; a.style.color = m === 'attack' ? '#fff' : '#94a3b8'; a.style.outline = m === 'attack' ? '3px solid #fca5a5' : 'none';
      d.style.background = m === 'defense' ? '#3b82f6' : '#1e293b'; d.style.color = m === 'defense' ? '#fff' : '#94a3b8'; d.style.outline = m === 'defense' ? '3px solid #93c5fd' : 'none';
    }
  }
  function vSetWord() {
    V.word = pickWord(1 + Math.floor(Math.random() * 9));
    V.pats = romaPatterns(V.word); V.typed = '';
    if (el('tsvWord')) el('tsvWord').textContent = V.word;
    if (el('tsvHint')) el('tsvHint').textContent = 'れい：' + V.pats[0];
    vRenderTyped();
  }
  function vRenderTyped() { if (el('tsvTyped')) el('tsvTyped').textContent = V.typed || '_'; }
  function vSetBars() {
    if (el('tsvOppBar')) el('tsvOppBar').style.width = Math.max(0, V.oppHp) + '%';
    if (el('tsvMyBar')) el('tsvMyBar').style.width = Math.max(0, V.myHp) + '%';
  }
  function vSpawnIncoming(word, ty) {
    var f = el('tsvField'); if (!f) return;
    var pats = romaPatterns(word);
    var col = TYPE_COLOR[ty] || '#9ca3af';
    var box = document.createElement('div');
    var x = 14 + Math.random() * Math.max(10, (f.clientWidth - 110));
    box.style.cssText = 'position:absolute;left:' + x + 'px;top:18px;background:#7f1d1d;border:2px solid #fca5a5;border-radius:8px;padding:2px 8px;text-align:center;min-width:52px';
    box.innerHTML = '<div style="font-size:10px;font-weight:800;color:#fff;background:' + col + ';border-radius:7px;padding:0 6px;display:inline-block;margin-bottom:1px">' + typeJa(ty) + '</div><div style="font-size:16px;font-weight:800;color:#fff;letter-spacing:1px">' + word + '</div><div style="font-size:11px;color:#fecaca;letter-spacing:1px">' + pats[0] + '</div>';
    f.appendChild(box);
    V.missiles.push({ node: box, y: 18, word: word, pats: pats });
  }
  function vFire() {
    var mon = vMyMon();
    vSend({ k: 'f', w: V.word, ty: mon.el, from: V.role }, 0);
    var f = el('tsvField'); if (f) fxFloat(f.clientWidth / 2 - 24, f.clientHeight - 74, 'はっしゃ！' + mon.sprite, '#fca5a5');
    vSetWord();
  }
  function vLoop(ts) {
    if (!V || V.ended) return;
    if (!V.last) V.last = ts;
    var dt = Math.min(50, ts - V.last); V.last = ts;
    if (V.ready) {
      var f = el('tsvField'); var fh = f ? f.clientHeight : 400;
      var speed = 0.06 * dt;
      for (var i = V.missiles.length - 1; i >= 0; i--) {
        var mo = V.missiles[i]; mo.y += speed; mo.node.style.top = mo.y + 'px';
        if (mo.y >= fh - 40) { vHitMe(); try { mo.node.remove(); } catch (e) {} V.missiles.splice(i, 1); }
      }
    }
    V.raf = requestAnimationFrame(vLoop);
  }
  function vHitMe() {
    var f = el('tsvField'); if (f) { fxBurst(f.clientWidth / 2 - 14, f.clientHeight - 58, '💥'); f.style.boxShadow = 'inset 0 0 0 3px #ef4444'; setTimeout(function () { if (f) f.style.boxShadow = 'none'; }, 150); }
    vSend({ k: 'h' }, 15);
  }
  function vKey(e) {
    if (!V || V.ended) return;
    if (e.key === 'Escape') { e.preventDefault(); vClose(); return; }
    if (e.key === ' ' || e.key === 'Spacebar') { e.preventDefault(); vSetMode(V.mode === 'attack' ? 'defense' : 'attack'); return; }
    if (!V.ready) return;
    if (e.key === 'Backspace') { e.preventDefault(); V.typed = V.typed.slice(0, -1); vRenderTyped(); return; }
    if (e.key && e.key.length === 1 && /[a-zA-Z\-]/.test(e.key)) {
      e.preventDefault();
      var t = V.typed + e.key.toLowerCase();
      if (V.mode === 'attack') {
        if (isPrefix(t, V.pats)) { V.typed = t; vRenderTyped(); if (isComplete(V.typed, V.pats)) vFire(); }
        else { V.typed = ''; vRenderTyped(); }
      } else {
        var cands = [];
        for (var ci = 0; ci < V.missiles.length; ci++) { if (isPrefix(t, V.missiles[ci].pats)) cands.push(V.missiles[ci]); }
        if (cands.length) {
          V.typed = t; vRenderTyped();
          var done = null, dy = -1;
          for (var cj = 0; cj < cands.length; cj++) { if (isComplete(t, cands[cj].pats) && cands[cj].y > dy) { dy = cands[cj].y; done = cands[cj]; } }
          if (done) { var fx = parseFloat(done.node.style.left) || 0, fy = done.y || 0; var di = V.missiles.indexOf(done); if (di >= 0) { try { done.node.remove(); } catch (e2) {} V.missiles.splice(di, 1); } var f = el('tsvField'); if (f) fxBurst(fx, fy, '💥'); V.typed = ''; vRenderTyped(); }
        } else { V.typed = ''; vRenderTyped(); }
      }
    }
  }
  function vSend(meta, dmg) {
    if (!V || !V.roomId) return;
    fetch('/api/rt/damage/' + V.roomId, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ damage: dmg || 0, monsterId: 0, eventType: (dmg ? 'self_damage' : 'damage'), meta: meta }) })
      .then(function (r) { return r.json(); }).then(function (d) { if (d && d.eventId) V.mine[d.eventId] = 1; }).catch(function () {});
  }
  function vPoll() {
    if (!V || !V.roomId) return;
    fetch('/api/rt/room/' + V.roomId + '?after=' + V.lastEventId).then(function (r) { return r.json(); }).then(function (d) {
      if (!d || !d.ok) return;
      var room = d.room || {};
      if (V.role === 'host') { V.myHp = room.hostHp; V.oppHp = room.guestHp; } else { V.myHp = room.guestHp; V.oppHp = room.hostHp; }
      vSetBars();
      var evs = d.events || [];
      for (var i = 0; i < evs.length; i++) {
        var ev = evs[i];
        if (ev.id > V.lastEventId) V.lastEventId = ev.id;
        if (!V.synced) continue;
        if (V.mine[ev.id]) continue;
        var m = null; try { m = ev.meta_json ? JSON.parse(ev.meta_json) : null; } catch (e) {}
        if (m && m.from === V.role) continue;
        if (m && m.k === 'f') vSpawnIncoming(m.w, m.ty || 'normal');
      }
      if (!V.synced) V.synced = true;
      if (room.status === 'finished' || room.winner) vFinish(room.winner);
    }).catch(function () {});
  }
  function vFinish(winner) {
    if (!V || V.ended) return; V.ended = true;
    if (V.raf) cancelAnimationFrame(V.raf);
    if (V.poll) { clearInterval(V.poll); V.poll = null; }
    document.removeEventListener('keydown', vKey, true);
    var iWon = (winner === V.role); var draw = (winner === 'draw');
    var r = el('tsvResult');
    r.innerHTML = '<div style="font-size:56px">' + (draw ? '🤝' : (iWon ? '🏆' : '💧')) + '</div>' +
      '<div style="font-size:28px;font-weight:800;color:' + (iWon ? '#4ade80' : '#f87171') + '">' + (draw ? 'ひきわけ' : (iWon ? 'かち！' : 'まけ…')) + '</div>' +
      '<div style="margin-top:18px"><button id="tsvBack" style="background:#334155;color:#fff;border:none;border-radius:10px;padding:10px 18px;font-weight:700;cursor:pointer">とじる</button></div>';
    r.style.display = 'flex';
    el('tsvBack').onclick = vClose;
  }
  function vClose() {
    if (V) { V.ended = true; if (V.raf) cancelAnimationFrame(V.raf); if (V.poll) clearInterval(V.poll); for (var i = 0; i < V.missiles.length; i++) { try { V.missiles[i].node.remove(); } catch (e) {} } }
    document.removeEventListener('keydown', vKey, true);
    if (el('tsvOverlay')) el('tsvOverlay').style.display = 'none';
    V = null;
  }
  function vCountdown(n) {
    var c = el('tsvCount'); if (!c) { if (V) V.ready = true; return; }
    c.style.display = 'flex';
    if (n > 0) { c.textContent = String(n); setTimeout(function () { vCountdown(n - 1); }, 700); }
    else { c.textContent = 'スタート！'; c.style.fontSize = '52px'; setTimeout(function () { c.style.display = 'none'; c.style.fontSize = '80px'; if (V) V.ready = true; }, 600); }
  }
  function startTypeShootVS(roomId, role, oppParty, oppName) {
    try {
      vBuild();
      var mon = vMyMon();
      V = { roomId: roomId, role: role || 'host', oppName: oppName || 'あいて', mode: 'attack', word: '', pats: [], typed: '', myHp: 100, oppHp: 100, missiles: [], raf: null, poll: null, last: 0, ended: false, ready: false, mine: {}, lastEventId: 0, synced: false };
      el('tsvOverlay').style.display = 'flex';
      el('tsvResult').style.display = 'none';
      if (el('tsvOppName')) el('tsvOppName').textContent = oppName || '';
      if (el('tsvMyChar')) el('tsvMyChar').textContent = mon.sprite;
      if (el('tsvInfo')) el('tsvInfo').textContent = 'あいて：' + (oppName || '???');
      vSetMode('attack'); vSetBars(); vSetWord();
      document.addEventListener('keydown', vKey, true);
      V.raf = requestAnimationFrame(vLoop);
      V.poll = setInterval(vPoll, 250);
      vCountdown(3);
    } catch (e) { console.error('[TypeShoot VS] start error', e); }
  }
  window.startTypeShootVS = startTypeShootVS;
  window.startTypeShoot = startGame;

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', injectButton);
  else injectButton();
  setTimeout(injectButton, 2000);
  console.log('[TypeShoot v0.4 endless] loaded');
})();
