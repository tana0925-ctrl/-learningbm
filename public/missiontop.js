/* 🏅 MISSION_TOP_V1 クラス共同ミッションの「活やく トップ3」と ボーナス — 2026-11-15
 *  ・クラスミッションの カードの 下に トップ3（正解した 数）を 出す
 *  ・ミッションを 達成した しゅんかんで きまる（MISSION_TOP_V2）。自分が トップ3なら「🏅 ボーナスを 受け取る」
 *  ・index.html の updateClassMissionUI を つつんで うごく（手で 編集しない）
 */
(function () {
  'use strict';
  if (window.__MISSION_TOP_V1__) return; window.__MISSION_TOP_V1__ = 1;
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  var MED = ['🥇', '🥈', '🥉'];
  var SUF = { correct: '問', catch: 'ひき', wildwin: '勝', streak: '連勝' };
  /* 🎯 MISSION_KIND_V1 ミッションの しゅるいに あわせて カードの ことばを かえる＋野生バトルの できごとを サーバーへ */
  var curKind = '';
  function kindText(r) {
    try {
      var el = document.getElementById('cmProgressText'); if (!el || !r || !r.kind) return;
      var par = el.parentNode; if (!par || par.__mtk === r.kind + (r.unitWord || '')) return;
      var v = el.textContent;
      if (r.kind === 'streak') par.innerHTML = '🔥 クラスの いちばん 連勝 <span class="font-black" id="cmProgressText">' + v + '</span> 連勝';
      else if (r.kind === 'correct' && !/の 正解数$/.test(r.unitWord || '')) par.innerHTML = 'クラス全員で <span class="font-black" id="cmProgressText">' + v + '</span> 問正解';
      else par.innerHTML = 'クラス全員の ' + esc(r.unitWord || '') + '：<span class="font-black" id="cmProgressText">' + v + '</span>';
      par.__mtk = r.kind + (r.unitWord || '');
    } catch (e) {}
  }
  function sendEv(o) { try { if (!(curKind === 'catch' || curKind === 'wildwin' || curKind === 'streak')) return; fetch('/api/student/mission-event', { method: 'POST', credentials: 'include', keepalive: true, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(o) }).catch(function () {}); } catch (e) {} }
  // 野生で つかまえた／勝った を 見はる（index.html の 中の 関数は 外から さわれないので、player の きろくを 2びょうごとに 見る）
  var base = null;
  function pl() { try { return (typeof player !== 'undefined' && player) ? player : null; } catch (e) { return null; } }
  function pollEv() {
    var P = pl(); if (!P) return;
    var log = Array.isArray(P.acquireLog) ? P.acquireLog : [], top = log.length ? Number(log[0].ts) || 0 : 0;
    var won = 0; try { won = Number(P.metrics.battles.pve.won) || 0; } catch (e) {}
    if (!base) { base = { ts: top, won: won }; return; }
    if (top > base.ts) {
      log.filter(function (x) { return Number(x.ts) > base.ts && /野生/.test(String(x.source || '')); }).slice(0, 10).forEach(function (x) {
        var mo = null; try { mo = (typeof getMonster === 'function') ? getMonster(Number(x.id)) : null; } catch (e) {}
        try { if (!mo) mo = ((typeof MONSTERS !== 'undefined' ? MONSTERS : window.MONSTERS) || []).find(function (m) { return m.id === Number(x.id); }); } catch (e) {}
        sendEv({ kind: 'catch', mid: Number(x.id), mname: x.name || (mo && mo.name) || '', mtype: (mo && mo.elementType) || '' });
      });
      base.ts = top;
    }
    if (won > base.won) {
      var st = 1; try { st = (typeof battle !== 'undefined' && battle && battle.winStreak) ? battle.winStreak : 1; } catch (e) {}
      for (var i = 0; i < Math.min(5, won - base.won); i++) sendEv({ kind: 'wildwin', val: st });
      base.won = won;
    }
  }
  setInterval(function () { try { pollEv(); } catch (e) {} }, 2000);
  var cur = null;
  function api(u, o) { if (typeof window.apiJson === 'function') return window.apiJson(u, o || { method: 'GET' }); return fetch(u, Object.assign({ credentials: 'include' }, o || {})).then(function (r) { return r.json(); }); }
  function box() {
    var card = document.getElementById('classMissionCard'); if (!card) return null;
    var b = document.getElementById('cmTopBox');
    if (!b) { b = document.createElement('div'); b.id = 'cmTopBox'; b.style.cssText = 'margin-top:8px;background:#fffbeb;border:2px solid #fde68a;border-radius:12px;padding:6px 10px;font-size:13px;color:#78350f'; card.appendChild(b); }
    return b;
  }
  function render(r) {
    var b = box(); if (!b) return;
    var top = (r && r.top) || [];
    if (!top.length) { b.style.display = 'none'; return; }
    b.style.display = '';
    var h = '<div style="font-weight:900">🏅 活やく トップ3 ' + (r.final ? '（きまり！）' : '（いま）') + '</div>';
    h += top.map(function (t) {
      var bc = Number(t.coins) || 0, bs = Number(t.shards) || 0;   // MISSION_TOP_V4 ボーナスも 見せる
      return '<div style="display:flex;justify-content:space-between;gap:6px;' + (t.me ? 'font-weight:900;color:#b45309' : '') + '"><span>' + MED[t.rank - 1] + ' ' + esc(t.name) + (t.me ? '（あなた）' : '') + '</span><span>' + t.n + (SUF[r.kind] || '問') + (bc ? ' ・🎁 +' + bc + 'コイン' + (bs ? '＋' + bs + 'かけら' : '') : '') + '</span></div>';
    }).join('');
    if (!r.final) h += '<div style="font-size:11px;color:#92400e;margin-top:2px">ミッションを 達成した しゅんかんの トップ3に ボーナス！</div>';
    var bo = r.bonus;
    if (bo) {
      if (bo.claimed) h += '<div style="margin-top:4px;font-weight:900;color:#15803d">✅ トップ3ボーナス 受け取りずみ</div>';
      else h += '<button type="button" id="cmTopBtn" style="margin-top:6px;width:100%;background:#f59e0b;color:#fff;border:0;border-radius:10px;padding:8px;font-weight:900;font-size:14px;cursor:pointer">🏅 ' + bo.rank + '位ボーナス（+' + bo.coins + 'コイン' + (bo.shards ? '＋' + bo.shards + 'かけら' : '') + '）を 受け取る</button>';
    }
    b.innerHTML = h;
    var btn = document.getElementById('cmTopBtn'); if (btn) btn.onclick = claim;
  }
  function jst(x) { try { var d = new Date(Date.parse(String(x).replace(' ', 'T') + 'Z') + 9 * 3600000); return (d.getUTCMonth() + 1) + '/' + d.getUTCDate() + '（' + '日月火水木金土'[d.getUTCDay()] + '）' + d.getUTCHours() + ':' + String(d.getUTCMinutes()).padStart(2, '0'); } catch (e) { return ''; } }
  // ⏰ MISSION_RESERVE_V1 予約された ミッションの「予告」
  function renderUp(r) {
    var old = document.getElementById('cmUpBox'); var card = document.getElementById('classMissionCard'); if (!card) return;
    var up = r && r.upcoming;
    if (!up) { if (old) old.remove(); if (card.__mtUpOnly) { card.classList.add('hidden'); card.__mtUpOnly = 0; } return; }
    var txt = '⏰ つぎの ミッション「' + esc(up.title) + '」は <b>' + esc(jst(up.startAt)) + '</b> から スタート！（目標 ' + up.goalCorrect + '問・ごほうび ' + up.rewardCoins + 'コイン）';
    if (card.classList.contains('hidden')) {
      // いま 進行中が ない ときは カードを 予告だけで 見せる
      card.classList.remove('hidden'); card.__mtUpOnly = 1;
      Array.prototype.forEach.call(card.children, function (ch) { if (ch.id !== 'cmUpBox') ch.style.display = 'none'; });
    }
    if (!old) { old = document.createElement('div'); old.id = 'cmUpBox'; old.style.cssText = 'margin-top:8px;background:#e0f2fe;border:2px solid #7dd3fc;border-radius:12px;padding:6px 10px;font-size:13px;color:#075985;font-weight:700'; card.appendChild(old); }
    old.style.display = ''; old.innerHTML = txt;
  }
  function load() {
    var id = ''; try { id = window.__classMissionId || ''; } catch (e) {}
    return api('/api/student/class-mission/top' + (id ? '?id=' + encodeURIComponent(id) : ''), { method: 'GET' }).then(function (r) { try { renderUp(r); } catch (e) {} if (r && r.ok && r.missionId) { cur = r; curKind = r.kind || 'correct'; kindText(r); render(r); } else { var b = document.getElementById('cmTopBox'); if (b) b.style.display = 'none'; } }).catch(function () {});
  }
  function claim() {
    if (!cur || !cur.missionId) return;
    var btn = document.getElementById('cmTopBtn'); if (btn) { btn.disabled = true; btn.textContent = '受け取り中...'; }
    api('/api/student/class-mission/' + encodeURIComponent(cur.missionId) + '/top-claim', { method: 'POST' }).then(function (res) {
      if (res && (res.rewardCoins || res.rewardShards)) {
        try {
          player.coins = (player.coins || 0) + (res.rewardCoins || 0);
          try { if (typeof player.oldCoinDailyStart != 'undefined') player.oldCoinDailyStart = (player.coins || 0); } catch (e) {}
          if (res.rewardShards && window.labAddShards) window.labAddShards(res.rewardShards);
          if (window.updatePlayerDisplay) window.updatePlayerDisplay();
        } catch (e) {}
      }
      load();
    }).catch(function () { if (btn) { btn.disabled = false; btn.textContent = 'もう一回 おしてね'; } });
  }
  function wrap() {
    var f = window.updateClassMissionUI;
    if (typeof f !== 'function' || f.__mt) return !!(f && f.__mt);
    var g = function () { var card0 = document.getElementById('classMissionCard'); if (card0 && card0.__mtUpOnly) { card0.__mtUpOnly = 0; card0.classList.add('hidden'); Array.prototype.forEach.call(card0.children, function (ch) { ch.style.display = ''; }); }
      var p = f.apply(this, arguments); Promise.resolve(p).then(function () { load(); }); return p; };
    g.__mt = 1; window.updateClassMissionUI = g;
    try { load(); } catch (e) {}
    return true;
  }
  /* MISSION_TOP_V4 🎁ごほうび（ヘッダーの ごほうびボックス）にも トップ3ボーナスを 出す */
  function wrapBox() {
    var f = window._rbRenderBox; if (typeof f !== 'function' || f.__mt) return !!(f && f.__mt);
    var g = async function () {
      var p = f.apply(this, arguments); try { await p; } catch (e) {}
      try {
        var id = window.__classMissionId || '';
        var r = await api('/api/student/class-mission/top' + (id ? '?id=' + encodeURIComponent(id) : ''), { method: 'GET' });
        var body = document.getElementById('rewardBoxBody'); if (!body || !r || !r.bonus) return;
        var bo = r.bonus, d = document.createElement('div');
        d.style.cssText = 'border:2px solid ' + (bo.claimed ? '#e5e7eb' : '#fcd34d') + ';border-radius:12px;padding:10px;margin-bottom:12px;background:' + (bo.claimed ? '#f9fafb' : '#fffbeb');
        d.innerHTML = '<div style="font-weight:900;color:#b45309">🏅 クラスミッション 活やくトップ3 ボーナス</div><div style="font-size:13px;margin:2px 0">' + MED[bo.rank - 1] + ' ' + bo.rank + '位！ +' + bo.coins + 'コイン' + (bo.shards ? '＋' + bo.shards + 'かけら' : '') + '</div>'
          + (bo.claimed ? '<div style="color:#16a34a;font-weight:900;font-size:13px">✅ 受け取り済み</div>' : '<button type="button" style="margin-top:4px;width:100%;background:#f59e0b;color:#fff;border:0;border-radius:10px;padding:9px;font-weight:900;cursor:pointer">🎉 受け取る</button>');
        var b = d.querySelector('button'); if (b) b.onclick = function () { cur = r; b.disabled = true; b.textContent = '受け取り中...'; claim(); setTimeout(function () { try { window._rbRenderBox(); } catch (e) {} }, 1200); };
        body.insertBefore(d, body.firstChild);
      } catch (e) {}
      return p;
    };
    g.__mt = 1; window._rbRenderBox = g; return true;
  }
  var tries2 = 0; (function t2() { if (wrapBox() || ++tries2 > 40) return; setTimeout(t2, 500); })();
  var tries = 0; (function t() { if (wrap() || ++tries > 40) return; setTimeout(t, 500); })();
  window.MISSIONTOP = { load: load, render: render };

  /* 📣 MISSION_START_NOTE_V1（2026-11-18 先生の指示）ミッションが はじまったら、子どもに 1回だけ おしらせ（カードは ステータス画面に しか ないので） */
  function startNote() {
    if (/teacher|pj|chitosele/.test(location.pathname)) return;
    api('/api/student/class-mission', { method: 'GET' }).then(function (r) {
      var m = r && r.mission; if (!m || m.achieved || m.claimed) return;
      var k = 'cmSeen:' + m.id; try { if (localStorage.getItem(k)) return; } catch (e) {}
      if (document.getElementById('cmStartNote')) return;
      var d = document.createElement('div'); d.id = 'cmStartNote';
      d.style.cssText = 'position:fixed;left:50%;top:84px;transform:translateX(-50%);z-index:9990;width:min(560px,calc(100vw - 24px));background:#faf5ff;border:3px solid #9333ea;border-radius:18px;box-shadow:0 10px 30px rgba(0,0,0,.25);padding:12px 14px;font-size:16px;line-height:1.6;color:#3b0764';
      var goalW = (m.kind === 'streak') ? ('だれかが ' + m.goalCorrect + '連勝') : ('みんなで ' + m.goalCorrect + (m.kind === 'catch' ? 'ひき' : m.kind === 'wildwin' ? '勝' : '問'));
      d.innerHTML = '<div style="font-weight:900;font-size:18px">🎯 新しい クラスミッションが はじまったで！</div>'
        + '<div style="font-weight:900;margin-top:4px">「' + esc(m.title || 'クラスミッション') + '」</div>'
        + '<div>' + esc(m.unitWord || '正解数') + 'で ' + esc(goalW) + '！' + (m.endAt ? '（' + esc(jst(String(m.endAt).replace(' 23:59:59', ' 14:59:59')).replace(/ ?\d+:\d+$/, '')) + 'まで）' : '') + '</div>'
        + '<div>ごほうび：💰' + (m.rewardCoins || 0) + 'コイン' + (m.rewardShards ? '＋' + m.rewardShards + 'かけら' : '') + '（自分も 参加した人）／ 🏅 活やく トップ3には ボーナス！</div>'
        + '<div style="display:flex;gap:8px;margin-top:8px"><button type="button" id="cmSnGo" style="flex:1;background:#9333ea;color:#fff;border:0;border-radius:12px;padding:10px;font-weight:900;font-size:16px;cursor:pointer">📊 くわしく 見る</button><button type="button" id="cmSnX" style="background:#fff;border:2px solid #d8b4fe;border-radius:12px;padding:10px 14px;font-weight:800;cursor:pointer">とじる</button></div>';
      document.body.appendChild(d);
      var done = function () { try { localStorage.setItem(k, '1'); } catch (e) {} d.remove(); };
      document.getElementById('cmSnX').onclick = done;
      document.getElementById('cmSnGo').onclick = function () { done(); try { if (typeof trySetMode === 'function') trySetMode('status'); } catch (e) {} };
    }).catch(function () {});
  }
  setTimeout(startNote, 7000);
  setInterval(startNote, 10 * 60 * 1000);   // 予約した ミッションが はじまった ときも
})();
