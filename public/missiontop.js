/* 🏅 MISSION_TOP_V1 クラス共同ミッションの「活やく トップ3」と ボーナス — 2026-11-15
 *  ・クラスミッションの カードの 下に トップ3（正解した 数）を 出す
 *  ・ミッション達成 ＆ しめきり（なければ 達成）で きまる。自分が トップ3なら「🏅 ボーナスを 受け取る」
 *  ・index.html の updateClassMissionUI を つつんで うごく（手で 編集しない）
 */
(function () {
  'use strict';
  if (window.__MISSION_TOP_V1__) return; window.__MISSION_TOP_V1__ = 1;
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  var MED = ['🥇', '🥈', '🥉'];
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
      var pv = (!r.final && r.preview && r.preview[t.rank - 1]) ? r.preview[t.rank - 1] : null;
      return '<div style="display:flex;justify-content:space-between;gap:6px;' + (t.me ? 'font-weight:900;color:#b45309' : '') + '"><span>' + MED[t.rank - 1] + ' ' + esc(t.name) + (t.me ? '（あなた）' : '') + '</span><span>' + t.n + '問' + (pv && pv.coins ? ' ・ボーナス +' + pv.coins : '') + '</span></div>';
    }).join('');
    if (!r.final) h += '<div style="font-size:11px;color:#92400e;margin-top:2px">ミッションを 達成すると、トップ3に ボーナス！（しめきりで きまるよ）</div>';
    var bo = r.bonus;
    if (bo) {
      if (bo.claimed) h += '<div style="margin-top:4px;font-weight:900;color:#15803d">✅ トップ3ボーナス 受け取りずみ</div>';
      else h += '<button type="button" id="cmTopBtn" style="margin-top:6px;width:100%;background:#f59e0b;color:#fff;border:0;border-radius:10px;padding:8px;font-weight:900;font-size:14px;cursor:pointer">🏅 ' + bo.rank + '位ボーナス（+' + bo.coins + 'コイン' + (bo.shards ? '＋' + bo.shards + 'かけら' : '') + '）を 受け取る</button>';
    }
    b.innerHTML = h;
    var btn = document.getElementById('cmTopBtn'); if (btn) btn.onclick = claim;
  }
  function load() {
    var id = ''; try { id = window.__classMissionId || ''; } catch (e) {}
    return api('/api/student/class-mission/top' + (id ? '?id=' + encodeURIComponent(id) : ''), { method: 'GET' }).then(function (r) { if (r && r.ok && r.missionId) { cur = r; render(r); } else { var b = document.getElementById('cmTopBox'); if (b) b.style.display = 'none'; } }).catch(function () {});
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
    var g = function () { var p = f.apply(this, arguments); Promise.resolve(p).then(function () { var card = document.getElementById('classMissionCard'); if (card && !card.classList.contains('hidden')) load(); }); return p; };
    g.__mt = 1; window.updateClassMissionUI = g;
    try { var card = document.getElementById('classMissionCard'); if (card && !card.classList.contains('hidden')) load(); } catch (e) {}
    return true;
  }
  var tries = 0; (function t() { if (wrap() || ++tries > 40) return; setTimeout(t, 500); })();
  window.MISSIONTOP = { load: load, render: render };
})();
