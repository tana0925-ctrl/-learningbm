/* 🎁 PJ_REWARD_PICK_V1 家庭学習の ごほうび（アプリの ふつうの 画面）— 2026-11-10
 *  ・自分が 1週間 毎日 出した → 🤝 契約延長券 か 200コイン
 *  ・クラスの 1日の 提出が 90% / 95% / 100% → 🎟 ノーマル券・🎯 ポジション券・💎 レア券 か 200 / 250 / 600コイン
 *  ・先生PJを やらない子も いるので、券 か コインを 本人が えらぶ。「あとで」で とじても のこる。
 *  ・コインは サーバが 足す（_pjGiftCoins 方式）。ここでは 画面の 数字と 端末の 控えを そろえるだけ。
 */
(function () {
  'use strict';
  if (window.__PJGIFT_V1__) return; window.__PJGIFT_V1__ = 1;
  var NM = { ext: '🤝 契約延長券', normal: '🎟 ノーマル券', pos: '🎯 ポジション券', rare: '💎 レア券' };
  var USE = { ext: '先生PJで 選手の 契約を 10日 のばせる', normal: '先生PJで ノーマルスカウトが 1回', pos: '先生PJで ポジション別スカウトが 1回', rare: '先生PJで レアスカウトが 1回' };
  var shown = false, later = {}, lastAt = 0;
  function md(dk) { var p = String(dk || '').split('-'); return p.length < 3 ? '' : Number(p[1]) + '/' + Number(p[2]); }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function why(g) {
    if (g.t === 'lg') return md(g.wk) + 'の 週の リーグ戦（' + (g.sp === 'sc' ? '⚽ サッカー' : '⚾ 野球') + '）、' + (g.rank === 1 ? '🥇 優勝！ おめでとう！' : g.rank === 2 ? '🥈 2位！' : g.rank === 3 ? '🥉 3位！' : g.rank + '位。参加 ありがとう！');
    if (g.why === 'week') return md(g.ws) + 'の 週、学校の日に 毎日 家庭学習を 出したね！';
    return md(g.day) + '、クラスの 家庭学習が ' + (g.n >= g.N ? 'ぜんいん そろった' : Math.floor(g.n / g.N * 100) + '% そろった') + '！ みんなの がんばりや！';
  }
  function viewOnly() { return !!window.__VIEWAS_ON__; }

  function check(force) {
    if (shown || viewOnly()) return;
    if (!force && Date.now() - lastAt < 3 * 60000) return;
    lastAt = Date.now();
    fetch('/api/pj/rewards', { credentials: 'include', cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; }).then(function (j) {
      if (!j || !j.ok || !j.list || !j.list.length) return;
      var g = j.list.filter(function (x) { return !later[x.id]; })[0];
      if (g) show(g, j.eq || {});
    }).catch(function () {});
  }

  function show(g, eq) {
    shown = true;
    var bg = document.createElement('div');
    bg.id = 'pjGiftModal';
    bg.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(15,23,42,.55);display:flex;align-items:center;justify-content:center;padding:16px';
    var amt = g.t === 'lg' ? (Number(g.coins) || 0) : (Number(eq[g.t]) || 0);
    bg.innerHTML = '<div style="background:#fff;border-radius:18px;max-width:420px;width:100%;padding:18px;box-shadow:0 10px 40px rgba(0,0,0,.3);font-family:inherit">'
      + '<div style="font-size:20px;font-weight:900;color:#0f766e">🎁 ごほうびが とどいたよ！</div>'
      + '<div style="margin:8px 0 12px;color:#334155;font-size:14px">' + esc(why(g)) + (g.t === 'lg' ? '' : '<br>どっちに する？') + '</div>'
      + (g.t === 'lg' ? '' : '<button data-pk="tk" style="display:block;width:100%;margin:6px 0;padding:12px;border-radius:14px;border:2px solid #14b8a6;background:#f0fdfa;font-weight:900;font-size:16px;cursor:pointer">' + NM[g.t] + '<br><small style="font-weight:700;color:#475569">' + USE[g.t] + '</small></button>')
      + '<button data-pk="coin" style="display:block;width:100%;margin:6px 0;padding:12px;border-radius:14px;border:2px solid #f59e0b;background:#fffbeb;font-weight:900;font-size:16px;cursor:pointer">💰 ' + amt + 'コイン' + (g.t === 'lg' ? ' うけとる' : '') + '<br><small style="font-weight:700;color:#475569">アプリの なんにでも つかえる</small></button>'
      + '<div style="text-align:center;margin-top:6px"><button data-pk="later" style="border:none;background:none;color:#64748b;font-size:13px;cursor:pointer;text-decoration:underline">あとで えらぶ</button></div>'
      + '<div class="pjg-msg" style="text-align:center;font-weight:900;color:#0f766e;min-height:1.2em"></div></div>';
    document.body.appendChild(bg);
    var busy = false;
    bg.addEventListener('click', function (ev) {
      var b = ev.target && ev.target.closest ? ev.target.closest('[data-pk]') : null;
      if (!b || busy) return;
      var pk = b.getAttribute('data-pk');
      if (pk === 'later') { later[g.id] = 1; close(); return; }
      busy = true;
      fetch('/api/pj/rewards/claim', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ id: g.id, pick: pk }) })
        .then(function (r) { return r.json(); }).then(function (j) {
          var m = bg.querySelector('.pjg-msg');
          if (!j || !j.ok) { busy = false; if (m) m.textContent = 'うまく いかなかったよ。もう一回 おしてね'; return; }
          if (pk === 'coin') {
            try {
              if (window.player) {
                if (typeof j.coins === 'number') player.coins = j.coins; else player.coins = (Number(player.coins) || 0) + (Number(j.amount) || 0);
                if (typeof j.pjGiftCoins === 'number') player._pjGiftCoins = j.pjGiftCoins;
                if (typeof saveData === 'function') saveData();
              }
              var ce = document.getElementById('coinCount'); if (ce && window.player) ce.innerText = player.coins || 0;
            } catch (e) {}
            if (m) m.textContent = '💰 ' + j.amount + 'コイン もらったよ！';
          } else if (m) m.textContent = NM[g.t] + ' を もらったよ！ 先生PJで つかってね';
          setTimeout(function () { close(); try { if (typeof window.PJ_AFTER_GIFT === 'function') window.PJ_AFTER_GIFT(); } catch (e) {} check(true); }, 1300);
        }).catch(function () { busy = false; var m = bg.querySelector('.pjg-msg'); if (m) m.textContent = 'うまく いかなかったよ。もう一回 おしてね'; });
    });
    function close() { try { bg.parentNode.removeChild(bg); } catch (e) {} shown = false; }
  }

  setTimeout(function () { check(true); }, 4000);
  setInterval(function () { check(false); }, 60000);
  document.addEventListener('visibilitychange', function () { if (!document.hidden) check(false); });
  window.PJGIFT = { check: check };
})();
