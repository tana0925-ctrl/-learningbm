/* QRHUNT_V1 — ひみつのQR（校内さがし）児童側
 *
 * ・読み取りは iPad のカメラがやる（QRの中身が /q/<token> というURLだから）。
 *   だからこのファイルには QR読み取りライブラリは要らない。jsQR は撤去した。
 * ・ここがやるのは2つだけ。
 *     (1) ホームに「何枚みつけたか」のカードを出す
 *     (2) サーバの台帳にあって、まだ player に入っていないごほうびを反映する
 * ・APIは1本も増やしていない。既存の /api/student/class-mission の
 *   レスポンスに qrHunt が相乗りしてくる。
 */
(function () {
  'use strict';
  if (window.__QRHUNT_V1) return;
  window.__QRHUNT_V1 = true;

  var state = null;

  function el(id) { return document.getElementById(id); }

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }

  /* ── カードの置き場所 ──
     クラスミッションのカードの、すぐ下に差し込む。新しい画面は作らない。 */
  function ensureCard() {
    var card = el('qrHuntCard');
    if (card) return card;
    var anchor = el('classMissionCard');
    if (!anchor || !anchor.parentNode) return null;
    card = document.createElement('div');
    card.id = 'qrHuntCard';
    card.className = 'hidden bg-white rounded-xl border-2 border-amber-300 p-3 mt-2 shadow-sm';
    card.style.cursor = 'pointer';
    card.onclick = showCollection;
    anchor.parentNode.insertBefore(card, anchor.nextSibling);
    return card;
  }

  /* ── 星だけ出す。番号は出さない ──
     印刷したカードには ①②③ の番号が入っている。画面に「③がまだ」と出すと
     探す範囲が一気に狭まってしまうので、ここは星のかず だけにする。 */
  function stars(found, total) {
    var s = '';
    for (var i = 0; i < total; i++) s += (i < found) ? '⭐️' : '☆';
    return s;
  }

  function render() {
    var card = ensureCard();
    if (!card) return;
    if (!state || !state.total) { card.classList.add('hidden'); return; }
    card.classList.remove('hidden');
    var done = state.found >= state.total;
    card.innerHTML =
      '<div class="flex items-center justify-between gap-2">' +
        '<div class="text-sm font-black text-amber-700">🔒 ' + esc(state.title) + '</div>' +
        '<div class="text-base leading-none">' + stars(state.found, state.total) + '</div>' +
      '</div>' +
      '<div class="mt-1 text-xs text-slate-600">' +
        state.found + ' / ' + state.total + ' まい みつけた' +
        (done ? '　<span class="font-bold text-amber-600">ぜんぶ そろった！</span>' : '') +
      '</div>' +
      (state.words && state.words.length
        ? '<div class="mt-1 text-[10px] text-slate-400">タップすると、もらったことばが読めます</div>'
        : '');
  }

  /* ── もらった「ことば」を読み返す（図鑑がわり。画面は増やさない＝その場のモーダル） ── */
  function showCollection() {
    if (!state || !state.words || !state.words.length) return;
    var bg = document.createElement('div');
    bg.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:9999;display:flex;align-items:center;justify-content:center;padding:16px;';
    var box = document.createElement('div');
    box.className = 'bg-white rounded-xl p-4 shadow-xl';
    box.style.cssText = 'max-width:520px;width:100%;max-height:70vh;overflow:auto;';
    var html = '<div class="font-black text-amber-700 mb-2">🔒 ' + esc(state.title) + '</div>';
    state.words.forEach(function (w) {
      html += '<div class="border-t border-slate-100 py-2 text-sm text-slate-700">' + esc(w) + '</div>';
    });
    html += '<button class="mt-3 w-full bg-slate-200 rounded-lg py-2 text-sm font-bold">とじる</button>';
    box.innerHTML = html;
    box.querySelector('button').onclick = function () { document.body.removeChild(bg); };
    bg.onclick = function (e) { if (e.target === bg) document.body.removeChild(bg); };
    bg.appendChild(box);
    document.body.appendChild(bg);
  }

  /* ── まだ player に入っていないごほうびを反映する ──
     サーバの台帳（qr_finds）が正。ここは反映するだけ。
     反映が終わったら applied を打って、次から降ってこないようにする。 */
  function applyPending(pending) {
    if (!pending || !pending.length) return;
    var done = [];
    pending.forEach(function (p) {
      try {
        if (p.kind === 'coin' && p.coins > 0) {
          player.coins = (player.coins || 0) + p.coins;
        } else if (p.kind === 'monster' && p.monsterId) {
          if (!player.monsters) player.monsters = {};
          if (!Array.isArray(player.pokedex)) player.pokedex = [];
          var id = Number(p.monsterId);
          if (!player.monsters[id]) {
            var nx = (typeof calculateNextExp === 'function') ? calculateNextExp(1) : 60;
            player.monsters[id] = { level: 1, exp: 0, nextExp: nx };
          }
          if (player.pokedex.indexOf(id) < 0) player.pokedex.push(id);
        }
        done.push(p.token);
      } catch (e) { /* 反映できなかったものは applied を打たない＝次回また来る */ }
    });
    if (!done.length) return;
    try { saveData(); } catch (e) {}
    try { if (typeof updatePlayerDisplay === 'function') updatePlayerDisplay(); } catch (e) {}
    fetch('/api/qr/applied', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tokens: done })
    }).catch(function () {});
  }

  /* ── 相乗りの受け口 ──
     class-mission の fetch を包んで、qrHunt を拾う。
     新しいAPI呼び出しは1本も足していない。 */
  var _origFetch = window.fetch;
  window.fetch = function (input, init) {
    var url = (typeof input === 'string') ? input : (input && input.url) || '';
    var p = _origFetch.apply(this, arguments);
    if (url.indexOf('/api/student/class-mission') === 0) {
      p.then(function (res) {
        try {
          res.clone().json().then(function (j) {
            if (!j || !j.qrHunt) { state = null; render(); return; }
            state = j.qrHunt;
            render();
            applyPending(state.pending);
          }).catch(function () {});
        } catch (e) {}
        return res;
      }).catch(function () {});
    }
    return p;
  };
})();
