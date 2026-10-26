/* ✍️ WEEKREF_V1 週の振り返り（子どもの画面）— 2026-10-22
 *
 *  1) 阪神マンのひとこと … 金・土・日（朝8:30前は前の日あつかい）にアプリを開いたら、
 *     「今週のふりかえり、書いてみる？」と1回だけ声をかける。1日1回まで。閉じられる。
 *     もう書いた子には出さない。
 *  2) 書き出しのヒント … 「🔄 今週の振り返り」の自由欄の上に、うすく出す。おすと書き出しが入る。
 *     （振り返りの型を示すと書けるようになる：木村・渡邉・宗實 2024）項目欄は増やさない。
 *  3) 書いたら小さなボーナス … 1週につき1回・5文字以上で20コイン。決めるのはサーバー（台帳）。
 *     ここはサーバーが足した分を、この端末の表示にも同じだけ写すだけ（台帳も同じだけ進める＝二重にならない）。
 *  4) 2週前の振り返りへの返事・過去の週を見たときの返事も、週の計画の画面に出す。
 *
 *  ・index.html は手で編集しない。画面にあるもの（hwReflectionArea など）に足すだけ。
 */
(function () {
  'use strict';
  if (window.__WEEKREF_V1__) return; window.__WEEKREF_V1__ = 1;

  var NUDGE_KEY = 'weekRefNudgeV1';
  var _st = null;            // /api/student/week-ref-status の結果

  function esc(s) {
    return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;');
  }
  function curP() { try { if (typeof player !== 'undefined' && player) return player; } catch (e) {} return window.player || null; }
  // 子どもの画面と同じ数え方（朝8:30前は前の日）
  function dayKey830() {
    try { if (typeof hsGetDayKey830 === 'function') return hsGetDayKey830(new Date()); } catch (e) {}
    var d = new Date(Date.now() - 8.5 * 3600000);
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }
  function isoWeek(ymd) {
    var p = String(ymd).split('-');
    var x = new Date(Date.UTC(Number(p[0]), Number(p[1]) - 1, Number(p[2])));
    x.setUTCDate(x.getUTCDate() + 4 - (x.getUTCDay() || 7));
    var ys = new Date(Date.UTC(x.getUTCFullYear(), 0, 1));
    var w = Math.ceil((((x.getTime() - ys.getTime()) / 86400000) + 1) / 7);
    return x.getUTCFullYear() + '-W' + (w < 10 ? '0' + w : '' + w);
  }
  // WEEKMON_V1 週は月曜0:00から（毎日の日付は dayKey830 のまま）
  function weekDayKey() {
    try { if (typeof hsGetWeekDayKey830 === 'function') return hsGetWeekDayKey830(new Date()); } catch (e) {}
    var n = new Date();
    if (n.getDay() === 1) { var p2 = function (x) { return (x < 10 ? '0' : '') + x; }; return n.getFullYear() + '-' + p2(n.getMonth() + 1) + '-' + p2(n.getDate()); }
    return dayKey830();
  }
  function weekKeyNow() {
    var dk = weekDayKey();
    try { if (typeof hsGetWeekKey === 'function') return hsGetWeekKey(dk); } catch (e) {}
    return isoWeek(dk);
  }
  function prevWeek(wk) {
    try { if (typeof hsPrevWeekKey === 'function') return hsPrevWeekKey(wk); } catch (e) {}
    var m = String(wk).match(/^(\d{4})-W(\d{2})$/); if (!m) return '';
    var j4 = new Date(Date.UTC(Number(m[1]), 0, 4)); var dw = j4.getUTCDay() || 7;
    var mon = new Date(j4.getTime() + ((1 - dw) + (Number(m[2]) - 1) * 7 - 7) * 86400000);
    return isoWeek(mon.getUTCFullYear() + '-' + (mon.getUTCMonth() + 1) + '-' + mon.getUTCDate());
  }
  function isRefDay() {
    var p = weekDayKey().split('-');   /* WEEKMON_V1 月曜0:00からは新しい週（声かけは出さない） */
    var dw = new Date(Date.UTC(Number(p[0]), Number(p[1]) - 1, Number(p[2]))).getUTCDay();
    return dw === 5 || dw === 6 || dw === 0;
  }
  function jget(url) {
    return fetch(url, { credentials: 'include' }).then(function (r) { return r.json(); }).catch(function () { return null; });
  }
  function loadStatus() {
    return jget('/api/student/week-ref-status?weekKey=' + encodeURIComponent(weekKeyNow())).then(function (d) {
      if (d && d.ok) _st = d;
      renderBonusNote();
      return d;
    });
  }

  // ---------- 2) 書き出しのヒント ＋ 3) ボーナスの一言 ----------
  var HINTS = ['今週がんばったことは、', 'うまくいったのは、', 'こまったことは、', '来週ためしたいことは、'];
  function ensureHints() {
    var ta = document.getElementById('hwReflectionInput');
    if (!ta || document.getElementById('weekRefHints')) return;
    var box = document.createElement('div');
    box.id = 'weekRefHints';
    box.setAttribute('style', 'font-size:11px;color:#9a6b4f;opacity:.85;display:flex;flex-wrap:wrap;gap:4px;align-items:center');
    var h = '<span>💡 書き出しのヒント（おすと入るよ）：</span>';
    for (var i = 0; i < HINTS.length; i++) {
      h += '<button type="button" data-h="' + i + '" style="background:#fff7ed;border:1px dashed #fdba74;color:#9a6b4f;border-radius:999px;padding:2px 8px;font-size:11px;cursor:pointer">' + esc(HINTS[i].replace(/、$/, '')) + '</button>';
    }
    box.innerHTML = h;
    box.addEventListener('click', function (ev) {
      var t = ev.target;
      if (!t || t.getAttribute('data-h') == null) return;
      var s = HINTS[Number(t.getAttribute('data-h'))] || '';
      var v = String(ta.value || '');
      ta.value = v + (v && !/\n$/.test(v) ? '\n' : '') + s;
      try { ta.focus(); ta.setSelectionRange(ta.value.length, ta.value.length); } catch (e) {}
    });
    ta.parentNode.insertBefore(box, ta);
    var note = document.createElement('div');
    note.id = 'weekRefBonusNote';
    note.setAttribute('style', 'font-size:11px;color:#c2410c;text-align:center');
    var msg = document.getElementById('hwReflectionMsg');
    if (msg && msg.parentNode) msg.parentNode.insertBefore(note, msg.nextSibling);
    renderBonusNote();
  }
  function renderBonusNote(text) {
    var el = document.getElementById('weekRefBonusNote');
    if (!el) return;
    if (text) { el.textContent = text; return; }
    if (!_st || !_st.student) { el.textContent = ''; return; }
    el.textContent = _st.rewarded
      ? '✅ 今週のふりかえりボーナスは もらったよ。書きなおしても だいじょうぶ'
      : '✍️ ' + (_st.minChars || 5) + '文字いじょう書いて出すと、1週間に1回 ' + (_st.reward || 20) + 'コイン';
  }

  // サーバーが足した分を、この端末にも写す（hwSubmitReflection の送信を横から見るだけ。中身は変えない）
  var _f = window.fetch;
  if (typeof _f === 'function' && !_f.__weekRef) {
    var wrapped = function (input, init) {
      var p = _f.apply(this, arguments);
      try {
        var url = (typeof input === 'string') ? input : (input && input.url) || '';
        var method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
        if (method === 'POST' && url.indexOf('/api/student/weekly-reflection') >= 0) {
          p.then(function (res) {
            try {
              res.clone().json().then(function (j) {
                var b = j && j.weekRefBonus;
                if (!b) return;
                if (b.rewardedNow) {
                  var pl = curP();
                  if (pl) {
                    pl.coins = (Number(pl.coins) || 0) + Number(b.reward || 0);
                    pl._weekRefCoinsApplied = (typeof b.weekRefCoinsApplied === 'number') ? b.weekRefCoinsApplied
                      : (Number(pl._weekRefCoinsApplied) || 0) + Number(b.reward || 0);
                    try { if (typeof updatePlayerDisplay === 'function') updatePlayerDisplay(); } catch (e) {}
                  }
                  if (_st) { _st.rewarded = true; _st.wrote = true; }
                  renderBonusNote('🪙 ' + b.reward + 'コイン ゲット！ ふりかえり、ありがとう');
                  setTimeout(function () { renderBonusNote(); }, 6000);
                } else if (b.tooShort) {
                  if (_st) _st.wrote = true;
                  renderBonusNote('おくったよ。' + (b.minChars || 5) + '文字いじょう書くと、コインがもらえるよ');
                  setTimeout(function () { renderBonusNote(); }, 6000);
                } else if (_st) { _st.wrote = true; if (b.rewarded) _st.rewarded = true; renderBonusNote(); }
              }).catch(function () {});
            } catch (e) {}
          }).catch(function () {});
        }
      } catch (e) {}
      return p;
    };
    wrapped.__weekRef = true;
    window.fetch = wrapped;
  }

  // ---------- 4) 2週前の返事・過去の週の返事 ----------
  function showOldComment(wk, cmt, label) {
    var notice = document.getElementById('hwRewardNotice');
    if (!notice) return;
    var old = document.getElementById('weekRefOldCmt');
    if (old && old.parentNode) old.parentNode.removeChild(old);
    if (!cmt) return;
    var el = document.createElement('div');
    el.id = 'weekRefOldCmt';
    el.className = 'bg-sky-50 border-2 border-sky-300 rounded-xl p-3 space-y-1';
    el.innerHTML = '<div class="font-bold text-sky-800 text-sm">💬 先生からのおへんじ <span class="text-[10px] font-normal text-sky-600">（' + esc(label) + '）</span></div>'
      + '<div class="text-xs text-slate-700 whitespace-pre-wrap"><b>🔄 ふりかえりに…</b> ' + esc(cmt) + '</div>';
    notice.insertBefore(el, notice.firstChild);
    notice.classList.remove('hidden');
    try { localStorage.setItem('hwSeenRefCmt_' + wk, '1'); } catch (e) {}
  }
  function afterRender() {
    ensureHints();
    var off = 0;
    try { if (typeof _hwWeekOffset !== 'undefined') off = Number(_hwWeekOffset) || 0; } catch (e) {}
    var cur = weekKeyNow();
    if (off === 0) {
      loadStatus();
      // 2週前の振り返りへの返事（月曜に返してもらうと、次の週にはもう「先週ぶん」に出なくなるため）
      var w2 = prevWeek(prevWeek(cur));
      if (!w2) return;
      jget('/api/student/weekly-plan-status?weekKey=' + encodeURIComponent(w2)).then(function (d) {
        var s = d && d.status;
        var ok = s && s.reflectionComment && Number(s.reflectionReturnedAt) > Date.now() - 14 * 86400000;
        showOldComment(w2, ok ? s.reflectionComment : '', '2週まえの ふりかえりへ');
      });
    } else {
      var vk = '';
      try { if (typeof hwGetOffsetDayKey === 'function') vk = (typeof hsGetWeekKey === 'function') ? hsGetWeekKey(hwGetOffsetDayKey(off)) : isoWeek(hwGetOffsetDayKey(off)); } catch (e) {}
      if (!vk) return;
      jget('/api/student/weekly-plan-status?weekKey=' + encodeURIComponent(vk)).then(function (d) {
        var s = d && d.status;
        showOldComment(vk, (s && s.reflectionComment) || '', 'この週の ふりかえりへ');
      });
    }
  }
  function hookRender() {
    try {
      if (typeof window.hwRenderWeekView === 'function' && !window.hwRenderWeekView.__weekRef) {
        var orig = window.hwRenderWeekView;
        var w = function () {
          var r;
          try { r = orig.apply(this, arguments); } catch (e) {}
          Promise.resolve(r).then(function () { try { afterRender(); } catch (e) {} }, function () {});
          return r;
        };
        w.__weekRef = true;
        window.hwRenderWeekView = w;
        return true;
      }
    } catch (e) {}
    return false;
  }

  // ---------- 1) 阪神マンのひとこと ----------
  function seenToday() { try { return localStorage.getItem(NUDGE_KEY) === dayKey830(); } catch (e) { return false; } }
  function markSeen() { try { localStorage.setItem(NUDGE_KEY, dayKey830()); } catch (e) {} }
  function closeNudge() { var el = document.getElementById('weekRefNudge'); if (el && el.parentNode) el.parentNode.removeChild(el); }
  function openWrite() {
    closeNudge();
    try {
      if (typeof openHomeStudy === 'function') openHomeStudy();
      else if (typeof trySetMode === 'function') trySetMode('hsweek');
    } catch (e) {}
    var n = 0;
    var t = setInterval(function () {
      n++;
      var area = document.getElementById('hwReflectionArea');
      if (area && !area.classList.contains('hidden')) {
        clearInterval(t);
        try { area.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (e) {}
        var ta = document.getElementById('hwReflectionInput');
        try { if (ta) ta.focus(); } catch (e) {}
      }
      if (n > 20) clearInterval(t);
    }, 300);
  }
  function showNudge() {
    if (document.getElementById('weekRefNudge')) return;
    markSeen();
    var face = '🐯';
    try { if (typeof window.monSpriteHtml === 'function') face = window.monSpriteHtml(154, '🐯'); } catch (e) {}
    var el = document.createElement('div');
    el.id = 'weekRefNudge';
    el.setAttribute('style', 'position:fixed;right:12px;top:84px;z-index:9997;width:330px;max-width:calc(100vw - 24px);background:#fff7ed;border:2px solid #fdba74;border-radius:16px;box-shadow:0 8px 24px rgba(0,0,0,.16);padding:10px 12px;color:#7c2d12');
    el.innerHTML =
      '<button type="button" id="weekRefNudgeX" aria-label="とじる" style="position:absolute;right:6px;top:4px;background:none;border:none;font-size:18px;color:#c2410c;cursor:pointer">×</button>' +
      '<div style="display:flex;gap:8px;align-items:flex-start">' +
        '<div style="font-size:30px;line-height:1">' + face + '</div>' +
        '<div style="flex:1;padding-right:12px">' +
          '<div style="font-weight:900;font-size:14px">今週のふりかえり、書いてみる？</div>' +
          '<div style="font-size:12px;line-height:1.6;margin-top:2px;color:#9a3412">1週間をふりかえると、来週の作戦が見えてくるで。ひとことでもええよ。' +
          ((_st && !_st.rewarded) ? '（' + (_st.reward || 20) + 'コインの おまけつき）' : '') + '</div>' +
        '</div>' +
      '</div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px">' +
        '<button type="button" id="weekRefNudgeNo" style="background:#fff;border:1px solid #fdba74;color:#9a3412;border-radius:10px;padding:6px 12px;font-size:12px;font-weight:700;cursor:pointer">またこんど</button>' +
        '<button type="button" id="weekRefNudgeGo" style="background:#f97316;border:none;color:#fff;border-radius:10px;padding:6px 14px;font-size:12px;font-weight:800;cursor:pointer">書いてみる</button>' +
      '</div>';
    document.body.appendChild(el);
    var x = document.getElementById('weekRefNudgeX'); if (x) x.onclick = closeNudge;
    var no = document.getElementById('weekRefNudgeNo'); if (no) no.onclick = closeNudge;
    var go = document.getElementById('weekRefNudgeGo'); if (go) go.onclick = openWrite;
    setTimeout(closeNudge, 30000);   // 30秒で自然に消える
  }
  function maybeNudge() {
    if (!isRefDay() || seenToday()) return;
    loadStatus().then(function (d) {
      if (!d || !d.ok || !d.student) return;
      if (d.wrote) return;              // もう書いた子には出さない
      if (seenToday()) return;
      // KANTAN_REF_V1 きっかけが ほしそうな子には「1タップで ふりかえり」を（見た目は同じ箱）。kantanref.js が決める。
      try { if (typeof window.kantanRefNudge === 'function' && window.kantanRefNudge(d, showNudge)) return; } catch (e) {}
      showNudge();
    });
  }

  // ---------- 起動 ----------
  var tries = 0, nudged = false;
  var timer = setInterval(function () {
    tries++;
    hookRender();
    ensureHints();
    var pl = curP();
    if (!nudged && pl && pl.userId) { nudged = true; setTimeout(maybeNudge, 4000); }
    if ((nudged && window.hwRenderWeekView && window.hwRenderWeekView.__weekRef) || tries > 60) clearInterval(timer);
  }, 2000);
})();
