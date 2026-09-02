/* 📒 わたしのカルテ（子ども向け）— 2026-09
 *
 *  ・先生が「公開」したときだけ画面に出る。公開していなければ何も出ない。
 *  ・サーバー側は自分の分しか返さない（ほかの子の user_id を渡すと 403）。
 *  ・テストの点数・得点率・順位・ほかの子との比較は一切出さない。
 *  ・数字は「今週 5日のうち○日」のような実数だけ。パーセントは使わない。
 *  ・文章は「その子自身が書いたことば」と「先生が読んで公開したメッセージ」だけ。
 */
(function () {
  'use strict';

  var DOW = ['月', '火', '水', '木', '金'];

  function esc(s) {
    return String(s == null ? '' : s)
      .split('&').join('&amp;')
      .split('<').join('&lt;')
      .split('>').join('&gt;');
  }

  function ensureCard() {
    var el = document.getElementById('myKarteCard');
    if (el) return el;
    var host = document.getElementById('homeReviewSuggest');
    if (!host || !host.parentNode) return null;
    el = document.createElement('div');
    el.id = 'myKarteCard';
    el.style.display = 'none';
    host.parentNode.insertBefore(el, host);
    return el;
  }

  function hide() {
    var el = document.getElementById('myKarteCard');
    if (el) el.style.display = 'none';
  }

  function render(d) {
    if (!d || !d.ok || !d.published) { hide(); return; }
    var el = ensureCard();
    if (!el) return;

    var w = d.week || {};
    var days = w.days || [];
    var cells = '';
    for (var i = 0; i < 5; i++) {
      var s = days[i];
      var mark = '・';
      if (s) {
        mark = (s.weather === 'sun') ? '☀️'
             : (s.weather === 'cloud') ? '☁️'
             : (s.weather === 'rain') ? '🌧️' : '⭕';
      }
      cells += '<div style="text-align:center;flex:1;min-width:38px">'
             + '<div style="font-size:11px;color:#64748b;font-weight:700">' + DOW[i] + '</div>'
             + '<div style="font-size:22px;line-height:1.2">' + mark + '</div></div>';
    }

    var h = '';
    h += '<div class="font-bold text-amber-700">📒 わたしのカルテ</div>';
    h += '<div class="mt-2 rounded-xl border-2 border-amber-200 bg-amber-50 p-3">';
    h += '<div style="display:flex;gap:6px;align-items:flex-end">' + cells + '</div>';
    h += '<div class="mt-2 text-sm font-bold text-amber-800">今週は 5日のうち ' + (w.done || 0) + '日 とりくめたよ'
       + ((w.minutes) ? '（ぜんぶで ' + w.minutes + '分）' : '') + '</div>';

    if (w.voices && w.voices.length) {
      h += '<div class="mt-2"><div class="text-xs font-bold text-amber-700">🗣 じぶんのことば</div>';
      h += '<ul class="text-sm text-gray-700 list-disc pl-5">';
      for (var v = 0; v < w.voices.length; v++) h += '<li>' + esc(w.voices[v]) + '</li>';
      h += '</ul></div>';
    }

    var r = d.reflection;
    if (r && (r.goodPoint || r.improvePoint || r.nextAction)) {
      h += '<div class="mt-2 text-sm text-gray-700"><div class="text-xs font-bold text-amber-700">📝 今週のふりかえり</div>';
      if (r.goodPoint) h += '<div>よかったこと … ' + esc(r.goodPoint) + '</div>';
      if (r.improvePoint) h += '<div>もうすこしなこと … ' + esc(r.improvePoint) + '</div>';
      if (r.nextAction) h += '<div>つぎにやること … ' + esc(r.nextAction) + '</div>';
      h += '</div>';
    }

    if (d.teacherMessage) {
      h += '<div class="mt-3 rounded-xl bg-white border border-amber-200 p-3">'
         + '<div class="text-xs font-bold text-amber-700">👩‍🏫 先生から</div>'
         + '<div class="text-sm text-gray-800" style="white-space:pre-wrap">' + esc(d.teacherMessage) + '</div></div>';
    }

    h += '<div class="text-xs text-gray-500 mt-2">※ 先生が読んで、わたしてくれたものだよ。</div>';
    h += '</div>';

    el.innerHTML = h;
    el.style.display = '';
  }

  var _busy = false;
  var _lastAt = 0;
  function load(force) {
    if (_busy) return;
    // ステータス画面は何度も描き直されるので、60秒に1回までにしておく
    if (!force && _lastAt && (Date.now() - _lastAt) < 60000) return;
    _busy = true;
    _lastAt = Date.now();
    try {
      fetch('/api/student/my-karte', { credentials: 'include' })
        .then(function (res) { return res.json(); })
        .then(function (d) { _busy = false; render(d); })
        .catch(function () { _busy = false; hide(); });
    } catch (e) { _busy = false; }
  }

  // ステータス画面が描かれるタイミングに相乗りする（⚡ミニ復習と同じ瞬間）
  function hook() {
    try {
      if (typeof window.loadMiniReview === 'function' && !window.loadMiniReview.__karteHooked) {
        var orig = window.loadMiniReview;
        var wrapped = function () {
          try { orig.apply(this, arguments); } catch (e) {}
          try { load(); } catch (e) {}
        };
        wrapped.__karteHooked = true;
        window.loadMiniReview = wrapped;
        return true;
      }
    } catch (e) {}
    return false;
  }

  var tries = 0, didFirst = false;
  var timer = setInterval(function () {
    tries++;
    var hooked = hook();
    if (!didFirst && document.getElementById('homeReviewSuggest')) { didFirst = true; load(true); }
    if ((hooked && didFirst) || tries > 30) clearInterval(timer);
  }, 1000);

  try { window.loadMyKarte = load; } catch (e) {}
})();
