/* ⏱ HSEXTRA_V1 家庭学習「追加ではかる」（子どもの画面）— 2026-11-09
 *  ・きょうの家庭学習を 提出したあとでも、同じ日のうち（朝8:30まで）なら もう一度 タイマーを 回せる。
 *  ・はかった分は きょうの「やった時間」に 足す（/api/homework/add-minutes）。コイン・かけらは ふやさない（1日1回の決まりは そのまま）。
 *  ・タイマーは 開始時刻から 計算（スリープや 画面の切りかえでも ずれない）。とちゅうの 状態は 端末に 控える。
 *  ・先生の「見るだけ」モード・先生のアカウントでは 足さない。
 *  ・index.html は 手で編集しない（hsRender の あとに パネルを 出す）。
 */
(function () {
  'use strict';
  if (window.__HSEXTRA_V1__) return; window.__HSEXTRA_V1__ = 1;

  var $ = function (id) { return document.getElementById(id); };
  function dayKey() { try { return hsGetDayKey830(new Date()); } catch (e) { return ''; } }
  function meKey() { try { return String((window.player && (player.id || player.name)) || ''); } catch (e) { return ''; } }
  function skey() { return 'hsExtraV1:' + meKey() + ':' + dayKey(); }
  function load() { try { var v = JSON.parse(localStorage.getItem(skey()) || 'null'); return v && typeof v === 'object' ? v : null; } catch (e) { return null; } }
  function save(v) { try { if (v) localStorage.setItem(skey(), JSON.stringify(v)); else localStorage.removeItem(skey()); } catch (e) {} }
  function elapsed(v) { if (!v) return 0; var b = Number(v.elapsedMs || 0) || 0; return v.startTs ? b + Math.max(0, Date.now() - v.startTs) : b; }
  function mmss(ms) { var s = Math.floor(ms / 1000), m = Math.floor(s / 60); s = s % 60; return m + ':' + (s < 10 ? '0' : '') + s; }
  function todayEntry() { try { return hsGetEntryForDay(hsLogs(), dayKey()); } catch (e) { return null; } }
  function viewOnly() { return !!window.__VIEWAS_ON__; }
  function teacherAcct() { var r = String(window.__loggedInRole || ''); return !viewOnly() && (r === 'teacher' || r === 'admin'); }

  var msg = '';
  function panel() {
    var p = $('hsExtraPanel');
    if (p) return p;
    var anchor = $('hsTodayInfo');
    if (!anchor || !anchor.parentNode) return null;
    p = document.createElement('div');
    p.id = 'hsExtraPanel';
    p.className = 'mt-2 p-2 rounded-xl border-2 border-sky-200 bg-sky-50 text-sm';
    anchor.parentNode.insertBefore(p, anchor.nextSibling);
    p.addEventListener('click', function (ev) {
      var b = ev.target && ev.target.closest ? ev.target.closest('[data-hx]') : null;
      if (!b) return;
      var a = b.getAttribute('data-hx');
      if (a === 'start') start(); else if (a === 'pause') pause(); else if (a === 'done') done(); else if (a === 'cancel') cancel();
    });
    return p;
  }
  function btn(a, label, cls) { return '<button type="button" data-hx="' + a + '" class="px-3 py-1.5 rounded-full font-bold text-xs shadow-sm ' + cls + '">' + label + '</button>'; }

  var lastSig = '';
  function draw(force) {
    var e = todayEntry(), p = $('hsExtraPanel');
    if (!e || e.restDay) { if (p) p.style.display = 'none'; lastSig = ''; return; }
    var v = load();
    var sig = [dayKey(), e.minutes, !!v, v && !!v.startTs, msg, !!p].join('|');
    if (!force && sig === lastSig && p) return;   // かわっていなければ 書きなおさない（ボタンを おしている 最中に 消えないように）
    p = panel(); if (!p) return;
    lastSig = [dayKey(), e.minutes, !!v, v && !!v.startTs, msg, true].join('|');
    p.style.display = '';
    var h;
    if (!v) {
      h = '<div class="font-bold text-sky-800">⏱ もっと やりたく なったら「追加ではかる」</div>' +
        '<div class="text-[11px] text-slate-500 mb-1">きょうは もう 提出ずみ（' + (Number(e.minutes || 0) || 0) + '分）。追加で はかった 時間は きょうの やった時間に 足されるで（コインは ふえへんよ）。</div>' +
        btn('start', '▶ 追加ではかる', 'bg-sky-500 text-white');
    } else {
      h = '<div class="font-bold text-sky-800">⏱ 追加 <span id="hsExtraClock" class="text-lg">' + mmss(elapsed(v)) + '</span>' + (v.startTs ? '' : '（とめてるで）') + '</div>' +
        '<div class="flex flex-wrap gap-2 mt-1">' +
        btn('pause', v.startTs ? '⏸ 一時停止' : '▶ 再開', 'bg-white text-sky-700 border border-sky-300') +
        btn('done', '✅ おわって 足す', 'bg-emerald-500 text-white') +
        btn('cancel', 'やめる', 'bg-slate-200 text-slate-600') + '</div>';
    }
    if (msg) h += '<div class="text-[12px] font-bold mt-1 ' + (/^✅/.test(msg) ? 'text-emerald-700' : 'text-amber-700') + '">' + msg + '</div>';
    p.innerHTML = h;
  }

  function start() { msg = ''; save({ startTs: Date.now(), elapsedMs: 0 }); draw(); }
  function pause() {
    var v = load(); if (!v) return;
    if (v.startTs) { v.elapsedMs = elapsed(v); v.startTs = null; } else { v.startTs = Date.now(); }
    save(v); draw();
  }
  function cancel() {
    var v = load();
    if (v && elapsed(v) > 60000 && !confirm('はかった 時間を 足さずに やめる？')) return;
    save(null); msg = ''; draw();
  }
  var busy = false;
  async function done() {
    if (busy) return;
    var v = load(); if (!v) return;
    var mins = Math.floor(elapsed(v) / 60000);
    if (mins < 1) { msg = '1分 たったら 足せるで。もうちょっと がんばってみよか！'; draw(); return; }
    if (viewOnly() || teacherAcct()) { msg = '👀 先生用の 画面なので、足されないよ'; draw(); return; }
    busy = true;
    try {
      var r = await apiJson('/api/homework/add-minutes', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ dayKey: dayKey(), minutes: mins }) });
      if (r && r.ok) {
        var e = todayEntry();
        if (e && typeof r.minutes === 'number') { e.minutes = r.minutes; try { saveData(); } catch (x) {} }
        save(null);
        msg = r.added > 0 ? ('✅ ' + r.added + '分 足したで！ きょうは ぜんぶで ' + r.minutes + '分。ようがんばったな！') : '✅ もう 足せる 時間が いっぱいやったで。きょうは ぜんぶで ' + r.minutes + '分！';
        try { hsRender(); } catch (x) {}
      } else {
        msg = (r && r.error === 'not_today') ? '日づけが かわったので 足せへんかったで。また あした はかろな！' : 'うまく 送れへんかった。もう一回 おしてみてな';
      }
    } catch (err) {
      var em = String((err && err.message) || '');
      msg = em === 'not_today' ? '日づけが かわったので 足せへんかったで。また あした はかろな！'
        : em === 'login_required' ? 'ログインが 切れてるみたい。ログインしなおしてから もう一回 おしてな（タイマーは 止めずに のこしとくで）'
        : 'うまく 送れへんかった。もう一回 おしてみてな';
    }
    busy = false; draw();
  }

  // hsRender の あとに いつも 出しなおす
  function hook() {
    if (typeof window.hsRender !== 'function' || window.hsRender.__hx) return !!(window.hsRender && window.hsRender.__hx);
    var orig = window.hsRender;
    var w = function () { var r = orig.apply(this, arguments); try { draw(); } catch (e) {} return r; };
    w.__hx = 1;
    window.hsRender = w;
    return true;
  }
  if (!hook()) { var n = 0, t = setInterval(function () { if (hook() || ++n > 60) clearInterval(t); }, 500); }
  // hsRender が 中から よばれて 上の フックを 通らないときのために、1秒ごとにも たしかめる
  setInterval(function () { try { var ti = $('hsTodayInfo'); if (ti && ti.offsetParent) draw(); var c = $('hsExtraClock'), v = load(); if (c && v) c.textContent = mmss(elapsed(v)); } catch (e) {} }, 1000);
})();
