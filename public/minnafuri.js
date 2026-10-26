/* 📖 MINNA_FURI_V1 みんなのふりかえり（子どもの画面）— 2026-10-26
 *
 *  1) 振り返り（毎日の家庭学習シート・週の振り返り）の最後に、えらんでもえらばなくてもいい同意の欄。
 *       □ 名前なしで のせてもいいよ　□ 名前ありで のせてもいいよ（どちらか1つ。えらばなければ のせない）
 *       ※ 先生が えらんで、いくつかを しょうかいします。
 *     「のせないで」という選択肢は置かない。チェックを外すと とりけし（すぐ見えなくなる）。
 *     同意できるのは、いまの日／いまの週の、出した振り返りだけ（サーバーで決める）。
 *  2) 「📖 みんなのふりかえり」ページ … 同じクラスの子だけが読める。週ごとのフォルダ（新しい週だけ開いている）。
 *     名前ありは名前だけ、名前なしは名前を出さない。ランキング・点数・いいねは出さない。
 *     じぶんの「のせてもいいよ」を、あとから とりけせる。
 *  ・index.html は手で編集しない。画面にあるもの（hsNextImprove・hwReflectionArea・maejibunEntry）に足すだけ。
 */
(function () {
  'use strict';
  if (window.__MINNAFURI_V1__) return; window.__MINNAFURI_V1__ = 1;

  var pending = { day: null, week: null };   // 出す前にえらんだもの（出したあとで保存する）
  var cur = { day: { ref: '', mode: '' }, week: { ref: '', mode: '' } };

  function esc(s) { return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;'); }
  function $(id) { return document.getElementById(id); }
  function curP() { try { if (typeof player !== 'undefined' && player) return player; } catch (e) {} return window.player || null; }
  function jget(url) { return fetch(url, { credentials: 'include' }).then(function (r) { return r.json(); }).catch(function () { return null; }); }
  function jpost(url, body) {
    return fetch(url, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json(); }).catch(function () { return null; });
  }
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
  function weekKeyNow() {
    var dk = dayKey830();
    try { if (typeof hsGetWeekKey === 'function') return hsGetWeekKey(dk); } catch (e) {}
    return isoWeek(dk);
  }
  function refOf(kind) { return kind === 'week' ? weekKeyNow() : dayKey830(); }
  function wkMonday(wk) {
    var m = String(wk || '').match(/^(\d{4})-W(\d{2})$/); if (!m) return null;
    var j4 = new Date(Date.UTC(Number(m[1]), 0, 4)); var dw = j4.getUTCDay() || 7;
    return new Date(j4.getTime() + ((1 - dw) + (Number(m[2]) - 1) * 7) * 86400000);
  }
  function wkLabel(wk) {
    var mo = wkMonday(wk); if (!mo) return String(wk || '');
    var fr = new Date(mo.getTime() + 4 * 86400000);
    return (mo.getUTCMonth() + 1) + '/' + mo.getUTCDate() + '〜' + (fr.getUTCMonth() + 1) + '/' + fr.getUTCDate() + 'の週';
  }
  var WD = ['日', '月', '火', '水', '木', '金', '土'];
  function dayLabel(ymd) { var p = String(ymd).split('-'); var d = new Date(Date.UTC(+p[0], +p[1] - 1, +p[2])); return (+p[1]) + '/' + (+p[2]) + '(' + WD[d.getUTCDay()] + ')'; }

  // ══════ 1) 同意の欄 ══════
  function boxHtml(kind) {
    var id = 'mfBox_' + kind;
    return '<div style="font-size:12.5px;font-weight:800;color:#0f766e">📖 みんなのふりかえり <span style="font-weight:600;font-size:11px;color:#64748b">（えらばなくても だいじょうぶ）</span></div>'
      + '<div style="display:flex;flex-wrap:wrap;gap:4px 14px;margin-top:3px">'
      + '<label style="display:inline-flex;align-items:center;gap:5px;font-size:13.5px;cursor:pointer;padding:3px 0"><input type="checkbox" id="' + id + '_anon" style="width:20px;height:20px;accent-color:#0d9488"> 名前なしで のせてもいいよ</label>'
      + '<label style="display:inline-flex;align-items:center;gap:5px;font-size:13.5px;cursor:pointer;padding:3px 0"><input type="checkbox" id="' + id + '_named" style="width:20px;height:20px;accent-color:#0d9488"> 名前ありで のせてもいいよ</label>'
      + '</div>'
      + '<div style="font-size:11.5px;color:#475569">※ 先生が えらんで、いくつかを しょうかいします。</div>'
      + '<div id="' + id + '_msg" style="font-size:11px;color:#0f766e;min-height:14px"></div>';
  }
  function setChecks(kind, mode) {
    var a = $('mfBox_' + kind + '_anon'), n = $('mfBox_' + kind + '_named');
    if (a) a.checked = mode === 'anon';
    if (n) n.checked = mode === 'named';
  }
  function say(kind, t) { var m = $('mfBox_' + kind + '_msg'); if (m) m.textContent = t || ''; }
  function bindBox(kind) {
    ['anon', 'named'].forEach(function (md) {
      var el = $('mfBox_' + kind + '_' + md);
      if (!el || el.__mf) return;
      el.__mf = 1;
      el.addEventListener('change', function () {
        var mode = this.checked ? md : '';
        setChecks(kind, mode);   // どちらか1つ
        save(kind, mode);
      });
    });
  }
  function save(kind, mode) {
    var ref = refOf(kind);
    pending[kind] = { ref: ref, mode: mode };
    return jpost('/api/student/minna/consent', { kind: kind, ref: ref, mode: mode }).then(function (j) {
      if (j && j.ok && j.saved) {
        pending[kind] = null; cur[kind] = { ref: ref, mode: mode };
        say(kind, mode ? (mode === 'named' ? '✅ 名前ありで のせてもいいよ、にしたよ' : '✅ 名前なしで のせてもいいよ、にしたよ') : 'とりけしたよ（のらないよ）');
      } else if (j && j.ok && j.reason === 'not_submitted') {
        say(kind, mode ? '出したときに いっしょに つたえるね' : '');
      } else if (j && j.ok && j.reason === 'not_now') {
        pending[kind] = null; setChecks(kind, ''); say(kind, '前の日・前の週の ふりかえりは えらべないよ');
      } else {
        say(kind, mode ? '出したときに いっしょに つたえるね' : '');
      }
      return j;
    });
  }
  function loadMode(kind) {
    var ref = refOf(kind);
    if (cur[kind].ref === ref && cur[kind].loaded) { setChecks(kind, (pending[kind] && pending[kind].ref === ref) ? pending[kind].mode : cur[kind].mode); return; }
    jget('/api/student/minna/consent?kind=' + kind + '&ref=' + encodeURIComponent(ref)).then(function (d) {
      if (!d || !d.ok) return;
      cur[kind] = { ref: ref, mode: d.mode || '', loaded: true };
      setChecks(kind, (pending[kind] && pending[kind].ref === ref) ? pending[kind].mode : cur[kind].mode);
    });
  }
  function ensureDayBox() {
    var ta = $('hsNextImprove');
    if (!ta) return;
    var box = $('mfBox_day');
    if (!box) {
      box = document.createElement('div');
      box.id = 'mfBox_day';
      box.setAttribute('style', 'margin-top:6px;background:#f0fdfa;border:1.5px dashed #5eead4;border-radius:10px;padding:6px 8px;text-align:left');
      box.innerHTML = boxHtml('day');
      // 「つぎにくふうすること」の欄のすぐ下（シートのいちばん最後の書く欄）
      var host = ta.parentNode;
      host.insertBefore(box, ta.nextSibling);
      bindBox('day');
    }
    loadMode('day');
  }
  function ensureWeekBox() {
    var area = $('hwReflectionArea'), ta = $('hwReflectionInput');
    if (!area || !ta) return;
    var off = 0;
    try { if (typeof _hwWeekOffset !== 'undefined') off = Number(_hwWeekOffset) || 0; } catch (e) {}
    var box = $('mfBox_week');
    if (off !== 0) { if (box) box.style.display = 'none'; return; }
    if (!box) {
      box = document.createElement('div');
      box.id = 'mfBox_week';
      box.setAttribute('style', 'background:#f0fdfa;border:1.5px dashed #5eead4;border-radius:10px;padding:6px 8px');
      box.innerHTML = boxHtml('week');
      var after = $('maejibunNext') || ta;
      after.parentNode.insertBefore(box, after.nextSibling);
      bindBox('week');
    }
    box.style.display = '';
    loadMode('week');
  }

  // 出したあとに、えらんでおいた同意を つたえる（送信を横から見るだけ。中身は変えない）
  var _f = window.fetch;
  if (typeof _f === 'function' && !_f.__minna) {
    var wrapped = function (input, init) {
      var p = _f.apply(this, arguments);
      try {
        var url = (typeof input === 'string') ? input : (input && input.url) || '';
        var method = String((init && init.method) || (input && input.method) || 'GET').toUpperCase();
        var kind = (method === 'POST' && url.indexOf('/api/homework/submit') >= 0) ? 'day'
          : (method === 'POST' && url.indexOf('/api/student/weekly-reflection') >= 0) ? 'week' : '';
        if (kind) {
          p.then(function (res) {
            if (!res || !res.ok) return;
            var pd = pending[kind];
            if (pd && pd.mode) setTimeout(function () { save(kind, pd.mode); }, 300);
          }).catch(function () {});
        }
      } catch (e) {}
      return p;
    };
    wrapped.__minna = true;
    if (_f.__weekRef) wrapped.__weekRef = true;
    window.fetch = wrapped;
  }

  // ══════ 2) みんなのふりかえり ページ ══════
  function ensureEntry() {
    if ($('minnaFuriEntry')) return;
    var p = curP(); if (!p || !p.userId) return;
    var host = $('maejibunEntry') || $('homeReviewSuggest');
    if (!host || !host.parentNode) return;
    var el = document.createElement('div');
    el.id = 'minnaFuriEntry';
    el.style.margin = '6px 0 10px';
    el.innerHTML = '<button type="button" id="minnaFuriOpen" style="display:inline-flex;align-items:center;gap:6px;background:#fff;border:1.5px solid #99f6e4;border-radius:999px;padding:6px 14px;cursor:pointer;color:#0f766e;font-weight:800;font-size:13px">📖 みんなのふりかえり <span style="font-weight:600;font-size:11px;color:#64748b">クラスの友だちの ふりかえりを 読む</span></button>';
    host.parentNode.insertBefore(el, host.nextSibling);
    $('minnaFuriOpen').onclick = openPage;
  }
  function closePage() { var o = $('minnaFuriPage'); if (o && o.parentNode) o.parentNode.removeChild(o); try { document.body.style.overflow = ''; } catch (e) {} }
  function openPage() {
    closePage();
    var o = document.createElement('div');
    o.id = 'minnaFuriPage';
    o.setAttribute('role', 'dialog');
    o.setAttribute('style', 'position:fixed;inset:0;z-index:9998;background:rgba(15,23,42,.45);overflow-y:auto;-webkit-overflow-scrolling:touch;padding:16px 10px');
    o.innerHTML = '<div id="minnaFuriBody" style="max-width:760px;margin:0 auto;background:#fff;border-radius:18px;box-shadow:0 12px 40px rgba(0,0,0,.25);padding:14px 16px 18px;color:#1e293b">'
      + head() + '<div style="padding:30px;text-align:center;color:#64748b">よみこみ中…</div></div>';
    o.addEventListener('click', function (ev) { if (ev.target === o) closePage(); });
    document.body.appendChild(o);
    try { document.body.style.overflow = 'hidden'; } catch (e) {}
    bindClose();
    Promise.all([jget('/api/student/minna/posts'), jget('/api/student/minna/mine')]).then(function (rs) { render(rs[0], rs[1]); });
  }
  function head() {
    return '<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:6px">'
      + '<div style="flex:1"><div style="font-size:20px;font-weight:900;color:#0f766e">📖 みんなのふりかえり</div>'
      + '<div style="font-size:12px;color:#475569">クラスの友だちが「のせてもいいよ」と言った ふりかえりを、先生が えらんで しょうかいしているよ。</div></div>'
      + '<button type="button" class="minnaFuriX" aria-label="とじる" style="background:#f1f5f9;border:none;border-radius:999px;width:40px;height:40px;font-size:20px;cursor:pointer;color:#334155">×</button></div>';
  }
  function bindClose() { var xs = document.querySelectorAll('.minnaFuriX'); for (var i = 0; i < xs.length; i++) xs[i].onclick = closePage; }
  function render(d, mine) {
    var box = $('minnaFuriBody'); if (!box) return;
    var h = head();
    var posts = (d && d.posts) || [];
    if (!posts.length) {
      h += '<div style="padding:24px 10px;text-align:center;color:#64748b;font-size:14px">まだ のっている ふりかえりは ないよ。<br>ふりかえりを 書いたら、さいごの「のせてもいいよ」を えらんでみてね。</div>';
    } else {
      var weeks = [], by = {};
      posts.forEach(function (p) { if (!by[p.weekKey]) { by[p.weekKey] = []; weeks.push(p.weekKey); } by[p.weekKey].push(p); });
      weeks.sort().reverse();
      weeks.forEach(function (wk, i) {
        var list = by[wk].slice().sort(function (a, b) { return (a.kind === b.kind) ? (a.ref < b.ref ? -1 : 1) : (a.kind === 'day' ? -1 : 1); });
        h += '<details' + (i === 0 ? ' open' : '') + ' style="margin-top:8px;border:2px solid #ccfbf1;border-radius:14px;background:#f0fdfa">'
          + '<summary style="cursor:pointer;padding:8px 12px;font-weight:900;color:#0f766e;font-size:15px">📁 ' + esc(wkLabel(wk)) + ' <span style="font-weight:600;font-size:12px;color:#64748b">' + list.length + 'こ</span></summary>'
          + '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;padding:0 10px 10px">';
        list.forEach(function (p) {
          h += '<div style="background:#fff;border:1.5px solid #99f6e4;border-radius:12px;padding:8px 10px">'
            + '<div style="font-size:11.5px;color:#0f766e;font-weight:800">' + (p.kind === 'week' ? '🔄 週の ふりかえり' : '📝 ' + esc(dayLabel(p.ref)) + 'の ふりかえり')
            + (p.name ? '　<span style="color:#334155">' + esc(p.name) + '</span>' : '') + (p.mine ? '　<span style="background:#ccfbf1;border-radius:999px;padding:0 6px">あなたの</span>' : '') + '</div>'
            + '<div style="font-size:14.5px;line-height:1.75;white-space:pre-wrap;margin-top:3px">' + esc(p.body) + '</div></div>';
        });
        h += '</div></details>';
      });
    }
    // じぶんの「のせてもいいよ」
    var items = (mine && mine.items) || [];
    h += '<div style="margin-top:14px;border-top:1px dashed #cbd5e1;padding-top:8px">'
      + '<div style="font-size:13px;font-weight:800;color:#475569">じぶんの「のせてもいいよ」</div>';
    if (!items.length) h += '<div style="font-size:12px;color:#94a3b8">いまは ないよ</div>';
    items.forEach(function (x, i) {
      h += '<div style="display:flex;align-items:center;gap:8px;font-size:12.5px;margin-top:4px">'
        + '<span style="flex:1">' + (x.kind === 'week' ? '週の ふりかえり（' + esc(wkLabel(x.ref)) + '）' : esc(dayLabel(x.ref)) + 'の ふりかえり') + '・' + (x.mode === 'named' ? '名前あり' : '名前なし') + (x.posted ? '・<b style="color:#0f766e">のってるよ</b>' : '') + '</span>'
        + '<button type="button" class="mfRevoke" data-i="' + i + '" style="background:#fff;border:1.5px solid #fca5a5;color:#b91c1c;border-radius:8px;padding:3px 10px;font-size:12px;font-weight:800;cursor:pointer">とりけす</button></div>';
    });
    h += '<div style="font-size:11px;color:#94a3b8;margin-top:4px">とりけすと、すぐに みんなから 見えなくなるよ。</div></div>';
    box.innerHTML = h;
    bindClose();
    var bs = box.querySelectorAll('.mfRevoke');
    for (var k = 0; k < bs.length; k++) bs[k].onclick = function () {
      var x = items[Number(this.getAttribute('data-i'))]; if (!x) return;
      if (!confirm('「のせてもいいよ」を とりけす？')) return;
      jpost('/api/student/minna/consent', { kind: x.kind, ref: x.ref, mode: '' }).then(function () {
        if (cur[x.kind] && cur[x.kind].ref === x.ref) { cur[x.kind].mode = ''; setChecks(x.kind, ''); }
        openPage();
      });
    };
  }

  // ---------- 起動 ----------
  // ⚠ hwRenderWeekView は weekref.js / maejibun.js が包んでいるので、ここでは包まない（包み合いを起こさない）。
  //   画面にあるかを ときどき見るだけにする（読みこみは日／週が変わったときだけ）。
  var tries = 0;
  var timer = setInterval(function () {
    tries++;
    try { ensureEntry(); ensureDayBox(); ensureWeekBox(); } catch (e) {}
    if ($('minnaFuriEntry') || tries > 90) clearInterval(timer);
  }, 2000);
  // 画面が描き直されて消えたときに戻す
  setInterval(function () { try { ensureEntry(); ensureDayBox(); ensureWeekBox(); } catch (e) {} }, 2500);
  try { window.minnaFuriOpen = openPage; } catch (e) {}
})();
