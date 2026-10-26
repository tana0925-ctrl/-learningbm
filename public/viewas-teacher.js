/* ===================================================================
   viewas-teacher.js — 👀 子どもの画面に入る（見るだけ）  VIEWAS_V1
   /teacher の右下にボタンを1つ置く。押すと、クラスと子どもを選べる窓が開く。
   子どもを押す → 確認 → その子の画面（本物のデータ）がこのタブで開く。
   見ているあいだは何も保存されない（サーバと画面の両方で止める）。上の帯の「終わる」で戻る。
   下に「だれが・いつ・だれの画面を見たか」の記録を出す。
   =================================================================== */
(function () {
  'use strict';
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;');
  }
  function getJSON(url) {
    return fetch(url, { credentials: 'include', cache: 'no-store' }).then(function (r) { return r.json(); }).catch(function () { return null; });
  }
  function jtime(v) {
    if (!v) return '';
    var d = new Date(String(v).replace(' ', 'T') + 'Z');
    if (isNaN(d.getTime())) return String(v);
    var j = new Date(d.getTime() + 9 * 3600000);
    return (j.getUTCMonth() + 1) + '/' + j.getUTCDate() + ' ' + String(j.getUTCHours()).padStart(2, '0') + ':' + String(j.getUTCMinutes()).padStart(2, '0');
  }
  function mins(a, b) {
    var x = new Date(String(a).replace(' ', 'T') + 'Z').getTime(), y = new Date(String(b).replace(' ', 'T') + 'Z').getTime();
    if (!x || !y || y < x) return '';
    return Math.max(1, Math.round((y - x) / 60000)) + '分';
  }

  var _data = null, _cls = 0;

  function build() {
    if ($('vaOpenBtn')) return;
    var btn = document.createElement('button');
    btn.id = 'vaOpenBtn';
    btn.type = 'button';
    btn.className = 'fixed bottom-36 right-4 z-[9998] bg-violet-600 hover:bg-violet-700 text-white font-black rounded-full shadow-lg px-5 py-3 text-sm';
    btn.textContent = '👀 子どもの画面に入る';
    btn.onclick = open;
    document.body.appendChild(btn);

    var ov = document.createElement('div');
    ov.id = 'vaOverlay';
    ov.className = 'fixed inset-0 z-[9999] bg-black/50 hidden';
    ov.innerHTML =
      '<div class="absolute inset-0 flex items-start justify-center p-2 sm:p-6 overflow-auto">' +
      '<div class="bg-white rounded-2xl shadow-2xl w-full max-w-3xl">' +
      '<div class="px-4 py-3 border-b border-slate-200 flex items-center gap-2 flex-wrap">' +
      '<div class="font-black text-slate-800">👀 子どもの画面に入る</div>' +
      '<div class="text-[11px] text-violet-700 bg-violet-50 border border-violet-200 rounded-full px-2 py-0.5 font-bold">見るだけ・保存されません</div>' +
      '<button type="button" id="vaClose" class="ml-auto px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-black text-white text-xs font-bold">閉じる</button>' +
      '</div>' +
      '<div class="px-4 py-2 text-xs text-slate-600 leading-relaxed border-b border-slate-100">' +
      '子どもの名前を押すと、<b>その子が見ているのと同じ画面</b>（本物のデータ）がこのタブで開きます。<br>' +
      '見ているあいだは、提出・保存・コイン・ゲームの進み・既読などは<b>一切記録されません</b>。上の紫の帯の「終わる」で戻ります（60分で自動的に終わります）。' +
      '</div>' +
      '<div id="vaTabs" class="px-4 pt-3 flex gap-2 flex-wrap"></div>' +
      '<div id="vaKids" class="p-4 grid grid-cols-2 sm:grid-cols-4 gap-2"></div>' +
      '<div class="px-4 pb-4">' +
      '<div class="font-bold text-sm text-slate-700 mb-1">🗒 見た記録（新しい順・50件まで）</div>' +
      '<div id="vaLog" class="text-xs text-slate-600 max-h-60 overflow-auto border border-slate-200 rounded-lg"></div>' +
      '</div>' +
      '</div></div>';
    document.body.appendChild(ov);
    $('vaClose').onclick = close;
    ov.addEventListener('click', function (e) { if (e.target === ov || e.target === ov.firstChild) close(); });
  }

  function open() {
    build();
    $('vaOverlay').classList.remove('hidden');
    $('vaKids').innerHTML = '<div class="col-span-full text-center text-sm text-slate-500 py-6">読み込み中…</div>';
    getJSON('/api/teacher/view-as/roster').then(function (d) {
      if (!d || !d.ok) { $('vaKids').innerHTML = '<div class="col-span-full text-center text-sm text-rose-600 py-6">読み込めませんでした。</div>'; return; }
      _data = d; _cls = 0; renderTabs(); renderKids();
    });
    loadLog();
  }
  function close() { var o = $('vaOverlay'); if (o) o.classList.add('hidden'); }

  function renderTabs() {
    var cs = (_data && _data.classes) || [];
    $('vaTabs').innerHTML = cs.map(function (c, i) {
      return '<button type="button" data-i="' + i + '" class="px-3 py-1.5 rounded-full text-sm font-bold border ' +
        (i === _cls ? 'bg-violet-600 text-white border-violet-600' : 'bg-white text-slate-700 border-slate-300') + '">' +
        esc(c.name || 'クラス') + (c.mine ? '' : ' <span class="text-[10px] opacity-70">（ほかの先生）</span>') + '</button>';
    }).join('');
    Array.prototype.forEach.call($('vaTabs').querySelectorAll('button'), function (b) {
      b.onclick = function () { _cls = Number(b.getAttribute('data-i')) || 0; renderTabs(); renderKids(); };
    });
  }
  function renderKids() {
    var cs = (_data && _data.classes) || [];
    var c = cs[_cls];
    if (!c) { $('vaKids').innerHTML = '<div class="col-span-full text-center text-sm text-slate-500 py-6">担任しているクラスがありません。</div>'; return; }
    var ms = c.members || [];
    if (!ms.length) { $('vaKids').innerHTML = '<div class="col-span-full text-center text-sm text-slate-500 py-6">このクラスに児童がいません。</div>'; return; }
    $('vaKids').innerHTML = ms.map(function (m) {
      return '<button type="button" data-id="' + esc(m.id) + '" data-name="' + esc(m.name) + '" class="px-2 py-3 rounded-xl border-2 border-violet-200 bg-violet-50 hover:bg-violet-100 text-sm font-bold text-slate-800">' + esc(m.name || '（名前なし）') + '</button>';
    }).join('');
    Array.prototype.forEach.call($('vaKids').querySelectorAll('button'), function (b) {
      b.onclick = function () { start(b.getAttribute('data-id'), b.getAttribute('data-name')); };
    });
  }
  function start(id, name) {
    if (!id) return;
    if (!confirm((name || 'この子') + ' さんの画面を「見るだけ」で開きます。\n\n・その子と同じ画面が、その子の本物のデータで出ます\n・提出／保存／コイン／ゲームの進み／既読などは一切記録されません\n・上の紫の帯の「終わる」で先生の画面に戻ります（60分で自動的に終わります）\n\n開きますか？')) return;
    fetch('/api/teacher/view-as/start', {
      method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ studentId: id })
    }).then(function (r) { return r.json(); }).then(function (j) {
      if (j && j.ok) { location.href = '/'; return; }
      var msg = (j && j.error === 'log_unavailable') ? '記録の準備ができていないため、開けませんでした（管理者に連絡してください）。' : '開けませんでした。' + (j && j.error ? '（' + j.error + '）' : '');
      alert(msg);
    }).catch(function () { alert('開けませんでした。通信を確かめてください。'); });
  }
  function loadLog() {
    $('vaLog').innerHTML = '<div class="p-2 text-slate-400">読み込み中…</div>';
    getJSON('/api/teacher/view-as/log').then(function (d) {
      var rows = (d && d.rows) || [];
      if (!rows.length) { $('vaLog').innerHTML = '<div class="p-2 text-slate-400">まだ記録はありません。</div>'; return; }
      $('vaLog').innerHTML = '<table class="w-full"><thead class="bg-slate-50 sticky top-0"><tr>' +
        '<th class="text-left p-1.5">いつ</th><th class="text-left p-1.5">見た先生</th><th class="text-left p-1.5">見た子</th><th class="text-left p-1.5">長さ</th><th class="text-left p-1.5">止めた保存</th></tr></thead><tbody>' +
        rows.map(function (r) {
          var endAt = r.endedAt || r.lastSeenAt;
          return '<tr class="border-t border-slate-100"><td class="p-1.5 whitespace-nowrap">' + esc(jtime(r.startedAt)) + '</td>' +
            '<td class="p-1.5">' + esc(r.teacherName || '') + '</td>' +
            '<td class="p-1.5">' + esc(r.studentName || '') + '</td>' +
            '<td class="p-1.5 whitespace-nowrap">' + esc(r.endedAt ? mins(r.startedAt, r.endedAt) : (endAt ? '〜' + mins(r.startedAt, endAt) : '')) + '</td>' +
            '<td class="p-1.5">' + esc(String(r.blockedCount || 0)) + '件</td></tr>';
        }).join('') + '</tbody></table>';
    });
  }

  function init() {
    try {
      if (location.pathname !== '/teacher') return;
      build();
      window.openViewAsPicker = open;
    } catch (e) {}
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { setTimeout(init, 450); });
  else setTimeout(init, 450);
})();
