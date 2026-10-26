/* 📮 TEISHUTSU_V1 提出状況のアドバイス（先生の画面）— 2026-10-27
 *
 *  1) 家庭学習タブに「📮 提出物チェック」のサブタブ（振り返り一覧のとなり）。
 *     ①提出物を作る（名前・しめきり日・教科は任意）
 *     ②クラス名簿が出席番号順（名前順）の格子で並ぶ → タップで ✓（出した）／もう一度で取り消し。全員✓・未提出だけ表示。
 *     作った提出物は一覧。終わったものは「完了」で畳む（子どもの📮からも消える）。iPad・PC で押しやすい大きさ。
 *  2) 📊 個人分析（個人ページ）に「📮 提出のようす」と「🧪 テストの傾向（先生用・点数は出さない）」を小さく。
 *     材料は student-full-analysis の teishutsu（サーバーで数えた事実）。比較・順位は出さない。
 *  3) 📋 振り返り一覧の1枚（開いたとき）に、提出のようすを1行（teibako.js から TS_T.yousuInto を呼ぶ）。
 *  4) 今日のひと往復のコピーに【提出・成果物のようす】【テストから見える傾向】（teacher-ai.js から TS_T.copyLines を呼ぶ）。
 *     名前は入れない（符号のまま）。点数・％は入れない。◎○△は言葉（得意そう／ふつう／もう少し）にして渡す。
 *  ・テストのデータが無い子・教科では、何も出さない（推測しない）。
 *  ・index.html / src/index.tsx の .replace() 対象は触らない。DDL はしない（migrations/0049）。
 */
(function () {
  'use strict';
  if (window.__TEISHUTSU_T_V1__) return; window.__TEISHUTSU_T_V1__ = 1;

  var WD = ['日', '月', '火', '水', '木', '金', '土'];
  var S = { cid: '', data: null, sel: '', onlyOpen: false, showDone: false, busy: false };
  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function jget(url) { return fetch(url, { credentials: 'include' }).then(function (r) { return r.json(); }).catch(function () { return null; }); }
  function jpost(url, body) { return fetch(url, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }).then(function (r) { return r.json(); }).catch(function () { return null; }); }
  function jstToday() { return new Date(Date.now() + 9 * 3600000).toISOString().slice(0, 10); }
  function md(ymd) { var p = String(ymd || '').split('-'); if (p.length < 3) return ''; var d = new Date(Date.UTC(+p[0], +p[1] - 1, +p[2])); return (+p[1]) + '/' + (+p[2]) + '(' + WD[d.getUTCDay()] + ')'; }
  function diff(a, b) { return Math.round((Date.parse(a + 'T00:00:00Z') - Date.parse(b + 'T00:00:00Z')) / 86400000); }
  function nameOf(r) { try { if (typeof resolveStudentName === 'function') return resolveStudentName(r.loginId, r.name) || r.name || r.loginId; } catch (e) {} return r.name || r.loginId || ''; }
  function unitJa(id) { try { if (typeof _unitJa === 'function') return _unitJa(id) || id; } catch (e) {} try { if (window.UNIT_JP && window.UNIT_JP[id]) return window.UNIT_JP[id]; } catch (e) {} return id; }
  var SUBJ = ['国語', '算数', '理科', '社会', '外国語', '音楽', '図工', '家庭', '体育', '道徳', '総合', 'その他'];

  // ═════════ 1) 📮 提出物チェック ═════════
  var BTN = 'min-height:44px;border-radius:12px;padding:6px 14px;font-size:14px;font-weight:900;cursor:pointer;';
  var CSS = '#tsGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(118px,1fr));gap:8px}'
    + '.tsKid{min-height:64px;border-radius:14px;border:2px solid #cbd5e1;background:#fff;font-size:15px;font-weight:900;color:#334155;cursor:pointer;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;padding:6px 4px;-webkit-tap-highlight-color:transparent;touch-action:manipulation;user-select:none}'
    + '.tsKid small{font-size:11px;font-weight:700;color:#94a3b8}'
    + '.tsKid.on{background:#dcfce7;border-color:#22c55e;color:#166534}'
    + '.tsKid.on small{color:#15803d}'
    + '.tsItem{display:flex;align-items:center;gap:8px;border:2px solid #e2e8f0;border-radius:14px;padding:8px 10px;background:#fff;cursor:pointer;min-height:52px;text-align:left;width:100%}'
    + '.tsItem.sel{border-color:#0ea5e9;box-shadow:0 0 0 3px #bae6fd}'
    + '.tsBar{height:8px;border-radius:99px;background:#e2e8f0;overflow:hidden;flex:0 0 80px}.tsBar i{display:block;height:100%;background:#22c55e}'
    + '#tsPane input,#tsPane select{min-height:44px;border:1.5px solid #cbd5e1;border-radius:10px;padding:6px 10px;font-size:15px;background:#fff}';

  function ensureTab() {
    var nav = $('hwSubTab_daily'); if (!nav) return false;
    if ($('hwSubTab_teishutsu')) return true;
    var b = document.createElement('button');
    b.id = 'hwSubTab_teishutsu';
    b.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100';
    b.innerHTML = '<span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">📮</span> 提出物チェック';
    b.onclick = function () { show(true); };
    var after = $('hwSubTab_teibako') || nav;
    after.parentNode.insertBefore(b, after.nextSibling);
    var pane = document.createElement('div');
    pane.id = 'hwPane_teishutsu'; pane.className = 'hidden space-y-3';
    var pa = $('hwPane_teibako') || $('hwPane_daily') || $('hwPane_dashboard');
    if (pa && pa.parentNode) pa.parentNode.insertBefore(pane, pa.nextSibling);
    ['hwSubTab_menu', 'hwSubTab_daily', 'hwSubTab_dashboard', 'hwSubTab_teibako'].forEach(function (id) { var x = $(id); if (x) x.addEventListener('click', function () { show(false); }); });
    return true;
  }
  var OFF = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100';
  var OFFN = 'bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
  function show(on) {
    var pane = $('hwPane_teishutsu'), btn = $('hwSubTab_teishutsu'), plan = $('hwPlanBox');
    if (!pane || !btn) return;
    if (on) {
      ['dashboard', 'menu', 'daily', 'teibako'].forEach(function (t) {
        var p = $('hwPane_' + t); if (p) p.classList.add('hidden');
        var bb = $('hwSubTab_' + t); if (bb) { bb.className = OFF; var n = bb.querySelector('span'); if (n) n.className = OFFN; }
      });
      if (plan) plan.style.display = 'none';
      pane.classList.remove('hidden');
      btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-sky-500 text-white';
      var n2 = btn.querySelector('span'); if (n2) n2.className = 'bg-white text-sky-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
      if (!pane.firstChild) drawFrame();
      load();
    } else {
      if (pane.classList.contains('hidden')) return;
      pane.classList.add('hidden');
      if (plan) plan.style.display = '';
      btn.className = OFF; var n3 = btn.querySelector('span'); if (n3) n3.className = OFFN;
    }
  }
  window.tsShowCheck = show;

  function drawFrame() {
    var pane = $('hwPane_teishutsu');
    var so = '<option value="">教科（任意）</option>' + SUBJ.map(function (x) { return '<option>' + x + '</option>'; }).join('');
    pane.innerHTML = '<style>' + CSS + '</style><div id="tsPane" class="bg-white rounded-xl shadow p-3" style="display:flex;flex-direction:column;gap:10px">'
      + '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center"><span style="font-weight:900;color:#0369a1;font-size:16px">📮 提出物チェック</span>'
      + '<select id="tsClass"></select><button type="button" id="tsReload" style="' + BTN + 'background:#fff;border:1.5px solid #cbd5e1;color:#334155">🔄</button>'
      + '<span style="font-size:12px;color:#64748b">子どもの画面には、本人の「まだの提出物」だけが出ます（ほかの子の状況は見えません）</span></div>'
      + '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;background:#f0f9ff;border:1.5px dashed #7dd3fc;border-radius:14px;padding:8px 10px">'
      + '<b style="color:#0369a1">① 作る</b><input id="tsTitle" maxlength="40" placeholder="例：漢字ドリル p.30〜31" style="flex:1;min-width:200px">'
      + '<label style="font-size:13px;font-weight:700;color:#0369a1">しめきり <input type="date" id="tsDue"></label>'
      + '<select id="tsSubj">' + so + '</select>'
      + '<button type="button" id="tsCreate" style="' + BTN + 'background:#0ea5e9;color:#fff;border:none">＋ 作る</button><span id="tsMsg" style="font-size:13px;font-weight:700;color:#047857"></span></div>'
      + '<div id="tsItems" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:8px"></div>'
      + '<div id="tsSel"></div>'
      + '<div id="tsDone"></div></div>';
    var src = $('hwClassFilter') || $('dashClassFilter') || $('analyticsClassFilter');
    var sel = $('tsClass');
    if (src && sel) { sel.innerHTML = src.innerHTML; sel.value = src.value; if (!sel.value && sel.options.length > 1) sel.selectedIndex = 1; }
    sel.onchange = function () { S.sel = ''; load(); };
    $('tsReload').onclick = function () { load(); };
    $('tsCreate').onclick = create;
    $('tsTitle').onkeydown = function (ev) { if (ev.key === 'Enter') create(); };
    // しめきりの初期値：あした
    try { $('tsDue').value = new Date(Date.now() + 9 * 3600000 + 86400000).toISOString().slice(0, 10); } catch (e) {}
  }
  function msg(t, bad) { var e = $('tsMsg'); if (e) { e.textContent = t || ''; e.style.color = bad ? '#b91c1c' : '#047857'; } }
  function create() {
    var t = String($('tsTitle').value || '').trim();
    if (!t) { msg('名前を入れてください', true); $('tsTitle').focus(); return; }
    if (!S.cid) { msg('クラスを選んでください', true); return; }
    var b = $('tsCreate'); b.disabled = true;
    jpost('/api/teacher/teishutsu/create', { classId: S.cid, title: t, dueDate: $('tsDue').value || '', subject: $('tsSubj').value || '' }).then(function (j) {
      b.disabled = false;
      if (!j || !j.ok) { msg('作れませんでした（' + ((j && j.error) || '通信') + '）', true); return; }
      if (j.viewOnly) { msg('見るだけモード中は作れません', true); return; }
      $('tsTitle').value = ''; msg('✓ 作りました');
      S.sel = j.id; load();
    });
  }
  var _seq = 0;
  function load() {
    var sel = $('tsClass'); if (!sel) return;
    S.cid = sel.value;
    var box = $('tsItems');
    if (!S.cid) { box.innerHTML = '<p style="color:#64748b;font-size:13px">クラスを選んでください</p>'; $('tsSel').innerHTML = ''; $('tsDone').innerHTML = ''; return; }
    var my = ++_seq;
    jget('/api/teacher/teishutsu?classId=' + encodeURIComponent(S.cid)).then(function (d) {
      if (my !== _seq) return;
      if (!d || !d.ok) { box.innerHTML = '<p style="color:#b91c1c;font-size:13px">読み込めませんでした（' + esc((d && d.error) || '通信') + '）</p>'; return; }
      S.data = d;
      var act = d.items.filter(function (x) { return !x.doneAt; });
      if (!S.sel || !d.items.some(function (x) { return x.id === S.sel; })) S.sel = act.length ? act[0].id : '';
      render();
    });
  }
  function cnt(it) { var n = 0; S.data.roster.forEach(function (r) { if (it.checked[r.userId]) n++; }); return n; }
  function dueTxt(it, today) {
    if (!it.dueDate) return 'しめきりなし';
    var dl = diff(it.dueDate, today);
    return md(it.dueDate) + (dl === 0 ? ' きょう' : dl === 1 ? ' あした' : dl < 0 ? ' 過ぎ' : '') + 'まで';
  }
  function render() {
    var d = S.data; if (!d) return;
    var today = d.today || jstToday(), N = d.roster.length;
    var act = d.items.filter(function (x) { return !x.doneAt; });
    var done = d.items.filter(function (x) { return !!x.doneAt; });
    var h = '';
    if (!act.length) h = '<p style="color:#64748b;font-size:13px;grid-column:1/-1">進行中の提出物はありません。上の「① 作る」から作れます。</p>';
    act.forEach(function (it) {
      var c = cnt(it), pct = N ? Math.round(c / N * 100) : 0;
      h += '<button type="button" class="tsItem' + (it.id === S.sel ? ' sel' : '') + '" data-id="' + esc(it.id) + '">'
        + '<div style="flex:1;min-width:0"><div style="font-weight:900;font-size:14.5px;color:#0f172a;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + (it.subject ? '<span style="font-size:11px;color:#0369a1">［' + esc(it.subject) + '］</span>' : '') + esc(it.title) + '</div>'
        + '<div style="font-size:12px;color:#64748b">' + esc(dueTxt(it, today)) + '</div></div>'
        + '<div style="text-align:right"><div style="font-weight:900;color:#166534;font-size:14px">' + c + '/' + N + '</div><div class="tsBar"><i style="width:' + pct + '%"></i></div></div></button>';
    });
    $('tsItems').innerHTML = h;
    var bs = $('tsItems').querySelectorAll('.tsItem');
    for (var i = 0; i < bs.length; i++) bs[i].onclick = function () { S.sel = this.getAttribute('data-id'); render(); };
    drawSel();
    var dh = '';
    if (done.length) {
      dh = '<details' + (S.showDone ? ' open' : '') + ' id="tsDoneD" style="background:#f8fafc;border-radius:12px;padding:6px 10px"><summary style="cursor:pointer;font-weight:900;color:#475569;min-height:36px;line-height:36px">✅ 完了した提出物（' + done.length + '）</summary>';
      done.forEach(function (it) {
        dh += '<div style="display:flex;align-items:center;gap:8px;padding:4px 0;border-top:1px solid #e2e8f0;font-size:13px"><span style="flex:1">' + esc(it.title) + ' <span style="color:#94a3b8">' + esc(it.dueDate ? md(it.dueDate) + 'まで' : '') + '・' + cnt(it) + '/' + N + '人</span></span>'
          + '<button type="button" class="tsOpenDone" data-id="' + esc(it.id) + '" style="' + BTN + 'min-height:38px;background:#fff;border:1.5px solid #cbd5e1;color:#334155">ひらく</button>'
          + '<button type="button" class="tsUndo" data-id="' + esc(it.id) + '" style="' + BTN + 'min-height:38px;background:#fff;border:1.5px solid #0ea5e9;color:#0369a1">もどす</button></div>';
      });
      dh += '</details>';
    }
    $('tsDone').innerHTML = dh;
    var dd = $('tsDoneD'); if (dd) dd.ontoggle = function () { S.showDone = dd.open; };
    var us = document.querySelectorAll('.tsUndo');
    for (var u = 0; u < us.length; u++) us[u].onclick = function () { var id = this.getAttribute('data-id'); jpost('/api/teacher/teishutsu/update', { id: id, done: false }).then(function () { S.sel = id; load(); }); };
    var os = document.querySelectorAll('.tsOpenDone');
    for (var o = 0; o < os.length; o++) os[o].onclick = function () { S.sel = this.getAttribute('data-id'); render(); try { $('tsSel').scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) {} };
  }
  function drawSel() {
    var box = $('tsSel'), d = S.data;
    var it = d.items.filter(function (x) { return x.id === S.sel; })[0];
    if (!it) { box.innerHTML = ''; return; }
    var N = d.roster.length, c = cnt(it);
    var h = '<div style="border:2px solid #0ea5e9;border-radius:16px;padding:10px;background:#f8fdff">'
      + '<div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:8px">'
      + '<div style="font-weight:900;font-size:16px;color:#0f172a">' + (it.subject ? '［' + esc(it.subject) + '］' : '') + esc(it.title) + ' <span style="font-size:12.5px;color:#64748b;font-weight:700">' + esc(dueTxt(it, d.today)) + (it.doneAt ? '・完了ずみ' : '') + '</span></div>'
      + '<div id="tsCount" style="margin-left:auto;font-weight:900;color:#166534;font-size:15px">出した ' + c + ' / ' + N + '人</div></div>'
      + '<div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:8px">'
      + '<button type="button" id="tsAll" style="' + BTN + 'background:#22c55e;color:#fff;border:none">✓ 全員</button>'
      + '<label style="' + BTN + 'background:#fff;border:1.5px solid #cbd5e1;color:#334155;display:inline-flex;align-items:center;gap:6px"><input type="checkbox" id="tsOnlyOpen"' + (S.onlyOpen ? ' checked' : '') + ' style="min-height:0;width:20px;height:20px"> 未提出だけ</label>'
      + (it.doneAt ? '<button type="button" id="tsUndone" style="' + BTN + 'background:#fff;border:1.5px solid #0ea5e9;color:#0369a1">もどす</button>'
                   : '<button type="button" id="tsDoneBtn" style="' + BTN + 'background:#0f172a;color:#fff;border:none">✅ 完了（たたむ）</button>')
      + '<button type="button" id="tsEdit" style="' + BTN + 'background:#fff;border:1.5px solid #cbd5e1;color:#334155">✏️ 直す</button>'
      + '<button type="button" id="tsDel" style="' + BTN + 'background:#fff;border:1.5px solid #fecaca;color:#b91c1c">🗑 けす</button>'
      + '<span style="font-size:12px;color:#64748b;align-self:center">名前をタップで ✓／もう一度タップで取り消し</span></div>'
      + '<div id="tsGrid">';
    d.roster.forEach(function (r) {
      var on = !!it.checked[r.userId];
      if (S.onlyOpen && on) return;
      h += '<button type="button" class="tsKid' + (on ? ' on' : '') + '" data-uid="' + esc(r.userId) + '">' + (r.rosterNo != null ? '<small>' + esc(r.rosterNo) + '</small>' : '') + '<span>' + (on ? '✓ ' : '') + esc(nameOf(r)) + '</span>' + (on && it.checked[r.userId] ? '<small>' + esc(md(it.checked[r.userId])) + '</small>' : '') + '</button>';
    });
    h += '</div>';
    if (S.onlyOpen && c === N) h += '<p style="font-size:14px;color:#166534;font-weight:800;margin-top:6px">🎉 全員そろいました</p>';
    h += '</div>';
    box.innerHTML = h;
    var ks = box.querySelectorAll('.tsKid');
    for (var i = 0; i < ks.length; i++) ks[i].onclick = function () { toggle(it, this.getAttribute('data-uid'), this); };
    $('tsOnlyOpen').onchange = function () { S.onlyOpen = this.checked; drawSel(); };
    $('tsAll').onclick = function () {
      if (!confirm('「' + it.title + '」を 全員 ✓（出した）にします。よろしいですか？')) return;
      jpost('/api/teacher/teishutsu/check', { id: it.id, all: true }).then(function (j) { if (j && j.ok && !j.viewOnly) { d.roster.forEach(function (r) { if (!it.checked[r.userId]) it.checked[r.userId] = j.day || d.today; }); render(); } else alert('できませんでした'); });
    };
    var db = $('tsDoneBtn'); if (db) db.onclick = function () { jpost('/api/teacher/teishutsu/update', { id: it.id, done: true }).then(function (j) { if (j && j.ok) { S.sel = ''; load(); } }); };
    var ub = $('tsUndone'); if (ub) ub.onclick = function () { jpost('/api/teacher/teishutsu/update', { id: it.id, done: false }).then(function () { load(); }); };
    $('tsEdit').onclick = function () {
      var t = prompt('提出物の名前', it.title); if (t == null) return;
      var due = prompt('しめきり日（例 2026-10-30／空ならしめきりなし）', it.dueDate || ''); if (due == null) return;
      due = String(due).trim().replace(/\//g, '-');
      if (due && !/^\d{4}-\d{2}-\d{2}$/.test(due)) { alert('しめきり日は 2026-10-30 の形で入れてください'); return; }
      jpost('/api/teacher/teishutsu/update', { id: it.id, title: t, dueDate: due }).then(function () { load(); });
    };
    $('tsDel').onclick = function () {
      if (!confirm('「' + it.title + '」をけします（✓の記録も見えなくなります）。よろしいですか？')) return;
      jpost('/api/teacher/teishutsu/update', { id: it.id, deleted: true }).then(function () { S.sel = ''; load(); });
    };
  }
  function toggle(it, uid, el) {
    var was = !!it.checked[uid];
    // すぐに見た目を変える（通信に失敗したら もどす）
    if (was) delete it.checked[uid]; else it.checked[uid] = S.data.today;
    drawSel(); renderCounts();
    jpost('/api/teacher/teishutsu/check', { id: it.id, userId: uid, on: !was }).then(function (j) {
      if (!j || !j.ok || j.viewOnly) {
        if (was) it.checked[uid] = S.data.today; else delete it.checked[uid];
        drawSel(); renderCounts();
        alert('記録できませんでした。もう一度おしてください');
      } else if (j.on && j.day) { it.checked[uid] = j.day; }
    });
  }
  function renderCounts() {
    var d = S.data, N = d.roster.length;
    var bs = $('tsItems') ? $('tsItems').querySelectorAll('.tsItem') : [];
    for (var i = 0; i < bs.length; i++) {
      var it = d.items.filter(function (x) { return x.id === bs[i].getAttribute('data-id'); })[0]; if (!it) continue;
      var c = cnt(it), b = bs[i].querySelector('.tsBar i'), t = bs[i].querySelector('div[style*="166534"]');
      if (b) b.style.width = (N ? Math.round(c / N * 100) : 0) + '%'; if (t) t.textContent = c + '/' + N;
    }
  }

  // ═════════ 共通：提出のようす（事実だけ）・テストの傾向（点数なし） ═════════
  function topDow(hw) { if (!hw || !hw.dow) return []; var idx = [1, 2, 3, 4, 5, 6, 0].filter(function (i) { return hw.dow[i] > 0; }).sort(function (a, b) { return hw.dow[b] - hw.dow[a]; }); var top = idx.length ? hw.dow[idx[0]] : 0; return idx.filter(function (i) { return hw.dow[i] === top && top >= 2; }).map(function (i) { return WD[i]; }); }
  function topBand(hw) { var b = (hw && hw.band) || {}, k = null; Object.keys(b).forEach(function (x) { if (b[x] > 0 && (!k || b[x] > b[k])) k = x; }); return k && b[k] >= 2 ? k : ''; }
  function leadTop(sc) { var l = (sc && sc.lead) || {}, k = null; Object.keys(l).forEach(function (x) { if (!k || l[x] > l[k]) k = x; }); if (!k || l[k] < 2) return ''; return (k === '1日前' ? 'しめきりの前の日' : k === '当日' ? 'しめきりの日' : k === 'あと' ? 'しめきりのあと' : 'しめきりの' + k) + '（' + l[k] + '回）'; }
  function wordMark(m) { return m === '◎' ? '得意そう' : m === '△' ? 'もう少し' : m === '○' ? 'ふつう' : ''; }
  function norm(s) { return String(s || '').replace(/[（(][^）)]*[）)]/g, '').replace(/たしかめテスト|まとめのテスト|テスト|ドリル|のかくにん|かくにん|[①-⑳0-9０-９]/g, '').replace(/[\s　・「」『』、。．.:：\-－]/g, ''); }
  // テストの名前 → 子どもが取り組んだアプリの単元（名前の重なりで いちばん長く合うもの）
  function matchUnit(test, units) {
    var tn = norm(test.name); if (tn.length < 2) return null;
    var best = null, bl = 0;
    units.forEach(function (u) {
      var un = norm(unitJa(u)); if (un.length < 2) return;
      var l = (tn.indexOf(un) >= 0) ? un.length : (un.indexOf(tn) >= 0) ? tn.length : 0;
      if (l > bl) { bl = l; best = u; }
    });
    return bl >= 3 ? best : null;
  }
  function accWord(rate) { rate = Number(rate); return rate >= 80 ? 'よく正解' : rate >= 50 ? '半分くらい正解' : 'ちょうせん中'; }
  // テストごとに：観点・アプリのようす・テスト前の準備・くいちがい
  function testRows(d) {
    var ts = d && d.teishutsu && d.teishutsu.tests; if (!ts || !ts.length) return [];
    var subs = {}; (d.subjects || []).forEach(function (s) { subs[String(s.unit)] = s; });
    var units = Object.keys(subs);
    return ts.map(function (t) {
      (t.prep || []).forEach(function (p) { if (units.indexOf(p.unit) < 0) units.push(p.unit); });
      var u = matchUnit(t, units), s = u ? subs[u] : null;
      var prepN = 0; if (u) (t.prep || []).forEach(function (p) { if (p.unit === u) prepN += Number(p.n || 0); });
      var gap = [];
      if (t.t === '△' && s && Number(s.total) >= 20 && Number(s.rate) >= 80) gap.push('アプリではよく正解しているのに、テストの思考・判断・表現でつまずきやすい → 考えを言葉や式で説明する練習');
      if (t.k === '△' && u && (!s || Number(s.total) < 10)) gap.push('アプリではこの単元をあまり解いていない → 少しずつ練習');
      if (t.k === '△' && s && Number(s.total) >= 20 && Number(s.rate) >= 80) gap.push('アプリはよく正解なのに知識・技能がもう少し → 紙に書いて解く・見直す練習');
      if ((t.k === '◎' || t.t === '◎') && prepN >= 10) gap.push('テスト前にアプリで準備できていた');
      return { t: t, unit: u, s: s, prepN: prepN, gap: gap };
    });
  }
  function subjTrend(rows) {
    var by = {};
    rows.forEach(function (r) { var k = r.t.subject || '（教科なし）'; var o = by[k] || (by[k] = { k: [], t: [] }); if (r.t.k) o.k.push(r.t.k); if (r.t.t) o.t.push(r.t.t); });
    var lab = function (a) { if (!a.length) return ''; var tri = a.filter(function (x) { return x === '△'; }).length, dbl = a.filter(function (x) { return x === '◎'; }).length; return tri * 2 >= a.length ? 'もう少し' : (!tri && dbl) ? '得意そう' : 'ふつう'; };
    return Object.keys(by).map(function (k) { return { subject: k, k: lab(by[k].k), t: lab(by[k].t), n: Math.max(by[k].k.length, by[k].t.length) }; });
  }
  function dateTxt(t) { return t.date ? (t.dateFrom === 'test' ? md(t.date) : md(t.date) + 'ごろ（取り込み日）') : ''; }

  // 今日のひと往復のコピー用（AIが読む・名前なし・点数なし・◎○△は言葉に）
  function copyLines(d) {
    var tp = d && d.teishutsu; if (!tp) return [];
    var out = [], sc = tp.habits && tp.habits.school, hw = tp.habits && tp.habits.hw, pr = (tp.habits && tp.habits.promise) || [];
    var L = [];
    if (sc && (sc.n > 0)) {
      L.push('・学校の提出物（この60日・しめきりのあるもの ' + sc.n + '回）：しめきりより前 ' + sc.before + '回／しめきりの日 ' + sc.same + '回／しめきりのあと ' + sc.after + '回' + (leadTop(sc) ? '。いちばん多い出し方は ' + leadTop(sc) : ''));
      var bs = Object.keys(sc.bySubject || {}).filter(function (k) { return sc.bySubject[k].n > 0; }).map(function (k) { var o = sc.bySubject[k]; return k + ' ' + o.n + '回中 ' + o.onTime + '回しめきりまで'; });
      if (bs.length > 1) L.push('・教科ごと：' + bs.join('／'));
      var ks = Object.keys(sc.kinds || {}).map(function (k) { var o = sc.kinds[k]; return { k: k, x: Number(o.late || 0) + Number(o.open || 0), n: Number(o.n || 0) + Number(o.open || 0) }; }).filter(function (o) { return o.x >= 2; }).sort(function (a, b) { return b.x - a.x; });
      if (ks.length) L.push('・ためやすい種類（しめきりのあと／これから が多い）：' + ks[0].k + '（' + ks[0].n + '件のうち ' + ks[0].x + '件）');
    }
    if (hw && hw.n > 0) {
      var dw = topDow(hw), bd = topBand(hw);
      L.push('・家庭学習（直近4週・' + hw.n + '日）：' + (dw.length ? 'よく出す曜日 ' + dw.join('・') : '曜日のかたよりなし') + (bd ? '／よく出す時間帯 ' + bd : '') + (hw.minAvg != null ? '／学習時間 平均' + hw.minAvg + '分' : ''));
      var ph = [];
      if (hw.photoDays) ph.push('写真をつけた日 ' + hw.photoDays + '日');
      if (hw.physicalDays) ph.push('「成果物（ノートなど）も提出あり」' + hw.physicalDays + '日');
      if (hw.minPhoto != null) ph.push('写真のある日の学習時間 平均' + hw.minPhoto + '分・ない日 平均' + hw.minNoPhoto + '分');
      if (ph.length) L.push('・' + ph.join('／'));
      var w = hw.weather || {};
      if ((w.sun || 0) + (w.cloud || 0) + (w.rain || 0) > 0) L.push('・手ごたえ：☀' + (w.sun || 0) + '日 ☁' + (w.cloud || 0) + '日 🌧' + (w.rain || 0) + '日');
    }
    var RJ = { done: 'できた', some: 'ちょっと', not: 'できなかった' }, RE = { time: '時間がなかった', forgot: 'わすれた', way: 'やり方が合わなかった', other: 'その他' };
    var pl = pr.filter(function (p) { return p.result; }).slice(0, 3).map(function (p) { var tx = String(p.text || ''); if (window._qnMask) tx = window._qnMask(tx); return (tx ? '「' + tx + '」' : '') + '→' + (RJ[p.result] || p.result) + (p.reason && RE[p.reason] ? '（' + RE[p.reason] + '）' : ''); });
    if (pl.length) L.push('・先週決めたことの結果（本人の見立て・新しい順）：' + pl.join('／'));
    if (L.length) { out.push('【提出・成果物のようす（事実だけ。責める材料にしない・未提出の数は子どもに書かない）】'); out = out.concat(L); }
    var rows = testRows(d);
    if (rows.length) {
      out.push('【テストから見える傾向（点数なし・子どもに書くのは練習のしかただけ）】');
      subjTrend(rows).forEach(function (x) { out.push('・' + x.subject + '（' + x.n + '回）：知識・技能 ' + (x.k || '記録なし') + '／思考・判断・表現 ' + (x.t || '記録なし')); });
      rows.slice(0, 4).forEach(function (r) {
        var a = '・' + (r.t.subject || '') + '「' + r.t.name + '」' + (dateTxt(r.t) ? '（' + dateTxt(r.t) + '）' : '') + '：知識・技能 ' + (wordMark(r.t.k) || '記録なし') + '／思考・判断・表現 ' + (wordMark(r.t.t) || '記録なし');
        if (r.unit) a += '／アプリの同じ単元「' + unitJa(r.unit) + '」' + (r.s ? Number(r.s.total) + '問・' + accWord(r.s.rate) : 'の記録なし') + '／テスト前1週間にアプリで' + (r.prepN ? r.prepN + '問' : 'この単元の記録なし');
        out.push(a);
        r.gap.forEach(function (g) { out.push('　→ くいちがい・見立て：' + g); });
      });
    }
    return out;
  }

  // ═════════ 2) 📊 個人分析（個人ページ）に小さく ═════════
  function faPanelHtml(d) {
    var tp = d.teishutsu; if (!tp) return '';
    var h = '<div id="tsFaPanel" class="bg-sky-50 rounded-xl border border-sky-200 p-3 mb-4" style="font-size:12.5px;color:#0f172a">';
    h += '<div class="font-bold text-sm text-sky-800 mb-1">📮 提出のようす（記録の事実・先生用）</div>';
    var kw = tp.karteWeek; if (kw) h += '<div>カルテの週（' + esc(md(kw.from)) + '〜）の家庭学習：<b>' + Number(kw.hwDays || 0) + '日</b>' + (kw.onTime ? '／しめきり前に出せた提出物：<b>' + kw.onTime + 'つ</b>' : '') + '</div>';
    var pd = tp.pending || [];
    if (pd.length) {
      h += '<div style="margin-top:4px"><b>未提出（学校の提出物）</b>：' + pd.map(function (it) { var dl = it.daysLeft; return esc(it.title) + '<span style="color:#64748b">（' + (it.dueDate ? md(it.dueDate) + 'まで' + (dl < 0 ? '・' + (-dl) + '日過ぎ' : '') : 'しめきりなし') + '）</span>'; }).join('、') + '</div>';
    } else h += '<div style="margin-top:4px;color:#166534">学校の提出物：進行中のものは すべて出ています</div>';
    var cl = copyLines(d);
    var a = [], b = [], inT = false;
    cl.forEach(function (l) { if (/^【テスト/.test(l)) { inT = true; return; } if (/^【/.test(l)) return; (inT ? b : a).push(l); });
    if (a.length) h += '<div style="margin-top:4px">' + a.map(function (l) { return '<div>' + esc(l) + '</div>'; }).join('') + '</div>';
    h += '<div class="font-bold text-sm text-emerald-800 mt-2 mb-1">🧪 テストの傾向（先生用・点数は出しません）</div>';
    var rows = testRows(d);
    if (!rows.length) h += '<div style="color:#64748b">観点（◎○△）のついたテストの記録はありません。テストの話は子どもにはしません。</div>';
    else {
      rows.slice(0, 6).forEach(function (r) {
        h += '<div style="margin-top:2px">・' + esc(r.t.subject) + '「' + esc(r.t.name) + '」' + (dateTxt(r.t) ? '<span style="color:#64748b">（' + esc(dateTxt(r.t)) + '）</span>' : '') + '　知識・技能 <b>' + esc(r.t.k || '－') + '</b>／思考・判断・表現 <b>' + esc(r.t.t || '－') + '</b>'
          + (r.unit ? '<span style="color:#475569">　アプリ「' + esc(unitJa(r.unit)) + '」' + (r.s ? Number(r.s.total) + '問・' + Number(r.s.rate) + '%' : '記録なし') + '・テスト前1週間 ' + (r.prepN || 0) + '問</span>' : '<span style="color:#94a3b8">　（アプリの単元と結びつけられませんでした）</span>') + '</div>';
        r.gap.forEach(function (g) { h += '<div style="margin-left:14px;color:#9a3412">→ ' + esc(g) + '</div>'; });
      });
    }
    h += '<div style="font-size:10.5px;color:#94a3b8;margin-top:4px">子どもの画面・紙のカルテには、未提出の数・点数・比較は出しません。カルテには「今週の家庭学習：〇日」と、先生が公開した「📮出し方のヒント」「📝テストに向けて」だけが出ます。</div>';
    return h + '</div>';
  }
  setInterval(function () {
    try {
      ensureTab();
      var c = $('fullAnalysisContent'), d = window._faData;
      if (!c || !d || !d.teishutsu || !d.student || $('tsFaPanel')) return;
      if (String(window._faId || '') !== String(d.student.id || '')) return;
      if (!c.firstElementChild || (/取得中/.test(c.textContent || '') && c.children.length < 2)) return;
      var w = document.createElement('div'); w.innerHTML = faPanelHtml(d);
      var p = w.firstChild; if (!p) return;
      var first = c.firstElementChild;
      if (first && first.nextSibling) c.insertBefore(p, first.nextSibling); else c.appendChild(p);
    } catch (e) {}
  }, 1200);

  // ═════════ 3) 📋 振り返り一覧の1枚に1行 ═════════
  var _yc = {};
  function yousuInto(uid, el) {
    if (!el || !uid) return;
    var draw = function (j) {
      if (!el.isConnected || !j || !j.ok) return;
      var sc = j.habits && j.habits.school, hw = j.habits && j.habits.hw, a = [];
      a.push('今週の家庭学習 ' + Number((j.week && j.week.hwDays) || 0) + '日');
      if (sc && sc.n > 0) a.push('学校の提出物 しめきりまでに ' + (sc.before + sc.same) + '/' + sc.n + '回' + (leadTop(sc) ? '（多いのは ' + leadTop(sc) + '）' : ''));
      if (hw) { var dw = topDow(hw); if (dw.length) a.push('よく出す曜日 ' + dw.join('・')); if (hw.photoDays || hw.physicalDays) a.push('写真 ' + (hw.photoDays || 0) + '日・成果物あり ' + (hw.physicalDays || 0) + '日'); }
      if ((j.pending || []).length) a.push('未提出 ' + j.pending.length + '件');
      el.innerHTML = '<div style="margin-top:6px;background:#f0f9ff;border:1px solid #bae6fd;border-radius:10px;padding:4px 8px;font-size:12px;color:#0c4a6e">📮 ' + esc(a.join('　・')) + '</div>';
    };
    if (_yc[uid] && Date.now() - _yc[uid].at < 120000) { draw(_yc[uid].j); return; }
    jget('/api/teacher/teishutsu/student?lite=1&studentId=' + encodeURIComponent(uid)).then(function (j) { if (j && j.ok) _yc[uid] = { at: Date.now(), j: j }; draw(j); });
  }

  window.TS_T = { copyLines: copyLines, yousuInto: yousuInto, testRows: testRows, matchUnit: matchUnit, faPanelHtml: faPanelHtml, subjTrend: subjTrend };
})();
