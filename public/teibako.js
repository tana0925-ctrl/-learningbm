/* 📋 MINNA_FURI_V1 振り返り一覧（先生の画面）— 2026-10-26
 *
 *  ロイロノートの提出箱のように、その日／その週の振り返りをクラス全員ぶんタイルで並べる。
 *  ・家庭学習タブに「📋 振り返り一覧」のサブタブを足す（HTMLは触らず、ここで差し込む）。
 *  ・読むのはその日／その週の分だけ（/api/teacher/teibako）。
 *  ・返却は既存のAPIそのまま（毎日：/api/teacher/homework/:id/return、週：/api/teacher/reflection-comments）。
 *    コインも既存のまま。ここで新しい付与はしない。
 *  ・今日のひと往復の下書き（公開前）があれば、開いたときに見える。返却に使ったら下書きは「公開ずみ」にする（二重に返さない）。
 *  ・みんなのふりかえり：子どもが「のせてもいいよ」とした振り返りのうち、AIが選んだ掲載候補（⭐）にだけ「のせる」ボタン。
 *    文面を直して「採用」。元の振り返りは書きかえない。採用の取り消しもできる。
 *  ・今日のひと往復のコピーに「みんなのふりかえり候補」を足す／AIの返事の [PICK:振り返りID] 理由 を取り込む（window.MINNA_PICK）。
 */
(function () {
  'use strict';
  if (window.__TEIBAKO_V1__) return; window.__TEIBAKO_V1__ = 1;

  var LS_ALL = 'teibakoPickFromAll';   // 設定：全同意分から選べる（初期はAI候補だけ）
  var S = { mode: 'day', date: '', week: '', cid: '', data: null, sort: 'name', fUnsub: false, fUnret: false, fPick: false, open: -1, list: [] };

  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function jget(url) { return fetch(url, { credentials: 'include' }).then(function (r) { return r.json(); }).catch(function () { return null; }); }
  function jpost(url, body) {
    return fetch(url, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (r) { return r.json(); }).catch(function () { return null; });
  }
  function lsGet(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function lsSet(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  var WD = ['日', '月', '火', '水', '木', '金', '土'];
  function jstToday() { var d = new Date(Date.now() + 9 * 3600000); return d.toISOString().slice(0, 10); }
  function addDay(ymd, n) { var p = ymd.split('-'); var d = new Date(Date.UTC(+p[0], +p[1] - 1, +p[2]) + n * 86400000); return d.toISOString().slice(0, 10); }
  function isoWeek(ymd) {
    var p = String(ymd).split('-'); var x = new Date(Date.UTC(+p[0], +p[1] - 1, +p[2]));
    x.setUTCDate(x.getUTCDate() + 4 - (x.getUTCDay() || 7));
    var ys = new Date(Date.UTC(x.getUTCFullYear(), 0, 1));
    var w = Math.ceil((((x.getTime() - ys.getTime()) / 86400000) + 1) / 7);
    return x.getUTCFullYear() + '-W' + pad(w);
  }
  function wkMonday(wk) {
    var m = String(wk || '').match(/^(\d{4})-W(\d{2})$/); if (!m) return null;
    var j4 = new Date(Date.UTC(+m[1], 0, 4)); var dw = j4.getUTCDay() || 7;
    return new Date(j4.getTime() + ((1 - dw) + (+m[2] - 1) * 7) * 86400000);
  }
  function wkShift(wk, n) { var mo = wkMonday(wk); return mo ? isoWeek(new Date(mo.getTime() + n * 7 * 86400000).toISOString().slice(0, 10)) : wk; }
  function dayJa(ymd) { var p = ymd.split('-'); var d = new Date(Date.UTC(+p[0], +p[1] - 1, +p[2])); return (+p[1]) + '/' + (+p[2]) + '(' + WD[d.getUTCDay()] + ')'; }
  function wkJa(wk) { var mo = wkMonday(wk); if (!mo) return wk; var fr = new Date(mo.getTime() + 4 * 86400000); return (mo.getUTCMonth() + 1) + '/' + mo.getUTCDate() + '〜' + (fr.getUTCMonth() + 1) + '/' + fr.getUTCDate() + 'の週'; }
  function timeJa(ms) {
    if (!ms) return '';
    var d = new Date(Number(ms) + 9 * 3600000);
    return (d.getUTCMonth() + 1) + '/' + d.getUTCDate() + '(' + WD[d.getUTCDay()] + ') ' + d.getUTCHours() + ':' + pad(d.getUTCMinutes());
  }
  function nameOf(r) { try { if (typeof resolveStudentName === 'function') return resolveStudentName(r.loginId, r.name) || r.name || r.loginId; } catch (e) {} return r.name || r.loginId || ''; }
  var WEA = { sun: '☀️', cloud: '☁️', rain: '🌧️' };

  // ───────── 中身（毎日／週）を文にする ─────────
  function summaryOf(it) {
    if (!it) return '';
    if (S.mode === 'day') {
      var a = [];
      if (it.kantan) a.push(String(it.kantan));   // かんたんふりかえり（あれば）
      if (it.weatherReason) a.push(it.weatherReason);
      if (it.nextImprove) a.push('つぎは：' + it.nextImprove);
      if (!a.length && it.todo) a.push('やったこと：' + it.todo);
      if (it.restDay && !a.length) a.push('（お休みの日）');
      return a.join('\n');
    }
    var b = [];
    var w2 = it.wr2 || null;   /* WEEKREF2_V1 */
    if (it.kantan || (w2 && w2.promise && w2.promise.resultJa)) b.push([it.kantan || '', (w2 && w2.promise && w2.promise.resultJa) ? '🤝' + w2.promise.resultJa : ''].filter(Boolean).join('　'));
    if (w2 && w2.school && w2.school.subj) b.push('🏫' + w2.school.subj + (w2.school.theme ? '「' + w2.school.theme + '」' : '') + (w2.school.learned ? ' ' + w2.school.learned : ''));
    var main = String(it.freeText || '').trim() || String(it.planReflection || '').trim();
    if (main) b.push(main);
    if (it.goodPoint) b.push('よかった：' + it.goodPoint);
    if (it.improvePoint) b.push('くふう：' + it.improvePoint);
    if (!b.length && it.star) b.push('🌟' + it.star.text);
    return b.join('\n');
  }
  function fullHtml(it) {
    var h = '';
    function row(label, v) { if (v == null || String(v).trim() === '') return; h += '<div style="margin:6px 0"><div style="font-size:11px;color:#64748b;font-weight:700">' + esc(label) + '</div><div style="white-space:pre-wrap;font-size:15px;line-height:1.7">' + esc(v) + '</div></div>'; }
    if (S.mode === 'day') {
      h += '<div style="font-size:14px;margin-bottom:4px">' + (WEA[it.endWeather] || '') + ' ' + (it.minutes ? it.minutes + '分' : '') + (it.restDay ? '　（お休みの日）' : '') + '</div>';
      if (it.kantan) row('かんたんふりかえり', it.kantan);
      row('やったこと', it.todo); row('なぜ', it.why); row('めあて', it.aim);
      row('ふりかえり', it.weatherReason); row('つぎにくふうすること', it.nextImprove);
      row('🌟週の振り返り（シート）', it.weeklyReflection); row('写真のようす', it.photoAnalysis); row('サポーターから', it.parentComment);
    } else {
      if (it.kantan) row('かんたんふりかえり（本人の見立て）', it.kantan);
      row('🔄 今週の振り返り', String(it.freeText || '').trim() || it.planReflection);
      if (String(it.freeText || '').trim() && it.planReflection && it.planReflection !== it.freeText) row('計画の金曜らん', it.planReflection);
      row('よかったこと', it.goodPoint); row('くふうしたいこと', it.improvePoint); row('つぎのアクション', it.nextAction);
      if (it.star) row('🌟家庭学習シート（' + dayJa(it.star.dayKey) + '）', it.star.text);
      var w2 = it.wr2;   /* WEEKREF2_V1 */
      if (w2 && w2.promise) row('🤝 先週決めたこと → どうだった？', (w2.promise.text ? '「' + w2.promise.text + '」' : '') + (w2.promise.resultJa ? ' → ' + w2.promise.resultJa + (w2.promise.reasonJa ? '（わけ：' + w2.promise.reasonJa + '）' : '') : '') + (w2.promise.note ? '\n一言：' + w2.promise.note : ''));
      if (w2 && w2.school) row('🏫 学校での学び', [w2.school.subj + (w2.school.theme ? '「' + w2.school.theme + '」' : ''), w2.school.learned ? 'わかったこと：' + w2.school.learned : '', w2.school.more ? 'もっと知りたい：' + w2.school.more : ''].filter(Boolean).join('\n'));
      if (w2 && w2.q) row('💭 ' + w2.q.label, [w2.q.choiceJa, w2.q.text].filter(Boolean).join('・'));
      if (w2 && w2.facts) row('📊 今週の記録（子どもに見せた事実）', factsJa(w2.facts));
      if (it.nextTry) row('🎯 来週やってみたいこと', (it.nextTry.unitName ? '「' + it.nextTry.unitName + '」 ' : '') + (it.nextTry.text || ''));
    }
    return h;
  }
  // ───────── WEEKREF2_V1 下書きの印（まとめて返す対象から外すもの） ─────────
  function unitJa2(id) { try { if (typeof _unitJa === 'function') return _unitJa(id) || id; } catch (e) {} return id; }
  function factsJa(f) {
    if (!f) return '';
    var a = ['アプリを開いた日 ' + (f.openDays || 0) + '日'];
    (f.units || []).forEach(function (u) { var nm = u.name || unitJa2(u.unit); if (u.c > 0) a.push(nm + (u.prevC > 0 && u.c > u.prevC ? ' せいかい 先週' + u.prevC + '問→今週' + u.c + '問' : ' 今週' + u.c + '問せいかい')); });
    if (f.planDays > 0) a.push('計画を書いた' + f.planDays + '日のうち' + (f.doneDays || 0) + '日 家庭学習');
    return a.join('／');
  }
  function otherNames(uid) {
    var out = [];
    ((S.data && S.data.roster) || []).forEach(function (r) {
      if (String(r.id) === String(uid)) return;
      var parts = [];
      [nameOf(r), r.name].forEach(function (n) { n = String(n || ''); parts.push(n.replace(/[\s　]/g, '')); n.split(/[\s　]+/).forEach(function (x) { parts.push(x); }); });
      // ひらがな・カタカナだけの2文字（例「りく」）は ふつうのことばにまざるので、3文字以上のときだけ見る
      parts.forEach(function (n) { var kana = /^[ぁ-んァ-ヶー]+$/.test(n); if ((kana ? n.length >= 3 : n.length >= 2) && out.indexOf(n) < 0) out.push(n); });
    });
    return out;
  }
  function draftFlags(o) {
    var it = o && o.it; if (!it || !it.draft) return null;
    var body = String(it.draft.body || ''), flat = body.replace(/[\s　]/g, '');
    var ng = ngWords(body);
    var nm = otherNames(o.r.id).filter(function (n) { return flat.indexOf(n) >= 0; });
    var stale = !!(it.draft.createdAt && Number(it.submittedAt) > Number(it.draft.createdAt) + 60000);
    return { ng: ng, names: nm, stale: stale, ok: !ng.length && !nm.length && !stale };
  }
  function flagChips(f) {
    if (!f) return '';
    var h = '';
    if (f.ng.length) h += '<span class="tbChip" style="background:#fef9c3;color:#854d0e;border:1px solid #fde047">🟡 ことば</span>';
    if (f.names.length) h += '<span class="tbChip" style="background:#fee2e2;color:#b91c1c">⚠ 名前</span>';
    if (f.stale) h += '<span class="tbChip" style="background:#e0f2fe;color:#0369a1">🔄 書き直しあり</span>';
    return h;
  }
  function returnWeek(list) {   // [{o, body}] … 既存の返却API（reflection-comments）をそのまま使う
    var comments = list.map(function (x) { return { studentId: x.o.r.id, comment: String(x.body).slice(0, 1000), weekKey: S.week }; });
    return jpost('/api/teacher/reflection-comments', { weekKey: S.week, comments: comments }).then(function (j) {
      if (!j || !j.ok) return { ok: false, saved: 0 };
      var ids = list.filter(function (x) { return x.o.it.draft; }).map(function (x) { return x.o.it.draft.id; });
      if (ids.length) jpost('/api/teacher/ai-drafts/mark', { ids: ids, status: 'published' });
      list.forEach(function (x) { if (!x.o.it.returnedAt) { x.o.it.returnedAt = Date.now(); x.o.it.teacherComment = x.body; } x.o.it.draft = null; });
      return { ok: true, saved: Number(j.saved) || 0 };
    });
  }
  function draftRows() {   // 絞り込みに関係なく、全員の中から
    var keep = { fUnsub: S.fUnsub, fUnret: S.fUnret, fPick: S.fPick };
    S.fUnsub = S.fUnret = S.fPick = false;
    var all = rows();
    S.fUnsub = keep.fUnsub; S.fUnret = keep.fUnret; S.fPick = keep.fPick;
    return all.filter(function (o) { return o.it && o.it.draft && isSubmitted(o.it) && !o.it.returnedAt; });
  }
  function drawBulk() {
    var el = $('tbBulk'); if (!el) return;
    if (S.mode !== 'week') { el.innerHTML = ''; return; }
    var ds = draftRows(), oks = ds.filter(function (o) { return draftFlags(o).ok; });
    if (!ds.length) { el.innerHTML = ''; return; }
    var held = ds.length - oks.length;
    el.innerHTML = '<div style="background:#eef2ff;border:2px solid #a5b4fc;border-radius:12px;padding:6px 10px;display:flex;flex-wrap:wrap;gap:8px;align-items:center">' +
      '<b style="color:#3730a3;font-size:13px">📝 ひと往復の下書き：' + ds.length + '人ぶん</b>' +
      (oks.length ? '<button type="button" id="tbBulkGo" style="background:#4f46e5;color:#fff;border:none;border-radius:10px;padding:7px 14px;font-size:13.5px;font-weight:900;cursor:pointer">📨 下書きをまとめて返却（' + oks.length + '人）</button>' : '') +
      (held ? '<span style="font-size:12px;color:#3730a3">🟡ことば・⚠名前・🔄書き直しあり の ' + held + '人は まとめ返却から外しています（ひらいて確かめてから返してください）</span>' : '') +
      '<span id="tbBulkMsg" style="font-size:12.5px;font-weight:800;color:#047857"></span></div>';
    var b = $('tbBulkGo');
    if (b) b.onclick = function () {
      if (!confirm('下書きのまま ' + oks.length + '人に返却します。\n（子どもの画面に先生からの返事として出ます）\nよろしいですか？')) return;
      b.disabled = true; $('tbBulkMsg').textContent = '返しています…';
      returnWeek(oks.map(function (o) { return { o: o, body: o.it.draft.body }; })).then(function (r) {
        var m = $('tbBulkMsg');
        if (!r.ok) { b.disabled = false; if (m) { m.style.color = '#b91c1c'; m.textContent = '返却できませんでした（通信）'; } return; }
        render();
        var m2 = $('tbBulkMsg'); if (m2) m2.textContent = '✓ ' + r.saved + '人に返却しました';
      });
    };
  }
  function isSubmitted(it) { return !!it && (S.mode === 'day' ? !!it.id : !!it.submitted); }
  function isUnret(it) { return isSubmitted(it) && !it.returnedAt; }
  function canPick(it) { return !!(it && it.consent && (it.pick || lsGet(LS_ALL) === '1')); }

  // ───────── 画面の差し込み ─────────
  function ensureTab() {
    var nav = $('hwSubTab_daily'); if (!nav || $('hwSubTab_teibako')) return !!$('hwSubTab_teibako');
    var b = document.createElement('button');
    b.id = 'hwSubTab_teibako';
    b.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100';
    b.innerHTML = '<span class="bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black">📋</span> 振り返り一覧';
    b.onclick = function () { show(true); };
    nav.parentNode.insertBefore(b, nav.nextSibling);
    var pane = document.createElement('div');
    pane.id = 'hwPane_teibako';
    pane.className = 'hidden space-y-3';
    var after = $('hwPane_daily') || $('hwPane_dashboard');
    if (after && after.parentNode) after.parentNode.insertBefore(pane, after.nextSibling);
    // ほかのサブタブを押したら閉じる
    ['hwSubTab_menu', 'hwSubTab_daily', 'hwSubTab_dashboard'].forEach(function (id) {
      var x = $(id); if (x) x.addEventListener('click', function () { show(false); });
    });
    return true;
  }
  function show(on) {
    var pane = $('hwPane_teibako'), btn = $('hwSubTab_teibako'), plan = $('hwPlanBox');
    if (!pane || !btn) return;
    if (on) {
      ['dashboard', 'menu', 'daily'].forEach(function (t) {
        var p = $('hwPane_' + t); if (p) p.classList.add('hidden');
        var bb = $('hwSubTab_' + t); if (bb) { bb.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100'; var n = bb.querySelector('span'); if (n) n.className = 'bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black'; }
      });
      if (plan) plan.style.display = 'none';
      pane.classList.remove('hidden');
      btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold bg-amber-500 text-white';
      var n2 = btn.querySelector('span'); if (n2) n2.className = 'bg-white text-amber-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
      if (!pane.firstChild) drawFrame();
      load();
    } else {
      pane.classList.add('hidden');
      if (plan) plan.style.display = '';
      btn.className = 'flex items-center gap-1 px-3 py-2 rounded-lg text-sm font-bold text-slate-500 hover:bg-slate-100';
      var n3 = btn.querySelector('span'); if (n3) n3.className = 'bg-slate-200 text-slate-600 rounded-full w-5 h-5 flex items-center justify-center text-xs font-black';
    }
  }

  var BTN = 'background:#fff;border:1.5px solid #cbd5e1;border-radius:10px;padding:6px 10px;font-size:13px;font-weight:800;color:#334155;cursor:pointer';
  function drawFrame() {
    var pane = $('hwPane_teibako');
    if (!S.date) S.date = jstToday();
    if (!S.week) S.week = isoWeek(jstToday());
    pane.innerHTML =
      '<style>' +
      '#tbGrid{display:grid;grid-template-columns:repeat(auto-fill,minmax(168px,1fr));gap:10px}' +
      '@media (max-width:480px){#tbGrid{grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}}' +
      '.tbTile{position:relative;background:#fff;border:2px solid #e2e8f0;border-radius:14px;padding:8px 9px;min-height:150px;cursor:pointer;display:flex;flex-direction:column;gap:4px;text-align:left;box-shadow:0 1px 2px rgba(0,0,0,.05)}' +
      '.tbTile:hover{border-color:#f59e0b}' +
      '.tbTile.off{background:#f1f5f9;border-color:#e2e8f0;cursor:default;min-height:64px;box-shadow:none}' +
      '.tbTile.star{border-color:#f59e0b;box-shadow:0 0 0 3px #fde68a}' +
      '.tbName{font-weight:900;font-size:14px;color:#1e293b;padding-right:14px;line-height:1.25}' +
      '.tbTime{font-size:11px;color:#64748b}' +
      '.tbTxt{font-size:12.5px;color:#334155;line-height:1.5;white-space:pre-wrap;display:-webkit-box;-webkit-line-clamp:4;-webkit-box-orient:vertical;overflow:hidden}' +
      '.tbDot{position:absolute;top:8px;right:8px;width:11px;height:11px;border-radius:999px;background:#ef4444}' +
      '.tbChip{display:inline-block;font-size:10.5px;font-weight:800;border-radius:999px;padding:1px 7px}' +
      '.tbThumb{width:100%;height:64px;object-fit:cover;border-radius:8px;background:#f1f5f9}' +
      '</style>' +
      '<div class="bg-white rounded-xl shadow p-3" style="display:flex;flex-direction:column;gap:8px">' +
      '<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">' +
      '<span style="font-weight:900;color:#b45309;font-size:15px">📋 振り返り一覧</span>' +
      '<select id="tbClass" style="border:1px solid #cbd5e1;border-radius:8px;padding:6px;font-size:13px;background:#fff"></select>' +
      '<span style="display:inline-flex;border:1.5px solid #f59e0b;border-radius:10px;overflow:hidden">' +
      '<button type="button" id="tbModeDay" style="padding:6px 12px;font-size:13px;font-weight:800;border:none;cursor:pointer">毎日の振り返り</button>' +
      '<button type="button" id="tbModeWeek" style="padding:6px 12px;font-size:13px;font-weight:800;border:none;cursor:pointer">週の振り返り</button></span>' +
      '<span id="tbCount" style="margin-left:auto;font-size:13px;font-weight:900;color:#334155"></span>' +
      '</div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">' +
      '<button type="button" id="tbPrev" style="' + BTN + '">◀ <span id="tbPrevL">前日</span></button>' +
      '<input type="date" id="tbDate" style="border:1px solid #cbd5e1;border-radius:8px;padding:5px 6px;font-size:13px">' +
      '<select id="tbWeek" style="display:none;border:1px solid #cbd5e1;border-radius:8px;padding:6px;font-size:13px;background:#fff"></select>' +
      '<button type="button" id="tbNext" style="' + BTN + '"><span id="tbNextL">翌日</span> ▶</button>' +
      '<button type="button" id="tbToday" style="' + BTN + '">きょう</button>' +
      '<span style="width:8px"></span>' +
      '<select id="tbSort" style="border:1px solid #cbd5e1;border-radius:8px;padding:6px;font-size:13px;background:#fff">' +
      '<option value="name">名前順</option><option value="time">提出順</option><option value="unret">未返却を先に</option></select>' +
      '<label style="font-size:13px;font-weight:700;display:inline-flex;gap:3px;align-items:center"><input type="checkbox" id="tbFUnsub">未提出だけ</label>' +
      '<label style="font-size:13px;font-weight:700;display:inline-flex;gap:3px;align-items:center"><input type="checkbox" id="tbFUnret">未返却だけ</label>' +
      '<label style="font-size:13px;font-weight:700;display:inline-flex;gap:3px;align-items:center;color:#b45309"><input type="checkbox" id="tbFPick">⭐掲載候補だけ</label>' +
      '<button type="button" id="tbReload" style="' + BTN + '">🔄</button>' +
      '</div>' +
      '<div id="tbPicks"></div>' +
      '<div id="tbBulk"></div>' +
      '</div>' +
      '<div id="tbGrid"></div>' +
      '<div style="font-size:11px;color:#94a3b8;text-align:right">⚙ <label style="cursor:pointer"><input type="checkbox" id="tbAllCons"> AI候補でなくても、「のせてもいいよ」の振り返りから選べるようにする</label></div>';
    // クラス（家庭学習のクラス選択と同じもの）
    var src = $('hwClassFilter') || $('dashClassFilter') || $('analyticsClassFilter');
    var sel = $('tbClass');
    if (src && sel) { sel.innerHTML = src.innerHTML; sel.value = src.value; if (!sel.value && sel.options.length > 1) sel.selectedIndex = 1; }
    sel.onchange = function () { load(); };
    $('tbModeDay').onclick = function () { S.mode = 'day'; load(); };
    $('tbModeWeek').onclick = function () { S.mode = 'week'; load(); };
    $('tbPrev').onclick = function () { if (S.mode === 'day') S.date = addDay(S.date, -1); else S.week = wkShift(S.week, -1); load(); };
    $('tbNext').onclick = function () { if (S.mode === 'day') S.date = addDay(S.date, 1); else S.week = wkShift(S.week, 1); load(); };
    $('tbToday').onclick = function () { S.date = jstToday(); S.week = isoWeek(jstToday()); load(); };
    $('tbDate').onchange = function () { if (/^\d{4}-\d{2}-\d{2}$/.test(this.value)) { S.date = this.value; load(); } };
    $('tbWeek').onchange = function () { S.week = this.value; load(); };
    $('tbSort').onchange = function () { S.sort = this.value; render(); };
    $('tbFUnsub').onchange = function () { S.fUnsub = this.checked; if (this.checked) { S.fUnret = false; $('tbFUnret').checked = false; } render(); };
    $('tbFUnret').onchange = function () { S.fUnret = this.checked; if (this.checked) { S.fUnsub = false; $('tbFUnsub').checked = false; } render(); };
    $('tbFPick').onchange = function () { S.fPick = this.checked; render(); };
    $('tbReload').onclick = function () { load(); };
    var ac = $('tbAllCons'); ac.checked = lsGet(LS_ALL) === '1'; ac.onchange = function () { lsSet(LS_ALL, this.checked ? '1' : '0'); render(); };
  }
  function drawNav() {
    var d = S.mode === 'day';
    $('tbModeDay').style.cssText = 'padding:6px 12px;font-size:13px;font-weight:800;border:none;cursor:pointer;' + (d ? 'background:#f59e0b;color:#fff' : 'background:#fff;color:#b45309');
    $('tbModeWeek').style.cssText = 'padding:6px 12px;font-size:13px;font-weight:800;border:none;cursor:pointer;' + (!d ? 'background:#f59e0b;color:#fff' : 'background:#fff;color:#b45309');
    $('tbPrevL').textContent = d ? '前日' : '前週'; $('tbNextL').textContent = d ? '翌日' : '翌週';
    $('tbToday').textContent = d ? 'きょう' : '今週';
    $('tbDate').style.display = d ? '' : 'none'; $('tbDate').value = S.date;
    var ws = $('tbWeek'); ws.style.display = d ? 'none' : '';
    var cur = isoWeek(jstToday()), h = '';
    for (var i = 0; i < 16; i++) { var w = wkShift(cur, -i); h += '<option value="' + w + '"' + (w === S.week ? ' selected' : '') + '>' + wkJa(w) + (i === 0 ? '（今週）' : '') + '</option>'; }
    if (h.indexOf('value="' + S.week + '"') < 0) h = '<option value="' + S.week + '" selected>' + wkJa(S.week) + '</option>' + h;
    ws.innerHTML = h;
  }

  var _seq = 0;
  function load() {
    if (!$('tbGrid')) return;
    drawNav();
    S.cid = $('tbClass').value;
    var grid = $('tbGrid');
    if (!S.cid) { grid.innerHTML = '<p style="color:#64748b;font-size:13px">クラスを選んでください</p>'; return; }
    grid.innerHTML = '<p style="color:#64748b;font-size:13px">読み込み中…</p>';
    var my = ++_seq;
    var url = '/api/teacher/teibako?classId=' + encodeURIComponent(S.cid) + '&mode=' + S.mode + (S.mode === 'day' ? '&date=' + S.date : '&week=' + S.week);
    jget(url).then(function (d) {
      if (my !== _seq) return;
      if (!d || !d.ok) { grid.innerHTML = '<p style="color:#b91c1c;font-size:13px">読み込めませんでした（' + esc((d && d.error) || '通信') + '）</p>'; S.data = null; return; }
      S.data = d;
      render();
    });
  }
  function rows() {
    var d = S.data; if (!d) return [];
    var by = {}; (d.items || []).forEach(function (it) { by[it.userId] = it; });
    var out = (d.roster || []).map(function (r) { return { r: r, it: by[r.id] || null, name: nameOf(r) }; });
    out.sort(function (a, b) {
      var an = a.r.rosterNo == null ? 9999 : a.r.rosterNo, bn = b.r.rosterNo == null ? 9999 : b.r.rosterNo;
      if (an !== bn) return an - bn;
      return String(a.name).localeCompare(String(b.name), 'ja');
    });
    if (S.sort === 'time') {
      out.sort(function (a, b) { var x = isSubmitted(a.it) ? (a.it.submittedAt || 1) : Infinity, y = isSubmitted(b.it) ? (b.it.submittedAt || 1) : Infinity; return x - y; });
    } else if (S.sort === 'unret') {
      out.sort(function (a, b) { var k = function (o) { return isUnret(o.it) ? 0 : isSubmitted(o.it) ? 1 : 2; }; return k(a) - k(b); });
    }
    if (S.fUnsub) out = out.filter(function (o) { return !isSubmitted(o.it); });
    if (S.fUnret) out = out.filter(function (o) { return isUnret(o.it); });
    if (S.fPick) out = out.filter(function (o) { return o.it && o.it.pick; });
    return out;
  }
  function photoUrl(uid, i) { return '/api/photo/' + encodeURIComponent(uid) + '/' + encodeURIComponent(S.date) + (i ? '?idx=' + i : ''); }
  function render() {
    var d = S.data, grid = $('tbGrid'); if (!d || !grid) return;
    var all = (d.roster || []);
    var by = {}; (d.items || []).forEach(function (it) { by[it.userId] = it; });
    var nSub = 0, nUnret = 0;
    all.forEach(function (r) { var it = by[r.id]; if (isSubmitted(it)) nSub++; if (isUnret(it)) nUnret++; });
    $('tbCount').innerHTML = '提出 <span style="font-size:18px;color:#b45309">' + nSub + '</span> / ' + all.length + '人' + (nUnret ? '　<span style="color:#ef4444">● 未返却 ' + nUnret + '</span>' : '');
    // 今回の掲載候補
    var picks = all.filter(function (r) { return by[r.id] && by[r.id].pick; });
    var ph = '';
    if (picks.length) {
      ph = '<div style="background:#fffbeb;border:2px solid #fcd34d;border-radius:12px;padding:6px 10px;display:flex;flex-wrap:wrap;gap:6px;align-items:center">' +
        '<b style="color:#b45309;font-size:13px">⭐ 今回の掲載候補：' + picks.length + '件</b>';
      picks.forEach(function (r) {
        var it = by[r.id];
        ph += '<button type="button" class="tbJump" data-uid="' + esc(r.id) + '" style="background:#fff;border:1.5px solid #f59e0b;border-radius:999px;padding:3px 10px;font-size:12px;font-weight:800;color:#92400e;cursor:pointer">' +
          esc(nameOf(r)) + (it.post && it.post.on ? ' 📖' : '') + '</button>';
      });
      ph += '<span style="font-size:11px;color:#92400e">（AIが「友だちが読んで参考になる」と選んだもの。のせるかどうかは先生が決めます）</span></div>';
    }
    $('tbPicks').innerHTML = ph;
    var list = rows();
    S.list = list;
    if (!list.length) { grid.innerHTML = '<p style="color:#64748b;font-size:13px;grid-column:1/-1">あてはまる子はいません</p>'; bindJump(); drawBulk(); return; }
    var h = '';
    list.forEach(function (o, idx) {
      var it = o.it, sub = isSubmitted(it);
      if (!sub) { h += '<div class="tbTile off"><div class="tbName" style="color:#94a3b8">' + esc(o.name) + '</div><div class="tbTime">未提出</div></div>'; return; }
      var star = !!it.pick;
      h += '<div class="tbTile' + (star ? ' star' : '') + '" data-i="' + idx + '" role="button" tabindex="0">';
      if (isUnret(it)) h += '<span class="tbDot" title="未返却"></span>';
      h += '<div class="tbName">' + (S.mode === 'day' && WEA[it.endWeather] ? WEA[it.endWeather] + ' ' : '') + (S.mode === 'week' && it.kantan ? '<span style="color:#b45309">' + esc(it.kantan.charAt(0)) + '</span> ' : '') + esc(o.name) + '</div>';
      h += '<div class="tbTime">' + esc(timeJa(it.submittedAt)) + (it.draft ? ' <span class="tbChip" style="background:#eef2ff;color:#4338ca">下書き</span>' : '') + '</div>';
      if (star) h += '<div><span class="tbChip" style="background:#f59e0b;color:#fff">⭐掲載候補</span></div><div style="font-size:11px;color:#92400e;line-height:1.4">AI：' + esc(it.pick.reason || '') + '</div>';
      h += '<div class="tbTxt">' + esc(summaryOf(it) || '（文はありません）') + '</div>';
      if (S.mode === 'week' && it.draft && !it.returnedAt) {   /* WEEKREF2_V1 ひと往復の下書きを そのまま */
        var fl = draftFlags(o);
        h += '<div style="background:#eef2ff;border:1.5px dashed #818cf8;border-radius:10px;padding:5px 7px;margin-top:2px">' +
          '<div style="font-size:10.5px;font-weight:900;color:#4338ca;display:flex;flex-wrap:wrap;gap:3px;align-items:center">📝 下書き（まだ子どもには見えない）' + flagChips(fl) + '</div>' +
          '<div style="font-size:12px;line-height:1.5;color:#1e1b4b;white-space:pre-wrap;display:-webkit-box;-webkit-line-clamp:6;-webkit-box-orient:vertical;overflow:hidden">' + markNg(it.draft.body) + '</div>' +
          (fl.ok ? '<button type="button" class="tbOneRet" data-i="' + idx + '" style="margin-top:3px;width:100%;min-height:36px;background:#4f46e5;color:#fff;border:none;border-radius:9px;font-size:12.5px;font-weight:900;cursor:pointer">このまま返す</button>'
                 : '<button type="button" class="tbOneOpen" data-i="' + idx + '" style="margin-top:3px;width:100%;min-height:36px;background:#fff;color:#4338ca;border:1.5px solid #818cf8;border-radius:9px;font-size:12.5px;font-weight:900;cursor:pointer">ひらいて 確かめる</button>') +
          '</div>';
      }
      if (S.mode === 'day' && it.photoCount) h += '<img class="tbThumb" loading="lazy" alt="写真" src="' + photoUrl(o.r.id, 0) + '" onerror="this.style.display=\'none\'">';
      var chips = '';
      if (it.consent) chips += '<span class="tbChip" style="background:#ecfdf5;color:#047857;border:1px solid #6ee7b7">のせてもいいよ（' + (it.consent.mode === 'named' ? '名前あり' : '名前なし') + '）</span>';
      if (it.post && it.post.on) chips += '<span class="tbChip" style="background:#dbeafe;color:#1d4ed8">📖のせた</span>';
      if (it.returnedAt) chips += '<span class="tbChip" style="background:#f1f5f9;color:#475569">返却ずみ</span>';
      if (chips) h += '<div style="display:flex;flex-wrap:wrap;gap:3px;margin-top:auto">' + chips + '</div>';
      if (canPick(it)) h += '<button type="button" class="tbPickBtn" data-i="' + idx + '" style="margin-top:2px;background:' + (it.post && it.post.on ? '#fff' : '#f59e0b') + ';color:' + (it.post && it.post.on ? '#b45309' : '#fff') + ';border:1.5px solid #f59e0b;border-radius:10px;padding:5px;font-size:12.5px;font-weight:900;cursor:pointer">' + (it.post && it.post.on ? '📖 のせた文を見る' : 'のせる') + '</button>';
      h += '</div>';
    });
    grid.innerHTML = h;
    var tiles = grid.querySelectorAll('.tbTile[data-i]');
    for (var i = 0; i < tiles.length; i++) {
      tiles[i].onclick = function (ev) { if (ev.target && ev.target.classList && (ev.target.classList.contains('tbPickBtn') || ev.target.classList.contains('tbOneRet') || ev.target.classList.contains('tbOneOpen'))) return; openAt(Number(this.getAttribute('data-i'))); };
      tiles[i].onkeydown = function (ev) { if (ev.key === 'Enter') openAt(Number(this.getAttribute('data-i'))); };
    }
    var ors = grid.querySelectorAll('.tbOneRet');   /* WEEKREF2_V1 */
    for (var q = 0; q < ors.length; q++) ors[q].onclick = function (ev) {
      ev.stopPropagation();
      var o = S.list[Number(this.getAttribute('data-i'))]; if (!o || !o.it || !o.it.draft) return;
      var self = this; self.disabled = true; self.textContent = '返しています…';
      returnWeek([{ o: o, body: o.it.draft.body }]).then(function (r) { if (!r.ok || !r.saved) { self.disabled = false; self.textContent = '返せませんでした（もう一度）'; return; } render(); });
    };
    var oos = grid.querySelectorAll('.tbOneOpen');
    for (var q2 = 0; q2 < oos.length; q2++) oos[q2].onclick = function (ev) { ev.stopPropagation(); openAt(Number(this.getAttribute('data-i'))); };
    drawBulk();
    var pbs = grid.querySelectorAll('.tbPickBtn');
    for (var j = 0; j < pbs.length; j++) pbs[j].onclick = function (ev) { ev.stopPropagation(); openPick(Number(this.getAttribute('data-i'))); };
    bindJump();
  }
  function bindJump() {
    var js = document.querySelectorAll('.tbJump');
    for (var i = 0; i < js.length; i++) js[i].onclick = function () {
      var uid = this.getAttribute('data-uid');
      for (var k = 0; k < S.list.length; k++) if (S.list[k].r.id === uid) { openAt(k); return; }
      // 絞り込みで見えていないときは絞り込みを外して開く
      S.fUnsub = S.fUnret = false; $('tbFUnsub').checked = $('tbFUnret').checked = false; render();
      for (var m = 0; m < S.list.length; m++) if (S.list[m].r.id === uid) { openAt(m); return; }
    };
  }

  // ───────── 大きく開く ─────────
  function closeModal() { var o = $('tbModal'); if (o && o.parentNode) o.parentNode.removeChild(o); S.open = -1; document.removeEventListener('keydown', onKey); }
  function onKey(ev) {
    var t = ev.target && ev.target.tagName;
    if (t === 'TEXTAREA' || t === 'INPUT') { if (ev.key === 'Escape') closeModal(); return; }
    if (ev.key === 'ArrowRight') step(1); else if (ev.key === 'ArrowLeft') step(-1); else if (ev.key === 'Escape') closeModal();
  }
  function step(n) {
    if (S.open < 0) return;
    var k = S.open;
    for (var c = 0; c < S.list.length; c++) { k = (k + n + S.list.length) % S.list.length; if (isSubmitted(S.list[k].it)) { openAt(k); return; } }
  }
  function openAt(i) {
    var o = S.list[i]; if (!o || !isSubmitted(o.it)) return;
    S.open = i;
    var it = o.it;
    var m = $('tbModal');
    if (!m) {
      m = document.createElement('div'); m.id = 'tbModal';
      m.setAttribute('style', 'position:fixed;inset:0;z-index:9999;background:rgba(15,23,42,.55);overflow-y:auto;-webkit-overflow-scrolling:touch;padding:14px 8px');
      m.addEventListener('click', function (ev) { if (ev.target === m) closeModal(); });
      document.body.appendChild(m);
      document.addEventListener('keydown', onKey);
    }
    var nav = 'background:#fff;border:none;border-radius:999px;width:44px;height:44px;font-size:22px;font-weight:900;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.2)';
    var photos = '';
    if (S.mode === 'day' && it.photoCount) {
      photos = '<div style="display:flex;gap:8px;flex-wrap:wrap;margin:8px 0">';
      for (var p = 0; p < Math.min(3, it.photoCount); p++) photos += '<a href="' + photoUrl(o.r.id, p) + '" target="_blank" rel="noopener"><img src="' + photoUrl(o.r.id, p) + '" alt="写真" style="max-height:220px;max-width:100%;border-radius:10px;border:1px solid #e2e8f0" onerror="this.style.display=\'none\'"></a>';
      photos += '</div>';
    }
    var ret = it.returnedAt
      ? '<div style="font-size:12px;color:#475569;margin-bottom:4px">✅ ' + esc(timeJa(it.returnedAt)) + ' に返却ずみ' + (S.mode === 'day' ? '（コメントを直せます。子どもへの知らせは送りません）' : '') + '</div>'
      : '';
    var draft = it.draft ? '<div style="background:#eef2ff;border:1.5px dashed #818cf8;border-radius:10px;padding:8px;margin-bottom:6px"><div style="font-size:12px;font-weight:900;color:#4338ca">📝 今日のひと往復の下書き（まだ子どもには見えていません）</div><div style="white-space:pre-wrap;font-size:13.5px;margin-top:3px">' + markNg(it.draft.body) + '</div>' + (ngWords(it.draft.body).length ? '<div style="font-size:12px;font-weight:800;color:#854d0e;background:#fef9c3;border-radius:6px;padding:2px 6px;margin-top:3px">🟡 子どもには きつく聞こえることば：「' + esc(ngWords(it.draft.body).join('」「')) + '」（直してから返してください）</div>' : '') + (function () { var f0 = draftFlags(o); return f0 && (f0.names.length || f0.stale) ? '<div style="font-size:12px;font-weight:800;color:#b91c1c;margin-top:3px">' + (f0.names.length ? '⚠ ほかの子の名前らしいことば：' + esc(f0.names.join('、')) + '　' : '') + (f0.stale ? '🔄 下書きを作ったあとで、この子が振り返りを書き直しています。今の文と合っているか確かめてください' : '') + '</div>' : ''; })() + '<button type="button" id="tbUseDraft" style="margin-top:4px;background:#4f46e5;color:#fff;border:none;border-radius:8px;padding:4px 10px;font-size:12px;font-weight:800;cursor:pointer">↓ この下書きを使う</button></div>' : '';
    var canReturn = S.mode === 'day' || !it.returnedAt;
    var star = it.pick ? '<div style="background:#fffbeb;border:2px solid #fcd34d;border-radius:10px;padding:6px 8px;margin:6px 0;font-size:13px"><b style="color:#b45309">⭐ 掲載候補</b>　AIの理由：' + esc(it.pick.reason || '') + '</div>' : '';
    var cons = it.consent ? '<span class="tbChip" style="background:#ecfdf5;color:#047857;border:1px solid #6ee7b7">のせてもいいよ（' + (it.consent.mode === 'named' ? '名前あり' : '名前なし') + '）</span>' : '';
    m.innerHTML = '<div style="max-width:980px;margin:0 auto;display:flex;align-items:flex-start;gap:8px">' +
      '<button type="button" id="tbL" aria-label="前の子" style="' + nav + ';position:sticky;top:45vh">‹</button>' +
      '<div style="flex:1;min-width:0;background:#fff;border-radius:18px;padding:14px 16px;box-shadow:0 12px 40px rgba(0,0,0,.3)">' +
      '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">' +
      '<div style="font-size:20px;font-weight:900;color:#1e293b">' + esc(o.name) + '</div>' +
      '<div style="font-size:12px;color:#64748b">' + esc(S.mode === 'day' ? dayJa(S.date) : wkJa(S.week)) + '・提出 ' + esc(timeJa(it.submittedAt)) + '</div>' + cons +
      (isUnret(it) ? '<span class="tbChip" style="background:#fee2e2;color:#b91c1c">● 未返却</span>' : '') +
      '<button type="button" id="tbX" aria-label="とじる" style="margin-left:auto;background:#f1f5f9;border:none;border-radius:999px;width:38px;height:38px;font-size:18px;cursor:pointer">×</button></div>' +
      star +
      '<div id="tbTsYousu"></div>' +   /* TEISHUTSU_V1 📮 提出のようす（小さく・先生だけ） */
      '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-top:6px">' +
      '<div><div style="font-size:12px;font-weight:900;color:#b45309">いまのふりかえり</div>' + fullHtml(it) + photos + '</div>' +
      '<div id="tbPrevBox" style="background:#f8fafc;border-radius:12px;padding:8px 10px"><div style="font-size:12px;font-weight:900;color:#475569">前回のふりかえり（くらべる）</div><div style="font-size:12px;color:#94a3b8">読み込み中…</div></div>' +
      '</div>' +
      '<div style="border-top:1px solid #e2e8f0;margin-top:10px;padding-top:8px">' +
      draft + ret +
      (canReturn
        ? '<textarea id="tbCmt" rows="3" maxlength="' + (S.mode === 'day' ? 500 : 1000) + '" style="width:100%;border:1.5px solid #cbd5e1;border-radius:10px;padding:8px;font-size:14px" placeholder="コメントを書いて返却">' + esc(it.teacherComment || '') + '</textarea>' +
          '<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-top:4px">' +
          (S.mode === 'day' && !it.returnedAt ? '<label style="font-size:12.5px"><input type="checkbox" id="tbPhys"> 成果物あり</label>' : '') +
          '<button type="button" id="tbRet" style="background:#ef4444;color:#fff;border:none;border-radius:10px;padding:8px 16px;font-size:14px;font-weight:900;cursor:pointer">' + (it.returnedAt ? 'コメントを直す' : '返却する') + '</button>' +
          '<span id="tbRetMsg" style="font-size:12.5px;font-weight:700;color:#047857"></span></div>'
        : '<div style="white-space:pre-wrap;font-size:14px;background:#f8fafc;border-radius:10px;padding:8px">' + esc(it.teacherComment || '') + '</div>') +
      (canPick(it) ? '<div style="margin-top:8px"><button type="button" id="tbPickOpen" style="background:#f59e0b;color:#fff;border:none;border-radius:10px;padding:7px 14px;font-size:13.5px;font-weight:900;cursor:pointer">' + (it.post && it.post.on ? '📖 のせた文を見る・取り消す' : '📖 みんなのふりかえりに のせる') + '</button></div>' : '') +
      '</div>' +
      '<div style="font-size:11px;color:#94a3b8;margin-top:6px;text-align:center">← → で次の子へ　／　Esc でとじる</div>' +
      '</div>' +
      '<button type="button" id="tbR" aria-label="次の子" style="' + nav + ';position:sticky;top:45vh">›</button></div>';
    $('tbX').onclick = closeModal;
    $('tbL').onclick = function () { step(-1); };
    $('tbR').onclick = function () { step(1); };
    var ud = $('tbUseDraft'); if (ud) ud.onclick = function () { var c = $('tbCmt'); if (c) { c.value = it.draft.body.slice(0, Number(c.getAttribute('maxlength')) || 1000); c.focus(); } };
    var rb = $('tbRet'); if (rb) rb.onclick = function () { doReturn(o); };
    var po = $('tbPickOpen'); if (po) po.onclick = function () { openPick(i); };
    m.scrollTop = 0;
    loadPrev(o);
    try { if (window.TS_T && typeof window.TS_T.yousuInto === 'function') window.TS_T.yousuInto(o.r.id, $('tbTsYousu')); } catch (e) {}   /* TEISHUTSU_V1 */
  }
  function loadPrev(o) {
    var url = '/api/teacher/teibako/prev?classId=' + encodeURIComponent(S.cid) + '&userId=' + encodeURIComponent(o.r.id) + '&mode=' + S.mode + '&ref=' + (S.mode === 'day' ? S.date : S.week);
    var me = S.open;
    jget(url).then(function (d) {
      var box = $('tbPrevBox'); if (!box || S.open !== me) return;
      var p = d && d.prev;
      var h = '<div style="font-size:12px;font-weight:900;color:#475569">前回のふりかえり（くらべる）</div>';
      if (!p) { box.innerHTML = h + '<div style="font-size:12.5px;color:#94a3b8;margin-top:4px">前回の分はありません</div>'; return; }
      function row(l, v) { return v ? '<div style="margin:5px 0"><div style="font-size:11px;color:#64748b;font-weight:700">' + esc(l) + '</div><div style="white-space:pre-wrap;font-size:13.5px;line-height:1.6;color:#334155">' + esc(v) + '</div></div>' : ''; }
      if (S.mode === 'day') {
        h += '<div style="font-size:12px;color:#64748b">' + esc(dayJa(p.dayKey)) + '　' + (WEA[p.endWeather] || '') + ' ' + (p.minutes ? p.minutes + '分' : '') + '</div>' + row('ふりかえり', p.weatherReason) + row('つぎにくふうすること', p.nextImprove) + (p.weatherReason || p.nextImprove ? '' : row('やったこと', p.todo));
      } else {
        h += '<div style="font-size:12px;color:#64748b">' + esc(wkJa(p.weekKey)) + '</div>' + row('振り返り', String(p.freeText || '').trim() || p.planReflection) + row('よかったこと', p.goodPoint) + row('くふうしたいこと', p.improvePoint);
      }
      box.innerHTML = h;
    });
  }
  function doReturn(o) {
    var it = o.it, c = $('tbCmt'), msg = $('tbRetMsg'), btn = $('tbRet');
    var text = c ? String(c.value || '').trim() : '';
    if (!text) { if (msg) { msg.style.color = '#b91c1c'; msg.textContent = 'コメントを書いてください'; } return; }
    btn.disabled = true; if (msg) { msg.style.color = '#475569'; msg.textContent = '送っています…'; }
    var p;
    if (S.mode === 'day') {
      var phys = $('tbPhys');
      p = jpost('/api/teacher/homework/' + encodeURIComponent(it.id) + '/return', it.returnedAt ? { comment: text, hasPhysical: !!it.hasPhysical, editOnly: true } : { comment: text, hasPhysical: !!(phys && phys.checked) });
    } else {
      p = jpost('/api/teacher/reflection-comments', { weekKey: S.week, comments: [{ studentId: o.r.id, comment: text, weekKey: S.week }] })
        .then(function (j) { return (j && j.ok && j.saved) ? j : { ok: false, error: (j && j.ok) ? 'もう返却ずみか、振り返りが見つかりません' : (j && j.error) }; });
    }
    p.then(function (j) {
      btn.disabled = false;
      if (!j || !j.ok) { if (msg) { msg.style.color = '#b91c1c'; msg.textContent = '返却できませんでした（' + ((j && j.error) || '通信') + '）'; } return; }
      var was = !!it.returnedAt;
      it.teacherComment = text;
      if (!was) it.returnedAt = Date.now();
      // ひと往復の下書きはもう使ったので「公開ずみ」にしておく（あとで二重に返さない）
      if (it.draft && !was) { jpost('/api/teacher/ai-drafts/mark', { ids: [it.draft.id], status: 'published' }); it.draft = null; }
      if (msg) { msg.style.color = '#047857'; msg.textContent = was ? '✓ コメントを直しました' : '✓ 返却しました'; }
      render();
      // 次の未返却の子へ
      setTimeout(function () {
        if (S.open < 0 || was) return;
        for (var k = 1; k <= S.list.length; k++) { var q = (S.open + k) % S.list.length; if (isUnret(S.list[q].it)) { openAt(q); return; } }
      }, 700);
    });
  }

  // ───────── のせる（文面を直して採用） ─────────
  function rosterNames() {
    var out = [];
    ((S.data && S.data.roster) || []).forEach(function (r) {
      [nameOf(r), r.name].forEach(function (n) { n = String(n || '').replace(/[\s　]/g, ''); if (n.length >= 2 && out.indexOf(n) < 0) out.push(n); });
      var full = String(nameOf(r) || '');
      var sp = full.split(/[\s　]+/); if (sp.length > 1) sp.forEach(function (x) { if (x.length >= 2 && out.indexOf(x) < 0) out.push(x); });
    });
    return out.sort(function (a, b) { return b.length - a.length; });
  }
  function ngWords(text) { try { return (typeof window.taiNgHits === 'function') ? window.taiNgHits(text) : []; } catch (e) { return []; } }   /* NGWORD_V1 */
  function markNg(text) {   // 下書きの中の気になることばに黄色の印
    var h = esc(text), ws = ngWords(text).filter(function (w) { return w !== 'まだ〜ない'; });
    ws.sort(function (a, b) { return b.length - a.length; }).forEach(function (w) { h = h.split(esc(w)).join('<mark style="background:#fde047">' + esc(w) + '</mark>'); });
    return h;
  }
  function warnWords(text) {
    var t = String(text || ''), hits = [];
    rosterNames().forEach(function (n) { if (t.replace(/[\s　]/g, '').indexOf(n) >= 0 && hits.indexOf(n) < 0) hits.push(n); });
    return hits;
  }
  function openPick(i) {
    var o = S.list[i]; if (!o || !o.it || !o.it.consent) return;
    var it = o.it;
    var old = $('tbPickWin'); if (old && old.parentNode) old.parentNode.removeChild(old);
    var w = document.createElement('div'); w.id = 'tbPickWin';
    w.setAttribute('style', 'position:fixed;inset:0;z-index:10000;background:rgba(15,23,42,.5);display:flex;align-items:center;justify-content:center;padding:10px');
    var init = (it.post && it.post.body) || summaryOf(it).replace(/^つぎは：/m, '');
    w.innerHTML = '<div style="width:100%;max-width:560px;background:#fff;border-radius:16px;padding:14px;box-shadow:0 12px 40px rgba(0,0,0,.35)">' +
      '<div style="font-size:16px;font-weight:900;color:#b45309">📖 みんなのふりかえりに のせる</div>' +
      '<div style="font-size:12px;color:#475569;margin:2px 0 6px">' + esc(o.name) + '（' + (it.consent.mode === 'named' ? '<b>名前あり</b>：子どもたちには名前だけ出ます' : '<b>名前なし</b>：名前は出ません') + '）。<br>個人がわかることば・ほかの子の名前・悪口は消してください。元の振り返りは書きかわりません。</div>' +
      (it.pick ? '<div style="font-size:12px;background:#fffbeb;border-radius:8px;padding:4px 8px;margin-bottom:6px">⭐ AIの理由：' + esc(it.pick.reason || '') + '</div>' : '') +
      '<textarea id="tbPickTxt" rows="7" maxlength="600" style="width:100%;border:1.5px solid #f59e0b;border-radius:10px;padding:8px;font-size:15px;line-height:1.7"></textarea>' +
      '<div id="tbPickWarn" style="font-size:12px;color:#b91c1c;min-height:16px"></div>' +
      '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:4px">' +
      '<button type="button" id="tbPickOk" style="background:#f59e0b;color:#fff;border:none;border-radius:10px;padding:8px 18px;font-size:14px;font-weight:900;cursor:pointer">採用</button>' +
      (it.post && it.post.on ? '<button type="button" id="tbPickOff" style="background:#fff;color:#b91c1c;border:1.5px solid #fca5a5;border-radius:10px;padding:8px 12px;font-size:13px;font-weight:800;cursor:pointer">採用を取り消す</button>' : '') +
      '<button type="button" id="tbPickCancel" style="background:#f1f5f9;color:#334155;border:none;border-radius:10px;padding:8px 12px;font-size:13px;font-weight:800;cursor:pointer">やめる</button>' +
      '<span id="tbPickMsg" style="font-size:12.5px;font-weight:800"></span></div>' +
      '<div style="font-size:11px;color:#64748b;margin-top:6px">はじめて採用したときだけ、その子に ' + ((S.data && S.data.adoptCoins) || 300) + 'コインと「のったよ！」のお知らせが届きます（取り消しても回収しません）。</div>' +
      '</div>';
    document.body.appendChild(w);
    var ta = $('tbPickTxt'); ta.value = init;
    function chk() { var h = warnWords(ta.value), g = ngWords(ta.value); $('tbPickWarn').textContent = (h.length ? '⚠ 名前らしいことばがあります：' + h.join('、') + '（消してから採用してください）　' : '') + (g.length ? '🟡 きつく聞こえることば：' + g.join('、') : ''); return h.concat(g); }
    ta.oninput = chk; chk();
    function close() { if (w.parentNode) w.parentNode.removeChild(w); }
    w.addEventListener('click', function (ev) { if (ev.target === w) close(); });
    $('tbPickCancel').onclick = close;
    $('tbPickOk').onclick = function () {
      var txt = String(ta.value || '').trim(), msg = $('tbPickMsg');
      if (!txt) { msg.style.color = '#b91c1c'; msg.textContent = '文が空です'; return; }
      if (chk().length && !confirm('名前らしいことば・きつく聞こえることばが残っています。このまま採用しますか？')) return;
      this.disabled = true; msg.style.color = '#475569'; msg.textContent = '保存しています…';
      var self = this;
      jpost('/api/teacher/minna/adopt', { consentId: it.consent.id, body: txt }).then(function (j) {
        self.disabled = false;
        if (!j || !j.ok) { msg.style.color = '#b91c1c'; msg.textContent = (j && j.error === 'no_consent') ? 'この子は「のせてもいいよ」を取り消しています' : '採用できませんでした'; return; }
        it.post = { body: txt, on: true };
        msg.style.color = '#047857'; msg.textContent = j.rewardedNow ? '✓ 採用しました（' + j.coins + 'コインを送りました）' : '✓ 採用しました';
        render(); if (S.open >= 0) openAt(S.open);
        setTimeout(close, 900);
      });
    };
    var off = $('tbPickOff'); if (off) off.onclick = function () {
      if (!confirm('採用を取り消して、みんなのふりかえりから外しますか？')) return;
      jpost('/api/teacher/minna/unadopt', { consentId: it.consent.id }).then(function (j) {
        if (j && j.ok) { it.post.on = false; render(); if (S.open >= 0) openAt(S.open); close(); }
        else { $('tbPickMsg').textContent = '取り消せませんでした'; }
      });
    };
  }

  // ═════════ 今日のひと往復：みんなのふりかえり候補（コピー／取り込み） ═════════
  function ensureTaiOption() {
    if ($('taiOptMinna')) return;
    var ref = $('taiOptSuggest') || $('taiOptReflect');
    var lab = ref && ref.parentNode;
    if (!lab || !lab.parentNode) return;
    var l = document.createElement('label');
    l.className = 'flex items-center gap-1';
    l.innerHTML = '<input type="checkbox" id="taiOptMinna" class="accent-amber-500"> ⭐みんなのふりかえり候補';
    lab.parentNode.insertBefore(l, lab.nextSibling);
  }
  function maskRoster(t) {
    var s = String(t || '');
    try {
      var names = [];
      if (typeof getStudentNameMap === 'function') { var mp = getStudentNameMap() || {}; Object.keys(mp).forEach(function (k) { var v = String(mp[k] || ''); [v, v.replace(/[\s　]/g, '')].concat(v.split(/[\s　]+/)).forEach(function (x) { if (x.length >= 2 && names.indexOf(x) < 0) names.push(x); }); }); }
      names.sort(function (a, b) { return b.length - a.length; }).forEach(function (n) { if (s.indexOf(n) >= 0) s = s.split(n).join('〇〇'); });
    } catch (e) {}
    return s;
  }
  function pickLines(src) {
    var max = (src && src.pickMax) || 5;
    var periods = (src && src.periods) || [];
    var out = [];
    out.push('==================================================');
    out.push('【みんなのふりかえり候補】（子どもが「友だちに読んでもらってもいいよ」と言った振り返り）');
    out.push('==================================================');
    out.push('先生が、クラスの子ども向けページ「みんなのふりかえり」で、いくつかを紹介します。その候補を選んでください。');
    out.push('・友だちが読んで「参考になる」「自分もやってみよう」「はげみになる」ものを、1回（1日分／1週分）につき最大' + max + '件まで選ぶ。少なくてもよい。合うものが無ければ0件でよい。');
    out.push('・選ばないもの：悪口・からかい・人をきずつける内容／本人や家族がわかる内容（住所・習いごとの場所・家の事情など）／ほかの子の名前が入っているもの（「〇〇」は名前が入っていたところ）。');
    out.push('・理由に、評価や順位づけのことば（いちばん・すばらしい・満点・○位 など）を使わない。どこが友だちの参考になるかを、事実で短く書く。');
    out.push('・理由にも、否定・比較・責めることば（おそい・少ない・足りない・できていない・〜しかない・まだ〜ない・ダメ・ちゃんと など）を使わない。');   /* NGWORD_V1 */
    out.push('・いろいろな子の振り返りが入るようにする。同じ子（同じ「K01」などの符号）ばかりにしない。「もう載せた」とあるものは選ばない。');
    out.push('・書き方（1件1行・行の形を変えない・前置きやまとめは書かない）：');
    out.push('[PICK:振り返りID] 理由（40字くらい）');
    out.push('');
    var n = 0;
    periods.forEach(function (p) {
      var items = (p.items || []).filter(function (x) { return !x.adopted; });
      var done = (p.items || []).length - items.length;
      if (!items.length) return;
      out.push('■ ' + (p.kind === 'week' ? '週の振り返り ' + wkJa(p.ref) : '毎日の振り返り ' + dayJa(p.ref)) + '（この回は最大' + Math.max(0, max - 0) + '件' + (done ? '・もう載せた' + done + '件' : '') + '）');
      items.forEach(function (x) { out.push('・振り返りID ' + x.id + '｜' + x.who + '｜' + maskRoster(x.text)); n++; });
      out.push('');
    });
    if (!n) return { lines: [], n: 0 };
    return { lines: out, n: n };
  }
  async function appendTo(txt, cid) {
    var src = await jget('/api/teacher/minna/pick-source?classId=' + encodeURIComponent(cid || ''));
    var pl = pickLines(src);
    window.__minnaPickExp = pl.n;
    if (!pl.n) return { text: txt, n: 0 };
    return { text: String(txt || '') + '\n\n' + pl.lines.join('\n'), n: pl.n };
  }
  async function copyOnly(cid, copyFn, sayFn) {
    var src = await jget('/api/teacher/minna/pick-source?classId=' + encodeURIComponent(cid || ''));
    var pl = pickLines(src);
    if (!pl.n) { if (sayFn) sayFn('「のせてもいいよ」の振り返り（最近7日・今週・先週）がまだありません'); return; }
    var head = ['あなたは小学校の担任の先生を手伝うアシスタントです。下の【みんなのふりかえり候補】だけを読んで、[PICK:振り返りID] の行だけを書いてください。', ''];
    var t = head.concat(pl.lines).join('\n');
    if (copyFn) copyFn(t);
    if (sayFn) setTimeout(function () { sayFn('✓ みんなのふりかえり候補 ' + pl.n + '件ぶんをコピーしました。AIに貼って、返事を下の欄へ'); }, 50);
  }
  // AIの返事から [PICK:...] の行をぬき出して取り込む。残りの行（ほかの目印）はそのまま返す。
  function stripDeco(line) {
    var s = String(line == null ? '' : line).replace(/[​﻿]/g, '');
    s = s.replace(/^[\s　>＞#＃*＊・`\-–—\\¥￥＼_＿~～]+/, '').replace(/[\\¥￥＼]/g, '');
    s = s.replace(/^[=＝]+[\s　]*/, '');
    return s;
  }
  function parsePicks(raw) {
    var lines = String(raw || '').split(/\r?\n/), picks = [], rest = [], bad = [];
    for (var i = 0; i < lines.length; i++) {
      var s = stripDeco(lines[i]);
      var m = s.match(/^[\[［]\s*P\s*I\s*C\s*K\s*[:：]\s*([^\]］]{1,40}?)\s*[\]］]\s*[=＝]*\s*[:：|｜\-—]?\s*([\s\S]*)$/i);
      if (m) {
        var id = String(m[1]).replace(/[\s　*＊`]/g, '').replace(/[Ａ-Ｚａ-ｚ０-９]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 65248); }).toLowerCase();
        var reason = String(m[2] || '').replace(/[*＊`]+$/g, '').replace(/^[\s　]+|[\s　]+$/g, '');
        if (!reason && i + 1 < lines.length && !/[\[［]/.test(lines[i + 1]) && String(lines[i + 1]).trim()) { reason = String(lines[i + 1]).trim(); i++; }
        if (/^[.．・…]*$/.test(id) || id === '振り返りid') continue;   // 指示の見本行
        picks.push({ id: id, reason: reason.replace(/[\\¥￥]([\\`*_{}\[\]()#+\-.!>~|=])/g, '$1').slice(0, 300) });
        continue;
      }
      if (/^【みんなのふりかえり候補】/.test(s)) continue;
      rest.push(lines[i]);
    }
    return { picks: picks, rest: rest.join('\n'), bad: bad };
  }
  async function importRaw(raw, cid, sayFn) {
    var pr = parsePicks(raw);
    if (!pr.picks.length) return { found: false, rest: raw, n: 0, only: false };
    var only = !String(pr.rest || '').replace(/[\s　=＝`~]/g, '');
    var j = await jpost('/api/teacher/minna/picks', { classId: cid, picks: pr.picks });
    var msg;
    if (!j || !j.ok) msg = '⚠ みんなのふりかえり候補を取り込めませんでした';
    else {
      msg = '⭐ みんなのふりかえり候補 ' + j.saved + '件を取り込みました（📋振り返り一覧に⭐が付きます）';
      if (j.overLimit && j.overLimit.length) msg += '／1回' + j.pickMax + '件をこえた ' + j.overLimit.length + '件は入れていません';
    }
    showPickHolds(j, pr.picks, msg);
    if (sayFn) sayFn(msg);
    try { if (S.data) load(); } catch (e) {}
    return { found: true, rest: pr.rest, n: (j && j.saved) || 0, only: only, msg: msg };
  }
  function showPickHolds(j, picks, okMsg) {
    var anchor = $('taiStatus'); if (!anchor || !anchor.parentNode) return;
    var el = $('tbPickHold');
    if (!el) { el = document.createElement('div'); el.id = 'tbPickHold'; el.className = 'mt-2'; anchor.parentNode.insertBefore(el, anchor.nextSibling); }
    var un = (j && j.unknown) || [];
    var okH = (j && j.ok && okMsg) ? '<div style="border:2px solid #fcd34d;background:#fffbeb;border-radius:10px;padding:5px 8px;font-size:12px;font-weight:800;color:#92400e;margin-bottom:4px">' + esc(okMsg) + '</div>' : '';
    if (!un.length && j && j.ok) { el.innerHTML = okH; return; }
    el.innerHTML = okH + '<div style="border:2px solid #fca5a5;background:#fef2f2;border-radius:10px;padding:6px 8px;font-size:12px;color:#b91c1c">' +
      '<b>⚠ 取り込めなかった掲載候補（' + (un.length || picks.length) + '件）</b>：' + esc((un.length ? un : picks.map(function (p) { return p.id; })).join('、')) +
      '<div style="font-size:11px">振り返りIDがちがうか、子どもが「のせてもいいよ」を取り消した可能性があります。' +
      ' <button type="button" id="tbPickRecopy" style="background:#dc2626;color:#fff;border:none;border-radius:8px;padding:2px 10px;font-size:11px;font-weight:800;cursor:pointer">候補の材料をもう一度コピー</button></div></div>';
    var b = $('tbPickRecopy');
    if (b) b.onclick = function () {
      var cid = ($('analyticsClassFilter') || {}).value || S.cid;
      copyOnly(cid, function (t) { try { navigator.clipboard.writeText(t); } catch (e) {} }, function (m) { var s = $('taiStatus'); if (s) s.textContent = m; });
    };
  }
  window.MINNA_PICK = { appendTo: appendTo, copyOnly: copyOnly, importRaw: importRaw, parsePicks: parsePicks, pickLines: pickLines, max: 5 };

  // ═════════ WEEKREF2_V1 カルテ（個人分析）に「週の振り返り」の新しい欄・⑥授業メモの書き方のヒント ═════════
  var _faSeen = '';
  function karteBox() {
    var ov = $('studentFullAnalysisOverlay'), ct = $('fullAnalysisContent');
    if (!ov || ov.classList.contains('hidden') || !ct) { _faSeen = ''; return; }
    var sid = String(window._faId || '');
    if (!sid || !window._faData) return;
    var box = $('wr2KarteBox');
    if (box && _faSeen === sid && ct.contains(box)) return;
    _faSeen = sid;
    if (!box) { box = document.createElement('div'); box.id = 'wr2KarteBox'; }
    box.className = 'bg-sky-50 rounded-xl border border-sky-200 p-4 mb-4';
    box.innerHTML = '<div class="font-bold text-sm text-sky-800 mb-1">🔄 週の振り返り（先週決めたこと・🏫学校での学び・考える問い）</div><div class="text-xs text-slate-400">読み込み中…</div>';
    ct.insertBefore(box, ct.firstChild);
    jget('/api/teacher/week-ref2?studentId=' + encodeURIComponent(sid) + '&weeks=4').then(function (d) {
      if (_faSeen !== sid) return;
      var items = (d && d.ok && d.items) || [];
      var h = '<div class="font-bold text-sm text-sky-800 mb-1">🔄 週の振り返り（先週決めたこと・🏫学校での学び・考える問い）</div>';
      if (!items.length) { box.innerHTML = h + '<div class="text-xs text-slate-500">まだありません（金曜の振り返りで書いた分が ここに出ます）</div>'; return; }
      items.forEach(function (r) {
        var ls = [];
        if (r.promise && (r.promise.text || r.promise.resultJa)) ls.push('🤝 ' + (r.promise.text ? '「' + esc(r.promise.text) + '」' : '') + (r.promise.resultJa ? ' → <b>' + esc(r.promise.resultJa) + '</b>' + (r.promise.reasonJa ? '（' + esc(r.promise.reasonJa) + '）' : '') : '') + (r.promise.note ? '　一言：' + esc(r.promise.note) : ''));
        if (r.school && r.school.subj) ls.push('🏫 <b>' + esc(r.school.subj) + (r.school.theme ? '「' + esc(r.school.theme) + '」' : '') + '</b>' + (r.school.learned ? '　' + esc(r.school.learned) : '') + (r.school.more ? '　→ もっと：' + esc(r.school.more) : ''));
        if (r.q && (r.q.choiceJa || r.q.text)) ls.push('💭 ' + esc(r.q.label) + ' → ' + esc([r.q.choiceJa, r.q.text].filter(Boolean).join('・')));
        if (r.facts) ls.push('📊 ' + esc(factsJa(r.facts)));
        if (!ls.length) return;
        h += '<div class="mt-1 bg-white rounded-lg border border-sky-100 px-2 py-1"><div class="text-[11px] font-bold text-sky-700">' + esc(wkJa(r.weekKey)) + '</div>' + ls.map(function (x) { return '<div class="text-xs text-slate-700" style="line-height:1.6">' + x + '</div>'; }).join('') + '</div>';
      });
      box.innerHTML = h;
    });
  }
  function noteHint() {
    var ta = $('cnoteBody'); if (!ta || $('wr2NoteHint')) return;
    var d = document.createElement('div'); d.id = 'wr2NoteHint';
    d.className = 'text-[11px] text-sky-700 bg-sky-50 rounded px-2 py-1';
    d.textContent = '💡 子どもの「🏫学校での学び」に単元を出したいときは、「算数：比の利用」「理科：てこのはたらき」のように 教科：単元 を1行で書いてください。この形の行だけが子どもの画面に候補として出ます（ほかのメモは出ません。名前の入った行も出ません）。';
    ta.parentNode.insertBefore(d, ta.nextSibling);
  }
  setInterval(function () { try { karteBox(); } catch (e) {} try { noteHint(); } catch (e) {} }, 1500);

  // ---------- 起動 ----------
  var tries = 0;
  var timer = setInterval(function () {
    tries++;
    var a = ensureTab(); ensureTaiOption();
    if ((a && $('taiOptMinna')) || tries > 120) clearInterval(timer);
  }, 1000);
  try { window.teibakoOpen = function () { if (ensureTab()) show(true); }; } catch (e) {}
})();
