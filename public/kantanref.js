/* 👆 KANTAN_REF_V1 かんたんふりかえり（子どもの画面）— 2026-10-26
 *
 *  1) かんたんふりかえり … 「🔄 今週の振り返り」の欄の上に、タップだけで答えられる欄を足す（1〜2分で終わる量）。
 *     型は「評価 → なんで？ → 次どうする？」（振り返りの型を示すと書けるようになる：木村・渡邉・宗實 2024）
 *       ① 今週の自分の学びは？ ◎よくできた／○まあまあ／△もう少し（本人の見立て。成績・評価には使わない）
 *       ② なんでそう思う？ … アプリの記録から作った理由の候補（できたこと・むずかしかったこと）から1つ ＋ 自分のことば（任意）
 *       ③ 次どうする？ … このまま続ける／やり方を変える（時間・場所・量）／ほかの単元に進む ＋ 一言（任意）
 *       ④ 今週の気もち（☀️☁️🌧️・えらばなくてもOK）
 *     （選択肢を与えると動機づけが上がる：Patall 2008）
 *     えらんだものは文章に組み立てて いつもの自由欄に入れ、いつもの「🔄 振り返りを提出」で出す。
 *     コイン（1週1回20コイン・サーバーの台帳）と先生の返却は これまでどおり（二重にならない）。
 *     保存は structured_reflections の既存の項目に入る：good_point「◎ よくできた ／ なんで：…」・next_action「次：…」・free_text（文）。
 *  2) 金曜の朝 … 授業中にみんなで書けるよう、金曜は 8:00 から振り返りの欄を出す（いつもは 8:30 から）。
 *  3) 月曜の計画 … 計画の欄の上に「📒 わたしのカルテ」の要点（🅰🅱🅲・はじめの一歩・前の週の ◎○△ と 次どうする？）を
 *     折りたたみで出し、「この道を計画に入れる」で計画の欄に書き入れる（提出は いつもの「📨 計画を提出」）。
 *  4) 阪神マンの1タップ案内 … きっかけが ほしそうな子には、いつもの声かけ（weekref.js・金土日・1日1回・閉じられる）の
 *     かわりに「1タップで ふりかえり できるで」。見た目は同じ。ラベルや特別あつかいの印は出さない。
 *  5) アプリを開いた日 … 1日1回だけ サーバーに知らせる（コインなし）。
 *
 *  ・評価・比較・順位・点・パーセントは出さない。命令形にしない。
 *  ・index.html は手で編集しない。画面にあるもの（hwReflectionArea・hwPlanArea など）に足すだけ。
 */
(function () {
  'use strict';
  if (window.__KANTAN_REF_V1__) return; window.__KANTAN_REF_V1__ = 1;

  var NUDGE_KEY = 'weekRefNudgeV1';      // weekref.js と同じ「今日はもう声をかけた」
  var OPEN_KEY = 'kantanOpenV1';
  var FRI_OPEN_MIN = 8 * 60;             // 金曜は この時刻（分）から 振り返りの欄を出す
  var _d = null, _dAt = 0, _busy = null;
  var _sel = { self: '', reason: '', next: '', how: '', mood: '' };
  var _sending = false, _pendingStruct = null;

  function esc(s) {
    return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;');
  }
  function cut(s, n) { var a = Array.from(String(s == null ? '' : s)); return a.length > n ? a.slice(0, n).join('') : a.join(''); }
  function curP() { try { if (typeof player !== 'undefined' && player) return player; } catch (e) {} return window.player || null; }
  function jget(url) { return fetch(url, { credentials: 'include' }).then(function (r) { return r.json(); }).catch(function () { return null; }); }
  function jpost(url, body) {
    return fetch(url, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
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
  function weekOffset() { var off = 0; try { if (typeof _hwWeekOffset !== 'undefined') off = Number(_hwWeekOffset) || 0; } catch (e) {} return off; }

  // ───────── 単元の名前（CURRICULUM は index.html の正本） ─────────
  function curriculum() { try { if (typeof CURRICULUM !== 'undefined') return CURRICULUM; } catch (e) {} return window.CURRICULUM || null; }
  var _uidx = null;
  function unitIdx() {
    if (_uidx) return _uidx;
    var C = curriculum(), idx = {};
    if (!C) return idx;
    Object.keys(C).forEach(function (sk) {
      var sub = C[sk]; if (!sub || !sub.grades) return;
      Object.keys(sub.grades).forEach(function (g) {
        (sub.grades[g].units || []).forEach(function (u, i) { idx[u.id] = { id: u.id, name: u.name || '', subj: sk, grade: Number(g), i: i }; });
      });
    });
    _uidx = idx;
    return idx;
  }
  function unitName(id) { var x = unitIdx()[id]; return x ? String(x.name || '') : ''; }
  function nextUnitOf(id) {   // 教科の中で つぎに ならんでいる単元（同じ学年 → つぎの学年）
    var x = unitIdx()[id]; var C = curriculum();
    if (!x || !C || !C[x.subj]) return '';
    var gd = C[x.subj].grades || {};
    var us = (gd[x.grade] && gd[x.grade].units) || [];
    if (us[x.i + 1]) return us[x.i + 1].id;
    var ng = gd[x.grade + 1];
    return (ng && ng.units && ng.units[0]) ? ng.units[0].id : '';
  }

  // ───────── サーバーの材料 ─────────
  function load(force) {
    if (!force && _d && Date.now() - _dAt < 60000) return Promise.resolve(_d);
    if (_busy) return _busy;
    _busy = jget('/api/student/kantan-ref?weekKey=' + encodeURIComponent(weekKeyNow())).then(function (d) {
      _busy = null;
      if (d && d.ok) {
        _d = d; _dAt = Date.now();
        if (d.taps && !_sel.self) _sel = { self: d.taps.self || '', reason: d.taps.reason || '', next: d.taps.next || '', how: d.taps.how || '', mood: d.taps.mood || '' };
      }
      return _d;
    });
    return _busy;
  }

  // ───────── 候補（記録から言えることだけ） ─────────
  var MARKS = [
    { k: 'good', sym: '◎', label: 'よくできた' },
    { k: 'ok', sym: '○', label: 'まあまあ' },
    { k: 'more', sym: '△', label: 'もう少し' }
  ];
  var MOODS = [
    { k: 'sun', icon: '☀️', label: 'はれ' },
    { k: 'cloud', icon: '☁️', label: 'くもり' },
    { k: 'rain', icon: '🌧️', label: 'あめ' }
  ];
  var HOWS = [{ k: 'time', label: '⏰ 時間' }, { k: 'place', label: '🏠 場所' }, { k: 'amount', label: '📏 量' }];
  function markOf(k) { for (var i = 0; i < MARKS.length; i++) if (MARKS[i].k === k) return MARKS[i]; return null; }
  // ② なんで？ … できたこと（＋）と むずかしかったこと（－）を記録から。◎なら＋を先に、△なら－を先に。
  function reasonList(d) {
    var w = (d && d.week) || {}, plus = [], minus = [];
    var bn = w.best ? unitName(w.best.unit) : '';
    var hw = Number(w.hwDays) || 0, od = Math.max(1, Number(w.openDays) || 0), q = Number(w.questions) || 0;
    if (bn) plus.push({ k: 'best:' + w.best.unit, label: '✅「' + bn + '」で ' + w.best.c + '問 せいかい', s: '「' + bn + '」で ' + w.best.c + '問 せいかいできた' });
    if (hw >= 3) plus.push({ k: 'hw', label: '📒 家庭学習を ' + hw + '日 つづけられた', s: '家庭学習を ' + hw + '日 つづけられた' });
    if (q > 0 && plus.length < 2) plus.push({ k: 'q', label: '📝 アプリで ' + q + '問 といた', s: 'アプリで ' + q + '問 といた' });
    if (od >= 3 && plus.length < 2) plus.push({ k: 'open', label: '📱 アプリを ' + od + '日 ひらけた', s: 'アプリを ' + od + '日 ひらけた' });
    ((d && d.hard) || []).forEach(function (h) {
      var nm = unitName(h.unit);
      if (nm && minus.length < 1) minus.push({ k: 'hard:' + h.unit, label: '🤔「' + nm + '」で まちがいが 多かった', s: '「' + nm + '」で まちがいが 多かった' });
    });
    if (hw <= 2) minus.push({ k: 'hwlow', label: '📒 家庭学習は ' + hw + '日 だった', s: hw ? '家庭学習が ' + hw + '日 だった' : '家庭学習を 出せなかった' });
    if (!plus.length) plus.push({ k: 'open', label: '📱 アプリを ' + od + '日 ひらけた', s: 'アプリを ' + od + '日 ひらけた' });
    minus.push({ k: 'time', label: '⏰ 時間が とりにくかった', s: '時間が とりにくかった' });
    var out = (_sel.self === 'more') ? minus.concat(plus) : (_sel.self === 'ok') ? [plus[0]].concat(minus.slice(0, 1), plus.slice(1), minus.slice(1)) : plus.concat(minus);
    return out.slice(0, 4);
  }
  function nextList(d) {
    var r = (d && d.reco) || null, w = (d && d.week) || {};
    var bId = (r && r.b && unitName(r.b.id)) ? r.b.id : '';
    if (!bId && w.recentUnit) { var nx = nextUnitOf(w.recentUnit); if (nx && unitName(nx)) bId = nx; }
    return [
      { k: 'keep', label: '➡️ このまま つづける', s: '次は このまま つづけてみる', text: 'このまま つづける' },
      { k: 'change', label: '🔧 やり方を 変える', s: '次は やり方を 変えてみる', text: 'やり方を 変える' },
      bId ? { k: 'go:' + bId, label: '🚀「' + unitName(bId) + '」に すすむ', s: '次は「' + unitName(bId) + '」に すすんでみる', text: 'すすんでみる', unit: bId }
          : { k: 'go', label: '🚀 ほかの 単元に すすむ', s: '次は ほかの 単元に すすんでみる', text: 'ほかの 単元に すすむ' }
    ];
  }
  function find(list, k) { for (var i = 0; i < list.length; i++) if (list[i] && list[i].k === k) return list[i]; return null; }
  function howLabel(k) { for (var i = 0; i < HOWS.length; i++) if (HOWS[i].k === k) return HOWS[i].label.replace(/^\S+\s/, ''); return ''; }
  function reasonFree() { return String((document.getElementById('kantanWhy') || {}).value || '').replace(/[\r\n\t]/g, ' ').trim().slice(0, 60); }
  function addFree() { return String((document.getElementById('kantanAdd') || {}).value || '').replace(/[\r\n\t]/g, ' ').trim().slice(0, 60); }
  function nextPhrase(d) {
    var c = find(nextList(d), _sel.next); if (!c) return '';
    if (c.k === 'change' && _sel.how) return '次は ' + howLabel(_sel.how) + 'を 変えてみる';
    return c.s;
  }
  function reasonPhrase(d) {
    var a = find(reasonList(d), _sel.reason), f = reasonFree();
    if (a && f) return a.s + '。' + f;
    return a ? a.s : f;
  }
  function compose(d) {
    var parts = [];
    var m = markOf(_sel.self);
    if (m) parts.push('今週の 自分の 学びは ' + m.sym + m.label + '。');
    var r = reasonPhrase(d); if (r) parts.push('そう思うのは、' + r + (/[。！？]$/.test(r) ? '' : 'から。'));
    var n = nextPhrase(d); if (n) parts.push(n + '。');
    var add = addFree(); if (add) parts.push(add + (/[。！？]$/.test(add) ? '' : '。'));
    var mo = null; for (var i = 0; i < MOODS.length; i++) if (MOODS[i].k === _sel.mood) mo = MOODS[i];
    if (mo) parts.push('気もちは ' + mo.icon + mo.label + '。');
    return parts.join('');
  }
  function ready() { return !!(_sel.self && (_sel.reason || reasonFree()) && _sel.next && (_sel.next !== 'change' || _sel.how)); }

  // ───────── 欄を描く ─────────
  var CSS = '#kantanRef,#kantanKarte{background:#fff;border:2px solid #fdba74;border-radius:14px;padding:10px 12px;color:#7c2d12}'
    + '#kantanKarte{border-color:#fcd34d;background:#fffbeb}'
    + '.kantanW .kq{font-weight:900;font-size:14px;margin:8px 0 4px;color:#9a3412}'
    + '.kantanW .kq small{font-weight:600;font-size:11px;color:#b45309;margin-left:4px}'
    + '.kantanW .kc{display:flex;flex-wrap:wrap;gap:6px}'
    + '.kantanW .kb{min-height:42px;border-radius:12px;padding:6px 12px;font-size:14px;font-weight:800;cursor:pointer;background:#fff7ed;border:2px solid #fed7aa;color:#9a3412;-webkit-tap-highlight-color:transparent}'
    + '.kantanW .kb.on{background:#f97316;border-color:#f97316;color:#fff}'
    + '.kantanW .kbig{font-size:16px;min-width:120px}'
    + '.kantanW .kbig b{font-size:22px;margin-right:4px}'
    + '.kantanW .ksm{min-height:36px;font-size:13px;padding:4px 10px}'
    + '.kantanW .kp{margin-top:10px;background:#fffbeb;border:1.5px dashed #fbbf24;border-radius:10px;padding:8px 10px;font-size:13.5px;line-height:1.7;color:#78350f;min-height:24px}'
    + '.kantanW input[type=text]{flex:1 1 220px;min-width:0;border:1.5px solid #fdba74;border-radius:10px;padding:8px 10px;font-size:14px}'
    + '.kantanW .kx{display:flex;gap:6px;align-items:center;margin-top:6px;flex-wrap:wrap}'
    + '.kantanW .ks{width:100%;margin-top:8px;min-height:46px;border:none;border-radius:12px;font-size:15px;font-weight:900;color:#fff;background:#f97316;cursor:pointer}'
    + '.kantanW .ks[disabled]{background:#fdba74;cursor:default}'
    + '.kantanW .kmsg{font-size:12.5px;text-align:center;margin-top:6px;min-height:16px;color:#c2410c;font-weight:700}'
    + '#kantanRef.kglow{box-shadow:0 0 0 4px rgba(249,115,22,.35)}'
    + '#kantanKarte summary{cursor:pointer;font-weight:900;font-size:14.5px;color:#92400e;list-style:none}'
    + '#kantanKarte .kpath{display:flex;gap:8px;align-items:flex-start;background:#fff;border:1.5px solid #fde68a;border-radius:10px;padding:6px 8px;margin-top:6px;font-size:13px;line-height:1.5}'
    + '#kantanKarte .kpath .kk{font-size:18px;line-height:1.1}'
    + '#kantanKarte .kin{margin-left:auto;flex-shrink:0;min-height:36px;border-radius:10px;border:1.5px solid #10b981;background:#ecfdf5;color:#047857;font-weight:800;font-size:12.5px;padding:4px 10px;cursor:pointer}';
  function ensureCss() {
    if (document.getElementById('kantanRefCss')) return;
    var st = document.createElement('style'); st.id = 'kantanRefCss'; st.textContent = CSS;
    document.head.appendChild(st);
  }
  function chips(list, key, cls) {
    var h = '<div class="kc">';
    list.forEach(function (x) {
      if (!x) return;
      h += '<button type="button" class="kb' + (cls ? ' ' + cls : '') + (_sel[key] === x.k ? ' on' : '') + '" data-key="' + key + '" data-v="' + esc(x.k) + '">' + esc(x.label) + '</button>';
    });
    return h + '</div>';
  }
  function draw() {
    var box = document.getElementById('kantanRef');
    if (!box) return;
    var d = _d;
    if (!d) { box.innerHTML = '<div style="font-size:12.5px;color:#b45309">👆 かんたんふりかえりを よみこみ中…</div>'; return; }
    var keepWhy = reasonFree(), keepAdd = addFree();
    var st = d.status || {};
    var h = '<div style="font-weight:900;font-size:15px;color:#c2410c">👆 かんたんふりかえり <span style="font-weight:600;font-size:11.5px;color:#b45309">（えらぶだけで できるよ。書きたいことは 下の らんにも 書けるよ）</span></div>';
    h += '<div class="kq">① 今週の 自分の 学びは？ <small>（じぶんの 見立てで OK）</small></div>';
    h += '<div class="kc">' + MARKS.map(function (m) { return '<button type="button" class="kb kbig' + (_sel.self === m.k ? ' on' : '') + '" data-key="self" data-v="' + m.k + '"><b>' + m.sym + '</b>' + m.label + '</button>'; }).join('') + '</div>';
    if (d.prev && d.prev.markLabel) h += '<div style="font-size:11.5px;color:#92400e;margin-top:3px">🕰 先週の あなたは「' + esc(d.prev.markLabel) + '」' + (d.prev.nextText ? '・' + esc(d.prev.nextText) : '') + '</div>';
    h += '<div class="kq">② なんで そう思う？ <small>（アプリの きろくから。1つ えらぶか、じぶんの ことばで）</small></div>' + chips(reasonList(d), 'reason');
    h += '<div class="kx"><input id="kantanWhy" type="text" maxlength="60" placeholder="じぶんの ことばで（なくても OK）" value="' + esc(keepWhy) + '"></div>';
    h += '<div class="kq">③ 次 どうする？</div>' + chips(nextList(d), 'next');
    if (_sel.next === 'change') h += '<div class="kx"><span style="font-size:12.5px;font-weight:800">なにを 変える？</span>' + chips(HOWS, 'how', 'ksm').replace('<div class="kc">', '<div class="kc" style="display:inline-flex">') + '</div>';
    h += '<div class="kx"><span style="font-size:12.5px;font-weight:800">✏️ 一言</span><input id="kantanAdd" type="text" maxlength="60" placeholder="なくても だいじょうぶ（例：夜ごはんの前に やる）" value="' + esc(keepAdd) + '"></div>';
    h += '<div class="kq">④ 今週の 気もち <small>（えらばなくても OK）</small></div><div class="kc">' + MOODS.map(function (m) { return '<button type="button" class="kb ksm' + (_sel.mood === m.k ? ' on' : '') + '" data-key="mood" data-v="' + m.k + '">' + m.icon + ' ' + m.label + '</button>'; }).join('') + '</div>';
    var txt = compose(d);
    h += '<div class="kp" id="kantanPrev">' + (txt ? esc(txt) : '<span style="color:#b45309">えらぶと、ここに ふりかえりの 文が できるよ</span>') + '</div>';
    h += '<button type="button" class="ks" id="kantanSend"' + (ready() ? '' : ' disabled') + '>' + (ready() ? '👆 これで 出す' + (st.rewarded ? '' : '（🪙' + (d.reward || 20) + 'コイン）') : '①②③を えらぶと 出せるよ') + '</button>';
    h += '<div class="kmsg" id="kantanMsg">' + (st.wrote ? '✅ 今週の ふりかえりは 出してあるよ。出しなおしても だいじょうぶ' : '') + '</div>';
    box.innerHTML = h;
    box.className = 'kantanW';
    var bs = box.querySelectorAll('.kb');
    for (var i = 0; i < bs.length; i++) bs[i].onclick = function () {
      var k = this.getAttribute('data-key'), v = this.getAttribute('data-v');
      _sel[k] = (k === 'mood' && _sel[k] === v) ? '' : v;   // 気もちは もう一度おすと けせる
      if (k === 'next' && v !== 'change') _sel.how = '';
      draw();
    };
    var upd = function () { var pv = document.getElementById('kantanPrev'); var t2 = compose(_d); if (pv) pv.innerHTML = t2 ? esc(t2) : ''; var sb2 = document.getElementById('kantanSend'); if (sb2) { sb2.disabled = !ready(); sb2.textContent = ready() ? '👆 これで 出す' + ((_d.status || {}).rewarded ? '' : '（🪙' + (_d.reward || 20) + 'コイン）') : '①②③を えらぶと 出せるよ'; } };
    var wy = document.getElementById('kantanWhy'); if (wy) wy.oninput = upd;
    var ad = document.getElementById('kantanAdd'); if (ad) ad.oninput = upd;
    var sb = document.getElementById('kantanSend'); if (sb) sb.onclick = send;
  }

  // 金曜は 8:00 から（いつもの画面は 8:30 から。8:30 前は前の日あつかいの きまりは そのまま）
  function jstNow() { var n = new Date(); return new Date(n.getTime() + n.getTimezoneOffset() * 60000 + 9 * 3600000); }
  function friEarly() { var j = jstNow(); var m = j.getHours() * 60 + j.getMinutes(); return j.getDay() === 5 && m >= FRI_OPEN_MIN && m < 8 * 60 + 30; }
  function openFriEarly(area) {
    if (!friEarly() || weekOffset() !== 0 || !area.classList.contains('hidden')) return;
    if (!document.getElementById('hwPlanArea') || document.getElementById('hwPlanArea').offsetParent === null) return;   // 週の計画の画面を見ているときだけ
    area.classList.remove('hidden');
    var ta = document.getElementById('hwReflectionInput');
    try {
      if (ta && !ta.value && typeof hwGetPlanForWeek === 'function') {
        var pl = hwGetPlanForWeek(weekKeyNow()) || {}; var f = pl.fri;
        if (f && typeof f === 'object' && f.reflection) ta.value = f.reflection;
      }
    } catch (e) {}
  }
  function areaVisible() {
    var area = document.getElementById('hwReflectionArea');
    if (!area || area.classList.contains('hidden')) return false;
    return weekOffset() === 0;
  }
  function ensurePanel() {
    var area = document.getElementById('hwReflectionArea');
    var ta = document.getElementById('hwReflectionInput');
    if (!area || !ta) return;
    openFriEarly(area);
    var box = document.getElementById('kantanRef');
    if (!areaVisible()) { if (box) box.style.display = 'none'; return; }
    var p = curP(); if (!p || !p.userId) return;
    ensureCss();
    if (!box) {
      box = document.createElement('div');
      box.id = 'kantanRef';
      box.className = 'kantanW';
      var hints = document.getElementById('weekRefHints');
      var before = hints && hints.parentNode === ta.parentNode ? hints : ta;
      ta.parentNode.insertBefore(box, before);
      draw();
      load(false).then(function () { draw(); });
    }
    box.style.display = '';
  }

  // ───────── 出す（いつもの提出の道を使う） ─────────
  function mergeText(prev, txt) {
    prev = String(prev || '');
    if (!prev.trim()) return txt;
    var lines = prev.split('\n');
    if (/^今週の 自分の 学びは /.test(lines[0])) { lines[0] = txt; return lines.join('\n'); }   // 前に かんたんで 出した文は 入れかえる
    if (prev.indexOf(txt) >= 0) return prev;
    return txt + '\n' + prev;
  }
  // いつもの提出（/api/student/weekly-reflection）に、項目欄（◎○△・なんで・次）を いっしょに のせる。中身の文は そのまま。
  var _f = window.fetch;
  if (typeof _f === 'function' && !_f.__kantan) {
    var wrapped = function (input, init) {
      try {
        var url = (typeof input === 'string') ? input : (input && input.url) || '';
        var method = String((init && init.method) || 'GET').toUpperCase();
        if (_pendingStruct && method === 'POST' && url.indexOf('/api/student/weekly-reflection') >= 0 && init && typeof init.body === 'string') {
          var b = JSON.parse(init.body);
          if (b && b.weekKey === _pendingStruct.weekKey) {
            b.goodPoint = _pendingStruct.goodPoint; b.nextAction = _pendingStruct.nextAction; b.improvePoint = _pendingStruct.improvePoint;
            init = Object.assign({}, init, { body: JSON.stringify(b) });
            _pendingStruct = null;
            return _f.call(this, input, init);
          }
        }
      } catch (e) {}
      return _f.apply(this, arguments);
    };
    wrapped.__kantan = true;
    if (_f.__weekRef) wrapped.__weekRef = true;
    window.fetch = wrapped;
  }
  function send() {
    if (_sending || !_d || !ready()) return;
    var ta = document.getElementById('hwReflectionInput');
    var msg = document.getElementById('kantanMsg');
    if (!ta || typeof window.hwSubmitReflection !== 'function') { if (msg) msg.textContent = 'いまは 出せなかったよ。もう一度 ひらいてみてね'; return; }
    var txt = compose(_d);
    var wasRewarded = !!(_d.status && _d.status.rewarded);
    var m = markOf(_sel.self);
    var why = reasonPhrase(_d);
    var nx = find(nextList(_d), _sel.next);
    var nextTxt = (_sel.next === 'change' && _sel.how) ? 'やり方を 変える（' + howLabel(_sel.how) + '）' : (nx ? (nx.unit ? '「' + unitName(nx.unit) + '」に すすむ' : nx.text) : '');
    var add = addFree();
    _pendingStruct = {
      weekKey: weekKeyNow(),
      goodPoint: cut((m ? m.sym + ' ' + m.label : '') + ' ／ なんで：' + why, 300),
      improvePoint: '',
      nextAction: cut('次：' + nextTxt + (add ? '　' + add : ''), 50)
    };
    _sending = true;
    var sb = document.getElementById('kantanSend'); if (sb) { sb.disabled = true; sb.textContent = 'おくっています…'; }
    ta.value = mergeText(ta.value, txt);
    try { window.hwSubmitReflection(); } catch (e) {}
    setTimeout(function () { _pendingStruct = null; }, 5000);
    jpost('/api/student/kantan-ref', { weekKey: weekKeyNow(), self: _sel.self, reason: _sel.reason, next: _sel.next, how: _sel.how, mood: _sel.mood, addedChars: Array.from(add + reasonFree()).length });
    // 🎯 来週やってみたいこと（まだ自分で のこしていない週だけ。自分で書いたものは上書きしない）
    if (nx) {
      jget('/api/student/next-try?weekKey=' + encodeURIComponent(weekKeyNow())).then(function (g) {
        if (!g || !g.ok || g.nextTry) return;
        jpost('/api/student/next-try', { weekKey: weekKeyNow(), unit: nx.unit || '', unitName: nx.unit ? unitName(nx.unit) : '', text: cut(nextTxt.replace(/^「[^」]*」に /, '') + (add ? ' ' + add : ''), 40) });
      });
    }
    setTimeout(function () {
      jget('/api/student/week-ref-status?weekKey=' + encodeURIComponent(weekKeyNow())).then(function (s) {
        _sending = false;
        if (_d && _d.status && s && s.ok) { _d.status.wrote = !!s.wrote; _d.status.rewarded = !!s.rewarded; }
        draw();
        var m2 = document.getElementById('kantanMsg');
        if (!m2) return;
        if (s && s.ok && s.rewarded && !wasRewarded) m2.textContent = '🪙 ' + (s.reward || 20) + 'コイン ゲット！ ふりかえり、ありがとう。先生も 読むで';
        else if (s && s.ok && s.wrote) m2.textContent = '✅ 出したよ。ありがとう。先生も 読むで';
        else m2.textContent = 'おくれなかったかも。もう一度 おしてみてね';
      });
    }, 1800);
  }

  // ───────── 月曜の計画：📒 わたしのカルテの要点（折りたたみ）＋「この道を計画に入れる」 ─────────
  var _k = null, _kAt = 0, _kBusy = false, _kOpen = null;
  function loadKarte() {
    if (_kBusy || (_k && Date.now() - _kAt < 120000)) return;
    _kBusy = true;
    Promise.all([jget('/api/student/my-karte'), jget('/api/student/karte-reco'), load(false)]).then(function (a) {
      _kBusy = false; _kAt = Date.now();
      _k = { mk: a[0] || {}, rc: a[1] || {}, kr: a[2] || null };
      drawKarte();
    });
  }
  function planTextareas() {
    var pi = document.getElementById('hwPlanInputs');
    if (!pi) return [];
    var out = [], ts = pi.querySelectorAll('textarea');
    for (var i = 0; i < ts.length; i++) if (!ts[i].disabled) out.push(ts[i]);
    return out;
  }
  function putInPlan(text, msgEl) {
    var ts = planTextareas();
    if (!ts.length) { if (msgEl) msgEl.textContent = 'いまは 計画の らんに 書けないみたい'; return; }
    var t = null;
    for (var i = 0; i < ts.length; i++) if (!String(ts[i].value || '').trim()) { t = ts[i]; break; }
    if (!t) { t = ts[0]; if (String(t.value).indexOf(text) < 0) t.value = String(t.value).trim() + '／' + text; }
    else t.value = text;
    try { t.dispatchEvent(new Event('input', { bubbles: true })); t.focus(); t.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (e) {}
    var lab = ['月', '火', '水', '木', '金'][Number(t.dataset.dayIdx)] || '';
    if (msgEl) msgEl.textContent = '✅ ' + lab + 'よう日の らんに 入れたよ。かえても いいよ。さいごに「📨 計画を提出」を おしてね';
  }
  function drawKarte() {
    var box = document.getElementById('kantanKarte');
    if (!box) return;
    var wasOpen = box.querySelector('details') ? box.querySelector('details').open : null;
    var isMon = jstNow().getDay() === 1;
    var open = (wasOpen != null) ? wasOpen : (_kOpen != null ? _kOpen : isMon);
    var h = '<details' + (open ? ' open' : '') + '><summary>📒 わたしのカルテを 見ながら 計画を たてる <span style="font-size:11px;font-weight:600;color:#a16207">（おすと ひらく・とじる）</span></summary>';
    if (!_k) h += '<div style="font-size:12.5px;color:#a16207;margin-top:6px">よみこみ中…</div>';
    else if (!(_k.mk && _k.mk.published) || !(_k.rc && _k.rc.reco && _k.rc.reco.a)) {
      h += '<div style="font-size:13px;color:#92400e;margin-top:6px">📭 カルテは まだ 届いていないよ。届いたら ここに 出るよ。</div>';
      var pv0 = _k.kr && _k.kr.prev;
      if (pv0 && pv0.markLabel) h += '<div style="font-size:12.5px;margin-top:4px">🕰 先週の 自分：「' + esc(pv0.markLabel) + '」' + (pv0.nextText ? '　' + esc(pv0.nextText) : '') + '</div>';
    } else {
      var r = _k.rc.reco, small = !!_k.rc.small;
      var paths = [];
      paths.push({ k: '🅰', t: 'もう一度 かためる：「' + r.a.name + '」', sub: r.a.entry || '', plan: '🅰「' + r.a.name + '」を もう一度' });
      if (r.b) paths.push({ k: '🅱', t: 'つぎに すすむ：「' + r.b.name + '」', sub: r.b.entry || '', plan: '🅱「' + r.b.name + '」に すすむ' });
      var c = r.c && r.c.say ? r.c.say : (_k.rc.nextTry ? ((_k.rc.nextTry.unitName ? '「' + _k.rc.nextTry.unitName + '」' : '') + (_k.rc.nextTry.text || '')) : '');
      paths.push({ k: '🅲', t: 'じぶんで 決める' + (c ? '：' + c : '：やりたい ところから でも OK'), sub: '', plan: c ? '🅲' + cut(c, 30) : '' });
      paths.forEach(function (p, i) {
        h += '<div class="kpath"><span class="kk">' + p.k + '</span><div style="flex:1"><b>' + esc(p.t) + '</b>' + (p.sub ? '<div style="font-size:11px;color:#7c2d12">' + esc(p.sub) + '</div>' : '') + '</div>'
          + (p.plan ? '<button type="button" class="kin" data-i="' + i + '">この道を 計画に 入れる</button>' : '') + '</div>';
      });
      h += '<div style="font-size:12.5px;margin-top:6px">👣 <b>はじめの一歩</b>：' + (small ? 'アプリを ひらいて「' + esc(r.a.name) + '」を 1問だけ（5分で おわる 大きさ）' : 'まずは いちばん かんたんな 1問だけ（5分で できる 大きさ）') + '</div>';
      var pv = _k.kr && _k.kr.prev;
      if (pv && pv.markLabel) h += '<div style="font-size:12.5px;margin-top:4px">🕰 先週の 自分：「' + esc(pv.markLabel) + '」' + (pv.nextText ? '　' + esc(pv.nextText) : '') + '</div>';
      h += '<div id="kantanKarteMsg" style="font-size:12px;color:#047857;font-weight:700;margin-top:4px;min-height:14px"></div>';
      box._paths = paths;
    }
    box.innerHTML = h + '</details>';
    var dt = box.querySelector('details'); if (dt) dt.addEventListener('toggle', function () { _kOpen = dt.open; });
    var bs = box.querySelectorAll('.kin');
    for (var i = 0; i < bs.length; i++) bs[i].onclick = function () {
      var p = (box._paths || [])[Number(this.getAttribute('data-i'))];
      if (p && p.plan) putInPlan(p.plan, document.getElementById('kantanKarteMsg'));
    };
  }
  function ensureKarte() {
    var pa = document.getElementById('hwPlanArea');
    var box = document.getElementById('kantanKarte');
    var show = pa && !pa.classList.contains('hidden') && weekOffset() === 0 && planTextareas().length > 0;
    if (!show) { if (box) box.style.display = 'none'; return; }
    var p = curP(); if (!p || !p.userId) return;
    ensureCss();
    if (!box) {
      box = document.createElement('div');
      box.id = 'kantanKarte';
      box.className = 'kantanW';
      pa.parentNode.insertBefore(box, pa);
      drawKarte();
    }
    box.style.display = '';
    loadKarte();
  }

  // ───────── 阪神マンの1タップ案内（weekref.js の声かけの かわり） ─────────
  function markSeen() { try { localStorage.setItem(NUDGE_KEY, dayKey830()); } catch (e) {} }
  function closeNudge() { var el = document.getElementById('weekRefNudge'); if (el && el.parentNode) el.parentNode.removeChild(el); }
  function openKantan() {
    closeNudge();
    try {
      if (typeof openHomeStudy === 'function') openHomeStudy();
      else if (typeof trySetMode === 'function') trySetMode('hsweek');
    } catch (e) {}
    var n = 0;
    var t = setInterval(function () {
      n++;
      ensurePanel();
      var box = document.getElementById('kantanRef');
      if (box && box.style.display !== 'none' && areaVisible()) {
        clearInterval(t);
        try { box.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) {}
        box.classList.add('kglow'); setTimeout(function () { box.classList.remove('kglow'); }, 2500);
      }
      if (n > 20) clearInterval(t);
    }, 300);
  }
  function showOneTap(st) {
    if (document.getElementById('weekRefNudge')) return;
    markSeen();
    var face = '🐯';
    try { if (typeof window.monSpriteHtml === 'function') face = window.monSpriteHtml(154, '🐯'); } catch (e) {}
    var el = document.createElement('div');
    el.id = 'weekRefNudge';   // いつもの声かけと同じ箱・同じ見た目
    el.setAttribute('style', 'position:fixed;right:12px;top:84px;z-index:9997;width:330px;max-width:calc(100vw - 24px);background:#fff7ed;border:2px solid #fdba74;border-radius:16px;box-shadow:0 8px 24px rgba(0,0,0,.16);padding:10px 12px;color:#7c2d12');
    el.innerHTML =
      '<button type="button" id="weekRefNudgeX" aria-label="とじる" style="position:absolute;right:6px;top:4px;background:none;border:none;font-size:18px;color:#c2410c;cursor:pointer">×</button>' +
      '<div style="display:flex;gap:8px;align-items:flex-start">' +
        '<div style="font-size:30px;line-height:1">' + face + '</div>' +
        '<div style="flex:1;padding-right:12px">' +
          '<div style="font-weight:900;font-size:14px">1タップで ふりかえり できるで</div>' +
          '<div style="font-size:12px;line-height:1.6;margin-top:2px;color:#9a3412">えらぶだけで、今週の ふりかえりが できるよ。書きたくなったら 書いても ええで。' +
          ((st && !st.rewarded) ? '（' + ((_d && _d.reward) || 20) + 'コインの おまけつき）' : '') + '</div>' +
        '</div>' +
      '</div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px">' +
        '<button type="button" id="weekRefNudgeNo" style="background:#fff;border:1px solid #fdba74;color:#9a3412;border-radius:10px;padding:6px 12px;font-size:12px;font-weight:700;cursor:pointer">またこんど</button>' +
        '<button type="button" id="weekRefNudgeGo" style="background:#f97316;border:none;color:#fff;border-radius:10px;padding:6px 14px;font-size:12px;font-weight:800;cursor:pointer">やってみる</button>' +
      '</div>';
    document.body.appendChild(el);
    var x = document.getElementById('weekRefNudgeX'); if (x) x.onclick = closeNudge;
    var no = document.getElementById('weekRefNudgeNo'); if (no) no.onclick = closeNudge;
    var go = document.getElementById('weekRefNudgeGo'); if (go) go.onclick = openKantan;
    setTimeout(closeNudge, 30000);
  }
  // weekref.js から呼ばれる。true を返したら weekref.js は自分の声かけを出さない（かわりに ここで どちらかを出す）。
  window.kantanRefNudge = function (st, fallback) {
    load(true).then(function (d) {
      if (d && d.ok && d.oneTap) showOneTap(st);
      else if (typeof fallback === 'function') { try { fallback(); } catch (e) {} }
    });
    return true;
  };
  window.kantanRefOpen = openKantan;

  // ───────── アプリを開いた日（1日1回） ─────────
  function pingOpen() {
    var dk = dayKey830();
    try { if (localStorage.getItem(OPEN_KEY) === dk) return; } catch (e) {}
    jpost('/api/student/app-open', {}).then(function (j) { if (j && j.ok && j.dayKey) { try { localStorage.setItem(OPEN_KEY, dk); } catch (e) {} } });
  }

  // ---------- 起動 ----------
  var pinged = false, tries = 0;
  var timer = setInterval(function () {
    tries++;
    var p = curP();
    if (!pinged && p && p.userId) { pinged = true; pingOpen(); }
    if (pinged || tries > 60) clearInterval(timer);
  }, 2000);
  setInterval(function () { try { ensurePanel(); } catch (e) {} try { ensureKarte(); } catch (e) {} }, 1500);
})();
