/* 🪞 MAEJIBUN_V1 前の自分とくらべる／来週やってみたいこと（子どもの画面）— 2026-10-22
 *
 *  1) 「🪞 前の自分とくらべる」… ステータス画面の「📒 わたしのカルテ」の近くに入口。
 *     押すと、自分の振り返りを新しい順にカードで出し、「3週間まえの あなた」と「いまの あなた」を並べて見られる。
 *     あわせて、記録から機械的に数えた『のびたこと』（同じ単元の 10問中○問 → ○問、家庭学習を出した日 など）を少しだけ。
 *     ほかの子との比較・順位・テストの点・パーセントは出さない。比べるのは前の自分だけ（自己決定理論の有能感）。
 *     サーバー（/api/student/my-growth）は引数なしで自分の分だけ返す。
 *  2) 「🎯 来週やってみたいこと」… 「🔄 今週の振り返り」の欄の下に、任意で 単元をえらぶ／一言 を足す。
 *     次の週のカルテの「🅲 じぶんで決める」に最初から入り、単元なら 🅰🅱 のおすすめにも優先して使われる（自律性）。
 *     書かなくてもよい。コインは付けない（外からのごほうびで「やらされ感」にしないため）。
 *
 *  ・index.html は手で編集しない。画面にあるもの（homeReviewSuggest・hwReflectionArea）に足すだけ。
 */
(function () {
  'use strict';
  if (window.__MAEJIBUN_V1__) return; window.__MAEJIBUN_V1__ = 1;

  function esc(s) {
    return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;');
  }
  function curP() { try { if (typeof player !== 'undefined' && player) return player; } catch (e) {} return window.player || null; }
  function jget(url) {
    return fetch(url, { credentials: 'include' }).then(function (r) { return r.json(); }).catch(function () { return null; });
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
  function wkMonday(wk) {
    var m = String(wk || '').match(/^(\d{4})-W(\d{2})$/);
    if (!m) return null;
    var j4 = new Date(Date.UTC(Number(m[1]), 0, 4));
    var dw = j4.getUTCDay() || 7;
    return new Date(j4.getTime() + ((1 - dw) + (Number(m[2]) - 1) * 7) * 86400000);
  }
  function weeksBetween(a, b) {   // b が a の何週あとか
    var ma = wkMonday(a), mb = wkMonday(b);
    if (!ma || !mb) return 0;
    return Math.round((mb.getTime() - ma.getTime()) / (7 * 86400000));
  }
  function wkLabel(wk) {
    var mo = wkMonday(wk); if (!mo) return String(wk || '');
    var fr = new Date(mo.getTime() + 4 * 86400000);
    return (mo.getUTCMonth() + 1) + '/' + mo.getUTCDate() + '〜' + (fr.getUTCMonth() + 1) + '/' + fr.getUTCDate() + 'の週';
  }
  function agoLabel(wk, cur) {
    var n = weeksBetween(wk, cur);
    if (n <= 0) return '今週';
    if (n === 1) return '先週';
    return n + '週間まえ';
  }

  // ───────── 単元の名前（CURRICULUM は index.html の正本） ─────────
  var SUBJ_ORDER = ['math', 'japanese', 'science', 'social', 'english'];
  function curriculum() { try { if (typeof CURRICULUM !== 'undefined') return CURRICULUM; } catch (e) {} return window.CURRICULUM || null; }
  var _uidx = null;
  function unitIdx() {
    if (_uidx) return _uidx;
    var C = curriculum(), idx = {};
    if (C) {
      Object.keys(C).forEach(function (sk) {
        var sub = C[sk]; if (!sub || !sub.grades) return;
        Object.keys(sub.grades).forEach(function (g) {
          var gd = sub.grades[g];
          (gd.units || []).forEach(function (u) { idx[u.id] = { id: u.id, name: u.name || u.id, subj: sk, subjName: sub.name || '', grade: Number(g), gl: gd.label || '' }; });
        });
      });
      _uidx = idx;
    }
    return idx;
  }
  function unitName(id) { var x = unitIdx()[id]; return x ? x.name : ''; }
  function myGrade() {
    var g = 0;
    try { g = Number(window.__userGrade || 0); } catch (e) {}
    if (!g) { try { var p = curP(); g = Number((p && p.grade) || 0); } catch (e) {} }
    return g;
  }

  // ══════ 1) 前の自分とくらべる ══════
  var _data = null, _busy = false, _leftWk = '';
  function ensureEntry() {
    if (document.getElementById('maejibunEntry')) return;
    var host = document.getElementById('homeReviewSuggest');
    if (!host || !host.parentNode) return;
    var p = curP(); if (!p || !p.userId) return;
    var el = document.createElement('div');
    el.id = 'maejibunEntry';
    el.style.margin = '10px 0';
    el.innerHTML = '<button type="button" id="maejibunOpen" style="width:100%;display:flex;align-items:center;gap:10px;text-align:left;background:linear-gradient(135deg,#f0fdf4,#ecfeff);border:2px solid #86efac;border-radius:14px;padding:10px 12px;cursor:pointer">'
      + '<span style="font-size:28px;line-height:1">🪞</span>'
      + '<span style="flex:1"><span style="display:block;font-weight:900;color:#166534;font-size:15px">前の自分と くらべる</span>'
      + '<span style="display:block;font-size:12px;color:#15803d">3週間まえの あなたと、いまの あなた。ふりかえりを ならべて 見られるよ</span></span>'
      + '<span style="font-size:18px;color:#16a34a;font-weight:900">▶</span></button>';
    host.parentNode.insertBefore(el, host);
    var b = document.getElementById('maejibunOpen');
    if (b) b.onclick = openPage;
  }
  function closePage() { var o = document.getElementById('maejibunPage'); if (o && o.parentNode) o.parentNode.removeChild(o); try { document.body.style.overflow = ''; } catch (e) {} }
  function openPage() {
    closePage();
    var o = document.createElement('div');
    o.id = 'maejibunPage';
    o.setAttribute('role', 'dialog');
    o.setAttribute('style', 'position:fixed;inset:0;z-index:9998;background:rgba(15,23,42,.45);overflow-y:auto;-webkit-overflow-scrolling:touch;padding:16px 10px');
    o.innerHTML = '<div id="maejibunBody" style="max-width:940px;margin:0 auto;background:#fff;border-radius:18px;box-shadow:0 12px 40px rgba(0,0,0,.25);padding:14px 16px 18px;color:#1e293b">'
      + head() + '<div style="padding:30px;text-align:center;color:#64748b">よみこみ中…</div></div>';
    o.addEventListener('click', function (ev) { if (ev.target === o) closePage(); });
    document.body.appendChild(o);
    try { document.body.style.overflow = 'hidden'; } catch (e) {}
    bindClose();
    if (_data && Date.now() - _data._at < 60000) { render(); return; }
    if (_busy) return;
    _busy = true;
    Promise.all([jget('/api/student/my-growth'), jget('/api/student/week-ref2/history')]).then(function (rs) {   /* WEEKREF2_V1 */
      _busy = false;
      var d = rs[0];
      if (d && d.ok) {
        d._at = Date.now(); _data = d;
        var by = {}; (((rs[1] && rs[1].ok && rs[1].items) || [])).forEach(function (x) { if (x && x.weekKey) by[x.weekKey] = x; });
        (d.cards || []).forEach(function (c) { if (by[c.weekKey]) c.r2 = by[c.weekKey]; });
      }
      render();
    });
  }
  function head() {
    return '<div style="display:flex;align-items:flex-start;gap:8px;margin-bottom:6px">'
      + '<div style="flex:1"><div style="font-size:20px;font-weight:900;color:#166534">🪞 前の自分と くらべる</div>'
      + '<div style="font-size:12px;color:#475569">くらべるのは、前の あなた だけ。ほかの人とは くらべないよ。</div></div>'
      + '<button type="button" class="maejibunX" aria-label="とじる" style="background:#f1f5f9;border:none;border-radius:999px;width:40px;height:40px;font-size:20px;cursor:pointer;color:#334155">×</button></div>';
  }
  function bindClose() { var xs = document.querySelectorAll('.maejibunX'); for (var i = 0; i < xs.length; i++) xs[i].onclick = closePage; }

  function ntLine(nt) {
    if (!nt || (!nt.text && !nt.unit)) return '';
    var un = nt.unit ? (unitName(nt.unit) || nt.unitName || '') : '';
    return '<div style="margin-top:6px;font-size:12.5px;color:#9a3412;background:#fff7ed;border-radius:8px;padding:4px 8px">🎯 来週やってみたいこと：'
      + (un ? '<b>「' + esc(un) + '」</b>' : '') + (nt.text ? (un ? '　' : '') + esc(nt.text) : '') + '</div>';
  }
  // KANTAN_REF_V1 その週の 自分の見立て（◎○△）と「次どうする？」。本人の見立てで、成績・評価ではない。
  var MARK = { good: '◎ よくできた', ok: '○ まあまあ', more: '△ もう少し' };
  function markLine(c) {
    if (!c || (!c.mark && !c.how)) return '';
    return '<div style="margin-bottom:4px;font-size:12.5px;color:#92400e;background:#fffbeb;border-radius:8px;padding:3px 8px">'
      + (c.mark && MARK[c.mark] ? '自分の見立て：<b>' + MARK[c.mark] + '</b>' : '') + (c.how ? (c.mark ? '　' : '') + esc(c.how) : '') + '</div>';
  }
  function marksRow(cards) {   // 古い順に ◎○△ を ならべる（変化が見えるように）
    var xs = cards.filter(function (c) { return c.mark && MARK[c.mark]; }).slice(0, 8).reverse();
    if (xs.length < 2) return '';
    var h = '<div style="margin-top:10px;border:2px solid #fde68a;background:#fffbeb;border-radius:14px;padding:8px 12px"><div style="font-weight:900;color:#92400e;font-size:14.5px">🗓 自分の見立ての ならび <span style="font-size:11px;font-weight:600">（古い じゅん → 新しい じゅん）</span></div><div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:6px;align-items:center">';
    xs.forEach(function (c, i) {
      if (i) h += '<span style="color:#d97706">▶</span>';
      h += '<div style="text-align:center;background:#fff;border:1.5px solid #fcd34d;border-radius:10px;padding:3px 8px"><div style="font-size:20px;font-weight:900;color:#b45309">' + MARK[c.mark].charAt(0) + '</div><div style="font-size:10.5px;color:#92400e">' + esc(wkLabel(c.weekKey).replace('の週', '')) + '</div></div>';
    });
    return h + '</div><div style="font-size:11.5px;color:#92400e;margin-top:4px">じぶんで つけた しるしだよ。せいせきでは ないよ。</div></div>';
  }
  // WEEKREF2_V1 先週決めたことの結果・🏫学校での学び（本人の見立て。成績・評価ではない）
  function r2Line(r) {
    if (!r) return '';
    var h = '';
    if (r.promise && r.promise.resultJa) h += '<div>🤝 先週 決めたこと：<b>' + esc(r.promise.resultJa) + '</b>' + (r.promise.reasonJa ? '（' + esc(r.promise.reasonJa) + '）' : '') + (r.promise.text ? '　「' + esc(r.promise.text) + '」' : '') + '</div>';
    if (r.school && r.school.subj) h += '<div>🏫 学校で：<b>' + esc(r.school.subj) + (r.school.theme ? '「' + esc(r.school.theme) + '」' : '') + '</b>' + (r.school.learned ? '　' + esc(r.school.learned) : '') + (r.school.more ? '　→ もっと：' + esc(r.school.more) : '') + '</div>';
    if (r.q && (r.q.choiceJa || r.q.text)) h += '<div>💭 ' + esc(r.q.label) + ' → ' + esc([r.q.choiceJa, r.q.text].filter(Boolean).join('・')) + '</div>';
    return h ? '<div style="margin-top:6px;font-size:12.5px;line-height:1.6;color:#1e3a8a;background:#eff6ff;border-radius:8px;padding:4px 8px">' + h + '</div>' : '';
  }
  function cardBody(c, big) {
    var fs = big ? '14.5px' : '13.5px';
    var h = markLine(c);
    if (c.text) h += '<div style="font-size:' + fs + ';line-height:1.7;white-space:pre-wrap">' + esc(c.text) + '</div>';
    if (c.star) h += '<div style="margin-top:4px;font-size:12.5px;color:#a16207">🌟 家庭学習シートに：' + esc(c.star) + '</div>';
    if (!c.text && !c.star && !c.mark) h += '<div style="font-size:12.5px;color:#94a3b8">（この週の ふりかえりの 文は ないよ）</div>';
    h += ntLine(c.nextTry);
    h += r2Line(c.r2);   /* WEEKREF2_V1 */
    return h;
  }
  function pickLeft(cards, cur) {
    if (_leftWk) { for (var i = 0; i < cards.length; i++) if (cards[i].weekKey === _leftWk) return cards[i]; }
    var latest = cards[0];
    var best = null;
    for (var j = 1; j < cards.length; j++) { if (weeksBetween(cards[j].weekKey, latest.weekKey) >= 3) { best = cards[j]; break; } }
    return best || cards[cards.length - 1];
  }
  function factsHtml(f) {
    if (!f) return '';
    var lines = [];
    (f.units || []).forEach(function (u) {
      var nm = unitName(u.unit);
      if (!nm) return;   // 名前が言えない単元は出さない
      lines.push('「' + esc(nm) + '」… 10問中 <b>' + u.before + '問</b> → 10問中 <b>' + u.after + '問</b> くらい せいかい <span style="color:#64748b;font-size:11.5px">（2〜4週間まえ → この2週間）</span>');
    });
    if (f.days && f.days.now > 0) {
      lines.push('家庭学習を 出した日：この4週間で <b>' + f.days.now + '日</b>' + (f.days.now > f.days.before ? ' <span style="color:#64748b;font-size:11.5px">（その前の4週間は ' + f.days.before + '日）</span>' : ''));
    }
    if (f.weeksWritten >= 2) lines.push('ふりかえりを 書いた週：<b>' + f.weeksWritten + '週ぶん</b>');
    if (!lines.length) return '';
    var h = '<div style="margin-top:12px;border:2px solid #bbf7d0;background:#f0fdf4;border-radius:14px;padding:10px 12px">'
      + '<div style="font-weight:900;color:#15803d;font-size:15px">🌱 のびたこと <span style="font-size:11.5px;font-weight:600;color:#16a34a">（記録から 数えた ことだけ）</span></div>';
    lines.slice(0, 4).forEach(function (l) { h += '<div style="font-size:13.5px;margin-top:4px">・' + l + '</div>'; });
    return h + '</div>';
  }
  function render() {
    var box = document.getElementById('maejibunBody');
    if (!box) return;
    var d = _data;
    var h = head();
    if (!d || !d.ok) {
      h += '<div style="padding:24px;text-align:center;color:#64748b">いまは 読みこめなかったよ。あとで もう一度 ひらいてみてね。</div>';
      box.innerHTML = h; bindClose(); return;
    }
    var cards = d.cards || [];
    var cur = d.currentWeek || weekKeyNow();
    if (!cards.length) {
      h += '<div style="padding:18px;text-align:center;color:#475569;line-height:1.8">まだ ふりかえりが ないよ。<br>週の計画の「🔄 今週の振り返り」に 書くと、ここに たまっていくよ。<br>書きためると、前の あなたと くらべられるように なるで。</div>';
      h += factsHtml(d.facts);
      box.innerHTML = h; bindClose(); return;
    }
    var latest = cards[0];
    if (cards.length >= 2) {
      var left = pickLeft(cards, cur);
      if (left === latest) left = cards[1];
      // くらべる週をえらぶ（先週・3週間まえ・いちばん前 など、ある週だけ）
      var chips = '';
      var seen = {};
      var want = [1, 2, 3, 4, 6, 8];
      cards.slice(1).forEach(function (c) {
        var n = weeksBetween(c.weekKey, latest.weekKey);
        if (want.indexOf(n) >= 0 && !seen[c.weekKey]) { seen[c.weekKey] = 1; chips += chip(c, latest); }
      });
      var oldest = cards[cards.length - 1];
      if (!seen[oldest.weekKey]) chips += chip(oldest, latest, 'いちばん前');
      h += '<div style="margin-top:6px;font-size:12px;color:#475569">くらべる週：' + chips + '</div>';
      h += '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-top:8px;align-items:stretch">'
        + '<div style="flex:1 1 300px;border:2px solid #cbd5e1;background:#f8fafc;border-radius:14px;padding:10px 12px">'
        + '<div style="font-weight:900;color:#475569;font-size:15px">🕰 ' + esc(agoLabel(left.weekKey, cur)) + 'の あなた <span style="font-size:11px;font-weight:600">（' + esc(wkLabel(left.weekKey)) + '）</span></div>'
        + '<div style="margin-top:4px">' + cardBody(left, true) + '</div></div>'
        + '<div style="align-self:center;font-size:22px;color:#16a34a;font-weight:900">▶</div>'
        + '<div style="flex:1 1 300px;border:2px solid #86efac;background:#f0fdf4;border-radius:14px;padding:10px 12px">'
        + '<div style="font-weight:900;color:#166534;font-size:15px">🌟 いちばん新しい あなた <span style="font-size:11px;font-weight:600">（' + esc(agoLabel(latest.weekKey, cur)) + '・' + esc(wkLabel(latest.weekKey)) + '）</span></div>'
        + '<div style="margin-top:4px">' + cardBody(latest, true) + '</div></div></div>';
      h += '<div style="margin-top:6px;font-size:12.5px;color:#166534;background:#ecfdf5;border-radius:10px;padding:6px 10px">💭 ならべて 見て、かわったことは ある？ 書き方・やってみたこと・気もち… 気づいたことを 次の ふりかえりに 書いてみてもいいね。</div>';
    } else {
      h += '<div style="margin-top:8px;border:2px solid #86efac;background:#f0fdf4;border-radius:14px;padding:10px 12px">'
        + '<div style="font-weight:900;color:#166534;font-size:15px">🌟 いちばん新しい あなた <span style="font-size:11px;font-weight:600">（' + esc(wkLabel(latest.weekKey)) + '）</span></div>'
        + '<div style="margin-top:4px">' + cardBody(latest, true) + '</div>'
        + '<div style="margin-top:6px;font-size:12px;color:#475569">来週も 書くと、前の あなたと ならべて 見られるように なるよ。</div></div>';
    }
    h += marksRow(cards);   /* KANTAN_REF_V1 */
    h += factsHtml(d.facts);
    // これまでの ふりかえり（新しい順）
    h += '<div style="margin-top:14px;font-weight:900;color:#334155;font-size:15px">📚 これまでの ふりかえり <span style="font-size:11.5px;font-weight:600;color:#64748b">（新しい順）</span></div>';
    cards.forEach(function (c) {
      h += '<div style="margin-top:8px;border:1.5px solid #e2e8f0;border-radius:12px;padding:8px 12px;background:#fff">'
        + '<div style="font-size:12px;font-weight:800;color:#64748b">' + esc(agoLabel(c.weekKey, cur)) + '　' + esc(wkLabel(c.weekKey)) + '</div>'
        + cardBody(c, false)
        + (c.reply ? '<div style="margin-top:6px;font-size:12.5px;color:#075985;background:#f0f9ff;border-radius:8px;padding:4px 8px">💬 先生から：' + esc(c.reply) + '</div>' : '')
        + '</div>';
    });
    h += '<div style="margin-top:14px;text-align:center"><button type="button" class="maejibunX" style="background:#16a34a;color:#fff;border:none;border-radius:12px;padding:10px 28px;font-weight:800;font-size:14px;cursor:pointer">とじる</button></div>';
    box.innerHTML = h;
    bindClose();
    var cs = box.querySelectorAll('.maejibunChip');
    for (var i = 0; i < cs.length; i++) cs[i].onclick = function () { _leftWk = this.getAttribute('data-wk'); render(); };
  }
  function chip(c, latest, label) {
    var n = weeksBetween(c.weekKey, latest.weekKey);
    var lab = label || (n === 1 ? '1週まえ' : n + '週まえ');
    var on = _leftWk ? _leftWk === c.weekKey : false;
    return '<button type="button" class="maejibunChip" data-wk="' + esc(c.weekKey) + '" style="margin:2px 3px;border-radius:999px;padding:4px 12px;font-size:12px;font-weight:800;cursor:pointer;' + (on ? 'background:#16a34a;color:#fff;border:1.5px solid #16a34a' : 'background:#fff;color:#166534;border:1.5px solid #86efac') + '">' + esc(lab) + '</button>';
  }

  // ══════ 2) 来週やってみたいこと（振り返りの欄の下） ══════
  var _nt = null, _ntWk = '', _ntSaving = false, _ntLast = '';
  function unitOptions(sel) {
    var C = curriculum(), g = myGrade();
    if (!C || !g) return '';
    var h = '<option value="">（単元を えらぶなら ここ）</option>';
    SUBJ_ORDER.forEach(function (sk) {
      var sub = C[sk]; if (!sub || !sub.grades) return;
      [g, g - 1].forEach(function (gg) {
        var gd = sub.grades[gg]; if (!gd || !(gd.units || []).length) return;
        h += '<optgroup label="' + esc((sub.name || sk) + '・' + (gd.label || gg)) + '">';
        gd.units.forEach(function (u) { h += '<option value="' + esc(u.id) + '"' + (u.id === sel ? ' selected' : '') + '>' + esc(u.name) + '</option>'; });
        h += '</optgroup>';
      });
    });
    if (sel && h.indexOf('value="' + sel + '"') < 0 && unitName(sel)) h += '<option value="' + esc(sel) + '" selected>' + esc(unitName(sel)) + '</option>';
    return h;
  }
  function ensureNextTry() {
    var area = document.getElementById('hwReflectionArea');
    var ta = document.getElementById('hwReflectionInput');
    if (!area || !ta) return;
    var off = 0;
    try { if (typeof _hwWeekOffset !== 'undefined') off = Number(_hwWeekOffset) || 0; } catch (e) {}
    var box = document.getElementById('maejibunNext');
    if (off !== 0) { if (box) box.style.display = 'none'; return; }
    if (!box) {
      box = document.createElement('div');
      box.id = 'maejibunNext';
      box.setAttribute('style', 'background:#fff;border:1.5px dashed #fdba74;border-radius:10px;padding:6px 8px');
      // 書く欄のすぐ下（提出ボタンの上）に置く
      ta.parentNode.insertBefore(box, ta.nextSibling);
    }
    box.style.display = '';
    var wk = weekKeyNow();
    if (_ntWk !== wk) {
      _ntWk = wk; _nt = null;
      drawNext(box);
      jget('/api/student/next-try?weekKey=' + encodeURIComponent(wk)).then(function (d) {
        if (d && d.ok) { _nt = d.nextTry || { unit: '', text: '' }; _ntLast = JSON.stringify([_nt.unit || '', _nt.text || '']); }
        var b2 = document.getElementById('maejibunNext');
        var a = document.activeElement;
        if (b2 && !(a && (a.id === 'maejibunNtText' || a.id === 'maejibunNtUnit'))) drawNext(b2);
      });
    } else if (!box.firstChild) drawNext(box);
  }
  function drawNext(box) {
    var nt = _nt || { unit: '', text: '' };
    var opts = unitOptions(nt.unit || '');
    box.innerHTML = '<div style="font-size:12.5px;font-weight:800;color:#c2410c">🎯 来週やってみたいこと <span style="font-weight:600;font-size:11px;color:#9a6b4f">（書かなくても だいじょうぶ。書くと、来週の カルテの 🅲 に 入るよ）</span></div>'
      + '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:4px;align-items:center">'
      + (opts ? '<select id="maejibunNtUnit" style="flex:1 1 200px;min-width:0;max-width:100%;border:1px solid #fdba74;border-radius:8px;padding:6px;font-size:13px;background:#fff">' + opts + '</select>' : '')
      + '<input id="maejibunNtText" type="text" maxlength="40" value="' + esc(nt.text || '') + '" placeholder="ひとことで（例：わり算の 筆算に ちょうせん）" style="flex:2 1 240px;min-width:0;border:1px solid #fdba74;border-radius:8px;padding:6px 8px;font-size:13px">'
      + '<button type="button" id="maejibunNtSave" style="background:#fff7ed;border:1.5px solid #f97316;color:#c2410c;border-radius:8px;padding:6px 12px;font-size:12.5px;font-weight:800;cursor:pointer">のこす</button>'
      + '</div><div id="maejibunNtMsg" style="font-size:11px;color:#9a3412;min-height:14px;margin-top:2px">' + ((nt.unit || nt.text) ? '✅ のこしてあるよ（かえても いいよ）' : '') + '</div>';
    var s = document.getElementById('maejibunNtSave'); if (s) s.onclick = function () { saveNext(true); };
    var u = document.getElementById('maejibunNtUnit'); if (u) u.onchange = function () { saveNext(false); };
  }
  function readNext() {
    var u = document.getElementById('maejibunNtUnit'), t = document.getElementById('maejibunNtText');
    var unit = u ? String(u.value || '') : ((_nt && _nt.unit) || '');
    return { unit: unit, unitName: unit ? unitName(unit) : '', text: t ? String(t.value || '').trim().slice(0, 40) : '' };
  }
  function saveNext(force) {
    var v = readNext();
    var sig = JSON.stringify([v.unit, v.text]);
    var msg = document.getElementById('maejibunNtMsg');
    if (!force && sig === _ntLast) return Promise.resolve(null);
    if (_ntSaving) return Promise.resolve(null);
    if (!_nt && !v.unit && !v.text) return Promise.resolve(null);   // まだ読みこむ前・何も書いていない
    _ntSaving = true;
    if (msg) msg.textContent = 'のこしています…';
    return fetch('/api/student/next-try', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ weekKey: weekKeyNow(), unit: v.unit, unitName: v.unitName, text: v.text }) })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        _ntSaving = false;
        if (j && j.ok) {
          _nt = { unit: v.unit, text: v.text }; _ntLast = sig;
          if (msg) msg.textContent = (v.unit || v.text) ? '✅ のこしたよ。来週の カルテの 🅲「じぶんで決める」に 入るよ' : 'けしたよ';
          if (_data) _data._at = 0;
        } else if (msg) msg.textContent = 'のこせなかったよ。もう一度 おしてみてね';
        return j;
      })
      .catch(function () { _ntSaving = false; if (msg) msg.textContent = 'のこせなかったよ。もう一度 おしてみてね'; });
  }
  // 「🔄 振り返りを提出」を押したときも いっしょに のこす（もとの提出はそのまま）
  function hookSubmit() {
    try {
      if (typeof window.hwSubmitReflection === 'function' && !window.hwSubmitReflection.__maejibun) {
        var orig = window.hwSubmitReflection;
        var w = function () {
          var r;
          try { r = orig.apply(this, arguments); } catch (e) {}
          try { saveNext(false); } catch (e) {}
          return r;
        };
        w.__maejibun = true;
        window.hwSubmitReflection = w;
      }
    } catch (e) {}
  }
  function hookRender() {
    try {
      if (typeof window.hwRenderWeekView === 'function' && !window.hwRenderWeekView.__maejibun) {
        var orig = window.hwRenderWeekView;
        var w = function () {
          var r;
          try { r = orig.apply(this, arguments); } catch (e) {}
          Promise.resolve(r).then(function () { try { ensureNextTry(); } catch (e) {} }, function () {});
          return r;
        };
        w.__maejibun = true;
        // weekref.js の目印も引きつぐ（二重に包まれないように）
        if (orig.__weekRef) w.__weekRef = true;
        window.hwRenderWeekView = w;
      }
    } catch (e) {}
  }

  // ---------- 起動 ----------
  var tries = 0;
  var timer = setInterval(function () {
    tries++;
    ensureEntry();
    hookSubmit();
    hookRender();
    ensureNextTry();
    if ((document.getElementById('maejibunEntry') && window.hwSubmitReflection && window.hwSubmitReflection.__maejibun && window.hwRenderWeekView && window.hwRenderWeekView.__maejibun) || tries > 90) clearInterval(timer);
  }, 2000);
  // ステータス画面が描き直されて入口が消えたときに戻す（⚡ミニ復習と同じ瞬間に相乗り）
  setInterval(function () { try { ensureEntry(); } catch (e) {} }, 5000);
  try { window.maejibunOpen = openPage; } catch (e) {}
})();
