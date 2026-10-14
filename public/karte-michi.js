/* ===================================================================
   karte-michi.js : 🧭 学びの道しるべ（印刷カルテ・A4両面）  MICHI_V1 2026-10
   -------------------------------------------------------------------
   ・先生用ページの _buildKarteHtml を、この形に差しかえる。
     もとの関数はそのまま残し、まず もとの紙を作ってから 中の欄を取り出して並べ直す。
     途中で何か失敗したら、もとの紙をそのまま返す（紙が出なくなる事故を防ぐ）。
   ・おもて：🧭まずここから／🗺道順マップ（算数）／📅先週のようす／🔁先週のやってみる／🐯阪神マン
     うら　：✏️これやってみる？／🌟できるようになったこと／💡学び方／📊グラフ／🎯めあて／📝先生から／✂おうちの人へ
   ・1人ぶんは必ず2ページ（裏表1枚）。全員ぶん印刷で次の子が裏にずれないように、
     面ごとに高さを決めて、はみ出す分は欄ごとの行数上限で切る。
   ・テストの点数・順位・ほかの子との比較は出さない。命令しない。
     記録にないことは書かない（機械で作る欄は、記録から言えることだけ）。
   ・AIの文（阪神マン・考えてほしいこと・これやってみる・おうちの人へ）は
     先生が④で確認して公開したものだけが来る（d.aiComment）。
   =================================================================== */
(function (global) {
  'use strict';
  if (global.__MICHI_V1__) return;
  global.__MICHI_V1__ = true;

  var NL = '\n';
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function cut(s, n) { s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
  function of10(rate) { return Math.max(0, Math.min(10, Math.round((rate || 0) / 10))); }

  // ───────── 単元の情報（教科・学年・アプリでのボタン名） ─────────
  var SUBJ = { math: { name: '算数', icon: '🔢' }, japanese: { name: '国語', icon: '📝' }, social: { name: '社会', icon: '🌏' }, science: { name: '理科', icon: '🔬' }, english: { name: '英語', icon: '🔤' } };
  var AREA2SUBJ = { math: 'math', jp: 'japanese', soc: 'social', sci: 'science', eng: 'english' };
  var _cur = null, _unitIdx = null;
  function loadCurriculum() {
    if (_cur) return Promise.resolve(_cur);
    if (global.CURRICULUM) { _cur = global.CURRICULUM; return Promise.resolve(_cur); }
    return fetch('/api/teacher/curriculum-units', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (j) { if (j && j.ok && j.source) { _cur = (new Function('return (' + j.source + ')'))(); _unitIdx = null; } return _cur; })
      .catch(function () { return null; });
  }
  function unitIndex() {
    if (_unitIdx) return _unitIdx;
    var idx = {};
    var C = _cur || global.CURRICULUM;
    if (C) {
      Object.keys(C).forEach(function (sk) {
        var sub = C[sk]; if (!sub || !sub.grades) return;
        Object.keys(sub.grades).forEach(function (g) {
          var gd = sub.grades[g]; (gd.units || []).forEach(function (u, i) {
            idx[u.id] = { id: u.id, subj: sk, subjName: sub.name || (SUBJ[sk] && SUBJ[sk].name) || '', icon: sub.icon || (SUBJ[sk] && SUBJ[sk].icon) || '', grade: Number(g), gradeLabel: gd.label || ((Number(g) <= 6 ? '小' : '中') + (Number(g) <= 6 ? g : Number(g) - 6)), name: u.name || '', order: i };
          });
        });
      });
      _unitIdx = idx;
    }
    return idx;
  }
  function unitInfo(id) {
    id = String(id || '');
    var x = unitIndex()[id];
    if (x) return x;
    var m = MATH_NAMES[id];
    if (m) return { id: id, subj: 'math', subjName: '算数', icon: '🔢', grade: m[0], gradeLabel: gLabel(m[0]), name: m[1], order: 0 };
    var area = (typeof global._subjectArea === 'function') ? global._subjectArea(id) : '';
    var sk = AREA2SUBJ[area] || '';
    var g = (typeof global._unitGrade === 'function') ? global._unitGrade(id) : null;
    var nm = (typeof global._unitJa === 'function') ? global._unitJa(id) : id;
    if (!sk || !g || !nm || nm === id) return null;   // アプリのどこにあるか言えない単元は使わない
    return { id: id, subj: sk, subjName: SUBJ[sk].name, icon: SUBJ[sk].icon, grade: g, gradeLabel: gLabel(g), name: nm, order: 0 };
  }
  function gLabel(g) { g = Number(g); return g <= 6 ? '小' + g : '中' + (g - 6); }

  // ───────── 算数の道順（単元のつながり） ─────────
  // アプリにある算数の単元を「つながり」ごとに並べた手づくりの表。学年をまたいでつながる。
  var MATH_NAMES = {
    'm1-add-no': [1, 'たしざん(くり上がりなし)'], 'm1-sub-no': [1, 'ひきざん(くり下がりなし)'], 'm1-add-cy': [1, 'たしざん(くり上がり)'], 'm1-sub-bo': [1, 'ひきざん(くり下がり)'], 'm1-3num': [1, '3つのかずのけいさん'],
    'm2-add2': [2, 'たし算(2けた)'], 'm2-sub2': [2, 'ひき算(2けた)'], 'm2-kuku': [2, '九九'], 'm2-length': [2, '長さ(cm, mm)'],
    'm3-mul1': [3, 'かけ算(2けた×1けた)'], 'm3-div0': [3, 'わり算(あまりなし)'], 'm3-divR': [3, 'わり算(あまりあり)'], 'm3-large': [3, '大きい数の位'], 'm3-weight': [3, '重さ(g, kg)'],
    'rounding': [4, 'がい数'], 'division': [4, 'わり算(暗算)'], 'fraction-mixed': [4, '分数'], 'decimal': [4, '小数(×÷)'], 'long-division': [4, '筆算(わり算)'], 'area': [4, '面積'], 'brackets': [4, '計算の順序'],
    'm5-frac-eq': [5, '約分と通分'], 'm5-percent': [5, '割合(百分率)'], 'm5-volume': [5, '体積'], 'm5-polygon': [5, '多角形の角'], 'm5-avg': [5, '平均'], 'm5-dec-mul': [5, '小数×小数'], 'm5-dec-div': [5, '小数÷小数'], 'm5-speed': [5, '速さ'], 'm5-unit-qty': [5, '単位量あたり'],
    'm6-frac-mul': [6, '分数×分数'], 'm6-frac-div': [6, '分数÷分数'], 'm6-frac-int': [6, '分数×÷整数'], 'm6-frac-mixed': [6, '帯分数の計算'], 'm6-frac-triple': [6, '分数3つの計算'], 'm6-frac-dec': [6, '小数と分数'], 'm6-ratio': [6, '比'], 'm6-circle': [6, '円の面積'], 'm6-proportion': [6, '比例と反比例'], 'm6-expression': [6, '文字と式'],
    'm7-seifu': [7, '正負の数'], 'm7-moji': [7, '文字と式'], 'm7-eq': [7, '1次方程式'], 'm7-hirei': [7, '比例・反比例'], 'm7-heimen': [7, '平面図形'], 'm7-kukan': [7, '空間図形'], 'm7-shiryo': [7, '資料の活用']
  };
  var MATH_ROUTES = [
    { name: 'たし算・ひき算', units: ['m1-add-no', 'm1-sub-no', 'm1-add-cy', 'm1-sub-bo', 'm1-3num', 'm2-add2', 'm2-sub2'] },
    { name: 'かけ算', units: ['m2-kuku', 'm3-mul1', 'decimal', 'm5-dec-mul'] },
    { name: 'わり算', units: ['m3-div0', 'm3-divR', 'division', 'long-division', 'm5-dec-div'] },
    { name: '分数', units: ['fraction-mixed', 'm5-frac-eq', 'm6-frac-int', 'm6-frac-mul', 'm6-frac-div', 'm6-frac-mixed', 'm6-frac-triple', 'm6-frac-dec'] },
    { name: '式と文字', units: ['brackets', 'm6-expression', 'm7-moji', 'm7-eq'] },
    { name: '大きな数', units: ['m3-large', 'rounding', 'm7-seifu'] },
    { name: '割合と比', units: ['m5-unit-qty', 'm5-speed', 'm5-percent', 'm6-ratio', 'm6-proportion', 'm7-hirei'] },
    { name: '図形と量', units: ['m2-length', 'm3-weight', 'area', 'm5-polygon', 'm5-volume', 'm6-circle', 'm7-heimen', 'm7-kukan'] },
    { name: 'データ', units: ['m5-avg', 'm7-shiryo'] }
  ];
  function routeOf(id) {
    for (var i = 0; i < MATH_ROUTES.length; i++) { var k = MATH_ROUTES[i].units.indexOf(id); if (k >= 0) return { route: MATH_ROUTES[i], pos: k }; }
    return null;
  }

  // ───────── クラスごとの「いま修行されている単元」 ─────────
  var _guide = {};   // classId -> {nowUnits, unitProgress}
  function loadGuide(cid) {
    if (!cid) return Promise.resolve(null);
    if (_guide[cid]) return Promise.resolve(_guide[cid]);
    return fetch('/api/teacher/class/' + encodeURIComponent(cid) + '/karte-guide', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (j) { if (j && j.ok) _guide[cid] = j; return _guide[cid] || null; })
      .catch(function () { return null; });
  }
  function preloadAll() {
    var ps = [loadCurriculum()];
    try {
      ['analyticsClassFilter', 'laClassSelect', 'activityClassFilter'].forEach(function (id) {
        var el = document.getElementById(id); if (!el) return;
        for (var i = 0; i < el.options.length; i++) { var v = el.options[i].value; if (v) ps.push(loadGuide(v)); }
      });
    } catch (e) {}
    return Promise.all(ps);
  }
  global.michiPreload = preloadAll;

  // ───────── AIの文を▼の見出しで分ける ─────────
  function splitAi(text) {
    var out = { main: '', ask: '', tries: [], home: '' };
    var lines = String(text || '').replace(/\r/g, '').split('\n');
    var cur = 'main', buf = { main: [], ask: [], try: [], home: [] };
    for (var i = 0; i < lines.length; i++) {
      var raw = lines[i];
      var t = raw.replace(/^[\s　*#>＃＊]+/, '').replace(/[\s　*＊]+$/, '');
      var m = t.match(/^▼[\s　]*(.*)$/);
      if (m) {
        var h = m[1];
        if (/考えて/.test(h)) cur = 'ask';
        else if (/やってみる/.test(h)) cur = 'try';
        else if (/おうち|家の人|保護者/.test(h)) cur = 'home';
        else cur = 'skip';
        continue;
      }
      if (cur !== 'skip') buf[cur].push(t);
    }
    out.main = buf.main.join('\n').replace(/^\s+|\s+$/g, '');
    out.ask = buf.ask.join(' ').replace(/\s+/g, ' ').trim();
    buf.try.forEach(function (l) {
      var x = l.replace(/^([・\-–—•●○◯□☐]|[0-9０-９]+[.．)）]|[①-⑩])[\s　]*/, '').trim();
      if (x && !/じぶんで決める|自分で決める/.test(x)) out.tries.push(x);
    });
    out.home = buf.home.join(' ').replace(/\s+/g, ' ').trim();
    return out;
  }
  global.michiSplitAi = splitAi;

  // ───────── 記録から作る部分 ─────────
  function daysAgo(iso) { if (!iso) return 9999; var t = Date.parse(String(iso).replace(' ', 'T') + (String(iso).length <= 10 ? 'T00:00:00Z' : '')); if (isNaN(t)) return 9999; return Math.floor((Date.now() - t) / 86400000); }
  function wdOf(dk) { var t = Date.parse(String(dk) + 'T00:00:00Z'); if (isNaN(t)) return -1; return new Date(t).getUTCDay(); }
  var WD = ['日', '月', '火', '水', '木', '金', '土'];

  function subjMap(d) { var m = {}; (d.subjects || []).forEach(function (s) { m[String(s.unit)] = s; }); return m; }

  function isTaught(guide, id) { var up = guide && guide.unitProgress && guide.unitProgress.units; return !(up && up[id] === false); }

  // 🧭 まずここから：今日・今週の最初の1歩を1つ
  function firstStep(d, guide) {
    var sg = Number((d.student && d.student.grade) || 0) || null;
    var sm = subjMap(d);
    var recent = (d.subjects || []).filter(function (s) { return s.lastAt && daysAgo(s.lastAt) <= 28 && Number(s.total || 0) > 0; })
      .sort(function (a, b) { return String(b.lastAt).localeCompare(String(a.lastAt)); })
      .map(function (s) { return { s: s, info: unitInfo(s.unit) }; })
      .filter(function (x) { return x.info && (!sg || x.info.grade <= sg + 1); });
    var now = ((guide && guide.nowUnits) || []).map(function (x) { return { n: x, info: unitInfo(x.unit) }; })
      .filter(function (x) { return x.info && sg && x.info.grade === sg && x.n.users >= 2 && isTaught(guide, x.info.id); });
    now.sort(function (a, b) { return (a.info.subj === 'math' ? 0 : 1) - (b.info.subj === 'math' ? 0 : 1) || b.n.users - a.n.users; });
    var lastSub = (d.overview && d.overview.lastDate) || '';
    var stalled = !lastSub || daysAgo(lastSub) >= 7;
    var lw = d.lastWeek || {};
    var thin = stalled || !(lw.total > 0);
    var pick = null, why = '';
    var r0 = recent[0];
    if (r0 && (r0.s.rate < 80 || r0.s.total < 20)) { pick = r0.info; why = 'さいごに 修行した単元の つづき'; }
    else if (now.length) {
      var n0 = now[0], mine = sm[n0.info.id];
      if (!mine || mine.total < 30 || mine.rate < 80) { pick = n0.info; why = 'いま 学年で 習っているところ'; }
    }
    if (!pick && r0) {
      var rt = routeOf(r0.info.id);
      var nx = rt && rt.route.units[rt.pos + 1] && unitInfo(rt.route.units[rt.pos + 1]);
      if (nx && (!sg || nx.grade <= sg) && isTaught(guide, nx.id)) { pick = nx; why = '「' + r0.info.name + '」が できてきたので、つぎの道へ'; }
      else { pick = r0.info; why = 'さいごに 修行した単元'; }
    }
    if (!pick && now.length) { pick = now[0].info; why = 'いま 学年で 習っているところ'; }
    if (!pick && sg) {   // 記録がまったく無い子：学年の算数で、習ったところの いちばん後ろ
      var C = _cur || global.CURRICULUM;
      var us = (C && C.math && C.math.grades && C.math.grades[sg] && C.math.grades[sg].units) || [];
      var cand = us.filter(function (u) { return isTaught(guide, u.id); });
      if (cand.length) { pick = unitInfo(cand[cand.length - 1].id); why = '学年の算数から'; }
    }
    if (!pick) return null;
    var mineP = sm[pick.id];
    var amount = thin ? '5問だけ' : (mineP && mineP.rate < 60 ? '5問' : '10問');
    return { info: pick, why: why, amount: amount, stalled: stalled, thin: thin, mine: mineP || null };
  }

  // 🗺 道順マップ（算数）
  function mathMap(d, step, guide) {
    var sm = subjMap(d);
    var anchor = null;
    var sg = Number((d.student && d.student.grade) || 0) || null;
    if (step && step.info.subj === 'math' && routeOf(step.info.id)) anchor = step.info.id;
    if (!anchor) {
      // 学年の算数で さいきん（4週間以内）さわった単元。とちゅうのもの（10問中8問未満）を先に。
      var ms = (d.subjects || []).filter(function (s) { var inf = unitInfo(s.unit); return s.lastAt && daysAgo(s.lastAt) <= 28 && routeOf(String(s.unit)) && inf && inf.grade === sg; })
        .sort(function (a, b) { return ((a.rate < 80 ? 0 : 1) - (b.rate < 80 ? 0 : 1)) || String(b.lastAt).localeCompare(String(a.lastAt)); });
      if (ms.length) anchor = String(ms[0].unit);
    }
    if (!anchor && guide) {
      var nm0 = (guide.nowUnits || []).filter(function (x) { var inf = unitInfo(x.unit); return routeOf(x.unit) && inf && inf.grade === sg && x.users >= 2; });
      if (nm0.length) anchor = nm0[0].unit;
    }
    if (!anchor) {
      var ms2 = (d.subjects || []).filter(function (s) { return s.lastAt && routeOf(String(s.unit)); })
        .sort(function (a, b) { return String(b.lastAt).localeCompare(String(a.lastAt)); });
      if (ms2.length) anchor = String(ms2[0].unit);
    }
    if (!anchor) return null;
    var rt = routeOf(anchor); if (!rt) return null;
    var u = rt.route.units, k = rt.pos;
    var ids = [];
    if (k - 1 >= 0) ids.push(u[k - 1]);
    ids.push(u[k]);
    if (k + 1 < u.length) ids.push(u[k + 1]);
    if (k + 2 < u.length) ids.push(u[k + 2]);
    var nodes = ids.map(function (id) {
      var s = sm[id], inf = unitInfo(id) || { name: id, gradeLabel: '' };
      var st = 'mada';
      if (s && Number(s.total) >= 10 && Number(s.rate) >= 80) st = 'ok';
      else if (s && Number(s.total) > 0) st = 'doing';
      return { id: id, name: inf.name, gl: inf.gradeLabel, st: st, s: s, here: id === anchor };
    });
    var hereS = sm[anchor];
    var back = '';
    if (hereS && Number(hereS.total) >= 10 && Number(hereS.rate) < 60 && k - 1 >= 0) {
      var pv = unitInfo(u[k - 1]);
      if (pv) back = 'むずかしいと感じたら、ひとつ前の「' + pv.name + '」に もどっても いいよ。道は つながっているから、もどるのも 前進やで。';
    }
    return { route: rt.route.name, nodes: nodes, back: back };
  }

  // 🌟 できるようになったこと（記録で言えることだけ）
  function canDo(d) {
    var out = [];
    var lw = d.lastWeek || {};
    (lw.units || []).forEach(function (u) {
      if (out.length >= 2) return;
      if (u.firstEver || Number(u.total) < 10 || u.yearRate == null) return;
      if (Number(u.rate) - Number(u.yearRate) >= 10) {
        var inf = unitInfo(u.unit);
        out.push('「' + esc(inf ? inf.name : (global._unitJa ? global._unitJa(u.unit) : u.unit)) + '」… これまでは 10問中 ' + of10(u.yearRate) + '問くらい → 先週は 10問中 ' + of10(u.rate) + '問くらい せいかい');
      }
    });
    (d.subjects || []).forEach(function (s) {
      if (out.length >= 3) return;
      if (Number(s.earlyTotal) >= 20 && Number(s.lateTotal) >= 20 && s.earlyRate != null && s.lateRate != null && s.lateRate - s.earlyRate >= 15) {
        var inf = unitInfo(s.unit);
        var line = '「' + esc(inf ? inf.name : (global._unitJa ? global._unitJa(s.unit) : s.unit)) + '」… 1学期は 10問中 ' + of10(s.earlyRate) + '問くらい → 9月からは 10問中 ' + of10(s.lateRate) + '問くらい';
        if (out.join('').indexOf(inf ? inf.name : s.unit) < 0) out.push(line);
      }
    });
    (lw.units || []).forEach(function (u) {
      if (out.length >= 3 || !u.firstEver) return;
      var inf = unitInfo(u.unit);
      out.push('「' + esc(inf ? inf.name : (global._unitJa ? global._unitJa(u.unit) : u.unit)) + '」に はじめて ちょうせん（' + u.total + '問）');
    });
    var ov = d.overview || {};
    if (out.length < 3 && Number(ov.currentStreak) >= 3) out.push('いま ' + ov.currentStreak + '日 つづけて 家庭学習を 出せているよ');
    var head = (lw.total > 0) ? ('先週は アプリで ' + lw.total + '問（' + lw.days + '日）とりくんだよ') : '';
    return { head: head, lines: out.slice(0, 3) };
  }

  // 💡 自分に合う学び方（回数が少ない・差がないときは出さない）
  function hints(d) {
    var subs = (d.recentSubmissions || []).filter(function (s) { return !s.rest_day; });
    var out = [];
    if (subs.length >= 6) {
      var B = [{ lo: 0, hi: 15, lab: '15分まで' }, { lo: 16, hi: 30, lab: '20〜30分くらい' }, { lo: 31, hi: 999, lab: '30分より長い' }];
      B.forEach(function (b) { b.n = 0; b.sun = 0; });
      subs.forEach(function (s) { var m = Number(s.minutes || 0); for (var i = 0; i < B.length; i++) if (m >= B[i].lo && m <= B[i].hi) { B[i].n++; if (s.end_weather === 'sun') B[i].sun++; } });
      var best = null;
      B.forEach(function (b) {
        if (b.n < 3) return;
        var others = B.filter(function (o) { return o !== b; }), on = 0, osun = 0;
        others.forEach(function (o) { on += o.n; osun += o.sun; });
        if (on < 3) return;
        var r = b.sun / b.n, ro = osun / on;
        if (r - ro >= 0.3 && (!best || r > best.r)) best = { b: b, r: r };
      });
      if (best) out.push(best.b.lab + 'の日は、' + best.b.n + '回中 ' + best.b.sun + '回 ☀ だったよ。きみに合った長さ かもしれへんな。');
      var cnt = [0, 0, 0, 0, 0, 0, 0];
      subs.forEach(function (s) { var w = wdOf(s.day_key); if (w >= 0) cnt[w]++; });
      var top = -1; for (var i = 0; i < 7; i++) if (top < 0 || cnt[i] > cnt[top]) top = i;
      if (top >= 0 && cnt[top] >= 3 && cnt[top] / subs.length >= 0.3) out.push(WD[top] + '曜日に よく とりくめているよ（さいきん ' + subs.length + '回のうち ' + cnt[top] + '回）。');
    }
    var ov = d.overview || {};
    if (out.length < 2 && Number(ov.maxStreak) >= 3) out.push('いちばん長く つづいたのは ' + ov.maxStreak + '日。つづける力が あるで。');
    return out.slice(0, 2);
  }

  function favWeekdays(d) {
    var cnt = [0, 0, 0, 0, 0, 0, 0];
    (d.recentSubmissions || []).forEach(function (s) { var w = wdOf(s.day_key); if (w >= 0) cnt[w]++; });
    var order = [1, 2, 3, 4, 5].sort(function (a, b) { return cnt[b] - cnt[a]; });
    return order.filter(function (w) { return cnt[w] > 0; });
  }

  // ✏️ AIの選択肢がない週だけ使う（記録から作る2つ）
  function fallbackTries(d, step, guide) {
    var out = [];
    if (!step) return out;
    var fw = favWeekdays(d);
    var day1 = fw.length ? WD[fw[0]] + '曜に' : 'あしたか あさってに';
    out.push(day1 + '、「' + step.info.name + '」を 5問 やってみる？');
    var sg = Number((d.student && d.student.grade) || 0) || null;
    var o = null;
    // 2つめ：さいきん（8週間以内）さわった 学年に近い単元。なければ、いま学年で習っているところ（ちがう教科を先に）
    var sm = (d.subjects || []).filter(function (s) { var inf = unitInfo(s.unit); return s.lastAt && daysAgo(s.lastAt) <= 56 && String(s.unit) !== step.info.id && inf && (!sg || inf.grade >= sg - 1); })
      .sort(function (a, b) { return String(b.lastAt).localeCompare(String(a.lastAt)); });
    if (sm.length) o = unitInfo(sm[0].unit);
    if (!o && guide) {
      var nw = (guide.nowUnits || []).map(function (x) { return { x: x, inf: unitInfo(x.unit) }; })
        .filter(function (z) { return z.inf && z.inf.id !== step.info.id && sg && z.inf.grade === sg && z.x.users >= 2 && isTaught(guide, z.inf.id); });
      nw.sort(function (a, b) { return (a.inf.subj !== step.info.subj ? 0 : 1) - (b.inf.subj !== step.info.subj ? 0 : 1) || b.x.users - a.x.users; });
      if (nw.length) o = nw[0].inf;
    }
    var day2 = fw.length > 1 ? WD[fw[1]] + '曜に' : '週の後半に';
    if (o) out.push(day2 + '、10分だけ「' + o.name + '」を やってみる？');
    else out.push(day2 + '、10分だけ 好きな単元を 1つ やってみる？');
    return out;
  }

  // 🔁 先週の「やってみる」（先週公開したカルテから取る）
  function lastPromise(d) {
    var hist = d.karteHist || [];
    if (!hist.length) return null;
    var cur = String(d.aiComment || '').trim();
    var i0 = 0;
    if (cur && String(hist[0].body || '').trim() === cur) i0 = 1;
    var prev = hist[i0];
    if (!prev) return null;
    var sp = splitAi(prev.body);
    if (sp.tries.length) return { tries: sp.tries.slice(0, 3), ask: '' };
    if (d.prevAsk) return { tries: [], ask: d.prevAsk };
    return null;
  }

  // ───────── 組み立て ─────────
  var CSS = [
    '.pg{height:271mm;overflow:hidden;break-after:page;page-break-after:always;position:relative;}',
    '.pg.last{break-after:auto;page-break-after:auto;}',
    '.mh{display:flex;align-items:center;justify-content:space-between;background:linear-gradient(135deg,#fef3c7,#fde68a);border-radius:14px;padding:8px 14px;margin-bottom:8px;}',
    '.mh h1{margin:0;font-size:20px;color:#b45309;} .mh .nm{font-size:16px;font-weight:800;color:#92400e;} .mh .pd{font-size:11px;color:#a16207;text-align:right;}',
    '.sec{padding:7px 12px !important;margin-bottom:7px !important;break-inside:avoid;} .sec h2{font-size:14.5px !important;margin:0 0 4px !important;}',
    '.pg .sec div[style*="font-size:24px"]{font-size:17px !important;}',
    '.pg ul.refl{margin:2px 0 !important;} .pg .refl li{margin:1px 0 !important;}',
    '.first{border:3px solid #f97316 !important;background:#fff7ed;}',
    '.first .path{display:flex;flex-wrap:wrap;align-items:center;gap:5px;margin:6px 0 4px;}',
    '.mchip{display:inline-block;border-radius:10px;padding:4px 10px;font-weight:800;font-size:14px;background:#fff;border:2px solid #fdba74;color:#9a3412;}',
    '.mchip.goal{background:#f97316;color:#fff;border-color:#f97316;}',
    '.arr{color:#fb923c;font-weight:900;}',
    '.why{font-size:11.5px;color:#9a3412;}',
    '.map{display:flex;align-items:stretch;gap:5px;flex-wrap:nowrap;margin:3px 0;}',
    '.st{flex:1;border-radius:10px;padding:5px 6px;font-size:12px;font-weight:800;text-align:center;line-height:1.25;background:#f1f5f9;color:#475569;}',
    '.st small{display:block;font-weight:600;font-size:10px;margin-top:2px;}',
    '.st.ok{background:#dcfce7;color:#15803d;} .st.doing{background:#fef9c3;color:#a16207;} .st.here{border:3px solid #f59e0b;background:#fffbeb;color:#b45309;}',
    '.box{display:inline-block;width:15px;height:15px;border:2px solid #64748b;border-radius:4px;vertical-align:-3px;margin-right:6px;}',
    '.ch{margin:5px 0;font-size:13px;}',
    '.circ{display:inline-block;border:1.5px solid #94a3b8;border-radius:12px;padding:0 9px;margin-left:5px;font-size:11.5px;}',
    '.line{border-bottom:1.5px dashed #94a3b8;height:26px;}',
    '.cutl{border-top:2px dashed #94a3b8;margin:10px 0 6px;padding-top:4px;font-size:10px;color:#94a3b8;text-align:center;}',
    '.home{font-size:12.5px;}',
    '.gr{display:flex;flex-wrap:wrap;gap:6px;align-items:flex-start;justify-content:space-around;}',
    '.gr .gt{font-size:11px;font-weight:700;color:#475569;margin-bottom:2px;text-align:center;}',
    'ul.refl li{margin:1px 0;}'
  ].join('\n');

  // 印刷する窓の中で、面からはみ出していたら その面だけ少しずつ縮める（フォントの差で数行あふれても切れないように）
  var FIT = '<script>(function(){function fit(){var ps=document.querySelectorAll(".pg");for(var i=0;i<ps.length;i++){var p=ps[i];if(p.getAttribute("data-fit"))continue;var z=1;while(p.scrollHeight>p.clientHeight+1&&z>0.8){z=Math.round((z-0.03)*100)/100;p.style.zoom=z;p.style.height=(271/z).toFixed(1)+"mm";}p.setAttribute("data-fit",String(z));}}try{fit();}catch(e){}window.addEventListener("load",function(){try{var ps=document.querySelectorAll(".pg");for(var i=0;i<ps.length;i++)ps[i].removeAttribute("data-fit");fit();}catch(e){}});})();<\/script>';
  function pickSec(doc, re) {
    var secs = doc.querySelectorAll('.sec');
    for (var i = 0; i < secs.length; i++) { var h = secs[i].querySelector('h2'); if (h && re.test(h.textContent || '')) return secs[i]; }
    return null;
  }

  function capWeekSec(sec) {
    if (!sec) return '';
    try {
      // 自分のことば：3つまで・1つ70字まで（紙を2ページに収めるための上限）
      var lis = sec.querySelectorAll('ul.refl li, ul li');
      for (var i = 0; i < lis.length; i++) { if (i >= 3) { lis[i].parentNode.removeChild(lis[i]); continue; } lis[i].textContent = cut(lis[i].textContent, 70); }
      // ふりかえり（よかったこと・自由記述など）：あわせて3行まで・1行70字まで
      var boxes = sec.querySelectorAll('div');
      for (var j = 0; j < boxes.length; j++) {
        var kids = boxes[j].children;
        if (!kids.length || !/ふりかえり/.test(kids[0].textContent || '') || kids[0].children.length) continue;
        var lines = [];
        for (var q = 1; q < kids.length; q++) lines.push(kids[q]);
        lines.forEach(function (el, idx) { if (idx >= 3) el.parentNode.removeChild(el); else el.textContent = cut(el.textContent, 70); });
      }
    } catch (e) {}
    return sec.outerHTML;
  }

  function compose(baseHtml) {
    var d = global._faData || {};
    var doc = new DOMParser().parseFromString(baseHtml, 'text/html');
    var styleM = baseHtml.match(/<style>([\s\S]*?)<\/style>/);
    var baseCss = styleM ? styleM[1] : '';
    var head = doc.querySelector('.head');
    var nm = head ? (head.querySelector('.nm') || {}).textContent || '' : '';
    var pd = head ? (head.querySelector('.pd') || {}).textContent || '' : '';
    var secWeek = pickSec(doc, /^📅/);
    try { var wh = secWeek && secWeek.querySelector('h2'); if (wh) { var mt = (wh.textContent || '').match(/(\d+月\d+日〜\d+月\d+日)/); if (mt) pd = mt[1] + ' を ふりかえって'; } } catch (e) {}
    var secHan = pickSec(doc, /阪神マン/);
    var secNotes = pickSec(doc, /先生からの記録/);
    var hanStale = secHan && /2週間以上/.test(secHan.textContent || '');
    var ai = (!hanStale && d.aiComment && String(d.aiComment).trim()) ? splitAi(d.aiComment) : null;
    var hanNote = '';
    try { var nn = secHan && secHan.querySelector('div[style*="font-size:10px"]'); hanNote = nn ? nn.textContent : ''; } catch (e) {}

    var guide = _guide[d.classId] || null;
    var step = firstStep(d, guide);
    var map = mathMap(d, step, guide);
    var cd = canDo(d);
    var hn = hints(d);
    var pr = lastPromise(d);
    var tries = (ai && ai.tries.length) ? ai.tries.slice(0, 3) : fallbackTries(d, step, guide);
    tries = tries.map(function (t) { return cut(t, 38); });

    var F = [], B = [];
    // ── おもて ──
    F.push('<div class="mh"><div><h1>🧭 学びの道しるべ</h1><div class="nm">' + esc(nm) + '</div></div><div class="pd">' + esc(pd) + '</div></div>');
    if (step) {
      var p = step.info;
      var h = '<div class="sec first"><h2 style="color:#c2410c">🧭 まずここから（' + (step.thin ? '今日' : '今週') + 'の さいしょの1歩）</h2>';
      h += '<div class="path"><span class="mchip">アプリの 🏋️修行</span><span class="arr">→</span><span class="mchip">' + esc(p.icon) + esc(p.subjName) + '</span><span class="arr">→</span><span class="mchip">' + esc(p.gradeLabel) + '</span><span class="arr">→</span><span class="mchip goal">「' + esc(p.name) + '」を ' + step.amount + '</span></div>';
      h += '<div class="why">（えらんだわけ：' + esc(step.why) + (step.mine && step.mine.total > 0 ? '。いままで ' + step.mine.total + '問 とりくんでいるよ' : '') + '）</div>';
      if (step.stalled) h += '<div style="font-size:12.5px;font-weight:700;color:#c2410c;margin-top:3px">5分で おわっても だいじょうぶ。1問 すすんだら、それが 前進やで。</div>';
      h += '</div>';
      F.push(h);
    }
    if (map) {
      var lab = { ok: '✅ できた', doing: 'とちゅう', mada: 'まだ' };
      var mh = '<div class="sec" style="border-color:#bae6fd;background:#f0f9ff"><h2>🗺 いまどこ？ 道順マップ（算数・' + esc(map.route) + 'の道）</h2><div class="map">';
      var seenHere = false, after = 0;
      map.nodes.forEach(function (n, i) {
        if (i) mh += '<span class="arr" style="align-self:center">→</span>';
        var tag;
        if (n.here) { tag = '📍 いまここ'; seenHere = true; }
        else if (!seenHere) tag = 'ひとつ前';
        else { after++; tag = after === 1 ? '🚩 つぎ' : 'そのつぎ'; }
        var stt = n.s && Number(n.s.total) > 0 ? '10問中' + of10(n.s.rate) + '問くらい' : lab[n.st];
        if (n.st === 'ok') stt = '✅ できた';
        mh += '<div class="st ' + n.st + (n.here ? ' here' : '') + '">' + esc(n.name) + '<small>' + esc(n.gl) + '｜' + tag + '</small><small>' + esc(stt) + '</small></div>';
      });
      mh += '</div>';
      if (map.back) mh += '<div style="font-size:12px;color:#0369a1;margin-top:3px">🔍 ' + esc(map.back) + '</div>';
      mh += '</div>';
      F.push(mh);
    }
    if (secWeek) F.push(capWeekSec(secWeek));
    if (pr) {
      var ph = '<div class="sec" style="border-color:#e9d5ff;background:#faf5ff"><h2>🔁 先週の「やってみる」どうだった？</h2>';
      if (pr.tries.length) {
        ph += '<div style="font-size:11.5px;color:#6b21a8">先週の紙にあったもの（えらんだものに ○）</div>';
        pr.tries.forEach(function (t) { ph += '<div class="ch" style="margin:2px 0"><span class="box"></span>' + esc(cut(t, 40)) + '</div>'; });
        ph += '<div style="font-size:12px;margin-top:3px">じぶんでは？<span class="circ">できた</span><span class="circ">ちょっと</span><span class="circ">まだ</span> <span style="font-size:10.5px;color:#94a3b8">（どれでも だいじょうぶ）</span></div>';
      } else {
        ph += '<div style="font-size:12.5px">先週きかれたこと …「' + esc(cut(pr.ask, 60)) + '」 どうやった？</div>';
      }
      ph += '</div>';
      F.push(ph);
    }
    if (ai && ai.main) {
      var hh = '<div class="sec"><h2>🐯 阪神マンから</h2><div style="font-size:12.5px;color:#334155;white-space:pre-wrap">' + esc(cut(ai.main.replace(/\n+/g, ' '), 300)) + '</div>';
      if (ai.ask) hh += '<div style="margin-top:5px;background:#fefce8;border-radius:8px;padding:5px 9px;font-size:12.5px">💭 <b>考えてみてほしいこと</b> … ' + esc(cut(ai.ask, 70)) + '</div>';
      if (hanNote) hh += '<div style="font-size:9.5px;color:#94a3b8;margin-top:3px">' + esc(hanNote) + '</div>';
      hh += '</div>';
      F.push(hh);
    } else if (secHan) {
      F.push(secHan.outerHTML);
    }

    // ── うら ──
    var th = '<div class="sec" style="border-color:#fda4af;background:#fff1f2"><h2>✏️ これやってみる？（1つ えらんで □ に○）</h2>';
    tries.forEach(function (t) { th += '<div class="ch"><span class="box"></span>' + esc(t) + '</div>'; });
    th += '<div class="ch"><span class="box"></span>じぶんで決める：<span style="display:inline-block;width:62%;border-bottom:1.5px dashed #94a3b8">&nbsp;</span></div>';
    th += '<div style="margin-top:4px;font-size:11.5px;color:#9f1239"><b>やり方も えらべるよ</b>（どれでもOK）<span class="circ">アプリの修行</span><span class="circ">ノートに書く</span><span class="circ">おうちの人に 問題を出してもらう</span></div></div>';
    B.push(th);
    if (cd.head || cd.lines.length) {
      var ch2 = '<div class="sec" style="border-color:#bbf7d0;background:#f0fdf4"><h2>🌟 できるようになったこと・やったこと</h2>';
      if (cd.head) ch2 += '<div style="font-size:12.5px;color:#15803d;font-weight:700">' + esc(cd.head) + '</div>';
      cd.lines.forEach(function (l) { ch2 += '<div style="font-size:12.5px">・' + l + '</div>'; });
      ch2 += '</div>';
      B.push(ch2);
    }
    if (hn.length) {
      var hh2 = '<div class="sec" style="border-color:#c7d2fe;background:#eef2ff"><h2>💡 きみに合う 学び方（記録から 見えたこと）</h2>';
      hn.forEach(function (l) { hh2 += '<div style="font-size:12.5px">・' + esc(l) + '</div>'; });
      B.push(hh2 + '</div>');
    }
    var gr = graphs(d);
    if (gr) B.push(gr);
    B.push('<div class="sec" style="border-color:#fcd34d"><h2>🎯 来週の わたしの めあて</h2><div class="line"></div><div class="line"></div></div>');
    if (secNotes) B.push(secNotes.outerHTML);
    if (ai && ai.home) {
      B.push('<div class="cutl">✂ ･････････････････････ きりとり ･････････････････････ ✂</div>' +
        '<div class="home"><div style="font-size:13px;font-weight:800;color:#0f766e">🏠 おうちの人へ</div><div>' + esc(cut(ai.home, 120)) + '</div>' +
        '<div style="font-size:9.5px;color:#94a3b8;margin-top:2px">' + esc(nm) + '／学びの道しるべ</div></div>');
    }

    var html = '<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>学びの道しるべ</title><style>' + baseCss + '\n' + CSS + '</style></head><body>' +
      '<div class="wrap"><div class="pg">' + F.join('') + '</div><div class="pg last">' + B.join('') + '<div class="foot">LearningBM ／ 学びの道しるべ</div></div></div>' + FIT + '</body></html>';
    return html;
  }

  function graphs(d) {
    if (typeof global._kRadar !== 'function' || typeof global._kBars !== 'function' || typeof global._kDonut !== 'function') return '';
    var ov = d.overview || {};
    var sg = Number((d.student && d.student.grade) || 0) || null;
    var areas = [{ key: 'jp', label: '国語' }, { key: 'math', label: '算数' }, { key: 'sci', label: '理科' }, { key: 'soc', label: '社会' }];
    var subjects = d.subjects || [];
    var agg = function (arr) { var tot = 0, cor = 0; arr.forEach(function (it) { var cc = (typeof it.correct === 'number') ? it.correct : Math.round((it.rate || 0) / 100 * (it.total || 0)); tot += (it.total || 0); cor += cc; }); return tot ? Math.round(cor / tot * 100) : null; };
    var radar = areas.map(function (a) {
      var all = subjects.filter(function (s) { return global._subjectArea(s.unit) === a.key; });
      var same = all.filter(function (s) { return sg && global._unitGrade(s.unit) === sg; });
      var v = agg(same); if (v == null) v = agg(all);
      return { label: a.label, value: v == null ? 0 : v, noData: v == null };
    });
    var bars = (d.monthlyTrends || []).slice(-6).map(function (m) { return { label: String(m.month || '').slice(5) + '月', value: m.count || 0 }; });
    if (!subjects.length && !bars.length) return '';
    var h = '<div class="sec"><h2>📊 4月からの 学習の 見える化</h2><div class="gr">';
    h += '<div><div class="gt">教科の定着（アプリの修行）</div>' + global._kRadar(radar) + '</div>';
    h += '<div><div class="gt">月ごとの 家庭学習の 回数</div>' + global._kBars(bars) + '</div>';
    h += '<div><div class="gt">きもちの わりあい</div>' + global._kDonut(ov.sunCount, ov.cloudCount, ov.rainCount) + '</div>';
    return h + '</div></div>';
  }

  // ───────── 差しかえ ─────────
  function install() {
    var orig = global._buildKarteHtml;
    if (typeof orig !== 'function' || orig.__michi) return false;
    var wrapped = function () {
      var base = orig.apply(this, arguments);
      try { return compose(base); } catch (e) { try { console.error('MICHI_V1 道しるべを作れなかったので、もとのカルテを出します', e); } catch (_e) {} return base; }
    };
    wrapped.__michi = true; wrapped.__orig = orig;
    global._buildKarteHtml = wrapped;
    // 全員ぶん：作る前に、クラスごとの材料を読んでおく
    var oa = global.downloadAllKartes;
    if (typeof oa === 'function' && !oa.__michi) {
      var wa = async function () { try { await preloadAll(); } catch (e) {} return oa.apply(this, arguments); };
      wa.__michi = true; global.downloadAllKartes = wa;
    }
    return true;
  }
  // ───────── HANSHIN_Q_V1 先生の画面：家庭学習 ②毎日の振り返り のいちばん上に「阪神マンへの返事」 ─────────
  var _hqCid = '', _hqAt = 0;
  function hqLoad(force) {
    var pane = document.getElementById('hwPane_daily');
    var sel = document.getElementById('hwClassFilter');
    if (!pane || !sel || !sel.value) return;
    if (pane.classList.contains('hidden') && !force) return;
    if (!force && _hqCid === sel.value && Date.now() - _hqAt < 60000) return;
    _hqCid = sel.value; _hqAt = Date.now();
    var box = document.getElementById('hqTeacherBox');
    if (!box) {
      box = document.createElement('div');
      box.id = 'hqTeacherBox';
      box.className = 'bg-amber-50 border-2 border-amber-300 rounded-xl p-3 shadow-sm';
      pane.insertBefore(box, pane.firstChild);
    }
    box.innerHTML = '<div class="text-xs text-slate-400">🐯 阪神マンへの返事を読み込み中...</div>';
    fetch('/api/teacher/class/' + encodeURIComponent(sel.value) + '/hanshin-answers', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        var it = (j && j.ok && j.items) || [];
        var h = '<div class="font-bold text-sm text-amber-800">🐯 阪神マンのしつもんへの返事 <span class="text-[11px] font-normal text-slate-500">（さいきん3週間・' + it.length + '件。次の「今日のひと往復」のコピーにも自動で入ります）</span></div>';
        if (!it.length) h += '<div class="text-xs text-slate-500 mt-1">まだ返事はありません。カルテを公開すると、子どもの画面に しつもんが出ます。</div>';
        else {
          h += '<div class="mt-2 space-y-1 max-h-72 overflow-y-auto">';
          it.forEach(function (x) {
            var nm = (typeof global.resolveStudentName === 'function') ? global.resolveStudentName(x.loginId, x.name) : (x.name || x.loginId || '');
            h += '<div class="bg-white rounded-lg border border-amber-200 p-2 text-sm"><div class="text-[11px] text-slate-500">' + esc(nm) + '｜' + esc(String(x.updatedAt || '').slice(5, 16)) + (x.rewarded ? '｜🪙済' : '') + '｜しつもん：' + esc(x.question || '') + '</div><div class="text-slate-800">' + esc(x.answer || '') + '</div></div>';
          });
          h += '</div>';
        }
        box.innerHTML = h;
      })
      .catch(function () { box.innerHTML = '<div class="text-xs text-red-500">阪神マンへの返事を読めませんでした</div>'; });
  }
  global.hqTeacherLoad = hqLoad;
  document.addEventListener('change', function (ev) { if (ev.target && ev.target.id === 'hwClassFilter') hqLoad(true); });
  setInterval(function () { try { hqLoad(false); } catch (e) {} }, 4000);

  global.michiCompose = compose;
  global.michiInstall = install;
  function boot() { install(); preloadAll(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
  // クラスの選択肢はあとから入るので、しばらく読み直す（1人ずつの印刷はポップアップの都合で待てないため）
  var tries_ = 0; var tm = setInterval(function () { tries_++; install(); preloadAll(); if (tries_ >= 6) clearInterval(tm); }, 5000);
  document.addEventListener('change', function (ev) { var id = ev.target && ev.target.id; if (id === 'analyticsClassFilter' || id === 'laClassSelect' || id === 'activityClassFilter') preloadAll(); });
})(window);
