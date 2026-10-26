/* ===================================================================
   karte-michi.js : 🧭 学びの道しるべ（印刷カルテ・A4両面）  MICHI_V1 / MICHI_V2 2026-10
   -------------------------------------------------------------------
   ・先生用ページの _buildKarteHtml を、この形に差しかえる。
     もとの関数はそのまま残し、まず もとの紙を作ってから 中の欄を取り出して並べ直す。
     途中で何か失敗したら、もとの紙をそのまま返す（紙が出なくなる事故を防ぐ）。
   ・おもて：🧭まずここから／🗺道順マップ（算数）／📅先週のようす／🔁先週のやってみる／🐯阪神マン
     うら　：✏️これやってみる？／🌟できるようになったこと／💡学び方／📊グラフ／🎯めあて／📝先生から
     （KANTAN_REF_V1 2026-10-26：✂おうちの人へ の欄は先生の判断でなくした。過去の文は消さず、表示しないだけ）
   ・1人ぶんは必ず2ページ（裏表1枚）。全員ぶん印刷で次の子が裏にずれないように、
     面ごとに高さを決めて、はみ出す分は欄ごとの行数上限で切る。
   ・テストの点数・順位・ほかの子との比較は出さない。命令しない。
     記録にないことは書かない（機械で作る欄は、記録から言えることだけ）。
   ・AIの文（阪神マン・考えてほしいこと・これやってみる）は
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
  function loadGuide(cid, fresh) {
    if (!cid) return Promise.resolve(null);
    if (_guide[cid] && !fresh && Date.now() - (_guide[cid]._at || 0) < 10 * 60000) return Promise.resolve(_guide[cid]);   // NOWUNIT_V1 10分で読み直す
    return fetch('/api/teacher/class/' + encodeURIComponent(cid) + '/karte-guide', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (j) { if (j && j.ok) { j._at = Date.now(); _guide[cid] = j; } return _guide[cid] || null; })
      .catch(function () { return null; });
  }
  // KANTAN_REF_V1 クラスの「ふりかえりの きっかけ」まわりの事実（アプリを開いた日など）。カルテの🌟と はじめの一歩に使う。
  var _watch = {};   // classId -> /api/teacher/class/:id/kantan-watch の結果
  function loadWatch(cid, fresh) {
    if (!cid) return Promise.resolve(null);
    if (_watch[cid] && !fresh && Date.now() - _watch[cid]._at < 5 * 60000) return Promise.resolve(_watch[cid]);
    return fetch('/api/teacher/class/' + encodeURIComponent(cid) + '/kantan-watch' + (fresh ? '?fresh=1' : ''), { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (j) { if (j && j.ok) { j._at = Date.now(); _watch[cid] = j; } return _watch[cid] || null; })
      .catch(function () { return null; });
  }
  function watchOf(d) {
    var w = d && _watch[d.classId], id = d && d.student && d.student.id;
    if (!w || !id) return null;
    var a = w.all || [];
    for (var i = 0; i < a.length; i++) if (a[i].userId === id) return a[i];
    return null;
  }
  global.michiWatchOf = watchOf;
  function preloadAll() {
    var ps = [loadCurriculum()];
    try {
      ['analyticsClassFilter', 'laClassSelect', 'activityClassFilter'].forEach(function (id) {
        var el = document.getElementById(id); if (!el) return;
        for (var i = 0; i < el.options.length; i++) { var v = el.options[i].value; if (v) { ps.push(loadGuide(v)); ps.push(loadWatch(v)); } }
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
    var _wt = watchOf(d);   /* KANTAN_REF_V1 きっかけが ほしそうな子は とくに小さく */
    var amount = (_wt && _wt.oneTap) ? '1問だけ' : thin ? '5問だけ' : (mineP && mineP.rate < 60 ? '5問' : '10問');
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
    if (!head && !out.length) {   /* KANTAN_REF_V1 記録が少なくても空にしない（言えるのは記録の事実だけ） */
      var wt = watchOf(d);
      var qAll = 0; (d.subjects || []).forEach(function (s) { qAll += Number(s.total || 0); });
      if (wt && Number(wt.openDays) > 0) out.push('この2週間で アプリを ' + Number(wt.openDays) + '日 ひらいたよ');
      if (wt && Number(wt.hwDays14) > 0) out.push('この2週間で 家庭学習を ' + Number(wt.hwDays14) + '日 出したよ');
      if (!out.length && Number(ov.totalSubmissions) > 0) out.push('これまでに 家庭学習を ' + Number(ov.totalSubmissions) + '回 出したよ');
      if (!out.length && qAll > 0) out.push('これまでに アプリで ' + qAll + '問 とりくんだよ');
      if (!out.length) out.push('アプリに 登録して、学びの道を 歩きはじめたよ');
    }
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
    out.push('「' + step.info.name + '」から はじめてみる？');   /* MICHI_V2B 曜日・問題数は本人が決める */
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
    if (o) out.push('「' + o.name + '」の つづきも いいかも');
    else out.push('すきな単元を 1つ えらんで やってみる？');
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

  // ═════════ MICHI_V2 えらべる3つの道（2026-10）═════════
  //  ・🅰 もう一度かためる／🅱 つぎに進む／🅲 じぶんで決める。どれを選ぶか・いつ・どれくらいは本人が○。
  //  ・💡わけ は記録から機械的に作る（期間と問題数つき）。記録の量も ◎○△ で出す。
  //  ・その教科の直近2週間が10問未満の子は、個別に推しはからず「教科書の順番」をスタート地点にする。
  //    先生が「いま授業でやっている単元」を設定する口は無いので、学年の標準的な進み方（下の表）で代用する。
  //  ・前の週の「このおすすめ、どう思う？」が かんたん→1つ先へ／むずかしい→1つ前へ ずらす。
  //  ・先生が差しかえたおすすめ（source='teacher'）は、それを使う。
  //  ・順位・平均・ほかの子との比較は出さない。比べるのは前のその子だけ。
  var MATH_PACE_ORDER = {
    1: ['m1-add-no', 'm1-sub-no', 'm1-3num', 'm1-add-cy', 'm1-sub-bo'],
    2: ['m2-add2', 'm2-sub2', 'm2-length', 'm2-kuku'],
    3: ['m3-div0', 'm3-divR', 'm3-large', 'm3-mul1', 'm3-weight'],
    4: ['division', 'long-division', 'rounding', 'brackets', 'area', 'decimal', 'fraction-mixed'],
    5: ['m5-volume', 'm5-dec-mul', 'm5-dec-div', 'm5-polygon', 'm5-frac-eq', 'm5-avg', 'm5-unit-qty', 'm5-speed', 'm5-percent'],
    6: ['m6-expression', 'm6-frac-int', 'm6-frac-mul', 'm6-frac-div', 'm6-frac-mixed', 'm6-frac-triple', 'm6-frac-dec', 'm6-ratio', 'm6-circle', 'm6-proportion']
  };
  // 月ごとの「だいたい いま授業でやっているところ」（一般的な年間指導計画から。学校ごとにずれるので目安）
  var MATH_PACE_MONTH = {
    1: { 4: 'm1-add-no', 5: 'm1-add-no', 6: 'm1-add-no', 7: 'm1-sub-no', 8: 'm1-sub-no', 9: 'm1-sub-no', 10: 'm1-3num', 11: 'm1-add-cy', 12: 'm1-sub-bo', 1: 'm1-sub-bo', 2: 'm1-sub-bo', 3: 'm1-sub-bo' },
    2: { 4: 'm2-add2', 5: 'm2-sub2', 6: 'm2-length', 7: 'm2-length', 8: 'm2-length', 9: 'm2-length', 10: 'm2-kuku', 11: 'm2-kuku', 12: 'm2-kuku', 1: 'm2-kuku', 2: 'm2-kuku', 3: 'm2-kuku' },
    3: { 4: 'm3-div0', 5: 'm3-div0', 6: 'm3-divR', 7: 'm3-large', 8: 'm3-large', 9: 'm3-mul1', 10: 'm3-mul1', 11: 'm3-weight', 12: 'm3-weight', 1: 'm3-weight', 2: 'm3-weight', 3: 'm3-weight' },
    4: { 4: 'division', 5: 'long-division', 6: 'long-division', 7: 'long-division', 8: 'long-division', 9: 'long-division', 10: 'rounding', 11: 'brackets', 12: 'area', 1: 'decimal', 2: 'decimal', 3: 'fraction-mixed' },
    5: { 4: 'm5-volume', 5: 'm5-dec-mul', 6: 'm5-dec-div', 7: 'm5-polygon', 8: 'm5-polygon', 9: 'm5-frac-eq', 10: 'm5-avg', 11: 'm5-unit-qty', 12: 'm5-speed', 1: 'm5-percent', 2: 'm5-percent', 3: 'm5-percent' },
    6: { 4: 'm6-expression', 5: 'm6-expression', 6: 'm6-frac-mul', 7: 'm6-frac-div', 8: 'm6-frac-div', 9: 'm6-ratio', 10: 'm6-circle', 11: 'm6-proportion', 12: 'm6-proportion', 1: 'm6-proportion', 2: 'm6-proportion', 3: 'm6-proportion' }
  };
  var SUBJ_LIST = ['math', 'japanese', 'social', 'science'];
  // 教科の中の順番（算数は上の標準の順番、ほかの教科はアプリの単元の並び）。学年をまたいで1本につなぐ。
  function subjOrder(subj) {
    var out = [];
    if (subj === 'math') { for (var g = 1; g <= 6; g++) out = out.concat(MATH_PACE_ORDER[g]); return out; }
    var C = _cur || global.CURRICULUM;
    var sub = C && C[subj];
    if (!sub || !sub.grades) return out;
    Object.keys(sub.grades).map(Number).sort(function (a, b) { return a - b; }).forEach(function (g) {
      if (g > 6) return;
      (sub.grades[g].units || []).forEach(function (u) { out.push(u.id); });
    });
    return out;
  }
  function jstNowM() { var n = new Date(); return new Date(n.getTime() + n.getTimezoneOffset() * 60000 + 9 * 3600000); }
  function md(iso) { var t = Date.parse(String(iso || '')); if (isNaN(t)) return ''; var x = new Date(t + 9 * 3600000); return (x.getUTCMonth() + 1) + '/' + x.getUTCDate(); }
  function isoWeekKey(dt) {
    var x = new Date(dt.getFullYear(), dt.getMonth(), dt.getDate()); var dn = (x.getDay() + 6) % 7; x.setDate(x.getDate() - dn + 3);
    var f = new Date(x.getFullYear(), 0, 4); var fn = (f.getDay() + 6) % 7; f.setDate(f.getDate() - fn + 3);
    var w = 1 + Math.round((x.getTime() - f.getTime()) / (7 * 86400000)); return x.getFullYear() + '-W' + (w < 10 ? '0' + w : '' + w);
  }
  function mastered(sm, id) { var s = sm[id]; return !!(s && Number(s.total) >= 10 && Number(s.rate) >= 80); }
  function entryOf(inf) { return 'アプリ：修行 ▶ ' + inf.subjName + ' ▶ ' + inf.gradeLabel + ' ▶「' + inf.name + '」'; }

  // MAEJIBUN_V1 振り返りに本人が書いた「来週やってみたいこと」（サーバーは16日以内の最新1件だけ返す）
  function nextTryOf(d) {
    var nt = d && d.nextTry;
    if (!nt || (!nt.text && !nt.unit)) return null;
    var cur = isoWeekKey(jstNowM());
    if (nt.weekKey && String(nt.weekKey) > cur) return null;
    var inf = nt.unit ? unitInfo(nt.unit) : null;
    var nm = inf ? inf.name : (nt.unitName || '');
    var q = cut(nt.text || nm, 30);
    var showNm = nm && !(nt.text && String(nt.text).indexOf(nm) >= 0);   // 一言に単元名が入っていれば重ねない
    var say = cut((showNm ? '「' + nm + '」' : '') + (nt.text ? (showNm ? ' ' : '') + nt.text : ''), 46);
    var from = (nt.weekKey && nt.weekKey === cur ? 'ふりかえりで' : '先週の') + ' あなたが『' + q + '』と 書いていたよ';
    return { unit: inf ? inf.id : '', unitName: nm, text: cut(nt.text || '', 40), say: say, from: from, weekKey: nt.weekKey || '' };
  }
  global.michiNextTryOf = nextTryOf;

  // ═════════ NOWUNIT_V1 クラスの「いまの単元」（教科ごと・2026-10-26）═════════
  //  決め方（上から順に、あるものを使う）：
  //   ① 先生が手で選んだもの（分析タブの「📍 いまの単元」。選んだら次に変えるまで有効）
  //   ② ⑥授業メモの「教科：単元」の いちばん新しい行（直近28日）。アプリの単元名に照合できたときだけ
  //   ③ クラスの子が まとめて取り組んでいる単元（直近1週で3人以上・15問以上 → なければ直近2週で3人以上・30問以上）
  //   ④ 算数だけ：標準の進み方（月ごとの目安）
  //  ・その学年の単元だけ（学年外・中学の単元は使わない）。
  var JP2SUBJ = { '算数': 'math', '国語': 'japanese', '社会': 'social', '理科': 'science' };
  var NOW_SRC_LABEL = { manual: '先生が選んだ', memo: '授業メモから', auto: 'クラスの記録から（自動）', std: '標準の進み方（目安）' };
  function normName(s) { return String(s || '').replace(/[（(][^）)]*[）)]/g, '').replace(/[\s　・「」『』、。．.:：]/g, '').replace(/の/g, ''); }
  function gradeUnits(subj, sg) { return subjOrder(subj).filter(function (id) { var inf = unitInfo(id); return !!(inf && inf.subj === subj && inf.grade === sg); }); }
  function matchTheme(subj, sg, theme) {
    // 授業メモの単元名 → アプリの単元。重なった文字数がいちばん多いもの（名前がまるごと入る／2文字ずつの重なりが6割以上）
    var t = normName(theme); if (!t) return '';
    var best = '', bs = 0;
    gradeUnits(subj, sg).forEach(function (id) {
      var n = normName(unitInfo(id).name); if (!n) return;
      var sc = 0;
      if (t.indexOf(n) >= 0 || (t.length >= 2 && n.indexOf(t) >= 0)) sc = Math.min(n.length, t.length) + 0.5;
      else if (n.length >= 3) {
        var cov = {}, hit = 0, ng = n.length - 1;
        for (var i = 0; i + 1 < n.length; i++) if (t.indexOf(n.slice(i, i + 2)) >= 0) { hit++; cov[i] = 1; cov[i + 1] = 1; }
        if (hit >= 2 && hit / ng >= 0.6) sc = Object.keys(cov).length;
      }
      if (sc > bs) { bs = sc; best = id; }
    });
    return best;
  }
  function resolveNow(guide, sg, subj) {
    sg = Number(sg || 0);
    if (!sg || sg > 6) return null;
    var ok = function (id) { var inf = unitInfo(id); return (inf && inf.subj === subj && inf.grade === sg) ? inf : null; };
    var g = guide || {};
    var m = g.nowManual && g.nowManual[subj];
    if (m && m.unit && ok(m.unit)) return { id: String(m.unit), src: 'manual', at: m.updatedAt || '' };
    var mt = g.memoTopics || [];
    for (var i = 0; i < mt.length; i++) {
      if (JP2SUBJ[mt[i].subj] !== subj) continue;
      var mid = matchTheme(subj, sg, mt[i].theme);   // いちばん新しい行だけ見る（照合できなければ使わない）
      if (mid) return { id: mid, src: 'memo', theme: mt[i].theme, at: mt[i].dayKey || '' };
      break;
    }
    var nu = (g.nowUnits || []).map(function (x) { return { x: x, inf: ok(x.unit) }; }).filter(function (z) { return !!z.inf; });
    var p7 = nu.filter(function (z) { return Number(z.x.users7 || 0) >= 3 && Number(z.x.n7 || 0) >= 15; }).sort(function (a, b) { return b.x.users7 - a.x.users7 || b.x.n7 - a.x.n7; })[0];
    if (p7) return { id: p7.inf.id, src: 'auto', users: Number(p7.x.users7), n: Number(p7.x.n7), days: 7 };
    var p14 = nu.filter(function (z) { return Number(z.x.users || 0) >= 3 && Number(z.x.n || 0) >= 30; }).sort(function (a, b) { return b.x.users - a.x.users || b.x.n - a.x.n; })[0];
    if (p14) return { id: p14.inf.id, src: 'auto', users: Number(p14.x.users), n: Number(p14.x.n), days: 14 };
    if (subj === 'math' && MATH_PACE_ORDER[sg]) {
      var mo = jstNowM().getMonth() + 1;
      var cur = (MATH_PACE_MONTH[sg] || {})[mo] || MATH_PACE_ORDER[sg][0];
      if (ok(cur)) return { id: cur, src: 'std' };
    }
    return null;
  }
  global.michiResolveNow = resolveNow;

  function computeReco(d, guideArg) {
    var sg = Number((d.student && d.student.grade) || 0) || null;
    if (!sg || sg > 6) return null;
    var guide = guideArg || (d && d.classId ? _guide[d.classId] : null) || null;
    var sm = subjMap(d);
    var ru = {}; (d.recentUnits || []).forEach(function (r) { ru[String(r.unit)] = r; });
    // 教科ごとの直近2週間の問題数（その学年の単元だけ）
    var tot = {}; SUBJ_LIST.forEach(function (k) { tot[k] = 0; });
    (d.recentUnits || []).forEach(function (r) { var inf = unitInfo(r.unit); if (inf && tot[inf.subj] != null && inf.grade === sg) tot[inf.subj] += Number(r.n || 0); });
    var override = null;
    try {
      var kr = d.karteReco;
      if (kr && kr.source === 'teacher' && kr.reco && kr.reco.anchor && daysAgo(String(kr.updatedAt).replace(' ', 'T') + 'Z') <= 10) override = kr.reco;
    } catch (e) {}
    var thisWeek = isoWeekKey(jstNowM());
    var subj, rich, anchor, note = '';
    var nt = nextTryOf(d);   /* MAEJIBUN_V1 */
    var npick = null;        // 本人がえらんだ単元（先生の差しかえが無いときだけ 🅰🅱 に優先）
    if (!override && nt && nt.unit) { var _pi = unitInfo(nt.unit); if (_pi && _pi.grade === sg && SUBJ_LIST.indexOf(_pi.subj) >= 0) npick = _pi; }
    var nowBy = {}; SUBJ_LIST.forEach(function (k) { nowBy[k] = resolveNow(guide, sg, k); });
    if (override && unitInfo(override.anchor)) {
      subj = unitInfo(override.anchor).subj; anchor = override.anchor; rich = (tot[subj] || 0) >= 10;
    } else if (npick) {
      subj = npick.subj; anchor = npick.id; rich = (tot[subj] || 0) >= 10;
    } else {
      // 教科：記録がある子は とりくんでいる教科（算数を先に）。いまの単元が わかる教科を先に。
      var many = SUBJ_LIST.filter(function (k) { return tot[k] >= 10; });
      var many2 = many.filter(function (k) { return !!nowBy[k]; });
      var pickSubj = function (arr) { if (arr.indexOf('math') >= 0) return 'math'; var b = null; arr.forEach(function (k) { if (!b || tot[k] > tot[b]) b = k; }); return b; };
      if (many2.length) subj = pickSubj(many2);
      else if (many.length) subj = pickSubj(many);
      else {
        // 記録が少ない子：先生が示した教科（手で選んだ・授業メモ）→ 算数
        var told = SUBJ_LIST.filter(function (k) { return nowBy[k] && (nowBy[k].src === 'manual' || nowBy[k].src === 'memo'); });
        subj = (told.length && told.indexOf('math') < 0) ? told[0] : 'math';
      }
      rich = (tot[subj] || 0) >= 10;
    }
    var order = subjOrder(subj);
    var gradeOf = function (id) { var inf = unitInfo(id); return inf ? inf.grade : 99; };
    var A, Bn, why = { a: '', b: '' }, now = null;
    // 前の週の返事でずらす（同じ教科のときだけ・その学年の中だけ）
    var fb = d.recoFeedback, fbShift = false;
    if (!override && !npick && fb && fb.unit && fb.subj === subj && daysAgo(String(fb.createdAt).replace(' ', 'T') + 'Z') <= 14) {
      var fi = order.indexOf(fb.unit);
      if (fi >= 0 && fb.choice === 'easy' && fi + 1 < order.length && gradeOf(order[fi + 1]) === sg) { anchor = order[fi + 1]; fbShift = true; note = '先週「かんたんすぎ」だったので、1つ先に すすめたよ'; }
      else if (fi >= 0 && fb.choice === 'hard' && fi - 1 >= 0 && gradeOf(order[fi - 1]) === sg) { anchor = order[fi - 1]; fbShift = true; note = '先週「むずかしすぎ」だったので、1つ前から にしたよ'; }
      else if (fb.choice === 'other') note = '先週「ちがうのがいい」だったので、🅲 で じぶんで 決めてみてね';
    }
    var wrongOf = function (id) {
      var r = ru[id]; var w = r ? Math.max(0, Number(r.n || 0) - Number(r.c || 0)) : 0;
      var s = sm[id]; var wa = s ? Math.round(Number(s.total || 0) * (100 - Number(s.rate || 0)) / 100) : 0;
      return w * 3 + Math.min(Math.max(0, wa), 30);
    };
    var useNow = !override && !npick && !fbShift && !!nowBy[subj];
    if (useNow) {
      // ── NOWUNIT_V1 いまの単元 を中心に：🅱＝いまの単元（十分なら その次）／🅰＝いまの単元か その1つ前で まちがいが多いほう
      now = nowBy[subj];
      var gu = gradeUnits(subj, sg), ni = gu.indexOf(now.id);
      var prevId = ni > 0 ? gu[ni - 1] : null, prev2 = ni > 1 ? gu[ni - 2] : null;
      var nextId = null; for (var j0 = (ni >= 0 ? ni + 1 : 0); j0 < gu.length; j0++) { if (gu[j0] !== now.id && !mastered(sm, gu[j0])) { nextId = gu[j0]; break; } }
      var rNow = ru[now.id], nowWrongRecent = rNow ? Number(rNow.n || 0) - Number(rNow.c || 0) : 0;
      if (mastered(sm, now.id)) Bn = nextId;
      else if (nowWrongRecent >= 2 && wrongOf(now.id) > (prevId ? wrongOf(prevId) : -1) && nextId) Bn = nextId;   // いまの単元で つまずき中 → 🅰で かためる
      else Bn = now.id;
      var pref = function (id) { return id === prevId ? 0 : id === now.id ? 1 : 2; };
      var cands = [now.id, prevId].filter(function (x) { return x && x !== Bn; });
      cands.sort(function (a, b) { return (mastered(sm, a) ? 1 : 0) - (mastered(sm, b) ? 1 : 0) || wrongOf(b) - wrongOf(a) || pref(a) - pref(b); });   // よくできている単元は あとに
      // 同じ単元が 何週も つづかないように：先週（自動で作ったもの）の🅰と同じなら、もう1つの候補へ
      var last = d.karteReco, lastA = '';
      try { if (last && last.source !== 'teacher' && last.weekKey && last.weekKey !== thisWeek && last.reco && last.reco.a) lastA = String(last.reco.a.id || ''); } catch (e) {}
      if (lastA && cands[0] === lastA) {
        var alt = cands.slice(1).concat(prev2 && prev2 !== Bn ? [prev2] : []).filter(function (x) { return x && x !== lastA; });
        if (alt.length) { cands = alt.concat([lastA]); note = note || '先週と ちがう 単元も まぜてみたよ'; }
      }
      A = cands[0] || null;
      if (!A) { A = now.id; if (Bn === now.id) Bn = nextId; }
      if (Bn === A) Bn = null;
      anchor = A;
    }
    if (!useNow && !anchor && rich) {
      var cand = (d.recentUnits || []).filter(function (r) { var inf = unitInfo(r.unit); return inf && inf.subj === subj && Number(r.n) >= 5 && order.indexOf(inf.id) >= 0 && inf.grade === sg; });
      var weak = cand.filter(function (r) { return Number(r.c) / Number(r.n) < 0.8; });
      var pick = weak[0] || cand[0] || null;
      if (pick) anchor = String(pick.unit); else rich = false;
    }
    if (!useNow && !rich && !anchor) {
      // 記録が少ない・いまの単元も わからない：教科書の順番どおり（算数の標準の進み方。いまの月の単元と、その1つ前）
      subj = 'math'; order = subjOrder('math');
      var mo = jstNowM().getMonth() + 1;
      var cur = (MATH_PACE_MONTH[sg] || {})[mo] || MATH_PACE_ORDER[sg][0];
      var ci = order.indexOf(cur);
      A = (ci > 0 && gradeOf(order[ci - 1]) === sg) ? order[ci - 1] : cur; Bn = A === cur ? null : cur; anchor = cur;
    }
    var pickSlot = '';
    if (npick) {   /* MAEJIBUN_V1 本人がえらんだ単元をどこに置くか（記録がある→🅰でかためる／まだ→🅱ですすむ） */
      var pi2 = order.indexOf(npick.id), pS = sm[npick.id];
      A = null; Bn = null;
      if (pi2 < 0) { A = npick.id; pickSlot = 'a'; Bn = '__none__'; }
      else if (!(pS && Number(pS.total) > 0) && pi2 - 1 >= 0 && gradeOf(order[pi2 - 1]) === sg) { A = order[pi2 - 1]; Bn = npick.id; pickSlot = 'b'; }
      else { anchor = npick.id; pickSlot = 'a'; }
      note = '「' + npick.name + '」は あなたが えらんだので、いちばんに 入れたよ';
    }
    if (Bn === '__none__') Bn = null;
    else if (!useNow && (!A || !Bn)) {
      var ai = order.indexOf(anchor);
      A = anchor;
      Bn = null;
      for (var j = ai + 1; j < order.length; j++) { if (!mastered(sm, order[j]) && gradeOf(order[j]) === sg && isTaught(guide, order[j])) { Bn = order[j]; break; } }
      if (!Bn) { for (var j2 = 0; j2 < order.length; j2++) { if (order[j2] !== A && gradeOf(order[j2]) === sg && !mastered(sm, order[j2]) && isTaught(guide, order[j2])) { Bn = order[j2]; break; } } }
    }
    var iA = unitInfo(A), iB = Bn ? unitInfo(Bn) : null;
    if (!iA) return null;
    var rA = ru[A], rB = Bn ? ru[Bn] : null;
    var period = function (r) { return r ? '（' + md(r.firstAt) + '〜' + md(r.lastAt) + '）' : ''; };
    var rec = function (id, r) {   // 記録のひとこと（短く）
      if (r && Number(r.n) > 0) return Number(r.n) + '問中 ' + Number(r.c) + '問 できたよ';
      if (sm[id] && Number(sm[id].total) > 0) return 'これまで ' + sm[id].total + '問 とりくんでいるよ';
      return '';
    };
    var fit = function (s, extra) { return (extra && (s + extra).length <= 76) ? s + extra : s; };
    if (useNow) {
      var iN = unitInfo(now.id), nn = iN ? iN.name : '';
      var real = now.src !== 'std';
      var nowPh = real ? 'いま 授業で やっている「' + nn + '」' : '教科書で いま 習う ころの「' + nn + '」';
      if (A === now.id) {
        var ra = rec(A, rA);
        why.a = fit(nowPh + 'を かためよう' + (ra ? '。' + ra : ''), rA ? period(rA) : '');
      } else {
        var ra2 = rec(A, rA);
        why.a = fit('「' + iA.name + '」は ' + nowPh + 'の 1つ前の 単元だよ' + (ra2 ? '。' + ra2 : ''), rA ? period(rA) : '');
        if (why.a.length > 76) why.a = '「' + iA.name + '」は ' + nowPh + 'の 1つ前だよ' + (ra2 ? '。' + ra2 : '');
      }
      if (iB) {
        if (Bn === now.id) why.b = real ? ('「' + iB.name + '」は いま 授業で やっている 単元だよ' + (rB && Number(rB.n) > 0 ? '。さいきん ' + rB.n + '問 とりくんでいるよ' : '。はじめの 1問から いってみよう')) : ('「' + iB.name + '」は 教科書の 順番で、いま ' + iB.gradeLabel + 'で 習う ころの 単元だよ');
        else if (mastered(sm, now.id)) why.b = '「' + nn + '」は よく できているので、つぎに 習う「' + iB.name + '」へ すすもう';
        else why.b = '「' + iB.name + '」は ' + nowPh + 'の つぎに 習う 単元だよ';
      }
    } else {
      if (rA && Number(rA.n) > 0) {
        var wrong = Number(rA.n) - Number(rA.c);
        why.a = wrong >= 2 ? ('「' + iA.name + '」は ' + rA.n + '問中 ' + rA.c + '問 できたよ' + period(rA) + '。のこりの ' + wrong + '問を かためると、もっと つよくなるで') : ('「' + iA.name + '」は ' + rA.n + '問中 ' + rA.c + '問 できていたよ' + period(rA) + '。しっかり かためるのも いいかも');
      } else if (sm[A] && Number(sm[A].total) > 0) {
        why.a = '「' + iA.name + '」は これまで ' + sm[A].total + '問 とりくんでいるよ';
      } else {
        why.a = rich ? '「' + iA.name + '」は つぎに むかう 前の 土台だよ' : '「' + iA.name + '」は 教科書で 1つ前に 習う ところだよ';
      }
      if (iB) {
        if (!rich && Bn === anchor) why.b = '「' + iB.name + '」は 教科書の 順番で、いま ' + iB.gradeLabel + 'で 習う ころの 単元だよ';
        else if (rB && Number(rB.n) > 0) why.b = '「' + iB.name + '」は さいきん ' + rB.n + '問。つづきから すすめるよ';
        else if (sm[Bn] && Number(sm[Bn].total) > 0) why.b = '「' + iB.name + '」は これまで ' + sm[Bn].total + '問。つづきから すすめるよ';
        else why.b = '「' + iB.name + '」は 「' + iA.name + '」の つぎに 習う 単元だよ';
      }
    }
    if (pickSlot === 'a') why.a = 'あなたが えらんだ 単元。' + ((rA && Number(rA.n) > 0) || (sm[A] && Number(sm[A].total) > 0) ? why.a.replace(/^「[^」]*」(は|で)\s*/, '') : 'はじめの 1問から ためしてみる？');
    if (pickSlot === 'b' && iB) why.b = 'あなたが えらんだ 単元。' + why.b.replace(/^「[^」]*」(は|で)\s*/, '');
    var n14 = tot[subj] || 0;
    var mark;
    if (override) mark = '✎ 先生が えらんだ おすすめだよ';
    else if (npick) mark = '🎯 あなたが えらんだ 単元から 作ったよ' + (rich ? '（さいきん2週間の ' + n14 + '問の記録も 見たよ）' : '');
    else if (useNow && now.src !== 'std') mark = '📍 いま 授業で やっている 単元から えらんだよ' + (rich ? '（さいきん2週間の ' + n14 + '問の記録も 見たよ）' : '');
    else if (useNow) mark = rich ? '📍 教科書の 順番（いま 習う ころ）と、さいきん2週間の ' + n14 + '問の記録から えらんだよ' : '△ 教科書の順番どおりの おすすめだよ（記録が ふえると、あなたに合わせた おすすめに なるよ）';
    else mark = !rich ? '△ 教科書の順番どおりの おすすめだよ（記録が ふえると、あなたに合わせた おすすめに なるよ）' : (n14 >= 30 ? '◎ たくさんの記録から えらんだよ（さいきん2週間で ' + n14 + '問）' : '○ さいきん2週間の ' + n14 + '問の記録から えらんだよ');
    var here = useNow ? now.id : ((rich || override || npick) ? A : (Bn || A));
    return {
      v: 3, subj: subj, subjName: iA.subjName, anchor: A, here: here, rich: rich, override: !!override, pick: npick ? npick.id : '',
      now: (useNow && now) ? { id: now.id, name: (unitInfo(now.id) || {}).name || '', src: now.src } : null,   /* NOWUNIT_V1 */
      a: { id: A, name: iA.name, entry: entryOf(iA), why: why.a },
      b: iB ? { id: Bn, name: iB.name, entry: entryOf(iB), why: why.b } : null,
      mark: mark, note: note, weekKey: thisWeek,
      c: nt ? { say: nt.say, from: nt.from, unit: nt.unit, text: nt.text, weekKey: nt.weekKey } : null   /* MAEJIBUN_V1 🅲 に最初から入れることば */
    };
  }
  global.michiComputeReco = computeReco;

  // すすみぐあいマップ：できた✓／いまここ📍／つぎ の3まいだけ（🅰🅱と同じ教科）
  function progressMap(d, reco) {
    if (!reco) return '';
    var here = reco.here || reco.anchor;
    var sm = subjMap(d), order = subjOrder(reco.subj), i = order.indexOf(here);
    var cards = [];
    if (i > 0 && mastered(sm, order[i - 1])) cards.push({ k: 'done', id: order[i - 1] });
    cards.push({ k: 'here', id: here });
    if (reco.b && reco.b.id !== here) cards.push({ k: 'next', id: reco.b.id });
    else if (i >= 0 && i + 1 < order.length) cards.push({ k: 'next', id: order[i + 1] });
    var LAB = { done: 'できた ✓', here: 'いま ここ 📍', next: 'つぎ' };
    var h = '<div class="sec mp"><h2 style="color:#075985">📍 ' + esc(reco.subjName) + 'の すすみぐあい <span style="font-size:11px;font-weight:600;color:#0369a1">（左から じゅんばんに すすむよ）</span></h2><div class="mr">';
    cards.forEach(function (c, k) {
      var inf = unitInfo(c.id) || { name: c.id };
      var m = String(inf.name).match(/^(.*?)\s*\((.*)\)$/);
      if (k) h += '<div class="mar">▶</div>';
      h += '<div class="mc ' + c.k + '"><div class="ml">' + LAB[c.k] + '</div><div class="mb"><span class="mn">' + esc(m ? m[1] : inf.name) + '</span>' + (m ? '<span class="ms">（' + esc(m[2]) + '）</span>' : '') + '</div></div>';
    });
    return h + '</div></div>';
  }

  function pathsHtml(reco, stalled, small) {
    var h = '<div class="sec first"><h2 style="color:#c2410c">🧭 えらべる 3つの道 <span style="font-size:12px;font-weight:700">（どれでも いいよ。どれに する？）</span></h2>';
    h += '<div class="pw"><span class="pk">🅰</span><div><b>もう一度 かためる</b>：「' + esc(reco.a.name) + '」の ふくしゅうも いいかも<div class="pe">' + esc(reco.a.entry) + '</div><div class="py">💡わけ：' + esc(cut(reco.a.why, 76)) + '</div></div></div>';
    if (reco.b) h += '<div class="pw"><span class="pk">🅱</span><div><b>つぎに すすむ</b>：「' + esc(reco.b.name) + '」の はじめに いってみる？<div class="pe">' + esc(reco.b.entry) + '</div><div class="py">💡わけ：' + esc(cut(reco.b.why, 76)) + '</div></div></div>';
    if (reco.c && reco.c.say) h += '<div class="pw"><span class="pk">🅲</span><div><b>じぶんで 決める</b>：<span class="cw">' + esc(cut(reco.c.say, 46)) + '</span><div class="py">💬 ' + esc(cut(reco.c.from, 48)) + '（かえても いいよ）</div></div></div>';   /* MAEJIBUN_V1 */
    else h += '<div class="pw"><span class="pk">🅲</span><div><b>じぶんで 決める</b>：<span class="bl" style="width:300px">&nbsp;</span></div></div>';
    h += '<div class="pm">' + esc(reco.mark) + (reco.note ? '　／　' + esc(reco.note) : '') + '</div>';
    h += '<div class="pr"><b>えらんだのは</b><span class="circ">A</span><span class="circ">B</span><span class="circ">C</span>　<b>そのわけ：</b><span class="bl" style="width:250px">&nbsp;</span></div>';
    h += '<div class="pr"><b>いつ？</b>' + ['月', '火', '水', '木', '金'].map(function (x) { return '<span class="cc">' + x + '</span>'; }).join('') + '　<b>どれくらい？</b>' + (small ? ['1問', '3問', '5問'] : ['3問', '5問', '10問']).map(function (x) { return '<span class="circ">' + x + '</span>'; }).join('') + '<span style="font-size:10.5px;color:#9a3412">（じぶんで ○）</span></div>';
    if (small) h += '<div class="pr">👣 <b>はじめの一歩</b>：アプリを ひらいて「' + esc(cut(reco.a.name, 20)) + '」を 1問だけ（5分で おわる 大きさ）。1問 といたら、それで 前進やで</div>';   /* KANTAN_REF_V1 */
    else h += '<div class="pr">👣 <b>はじめの一歩</b>：まずは いちばん かんたんな 1問だけ（5分で できる 大きさ）' + (stalled ? '。1問 すすんだら それで 前進やで' : '') + '</div>';
    h += '<div class="pr">🛟 <b>こまったら作戦</b>：もし わからない問題が出たら→<span class="circ sm">ヒントを見る</span><span class="circ sm">友だちに聞く</span><span class="circ sm">先生に聞く</span><span class="circ sm">家の人に聞く</span></div>';
    h += '<div class="pr pf"><b>このおすすめ、どう思う？</b><span class="bx">□ぴったり</span><span class="bx">□かんたんすぎ</span><span class="bx">□むずかしすぎ</span><span class="bx">□ちがうのがいい</span></div>';
    return h + '</div>';
  }

  // 印刷のときに おすすめを保存（子どもの「わたしのカルテ」で「どう思う？」に答えられるように）
  var _recoQ = [], _recoT = null;
  function queueReco(userId, reco) {
    if (!userId || !reco || reco.override) return;
    _recoQ.push({ userId: userId, weekKey: reco.weekKey, reco: reco, source: 'auto' });
    if (_recoT) clearTimeout(_recoT);
    _recoT = setTimeout(flushReco, 1200);
  }
  function flushReco() {
    _recoT = null;
    if (!_recoQ.length) return;
    var items = _recoQ.splice(0, 80);
    try { fetch('/api/teacher/karte-recos', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ items: items }) }).catch(function () {}); } catch (e) {}
    if (_recoQ.length) _recoT = setTimeout(flushReco, 500);
  }
  global.michiSaveReco = function (userId, reco, source) {
    return fetch('/api/teacher/karte-recos', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ items: [{ userId: userId, weekKey: reco.weekKey, reco: reco, source: source || 'teacher' }] }) }).then(function (r) { return r.json(); });
  };
  var CSS2 = [
    '.first .pw{display:flex;gap:7px;align-items:flex-start;margin:3px 0;font-size:12.5px;line-height:1.45;}',
    '.first .pk{font-size:17px;line-height:1.1;} .first .pe{font-size:11px;color:#7c2d12;} .first .py{font-size:11px;color:#9a3412;}',
    '.first .pm{font-size:11px;color:#475569;margin:3px 0 2px;} .first .pr{font-size:12px;margin:4px 0;}',
    '.first .cc{display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border:1.5px solid #fb923c;border-radius:50%;margin-left:4px;font-size:11.5px;font-weight:800;color:#9a3412;}',
    '.first .bl{display:inline-block;border-bottom:1.5px dashed #94a3b8;margin-left:4px;}',
    '.first .cw{font-weight:800;color:#7c2d12;border-bottom:1.5px dashed #fb923c;padding:0 2px;}',
    '.first .bx{margin-left:8px;font-size:12px;} .first .pf{border-top:1px dashed #fdba74;padding-top:4px;} .first .circ.sm{font-size:10.5px;padding:0 6px;margin-left:3px;}',
    '.mp{border-color:#bae6fd !important;background:#f0f9ff;} .mr{display:flex;align-items:stretch;gap:6px;}',
    '.mar{align-self:center;font-size:16px;color:#7dd3fc;font-weight:900;}',
    '.mc{flex:1;border-radius:10px;overflow:hidden;background:#fff;border:2px solid #e2e8f0;text-align:center;}',
    '.mc .ml{font-size:13.5px;font-weight:900;padding:3px 0;color:#fff;} .mc.done .ml{background:#16a34a;} .mc.here .ml{background:#f59e0b;} .mc.next .ml{background:#64748b;}',
    '.mc.here{border:3px solid #f59e0b;} .mc .mb{padding:5px 4px 6px;} .mc .mn{display:block;font-size:15px;font-weight:900;color:#1e293b;} .mc .ms{display:block;font-size:10px;color:#64748b;}'
  ].join('\n');

  // ───────── 先生の画面：印刷の前に おすすめを確認・差しかえ ─────────
  function recoPanel() {
    var st = document.getElementById('allAiStatus');
    if (!st || document.getElementById('michiRecoBtn')) return;
    var b = document.createElement('button');
    b.id = 'michiRecoBtn'; b.type = 'button';
    b.textContent = '🧭 印刷の前に「えらべる3つの道」を確認・差しかえ';
    b.className = 'bg-orange-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow ml-2';
    b.onclick = openRecoPanel;
    st.parentNode.insertBefore(b, st);
  }
  async function openRecoPanel() {
    var box = document.getElementById('michiRecoBox');
    var st = document.getElementById('allAiStatus');
    if (!box) { box = document.createElement('div'); box.id = 'michiRecoBox'; box.className = 'mt-2 bg-orange-50 border-2 border-orange-300 rounded-xl p-3 text-sm'; st.parentNode.insertBefore(box, st.nextSibling); }
    var students = global._lastStudentSummaries || [];
    if (!students.length) { box.innerHTML = '先に児童一覧を表示してください'; return; }
    box.innerHTML = '読み込み中...';
    await preloadAll();
    var rows = [];
    for (var i = 0; i < students.length; i++) {
      var s = students[i];
      try {
        var r = await fetch('/api/teacher/student-full-analysis?studentId=' + encodeURIComponent(s.userId || s.name), { credentials: 'same-origin' });
        var d = await r.json();
        if (d && d.ok) rows.push({ s: s, d: d, reco: computeReco(d) });
      } catch (e) {}
      box.innerHTML = '読み込み中...(' + (i + 1) + '/' + students.length + ')';
    }
    var FB = { fit: 'ぴったり', easy: 'かんたんすぎ', hard: 'むずかしすぎ', other: 'ちがうのがいい' };
    var h = '<div class="font-bold text-orange-800 mb-1">🧭 えらべる3つの道（印刷の前に確認）</div><div class="text-[11px] text-slate-600 mb-2">「いまここ（🅰）」を変えて［この子だけ保存］を押すと、7日間はその単元で印刷します（🅱はその次の単元になります）。◎○は記録から、△は教科書の順番どおり、🎯は本人が振り返りで選んだ単元、✎は先生が選んだものです。本人が書いた「来週やってみたいこと」は、差しかえても🅲にそのまま入ります。</div>';
    try {   /* NOWUNIT_V1 いまの単元と、どこから決まったか */
      var _cid0 = rows.length ? rows[0].d.classId : '', _g0 = _cid0 ? _guide[_cid0] : null, _sg0 = _g0 ? Number(_g0.classGrade || 0) : 0;
      if (_g0 && _sg0) h += '<div class="text-[11px] text-sky-800 bg-sky-50 border border-sky-200 rounded px-2 py-1 mb-2">📍 いまの単元：' + SUBJ_LIST.map(function (k) { var r = resolveNow(_g0, _sg0, k); return esc(SUBJ[k].name) + ' ' + esc(r ? nowLabel(r) : '－'); }).join('　') + '<span class="text-slate-500">（変えるときは 分析タブの「📍 いまの単元」で）</span></div>';
    } catch (e) {}
    h += '<div class="overflow-x-auto"><table class="text-xs w-full"><tr class="text-left text-slate-500"><th>名前</th><th>教科</th><th>🅰 いまここ</th><th>🅱 つぎ</th><th>記録</th><th>子どもの声（先週）</th><th></th></tr>';
    rows.forEach(function (x, k) {
      var nm = (typeof global.resolveStudentName === 'function') ? global.resolveStudentName(x.s.loginId, x.s.name) : (x.s.name || '');
      var rc = x.reco;
      var fb = x.d.recoFeedback && FB[x.d.recoFeedback.choice] ? FB[x.d.recoFeedback.choice] : '';
      var ntp = nextTryOf(x.d); if (ntp) fb = (fb ? fb + '／' : '') + '🎯' + ntp.say;   /* MAEJIBUN_V1 本人の「来週やってみたいこと」 */
      h += '<tr class="border-t"><td class="py-1 pr-2 font-bold">' + esc(nm) + '</td>';
      if (!rc) { h += '<td colspan="6" class="text-slate-400">学年が登録されていないため作れません</td></tr>'; return; }
      var sg = Number((x.d.student && x.d.student.grade) || 0);
      var opts = '';
      SUBJ_LIST.forEach(function (sk) {
        subjOrder(sk).forEach(function (id) { var inf = unitInfo(id); if (inf && inf.grade <= sg && inf.grade >= sg - 1) opts += '<option value="' + esc(id) + '"' + (id === rc.anchor ? ' selected' : '') + '>' + esc(inf.subjName + '・' + inf.gradeLabel + '・' + inf.name) + '</option>'; });
      });
      h += '<td>' + esc(rc.subjName) + '</td><td><select data-k="' + k + '" class="michiSel border rounded p-0.5 max-w-[14rem]">' + opts + '</select></td><td>' + esc(rc.b ? rc.b.name : '－') + '</td><td>' + esc(Array.from(rc.mark)[0] || '') + (rc.now ? ' <span class="text-[10px] text-sky-700">いま「' + esc(rc.now.name) + '」</span>' : '') + '</td><td>' + esc(fb) + '</td>';
      h += '<td><button type="button" data-k="' + k + '" class="michiSave bg-orange-500 text-white rounded px-2 py-0.5">この子だけ保存</button> <span class="michiMsg text-[10px]" data-k="' + k + '"></span></td></tr>';
    });
    h += '</table></div>';
    box.innerHTML = h;
    var btns = box.querySelectorAll('.michiSave');
    for (var q = 0; q < btns.length; q++) btns[q].onclick = function () {
      var k = Number(this.getAttribute('data-k')); var x = rows[k];
      var sel = box.querySelector('.michiSel[data-k="' + k + '"]'); var msg = box.querySelector('.michiMsg[data-k="' + k + '"]');
      var d2 = JSON.parse(JSON.stringify(x.d));
      d2.karteReco = { source: 'teacher', reco: { anchor: sel.value }, updatedAt: new Date().toISOString().slice(0, 19).replace('T', ' ') };
      var rc2 = computeReco(d2);
      if (!rc2) { msg.textContent = '作れませんでした'; return; }
      msg.textContent = '保存中...';
      global.michiSaveReco(x.s.userId, rc2, 'teacher').then(function (j) { msg.textContent = (j && j.ok && j.saved) ? '✓ 保存（🅱 ' + (rc2.b ? rc2.b.name : '－') + '）' : '保存できませんでした'; }).catch(function () { msg.textContent = '保存できませんでした'; });
    };
  }
  setInterval(function () { try { recoPanel(); } catch (e) {} }, 3000);

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
    var reco = null;
    try { reco = computeReco(d); } catch (e) { reco = null; }   /* MICHI_V2 */
    var map = reco ? null : mathMap(d, step, guide);
    if (reco) { try { queueReco((d.student && d.student.id) || '', reco); } catch (e) {} }
    var cd = canDo(d);
    var hn = hints(d);
    var pr = lastPromise(d);
    /* MICHI_V2B 曜日・問題数をこちらで決める案は出さない。AIの選択肢が無い週は、おもての「えらべる3つの道」だけにする。 */
    var tries = (ai && ai.tries.length) ? ai.tries.slice(0, 3) : (reco ? [] : fallbackTries(d, step, guide));
    tries = tries.map(function (t) { return cut(t, 38); });

    var F = [], B = [];
    // ── おもて ──
    F.push('<div class="mh"><div><h1>🧭 学びの道しるべ</h1><div class="nm">' + esc(nm) + '</div></div><div class="pd">' + esc(pd) + '</div></div>');
    if (reco) {   /* MICHI_V2 えらべる3つの道 ＋ すすみぐあいマップ */
      var _wt2 = watchOf(d);
      F.push(pathsHtml(reco, step && step.stalled, !!(_wt2 && _wt2.oneTap)));
      F.push(progressMap(d, reco));
    } else if (step) {
      var p = step.info;
      var h = '<div class="sec first"><h2 style="color:#c2410c">🧭 まずここから（' + (step.thin ? '今日' : '今週') + 'の さいしょの1歩）</h2>';
      h += '<div class="path"><span class="mchip">アプリの 🏋️修行</span><span class="arr">→</span><span class="mchip">' + esc(p.icon) + esc(p.subjName) + '</span><span class="arr">→</span><span class="mchip">' + esc(p.gradeLabel) + '</span><span class="arr">→</span><span class="mchip goal">「' + esc(p.name) + '」を ' + step.amount + '</span></div>';
      h += '<div class="why">（えらんだわけ：' + esc(step.why) + (step.mine && step.mine.total > 0 ? '。いままで ' + step.mine.total + '問 とりくんでいるよ' : '') + '）</div>';
      if (step.stalled) h += '<div style="font-size:12.5px;font-weight:700;color:#c2410c;margin-top:3px">5分で おわっても だいじょうぶ。1問 すすんだら、それが 前進やで。</div>';
      h += '</div>';
      F.push(h);
    }
    if (map) {
      var lab = { ok: '✅ できた', doing: 'とちゅう', mada: 'これから' };
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
    var prHtml = '';
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
      if (reco) prHtml = ph; else F.push(ph);   /* MICHI_V2 おもてが いっぱいなので うらへ */
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
    if (prHtml) B.push(prHtml);
    var th = '<div class="sec" style="border-color:#fda4af;background:#fff1f2"><h2>✏️ これやってみる？（1つ えらんで □ に○）</h2>';
    tries.forEach(function (t) { th += '<div class="ch"><span class="box"></span>' + esc(t) + '</div>'; });
    th += '<div class="ch"><span class="box"></span>じぶんで決める：<span style="display:inline-block;width:62%;border-bottom:1.5px dashed #94a3b8">&nbsp;</span></div>';
    th += '<div style="margin-top:4px;font-size:11.5px;color:#9f1239"><b>やり方も えらべるよ</b>（どれでもOK）<span class="circ">アプリの修行</span><span class="circ">ノートに書く</span><span class="circ">おうちの人に 問題を出してもらう</span></div></div>';
    if (tries.length) B.push(th);
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
    /* KANTAN_REF_V1 ✂おうちの人へ の欄は なくした（先生の判断・2026-10-26）。過去に作られた文（ai.home）は消さず、表示しないだけ。 */

    var html = '<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>学びの道しるべ</title><style>' + baseCss + '\n' + CSS + '\n' + CSS2 + '</style></head><body>' +
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


  // ───────── KANTAN_REF_V1 先生の画面（分析タブ）：ふりかえりの きっかけ案内の 対象（見るだけ・作業なし） ─────────
  //  ・自動で決まる。直近2週で アプリを開いた日が少ない／週の振り返りが2週つづけて無い／家庭学習が1週間止まっている の
  //    うち2つ以上の子。子どもの画面では いつもと同じ見た目で「1タップで ふりかえり」を案内し、カルテの はじめの一歩を小さくする。
  var _kwCid = '', _kwAt = 0;
  function kwRender(box, j) {
    if (!j || !j.ok) { box.innerHTML = '<span class="text-slate-400">👆 ふりかえりのきっかけ案内：読めませんでした</span>'; return; }
    var r = j.rule || {};
    var names = (j.items || []).map(function (x) {
      var nm = (typeof global.resolveStudentName === 'function') ? global.resolveStudentName(x.loginId, x.name) : (x.name || x.loginId || '');
      var why = [];
      if (x.reasons && x.reasons.fewOpen) why.push('開いた日' + x.openDays + '日');
      if (x.reasons && x.reasons.refMiss) why.push('振り返り' + x.refMissWeeks + '週なし');
      if (x.reasons && x.reasons.hwStop) why.push('家庭学習1週なし');
      return '<span class="inline-block bg-white border border-amber-200 rounded px-1.5 py-0.5 mr-1 mb-1">' + esc(nm) + ' <span class="text-[10px] text-slate-400">' + esc(why.join('・')) + '</span></span>';
    }).join('');
    box.innerHTML = '<div class="flex items-center gap-2 flex-wrap"><span class="font-bold text-amber-800">👆 ふりかえりの きっかけ案内（自動）</span>'
      + '<span class="text-slate-700">いま <b>' + j.count + '人</b> ／ ' + j.total + '人</span>'
      + '<span class="text-slate-500">・今週「かんたんふりかえり」で出した子 ' + (j.tappedThisWeek || 0) + '人</span>'
      + '<span class="text-[10px] text-slate-400">（見るだけ。先生の作業はありません）</span></div>'
      + (names ? '<div class="mt-1">' + names + '</div>' : '<div class="mt-1 text-slate-400">いまは 対象の子は いません</div>')
      + '<div class="text-[10px] text-slate-400 mt-0.5">きまり：直近' + (r.openDaysWindow || 14) + '日で アプリを開いた日が' + (r.openDaysMin || 4) + '日より少ない／週の振り返りが' + (r.refMissWeeks || 2) + '週つづけて無い／家庭学習が' + (r.hwStopDays || 7) + '日ない、のうち' + (r.minHits || 2) + 'つ以上。'
      + '対象の子には、金〜日に阪神マンが「1タップで ふりかえり できるで」と案内し（1日1回・とじられる）、カルテの🌟を必ず1つ以上・はじめの一歩を「1問だけ・5分」にします。子どもの画面の見た目は ほかの子と同じです。</div>';
  }
  function kwLoad(force) {
    var sel = document.getElementById('analyticsClassFilter');
    if (!sel || !sel.value) return;
    var host = sel.parentNode;
    if (!host || !host.parentNode) return;
    if (host.offsetParent === null && !force) return;   // 分析タブを ひらいていないときは読まない
    var box = document.getElementById('kantanWatchBox');
    if (!box) {
      box = document.createElement('div');
      box.id = 'kantanWatchBox';
      box.className = 'bg-amber-50 border border-amber-200 rounded-xl px-3 py-2 text-xs';
      host.parentNode.insertBefore(box, host.nextSibling);
    }
    if (!force && _kwCid === sel.value && Date.now() - _kwAt < 5 * 60000) return;
    _kwCid = sel.value; _kwAt = Date.now();
    box.innerHTML = '<span class="text-slate-400">👆 ふりかえりのきっかけ案内を読み込み中...</span>';
    loadWatch(sel.value, !!force).then(function (j) { kwRender(box, j); });
  }
  global.kantanWatchLoad = kwLoad;
  document.addEventListener('change', function (ev) { if (ev.target && ev.target.id === 'analyticsClassFilter') { _kwAt = 0; kwLoad(false); } });
  setInterval(function () { try { kwLoad(false); } catch (e) {} }, 4000);

  // ───────── NOWUNIT_V1 先生の画面（分析タブ）：「📍 いまの単元」を教科ごとに1つ（選ばなくてもよい） ─────────
  var _nwCid = '', _nwAt = 0;
  function nowSummary(g, sg) {
    var out = [];
    SUBJ_LIST.forEach(function (k) { var r = resolveNow(g, sg, k); if (r) out.push({ subj: k, r: r }); });
    return out;
  }
  function nowLabel(r) {
    if (!r) return 'わかりません（記録がふえると自動で決まります）';
    var inf = unitInfo(r.id) || { name: r.id };
    var why = NOW_SRC_LABEL[r.src] || '';
    if (r.src === 'memo' && r.theme) why += '「' + cut(r.theme, 14) + '」';
    if (r.src === 'auto') why += '・直近' + r.days + '日で' + r.users + '人';
    return '「' + inf.name + '」（' + why + '）';
  }
  function nwRender(box, cid) {
    var g = _guide[cid];
    if (!g) { box.innerHTML = '<span class="text-slate-400">📍 いまの単元：読めませんでした</span>'; return; }
    var sg = Number(g.classGrade || 0);
    if (!sg || sg > 6) { box.innerHTML = '<span class="text-slate-400">📍 いまの単元：クラスの学年がわからないため使えません</span>'; return; }
    var auto = { nowManual: {}, memoTopics: g.memoTopics, nowUnits: g.nowUnits };
    var h = '<div class="flex items-center gap-2 flex-wrap"><span class="font-bold text-sky-800">📍 いまの単元</span><span class="text-[10px] text-slate-500">（カルテの🅰🅱・阪神マンの候補・月曜の計画は、この単元を中心に作ります。選ばなくても自動で決まります）</span></div>';
    h += '<div class="grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-1 mt-1">';
    SUBJ_LIST.forEach(function (k) {
      var man = g.nowManual && g.nowManual[k] && g.nowManual[k].unit ? String(g.nowManual[k].unit) : '';
      var ar = resolveNow(auto, sg, k), cur = resolveNow(g, sg, k);
      var opts = '<option value="">おまかせ ' + esc(ar ? nowLabel(ar) : '（いまは決まっていません）') + '</option>';
      gradeUnits(k, sg).forEach(function (id) { opts += '<option value="' + esc(id) + '"' + (id === man ? ' selected' : '') + '>✋ ' + esc(unitInfo(id).name) + '</option>'; });
      h += '<label class="flex items-center gap-1"><span class="w-10 font-bold text-slate-700">' + esc(SUBJ[k].name) + '</span><select data-subj="' + k + '" class="nwSel border rounded p-0.5 text-xs max-w-[17rem]">' + opts + '</select>'
        + '<span class="nwMsg text-[10px] text-slate-500" data-subj="' + k + '">' + (cur ? '→ ' + esc(NOW_SRC_LABEL[cur.src] || '') : '') + '</span></label>';
    });
    h += '</div><div class="text-[10px] text-slate-400 mt-0.5">決まり方：①先生が選んだ単元 → ②⑥授業メモの「算数：円の面積」のような いちばん新しい行（直近4週） → ③クラスの3人以上が まとめて取り組んでいる単元 → ④算数は標準の進み方。選んだ単元は 次に変えるまで そのままです。</div>';
    box.innerHTML = h;
    var sels = box.querySelectorAll('.nwSel');
    for (var i = 0; i < sels.length; i++) sels[i].onchange = function () {
      var el = this, k = el.getAttribute('data-subj'), v = el.value;
      var msg = box.querySelector('.nwMsg[data-subj="' + k + '"]');
      if (msg) msg.textContent = '保存中...';
      fetch('/api/teacher/class/' + encodeURIComponent(cid) + '/now-unit', { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ subj: k, unit: v }) })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          if (!j || !j.ok) { if (msg) msg.textContent = '保存できませんでした'; return; }
          var gg = _guide[cid]; if (gg) { gg.nowManual = gg.nowManual || {}; if (v) gg.nowManual[k] = { unit: v, updatedAt: new Date().toISOString().slice(0, 19).replace('T', ' ') }; else delete gg.nowManual[k]; }
          nwRender(box, cid);
          var m2 = box.querySelector('.nwMsg[data-subj="' + k + '"]'); if (m2) m2.textContent = '✓ 保存（' + (v ? '先生が選んだ' : 'おまかせ') + '）';
        })
        .catch(function () { if (msg) msg.textContent = '保存できませんでした'; });
    };
  }
  function nwLoad(force) {
    var sel = document.getElementById('analyticsClassFilter');
    if (!sel || !sel.value) return;
    var host = sel.parentNode;
    if (!host || !host.parentNode) return;
    if (host.offsetParent === null && !force) return;   // 分析タブを ひらいていないときは読まない
    var box = document.getElementById('nowUnitBox');
    if (!box) {
      box = document.createElement('div');
      box.id = 'nowUnitBox';
      box.className = 'bg-sky-50 border border-sky-200 rounded-xl px-3 py-2 text-xs';
      var after = document.getElementById('kantanWatchBox') || host;
      after.parentNode.insertBefore(box, after.nextSibling);
    }
    if (!force && _nwCid === sel.value && Date.now() - _nwAt < 10 * 60000) return;
    _nwCid = sel.value; _nwAt = Date.now();
    box.innerHTML = '<span class="text-slate-400">📍 いまの単元を読み込み中...</span>';
    var cid = sel.value;
    Promise.all([loadCurriculum(), loadGuide(cid, true)]).then(function () { _unitIdx = null; nwRender(box, cid); });
  }
  global.nowUnitLoad = nwLoad;
  document.addEventListener('change', function (ev) { if (ev.target && ev.target.id === 'analyticsClassFilter') { _nwAt = 0; nwLoad(false); } });
  setInterval(function () { try { nwLoad(false); } catch (e) {} }, 4000);

  global.michiCompose = compose;
  global.michiInstall = install;
  function boot() { install(); preloadAll(); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
  // クラスの選択肢はあとから入るので、しばらく読み直す（1人ずつの印刷はポップアップの都合で待てないため）
  var tries_ = 0; var tm = setInterval(function () { tries_++; install(); preloadAll(); if (tries_ >= 6) clearInterval(tm); }, 5000);
  document.addEventListener('change', function (ev) { var id = ev.target && ev.target.id; if (id === 'analyticsClassFilter' || id === 'laClassSelect' || id === 'activityClassFilter') preloadAll(); });
})(window);
