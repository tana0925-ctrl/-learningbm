/* ===================================================================
   karte-shinbun.js : 📰 道しるべ新聞（印刷カルテ・A4両面）  SHINBUN_V1 2026-10-28
   -------------------------------------------------------------------
   ・karte-michi.js の compose() が 材料をそろえて KARTE_SHINBUN(ctx) を呼ぶ。ここで 新聞の形に組む。
     失敗したら michi の紙（学びの道しるべ）にもどる（michi 側で try/catch）。
   ・阪神マン新聞社が発行して、その子が「今週の 主役」。記事を書くのは 阪神マン記者。
   ・印刷は「見るだけ」の紙（MIRU_V1）：○つけ・□・書く線は のせない。入力はアプリのカルテで。
   ・のせるのは 記録にあることと、先生が確認して公開した 阪神マンの文（▼見出し・▼トップ記事 など）だけ。
     AIの記事が無い週は、記録の事実だけで 機械的に 見出しと記事を作る（推しはからない）。
   ・家庭学習を出していない週は、出していないことを 見出しにしない（アプリ・学校での学び・4月からの記録を中心に）。
   ・テストの点数・順位・ほかの子との比較は出さない。数字は「日・分・問・回」の実数だけ。
   ・1人ぶんは 必ず2ページ（裏表1枚）。紙の高さは決めて、本文は3段の段組みで流す。
     あふれたら 字を少し小さく → それでも あふれたら 優先度の低い欄（data-opt の小さい順）から省く。
     すき間が大きいときは 字を少し大きくして うめる（最大まで）。
   =================================================================== */
(function (global) {
  'use strict';
  if (global.__SHINBUN_V1__) return;
  global.__SHINBUN_V1__ = true;

  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function cut(s, n) { s = String(s == null ? '' : s).replace(/\s+/g, ' ').trim(); return s.length > n ? s.slice(0, n - 1) + '…' : s; }
  function pad(n) { return (n < 10 ? '0' : '') + n; }
  function ymd(t) { var x = new Date(t); return x.getUTCFullYear() + '-' + pad(x.getUTCMonth() + 1) + '-' + pad(x.getUTCDate()); }
  function dms(dk) { return Date.parse(String(dk) + 'T00:00:00Z'); }
  function ja(dk) { var p = String(dk || '').split('-'); return p.length < 3 ? '' : Number(p[1]) + '月' + Number(p[2]) + '日'; }
  function jaS(dk) { var p = String(dk || '').split('-'); return p.length < 3 ? '' : Number(p[1]) + '/' + Number(p[2]); }
  var WD = ['月', '火', '水', '木', '金'];
  var WX = { sun: '☀️', cloud: '☁️', rain: '☂️' };
  var WXJ = { sun: '晴れ', cloud: 'くもり', rain: '雨' };
  function stripIcon(t) { return String(t || '').replace(/^[^぀-ヿ一-鿿A-Za-z0-9\u{1F170}\u{1F171}「]+\s*/u, '').trim(); }

  // ───────── 🗞 SHINBUN_NETA_V1 一度 紙に のせた ネタは もう のせない ─────────
  //  印刷した 新聞の ネタは サーバー（karte_neta）に のこる（キー → はじめて のせた週・さいごに のせた値）。
  //  ・前の号までに のせた キー（ws が この号より 前）は old() … その欄・その行は のせない。
  //  ・同じ号の 刷りなおしは old ではない（同じ紙が 出る）。
  //  ・くらべる ための 前の値は prevV()（「前の号では 12回」の 形で 使う）。
  //  ・どの ネタを のせたかは 欄の data-nk に 書いておき、印刷の あと（afterprint）に のこった欄だけ 記録する。
  var NT = { m: {}, ws: '', used: {} };
  // キーは 文の まま のこさず ハッシュに する（子どもの ことばや 友だちの 名前を サーバーに のこさない）
  function nk(x) { var t = String(x == null ? '' : x).replace(/<[^>]*>/g, '').replace(/[\s\u3000、。・，．,.!?！？「」『』（）()…:：]/g, ''); return hashN(t).toString(36) + t.length.toString(36); }
  function old(k) { var e = NT.m[k]; return !!(e && e.ws && e.ws < NT.ws); }
  function prevV(k) { var e = NT.m[k]; if (!e) return null; if (e.lw && e.lw < NT.ws) return e.v; if (e.pws && e.pws < NT.ws) return e.pv; return null; }
  function use(k, v) { NT.used[k] = v == null ? '' : String(v); return k; }
  function tag(html, keys) { if (!html || !keys || !keys.length) return html; return String(html).replace(/^<section/, '<section data-nk="' + esc(keys.join('|')) + '"'); }
  function fresh(arr, keyOf) { return (arr || []).filter(function (x) { return !old(keyOf(x)); }); }

  // ───────── 材料 ─────────
  function weekStart(d) {
    var m = d.aiCommentMeta && d.aiCommentMeta.weekStart;
    if (/^\d{4}-\d{2}-\d{2}$/.test(String(m || ''))) return String(m);
    if (d.lastWeek && /^\d{4}-\d{2}-\d{2}$/.test(String(d.lastWeek.from || ''))) return String(d.lastWeek.from);
    var n = Date.now() + 9 * 3600000, wd = (new Date(n).getUTCDay() + 6) % 7;
    return ymd(n - (wd + 7) * 86400000);
  }
  function weekDays(ws) { var a = []; for (var i = 0; i < 5; i++) a.push(ymd(dms(ws) + i * 86400000)); return a; }
  function weekRows(d, days) {
    var by = {};
    (d.recentSubmissions || []).forEach(function (s) { if (s && s.day_key) by[s.day_key] = s; });
    return days.map(function (dk, i) { var s = by[dk]; return { dk: dk, wd: WD[i], s: (s && !s.rest_day) ? s : null, rest: !!(s && s.rest_day) }; });
  }
  function issueNo(ws) {   // 年度（4月）の はじめの月曜から かぞえた週
    var y = Number(ws.slice(0, 4)), mo = Number(ws.slice(5, 7)); if (mo < 4) y--;
    var a = dms(y + '-04-01'), wd = (new Date(a).getUTCDay() + 6) % 7, m0 = a - wd * 86400000;
    return Math.max(1, Math.floor((dms(ws) - m0) / (7 * 86400000)) + 1);
  }
  function quoteOf(s) { var t = String((s && s.weather_reason) || '').trim(); return t; }
  function bestQuote(rows) {
    var best = null;
    rows.forEach(function (r) { if (!r.s) return; var q = quoteOf(r.s); if (!q) return; var sc = (r.s.end_weather === 'sun' ? 100 : r.s.end_weather === 'cloud' ? 50 : 0) + Math.min(40, q.length); if (!best || sc > best.sc) best = { sc: sc, r: r, q: q }; });
    return best;
  }
  function headlinesOf(hist, cur) {   // バックナンバー：前に公開した 阪神マンの文の ▼見出し
    var out = [], split = global.michiSplitAi;
    if (typeof split !== 'function') return out;
    (hist || []).forEach(function (h) {
      if (!h || !h.body || String(h.body).trim() === String(cur || '').trim()) return;
      var sp = split(h.body); if (sp.head) out.push({ wk: h.weekKey || '', at: String(h.publishedAt || '').slice(0, 10), head: sp.head });
    });
    return out.slice(0, 3);
  }

  // ───────── 欄（sec）を つくる小道具 ─────────
  function sec(title, body, opt, cls, small) {
    if (!body) return '';
    return '<section class="sec' + (cls ? ' ' + cls : '') + '"' + (opt ? ' data-opt="' + opt + '"' : '') + '><h2>' + title + (small ? '<small>' + small + '</small>' : '') + '</h2>' + body + '</section>';
  }
  function li(t) { return '<div class="li">' + t + '</div>'; }

  // ───────── 1面 ─────────
  function topArticle(c, rows, facts, noAi) {
    var ai = noAi ? null : c.ai, d = c.d, q = bestQuote(rows);
    if (ai && ai.head && ai.top) {
      var paras = String(ai.top).split(/\n+/).map(function (p) { return p.trim(); }).filter(Boolean);
      return { head: cut(ai.head, 24), sub: cut(ai.sub, 40), body: paras.map(function (p) { return '<p>' + esc(p) + '</p>'; }).join(''), by: '文・阪神マン記者（本人の 記録と ふりかえりから）', ai: true };
    }
    // AIの記事が無い週：記録の事実だけで作る
    var P = [], head = '', sub = '';
    if (facts.days > 0) {
      head = q ? '「' + cut(q.q, 18) + '」' : ('今週は ' + facts.days + '日 とりくんだ');
      sub = (q ? q.r.wd + '曜日の ふりかえりより ／ ' : '') + '5日のうち ' + facts.days + '日・合わせて ' + facts.minutes + '分';
      P.push('先週は 5日のうち ' + facts.days + '日、合わせて ' + facts.minutes + '分 家庭学習に とりくんだ。' + (facts.longest ? 'いちばん 長かったのは ' + facts.longest.wd + '曜日の ' + facts.longest.m + '分。' : ''));
      var vs = rows.filter(function (r) { return r.s && quoteOf(r.s); }).map(function (r) { return r.wd + '曜日は「' + cut(quoteOf(r.s), 34) + '」'; });
      if (vs.length) P.push('ふりかえりには、' + vs.slice(0, 3).join('、') + 'と 書いている。');
    }
    var lw = d.lastWeek || {};
    if (Number(lw.total) > 0) {
      if (!head) { head = 'アプリで ' + lw.total + '問に 挑戦'; sub = lw.days + '日・' + (lw.units || []).length + '単元'; }
      var fe = (lw.units || []).filter(function (u) { return u.firstEver; }).map(function (u) { return '「' + c.unitName(u.unit) + '」'; });
      P.push('アプリの 修行では ' + lw.days + '日で ' + lw.total + '問に とりくんだ。' + (fe.length ? fe.slice(0, 2).join('・') + 'の 単元に はじめて 出会った。' : ''));
    }
    var ov = d.overview || {};
    if (!head) {
      if (Number(ov.totalSubmissions) > 0) { head = '4月から ' + ov.totalSubmissions + '回の 家庭学習'; sub = 'これまでの 記録から'; }
      else { head = '学びの 道を 歩きはじめた'; sub = 'これからの 記録が 楽しみ'; }
    }
    if (Number(ov.totalSubmissions) > 0) {   /* SHINBUN_NETA_V1 前の号と 同じ数なら のせない。ふえたら くらべて のせる */
      var pt = prevV('S:tot');
      if (pt == null || String(pt) !== String(ov.totalSubmissions)) P.push('4月からの 家庭学習は ' + ov.totalSubmissions + '回' + (pt != null ? '（前の号の ときは ' + pt + '回）' : '') + (Number(ov.maxStreak) >= 2 ? '、いちばん 長く つづいたのは ' + ov.maxStreak + '日。' : '。'));
      use('S:tot', ov.totalSubmissions);
    }
    if (c.tsFact) P.push(c.tsFact.replace(/／/g, '、') + '。');
    return { head: head, sub: sub, body: P.map(function (p) { return '<p>' + esc(p) + '</p>'; }).join(''), by: '記録から まとめました', ai: false };
  }
  function weatherSec(rows) {
    if (!rows.some(function (r) { return r.s; })) return '';
    var h = '<table class="wx"><tr>' + rows.map(function (r) { return '<th>' + r.wd + '</th>'; }).join('') + '</tr><tr>';
    h += rows.map(function (r) {
      if (!r.s) return '<td class="off"><div class="ic">・</div><div class="m">' + (r.rest ? '休み' : '―') + '</div></td>';
      return '<td><div class="ic">' + (WX[r.s.end_weather] || '⭕') + '</div><div class="m">' + (Number(r.s.minutes) || 0) + '分</div></td>';
    }).join('') + '</tr></table>';
    return sec('先週の 天気', h, 0, '', 'きもちの 天気');
  }
  function voicesSec(rows) {
    var v = rows.filter(function (r) { return r.s && quoteOf(r.s) && !old('v:' + nk(quoteOf(r.s))); });
    if (!v.length) return '';
    return tag(sec('わたしの ことば', v.map(function (r) { return '<div class="vo"><b>' + r.wd + '</b>' + esc(cut(quoteOf(r.s), 60)) + '</div>'; }).join(''), 0, '', '毎日の ふりかえり'), v.map(function (r) { return use('v:' + nk(quoteOf(r.s))); }));
  }
  function columnSec(c) {
    var ai = c.ai;
    if (!ai || !ai.main) {
      if (c.stale) return sec('🐯 阪神マン記者の コラム', '<p class="mute">（新しい コラムは 先生が 公開すると ここに 出ます）</p>', 1, 'col');
      return '';
    }
    var ck = 'col:' + nk(ai.main).slice(0, 50); if (old(ck)) return '';   /* SHINBUN_NETA_V1 前の号と 同じ コラムは のせない */
    var paras = String(ai.main).split(/\n+/).map(function (p) { return p.trim(); }).filter(Boolean);
    var h = paras.map(function (p) { return '<p>' + esc(p) + '</p>'; }).join('');
    if (ai.ask) h += '<div class="q">💭 ' + esc(cut(ai.ask, 70)) + '</div>';
    if (ai.hint) h += '<div class="sm">📮 <b>出し方のヒント</b> … ' + esc(cut(ai.hint, 50)) + '</div>';
    if (ai.test) h += '<div class="sm">📝 <b>テストに向けて</b> … ' + esc(cut(ai.test, 50)) + '</div>';
    if (!ai.hint && !ai.test && c.tsFact) h += '<div class="sm">📮 ' + esc(c.tsFact) + '</div>';
    if (c.hanNote) h += '<div class="note">' + esc(c.hanNote) + '</div>';
    use(ck);
    return '<section data-nk="' + esc(ck) + '" class="sec col"><h2><span class="f">🐯</span>阪神マン記者の コラム</h2>' + h + '</section>';
  }
  function roadsSec(c) {
    var r = c.reco, mp = c.mp;
    var help = '<div class="sm">🛟 <b>こまったら</b>：' + (mp && mp.help ? esc(mp.help) + '。ほかにも ' : '') + (mp && mp.dom === 'inter' ? 'ヒントを見る・家の人に聞く' : 'ヒントを見る・友だちに聞く・先生に聞く・家の人に聞く') + '</div>';
    if (r) {
      var rk = 'roads:' + nk(r.a.name + '/' + (r.b ? r.b.name : '') + '/' + (r.c && r.c.say || ''));
      if (old(rk)) return '';   /* SHINBUN_NETA_V1 3つの道が 前の号と 同じなら のせない（かわったら また のせる） */
      use(rk);
      var h = '<div class="rd"><span class="k">A</span><div><b>「' + esc(r.a.name) + '」を もう一度 かためる</b><div class="mute">' + esc(r.a.entry) + '</div><div class="mute">💡 ' + esc(cut(r.a.why, 60)) + '</div></div></div>';
      if (r.b) h += '<div class="rd"><span class="k">B</span><div><b>「' + esc(r.b.name) + '」の はじめに すすむ</b><div class="mute">' + esc(r.b.entry) + '</div><div class="mute">💡 ' + esc(cut(r.b.why, 60)) + '</div></div></div>';
      h += '<div class="rd"><span class="k">C</span><div><b>自分で 決める</b>' + (r.c && r.c.say ? '<div>「' + esc(cut(r.c.say, 46)) + '」</div><div class="mute">' + esc(cut(r.c.from, 48)) + '（かえても いいよ）</div>' : '<div class="mute">やりたいことを 自分で 決めても いいよ</div>') + '</div></div>';
      h += '<div class="sm">👣 <b>はじめの一歩</b>：いちばん かんたんな 1問だけ（5分で できる 大きさ）</div>' + help;
      return tag(sec('特集　えらべる 3つの道', h, 0, 'roads', 'どれでも いいよ'), [rk]);
    }
    var st = c.step;
    if (st && st.info) {
      var p = st.info, sk = 'step:' + nk(p.name);
      if (old(sk)) return '';
      use(sk);
      return tag(sec('特集　まずは ここから', '<div><b>アプリの 修行 → ' + esc(p.icon || '') + esc(p.subjName || '') + ' → ' + esc(p.gradeLabel || '') + ' →「' + esc(p.name || '') + '」</b></div><div class="mute">💡 ' + esc(cut(st.why, 70)) + '</div>' + help, 0, 'roads'), [sk]);
    }
    return '';
  }
  function triesSec(c) {
    var ts = fresh(c.tries, function (t) { return 'try:' + nk(t); });
    if (!ts.length) return '';
    return tag(sec('これ やってみる？', ts.map(function (t) { return li('● ' + esc(t)); }).join('') + '<div class="mute sm">やり方は どれでもOK：アプリの修行・ノートに書く・おうちの人に 問題を出してもらう など</div>', 0), ts.map(function (t) { return use('try:' + nk(t)); }));
  }
  function progressSec(c) {
    var cards = c.cards || [];
    var pk = 'prog:' + nk(cards.map(function (x) { return x.name + x.k; }).join('/') || ((c.map && c.map.nodes) || []).slice(0, 4).map(function (n) { return n.name + (n.here ? 'h' : n.st); }).join('/'));
    if (old(pk)) return '';   /* SHINBUN_NETA_V1 すすみぐあいが かわらなければ のせない */
    use(pk);
    if (cards.length) {
      var LAB = { done: 'できた', here: 'いまここ', next: 'つぎ' };
      var h = '<div class="line">' + cards.map(function (x, i) { return (i ? '<div class="ln"></div>' : '') + '<div class="st ' + x.k + '"><div class="dot"></div>' + esc(x.name) + (x.sub ? '<small>（' + esc(x.sub) + '）</small>' : '') + '<br>' + LAB[x.k] + '</div>'; }).join('') + '</div>';
      return tag(sec(esc((c.reco && c.reco.subjName) || '算数') + ' すすみぐあい', h, 0), [pk]);
    }
    var mp = c.map;
    if (mp && mp.nodes && mp.nodes.length) {
      var seen = false;
      var h2 = '<div class="line">' + mp.nodes.slice(0, 4).map(function (n, i) { var k = n.here ? 'here' : (n.st === 'ok' ? 'done' : 'next'); if (n.here) seen = true; return (i ? '<div class="ln"></div>' : '') + '<div class="st ' + k + '"><div class="dot"></div>' + esc(n.name) + '<br>' + (n.here ? 'いまここ' : (n.st === 'ok' ? 'できた' : (seen ? 'つぎ' : ''))) + '</div>'; }).join('') + '</div>';
      return tag(sec('算数 すすみぐあい', h2, 4), [pk]);
    }
    return '';
  }
  function newsSec(c, facts) {
    var d = c.d, L = [], lw = d.lastWeek || {}, ov = d.overview || {};
    (lw.units || []).slice(0, 2).forEach(function (u) { L.push('<b>修行</b>　「' + esc(c.unitName(u.unit)) + '」を ' + u.total + '問' + (u.firstEver ? '（はじめての 単元）' : '')); });
    if (Number(ov.currentStreak) >= 3) L.push('<b>れんぞく</b>　いま ' + ov.currentStreak + '日 つづけて 家庭学習を 出している');
    if (Number(ov.maxStreak) >= 3) L.push('<b>記録</b>　今年度 いちばん 長い れんぞくは ' + ov.maxStreak + '日');
    var kw = d.teishutsu && d.teishutsu.karteWeek;
    if (kw && Number(kw.onTime) > 0) L.push('<b>提出</b>　しめきり前に 出せた 提出物が ' + Number(kw.onTime) + 'つ');
    if (facts.days > 0 && facts.longest) L.push('<b>最長</b>　' + facts.longest.wd + '曜日に ' + facts.longest.m + '分 とりくんだ');
    L = fresh(L, function (x) { return 'n:' + nk(x); }).slice(0, 5);
    if (!L.length) return '';
    return tag(sec('ニュース ななめ読み', L.map(function (x) { return li('● ' + x); }).join(''), 3, 'news'), L.map(function (x) { return use('n:' + nk(x)); }));
  }
  function numsSec(c, facts) {
    var lw = c.d.lastWeek || {}, kw = c.d.teishutsu && c.d.teishutsu.karteWeek, a = [];
    if (facts.days > 0) { a.push([facts.days, '日', '家庭学習']); a.push([facts.minutes, '分', 'やった時間']); }
    if (Number(lw.total) > 0) a.push([lw.total, '問', 'アプリの修行']);
    if (kw && Number(kw.onTime) > 0) a.push([Number(kw.onTime), 'つ', 'しめきり前']);
    if (!a.length) return '';
    var nmk = 'nums:' + a.slice(0, 4).map(function (x) { return x[0] + x[1]; }).join('-'); if (old(nmk)) return '';
    return tag(sec('数字で 見る 先週', '<div class="nums">' + a.slice(0, 4).map(function (x) { return '<div><b>' + x[0] + '</b><i>' + x[1] + '</i><small>' + x[2] + '</small></div>'; }).join('') + '</div>', 4), [use(nmk)]);
  }
  function hqSec(c) {
    var ha = (c.d.hanshinAnswers || []).filter(function (x) { return x && x.answer; })[0];
    if (!ha) return '';
    var hk = 'hq:' + nk(ha.question + ha.answer); if (old(hk)) return '';
    return tag(sec('阪神マンからの しつもん', li('<b>しつもん</b>「' + esc(cut(ha.question, 50)) + '」') + li('<b>きみの 答え</b>「' + esc(cut(ha.answer, 70)) + '」'), 2), [use(hk)]);
  }
  function lessonSec(c) {
    var ls = fresh((c.d.shinbun && c.d.shinbun.lesson) || [], function (x) { return 'les:' + nk(x.subj + x.unit + x.dayKey); });
    if (!ls.length) return '';
    return tag(sec('今週の 授業', ls.map(function (x) { return li('● ' + esc(x.subj) + '「' + esc(x.unit) + '」<span class="mute">（' + jaS(x.dayKey) + '）</span>'); }).join(''), 2, '', '学校で 学んだこと'), ls.map(function (x) { return use('les:' + nk(x.subj + x.unit + x.dayKey)); }));
  }
  function memoTable(rows) {
    if (!rows.some(function (r) { return r.s; })) return '';
    var h = '<table class="tb memo"><tr><th class="w1">曜日</th><th>やったこと</th><th class="w2">時間</th><th class="w1">天気</th><th class="w3">ふりかえり</th><th class="w4">次の 作戦</th></tr>';
    rows.forEach(function (r) {
      if (!r.s) { h += '<tr><td class="c">' + r.wd + '</td><td colspan="5" class="mute">' + (r.rest ? '休み' : '―') + '</td></tr>'; return; }
      h += '<tr><td class="c">' + r.wd + '</td><td>' + esc(cut(stripIcon(r.s.todo), 34)) + '</td><td class="n">' + (Number(r.s.minutes) || 0) + '分</td><td class="c">' + (WX[r.s.end_weather] || '') + '</td><td>' + esc(cut(quoteOf(r.s), 30)) + '</td><td>' + esc(cut(stripIcon(r.s.next_improve), 14)) + '</td></tr>';
    });
    h += '</table>';
    var pc = rows.filter(function (r) { return r.s && String(r.s.parent_comment || '').trim(); }).map(function (r) { return '「' + esc(cut(String(r.s.parent_comment).replace(/^👍\s*見たよ\s*/, '👍 見たよ　').trim(), 40)) + '」（' + r.wd + '）'; });
    if (pc.length) h += '<div class="sm home">🏠 <b>おうちの人から</b>：' + pc.slice(0, 3).join(' ／ ') + '</div>';
    return '<section class="memo-wrap"><h2>取材メモ　1週間の 動き<small>本人の 記録から</small></h2>' + h + '</section>';
  }

  // ───────── 2面 ─────────
  function interviewSec(c, ws) {
    var d = c.d, QA = [], r2 = d.shinbun && d.shinbun.ref2;
    var wk = isoWeek(ws), refs = (d.reflections || []).filter(function (r) { return r && (r.weekKey === wk || r.weekKey === ws); });
    var rf = refs[0] || null;
    if (r2 && r2.promise) QA.push(['先週 決めた ことは できた？', '「' + cut(r2.promise, 30) + '」' + (r2.result ? ' … ' + cut(r2.result, 16) : '') + (r2.reason ? '。' + cut(r2.reason, 40) : '')]);
    if (rf) {
      if (rf.goodPoint) QA.push(['今週は どうだった？', cut(rf.goodPoint, 70)]);
      if (rf.improvePoint) QA.push(['もう少しだったことは？', cut(rf.improvePoint, 60)]);
      if (rf.nextAction) QA.push(['次は どうする？', cut(String(rf.nextAction).replace(/^次[：:]\s*/, ''), 60)]);
      if (rf.freeText) QA.push(['ひとこと どうぞ', cut(rf.freeText, 90)]);
    }
    if (r2 && (r2.learned || r2.theme)) QA.push(['学校で 学んだ ことは？', (r2.subj ? r2.subj + (r2.theme ? '「' + cut(r2.theme, 20) + '」' : '') + '。' : '') + cut(r2.learned || '', 60) + (r2.more ? '　' + cut(r2.more, 30) : '')]);
    if (r2 && r2.q) QA.push(['考えてみたい 問いは？', cut(r2.q, 60)]);
    QA = fresh(QA, function (x) { return 'qa:' + nk(x[1]); });
    if (!QA.length) return '';
    return tag(sec('インタビュー　阪神マン記者が きいた', '<dl class="qa">' + QA.map(function (x) { return '<dt>' + esc(x[0]) + '</dt><dd>' + esc(x[1]) + '</dd>'; }).join('') + '</dl><div class="src">本人が アプリで 書いた ことば そのままです</div>', 0, '', '週の ふりかえりより'), QA.map(function (x) { return use('qa:' + nk(x[1])); }));
  }
  function isoWeek(dk) {
    var t = dms(dk); if (isNaN(t)) return '';
    var x = new Date(t), dn = (x.getUTCDay() + 6) % 7; x.setUTCDate(x.getUTCDate() - dn + 3);
    var f = new Date(Date.UTC(x.getUTCFullYear(), 0, 4)), fn = (f.getUTCDay() + 6) % 7; f.setUTCDate(f.getUTCDate() - fn + 3);
    var w = 1 + Math.round((x - f) / (7 * 86400000)); return x.getUTCFullYear() + '-W' + pad(w);
  }
  function compareSec(c, facts, rows) {
    var a = c.d.shinbun && c.d.shinbun.ago3;
    if (!a || !(facts.days > 0) || facts.days < Number(a.days || 0)) return '';   // よくなったか 同じときだけ くらべる
    var nowV = bestQuote(rows), nowNext = '';
    rows.forEach(function (r) { if (r.s && String(r.s.next_improve || '').trim()) nowNext = stripIcon(r.s.next_improve); });
    var box = function (cls, ttl, days, min, v, nx) { return '<div class="' + cls + '"><b>' + ttl + '</b>家庭学習 ' + days + '日・' + min + '分' + (v ? '<br>「' + esc(cut(v, 30)) + '」' : '') + (nx ? '<br>次：' + esc(cut(stripIcon(nx), 16)) : '') + '</div>'; };
    var h = '<div class="cmp">' + box('', ja(a.from) + '〜', a.days || 0, a.minutes || 0, (a.voices || [])[0] || '', a.next) + box('now', ja(c.ws) + '〜', facts.days, facts.minutes, nowV ? nowV.q : '', nowNext) + '</div>';
    return sec('くらべてみよう　3週間前の わたし', h, 3);
  }
  /* SHINBUN_FRESH_V1 ことばのアルバム（4週より前のことば）は 新聞から はずした。古い出来事が のるため（先生の指摘）。関数は のこす */
  function albumSec(c) {
    var al = (c.d.shinbun && c.d.shinbun.album) || [];
    if (!al.length) return '';
    return sec('ことばの アルバム', al.map(function (x) { return '<div class="li alb">「' + esc(cut(x.text, 50)) + '」<small>（' + ja(x.dayKey) + '）</small></div>'; }).join(''), 2, '', '4月からの ふりかえりから');
  }
  function backSec(c) {
    var hs = fresh(headlinesOf(c.d.karteHist, c.d.aiComment), function (x) { return 'back:' + nk(x.head); });
    if (!hs.length) return '';
    return tag(sec('バックナンバー', hs.map(function (x) { return li('<span class="mute">' + esc(jaS(x.at)) + '</span>「' + esc(cut(x.head, 26)) + '」'); }).join(''), 1, '', 'これまでの トップ記事'), hs.map(function (x) { return use('back:' + nk(x.head)); }));
  }
  function yokokuSec(c) {
    var nt = typeof global.michiNextTryOf === 'function' ? global.michiNextTryOf(c.d) : null;
    if (!nt || !nt.say) return '';
    var yk = 'yokoku:' + nk(nt.say); if (old(yk)) return '';
    use(yk);
    return '<section data-nk="' + esc(yk) + '" class="sec yokoku"><h2>来週の 予告</h2><div class="t">「' + esc(nt.say) + '」</div><div class="mute sm">本人が 書いた「来週 やってみたいこと」</div></section>';
  }
  function trainSec(c) {
    var us = ((c.d.lastWeek || {}).units || []).slice(0, 5);
    if (!us.length) return '';
    var trk = 'train:' + us.map(function (u) { return u.unit + '=' + u.total; }).join(','); if (old(trk)) return '';
    var mx = Math.max.apply(null, us.map(function (u) { return Number(u.total) || 0; }).concat([1]));
    var h = '<table class="tb"><tr><th>単元</th><th class="w2">問題</th><th style="width:40%">とりくみ</th></tr>' + us.map(function (u, i) { return '<tr><td>' + esc(cut(c.unitName(u.unit), 16)) + (u.firstEver ? ' 🆕' : '') + '</td><td class="n">' + u.total + '</td><td><span class="meter' + (i ? '' : ' r') + '" style="width:' + Math.max(4, Math.round(u.total / mx * 100)) + '%"></span></td></tr>'; }).join('') + '</table>';
    return tag(sec('修行 レポート', h, 2, '', '先週 アプリで とりくんだ 単元'), [use(trk)]);
  }
  function monthSec(c) {
    var mt = (c.d.monthlyTrends || []).slice(-7);
    if (!mt.length) return '';
    var sum = mt.reduce(function (a, m) { return a + (Number(m.count) || 0); }, 0), mk = 'month:' + mt.map(function (m) { return m.month + '=' + (Number(m.count) || 0); }).join(',');
    if (old(mk)) return '';   /* SHINBUN_NETA_V1 グラフが 前の号と 同じなら のせない */
    var pm = prevV('S:month'); use(mk); use('S:month', sum);
    var mx = Math.max.apply(null, mt.map(function (m) { return Number(m.count) || 0; }).concat([1]));
    var h = '<table class="bg"><tr>' + mt.map(function (m, i) { var v = Number(m.count) || 0; return '<td' + (i === mt.length - 1 ? ' class="now"' : '') + '>' + v + '<i style="height:' + (v ? Math.max(0.15, v / mx * 6.2).toFixed(2) : 0) + 'em"></i></td>'; }).join('') + '</tr><tr class="lb">' + mt.map(function (m) { return '<td>' + Number(String(m.month || '').slice(5)) + '月</td>'; }).join('') + '</tr></table>';
    if (pm != null && Number(pm) < sum) h += '<div class="mute sm">前の号から ＋' + (sum - Number(pm)) + '回</div>';
    return tag(sec('月ごとの 家庭学習', h, 0, '', '4月から（回）'), [mk]);
  }
  function moodSec(c) {
    var ov = c.d.overview || {}, a = Number(ov.sunCount) || 0, b = Number(ov.cloudCount) || 0, r = Number(ov.rainCount) || 0, t = a + b + r;
    if (t < 3) return '';
    var mdk = 'mood:' + a + '-' + b + '-' + r; if (old(mdk)) return '';
    var pmd = prevV('S:mood'); use(mdk); use('S:mood', a + '-' + b + '-' + r);
    var cmp = '';
    if (pmd) { var pp = String(pmd).split('-').map(Number); var dd = [['☀', a - pp[0]], ['☁', b - pp[1]], ['☂', r - pp[2]]].filter(function (x) { return x[1] > 0; }); if (dd.length) cmp = '<div class="mute sm">前の号から ' + dd.map(function (x) { return x[0] + '＋' + x[1]; }).join(' ') + '</div>'; }
    var w = function (n) { return Math.max(n ? 6 : 0, Math.round(n / t * 100)); };
    return tag(sec('きもちの 天気の わりあい', '<div class="ratio"><i style="width:' + w(a) + '%;background:#f2c94c">☀ ' + a + '</i><i style="width:' + w(b) + '%;background:#c9d2de">☁ ' + b + '</i><i style="width:' + w(r) + '%;background:#7d8ca3;color:#fff">☂ ' + r + '</i></div><div class="mute sm">家庭学習を 出した日の 天気の 回数</div>' + cmp, 3, '', '4月から'), [mdk]);
  }
  function subjSec(c) {
    var fn = global._subjectArea; if (typeof fn !== 'function') return '';
    var A = [['math', '🔢 算数'], ['jp', '📝 国語'], ['soc', '🌏 社会'], ['sci', '🔬 理科'], ['eng', '🔤 英語']], tot = {};
    (c.d.subjects || []).forEach(function (s) { var k = fn(s.unit); if (k) tot[k] = (tot[k] || 0) + (Number(s.total) || 0); });
    var rows = A.filter(function (a) { return tot[a[0]] > 0; });
    if (!rows.length) return '';
    var sjk = 'subj:' + rows.map(function (a) { return a[0] + tot[a[0]]; }).join(','); if (old(sjk)) return '';
    var psj = {}; String(prevV('S:subj') || '').split(',').forEach(function (x) { var q = x.split('='); if (q[0]) psj[q[0]] = Number(q[1]) || 0; });
    use(sjk); use('S:subj', rows.map(function (a) { return a[0] + '=' + tot[a[0]]; }).join(','));
    var mx = Math.max.apply(null, rows.map(function (a) { return tot[a[0]]; }));
    return tag(sec('教科ごとの 修行', '<table class="tb">' + rows.map(function (a, i) { return '<tr><td style="width:24%;white-space:nowrap">' + a[1] + '</td><td><span class="meter' + (i ? '' : ' r') + '" style="width:' + Math.max(3, Math.round(tot[a[0]] / mx * 100)) + '%"></span></td><td class="n" style="width:16%">' + tot[a[0]] + (psj[a[0]] != null && tot[a[0]] > psj[a[0]] ? '<small>（＋' + (tot[a[0]] - psj[a[0]]) + '）</small>' : '') + '</td></tr>'; }).join('') + '</table>', 2, '', '4月から（問）'), [sjk]);
  }
  function unitsSec(c) {   // 4月から いちばん とりくんだ 単元（問題の数だけ）
    var us = (c.d.subjects || []).filter(function (s) { return Number(s.total) >= 10; }).sort(function (a, b) { return (Number(b.total) || 0) - (Number(a.total) || 0); }).slice(0, 6);
    if (us.length < 2) return '';
    var uk = 'units:' + us.map(function (u) { return u.unit + '=' + Number(u.total); }).join(','); if (old(uk)) return '';
    var pu = {}; String(prevV('S:units') || '').split(',').forEach(function (x) { var q = x.split('='); if (q[0]) pu[q[0]] = Number(q[1]) || 0; });
    use(uk); use('S:units', us.map(function (u) { return u.unit + '=' + Number(u.total); }).join(','));
    var mx = Number(us[0].total) || 1;
    return tag(sec('単元の あゆみ', '<table class="tb">' + us.map(function (s, i) { return '<tr><td style="width:44%">' + esc(cut(c.unitName(s.unit), 16)) + '</td><td><span class="meter' + (i ? '' : ' r') + '" style="width:' + Math.max(3, Math.round(Number(s.total) / mx * 100)) + '%"></span></td><td class="n" style="width:16%">' + Number(s.total) + '問' + (pu[s.unit] != null && Number(s.total) > pu[s.unit] ? '<small>（＋' + (Number(s.total) - pu[s.unit]) + '）</small>' : (pu[s.unit] == null && Object.keys(pu).length ? '<small>🆕</small>' : '')) + '</td></tr>'; }).join('') + '</table>', 1, '', '4月から アプリで とりくんだ 単元'), [uk]);
  }
  // 学び方 ミニ講座：記録ではなく、だれにでも 使える 学び方のヒント。週ごとに 入れかわる。
  //  すき間を うめるための欄なので、いちばん先に 省かれる（data-opt=1）。その子についての ことは 書かない。
  var TIPS = [
    ['おぼえたい ことは、声に 出して 読む', '目と 耳の 両方から 入るので、頭に のこりやすく なるで。'],
    ['まちがえた 問題に しるしを つける', 'しるしの 問題だけ もう一度 とくと、短い 時間で 力が つくで。'],
    ['はじめる 前に「今日 やること」を 1つ 決める', 'やることが はっきりすると、すっと 始められるで。'],
    ['わかったことを だれかに 説明してみる', '人に 話せたら、ほんまに わかった しるしやで。'],
    ['図や 表に かいて 考える', 'ことばだけで わかりにくい ときは、絵に すると 見えてくるで。'],
    ['10分 やったら 少し 休む', '短く 区切ると、集中が つづきやすいで。'],
    ['終わったら「今日 わかったこと」を 1行 書く', '書くと、次の日に 思い出しやすく なるで。'],
    ['にている 問題を さがして くらべる', 'どこが 同じで どこが ちがうかで、しくみが 見えてくるで。'],
    ['しずかな 場所を 自分で えらぶ', '自分に 合う 場所を 見つけるのも 大事な 作戦やで。'],
    ['わからない ところを 言葉に してみる', '「どこが わからないか」が わかると、半分 とけたも 同じやで。'],
    ['問題を 読んだら、大事な ところに 線を 引く', '何を きかれているかが はっきりして、まちがいが へるで。'],
    ['答えを 出したら、もとの 問題に もどして たしかめる', 'たしかめ算は、自分で できる ○つけやで。'],
    ['わからない ことばは 辞書や 教科書で しらべる', 'ことばが わかると、問題の 半分は 見えてくるで。'],
    ['ノートは 1問ごとに 線で 区切る', 'あとで 見なおす ときに さがしやすく なるで。'],
    ['前の 日に やった 問題を 1問だけ もう一度 とく', 'くりかえすと、わすれにくく なるで。'],
    ['ねる 前に 今日 おぼえたことを 思い出す', 'ねている あいだに 頭が せいりしてくれるで。'],
    ['まちがいノートを つくる', 'どこで まちがえやすいかが、自分だけの 地図に なるで。'],
    ['問題を 自分で 1つ つくってみる', 'つくる 側に なると、しくみが よく わかるで。'],
    ['むずかしい 問題は 小さく 分けて 考える', '一歩ずつ なら、大きな 山も のぼれるで。'],
    ['かんたんな 数で ためしてみる', '大きな 数で こまったら、小さな 数で しくみを さがすんや。'],
    ['ことばの 意味を 自分の ことばで 言いかえる', '言いかえられたら、ほんまに わかった しるしやで。'],
    ['大事な ところを 色ペン 1色で まとめる', '色を しぼると、ほんまに 大事な ところが 目立つで。'],
    ['教科書の 例題を まねして といてみる', 'お手本を まねるのは、上手に なる 近道やで。'],
    ['時間を はかって といてみる', '自分の ペースが わかると、作戦が 立てやすいで。'],
    ['声に 出して 計算の 手順を 言う', '手順を 口に すると、とちゅうの まちがいに 気づけるで。'],
    ['漢字は 1回 書いたら、見ないで もう1回 書く', '見ないで 書けたら、頭に 入った しるしやで。'],
    ['読んだ 文の「いちばん 言いたいこと」を 1行に する', 'まとめる 力は、どの 教科でも つかえるで。'],
    ['まちがえた 理由を 1つ 書いておく', '理由が わかれば、次は 同じ まちがいを せえへんで。'],
    ['しらべた ことを 絵や 図に する', '目で 見える 形に すると、おぼえやすいで。'],
    ['友だちと 問題を 出しあう', '出す 側も とく 側も、どっちも 力に なるで。'],
    ['答えが 出たら「本当に そうかな？」と 1回 考える', 'たしかめる くせは、かしこさの もとやで。'],
    ['ふせんに 1つだけ 書いて 目に つく ところに はる', '何回も 見るうちに、自然と おぼえるで。'],
    ['わかった ところと わからない ところを 分ける', 'わからない ところだけ やれば、時間が むだに ならへんで。'],
    ['ときかたを 2とおり 考えてみる', 'べつの 道でも 同じ 答えなら、自信を もってええで。'],
    ['表に まとめて くらべる', 'ならべると、ちがいが ひと目で わかるで。'],
    ['教科書の 太字を さがして 読む', '太字は 教科書からの「ここ 大事やで」の 合図や。'],
    ['1つ おぼえたら、にている ものと セットに する', 'なかまで おぼえると、わすれにくいで。'],
    ['テストの 前は、まちがえた 問題から やりなおす', 'できる 問題より、できない 問題が 力を のばすで。'],
    ['おわりに「明日 やること」を メモする', '次の 日の スタートが 早く なるで。'],
    ['大事な ことは 3日後に もう一度 見る', 'わすれかけた ころに 見なおすと、ぐっと のこるで。']   /* SHINBUN_NETA_V1 一度 のせた ものは もう 出さないので ふやした */
  ];
  function pickFresh(list, pre, ws, n) {   // SHINBUN_NETA_V1 まだ のせていない ものだけを 週ごとに ずらして えらぶ
    var w = Math.floor(dms(ws) / (7 * 86400000)), out = [];
    for (var j = 0; j < list.length && out.length < n; j++) { var i = (w * n + j) % list.length; if (!old(pre + i)) out.push(i); }
    return out;
  }
  function tipsSec(ws) {
    var ix = pickFresh(TIPS, 'tip:', ws, 2);
    if (!ix.length) return '';
    return tag(sec('学び方 ミニ講座', ix.map(function (i) { var t = TIPS[i]; return '<div class="li"><b>● ' + esc(t[0]) + '</b><br>' + esc(t[1]) + '</div>'; }).join(''), 1, '', '阪神マンの ひとくち アドバイス'), ix.map(function (i) { return use('tip:' + i); }));
  }
  var SWITCH = [
    ['タイマーを 5分に して、まず 1問', '始めて しまえば、つづきは らくに なるで。'],
    ['やる 場所と 時間を 毎日 同じに する', '「ここに すわったら 勉強」と 体が おぼえるで。'],
    ['終わったら アプリで 天気を つける', 'その日の 気もちを 見える 形に すると、次の 作戦が 立てやすいで。'],
    ['できた 問題に 色を ぬる', 'ぬった ところが ふえると、自分の のびが 目で わかるで。'],
    ['すきな 単元から 始める', '気もちが のってきたら、ほかの 単元にも 進みやすいで。'],
    ['おうちの人に「今日 やること」を 言ってから 始める', '言葉に すると、やる ことが はっきり するで。'],
    ['やる 前に 机の 上を かたづける', 'すっきりした 机は、頭も すっきりさせるで。'],
    ['「5問 やったら 休けい」と 先に 決める', 'ゴールが 見えると、がんばりやすいで。'],
    ['できたら カレンダーに しるしを つける', 'しるしが ならぶと、つづけたく なるで。'],
    ['きのうの 自分と くらべる', 'くらべる あいては、いつも きのうの 自分で ええねん。'],
    ['むずかしい ときは「まだ できない だけ」と 言ってみる', '「まだ」を つけると、のびる 気もちに なるで。'],
    ['やる気が 出ない 日は、いちばん かんたんな 1問だけ', '1問 できたら、それで 大きな 前進や。'],
    ['のびを してから はじめる', '体を うごかすと、頭も 目を さますで。'],
    ['水を 1ぱい 飲んでから はじめる', 'ちょっとした ことで、気もちが きりかわるで。'],
    ['目ひょうを 声に 出して 言う', '言った ことばは、自分の 背中を おしてくれるで。'],
    ['できた 問題の 数を 数える', 'ふえていく 数は、がんばった しょうこやで。'],
    ['とちゅうで 止まったら、次の 1行だけ 書く', '1行 書けば、また 手が 動きだすで。'],
    ['おうちの 人に できた ことを 1つ 話す', '話すと、うれしさが ふえるで。'],
    ['勉強する 時間に 名前を つける', '「修行タイム」なんて よぶと、ちょっと わくわくするで。'],
    ['終わる 時こくを 先に 決める', '終わりが 決まっていると、集中しやすいで。'],
    ['にがてな ものは 元気な 時間に やる', '元気な ときなら、むずかしい ことも のりこえやすいで。'],
    ['まちがえても「おしい！」と 言う', 'まちがいは、正かいへの 道しるべやで。'],
    ['道具を 先に ぜんぶ そろえる', 'さがす 時間が なくなると、すぐ はじめられるで。'],
    ['きょう がんばる ことを 1つ だけ えらぶ', 'あれもこれもより、1つに しぼるほうが 進むで。'],
    ['すわる 前に ゆっくり いきを 3回', 'ゆっくり いきを すると、気もちが 落ちつくで。'],
    ['休けいの 長さは タイマーで 決める', '休みすぎを ふせげるで。'],
    ['お気に入りの えんぴつを つかう', '好きな 道具は、手を 動かしたく させるで。'],
    ['友だちと「今日 やること」を 言いあう', 'なかまが いると、がんばる 力が わいてくるで。'],
    ['きのうより 1問 多く やってみる', '小さな 1歩の つみかさねが、大きな 力に なるで。'],
    ['思うように 進まなかった 日は「明日の 作戦」を 1つ 考える', '作戦が あれば、明日は きっと 前に 進めるで。'],
    ['同じ 時間に 同じ 場所で 3日 つづける', '3日 つづくと、習かんの たまごが 生まれるで。'],
    ['終わったら 自分に「ようやった」と 言う', '自分を ほめるのも、だいじな 修行やで。'],
    ['好きな 教科を ごほうびに とっておく', 'にがてを 先に すませると、あとが 楽しみに なるで。'],
    ['はじめの 1分は 前回の ノートを 見るだけ', 'ながめる だけで、頭が じゅんび 運動を はじめるで。']
  ];
  function switchSec(ws) {
    var ix = pickFresh(SWITCH, 'sw:', ws, 2);
    if (!ix.length) return '';
    return tag(sec('やる気スイッチの 入れ方', ix.map(function (i) { var t = SWITCH[i]; return '<div class="li"><b>● ' + esc(t[0]) + '</b><br>' + esc(t[1]) + '</div>'; }).join(''), 1, '', '阪神マンの ひとくち アドバイス'), ix.map(function (i) { return use('sw:' + i); }));
  }
  // 🛡 SHINBUN_ADV_V1 冒険ニュース：その子が アプリで したことだけ（ほかの子の名前・勝ち負け・順位の数字は 出さない）
  var STRAT = { attack: 'こうげき 重視', guard: 'まもり 重視', weakness: '弱点ねらい', balance: 'バランス' };
  var MVPJ = { seme: 'はたらいた かず', nebari: 'のこった じかん', mamori: 'たえた わりあい', kufu: 'くふう' };
  function advLines(d) {
    var L = [], sp = d.lastWeekSpecial || {}, df = d.shinbun && d.shinbun.adv && d.shinbun.adv.def;
    if (df && Number(df.count) > 0) {
      var m = (df.monsters || []).filter(Boolean);
      L.push('🛡 <b>クラス基地防衛戦</b>　' + df.count + '回 出場' + (m.length ? '。' + m.map(function (x) { return '「' + esc(x) + '」'; }).join('と') + 'で' : '') + (STRAT[df.strategy] ? '、作戦は ' + STRAT[df.strategy] : ''));
      (df.mvp || []).forEach(function (k) { if (MVPJ[k]) L.push('🏅 <b>MVP</b>　「' + MVPJ[k] + '」部門に えらばれた'); });
    }
    var rp = d.rankPt;   /* SHINBUN_RANK_V1 順位は出さない。くらべるのは 前の週の その子だけ。へったときは 数だけ */
    if (rp && Number(rp.now) > 0) {
      var up = rp.prev != null && Number(rp.now) > Number(rp.prev);
      var up3 = up && rp.prev2 != null && Number(rp.prev) > Number(rp.prev2);
      L.push('🏆 <b>週間ランキング</b>　正解ポイント ' + Number(rp.now) + (up3 ? '（3週 つづけて のびている）' : up ? '（先週より ' + (Number(rp.now) - Number(rp.prev)) + ' ふえた）' : ''));
    }
    if (Number(sp.pokedex) > 0) L.push('📖 <b>図鑑</b>　新しく ' + Number(sp.pokedex) + 'ひき 登録');
    if (Number(sp.typeshoot) > 0) L.push('🎯 <b>タイプシュート</b>　' + Number(sp.typeshoot) + '点');
    if (Number(sp.wild) > 0) L.push('🌿 <b>野生</b>　' + Number(sp.wild) + 'ひきと 出会った');
    return L;
  }
  function specialSec(c) {
    var L = fresh(advLines(c.d), function (x) { return 'adv:' + nk(x); });
    if (!L.length) return '';
    return tag(sec('冒険ニュース', L.map(function (x) { return li(x); }).join(''), 2, 'news', 'アプリでの 1週間'), L.map(function (x) { return use('adv:' + nk(x)); }));
  }
  function wisdomSec(c) {
    var mp = c.mp, K = [], h = '';
    var mt = mp ? fresh(mp.tips, function (t) { return 'wis:' + nk(t); }) : [];
    var hn = fresh(c.hn || [], function (t) { return 'wis:' + nk(t); });
    if (mt.length) { h += '<div class="mute sm">' + esc(mp.from) + '</div>' + mt.map(function (t) { K.push(use('wis:' + nk(t))); return li('● ' + esc(t)); }).join(''); }
    if (hn.length) { if (mt.length) h += '<div class="mute sm">記録から 見えたこと</div>'; h += hn.map(function (t) { K.push(use('wis:' + nk(t))); return li('● ' + esc(t)); }).join(''); }
    if (!h) return '';
    return tag(sec('くらしの 知恵　きみに 合いそうな 学び方', h, mt.length ? 0 : 2), K);
  }
  function cando(c) {
    var cd = c.cd || {}, L = [], K = [];
    var all = (cd.head ? [esc(cd.head)] : []).concat(cd.lines || []);   // canDo の行は michi 側で esc ずみ
    fresh(all, function (l) { return 'cd:' + nk(l); }).forEach(function (l) { K.push(use('cd:' + nk(l))); L.push(li('● ' + l)); });
    return tag(sec('できるように なったこと', L.join(''), 0), K);
  }
  function ayumiSec(c) {
    var ov = c.d.overview || {}, a = [];
    if (Number(ov.totalSubmissions) > 0) a.push([ov.totalSubmissions, '家庭学習の 回数']);
    if (Number(ov.totalMinutes) >= 60) a.push([Math.round(ov.totalMinutes / 60), 'やった 時間（時間）']);
    if (Number(ov.maxStreak) >= 2) a.push([ov.maxStreak, 'いちばん 長い れんぞく（日）']);
    if (!a.length) return '';
    var ak = 'ayumi:' + a.map(function (x) { return x[0]; }).join('-'); if (old(ak)) return '';
    var pa = String(prevV('S:ayumi') || '').split('-');
    use(ak); use('S:ayumi', a.map(function (x) { return x[0]; }).join('-'));
    return tag(sec('4月からの あゆみ', '<div class="nums">' + a.map(function (x, i) { var p = Number(pa[i]); return '<div><b>' + x[0] + '</b><small>' + x[1] + (pa.length === a.length && p >= 0 && Number(x[0]) > p ? '<br>前の号から ＋' + (Number(x[0]) - p) : '') + '</small></div>'; }).join('') + '</div>', 3), [ak]);
  }
  function classSec(c) {
    var t = c.ai && c.ai.cls; if (!t) return '';
    var tk = 'cls:' + nk(t); if (old(tk)) return '';
    return tag(sec('教室から', '<p>' + esc(cut(t, 90)) + '</p>', 0, '', '学校での 学習の ようす'), [use(tk)]);
  }
  function teacherSec(c) {
    var lo = ymd(dms(c.ws) - 7 * 86400000), hi = ymd(dms(c.ws) + 13 * 86400000);   /* SHINBUN_FRESH_V1 この週と その前の週だけ（古いメモは 紙に のせない） */
    var ns = (c.d.teacherNotes || []).filter(function (n) { var dk = String((n && n.dayKey) || ''); return n && n.showInKarte && String(n.body || '').trim() && dk >= lo && dk <= hi; }).slice(0, 3);
    ns = fresh(ns, function (n) { return 'tn:' + nk(n.body); });
    if (!ns.length) return '';
    return tag(sec('先生から', ns.map(function (n) { return li((n.dayKey ? '<span class="mute">' + esc(jaS(n.dayKey)) + '</span> ' : '') + esc(cut(n.body, 60))); }).join(''), 0), ns.map(function (n) { return use('tn:' + nk(n.body)); }));
  }

  // ───────── 🧩 SHINBUN_QUIZ_V1 きみクイズ（読むだけ。こたえは さかさまに 下に）─────────
  //  その子の 記録から 3問。同じ しつもんでも こたえが かわれば 新しい ネタ。こたえが 前の号と 同じなら 出さない。
  function hashN(x) { x = String(x || ''); var h = 2166136261 >>> 0; for (var i = 0; i < x.length; i++) { h ^= x.charCodeAt(i); h = Math.imul(h, 16777619) >>> 0; } return h; }
  function shuf(a, seed) { a = a.slice(); var h = seed >>> 0; for (var i = a.length - 1; i > 0; i--) { h = Math.imul(h ^ (h >>> 15), 2246822507) >>> 0; h = (h + 0x9e3779b9) >>> 0; var j = h % (i + 1); var t = a[i]; a[i] = a[j]; a[j] = t; } return a; }
  function quizSec(c, facts, rows, seed) {
    var d = c.d, ov = d.overview || {}, lw = d.lastWeek || {}, Q = [];
    var nums = function (n, u) { n = Number(n); var a = [n, n + 3, Math.max(1, n - 3)]; if (a[2] === n) a[2] = n + 6; return a.map(function (x) { return x + u; }); };
    var us = (d.subjects || []).filter(function (x) { return Number(x.total) > 0; }).sort(function (a, b) { return (Number(b.total) || 0) - (Number(a.total) || 0); });
    if (us.length >= 3 && Number(us[0].total) > Number(us[1].total)) Q.push(['u1', '4月から いちばん たくさん 修行した 単元は？', c.unitName(us[0].unit), [us[0], us[1], us[2]].map(function (x) { return c.unitName(x.unit); })]);
    if (facts.days >= 2 && facts.longest) { var lg = rows.filter(function (r) { return r.s && (Number(r.s.minutes) || 0) === facts.longest.m; }); if (lg.length === 1) { var ot = WD.filter(function (w) { return w !== facts.longest.wd; }); Q.push(['lg', '先週、いちばん 長く 家庭学習を した 曜日は？', facts.longest.wd + '曜日', [facts.longest.wd].concat(shuf(ot, seed).slice(0, 2)).map(function (w) { return w + '曜日'; })]); } }
    if (Number(lw.total) > 0) Q.push(['lw', '先週 アプリで といた 問題は ぜんぶで 何問？', lw.total + '問', nums(lw.total, '問')]);
    if (Number(ov.totalSubmissions) >= 3) Q.push(['tot', '4月から 家庭学習を 出した 回数は？', ov.totalSubmissions + '回', nums(ov.totalSubmissions, '回')]);
    if (Number(ov.maxStreak) >= 2) Q.push(['stk', '今年度、家庭学習が いちばん 長く つづいたのは 何日？', ov.maxStreak + '日', nums(ov.maxStreak, '日')]);
    var mt = (d.monthlyTrends || []).filter(function (m) { return Number(m.count) > 0; });
    if (mt.length >= 3) { var sm = mt.slice().sort(function (a, b) { return Number(b.count) - Number(a.count); }); if (Number(sm[0].count) > Number(sm[1].count)) { var mj = function (m) { return Number(String(m.month || '').slice(5)) + '月'; }; Q.push(['mon', '4月から、家庭学習を いちばん 多く 出した 月は？', mj(sm[0]), [sm[0], sm[1], sm[2]].map(mj)]); } }
    var wc = { sun: 0, cloud: 0, rain: 0 }; rows.forEach(function (r) { if (r.s && wc[r.s.end_weather] != null) wc[r.s.end_weather]++; });
    var wk = ['sun', 'cloud', 'rain'].sort(function (a, b) { return wc[b] - wc[a]; });
    if (facts.days >= 2 && wc[wk[0]] > wc[wk[1]]) Q.push(['wx', '先週の きもちの 天気で、いちばん 多かったのは？', WXJ[wk[0]], ['sun', 'cloud', 'rain'].map(function (k) { return WXJ[k]; })]);
    var fn = global._subjectArea, st = {}, SN = { math: '算数', jp: '国語', soc: '社会', sci: '理科', eng: '英語' };
    if (typeof fn === 'function') { (d.subjects || []).forEach(function (x) { var k = fn(x.unit); if (k && SN[k]) st[k] = (st[k] || 0) + (Number(x.total) || 0); }); var sk = Object.keys(st).sort(function (a, b) { return st[b] - st[a]; }); if (sk.length >= 2 && st[sk[0]] > st[sk[1]]) { var ch = sk.slice(0, 3).map(function (k) { return SN[k]; }); if (ch.length < 3) ch.push(['算数', '国語', '社会', '理科'].filter(function (x) { return ch.indexOf(x) < 0; })[0]); Q.push(['sbj', '4月から アプリで いちばん たくさん 修行した 教科は？', SN[sk[0]], ch]); } }
    var qs = shuf(Q.filter(function (q) { return !old('quiz:' + q[0] + ':' + nk(q[2])); }), seed).slice(0, 3);
    if (!qs.length) return '';
    var MK = ['ア', 'イ', 'ウ'], ans = [];
    var h = qs.map(function (q, i) {
      var cs = shuf(q[3], seed + i * 7);
      ans.push((i + 1) + '…' + MK[cs.indexOf(q[2])]);
      return '<div class="qz"><b>Q' + (i + 1) + '</b> ' + esc(q[1]) + '<div class="ch">' + cs.map(function (x, j) { return '<span>' + MK[j] + ' ' + esc(x) + '</span>'; }).join('') + '</div></div>';
    }).join('') + '<div class="ans">こたえ　' + ans.join('　') + '</div>';
    return tag(sec('きみクイズ', h, 2, 'quiz', '自分の 記録から 出題'), qs.map(function (q) { return use('quiz:' + q[0] + ':' + nk(q[2])); }));
  }

  // ───────── 見た目 ─────────
  var MINCHO = '"BIZ UDPMincho","Yu Mincho","YuMincho","Hiragino Mincho ProN","Noto Serif CJK JP","Noto Serif JP",serif';
  var GOTHIC = '"BIZ UDPGothic","Yu Gothic","YuGothic","Meiryo","Hiragino Sans","Noto Sans CJK JP",sans-serif';
  var CSS = [
    '@page{size:A4;margin:0}',
    '*{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact}',
    'html,body{margin:0;padding:0}',
    'body{background:#d6d3c8;color:#1c1c1c}',
    '@media print{body{background:none}.pg{margin:0!important;box-shadow:none!important}}',
    '.pg{--fs:12px;--acc:#c8312b;font-family:' + GOTHIC + ';font-size:var(--fs);line-height:1.55;width:210mm;height:297mm;margin:8px auto;background:#fbfaf4;padding:6.5mm 7.5mm 5mm;display:flex;flex-direction:column;overflow:hidden;break-after:page;page-break-after:always;position:relative;contain:strict}'   /* SHINBUN_FAST_V1 1ページずつ べつに 計算させる（全員ぶんで 止まらないように） */,
    '.pg.last{break-after:auto;page-break-after:auto}',
    '.qz{padding:1px 0;border-bottom:1px dotted #999}.qz b{color:var(--acc)}.qz .ch{display:flex;gap:8px;flex-wrap:wrap;padding-left:1.4em}.ans{transform:rotate(180deg);text-align:center;font-size:.85em;color:#5a5a55;margin-top:2px}',   /* SHINBUN_QUIZ_V1 */
    '.mc,.pg h1,.pg h2,.hl,.sub,.logo,.nums b{font-family:' + MINCHO + '}',
    '.pg p{margin:0 0 .2em;text-indent:1em}',
    '.mute{color:#5a5a55}.sm{font-size:.9em;margin-top:.25em}',
    '.mast{display:flex;align-items:flex-end;gap:10px;border-bottom:4px double #1c1c1c;padding-bottom:3px;flex:0 0 auto}',
    '.logo{background:var(--acc);color:#fff;font-weight:800;font-size:28px;line-height:1;padding:7px 11px 5px}',
    '.logo small{display:block;font-size:10px;font-weight:700;letter-spacing:.3em;margin-top:3px}',
    '.who{flex:1;font-size:12px}.who b{font-family:' + MINCHO + ';font-size:21px}',
    '.ear{border:1.5px solid #1c1c1c;background:#fff;padding:2px 7px;font-size:10px;line-height:1.45;max-width:46mm}.ear b{color:var(--acc)}',
    '.no{text-align:right;font-size:10px;line-height:1.45}.no b{font-size:13px}',
    '.top{flex:0 0 auto;border-bottom:1.5px solid #1c1c1c;padding:3px 0 4px}',
    '.kick{display:inline-block;background:#1c1c1c;color:#fff;font-size:10px;font-weight:700;padding:0 8px}',
    '.hl{font-weight:800;font-size:2.45em;line-height:1.15;margin:2px 0 1px}',
    '.sub{font-weight:700;font-size:1.25em;color:var(--acc);margin-bottom:3px}',
    '.art{column-count:4;column-gap:10px;column-rule:1px solid #bbb}',
    '.by{font-size:.8em;color:#5a5a55;text-align:right;margin-top:1px}',
    '.flow{flex:1 1 auto;min-height:0;column-count:3;column-gap:12px;column-rule:1px solid #1c1c1c;column-fill:balance;overflow:hidden;margin-top:3px}',
    '.sec{break-inside:avoid;page-break-inside:avoid;margin:0 0 .45em;padding:0!important;border:0!important;background:none!important;border-radius:0!important}',
    '.pg h2{font-weight:800;font-size:1.22em;line-height:1.35;border-bottom:2px solid #1c1c1c;margin:0 0 .25em!important;padding-bottom:1px;display:block;color:#1c1c1c!important}',
    '.pg h2 small{font-family:' + GOTHIC + ';font-size:.66em;font-weight:400;color:#5a5a55;margin-left:.6em;white-space:nowrap}',
    '.li{padding:1px 0 1px 1.1em;text-indent:-1.1em;border-bottom:1px dotted #999}',
    '.li:last-child{border-bottom:0}',
    '.vo{font-size:.95em;padding:1px 0 1px 1.3em;text-indent:-1.3em;border-bottom:1px dotted #999}.vo b{color:var(--acc);margin-right:.3em}',
    '.wx{width:100%;border-collapse:collapse;text-align:center}.wx th{background:#1c1c1c;color:#fff;font-size:.9em}.wx td{border:1px solid #1c1c1c;padding:1px}.wx .ic{font-size:1.45em;line-height:1.2}.wx .m{font-weight:700;font-size:.85em}.wx td.off{color:#999}',
    '.col{background:#efece0!important;border:1.5px solid #1c1c1c!important;padding:4px 7px 5px!important}',
    '.col h2 .f{display:inline-flex;width:1.8em;height:1.8em;border-radius:50%;border:2px solid #1c1c1c;align-items:center;justify-content:center;background:#fff;margin-right:4px;font-size:.8em}',
    '.col h2{justify-content:flex-start}',
    '.col .q{margin-top:.3em;font-weight:700;border-left:4px solid var(--acc);padding-left:6px}',
    '.note{font-size:.75em;color:#94a3b8;margin-top:2px}',
    '.rd{display:flex;gap:5px;padding:2px 0;border-bottom:1px dotted #888}.rd .k{flex:0 0 1.7em;height:1.7em;border:2px solid #1c1c1c;display:flex;align-items:center;justify-content:center;font-weight:700;background:#fff}.rd .mute{font-size:.88em}',
    '.line{display:flex;align-items:flex-start;margin-top:2px}.st{flex:1;text-align:center;font-size:.85em;line-height:1.3}.st small{display:block;font-size:.85em}.st .dot{width:13px;height:13px;border-radius:50%;border:2px solid #1c1c1c;margin:0 auto 2px;background:#fff}.st.done .dot{background:#1c1c1c}.st.here .dot{background:var(--acc);border-color:var(--acc)}.st.here{color:var(--acc);font-weight:700}.ln{flex:0 0 6px;border-top:2px solid #1c1c1c;margin-top:7px}',
    '.news .li b{font-family:' + MINCHO + '}',
    '.nums{display:flex;gap:4px;text-align:center}.nums div{flex:1;border:1.5px solid #1c1c1c;background:#fff;padding:1px}.nums b{font-size:1.6em;font-weight:800;line-height:1.2}.nums i{font-style:normal;font-size:.8em}.nums small{display:block;font-size:.75em;line-height:1.3}',
    '.memo-wrap{flex:0 0 auto;margin-top:3px}',
    '.tb{width:100%;border-collapse:collapse;font-size:.9em}.tb th{background:#efece0;border:1px solid #1c1c1c;font-weight:700;padding:1px 3px}.tb td{border:1px solid #1c1c1c;padding:1px 4px}.tb td.n{text-align:right;font-weight:700;white-space:nowrap}.tb td.c{text-align:center}.memo .w1{width:6%}.memo .w2{width:8%}.memo .w3{width:30%}.memo .w4{width:14%}',
    '.meter{display:inline-block;height:7px;background:#1c1c1c;vertical-align:middle}.meter.r{background:var(--acc)}',
    '.home{margin-top:2px}',
    '.qa{margin:0}.qa dt{font-weight:700;margin-top:2px}.qa dt:before{content:"Q ";color:var(--acc)}.qa dd{margin:0 0 1px;padding-left:1.2em;border-bottom:1px dotted #bbb}.qa dd:before{content:"A ";font-weight:700;margin-left:-1.2em}',
    '.src{font-size:.75em;color:#5a5a55;text-align:right}',
    '.cmp{display:flex;gap:5px}.cmp div{flex:1;border:1.5px solid #1c1c1c;background:#fff;padding:3px 5px;font-size:.92em}.cmp div b{display:block;border-bottom:1px solid #1c1c1c;margin-bottom:1px}.cmp .now{border-color:var(--acc)}.cmp .now b{color:var(--acc);border-color:var(--acc)}',
    '.alb{font-family:' + MINCHO + ';font-weight:700}.alb small{font-family:' + GOTHIC + ';font-weight:400;color:#5a5a55}',
    '.yokoku{border:2px solid var(--acc)!important;padding:3px 7px!important;background:#fff!important}.yokoku h2{color:var(--acc)!important;border-color:var(--acc)}.yokoku .t{font-family:' + MINCHO + ';font-weight:800;font-size:1.15em}',
    '.bg{width:100%;border-collapse:collapse;table-layout:fixed}.bg td{vertical-align:bottom;text-align:center;height:7.6em;padding:0 3px;border-bottom:2px solid #1c1c1c;font-size:.8em;font-weight:700}.bg td i{display:block;background:#1c1c1c;margin:0 auto;width:70%}.bg td.now i{background:var(--acc)}.bg tr.lb td{height:auto;border:0;font-weight:400;padding-top:1px}',
    '.ratio{display:flex;height:15px;border:1.5px solid #1c1c1c}.ratio i{display:flex;align-items:center;justify-content:center;font-size:.75em;font-weight:700;font-style:normal;white-space:nowrap;overflow:hidden}',
    '.after{flex:0 0 auto;background:#efece0;border-top:2px solid #1c1c1c;padding:3px 8px;margin-top:3px}.after b{font-family:' + MINCHO + '}',
    '.foot{flex:0 0 auto;display:flex;justify-content:space-between;border-top:4px double #1c1c1c;padding-top:2px;margin-top:3px;font-size:9px;color:#666}',
    '.pg .sec div[style]{font-size:inherit!important}',
    '.pf-ph{margin:0 0 3px;break-inside:avoid}.pf-ph img{display:block;width:100%;max-height:52mm;object-fit:contain;border:1px solid #1c1c1c;background:#fff}.pf-ph figcaption{font-size:.75em;color:#5a5a55;text-align:right}'   /* SHINBUN_PHOTO_V1 */   // 📓（portfolio.js）の中の小さな字も 新聞の大きさに
  ].join('\n');

  // 印刷の窓で：あふれたら字を小さく → それでも だめなら data-opt の小さい順に省く → あまったら 字を大きく
  var FIT = '<script>(function(){' +
    'function over(f){return f.scrollWidth>f.clientWidth+2||f.scrollHeight>f.clientHeight+2;}' +
    'function fitOne(p){var f=p.querySelector(".flow");if(!f)return;var fs=12,MIN=10,MAX=16;p.style.setProperty("--fs",fs+"px");' +
    'while(over(f)&&fs>MIN){fs=Math.round((fs-0.25)*100)/100;p.style.setProperty("--fs",fs+"px");}' +
    'while(over(f)){var os=f.querySelectorAll("[data-opt]"),op=null;for(var k=0;k<os.length;k++){var v=Number(os[k].getAttribute("data-opt"));if(v>0&&(!op||v<Number(op.getAttribute("data-opt"))))op=os[k];}if(!op)break;op.parentNode.removeChild(op);}' +
    'if(fs>=12){while(!over(f)&&fs<MAX){fs=Math.round((fs+0.25)*100)/100;p.style.setProperty("--fs",fs+"px");}if(over(f)){fs=Math.round((fs-0.25)*100)/100;p.style.setProperty("--fs",fs+"px");}}' +
    'p.setAttribute("data-fs",String(fs));}' +
    'function fit(){var ps=document.querySelectorAll(".pg.np");for(var i=0;i<ps.length;i++){if(!ps[i].getAttribute("data-fs"))fitOne(ps[i]);}}' +
    'try{fit();}catch(e){}' +
    'function again(){try{var ps=document.querySelectorAll(".pg.np");for(var i=0;i<ps.length;i++)ps[i].removeAttribute("data-fs");fit();}catch(e){}}' +
    'try{if(document.fonts&&document.fonts.status!=="loaded"&&document.fonts.ready)document.fonts.ready.then(again);}catch(e){}' +   /* SHINBUN_FAST_V1 やりなおしは 字が あとから そろったときだけ */
    '})();<\/script>';

  // 🗞 SHINBUN_NETA_V1 印刷の あとで、紙に のこった 欄の ネタだけを 記録する（はみ出して 省いた欄は 記録しない）
  var SAVE = '<script>(function(){if(window.__netaSaver)return;window.__netaSaver=1;var sent=false;' +
    'function collect(){var out=[];var vs=document.querySelectorAll("script.neta-v");for(var i=0;i<vs.length;i++){var v=vs[i],uid=v.getAttribute("data-uid"),ws=v.getAttribute("data-ws"),map={};try{map=JSON.parse(v.textContent)||{};}catch(e){}' +
    'var keep={},els=document.querySelectorAll(".pg[data-uid=\\""+uid+"\\"] [data-nk]");for(var j=0;j<els.length;j++){String(els[j].getAttribute("data-nk")||"").split("|").forEach(function(k){if(k)keep[k]=1;});}' +
    'Object.keys(map).forEach(function(k){if(k.indexOf("S:")!==0)return;var b=k.slice(2);if(b==="tot"||Object.keys(keep).some(function(x){return x.indexOf(b+":")===0;}))keep[k]=1;});' +
    'var items=Object.keys(keep).map(function(k){return {k:k,v:map[k]==null?"":map[k]};});if(uid&&items.length)out.push({userId:uid,ws:ws,items:items});}return out;}' +
    'function send(){if(sent)return;sent=true;var rows=collect();if(!rows.length)return;var o=window.opener||window;try{o.fetch("/api/teacher/karte-neta/save",{method:"POST",credentials:"include",headers:{"content-type":"application/json"},body:JSON.stringify({rows:rows})});}catch(e){}}' +
    'window.__netaCollect=collect;window.addEventListener("afterprint",send);})();<\/script>';

  // ───────── 👫 SHINBUN_NAME_V1 友だちの名前は 紙に出さない ─────────
  //  子どもが書いた ことば（ふりかえり・インタビュー・おうちの人の ひとこと など）に クラスの子の名前があれば「友だち」にする。
  //  題字の「今週の主役」以外の 本文ぜんぶに かける（タグの中・写真の data: には さわらない）。
  //  名前のもと：名簿（getStudentNameMap）・ふりがな（_serverFuriganaMap）・児童一覧（_lastStudentSummaries）。
  //  漢字の名前は 先頭2〜3文字（名字だけで 書かれたとき）も。ひらがなは 名前ぜんぶ（3文字以上）だけ（「ゆうがた」などを こわさないため）。
  function nameList() {
    var c = [], push = function (v, min) { v = String(v == null ? '' : v).replace(/[\s　]+/g, '').trim(); if (v.length >= min && c.indexOf(v) < 0) c.push(v); };
    var kanji = function (v) { v = String(v || '').replace(/[\s　]+/g, ''); push(v, 2); if (/^[\u4e00-\u9fff々]{2,}/.test(v)) { var m = v.match(/^[\u4e00-\u9fff々]+/)[0]; if (m.length >= 2) { push(m.slice(0, 2), 2); push(m.slice(0, 3), 3); } } };
    try { var m = typeof global.getStudentNameMap === 'function' ? (global.getStudentNameMap() || {}) : {}; Object.keys(m).forEach(function (k) { kanji(m[k]); }); } catch (e) {}
    try { var f = global._serverFuriganaMap || {}; Object.keys(f).forEach(function (k) { push(f[k], 3); }); } catch (e) {}
    try { (global._lastStudentSummaries || []).forEach(function (st) { kanji(st && st.name); }); } catch (e) {}
    c.sort(function (a, b) { return b.length - a.length; });
    return c;
  }
  function maskNames(html, names) {
    if (!names || !names.length) return html;
    return String(html).replace(/>([^<]+)</g, function (all, tx) {
      var t = tx;
      for (var i = 0; i < names.length; i++) if (t.indexOf(names[i]) >= 0) t = t.split(names[i]).join('友だち');
      return '>' + t + '<';
    });
  }

  // ───────── 組み立て ─────────
  function build(c) {
    var d = c.d || {};
    c.unitName = function (id) { var inf = c.unitInfo ? c.unitInfo(id) : null; return (inf && inf.name) || (global._unitJa ? global._unitJa(id) : id); };
    var ws = weekStart(d); c.ws = ws;
    NT = { m: d.neta || {}, ws: ws, used: {} };   /* SHINBUN_NETA_V1 */
    var uid = String((d.student && d.student.id) || '');
    var no = issueNo(ws), seed = hashN(uid + ':' + ws);
    var ACC = ['#c8312b', '#1d4ed8', '#047857', '#7c3aed', '#c2410c', '#0e7490'];   /* 号ごとに 題字の 色が かわる */
    var acc = ACC[no % ACC.length];
    var days = weekDays(ws), rows = weekRows(d, days);
    var facts = { days: 0, minutes: 0, longest: null };
    rows.forEach(function (r) { if (!r.s) return; facts.days++; var m = Number(r.s.minutes) || 0; facts.minutes += m; if (!facts.longest || m > facts.longest.m) facts.longest = { wd: r.wd, m: m }; });
    var wcount = { sun: 0, cloud: 0, rain: 0 }; rows.forEach(function (r) { if (r.s && wcount[r.s.end_weather] != null) wcount[r.s.end_weather]++; });
    var wtxt = ['sun', 'cloud', 'rain'].filter(function (k) { return wcount[k]; }).map(function (k) { return WXJ[k] + (wcount[k] > 1 ? wcount[k] : ''); }).join('・');
    var nm = String(c.name || '').replace(/\s*さん.*$/, '').trim() || '主役';
    var ta = topArticle(c, rows, facts);
    var tk = 'top:' + nk(ta.head);
    if (old(tk) && ta.ai) { ta = topArticle(c, rows, facts, true); tk = 'top:' + nk(ta.head); }   /* SHINBUN_NETA_V1 前の号と 同じ 見出しは つかわない */
    if (old(tk)) {
      var lw0 = d.lastWeek || {}, alts = [];
      if (facts.days > 0) alts.push('今週は ' + facts.days + '日・' + facts.minutes + '分');
      if (Number(lw0.total) > 0) alts.push('アプリで ' + lw0.total + '問に 挑戦');
      alts.push('第' + no + '号　' + (String(c.name || '').replace(/\s*さん.*$/, '').trim() || '主役') + 'さんの 1週間');
      for (var ai2 = 0; ai2 < alts.length; ai2++) { if (!old('top:' + nk(alts[ai2])) || ai2 === alts.length - 1) { ta.head = alts[ai2]; break; } }
      tk = 'top:' + nk(ta.head);
    }
    use(tk);

    var mast = '<div class="mast"><div class="logo">道しるべ新聞<small>阪神マン新聞社 発行</small></div>' +
      '<div class="who">今週の 主役　<b>' + esc(nm) + '</b> さん</div>' +
      (facts.days ? '<div class="ear">きょうの<b>天気</b>：' + esc(wtxt || '―') + '<br>家庭学習 ' + facts.days + '日・' + facts.minutes + '分</div>' : '') +
      '<div class="no">' + esc(ja(days[0])) + '〜' + esc(ja(days[4])) + '号<br><b>第' + issueNo(ws) + '号</b></div></div>';
    var top = '<div class="top" data-nk="' + esc(tk) + '"><span class="kick">今週の トップ</span><div class="hl">' + esc(ta.head) + '</div>' + (ta.sub ? '<div class="sub">' + esc(ta.sub) + '</div>' : '') + '<div class="art">' + ta.body + '<div class="by">' + esc(ta.by) + '</div></div></div>';

    /* SHINBUN_NETA_V1 欄の ならびも 号ごとに かえる（コラムは 1面の 頭のほう・天気は 1面に のこす） */
    var F0 = [weatherSec(rows), columnSec(c)], F1 = [voicesSec(rows), numsSec(c, facts), progressSec(c), newsSec(c, facts), roadsSec(c), triesSec(c), hqSec(c), lessonSec(c), quizSec(c, facts, rows, seed)];
    var F = shuf(F0, seed).concat(shuf(F1, seed + 1)).join('');
    var B = shuf([interviewSec(c, ws), compareSec(c, facts, rows), '<!--PF_WORK-->', backSec(c), yokokuSec(c), classSec(c), trainSec(c), monthSec(c), moodSec(c), subjSec(c), unitsSec(c), specialSec(c), wisdomSec(c), cando(c), ayumiSec(c), teacherSec(c)], seed + 2).concat([tipsSec(ws), switchSec(ws)]).join('');
    var afk = c.ai && c.ai.after ? 'after:' + nk(c.ai.after) : '';
    var after = afk && !old(afk) ? '<div class="after" data-nk="' + esc(use(afk)) + '"><b>編集後記</b>　' + esc(cut(c.ai.after, 90)) + '（阪神マン）</div>' : '';
    var foot = function (n) { return '<div class="foot"><span>LearningBM ／ 道しるべ新聞（学びの道しるべ）</span><span>' + n + '面</span></div>'; };

    var NM = nameList(), mk = function (x) { return maskNames(x, NM); };   /* SHINBUN_NAME_V1 */
    top = mk(top); F = mk(F); B = mk(B); after = mk(after);
    var memo = mk(memoTable(rows));
    return '<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>道しるべ新聞</title><style>' + CSS + '</style></head><body>' +
      '<div class="pg np" data-uid="' + esc(uid) + '" style="--acc:' + acc + '">' + mast + top + '<div class="flow">' + F + '</div>' + memo + foot(1) + '</div>' +
      '<div class="pg np last" data-uid="' + esc(uid) + '" style="--acc:' + acc + '"><div class="mast"><div class="mc" style="font-size:19px;font-weight:800;flex:1">道しるべ新聞　2面</div><div class="no">今週の 主役　' + esc(nm) + ' さん<br>' + esc(ja(days[0])) + '〜' + esc(ja(days[4])) + '号</div></div>' +
      '<div class="flow">' + B + '</div>' + after + foot(2) + '</div>' + FIT +
      (uid ? '<script type="application/json" class="neta-v" data-uid="' + esc(uid) + '" data-ws="' + esc(ws) + '">' + JSON.stringify(NT.used).replace(/</g, '\\u003c') + '<\/script>' + SAVE : '') + '</body></html>';
  }

  global.KARTE_SHINBUN = build;
  global.__SHINBUN_FRESH = true;
  global.__SHINBUN_T = { maskNames: maskNames, nameList: nameList, advLines: advLines, weekStart: weekStart, weekRows: weekRows, topArticle: topArticle, issueNo: issueNo, isoWeek: isoWeek, headlinesOf: headlinesOf, CSS: CSS };
})(window);
