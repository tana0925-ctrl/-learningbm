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
  function topArticle(c, rows, facts) {
    var ai = c.ai, d = c.d, q = bestQuote(rows);
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
    if (Number(ov.totalSubmissions) > 0) P.push('4月からの 家庭学習は ' + ov.totalSubmissions + '回' + (Number(ov.maxStreak) >= 2 ? '、いちばん 長く つづいたのは ' + ov.maxStreak + '日。' : '。'));
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
    var v = rows.filter(function (r) { return r.s && quoteOf(r.s); });
    if (!v.length) return '';
    return sec('わたしの ことば', v.map(function (r) { return '<div class="vo"><b>' + r.wd + '</b>' + esc(cut(quoteOf(r.s), 60)) + '</div>'; }).join(''), 0, '', '毎日の ふりかえり');
  }
  function columnSec(c) {
    var ai = c.ai;
    if (!ai || !ai.main) {
      if (c.stale) return sec('🐯 阪神マン記者の コラム', '<p class="mute">（新しい コラムは 先生が 公開すると ここに 出ます）</p>', 1, 'col');
      return '';
    }
    var paras = String(ai.main).split(/\n+/).map(function (p) { return p.trim(); }).filter(Boolean);
    var h = paras.map(function (p) { return '<p>' + esc(p) + '</p>'; }).join('');
    if (ai.ask) h += '<div class="q">💭 ' + esc(cut(ai.ask, 70)) + '</div>';
    if (ai.hint) h += '<div class="sm">📮 <b>出し方のヒント</b> … ' + esc(cut(ai.hint, 50)) + '</div>';
    if (ai.test) h += '<div class="sm">📝 <b>テストに向けて</b> … ' + esc(cut(ai.test, 50)) + '</div>';
    if (!ai.hint && !ai.test && c.tsFact) h += '<div class="sm">📮 ' + esc(c.tsFact) + '</div>';
    if (c.hanNote) h += '<div class="note">' + esc(c.hanNote) + '</div>';
    return '<section class="sec col"><h2><span class="f">🐯</span>阪神マン記者の コラム</h2>' + h + '</section>';
  }
  function roadsSec(c) {
    var r = c.reco, mp = c.mp;
    var help = '<div class="sm">🛟 <b>こまったら</b>：' + (mp && mp.help ? esc(mp.help) + '。ほかにも ' : '') + (mp && mp.dom === 'inter' ? 'ヒントを見る・家の人に聞く' : 'ヒントを見る・友だちに聞く・先生に聞く・家の人に聞く') + '</div>';
    if (r) {
      var h = '<div class="rd"><span class="k">A</span><div><b>「' + esc(r.a.name) + '」を もう一度 かためる</b><div class="mute">' + esc(r.a.entry) + '</div><div class="mute">💡 ' + esc(cut(r.a.why, 60)) + '</div></div></div>';
      if (r.b) h += '<div class="rd"><span class="k">B</span><div><b>「' + esc(r.b.name) + '」の はじめに すすむ</b><div class="mute">' + esc(r.b.entry) + '</div><div class="mute">💡 ' + esc(cut(r.b.why, 60)) + '</div></div></div>';
      h += '<div class="rd"><span class="k">C</span><div><b>自分で 決める</b>' + (r.c && r.c.say ? '<div>「' + esc(cut(r.c.say, 46)) + '」</div><div class="mute">' + esc(cut(r.c.from, 48)) + '（かえても いいよ）</div>' : '<div class="mute">やりたいことを 自分で 決めても いいよ</div>') + '</div></div>';
      h += '<div class="sm">👣 <b>はじめの一歩</b>：いちばん かんたんな 1問だけ（5分で できる 大きさ）</div>' + help;
      return sec('特集　えらべる 3つの道', h, 0, 'roads', 'どれでも いいよ');
    }
    var st = c.step;
    if (st && st.info) {
      var p = st.info;
      return sec('特集　まずは ここから', '<div><b>アプリの 修行 → ' + esc(p.icon || '') + esc(p.subjName || '') + ' → ' + esc(p.gradeLabel || '') + ' →「' + esc(p.name || '') + '」</b></div><div class="mute">💡 ' + esc(cut(st.why, 70)) + '</div>' + help, 0, 'roads');
    }
    return '';
  }
  function triesSec(c) {
    if (!c.tries || !c.tries.length) return '';
    return sec('これ やってみる？', c.tries.map(function (t) { return li('● ' + esc(t)); }).join('') + '<div class="mute sm">やり方は どれでもOK：アプリの修行・ノートに書く・おうちの人に 問題を出してもらう など</div>', 0);
  }
  function progressSec(c) {
    var cards = c.cards || [];
    if (cards.length) {
      var LAB = { done: 'できた', here: 'いまここ', next: 'つぎ' };
      var h = '<div class="line">' + cards.map(function (x, i) { return (i ? '<div class="ln"></div>' : '') + '<div class="st ' + x.k + '"><div class="dot"></div>' + esc(x.name) + (x.sub ? '<small>（' + esc(x.sub) + '）</small>' : '') + '<br>' + LAB[x.k] + '</div>'; }).join('') + '</div>';
      return sec(esc((c.reco && c.reco.subjName) || '算数') + ' すすみぐあい', h, 0);
    }
    var mp = c.map;
    if (mp && mp.nodes && mp.nodes.length) {
      var seen = false;
      var h2 = '<div class="line">' + mp.nodes.slice(0, 4).map(function (n, i) { var k = n.here ? 'here' : (n.st === 'ok' ? 'done' : 'next'); if (n.here) seen = true; return (i ? '<div class="ln"></div>' : '') + '<div class="st ' + k + '"><div class="dot"></div>' + esc(n.name) + '<br>' + (n.here ? 'いまここ' : (n.st === 'ok' ? 'できた' : (seen ? 'つぎ' : ''))) + '</div>'; }).join('') + '</div>';
      return sec('算数 すすみぐあい', h2, 4);
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
    if (!L.length) return '';
    return sec('ニュース ななめ読み', L.slice(0, 5).map(function (x) { return li('● ' + x); }).join(''), 3, 'news');
  }
  function numsSec(c, facts) {
    var lw = c.d.lastWeek || {}, kw = c.d.teishutsu && c.d.teishutsu.karteWeek, a = [];
    if (facts.days > 0) { a.push([facts.days, '日', '家庭学習']); a.push([facts.minutes, '分', 'やった時間']); }
    if (Number(lw.total) > 0) a.push([lw.total, '問', 'アプリの修行']);
    if (kw && Number(kw.onTime) > 0) a.push([Number(kw.onTime), 'つ', 'しめきり前']);
    if (!a.length) return '';
    return sec('数字で 見る 先週', '<div class="nums">' + a.slice(0, 4).map(function (x) { return '<div><b>' + x[0] + '</b><i>' + x[1] + '</i><small>' + x[2] + '</small></div>'; }).join('') + '</div>', 4);
  }
  function hqSec(c) {
    var ha = (c.d.hanshinAnswers || []).filter(function (x) { return x && x.answer; })[0];
    if (!ha) return '';
    return sec('阪神マンからの しつもん', li('<b>しつもん</b>「' + esc(cut(ha.question, 50)) + '」') + li('<b>きみの 答え</b>「' + esc(cut(ha.answer, 70)) + '」'), 2);
  }
  function lessonSec(c) {
    var ls = (c.d.shinbun && c.d.shinbun.lesson) || [];
    if (!ls.length) return '';
    return sec('今週の 授業', ls.map(function (x) { return li('● ' + esc(x.subj) + '「' + esc(x.unit) + '」<span class="mute">（' + jaS(x.dayKey) + '）</span>'); }).join(''), 2, '', '学校で 学んだこと');
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
    if (!QA.length) return '';
    return sec('インタビュー　阪神マン記者が きいた', '<dl class="qa">' + QA.map(function (x) { return '<dt>' + esc(x[0]) + '</dt><dd>' + esc(x[1]) + '</dd>'; }).join('') + '</dl><div class="src">本人が アプリで 書いた ことば そのままです</div>', 0, '', '週の ふりかえりより');
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
  function albumSec(c) {
    var al = (c.d.shinbun && c.d.shinbun.album) || [];
    if (!al.length) return '';
    return sec('ことばの アルバム', al.map(function (x) { return '<div class="li alb">「' + esc(cut(x.text, 50)) + '」<small>（' + ja(x.dayKey) + '）</small></div>'; }).join(''), 2, '', '4月からの ふりかえりから');
  }
  function backSec(c) {
    var hs = headlinesOf(c.d.karteHist, c.d.aiComment);
    if (!hs.length) return '';
    return sec('バックナンバー', hs.map(function (x) { return li('<span class="mute">' + esc(jaS(x.at)) + '</span>「' + esc(cut(x.head, 26)) + '」'); }).join(''), 1, '', 'これまでの トップ記事');
  }
  function yokokuSec(c) {
    var nt = typeof global.michiNextTryOf === 'function' ? global.michiNextTryOf(c.d) : null;
    if (!nt || !nt.say) return '';
    return '<section class="sec yokoku"><h2>来週の 予告</h2><div class="t">「' + esc(nt.say) + '」</div><div class="mute sm">本人が 書いた「来週 やってみたいこと」</div></section>';
  }
  function trainSec(c) {
    var us = ((c.d.lastWeek || {}).units || []).slice(0, 5);
    if (!us.length) return '';
    var mx = Math.max.apply(null, us.map(function (u) { return Number(u.total) || 0; }).concat([1]));
    var h = '<table class="tb"><tr><th>単元</th><th class="w2">問題</th><th style="width:40%">とりくみ</th></tr>' + us.map(function (u, i) { return '<tr><td>' + esc(cut(c.unitName(u.unit), 16)) + (u.firstEver ? ' 🆕' : '') + '</td><td class="n">' + u.total + '</td><td><span class="meter' + (i ? '' : ' r') + '" style="width:' + Math.max(4, Math.round(u.total / mx * 100)) + '%"></span></td></tr>'; }).join('') + '</table>';
    return sec('修行 レポート', h, 2, '', '先週 アプリで とりくんだ 単元');
  }
  function monthSec(c) {
    var mt = (c.d.monthlyTrends || []).slice(-7);
    if (!mt.length) return '';
    var mx = Math.max.apply(null, mt.map(function (m) { return Number(m.count) || 0; }).concat([1]));
    var h = '<table class="bg"><tr>' + mt.map(function (m, i) { var v = Number(m.count) || 0; return '<td' + (i === mt.length - 1 ? ' class="now"' : '') + '>' + v + '<i style="height:' + (v ? Math.max(0.15, v / mx * 6.2).toFixed(2) : 0) + 'em"></i></td>'; }).join('') + '</tr><tr class="lb">' + mt.map(function (m) { return '<td>' + Number(String(m.month || '').slice(5)) + '月</td>'; }).join('') + '</tr></table>';
    return sec('月ごとの 家庭学習', h, 0, '', '4月から（回）');
  }
  function moodSec(c) {
    var ov = c.d.overview || {}, a = Number(ov.sunCount) || 0, b = Number(ov.cloudCount) || 0, r = Number(ov.rainCount) || 0, t = a + b + r;
    if (t < 3) return '';
    var w = function (n) { return Math.max(n ? 6 : 0, Math.round(n / t * 100)); };
    return sec('きもちの 天気の わりあい', '<div class="ratio"><i style="width:' + w(a) + '%;background:#f2c94c">☀ ' + a + '</i><i style="width:' + w(b) + '%;background:#c9d2de">☁ ' + b + '</i><i style="width:' + w(r) + '%;background:#7d8ca3;color:#fff">☂ ' + r + '</i></div><div class="mute sm">家庭学習を 出した日の 天気の 回数</div>', 3, '', '4月から');
  }
  function subjSec(c) {
    var fn = global._subjectArea; if (typeof fn !== 'function') return '';
    var A = [['math', '🔢 算数'], ['jp', '📝 国語'], ['soc', '🌏 社会'], ['sci', '🔬 理科'], ['eng', '🔤 英語']], tot = {};
    (c.d.subjects || []).forEach(function (s) { var k = fn(s.unit); if (k) tot[k] = (tot[k] || 0) + (Number(s.total) || 0); });
    var rows = A.filter(function (a) { return tot[a[0]] > 0; });
    if (!rows.length) return '';
    var mx = Math.max.apply(null, rows.map(function (a) { return tot[a[0]]; }));
    return sec('教科ごとの 修行', '<table class="tb">' + rows.map(function (a, i) { return '<tr><td style="width:24%;white-space:nowrap">' + a[1] + '</td><td><span class="meter' + (i ? '' : ' r') + '" style="width:' + Math.max(3, Math.round(tot[a[0]] / mx * 100)) + '%"></span></td><td class="n" style="width:16%">' + tot[a[0]] + '</td></tr>'; }).join('') + '</table>', 2, '', '4月から（問）');
  }
  function unitsSec(c) {   // 4月から いちばん とりくんだ 単元（問題の数だけ）
    var us = (c.d.subjects || []).filter(function (s) { return Number(s.total) >= 10; }).sort(function (a, b) { return (Number(b.total) || 0) - (Number(a.total) || 0); }).slice(0, 6);
    if (us.length < 2) return '';
    var mx = Number(us[0].total) || 1;
    return sec('単元の あゆみ', '<table class="tb">' + us.map(function (s, i) { return '<tr><td style="width:44%">' + esc(cut(c.unitName(s.unit), 16)) + '</td><td><span class="meter' + (i ? '' : ' r') + '" style="width:' + Math.max(3, Math.round(Number(s.total) / mx * 100)) + '%"></span></td><td class="n" style="width:16%">' + Number(s.total) + '問</td></tr>'; }).join('') + '</table>', 1, '', '4月から アプリで とりくんだ 単元');
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
    ['わからない ところを 言葉に してみる', '「どこが わからないか」が わかると、半分 とけたも 同じやで。']
  ];
  function tipsSec(ws) {
    var w = Math.floor(dms(ws) / (7 * 86400000)), L = [];
    for (var i = 0; i < 3; i++) { var t = TIPS[(w * 3 + i) % TIPS.length]; L.push('<div class="li"><b>● ' + esc(t[0]) + '</b><br>' + esc(t[1]) + '</div>'); }
    return sec('学び方 ミニ講座', L.join(''), 1, '', '阪神マンの ひとくち アドバイス');
  }
  var SWITCH = [
    ['タイマーを 5分に して、まず 1問', '始めて しまえば、つづきは らくに なるで。'],
    ['やる 場所と 時間を 毎日 同じに する', '「ここに すわったら 勉強」と 体が おぼえるで。'],
    ['終わったら アプリで 天気を つける', 'その日の 気もちを 見える 形に すると、次の 作戦が 立てやすいで。'],
    ['できた 問題に 色を ぬる', 'ぬった ところが ふえると、自分の のびが 目で わかるで。'],
    ['すきな 単元から 始める', '気もちが のってきたら、ほかの 単元にも 進みやすいで。'],
    ['おうちの人に「今日 やること」を 言ってから 始める', '言葉に すると、やる ことが はっきり するで。']
  ];
  function switchSec(ws) {
    var w = Math.floor(dms(ws) / (7 * 86400000)), L = [];
    for (var i = 0; i < 3; i++) { var t = SWITCH[(w * 3 + i) % SWITCH.length]; L.push('<div class="li"><b>● ' + esc(t[0]) + '</b><br>' + esc(t[1]) + '</div>'); }
    return sec('やる気スイッチの 入れ方', L.join(''), 1, '', '阪神マンの ひとくち アドバイス');
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
    if (Number(sp.pokedex) > 0) L.push('📖 <b>図鑑</b>　新しく ' + Number(sp.pokedex) + 'ひき 登録');
    if (Number(sp.typeshoot) > 0) L.push('🎯 <b>タイプシュート</b>　' + Number(sp.typeshoot) + '点');
    if (Number(sp.wild) > 0) L.push('🌿 <b>野生</b>　' + Number(sp.wild) + 'ひきと 出会った');
    return L;
  }
  function specialSec(c) {
    var L = advLines(c.d);
    if (!L.length) return '';
    return sec('冒険ニュース', L.map(function (x) { return li(x); }).join(''), 2, 'news', 'アプリでの 1週間');
  }
  function wisdomSec(c) {
    var mp = c.mp, hn = c.hn || [], h = '';
    if (mp) { h += '<div class="mute sm">' + esc(mp.from) + '</div>' + mp.tips.map(function (t) { return li('● ' + esc(t)); }).join(''); }
    if (hn.length) { if (mp) h += '<div class="mute sm">記録から 見えたこと</div>'; h += hn.map(function (t) { return li('● ' + esc(t)); }).join(''); }
    return sec('くらしの 知恵　きみに 合いそうな 学び方', h, mp ? 0 : 2);
  }
  function cando(c) {
    var cd = c.cd || {}; var L = [];
    if (cd.head) L.push(li('● ' + esc(cd.head)));
    (cd.lines || []).forEach(function (l) { L.push(li('● ' + l)); });   // canDo の行は michi 側で esc ずみ
    return sec('できるように なったこと', L.join(''), 0);
  }
  function ayumiSec(c) {
    var ov = c.d.overview || {}, a = [];
    if (Number(ov.totalSubmissions) > 0) a.push([ov.totalSubmissions, '家庭学習の 回数']);
    if (Number(ov.totalMinutes) >= 60) a.push([Math.round(ov.totalMinutes / 60), 'やった 時間（時間）']);
    if (Number(ov.maxStreak) >= 2) a.push([ov.maxStreak, 'いちばん 長い れんぞく（日）']);
    if (!a.length) return '';
    return sec('4月からの あゆみ', '<div class="nums">' + a.map(function (x) { return '<div><b>' + x[0] + '</b><small>' + x[1] + '</small></div>'; }).join('') + '</div>', 3);
  }
  function classSec(c) {
    var t = c.ai && c.ai.cls; if (!t) return '';
    return sec('教室から', '<p>' + esc(cut(t, 90)) + '</p>', 0, '', '学校での 学習の ようす');
  }
  function teacherSec(c) {
    var ns = (c.d.teacherNotes || []).filter(function (n) { return n && n.showInKarte && String(n.body || '').trim(); }).slice(0, 3);
    if (!ns.length) return '';
    return sec('先生から', ns.map(function (n) { return li((n.dayKey ? '<span class="mute">' + esc(jaS(n.dayKey)) + '</span> ' : '') + esc(cut(n.body, 60))); }).join(''), 0);
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
    '.pg{--fs:12px;font-family:' + GOTHIC + ';font-size:var(--fs);line-height:1.55;width:210mm;height:297mm;margin:8px auto;background:#fbfaf4;padding:6.5mm 7.5mm 5mm;display:flex;flex-direction:column;overflow:hidden;break-after:page;page-break-after:always;position:relative}',
    '.pg.last{break-after:auto;page-break-after:auto}',
    '.mc,.pg h1,.pg h2,.hl,.sub,.logo,.nums b{font-family:' + MINCHO + '}',
    '.pg p{margin:0 0 .2em;text-indent:1em}',
    '.mute{color:#5a5a55}.sm{font-size:.9em;margin-top:.25em}',
    '.mast{display:flex;align-items:flex-end;gap:10px;border-bottom:4px double #1c1c1c;padding-bottom:3px;flex:0 0 auto}',
    '.logo{background:#c8312b;color:#fff;font-weight:800;font-size:28px;line-height:1;padding:7px 11px 5px}',
    '.logo small{display:block;font-size:10px;font-weight:700;letter-spacing:.3em;margin-top:3px}',
    '.who{flex:1;font-size:12px}.who b{font-family:' + MINCHO + ';font-size:21px}',
    '.ear{border:1.5px solid #1c1c1c;background:#fff;padding:2px 7px;font-size:10px;line-height:1.45;max-width:46mm}.ear b{color:#c8312b}',
    '.no{text-align:right;font-size:10px;line-height:1.45}.no b{font-size:13px}',
    '.top{flex:0 0 auto;border-bottom:1.5px solid #1c1c1c;padding:3px 0 4px}',
    '.kick{display:inline-block;background:#1c1c1c;color:#fff;font-size:10px;font-weight:700;padding:0 8px}',
    '.hl{font-weight:800;font-size:2.45em;line-height:1.15;margin:2px 0 1px}',
    '.sub{font-weight:700;font-size:1.25em;color:#c8312b;margin-bottom:3px}',
    '.art{column-count:4;column-gap:10px;column-rule:1px solid #bbb}',
    '.by{font-size:.8em;color:#5a5a55;text-align:right;margin-top:1px}',
    '.flow{flex:1 1 auto;min-height:0;column-count:3;column-gap:12px;column-rule:1px solid #1c1c1c;column-fill:balance;overflow:hidden;margin-top:3px}',
    '.sec{break-inside:avoid;page-break-inside:avoid;margin:0 0 .45em;padding:0!important;border:0!important;background:none!important;border-radius:0!important}',
    '.pg h2{font-weight:800;font-size:1.22em;line-height:1.35;border-bottom:2px solid #1c1c1c;margin:0 0 .25em!important;padding-bottom:1px;display:block;color:#1c1c1c!important}',
    '.pg h2 small{font-family:' + GOTHIC + ';font-size:.66em;font-weight:400;color:#5a5a55;margin-left:.6em;white-space:nowrap}',
    '.li{padding:1px 0 1px 1.1em;text-indent:-1.1em;border-bottom:1px dotted #999}',
    '.li:last-child{border-bottom:0}',
    '.vo{font-size:.95em;padding:1px 0 1px 1.3em;text-indent:-1.3em;border-bottom:1px dotted #999}.vo b{color:#c8312b;margin-right:.3em}',
    '.wx{width:100%;border-collapse:collapse;text-align:center}.wx th{background:#1c1c1c;color:#fff;font-size:.9em}.wx td{border:1px solid #1c1c1c;padding:1px}.wx .ic{font-size:1.45em;line-height:1.2}.wx .m{font-weight:700;font-size:.85em}.wx td.off{color:#999}',
    '.col{background:#efece0!important;border:1.5px solid #1c1c1c!important;padding:4px 7px 5px!important}',
    '.col h2 .f{display:inline-flex;width:1.8em;height:1.8em;border-radius:50%;border:2px solid #1c1c1c;align-items:center;justify-content:center;background:#fff;margin-right:4px;font-size:.8em}',
    '.col h2{justify-content:flex-start}',
    '.col .q{margin-top:.3em;font-weight:700;border-left:4px solid #c8312b;padding-left:6px}',
    '.note{font-size:.75em;color:#94a3b8;margin-top:2px}',
    '.rd{display:flex;gap:5px;padding:2px 0;border-bottom:1px dotted #888}.rd .k{flex:0 0 1.7em;height:1.7em;border:2px solid #1c1c1c;display:flex;align-items:center;justify-content:center;font-weight:700;background:#fff}.rd .mute{font-size:.88em}',
    '.line{display:flex;align-items:flex-start;margin-top:2px}.st{flex:1;text-align:center;font-size:.85em;line-height:1.3}.st small{display:block;font-size:.85em}.st .dot{width:13px;height:13px;border-radius:50%;border:2px solid #1c1c1c;margin:0 auto 2px;background:#fff}.st.done .dot{background:#1c1c1c}.st.here .dot{background:#c8312b;border-color:#c8312b}.st.here{color:#c8312b;font-weight:700}.ln{flex:0 0 6px;border-top:2px solid #1c1c1c;margin-top:7px}',
    '.news .li b{font-family:' + MINCHO + '}',
    '.nums{display:flex;gap:4px;text-align:center}.nums div{flex:1;border:1.5px solid #1c1c1c;background:#fff;padding:1px}.nums b{font-size:1.6em;font-weight:800;line-height:1.2}.nums i{font-style:normal;font-size:.8em}.nums small{display:block;font-size:.75em;line-height:1.3}',
    '.memo-wrap{flex:0 0 auto;margin-top:3px}',
    '.tb{width:100%;border-collapse:collapse;font-size:.9em}.tb th{background:#efece0;border:1px solid #1c1c1c;font-weight:700;padding:1px 3px}.tb td{border:1px solid #1c1c1c;padding:1px 4px}.tb td.n{text-align:right;font-weight:700;white-space:nowrap}.tb td.c{text-align:center}.memo .w1{width:6%}.memo .w2{width:8%}.memo .w3{width:30%}.memo .w4{width:14%}',
    '.meter{display:inline-block;height:7px;background:#1c1c1c;vertical-align:middle}.meter.r{background:#c8312b}',
    '.home{margin-top:2px}',
    '.qa{margin:0}.qa dt{font-weight:700;margin-top:2px}.qa dt:before{content:"Q ";color:#c8312b}.qa dd{margin:0 0 1px;padding-left:1.2em;border-bottom:1px dotted #bbb}.qa dd:before{content:"A ";font-weight:700;margin-left:-1.2em}',
    '.src{font-size:.75em;color:#5a5a55;text-align:right}',
    '.cmp{display:flex;gap:5px}.cmp div{flex:1;border:1.5px solid #1c1c1c;background:#fff;padding:3px 5px;font-size:.92em}.cmp div b{display:block;border-bottom:1px solid #1c1c1c;margin-bottom:1px}.cmp .now{border-color:#c8312b}.cmp .now b{color:#c8312b;border-color:#c8312b}',
    '.alb{font-family:' + MINCHO + ';font-weight:700}.alb small{font-family:' + GOTHIC + ';font-weight:400;color:#5a5a55}',
    '.yokoku{border:2px solid #c8312b!important;padding:3px 7px!important;background:#fff!important}.yokoku h2{color:#c8312b!important;border-color:#c8312b}.yokoku .t{font-family:' + MINCHO + ';font-weight:800;font-size:1.15em}',
    '.bg{width:100%;border-collapse:collapse;table-layout:fixed}.bg td{vertical-align:bottom;text-align:center;height:7.6em;padding:0 3px;border-bottom:2px solid #1c1c1c;font-size:.8em;font-weight:700}.bg td i{display:block;background:#1c1c1c;margin:0 auto;width:70%}.bg td.now i{background:#c8312b}.bg tr.lb td{height:auto;border:0;font-weight:400;padding-top:1px}',
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
    'window.addEventListener("load",again);try{if(document.fonts&&document.fonts.ready)document.fonts.ready.then(again);}catch(e){}' +
    '})();<\/script>';

  // ───────── 組み立て ─────────
  function build(c) {
    var d = c.d || {};
    c.unitName = function (id) { var inf = c.unitInfo ? c.unitInfo(id) : null; return (inf && inf.name) || (global._unitJa ? global._unitJa(id) : id); };
    var ws = weekStart(d); c.ws = ws;
    var days = weekDays(ws), rows = weekRows(d, days);
    var facts = { days: 0, minutes: 0, longest: null };
    rows.forEach(function (r) { if (!r.s) return; facts.days++; var m = Number(r.s.minutes) || 0; facts.minutes += m; if (!facts.longest || m > facts.longest.m) facts.longest = { wd: r.wd, m: m }; });
    var wcount = { sun: 0, cloud: 0, rain: 0 }; rows.forEach(function (r) { if (r.s && wcount[r.s.end_weather] != null) wcount[r.s.end_weather]++; });
    var wtxt = ['sun', 'cloud', 'rain'].filter(function (k) { return wcount[k]; }).map(function (k) { return WXJ[k] + (wcount[k] > 1 ? wcount[k] : ''); }).join('・');
    var nm = String(c.name || '').replace(/\s*さん.*$/, '').trim() || '主役';
    var ta = topArticle(c, rows, facts);

    var mast = '<div class="mast"><div class="logo">道しるべ新聞<small>阪神マン新聞社 発行</small></div>' +
      '<div class="who">今週の 主役　<b>' + esc(nm) + '</b> さん</div>' +
      (facts.days ? '<div class="ear">きょうの<b>天気</b>：' + esc(wtxt || '―') + '<br>家庭学習 ' + facts.days + '日・' + facts.minutes + '分</div>' : '') +
      '<div class="no">' + esc(ja(days[0])) + '〜' + esc(ja(days[4])) + '号<br><b>第' + issueNo(ws) + '号</b></div></div>';
    var top = '<div class="top"><span class="kick">今週の トップ</span><div class="hl">' + esc(ta.head) + '</div>' + (ta.sub ? '<div class="sub">' + esc(ta.sub) + '</div>' : '') + '<div class="art">' + ta.body + '<div class="by">' + esc(ta.by) + '</div></div></div>';

    var F = [weatherSec(rows), voicesSec(rows), numsSec(c, facts), columnSec(c), progressSec(c), newsSec(c, facts), roadsSec(c), triesSec(c), hqSec(c), lessonSec(c)].join('');
    var B = [interviewSec(c, ws), compareSec(c, facts, rows), albumSec(c), '<!--PF_WORK-->', backSec(c), yokokuSec(c), classSec(c), trainSec(c), monthSec(c), moodSec(c), subjSec(c), unitsSec(c), specialSec(c), wisdomSec(c), cando(c), ayumiSec(c), teacherSec(c), tipsSec(ws), switchSec(ws)].join('');
    var after = c.ai && c.ai.after ? '<div class="after"><b>編集後記</b>　' + esc(cut(c.ai.after, 90)) + '（阪神マン）</div>' : '';
    var foot = function (n) { return '<div class="foot"><span>LearningBM ／ 道しるべ新聞（学びの道しるべ）</span><span>' + n + '面</span></div>'; };

    return '<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>道しるべ新聞</title><style>' + CSS + '</style></head><body>' +
      '<div class="pg np">' + mast + top + '<div class="flow">' + F + '</div>' + memoTable(rows) + foot(1) + '</div>' +
      '<div class="pg np last"><div class="mast"><div class="mc" style="font-size:19px;font-weight:800;flex:1">道しるべ新聞　2面</div><div class="no">今週の 主役　' + esc(nm) + ' さん<br>' + esc(ja(days[0])) + '〜' + esc(ja(days[4])) + '号</div></div>' +
      '<div class="flow">' + B + '</div>' + after + foot(2) + '</div>' + FIT + '</body></html>';
  }

  global.KARTE_SHINBUN = build;
  global.__SHINBUN_T = { advLines: advLines, weekStart: weekStart, weekRows: weekRows, topArticle: topArticle, issueNo: issueNo, isoWeek: isoWeek, headlinesOf: headlinesOf, CSS: CSS };
})(window);
