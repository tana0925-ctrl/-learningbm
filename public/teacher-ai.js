/* ===================================================================
   teacher-ai.js  —  教師ダッシュボード「今日のひと往復」
   ------------------------------------------------------------------
   ・アプリは AI を呼ばない。AI は先生が外部（ChatGPT/Gemini/Claude）で使う。
   ・①まとめてコピー → ②外部AIに貼る → ③貼り戻して下書きに取り込む
     → ④先生が目で確認して公開、の1往復。人数が増えても操作回数は同じ。
   ・貼り戻した内容は「下書き」に入るだけ。公開ボタンを押すまで子どもには届かない。
   ・公開は既存APIをそのまま呼ぶ（コイン付与の新設はしない）。
   =================================================================== */
(function () {
  'use strict';

  var NL = String.fromCharCode(10);

  // ---------- 小道具 ----------
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function classId() { var e = $('analyticsClassFilter'); return e ? e.value : ''; }
  function weekKey() {
    try { if (typeof getWeekKeyLocal === 'function') return getWeekKeyLocal(); } catch (e) {}
    return '';
  }
  function todayKey() {
    var d = new Date();
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }
  // --- 日本時間で「今日の曜日」と「今週の月〜金」を求める ---
  function jstNow() {
    var n = new Date();
    return new Date(n.getTime() + n.getTimezoneOffset() * 60000 + 9 * 3600000);
  }
  function fmtDay(d) {
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }
  function isFridayJst() { return jstNow().getDay() === 5; }
  function weekDaysJst() {
    var d = jstNow();
    var wd = (d.getDay() + 6) % 7;              // 0=月
    var mon = new Date(d.getTime() - wd * 86400000);
    var out = [];
    for (var i = 0; i < 5; i++) out.push(fmtDay(new Date(mon.getTime() + i * 86400000)));
    return out;
  }
  var DOW_JA = ['日', '月', '火', '水', '木', '金', '土'];

  // ---- コピー結果のキャッシュ ----
  //  同じクラス・同じチェック・同じ日なら、2回目以降はデータベースを一切読み直さない。
  //  （何回押しても重くならないように。最新にしたいときは「🔄 最新データで作り直す」）
  var CACHE_KEY = 'taiCopyCache';
  function cacheKeyOf(cid, want) {
    var flags = ['daily', 'karte', 'classOv', 'report', 'plan', 'reflect', 'suggest']
      .map(function (k) { return want[k] ? '1' : '0'; }).join('');
    return cid + '|' + flags + '|' + todayKey();
  }
  function cacheGet(key) {
    try {
      var raw = sessionStorage.getItem(CACHE_KEY);
      if (!raw) return null;
      var o = JSON.parse(raw);
      if (!o || o.key !== key) return null;
      return o;
    } catch (e) { return null; }
  }
  function cacheSet(key, text, blocks) {
    try {
      sessionStorage.setItem(CACHE_KEY, JSON.stringify({
        key: key, text: text, blocks: blocks, at: Date.now()
      }));
    } catch (e) {}
  }
  function cacheClear() { try { sessionStorage.removeItem(CACHE_KEY); } catch (e) {} }
  // _aiBodyLines() の出力を軽くする。
  //  コピーが長すぎるとAIの「出力」が途中で切れるため。削るのは全期間の積み上げ側だけで、
  //  【この1週間】は一切削らない（個人カルテ・家庭学習コメントの主役なので）。
  function trimBody(lines) {
    var out = [], i = 0;
    var isItem = function (x) { return x.indexOf('・') === 0; };
    while (i < lines.length) {
      var head = lines[i];
      if (head.indexOf('【') !== 0) { out.push(head); i++; continue; }
      var j = i + 1, items = [];
      while (j < lines.length && lines[j].indexOf('【') !== 0) { items.push(lines[j]); j++; }
      i = j;
      // 【直近の学習記録】は【この1週間（月〜金）】と内容が重複するので丸ごと落とす
      if (head.indexOf('【直近の学習記録') === 0) continue;
      out.push(head);
      if (head.indexOf('【ポートフォリオ') === 0) {
        var n = 0;
        items.forEach(function (it) {
          if (!isItem(it)) { out.push(it); return; }
          if (n >= 3) return;
          n++;
          out.push(it.length > 120 ? it.slice(0, 120) + '…' : it);
        });
      } else if (head.indexOf('【先生の観察メモ') === 0) {
        var m = 0;
        items.forEach(function (it) {
          if (!isItem(it)) { out.push(it); return; }
          if (m >= 4) return;
          m++; out.push(it);
        });
      } else if (head.indexOf('【教科別の正答率') === 0) {
        var rows = [], other = [];
        items.forEach(function (it) {
          if (!isItem(it)) { other.push(it); return; }
          var mm = it.match(/正答率(\d+)%/);
          rows.push({ line: it, rate: mm ? Number(mm[1]) : 999 });
        });
        rows.sort(function (a, b) { return a.rate - b.rate; });
        var low = rows.slice(0, 6);
        var high = rows.slice(6).slice(-3);
        low.forEach(function (r) { out.push(r.line); });
        if (high.length) {
          out.push('（とくいな方）');
          high.forEach(function (r) { out.push(r.line); });
        }
        var rest = rows.length - low.length - high.length;
        if (rest > 0) out.push('（ほか ' + rest + ' 単元は省略）');
        other.forEach(function (o) { out.push(o); });
      } else {
        items.forEach(function (it) { out.push(it); });
      }
    }
    return out;
  }
  // _aiBodyLines() の出力を「テストの記録」とそれ以外に分ける。
  // 個人カルテ用のかたまりにはテストの点数を入れないため。
  function splitBody(lines) {
    var main = [], test = [], cur = main;
    for (var i = 0; i < lines.length; i++) {
      var l = String(lines[i] == null ? '' : lines[i]);
      if (l.indexOf('【') === 0) cur = (l.indexOf('【テストの記録') === 0) ? test : main;
      cur.push(l);
    }
    return { main: main, test: test };
  }
  function nameOf(loginId, fallback) {
    try { if (typeof resolveStudentName === 'function') return resolveStudentName(loginId, fallback); } catch (e) {}
    return fallback || '';
  }
  function unitJa(u) {
    try { if (typeof _unitJa === 'function') return _unitJa(u); } catch (e) {}
    return u;
  }
  function say(msg) { var e = $('taiStatus'); if (e) e.textContent = msg || ''; }
  function sayPub(msg) { var e = $('taiPubStatus'); if (e) e.textContent = msg || ''; }
  function sayOne(msg) { var e = $('taiOneStatus'); if (e) e.textContent = msg || ''; }
  function opt(id) { var e = $(id); return e ? !!e.checked : false; }

  function getJson(url) {
    return fetch(url, { credentials: 'include' })
      .then(function (r) { return r.json(); })
      .catch(function () { return null; });
  }
  function postJson(url, body) {
    return fetch(url, {
      method: 'POST', credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    }).then(function (r) { return r.json(); }).catch(function () { return null; });
  }
  function copyText(txt) {
    var done = function () {
      var m = window.__taiLast || {};
      var warn = (m.blocks > 60 || m.chars > 90000) ? '　⚠ 量が多いので、AIの返事が途中で切れることがあります（項目を減らすと安全です）' : '';
      var from = m.cached ? '（さっき作ったものを再利用：データベースは読んでいません）' : '';
      say('✓ コピーしました' + from + '（約' + Math.round((m.chars || 0) / 1000) + '千字 / AIが書く欄 ' + (m.blocks || 0) + '個）。ChatGPT / Gemini / Claude に貼り付けてください' + warn);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(txt).then(done, function () { fallbackCopy(txt); done(); });
    } else { fallbackCopy(txt); done(); }
  }
  function fallbackCopy(txt) {
    try {
      if (typeof _faFallbackCopy === 'function') { _faFallbackCopy(txt); return; }
      var ta = document.createElement('textarea');
      ta.value = txt; ta.style.position = 'fixed'; ta.style.left = '-9999px';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy');
      document.body.removeChild(ta);
    } catch (e) {}
  }

  // ===================================================================
  //  ① まとめてコピー
  // ===================================================================
  //  opts.onlyStudentId / opts.onlyKind をつけて呼ぶと「1人だけ・1種類だけ」作り直せる
  //  （旧「1人ずつの計画コピー」の置きかえ。データの作り方は全員ぶんとまったく同じ）
  async function taiCopyAll(opts) {
    opts = opts || {};
    var oneId = String(opts.onlyStudentId || '');
    var oneKind = String(opts.onlyKind || '');
    var cid = classId();
    if (!cid) { say('先にクラスを選んでください'); return; }

    var want = oneKind ? {
      daily:   oneKind === 'DAILY',
      karte:   oneKind === 'KARTE',
      classOv: false,
      report:  false,
      plan:    oneKind === 'PLAN',
      reflect: oneKind === 'REFLECT',
      suggest: oneKind === 'SUGGEST'
    } : {
      daily:   opt('taiOptDaily'),
      karte:   opt('taiOptKarte'),
      classOv: opt('taiOptClass'),
      report:  opt('taiOptReport'),
      plan:    opt('taiOptPlan'),
      reflect: opt('taiOptReflect'),
      suggest: opt('taiOptSuggest')
    };
    if (!want.daily && !want.karte && !want.classOv && !want.report &&
        !want.plan && !want.reflect && !want.suggest) {
      say('「今回ふくめるもの」を1つ以上えらんでください'); return;
    }
    // ★ 同じ条件で今日すでに作ってあるなら、データベースを読まずにそのまま使う
    var _ckey = cacheKeyOf(cid, want);
    if (!oneId && !window.__taiForceRefresh) {
      var hit = cacheGet(_ckey);
      if (hit && hit.text) {
        window.__taiLast = { chars: hit.text.length, blocks: hit.blocks, cached: true };
        copyText(hit.text);
        return;
      }
    }
    window.__taiForceRefresh = false;

    // 二重押し防止（押している間はボタンを止める）
    if (window.__taiBusy) { say('いま作っています。少し待ってください…'); return; }
    window.__taiBusy = true;

    // 金曜日は週の振り返りを厚めに入れる（先生がチェックを外していれば入れない）
    var isFri = isFridayJst() && want.reflect;
    var weekDays = weekDaysJst();
    // テストの点数は「クラス所見・週報」を作るときだけ入れる。
    // 個人カルテはその週の家庭学習が主役で、テストの点数には触れない方針。
    var wantWide = want.classOv || want.report;

    say('名簿を読み込み中...');
    var roster = [];
    try {
      var rd = await postJson('/api/teacher/records/parse', { classId: cid, text: '' });
      roster = (rd && rd.roster) || [];
    } catch (e) {}
    if (!roster.length) { say('名簿が取得できませんでした'); window.__taiBusy = false; return; }
    if (oneId) {
      roster = roster.filter(function (r) { return String(r.userId) === oneId; });
      if (!roster.length) { sayOne('その児童が名簿に見つかりません'); window.__taiBusy = false; return; }
    }

    var wk = weekKey();
    var out = [];

    // ---------- 見出し・AIへの指示 ----------
    out.push('あなたは小学校の担任の先生を手伝うアシスタントです。');
    out.push('下のデータを読んで、「=== [ ... ] ===」で始まる目印の行の直後に、日本語で文章を書いてください。');
    out.push('');
    out.push('【まもってほしいこと】');
    out.push('1. 目印の行（=== [...] === ）は1文字も変えずにそのまま残す。行の順番も変えない。');
    out.push('2. 前置き・あいさつ・まとめ・「承知しました」などは書かない。目印と本文だけ。');
    out.push('3. 数字の言いかえはしない。「提出率は80%です」のように、見ればわかることを書き直すのは不要。');
    out.push('4. かわりに、離れたデータを突き合わせて「見立て」を書く。例：');
    if (wantWide) out.push('   ・アプリの社会は正答率98%なのにテストは55点 → 知識はあるが記述で落としている可能性');
    out.push('   ・学習時間は長いのに正答率が上がらない → やり方が作業になっているかも');
    out.push('   ・提出率は高いのに満足度が🌧続き → むずかしさに一人で向き合っているかも');
    out.push('   ・クラス平均より大きく下 / 上の単元 → どこで差がついたか');
    out.push('   ・計画には書いてあるのに実際の記録に無い → つまずいた所かも');
    out.push('5. 相手は小学生。課題ははっきり書いてよいが、必ず「次の一歩」とセットにする。');
    out.push('6. 先生が読む文（クラス所見・週報）はていねいな文体、子どもが読む文（家庭学習コメント・');
    out.push('   計画アドバイス・振り返り返却・カルテ・おすすめ計画）はやさしい話し言葉で。');
    out.push('7. 【A】の「リスクのサイン」「早期対応リスト」「最近ペースが落ちている子」は、');
    out.push('   アプリが機械的に数えた\u300c兆候\u300dであって、確定した診断ではありません。断定した書き方をしないでください。');
    out.push('8. そのかわり、同じ子の名前が複数のデータ（提出・正答率・満足度・振り返り' + (wantWide ? '・テスト' : '') + '）で');
    out.push('   重なって出てきたときは、そこを重く見て、何が起きていそうかを書いてください。');
    out.push('   逆に1つのサインしか出ていない子は、まだ様子見であることが分かるように書いてください。');
    if (isFri) {
      out.push('9. 今日は金曜日です。児童ごとの【この1週間（月〜金）】に、その週の記録と振り返りを');
      out.push('   入れてあります。REFLECT には、その1週間の流れ（月曜からどう変わったか）を');
      out.push('   ふまえた返却コメントを書いてください。1日だけを見て書かないこと。');
    }
    out.push('');
    out.push('【目印の種類】');
    if (want.daily)   out.push('・=== [DAILY:...] === … その日の家庭学習への先生コメント。1〜2文、40字以内。子ども向け。');
    if (want.karte)   out.push('・=== [KARTE:...] === … 個人カルテ。①よいところ ②気になるところ ③次の一歩。子ども向け。');
    if (want.karte) {
      out.push('    ※個人カルテのきまり（大事）:');
      out.push('      - 【この1週間（月〜金）】を主役にする。今週やったこと・書いたことを具体的に取り上げる。');
      out.push('      - 【ふだんの様子】は背景。触れるとしても一言まで。今年度ぜんたいの話にしない。');
      out.push('      - テストの点数・得点率・順位には いっさい触れない。');
      out.push('      - この下に先生がプリントやノートの内容を貼ることがあります。');
      out.push('        貼ってあれば、その中身を読んで具体的にほめてください（例：どこの説明がよかったか）。');
    }
    if (want.plan)    out.push('・=== [PLAN:...] === … 今週の計画へのアドバイス。①よい点 ②もっとよくする点 ③ひとこと。子ども向け。');
    if (want.reflect) out.push('・=== [REFLECT:...] === … 今週の振り返りへの返却コメント。2〜3文。子ども向け。');
    if (want.suggest) out.push('・=== [SUGGEST:...] === … 今週のおすすめ家庭学習。曜日ごとに3〜5項目。子ども向け。');
    if (want.classOv) out.push('・=== [CLASS] === … クラス全体の所見。5〜8行（よい傾向／気になる点／来週の手立て）。先生向け。【テスト・成績】も使ってよい。');
    if (want.report)  out.push('・=== [WEEKREPORT] === … 今週の週報。管理職・保護者にも見せられる文体で10行程度。先生向け。【テスト・成績】も使ってよい。');
    out.push('');
    out.push('【児童ごとのデータの並び】');
    out.push('・【この1週間（月〜金）】…個人カルテ・家庭学習コメント・振り返り返却は、ここを主役に。');
    out.push('・【ふだんの様子（今年度の積み上げ）】…背景。カルテでは軽く触れる程度に。');
    if (wantWide) out.push('・【テスト・成績】…クラス所見と週報のための材料。個人カルテには使わないこと。');
    else out.push('（今回はテストの点数を渡していません。テストの話は書かないでください。）');
    out.push('');
    out.push('==================================================');
    out.push('【A】クラスの土台（ここは読むだけ。書き足さなくてよい）');
    out.push('==================================================');

    // ---------- A. クラス共通データ ----------
    say('クラスのデータを集めています... (1/8)');
    var className = '';
    try {
      var csel = $('analyticsClassFilter');
      if (csel && csel.selectedIndex >= 0) className = csel.options[csel.selectedIndex].textContent || '';
    } catch (e) {}
    out.push('クラス: ' + className + '　児童数: ' + roster.length + '人　今日: ' + todayKey() + '　週: ' + wk);
    out.push('');

    // A-1 今週の先生メニュー
    try {
      var mn = await getJson('/api/teacher/class/' + encodeURIComponent(cid) + '/weekly-menu?weekKey=' + encodeURIComponent(wk));
      var m = mn && mn.menu;
      out.push('■ 今週の先生からの課題');
      if (m) {
        if (m.kanji_page || m.kanjiPage)   out.push('・漢字スキル: ' + (m.kanji_page || m.kanjiPage));
        if (m.keisan_page || m.keisanPage) out.push('・計算スキル: ' + (m.keisan_page || m.keisanPage));
        if (m.other_tasks || m.otherTasks) out.push('・その他: ' + (m.other_tasks || m.otherTasks));
        if (m.tests)       out.push('・今週のテスト: ' + m.tests);
        if (m.active_days || m.activeDays) out.push('・家庭学習がある曜日: ' + (m.active_days || m.activeDays));
      } else { out.push('（未設定）'); }
      out.push('');
    } catch (e) {}

    // A-2 今週の提出状況
    say('クラスのデータを集めています... (2/8)');
    var dashboard = null;
    try {
      dashboard = await getJson('/api/teacher/class/' + encodeURIComponent(cid) + '/submission-dashboard?weekKey=' + encodeURIComponent(wk));
      if (dashboard && dashboard.ok) {
        out.push('■ 今週の提出状況');
        var byDay = {};
        (dashboard.dailySubmissions || []).forEach(function (s) {
          var k = s.day_key || s.dayKey; if (!k) return;
          byDay[k] = (byDay[k] || 0) + 1;
        });
        (dashboard.weekDays || []).forEach(function (d) {
          if (!d.isActive) return;
          out.push('・' + d.label + '(' + d.date + '): ' + (byDay[d.date] || 0) + '/' + roster.length + '人');
        });
        out.push('');
      }
    } catch (e) {}

    // A-3 単元別クラス平均（ゲーム内学習データ）
    say('クラスのデータを集めています... (3/8)');
    var unitAna = null, classUnitAvg = {}, unitSubject = {};
    try {
      unitAna = await getJson('/api/teacher/class/' + encodeURIComponent(cid) + '/unit-analytics');
      if (unitAna && unitAna.ok) {
        out.push('■ アプリ学習の単元別 クラス平均正答率（低い順）');
        (unitAna.unitSummary || []).forEach(function (u) {
          classUnitAvg[u.mode] = u.classAvg;
          unitSubject[u.mode] = u.subject || '';
          out.push('・' + (u.name || u.mode) + (u.subject ? '（' + u.subject + '）' : '') +
                   ': ' + (u.classAvg == null ? '-' : u.classAvg + '%') + '（' + u.studentCount + '人）');
        });
        out.push('');
      }
    } catch (e) {}

    // A-4 ラーニングアナリティクス（テスト平均・満足度・キーワード）
    //     ※単元別の弱点と「問題数×正答率の相関」は A-3 / A-5 と重複するのでここでは出さない
    say('クラスのデータを集めています... (4/8)');
    var laData = null;
    try {
      var la = await getJson('/api/teacher/learning-analytics?classId=' + encodeURIComponent(cid));
      laData = la;
      if (la && la.ok) {
        var tb = wantWide ? ((la.tests && la.tests.bySubject) || []) : [];
        if (tb.length) {
          out.push('■ 紙のテスト 教科別クラス平均');
          tb.forEach(function (t) {
            out.push('・' + t.subject + ': ' + (t.avgPct == null ? '-' : t.avgPct + '%') + '（' + t.count + '回分）');
          });
          out.push('');
        }
        var ov = (la.satisfaction && la.satisfaction.overall) || null;
        if (ov) {
          var tot = (ov.sun || 0) + (ov.cloud || 0) + (ov.rain || 0);
          out.push('■ 家庭学習の手ごたえ（クラス合計） ☀' + (ov.sun || 0) + ' ☁' + (ov.cloud || 0) + ' 🌧' + (ov.rain || 0) +
                   (tot ? '（☀の割合 ' + Math.round((ov.sun || 0) / tot * 100) + '%）' : ''));
        }
        var kw = (la.satisfaction && la.satisfaction.keywords) || [];
        if (kw.length) {
          out.push('■ 振り返りによく出る言葉: ' + kw.slice(0, 8).map(function (k) { return k.word + '(' + k.count + ')'; }).join('、'));
        }
        out.push('');
      }
    } catch (e) {}

    // A-5 要因分析（相関）— 計算で出している数字。AIには「見立ての材料」として渡す
    say('クラスのデータを集めています... (5/8)');
    try {
      var fa = await getJson('/api/teacher/factor-analysis?classId=' + encodeURIComponent(cid));
      if (fa && fa.ok) {
        out.push('■ 何をすると伸びる？（クラス内の相関・計算値／因果ではない）');
        if (!fa.enough) {
          out.push('（人数・記録が少ないため参考値。有効' + (fa.n || 0) + '人）');
        }
        (fa.correlations || []).forEach(function (c) {
          out.push('・' + c.factorLabel + ' × ' + c.outcomeLabel + ': r=' + (c.r >= 0 ? '+' : '') + c.r + '（n=' + c.n + '）');
        });
        (fa.insights || []).forEach(function (s) { out.push('・' + s); });
        out.push('');
      }
    } catch (e) {}

    // A-6 早期対応リスト
    say('クラスのデータを集めています... (6/8)');
    try {
      var ea = await getJson('/api/teacher/early-alerts?classId=' + encodeURIComponent(cid));
      if (ea && ea.ok && (ea.alerts || []).length) {
        var sigJa = { consec: '直近3問連続で不正解', drop: '後半で正答率が下がった', regress: '一度できたのに戻った' };
        out.push('■ 早期対応リスト（アプリ学習のつまずきサイン）');
        (ea.alerts || []).slice(0, 25).forEach(function (a) {
          out.push('・' + nameOf(a.loginId, a.name) + '／' + unitJa(a.unit) + '：' +
                   (a.signals || []).map(function (s) { return sigJa[s] || s; }).join('・') +
                   '（正答率' + a.acc + '%' + (a.recentAcc != null ? '→直近' + a.recentAcc + '%' : '') + '・' + a.total + '問）');
        });
        out.push('');
      }
    } catch (e) {}

    // A-7 リスクのサイン（提出・活動・正答率の危険サインを重みづけ集計）
    //     声かけ案（固定文）はわざと渡さない。AIに言い直させても情報が増えないため。
    say('クラスのデータを集めています... (7/8)');
    try {
      var rs = await getJson('/api/teacher/risk-scores?classId=' + encodeURIComponent(cid));
      if (rs && rs.ok) {
        var LV = { high: '高', mid: '中', low: '低', partial: 'データ不足', unknown: '判定不可' };
        out.push('■ リスクのサイン（提出・活動・正答率の危険サインを機械的に集計したもの）');
        out.push('（目安：50点以上=高 / 25点以上=中 / 24点以下=低 / データ不足=判定材料が片方しかない / 判定不可=記録がほとんどない）');
        var lows = [], unknowns = [], listed = 0;
        (rs.students || []).forEach(function (st) {
          var nm2 = nameOf(st.loginId, st.name);
          if (st.level === 'unknown') { unknowns.push(nm2); return; }
          if (st.level === 'low') { lows.push(nm2); return; }
          var sg = (st.signals || []).join('／') || '（サインなし）';
          out.push('・' + nm2 + '：' + (LV[st.level] || st.level) + '（' + st.riskScore + '点）｜' + sg);
          listed++;
        });
        if (!listed) out.push('・（高・中・データ不足に当てはまる子はいません）');
        if (lows.length) out.push('・低リスク（' + lows.length + '人）：' + lows.join('、'));
        if (unknowns.length) out.push('・判定不可＝記録がほとんどない（' + unknowns.length + '人）：' + unknowns.join('、'));
        out.push('');
      }
    } catch (e) {}

    // A-8 最近ペースが落ちている子（ラーニングアナリティクスの「離れ気味アラート」）
    say('クラスのデータを集めています... (8/8)');
    try {
      var dropList = (laData && laData.ok && laData.continuity && laData.continuity.droppingStudents) || [];
      out.push('■ 最近ペースが落ちている子（直近7日の提出回数が、その前の7日より大きく減っている）');
      if (dropList.length) {
        dropList.forEach(function (ds) {
          out.push('・' + nameOf(ds.loginId, ds.name) + '（前の7日 ' + ds.prev7 + '回 → 直近7日 ' + ds.recent7 + '回）');
        });
      } else {
        out.push('・（直近で大きく落ちている子はいません）');
      }
      out.push('');
    } catch (e) {}

    // ---------- B. 児童ごと ----------
    out.push('==================================================');
    out.push('【B】児童ごとのデータと、書いてほしい欄');
    out.push('==================================================');
    out.push('');

    // 今週の計画・振り返り
    var plans = [];
    if (want.plan || want.reflect || want.suggest || want.karte) {
      try {
        var pd = await getJson('/api/teacher/weekly-plans?weekKey=' + encodeURIComponent(wk) + '&classId=' + encodeURIComponent(cid));
        plans = (pd && pd.plans) || [];
      } catch (e) {}
    }
    var planByUser = {};
    plans.forEach(function (p) { planByUser[p.userId] = p; });

    // 未返却の家庭学習（DAILY用）
    var hwByUser = {};
    if (want.daily) {
      try {
        var hd = await getJson('/api/teacher/homework?classId=' + encodeURIComponent(cid));
        (hd && hd.submissions || []).forEach(function (s) {
          if (s.returnedAt) return;                 // 返却済みは対象外
          if (hwByUser[s.userId]) return;           // 1人1件（いちばん新しいもの）
          hwByUser[s.userId] = s;
        });
      } catch (e) {}
    }

    // 単元→教科 の対応表（unit-analytics の unitInfo）
    var unitInfo = (unitAna && unitAna.unitInfo) || {};
    var stuUnitById = {};
    var stuBySubjectById = {};
    (unitAna && unitAna.students || []).forEach(function (s) {
      stuUnitById[s.id] = s.units || {};
      stuBySubjectById[s.id] = s.bySubject || {};
    });

    var dayLabels = ['月', '火', '水', '木', '金'];
    var wCount = 0;

    for (var i = 0; i < roster.length; i++) {
      var st = roster[i];
      var nm = nameOf(st.loginId, st.name);
      var sid = st.loginId || st.userId;
      say('児童のデータを集めています... (' + (i + 1) + '/' + roster.length + ')');

      var data = null;
      try { data = await getJson('/api/teacher/student-full-analysis?studentId=' + encodeURIComponent(st.userId)); } catch (e) {}

      out.push('--------------------------------------------------');
      out.push('▼ 児童データ: ' + nm + '（ID: ' + sid + '）');
      out.push('--------------------------------------------------');

      // ===== ① この1週間（個人カルテ・家庭学習コメント・振り返り返却の主役） =====
      var weekRefl = null;
      var planLines = [], reflText = '';
      var p = planByUser[st.userId];
      out.push('【この1週間（月〜金）】※個人カルテはここを主役に書く');
      if (data && data.ok) {
        try {
          var wsubs = (data.recentSubmissions || []).filter(function (r) {
            return weekDays.indexOf(r.day_key) >= 0;
          }).sort(function (a2, b2) { return (a2.day_key < b2.day_key) ? -1 : 1; });
          if (wsubs.length) {
            wsubs.forEach(function (r) {
              var dd = new Date(r.day_key + 'T00:00:00Z');
              var w = r.end_weather === 'sun' ? '☀' : r.end_weather === 'cloud' ? '☁' : r.end_weather === 'rain' ? '🌧' : '?';
              var ln = '・' + r.day_key + '(' + DOW_JA[dd.getUTCDay()] + ') ' + w + ' ' + (r.todo || '') + '（' + (r.minutes || 0) + '分）';
              if (r.aim) ln += ' めあて:' + r.aim;
              if (r.weather_reason) ln += ' ふりかえり:' + r.weather_reason;
              if (r.next_improve) ln += ' 次:' + r.next_improve;
              if (r.rest_day) ln += '（おやすみ）';
              out.push(ln);
            });
            var mins = wsubs.reduce(function (a2, r) { return a2 + (Number(r.minutes) || 0); }, 0);
            var suns = wsubs.filter(function (r) { return r.end_weather === 'sun'; }).length;
            out.push('・今週の合計：' + wsubs.length + '日 / ' + mins + '分 / ☀' + suns + '日');
          } else {
            out.push('・（今週の提出はまだありません）');
          }
        } catch (e) {}
      }

      // 今週の計画・振り返り（自由記述）
      if (p) {
        var parsed = {};
        try { parsed = JSON.parse(p.plansJson || '{}'); } catch (e) {}
        var keys = Object.keys(parsed).filter(function (k) { return k !== '_modified'; });
        for (var d2 = 0; d2 < 5; d2++) {
          var kk = keys[d2] || '';
          var val = kk ? parsed[kk] : '';
          var txt = (val && typeof val === 'object') ? (val.free || '') : (val || '');
          if (txt && String(txt).trim()) planLines.push(dayLabels[d2] + '：' + txt);
        }
        var friK = keys[4] || '';
        var friV = friK ? parsed[friK] : '';
        reflText = (friV && typeof friV === 'object') ? (friV.reflection || '') : '';
        if (planLines.length) {
          out.push('・今週の計画（本人が書いたもの）');
          planLines.forEach(function (l) { out.push('　' + l); });
          if (p.revisionCount) out.push('　（' + p.revisionCount + '回 書きなおしています）');
        }
        if (reflText && String(reflText).trim()) {
          out.push('・今週の振り返り（本人が書いたもの）: ' + reflText);
        }
      }

      // 今週の振り返り（項目式）
      if (data && data.ok) {
        try {
          var refs = (data.reflections || []).filter(function (r) { return r.weekKey === wk; });
          if (refs.length) {
            weekRefl = refs[0];
            out.push('・今週の振り返り（項目ごと）');
            if (weekRefl.concentration != null && weekRefl.concentration !== '') out.push('　集中できた度合い: ' + weekRefl.concentration);
            if (weekRefl.goodPoint) out.push('　よかったこと: ' + weekRefl.goodPoint);
            if (weekRefl.improvePoint) out.push('　もっとよくしたいこと: ' + weekRefl.improvePoint);
            if (weekRefl.nextAction) out.push('　来週やること: ' + weekRefl.nextAction);
          }
        } catch (e) {}
      }

      // まだ返していない家庭学習
      var hw = hwByUser[st.userId];
      if (hw) {
        out.push('・まだ返していない家庭学習（' + (hw.dayKey || '') + '）');
        if (hw.aim)            out.push('　めあて: ' + hw.aim);
        if (hw.todo)           out.push('　やったこと: ' + hw.todo);
        if (hw.why)            out.push('　えらんだ理由: ' + hw.why);
        out.push('　学習時間: ' + (hw.minutes || 0) + '分');
        out.push('　手ごたえ: ' + (hw.endWeather === 'sun' ? '☀' : hw.endWeather === 'cloud' ? '☁' : hw.endWeather === 'rain' ? '🌧' : '?'));
        if (hw.weatherReason)  out.push('　ふりかえり: ' + hw.weatherReason);
        if (hw.nextImprove)    out.push('　次にがんばること: ' + hw.nextImprove);
        if (hw.parentComment)  out.push('　おうちの人から: ' + hw.parentComment);
        if (hw.restDay)        out.push('　（おやすみの記録）');
      }

      // ===== ② ふだんの様子（今年度の積み上げ・カルテでは背景あつかい） =====
      if (data && data.ok) {
        var body = { main: [], test: [] };
        try {
          if (typeof _aiBodyLines === 'function') body = splitBody(trimBody(_aiBodyLines(data)));
        } catch (e) { body = { main: ['(基本データの整形に失敗)'], test: [] }; }

        out.push('');
        out.push('【ふだんの様子（今年度の積み上げ）】※個人カルテでは背景として軽く触れる程度に');
        out = out.concat(body.main);

        // クラス平均との差（アプリ学習のみ。テストの点は含まない）
        try {
          var mine = stuUnitById[st.userId] || {};
          var diffs = [];
          Object.keys(mine).forEach(function (mode) {
            var v = mine[mode];
            if (!v || v.acc == null) return;
            var avg = classUnitAvg[mode];
            if (avg == null) return;
            var info = unitInfo[mode] || {};
            diffs.push({ name: info.name || mode, mine: v.acc, avg: avg, d: v.acc - avg, n: v.total });
          });
          diffs.sort(function (x, y) { return x.d - y.d; });
          if (diffs.length) {
            out.push('');
            out.push('【クラス平均との差（アプリ学習・単元ごと／差の小さい順）】');
            diffs.slice(0, 5).forEach(function (d) {
              out.push('・' + d.name + '：本人' + d.mine + '% / クラス' + d.avg + '%（差 ' + (d.d >= 0 ? '+' : '') + d.d + 'pt・' + d.n + '問）');
            });
          }
        } catch (e) {}

        // ===== ③ テスト・成績（クラス所見／週報のときだけ。個人カルテには使わない） =====
        if (wantWide) {
          out.push('');
          out.push('【テスト・成績】※クラス所見・週報のための材料。個人カルテには使わないこと');
          if (body.test.length) out = out.concat(body.test);
          try {
            var bySub = stuBySubjectById[st.userId] || {};
            var testBySub = {};
            (data.testScores || []).forEach(function (t) {
              var k = t.subject || '(教科なし)';
              if (t.pct == null) return;
              (testBySub[k] = testBySub[k] || []).push(t.pct);
            });
            var subjKeys = {};
            Object.keys(bySub).forEach(function (k) { subjKeys[k] = 1; });
            Object.keys(testBySub).forEach(function (k) { subjKeys[k] = 1; });
            var subjList = Object.keys(subjKeys);
            if (subjList.length) {
              out.push('【★アプリ学習 と 紙のテスト の対応（教科ごと・突き合わせて見立てを）】');
              subjList.forEach(function (k) {
                var a = bySub[k];
                var appTxt = (a && a.total) ? (a.acc + '%（' + a.total + '問）') : 'データなし';
                var ts = testBySub[k] || [];
                var tsTxt = ts.length
                  ? (Math.round(ts.reduce(function (x, y) { return x + y; }, 0) / ts.length) + '%（' + ts.length + '回）')
                  : 'データなし';
                out.push('・' + k + '：アプリ正答率 ' + appTxt + ' ／ テスト平均 ' + tsTxt);
              });
            }
          } catch (e) {}
        }
      } else {
        out.push('(データを取得できませんでした)');
      }

      // ---- 書いてほしい欄（目印） ----
      out.push('');
      if (want.daily && hw && !hw.restDay) {
        out.push('=== [DAILY:' + hw.id + '] ' + nm + '｜' + (hw.dayKey || '') + ' ===');
        out.push('');
      }
      if (want.karte)   { out.push('=== [KARTE:' + sid + '] ' + nm + ' ==='); out.push(''); }
      if (want.plan && planLines.length)  { out.push('=== [PLAN:' + sid + '] ' + nm + ' ==='); out.push(''); }
      var hasRefl = !!(reflText && String(reflText).trim()) || !!weekRefl;
      if (want.reflect && hasRefl && p && !p.reflectionReturnedAt) {
        out.push('=== [REFLECT:' + sid + '] ' + nm + ' ==='); out.push('');
      }
      if (want.suggest) { out.push('=== [SUGGEST:' + sid + '] ' + nm + ' ==='); out.push(''); }
      wCount++;

      // 個人カルテのボタン列にも反映しておく
    }

    // ---------- C. クラス単位 ----------
    if (want.classOv || want.report) {
      out.push('==================================================');
      out.push('【C】クラス全体について書いてほしい欄');
      out.push('==================================================');
      out.push('');
      if (want.classOv) { out.push('=== [CLASS] ==='); out.push(''); }
      if (want.report)  { out.push('=== [WEEKREPORT] ==='); out.push(''); }
    }

    // 個人カルテの児童一覧も同時に用意しておく（古いボタンを押さなくても使えるように）
    try {
      var summaries = roster.map(function (r) { return { userId: r.userId, loginId: r.loginId, name: r.name }; });
      if (typeof updateKarteStudentList === 'function') updateKarteStudentList(summaries, cid);
    } catch (e) {}

    var _txt = out.join(NL);
    var _blocks = 0;
    for (var bi = 0; bi < out.length; bi++) { if (out[bi].indexOf('=== [') === 0) _blocks++; }
    window.__taiLast = { chars: _txt.length, blocks: _blocks, cached: false };
    if (!oneId) cacheSet(_ckey, _txt, _blocks);
    window.__taiBusy = false;
    copyText(_txt);
    if (oneId) sayOne('✓ この子のぶんをコピーしました。AIに貼って、返事を下の欄へ');
  }

  // 🔄 最新のデータで作り直す（キャッシュを捨ててから作る）
  async function taiCopyFresh() {
    cacheClear();
    window.__taiForceRefresh = true;
    await taiCopyAll();
  }

  // ===================================================================
  //  ③ 貼り戻し → 下書きに取り込む
  // ===================================================================
  function parseBlocks(raw) {
    var lines = String(raw || '').split(/\r?\n/);
    var blocks = [], cur = null;
    var re = /^[\s　]*[=＝]{2,}[\s　]*[\[［]\s*([^\]］]+?)\s*[\]］]/;
    for (var i = 0; i < lines.length; i++) {
      var m = lines[i].match(re);
      if (m) { if (cur) blocks.push(cur); cur = { id: m[1], lines: [] }; }
      else if (cur) { cur.lines.push(lines[i]); }
    }
    if (cur) blocks.push(cur);
    return blocks.map(function (b) {
      return { id: b.id, body: b.lines.join(NL).replace(/^\s+|\s+$/g, '') };
    });
  }
  function normId(s) {
    return String(s == null ? '' : s)
      .replace(/[Ａ-Ｚａ-ｚ０-９]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 65248); })
      .replace(/[\s　]/g, '').toLowerCase();
  }

  //  opts.append=true のときは、いまある下書きを消さずに追加する（1人だけ作り直すとき）
  async function taiImport(opts) {
    opts = opts || {};
    var appendMode = !!opts.append;
    var say2 = appendMode ? sayOne : say;
    var cid = classId();
    var ta = $(appendMode ? 'taiOnePaste' : 'taiPaste');
    var raw = ta ? ta.value : '';
    if (!cid) { say2('先にクラスを選んでください'); return; }
    if (!raw || !raw.trim()) { say2('AIの返事を貼り付けてください'); return; }

    say2('読み取り中...');
    var roster = [];
    try {
      var rd = await postJson('/api/teacher/records/parse', { classId: cid, text: '' });
      roster = (rd && rd.roster) || [];
    } catch (e) {}
    var map = {}, nameMap = {};
    roster.forEach(function (s) {
      if (s.loginId) { map[normId(s.loginId)] = s.userId; }
      if (s.userId)  { map[normId(s.userId)]  = s.userId; }
      if (s.name)    { map[normId(s.name)]    = s.userId; }
      var dn = nameOf(s.loginId, s.name);
      if (dn) map[normId(dn)] = s.userId;
      nameMap[s.userId] = dn || s.name || s.loginId;
    });

    var blocks = parseBlocks(raw);
    var items = [], unmatched = [];
    blocks.forEach(function (b) {
      var body = b.body;
      if (!body) return;
      var idRaw = String(b.id || '');
      var kind = 'KARTE', idPart = idRaw;
      var ci = idRaw.indexOf(':');
      if (ci >= 0) {
        kind = idRaw.slice(0, ci).toUpperCase().replace(/[^A-Z]/g, '');
        idPart = idRaw.slice(ci + 1);
      } else {
        var up = idRaw.toUpperCase();
        if (up.indexOf('WEEKREPORT') >= 0) kind = 'WEEKREPORT';
        else if (up.indexOf('CLASS') >= 0 || idRaw.indexOf('クラス') >= 0) kind = 'CLASS';
      }
      if (kind === 'CLASS' || kind === 'WEEKREPORT') {
        items.push({ kind: kind, targetId: '', targetName: '', refKey: '', body: body });
        return;
      }
      if (kind === 'DAILY') {
        // DAILY の ID は「提出ID」。名前は目印の後ろに書いてある。
        var hwId = idPart.replace(/[\s　]/g, '');
        items.push({ kind: 'DAILY', targetId: '', targetName: '', refKey: hwId, body: body });
        return;
      }
      var uid = map[normId(idPart)];
      if (!uid) { unmatched.push(idRaw); return; }
      items.push({ kind: kind, targetId: uid, targetName: nameMap[uid] || '', refKey: '', body: body });
    });

    if (!items.length) {
      say2('目印（=== [ ... ] === ）が見つかりませんでした（' + blocks.length + 'ブロック検出）');
      return;
    }

    var res = await postJson('/api/teacher/ai-drafts', {
      classId: cid, weekKey: weekKey(), replace: !appendMode, items: items
    });
    if (!res || !res.ok) { say2('下書きの保存に失敗しました'); return; }
    say2('✓ ' + res.saved + '件を下書きに' + (appendMode ? '追加' : '取り込み') + 'ました。下の「④ 先生が確認して公開」を見てください' +
        (unmatched.length ? '（名前が一致しなかったもの: ' + unmatched.slice(0, 5).join(', ') + '）' : ''));
    if (ta) ta.value = '';
    taiLoadDrafts();
  }

  // ===================================================================
  //  ④ 先生が確認して公開
  // ===================================================================
  // to: 'kid'=子どものアプリ画面に出る / 'paper'=紙のカルテに載る（画面には出ない） / 'teacher'=先生だけ
  var KIND_JA = {
    DAILY:     { ja: '家庭学習コメント', to: 'kid',     badge: '子どもの画面に出る' },
    KARTE:     { ja: '個人カルテ',       to: 'kid',     badge: '子どもの画面に出る／印刷もできる' },
    PLAN:      { ja: '計画アドバイス',   to: 'kid',     badge: '子どもの画面に出る' },
    REFLECT:   { ja: '振り返りの返却',   to: 'kid',     badge: '子どもの画面に出る' },
    SUGGEST:   { ja: 'おすすめ計画',     to: 'kid',     badge: '子どもの画面に出る' },
    CLASS:     { ja: 'クラス所見',       to: 'teacher', badge: '先生だけ' },
    WEEKREPORT:{ ja: '週報',             to: 'teacher', badge: '先生だけ' }
  };
  var _drafts = [];

  async function taiLoadDrafts() {
    var cid = classId();
    var box = $('taiDraftList');
    if (!box) return;
    if (!cid) { box.innerHTML = '<p class="text-xs text-slate-400">クラスを選んでください</p>'; return; }
    box.innerHTML = '<p class="text-xs text-slate-400">読み込み中...</p>';
    var d = await getJson('/api/teacher/ai-drafts?classId=' + encodeURIComponent(cid));
    if (!d || !d.ok) { box.innerHTML = '<p class="text-xs text-red-500">読み込みに失敗しました</p>'; return; }
    _drafts = d.drafts || [];
    renderDrafts();
  }

  function renderDrafts() {
    var box = $('taiDraftList');
    if (!box) return;
    var pend = _drafts.filter(function (x) { return x.status === 'draft'; });
    var done = _drafts.filter(function (x) { return x.status === 'published'; });
    if (!pend.length && !done.length) {
      box.innerHTML = '<p class="text-xs text-slate-400">まだ下書きはありません。上の①〜③をやってみてください。</p>';
      var c0 = $('taiPubCount'); if (c0) c0.textContent = '';
      return;
    }
    var h = '';
    if (pend.length) {
      h += '<div class="flex items-center gap-2 mb-2 flex-wrap">' +
           '<button onclick="taiCheckAll(true)" class="bg-slate-200 text-slate-700 rounded px-2 py-1 text-xs font-bold hover:bg-slate-300">すべて選ぶ</button>' +
           '<button onclick="taiCheckAll(false)" class="bg-slate-200 text-slate-700 rounded px-2 py-1 text-xs font-bold hover:bg-slate-300">選択を外す</button>' +
           '<span class="text-xs text-slate-500">中身を読んで、直したいところは書きかえられます</span></div>';
      h += '<div class="space-y-2 max-h-[28rem] overflow-y-auto">';
      pend.forEach(function (x) {
        var k = KIND_JA[x.kind] || { ja: x.kind, to: '', badge: '' };
        var toCls = k.to === 'kid' ? 'bg-rose-100 text-rose-700' : (k.to === 'paper' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-600');
        h += '<div class="bg-white rounded-lg border border-slate-200 p-2">' +
             '<div class="flex items-center gap-2 flex-wrap mb-1">' +
             '<input type="checkbox" class="tai-chk accent-indigo-600" data-id="' + esc(x.id) + '" checked>' +
             '<span class="text-xs font-bold text-slate-700">' + esc(k.ja) + '</span>' +
             (x.targetName ? '<span class="text-xs text-slate-600">' + esc(x.targetName) + '</span>' : '') +
             (x.refLabel ? '<span class="text-[10px] text-slate-400">' + esc(x.refLabel) + '</span>' : '') +
             '<span class="text-[10px] px-1.5 py-0.5 rounded ' + toCls + '">' + esc(k.badge) + '</span>' +
             '</div>' +
             '<textarea class="tai-body w-full border border-slate-200 rounded p-1.5 text-xs" rows="' +
             Math.min(8, Math.max(2, String(x.body || '').split(NL).length)) + '" data-id="' + esc(x.id) + '">' +
             esc(x.body) + '</textarea></div>';
      });
      h += '</div>';
    } else {
      h += '<p class="text-xs text-slate-400">未公開の下書きはありません。</p>';
    }
    if (done.length) {
      h += '<details class="mt-2"><summary class="cursor-pointer text-xs font-bold text-slate-500 select-none">公開ずみ（' + done.length + '件）</summary><div class="mt-1 space-y-1">';
      done.forEach(function (x) {
        var k = KIND_JA[x.kind] || { ja: x.kind };
        h += '<div class="bg-slate-50 rounded border border-slate-200 p-2"><div class="text-xs font-bold text-slate-600">' +
             esc(k.ja) + ' ' + esc(x.targetName || '') + ' <span class="text-[10px] text-slate-400 font-normal">' +
             esc(x.publishedAt || '') + '</span></div><div class="text-xs text-slate-600 whitespace-pre-wrap">' +
             esc(x.body) + '</div></div>';
      });
      h += '</div></details>';
    }
    box.innerHTML = h;
    var cEl = $('taiPubCount');
    if (cEl) cEl.textContent = pend.length ? ('未公開 ' + pend.length + '件') : '';
  }

  function taiCheckAll(on) {
    var els = document.querySelectorAll('.tai-chk');
    for (var i = 0; i < els.length; i++) els[i].checked = !!on;
  }

  function collectChecked() {
    var out = [];
    var els = document.querySelectorAll('.tai-chk');
    for (var i = 0; i < els.length; i++) {
      if (!els[i].checked) continue;
      var id = els[i].getAttribute('data-id');
      var ta = document.querySelector('.tai-body[data-id="' + id + '"]');
      var d = null;
      for (var j = 0; j < _drafts.length; j++) if (_drafts[j].id === id) d = _drafts[j];
      if (!d) continue;
      out.push({ id: id, kind: d.kind, targetId: d.targetId, refKey: d.refKey, body: ta ? ta.value : d.body });
    }
    return out;
  }

  async function taiPublish() {
    var cid = classId();
    var picks = collectChecked();
    if (!cid) { sayPub('クラスを選んでください'); return; }
    if (!picks.length) { sayPub('公開するものにチェックを入れてください'); return; }
    var kidCount = picks.filter(function (x) { return (KIND_JA[x.kind] || {}).to === 'kid'; }).length;
    var paperCount = picks.filter(function (x) { return (KIND_JA[x.kind] || {}).to === 'paper'; }).length;
    if (!confirm('チェックした ' + picks.length + '件を公開します。\n・子どもの画面に出る: ' + kidCount + '件\n・紙のカルテに載る（印刷して渡す）: ' + paperCount + '件\nよろしいですか？')) return;

    sayPub('公開中...');
    var wk = weekKey();
    var okIds = [], msgs = [];
    var byKind = {};
    picks.forEach(function (p) { (byKind[p.kind] = byKind[p.kind] || []).push(p); });

    // --- クラス所見 ---
    if (byKind.CLASS) {
      var body = byKind.CLASS.map(function (x) { return x.body; }).join(NL + NL);
      var r = await postJson('/api/teacher/class-ai-summary', { classId: cid, overview: body });
      if (r && r.ok) { byKind.CLASS.forEach(function (x) { okIds.push(x.id); }); msgs.push('クラス所見'); }
    }
    // --- 週報（先生だけが見る。下書き表にそのまま残す） ---
    if (byKind.WEEKREPORT) {
      byKind.WEEKREPORT.forEach(function (x) { okIds.push(x.id); });
      msgs.push('週報');
    }
    // --- 個人カルテ ---
    if (byKind.KARTE) {
      var r2 = await postJson('/api/teacher/student-ai-comments', {
        comments: byKind.KARTE.map(function (x) { return { studentId: x.targetId, comment: x.body }; })
      });
      if (r2 && r2.ok) {
        byKind.KARTE.forEach(function (x) { okIds.push(x.id); });
        msgs.push('カルテ' + r2.saved + '人');
        // 📒 2026-09: 公開したカルテを、その子のアプリ画面にも出す。
        //   ここで記録した子だけが /api/student/my-karte で自分のカルテを見られる。
        //   （先生が公開していない子には何も出ない）
        try {
          await postJson('/api/teacher/karte-share', {
            classId: cid,
            studentIds: byKind.KARTE.map(function (x) { return x.targetId; })
          });
        } catch (e) {}
      }
    }
    // --- 計画アドバイス ---
    if (byKind.PLAN) {
      var r3 = await postJson('/api/teacher/plan-ai-comments', {
        weekKey: wk, comments: byKind.PLAN.map(function (x) { return { studentId: x.targetId, comment: x.body }; })
      });
      if (r3 && r3.ok) { byKind.PLAN.forEach(function (x) { okIds.push(x.id); }); msgs.push('計画' + r3.saved + '人'); }
    }
    // --- おすすめ計画 ---
    if (byKind.SUGGEST) {
      var r4 = await postJson('/api/teacher/plan-suggestions', {
        weekKey: wk, comments: byKind.SUGGEST.map(function (x) { return { studentId: x.targetId, comment: x.body }; })
      });
      if (r4 && r4.ok) { byKind.SUGGEST.forEach(function (x) { okIds.push(x.id); }); msgs.push('おすすめ計画' + r4.saved + '人'); }
    }
    // --- 週の振り返りの返却 ---
    if (byKind.REFLECT) {
      var r5 = await postJson('/api/teacher/reflection-comments', {
        weekKey: wk, comments: byKind.REFLECT.map(function (x) { return { studentId: x.targetId, comment: x.body }; })
      });
      if (r5 && r5.ok) { byKind.REFLECT.forEach(function (x) { okIds.push(x.id); }); msgs.push('振り返り返却' + r5.saved + '人'); }
    }
    // --- 家庭学習コメント（既存の返却APIをそのまま使う＝コイン付与は既存のまま） ---
    if (byKind.DAILY) {
      var n = 0;
      for (var i = 0; i < byKind.DAILY.length; i++) {
        var it = byKind.DAILY[i];
        sayPub('家庭学習コメントを返しています... (' + (i + 1) + '/' + byKind.DAILY.length + ')');
        try {
          var rr = await fetch('/api/teacher/homework/' + encodeURIComponent(it.refKey) + '/return', {
            method: 'POST', credentials: 'include',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ comment: it.body, hasPhysical: false })
          });
          var jj = await rr.json().catch(function () { return null; });
          if (jj && jj.ok) { okIds.push(it.id); n++; }
        } catch (e) {}
      }
      if (n) msgs.push('家庭学習コメント' + n + '人');
    }

    if (okIds.length) {
      await postJson('/api/teacher/ai-drafts/mark', { ids: okIds, status: 'published' });
    }
    sayPub(okIds.length ? ('✓ 公開しました: ' + msgs.join(' / ')) : '公開できませんでした');
    taiLoadDrafts();
    try { if (typeof loadAiSummary === 'function') loadAiSummary(); } catch (e) {}
  }

  async function taiDiscard() {
    var picks = collectChecked();
    if (!picks.length) { sayPub('消すものにチェックを入れてください'); return; }
    if (!confirm('チェックした ' + picks.length + '件の下書きを消します。よろしいですか？')) return;
    await postJson('/api/teacher/ai-drafts/mark', { ids: picks.map(function (x) { return x.id; }), status: 'discarded' });
    sayPub('下書きを消しました');
    taiLoadDrafts();
  }

  // 📄 全員分のカルテを印刷（A4・1人1枚）。既存の downloadAllKartes() をそのまま使う。
  async function taiPrintKartes() {
    var st = $('taiPrintStatus');
    var cid = classId();
    if (!cid) { if (st) st.textContent = 'クラスを選んでください'; return; }
    if (typeof downloadAllKartes !== 'function') { if (st) st.textContent = 'この画面では使えません'; return; }
    if (st) st.textContent = '名簿を読み込み中...';
    try { await taiLoadRoster(); } catch (e) {}
    if (st) st.textContent = 'カルテを作成しています...（人数ぶん時間がかかります）';
    try { await downloadAllKartes(); } catch (e) {}
    if (st) st.textContent = '✓ 印刷用の画面を開きました（出てこないときはポップアップを許可してください）';
  }

  // 個人カルテの児童一覧を、古いAIボタンを押さなくても出せるようにする
  async function taiLoadRoster() {
    var cid = classId();
    if (!cid) return;
    var rd = await postJson('/api/teacher/records/parse', { classId: cid, text: '' });
    var roster = (rd && rd.roster) || [];
    try {
      if (typeof updateKarteStudentList === 'function') {
        updateKarteStudentList(roster.map(function (r) {
          return { userId: r.userId, loginId: r.loginId, name: r.name };
        }), cid);
      }
    } catch (e) {}
    try { taiOneFill(roster); } catch (e) {}
  }

  // --- 🔁 1人だけ作り直す（旧「1人ずつの計画コピー」の置きかえ） ---
  function taiOneEsc(s) {
    return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;');
  }
  function taiOneFill(roster) {
    var sel = $('taiOneStu');
    if (!sel) return;
    var cur = sel.value;
    var h = '<option value="">児童をえらぶ</option>';
    (roster || []).forEach(function (r) {
      h += '<option value="' + taiOneEsc(r.userId) + '">' + taiOneEsc(nameOf(r.loginId, r.name)) + '</option>';
    });
    sel.innerHTML = h;
    if (cur) { try { sel.value = cur; } catch (e) {} }
  }
  async function taiOneOpen() { try { await taiLoadRoster(); } catch (e) {} }
  async function taiOneCopy() {
    var sel = $('taiOneStu'), kd = $('taiOneKind');
    var sid = sel ? sel.value : '';
    if (!sid) { sayOne('児童をえらんでください'); return; }
    sayOne('この子のぶんを作っています…');
    await taiCopyAll({ onlyStudentId: sid, onlyKind: (kd ? kd.value : 'DAILY') });
  }
  async function taiOneImport() { await taiImport({ append: true }); }

  // ---------- 公開（グローバル） ----------
  window.taiCopyAll = taiCopyAll;
  window.taiImport = taiImport;
  window.taiLoadDrafts = taiLoadDrafts;
  window.taiPublish = taiPublish;
  window.taiDiscard = taiDiscard;
  window.taiCheckAll = taiCheckAll;
  window.taiLoadRoster = taiLoadRoster;
  window.taiPrintKartes = taiPrintKartes;
  window.taiCopyFresh = taiCopyFresh;
  window.taiOneOpen = taiOneOpen;
  window.taiOneCopy = taiOneCopy;
  window.taiOneImport = taiOneImport;

  // ---------- 初期化 ----------
  // 金曜日は「週の振り返りの返却」を既定でONにし、その旨を画面に出す（先生は外せる）
  function applyFriday() {
    if (!isFridayJst()) return;
    var cb = $('taiOptReflect');
    if (!cb || cb.getAttribute('data-fri')) return;
    cb.setAttribute('data-fri', '1');
    cb.checked = true;
    if ($('taiFriNote')) return;
    var row = cb.parentNode && cb.parentNode.parentNode;
    if (!row || !row.parentNode) return;
    var note = document.createElement('div');
    note.id = 'taiFriNote';
    note.className = 'bg-amber-50 border border-amber-200 rounded-lg px-2 py-1.5 text-xs text-amber-800 font-bold mb-2';
    note.textContent = '📅 今日は金曜日です。「週の振り返りの返却」も入れてあります（コピーは1週間ぶん長くなります）。今週はやらない場合はチェックを外してください。';
    row.parentNode.insertBefore(note, row.nextSibling);
  }

  var _lastCid = null;
  function init() {
    applyFriday();
    var sel = $('analyticsClassFilter');
    if (sel && !sel.getAttribute('data-tai')) {
      sel.setAttribute('data-tai', '1');
      sel.addEventListener('change', function () { _lastCid = sel.value; taiLoadDrafts(); });
    }
    // クラス一覧はあとから入るので、値が入ったタイミングで一度だけ読み込む
    setInterval(function () {
      var cid = classId();
      if (cid && cid !== _lastCid) { _lastCid = cid; taiLoadDrafts(); }
    }, 1200);
    taiLoadDrafts();
  }
  if (document.readyState !== 'loading') setTimeout(init, 600);
  else document.addEventListener('DOMContentLoaded', function () { setTimeout(init, 600); });
})();
