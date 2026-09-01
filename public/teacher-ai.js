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
    var done = function () { say('✓ コピーしました。ChatGPT / Gemini / Claude に貼り付けてください'); };
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
  async function taiCopyAll() {
    var cid = classId();
    if (!cid) { say('先にクラスを選んでください'); return; }

    var want = {
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

    say('名簿を読み込み中...');
    var roster = [];
    try {
      var rd = await postJson('/api/teacher/records/parse', { classId: cid, text: '' });
      roster = (rd && rd.roster) || [];
    } catch (e) {}
    if (!roster.length) { say('名簿が取得できませんでした'); return; }

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
    out.push('   ・アプリの社会は正答率98%なのにテストは55点 → 知識はあるが記述で落としている可能性');
    out.push('   ・学習時間は長いのに正答率が上がらない → やり方が作業になっているかも');
    out.push('   ・提出率は高いのに満足度が🌧続き → むずかしさに一人で向き合っているかも');
    out.push('   ・クラス平均より大きく下 / 上の単元 → どこで差がついたか');
    out.push('5. 相手は小学生。課題ははっきり書いてよいが、必ず「次の一歩」とセットにする。');
    out.push('6. 先生が読む文（クラス所見・週報）はていねいな文体、子どもが読む文（家庭学習コメント・');
    out.push('   計画アドバイス・振り返り返却・カルテ・おすすめ計画）はやさしい話し言葉で。');
    out.push('');
    out.push('【目印の種類】');
    if (want.daily)   out.push('・=== [DAILY:...] === … その日の家庭学習への先生コメント。1〜2文、40字以内。子ども向け。');
    if (want.karte)   out.push('・=== [KARTE:...] === … 個人カルテ。①よいところ ②気になるところ ③次の一歩。子ども向け。');
    if (want.plan)    out.push('・=== [PLAN:...] === … 今週の計画へのアドバイス。①よい点 ②もっとよくする点 ③ひとこと。子ども向け。');
    if (want.reflect) out.push('・=== [REFLECT:...] === … 今週の振り返りへの返却コメント。2〜3文。子ども向け。');
    if (want.suggest) out.push('・=== [SUGGEST:...] === … 今週のおすすめ家庭学習。曜日ごとに3〜5項目。子ども向け。');
    if (want.classOv) out.push('・=== [CLASS] === … クラス全体の所見。5〜8行（よい傾向／気になる点／来週の手立て）。先生向け。');
    if (want.report)  out.push('・=== [WEEKREPORT] === … 今週の週報。管理職・保護者にも見せられる文体で10行程度。先生向け。');
    out.push('');
    out.push('==================================================');
    out.push('【A】クラスの土台（ここは読むだけ。書き足さなくてよい）');
    out.push('==================================================');

    // ---------- A. クラス共通データ ----------
    say('クラスのデータを集めています... (1/6)');
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
    say('クラスのデータを集めています... (2/6)');
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
    say('クラスのデータを集めています... (3/6)');
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

    // A-4 ラーニングアナリティクス（テスト平均・満足度・キーワード・相関）
    say('クラスのデータを集めています... (4/6)');
    try {
      var la = await getJson('/api/teacher/learning-analytics?classId=' + encodeURIComponent(cid));
      if (la && la.ok) {
        var tb = (la.tests && la.tests.bySubject) || [];
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
          out.push('■ 振り返りによく出る言葉: ' + kw.slice(0, 12).map(function (k) { return k.word + '(' + k.count + ')'; }).join('、'));
        }
        if (la.relation && la.relation.correlation != null) {
          out.push('■ 取り組んだ問題数と正答率の相関: r=' + la.relation.correlation);
        }
        var wk2 = (la.subjects && la.subjects.weak) || [];
        if (wk2.length) {
          out.push('■ クラスの弱い単元: ' + wk2.slice(0, 8).map(function (x) {
            return (x.name || x.unit || '') + (x.rate != null ? '(' + x.rate + '%)' : '');
          }).join('、'));
        }
        out.push('');
      }
    } catch (e) {}

    // A-5 要因分析（相関）— 計算で出している数字。AIには「見立ての材料」として渡す
    say('クラスのデータを集めています... (5/6)');
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
    say('クラスのデータを集めています... (6/6)');
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

      if (data && data.ok) {
        try {
          if (typeof _aiBodyLines === 'function') out = out.concat(_aiBodyLines(data));
        } catch (e) { out.push('(基本データの整形に失敗)'); }

        // ★ アプリ学習 と 紙のテスト の突き合わせ（教科ごと）
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
            out.push('');
            out.push('【★アプリ学習 と 紙のテスト の対応（教科ごと・ここを突き合わせて見立てを）】');
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

        // ★ クラス平均との差（単元ごと）
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
            out.push('【★クラス平均との差（アプリ学習・単元ごと／差の小さい順）】');
            diffs.slice(0, 10).forEach(function (d) {
              out.push('・' + d.name + '：本人' + d.mine + '% / クラス' + d.avg + '%（差 ' + (d.d >= 0 ? '+' : '') + d.d + 'pt・' + d.n + '問）');
            });
          }
        } catch (e) {}
      } else {
        out.push('(データを取得できませんでした)');
      }

      // 今週の計画
      var p = planByUser[st.userId];
      var planLines = [], reflText = '';
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
          out.push('');
          out.push('【今週の計画（本人が書いたもの）】');
          out = out.concat(planLines);
          if (p.revisionCount) out.push('（' + p.revisionCount + '回 書きなおしています）');
        }
        if (reflText && String(reflText).trim()) {
          out.push('');
          out.push('【今週の振り返り（本人が書いたもの）】');
          out.push(reflText);
        }
      }

      // 今日（未返却）の家庭学習
      var hw = hwByUser[st.userId];
      if (hw) {
        out.push('');
        out.push('【まだ返していない家庭学習】' + (hw.dayKey || ''));
        if (hw.aim)            out.push('・めあて: ' + hw.aim);
        if (hw.todo)           out.push('・やったこと: ' + hw.todo);
        if (hw.why)            out.push('・えらんだ理由: ' + hw.why);
        out.push('・学習時間: ' + (hw.minutes || 0) + '分');
        out.push('・手ごたえ: ' + (hw.endWeather === 'sun' ? '☀' : hw.endWeather === 'cloud' ? '☁' : hw.endWeather === 'rain' ? '🌧' : '?'));
        if (hw.weatherReason)  out.push('・ふりかえり: ' + hw.weatherReason);
        if (hw.nextImprove)    out.push('・次にがんばること: ' + hw.nextImprove);
        if (hw.parentComment)  out.push('・おうちの人から: ' + hw.parentComment);
        if (hw.restDay)        out.push('・（おやすみの記録）');
      }

      // ---- 書いてほしい欄（目印） ----
      out.push('');
      if (want.daily && hw && !hw.restDay) {
        out.push('=== [DAILY:' + hw.id + '] ' + nm + '｜' + (hw.dayKey || '') + ' ===');
        out.push('');
      }
      if (want.karte)   { out.push('=== [KARTE:' + sid + '] ' + nm + ' ==='); out.push(''); }
      if (want.plan && planLines.length)  { out.push('=== [PLAN:' + sid + '] ' + nm + ' ==='); out.push(''); }
      if (want.reflect && reflText && p && !p.reflectionReturnedAt) {
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

    copyText(out.join(NL));
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

  async function taiImport() {
    var cid = classId();
    var ta = $('taiPaste');
    var raw = ta ? ta.value : '';
    if (!cid) { say('先にクラスを選んでください'); return; }
    if (!raw || !raw.trim()) { say('AIの返事を貼り付けてください'); return; }

    say('読み取り中...');
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
      say('目印（=== [ ... ] === ）が見つかりませんでした（' + blocks.length + 'ブロック検出）');
      return;
    }

    var res = await postJson('/api/teacher/ai-drafts', {
      classId: cid, weekKey: weekKey(), replace: true, items: items
    });
    if (!res || !res.ok) { say('下書きの保存に失敗しました'); return; }
    say('✓ ' + res.saved + '件を下書きに取り込みました。下の「④ 先生が確認して公開」を見てください' +
        (unmatched.length ? '（名前が一致しなかったもの: ' + unmatched.slice(0, 5).join(', ') + '）' : ''));
    if (ta) ta.value = '';
    taiLoadDrafts();
  }

  // ===================================================================
  //  ④ 先生が確認して公開
  // ===================================================================
  var KIND_JA = {
    DAILY:     { ja: '家庭学習コメント', to: '子ども' },
    KARTE:     { ja: '個人カルテ',       to: '子ども' },
    PLAN:      { ja: '計画アドバイス',   to: '子ども' },
    REFLECT:   { ja: '振り返りの返却',   to: '子ども' },
    SUGGEST:   { ja: 'おすすめ計画',     to: '子ども' },
    CLASS:     { ja: 'クラス所見',       to: '先生だけ' },
    WEEKREPORT:{ ja: '週報',             to: '先生だけ' }
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
        var k = KIND_JA[x.kind] || { ja: x.kind, to: '' };
        var toCls = k.to === '子ども' ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-600';
        h += '<div class="bg-white rounded-lg border border-slate-200 p-2">' +
             '<div class="flex items-center gap-2 flex-wrap mb-1">' +
             '<input type="checkbox" class="tai-chk accent-indigo-600" data-id="' + esc(x.id) + '" checked>' +
             '<span class="text-xs font-bold text-slate-700">' + esc(k.ja) + '</span>' +
             (x.targetName ? '<span class="text-xs text-slate-600">' + esc(x.targetName) + '</span>' : '') +
             (x.refLabel ? '<span class="text-[10px] text-slate-400">' + esc(x.refLabel) + '</span>' : '') +
             '<span class="text-[10px] px-1.5 py-0.5 rounded ' + toCls + '">' + esc(k.to) + 'に届く</span>' +
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
    var kidCount = picks.filter(function (x) { return (KIND_JA[x.kind] || {}).to === '子ども'; }).length;
    if (!confirm('チェックした ' + picks.length + '件を公開します。\nうち ' + kidCount + '件は子どもの画面に出ます。よろしいですか？')) return;

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
      if (r2 && r2.ok) { byKind.KARTE.forEach(function (x) { okIds.push(x.id); }); msgs.push('カルテ' + r2.saved + '人'); }
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
  }

  // ---------- 公開（グローバル） ----------
  window.taiCopyAll = taiCopyAll;
  window.taiImport = taiImport;
  window.taiLoadDrafts = taiLoadDrafts;
  window.taiPublish = taiPublish;
  window.taiDiscard = taiDiscard;
  window.taiCheckAll = taiCheckAll;
  window.taiLoadRoster = taiLoadRoster;

  // ---------- 初期化 ----------
  var _lastCid = null;
  function init() {
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
