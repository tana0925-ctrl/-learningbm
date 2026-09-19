/* ===================================================================
   war-mix.js : 攻略モードの出題の組み立て（2026-09 WARMIX_V1）
     ・「まちがえた問題」を中心のひとつにする（4択もちゃんと戻す）
     ・「該当学年の既習単元」を厚く、下の学年は復習として少数
     ・未習の単元は出さない（先生がクラスごとに設定／未設定なら全部出す）

   public/index.html は編集しない。中身はこのファイル。
   攻略モードの本体は IIFE の中にあるので、src/index.tsx の書きかえで
   この WARMIX を呼ぶフックだけを差し込んでいる。WARMIX が無い／壊れた
   場合は、どのフックも従来の処理にそのまま戻る。

   ※ 攻略モードだけに効く。修行モード・野生バトルには触らない。
   ※ 児童データ（progress）への書き込みはしない。読むだけ。
   =================================================================== */
(function (global) {
  'use strict';

  // ─────────────────────────────────────────────────────────────
  // 調整つまみ。ここの数字だけ変えれば比率が変わる。
  // ブラウザのコンソールから window.WARMIX.tuning.xxx = n でも試せる。
  // ─────────────────────────────────────────────────────────────
  var tuning = {
    // まちがえた問題を出す確率。手持ちの誤答が無ければ自動的に通常出題になる。
    wrongRate: 0.35,

    // 単元の重み。該当学年（その子の登録学年）を厚く、下の学年は薄く。
    ownGradeWeight: 100,
    lowerGradeWeight: 13,

    // 正答率による上のせ／下げ（該当学年・下の学年のどちらにも掛かる）
    accBoostMin: 0.40,   // よくできている単元はここまで下がる
    accBoostMax: 1.60,   // 苦手な単元はここまで上がる
    fewDataBoost: 1.20,  // 回答が6件未満の単元を少しだけ多めに
    fewDataThreshold: 6,

    // 誤答の出し直しで、同じ問題ばかりにならないようにする
    wrongRecentSkip: 6,  // 直近この回数に出した誤答は避ける
    wrongCountPower: 1.25,

    // 安全弁：進度でしぼった結果これを下回るならしぼらない
    minCandidates: 8,

    // 図（SVG）の問題を出してよい画面のはば。
    // 攻略モードの問題欄は答え欄と決定ボタンに約200px取られるので、
    // スマホ(375px)だと図が160px幅まで縮み、数直線の目もりが7px程度になって読めない。
    // 実機で確認したうえでの数字。768pxのタブレットでははっきり読める。
    figureMinWidth: 640
  };

  // ─────────────────────────────────────────────────────────────
  // 小道具
  // ─────────────────────────────────────────────────────────────
  // app 側の player は `let player`（window には載らない）。sticker.js と同じ作法で取る。
  function curP() {
    try { if (typeof player !== 'undefined' && player) return player; } catch (e) {}
    return global.player || null;
  }
  function strip(s) {
    return String(s == null ? '' : s).replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim();
  }
  function clamp(v, lo, hi) { return v < lo ? lo : (v > hi ? hi : v); }
  function uGrade() { return Number(global.__userGrade || 0) || 0; }

  // 図（SVG）の問題を出してよい画面かどうか。毎回みるので、
  // タブレットを横にした・縦にしたにもその場で追従する。
  function figuresOk() {
    try {
      var wpx = Number(global.innerWidth) || 0;
      if (!wpx) return true;            // 幅がわからないときは止めない
      return wpx >= tuning.figureMinWidth;
    } catch (e) { return true; }
  }

  // CURRICULUM の単元を id で引けるようにしておく（初回だけ作る）
  var _ix = null, _ixLen = -1;
  function unitIndex() {
    var C = global.CURRICULUM;
    if (!C) return {};
    var n = Object.keys(C).length;
    if (_ix && _ixLen === n) return _ix;
    var ix = {};
    for (var sk in C) {
      var sub = C[sk]; if (!sub || !sub.grades) continue;
      for (var g in sub.grades) {
        var gd = sub.grades[g]; if (!gd || !gd.units) continue;
        for (var i = 0; i < gd.units.length; i++) {
          var u = gd.units[i];
          if (u && u.id) ix[u.id] = { id: u.id, name: u.name, gen: u.gen, input: u.input, grade: Number(g), subject: sk, subjectName: sub.name };
        }
      }
    }
    _ix = ix; _ixLen = n;
    return ix;
  }
  function unitInfo(mode) { return unitIndex()[String(mode)] || null; }

  // 正答率（_recentAcc は攻略モードから見えないので自前で同じ計算をする）
  function recentAcc(mode) {
    var p = curP();
    var prog = (p && p.trainingProgress) ? p.trainingProgress[mode] : null;
    var recent = (prog && prog.recentAnswers) ? prog.recentAnswers : [];
    var total = recent.length, correct = 0;
    for (var i = 0; i < recent.length; i++) if (recent[i] === true) correct++;
    return { total: total, correct: correct, acc: total ? Math.round((correct / total) * 100) : 0 };
  }

  // ─────────────────────────────────────────────────────────────
  // 進度（習ったところまで）。先生がクラスごとに設定する。
  //   allowed[unitId] === false  → 未習。出さない。
  //   設定が無い単元 → 出す。
  //
  // クラスにまだ設定が無いときは、下の「9月時点の草案」を初期値として使う。
  // これは一般的な年間指導計画から組んだ仮の設定で、先生が教師画面で
  // いつでも変更できる。教師画面にも「仮の設定です」と表示している。
  // 理科は学校ごとに順序の差が大きく、とくに自信が無い。
  // ─────────────────────────────────────────────────────────────
  var DEFAULT_PROGRESS = {
    note: '2026年9月時点の仮の設定です。先生が確認して直してください。',
    units: {
      // ── 算数 小6：比例と反比例は10〜11月の想定
      'm6-proportion': false,
      // ── 社会 小6：歴史は「天下統一」(9・10月) まで。江戸以降と世界は未習の想定
      's6-hist-u7': false, 's6-hist-u8': false, 's6-hist-u9': false,
      's6-hist-u10': false, 's6-hist-u11': false, 's6-world': false,
      // ── 理科 小6：ここは自信が薄い。先生の確認がとくに必要
      'r6-earth': false, 'r6-moon': false, 'r6-lever': false, 'r6-electric': false,
      // ── 国語 小6：古典は秋以降の想定
      'j6-classic': false,
      // ── 社会 小4 の地域学習：前任校の教材なので、既定は「出さない」。
      //    このクラスで扱っていれば先生が「出す」に切りかえる。
      's4-inuyama': false, 's4-minamichita': false, 's4-toyohashi': false,
      'social-nagoyasouth': false, 'social-seto': false
    },
    // 先生がとくに確認すべき教科（教師画面で注意書きを出すため）
    lowConfidence: ['science']
  };

  var allowed = null;       // null = 未設定
  var allowedLoaded = false;

  function setAllowed(map) {
    allowed = (map && typeof map === 'object') ? map : null;
    allowedLoaded = true;
  }
  function isAllowed(mode) {
    if (!allowed) return true;
    return allowed[String(mode)] !== false;
  }

  function loadAllowed() {
    if (allowedLoaded) return Promise.resolve(allowed);
    return fetch('/api/student/class-info', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        // クラスに入っていない子（先生の画面など）は、しぼらない
        if (!j || !j.ok || !j.class) { setAllowed(null); return allowed; }
        var raw = j.class.unitProgress;
        if (!raw) { setAllowed(DEFAULT_PROGRESS.units); return allowed; }  // 未設定 → 草案を使う
        var obj = (typeof raw === 'string') ? JSON.parse(raw) : raw;
        setAllowed(obj && obj.units ? obj.units : DEFAULT_PROGRESS.units);
        return allowed;
      })
      .catch(function () { setAllowed(null); return allowed; });
  }

  // 候補のしぼりこみ。攻略モードの _warBuildGradeCandidates から呼ばれる。
  function filterCandidates(cands) {
    try {
      if (!allowed || !Array.isArray(cands)) return cands;
      var out = [];
      for (var i = 0; i < cands.length; i++) if (isAllowed(cands[i].mode)) out.push(cands[i]);
      if (out.length < tuning.minCandidates) return cands;   // 安全弁
      return out;
    } catch (e) { return cands; }
  }

  // ─────────────────────────────────────────────────────────────
  // 単元の重み。該当学年を厚く、下の学年を薄く。
  // ─────────────────────────────────────────────────────────────
  function weightOf(c) {
    try {
      var mode = c && c.mode;
      var info = unitInfo(mode);
      var g = info ? info.grade : Number(c && c.grade) || 0;
      var ug = uGrade();

      var w = (ug && g === ug) ? tuning.ownGradeWeight : tuning.lowerGradeWeight;
      if (!ug) w = tuning.ownGradeWeight;   // 学年が取れないときは平らに

      var r = recentAcc(mode);
      if (r.total > 0) {
        // 苦手な単元ほど多め。ただし振れ幅は抑える。
        w = w * clamp((110 - r.acc) / 70, tuning.accBoostMin, tuning.accBoostMax);
        if (r.total < tuning.fewDataThreshold) w = w * tuning.fewDataBoost;
      }
      // ★ 回答が1件も無い単元は既定のまま（acc=0 を「正答率0%」と読まない）。
      //    これが「35単元だけ3.7倍」の元になっていた計算の直し。
      return Math.max(1, Math.round(w));
    } catch (e) { return tuning.lowerGradeWeight; }
  }

  // ─────────────────────────────────────────────────────────────
  // まちがえた問題
  //   記録：4択なら選択肢もいっしょに残す（これが無いと戻せない）
  //   復元：選択肢があればそのまま。無い古い記録は、その単元の問題を
  //         作り直して同じ問題文を探す。
  // ─────────────────────────────────────────────────────────────
  function recordWrong(prob) {
    try {
      var p = curP(); if (!p) return;
      if (!p.wrongQuestions) p.wrongQuestions = {};
      if (!prob) return;

      var mode = String(prob.mode || prob._mode || 'war');
      var qText = strip(prob.q);
      if (!qText) return;

      var isMCQ = Array.isArray(prob.options) && prob.options.length === 4;
      var ansVal, opts = null;
      if (isMCQ) {
        var idx = Number(prob.ans);
        if (!(idx >= 0 && idx < 4)) idx = prob.options.indexOf(String(prob.ans));
        if (!(idx >= 0 && idx < 4)) return;
        ansVal = String(prob.options[idx]);
        opts = prob.options.slice(0, 4).map(String);
      } else {
        ansVal = String(prob.ans);
      }

      var key = ('war||' + qText + '||' + ansVal).slice(0, 300);
      var cur = p.wrongQuestions[key] || { count: 0 };
      cur.count = (cur.count || 0) + 1;
      cur.mode = mode;          // 'war' ではなく単元IDを残す
      cur.q = qText;
      cur.ans = ansVal;
      cur.qhtml = (typeof prob.q === 'string' && /^\s*</.test(prob.q)) ? String(prob.q).slice(0, 4000) : undefined;
      if (opts) { cur.opts = opts; cur.mcq = 1; } else { delete cur.opts; delete cur.mcq; }
      p.wrongQuestions[key] = cur;
    } catch (e) {}
  }

  // 古い記録（選択肢なし）を、その単元の生成関数を回して復元する
  function rebuildFromUnit(mode, qText, ansText) {
    try {
      var info = unitInfo(mode); if (!info) return null;
      var fn = global[info.gen]; if (typeof fn !== 'function') return null;
      for (var i = 0; i < 60; i++) {
        var p = fn(); if (!p) continue;
        if (strip(p.q) !== qText) continue;
        if (Array.isArray(p.options) && p.options.length === 4) {
          var idx = Number(p.ans);
          if (!(idx >= 0 && idx < 4)) idx = p.options.indexOf(ansText);
          if (idx >= 0 && idx < 4) return { q: p.q, ans: idx, options: p.options.slice(0, 4).map(String), mode: mode, _weak: true };
          return null;
        }
        return { q: p.q, ans: p.ans, mode: mode, _weak: true };
      }
    } catch (e) {}
    return null;
  }

  var recentWrong = [];   // 直近に出した誤答のキー

  function pickWrong() {
    try {
      var p = curP();
      if (!p || !p.wrongQuestions) return null;

      var keys = [], arr = [];
      for (var k in p.wrongQuestions) {
        var it = p.wrongQuestions[k];
        if (!it || !it.q || it.ans == null || !(it.count > 0)) continue;
        // 進度で「出さない」にした単元の誤答は出さない
        if (it.mode && it.mode !== 'war' && !isAllowed(it.mode)) continue;
        keys.push(k); arr.push(it);
      }
      if (!arr.length) return null;

      // 直近に出したものは避ける（全部避けることになるなら避けない）
      var pool = [], poolKeys = [];
      for (var i = 0; i < arr.length; i++) {
        if (recentWrong.indexOf(keys[i]) >= 0) continue;
        pool.push(arr[i]); poolKeys.push(keys[i]);
      }
      if (!pool.length) { pool = arr; poolKeys = keys; }

      // まちがえた回数が多いものほど出やすく
      var total = 0, ws = [];
      for (var j = 0; j < pool.length; j++) {
        var wv = Math.pow(Math.max(1, Number(pool[j].count) || 1), tuning.wrongCountPower);
        total += wv; ws.push(wv);
      }

      // 復元に失敗することがあるので、何度か引き直す
      for (var attempt = 0; attempt < 12; attempt++) {
        var r = Math.random() * total, pickIdx = 0;
        for (var m = 0; m < pool.length; m++) { r -= ws[m]; if (r <= 0) { pickIdx = m; break; } }
        var it2 = pool[pickIdx];
        var built = restore(it2);
        if (built) {
          recentWrong.push(poolKeys[pickIdx]);
          while (recentWrong.length > tuning.wrongRecentSkip) recentWrong.shift();
          return built;
        }
      }
    } catch (e) {}
    return null;
  }

  function restore(it) {
    try {
      var qText = String(it.q || '').trim();
      var ansStr = String(it.ans == null ? '' : it.ans).trim();
      if (!qText) return null;

      // (a) 選択肢を残してある記録 → そのまま戻す（選択肢の順は毎回シャッフル）
      if (it.mcq && Array.isArray(it.opts) && it.opts.length === 4) {
        var opts = it.opts.slice();
        for (var i = opts.length - 1; i > 0; i--) { var j = Math.floor(Math.random() * (i + 1)); var t = opts[i]; opts[i] = opts[j]; opts[j] = t; }
        var idx = opts.indexOf(ansStr);
        if (idx < 0) return null;
        return { q: it.qhtml || qText, ans: idx, options: opts, mode: String(it.mode || 'war'), _weak: true };
      }

      // (b) 素直な数で答える問題 → そのまま戻す
      if (/^-?\d+(\.\d+)?$/.test(ansStr)) {
        return { q: it.qhtml || qText, ans: Number(ansStr), mode: String(it.mode || 'war'), _weak: true };
      }

      // (c) 古い記録：単元がわかるなら作り直して探す
      if (it.mode && it.mode !== 'war') {
        var built = rebuildFromUnit(it.mode, qText, ansStr);
        if (built) return built;
      }
    } catch (e) {}
    return null;   // 戻せないものは出さない（変な問題を出すよりよい）
  }

  // ─────────────────────────────────────────────────────────────
  // 出しわけの記録（実測・デバッグ用）。出題のたびに数える。
  // ─────────────────────────────────────────────────────────────
  var stats = { wrong: 0, ownGrade: 0, lowerGrade: 0, unknown: 0, total: 0 };
  function note(prob) {
    try {
      stats.total++;
      if (prob && prob._weak) { stats.wrong++; return; }
      var info = prob ? unitInfo(prob.mode || prob._mode) : null;
      if (!info) { stats.unknown++; return; }
      if (uGrade() && info.grade === uGrade()) stats.ownGrade++; else stats.lowerGrade++;
    } catch (e) {}
  }
  function report() {
    var t = stats.total || 1, r = function (n) { return +(100 * n / t).toFixed(1); };
    return { 出題数: stats.total, 'まちがえた問題%': r(stats.wrong), '該当学年%': r(stats.ownGrade),
             '下の学年%': r(stats.lowerGrade), 'その他%': r(stats.unknown) };
  }

  global.WARMIX = {
    version: 'WARMIX_V1',
    tuning: tuning,
    DEFAULT_PROGRESS: DEFAULT_PROGRESS,   // 教師画面(teacher-progress.js)も同じものを使う
    // 攻略モード本体から呼ばれるもの
    wrongRate: function () { return Number(tuning.wrongRate) || 0; },
    filterCandidates: filterCandidates,
    weightOf: weightOf,
    pickWrong: pickWrong,
    recordWrong: recordWrong,
    note: note,
    // 設定・調査用
    figuresOk: figuresOk,
    loadAllowed: loadAllowed,
    setAllowed: setAllowed,
    isAllowed: isAllowed,
    getAllowed: function () { return allowed; },
    unitInfo: unitInfo,
    recentAcc: recentAcc,
    report: report,
    resetStats: function () { stats = { wrong: 0, ownGrade: 0, lowerGrade: 0, unknown: 0, total: 0 }; }
  };

  // 起動時にクラスの進度設定を読む（失敗したら「未設定＝全部出す」）
  try {
    if (typeof fetch === 'function') {
      if (document.readyState !== 'loading') loadAllowed();
      else document.addEventListener('DOMContentLoaded', loadAllowed);
    }
  } catch (e) {}

})(typeof window !== 'undefined' ? window : globalThis);
