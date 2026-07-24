/* ============================================================
   学年 段階解禁チェーン ＆ 高1（grade10）コア v182
   ・自分の学年（__userGrade）以下は常時開放。自分の学年より上だけ段階解禁
   ・1つ下の学年ユニットの合計正解数(修行＋野生) ≧ NEED で次の学年が開く
   ・移行措置（グランドファザー）: すでにその学年で解答済みの子は自動解禁
   ・解禁時だけ「扉が開いた」演出。事前告知UIなし
   ・g8core のヘルパ再利用。public/index.html は無編集（.replace非接触）
   ============================================================ */
(function () {
  if (window.__G10CORE__) return;
  window.__G10CORE__ = 1;

  var G8 = window.G8;
  if (!G8) return;

  var G10 = (window.G10 = window.G10 || {});
  G10.R = G8.R; G10.pick = G8.pick; G10.shuffle = G8.shuffle; G10.q = G8.q;

  // ▼▼ 解禁のしきい値（あとで調整しやすいよう定数化）▼▼
  var NEED_CORRECT = 100;  // 1つ下の学年での「合計正解数」がこの数以上
  var NEED_ACC = 0.80;     // かつ その学年の正答率がこの割合以上（0.80 = 80%）
  var MIN_TOTAL = 1;       // 正答率を判定するのに必要な最低解答数（0除算回避）
  // ▲▲ ここまで ▲▲
  var LABEL = { 2: '小2', 3: '小3', 4: '小4', 5: '小5', 6: '小6', 7: '中1', 8: '中2', 9: '中3', 10: '高校' };

  // 自分の学年（1〜6）。不明なら小6まで常時開放という自然な代替
  function baseGrade() {
    try {
      var g = Number(window.__userGrade || 0);
      if (g >= 1 && g <= 6) return g;
    } catch (e) {}
    return 6;
  }

  // CURRICULUM を真実源に、学年Lの「合計正解数」と「合計解答数」を集計
  //  正答率トラッキング metrics.learn.byUnit（正誤とも加算・修行/野生の両方）を優先。
  //  無ければ trainingProgress（correctCount / count）でフォールバック。小4のレガシー名も網羅。
  function gradeStats(L) {
    var c = 0, t = 0;
    try {
      var C = window.CURRICULUM; if (!C) return { c: 0, t: 0 };
      var P = (typeof player !== 'undefined' && player) ? player : null; if (!P) return { c: 0, t: 0 };
      var byUnit = (P.metrics && P.metrics.learn && P.metrics.learn.byUnit) ? P.metrics.learn.byUnit : {};
      var tp = P.trainingProgress || {};
      Object.keys(C).forEach(function (subj) {
        var g = C[subj] && C[subj].grades && C[subj].grades[L];
        if (!g || !g.units) return;
        g.units.forEach(function (u) {
          var id = u.id;
          var bu = byUnit[id];
          var pu = tp[id];
          var uc = 0, ut = 0;
          if (bu) { uc = Number(bu.correct || 0) || 0; ut = Number(bu.total || 0) || 0; }
          // trainingProgress で補完（byUnit未記録の解答も拾う）
          if (pu) { uc = Math.max(uc, Number(pu.correctCount || 0) || 0); ut = Math.max(ut, Number(pu.count || 0) || 0); }
          if (ut < uc) ut = uc; // 念のため total>=correct
          c += uc; t += ut;
        });
      });
    } catch (e) {}
    return { c: c, t: t };
  }
  G10.gradeStats = gradeStats;
  // 到達条件を満たすか（100問正解 かつ 正答率80%以上）
  function gradeCleared(L) {
    var s = gradeStats(L);
    return (s.c >= NEED_CORRECT) && (s.t >= MIN_TOTAL) && ((s.c / s.t) >= NEED_ACC);
  }
  G10.gradeCleared = gradeCleared;

  // 解禁状態の共有アクセサ（g8core/g9core からも参照）
  // 自分の学年以下は常に true。上は player.gradeUnlocked を見る。
  window.__gradeUnlocked = function (g) {
    try {
      if (Number(g) <= baseGrade()) return true;
      return !!(typeof player !== 'undefined' && player && player.gradeUnlocked && player.gradeUnlocked[g]);
    } catch (e) { return false; }
  };

  // 高校エリアの登録内容（各g10教科ファイルが stage する）
  G10._pending = {};
  G10.stage = function (subject, units, displays) {
    G10._pending[subject] = { units: units, displays: displays || {} };
    try { if (window.__gradeUnlocked(10)) _registerAll(); } catch (e) {}
  };
  function _registerAll() {
    try {
      var C = window.CURRICULUM; if (!C) return;
      Object.keys(G10._pending).forEach(function (subject) {
        if (!C[subject] || !C[subject].grades) return;
        var g = C[subject].grades;
        if (!g[10]) g[10] = { label: '高校', units: [] };
        var have = {}; g[10].units.forEach(function (u) { have[u.id] = 1; });
        G10._pending[subject].units.forEach(function (u) { if (!have[u.id]) g[10].units.push(u); });
        G8.addDisplay(G10._pending[subject].displays);
      });
    } catch (e) {}
  }

  function doorAlert(g) {
    setTimeout(function () {
      try {
        if (g === 10) alert('🏫✨ 高校への扉が開いた！ ✨\n中3をやりこんだキミの前に、\n隠されていた「高校エリア」があらわれた！\n\n野生バトルの学年で「🏫高校」を選んでみよう！');
        else alert('🚪✨ ' + (LABEL[g] || (g + '年')) + 'への扉が開いた！ ✨\n下の学年をがんばったごほうびに、\n「' + (LABEL[g] || (g + '年')) + '」がひらいたよ！\n\n野生バトルの学年で選べるよ！');
      } catch (e) {}
    }, 400);
  }

  // 解禁チェック（自分の学年より上をチェーン＋グランドファザー）
  G10.checkUnlock = function () {
    try {
      if (typeof player === 'undefined' || !player) return;
      if (!player.gradeUnlocked || typeof player.gradeUnlocked !== 'object') player.gradeUnlocked = {};
      var U = player.gradeUnlocked;
      var base = baseGrade();
      var changed = false;

      // 1) 移行措置（グランドファザー）：自分の学年より上で、すでに解答済み(1問でも)なら、その学年と下位（baseより上）を静かに解禁
      for (var g = base + 1; g <= 10; g++) {
        if (!U[g] && gradeStats(g).t > 0) {
          for (var gg = base + 1; gg <= g; gg++) { if (!U[gg]) { U[gg] = true; changed = true; } }
        }
      }

      // 2) チェーン解禁：1つ下の学年で「合計100問正解＋正答率80%以上」を満たすと解禁（演出あり）
      for (var G = base + 1; G <= 10; G++) {
        if (U[G]) continue;
        var prevOpen = (G - 1 <= base) || !!U[G - 1];
        if (prevOpen && gradeCleared(G - 1)) {
          U[G] = true; changed = true; doorAlert(G);
        }
      }

      if (window.__gradeUnlocked(10)) _registerAll();
      if (changed) { try { if (window.saveData) window.saveData(); } catch (e) {} }
    } catch (e) {}
  };

  // ---- 学年ボタンの整合（自分の学年より上でロック中は消す／高校は解禁時だけ出す）----
  function g10BtnClass(sel) {
    return 'px-3 py-1 rounded-full text-sm font-bold border-2 transition ' +
      (sel ? 'bg-purple-600 text-white border-purple-600 shadow'
           : 'bg-white text-purple-700 border-purple-300 hover:border-purple-500');
  }
  function addGrade10Button() {
    try {
      if (!window.__gradeUnlocked(10)) return;
      var wrap = document.getElementById('pveGradeSelectorWrap');
      if (!wrap || wrap.querySelector('button[data-grade="10"]')) return;
      var btn = document.createElement('button');
      btn.dataset.grade = '10'; btn.textContent = '🏫高校';
      btn.className = g10BtnClass(Number(window.pveSelectedGrade) === 10);
      btn.onclick = function () { window.pveSelectedGrade = 10; if (window.renderPvEDistrictSelect) window.renderPvEDistrictSelect(); };
      wrap.appendChild(btn);
    } catch (e) {}
  }
  function enforceButtons() {
    try {
      var wrap = document.getElementById('pveGradeSelectorWrap');
      if (!wrap) return;
      var base = baseGrade();
      // 自分の学年より上でロック中の 2〜10 ボタンを消す（index.htmlは1〜7を無条件生成）
      for (var g = 2; g <= 10; g++) {
        if (!window.__gradeUnlocked(g)) {
          var b = wrap.querySelector('button[data-grade="' + g + '"]');
          if (b) b.remove();
          if (Number(window.pveSelectedGrade) === g) {
            window.pveSelectedGrade = base;
            if (window.renderPvEDistrictSelect) try { window.renderPvEDistrictSelect(); } catch (e) {}
          }
        }
      }
      if (window.__gradeUnlocked(10)) addGrade10Button();
    } catch (e) {}
  }
  G10.enforceButtons = enforceButtons;

  setInterval(function () { try { G10.checkUnlock(); enforceButtons(); } catch (e) {} }, 2000);
  setTimeout(function () { try { G10.checkUnlock(); enforceButtons(); } catch (e) {} }, 1200);
})();
