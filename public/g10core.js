/* ============================================================
   学年 段階解禁チェーン ＆ 高1（grade10）コア v181
   ・小6実績→中1→中2→中3→高校 の「扉が開く」段階解禁
   ・移行措置（グランドファザー）: すでにその学年で解答済みの子は自動解禁
   ・解禁されるまでその学年ボタンは出さない（事前告知UIなし）
   ・高校は隠しの最上級エリア。中3をやりこむと開く
   ・g8core のヘルパ再利用。public/index.html は無編集（.replace非接触）
   ============================================================ */
(function () {
  if (window.__G10CORE__) return;
  window.__G10CORE__ = 1;

  var G8 = window.G8;
  if (!G8) return;

  var G10 = (window.G10 = window.G10 || {});
  G10.R = G8.R; G10.pick = G8.pick; G10.shuffle = G8.shuffle; G10.q = G8.q;

  var NEED = 20; // 各段階の解禁に必要な「1つ下の学年ユニットの合計正解数」（自然に届く範囲）
  var LABEL = { 7: '中1', 8: '中2', 9: '中3', 10: '高校' };

  // 学年Lのユニット群の correctCount 合計（修行＋野生の両方が加算される）
  function gradeCorrectSum(L) {
    var sum = 0;
    try {
      var tp = (typeof player !== 'undefined' && player && player.trainingProgress) ? player.trainingProgress : null;
      if (!tp) return 0;
      var re = new RegExp('^[a-z]+' + L + '-');
      for (var k in tp) {
        if (re.test(k)) { var u = tp[k]; if (u) sum += Number(u.correctCount || 0) || 0; }
      }
    } catch (e) {}
    return sum;
  }
  G10.gradeCorrectSum = gradeCorrectSum;

  // 解禁状態の共有アクセサ（g8core/g9core から参照される）
  window.__gradeUnlocked = function (g) {
    try { return !!(typeof player !== 'undefined' && player && player.gradeUnlocked && player.gradeUnlocked[g]); }
    catch (e) { return false; }
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
        else alert('🚪✨ ' + LABEL[g] + 'への扉が開いた！ ✨\n下の学年をがんばったごほうびに、\n「' + LABEL[g] + '」の学年がひらいたよ！\n\n野生バトルの学年で「' + LABEL[g] + '」を選べるよ！');
      } catch (e) {}
    }, 400);
  }

  // 解禁チェック（チェーン＋グランドファザー）。達成の瞬間だけ演出＋保存
  G10.checkUnlock = function () {
    try {
      if (typeof player === 'undefined' || !player) return;
      if (!player.gradeUnlocked || typeof player.gradeUnlocked !== 'object') player.gradeUnlocked = {};
      var U = player.gradeUnlocked;
      var changed = false;

      // 1) 移行措置：すでにその学年で解答済み(correctCount>0)なら、その学年と下位を静かに解禁
      [7, 8, 9].forEach(function (g) {
        if (!U[g] && gradeCorrectSum(g) > 0) {
          for (var gg = 7; gg <= g; gg++) { if (!U[gg]) { U[gg] = true; changed = true; } }
        }
      });

      // 2) チェーン解禁：1つ下の学年の合計正解数がしきい値以上（演出あり）
      function tryChain(g, prevL) {
        if (U[g]) return;
        // 高校(10)以外は「その学年自体を触っていない」場合のみチェーン扱い（触っていれば上の移行で解禁済み）
        var prereqOk = (g === 7) ? true : !!U[g - 1];
        if (prereqOk && gradeCorrectSum(prevL) >= NEED) {
          U[g] = true; changed = true; doorAlert(g);
        }
      }
      tryChain(7, 6);
      tryChain(8, 7);
      tryChain(9, 8);
      tryChain(10, 9);

      if (U[10]) _registerAll();
      if (changed) { try { if (window.saveData) window.saveData(); } catch (e) {} }
    } catch (e) {}
  };

  // ---- 学年ボタンの整合（ロック中は消す／高校は解禁時だけ出す）----
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
      // ロック中の 7/8/9/10 ボタンを消す（index.htmlは7を無条件生成、g8/g9はゲート済みだが保険）
      [7, 8, 9, 10].forEach(function (g) {
        if (!window.__gradeUnlocked(g)) {
          var b = wrap.querySelector('button[data-grade="' + g + '"]');
          if (b) b.remove();
          // ロック学年が選択中なら小6に戻す
          if (Number(window.pveSelectedGrade) === g) {
            window.pveSelectedGrade = 6;
            if (window.renderPvEDistrictSelect) try { window.renderPvEDistrictSelect(); } catch (e) {}
          }
        }
      });
      if (window.__gradeUnlocked(10)) addGrade10Button();
    } catch (e) {}
  }
  G10.enforceButtons = enforceButtons;

  setInterval(function () { try { G10.checkUnlock(); enforceButtons(); } catch (e) {} }, 2000);
  // 初回は素早く（ログイン直後の移行反映）
  setTimeout(function () { try { G10.checkUnlock(); enforceButtons(); } catch (e) {} }, 1200);
})();
