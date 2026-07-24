/* ============================================================
   中3（grade 9）コア v180（ネットレ対応 第6弾）
   ・g8core の共通ヘルパ（G8.R/pick/shuffle/q）を再利用
   ・CURRICULUM への学年9登録 / UNIT_DISPLAY 追加
   ・野生バトルの学年ボタン「中3」追加（G8._wild を共有）
   ※ public/index.html は変更せず window 経由で拡張する方式（.replace非接触）
   ============================================================ */
(function () {
  if (window.__G9CORE__) return;
  window.__G9CORE__ = 1;

  var G8 = window.G8;
  if (!G8) { // g8core が無い場合の最小フォールバック
    G8 = window.G8 = {};
    G8.R = function (a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; };
    G8.pick = function (a) { return a[G8.R(0, a.length - 1)]; };
    G8.shuffle = function (a) { for (var i = a.length - 1; i > 0; i--) { var j = G8.R(0, i); var t = a[i]; a[i] = a[j]; a[j] = t; } return a; };
    G8.q = function (diff, q, correct, wrongs) {
      var c = String(correct), ws = [], i, w; wrongs = wrongs || [];
      for (i = 0; i < wrongs.length && ws.length < 3; i++) { w = String(wrongs[i]); if (w !== c && ws.indexOf(w) < 0) ws.push(w); }
      var k = 1; while (ws.length < 3 && k < 12) { w = c + Array(k + 1).join('？'); if (ws.indexOf(w) < 0) ws.push(w); k++; }
      var opt = G8.shuffle([c, ws[0], ws[1], ws[2]]);
      return { q: '【' + diff + '】' + q, ans: opt.indexOf(c), options: opt, inputType: 'mcq' };
    };
    G8._wild = G8._wild || {};
    G8.addWild = function (map) { for (var k in map) G8._wild[k] = map[k]; };
    G8.addDisplay = function (map) { window.UNIT_DISPLAY = window.UNIT_DISPLAY || {}; for (var k in map) { if (!window.UNIT_DISPLAY[k]) window.UNIT_DISPLAY[k] = map[k]; } };
    // pickWildMonsterId 未パッチならパッチ
    (function () {
      var orig = window.pickWildMonsterId;
      if (typeof orig !== 'function' || orig.__g8) return;
      var patched = function (areaId, depth) {
        try {
          var pool = G8._wild[areaId];
          if (pool) {
            var arr = pool[depth] || pool[3] || pool[1];
            var isFriend = false;
            try { isFriend = (typeof battle !== 'undefined' && battle && (battle.friendGym || battle.friendCodeKey)); } catch (e) {}
            if (arr && arr.length && !isFriend && Math.random() < 0.12) return arr[Math.floor(Math.random() * arr.length)];
          }
        } catch (e) {}
        return orig.apply(this, arguments);
      };
      patched.__g8 = 1; window.pickWildMonsterId = patched;
    })();
  }

  var G9 = (window.G9 = window.G9 || {});
  G9.R = G8.R; G9.pick = G8.pick; G9.shuffle = G8.shuffle; G9.q = G8.q;

  // ---------- CURRICULUM に中3(grade9)を登録 ----------
  G9.addUnits = function (subjectKey, units) {
    try {
      var C = window.CURRICULUM;
      if (!C || !C[subjectKey] || !C[subjectKey].grades) return false;
      var g = C[subjectKey].grades;
      if (!g[9]) g[9] = { label: '中3', units: [] };
      var have = {};
      g[9].units.forEach(function (u) { have[u.id] = 1; });
      units.forEach(function (u) { if (!have[u.id]) g[9].units.push(u); });
      return true;
    } catch (e) { return false; }
  };
  // 表示情報と野生出現テーブルは g8 の共有ヘルパを使う
  G9.addDisplay = function (m) { return G8.addDisplay(m); };
  G9.addWild = function (m) { return G8.addWild(m); };

  // ---------- 野生バトル：学年ボタン「中3」を追加 ----------
  function g9BtnClass(sel) {
    return 'px-3 py-1 rounded-full text-sm font-bold border-2 transition ' +
      (sel ? 'bg-red-500 text-white border-red-500 shadow'
           : 'bg-white text-gray-600 border-gray-300 hover:border-red-400');
  }
  function addGrade9Button() {
    try {
      var wrap = document.getElementById('pveGradeSelectorWrap');
      if (!wrap) return;
      if (wrap.querySelector('button[data-grade="9"]')) return;
      var btn = document.createElement('button');
      btn.dataset.grade = '9';
      btn.textContent = '中3';
      btn.className = g9BtnClass(Number(window.pveSelectedGrade) === 9);
      btn.onclick = function () {
        window.pveSelectedGrade = 9;
        if (window.renderPvEDistrictSelect) window.renderPvEDistrictSelect();
      };
      wrap.appendChild(btn);
    } catch (e) {}
  }
  G9.addGrade9Button = addGrade9Button;

  // 学年ボタンが描き直されても中3ボタンを保つ（画面が開いているときだけ働く）
  setInterval(function () {
    try {
      var w = document.getElementById('pveGradeSelectorWrap');
      if (w && !w.querySelector('button[data-grade="9"]')) addGrade9Button();
    } catch (e) {}
  }, 1500);
})();
