/* ============================================================
   中2（grade 8）コア v173
   ・共通ヘルパ（乱数・シャッフル・4択組み立て）
   ・CURRICULUM への学年8登録 / UNIT_DISPLAY 追加
   ・野生バトルの学年ボタン「中2」追加・野生出現テーブル拡張
   ※ public/index.html は変更せず window 経由で拡張する方式
   ============================================================ */
(function () {
  if (window.__G8CORE__) return;
  window.__G8CORE__ = 1;

  var G8 = (window.G8 = window.G8 || {});

  // ---------- 共通ヘルパ ----------
  G8.R = function (a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; };
  G8.pick = function (arr) { return arr[G8.R(0, arr.length - 1)]; };
  G8.shuffle = function (a) {
    for (var i = a.length - 1; i > 0; i--) { var j = G8.R(0, i); var t = a[i]; a[i] = a[j]; a[j] = t; }
    return a;
  };

  // 数字を含む文字列から、もっともらしい誤答を作る（重複補完用）
  G8._numVariant = function (c, k) {
    var nums = [], re = /\d+/g, m;
    while ((m = re.exec(c)) !== null) nums.push({ i: m.index, t: m[0] });
    if (!nums.length) return null;
    var idx = (k - 1) % nums.length;
    var tgt = nums[idx];
    var delta = Math.ceil(k / nums.length);
    var base = Number(tgt.t);
    var cand = [base + delta, base - delta, base + delta + 1, base + delta + 2, base * 2 + 1];
    for (var ci = 0; ci < cand.length; ci++) {
      var nv = cand[ci];
      if (nv < 0 || nv === base) continue;
      var out = c.slice(0, tgt.i) + nv + c.slice(tgt.i + tgt.t.length);
      // 「1x」「0y」のような不自然な表示は避ける
      if (/(^|[^0-9.])[01][a-zA-Zｘ²³]/.test(out)) continue;
      return out;
    }
    return null;
  };

  // 4択問題を組み立てる（重複除去・不足時は数値ゆらぎ／記号付けで補完）
  G8.q = function (diff, q, correct, wrongs) {
    var c = String(correct), ws = [], i, w;
    wrongs = wrongs || [];
    for (i = 0; i < wrongs.length && ws.length < 3; i++) {
      w = String(wrongs[i]);
      if (w !== c && ws.indexOf(w) < 0) ws.push(w);
    }
    var n = parseFloat(c), k = 1;
    while (ws.length < 3 && k < 80) {
      if (!isNaN(n) && isFinite(n) && String(n) === c) {
        w = String(Math.round((n + k) * 100) / 100);
        if (w !== c && ws.indexOf(w) < 0) ws.push(w);
        if (ws.length < 3) {
          w = String(Math.round((n - k) * 100) / 100);
          if (w !== c && ws.indexOf(w) < 0) ws.push(w);
        }
      } else {
        w = G8._numVariant(c, k);
        if (w === null) w = c + Array(k + 1).join('？');
        if (w !== c && ws.indexOf(w) < 0) ws.push(w);
      }
      k++;
    }
    var options = G8.shuffle([c, ws[0], ws[1], ws[2]]);
    return { q: '【' + diff + '】' + q, ans: options.indexOf(c), options: options, inputType: 'mcq' };
  };

  // 符号つき表示・1次式表示（数学で共用）
  G8.s = function (v) { return v < 0 ? '-' + (-v) : String(v); };
  G8.p = function (v) { return v < 0 ? '(-' + (-v) + ')' : String(v); };
  G8.lin = function (k, b, x) {
    x = x || 'x';
    var s = (k === 1 ? x : (k === -1 ? '-' + x : k + x));
    if (b > 0) s += '+' + b; else if (b < 0) s += '-' + (-b);
    return s;
  };

  // ---------- CURRICULUM に中2を登録 ----------
  G8.addUnits = function (subjectKey, units) {
    try {
      var C = window.CURRICULUM;
      if (!C || !C[subjectKey] || !C[subjectKey].grades) return false;
      var g = C[subjectKey].grades;
      if (!g[8]) g[8] = { label: '中2', units: [] };
      var have = {};
      g[8].units.forEach(function (u) { have[u.id] = 1; });
      units.forEach(function (u) { if (!have[u.id]) g[8].units.push(u); });
      return true;
    } catch (e) { return false; }
  };

  // ---------- 野生エリアの表示情報 ----------
  G8.addDisplay = function (map) {
    try {
      window.UNIT_DISPLAY = window.UNIT_DISPLAY || {};
      for (var k in map) { if (!window.UNIT_DISPLAY[k]) window.UNIT_DISPLAY[k] = map[k]; }
    } catch (e) {}
  };

  // ---------- 野生出現テーブル（中2エリア） ----------
  G8._wild = {};
  G8.addWild = function (map) { for (var k in map) G8._wild[k] = map[k]; };

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
          if (arr && arr.length && !isFriend && Math.random() < 0.12) {
            return arr[Math.floor(Math.random() * arr.length)];
          }
        }
      } catch (e) {}
      return orig.apply(this, arguments);
    };
    patched.__g8 = 1;
    window.pickWildMonsterId = patched;
  })();

  // ---------- 野生バトル：学年ボタン「中2」を追加 ----------
  function g8GradeBtnClass(sel) {
    return 'px-3 py-1 rounded-full text-sm font-bold border-2 transition ' +
      (sel ? 'bg-red-500 text-white border-red-500 shadow'
           : 'bg-white text-gray-600 border-gray-300 hover:border-red-400');
  }

  function addGrade8Button() {
    try {
      // v181: 段階解禁。中2がまだ解禁されていなければ出さない（解禁管理はg10core）
      if (window.__gradeUnlocked && !window.__gradeUnlocked(8)) return;
      var wrap = document.getElementById('pveGradeSelectorWrap');
      if (!wrap) return;
      var sel8 = (Number(window.pveSelectedGrade) === 8);
      Array.prototype.forEach.call(wrap.querySelectorAll('button'), function (b) {
        var bg = Number(b.dataset.grade);
        if (bg === 8) return;
        b.className = g8GradeBtnClass(!sel8 && bg === Number(window.pveSelectedGrade));
      });
      if (wrap.querySelector('button[data-grade="8"]')) return;
      var btn = document.createElement('button');
      btn.dataset.grade = '8';
      btn.textContent = '中2';
      btn.className = g8GradeBtnClass(sel8);
      btn.onclick = function () {
        window.pveSelectedGrade = 8;
        if (window.renderPvEDistrictSelect) window.renderPvEDistrictSelect();
      };
      wrap.appendChild(btn);
    } catch (e) {}
  }
  G8.addGrade8Button = addGrade8Button;

  // renderPvEDistrictSelect は「ログイン後」に定義・再代入されるため、
  // ポーリングではなくアクセサで捕まえて、いつ差し替えられても中2ボタンを足す
  function wrapDistrict(fn) {
    if (typeof fn !== 'function' || fn.__g8) return fn;
    var w = function () {
      var r = fn.apply(this, arguments);
      try { addGrade8Button(); } catch (e) {}
      return r;
    };
    w.__g8 = 1;
    return w;
  }

  (function () {
    var _val = wrapDistrict(window.renderPvEDistrictSelect);
    try {
      Object.defineProperty(window, 'renderPvEDistrictSelect', {
        configurable: true,
        get: function () { return _val; },
        set: function (v) { _val = wrapDistrict(v); }
      });
    } catch (e) {
      // アクセサが使えない環境向けフォールバック（ゆっくり監視し続ける）
      setInterval(function () {
        try {
          var f = window.renderPvEDistrictSelect;
          if (typeof f === 'function' && !f.__g8) window.renderPvEDistrictSelect = wrapDistrict(f);
        } catch (e2) {}
      }, 1000);
    }
  })();

  // 学年ボタンが後から描き直された場合の保険（画面が開いているときだけ働く）
  setInterval(function () {
    try {
      var w = document.getElementById('pveGradeSelectorWrap');
      if (w && !w.querySelector('button[data-grade="8"]')) addGrade8Button();
    } catch (e) {}
  }, 1500);
})();
