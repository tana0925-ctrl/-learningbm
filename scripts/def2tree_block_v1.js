  /* ===== DEF2TREE_V1_MARK : 防衛戦の プログラムを ツリーにする =====================

     ねらい
       防衛戦の プログラム欄は じょうけん4しゅるい・うごき5しゅるいの ひょうだけで、
       くりかえし も ぶんき も なかった。小学校の プログラミングは
       じゅんじ・じょうけんぶんき・くりかえし を あつかうので、
       ジムチャレンジと おなじ ブロック形式を 防衛戦にも つなぐ。

     やりかた
       ジムチャレンジ側の コードは 1文字も 書きかえていない。
       index.html の 中の 絵をかく しくみ（_pbRenderNode / _pbAddPal / _pbCatalog）を
       かりるための さしこみ口を、src/index.tsx の replace チェーンで 3つ 足してある。
         window._pbPrepHook    … かきなおす とき、防衛戦の 画面なら こちらで かく
         window._pbCatalogHook … えらべる じょうけん／うごき を しぼる
         window._pbBlocksHook  … えらべる ブロックの しゅるいを しぼる
       どの さしこみ口も、だれも つけていなければ 何も しない。
       さしこみ口が 見つからないときは これまでの ひょう形式が そのまま 出る。

     はずした うごき（本番と おなじ forts:false・3レーン・接敵ありで 実機で 何回も まわして確認）
       attackFort   … とりでが 出ないので「相手の基地を攻める」と 出力が 完全に 同じ
       advanceFront … 同上
       retreatBack  … 「みかたの基地をまもる」と 出力が 完全に 同じ
       aimWeakest   … 「いちばん近い敵をこうげき」と 出力が 完全に 同じ
       defendFort   … まもる さきの とりでが そもそも 存在しない
       scatter      … 「ちらばる」のに ばしょが 1ミリも かわらない
     はずした じょうけん
       enemyNear    … いつでも あてはまる（fighter に lane が つかないため）
       onPoint      … ぜったいに あてはまらない（同じ りゆう）

     ふるい ひょう形式の プログラムは、そのままの うごきに なる かたちで
     ツリーに 直す（d2tFromFlat）。もし〜でなければ の 入れ子 1本にすると、
     毎ターン 上から 見なおす ひょう形式と まったく 同じ うごきになる。
     実機で 120とおり ためして 1つの ちがいも 出なかった。
  ============================================================================ */

  var D2T_KEY = '__def';
  var D2T_MAXLV = 3;

  var D2T_DROP_A = ['attackFort', 'advanceFront', 'retreatBack', 'aimWeakest', 'defendFort', 'scatter'];
  var D2T_DROP_C = ['enemyNear', 'onPoint'];

  var D2T_C1 = ['always', 'selfHpBelow', 'allyBaseBelow', 'allyDown'];
  var D2T_A1 = ['attackBase', 'returnBase', 'laneL', 'laneC', 'laneR', 'wait'];
  var D2T_C2 = D2T_C1.concat(['battleStart', 'lateGame', 'selfHpAbove', 'enemyBaseBelow', 'enemyCountAtLeast', 'strongEnemy', 'allyCountBelow', 'openPointNear', 'pointTaken', 'timeElapsed']);
  var D2T_A2 = D2T_A1.concat(['attackNearest', 'aimWeak', 'aimStrong', 'charge', 'goPoint', 'defendPoint', 'fleeLane', 'gather']);
  var D2T_B1 = ['a', 'if', 'fv'];
  var D2T_B2 = ['a', 'if', 'fv', 'rep', 'un'];
  var D2T_B3 = ['a', 'if', 'fv', 'rep', 'un', 'sq'];

  var D2T_LVNAME = { 1: 'レベル1 じゅんばん と ぶんき', 2: 'レベル2 くりかえし', 3: 'レベル3 ぜんぶ' };
  var D2T_LVNEXT = {
    1: 'つぎは「くりかえす」「〜になるまで」と、てき・なかま・きょてん の じょうけんが ふえるよ',
    2: 'つぎは「じゅんばんに」と、きもちを あらわす うごきが ふえるよ'
  };

  /* まだ 1つも つくっていない 子の さいしょの すがた（レベル1の ぶひんだけ） */
  var D2T_START = [{ t: 'if', c: 'allyBaseBelow', cn: 40, body: [{ t: 'a', a: 'returnBase' }], els: [{ t: 'a', a: 'attackBase' }] }];

  var D2T_TPL = [
    { name: '⚔ まっすぐ せめる', lv: 1, prog: [{ t: 'a', a: 'attackBase' }] },
    { name: '🛡 きちが あぶなくなったら もどる', lv: 1, prog: [{ t: 'if', c: 'allyBaseBelow', cn: 40, body: [{ t: 'a', a: 'returnBase' }], els: [{ t: 'a', a: 'attackBase' }] }] },
    { name: '💧 HPが へったら まもる', lv: 1, prog: [{ t: 'if', c: 'selfHpBelow', cn: 35, body: [{ t: 'a', a: 'returnBase' }], els: [{ t: 'a', a: 'attackBase' }] }] },
    { name: '🛣 まん中の みちを ゆく', lv: 1, prog: [{ t: 'a', a: 'laneC' }] },
    { name: '🔁 ひだり5かい → みぎ5かい', lv: 2, prog: [{ t: 'rep', n: 5, body: [{ t: 'a', a: 'laneL' }] }, { t: 'rep', n: 5, body: [{ t: 'a', a: 'laneR' }] }] },
    { name: '🚩 きょてんを とりに いく', lv: 2, prog: [{ t: 'if', c: 'openPointNear', body: [{ t: 'a', a: 'goPoint' }], els: [{ t: 'a', a: 'attackBase' }] }] }
  ];

  var _d2tOff = false;        /* まさかの ときに ひょう形式へ もどす しるし */
  var _d2tPainting = false;   /* 呼びあいを ふせぐ */
  var _d2tCharSet = false;
  var _d2tAdopted = false;
  var _d2tTplOpen = false;

  function d2tReady() {
    return !!(window.__pbHooksV1
      && typeof window._pbCur === 'function'
      && typeof window._pbRenderNode === 'function'
      && typeof window._pbAddPal === 'function'
      && typeof window._pbCatalog === 'function'
      && typeof window._pbInjectCss === 'function'
      && typeof window._pbEnsureIds === 'function'
      && typeof window._pbIsTree === 'function'
      && typeof window._pbPersist === 'function'
      && typeof window._pbSetEditChar === 'function'
      && typeof window._pbTreeAdd === 'function');
  }

  function d2tActive() { return !_d2tOff && d2tReady(); }

  function d2tLevel() {
    var p = null, n = 1;
    try { p = progPlayer(); } catch (e) { }
    try { if (p) n = Number(p.defProgLevel || 1); } catch (e) { }
    if (!(n >= 1)) n = 1;
    if (n > D2T_MAXLV) n = D2T_MAXLV;
    return n;
  }

  /* ふるい ひょう形式 → まったく 同じ うごきの ツリー。
     もし A なら x、でなければ（もし B なら y、でなければ z）… の 1本にする。
     ねっこが 1つだけ なので、毎ターン かならず いちばん上から 見なおす。 */
  function d2tFromFlat(flat) {
    var i, r, nd, list = [];
    for (i = 0; i < (flat || []).length; i++) {
      r = flat[i];
      if (r && !r.t && r.a) list.push(r);
    }
    if (!list.length) return null;
    var tail = [{ t: 'a', a: 'attackBase' }];
    for (i = list.length - 1; i >= 0; i--) {
      r = list[i];
      if (!r.c || r.c === 'always') { tail = [{ t: 'a', a: r.a }]; continue; }
      nd = { t: 'if', c: r.c, body: [{ t: 'a', a: r.a }], els: tail };
      if (r.cn !== null && r.cn !== undefined) nd.cn = Number(r.cn);
      tail = [nd];
    }
    return tail;
  }

  function d2tEnsureChar() {
    if (_d2tCharSet) return;
    _d2tCharSet = true;
    try { window._pbSetEditChar(D2T_KEY); } catch (e) { _d2tCharSet = false; }
  }

  function d2tReplace(cur, next) {
    var i;
    cur.length = 0;
    for (i = 0; i < (next || []).length; i++) cur.push(next[i]);
    try { window._pbEnsureIds(cur); } catch (e) { }
  }

  /* いま つかっている ツリー本体（_pbProgs['__def'] そのもの）を かえす。 */
  function d2tProg() {
    var cur, p, sv, t;
    try { d2tEnsureChar(); cur = window._pbCur() || []; } catch (e) { return []; }
    /* player は loadData で まるごと 入れかわる。だから ほぞんぶんが 見つかるまで
       なんども さがす。子が さわったら（_progTouched）もう 上書きしない。 */
    if (!_d2tAdopted && !_progTouched) {
      try {
        p = progPlayer();
        sv = p && p.defProgram;
        if (Array.isArray(sv) && sv.length) {
          _d2tAdopted = true;
          t = window._pbIsTree(sv) ? JSON.parse(JSON.stringify(sv)) : d2tFromFlat(sv);
          if (t && t.length) d2tReplace(cur, t);
        } else if (!window._pbIsTree(cur)) {
          d2tReplace(cur, JSON.parse(JSON.stringify(D2T_START)));
        }
      } catch (e) { }
    }
    if (!window._pbIsTree(cur)) {
      t = d2tFromFlat(cur) || [{ t: 'a', a: 'attackBase' }];
      d2tReplace(cur, t);
    }
    try { window._pbEnsureIds(cur); } catch (e) { }
    return cur;
  }

  /* いま おいてある ブロックで つかわれている きーは、レベルが 下でも けさない。
     きゅうに ブロックが きえたら 子どもが こまるから。 */
  function d2tUsed(prog) {
    var used = { c: {}, a: {} };
    (function rec(arr) {
      var i, n;
      for (i = 0; i < (arr || []).length; i++) {
        n = arr[i];
        if (!n || typeof n !== 'object') continue;
        if (n.a) used.a[n.a] = 1;
        if (n.c) used.c[n.c] = 1;
        if (n.body) rec(n.body);
        if (n.els) rec(n.els);
      }
    })(prog);
    return used;
  }

  function d2tKeep(list, allow, drop, used) {
    var i, o, out = [];
    for (i = 0; i < (list || []).length; i++) {
      o = list[i];
      if (!o || !o.k) continue;
      if (used[o.k]) { out.push(o); continue; }
      if (drop.indexOf(o.k) >= 0) continue;
      if (allow && allow.indexOf(o.k) < 0) continue;
      out.push(o);
    }
    return out;
  }

  function d2tCatalogHook(full) {
    try {
      if (!full || !full.conds || !full.acts) return null;
      var lv = d2tLevel();
      var okC = (lv >= 3) ? null : (lv === 2 ? D2T_C2 : D2T_C1);
      var okA = (lv >= 3) ? null : (lv === 2 ? D2T_A2 : D2T_A1);
      var used = d2tUsed(window._pbCur ? (window._pbCur() || []) : []);
      var conds = d2tKeep(full.conds, okC, D2T_DROP_C, used.c);
      var acts = d2tKeep(full.acts, okA, D2T_DROP_A, used.a);
      if (!conds.length || !acts.length) return null;
      return { conds: conds, acts: acts };
    } catch (e) { return null; }
  }

  function d2tBlocksHook(kind) {
    try {
      var lv = d2tLevel();
      var list = (lv >= 3) ? D2T_B3 : (lv === 2 ? D2T_B2 : D2T_B1);
      return list.indexOf(kind) >= 0;
    } catch (e) { return true; }
  }

  function d2tHead(lv) {
    return '<div style="font-weight:800;font-size:12px;color:#334155;display:flex;align-items:center;gap:6px;flex-wrap:wrap;">'
      + '<span>🧩 ③ うごきかたを プログラムする</span>'
      + '<span style="font-size:10px;font-weight:900;color:#4f46e5;background:#eef2ff;border-radius:999px;padding:2px 8px;">' + esc(D2T_LVNAME[lv] || '') + '</span>'
      + '</div>'
      + '<div style="font-size:11px;color:#64748b;margin:2px 0 6px;">ブロックを 上から じゅんに 実行するよ。いちばん下まで いったら また 上に もどるよ。</div>';
  }

  function d2tTplBar(lv) {
    var i, out;
    out = '<button onclick="_def2TreeTplToggle()" style="width:100%;margin:2px 0 6px;background:#10b981;color:#fff;border:0;border-radius:10px;padding:8px;font-weight:900;cursor:pointer;box-shadow:0 3px 0 #047857;font-size:12px;">📋 お手本からえらぶ</button>';
    if (!_d2tTplOpen) return out;
    for (i = 0; i < D2T_TPL.length; i++) {
      if ((D2T_TPL[i].lv || 1) > lv) continue;
      out += '<div style="display:flex;align-items:center;gap:6px;justify-content:space-between;background:#fff;border:1px solid #e2e8f0;border-radius:8px;padding:6px 8px;margin-bottom:5px;flex-wrap:wrap;">'
        + '<span style="font-weight:900;font-size:12px;">' + esc(D2T_TPL[i].name) + '</span>'
        + '<button onclick="_def2TreeTpl(' + i + ')" style="background:#6366f1;color:#fff;border:0;border-radius:7px;padding:5px 9px;font-size:11px;font-weight:900;cursor:pointer;">これにする</button>'
        + '</div>';
    }
    return out;
  }

  function d2tFoot(lv) {
    var out = '';
    if (lv < D2T_MAXLV) {
      out += '<button onclick="_def2TreeLevelUp()" style="width:100%;margin-top:8px;border:0;background:#4f46e5;color:#fff;border-radius:10px;padding:8px;font-weight:900;cursor:pointer;box-shadow:0 3px 0 #3730a3;font-size:12px;">🔓 もっと つかう</button>'
        + '<div style="font-size:10px;color:#94a3b8;margin-top:3px;text-align:center;line-height:1.5;">' + esc(D2T_LVNEXT[lv] || '') + '</div>';
    }
    out += '<button onclick="_def2TreeReset()" style="width:100%;margin-top:6px;border:1px solid #fecaca;background:#fff;color:#dc2626;border-radius:10px;padding:6px;font-weight:900;cursor:pointer;font-size:12px;">🗑 さいしょから 作りなおす</button>'
      + '<div style="font-size:10px;color:#94a3b8;margin-top:4px;text-align:center;">じどうで ほぞんされるよ</div>';
    return out;
  }

  /* ここが 絵をかく ところ。うまく かけなければ false を かえして、
     これまでの ひょう形式に もどす。子どもの 画面が 空になるより ずっと よい。 */
  function d2tPaint(box) {
    var i, lv, prog, tree, html;
    if (_d2tPainting) return true;
    _d2tPainting = true;
    try {
      prog = d2tProg();
      if (!prog || !prog.length) { d2tReplace(prog, [{ t: 'a', a: 'attackBase' }]); }
      lv = d2tLevel();
      window._pbInjectCss();
      window._pbCatalogHook = d2tCatalogHook;
      window._pbBlocksHook = d2tBlocksHook;
      try {
        tree = '';
        for (i = 0; i < prog.length; i++) tree += window._pbRenderNode(prog[i], 0);
        html = d2tHead(lv)
          + d2tTplBar(lv)
          + '<div style="background:#f8fafc;border-radius:12px;padding:8px;">'
          + tree
          + window._pbAddPal(null, 'body', 'ここに：')
          + '</div>'
          + d2tFoot(lv);
      } finally {
        window._pbCatalogHook = null;
        window._pbBlocksHook = null;
      }
      if (!html) return false;
      box.innerHTML = html;
      /* ほぞんぶんを まだ さがしている あいだは 書かない（子の ほぞんを 消さないため） */
      if (_d2tAdopted || _progTouched) progSaveSoon();
      return true;
    } catch (e) {
      try { console.error('def2 tree paint', e); } catch (e2) { }
      return false;
    } finally {
      _d2tPainting = false;
    }
  }

  /* index.html の _gcRenderPrep から よばれる さしこみ口。
     true を かえした ときだけ、ジムの かきなおしを とめて こちらで かく。
     ジムの 画面が 見えている ときは かならず false（ジムを 止めない）。 */
  function d2tPrepHook() {
    var box, gym;
    try {
      if (_d2tOff || !d2tReady()) return false;
      box = document.getElementById('def2ProgBox');
      if (!box || box.offsetParent === null) return false;
      gym = document.getElementById('gymChallengeBody');
      if (gym && gym.offsetParent !== null) return false;
      if (d2tPaint(box)) return true;
      _d2tOff = true;
      try { renderEditor(); } catch (e) { }
      return true;
    } catch (e) { return false; }
  }

  function d2tRepaint() {
    var box = document.getElementById('def2ProgBox');
    if (box) d2tPaint(box);
  }

  function d2tInstallHook() {
    var box;
    try { if (window._pbPrepHook !== d2tPrepHook) window._pbPrepHook = d2tPrepHook; } catch (e) { }
    /* player は あとから 入れかわるので、ほぞんぶんが 見つかるまで かきなおしつづける */
    try {
      if (!_d2tOff && !_d2tAdopted && !_progTouched && d2tReady()) {
        box = document.getElementById('def2ProgBox');
        if (box && box.offsetParent !== null) d2tPaint(box);
      }
    } catch (e) { }
  }

  window._def2TreeLevelUp = function () {
    var p, lv = d2tLevel();
    if (lv >= D2T_MAXLV) return;
    try { p = progPlayer(); if (p) p.defProgLevel = lv + 1; } catch (e) { }
    _d2tTplOpen = false;
    try { if (typeof window.saveData === 'function') window.saveData(); } catch (e) { }
    d2tRepaint();
  };

  window._def2TreeTplToggle = function () {
    _d2tTplOpen = !_d2tTplOpen;
    d2tRepaint();
  };

  window._def2TreeTpl = function (i) {
    var tp = D2T_TPL[i];
    if (!tp) return;
    d2tReplace(d2tProg(), JSON.parse(JSON.stringify(tp.prog)));
    _d2tTplOpen = false;
    try { window._pbPersist(); } catch (e) { }
    progSaveSoon();
    d2tRepaint();
  };

  window._def2TreeReset = function () {
    try { if (!window.confirm('プログラムを さいしょから 作りなおす？')) return; } catch (e) { }
    d2tReplace(d2tProg(), [{ t: 'a', a: 'attackBase' }]);
    _d2tTplOpen = false;
    try { window._pbPersist(); } catch (e) { }
    progSaveSoon();
    d2tRepaint();
  };

  /* ためしバトルの「何かい うごいた」ひょう用に、ツリーを
     うごきの ブロックだけの ならびに ひらく。_id は そのまま つかう。 */
  function d2tCondJa(n) {
    var i, cat = null, o, l = String(n.c || '');
    try { cat = window._pbCatalog(); } catch (e) { }
    if (cat && cat.conds) {
      for (i = 0; i < cat.conds.length; i++) {
        o = cat.conds[i];
        if (o.k === n.c) {
          l = o.l + (o.n ? (' ' + (n.cn !== null && n.cn !== undefined ? n.cn : o.nd) + (o.suf || '')) : '');
          break;
        }
      }
    }
    return l;
  }

  function d2tBlockJa(n) {
    if (n.t === 'rep') return 'くりかえす' + (n.n || 3) + '回';
    if (n.t === 'fv') return 'ずっと';
    if (n.t === 'sq') return 'じゅんばんに';
    if (n.t === 'un') return d2tCondJa(n) + ' になるまで';
    if (n.t === 'if') return 'もし ' + d2tCondJa(n) + ' なら';
    return '';
  }

  function d2tTallyRules(prog) {
    var i, r, out = [];
    if (window._pbIsTree && window._pbIsTree(prog)) {
      (function rec(arr, path) {
        var j, n, lb;
        for (j = 0; j < (arr || []).length; j++) {
          n = arr[j];
          if (!n || typeof n !== 'object') continue;
          if (n.t === 'a' || (!n.t && n.a)) {
            out.push({ _id: n._id, line: (path ? path + ' → ' : '') + tbActLabel(n.a) });
            continue;
          }
          lb = d2tBlockJa(n);
          if (n.body) rec(n.body, path ? (path + ' / ' + lb) : lb);
          if (n.els) rec(n.els, (path ? (path + ' / ') : '') + lb + ' でなければ');
        }
      })(prog, '');
      return out;
    }
    for (i = 0; i < (prog || []).length; i++) {
      r = prog[i] || {};
      out.push({ _id: r._id, c: r.c, a: r.a, cn: r.cn, line: tbRuleLine(r) });
    }
    return out;
  }

  /* ===== DEF2TREE_V1_MARK ここまで ===== */
