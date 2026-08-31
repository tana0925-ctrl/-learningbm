/* ===================================================================
   mi.js : 「MIしらべ」児童用（/mi ページ専用）
   - index.html には一切さわらない。/mi の小さなシェルHTMLから読み込む。
   - 本体(index.html)の変数には依存しない。完全に自己完結。
   - 方針：タイプのラベルを貼らない。「いまの自分がどう感じているか」の記録。
   =================================================================== */
(function (global) {
  'use strict';

  var Q = [
    '本を読むのが好きです（マンガ以外）。',
    '算数の問題を解くのが好きです。',
    'おもちゃや虫など、特定の物をたくさん集めるのが好きです。',
    '日記を書きます。',
    '図や絵を描いて説明してもらうとわかりやすいです。',
    '身体を動かすのが好きです。',
    '楽器を演奏するのが好きです。',
    '友だちといっしょに勉強するのが好きです。',
    '作文や物語を書くのが得意です。',
    'ものごとの仕組みが気になります。',
    '家や学校で、動物や植物の世話をしています。',
    '自分の得意なことと、苦手なことがはっきりわかっています。',
    '絵を描くのが好きです。',
    '友だちに話すとき、ジェスチャーをたくさん使います。',
    '歌を歌うのが好きです。',
    'グループのリーダーを任されます。',
    '人や物の名前、場所や日付を覚えることができます。',
    'なぞなぞやパズルなど、頭を使う遊びが好きです。',
    '新しいことや物を、じっくりと調べるのが好きです。',
    '自分の気持ちを、きちんと人に伝えることができます。',
    '物の長さや重さなどが、見ただけでほぼ正確にわかります。',
    '人の動きをまねすることが得意です。',
    '歌のメロディーをすぐに覚えられます。',
    'だれとでもすぐ友だちになれます。',
    '人の話を聞いたり、人前で話をしたりすることが好きです。',
    '計画を立てて、毎日少しずつ勉強しています。',
    'ふしぎに思ったことを、よく図鑑や本で調べます。',
    'その日にあった出来事を、よく夜にふりかえります。',
    'レゴのようなブロックや積木で遊ぶのが好きです。',
    '図工の作品は、できるだけ丁寧に作りたいです。',
    '他の人の声を聞いて、どんな気持ちなのかがわかります。',
    '他の人の表情を見て、どんな気持ちなのかがわかります。'
  ];

  // 領域の並びは配布エクセルの左からの順。同点のときはこの順で上位になる。
  var DOMAINS = [
    { key: 'lang',   name: '言語・語学',   qs: [1, 9, 17, 25],  side: 'L', emoji: '📖', color: '#f97316' },
    { key: 'logic',  name: '論理・数学',   qs: [2, 10, 18, 26], side: 'L', emoji: '🔢', color: '#3b82f6' },
    { key: 'nature', name: '自然・博物学', qs: [3, 11, 19, 27], side: 'L', emoji: '🌱', color: '#22c55e' },
    { key: 'intra',  name: '内省',         qs: [4, 12, 20, 28], side: 'L', emoji: '🪞', color: '#8b5cf6' },
    { key: 'visual', name: '視覚・空間',   qs: [5, 13, 21, 29], side: 'R', emoji: '🎨', color: '#ec4899' },
    { key: 'body',   name: '身体・運動',   qs: [6, 14, 22, 30], side: 'R', emoji: '🏃', color: '#ef4444' },
    { key: 'music',  name: '音楽・リズム', qs: [7, 15, 23, 31], side: 'R', emoji: '🎵', color: '#14b8a6' },
    { key: 'inter',  name: '対人',         qs: [8, 16, 24, 32], side: 'R', emoji: '🤝', color: '#eab308' }
  ];

  var CHOICES = [
    { v: 1, label: 'まったくあてはまらない' },
    { v: 2, label: '少し当てはまる' },
    { v: 3, label: 'だいたい当てはまる' },
    { v: 4, label: 'とても当てはまる' }
  ];

  // 「いま好き・得意だと感じていること」の言い方。断定（〜タイプ／〜型）は使わない。
  var FEELS = {
    lang:   '読んだり書いたり、ことばを使うこと',
    logic:  '数や、しくみを考えること',
    nature: '生きものや自然を見つけたり、しらべること',
    intra:  '自分の気持ちをふりかえること',
    visual: '絵や形、ものの様子を思いうかべること',
    body:   'からだを動かしたり、手を使って作ること',
    music:  '音やリズム、歌にふれること',
    inter:  '友だちや人とかかわること'
  };

  var MAX = 16;

  // ------------------------------------------------------------------
  // 採点（サーバー側と同じ計算。表示用）
  // ------------------------------------------------------------------
  function score(answers) {
    var scores = {}, left = 0, right = 0, i, j, s, v;
    for (i = 0; i < DOMAINS.length; i++) {
      s = 0;
      for (j = 0; j < DOMAINS[i].qs.length; j++) {
        v = Number(answers[DOMAINS[i].qs[j] - 1]);
        s += (v >= 1 && v <= 4) ? Math.floor(v) : 0;
      }
      scores[DOMAINS[i].key] = s;
      if (DOMAINS[i].side === 'L') left += s; else right += s;
    }
    var rank = DOMAINS.map(function (d, idx) {
      return { key: d.key, name: d.name, score: scores[d.key], idx: idx };
    }).sort(function (a, b) { return (b.score - a.score) || (a.idx - b.idx); });
    return { scores: scores, left: left, right: right, ranking: rank };
  }
  global.__miScore = score; // 検証用

  // ------------------------------------------------------------------
  // 状態
  // ------------------------------------------------------------------
  var PER_PAGE = 4;
  var PAGES = Math.ceil(Q.length / PER_PAGE);
  var answers = new Array(32).fill(null);
  var page = 0;
  var history = [];
  var rewardInfo = null;   // サーバーが返す今月の特典の状態。クライアントでは一切いじらない。
  var lastReward = null;   // 直近の提出で実際に付与されたかどうか
  var tipsCat = null;      // 学び方の工夫カタログ（サーバーから取得。単一の出どころ）
  var saveTimer = null;
  var app = null;

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function jget(u) {
    return fetch(u, { credentials: 'same-origin' }).then(function (r) {
      return r.json().then(function (j) { j = j || {}; j.__status = r.status; return j; })
        .catch(function () { return { ok: false, __status: r.status }; });
    }).catch(function () { return { ok: false, __status: 0 }; });
  }
  function jsend(u, method, body) {
    return fetch(u, {
      method: method, credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body || {})
    }).then(function (r) {
      return r.json().then(function (j) { j = j || {}; j.__status = r.status; return j; })
        .catch(function () { return { ok: false, __status: r.status }; });
    }).catch(function () { return { ok: false, __status: 0 }; });
  }
  function answeredCount() {
    var n = 0;
    for (var i = 0; i < 32; i++) if (answers[i]) n++;
    return n;
  }
  function saveDraft() {
    if (saveTimer) clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      jsend('/api/mi/draft', 'PUT', { answers: answers }).then(function () {
        var el = document.getElementById('miSaved');
        if (el) {
          el.textContent = '✅ とちゅうまで ほぞんしました';
          setTimeout(function () { if (el) el.textContent = ''; }, 2000);
        }
      });
    }, 600);
  }

  // ------------------------------------------------------------------
  // 画面
  // ------------------------------------------------------------------
  function fmtDate(iso) {
    try {
      var d = new Date(String(iso).replace(' ', 'T') + (String(iso).indexOf('Z') < 0 && String(iso).indexOf('+') < 0 ? 'Z' : ''));
      if (isNaN(d.getTime())) return String(iso).slice(0, 16);
      var jp = new Date(d.getTime() + 9 * 3600 * 1000);
      return jp.getUTCFullYear() + '年' + (jp.getUTCMonth() + 1) + '月' + jp.getUTCDate() + '日';
    } catch (e) { return String(iso).slice(0, 16); }
  }

  function renderIntro() {
    var resume = answeredCount() > 0 && answeredCount() < 32;
    var h = '';
    h += '<div class="bg-white rounded-2xl shadow p-5">';
    h += '<h1 class="text-2xl font-black text-indigo-700 mb-1">🧭 MIしらべ</h1>';
    // ---- 導入：MIって何？ 自分にとって何がいいの？ ----
    h += '<p class="text-sm text-slate-700 leading-relaxed mb-3">人の「とくい」や「好き」は、ひとつだけでは ありません。<br>ことばが 好きな人、数や しくみを 考えるのが 好きな人、体を 動かすのが 好きな人、音や リズムが 好きな人、生きものを しらべるのが 好きな人、絵や 形を 思いうかべるのが 好きな人、友だちと かかわるのが 好きな人、自分の 気もちを ふりかえるのが 好きな人。<b>どの人にも、いろんな面が あります。</b><br>この「MIしらべ」は、その <b>いろんな面</b> を 8つの まとまりで 見てみる ものです。</p>';
    h += '<div class="bg-indigo-50 border border-indigo-200 rounded-xl p-3 text-xs text-indigo-900 leading-relaxed mb-3">';
    h += '<b>やると どんな いいこと？</b><br>';
    h += '・<b>いまの じぶん</b>が「好き・とくい」と 感じている ことが 見えるよ。<br>';
    h += '・気もちは 時間が たつと かわります。あとで もう一度 やって、<b>むかしの じぶんと 見くらべ</b>られるよ。';
    h += '</div>';
    h += '<div class="bg-amber-50 border border-amber-200 rounded-xl p-3 text-xs text-amber-900 leading-relaxed mb-3">';
    h += '<b>やる前に 知っておいてね</b><br>';
    h += '・これは <b>せいかく しんだん でも、タイプ分け でも ありません。</b>これで「きみは こういう人だ」と 決まる ものでは ありません。<br>';
    h += '・正かいは ありません。数が 多い・少ないに、よい・わるいも ありません。<br>';
    h += '・思った とおりに <b>正直に 答えるのが いちばん いい</b>です。';
    h += '</div>';
    // 🎁 今月の特典（サーバーが判定した状態をそのまま出す）
    if (rewardInfo) {
      if (rewardInfo.takenThisMonth) {
        h += '<div class="bg-slate-50 border border-slate-200 rounded-xl p-3 text-xs text-slate-500 mb-3">🎁 今月の ごほうびは 受け取りずみです。（ごほうびは 月に1回まで。しらべ自体は 何回でも できます）</div>';
      } else {
        h += '<div class="bg-emerald-50 border border-emerald-200 rounded-xl p-3 text-xs text-emerald-800 mb-3">🎁 さいごまで 答えると <b>' + (rewardInfo.coins || 0) + 'コイン</b> もらえます。（月に1回まで）</div>';
      }
    }
    if (resume) {
      h += '<div class="bg-emerald-50 border border-emerald-200 rounded-xl p-3 text-sm text-emerald-800 mb-3">とちゅうまで（' + answeredCount() + '／32問）ほぞんされています。つづきから できます。</div>';
    }
    h += '<button id="miStart" class="w-full bg-indigo-600 text-white rounded-xl py-3 font-black text-lg shadow active:scale-95 transition">' + (resume ? 'つづきから やる' : 'はじめる') + '</button>';
    if (resume) {
      h += '<button id="miReset" class="w-full mt-2 bg-slate-100 text-slate-600 rounded-xl py-2 font-bold text-sm">さいしょから やりなおす</button>';
    }
    h += '</div>';

    if (history.length) {
      h += '<div class="bg-white rounded-2xl shadow p-5 mt-4">';
      h += '<h2 class="font-black text-slate-700 mb-2">📚 これまでの きろく</h2>';
      h += '<p class="text-xs text-slate-500 mb-2">おなじ しつもんでも、時期に よって 答えは かわります。見くらべてみよう。</p>';
      for (var i = 0; i < history.length; i++) {
        h += '<button class="mi-hist w-full text-left border border-slate-200 rounded-xl p-3 mb-2 hover:bg-slate-50" data-i="' + i + '">';
        h += '<div class="font-bold text-sm text-indigo-700">' + esc(fmtDate(history[i].takenAt)) + ' の きろく</div>';
        h += '<div class="text-xs text-slate-500 mt-0.5">左のまとまり ' + history[i].left + ' ／ 右のまとまり ' + history[i].right + '</div>';
        var hp = history[i].picks || [];
        if (hp.length && tipsCat) {
          var names = [];
          for (var q = 0; q < hp.length; q++) { var tx = tipKidText(hp[q]); if (tx) names.push(tx); }
          if (names.length) h += '<div class="text-[11px] text-emerald-700 mt-1 leading-relaxed">📚 このとき「やってみたい」と えらんだこと：' + esc(names.join(' ／ ')) + '</div>';
        }
        h += '</button>';
      }
      h += '</div>';
    }
    app.innerHTML = h;
    var sb = document.getElementById('miStart');
    if (sb) sb.onclick = function () {
      page = 0;
      for (var i = 0; i < PAGES; i++) {
        var start = i * PER_PAGE, done = true;
        for (var j = start; j < Math.min(start + PER_PAGE, 32); j++) if (!answers[j]) done = false;
        if (!done) { page = i; break; }
      }
      renderQuestions();
    };
    var rb = document.getElementById('miReset');
    if (rb) rb.onclick = function () {
      if (!confirm('とちゅうの こたえを けして、さいしょから やり直しますか？')) return;
      answers = new Array(32).fill(null);
      saveDraft(); page = 0; renderQuestions();
    };
    var hs = document.querySelectorAll('.mi-hist');
    for (var k = 0; k < hs.length; k++) {
      hs[k].onclick = function () { showResult(history[Number(this.getAttribute('data-i'))], true); };
    }
  }

  // 選択肢のHTML。renderQuestions と、回答時の部分更新の両方から使う（表示のブレ防止）。
  function optsHtml(i) {
    var s = '';
    for (var c = 0; c < CHOICES.length; c++) {
      var on = answers[i] === CHOICES[c].v;
      s += '<button class="mi-a text-left rounded-xl border-2 px-3 py-3 font-bold text-sm transition active:scale-95 ' +
        (on ? 'border-indigo-500 bg-indigo-50 text-indigo-800' : 'border-slate-200 bg-white text-slate-600') +
        '" data-q="' + i + '" data-v="' + CHOICES[c].v + '">' +
        '<span class="inline-block w-6 h-6 leading-6 text-center rounded-full mr-2 ' +
        (on ? 'bg-indigo-600 text-white' : 'bg-slate-100 text-slate-500') + '">' + CHOICES[c].v + '</span>' +
        esc(CHOICES[c].label) + '</button>';
    }
    return s;
  }

  // 進み具合（「n / 32 問」とバー）だけを書き換える。
  function paintProgress() {
    var n = answeredCount();
    var cnt = document.getElementById('miProgCount');
    if (cnt) cnt.textContent = n + ' / 32 問';
    var bar = document.getElementById('miProgBar');
    if (bar) bar.style.width = Math.round(n / 32 * 100) + '%';
  }

  // 1問ぶんの選択肢にタップ処理をつける。
  // ★ 回答しても画面全体は作り直さない。触った問題の選択肢と進み具合だけを描き直す。
  //    以前はここで renderQuestions() を呼んでいたため、app.innerHTML の入れ替えと
  //    window.scrollTo(0,0) が走り、1問答えるたびに画面の先頭に戻ってしまっていた。
  function bindOpts(i) {
    var box = document.getElementById('mi-opts-' + i);
    if (!box) return;
    var bs = box.querySelectorAll('.mi-a');
    for (var b = 0; b < bs.length; b++) {
      bs[b].onclick = function () {
        var qi = Number(this.getAttribute('data-q'));
        answers[qi] = Number(this.getAttribute('data-v'));
        saveDraft();
        var bx = document.getElementById('mi-opts-' + qi);
        if (bx) { bx.innerHTML = optsHtml(qi); bindOpts(qi); }
        paintProgress();
      };
    }
  }

  function renderQuestions() {
    var start = page * PER_PAGE;
    var end = Math.min(start + PER_PAGE, 32);
    var pct = Math.round(answeredCount() / 32 * 100);
    var h = '';
    h += '<div class="sticky top-0 bg-slate-100 pt-1 pb-2 z-10">';
    h += '<div class="flex items-center justify-between text-xs font-bold text-slate-500 mb-1"><span>' + (page + 1) + ' / ' + PAGES + ' ページ</span><span id="miProgCount">' + answeredCount() + ' / 32 問</span></div>';
    h += '<div class="h-2.5 rounded-full bg-white overflow-hidden shadow-inner"><div id="miProgBar" style="width:' + pct + '%;height:100%;background:#6366f1;transition:width .2s"></div></div>';
    h += '<div id="miSaved" class="text-[11px] text-emerald-600 font-bold h-4 mt-0.5"></div>';
    h += '</div>';

    for (var i = start; i < end; i++) {
      h += '<div class="bg-white rounded-2xl shadow p-4 mb-3">';
      h += '<div class="flex items-start gap-2 mb-3"><span class="shrink-0 bg-indigo-100 text-indigo-700 rounded-lg px-2 py-0.5 text-xs font-black">' + (i + 1) + '</span>';
      h += '<span class="text-base font-bold text-slate-800 leading-snug">' + esc(Q[i]) + '</span></div>';
      h += '<div class="grid grid-cols-1 gap-2" id="mi-opts-' + i + '">' + optsHtml(i) + '</div>';
      h += '</div>';
    }

    h += '<div class="flex gap-2 mt-2 mb-8">';
    h += '<button id="miPrev" class="flex-1 bg-white border-2 border-slate-200 text-slate-600 rounded-xl py-3 font-bold"' + (page === 0 ? ' disabled style="opacity:.4"' : '') + '>← もどる</button>';
    if (page < PAGES - 1) {
      h += '<button id="miNext" class="flex-[2] bg-indigo-600 text-white rounded-xl py-3 font-black shadow">つぎへ →</button>';
    } else {
      h += '<button id="miSubmit" class="flex-[2] bg-emerald-600 text-white rounded-xl py-3 font-black shadow">けっかを 見る 🎉</button>';
    }
    h += '</div>';
    h += '<div class="text-center mb-10"><button id="miQuit" class="text-xs text-slate-400 underline">とちゅうで やめる（ほぞんされます）</button></div>';

    app.innerHTML = h;
    // 先頭に戻すのは「ページを送った/戻した」ときだけ。回答したときはここを通らない。
    window.scrollTo(0, 0);

    for (var qi = start; qi < end; qi++) bindOpts(qi);
    var pv = document.getElementById('miPrev');
    if (pv) pv.onclick = function () { if (page > 0) { page--; renderQuestions(); } };
    var nx = document.getElementById('miNext');
    if (nx) nx.onclick = function () { page++; renderQuestions(); };
    var qt = document.getElementById('miQuit');
    if (qt) qt.onclick = function () { renderIntro(); window.scrollTo(0, 0); };
    var sb = document.getElementById('miSubmit');
    if (sb) sb.onclick = function () {
      var miss = [];
      for (var i = 0; i < 32; i++) if (!answers[i]) miss.push(i + 1);
      if (miss.length) {
        alert('まだ 答えていない しつもんが あります：' + miss.slice(0, 8).join('、') + (miss.length > 8 ? ' ほか' : '') + '番');
        page = Math.floor((miss[0] - 1) / PER_PAGE);
        renderQuestions();
        return;
      }
      sb.disabled = true; sb.textContent = 'ほぞん中…';
      jsend('/api/mi/submit', 'POST', { answers: answers }).then(function (res) {
        if (res && res.ok && res.result) {
          history.unshift(res.result);
          lastReward = res.reward || null;
          if (lastReward && (lastReward.granted || lastReward.alreadyTakenThisMonth)) {
            rewardInfo = { monthKey: lastReward.monthKey, coins: lastReward.coins, takenThisMonth: true, canClaim: false };
          }
          answers = new Array(32).fill(null);
          showResult(res.result, false);
        } else {
          sb.disabled = false; sb.textContent = 'けっかを 見る 🎉';
          alert('ほぞんできませんでした。もう一度 ためしてね。' + (res && res.__status === 401 ? '（ログインが 切れているかも）' : ''));
        }
      });
    };
  }

  // ------------------------------------------------------------------
  // レーダーチャート（8軸・各16点満点）。外部ライブラリは使わず SVG を自前で描く。
  //  - 目盛りは 4/8/12/16 の同心8角形
  //  - 各頂点に領域名と「12/16」を出す（棒グラフで数値が見えていた良さを残す）
  //  - 塗りは1色。前回の記録があれば、薄い破線で重ねる
  //  - 幅が狭いときは読めなくなるので、呼び出し側で棒グラフにフォールバックする
  // ------------------------------------------------------------------
  // 幅に応じて2通りのレイアウトを使い分ける（タブレット縦でも文字が潰れないように）
  //   wide  : 幅に余裕あり → 領域名をフルで出す
  //   narrow: 少し狭い     → 領域名を短くして文字を相対的に大きくする（下に対応表を出す）
  //   さらに狭いときは呼び出し側が棒グラフに切り替える
  var RD_WIDE = { W: 380, H: 350, CX: 190, CY: 165, R: 98, LR: 116, FS: 10.5, short: false };
  var RD_NARROW = { W: 320, H: 300, CX: 160, CY: 145, R: 88, LR: 104, FS: 11.5, short: true };

  function rdPt(cfg, i, ratio) {
    var a = (-90 + i * 45) * Math.PI / 180;
    return [cfg.CX + Math.cos(a) * cfg.R * ratio, cfg.CY + Math.sin(a) * cfg.R * ratio];
  }
  function rdPoly(cfg, ratios) {
    var pts = [];
    for (var i = 0; i < 8; i++) { var p = rdPt(cfg, i, ratios[i]); pts.push(p[0].toFixed(1) + ',' + p[1].toFixed(1)); }
    return pts.join(' ');
  }
  function rdAnchor(i) {
    if (i === 0 || i === 4) return 'middle';        // 真上・真下
    return (i >= 1 && i <= 3) ? 'start' : 'end';    // 右側 / 左側
  }
  function shortName(n) { var i = n.indexOf('・'); return i > 0 ? n.slice(0, i) : n; }
  function ratios(sc) {
    var r = [];
    for (var i = 0; i < 8; i++) r.push(Math.max(0, Math.min(1, Number(sc[DOMAINS[i].key] || 0) / MAX)));
    return r;
  }

  function radarSvg(sc, prevSc, cfg) {
    cfg = cfg || RD_WIDE;
    var i, p, g, h = '';
    h += '<svg viewBox="0 0 ' + cfg.W + ' ' + cfg.H + '" style="width:100%;height:auto;display:block" role="img" aria-label="8つのまとまりのレーダーチャート">';
    // 目盛り（4・8・12・16 の同心8角形）
    for (g = 1; g <= 4; g++) {
      var rr = []; for (i = 0; i < 8; i++) rr.push(g / 4);
      h += '<polygon points="' + rdPoly(cfg, rr) + '" fill="none" stroke="#e2e8f0" stroke-width="1"/>';
    }
    // 軸線
    for (i = 0; i < 8; i++) {
      p = rdPt(cfg, i, 1);
      h += '<line x1="' + cfg.CX + '" y1="' + cfg.CY + '" x2="' + p[0].toFixed(1) + '" y2="' + p[1].toFixed(1) + '" stroke="#e2e8f0" stroke-width="1"/>';
    }
    // 目盛りの数字（真上の軸にだけ小さく）
    for (g = 1; g <= 4; g++) {
      var gp = rdPt(cfg, 0, g / 4);
      h += '<text x="' + (gp[0] + 4).toFixed(1) + '" y="' + (gp[1] + 3).toFixed(1) + '" font-size="8" fill="#cbd5e1">' + (g * 4) + '</text>';
    }
    // 前回の記録（薄い破線・塗りなし）
    if (prevSc) {
      h += '<polygon points="' + rdPoly(cfg, ratios(prevSc)) + '" fill="none" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="4 3"/>';
    }
    // 今回（塗りは1色）
    var cur = ratios(sc);
    h += '<polygon points="' + rdPoly(cfg, cur) + '" fill="#6366f1" fill-opacity="0.22" stroke="#4f46e5" stroke-width="2.5" stroke-linejoin="round"/>';
    for (i = 0; i < 8; i++) { p = rdPt(cfg, i, cur[i]); h += '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="3.5" fill="#4f46e5"/>'; }
    // 頂点のラベル（領域名＋点数）
    for (i = 0; i < 8; i++) {
      var a = (-90 + i * 45) * Math.PI / 180;
      var lx = cfg.CX + Math.cos(a) * cfg.LR, ly = cfg.CY + Math.sin(a) * cfg.LR;
      var v = Number(sc[DOMAINS[i].key] || 0);
      var nm = cfg.short ? shortName(DOMAINS[i].name) : (DOMAINS[i].emoji + DOMAINS[i].name);
      h += '<text x="' + lx.toFixed(1) + '" y="' + ly.toFixed(1) + '" text-anchor="' + rdAnchor(i) + '" font-size="' + cfg.FS + '" font-weight="bold" fill="' + DOMAINS[i].color + '">' + esc(nm) + '</text>';
      h += '<text x="' + lx.toFixed(1) + '" y="' + (ly + cfg.FS + 1.5).toFixed(1) + '" text-anchor="' + rdAnchor(i) + '" font-size="' + (cfg.FS - 0.5) + '" font-weight="bold" fill="#475569">' + v + '/' + MAX + '</text>';
    }
    h += '</svg>';
    return h;
  }

  // 図を出せる幅があるか。狭すぎるときは棒グラフに戻す。
  function chartWidth() {
    var el = document.getElementById('miChart');
    var w = el ? el.clientWidth : 0;
    if (!w) w = Math.min(window.innerWidth || 360, (app && app.clientWidth) || 360);
    return w;
  }
  function autoMode() {
    var w = chartWidth();
    if (w >= 380) return 'radar';
    if (w >= 300) return 'radarS';
    return 'bar';   // 極端に狭いときは読めなくなるので棒グラフ
  }

  // 図の中身だけを描き直す（結果画面全体は作り直さない）
  function paintChart() {
    var box = document.getElementById('miChart');
    if (!box || !box.__sc) return;
    var sc = box.__sc, prevSc = box.__prev;
    var mode = box.__mode || autoMode();
    var h = '', i;
    if (mode === 'radar' || mode === 'radarS') {
      var cfg = (mode === 'radarS') ? RD_NARROW : RD_WIDE;
      h += radarSvg(sc, prevSc, cfg);
      if (cfg.short) {
        var leg = [];
        for (i = 0; i < DOMAINS.length; i++) if (DOMAINS[i].name !== shortName(DOMAINS[i].name)) leg.push(shortName(DOMAINS[i].name) + '＝' + DOMAINS[i].name);
        if (leg.length) h += '<div class="text-[10px] text-slate-400 leading-relaxed mt-1">' + esc(leg.join('／')) + '</div>';
      }
      if (prevSc) h += '<div class="text-[11px] text-slate-400 text-center mt-1">――― いまの きろく　／　- - - まえの きろく</div>';
    } else {
      for (i = 0; i < DOMAINS.length; i++) h += bar(DOMAINS[i], Number(sc[DOMAINS[i].key] || 0));
    }
    h += '<div class="text-center mt-2"><button id="miChartToggle" class="text-xs text-indigo-600 underline">' +
      (mode === 'bar' ? 'レーダーで 見る' : 'ぼうグラフで 見る') + '</button></div>';
    box.innerHTML = h;
    var tg = document.getElementById('miChartToggle');
    if (tg) tg.onclick = function () {
      var now = box.__mode || autoMode();
      box.__mode = (now === 'bar') ? (chartWidth() >= 380 ? 'radar' : 'radarS') : 'bar';
      paintChart();
    };
  }

  // 画面の向きを変えたときだけ、図の形を作り直す（手動で切り替えた後は尊重する）
  window.addEventListener('resize', function () {
    var box = document.getElementById('miChart');
    if (!box || !box.__sc || box.__mode) return;
    paintChart();
  });

  function bar(d, v) {
    var pct = Math.round(v / MAX * 100);
    var h = '';
    h += '<div class="mb-2">';
    h += '<div class="flex items-center justify-between text-xs font-bold mb-0.5"><span class="text-slate-700">' + d.emoji + ' ' + esc(d.name) + '</span><span style="color:' + d.color + '">' + v + ' / 16</span></div>';
    h += '<div class="h-4 rounded-full bg-slate-100 overflow-hidden"><div style="width:' + pct + '%;height:100%;background:' + d.color + ';border-radius:9999px;transition:width .5s"></div></div>';
    h += '</div>';
    return h;
  }

  // 工夫のキーから児童向けの文言を引く
  function tipKidText(key) {
    if (!tipsCat) return '';
    for (var k in tipsCat) { var l = tipsCat[k] || []; for (var i = 0; i < l.length; i++) if (l[i].key === key) return l[i].kid; }
    return '';
  }

  // 表示する工夫を選ぶ: 上位3つの領域から2つずつ ＋ 最下位の領域から1つ。
  // 「上位＝あなたの型」ではなく「いま好きだと感じていること」の続きとして出す。
  function pickTipCandidates(rank) {
    if (!tipsCat) return [];
    var out = [], i, j;
    var meta = {};
    for (i = 0; i < DOMAINS.length; i++) meta[DOMAINS[i].key] = DOMAINS[i];
    for (i = 0; i < 3 && i < rank.length; i++) {
      var k = rank[i].key, list = tipsCat[k] || [];
      for (j = 0; j < Math.min(2, list.length); j++) {
        out.push({ key: list[j].key, kid: list[j].kid, domainName: meta[k].name, color: meta[k].color, emoji: meta[k].emoji, low: false });
      }
    }
    var lowK = rank.length ? rank[rank.length - 1].key : null;
    if (lowK && tipsCat[lowK] && tipsCat[lowK].length) {
      var lt = tipsCat[lowK][0];
      out.push({ key: lt.key, kid: lt.kid, domainName: meta[lowK].name, color: meta[lowK].color, emoji: meta[lowK].emoji, low: true });
    }
    return out;
  }

  // 選んだものを保存する（最大3つ）。サーバーがカタログに実在するキーだけを受け付ける。
  function bindTips(r, isHistory) {
    var btns = document.querySelectorAll('.mi-tip');
    if (!btns.length) return;
    var msg = document.getElementById('miTipMsg');
    for (var b = 0; b < btns.length; b++) {
      btns[b].onclick = function () {
        var k = this.getAttribute('data-k');
        var cur = (r.picks || []).slice();
        var at = cur.indexOf(k);
        if (at >= 0) cur.splice(at, 1);
        else {
          if (cur.length >= 3) { if (msg) { msg.className = 'text-xs font-bold text-amber-600 h-4 mt-1'; msg.textContent = 'えらべるのは 3つまでだよ'; } return; }
          cur.push(k);
        }
        r.picks = cur;
        // 表示だけ先に切り替える（画面全体は作り直さないのでスクロールは動かない）
        for (var x = 0; x < btns.length; x++) {
          var kk = btns[x].getAttribute('data-k'), onn = cur.indexOf(kk) >= 0;
          btns[x].className = 'mi-tip w-full text-left rounded-xl border-2 px-3 py-2.5 mb-2 transition active:scale-95 ' + (onn ? 'border-emerald-500 bg-emerald-50' : 'border-slate-200 bg-white');
          var dot = btns[x].querySelectorAll('span')[0];
          if (dot) { dot.className = 'shrink-0 w-5 h-5 rounded-full text-[11px] leading-5 text-center ' + (onn ? 'bg-emerald-500 text-white' : 'bg-slate-100 text-slate-400'); dot.textContent = onn ? '✓' : ''; }
        }
        // 履歴を見ているときも保存できる（あとから選び直せる）
        jsend('/api/mi/picks', 'PUT', { resultId: r.id, picks: cur }).then(function (res) {
          if (msg) {
            if (res && res.ok) { msg.className = 'text-xs font-bold text-emerald-600 h-4 mt-1'; msg.textContent = cur.length ? '✅ ' + cur.length + 'つ ほぞんしました' : 'ぜんぶ はずしました'; }
            else { msg.className = 'text-xs font-bold text-red-500 h-4 mt-1'; msg.textContent = 'ほぞんできませんでした'; }
          }
          for (var hi = 0; hi < history.length; hi++) if (history[hi].id === r.id) history[hi].picks = cur;
        });
      };
    }
  }

  function showResult(r, isHistory) {
    var sc = r.scores || {};
    var rank = r.ranking || score(r.answers || []).ranking;
    var h = '';
    // 🎁 特典の結果（提出した直後だけ表示）。金額も可否もサーバーが決めたものをそのまま出す。
    if (!isHistory && lastReward) {
      if (lastReward.granted) {
        h += '<div class="bg-emerald-50 border-2 border-emerald-300 rounded-2xl p-4 mb-4 text-center">';
        h += '<div class="text-3xl">🎁</div>';
        h += '<div class="font-black text-emerald-800 mt-1">' + (lastReward.coins || 0) + 'コイン もらったよ！</div>';
        h += '<div class="text-xs text-emerald-700 mt-1">ゲームの がめんに もどると コインが ふえています。<br>ごほうびは 月に1回まで。しらべ自体は 何回でも できるよ。</div>';
        h += '</div>';
      } else if (lastReward.alreadyTakenThisMonth) {
        h += '<div class="bg-slate-50 border border-slate-200 rounded-2xl p-3 mb-4 text-center text-xs text-slate-500">🎁 今月の ごほうびは 受け取りずみです。（月に1回まで）<br>ごほうびが なくても、なんども やって 見くらべられるよ。</div>';
      } else {
        h += '<div class="bg-amber-50 border border-amber-200 rounded-2xl p-3 mb-4 text-center">';
        h += '<div class="text-xs text-amber-800">🎁 ごほうびの コインが まだ うけとれていません。</div>';
        h += '<button id="miClaim" class="mt-2 bg-amber-500 text-white rounded-xl px-4 py-2 text-sm font-black">ごほうびを 受け取る</button>';
        h += '<div id="miClaimMsg" class="text-xs text-amber-700 mt-1"></div>';
        h += '</div>';
      }
    }
    h += '<div class="bg-white rounded-2xl shadow p-5 mb-4">';
    h += '<h1 class="text-xl font-black text-indigo-700 mb-0.5">🧭 ' + esc(fmtDate(r.takenAt)) + ' の じぶんマップ</h1>';
    h += '<p class="text-xs text-slate-500 mb-3">これは <b>いまの あなたが 自分を どう見ているか</b> の きろくです。テストの点数では ありません。</p>';
    h += '<div id="miChart"></div>';
    h += '</div>';

    // 左右のまとまり
    var lp = Math.round(r.left / (r.left + r.right || 1) * 100);
    h += '<div class="bg-white rounded-2xl shadow p-5 mb-4">';
    h += '<h2 class="font-black text-slate-700 mb-1">🧠 2つの まとまり</h2>';
    h += '<p class="text-xs text-slate-500 mb-3">「ことば・数・しらべる・ふりかえる」のまとまりと、「見る・動く・音・人とかかわる」のまとまり。どちらが 多くても すごいことだよ。</p>';
    h += '<div class="flex h-9 rounded-xl overflow-hidden text-white text-xs font-black">';
    h += '<div style="width:' + lp + '%;background:#6366f1;display:flex;align-items:center;justify-content:center">' + r.left + '</div>';
    h += '<div style="width:' + (100 - lp) + '%;background:#ec4899;display:flex;align-items:center;justify-content:center">' + r.right + '</div>';
    h += '</div>';
    h += '<div class="flex justify-between text-xs font-bold mt-1"><span style="color:#6366f1">ことば・数・しらべる・ふりかえる（' + r.left + '/64）</span><span style="color:#ec4899">見る・動く・音・人（' + r.right + '/64）</span></div>';
    h += '</div>';

    // ベスト3（断定しない言い回し）
    h += '<div class="bg-white rounded-2xl shadow p-5 mb-4">';
    h += '<h2 class="font-black text-slate-700 mb-1">✨ いま あなたが いちばん「好き・とくい」と 感じていること</h2>';
    h += '<p class="text-xs text-slate-500 mb-3">これは「あなたは こういう人だ」という 意味では ありません。<b>いまの あなたの 感じ方</b>です。</p>';
    for (var t = 0; t < 3; t++) {
      var dk = rank[t].key, dd = null;
      for (var m = 0; m < DOMAINS.length; m++) if (DOMAINS[m].key === dk) dd = DOMAINS[m];
      h += '<div class="flex items-start gap-3 border border-slate-100 rounded-xl p-3 mb-2" style="background:' + dd.color + '11">';
      h += '<div class="text-2xl">' + dd.emoji + '</div><div>';
      h += '<div class="font-black text-sm" style="color:' + dd.color + '">' + (t + 1) + '. ' + esc(FEELS[dk]) + '</div>';
      h += '<div class="text-xs text-slate-500 mt-0.5">（' + esc(dd.name) + '　' + rank[t].score + '/16）</div>';
      h += '</div></div>';
    }
    h += '<div class="bg-slate-50 rounded-xl p-3 text-xs text-slate-600 leading-relaxed mt-2">';
    h += '数が 少ない ところは「にがて」では ありません。<b>まだ あまり やっていない だけ</b>かもしれないし、これから 好きに なるかも しれません。<br>';
    h += 'ためしに、いつもと ちがう まとまりの ことを ひとつ やってみるのも おもしろいよ。';
    h += '</div>';
    h += '</div>';

    // 📚 やってみたい勉強のしかた
    //    方針: タイプ分けにしない。「こんなやり方も試せるよ」の提案にとどめる。
    //          点の高い領域からいくつか＋点の低い領域からも必ず1つ混ぜる。
    var picked = (r.picks || []).slice();
    var cand = pickTipCandidates(rank);
    if (cand.length) {
      h += '<div class="bg-white rounded-2xl shadow p-5 mb-4">';
      h += '<h2 class="font-black text-slate-700 mb-1">📚 やってみたい 勉強の しかた</h2>';
      h += '<p class="text-xs text-slate-500 mb-3">「あなたは こうしなさい」では ありません。<b>こんな やり方も 試せるよ</b>。合いそうな ものを えらんでみてね。えらばなくても だいじょうぶ。</p>';
      for (var ci = 0; ci < cand.length; ci++) {
        var t = cand[ci];
        var on = picked.indexOf(t.key) >= 0;
        h += '<button class="mi-tip w-full text-left rounded-xl border-2 px-3 py-2.5 mb-2 transition active:scale-95 ' +
          (on ? 'border-emerald-500 bg-emerald-50' : 'border-slate-200 bg-white') + '" data-k="' + esc(t.key) + '">';
        h += '<div class="flex items-start gap-2">';
        h += '<span class="shrink-0 w-5 h-5 rounded-full text-[11px] leading-5 text-center ' + (on ? 'bg-emerald-500 text-white' : 'bg-slate-100 text-slate-400') + '">' + (on ? '✓' : '') + '</span>';
        h += '<span class="flex-1"><span class="text-sm font-bold text-slate-700">' + esc(t.kid) + '</span>';
        h += '<span class="block text-[11px] mt-0.5" style="color:' + t.color + '">' + esc(t.emoji + t.domainName) + (t.low ? '・まだ あまり やっていない ところ' : '') + '</span></span>';
        h += '</div></button>';
      }
      h += '<div class="bg-slate-50 rounded-xl p-3 text-xs text-slate-600 leading-relaxed mt-1">いちばん 下の ひとつは、<b>いま 点が 少なかった まとまり</b>から えらんで います。少ない＝にがて では なくて、<b>まだ あまり やって いない だけ</b>かも しれないから、ためすと あたらしい 発見が あるかも。</div>';
      h += '<div id="miTipMsg" class="text-xs font-bold text-emerald-600 h-4 mt-1"></div>';
      h += '</div>';
    }

    // 前回との見くらべ
    var prev = null;
    for (var p = 0; p < history.length; p++) {
      if (history[p].id !== r.id && new Date(history[p].takenAt) < new Date(r.takenAt)) { prev = history[p]; break; }
    }
    if (prev) {
      h += '<div class="bg-white rounded-2xl shadow p-5 mb-4">';
      h += '<h2 class="font-black text-slate-700 mb-1">🔄 まえの きろく（' + esc(fmtDate(prev.takenAt)) + '）と くらべて</h2>';
      h += '<p class="text-xs text-slate-500 mb-3">かわっていて 当たり前。かわらなくても 大丈夫。</p>';
      for (var g = 0; g < DOMAINS.length; g++) {
        var dg = DOMAINS[g];
        var now = Number(sc[dg.key] || 0), was = Number((prev.scores || {})[dg.key] || 0), df = now - was;
        var mark = df > 0 ? '<span class="text-emerald-600 font-black">+' + df + '</span>' : (df < 0 ? '<span class="text-sky-600 font-black">' + df + '</span>' : '<span class="text-slate-400">±0</span>');
        h += '<div class="flex items-center justify-between text-xs border-b border-slate-50 py-1"><span class="font-bold text-slate-600">' + dg.emoji + ' ' + esc(dg.name) + '</span><span class="text-slate-400">' + was + ' → <b class="text-slate-700">' + now + '</b>　' + mark + '</span></div>';
      }
      h += '</div>';
    }

    h += '<div class="flex flex-col gap-2 mb-10">';
    h += '<button id="miAgain" class="bg-indigo-600 text-white rounded-xl py-3 font-black shadow">もう一度 やってみる</button>';
    h += '<button id="miHome" class="bg-white border-2 border-slate-200 text-slate-600 rounded-xl py-3 font-bold">さいしょの がめんへ</button>';
    h += '<a href="/" class="text-center text-sm text-slate-400 underline py-2">← ゲームに もどる</a>';
    h += '</div>';

    app.innerHTML = h;
    window.scrollTo(0, 0);
    // 図（レーダー／棒）は DOM に入れてから、実際の幅を見て描く
    var chartBox = document.getElementById('miChart');
    if (chartBox) { chartBox.__sc = sc; chartBox.__prev = prev ? (prev.scores || null) : null; paintChart(); }
    bindTips(r, isHistory);
    document.getElementById('miAgain').onclick = function () {
      answers = new Array(32).fill(null);
      saveDraft(); page = 0; renderQuestions();
    };
    document.getElementById('miHome').onclick = function () { renderIntro(); window.scrollTo(0, 0); };
    var cb = document.getElementById('miClaim');
    if (cb) cb.onclick = function () {
      cb.disabled = true; cb.textContent = '受け取り中…';
      var msg = document.getElementById('miClaimMsg');
      jsend('/api/mi/reward/claim', 'POST', {}).then(function (res) {
        var rw = res && res.reward;
        if (rw && rw.granted) {
          lastReward = rw;
          rewardInfo = { monthKey: rw.monthKey, coins: rw.coins, takenThisMonth: true, canClaim: false };
          showResult(r, isHistory);
        } else if (rw && rw.alreadyTakenThisMonth) {
          lastReward = rw; showResult(r, isHistory);
        } else {
          cb.disabled = false; cb.textContent = 'ごほうびを 受け取る';
          if (msg) msg.textContent = 'いま 受け取れませんでした。ゲームの がめんを 一度 ひらいてから、もう一度 ためしてね。';
        }
      });
    };
  }

  // ------------------------------------------------------------------
  // 起動
  // ------------------------------------------------------------------
  function boot() {
    app = document.getElementById('miApp');
    if (!app) return;
    app.innerHTML = '<div class="text-center text-slate-400 py-10">よみこみ中…</div>';
    jget('/api/auth/me').then(function (me) {
      if (!me || !me.user) {
        app.innerHTML = '<div class="bg-white rounded-2xl shadow p-6 text-center"><p class="font-bold text-slate-700 mb-3">ログインしてから つかってね。</p><a href="/login" class="inline-block bg-indigo-600 text-white rounded-xl px-6 py-3 font-black">ログインへ</a></div>';
        return;
      }
      jget('/api/mi/tips').then(function (tc) { if (tc && tc.ok) tipsCat = tc.tips || null; });
      return jget('/api/mi/my').then(function (d) {
        if (d && d.ok) {
          history = d.results || [];
          rewardInfo = d.reward || null;
          if (d.draft && d.draft.answers) {
            for (var i = 0; i < 32; i++) {
              var v = Number(d.draft.answers[i]);
              answers[i] = (v >= 1 && v <= 4) ? v : null;
            }
          }
        }
        renderIntro();
      });
    });
  }

  if (document.readyState !== 'loading') boot();
  else document.addEventListener('DOMContentLoaded', boot);

})(typeof window !== 'undefined' ? window : globalThis);
