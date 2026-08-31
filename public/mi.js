// TEST-LINE-1
// TEST-LINE-2
  var x = {a:1};
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
    h += '<p class="text-sm text-slate-600 leading-relaxed mb-3">32個の しつもんに 答えると、<b>いまの あなたが 自分を どう見ているか</b>を 8つの まとまりで 見ることが できます。</p>';
    h += '<div class="bg-amber-50 border border-amber-200 rounded-xl p-3 text-xs text-amber-800 leading-relaxed mb-3">';
    h += '<b>だいじなこと</b><br>・正かい や まちがい は ありません。テストでは ないよ。<br>';
    h += '・これは「あなたは○○な人だ」と 決めるもの では ありません。<br>';
    h += '・数が 少ない ところが「にがて」という 意味 でも ありません。<br>';
    h += '・今の 気もち で 答えてね。時間が たつと 答えは かわります。何回でも やり直せます。';
    h += '</div>';
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

  function renderQuestions() {
    var start = page * PER_PAGE;
    var end = Math.min(start + PER_PAGE, 32);
    var pct = Math.round(answeredCount() / 32 * 100);
    var h = '';
    h += '<div class="sticky top-0 bg-slate-100 pt-1 pb-2 z-10">';
    h += '<div class="flex items-center justify-between text-xs font-bold text-slate-500 mb-1"><span>' + (page + 1) + ' / ' + PAGES + ' ページ</span><span>' + answeredCount() + ' / 32 問</span></div>';
    h += '<div class="h-2.5 rounded-full bg-white overflow-hidden shadow-inner"><div style="width:' + pct + '%;height:100%;background:#6366f1;transition:width .2s"></div></div>';
    h += '<div id="miSaved" class="text-[11px] text-emerald-600 font-bold h-4 mt-0.5"></div>';
    h += '</div>';

    for (var i = start; i < end; i++) {
      h += '<div class="bg-white rounded-2xl shadow p-4 mb-3">';
      h += '<div class="flex items-start gap-2 mb-3"><span class="shrink-0 bg-indigo-100 text-indigo-700 rounded-lg px-2 py-0.5 text-xs font-black">' + (i + 1) + '</span>';
      h += '<span class="text-base font-bold text-slate-800 leading-snug">' + esc(Q[i]) + '</span></div>';
      h += '<div class="grid grid-cols-1 gap-2">';
      for (var c = 0; c < CHOICES.length; c++) {
        var on = answers[i] === CHOICES[c].v;
        h += '<button class="mi-a text-left rounded-xl border-2 px-3 py-3 font-bold text-sm transition active:scale-95 ' +
          (on ? 'border-indigo-500 bg-indigo-50 text-indigo-800' : 'border-slate-200 bg-white text-slate-600') +
          '" data-q="' + i + '" data-v="' + CHOICES[c].v + '">' +
          '<span class="inline-block w-6 h-6 leading-6 text-center rounded-full mr-2 ' + (on ? 'bg-indigo-600 text-white' : 'bg-slate-100 text-slate-500') + '">' + CHOICES[c].v + '</span>' +
          esc(CHOICES[c].label) + '</button>';
      }
      h += '</div></div>';
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
    window.scrollTo(0, 0);

    var btns = document.querySelectorAll('.mi-a');
    for (var b = 0; b < btns.length; b++) {
      btns[b].onclick = function () {
        answers[Number(this.getAttribute('data-q'))] = Number(this.getAttribute('data-v'));
        saveDraft();
        renderQuestions();
      };
    }
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
          answers = new Array(32).fill(null);
          showResult(res.result, false);
        } else {
          sb.disabled = false; sb.textContent = 'けっかを 見る 🎉';
          alert('ほぞんできませんでした。もう一度 ためしてね。' + (res && res.__status === 401 ? '（ログインが 切れているかも）' : ''));
        }
      });
    };
  }

  function bar(d, v) {
    var pct = Math.round(v / MAX * 100);
    var h = '';
    h += '<div class="mb-2">';
    h += '<div class="flex items-center justify-between text-xs font-bold mb-0.5"><span class="text-slate-700">' + d.emoji + ' ' + esc(d.name) + '</span><span style="color:' + d.color + '">' + v + ' / 16</span></div>';
    h += '<div class="h-4 rounded-full bg-slate-100 overflow-hidden"><div style="width:' + pct + '%;height:100%;background:' + d.color + ';border-radius:9999px;transition:width .5s"></div></div>';
    h += '</div>';
    return h;
  }

  function showResult(r, isHistory) {
    var sc = r.scores || {};
    var rank = r.ranking || score(r.answers || []).ranking;
    var h = '';
    h += '<div class="bg-white rounded-2xl shadow p-5 mb-4">';
    h += '<h1 class="text-xl font-black text-indigo-700 mb-0.5">🧭 ' + esc(fmtDate(r.takenAt)) + ' の じぶんマップ</h1>';
    h += '<p class="text-xs text-slate-500 mb-4">これは <b>いまの あなたが 自分を どう見ているか</b> の きろくです。テストの点数では ありません。</p>';
    for (var i = 0; i < DOMAINS.length; i++) h += bar(DOMAINS[i], Number(sc[DOMAINS[i].key] || 0));
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
    document.getElementById('miAgain').onclick = function () {
      answers = new Array(32).fill(null);
      saveDraft(); page = 0; renderQuestions();
    };
    document.getElementById('miHome').onclick = function () { renderIntro(); window.scrollTo(0, 0); };
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
      return jget('/api/mi/my').then(function (d) {
        if (d && d.ok) {
          history = d.results || [];
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
