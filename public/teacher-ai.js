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
  // カルテは月曜に印刷して配るので、児童の週の記録は「直前に終わった週」を使う。
//
// ⚠ 2026-09-24 の直し：ここは「作った日から見て、直前に終わった月〜金」に戻した。
//
//    前日(09-23)に「配る月曜」を基準にする形へ変えたが、それが間違いだった。
//    火〜金に作ると「今週（まだ終わっていない週）」が対象になってしまい、
//    9月24日(木)に作ると 9/21〜9/25 を見にいった。その週の提出はクラス全体で
//    2件しかなく、23人のほとんどが「先週は提出がなかった」と書かれてしまった。
//    （正しい 9/14〜9/18 には 10〜13人/日 の提出がある）
//
//    見出しと本文の一週ズレは、この式ではなく「公開時に週を保存して、
//    紙の見出しもその週を使う」側だけで解決している（week_start / week_end）。
//    だから生成側はここで触らないのが正しい。
function lastWeekDaysJst() {
  var d = jstNow();
  var wd = (d.getDay() + 6) % 7;                          // 0=月
  var mon = new Date(d.getTime() - wd * 86400000 - 7 * 86400000);
  var out = [];
  for (var i = 0; i < 5; i++) out.push(fmtDay(new Date(mon.getTime() + i * 86400000)));
  return out;
}
function jaDay(s) { var p = String(s).split('-'); return Number(p[1]) + '月' + Number(p[2]) + '日'; }
function isoWeekOf(ymd) {
  var p = String(ymd).split('-');
  var x = new Date(Number(p[0]), Number(p[1]) - 1, Number(p[2]));
  var dn = (x.getDay() + 6) % 7;
  x.setDate(x.getDate() - dn + 3);
  var f = new Date(x.getFullYear(), 0, 4);
  var fn = (f.getDay() + 6) % 7;
  f.setDate(f.getDate() - fn + 3);
  var w = 1 + Math.round((x.getTime() - f.getTime()) / (7 * 86400000));
  return x.getFullYear() + '-W' + (w < 10 ? '0' + w : '' + w);
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
  function cacheSet(key, text, blocks, noMaterial, peopleWords) {
    try {
      sessionStorage.setItem(CACHE_KEY, JSON.stringify({
        key: key, text: text, blocks: blocks, noMaterial: noMaterial || 0, peopleWords: peopleWords || 0, at: Date.now()
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
      // 【ポートフォリオ】も丸ごと落とす。
      //   取り込んだプリントは【今回の新しい取り込み】として別に渡すようになった。
      //   そちらは「まだ一度もカルテに使っていないもの」だけで、取り込んだ日つき。
      //   ここに残すと、前にほめた材料がもう一度まざる（2026-09 の事故）。
      if (head.indexOf('【ポートフォリオ') === 0) continue;
      out.push(head);
      if (false) {
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
  // ══════ KARTE_ANON_V1 (2026-09-24) 束から児童の実名を外す ══════
  //  外部AIに貼る文章には、名前のかわりに その場かぎりの符号（A01〜）を入れる。
  //  ・割り当てはコピーのたびにシャッフルする。先週と今週で同じ子でも違う符号になる。
  //  ・目印のIDは loginId（名前そのものの子がいる）をやめて userId（UUID）にする。
  //    取り込み側は もともと userId でも照合できる（put(normId(s.userId), s.userId)）。
  //  ・対応表はこのブラウザの sessionStorage にだけ置く。貼り戻すときに使う。
  //  ⚠ これで外れるのは「児童本人の氏名」だけ。子どもが書いた本文の中の
  //    友達の名前・先生の名前・塾名などは消せない（消すと引用が壊れる）。
  var TAI_ALIAS_KEY = 'taiAliasMap';
  var _aliasByUid = {}, _aliasByKey = {};
  function _akey(v) { return String(v == null ? '' : v).replace(/[\s　]/g, '').toLowerCase(); }
  function buildAliases(roster) {
    _aliasByUid = {}; _aliasByKey = {};
    var idx = [];
    for (var i = 0; i < roster.length; i++) idx.push(i + 1);
    for (var j = idx.length - 1; j > 0; j--) { var k = Math.floor(Math.random() * (j + 1)); var t = idx[j]; idx[j] = idx[k]; idx[k] = t; }
    for (var m = 0; m < roster.length; m++) {
      var n = idx[m], a = 'A' + (n < 10 ? '0' + n : '' + n), r = roster[m];
      _aliasByUid[r.userId] = a;
      if (r.userId) _aliasByKey[_akey(r.userId)] = a;
      if (r.loginId) _aliasByKey[_akey(r.loginId)] = a;
      if (r.name) _aliasByKey[_akey(r.name)] = a;
      try { var dn = nameOf(r.loginId, r.name); if (dn) _aliasByKey[_akey(dn)] = a; } catch (e) {}
    }
    try { sessionStorage.setItem(TAI_ALIAS_KEY, JSON.stringify(_aliasByUid)); } catch (e) {}
  }
  // 名簿に無い子は名前を出さずに伏せる。実名が漏れるより、分からないほうが安全。
  function anonOf(loginId, name) { return _aliasByKey[_akey(loginId)] || _aliasByKey[_akey(name)] || '（名簿外）'; }
  function anonUid(uid) { return _aliasByUid[uid] || '（名簿外）'; }

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
      // 「新しい取り込みなし」の子が何人いるかを出す。先生が
      //   「この子には何か足すか、別の観点で書かせるか」を判断できるように。
      var none = (m.noMaterial > 0) ? ('　📎新しい取り込みなし：' + m.noMaterial + '人') : '';
      // 実名は外してあるが、本文の中の人名までは消せない。貼る前に気づけるように数だけ出す。
      if (m.peopleWords > 0) none += '　⚠ 本文に人名らしい語 ' + m.peopleWords + '件';
      say('✓ コピーしました' + from + '（約' + Math.round((m.chars || 0) / 1000) + '千字 / AIが書く欄 ' + (m.blocks || 0) + '個）' + none + '。ChatGPT / Gemini / Claude に貼り付けてください' + warn);
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
        window.__taiLast = { chars: hit.text.length, blocks: hit.blocks, cached: true, noMaterial: hit.noMaterial || 0, peopleWords: hit.peopleWords || 0 };
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
    var weekDays = lastWeekDaysJst();
  var weekLabel = jaDay(weekDays[0]) + '〜' + jaDay(weekDays[4]);
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
    buildAliases(roster);   // KARTE_ANON_V1 この回かぎりの符号を割り当てる
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
    out.push('【この文章の目的（いちばん上の前提）】');
    out.push('・ここで書く文は、子どもが「自分の学びを自分で動かせる」ようになるための材料です。');
    out.push('  先生が指示を出すための文ではありません。');
    out.push('・だから、ほめて終わりにしない。評価して終わりにしない。');
    out.push('  最後は、本人が次を自分で決められる問いかけで終わる。決めるのは子ども本人です。');
    out.push('・こちらが見つけた答えを渡すほど、子どもは自分で考えなくなります。');
    out.push('  答えではなく、本人が気づける材料を差し出してください。');
    out.push('');
    out.push('【⚠ 正答率の読み方（ここを間違えると、事実と違う紙が子どもに渡ります）】');
    out.push('・このアプリは、単元によって「問題の種類」の数がまるで違います。');
    out.push('  種類が少ない単元は、同じ問題を何十回も解くことになります。');
    out.push('  だから【教科別の正答率】には、問題の種類と「1問あたり何回解いたか」を書いてあります。');
    out.push('  実際にあった例（同じクラスの、同じ子のデータ）:');
    out.push('    ある社会の単元 … 問題の種類 7 ／ 1問あたり 14.7回 ／ 正答率 97%');
    out.push('    ある算数の単元 … 問題の種類 220 ／ 1問あたり 1.1回 ／ 正答率 42%');
    out.push('  この2つの「正答率」は、まったく意味がちがいます。');
    out.push('・きまり:');
    out.push('  - 1問あたりの回数が多い単元（「周回ぎみ」と書いてあるもの）の高い正答率を、');
    out.push('    「理解している」「得意」「よくわかっている」の根拠にしないでください。');
    out.push('    それは覚えているだけかもしれません。');
    out.push('  - 1問あたりの回数が少ないのに正答率が高いときだけ、「力がついている」と書いてよいです。');
    out.push('  - 1問あたりの回数が少なくて正答率が低いのは、いま初めて出会っている最中です。');
    out.push('    「できていない」ではなく「いま出会っているところ」として書いてください。');
    out.push('・周回している子を責めないでください。その子はルールの中でちゃんとがんばっています。');
    out.push('  書くなら「同じところをようけ回っとるな。次はこっちにも行ってみいひん？」のように、');
    out.push('  新しい場所へのさそいにする。「意味がない」「ずるい」とは絶対に書かない。');
    out.push('');
    out.push('【事実と見立てを分ける】');
    out.push('・データから確実に言えること（事実）と、そこからの推しはかり（見立て）を混ぜないでください。');
    out.push('  事実 … 「水曜に20分やって『楽しかった』って書いとったな」');
    out.push('  見立て … 「好きなことやと長う続くんかもな」「〜のようや」「〜かもしれん」');
    out.push('・見立てを書くときは、見立てだと分かる語尾にする。言い切らない。');
    out.push('・記録に無いことは書かない。分からないことは、うめずに書かないでおく。');
    out.push('');
    out.push('【まもってほしいこと】');
    out.push('0. 児童の名前は渡していません。かわりに「A01」のような符号が入っています。');
    out.push('   あなたが書く文の中に、符号を書かないでください（紙に記号が載ってしまいます）。');
    out.push('   先生が読む文（クラス所見・週報）では「A01の子」のように符号で書いてかまいません。');
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
out.push('9. データは全部読んでよいが、書くのは絞ること。数字を並べるほど文章は当たり障りがなくなります。');
out.push('   「この子について本当に言うべきこと」を1〜2点えらび、具体的に書いてください。');
out.push('10. 【MIしらべ】は、本人が自分をどう見ているかの自己申告であって、能力の判定ではありません。');
out.push('   - 「◯◯タイプ」「◯◯型」のような決めつけ・タイプ分けは絶対に書かない。');
out.push('   - 点が低い項目を「苦手」と決めつけない。');
out.push('   - MIだけを根拠にしない。ほかのデータと重なったときだけ、きっかけとして使う。');
out.push('   - MIしらべが無い子には、そのことに触れない（「受けていないので分からない」等は書かない）。');
    if (isFri) {
      out.push('11. 今日は金曜日です。児童ごとの【先週（' + weekLabel + '）】に、その週の記録と振り返りを');
      out.push('   入れてあります。REFLECT には、その1週間の流れ（月曜からどう変わったか）を');
      out.push('   ふまえた返却コメントを書いてください。1日だけを見て書かないこと。');
    }
    out.push('');
    out.push('');
out.push('【深く書くための突き合わせ方（ここが一番大事）】');
out.push('・浅い例（こう書かないでほしい）：「先週は3日とりくめました。えらいね。」');
out.push('  … データを言いかえただけで、その子だけの発見がありません。');
out.push('・深い例（こう書いてほしい）：「先週は理科を20分やって『楽しかった』と書いていたのに、');
out.push('  算数の日は5分で終わっていたね。好きなことだと長く続けられるみたいだから、');
out.push('  算数も好きな単元から始めてみよう。」');
out.push('  … 離れたデータ（教科・時間・本人のことば）を突き合わせて、次の一歩につないでいます。');
out.push('・突き合わせの型（当てはまるものを1つ選べばよい。むりに全部使わない）:');
out.push('  1) 本人が書いたことば × 実際の記録 … 「やる」と書いた日に記録があるか、時間はどうか');
out.push('  2) 教科ごとの続いた時間の差 … 好きな教科と苦手な教科で、続く時間がどう違うか');
out.push('  3) 問題の種類 × 1問あたりの回数 × 正答率 … のべ問題数だけを「量」と読まない。');
out.push('     種類が少なく回数が多い＝周回。種類が多く回数が少ない＝新しいことに出会っている最中。');
out.push('  4) 先週 × その前の週 … 何が変わったか（増えた・減った・やり方が変わった）');
out.push('  5) 得意な教科でのやり方 × 苦手な教科 … うまくいくやり方を別の教科に移せないか');
out.push('  6) 手ごたえ（☀☁🌧）× 学習内容 … どんな内容のときに手ごたえがよいか');
out.push('  7) MIしらべ（自己申告）× 実際の記録 … 本人が「好き」と答えたことが記録にも出ているか');
out.push('  8) 今週の予定・テスト × 先週の様子 … これからの1週間に効く形にする');
if (wantWide) out.push('  9) アプリの正答率 × 紙のテストの傾向 … 知識はあるのに書いて答えるとくずれる、など');
out.push('・「この子にしか当てはまらないこと」を書いてください。');
out.push('  ほかの子にもそのまま言える文になったら、書き直してください。');
out.push('・提出率のパーセントは、子どもが読む文には書かないでください。');
out.push('  「5日のうち3日」のように、数えられる形で書いてください。');
out.push('・深く書くことと、きつく書くことは違います。');
out.push('  できていないことを責めない／点数・順位に触れない／ほかの子と比べない／');
out.push('  タイプ分けをしない、は変わりません。理由は前向きな言い回しで書いてください。');
out.push('');
out.push('【目印の種類】');
    if (want.daily)   out.push('・=== [DAILY:...] === … その日の家庭学習への先生コメント。1〜2文、40字以内。子ども向け。');
    if (want.karte)   out.push('・=== [KARTE:...] === … 阪神マンから本人へのひとこと。子ども向け。');
    if (want.karte) {
      out.push('    ※阪神マンのひとこと（大事）:');
      out.push('      - 書くのは先生ではなく「阪神マン」。関西弁の話しことばで、元気に、親しみをもって書く。');
      out.push('        例：〜やったな／〜しとったな／〜ちゃう／〜やで／〜か？。ていねい語（です・ます）は使わない。');
      out.push('        文体は、上の共通のきまりより この阪神マンのきまりを優先する。');
      out.push('      - ①よいところ ②気になるところ ③次の一歩 のような番号の見出しは使わない。通信簿の形にしない。');
      out.push('      - 4〜6文・280字以内。ひとかたまりの話しことばで書く。紙に印刷するので、これより長くしない。');
      out.push('        280字は上限であって目標ではない。書くことが少ない週は150字でもよい。');
      out.push('        長くするために、同じことの言いかえを増やさない。');
      out.push('        「がんばろう」「大事だよ」のような、だれにでも言える文を足さない。');
      out.push('      - 次の4つを必ず全部入れる（順番は自由。1文に2つ入れてもよい）:');
      out.push('        (1) 先週の事実を1つ。本人が書いたことばを「 」でそのまま引用する');
      out.push('        (2) 【4月からの移りかわり】から1つ（のびた／夏休みで落ちた／ずっと続いている）');
      out.push('        (3) 見立てを1つ。「〜かもしれん」「〜ちゃうか？」と、見立てと分かる語尾で');
      out.push('        (4) 本人が決められる問いかけで終わる');
      out.push('        （これまでの実績は平均152字・最長276字。180字なら紙に収まります）');
      out.push('      - 本人が書いたことば（ふりかえり・きもちの理由・計画）があれば、かならず「 」でそのまま引用する。');
      out.push('        例：金曜に「複雑な円の面積が求められた！」って、自分で書いとったで。');
      out.push('      - できていないことは責めない。事実として返したうえで、それは別に悪いことちゃう、と受けとめる。');
      out.push('      - 最後は指示ではなく、本人が決められる問いかけで終わる。決めるのは本人。');
      out.push('        終わり方は週のタイプで変える。毎回おなじ問いかけをくり返さない:');
      out.push('        ・うまくいった週 … なぜうまくいったかを本人に言わせる（例：なんでうまいこといったか、自分では何やと思う？）');
      out.push('        ・つまずいた週 … 責めずに選ばせる（例：立て直すなら、どっちからいく？）');
      out.push('        ・記録がない週 … ハードルを下げて一つ選ばせる（例：5分だけやるとしたら、何にする？）');
      out.push('        上の例文はそのまま使わず、その子の中身に合わせて書きかえる。');
      out.push('      - 土台は【先週（' + weekLabel + '）】。先週やったこと・書いたことを具体的に取り上げる。');
      out.push('      - そのうえで【4月からの移りかわり】に、かならず一度は触れる。');
      out.push('        のびたところ／夏休みで落ちたところ／ずっと続いていること のどれか一つでよい。');
      out.push('        1週間だけでは言えない話が、その子にはいちばん効きます。');
      out.push('      - 【今回の新しい取り込み】は、まだ一度もカルテでほめていないプリント・作品です。');
      out.push('        ここにあるものは、中身を読んで具体的にほめてよいです（例：どこの説明がよかったか）。');
      out.push('        日付が添えてあります。古い日付のものを「先週やったこと」のように書かないでください。');
      out.push('        書くなら「前に書いた◯◯やけどな」のように、いつのものか分かる形にする。');
      out.push('      - 【今回の新しい取り込み】が「なし」のときは、プリントや作品の話を書かない。');
      out.push('        先週の家庭学習・本人のことば・4月からの移りかわり だけで書く。');
      out.push('        むりに掘り返さない。書くことが少ない週は、短くてよいです。');
      out.push('      - 【前に渡したカルテ】には、前にこの子へ渡した文が入っています。');
      out.push('        同じ話題・同じほめ方・同じ問いかけをくり返さない。');
      out.push('        前の文の続きとして書く（例：先週言うてた◯◯、その後どうなった？）か、別の角度から書く。');
      out.push('      - 名前も「A07」のような符号も、文の中には絶対に書かない。');
      out.push('        符号はこちらが誰のことか区別するための目印で、子どもには意味がない。');
      out.push('        文は本人に向けて書くので、「あなた」「きみ」も要らない。');
      out.push('      - テストは「いつ・何があったか」だけ渡してある。点数・評価は渡していない。');
      out.push('        点数を推測して書かない。「よくできた」「結果が出た」など出来ばえにも触れない。');
      out.push('        ほめてよいのは、テストに向けた取り組み（家庭学習の記録や本人のことば）だけ。');
      out.push('      - 正答率を「できている」の根拠にするときは、上の【⚠ 正答率の読み方】を必ず守る。');
      out.push('        「周回ぎみ」と書いてある単元の高い正答率を、理解の証拠として書かない。');
      out.push('      - 上の「突き合わせの型」を1つ使って、この子だけの見立てを書く。データの言いかえで終わらせない。');
      out.push('      - この下に先生がプリントやノートの内容を手で貼ることがあります。');
      out.push('        貼ってあれば、その中身も読んで具体的にほめてください。');
    }
    if (want.plan)    {
out.push('・=== [PLAN:...] === … 今週の計画へのアドバイス。①よい点 ②もっとよくする点 ③ひとこと。子ども向け。');
out.push('   ※計画アドバイスのきまり（大事）:');
out.push('   - これは過去のふり返りではなく、これから始まる1週間への助言です。');
out.push('   - 本人が書いた計画の中身に、必ず具体的に触れる。');
out.push('     例：「月曜に漢字ドリル37まで、と書いてあるね」');
out.push('   - 【A】の「今週の先生からの課題」にテストの予定があるときは、計画と突き合わせる。');
out.push('     例：「金曜に社会のテストがあるから、木曜にまとめてやるより、火曜から分けるといいよ」');
out.push('     予定が書かれていないときは、そのことに触れない。');
out.push('   - 空の日が多い子・書いた量が少ない子を責めない。');
out.push('     「まずは1日だけ決めてみよう」のような、小さくて確実にできる提案にする。');
out.push('   - ★「書きなおした回数」は、迷っている印ではありません。よく考えて直せた印です。');
out.push('     回数の多さを否定的に書かない。触れるなら「考え直せたね」の向きだけ。');
out.push('   - テストの点数・得点率・順位には いっさい触れない。ほかの子とも比べない。');
out.push('   - 全部で3行以内・150字以内。');
}
    if (want.reflect) out.push('・=== [REFLECT:...] === … 今週の振り返りへの返却コメント。2〜3文。子ども向け。');
    if (want.suggest) {
out.push('・=== [SUGGEST:...] === … 今週のおすすめ。1〜2つだけ。子ども向け。');
out.push('   ※今週のおすすめのきまり（大事）:');
out.push('   - おすすめは1〜2つだけ。たくさん挙げない。曜日ごとの一覧にしない。');
out.push('   - 中身は「見立て → 根拠 → 次の一歩」の順で書く。');
out.push('     見立て … この子について気づいたこと（上の「突き合わせの型」を1つ使う）');
out.push('     根拠   … そう思ったもとになった、先週の具体的な事実');
out.push('     次の一歩 … 今週やってみることを一つだけ');
out.push('   - 「なぜそれがおすすめか」を必ず書く。形は「先週◯◯だったから、今週は△△をやってみよう」。');
out.push('     例：「先週は水曜に理科を20分やって『楽しかった』と書いていたから」');
out.push('   - 【A】の「今週の先生からの課題」に今週の予定やテストが書いてあるときは、それも織り込む。');
out.push('     例：「金曜に社会のテストがあるから、月曜から少しずつ分けてやってみよう」');
out.push('     ただし予定やテストが書かれていないときは、そのことに触れない。');
out.push('   - 「がんばっているから」「力がつくから」のような、だれにでも当てはまる理由は書かない。');
out.push('   - 理由を「◯◯ができていないから」「正答率が低いから」とは書かない。');
out.push('     「まだあまりやっていないから」「先週これが楽しそうだったから」のような前向きな言い方にする。');
out.push('   - テストの点数・得点率・順位には いっさい触れない。ほかの子とも比べない。');
out.push('   - 1行目だけを読んでも意味が通るように書く。この文は紙だけでなく、子どものアプリ画面にも出ます。');
out.push('   - 全部で4行以内・200字以内。紙に印刷して配るので、それより長く書かない。');
}
    if (want.classOv) out.push('・=== [CLASS] === … クラス全体の所見。5〜8行（よい傾向／気になる点／来週の手立て）。先生向け。【テスト・成績】も使ってよい。');
    if (want.report)  out.push('・=== [WEEKREPORT] === … 今週の週報。管理職・保護者にも見せられる文体で10行程度。先生向け。【テスト・成績】も使ってよい。');
    out.push('');
    out.push('【児童ごとのデータの並び】');
    out.push('・【先週（' + weekLabel + '）】…個人カルテ・今週のおすすめ・振り返り返却は、ここが土台。');
    out.push('・【4月からの移りかわり】…月ごとの動きと、前期(4〜7月)→後期(8月〜)のくらべ。カルテで一度は触れる。');
    out.push('・【最近の取り込み】…まだ一度もカルテに使っていないプリント・作品。取り込んだ日つき。');
    out.push('  古いものは渡していません。ここに無いものは、今週は話題にしないでください。');
    out.push('・【最近のテスト】…あったという事実だけ。点数・評価は渡していません。');
    out.push('・【前に渡したカルテ】…前にこの子へ渡した文。同じことを書かないための参考。');
    out.push('・【ふだんの様子（4月からの積み上げ）】…背景。正答率は かならず「1問あたりの回数」とセットで読む。');
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
          out.push('・' + anonOf(a.loginId, a.name) + '／' + unitJa(a.unit) + '：' +
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
          var nm2 = anonOf(st.loginId, st.name);
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
          out.push('・' + anonOf(ds.loginId, ds.name) + '（前の7日 ' + ds.prev7 + '回 → 直近7日 ' + ds.recent7 + '回）');
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

    // ── カルテの材料を受け取る（クラスで1回だけ・読み取りは約300行）──
    //   返ってくるのは「まだ一度もカルテに使っていないもの」だけ。
    //   引き出しは4月からの全期間ぜんぶ。使ったものだけが外れる仕組み（karte_material_uses）。
    //   ここで受け取った時点では「予約」で、先生が公開したときに「使った」に変わる。
    var pickBy = {}, pickNone = 0, pickFreshFrom = '', pickFreshDays = 0;
    if (want.karte) {
      say('カルテの材料をえらんでいます...');
      var picked = await postJson('/api/teacher/karte-materials/pick', { classId: cid });
      if (picked && picked.ok) { pickBy = picked.byStudent || {}; pickNone = picked.exhaustedCount || 0; pickFreshFrom = picked.freshFrom || ''; pickFreshDays = picked.freshDays || 0; }
      else { say('材料の台帳が読めませんでした。プリントの話は今回は渡しません。'); }
    }

    for (var i = 0; i < roster.length; i++) {
      var st = roster[i];
      var nm = anonUid(st.userId);          // 束には符号だけ（実名は入れない）
      var sid = st.userId;                  // 目印のIDは UUID（loginId が実名の子がいるため）
      say('児童のデータを集めています... (' + (i + 1) + '/' + roster.length + ')');

      var data = null;
      try { data = await getJson('/api/teacher/student-full-analysis?studentId=' + encodeURIComponent(st.userId)); } catch (e) {}

      out.push('--------------------------------------------------');
      out.push('▼ 児童データ: ' + nm + '（ID: ' + sid + '）');  // nm は符号
      out.push('--------------------------------------------------');

      // ===== ① この1週間（個人カルテ・家庭学習コメント・振り返り返却の主役） =====
      var weekRefl = null;
      var planLines = [], reflText = '';
      var p = planByUser[st.userId];
      out.push('【先週（' + weekLabel + '）】※個人カルテと今週のおすすめは、ここを主役に書く');
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
            out.push('・先週の合計：' + wsubs.length + '日 / ' + mins + '分 / ☀' + suns + '日');
          } else {
            out.push('・（先週の提出はありませんでした）');
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
          if (p.revisionCount) out.push('　（' + p.revisionCount + '回 考え直して書きなおしています）');
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

      // 先週のふりかえり（紙のカルテに載るのと同じ週のもの）
try {
  var _lwk = isoWeekOf(weekDays[0]);
  var _lref = null;
  ((data && data.reflections) || []).forEach(function (r) { if (r && String(r.weekKey) === _lwk) _lref = r; });
  if (_lref && (_lref.goodPoint || _lref.improvePoint || _lref.nextAction)) {
    out.push('・先週のふりかえり（本人が書いたもの）');
    if (_lref.goodPoint) out.push('  よかったこと: ' + _lref.goodPoint);
    if (_lref.improvePoint) out.push('  もっとよくしたいこと: ' + _lref.improvePoint);
    if (_lref.nextAction) out.push('  来週やること: ' + _lref.nextAction);
  }
} catch (e) {}
// MIしらべ（本人の自己申告。能力の判定ではない）
try {
  var _mi = data && data.mi;
  if (_mi && _mi.scores) {
    var _mj = JSON.parse(_mi.scores);
    var _mr = (_mj && _mj.ranking) || [];
    if (_mr.length) {
      out.push('・MIしらべ（自己申告・' + String(_mi.takenAt || '').slice(0, 10) + '）本人が「好き・得意」と答えた上位: ' + _mr.slice(0, 3).map(function (x) { return x.name; }).join('、'));
    }
  }
} catch (e) {}
// ===== ②-1 4月からの移りかわり（1週間だけでは言えない話は ここから作る）=====
      try {
        var _mt = (data && data.monthlyTrends) || [];
        if (_mt.length) {
          out.push('');
          out.push('【4月からの移りかわり】');
          out.push('・月ごと … ' + _mt.map(function (mm) {
            return String(mm.month || '').slice(5) + '月:' + (mm.count || 0) + '回/' + (mm.avgMin || 0) + '分/☀' + (mm.sunRate || 0) + '%';
          }).join('  '));
          var _ups = [], _dns = [];
          ((data && data.subjects) || []).forEach(function (su2) {
            if (su2.earlyRate == null || su2.lateRate == null) return;
            if ((su2.earlyTotal || 0) < 20 || (su2.lateTotal || 0) < 20) return;
            var _df = su2.lateRate - su2.earlyRate;
            var _nm = unitJa(su2.unit) + '(' + su2.earlyRate + '%→' + su2.lateRate + '%)';
            if (_df >= 10) _ups.push(_nm); else if (_df <= -10) _dns.push(_nm);
          });
          if (_ups.length) out.push('・4〜7月 → 8月以降 でのびた … ' + _ups.slice(0, 4).join('、'));
          if (_dns.length) out.push('・4〜7月 → 8月以降 で下がった … ' + _dns.slice(0, 4).join('、'));
          if (!_ups.length && !_dns.length) out.push('・4〜7月 と 8月以降 で、はっきり動いた単元はありません（どちらも20問以上ある単元だけで比べています）。');
        }
      } catch (e) {}

      // ===== ②-2 今回の新しい取り込み（一度カルテに使ったものは渡さない）=====
      //   「一度ほめた内容をもう一度ほめない」ための本体。
      //   渡せる材料が無い子には、無いと はっきり書く。掘り返させない。
      var _pk = pickBy[st.userId] || null;
      if (want.karte) {
        out.push('');
        if (_pk && _pk.materials && _pk.materials.length) {
          out.push('【最近の取り込み（' + (pickFreshDays ? 'この' + Math.round(pickFreshDays / 7) + '週以内・' : '') + 'まだ一度もカルテで使っていないもの）】');
          _pk.materials.forEach(function (mt) {
            // KARTE_TEST_V1 ◎○△ は渡さない（子どもの紙に評価記号が出る事故を構造で防ぐ）。
            //   先生が言葉で書かれた「評価コメント」は数値ではないので残す。
            var ln = '・[' + mt.kind + '] ' + (mt.title || '(無題)') + '（取り込み ' + (mt.on || '日付不明') + (mt.unit ? '／' + mt.unit : '') + '）';
            if (mt.evalComment) ln += ' 評価コメント:' + mt.evalComment;
            if (mt.body) ln += ' 本文:' + mt.body;
            if (mt.reflection) ln += ' ／本人の振り返り:' + mt.reflection;
            out.push(ln);
          });
          if (_pk.heldBack) out.push('（ほかに ' + _pk.heldBack + ' 件ありますが、前のカルテでもうほめているので渡していません）');
        } else {
          out.push('【今回の新しい取り込み】…なし');
          out.push('（この子の取り込み物は、前のカルテでもうほめています。プリントや作品の話は書かないでください）');
        }
        // ④ テストは「いつ・何があったか」だけ。点数・満点・得点率・順位・◎○△は渡さない。
        //    読み取りに間違いがあっても、数値が束に入らなければ子どもの紙に害が出ない。
        try {
          var _ts = (data && data.testScores) || [];
          var _tl = [];
          for (var _ti = 0; _ti < _ts.length && _tl.length < 5; _ti++) {
            var _t = _ts[_ti];
            var _td = String((_t && _t.testDate) || '').slice(0, 10);
            if (!_td) continue;                              // 日付のないものは渡さない
            if (pickFreshFrom && _td < pickFreshFrom) continue;  // 古いものは渡さない
            _tl.push('・' + _td + ' ' + String(_t.subject || '') + ' 「' + String(_t.testName || '') + '」');
          }
          if (_tl.length) {
            out.push('');
            out.push('【最近のテスト】※点数・評価は渡していません。あったという事実だけです');
            out = out.concat(_tl);
          }
        } catch (e) {}
        if (_pk && _pk.pastKartes && _pk.pastKartes.length) {
          out.push('');
          out.push('【前に渡したカルテ（同じことを書かないための参考）】');
          _pk.pastKartes.forEach(function (pkx) { out.push('・' + (pkx.on || '') + ' に渡した文：' + pkx.text); });
        }
      }

      // ===== ③ ふだんの様子（4月からの積み上げ・カルテでは背景あつかい）=====
      if (data && data.ok) {
        var body = { main: [], test: [] };
        try {
          if (typeof _aiBodyLines === 'function') body = splitBody(trimBody(_aiBodyLines(data)));
        } catch (e) { body = { main: ['(基本データの整形に失敗)'], test: [] }; }

        out.push('');
        out.push('【ふだんの様子（4月からの積み上げ）】※正答率は「1問あたりの回数」とセットで読むこと');
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
    // KARTE_ANON_V1 本文に人名らしい語が残っていないか、貼る前に気づけるようにする。
    //   ⚠ 「さん・くん・ちゃん・先生」を数えるだけの簡易な見張り。人名かどうかは判定していない。
    var _pn = 0;
    try {
      var _pl = _txt.split(String.fromCharCode(10));
      for (var _pi = 0; _pi < _pl.length; _pi++) {
        var _pt = _pl[_pi];
        if (_pt.indexOf('【') === 0 || _pt.indexOf('===') === 0 || _pt.indexOf('・【') === 0) continue;
        if (/(くん|君|ちゃん|先生)/.test(_pt)) { _pn++; continue; }
        if (/さん/.test(_pt) && !/(たくさん|みなさん|皆さん)/.test(_pt)) _pn++;
      }
    } catch (e) {}
    window.__taiLast = { chars: _txt.length, blocks: _blocks, cached: false, noMaterial: pickNone, peopleWords: _pn };
    if (!oneId) cacheSet(_ckey, _txt, _blocks, pickNone, _pn);
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
  return _taiParse(raw);
}

// --- 目印として認めるもの ---
var TAI_KINDS = ['DAILY', 'KARTE', 'PLAN', 'REFLECT', 'SUGGEST', 'CLASS', 'WEEKREPORT'];

function reEsc(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

// 装飾（** ## - > ` 全角空白など）を落とす。ChatGPT が目印を太字や見出しにすることがあるため。
function stripDeco(line) {
  var s = String(line == null ? '' : line);
  s = s.replace(/[​﻿]/g, '');
  s = s.replace(/^[\s　>＞#＃*＊・`\-–—]+/, '');
  s = s.replace(/[\s　*＊#＃`]+$/, '');
  return s;
}

// 1行が目印なら {kind, idPart, after, isSample} を返す。ちがえば null。
function matchMarker(line) {
  var s = stripDeco(line);
  if (!s) return null;
  s = s.replace(/^[=＝]+[\s　]*/, '');
  var m = s.match(/^[\[［]\s*([^\]］]{1,160}?)\s*[\]］]([\s\S]*)$/);
  if (!m) return null;
  var inner = String(m[1]);
  var after = String(m[2] || '')
    .replace(/[=＝\s　*＊]+$/, '')
    .replace(/^[\s　:：|｜]+/, '');
  var kind = inner, idPart = '';
  var ci = inner.indexOf(':');
  if (ci < 0) ci = inner.indexOf('：');
  if (ci >= 0) { kind = inner.slice(0, ci); idPart = inner.slice(ci + 1); }
  var k = kind.toUpperCase().replace(/[^A-Z]/g, '');
  if (k === '' && inner.indexOf('クラス') >= 0) k = 'CLASS';
  if (TAI_KINDS.indexOf(k) < 0) return null;
  idPart = idPart.replace(/[\s　]/g, '');
  // 「=== [KARTE:...] === … 個人カルテ。」のような、貼り付ける前の説明文の見本
  var isSample = /^[.．・…]*$/.test(idPart) && (k !== 'CLASS' && k !== 'WEEKREPORT');
  return { kind: k, idPart: idPart, after: after, isSample: isSample };
}

// 先生がプロンプト（元データ）ごと貼ってしまったときにだけ現れる行。
// これが出たら、そこから先はAIの文章ではないので本文から切り離す。
var TAI_DATA_HEAD = [
  '▼ 児童データ',
  '【この1週間',
  '【ふだんの様子',
  '【テスト・成績',
  '【クラス平均との差',
  '【まもってほしいこと】',
  '【目印の種類】',
  '【児童ごとのデータの並び】',
  '【直近の学習記録',
  '【ポートフォリオ',
  '【先生の観察メモ',
  '【教科別の正答率',
  '【A】', '【B】', '【C】',
  '■ ',
  'あなたは小学校の担任の先生を手伝う'
];
function isDataLine(line) {
  // 区切り線は装飾を落とすと空になるので、先に生の行で見る
  var bare = String(line == null ? '' : line).replace(/[\s　]/g, '');
  if (/^[-=＝─―ー_]{10,}$/.test(bare)) return true;
  var s = stripDeco(line);
  if (!s) return false;
  for (var i = 0; i < TAI_DATA_HEAD.length; i++) {
    if (s.indexOf(TAI_DATA_HEAD[i]) === 0) return true;
  }
  return false;
}

// 目印ごとに切り分ける。
// ★ 読み取れなかった塊は、直前の児童の本文に吸収させず orphans へよける。
function _taiParse(raw) {
  var lines = String(raw || '').split(/\r?\n/);
  var blocks = [], orphans = [], cur = null, pre = [];
  function flush(arr, why, near) {
    var t = arr.join(NL).replace(/^\s+|\s+$/g, '');
    if (t) orphans.push({ why: why, near: near || '', text: t });
  }
  for (var i = 0; i < lines.length; i++) {
    var mk = matchMarker(lines[i]);
    if (mk) {
      if (cur) blocks.push(cur);
      else { flush(pre, '目印より前にあった文', ''); pre = []; }
      cur = { kind: mk.kind, idPart: mk.idPart, after: mk.after, isSample: mk.isSample, marker: lines[i], lines: [], cut: [] };
      continue;
    }
    if (!cur) { pre.push(lines[i]); continue; }
    if (cur.cut.length || isDataLine(lines[i])) { cur.cut.push(lines[i]); continue; }
    cur.lines.push(lines[i]);
  }
  if (cur) blocks.push(cur);
  else flush(pre, '目印より前にあった文', '');
  var out = [];
  for (var j = 0; j < blocks.length; j++) {
    var b = blocks[j];
    if (b.cut.length) {
      flush(b.cut, '目印のない余分な行（元データを一緒に貼った可能性）', b.marker);
    }
    out.push({
      kind: b.kind, idPart: b.idPart, after: b.after, isSample: b.isSample,
      marker: String(b.marker || '').replace(/^\s+|\s+$/g, ''),
      body: b.lines.join(NL).replace(/^\s+|\s+$/g, '')
    });
  }
  return { blocks: out, orphans: orphans };
}

function normId(s) {
  return String(s == null ? '' : s)
    .replace(/[Ａ-Ｚａ-ｚ０-９]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 65248); })
    .replace(/[\s　]/g, '').toLowerCase();
}
function normName(s) {
  return String(s == null ? '' : s)
    .replace(/[Ａ-Ｚａ-ｚ０-９]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 65248); })
    .replace(/[\s　・,，]/g, '')
    .replace(/(さん|くん|君|ちゃん|様|さま)$/, '')
    .toLowerCase();
}

// 名簿 → 突き合わせ用の人リスト
var _rosterPeople = [];
var _rosterCache = {};
function buildPeople(roster) {
  var arr = [];
  (roster || []).forEach(function (s) {
    var dn = nameOf(s.loginId, s.name) || s.name || s.loginId || '';
    arr.push({ uid: s.userId, name: String(dn), sei: String(dn).slice(0, 2), loginId: String(s.loginId || '') });
  });
  return arr;
}
async function ensureRoster(cid) {
  if (!cid) return;
  if (_rosterCache[cid]) { _rosterPeople = _rosterCache[cid]; return; }
  var rd = await postJson('/api/teacher/records/parse', { classId: cid, text: '' });
  var pp = buildPeople((rd && rd.roster) || []);
  if (pp.length) { _rosterCache[cid] = pp; _rosterPeople = pp; }
}

// 文章に「その子以外の実名」が入っていないか。
// strong = 赤字警告してチェックを外す / weak = 念のための注意
function scanOthers(body, selfUid, selfName, people) {
  var strong = [], weak = [], t = String(body || '');
  if (t.indexOf('=== [') >= 0 || t.indexOf('＝＝') >= 0) strong.push('目印らしい行');
  // KARTE_ANON_V1 符号（A07 など）が本文に残っていたら、紙に記号が載ってしまう。
  var _sym = t.match(/A[0-9]{2}/g);
  if (_sym && _sym.length) strong.push('符号 ' + _sym[0] + ' が本文に残っています');
  for (var i = 0; i < (people || []).length; i++) {
    var p = people[i];
    if (selfUid && p.uid === selfUid) continue;
    if (!selfUid && selfName && p.name === selfName) continue;
    if (p.name && p.name.length >= 2 && t.indexOf(p.name) >= 0) { strong.push(p.name); continue; }
    if (p.loginId && p.loginId.length >= 4 && /[A-Za-z]/.test(p.loginId) && t.indexOf(p.loginId) >= 0) { strong.push(p.loginId); continue; }
    if (p.sei && p.sei.length >= 2) {
      if (new RegExp(reEsc(p.sei) + '(さん|くん|君|ちゃん|さま|様)').test(t)) { strong.push(p.sei + 'さん'); continue; }
      if (t.indexOf(p.sei) >= 0) weak.push(p.sei);
    }
  }
  return { strong: strong, weak: weak };
}
function warnOf(d) {
  var k = KIND_JA[d.kind] || {};
  if (k.to !== 'kid') return { strong: [], weak: [] };   // 先生だけが読むものは名前が出て当然
  return scanOthers(d.body, d.targetId || '', d.targetName || '', _rosterPeople);
}

// 「どこにも割り当てなかったもの」を先生に見せる箱（HTMLは触らずJSで差し込む）
function holdBox(create) {
  var el = $('taiHoldBox');
  if (el || !create) return el;
  var anchor = $('taiStatus') || $('taiDraftList');
  if (!anchor || !anchor.parentNode) return null;
  el = document.createElement('div');
  el.id = 'taiHoldBox';
  el.className = 'mt-2';
  el.style.display = 'none';
  anchor.parentNode.insertBefore(el, anchor.nextSibling);
  return el;
}
function showHolds(holds) {
  var el = holdBox(true);
  if (!el) return;
  if (!holds || !holds.length) { el.innerHTML = ''; el.style.display = 'none'; return; }
  var h = '<div class="rounded-lg border-2 border-red-300 bg-red-50 p-2">' +
    '<div class="text-xs font-black text-red-700">⚠ どこにも割り当てなかったもの（' + holds.length + '件）</div>' +
    '<div class="text-[11px] text-red-700 mb-1">下の④には入れていません。貼り方を確かめて、目印と本文だけを貼り直してください。</div>' +
    '<ul class="text-[11px] text-red-800 list-disc pl-4 space-y-0.5">';
  holds.forEach(function (x) {
    h += '<li>' + esc(x.why) + (x.marker ? '｜' + esc(String(x.marker).slice(0, 60)) : '') +
      (x.detail ? '<div class="text-[10px] text-red-600 whitespace-pre-wrap">' + esc(x.detail) + '</div>' : '') + '</li>';
  });
  h += '</ul></div>';
  el.innerHTML = h;
  el.style.display = '';
}

// opts.append=true のときは、いまある下書きを消さずに追加する（1人だけ作り直すとき）
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
  if (!roster.length) { say2('名簿が取得できませんでした。取り込みを中止します'); return; }

  var map = {}, ambiguous = {}, nameMap = {};
  function put(key, uid) {
    if (!key) return;
    if (map[key] && map[key] !== uid) { ambiguous[key] = 1; return; }
    map[key] = uid;
  }
  roster.forEach(function (s) {
    var dn = nameOf(s.loginId, s.name) || s.name || s.loginId || '';
    // ★ 子どもが自由に変えられる表示名（s.name）はキーにしない。
    put(normId(s.loginId), s.userId);
    put(normId(s.userId), s.userId);
    put(normId(dn), s.userId);
    nameMap[s.userId] = dn;
  });
  _rosterPeople = buildPeople(roster);
  _rosterCache[cid] = _rosterPeople;

  var parsed = _taiParse(raw);
  var items = [], holds = [];
  function hold(why, marker, detail) { holds.push({ why: why, marker: marker || '', detail: detail || '' }); }

  parsed.orphans.forEach(function (o) {
    hold(o.why, o.near, o.text.length > 140 ? o.text.slice(0, 140) + '…' : o.text);
  });

  parsed.blocks.forEach(function (b) {
    var label = b.marker;
    if (b.isSample) { hold('貼り付ける前の説明文のようです', label, ''); return; }
    if (!b.body) { hold('本文が空でした', label, ''); return; }

    if (b.kind === 'CLASS' || b.kind === 'WEEKREPORT') {
      items.push({ kind: b.kind, targetId: '', targetName: '', refKey: '', body: b.body });
      return;
    }

    var afterName = String(b.after || '').split(/[｜|]/)[0].replace(/^\s+|\s+$/g, '');

    if (b.kind === 'DAILY') {
      if (!b.idPart) { hold('DAILY の提出が読み取れませんでした', label, ''); return; }
      if (!afterName) { hold('DAILY に氏名がなく、だれ宛てか確かめられません', label, ''); return; }
      items.push({ kind: 'DAILY', targetId: '', targetName: afterName, refKey: b.idPart, body: b.body });
      return;
    }

    var key = normId(b.idPart);
    if (!key) { hold('目印にIDがありません', label, ''); return; }
    if (ambiguous[key]) { hold('同じ名前・IDの子が複数いて、どちらか決められません', label, ''); return; }
    var uid = map[key];
    if (!uid) { hold('名簿に一致する児童が見つかりません', label, ''); return; }

    var expect = nameMap[uid] || '';
    // KARTE_ANON_V1 束では名前を符号(A07)に置きかえている。符号どうしで照合する。
    //   符号は完全一致で比べるので、氏名の部分一致より取り違えに強い。
    //   対応表が無いとき（翌日貼るなど）は、これまでどおり氏名で比べる。
    var _alMap = null;
    try { _alMap = JSON.parse(sessionStorage.getItem(TAI_ALIAS_KEY) || 'null'); } catch (e) {}
    var _af = String(afterName || '').trim();
    if (_alMap && /^A[0-9]{2}$/.test(_af)) {
      var _want = _alMap[uid] || '';
      if (_want && _af !== _want) {
        hold('符号と児童が食い違っています（ID→' + _want + ' ／ 目印には「' + _af + '」）', label, '');
        return;
      }
    } else if (afterName && expect) {
      var a = normName(afterName), e2 = normName(expect);
      if (a && e2 && a.indexOf(e2) < 0 && e2.indexOf(a) < 0) {
        hold('IDと氏名が食い違っています（ID→' + expect + ' ／ 目印には「' + afterName + '」）', label, '');
        return;
      }
    }
    items.push({ kind: b.kind, targetId: uid, targetName: expect, refKey: '', body: b.body });
  });

  // ★ ①で渡した欄の数よりも読み取れた欄が少ないときは、目印が消えている
  var _expect = 0;
  try { _expect = Number((window.__taiLast && window.__taiLast.blocks) || 0) || 0; } catch (e) {}
  if (!_expect) {
    try {
      var _o = JSON.parse(sessionStorage.getItem(CACHE_KEY) || 'null');
      if (_o && _o.blocks) _expect = Number(_o.blocks) || 0;
    } catch (e) {}
  }
  if (!appendMode && _expect && parsed.blocks.length < _expect) {
    hold('①で渡した欄は ' + _expect + '個ですが、返事から読み取れた欄は ' + parsed.blocks.length + '個です。目印が消えて、前の子の文にくっついているおそれがあります', '', '');
  }
  var risky = 0;
  items.forEach(function (it) {
    if (warnOf(it).strong.length) risky++;
  });

  if (!items.length) {
    showHolds(holds);
    say2('取り込めるものがありませんでした（読めた目印 ' + parsed.blocks.length + '件 ／ 保留 ' + holds.length + '件）');
    return;
  }

  var res = await postJson('/api/teacher/ai-drafts', {
    classId: cid, weekKey: weekKey(), replace: !appendMode, items: items
  });
  if (!res || !res.ok) { say2('下書きの保存に失敗しました'); return; }
  showHolds(holds);
  say2('✓ ' + res.saved + '件を下書きに' + (appendMode ? '追加' : '取り込み') + 'ました。' +
    (holds.length ? '⚠ ' + holds.length + '件は割り当てず保留しました（上の赤い枠）。' : '') +
    (risky ? '⚠ ' + risky + '件にほかの子の名前が入っている可能性があります。' : '') +
    '下の「④ 先生が確認して公開」を見てください');
  if (ta) ta.value = '';
  taiLoadDrafts();
}

// ===================================================================
// ④ 先生が確認して公開
// ===================================================================
// to: 'kid'=子どものアプリ画面に出る / 'paper'=紙のカルテに載る / 'teacher'=先生だけ
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
  try { await ensureRoster(cid); } catch (e) {}
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
  var dangerCount = 0;
  if (pend.length) {
    h += '<div class="flex items-center gap-2 mb-2 flex-wrap">' +
      '<button onclick="taiCheckAll(true)" class="bg-slate-200 text-slate-700 rounded px-2 py-1 text-xs font-bold hover:bg-slate-300">すべて選ぶ</button>' +
      '<button onclick="taiCheckAll(false)" class="bg-slate-200 text-slate-700 rounded px-2 py-1 text-xs font-bold hover:bg-slate-300">選択を外す</button>' +
      '<span class="text-xs text-slate-500">中身を読んで、直したいところは書きかえられます</span></div>';
    h += '<div class="space-y-2 max-h-[28rem] overflow-y-auto">';
    pend.forEach(function (x) {
      var k = KIND_JA[x.kind] || { ja: x.kind, to: '', badge: '' };
      var w = warnOf(x);
      x.__warn = w;
      var danger = w.strong.length > 0;
      if (danger) dangerCount++;
      var toCls = k.to === 'kid' ? 'bg-rose-100 text-rose-700' : (k.to === 'paper' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-600');
      h += '<div class="rounded-lg p-2 ' + (danger ? 'bg-red-50 border-2 border-red-400' : 'bg-white border border-slate-200') + '">' +
        '<div class="flex items-center gap-2 flex-wrap mb-1">' +
        '<input type="checkbox" class="tai-chk accent-indigo-600" data-id="' + esc(x.id) + '"' + (danger ? '' : ' checked') + '>' +
        '<span class="text-xs font-bold text-slate-700">' + esc(k.ja) + '</span>' +
        (x.targetName ? '<span class="text-xs text-slate-600">' + esc(x.targetName) + '</span>'
                      : '<span class="text-xs text-red-600 font-bold">氏名なし</span>') +
        (x.refLabel ? '<span class="text-[10px] text-slate-400">' + esc(x.refLabel) + '</span>' : '') +
        '<span class="text-[10px] px-1.5 py-0.5 rounded ' + toCls + '">' + esc(k.badge) + '</span>' +
        '</div>';
      if (danger) {
        h += '<div class="text-xs font-black text-red-700 mb-1">⚠ ほかの子の名前が入っているかもしれません：' +
          esc(w.strong.join('、')) +
          '<div class="font-bold">この文は' + esc(k.badge) + 'ため、チェックを外してあります。直してから公開してください。</div></div>';
      } else if (w.weak.length) {
        h += '<div class="text-[11px] font-bold text-amber-700 mb-1">△ 念のため確認：「' + esc(w.weak.join('」「')) + '」という言葉が入っています</div>';
      }
      h += '<textarea class="tai-body w-full border ' + (danger ? 'border-red-300' : 'border-slate-200') + ' rounded p-1.5 text-xs" rows="' +
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
  if (cEl) cEl.textContent = pend.length ? ('未公開 ' + pend.length + '件' + (dangerCount ? ' / ⚠要確認 ' + dangerCount + '件' : '')) : '';
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
      out.push({ id: id, kind: d.kind, targetId: d.targetId, targetName: d.targetName || '', refKey: d.refKey, body: ta ? ta.value : d.body });
    }
    return out;
  }

  async function taiPublish() {
    var cid = classId();
    var picks = collectChecked();
    if (!cid) { sayPub('クラスを選んでください'); return; }
    if (!picks.length) { sayPub('公開するものにチェックを入れてください'); return; }
      // ★ 公開の直前に、いま画面にある文章をもう一度見て、ほかの子の名前が残っていないか確かめる
  var _risky = picks.filter(function (p) {
    var kk = KIND_JA[p.kind] || {};
    if (kk.to !== 'kid') return false;
    return scanOthers(p.body, p.targetId || '', p.targetName || '', _rosterPeople).strong.length > 0;
  });
  if (_risky.length) {
    if (!confirm('⚠ ' + _risky.length + '件に、ほかの子の名前が入っているかもしれません。\nこのまま公開すると、その文は子どもの画面に出ます。\n本当に公開しますか？')) {
      sayPub('公開をやめました。赤い警告のところを直してから、もう一度おしてください');
      return;
    }
  }
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
      // どの週について書いたカルテかを一緒に送る。サーバが本文と並べて保存し、
      // 紙のカルテの見出しもこの週を使う（印刷日から逆算するのをやめたので、
      // 金曜に作って月曜に配ってもズレない）。
      var _pw = lastWeekDaysJst();
      var r2 = await postJson('/api/teacher/student-ai-comments', {
        weekStart: _pw[0], weekEnd: _pw[4],
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
  function isMondayJst() { return jstNow().getDay() === 1; }

// 月曜は「計画アドバイス」を既定でONにする（金曜の振り返り返却と同じ作法）
function applyMonday() {
  if (!isMondayJst()) return;
  var cb = $('taiOptPlan');
  if (!cb || cb.getAttribute('data-mon')) return;
  cb.setAttribute('data-mon', '1');
  cb.checked = true;
  if ($('taiMonNote')) return;
  var row = cb.parentNode && cb.parentNode.parentNode;
  if (!row || !row.parentNode) return;
  var note = document.createElement('div');
  note.id = 'taiMonNote';
  note.className = 'bg-sky-50 border border-sky-200 rounded-lg px-2 py-1.5 text-xs text-sky-800 font-bold mb-2';
  note.textContent = '\U0001F4C5 今日は月曜日です。「今週の計画へのアドバイス」も入れてあります。子どもが計画を出しおわってから①を押してください。';
  row.parentNode.insertBefore(note, row.nextSibling);
}

// 押す前に「いま何人ぶんの材料があるか」を見せる。
// 2026-09-08 は、子どもが計画を書く2時間半前にコピーしたため、22人中4人ぶんしか出なかった。
function matBox(create) {
  var el = $('taiMatBox');
  if (el || !create) return el;
  var anchor = $('taiStatus') || $('taiDraftList');
  if (!anchor || !anchor.parentNode) return null;
  el = document.createElement('div');
  el.id = 'taiMatBox';
  el.className = 'mb-2';
  el.style.display = 'none';
  anchor.parentNode.insertBefore(el, anchor);
  return el;
}
async function taiShowMaterials(cid) {
  var el = matBox(true);
  if (!el || !cid) return;
  var total = (_rosterPeople || []).length;
  var planN = 0, reflN = 0, hwN = 0, ok = false;
  try {
    var pd = await getJson('/api/teacher/weekly-plans?weekKey=' + encodeURIComponent(weekKey()) + '&classId=' + encodeURIComponent(cid));
    ((pd && pd.plans) || []).forEach(function (p) {
      var o = {};
      try { o = JSON.parse(p.plansJson || '{}'); } catch (e) {}
      var wrote = false, refl = false;
      Object.keys(o).forEach(function (k) {
        if (k === '_modified') return;
        var v = o[k];
        var tx = (v && typeof v === 'object') ? (v.free || '') : (v || '');
        if (String(tx).trim()) wrote = true;
        if (v && typeof v === 'object' && String(v.reflection || '').trim()) refl = true;
      });
      if (wrote) planN++;
      if (refl) reflN++;
    });
    ok = true;
  } catch (e) {}
  try {
    var hd = await getJson('/api/teacher/homework?classId=' + encodeURIComponent(cid));
    var seen = {};
    ((hd && hd.submissions) || []).forEach(function (s) {
      if (!s.returnedAt && s.userId && !seen[s.userId]) { seen[s.userId] = 1; hwN++; }
    });
    ok = true;
  } catch (e) {}
  if (!ok) { el.style.display = 'none'; return; }
  var warn = !!(total && planN < total);
  var tone = warn ? 'amber' : 'emerald';
  var h = '<div class="rounded-lg border-2 border-' + tone + '-300 bg-' + tone + '-50 p-2">';
  h += '<div class="text-xs font-black text-' + tone + '-800">\U0001F4CA いま何人ぶんの材料があるか</div>';
  h += '<ul class="text-[11px] text-' + tone + '-800 list-disc pl-4 mt-1 space-y-0.5">';
  h += '<li>今週の計画を書いているのは <b>' + total + '人中 ' + planN + '人</b> です（計画アドバイス）</li>';
  h += '<li>まだ返していない家庭学習は <b>' + hwN + '人ぶん</b> です（家庭学習コメント）</li>';
  h += '<li>今週の振り返りを書いているのは <b>' + reflN + '人</b> です（振り返りの返却）</li>';
  h += '</ul>';
  if (warn) {
    h += '<div class="text-[11px] font-bold text-amber-800 mt-1">全員ぶん出すなら、提出がそろってから①を押してください。いま押すと、書いている子のぶんしか出ません。</div>';
  }
  h += '</div>';
  el.innerHTML = h;
  el.style.display = '';
}

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
  applyMonday();
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
