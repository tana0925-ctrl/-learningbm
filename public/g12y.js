/* ============================================================
   小学校 修行 追加パック g12y v1（2026-11-19）1・2年の 足りない 単元を 追加
   算数1年：かずと すうじ・なんばんめ・いくつと いくつ・とけい・おおきい かず（100まで）・かたちと ながさ
   算数2年：時こくと時間・1000までの数・かさ・長さ（m）・三角形と四角形・はこの形・分数・ひょうとグラフ
   国語1年：カタカナ・「は・を・へ」　国語2年：なかまの ことば・はんたいの ことば・かたかなで 書く ことば
   ※ 問題文は すべて オリジナル。public/index.html は 変えずに window 経由で 足す
   ============================================================ */
(function () {
  if (window.__G12Y__) return;
  window.__G12Y__ = 1;
  var R = function (a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; };
  var P = function (a) { return a[R(0, a.length - 1)]; };
  var bank = function (b) { return (typeof _pickBank === 'function') ? _pickBank(b) : null; };
  var Q = function (q, correct, wrongs) { return { q: q, correct: correct, wrongs: wrongs }; };
  var EMO = ['🍎', '🐟', '🌸', '⭐', '🚗', '🐤', '🍙', '⚽'];

  /* ═════════════ 算数 1年 ═════════════ */
  window.genKazu1 = function () {
    var p = R(0, 4), n = R(1, 10), e = P(EMO);
    if (p === 0) return { q: 'いくつ あるかな？\n' + Array(n + 1).join(e), ans: n };
    if (p === 1) { var a = R(1, 9); return { q: a + ' と いくつで 10？', ans: 10 - a }; }
    if (p === 2) { var t = R(3, 9), b = R(1, t - 1); return { q: t + ' は ' + b + ' と いくつ？', ans: t - b }; }
    if (p === 3) { var x = R(1, 9), y = R(1, 9); if (x === y) y = x % 9 + 1; return bank([Q(x + ' と ' + y + '、おおきいのは どっち？', String(Math.max(x, y)), [String(Math.min(x, y)), 'おなじ', 'わからない'])]); }
    return { q: '0 は いくつ ない こと？\n「りんごが 0こ」は りんごが いくつ？', ans: 0 };
  };
  window.genBanme1 = function () {
    var arr = EMO.slice().sort(function () { return Math.random() - 0.5; }).slice(0, 6), k = R(1, 6), p = R(0, 2);
    if (p === 0) return bank([Q('まえから ' + k + 'ばんめは どれ？\n（まえ）' + arr.join(' ') + '（うしろ）', arr[k - 1], arr.filter(function (x, i) { return i !== k - 1; }).slice(0, 3))]);
    if (p === 1) return bank([Q('うしろから ' + k + 'ばんめは どれ？\n（まえ）' + arr.join(' ') + '（うしろ）', arr[6 - k], arr.filter(function (x, i) { return i !== 6 - k; }).slice(0, 3))]);
    var t = R(5, 9), m = R(2, t - 1); return { q: t + 'にん ならんで います。まえから ' + m + 'ばんめの 人は、\nうしろから なんばんめ？', ans: t - m + 1 };
  };
  window.genTokei1 = function () {
    var h = R(1, 12), p = R(0, 3), m = P([0, 30]);
    if (p === 0) return bank([Q('みじかい はりが ' + h + '、ながい はりが 12 を さして います。\nなんじ？', h + 'じ', [(h % 12 + 1) + 'じ', h + 'じはん', ((h + 5) % 12 + 1) + 'じ'])]);
    if (p === 1) return bank([Q('みじかい はりが ' + h + ' と ' + (h % 12 + 1) + ' の あいだ、ながい はりが 6。\nなんじ なんぷん？', h + 'じはん', [(h % 12 + 1) + 'じはん', h + 'じ', h + 'じ6ふん'])]);
    if (p === 2) { var mm = R(1, 11) * 5; return { q: 'ながい はりが ' + (mm / 5) + ' を さして います。\nなんぷん？', ans: mm }; }
    return { q: '1じかん は なんぷん？', ans: 60 };
  };
  window.genOokii1 = function () {
    var p = R(0, 4), a;
    if (p === 0) { a = R(2, 9); var b = R(0, 9); return { q: '10が ' + a + 'こ と 1が ' + b + 'こ で いくつ？', ans: a * 10 + b }; }
    if (p === 1) { a = R(21, 99); return { q: a + ' の 十のくらいの すうじは？', ans: Math.floor(a / 10) }; }
    if (p === 2) { a = R(20, 98); return { q: a + ' より 1 おおきい かずは？', ans: a + 1 }; }
    if (p === 3) { a = R(2, 9) * 10; var c = R(1, 9) * 10; return { q: a + ' ＋ ' + c + ' ＝ ？', ans: a + c }; }
    return { q: '10が 10こ で いくつ？', ans: 100 };
  };
  var KATA1 = [
    Q('まるい かたちは どれ？', '⭕', ['🔺', '🟦', '⬛']), Q('さんかくの かたちは どれ？', '🔺', ['⭕', '🟦', '⭐']), Q('しかくの かたちは どれ？', '🟦', ['⭕', '🔺', '❤️']),
    Q('ころがりやすい かたちは？', 'ボールの かたち', ['はこの かたち', 'さいころの かたち', 'いたの かたち']), Q('つみやすい かたちは？', 'はこの かたち', ['ボールの かたち', 'まるい かたち', 'たまごの かたち']),
    Q('ながさを くらべる とき、はしを どう する？', 'そろえる', ['ずらす', 'まげる', 'かくす']), Q('えんぴつ A は マス 5こぶん、B は マス 7こぶん。ながいのは？', 'B', ['A', 'おなじ', 'わからない'])
  ];
  window.genKatachi1 = function () { return bank(KATA1); };

  /* ═════════════ 算数 2年 ═════════════ */
  window.genJikan2 = function () {
    var p = R(0, 3), h = R(7, 16), m = R(0, 5) * 10, d = R(1, 5) * 10;
    if (p === 0) return { q: '1時間は 何分？', ans: 60 };
    if (p === 1) return { q: '1日は 何時間？', ans: 24 };
    if (p === 2) return { q: h + '時' + (m ? m + '分' : '') + ' から ' + d + '分後は 何時何分？\n（「分」だけ 答えよう）', ans: (m + d) % 60 };
    return bank([P([Q('午前と 午後は それぞれ 何時間？', '12時間', ['24時間', '6時間', '10時間']), Q('正午は 何時？', '昼の 12時', ['夜の 12時', '朝の 6時', '昼の 1時']), Q('午前8時から 午前11時までは 何時間？', '3時間', ['2時間', '4時間', '11時間'])])]);
  };
  window.genSen2 = function () {
    var p = R(0, 4), a;
    if (p === 0) { var h = R(1, 9), t = R(0, 9), o = R(0, 9); return { q: '100を ' + h + 'こ、10を ' + t + 'こ、1を ' + o + 'こ あわせた 数は？', ans: h * 100 + t * 10 + o }; }
    if (p === 1) { a = R(101, 999); return { q: a + ' の 百のくらいの 数字は？', ans: Math.floor(a / 100) }; }
    if (p === 2) { a = R(2, 9) * 100; var b = R(1, 9) * 100; if (a + b > 1000) b = 1000 - a; return { q: a + ' ＋ ' + b + ' ＝ ？', ans: a + b }; }
    if (p === 3) { a = R(11, 99); return { q: '10を ' + a + 'こ 集めた 数は？', ans: a * 10 }; }
    return { q: '100を 10こ 集めた 数は？', ans: 1000 };
  };
  window.genKasa2 = function () {
    var p = R(0, 4), a = R(1, 9);
    if (p === 0) return { q: a + 'L は 何dL？', ans: a * 10 };
    if (p === 1) return { q: a + 'dL は 何mL？', ans: a * 100 };
    if (p === 2) return { q: '1L は 何mL？', ans: 1000 };
    if (p === 3) { var b = R(1, 9); return { q: a + 'L' + b + 'dL は 何dL？', ans: a * 10 + b }; }
    var m = R(1, 9); return { q: m + 'm は 何cm？', ans: m * 100 };
  };
  var SANKAKU2 = [
    Q('3本の 直線で かこまれた 形は？', '三角形', ['四角形', '円', '五角形']), Q('4本の 直線で かこまれた 形は？', '四角形', ['三角形', '円', '六角形']),
    Q('四角形の 頂点の 数は？', '4', ['3', '5', '6']), Q('三角形の 辺の 数は？', '3', ['4', '2', '5']),
    Q('かどが みんな 直角の 四角形は？', '長方形（か 正方形）', ['台形', '三角形', 'ひし形']), Q('かどが みんな 直角で、辺の 長さも みんな 同じ 四角形は？', '正方形', ['長方形', '三角形', '平行四辺形']),
    Q('直角の かどが ある 三角形は？', '直角三角形', ['正三角形', '二等辺三角形', '四角形']),
    Q('はこの 形の 面の 数は？', '6', ['4', '8', '12']), Q('はこの 形の 辺の 数は？', '12', ['6', '8', '4']), Q('はこの 形の 頂点の 数は？', '8', ['6', '12', '4']),
    Q('さいころの 形の 面は どんな 形？', '正方形', ['長方形', '三角形', '円']), Q('円を 半分に 2回 おって できる 大きさは もとの 何分の1？', '4分の1', ['2分の1', '8分の1', '3分の1']),
    Q('もとの 大きさを 同じ 大きさに 2つに 分けた 1つ分は？', '2分の1', ['4分の1', '3分の1', '2倍']), Q('ひょうと グラフで、いちばん 多い ものを 見つけやすいのは？', 'グラフ', ['ひょう', 'どちらも 同じ', 'わからない'])
  ];
  window.genSankaku2 = function () { return bank(SANKAKU2); };

  /* ═════════════ 国語 1・2年 ═════════════ */
  var KATAKANA = [['あ', 'ア'], ['い', 'イ'], ['う', 'ウ'], ['え', 'エ'], ['お', 'オ'], ['か', 'カ'], ['き', 'キ'], ['く', 'ク'], ['け', 'ケ'], ['こ', 'コ'], ['さ', 'サ'], ['し', 'シ'], ['す', 'ス'], ['せ', 'セ'], ['そ', 'ソ'], ['た', 'タ'], ['ち', 'チ'], ['つ', 'ツ'], ['て', 'テ'], ['と', 'ト'], ['な', 'ナ'], ['に', 'ニ'], ['ぬ', 'ヌ'], ['ね', 'ネ'], ['の', 'ノ'], ['は', 'ハ'], ['ひ', 'ヒ'], ['ふ', 'フ'], ['へ', 'ヘ'], ['ほ', 'ホ'], ['ま', 'マ'], ['み', 'ミ'], ['む', 'ム'], ['め', 'メ'], ['も', 'モ'], ['や', 'ヤ'], ['ゆ', 'ユ'], ['よ', 'ヨ'], ['ら', 'ラ'], ['り', 'リ'], ['る', 'ル'], ['れ', 'レ'], ['ろ', 'ロ'], ['わ', 'ワ'], ['を', 'ヲ'], ['ん', 'ン']];
  var NIGATE = { 'シ': ['ツ', 'ソ', 'ン'], 'ツ': ['シ', 'ソ', 'ン'], 'ソ': ['ン', 'シ', 'ツ'], 'ン': ['ソ', 'シ', 'ツ'], 'ク': ['ワ', 'ケ', 'タ'], 'ワ': ['ウ', 'ク', 'フ'], 'ヌ': ['メ', 'ス', 'マ'], 'メ': ['ヌ', 'ナ', 'X'.replace('X', 'ノ')], 'ア': ['マ', 'ヤ', 'ス'], 'マ': ['ア', 'ム', 'ヌ'] };
  var JOSHI = [
    Q('ただしい 文は？', 'わたしは こうえんへ いきます。', ['わたしわ こうえんえ いきます。', 'わたしは こうえんえ いきます。', 'わたしわ こうえんへ いきます。']),
    Q('ただしい 文は？', 'ほんを よみます。', ['ほんお よみます。', 'ほんわ よみます。', 'ほんへ よみます。']),
    Q('「がっこう（　）いく。」 に はいる ひらがなは？', 'へ', ['え', 'わ', 'お']), Q('「おにぎり（　）たべる。」 に はいる ひらがなは？', 'を', ['お', 'は', 'へ']),
    Q('「ぼく（　）いちねんせいです。」 に はいる ひらがなは？', 'は', ['わ', 'を', 'え']), Q('「。」の なまえは？', 'まる（くてん）', ['てん', 'かぎ', 'なかてん']),
    Q('はなした ことばを かこむ 記号は？', '「　」（かぎ）', ['。（まる）', '、（てん）', '？']), Q('小さく かく じは？', 'きって の「っ」', ['きつね の「つ」', 'つき の「つ」', 'くつ の「つ」'])
  ];
  window.genKana1 = function () {
    if (R(0, 2) === 0) return bank(JOSHI);
    var k = P(KATAKANA), w = NIGATE[k[1]] || KATAKANA.filter(function (x) { return x !== k; }).sort(function () { return Math.random() - 0.5; }).slice(0, 3).map(function (x) { return x[1]; });
    return R(0, 1) ? bank([Q('「' + k[0] + '」の カタカナは？', k[1], w)]) : bank([Q('カタカナ「' + k[1] + '」の ひらがなは？', k[0], KATAKANA.filter(function (x) { return x !== k; }).sort(function () { return Math.random() - 0.5; }).slice(0, 3).map(function (x) { return x[0]; }))]);
  };
  var KOTOBA2 = [
    Q('「りんご・みかん・ぶどう」を まとめた ことばは？', 'くだもの', ['やさい', 'のみもの', 'おかし']), Q('「赤・青・黄色」を まとめた ことばは？', '色', ['形', '天気', '音']),
    Q('「犬・ねこ・うさぎ」を まとめた ことばは？', 'どうぶつ', ['しょくぶつ', 'のりもの', '虫']), Q('「バス・電車・ひこうき」を まとめた ことばは？', 'のりもの', ['どうぶつ', 'たてもの', 'がっき']),
    Q('なかまで ない ものは？（くだもの）', 'にんじん', ['もも', 'バナナ', 'いちご']), Q('「大きい」の はんたいの ことばは？', '小さい', ['長い', '高い', '多い']),
    Q('「あつい」の はんたいの ことばは？', 'さむい', ['あたたかい', 'すずしい', 'ひくい']), Q('「上る」の はんたいの ことばは？', '下る', ['走る', '入る', '進む']),
    Q('「おもい」の はんたいの ことばは？', 'かるい', ['大きい', 'ながい', 'つよい']), Q('かたかなで 書く ことばは？', 'チョコレート', ['ちょこれえと', 'ちょこ', 'ちょうこう']),
    Q('かたかなで 書く ことば（ものの 音）は？', 'ワンワン', ['わんわん（ひらがなの まま）', 'いぬ', 'なく']), Q('かたかなで 書く ことば（外国の 国や 地名）は？', 'アメリカ', ['あめりか', '米', 'くに']),
    Q('「白い 雲が うかぶ。」の「だれが（何が）」は？', '雲が', ['白い', 'うかぶ', '白い 雲']), Q('「ぼくは 走る。」の「どうする」は？', '走る', ['ぼくは', 'ぼく', 'は'])
  ];
  window.genKotoba2 = function () { return bank(KOTOBA2); };

  var ADD = {
    math: {
      1: [
        { id: 'm1-kazu', name: 'かずと すうじ・いくつと いくつ', icon: '🍎', color: 'red', gen: 'genKazu1', input: 'numpad', desc: '10までの かず・10の あわせかた' },
        { id: 'm1-banme', name: 'なんばんめ', icon: '🚃', color: 'green', gen: 'genBanme1', input: 'numpad', desc: 'まえから・うしろから' },
        { id: 'm1-tokei', name: 'とけい', icon: '🕐', color: 'orange', gen: 'genTokei1', input: 'numpad', desc: 'なんじ・なんじはん' },
        { id: 'm1-ookii', name: 'おおきい かず（100まで）', icon: '💯', color: 'blue', gen: 'genOokii1', input: 'numpad', desc: '十のくらい・一のくらい' },
        { id: 'm1-katachi', name: 'かたちと ながさ', icon: '🔺', color: 'purple', gen: 'genKatachi1', input: 'mcq', desc: 'まる・さんかく・しかく' }
      ],
      2: [
        { id: 'm2-jikan', name: '時こくと時間', icon: '🕑', color: 'orange', gen: 'genJikan2', input: 'numpad', desc: '1時間＝60分・午前と午後' },
        { id: 'm2-sen', name: '1000までの数', icon: '🔢', color: 'blue', gen: 'genSen2', input: 'numpad', desc: '百のくらい' },
        { id: 'm2-kasa', name: 'かさ・長さ（m）', icon: '🥛', color: 'teal', gen: 'genKasa2', input: 'numpad', desc: 'L・dL・mL・m・cm' },
        { id: 'm2-sankaku', name: '三角形と四角形・はこの形・分数', icon: '🔷', color: 'purple', gen: 'genSankaku2', input: 'mcq', desc: '直角・長方形・正方形・2分の1' }
      ]
    },
    japanese: {
      1: [{ id: 'j1-kana', name: 'カタカナ・「は・を・へ」', icon: '🅰️', color: 'pink', gen: 'genKana1', input: 'mcq', desc: 'カタカナと 文の きまり' }],
      2: [{ id: 'j2-kotoba', name: 'なかま・はんたいの ことば', icon: '🔗', color: 'green', gen: 'genKotoba2', input: 'mcq', desc: 'まとめる ことば・かたかな・主語と述語' }]
    }
  };
  var DISP = {
    'm1-kazu': { name: 'りんごの 木', emoji: '🍎', desc: 'かずと すうじ' }, 'm1-banme': { name: 'ならびの 駅', emoji: '🚃', desc: 'なんばんめ' }, 'm1-tokei': { name: 'とけいの 森', emoji: '🕐', desc: 'とけい' }, 'm1-ookii': { name: '100の 山', emoji: '💯', desc: 'おおきい かず' }, 'm1-katachi': { name: 'かたちの 原っぱ', emoji: '🔺', desc: 'かたち' },
    'm2-jikan': { name: '時間の 川', emoji: '🕑', desc: '時こくと時間' }, 'm2-sen': { name: '千の 丘', emoji: '🔢', desc: '1000までの数' }, 'm2-kasa': { name: 'みずの 泉', emoji: '🥛', desc: 'かさ・長さ' }, 'm2-sankaku': { name: 'かたちの 遺跡', emoji: '🔷', desc: '三角形と四角形' },
    'j1-kana': { name: 'カタカナの 小道', emoji: '🅰️', desc: 'カタカナ' }, 'j2-kotoba': { name: 'ことばの 輪', emoji: '🔗', desc: 'なかまの ことば' }
  };
  var LABEL = { 1: '小1', 2: '小2', 3: '小3', 4: '小4', 5: '小5', 6: '小6' };
  function addAll() {
    try {
      var C = window.CURRICULUM; if (!C) return false;
      Object.keys(ADD).forEach(function (sk) {
        var S = C[sk]; if (!S) return; S.grades = S.grades || {};
        Object.keys(ADD[sk]).forEach(function (g) {
          var G = S.grades[g]; if (!G) G = S.grades[g] = { label: LABEL[g] || g, units: [] };
          var have = {}; G.units.forEach(function (u) { have[u.id] = 1; });
          ADD[sk][g].forEach(function (u) { if (!have[u.id]) G.units.push(u); });
        });
      });
      window.UNIT_DISPLAY = window.UNIT_DISPLAY || {};
      Object.keys(DISP).forEach(function (k) { if (!window.UNIT_DISPLAY[k]) window.UNIT_DISPLAY[k] = DISP[k]; });
      return true;
    } catch (e) { return false; }
  }
  if (!addAll()) { var tries = 0, t = setInterval(function () { if (addAll() || ++tries > 40) clearInterval(t); }, 250); }
})();
