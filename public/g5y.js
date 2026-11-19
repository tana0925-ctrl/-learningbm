/* ============================================================
   小学校 修行 追加パック g5y v1（2026-11-19）5年の 足りない 単元を 追加
   算数：整数の性質・合同な図形・分数のたし算ひき算・分数と小数・図形の面積・正多角形と円周・
         角柱と円柱・割合のグラフ（帯・円）・比例と変わり方
   英語（小5・新設）：5年の 単語・誕生日と月・できること（can）・道案内と場所・ほしいもの／注文
   ※ 問題文は すべて オリジナル。public/index.html は 変えずに window 経由で 足す（g6x と 同じ やり方）
   ============================================================ */
(function () {
  if (window.__G5Y__) return;
  window.__G5Y__ = 1;
  var R = function (a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; };
  var P = function (a) { return a[R(0, a.length - 1)]; };
  var bank = function (b) { return (typeof _pickBank === 'function') ? _pickBank(b) : null; };
  var Q = function (q, correct, wrongs) { return { q: q, correct: correct, wrongs: wrongs }; };
  var gcd = function (a, b) { while (b) { var t = a % b; a = b; b = t; } return a; };
  var lcm = function (a, b) { return a / gcd(a, b) * b; };
  var fr = function (n, d) { var g = gcd(n, d); n /= g; d /= g; if (d === 1) return String(n); if (n > d) { var w = Math.floor(n / d); return w + 'と' + (n - w * d) + '/' + d; } return n + '/' + d; };
  var mcq = function (q, ok, wrongs) { var w = []; wrongs.forEach(function (x) { if (x !== ok && w.indexOf(x) < 0) w.push(x); }); while (w.length < 3) w.push(String(R(2, 30)) + '/' + R(31, 40)); return bank([Q(q, ok, w.slice(0, 3))]); };

  /* ═════════════ 算数 5年 ═════════════ */
  window.genSeishitsu5 = function () {
    var p = R(0, 7), a, b;
    if (p === 0) { a = R(2, 9); var n = R(2, 6); return { q: a + 'の 倍数を 小さい 順に ならべた とき、' + n + '番目の 数は？', ans: a * n }; }
    if (p === 1) { a = P([2, 3, 4, 6]); b = P([3, 4, 5, 6, 8, 9]); if (a === b) b = a + 1; return { q: a + 'と ' + b + 'の 最小公倍数は？', ans: lcm(a, b) }; }
    if (p === 2) { var g = P([2, 3, 4, 6]); a = g * R(2, 5); b = g * R(2, 7); if (a === b) b += g; return { q: a + 'と ' + b + 'の 最大公約数は？', ans: gcd(a, b) }; }
    if (p === 3) { a = P([12, 18, 20, 24, 16, 30, 36]); var c = 0; for (var i = 1; i <= a; i++) if (a % i === 0) c++; return { q: a + 'の 約数は 全部で いくつ ある？', ans: c }; }
    if (p === 4) { a = R(2, 5); b = R(6, 9); return { q: 'たて ' + a + 'cm・横 ' + b + 'cm の 長方形の 紙を すきまなく ならべて、\nできるだけ 小さい 正方形を つくります。1辺は 何cm？', ans: lcm(a, b) }; }
    if (p === 5) { var g2 = P([3, 4, 6]); a = g2 * R(2, 4); b = g2 * R(5, 7); return { q: 'あめ ' + a + 'こと クッキー ' + b + 'こを、それぞれ 同じ 数ずつ\nあまりなく 分けます。できるだけ 多くの 人に 分けると 何人？', ans: gcd(a, b) }; }
    if (p === 6) { a = R(2, 4); b = R(5, 6); return { q: '東駅から バスが ' + a + '分ごと、電車が ' + b + '分ごとに 出ます。\n9時に 同時に 出ました。次に 同時に 出るのは 何分後？', ans: lcm(a, b) }; }
    return bank([P([Q('偶数は どれ？', '38', ['27', '15', '41']), Q('奇数は どれ？', '53', ['40', '18', '72']), Q('0は 偶数？ 奇数？', '偶数', ['奇数', 'どちらでもない', '両方']), Q('2で わりきれない 整数を 何と いう？', '奇数', ['偶数', '倍数', '約数'])])]);
  };

  var GOUDOU = [
    Q('形も 大きさも 同じで、ぴったり 重なる 図形を 何と いう？', '合同な 図形', ['拡大図', '縮図', '線対称な 図形']),
    Q('合同な 図形で、重なり合う 辺を 何と いう？', '対応する 辺', ['等しい 辺', '底辺', '対角線']),
    Q('合同な 図形で、対応する 辺の 長さは？', '等しい', ['2倍', 'ちがう', '半分']),
    Q('合同な 図形で、対応する 角の 大きさは？', '等しい', ['2倍', 'ちがう', '90°']),
    Q('三角形の 3つの 角の 大きさの 和は？', '180°', ['360°', '90°', '270°']),
    Q('四角形の 4つの 角の 大きさの 和は？', '360°', ['180°', '540°', '720°']),
    Q('五角形の 角の 大きさの 和は？', '540°', ['360°', '720°', '450°']),
    Q('六角形の 角の 大きさの 和は？', '720°', ['540°', '900°', '600°']),
    Q('合同な 三角形を かく ための 条件に ならない ものは？', '3つの 角の 大きさ', ['3つの 辺の 長さ', '2つの 辺と その 間の 角', '1つの 辺と その 両はしの 角']),
    Q('平行四辺形に 対角線を 1本 引くと、できる 2つの 三角形は？', '合同', ['大きさが ちがう', '形が ちがう', '直角三角形に なる']),
    Q('長方形に 2本の 対角線を 引くと、合同な 三角形は 何組 できる？（4つの 小さい 三角形で 考える）', '2組', ['4組', '1組', '0組']),
    Q('正方形の 2本の 対角線で できる 4つの 三角形は？', 'すべて 合同', ['2つずつ 合同', 'どれも 合同でない', '1つだけ 大きい'])
  ];
  window.genGoudou5 = function () {
    if (R(0, 2)) return bank(GOUDOU);
    var a = R(30, 80), b = R(30, 150 - a); if (R(0, 1)) return { q: '三角形の 2つの 角が ' + a + '° と ' + b + '° です。\nのこりの 角は 何度？', ans: 180 - a - b };
    var c = R(60, 120), d = R(60, 120), e = R(50, 100); return { q: '四角形の 3つの 角が ' + c + '°・' + d + '°・' + e + '° です。\nのこりの 角は 何度？', ans: 360 - c - d - e };
  };

  window.genFracAdd5 = function () {
    var d1 = P([2, 3, 4, 5, 6]), d2 = P([3, 4, 6, 8, 10]); if (d1 === d2) d2 = d1 * 2;
    var n1 = R(1, d1 - 1), n2 = R(1, d2 - 1), L = lcm(d1, d2), sub = R(0, 1);
    if (sub && n1 * L / d1 <= n2 * L / d2) { var t = n1; n1 = n2; n2 = t; t = d1; d1 = d2; d2 = t; }
    if (sub && n1 * L / d1 <= n2 * L / d2) sub = 0;
    var N = sub ? n1 * L / d1 - n2 * L / d2 : n1 * L / d1 + n2 * L / d2;
    var ok = fr(N, L);
    var w = [fr(n1 + (sub ? -n2 : n2) > 0 ? n1 + (sub ? -n2 : n2) : n1 + n2, d1 + d2), fr(N + 1, L), fr(Math.max(1, N - 1), L)];
    return mcq(n1 + '/' + d1 + (sub ? ' − ' : ' ＋ ') + n2 + '/' + d2 + ' ＝ ？\n（答えは 約分して、1より 大きい ときは 帯分数）', ok, w);
  };

  window.genFracDec5 = function () {
    var p = R(0, 4);
    if (p === 0) { var x = P([[1, 2, 0.5], [1, 4, 0.25], [3, 4, 0.75], [1, 5, 0.2], [2, 5, 0.4], [3, 5, 0.6], [4, 5, 0.8], [1, 8, 0.125], [3, 8, 0.375], [7, 10, 0.7]]); return { q: x[0] + '/' + x[1] + ' を 小数で 表すと？', ans: x[2] }; }
    if (p === 1) { var y = P([[0.3, '3/10'], [0.7, '7/10'], [0.25, '1/4'], [0.5, '1/2'], [0.6, '3/5'], [0.75, '3/4'], [0.2, '1/5'], [0.9, '9/10']]); return mcq(y[0] + ' を 分数で 表すと？（約分した 形）', y[1], ['1/' + Math.round(y[0] * 10), y[0] * 10 + '/100', '10/' + Math.round(y[0] * 10)]); }
    if (p === 2) { var a = R(1, 7), b = a + R(1, 5); if (gcd(a, b) > 1) b++; if (gcd(a, b) > 1) b++; return mcq(a + ' ÷ ' + b + ' の 商を 分数で 表すと？', a + '/' + b, [b + '/' + a, a + '/' + (b * 10), (a + b) + '/' + b]); }
    if (p === 3) { var n = R(2, 9); return mcq('整数の ' + n + ' を 分母が 1の 分数で 表すと？', n + '/1', ['1/' + n, n + '/' + n, n + '/10']); }
    var f = P([['3/5', '0.5', '3/5'], ['0.7', '3/4', '3/4'], ['2/3', '0.6', '2/3'], ['0.3', '1/4', '0.3'], ['5/8', '0.6', '5/8']]); return mcq(f[0] + ' と ' + f[1] + ' で 大きいのは？', f[2], [f[2] === f[0] ? f[1] : f[0], '同じ', 'くらべられない']);
  };

  window.genMenseki5 = function () {
    var p = R(0, 5), a, b, h;
    if (p === 0) { a = R(3, 12); h = R(2, 10); return { q: '底辺 ' + a + 'cm・高さ ' + h + 'cm の 平行四辺形の 面積は 何cm²？', ans: a * h }; }
    if (p === 1) { a = R(2, 12); h = R(2, 10); if ((a * h) % 2) a++; return { q: '底辺 ' + a + 'cm・高さ ' + h + 'cm の 三角形の 面積は 何cm²？', ans: a * h / 2 }; }
    if (p === 2) { a = R(2, 8); b = a + R(1, 6); h = R(2, 8); if (((a + b) * h) % 2) h++; return { q: '上底 ' + a + 'cm・下底 ' + b + 'cm・高さ ' + h + 'cm の 台形の 面積は 何cm²？', ans: (a + b) * h / 2 }; }
    if (p === 3) { a = R(2, 10) * 2; b = R(2, 10); return { q: '対角線が ' + a + 'cm と ' + b + 'cm の ひし形の 面積は 何cm²？', ans: a * b / 2 }; }
    if (p === 4) { a = R(3, 12); h = R(2, 9); return { q: '面積が ' + (a * h) + 'cm² で、底辺が ' + a + 'cm の 平行四辺形の 高さは 何cm？', ans: h }; }
    return bank([P([Q('三角形の 面積の 公式は？', '底辺 × 高さ ÷ 2', ['底辺 × 高さ', 'たて × 横', '底辺 ＋ 高さ ÷ 2']), Q('台形の 面積の 公式は？', '（上底＋下底）× 高さ ÷ 2', ['上底 × 下底 × 高さ', '底辺 × 高さ', '上底 ＋ 下底 ＋ 高さ']), Q('平行四辺形の 面積の 公式は？', '底辺 × 高さ', ['底辺 × 高さ ÷ 2', '対角線 × 対角線 ÷ 2', '上底 × 高さ']), Q('ひし形の 面積の 公式は？', '対角線 × 対角線 ÷ 2', ['底辺 × 高さ', '辺 × 辺', '対角線 ＋ 対角線'])])].map(function (x) { x.wrongs = x.wrongs.map(function (w) { return w.replace(/[（）]/g, ''); }); x.correct = x.correct.replace(/[（）]/g, ''); return x; }));
  };

  window.genEnshu5 = function () {
    var p = R(0, 5), d;
    if (p === 0) { d = R(2, 10); return { q: '直径 ' + d + 'cm の 円の 円周は 何cm？（円周率＝3.14）', ans: Math.round(d * 314) / 100 }; }
    if (p === 1) { var r = R(1, 6); return { q: '半径 ' + r + 'cm の 円の 円周は 何cm？（円周率＝3.14）', ans: Math.round(r * 2 * 314) / 100 }; }
    if (p === 2) { d = R(2, 9); return { q: '円周が ' + Math.round(d * 314) / 100 + 'cm の 円の 直径は 何cm？（円周率＝3.14）', ans: d }; }
    if (p === 3) { var n = P([3, 4, 5, 6, 8, 9, 10, 12]); var KN = { 3: '正三角形', 4: '正方形', 5: '正五角形', 6: '正六角形', 8: '正八角形', 9: '正九角形', 10: '正十角形', 12: '正十二角形' }; return { q: KN[n] + 'の 1つの 角の 大きさは 何度？\n（ヒント：角の 大きさの 和 ÷ ' + n + '）', ans: 180 - 360 / n }; }
    if (p === 4) { var m = P([5, 6, 8, 9, 10]); var KM = { 5: '正五角形', 6: '正六角形', 8: '正八角形', 9: '正九角形', 10: '正十角形' }; return { q: '円の 中心の まわりの 角を ' + m + '等分して ' + KM[m] + 'を かきます。\n中心の 角を 何度ずつ に すれば よい？', ans: 360 / m }; }
    return bank([P([Q('円周 ÷ 直径 の 値を 何と いう？', '円周率', ['半径', '面積', '中心角']), Q('辺の 長さが すべて 等しく、角の 大きさも すべて 等しい 多角形は？', '正多角形', ['四角形', '合同な 図形', 'ひし形']), Q('円周率は 約 いくつ？', '3.14', ['2.14', '3.41', '31.4'])])]);
  };

  var KAKU5 = [
    Q('三角柱の 面の 数は？', '5', ['6', '4', '9']), Q('三角柱の 頂点の 数は？', '6', ['5', '9', '3']), Q('三角柱の 辺の 数は？', '9', ['6', '12', '8']),
    Q('四角柱の 面の 数は？', '6', ['8', '4', '12']), Q('四角柱の 辺の 数は？', '12', ['8', '6', '10']), Q('五角柱の 面の 数は？', '7', ['5', '10', '15']),
    Q('五角柱の 頂点の 数は？', '10', ['5', '7', '15']), Q('六角柱の 辺の 数は？', '18', ['12', '6', '8']),
    Q('角柱の 2つの 底面の 関係は？', '平行で 合同', ['垂直で 合同', '平行で 大きさが ちがう', '同じ 面']),
    Q('角柱の 側面の 形は？', '長方形（か 正方形）', ['三角形', '円', '台形']),
    Q('円柱の 側面の 展開図の 形は？', '長方形', ['円', '三角形', 'おうぎ形']),
    Q('円柱の 底面の 形は？', '円', ['長方形', '三角形', '正方形']),
    Q('円柱の 展開図で、側面の 長方形の 横の 長さは 底面の 何と 等しい？', '円周', ['直径', '半径', '高さ']),
    Q('角柱の 底面と 側面の 関係は？', '垂直', ['平行', '同じ 面', '合同'])
  ];
  window.genKakuchu5 = function () { return bank(KAKU5); };

  window.genWariaiGraph5 = function () {
    var p = R(0, 4), all = P([200, 400, 500, 100, 300]), part;
    if (p === 0) { part = all * P([10, 20, 25, 30, 40, 50]) / 100; return { q: '全体 ' + all + '人の うち ' + part + '人は、\n全体の 何%？（帯グラフに かく とき）', ans: part / all * 100 }; }
    if (p === 1) { var pc = P([10, 20, 25, 40, 50]); return { q: '円グラフで、全体の ' + pc + '% に あたる 部分の 中心の 角は 何度？', ans: 360 * pc / 100 }; }
    if (p === 2) { var a = R(1, 4) * 10, b = R(1, 3) * 10; return { q: '帯グラフで、A が ' + a + '%、B が ' + b + '%、のこりが C です。\nC は 何%？', ans: 100 - a - b }; }
    if (p === 3) { var pc2 = P([10, 20, 25, 30, 40]); return { q: '全体が ' + all + '人で、そのうち ' + pc2 + '% は 何人？', ans: all * pc2 / 100 }; }
    return bank([P([Q('全体を 100% として、割合を 帯の 長さで 表す グラフは？', '帯グラフ', ['棒グラフ', '折れ線グラフ', '円グラフ']), Q('全体を 円で 表し、割合を おうぎ形で 表す グラフは？', '円グラフ', ['帯グラフ', '棒グラフ', '柱状グラフ']), Q('帯グラフ・円グラフで ふつう どこから かく？', '割合の 大きい 順（その他は 最後）', ['小さい 順', 'あいうえお順', 'どこからでも'])])]);
  };

  window.genHirei5 = function () {
    var p = R(0, 3), k = R(2, 9), x = R(2, 9);
    if (p === 0) return { q: '1こ ' + k + '0円の あめを □こ 買うと 代金は ○円。\n□が ' + x + 'の とき ○は？', ans: k * 10 * x };
    if (p === 1) return { q: 'たて ' + k + 'cm の 長方形で、横の 長さを ' + x + '倍に すると、\n面積は 何倍に なる？', ans: x };
    if (p === 2) { var n = R(3, 8); return { q: '正方形を ' + n + 'こ 横に ならべて つなげます（1辺 1本ずつの ぼう で 作る）。\nぼうは 何本 いる？', ans: 3 * n + 1 }; }
    return { q: '水そうに 毎分 ' + k + 'L ずつ 水を 入れます。\n' + x + '分後には 何L に なる？', ans: k * x };
  };

  /* ═════════════ 英語 5年 ═════════════ */
  var W5 = [['🐶', 'dog', '犬'], ['🐱', 'cat', 'ねこ'], ['🐰', 'rabbit', 'うさぎ'], ['🐻', 'bear', 'クマ'], ['🍓', 'strawberry', 'いちご'], ['🍊', 'orange', 'オレンジ'], ['🍉', 'watermelon', 'すいか'], ['🥕', 'carrot', 'にんじん'], ['🍅', 'tomato', 'トマト'], ['🥛', 'milk', '牛乳'], ['🍞', 'bread', 'パン'], ['🍙', 'rice ball', 'おにぎり'],
    ['📕', 'book', '本'], ['🖊️', 'pen', 'ペン'], ['📏', 'ruler', '定規'], ['✂️', 'scissors', 'はさみ'], ['🎹', 'piano', 'ピアノ'], ['🎸', 'guitar', 'ギター'], ['🚲', 'bike', '自転車'], ['🚗', 'car', '車'], ['🚉', 'station', '駅'], ['🏪', 'convenience store', 'コンビニ'], ['🏤', 'post office', '郵便局'], ['📚', 'library', '図書館'],
    ['❤️', 'red', '赤'], ['💙', 'blue', '青'], ['💛', 'yellow', '黄'], ['💚', 'green', '緑'], ['🔴', 'circle', '円'], ['⭐', 'star', '星'], ['🌸', 'spring', '春'], ['☀️', 'summer', '夏'], ['🍁', 'fall', '秋'], ['⛄', 'winter', '冬'], ['☔', 'rainy', '雨の'], ['☀️', 'sunny', '晴れの']];
  window.genWords5E = function () {
    var w = P(W5), o = W5.filter(function (x) { return x[1] !== w[1]; });
    var pick3 = function (k) { var c = o.slice(), out = []; while (out.length < 3) { var z = c.splice(R(0, c.length - 1), 1)[0][k]; if (out.indexOf(z) < 0) out.push(z); } return out; };
    if (R(0, 1)) return bank([Q('この 絵を 英語で 言うと？\n' + w[0], w[1], pick3(1))]);
    return bank([Q('「' + w[1] + '」の 意味は？', w[2], pick3(2))]);
  };
  var MONTH = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  var ORD = ['1st', '2nd', '3rd', '4th', '5th', '6th', '7th', '8th', '9th', '10th', '11th', '12th', '13th', '14th', '15th', '16th', '17th', '18th', '19th', '20th', '21st', '22nd', '23rd', '24th', '25th', '26th', '27th', '28th', '29th', '30th', '31st'];
  window.genBday5E = function () {
    var m = R(0, 11), d = R(1, 28), p = R(0, 3), wr = function (i) { var o = [], c = MONTH.slice(); c.splice(i, 1); while (o.length < 3) o.push(c.splice(R(0, c.length - 1), 1)[0]); return o; };
    if (p === 0) return bank([Q((m + 1) + '月は 英語で？', MONTH[m], wr(m))]);
    if (p === 1) return bank([Q('「' + MONTH[m] + '」は 何月？', (m + 1) + '月', [((m + 1) % 12 + 1) + '月', ((m + 10) % 12 + 1) + '月', ((m + 5) % 12 + 1) + '月'])]);
    if (p === 2) return bank([Q('「わたしの 誕生日は ' + (m + 1) + '月' + d + '日です。」', 'My birthday is ' + MONTH[m] + ' ' + ORD[d - 1] + '.', ['My birthday is ' + MONTH[(m + 1) % 12] + ' ' + ORD[d - 1] + '.', 'I am ' + MONTH[m] + ' ' + ORD[d - 1] + '.', 'My birthday ' + MONTH[m] + '.'])]);
    return bank([P([Q('When is your birthday?　の 意味は？', 'あなたの 誕生日は いつですか？', ['あなたは 何才ですか？', '誕生日に 何が ほしい？', 'どこで 生まれましたか？']), Q('What do you want for your birthday?　の 意味は？', '誕生日に 何が ほしいですか？', ['誕生日は いつ？', '誕生日に どこへ 行く？', '何が 好き？']), Q('「わたしは 新しい 自転車が ほしいです。」', 'I want a new bike.', ['I have a new bike.', 'I like new bike.', 'I am a new bike.']), Q('3rd の 読み方は？', 'third', ['three', 'thirty', 'thirteen'])])]);
  };
  var CAN5 = [
    Q('「わたしは 速く 泳げます。」', 'I can swim fast.', ['I can\'t swim fast.', 'I swim can fast.', 'I am swim fast.']),
    Q('「わたしは ピアノを ひけません。」', 'I can\'t play the piano.', ['I can play the piano.', 'I don\'t piano.', 'I not play the piano.']),
    Q('Can you cook?　に「はい」で 答える', 'Yes, I can.', ['Yes, I do.', 'Yes, I am.', 'No, I can\'t.']),
    Q('Can you ski?　に「いいえ」で 答える', 'No, I can\'t.', ['No, I don\'t.', 'No, I\'m not.', 'Yes, I can.']),
    Q('He can run fast. の 意味は？', '彼は 速く 走れます。', ['彼は 速く 走りません。', 'わたしは 速く 走れます。', '彼女は 速く 走れます。']),
    Q('She can play the guitar. の She は？', '彼女', ['彼', 'わたし', 'あなた']),
    Q('友だちを 紹介する とき「こちらは ケンです。」', 'This is Ken.', ['I\'m Ken.', 'He Ken.', 'That Ken is.']),
    Q('「彼は 親切です。」', 'He is kind.', ['She is kind.', 'He kind.', 'He can kind.']),
    Q('「彼女は ダンスが 得意です。」', 'She is good at dancing.', ['She can\'t dance.', 'She likes dancing not.', 'He is good at dancing.']),
    Q('Who is this?　の 意味は？', 'こちらは だれですか？', ['これは 何ですか？', 'どこですか？', 'いつですか？']),
    Q('「一輪車に 乗れる？」', 'Can you ride a unicycle?', ['Do you unicycle?', 'You can a unicycle?', 'Can unicycle you?']),
    Q('cook の 意味は？', '料理する', ['走る', '泳ぐ', '歌う'])
  ];
  window.genCan5E = function () { return bank(CAN5); };
  var WHERE5 = [
    Q('Where is the station?　の 意味は？', '駅は どこですか？', ['駅に 行きたい', 'これは 駅ですか？', '駅は 遠いですか？']),
    Q('「まっすぐ 行って ください。」', 'Go straight.', ['Turn right.', 'Turn left.', 'Stop here.']),
    Q('「右に 曲がって ください。」', 'Turn right.', ['Turn left.', 'Go straight.', 'Go back.']),
    Q('「左に 曲がって ください。」', 'Turn left.', ['Turn right.', 'Go straight.', 'Come here.']),
    Q('You can see it on your right. の 意味は？', '右手に 見えます。', ['左手に 見えます。', 'まっすぐ 見えます。', '見えません。']),
    Q('The cat is on the box. の ねこは どこ？', '箱の 上', ['箱の 中', '箱の 下', '箱の そば']),
    Q('The ball is in the bag. の ボールは どこ？', 'かばんの 中', ['かばんの 上', 'かばんの 下', 'かばんの 横']),
    Q('The pen is under the desk. の ペンは どこ？', '机の 下', ['机の 上', '机の 中', '机の そば']),
    Q('The shoes are by the door. の くつは どこ？', 'ドアの そば', ['ドアの 上', 'ドアの 中', 'ドアの 下']),
    Q('「ありがとう。」と お礼を 言われたら 返す ことば', 'You\'re welcome.', ['I\'m sorry.', 'See you.', 'Good night.']),
    Q('What would you like?　の 意味（お店で）は？', '何に なさいますか？', ['いくらですか？', 'どこですか？', '何が 好き？']),
    Q('「ピザを ください。」（ていねいに）', 'I\'d like pizza.', ['I want pizza is.', 'Pizza I like.', 'I am pizza.']),
    Q('How much is it?　の 意味は？', 'いくらですか？', ['いくつですか？', 'どれくらい 好き？', '何時ですか？']),
    Q('It\'s 500 yen. の 意味は？', '500円です。', ['5円です。', '50円です。', '5000円です。'])
  ];
  window.genWhere5E = function () { return bank(WHERE5); };

  var ADD = {
    math: { 5: [
      { id: 'm5-seishitsu', name: '整数の性質', icon: '🔢', color: 'blue', gen: 'genSeishitsu5', input: 'numpad', desc: '偶数・奇数・倍数・約数' },
      { id: 'm5-goudou', name: '合同な図形・角', icon: '🔺', color: 'green', gen: 'genGoudou5', input: 'numpad', desc: '合同・三角形と四角形の角' },
      { id: 'm5-fracadd', name: '分数のたし算ひき算', icon: '➕', color: 'orange', gen: 'genFracAdd5', input: 'mcq', desc: '分母のちがう分数' },
      { id: 'm5-fracdec', name: '分数と小数・整数', icon: '🔄', color: 'teal', gen: 'genFracDec5', input: 'numpad', desc: 'わり算と分数・小数に直す' },
      { id: 'm5-menseki', name: '図形の面積', icon: '📐', color: 'cyan', gen: 'genMenseki5', input: 'numpad', desc: '三角形・平行四辺形・台形・ひし形' },
      { id: 'm5-enshu', name: '正多角形と円周', icon: '⭕', color: 'purple', gen: 'genEnshu5', input: 'numpad', desc: '円周＝直径×3.14' },
      { id: 'm5-kakuchu', name: '角柱と円柱', icon: '🧊', color: 'indigo', gen: 'genKakuchu5', input: 'mcq', desc: '面・辺・頂点・展開図' },
      { id: 'm5-graph', name: '帯グラフ・円グラフ', icon: '🥧', color: 'pink', gen: 'genWariaiGraph5', input: 'numpad', desc: '割合を グラフに' },
      { id: 'm5-hirei', name: '比例と変わり方', icon: '📈', color: 'amber', gen: 'genHirei5', input: 'numpad', desc: '□と○の 関係' }
    ] },
    english: { 5: [
      { id: 'e5-words', name: '5年の 単語', icon: '🔤', color: 'sky', gen: 'genWords5E', input: 'mcq', desc: '動物・食べ物・文房具・町・色・季節' },
      { id: 'e5-bday', name: '誕生日と月', icon: '🎂', color: 'pink', gen: 'genBday5E', input: 'mcq', desc: 'January〜December / When is 〜?' },
      { id: 'e5-can', name: 'できること・人の紹介', icon: '💪', color: 'orange', gen: 'genCan5E', input: 'mcq', desc: 'I can 〜 / He・She is 〜' },
      { id: 'e5-where', name: '道案内・場所・注文', icon: '🗺️', color: 'green', gen: 'genWhere5E', input: 'mcq', desc: 'Go straight / on・in・under / I\'d like 〜' }
    ] }
  };
  var DISP = {
    'm5-seishitsu': { name: '数の 迷宮', emoji: '🔢', desc: '整数の性質' }, 'm5-goudou': { name: '合同の 石だたみ', emoji: '🔺', desc: '合同な図形' }, 'm5-fracadd': { name: '分数の 合流点', emoji: '➕', desc: '分数のたし算ひき算' },
    'm5-fracdec': { name: '変身の 泉', emoji: '🔄', desc: '分数と小数' }, 'm5-menseki': { name: '面積の 畑', emoji: '📐', desc: '図形の面積' }, 'm5-enshu': { name: '円周の 闘技場', emoji: '⭕', desc: '正多角形と円周' },
    'm5-kakuchu': { name: '柱の 神殿', emoji: '🧊', desc: '角柱と円柱' }, 'm5-graph': { name: 'グラフの 丘', emoji: '🥧', desc: '帯グラフ・円グラフ' }, 'm5-hirei': { name: '比例の 坂道', emoji: '📈', desc: '比例と変わり方' },
    'e5-words': { name: 'ABCの 林', emoji: '🔤', desc: '5年の 英単語' }, 'e5-bday': { name: 'たんじょう日の 丘', emoji: '🎂', desc: '誕生日と月' }, 'e5-can': { name: 'できるの 広場', emoji: '💪', desc: 'できること' }, 'e5-where': { name: 'まちの 交差点', emoji: '🗺️', desc: '道案内・場所' }
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
