/* ============================================================
   中2数学 増量パック g8xmath v186
   ・既存 genShiki8/genRenritsu8/genIchiji8/genZukei8/genKakuritsu8 を
     window経由でラップして新パターンを追加（既存ファイル非改変）
   ・全問題に patternId を付与（既存パターンは問題文から分類）
   ・基礎40/標準40/発展20 は新旧プールとも維持
   ============================================================ */
(function () {
  var G8 = window.G8; if (!G8) return;
  if (window.__G8XMATH__) return; window.__G8XMATH__ = 1;
  var R = G8.R, Q = G8.q, S = G8.s, LIN = G8.lin;
  function pick(a) { return a[R(0, a.length - 1)]; }
  function nz(a, b) { var v = 0; while (v === 0) v = R(a, b); return v; }
  function gcd(a, b) { a = Math.abs(a); b = Math.abs(b); while (b) { var t = a % b; a = b; b = t; } return a || 1; }
  function frac(n, d) { var g = gcd(n, d); n /= g; d /= g; if (d === 1) return String(n); return n + '/' + d; }
  function xy(a, b, X, Y) {
    X = X || 'x'; Y = Y || 'y';
    var s = '';
    if (a !== 0) s += (a === 1 ? X : (a === -1 ? '-' + X : a + X));
    if (b !== 0) {
      if (s) s += (b > 0 ? '+' : '-') + (Math.abs(b) === 1 ? Y : Math.abs(b) + Y);
      else s = (b === 1 ? Y : (b === -1 ? '-' + Y : b + Y));
    }
    if (!s) s = '0';
    return s;
  }
  function pair(x, y) { return '(x, y) = (' + S(x) + ', ' + S(y) + ')'; }

  // pool = { b:[[key,fn],...], s:[...], h:[...] }, rules=[[regex,key],...]
  var WRAP = window.__G8X_WRAP = window.__G8X_WRAP || function (origName, unitId, pool, rules, nOld) {
    var orig = window[origName];
    if (typeof orig !== 'function' || orig.__x) return;
    var nNew = pool.b.length + pool.s.length + pool.h.length;
    function classify(q) {
      for (var i = 0; i < rules.length; i++) { if (rules[i][0].test(q)) return unitId + ':' + rules[i][1]; }
      return null;
    }
    var f = function () {
      var p, pid = null;
      if (Math.random() < nNew / (nNew + nOld)) {
        var r = R(1, 10);
        var arr = (r <= 4) ? pool.b : (r <= 8 ? pool.s : pool.h);
        var tpl = arr[R(0, arr.length - 1)];
        p = tpl[1]();
        pid = unitId + ':' + tpl[0];
      } else {
        p = orig();
        pid = classify((p && p.q) || '');
      }
      if (p && pid) p.patternId = pid;
      return p;
    };
    f.__x = 1;
    window[origName] = f;
  };

  // ================= 式の計算（+8 → 22パターン） =================
  var shikiPool = {
    b: [
      ['n-dokei', function () {
        var p = R(3, 9), r2 = R(2, p - 1), q2 = R(2, 8), s2 = R(2, 8);
        while (q2 * s2 === q2 + s2) s2++;
        return Q('基礎', p + 'a + ' + q2 + 'b - ' + r2 + 'a + ' + s2 + 'b を計算すると？',
          xy(p - r2, q2 + s2, 'a', 'b'),
          [xy(p + r2, q2 + s2, 'a', 'b'), xy(p - r2, Math.abs(q2 - s2) || 1, 'a', 'b'), xy(p - r2, q2 * s2, 'a', 'b')]);
      }],
      ['n-bunpai', function () {
        var a = R(2, 6), b2 = R(2, 7), c = nz(-7, 7);
        return Q('基礎', a + '(' + xy(b2, c) + ') を計算すると？',
          xy(a * b2, a * c), [xy(a * b2, c), xy(a + b2, a + c), xy(a * b2, -a * c)]);
      }],
      ['n-jijou', function () {
        var a = R(3, 5);
        return Q('基礎', '(' + a + 'x)² を計算すると？',
          (a * a) + 'x²', [(2 * a) + 'x²', (a * a) + 'x', (2 * a) + 'x']);
      }]
    ],
    s: [
      ['n-bunsuu', function () {
        var a = nz(-4, 4), b2 = nz(-4, 4), py = 3 * a + 2 * b2;
        while (py === 0) { a = nz(-4, 4); b2 = nz(-4, 4); py = 3 * a + 2 * b2; }
        return Q('標準', '(' + xy(1, a) + ')/2 + (' + xy(1, b2) + ')/3 を計算すると？',
          '(' + xy(5, py) + ')/6', ['(' + xy(5, a + b2) + ')/6', '(' + xy(2, py) + ')/5', '(' + xy(5, py) + ')/5']);
      }],
      ['n-warizan', function () {
        var c = R(2, 4), p = R(2, 5) * c, q2 = nz(-4, 4) * c;
        return Q('標準', '(' + xy(p, q2) + ') ÷ ' + c + ' を計算すると？',
          xy(p / c, q2 / c), [xy(p / c, q2), xy(p, q2 / c), xy(p / c, -q2 / c)]);
      }],
      ['n-atai-jo', function () {
        var b2 = R(2, 4), m = R(2, 4), a = b2 * m;
        var x = nz(-3, 3), y = nz(-3, 3);
        while (y === x) y = nz(-3, 3);
        return Q('標準', 'x = ' + S(x) + ' , y = ' + S(y) + ' のとき、' + a + 'xy ÷ ' + b2 + 'y の値は？',
          m * x, [m * y, a * x, -m * x]);
      }]
    ],
    h: [
      ['n-guuki', function () {
        return Q('発展', 'm、n を整数とするとき、偶数 2m と奇数 2n+1 の和はどう表せる？',
          '2(m+n)+1', ['2(m+n)', '2mn+1', 'm+n+1']);
      }],
      ['n-keta3', function () {
        return Q('発展', '百の位が a、十の位が b、一の位が c の3けたの整数を表すと？',
          '100a+10b+c', ['abc', 'a+b+c', '100c+10b+a']);
      }]
    ]
  };
  var shikiRules = [
    [/^【基礎】\(.+\) \+ \(.+\) を計算/, 'o-tashizan'],
    [/単項式 .+ の次数は？/, 'o-jisuu'],
    [/の x² の係数は？/, 'o-keisuu'],
    [/^【基礎】\d+a \+ \d+a を計算/, 'o-douruikou'],
    [/は何次式？/, 'o-nanjishiki'],
    [/^【標準】\(.+\) - \(.+\) を計算/, 'o-hikizan'],
    [/^【標準】\d+\(.+\) \+ \d+\(.+\) を計算/, 'o-kakko2'],
    [/÷ \d+x を計算すると？/, 'o-tanko-waru'],
    [/× .+ を計算すると？/, 'o-tanko-kake'],
    [/^【標準】x = .+ のとき、.+ の値は？/, 'o-shiki-atai'],
    [/^【発展】x = .+ のとき、[\s\S]*の値は？/, 'o-shiki-atai-h'],
    [/を y について解くと？/, 'o-toushiki'],
    [/連続する3つの整数/, 'o-renzoku'],
    [/十の位が a、一の位が b/, 'o-keta2moji']
  ];

  // ================= 連立方程式（+10 → 21パターン） =================
  var renPool = {
    b: [
      ['n-kai-check', function () {
        var x0 = nz(-4, 4), y0 = nz(-4, 4);
        return Q('基礎', '連立方程式\n x + y = ' + S(x0 + y0) + '\n 2x + y = ' + S(2 * x0 + y0) + '\nの解はどれ？',
          pair(x0, y0), [pair(y0, x0), pair(x0 + 1, y0 - 1), pair(-x0, -y0)]);
      }],
      ['n-yougo-dainyu', function () {
        return Q('基礎', '連立方程式の解き方のうち、一方の式を他方の式に代入して文字を消す方法を何という？',
          '代入法', ['加減法', '移項法', '等置法']);
      }],
      ['n-shoukyo', function () {
        var a = R(2, 5), b2 = R(2, 6), c = R(2, 6), e = R(1, 9), f2 = R(1, 9);
        while (c === b2) c = R(2, 6);
        return Q('基礎', '連立方程式 ①' + xy(a, b2) + ' = ' + e + '　②' + xy(a, c) + ' = ' + f2 + '\n加減法で x を消去するには？',
          '①と②をひき算する', ['①と②をたし算する', '①を2倍して②をたす', '②を' + a + '倍して①をたす']);
      }],
      ['n-nanbai', function () {
        var q2 = R(2, 4), a = R(2, 5), r2 = R(2, 5), e = R(1, 9), f2 = R(1, 9);
        return Q('基礎', '連立方程式 ①' + xy(a, q2) + ' = ' + e + '　②' + xy(r2, 1) + ' = ' + f2 + '\n加減法で y を消去するには、②を何倍して①からひけばよい？',
          q2 + '倍', [(q2 + 1) + '倍', (q2 + 2) + '倍', (q2 - 1) + '倍']);
      }]
    ],
    s: [
      ['n-shousuu', function () {
        var x = R(2, 8), y = R(2, 8);
        while (y === x) y = R(2, 8);
        var c1 = (3 * x + y) / 10;
        return Q('標準', '連立方程式を解こう。\n 0.3x + 0.1y = ' + c1 + '\n x + y = ' + (x + y),
          pair(x, y), [pair(y, x), pair(x + 1, y - 1), pair(x, y + 1)]);
      }],
      ['n-bunsuu2', function () {
        var x = 2 * R(1, 4), y = 3 * R(1, 3), c = x / 2 + y / 3, d = x - y;
        return Q('標準', '連立方程式を解こう。\n x/2 + y/3 = ' + c + '\n x - y = ' + S(d),
          pair(x, y), [pair(y, x), pair(x + 2, y - 2), pair(x, y + 3)]);
      }],
      ['n-keta2', function () {
        var x = R(1, 6), dy = R(1, Math.min(3, 9 - x)), y = x + dy;
        var wa = x + y, sa = 9 * dy, moto = 10 * x + y;
        return Q('標準', '2けたの自然数があります。十の位と一の位の数の和は ' + wa + ' で、\n十の位と一の位を入れかえた数は、もとの数より ' + sa + ' 大きくなります。もとの数は？',
          moto, [10 * y + x, wa, moto - 9]);
      }],
      ['n-abc', function () {
        var m = R(1, 4);
        return Q('標準', '連立方程式 x + y = 2x - y = ' + (3 * m) + ' を解くと？',
          pair(2 * m, m), [pair(m, 2 * m), pair(3 * m, 0), pair(2 * m, -m)]);
      }]
    ],
    h: [
      ['n-wariai', function () {
        var t = pick([[500, 10, 10, 10, 300, 200], [450, 10, 10, 5, 250, 200], [300, 10, 5, 15, 200, 100], [600, 5, 10, -24, 240, 360]]);
        var word = t[3] > 0 ? '全体で' + t[3] + '人増えました' : '全体で' + (-t[3]) + '人減りました';
        return Q('発展', '昨年の生徒数は男女合わせて ' + t[0] + ' 人でした。今年は男子が ' + t[1] + '%増え、女子が ' + t[2] + '%減ったので、' + word + '。昨年の男子の人数は？',
          t[4] + '人', [t[5] + '人', (t[4] + 10) + '人', (t[4] - 20) + '人']);
      }],
      ['n-shokuen', function () {
        var t = pick([[5, 10, 8, 300, 120, 180], [4, 10, 7, 300, 150, 150], [3, 9, 7, 300, 100, 200], [5, 8, 6, 300, 200, 100], [4, 12, 10, 400, 100, 300]]);
        return Q('発展', t[0] + '%の食塩水 x g と ' + t[1] + '%の食塩水 y g を混ぜたら、' + t[2] + '%の食塩水が ' + t[3] + ' g できました。\n' + t[0] + '%の食塩水は何 g 混ぜた？',
          t[4] + 'g', [t[5] + 'g', (t[4] + 50) + 'g', (t[4] - 50) + 'g']);
      }]
    ]
  };
  var renRules = [
    [/^【基礎】連立方程式を解こう。\n x \+ y =/, 'o-wa-sa'],
    [/^【基礎】連立方程式を解こう。\n y =/, 'o-x-shitei'],
    [/どの式にあてはまる？/, 'o-kai-atehamaru'],
    [/たしたりひいたりして文字を消す方法/, 'o-yougo-kagen'],
    [/^【標準】連立方程式を解こう。\n y =/, 'o-dainyu'],
    [/^【標準】連立方程式を解こう。/, 'o-kagen'],
    [/えんぴつ1本/, 'o-daikin-shiki'],
    [/大人 x 人と子ども y 人/, 'o-goukei-shiki'],
    [/あめと.*ガム/, 'o-kosuu-bun'],
    [/時速.*歩き、時速.*走った/, 'o-hayasa-bun'],
    [/和は .+、差は/, 'o-wa-sa-bun']
  ];

  // ================= 1次関数（+8 → 22パターン） =================
  var ichijiPool = {
    b: [
      ['n-kyuu', function () {
        var arr = [1, 2, 3, 4, 5, 6, 7], sel = [];
        for (var i = 0; i < 4; i++) sel.push(arr.splice(R(0, arr.length - 1), 1)[0]);
        var mx = Math.max(sel[0], sel[1], sel[2], sel[3]);
        function L(k) { return 'y = ' + LIN(k, nz(-5, 5)); }
        var ansL = L(mx), w = [];
        for (var j = 0; j < 4; j++) if (sel[j] !== mx) w.push(L(sel[j]));
        return Q('基礎', '次の1次関数のうち、グラフの傾きがいちばん急（大きい）なのはどれ？', ansL, w);
      }],
      ['n-hyou', function () {
        var a = nz(-4, 4), b2 = nz(-6, 6);
        while (b2 === a) b2 = nz(-6, 6);
        return Q('基礎', 'x の値が 0, 1, 2, 3 と増えるとき、y の値は順に ' + S(b2) + ', ' + S(a + b2) + ', ' + S(2 * a + b2) + ', ' + S(3 * a + b2) + ' です。\ny を x の式で表すと？',
          'y = ' + LIN(a, b2), ['y = ' + LIN(b2, a), 'y = ' + LIN(-a, b2), 'y = ' + LIN(a, -b2)]);
      }],
      ['n-kiri-zahyou', function () {
        var a = nz(-5, 5), b2 = nz(-9, 9);
        while (b2 === a) b2 = nz(-9, 9);
        return Q('基礎', '1次関数 y = ' + LIN(a, b2) + ' のグラフが y 軸と交わる点の座標は？',
          '(0, ' + S(b2) + ')', ['(' + S(b2) + ', 0)', '(0, ' + S(a) + ')', '(' + S(a) + ', 0)']);
      }]
    ],
    s: [
      ['n-heikou-ten', function () {
        var a = nz(-4, 4), b2 = nz(-6, 6), c = nz(-6, 6);
        while (c === b2) c = nz(-6, 6);
        return Q('標準', '直線 y = ' + LIN(a, b2) + ' に平行で、点 (0, ' + S(c) + ') を通る直線の式は？',
          'y = ' + LIN(a, c), ['y = ' + LIN(a, b2), 'y = ' + LIN(-a, c), 'y = ' + LIN(c, a)]);
      }],
      ['n-x-fuae', function () {
        var a = nz(-4, 4), d = R(2, 5), b2 = nz(-6, 6);
        while (a === 1) a = nz(-4, 4);
        return Q('標準', '1次関数 y = ' + LIN(a, b2) + ' で、y が ' + S(a * d) + ' 増えるとき、x の増加量は？',
          S(d), [S(a * d), S(a + d), S(-d)]);
      }],
      ['n-ryoukin', function () {
        var a = R(2, 9) * 10, b2 = R(2, 9) * 100;
        return Q('標準', '基本料金 ' + b2 + ' 円で、1分ごとに ' + a + ' 円かかる電話プランがあります。\nx 分間の通話料金 y 円を式で表すと？',
          'y = ' + a + 'x + ' + b2, ['y = ' + b2 + 'x + ' + a, 'y = ' + a + 'x - ' + b2, 'y = ' + (a + b2) + 'x']);
      }]
    ],
    h: [
      ['n-menseki', function () {
        var a1 = pick([1, 2, 3]), r2 = pick([2, 4, 6]), b2 = a1 * r2, area = r2 * b2 / 2;
        return Q('発展', '直線 y = ' + LIN(-a1, b2) + ' と x 軸、y 軸で囲まれた三角形の面積は？',
          area, [area * 2, area * 4, b2 + r2]);
      }],
      ['n-doten', function () {
        var b2 = 2 * R(2, 5), a = R(4, 9);
        while (a === b2 || a === b2 / 2) a = R(4, 9);
        return Q('発展', '長方形ABCDで AB = ' + a + 'cm、AD = ' + b2 + 'cm。点 P は A を出発して辺 AB 上を毎秒 1cm で動きます。\nx 秒後の △APD の面積 y cm² を式で表すと？',
          'y = ' + (b2 / 2) + 'x', ['y = ' + b2 + 'x', 'y = ' + (b2 / 2) + 'x + ' + a, 'y = ' + a + 'x']);
      }]
    ]
  };
  var ichijiRules = [
    [/の傾きは？/, 'o-katamuki'],
    [/の切片は？/, 'o-seppen'],
    [/^【基礎】y = .+ で、x = .+ のときの y は？/, 'o-y-atai'],
    [/1次関数であるものはどれ？/, 'o-hantei'],
    [/右上がり・右下がり/, 'o-muki'],
    [/x が \d+ 増えると y はどれだけ増える？/, 'o-y-zouka'],
    [/の変化の割合は？/, 'o-henka-wariai'],
    [/^【標準】2点 .+ を通る直線の式は？/, 'o-niten'],
    [/x 軸と交わる点/, 'o-x-kouten'],
    [/に平行な直線はどれ？/, 'o-heikou'],
    [/の交点の座標は？/, 'o-kouten'],
    [/の変域は？/, 'o-heniki'],
    [/傾きが .+ で、点 .+ を通る直線の式は？/, 'o-katamuki-1ten'],
    [/水そうに水が/, 'o-suisou']
  ];

  // ================= 図形の性質（+7 → 22パターン） =================
  var zukeiPool = {
    b: [
      ['n-teigi-nitou', function () {
        return Q('基礎', '二等辺三角形の定義は？',
          '2つの辺が等しい三角形', ['3つの辺が等しい三角形', '直角を1つもつ三角形', '2つの角が等しい三角形']);
      }],
      ['n-gaikaku-kotoba', function () {
        return Q('基礎', '三角形の1つの外角は、それととなり合わない（　）に等しい。（　）に入るのは？',
          '2つの内角の和', ['2つの内角の差', '1つの内角', '3つの内角の和']);
      }],
      ['n-heiko-seishitsu', function () {
        return Q('基礎', '平行四辺形の性質として正しいものはどれ？',
          '対角線はそれぞれの中点で交わる', ['対角線の長さは等しい', '対角線は垂直に交わる', '4つの角がすべて等しい']);
      }]
    ],
    s: [
      ['n-sei-naikaku', function () {
        var n = pick([5, 6, 8, 9, 10, 12]);
        return Q('標準', '正' + n + '角形の1つの内角は何度？',
          (180 * (n - 2) / n) + '°', [(360 / n) + '°', (180 * (n - 2)) + '°', '180°']);
      }],
      ['n-choukaku', function () {
        var a = 2 * R(15, 60);
        while (a === 60) a = 2 * R(15, 60);
        return Q('標準', '二等辺三角形の頂角が ' + a + '° のとき、底角の1つは何度？',
          ((180 - a) / 2) + '°', [a + '°', (180 - a) + '°', ((90 - a) > 0 ? (90 - a) : (a - 30)) + '°']);
      }]
    ],
    h: [
      ['n-hishigata', function () {
        return Q('発展', '平行四辺形に「対角線が垂直に交わる」という条件を加えると、何という四角形になる？',
          'ひし形', ['長方形', '正方形', '台形']);
      }],
      ['n-hoshi', function () {
        return Q('発展', '星形五角形（星のマーク）の先端にできる5つの角の和は何度？',
          '180°', ['360°', '540°', '108°']);
      }]
    ]
  };
  var zukeiRules = [
    [/対頂角/, 'o-taichoukaku'],
    [/同位角/, 'o-douikaku'],
    [/錯角/, 'o-sakkaku'],
    [/残りの内角は何度？/, 'o-nokori-naikaku'],
    [/多角形の外角の和/, 'o-gaikaku-wa'],
    [/角形の内角の和は何度？/, 'o-naikaku-wa'],
    [/正\d+角形の1つの外角/, 'o-sei-gaikaku'],
    [/となり合わない外角は何度？/, 'o-gaikaku-teiri'],
    [/三角形の合同条件のうち/, 'o-goudou-jouken'],
    [/底角の1つが/, 'o-teikaku'],
    [/AB=DE、BC=EF、∠B=∠E/, 'o-shoumei-hen'],
    [/∠B=∠E、∠C=∠F、BC=EF/, 'o-shoumei-kaku'],
    [/直角三角形の合同条件/, 'o-chokkaku-goudou'],
    [/平行四辺形ABCDで/, 'o-heikou-kaku'],
    [/平行四辺形になる条件/, 'o-heikou-jouken']
  ];

  // ================= 確率（+8 → 22パターン） =================
  var kakuPool = {
    b: [
      ['n-zero', function () {
        return Q('基礎', '絶対に起こらないことがらの確率はいくつ？', '0', ['1', '1/2', '-1']);
      }],
      ['n-trump', function () {
        var s2 = pick(['ハート', 'スペード', 'ダイヤ', 'クラブ']);
        return Q('基礎', 'ジョーカーを除く52枚のトランプから1枚引くとき、' + s2 + 'のカードが出る確率は？',
          '1/4', ['1/13', '1/2', '1/52']);
      }],
      ['n-kuji', function () {
        var a = R(1, 4), b2 = R(3, 8);
        while (b2 === a) b2 = R(3, 8);
        return Q('基礎', '当たりくじ ' + a + ' 本、はずれくじ ' + b2 + ' 本のくじから1本引くとき、当たる確率は？',
          frac(a, a + b2), [frac(b2, a + b2), frac(a, b2), frac(1, a + b2)]);
      }]
    ],
    s: [
      ['n-wa-k', function () {
        var mp = { 4: 3, 5: 4, 6: 5, 8: 5, 9: 4, 10: 3 };
        var k = pick([4, 5, 6, 8, 9, 10]), cnt = mp[k];
        return Q('標準', '2個のさいころを同時に投げるとき、出る目の和が ' + k + ' になる確率は？',
          frac(cnt, 36), ['1/6', frac(cnt + 2, 36), frac(36 - cnt, 36)]);
      }],
      ['n-douji', function () {
        var n = R(4, 6);
        return Q('標準', n + ' 本のくじの中に当たりが2本あります。同時に2本引くとき、2本とも当たりになる確率は？',
          frac(2, n * (n - 1)), [frac(1, n), frac(2, n), frac(1, n * (n - 1))]);
      }],
      ['n-janken', function () {
        return Q('標準', '2人でじゃんけんを1回するとき、あいこになる確率は？',
          '1/3', ['1/9', '1/2', '2/3']);
      }]
    ],
    h: [
      ['n-roku', function () {
        return Q('発展', '2個のさいころを同時に投げるとき、少なくとも1つは6の目が出る確率は？',
          '11/36', ['1/6', '25/36', '1/36']);
      }],
      ['n-iin', function () {
        var a = R(4, 6);
        return Q('発展', a + ' 人の中から委員長と副委員長を1人ずつ選ぶとき、選び方は全部で何通り？',
          (a * (a - 1)) + '通り', [(a * (a - 1) / 2) + '通り', (a * a) + '通り', (2 * a) + '通り']);
      }]
    ]
  };
  var kakuRules = [
    [/^【基礎】1個のさいころを1回投げるとき、\dの目/, 'o-hitotsu-me'],
    [/偶数の目が出る確率/, 'o-guusuu'],
    [/袋から1個取り出すとき、赤玉/, 'o-tama1'],
    [/1枚の硬貨を1回/, 'o-kouka1'],
    [/必ず起こる/, 'o-kanarazu'],
    [/2枚の硬貨を同時に投げるとき、2枚とも表/, 'o-kouka2'],
    [/和が7になる確率/, 'o-wa7'],
    [/目の出方は全部で何通り/, 'o-toori36'],
    [/2つとも同じ目/, 'o-zorome'],
    [/の倍数の目が出る確率/, 'o-baisuu'],
    [/少なくとも1枚が表/, 'o-sukunakutomo-omote'],
    [/3枚の硬貨を同時に投げるとき、3枚とも裏/, 'o-kouka3'],
    [/続けて2個取り出す/, 'o-tama2-tsuzuke'],
    [/3人が1列に並ぶ/, 'o-narabikata']
  ];

  WRAP('genShiki8', 'm8-shiki', shikiPool, shikiRules, 14);
  WRAP('genRenritsu8', 'm8-renritsu', renPool, renRules, 11);
  WRAP('genIchiji8', 'm8-ichiji', ichijiPool, ichijiRules, 14);
  WRAP('genZukei8', 'm8-zukei', zukeiPool, zukeiRules, 15);
  WRAP('genKakuritsu8', 'm8-kakuritsu', kakuPool, kakuRules, 14);
})();
