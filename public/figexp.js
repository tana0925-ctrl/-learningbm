/* ============================================================
   📐 FIGEXP_V1（2026-11-19）修行の 問題に「図」と「かいせつ」を そえる
   ・答え方は 変えない（4択・数字入力の まま）。問題の データに fig（SVG）と exp（1〜2行）を 足すだけ。
   ・図は 修行・復習の 画面だけに 出す（野生バトル・攻略モードは テンポを 大事に して 出さない）。
   ・かいせつは まちがえた ときに「わかった → つぎへ」の 上に 出る（TRAIN_WRONG_V1）。
   ・もとの 問題づくり（gen〜）は さわらず、出てきた 問題文から 数を 読みとって 足す。読めなければ 何も 足さない。
   ============================================================ */
(function () {
  if (window.__FIGEXP__) return; window.__FIGEXP__ = 1;
  var gcd = function (a, b) { a = Math.abs(a); b = Math.abs(b); while (b) { var t = a % b; a = b; b = t; } return a || 1; };
  var r2 = function (x) { return Math.round(x * 100) / 100; };
  var F = function (n, d) { return n + '/' + d; };
  var num = function (s) { return Number(String(s).replace(/[^\d.]/g, '')); };
  var C = { line: '#334155', a: '#059669', b: '#d97706', red: '#e11d48', fillA: '#dcfce7', fillB: '#fef3c7', blue: '#2563eb' };
  var svg = function (w, h, body) { return '<svg viewBox="0 0 ' + w + ' ' + h + '" style="width:100%;max-width:' + Math.min(320, w * 1.4) + 'px;max-height:150px" xmlns="http://www.w3.org/2000/svg" font-family="sans-serif">' + body + '</svg>'; };
  var t = function (x, y, s, o) { o = o || {}; return '<text x="' + x + '" y="' + y + '" font-size="' + (o.fs || 12) + '" fill="' + (o.c || C.line) + '" text-anchor="' + (o.a || 'middle') + '" font-weight="' + (o.b ? 800 : 500) + '">' + s + '</text>'; };

  /* ── 図の 部品 ── */
  function figCircle(r) {
    return svg(170, 130, '<circle cx="85" cy="62" r="52" fill="#ede9fe" stroke="#7c3aed" stroke-width="2.5"/><circle cx="85" cy="62" r="3" fill="' + C.line + '"/><line x1="85" y1="62" x2="137" y2="62" stroke="' + C.red + '" stroke-width="2.5"/>' + t(111, 55, '半径 ' + r + 'cm', { c: C.red, b: 1 }) + t(85, 126, '面積 ＝ 半径 × 半径 × 3.14', { fs: 11 }));
  }
  function figTri(L, k, small) {   // もとの 図と 拡大図（または 縮図）
    var s1 = small ? 1 / k : 1, s2 = small ? 1 : 1, u = 16;
    var A = function (x0, s) { var w = 4 * u * s, h = 3 * u * s; return '<polygon points="' + x0 + ',110 ' + (x0 + w) + ',110 ' + x0 + ',' + (110 - h) + '"'; };
    if (!small) return svg(260, 125, A(15, 0.6) + ' fill="' + C.fillA + '" stroke="' + C.a + '" stroke-width="2"/>' + t(15 + 4 * u * 0.3, 122, L + 'cm', { c: C.a, b: 1 }) + t(40, 20, 'もとの 図', { fs: 11 }) + A(110, 0.6 * k > 2.2 ? 2.2 : 0.6 * k) + ' fill="' + C.fillB + '" stroke="' + C.b + '" stroke-width="2"/>' + t(110 + 4 * u * Math.min(2.2, 0.6 * k) / 2, 122, '？cm', { c: C.b, b: 1 }) + t(200, 20, k + '倍の 拡大図', { fs: 11, b: 1, c: C.b }));
    return svg(260, 125, A(15, 2.0) + ' fill="' + C.fillA + '" stroke="' + C.a + '" stroke-width="2"/>' + t(15 + 4 * u, 122, (L * k) + 'cm', { c: C.a, b: 1 }) + t(60, 20, 'もとの 図', { fs: 11 }) + A(170, 2.0 / k < 0.5 ? 0.5 : 2.0 / k) + ' fill="' + C.fillB + '" stroke="' + C.b + '" stroke-width="2"/>' + t(170 + 4 * u * Math.max(0.5, 2.0 / k) / 2, 122, '？cm', { c: C.b, b: 1 }) + t(215, 20, '1/' + k + ' の 縮図', { fs: 11, b: 1, c: C.b }));
  }
  function figPrism(kind, a, b, h) {   // kind: 'tri' | 'cyl' | 'trap' | 'any'
    var dx = 22, dy = -16, H = 62, base = 110;
    if (kind === 'cyl') return svg(170, 140, '<ellipse cx="85" cy="' + (base - H) + '" rx="40" ry="12" fill="' + C.fillB + '" stroke="' + C.b + '" stroke-width="2"/><line x1="45" y1="' + (base - H) + '" x2="45" y2="' + base + '" stroke="' + C.b + '" stroke-width="2"/><line x1="125" y1="' + (base - H) + '" x2="125" y2="' + base + '" stroke="' + C.b + '" stroke-width="2"/><path d="M45,' + base + ' A40,12 0 0,0 125,' + base + '" fill="none" stroke="' + C.b + '" stroke-width="2"/><line x1="85" y1="' + (base - H) + '" x2="125" y2="' + (base - H) + '" stroke="' + C.red + '" stroke-width="2"/>' + t(105, base - H - 6, '半径' + a + 'cm', { fs: 11, c: C.red, b: 1 }) + t(140, base - H / 2, '高さ' + b + 'cm', { fs: 11, a: 'start', b: 1 }) + t(85, 136, '体積 ＝ 底面積（半径×半径×3.14）× 高さ', { fs: 10 }));
    var pts = kind === 'tri' ? [[30, base], [100, base], [30, base - 40]] : kind === 'trap' ? [[25, base], [115, base], [85, base - 40], [45, base - 40]] : [[30, base], [100, base], [100, base - 40], [30, base - 40]];
    var P = function (arr) { return arr.map(function (p) { return p[0] + ',' + p[1]; }).join(' '); };
    var back = pts.map(function (p) { return [p[0] + dx, p[1] + dy - H + 40]; });
    var body = '<polygon points="' + P(back) + '" fill="none" stroke="#94a3b8" stroke-dasharray="3 3"/>';
    pts.forEach(function (p, i) { body += '<line x1="' + p[0] + '" y1="' + p[1] + '" x2="' + back[i][0] + '" y2="' + back[i][1] + '" stroke="' + C.line + '" stroke-width="1.5"/>'; });
    body += '<polygon points="' + P(pts) + '" fill="' + C.fillB + '" stroke="' + C.b + '" stroke-width="2.5"/>';
    body += t(65, base + 14, '底面', { fs: 11, c: C.b, b: 1 }) + t(150, base - 30, '高さ ' + h + 'cm', { fs: 11, a: 'start', b: 1 });
    return svg(220, 152, body + t(110, 148, '体積 ＝ 底面積 × 高さ', { fs: 11 }));
  }
  function figTape(a, b, la, lb, known, ask) {   // テープ図：a：b
    var u = Math.min(30, 200 / (a + b)), x = 15, y = 30, h = 26, body = '';
    for (var i = 0; i < a + b; i++) body += '<rect x="' + (x + i * u) + '" y="' + y + '" width="' + u + '" height="' + h + '" fill="' + (i < a ? C.fillA : C.fillB) + '" stroke="' + (i < a ? C.a : C.b) + '"/>';
    body += t(x + a * u / 2, y - 6, la + '（' + a + '）', { fs: 11, c: C.a, b: 1 }) + t(x + a * u + b * u / 2, y - 6, lb + '（' + b + '）', { fs: 11, c: C.b, b: 1 });
    body += t(x + (a + b) * u / 2, y + h + 18, known, { fs: 11, b: 1 }) + t(x + (a + b) * u / 2, y + h + 34, ask, { fs: 11, c: C.red, b: 1 });
    return svg(240, 100, body);
  }
  function figTable(rows) {   // 比例・反比例の 表
    var w = 44, body = '';
    rows[0].forEach(function (_, i) { body += '<rect x="' + (10 + i * w) + '" y="10" width="' + w + '" height="26" fill="' + (i ? '#fff' : '#f1f5f9') + '" stroke="' + C.line + '"/><rect x="' + (10 + i * w) + '" y="36" width="' + w + '" height="26" fill="' + (i ? '#fff' : '#f1f5f9') + '" stroke="' + C.line + '"/>' + t(10 + i * w + w / 2, 28, rows[0][i], { b: !i }) + t(10 + i * w + w / 2, 54, rows[1][i], { b: !i, c: rows[1][i] === '?' ? C.red : C.line }); });
    return svg(10 + rows[0].length * w + 10, 72, body);
  }

  /* ── かいせつ・図を 足す しくみ ── */
  function wrap(name, add) {
    var o = window[name]; if (typeof o !== 'function' || o.__fx) return;
    var w = function () { var p = o.apply(this, arguments); try { if (p && typeof p === 'object' && !p.exp) { var x = add(String(p.q || ''), p); if (x) { if (x.exp) p.exp = x.exp; if (x.fig) p.fig = x.fig; } } } catch (e) {} return p; };
    w.__fx = 1; window[name] = w;
  }
  var M = function (q, re) { var m = q.match(re); return m; };

  function install() {
    // 分数 × 分数／÷ 分数
    wrap('genFracMul6', function (q) { var m = M(q, /(\d+)\/(\d+) × (\d+)\/(\d+)/); if (!m) return; var a = +m[1], b = +m[2], c = +m[3], d = +m[4], n = a * c, dd = b * d, g = gcd(n, dd); return { exp: '分子どうし・分母どうしを かける：' + a + '×' + c + '＝' + n + '、' + b + '×' + d + '＝' + dd + ' → ' + F(n, dd) + (g > 1 ? ' → ' + g + 'で 約分して ' + F(n / g, dd / g) : '（約分できない）') }; });
    wrap('genFracDiv6', function (q) { var m = M(q, /(\d+)\/(\d+) ÷ (\d+)\/(\d+)/); if (!m) return; var a = +m[1], b = +m[2], c = +m[3], d = +m[4], n = a * d, dd = b * c, g = gcd(n, dd); return { exp: 'わる数を ひっくり返して かける：' + F(a, b) + ' × ' + F(d, c) + ' ＝ ' + F(n, dd) + (g > 1 ? ' → ' + g + 'で 約分して ' + F(n / g, dd / g) : '（約分できない）') }; });
    wrap('genFracInt6', function (q) { var m = M(q, /(\d+)\/(\d+) ([×÷]) (\d+)/); if (!m) return; var a = +m[1], b = +m[2], k = +m[4]; if (m[3] === '×') { var g = gcd(a * k, b); return { exp: '分数 × 整数は 分子に かける：（' + a + '×' + k + '）/' + b + ' ＝ ' + F(a * k, b) + (g > 1 ? ' → 約分して ' + F(a * k / g, b / g) : '') }; } var g2 = gcd(a, b * k); return { exp: '分数 ÷ 整数は 分母に かける：' + a + '/（' + b + '×' + k + '）＝ ' + F(a, b * k) + (g2 > 1 ? ' → 約分して ' + F(a / g2, b * k / g2) : '') }; });
    // 比
    wrap('genRatio6', function (q) {
      var m;
      if ((m = M(q, /^([\d.]+)：([\d.]+)\n.*かんたんな/))) { var a = +m[1], b = +m[2]; if (Math.floor(a) !== a || Math.floor(b) !== b) { var A = Math.round(a * 10), B = Math.round(b * 10), g0 = gcd(A, B); return { exp: '小数の 比は 10倍して 整数に：' + A + '：' + B + ' → 両方を ' + g0 + 'で わって ' + (A / g0) + '：' + (B / g0) }; } var g = gcd(a, b); return { exp: '両方を 同じ 数（' + g + '）で わる：' + a + '÷' + g + '＝' + (a / g) + '、' + b + '÷' + g + '＝' + (b / g) + ' → ' + (a / g) + '：' + (b / g) }; }
      if ((m = M(q, /^(\d+)\/(\d+)：(\d+)\/(\d+)/))) { var n1 = +m[1], d1 = +m[2], n2 = +m[3], d2 = +m[4], x = n1 * d2, y = n2 * d1, g1 = gcd(x, y); return { exp: '分母を そろえる（通分）：' + F(x, d1 * d2) + '：' + F(y, d1 * d2) + ' → 分子だけ くらべて ' + x + '：' + y + ' → ' + (x / g1) + '：' + (y / g1) }; }
      if ((m = M(q, /^(\d+)：(\d+) の 比の値/))) return { exp: '比の値 ＝ 前の 数 ÷ 後ろの 数：' + m[1] + ' ÷ ' + m[2] + ' ＝ ' + r2(+m[1] / +m[2]) };
      if ((m = M(q, /^(\d+)：(\d+) ＝ x：(\d+)/))) { var k = +m[3] / +m[2]; return { exp: '後ろの 数が ' + m[2] + ' → ' + m[3] + ' で ' + k + '倍。前の 数も ' + k + '倍：' + m[1] + '×' + k + '＝' + (+m[1] * k) }; }
      if ((m = M(q, /^(\d+)：(\d+) ＝ (\d+)：x/))) { var k2 = +m[3] / +m[1]; return { exp: '前の 数が ' + m[1] + ' → ' + m[3] + ' で ' + k2 + '倍。後ろの 数も ' + k2 + '倍：' + m[2] + '×' + k2 + '＝' + (+m[2] * k2) }; }
      if ((m = M(q, /^(\d+)円を 兄と 弟で (\d+)：(\d+) に 分けます。\n(兄|弟)/))) { var T = +m[1], a5 = +m[2], b5 = +m[3], u = T / (a5 + b5); return { exp: '全体を ' + a5 + '＋' + b5 + '＝' + (a5 + b5) + 'こに 分ける：1こ分 ＝ ' + T + '÷' + (a5 + b5) + '＝' + u + '円 → ' + m[4] + 'は ' + u + '×' + (m[4] === '兄' ? a5 : b5) + '＝' + u * (m[4] === '兄' ? a5 : b5) + '円', fig: figTape(a5, b5, '兄', '弟', '全部で ' + T + '円', m[4] + 'は？') }; }
      if ((m = M(q, /水を (\d+)：(\d+) で まぜます。\nジュースが (\d+)mL/))) { var a6 = +m[1], b6 = +m[2], u6 = +m[3] / a6; return { exp: 'ジュース ' + a6 + 'こ分が ' + m[3] + 'mL → 1こ分 ＝ ' + m[3] + '÷' + a6 + '＝' + u6 + 'mL → 水は ' + u6 + '×' + b6 + '＝' + u6 * b6 + 'mL', fig: figTape(a6, b6, 'ジュース', '水', 'ジュース ' + m[3] + 'mL', '水は？') }; }
      if ((m = M(q, /女子の 人数の 比は (\d+)：(\d+) です。\n男子が (\d+)人/))) { var a7 = +m[1], b7 = +m[2], u7 = +m[3] / a7; return { exp: '男子 ' + a7 + 'こ分が ' + m[3] + '人 → 1こ分 ' + u7 + '人 → 全員は ' + (a7 + b7) + 'こ分で ' + u7 + '×' + (a7 + b7) + '＝' + u7 * (a7 + b7) + '人', fig: figTape(a7, b7, '男子', '女子', '男子 ' + m[3] + '人', '全員は？') }; }
    });
    // 円の 面積
    wrap('genCircleArea6', function (q) { var m = M(q, /半径 (\d+)cm/); if (!m) return; var r = +m[1]; return { exp: '円の 面積 ＝ 半径 × 半径 × 3.14：' + r + '×' + r + '×3.14 ＝ ' + r2(r * r * 3.14) + 'cm²（直径では ないので 注意）', fig: figCircle(r) }; });
    // 拡大図と 縮図
    wrap('genScale6', function (q) {
      var m;
      if ((m = M(q, /の (\d+)倍の 拡大図を かきます。\nもとの 辺が (\d+)cm/))) return { exp: '拡大図は 辺の 長さが 全部 同じ 倍：' + m[2] + '×' + m[1] + '＝' + (+m[2] * +m[1]) + 'cm', fig: figTri(+m[2], +m[1], false) };
      if ((m = M(q, /の 1\/(\d+) の 縮図を かきます。\nもとの 辺が (\d+)cm/))) return { exp: '1/' + m[1] + ' の 縮図は 辺を ' + m[1] + 'で わる：' + m[2] + '÷' + m[1] + '＝' + (+m[2] / +m[1]) + 'cm', fig: figTri(+m[2] / +m[1], +m[1], true) };
      if ((m = M(q, /辺 (\d+)cm が、拡大図では (\d+)cm/))) return { exp: '何倍か ＝ 拡大図の 長さ ÷ もとの 長さ：' + m[2] + '÷' + m[1] + '＝' + (+m[2] / +m[1]) + '倍' };
      if ((m = M(q, /角の 1つが (\d+)°/))) return { exp: '拡大図・縮図では 角の 大きさは 変わらない。だから ' + m[1] + '° の まま' };
      if ((m = M(q, /縮尺 1\/(\d+) の 地図で (\d+)cm/))) { var cm = +m[2] * +m[1]; return { exp: '本当の 長さ ＝ 地図の 長さ × ' + m[1] + '：' + m[2] + '×' + m[1] + '＝' + cm + 'cm ＝ ' + cm / 100 + 'm（100cm ＝ 1m）' }; }
      if ((m = M(q, /きょりが ([\d.]+)m の 道は、\n縮尺 1\/(\d+)/))) return { exp: 'まず cmに：' + m[1] + 'm ＝ ' + (+m[1] * 100) + 'cm → 地図の 長さ ＝ ' + (+m[1] * 100) + '÷' + m[2] + '＝' + (+m[1] * 100 / +m[2]) + 'cm' };
      if ((m = M(q, /縮尺 1\/(\d+) の 縮図で、木の 高さが (\d+)cm/))) { var c2 = +m[2] * +m[1]; return { exp: m[2] + '×' + m[1] + '＝' + c2 + 'cm ＝ ' + c2 / 100 + 'm（本番で 測る ときは、ここに 目の 高さを たす）' }; }
    });
    // 角柱と 円柱の 体積
    wrap('genPrism6', function (q) {
      var m;
      if ((m = M(q, /底面積が (\d+)cm² で、高さが (\d+)cm の 角柱/))) return { exp: '角柱の 体積 ＝ 底面積 × 高さ：' + m[1] + '×' + m[2] + '＝' + (+m[1] * +m[2]) + 'cm³', fig: figPrism('any', 0, 0, +m[2]) };
      if ((m = M(q, /底辺 (\d+)cm・高さ (\d+)cm の 三角形で、\n高さが (\d+)cm/))) { var S = +m[1] * +m[2] / 2; return { exp: '底面積（三角形）＝ ' + m[1] + '×' + m[2] + '÷2 ＝ ' + S + 'cm² → 体積 ＝ ' + S + '×' + m[3] + '＝' + S * +m[3] + 'cm³', fig: figPrism('tri', 0, 0, +m[3]) }; }
      if ((m = M(q, /半径が (\d+)cm、高さが (\d+)cm の 円柱/))) { var S2 = r2(+m[1] * +m[1] * 3.14); return { exp: '底面積（円）＝ ' + m[1] + '×' + m[1] + '×3.14 ＝ ' + S2 + 'cm² → 体積 ＝ ' + S2 + '×' + m[2] + '＝' + r2(S2 * +m[2]) + 'cm³', fig: figPrism('cyl', +m[1], +m[2], +m[2]) }; }
      if ((m = M(q, /体積が (\d+)cm³ で、底面積が (\d+)cm²/))) return { exp: '高さ ＝ 体積 ÷ 底面積：' + m[1] + '÷' + m[2] + '＝' + (+m[1] / +m[2]) + 'cm' };
      if ((m = M(q, /上底 (\d+)cm・下底 (\d+)cm・高さ (\d+)cm の 台形で、\n高さが (\d+)cm/))) { var S4 = (+m[1] + +m[2]) * +m[3] / 2; return { exp: '底面積（台形）＝（' + m[1] + '＋' + m[2] + '）×' + m[3] + '÷2 ＝ ' + S4 + 'cm² → 体積 ＝ ' + S4 + '×' + m[4] + '＝' + S4 * +m[4] + 'cm³', fig: figPrism('trap', 0, 0, +m[4]) }; }
    });
    // 場合の 数
    wrap('genCases6', function (q) {
      var m;
      if ((m = M(q, /^(\d+)人が 1列に/))) { var n = +m[1], s = []; for (var i = n; i >= 1; i--) s.push(i); return { exp: '1番目は ' + n + '通り、2番目は のこり ' + (n - 1) + '通り…と へっていく：' + s.join('×') + '＝' + s.reduce(function (a, b) { return a * b; }, 1) + '通り（樹形図で たしかめよう）' }; }
      if ((m = M(q, /^(\d+)人の 中から 班長と 副班長/))) return { exp: '班長 ' + m[1] + '通り × 副班長（のこり）' + (+m[1] - 1) + '通り ＝ ' + (+m[1] * (+m[1] - 1)) + '通り（順番が ある）' };
      if ((m = M(q, /^(\d+)チームで、どの チームとも/))) return { exp: 'A対B と B対A は 同じ 試合。' + m[1] + '×' + (+m[1] - 1) + '÷2 ＝ ' + (+m[1] * (+m[1] - 1) / 2) + '試合（表に ○を かいて 数えよう）' };
      if ((m = M(q, /^(\d+)種類の くだものから 2種類/))) return { exp: '順番は 関係ない ので、ならべ方の 数を 2で わる：' + m[1] + '×' + (+m[1] - 1) + '÷2 ＝ ' + (+m[1] * (+m[1] - 1) / 2) + '通り' };
      if ((m = M(q, /コインを (\d+)回/))) { var k = +m[1], a = []; for (var j = 0; j < k; j++) a.push(2); return { exp: '1回ごとに 表・裏の 2通り：' + a.join('×') + '＝' + Math.pow(2, k) + '通り' }; }
      if ((m = M(q, /^1〜(\d+) の 数字カード/))) return { exp: '十の位 ' + m[1] + '通り × 一の位（のこり）' + (+m[1] - 1) + '通り ＝ ' + (+m[1] * (+m[1] - 1)) + '通り' };
      if (/0・1・2 の 数字カード/.test(q)) return { exp: '百の位に 0は 使えない：百の位 2通り × 十の位 2通り × 一の位 1通り ＝ 4通り' };
      if (/0・1・2・3 の/.test(q)) return { exp: '十の位に 0は 使えない：十の位 3通り × 一の位 3通り ＝ 9通り' };
    });
    // 比例と 反比例
    wrap('genProportion6', function (q) {
      var m;
      if ((m = M(q, /比例し、\nx=1のとき y=(\d+)。\nx=(\d+)のとき/))) return { exp: '比例は y ＝ きまった数 × x：y ＝ ' + m[1] + ' × ' + m[2] + ' ＝ ' + (+m[1] * +m[2]), fig: figTable([['x', '1', m[2]], ['y', m[1], '?']]) };
      if ((m = M(q, /y=(\d+)x のとき\ny=(\d+)/))) return { exp: 'x ＝ y ÷ ' + m[1] + '：' + m[2] + '÷' + m[1] + '＝' + (+m[2] / +m[1]) };
      if ((m = M(q, /反比例し、\nx=1のとき y=(\d+)。\nx=(\d+)のとき/))) return { exp: '反比例は x × y が いつも 同じ（' + m[1] + '）：y ＝ ' + m[1] + ' ÷ ' + m[2] + ' ＝ ' + (+m[1] / +m[2]), fig: figTable([['x', '1', m[2]], ['y', m[1], '?']]) };
      if ((m = M(q, /xy=(\d+)。\ny=(\d+)のとき/))) return { exp: 'x × y ＝ ' + m[1] + ' だから x ＝ ' + m[1] + ' ÷ ' + m[2] + ' ＝ ' + (+m[1] / +m[2]) };
    });
  }

  /* ── 修行の 画面に 図を 出す（問題が 変わったら けす）── */
  window.__fxShow = function (prob) {
    try {
      var qEl = document.getElementById('trainingQuestion'); if (!qEl) return;
      var box = document.getElementById('trainingFig');
      if (!box) { box = document.createElement('div'); box.id = 'trainingFig'; box.style.cssText = 'display:none;margin:0 auto 6px;text-align:center;background:#fff;border-radius:12px;padding:4px 6px;max-width:340px'; qEl.parentNode.insertBefore(box, qEl.nextSibling);
        try { new MutationObserver(function () { if (box.getAttribute('data-q') !== qEl.innerText) box.style.display = 'none'; }).observe(qEl, { childList: true, characterData: true, subtree: true }); } catch (e) {} }
      if (prob && prob.fig) { box.innerHTML = prob.fig; box.style.display = 'block'; box.setAttribute('data-q', qEl.innerText); }
      else { box.innerHTML = ''; box.style.display = 'none'; box.removeAttribute('data-q'); }
    } catch (e) {}
  };
  install();
  // あとから 読みこまれる 問題ファイル（g6x など）にも 効くように、少し あとで もう一度
  setTimeout(install, 0); setTimeout(install, 1500); window.addEventListener('load', install);
})();
