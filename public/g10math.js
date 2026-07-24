/* ============================================================
   高1数学 単元パック v181（ネットレ超え・隠し高校エリア）
   数と式 / 不等式 / 二次関数 / 三角比 / 順列・組合せ / 確率
   基礎40%・標準40%・発展20% 混合ランダム（4択・自己完結型）
   ============================================================ */
(function () {
  var G10 = window.G10; if (!G10) return;
  var R = G10.R, pick = G10.pick, Q = G10.q;
  function nz(a, b) { var v = 0; while (v === 0) v = R(a, b); return v; }
  function fact(n) { var f = 1; for (var i = 2; i <= n; i++) f *= i; return f; }
  function nPr(n, r) { var v = 1; for (var i = 0; i < r; i++) v *= (n - i); return v; }
  function nCr(n, r) { return nPr(n, r) / fact(r); }
  function gcd(a, b) { a = Math.abs(a); b = Math.abs(b); while (b) { var t = a % b; a = b; b = t; } return a || 1; }
  function frac(n, d) { if (d < 0) { n = -n; d = -d; } var g = gcd(n, d); n /= g; d /= g; if (d === 1) return String(n); return n + '/' + d; }

  // ① 数と式（展開・因数分解・式の値）
  function genSuushiki10() {
    var r = R(1, 10), a, b, t;
    if (r <= 4) {
      t = R(0, 2);
      if (t === 0) { a = R(1, 6); b = R(1, 6);
        return Q('基礎', '(x+' + a + ')(x+' + b + ') を展開すると？', 'x²+' + (a + b) + 'x+' + (a * b), ['x²+' + (a * b) + 'x+' + (a + b), 'x²+' + (a + b) + 'x+' + (a + b), 'x²+' + (a * b) + 'x+' + (a * b)]); }
      if (t === 1) { a = R(2, 5);
        return Q('基礎', '(x+' + a + ')² を展開すると？', 'x²+' + (2 * a) + 'x+' + (a * a), ['x²+' + (a * a) + 'x+' + (2 * a), 'x²+' + a + 'x+' + (a * a), 'x²+' + (2 * a) + 'x+' + (2 * a)]); }
      a = R(2, 6);
      return Q('基礎', 'x²-' + (a * a) + ' を因数分解すると？', '(x+' + a + ')(x-' + a + ')', ['(x-' + a + ')²', '(x+' + a + ')²', '(x-' + (a * a) + ')(x+1)']); }
    if (r <= 8) {
      t = R(0, 2);
      if (t === 0) { a = R(2, 4); b = R(1, 5);
        // (ax+b)(ax-b)=a²x²-b²
        return Q('標準', '(' + a + 'x+' + b + ')(' + a + 'x-' + b + ') を展開すると？', (a * a) + 'x²-' + (b * b), [(a * a) + 'x²+' + (b * b), (a * 2) + 'x²-' + (b * b), (a * a) + 'x²-' + (2 * b)]); }
      if (t === 1) { a = R(2, 3); b = R(1, 5); var c = R(1, 5); while (c === b) c = R(1, 5);
        // ax²+(b+c)a x + bc a? use a x²+(b+c)x+bc factorization with leading 1
        return Q('標準', 'x²+' + (b + c) + 'x+' + (b * c) + ' を因数分解すると？', '(x+' + b + ')(x+' + c + ')', ['(x+' + (b * c) + ')(x+1)', '(x-' + b + ')(x-' + c + ')', '(x+' + b + ')(x-' + c + ')']); }
      a = R(2, 5);
      return Q('標準', 'x = ' + a + ' のとき、x²-' + a + 'x+3 の値は？', String(a * a - a * a + 3), [String(a * a + 3), String(a * a - a + 3), String(3 * a)]); }
    // 発展: たすきがけ
    var p = R(2, 3), q = R(2, 3), s = R(1, 3), u = R(1, 3);
    // (px+s)(qx+u)=pq x²+(pu+qs)x+su
    return Q('発展', (p * q) + 'x²+' + (p * u + q * s) + 'x+' + (s * u) + ' を因数分解すると？',
      '(' + p + 'x+' + s + ')(' + q + 'x+' + u + ')', ['(' + p + 'x+' + u + ')(' + q + 'x+' + s + ')', '(x+' + s + ')(x+' + u + ')', '(' + (p * q) + 'x+' + s + ')(x+' + u + ')']);
  }

  // ② 不等式
  function genFutoushiki10() {
    var r = R(1, 10), a, b, c, t;
    if (r <= 4) {
      // ax+b<c → x<(c-b)/a （a>0）
      a = R(2, 5); var x0 = nz(-4, 5); b = nz(-6, 6); c = a * x0 + b;
      return Q('基礎', '不等式 ' + a + 'x+' + (b >= 0 ? b : '(' + b + ')') + ' < ' + c + ' を解くと？', 'x < ' + x0, ['x > ' + x0, 'x < ' + (x0 + 1), 'x > ' + (x0 - 1)]); }
    if (r <= 8) {
      // 負の数で割る→不等号の向き
      a = R(2, 5); var x1 = nz(-4, 5); b = nz(-5, 5); c = -a * x1 + b;
      return Q('標準', '不等式 -' + a + 'x+' + (b >= 0 ? b : '(' + b + ')') + ' > ' + c + ' を解くと？（両辺を負でわると向きが変わる）', 'x < ' + x1, ['x > ' + x1, 'x < ' + (-x1), 'x > ' + (-x1)]); }
    // 発展: 連立不等式の整数解の個数
    var lo = nz(-3, 2), hi = lo + R(2, 5);
    var count = hi - lo + 1;
    return Q('発展', '' + lo + ' ≦ x ≦ ' + hi + ' を満たす整数 x は全部で何個？', String(count) + '個', [String(count - 1) + '個', String(count + 1) + '個', String(hi - lo) + '個']);
  }

  // ③ 二次関数（頂点・最大最小）
  function genNijikansu10() {
    var r = R(1, 10), a, p, q, t;
    if (r <= 4) {
      t = R(0, 1);
      if (t === 0) { p = nz(-4, 4); q = nz(-5, 5);
        return Q('基礎', 'y = (x-' + (p >= 0 ? p : '(' + p + ')') + ')²+' + (q >= 0 ? q : '(' + q + ')') + ' の頂点の座標は？', '(' + p + ', ' + q + ')', ['(' + (-p) + ', ' + q + ')', '(' + p + ', ' + (-q) + ')', '(' + q + ', ' + p + ')']); }
      a = pick([1, 2, 3]);
      return Q('基礎', 'y = ' + (a === 1 ? '' : a) + 'x² のグラフの頂点はどこ？', '原点(0, 0)', ['(0, ' + a + ')', '(' + a + ', 0)', '(1, 1)']); }
    if (r <= 8) {
      // y = x² + bx + c を平方完成 → 頂点x = -b/2
      var b = nz(-8, 8) * 2; var cc = R(-3, 5); // bを偶数に
      var vx = -b / 2; var vy = cc - (b / 2) * (b / 2);
      return Q('標準', 'y = x²+' + (b >= 0 ? b : '(' + b + ')') + 'x+' + (cc >= 0 ? cc : '(' + cc + ')') + ' の頂点の x 座標は？', String(vx), [String(-b), String(b), String(vx + 1)]); }
    // 発展: 下に凸の最小値
    var b2 = nz(-6, 6) * 2; var c2 = R(1, 8);
    var min = c2 - (b2 / 2) * (b2 / 2);
    return Q('発展', 'y = x²+' + (b2 >= 0 ? b2 : '(' + b2 + ')') + 'x+' + c2 + ' の最小値は？', String(min), [String(c2), String(-min), String(min + 1)]);
  }

  // ④ 三角比
  function genSankakuhi10() {
    var r = R(1, 10), t;
    if (r <= 4) {
      t = R(0, 2);
      if (t === 0) return Q('基礎', '直角三角形で、sin は「（斜辺に対する）どの辺の比」？', '対辺 ÷ 斜辺', ['隣辺 ÷ 斜辺', '対辺 ÷ 隣辺', '斜辺 ÷ 対辺']);
      if (t === 1) return Q('基礎', 'cos の定義はどれ？', '隣辺 ÷ 斜辺', ['対辺 ÷ 斜辺', '対辺 ÷ 隣辺', '斜辺 ÷ 隣辺']);
      return Q('基礎', 'tan の定義はどれ？', '対辺 ÷ 隣辺', ['対辺 ÷ 斜辺', '隣辺 ÷ 斜辺', '斜辺 ÷ 対辺']); }
    if (r <= 8) {
      t = R(0, 3);
      if (t === 0) return Q('標準', 'sin 30° の値は？', '1/2', ['1/√2', '√3/2', '1']);
      if (t === 1) return Q('標準', 'cos 60° の値は？', '1/2', ['√3/2', '1/√2', '1']);
      if (t === 2) return Q('標準', 'sin 45° の値は？', '1/√2', ['1/2', '√3/2', '√2']);
      return Q('標準', 'tan 45° の値は？', '1', ['√3', '1/√3', '0']); }
    // 発展
    t = R(0, 2);
    if (t === 0) return Q('発展', 'sin 60° の値は？', '√3/2', ['1/2', '1/√2', '√3']);
    if (t === 1) return Q('発展', 'tan 60° の値は？', '√3', ['1/√3', '1', '√3/2']);
    return Q('発展', 'sin²θ + cos²θ の値は（相互関係）？', '1', ['0', 'tanθ', '2']);
  }

  // ⑤ 順列・組合せ
  function genJunretsu10() {
    var r = R(1, 10), n, k, t;
    if (r <= 4) {
      t = R(0, 1);
      if (t === 0) { n = R(3, 6);
        return Q('基礎', '異なる ' + n + ' 個を1列に並べる並べ方は全部で何通り？（' + n + '!）', String(fact(n)) + '通り', [String(n * n) + '通り', String(fact(n - 1)) + '通り', String(n * (n - 1)) + '通り']); }
      n = R(4, 6); k = R(2, 3);
      return Q('基礎', '異なる ' + n + ' 個から ' + k + ' 個を選んで1列に並べる（' + n + 'P' + k + '）は何通り？', String(nPr(n, k)) + '通り', [String(nCr(n, k)) + '通り', String(fact(n)) + '通り', String(n * k) + '通り']); }
    if (r <= 8) {
      n = R(4, 7); k = R(2, 3);
      return Q('標準', '異なる ' + n + ' 個から ' + k + ' 個を選ぶ組合せ（' + n + 'C' + k + '）は何通り？', String(nCr(n, k)) + '通り', [String(nPr(n, k)) + '通り', String(fact(k)) + '通り', String(n * k) + '通り']); }
    // 発展
    t = R(0, 1);
    if (t === 0) { n = R(4, 6);
      return Q('発展', '' + n + '人が輪になって座る円順列は何通り？（(n-1)!）', String(fact(n - 1)) + '通り', [String(fact(n)) + '通り', String(nPr(n, 2)) + '通り', String(n * (n - 1)) + '通り']); }
    n = R(5, 7);
    return Q('発展', '' + n + 'C2 と ' + n + 'C' + (n - 2) + ' の関係で正しいのは？', '等しい（nCr = nC(n-r)）', ['nC2の方が大きい', 'nC(n-2)の方が大きい', '和が n になる']);
  }

  // ⑥ 確率
  function genKakuritsu10() {
    var r = R(1, 10), t;
    if (r <= 4) {
      t = R(0, 2);
      if (t === 0) return Q('基礎', 'さいころを1回投げて、3の倍数の目が出る確率は？', '1/3', ['1/2', '1/6', '2/3']);
      if (t === 1) return Q('基礎', 'コインを1枚投げて表が出る確率は？', '1/2', ['1/3', '1/4', '1']);
      return Q('基礎', 'さいころを1回投げて、偶数の目が出る確率は？', '1/2', ['1/3', '1/6', '2/3']); }
    if (r <= 8) {
      t = R(0, 2);
      if (t === 0) return Q('標準', 'コインを2枚投げて、2枚とも表が出る確率は？', '1/4', ['1/2', '1/3', '1/8']);
      if (t === 1) return Q('標準', 'さいころを2個投げて、目の和が7になる確率は？', '1/6', ['1/12', '1/9', '5/36']);
      // 玉の確率
      var a = R(2, 4), b = R(2, 4); var tot = a + b;
      return Q('標準', '赤玉 ' + a + '個、白玉 ' + b + '個の袋から1個取り出すとき、赤玉が出る確率は？', frac(a, tot), [frac(b, tot), frac(a, b), frac(1, tot)]); }
    // 発展: 余事象
    t = R(0, 1);
    if (t === 0) return Q('発展', 'さいころを2個投げて、少なくとも1個は6が出る確率は？（余事象を使う）', '11/36', ['1/6', '1/3', '25/36']);
    // 続けて取り出す(もどさない)
    var a2 = R(2, 4), b2 = R(2, 4); var tot2 = a2 + b2;
    var pn = a2 * (a2 - 1), pd = tot2 * (tot2 - 1);
    return Q('発展', '赤玉 ' + a2 + '個、白玉 ' + b2 + '個から続けて2個取り出す（もどさない）とき、2個とも赤の確率は？', frac(pn, pd), [frac(a2 * a2, tot2 * tot2), frac(a2, tot2), frac(a2 * (a2 - 1), tot2 * tot2)]);
  }

  try {
    window.genSuushiki10 = genSuushiki10;
    window.genFutoushiki10 = genFutoushiki10;
    window.genNijikansu10 = genNijikansu10;
    window.genSankakuhi10 = genSankakuhi10;
    window.genJunretsu10 = genJunretsu10;
    window.genKakuritsu10 = genKakuritsu10;
  } catch (e) {}

  G10.stage('math', [
    { id: 'm10-suushiki', name: '数と式', icon: 'π', color: 'blue', gen: 'genSuushiki10', input: 'mcq', desc: '展開・因数分解・式の値' },
    { id: 'm10-futoushiki', name: '不等式', icon: '⚖️', color: 'purple', gen: 'genFutoushiki10', input: 'mcq', desc: '1次不等式・連立不等式' },
    { id: 'm10-niji', name: '二次関数', icon: '📈', color: 'orange', gen: 'genNijikansu10', input: 'mcq', desc: '頂点・平方完成・最大最小' },
    { id: 'm10-sankaku', name: '三角比', icon: '🔺', color: 'red', gen: 'genSankakuhi10', input: 'mcq', desc: 'sin・cos・tan' },
    { id: 'm10-junretsu', name: '順列・組合せ', icon: '🎲', color: 'cyan', gen: 'genJunretsu10', input: 'mcq', desc: 'nPr・nCr・円順列' },
    { id: 'm10-kakuritsu', name: '確率', icon: '🎰', color: 'green', gen: 'genKakuritsu10', input: 'mcq', desc: 'さいころ・玉・余事象' }
  ], {
    'm10-suushiki': { name: '数と式の工房', emoji: 'π', desc: '数と式（高1数学）' },
    'm10-futoushiki': { name: '不等式のてんびん', emoji: '⚖️', desc: '不等式（高1数学）' },
    'm10-niji': { name: '放物線の展望台', emoji: '📈', desc: '二次関数（高1数学）' },
    'm10-sankaku': { name: '三角比の測量塔', emoji: '🔺', desc: '三角比（高1数学）' },
    'm10-junretsu': { name: '順列組合せの回廊', emoji: '🎲', desc: '順列・組合せ（高1数学）' },
    'm10-kakuritsu': { name: '確率の賭博場', emoji: '🎰', desc: '確率（高1数学）' }
  });
})();
