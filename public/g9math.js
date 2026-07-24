/* ============================================================
   中3数学 単元パック v180（ネットレ対応 第6弾）
   展開と因数分解 / 平方根 / 2次方程式 / 2次関数y=ax² /
   相似 / 円周角 / 三平方の定理 / 標本調査
   基礎40%・標準40%・発展20% 混合ランダム（4択・自己完結型）
   ============================================================ */
(function () {
  var G9 = window.G9; if (!G9) return;
  var R = G9.R, pick = G9.pick, Q = G9.q;
  function nz(a, b) { var v = 0; while (v === 0) v = R(a, b); return v; }
  function isSq(n) { var r = Math.round(Math.sqrt(n)); return r * r === n; }
  function simRoot(n) { // √n を a√b に。返り値は表示文字列
    var a = 1, b = n;
    for (var k = 2; k * k <= b; k++) { while (b % (k * k) === 0) { a *= k; b /= (k * k); } }
    if (b === 1) return String(a);
    return (a === 1 ? '' : a) + '√' + b;
  }

  // ① 展開と因数分解
  function genTenkai9() {
    var r = R(1, 10), a, b, t;
    if (r <= 4) { // 基礎: 乗法公式の展開
      t = R(0, 2);
      if (t === 0) { a = R(1, 6); b = R(1, 6);
        return Q('基礎', '(x+' + a + ')(x+' + b + ') を展開すると？',
          'x²+' + (a + b) + 'x+' + (a * b), ['x²+' + (a * b) + 'x+' + (a + b), 'x²+' + (a + b) + 'x+' + (a + b), 'x²+' + (a * b) + 'x+' + (a * b)]); }
      if (t === 1) { a = R(2, 8);
        return Q('基礎', '(x+' + a + ')² を展開すると？',
          'x²+' + (2 * a) + 'x+' + (a * a), ['x²+' + (a * a) + 'x+' + (2 * a), 'x²+' + a + 'x+' + (a * a), 'x²+' + (2 * a) + 'x+' + (2 * a)]); }
      a = R(2, 9);
      return Q('基礎', '(x+' + a + ')(x-' + a + ') を展開すると？',
        'x²-' + (a * a), ['x²+' + (a * a), 'x²-' + (2 * a), 'x²-' + a]); }
    if (r <= 8) { // 標準: 因数分解
      t = R(0, 2);
      if (t === 0) { a = R(1, 6); b = R(1, 6); while (b === a) b = R(1, 6);
        return Q('標準', 'x²+' + (a + b) + 'x+' + (a * b) + ' を因数分解すると？',
          '(x+' + a + ')(x+' + b + ')', ['(x+' + (a * b) + ')(x+1)', '(x-' + a + ')(x-' + b + ')', '(x+' + a + ')(x-' + b + ')']); }
      if (t === 1) { a = R(2, 9);
        return Q('標準', 'x²-' + (a * a) + ' を因数分解すると？',
          '(x+' + a + ')(x-' + a + ')', ['(x-' + a + ')²', '(x+' + a + ')²', '(x-' + (a * a) + ')(x+1)']); }
      a = R(2, 8);
      return Q('標準', 'x²+' + (2 * a) + 'x+' + (a * a) + ' を因数分解すると？',
        '(x+' + a + ')²', ['(x+' + (2 * a) + ')²', '(x+' + a + ')(x-' + a + ')', '(x+' + (a * a) + ')(x+2)']); }
    // 発展: 共通因数＋公式
    a = R(2, 5);
    return Q('発展', a + 'x²-' + (a * 9) + ' を因数分解すると？',
      a + '(x+3)(x-3)', ['(x+3)(x-3)', a + '(x-3)²', a + '(x²-9)']);
  }

  // ② 平方根
  function genHeihokon9() {
    var r = R(1, 10), a, b, t, n;
    if (r <= 4) { // 基礎
      t = R(0, 2);
      if (t === 0) { a = pick([4, 9, 16, 25, 36, 49, 64, 81, 100]);
        return Q('基礎', '√' + a + ' を計算すると？', String(Math.sqrt(a)), [String(a / 2), String(Math.sqrt(a) + 1), String(a)]); }
      if (t === 1) { a = pick([2, 3, 5, 6, 7, 10]);
        return Q('基礎', '（√' + a + '）² の値は？', String(a), [String(a * a), String(Math.round(Math.sqrt(a) * 10) / 10), String(2 * a)]); }
      a = pick([2, 3, 5, 7]); b = R(2, 5);
      return Q('基礎', '√' + a + ' × √' + b + ' を計算すると？', '√' + (a * b), ['√' + (a + b), String(a * b), '√' + (a * a * b)]); }
    if (r <= 8) { // 標準
      t = R(0, 2);
      if (t === 0) { b = pick([2, 3, 5, 6, 7]); a = pick([2, 3]); n = a * a * b;
        return Q('標準', '√' + n + ' を a√b の形にすると？', simRoot(n), ['√' + n, a + '√' + (b * a), (a + 1) + '√' + b]); }
      if (t === 1) { a = pick([2, 3, 5]); var c1 = R(2, 5), c2 = R(2, 5);
        return Q('標準', c1 + '√' + a + ' + ' + c2 + '√' + a + ' を計算すると？', (c1 + c2) + '√' + a, [(c1 * c2) + '√' + a, (c1 + c2) + '√' + (2 * a), (c1 + c2) + String(a)]); }
      a = pick([6, 10, 14, 15]); b = pick([2, 3, 5]);
      // √a ÷ √b が割り切れる組み合わせに限定
      var ok = (a % b === 0);
      if (!ok) { a = b * pick([2, 3, 5]); }
      return Q('標準', '√' + a + ' ÷ √' + b + ' を計算すると？', simRoot(a / b), ['√' + (a - b), '√' + (a * b), String(a / b)]); }
    // 発展: 分母の有理化
    a = pick([2, 3, 5, 7]);
    return Q('発展', '6/√' + a + ' の分母を有理化すると？（√を使った形）',
      (6 / a === Math.floor(6 / a) ? (6 / a) + '√' + a : '6√' + a + '/' + a),
      ['√' + a + '/6', '6/' + a, '√' + (6 * a)]);
  }

  // ③ 2次方程式
  function genNijihoutei9() {
    var r = R(1, 10), a, b, t;
    if (r <= 4) { // 基礎: x²=k, 因数分解で解ける
      t = R(0, 1);
      if (t === 0) { a = pick([4, 9, 16, 25, 36, 49]);
        return Q('基礎', 'x² = ' + a + ' の解は？', 'x = ±' + Math.sqrt(a), ['x = ' + Math.sqrt(a), 'x = ' + (a / 2), 'x = ±' + (a / 2)]); }
      a = R(1, 6); b = R(1, 6); while (b === a) b = R(1, 6);
      return Q('基礎', '(x-' + a + ')(x-' + b + ') = 0 の解は？', 'x = ' + a + ', ' + b, ['x = -' + a + ', -' + b, 'x = ' + (a + b), 'x = ' + a + b]); }
    if (r <= 8) { // 標準: 因数分解して解く
      a = R(1, 6); b = R(1, 6); while (b === a) b = R(1, 6);
      return Q('標準', 'x²-' + (a + b) + 'x+' + (a * b) + ' = 0 の解は？',
        'x = ' + a + ', ' + b, ['x = -' + a + ', -' + b, 'x = ' + (a + b) + ', ' + (a * b), 'x = ' + a + ', -' + b]); }
    // 発展: 解の公式（判別式がきれいな数）
    // x² + bx + c = 0, 解が整数 p,q → b=-(p+q), c=pq。あえて解の公式で確認する問い
    var p = nz(-5, 5), q = nz(-5, 5); while (q === p) q = nz(-5, 5);
    var bb = -(p + q), cc = p * q;
    var bs = (bb >= 0 ? '+' + bb : bb);
    var cs = (cc >= 0 ? '+' + cc : cc);
    var sol = 'x = ' + Math.min(p, q) + ', ' + Math.max(p, q);
    return Q('発展', 'x²' + (bb === 0 ? '' : bs + 'x') + cs + ' = 0 の解は？',
      sol, ['x = ' + (-p) + ', ' + (-q), 'x = ' + (p + q), 'x = ' + (p * q)]);
  }

  // ④ 2次関数 y=ax²
  function genNijikansu9() {
    var r = R(1, 10), a, x, t;
    if (r <= 4) { // 基礎
      t = R(0, 1);
      if (t === 0) { a = nz(-4, 4); x = R(1, 5);
        return Q('基礎', 'y = ' + (a === 1 ? '' : a) + 'x² で、x = ' + x + ' のときの y の値は？',
          String(a * x * x), [String(a * x), String(a * x * 2), String(a * (x + 1) * (x + 1))]); }
      return Q('基礎', 'y = 2x² のグラフの開き方（向き）は？', '上に開く（下に頂点）', ['下に開く（上に頂点）', '右に開く', '直線になる']); }
    if (r <= 8) { // 標準
      t = R(0, 1);
      if (t === 0) { a = pick([2, 3, -2, -3]); x = R(2, 4);
        // 変化の割合 = a(x1+x2)。x1=1..x, x2=x+1
        var x1 = R(1, 3), x2 = x1 + R(1, 3);
        var roc = a * (x1 + x2);
        return Q('標準', 'y = ' + a + 'x² で、x が ' + x1 + ' から ' + x2 + ' まで増加するときの変化の割合は？',
          String(roc), [String(a * (x2 - x1)), String(a * x1 * x2), String(a)]); }
      // 通る点から a を求める
      a = nz(-3, 3); x = R(2, 4); var y = a * x * x;
      return Q('標準', 'y = ax² が点(' + x + ', ' + y + ')を通るとき、a の値は？',
        String(a), [String(y), String(a * x), String(-a)]); }
    // 発展: yの変域
    a = pick([1, 2, 3]); var lo = nz(-3, -1), hi = R(1, 3);
    var vals = [a * lo * lo, a * hi * hi]; var ymax = Math.max(vals[0], vals[1]);
    return Q('発展', 'y = ' + (a === 1 ? '' : a) + 'x²（' + lo + ' ≦ x ≦ ' + hi + '）の y の変域は？',
      '0 ≦ y ≦ ' + ymax, [(a * lo * lo) + ' ≦ y ≦ ' + (a * hi * hi), '0 ≦ y ≦ ' + (a * Math.max(Math.abs(lo), hi)), lo + ' ≦ y ≦ ' + hi]);
  }

  // ⑤ 相似
  function genSoji9() {
    var r = R(1, 10), a, b, t;
    if (r <= 4) { // 基礎
      t = R(0, 1);
      if (t === 0) { a = R(2, 4); b = a * R(2, 4);
        return Q('基礎', '相似比が ' + a + ' : ' + b + ' のとき、対応する辺の長さの比は？',
          a + ' : ' + b, [b + ' : ' + a, (a * a) + ' : ' + (b * b), '1 : ' + (a + b)]); }
      return Q('基礎', '2つの三角形が相似であるとき、対応する角の大きさは？', 'それぞれ等しい', ['それぞれ2倍になる', 'すべて90°', '合計が180°']); }
    if (r <= 8) { // 標準: 相似比→線分の長さ
      a = R(2, 5); b = a + R(1, 4); var base = a * R(2, 4);
      var ans = base * b / a;
      return Q('標準', '相似な三角形で、相似比が ' + a + ' : ' + b + '。小さい方の辺が ' + base + ' のとき、対応する大きい方の辺は？',
        String(ans), [String(base * a / b), String(base + (b - a)), String(base * b)]); }
    // 発展: 面積比 = 相似比²
    a = R(2, 4); b = a + R(1, 3);
    return Q('発展', '相似比が ' + a + ' : ' + b + ' の2つの図形の面積比は？',
      (a * a) + ' : ' + (b * b), [a + ' : ' + b, (a * a * a) + ' : ' + (b * b * b), (2 * a) + ' : ' + (2 * b)]);
  }

  // ⑥ 円周角
  function genEnshukaku9() {
    var r = R(1, 10), a, t;
    if (r <= 4) { // 基礎
      t = R(0, 1);
      if (t === 0) { a = R(2, 8) * 10;
        return Q('基礎', '同じ弧に対する中心角が ' + a + '° のとき、円周角の大きさは？',
          (a / 2) + '°', [a + '°', (2 * a) + '°', (a / 2 + 10) + '°']); }
      a = R(2, 8) * 10;
      return Q('基礎', 'ある弧に対する円周角が ' + a + '° のとき、同じ弧に対する中心角は？',
        (2 * a) + '°', [(a / 2) + '°', a + '°', (a + 90) + '°']); }
    if (r <= 8) { // 標準
      t = R(0, 1);
      if (t === 0) return Q('標準', '半円の弧（直径）に対する円周角の大きさは？', '90°', ['180°', '45°', '60°']);
      a = R(2, 6) * 10;
      return Q('標準', '同じ弧に対する円周角どうしの大きさの関係は？（1つが ' + a + '° のとき、もう1つは）',
        a + '°（等しい）', [(a * 2) + '°', (a / 2) + '°', (180 - a) + '°']); }
    // 発展: 円に内接する四角形
    a = R(5, 12) * 10;
    return Q('発展', '円に内接する四角形で、1つの角が ' + a + '° のとき、向かい合う角の大きさは？',
      (180 - a) + '°', [a + '°', (360 - a) + '°', (a / 2) + '°']);
  }

  // ⑦ 三平方の定理
  function genSanpeihou9() {
    var r = R(1, 10), t;
    // 代表的なピタゴラス数
    var triples = [[3, 4, 5], [5, 12, 13], [8, 15, 17], [7, 24, 25], [6, 8, 10], [9, 12, 15]];
    if (r <= 4) { // 基礎: 斜辺を求める
      var tri = pick(triples); var k = pick([1, 1, 1, 2]);
      var a = tri[0] * k, b = tri[1] * k, c = tri[2] * k;
      return Q('基礎', '直角三角形で、直角をはさむ2辺が ' + a + ' と ' + b + ' のとき、斜辺の長さは？',
        String(c), [String(a + b), String(c + 1), String(Math.max(a, b))]); }
    if (r <= 8) { // 標準: 他の1辺を求める
      var tri2 = pick(triples); var a2 = tri2[0], b2 = tri2[1], c2 = tri2[2];
      return Q('標準', '直角三角形で、斜辺が ' + c2 + '、1辺が ' + a2 + ' のとき、残りの辺の長さは？',
        String(b2), [String(c2 - a2), String(c2), String(a2 + 1)]); }
    // 発展: 正方形の対角線・特別な直角三角形
    t = R(0, 1);
    if (t === 0) { var s = R(2, 6);
      return Q('発展', '1辺が ' + s + ' の正方形の対角線の長さは？', s + '√2', [s + '√3', String(s * 2), String(s) + '√' + s]); }
    var s2 = R(2, 6);
    return Q('発展', '1辺が ' + s2 + ' の正三角形の高さは？', (s2 % 2 === 0 ? (s2 / 2) + '√3' : s2 + '√3/2'), [s2 + '√2', String(s2), (s2 / 2) + '√2']);
  }

  // ⑧ 標本調査
  function genHyohon9() {
    var r = R(1, 10), t;
    if (r <= 4) { // 基礎: 用語
      t = R(0, 2);
      if (t === 0) return Q('基礎', '調べたい集団全体を調査することを何という？', '全数調査', ['標本調査', '無作為調査', '母集団']);
      if (t === 1) return Q('基礎', '集団の一部を取り出して調べ、全体を推測する調査を何という？', '標本調査', ['全数調査', '国勢調査', '実験']);
      return Q('基礎', '調査の対象となる集団全体を何という？', '母集団', ['標本', '度数', '階級']); }
    if (r <= 8) { // 標準: どちらの調査が適切か
      t = R(0, 1);
      if (t === 0) return Q('標準', '「電球の寿命の検査」に適した調査はどれ？', '標本調査', ['全数調査', 'どちらでもよい', '調査できない']);
      return Q('標準', '「学校の身体測定」に適した調査はどれ？', '全数調査', ['標本調査', 'どちらでもよい', '調査できない']); }
    // 発展: 比例で推定
    var cap = R(2, 5) * 10, marked = R(2, 5) * 10, recap = R(2, 6) * 10;
    // 池の魚: 印つき marked 匹を放流→再捕獲 recap 匹中 cap 匹に印。総数 = marked*recap/cap
    var mm = pick([2, 3, 4, 5]); var total = marked * mm; var recap2 = R(4, 8) * 10; var found = Math.round(recap2 * marked / total);
    if (found < 1) found = 1;
    var est = Math.round(marked * recap2 / found);
    return Q('発展', '池の魚に印をつけて ' + marked + ' 匹放流した。後日 ' + recap2 + ' 匹つかまえたら印つきが ' + found + ' 匹いた。池の魚はおよそ何匹と推定できる？',
      String(est) + '匹', [String(marked + recap2) + '匹', String(recap2 * found) + '匹', String(Math.round(recap2 / found)) + '匹']);
  }

  try {
    window.genTenkai9 = genTenkai9;
    window.genHeihokon9 = genHeihokon9;
    window.genNijihoutei9 = genNijihoutei9;
    window.genNijikansu9 = genNijikansu9;
    window.genSoji9 = genSoji9;
    window.genEnshukaku9 = genEnshukaku9;
    window.genSanpeihou9 = genSanpeihou9;
    window.genHyohon9 = genHyohon9;
  } catch (e) {}

  G9.addUnits('math', [
    { id: 'm9-tenkai', name: '展開と因数分解', icon: '🟰', color: 'blue', gen: 'genTenkai9', input: 'mcq', desc: '乗法公式・因数分解' },
    { id: 'm9-heihokon', name: '平方根', icon: '√', color: 'purple', gen: 'genHeihokon9', input: 'mcq', desc: '√の計算・有理化' },
    { id: 'm9-niji', name: '2次方程式', icon: '🔢', color: 'red', gen: 'genNijihoutei9', input: 'mcq', desc: '因数分解・解の公式' },
    { id: 'm9-nijikansu', name: '2次関数 y=ax²', icon: '📈', color: 'orange', gen: 'genNijikansu9', input: 'mcq', desc: '変化の割合・変域' },
    { id: 'm9-soji', name: '相似', icon: '📐', color: 'cyan', gen: 'genSoji9', input: 'mcq', desc: '相似比・面積比' },
    { id: 'm9-enshu', name: '円周角', icon: '⭕', color: 'pink', gen: 'genEnshukaku9', input: 'mcq', desc: '円周角と中心角' },
    { id: 'm9-sanpei', name: '三平方の定理', icon: '📏', color: 'teal', gen: 'genSanpeihou9', input: 'mcq', desc: 'ピタゴラスの定理' },
    { id: 'm9-hyohon', name: '標本調査', icon: '🎯', color: 'green', gen: 'genHyohon9', input: 'mcq', desc: '全数調査・標本調査・推定' }
  ]);
  G9.addDisplay({
    'm9-tenkai': { name: '展開因数の工房', emoji: '🟰', desc: '展開と因数分解（中3）' },
    'm9-heihokon': { name: '平方根の泉', emoji: '√', desc: '平方根（中3）' },
    'm9-niji': { name: '2次方程式の関所', emoji: '🔢', desc: '2次方程式（中3）' },
    'm9-nijikansu': { name: '放物線の丘', emoji: '📈', desc: '2次関数 y=ax²（中3）' },
    'm9-soji': { name: '相似の神殿', emoji: '📐', desc: '相似（中3）' },
    'm9-enshu': { name: '円周角の広間', emoji: '⭕', desc: '円周角（中3）' },
    'm9-sanpei': { name: '三平方の塔', emoji: '📏', desc: '三平方の定理（中3）' },
    'm9-hyohon': { name: '標本調査の観測所', emoji: '🎯', desc: '標本調査（中3）' }
  });
})();
