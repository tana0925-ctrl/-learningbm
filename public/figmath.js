/* ============================================================
   📐 FIGMATH_V1（2026-11-20）ネットレの 出題画面に ならって、算数・数学の 問題に 図を そえる
   ・答え方は 変えない（4択・数字入力の まま）。
   ・図は 修行・復習の 画面だけ（__fxShow を つかう）。問題に もともと 図が ある ものは さわらない。
   ・問題文から 数を 読みとって かく。読めなければ 何も 出さない。
   ・答えが そのまま 見えて しまう 図は かかない（数える・はかる ことが 学習の 中身の ときは のぞく）。
   QBLANK_V1：「分母だけ 答えて」「左の 数を 答えて」の 形を、ネットレと 同じ「□に あてはまる 数」に なおす。
   ============================================================ */
(function () {
  if (window.__FIGMATH__) return; window.__FIGMATH__ = 1;

  /* ── 分数の 計算（約分つき）── */
  function gcd(a, b) { a = Math.abs(a); b = Math.abs(b); while (b) { var t = a % b; a = b; b = t; } return a || 1; }
  function Fr(n, d) { if (d < 0) { n = -n; d = -d; } var g = gcd(n, d); return { n: n / g, d: d / g }; }
  function fmul(a, b) { return Fr(a.n * b.n, a.d * b.d); }
  function fdiv(a, b) { return Fr(a.n * b.d, a.d * b.n); }
  function parseNum(s) {   // "3と2/5" "2/7" "0.25" "4"
    s = String(s).trim(); var m;
    if ((m = s.match(/^(\d+)と(\d+)\/(\d+)$/))) return Fr(+m[1] * +m[3] + +m[2], +m[3]);
    if ((m = s.match(/^(\d+)\/(\d+)$/))) return Fr(+m[1], +m[2]);
    if ((m = s.match(/^(\d+)\.(\d+)$/))) { var k = Math.pow(10, m[2].length); return Fr(Math.round(parseFloat(s) * k), k); }
    if (/^\d+$/.test(s)) return Fr(+s, 1);
    return null;
  }
  function evalChain(expr) {   // "2/7 × 2/3 ÷ 1/2"
    var t = expr.split(/\s+([×÷])\s+/); var v = parseNum(t[0]); if (!v) return null;
    for (var i = 1; i < t.length; i += 2) { var x = parseNum(t[i + 1]); if (!x || !x.n && t[i] === '÷') return null; v = t[i] === '×' ? fmul(v, x) : fdiv(v, x); }
    return v;
  }

  /* ── QBLANK_V1：問題の 形を なおす ── */
  function fixFrac(p) {
    var q = String(p.q || ''); var m = q.match(/^([^\n]+?)\n(?:= \?\/\?\n|\(小数を分数に直して計算\)\n)?約分後の(分子|分母)は？$/);
    if (!m) return;
    var v = evalChain(m[1].replace(/\s+$/, '')); if (!v) return;
    var askN = m[2] === '分子'; if ((askN ? v.n : v.d) !== Number(p.ans)) return;
    var note = /小数を分数/.test(q) ? '（小数は 分数に なおして 計算）\n' : '';
    p.q = m[1] + ' ＝ ' + (askN ? '□/' + v.d : v.n + '/□') + '\n' + note + '□に あてはまる 数は？（約分した 答え）';
    if (!p.exp) p.exp = '計算して 約分すると ' + v.n + '/' + v.d + '。' + (askN ? '分子' : '分母') + 'は ' + (askN ? v.n : v.d);
  }
  function fixRatio(p) {
    var q = String(p.q || ''); var m = q.match(/^([\d./]+)：([\d./]+)\nかんたんな (?:整数の )?比に すると？\n（(左|右)の 数を 答えて）$/) || q.match(/^([\d./]+)：([\d./]+)\nかんたんな(?:整数の)?比にすると？\n（(左|右)の数を答えて）$/);
    if (!m) return;
    var a = parseNum(m[1]), b = parseNum(m[2]); if (!a || !b) return;
    var x = a.n * b.d, y = b.n * a.d, g = gcd(x, y); x /= g; y /= g;
    var left = m[3] === '左'; if ((left ? x : y) !== Number(p.ans)) return;
    p.q = m[1] + '：' + m[2] + ' ＝ ' + (left ? '□：' + y : x + '：□') + '\n□に あてはまる 数は？（かんたんな 整数の 比）';
    if (!p.exp) p.exp = '前と 後ろに 同じ 数を かけたり わったり して、いちばん かんたんな 整数に すると ' + x + '：' + y;
  }
  function wrapQ(name, fix) {
    var o = window[name]; if (typeof o !== 'function' || o.__fq) return;
    var w = function () { var p = o.apply(this, arguments); try { if (p && typeof p === 'object') fix(p); } catch (e) {} return p; };
    w.__fq = 1; w.__fx = 1; window[name] = w;
  }
  function installQ() {
    ['genFracMul6', 'genFracDiv6', 'genFracInt6', 'genFracMixed6', 'genFracTriple6', 'genFracDec6'].forEach(function (n) { wrapQ(n, fixFrac); });
    wrapQ('genRatio6', fixRatio);
  }

  /* ── 図の 部品 ── */
  var C = { line: '#334155', a: '#059669', b: '#d97706', red: '#e11d48', fillA: '#dcfce7', fillB: '#fef3c7', blue: '#2563eb', fillC: '#dbeafe', gray: '#94a3b8' };
  function svg(w, h, body, maxh) { return '<svg viewBox="0 0 ' + w + ' ' + h + '" style="width:100%;max-width:' + Math.min(330, Math.round(w * 1.3)) + 'px;max-height:' + (maxh || 150) + 'px" xmlns="http://www.w3.org/2000/svg" font-family="sans-serif">' + body + '</svg>'; }
  function tx(x, y, s, o) { o = o || {}; return '<text x="' + x + '" y="' + y + '" font-size="' + (o.fs || 12) + '" fill="' + (o.c || C.line) + '" text-anchor="' + (o.a || 'middle') + '"' + (o.b ? ' font-weight="bold"' : '') + '>' + s + '</text>'; }
  function ln(x1, y1, x2, y2, c, w, dash) { return '<line x1="' + x1 + '" y1="' + y1 + '" x2="' + x2 + '" y2="' + y2 + '" stroke="' + (c || C.line) + '" stroke-width="' + (w || 2) + '"' + (dash ? ' stroke-dasharray="4 3"' : '') + '/>'; }
  function rect(x, y, w, h, f, s, sw) { return '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" fill="' + (f || 'none') + '" stroke="' + (s || C.line) + '" stroke-width="' + (sw || 1.5) + '"/>'; }
  function poly(pts, f, s) { return '<polygon points="' + pts.map(function (p) { return p[0] + ',' + p[1]; }).join(' ') + '" fill="' + (f || 'none') + '" stroke="' + (s || C.line) + '" stroke-width="2"/>'; }
  function dot(x, y, r, f) { return '<circle cx="' + x + '" cy="' + y + '" r="' + r + '" fill="' + f + '"/>'; }

  var EMO = { 'クッキー': '🍪', 'いちご': '🍓', 'あめ': '🍬', 'みかん': '🍊', 'りんご': '🍎' };
  // もの を ならべる（5こずつ）。gone こ には ×
  function objs(e, n, gone) {
    var per = 5, gap = 4, s = 22, w = Math.min(n, 10) * (s + 2) + Math.floor((Math.min(n, 10) - 1) / 5) * gap + 10, rows = Math.ceil(n / 10), h = rows * (s + 6) + 6, b = '';
    for (var i = 0; i < n; i++) {
      var col = i % 10, row = Math.floor(i / 10), x = 5 + col * (s + 2) + Math.floor(col / per) * gap + s / 2, y = 4 + row * (s + 6) + s - 4;
      b += tx(x, y, e, { fs: 18 });
      if (gone && i >= n - gone) b += ln(x - 9, y - 15, x + 9, y + 3, C.red, 2.5) + ln(x + 9, y - 15, x - 9, y + 3, C.red, 2.5);
    }
    return { w: w, h: h, b: b };
  }
  function figObjAdd(e, a, b) {
    var A = objs(e, a), B = objs(e, b), W = A.w + B.w + 30, H = Math.max(A.h, B.h) + 8;
    return svg(W, H, rect(1, 1, A.w, H - 2, C.fillA, C.a, 1.5) + '<g transform="translate(0,4)">' + A.b + '</g>' + tx(A.w + 15, H / 2 + 6, '＋', { fs: 18, b: 1 }) + rect(A.w + 29, 1, B.w, H - 2, C.fillB, C.b, 1.5) + '<g transform="translate(' + (A.w + 29) + ',4)">' + B.b + '</g>', 110);
  }
  function figObjSub(e, a, b) { var A = objs(e, a, b); return svg(A.w + 4, A.h + 8, rect(1, 1, A.w, A.h + 4, C.fillA, C.a, 1.5) + '<g transform="translate(1,4)">' + A.b + '</g>', 110); }
  // 10の まとまり（●）
  function figDots(a, b, sub) {
    var n = sub ? a : a + b, cols = Math.ceil(n / 10), W = cols * 70 + 10, b2 = '';
    for (var k = 0; k < cols; k++) {
      var x0 = 8 + k * 70; b2 += rect(x0, 8, 60, 26, '#fff', C.line, 1.2);
      for (var j = 0; j < 10; j++) { var i = k * 10 + j; if (i >= n) break; var cx = x0 + 6 + (j % 5) * 12, cy = 15 + Math.floor(j / 5) * 12; var col = sub ? (i >= a - b ? '#cbd5e1' : C.blue) : (i < a ? C.blue : C.b); b2 += dot(cx, cy, 4.5, col); if (sub && i >= a - b) b2 += ln(cx - 4, cy - 4, cx + 4, cy + 4, C.red, 1.5); }
    }
    return svg(W, 42, b2, 70);
  }
  // 位の ブロック（百・十・一）
  function figBlocks(n) {
    var h = Math.floor(n / 100), t = Math.floor(n % 100 / 10), o = n % 10, b = '', x = 6;
    for (var i = 0; i < h; i++) { b += rect(x, 6, 40, 40, '#fde68a', C.b, 1.2); for (var g = 1; g < 10; g++) b += ln(x + g * 4, 6, x + g * 4, 46, '#f59e0b', 0.5) + ln(x, 6 + g * 4, x + 40, 6 + g * 4, '#f59e0b', 0.5); x += 44; }
    if (h) x += 6;
    for (var j = 0; j < t; j++) { b += rect(x, 6, 6, 40, '#bfdbfe', C.blue, 1); x += 8; }
    if (t) x += 6;
    for (var k = 0; k < o; k++) { b += rect(x + (k % 2) * 8, 6 + Math.floor(k / 2) * 8, 6, 6, '#bbf7d0', C.a, 1); }
    if (o) x += 18;
    return svg(Math.max(60, x + 4), 52, b, 80);
  }
  // テープ図：全体 と 部分（□は わからない ところ）
  function figTape(parts, total, labels) {
    var W = 300, x0 = 10, w = 280, sum = 0; parts.forEach(function (p) { sum += (typeof p.v === 'number' ? p.v : 0); });
    var known = parts.filter(function (p) { return typeof p.v === 'number'; }).length, unk = parts.length - known;
    var T = typeof total === 'number' ? total : sum; var b = '', x = x0, cols = [C.fillA, C.fillB, C.fillC];
    parts.forEach(function (p, i) {
      var pw = typeof p.v === 'number' ? Math.max(30, w * p.v / (T || 1)) : Math.max(40, (w - (x - x0)) / unk - 0);
      if (i === parts.length - 1) pw = x0 + w - x;
      b += rect(x, 30, pw, 24, cols[i % 3], C.line, 1.5) + tx(x + pw / 2, 47, p.label != null ? p.label : String(p.v), { fs: 13, b: 1, c: p.v == null ? C.red : C.line });
      x += pw;
    });
    b += ln(x0, 22, x0 + w, 22, C.line, 1) + ln(x0, 18, x0, 26, C.line, 1) + ln(x0 + w, 18, x0 + w, 26, C.line, 1) + tx(x0 + w / 2, 15, total == null ? '□' : String(total), { fs: 13, b: 1, c: total == null ? C.red : C.line });
    return svg(W, 62, b, 85);
  }
  // 時計
  function figClock(h, m) {
    var cx = 70, cy = 70, R = 60, b = '<circle cx="70" cy="70" r="60" fill="#fff" stroke="' + C.line + '" stroke-width="3"/>';
    for (var i = 0; i < 60; i++) { var a = i * Math.PI / 30, r1 = i % 5 ? 55 : 50; b += ln(cx + Math.sin(a) * r1, cy - Math.cos(a) * r1, cx + Math.sin(a) * 58, cy - Math.cos(a) * 58, C.line, i % 5 ? 0.8 : 2); }
    for (var k = 1; k <= 12; k++) { var a2 = k * Math.PI / 6; b += tx(cx + Math.sin(a2) * 41, cy - Math.cos(a2) * 41 + 5, k, { fs: 13, b: 1 }); }
    var am = m * Math.PI / 30, ah = ((h % 12) + m / 60) * Math.PI / 6;
    b += ln(cx, cy, cx + Math.sin(ah) * 30, cy - Math.cos(ah) * 30, C.red, 5) + ln(cx, cy, cx + Math.sin(am) * 48, cy - Math.cos(am) * 48, C.blue, 3) + dot(cx, cy, 4, C.line);
    return svg(140, 140, b, 140);
  }
  // ものさし（cm と mm）
  function figRuler(mm, maxcm) {
    maxcm = maxcm || Math.max(3, Math.ceil(mm / 10) + 1); var u = Math.min(28, 290 / maxcm), W = maxcm * u + 24, b = rect(8, 26, maxcm * u + 8, 26, '#fef9c3', C.b, 1.5);
    for (var i = 0; i <= maxcm * 10; i++) { var x = 12 + i * u / 10, L = i % 10 ? (i % 5 ? 6 : 10) : 14; b += ln(x, 26, x, 26 + L, C.line, i % 10 ? 0.7 : 1.4); if (i % 10 === 0) b += tx(x, 64, i / 10, { fs: 10 }); }
    b += rect(12, 10, mm * u / 10, 10, '#93c5fd', C.blue, 1.2);
    return svg(W, 70, b, 90);
  }
  // 筆算（たて書き）
  function figHissan(a, op, b) {
    var A = String(a), B = String(b), L = Math.max(A.length, B.length + 1), cw = 22, W = (L + 1) * cw + 16, b2 = '';
    function row(s, y) { var o = ''; for (var i = 0; i < s.length; i++) o += tx(W - 10 - (s.length - i - 0.5) * cw, y, s[i], { fs: 22, b: 1 }); return o; }
    b2 += row(A, 28) + row(B, 58) + tx(W - 10 - (L + 0.3) * cw + 6, 58, op, { fs: 22, b: 1 }) + ln(8, 66, W - 6, 66, C.line, 2.5);
    b2 += tx(W - 10 - cw / 2, 92, '？', { fs: 18, c: C.red });
    return svg(W, 100, b2, 120);
  }
  // 数直線
  function figNumLine(min, max, step, marks, lab) {
    var W = 320, x0 = 18, w = 284, n = Math.round((max - min) / step), b = ln(x0 - 6, 40, x0 + w + 8, 40, C.line, 2);
    for (var i = 0; i <= n; i++) { var v = min + i * step, x = x0 + w * i / n, big = Math.abs(v - Math.round(v / (step * 5)) * step * 5) < 1e-9; b += ln(x, 40 - (big ? 8 : 5), x, 40 + (big ? 8 : 5), C.line, big ? 1.6 : 1); if (lab(v, i)) b += tx(x, 64, lab(v, i), { fs: 11 }); }
    (marks || []).forEach(function (mk) { var x = x0 + w * (mk.v - min) / (max - min); b += '<path d="M' + x + ' 30 l-6 -10 h12 z" fill="' + (mk.c || C.red) + '"/>' + (mk.t ? tx(x, 16, mk.t, { fs: 12, b: 1, c: mk.c || C.red }) : ''); });
    return svg(W, 72, b, 90);
  }
  // 棒グラフ
  function figBars(items, unit) {
    var mx = Math.max.apply(null, items.map(function (i) { return i.v; })), top = Math.ceil(mx / 5) * 5 || 5, W = 60 + items.length * 52, H = 150, b = '';
    var st = top <= 20 ? 5 : top <= 50 ? 10 : 20; top = Math.ceil(mx / st) * st || st;
    for (var g = 0; g <= top; g += st / 5) { var y = 125 - 105 * g / top; b += ln(34, y, W - 6, y, g % st ? '#eef2f7' : '#cbd5e1', 1); if (g % st === 0) b += tx(28, y + 4, g, { fs: 10, a: 'end' }); }
    items.forEach(function (it, i) { var x = 46 + i * 52, h = 105 * it.v / top; b += rect(x, 125 - h, 30, h, '#93c5fd', C.blue, 1.5) + tx(x + 15, 141, it.l, { fs: 11 }); });
    b += ln(34, 125, W - 6, 125) + ln(34, 18, 34, 125) + tx(10, 14, '（' + unit + '）', { fs: 10, a: 'start' });
    return svg(W, H, b, 160);
  }
  // 円（半径・直径）
  function figCircle(lab, kind) {
    var b = '<circle cx="80" cy="62" r="52" fill="' + C.fillC + '" stroke="' + C.blue + '" stroke-width="2.5"/>' + dot(80, 62, 3, C.line);
    if (kind === 'd') b += ln(28, 62, 132, 62, C.red, 2.5) + tx(80, 56, lab, { fs: 13, b: 1, c: C.red }); else b += ln(80, 62, 132, 62, C.red, 2.5) + tx(106, 56, lab, { fs: 13, b: 1, c: C.red });
    return svg(160, 124, b, 130);
  }
  // 長方形・平行四辺形・三角形・台形・ひし形
  function figShape(kind, a, b, c) {
    var s = '', base = 112;
    if (kind === 'rect') s = rect(30, 20, 150, 80, C.fillA, C.a, 2.5) + tx(105, 116, a, { b: 1 }) + tx(192, 64, b, { b: 1, a: 'start' });
    if (kind === 'para') s = poly([[30, base], [170, base], [210, 30], [70, 30]], C.fillA, C.a) + ln(70, 30, 70, base, C.red, 1.5, 1) + rect(70, base - 8, 8, 8, 'none', C.red, 1) + tx(100, base + 14, a, { b: 1 }) + tx(64, 74, b, { b: 1, c: C.red, a: 'end' });
    if (kind === 'tri') s = poly([[30, base], [190, base], [120, 26]], C.fillA, C.a) + ln(120, 26, 120, base, C.red, 1.5, 1) + rect(120, base - 8, 8, 8, 'none', C.red, 1) + tx(110, base + 14, a, { b: 1 }) + tx(126, 74, b, { b: 1, c: C.red, a: 'start' });
    if (kind === 'trap') s = poly([[30, base], [210, base], [160, 30], [80, 30]], C.fillA, C.a) + ln(80, 30, 80, base, C.red, 1.5, 1) + tx(120, 22, a, { b: 1 }) + tx(120, base + 14, b, { b: 1 }) + tx(74, 76, c, { b: 1, c: C.red, a: 'end' });
    if (kind === 'rhom') s = poly([[120, 14], [200, 66], [120, 118], [40, 66]], C.fillA, C.a) + ln(40, 66, 200, 66, C.red, 1.5, 1) + ln(120, 14, 120, 118, C.blue, 1.5, 1) + tx(170, 60, a, { b: 1, c: C.red }) + tx(128, 100, b, { b: 1, c: C.blue, a: 'start' });
    return svg(240, 130, s, 140);
  }
  // 直方体（見取図）
  function figBox(a, b, c, cube) {
    var x = 30, y = 50, W = cube ? 70 : 110, H = cube ? 70 : 60, dx = 34, dy = -26, s = '';
    s += poly([[x, y], [x + W, y], [x + W, y + H], [x, y + H]], C.fillA, C.a) + poly([[x, y], [x + dx, y + dy], [x + W + dx, y + dy], [x + W, y]], '#bbf7d0', C.a) + poly([[x + W, y], [x + W + dx, y + dy], [x + W + dx, y + H + dy], [x + W, y + H]], '#86efac', C.a);
    s += ln(x, y + H, x + dx, y + H + dy, C.gray, 1.2, 1) + ln(x + dx, y + H + dy, x + dx, y + dy, C.gray, 1.2, 1) + ln(x + dx, y + H + dy, x + W + dx, y + H + dy, C.gray, 1.2, 1);
    if (a) s += tx(x + W / 2, y + H + 16, a, { b: 1 }); if (b) s += tx(x + W + dx / 2 + 8, y + H + dy / 2 + 12, b, { b: 1, a: 'start' }); if (c) s += tx(x - 6, y + H / 2 + 4, c, { b: 1, a: 'end' });
    return svg(220, 140, s, 140);
  }
  // 円柱
  function figCyl(r, h) {
    var s = '<ellipse cx="90" cy="30" rx="50" ry="13" fill="' + C.fillB + '" stroke="' + C.b + '" stroke-width="2"/>' + ln(40, 30, 40, 110, C.b) + ln(140, 30, 140, 110, C.b) + '<path d="M40 110 A50 13 0 0 0 140 110" fill="none" stroke="' + C.b + '" stroke-width="2"/>' + '<path d="M40 110 A50 13 0 0 1 140 110" fill="none" stroke="' + C.b + '" stroke-width="1.2" stroke-dasharray="4 3"/>';
    s += ln(90, 30, 140, 30, C.red, 1.8) + dot(90, 30, 2.5, C.line) + tx(115, 25, r, { b: 1, c: C.red }) + tx(148, 74, h, { b: 1, a: 'start' });
    return svg(200, 128, s, 135);
  }
  // 角（一直線・1回転・対頂角）
  function figAngle(kind, known) {
    var s = '';
    if (kind === 'line') { var ra = Math.PI * known / 180, h1 = ra / 2, h2 = (ra + Math.PI) / 2; s = ln(10, 100, 230, 100, C.line, 2.5) + ln(120, 100, 120 + Math.cos(ra) * 95, 100 - Math.sin(ra) * 95, C.blue, 2.5) + tx(120 + Math.cos(h1) * 40, 104 - Math.sin(h1) * 40, known + '°', { b: 1, c: C.blue }) + tx(120 + Math.cos(h2) * 40, 104 - Math.sin(h2) * 40, '□', { b: 1, c: C.red }); }
    if (kind === 'cross') s = ln(20, 20, 220, 110, C.line, 2.5) + ln(20, 110, 220, 20, C.line, 2.5) + tx(52, 70, known + '°', { b: 1, c: C.blue }) + tx(188, 70, '□', { b: 1, c: C.red });
    return svg(240, 120, s, 130);
  }
  // 三角形（角）
  function figTriAngles(a, b) { return svg(240, 125, poly([[20, 110], [220, 110], [140, 20]], C.fillA, C.a) + tx(46, 104, a + '°', { b: 1, c: C.blue }) + tx(196, 104, b + '°', { b: 1, c: C.blue }) + tx(140, 46, '□', { b: 1, c: C.red }), 130); }
  // 分数の テープ
  function figFracBar(n, d) {
    var w = 260, b = '';
    for (var i = 0; i < d; i++) b += rect(20 + i * w / d, 18, w / d, 26, i < n ? '#fca5a5' : '#fff', C.line, 1.5);
    b += tx(10, 36, '0', { fs: 11 }) + tx(290, 36, '1', { fs: 11 });
    return svg(300, 56, b, 70);
  }
  // 座標（比例・1次関数）
  function figGraph(fn, xr, yr, pts) {
    var W = 200, H = 200, ox = W / 2, oy = H / 2, ux = 90 / xr, uy = 90 / yr, b = '';
    for (var i = -xr; i <= xr; i++) b += ln(ox + i * ux, 8, ox + i * ux, H - 8, '#e2e8f0', 0.8);
    for (var j = -yr; j <= yr; j++) b += ln(8, oy - j * uy, W - 8, oy - j * uy, '#e2e8f0', 0.8);
    b += ln(6, oy, W - 6, oy, C.line, 1.5) + ln(ox, H - 6, ox, 6, C.line, 1.5) + tx(W - 6, oy - 4, 'x', { fs: 11, a: 'end' }) + tx(ox + 6, 14, 'y', { fs: 11, a: 'start' }) + tx(ox - 6, oy + 12, 'O', { fs: 10 });
    if (fn) { var d = '', pen = false; for (var x = -xr; x <= xr + 1e-9; x += xr / 60) { var y = fn(x); if (!isFinite(y) || Math.abs(y) > yr * 1.05) { pen = false; continue; } d += (pen ? ' L' : ' M') + (ox + x * ux).toFixed(1) + ' ' + (oy - y * uy).toFixed(1); pen = true; } b += '<path d="' + d.trim() + '" fill="none" stroke="' + C.blue + '" stroke-width="2.5"/>'; }
    (pts || []).forEach(function (p) { b += dot(ox + p[0] * ux, oy - p[1] * uy, 4, C.red) + tx(ox + p[0] * ux + 6, oy - p[1] * uy - 6, '(' + p[0] + ', ' + p[1] + ')', { fs: 10, c: C.red, a: 'start' }); });
    return svg(W, H, b, 170);
  }
  // 直角三角形（三平方）
  function figRightTri(a, b, c) { return svg(220, 130, poly([[30, 110], [190, 110], [30, 20]], C.fillA, C.a) + rect(30, 100, 10, 10, 'none', C.line, 1) + tx(110, 126, a, { b: 1 }) + tx(22, 70, b, { b: 1, a: 'end' }) + tx(118, 58, c, { b: 1, c: C.red }), 130); }
  // 円周角
  function figInscribed(center, insc) {
    var cx = 100, cy = 70, R = 55, cd = (parseFloat(center) || parseFloat(insc) * 2 || 100) * Math.PI / 180, A = [cx - R * Math.sin(cd / 2), cy + R * Math.cos(cd / 2)], B = [cx + R * Math.sin(cd / 2), cy + R * Math.cos(cd / 2)], P = [cx - 10, cy - 54];
    var s = '<circle cx="' + cx + '" cy="' + cy + '" r="' + R + '" fill="#fff" stroke="' + C.line + '" stroke-width="2"/>' + ln(A[0], A[1], P[0], P[1], C.blue) + ln(B[0], B[1], P[0], P[1], C.blue) + ln(A[0], A[1], cx, cy, C.b) + ln(B[0], B[1], cx, cy, C.b) + dot(cx, cy, 3, C.line);
    s += tx(P[0], P[1] + 26, insc, { b: 1, c: C.blue }) + tx(cx, cy + 22, center, { b: 1, c: C.b }) + tx(A[0] - 6, A[1] + 12, 'A', { fs: 11 }) + tx(B[0] + 6, B[1] + 12, 'B', { fs: 11 }) + tx(cx + 4, cy - 4, 'O', { fs: 10, a: 'start' });
    return svg(200, 140, s, 140);
  }
  // おうぎ形
  function figSector(r, deg) {
    var a = deg * Math.PI / 180, x = 80 + 70 * Math.cos(-a), y = 110 + 70 * Math.sin(-a);
    return svg(200, 130, '<path d="M80 110 L150 110 A70 70 0 ' + (deg > 180 ? 1 : 0) + ' 0 ' + x.toFixed(1) + ' ' + y.toFixed(1) + ' Z" fill="' + C.fillB + '" stroke="' + C.b + '" stroke-width="2"/>' + tx(115, 124, r, { b: 1 }) + tx(98, 104, deg + '°', { fs: 11, b: 1, c: C.red }), 130);
  }
  // 温度計ふうの 数直線（正負）
  function figSignLine(vals) {
    var mn = Math.min.apply(null, vals.concat([0])), mx = Math.max.apply(null, vals.concat([0])), lo = Math.floor(Math.min(mn, -1) - 1), hi = Math.ceil(Math.max(mx, 1) + 1);
    if (hi - lo > 24) { var st = Math.ceil((hi - lo) / 20); return figNumLine(lo - (lo % st + st) % st, hi + (st - (hi % st + st) % st) % st, st, vals.map(function (v) { return { v: v, t: String(v) }; }), function (v) { return v % (st * 5) === 0 ? String(v) : ''; }); }
    return figNumLine(lo, hi, 1, vals.map(function (v) { return { v: v, t: String(v) }; }), function (v) { return (v === 0 || v % 5 === 0 || v === lo || v === hi) ? String(v) : ''; });
  }


  // L・dL の ます
  function figKasa(L, dL) {
    var b = '', x = 8;
    for (var i = 0; i < L; i++) { b += rect(x, 10, 34, 70, '#fff', C.line, 1.5) + rect(x, 10, 34, 70, '#93c5fd', C.blue, 1.5) + tx(x + 17, 96, '1L', { fs: 11 }); x += 40; }
    if (dL) { b += rect(x, 10, 34, 70, '#fff', C.line, 1.5) + rect(x, 10 + 70 * (1 - dL / 10), 34, 70 * dL / 10, '#93c5fd', C.blue, 1); for (var k = 1; k < 10; k++) b += ln(x, 10 + 7 * k, x + 8, 10 + 7 * k, C.line, 0.8); b += tx(x + 17, 96, '1Lます', { fs: 10 }); x += 40; }
    return svg(Math.max(60, x + 4), 104, b, 110);
  }
  // はかり（kg）
  function figScale(g, maxkg) {
    var cx = 80, cy = 78, R = 62, b = '<circle cx="80" cy="78" r="62" fill="#fff" stroke="' + C.line + '" stroke-width="3"/>', tot = maxkg * 1000;
    for (var i = 0; i < maxkg * 10; i++) { var a = 2 * Math.PI * i / (maxkg * 10), r1 = i % 10 ? (i % 5 ? 56 : 52) : 48; b += ln(cx + Math.sin(a) * r1, cy - Math.cos(a) * r1, cx + Math.sin(a) * 60, cy - Math.cos(a) * 60, C.line, i % 10 ? 0.8 : 2); if (i % 10 === 0) b += tx(cx + Math.sin(a) * 38, cy - Math.cos(a) * 38 + 4, (i / 10) + 'kg', { fs: 10, b: 1 }); }
    var an = 2 * Math.PI * g / tot; b += ln(cx, cy, cx + Math.sin(an) * 54, cy - Math.cos(an) * 54, C.red, 3) + dot(cx, cy, 4, C.line);
    return svg(160, 150, b, 140);
  }
  // 位取りの 表
  function figPlace(heads, digits) {
    var w = Math.min(44, 300 / heads.length), W = heads.length * w + 12, b = '';
    heads.forEach(function (h, i) { b += rect(6 + i * w, 6, w, 22, '#f1f5f9', C.line, 1) + tx(6 + i * w + w / 2, 21, h, { fs: Math.min(12, w / 2.6) }) + rect(6 + i * w, 28, w, 30, '#fff', C.line, 1) + (digits[i] != null ? tx(6 + i * w + w / 2, 50, digits[i], { fs: 18, b: 1, c: digits[i] === '□' ? C.red : C.line }) : ''); });
    return svg(W, 64, b, 80);
  }
  // 円グラフ（割合）
  function figPie(parts) {
    var cx = 70, cy = 70, R = 60, a0 = -Math.PI / 2, b = '', cols = ['#93c5fd', '#fca5a5', '#fde68a', '#bbf7d0', '#e9d5ff'];
    parts.forEach(function (p, i) { var a1 = a0 + 2 * Math.PI * p.v / 100, la = p.v > 50 ? 1 : 0; b += '<path d="M70 70 L' + (cx + R * Math.cos(a0)).toFixed(1) + ' ' + (cy + R * Math.sin(a0)).toFixed(1) + ' A60 60 0 ' + la + ' 1 ' + (cx + R * Math.cos(a1)).toFixed(1) + ' ' + (cy + R * Math.sin(a1)).toFixed(1) + ' Z" fill="' + cols[i % 5] + '" stroke="#fff" stroke-width="2"/>'; var am = (a0 + a1) / 2; b += tx(cx + 36 * Math.cos(am), cy + 36 * Math.sin(am) + 4, p.l, { fs: 11, b: 1 }); a0 = a1; });
    return svg(140, 140, b, 130);
  }
  // 表（比例・反比例）
  function figTable(r1, r2) {
    var w = Math.min(48, 300 / r1.length), W = r1.length * w + 10, b = '';
    [r1, r2].forEach(function (r, j) { r.forEach(function (v, i) { b += rect(5 + i * w, 6 + j * 28, w, 28, i ? '#fff' : '#f1f5f9', C.line, 1) + tx(5 + i * w + w / 2, 25 + j * 28, v, { fs: 13, b: i === 0, c: v === '□' ? C.red : C.line }); }); });
    return svg(W, 66, b, 80);
  }
  // 玉の ふくろ
  function figBalls(list) {
    var b = '<path d="M20 40 Q20 110 90 110 Q160 110 160 40 Z" fill="#f8fafc" stroke="' + C.line + '" stroke-width="2"/>', k = 0;
    list.forEach(function (it) { for (var i = 0; i < it.n; i++) { var x = 42 + (k % 6) * 19, y = 58 + Math.floor(k / 6) * 19; b += dot(x, y, 8, it.c); k++; } });
    return svg(180, 118, b, 110);
  }
  // さいころ 2こ の 表
  function figDiceTable() {
    var b = '', w = 22;
    for (var i = 0; i <= 6; i++) for (var j = 0; j <= 6; j++) { var x = 6 + j * w, y = 6 + i * w; b += rect(x, y, w, w, (i && j) ? '#fff' : '#e2e8f0', C.line, 0.8); if (!i && j) b += tx(x + w / 2, y + 15, j, { fs: 11, b: 1 }); if (i && !j) b += tx(x + w / 2, y + 15, i, { fs: 11, b: 1 }); }
    return svg(7 * w + 12, 7 * w + 12, b + tx(6 + w / 2, 21, '＋', { fs: 10 }), 170);
  }
  // 樹形図（ならび方）
  function figTree(names) {
    var n = names.length, b = '', W = 300, H = 40 + (n - 1) * 30;
    if (n > 4) return '';
    names.forEach(function (a, i) { var y0 = 20 + i * (H - 30) / Math.max(1, n - 1); b += tx(20, y0 + 4, a, { b: 1, c: C.blue }); var rest = names.filter(function (_, k) { return k !== i; }); rest.forEach(function (r, j) { var y1 = y0 - 10 + j * 10; b += ln(30, y0, 80, y1, C.gray, 1) + tx(88, y1 + 4, r, { fs: 10 }); }); });
    return svg(W, H + 10, b + tx(150, H + 4, '1番目を きめると、2番目は のこりから えらぶ', { fs: 10, c: C.gray }), 130);
  }
  // 角柱・角すい（見取図）
  function figPrismN(n, pyramid) {
    var cx = 100, top = 24, bot = 104, rx = 60, ry = 16, b = '', P = [], Q = [];
    ry = 22; for (var i = 0; i < n; i++) { var a = 2 * Math.PI * i / n + Math.PI / 2 + 0.35; P.push([cx + rx * Math.cos(a), bot + ry * Math.sin(a)]); Q.push([cx + rx * Math.cos(a), top + ry * Math.sin(a)]); }
    var front = function (i) { return Math.sin(2 * Math.PI * i / n + Math.PI / 2 + 0.35) >= -0.01; };
    for (var j = 0; j < n; j++) { var k = (j + 1) % n, fr = front(j) && front(k); b += ln(P[j][0], P[j][1], P[k][0], P[k][1], fr ? C.a : C.gray, fr ? 2 : 1.2, !fr); if (pyramid) b += ln(P[j][0], P[j][1], cx, top - 6, front(j) ? C.a : C.gray, front(j) ? 2 : 1.2, !front(j)); else { b += ln(Q[j][0], Q[j][1], Q[k][0], Q[k][1], C.a, 2) + ln(P[j][0], P[j][1], Q[j][0], Q[j][1], front(j) ? C.a : C.gray, front(j) ? 2 : 1.2, !front(j)); } }
    return svg(200, 128, b, 130);
  }
  // 円すい
  function figCone() { return svg(200, 128, '<ellipse cx="100" cy="104" rx="60" ry="16" fill="' + C.fillB + '" stroke="' + C.b + '" stroke-width="2"/>' + ln(40, 104, 100, 14, C.b) + ln(160, 104, 100, 14, C.b), 130); }
  function figSphere() { return svg(160, 128, '<circle cx="80" cy="64" r="56" fill="' + C.fillC + '" stroke="' + C.blue + '" stroke-width="2"/><ellipse cx="80" cy="64" rx="56" ry="14" fill="none" stroke="' + C.blue + '" stroke-width="1" stroke-dasharray="4 3"/>', 130); }
  /* ── 単元ごとの 図 ── */
  var N = function (s) { return Number(s); };
  function FIG(mode, q) {
    var m, e;
    // ものの 文章題（1年・2年）
    if ((m = q.match(/^(クッキー|いちご|あめ|みかん|りんご)が (\d+)こ あります。\n(\d+)こ (もらう|たべる)と/))) {
      e = EMO[m[1]]; var a = N(m[2]), b = N(m[3]);
      if (a + b <= 20 && m[4] === 'もらう') return figObjAdd(e, a, b);
      if (a <= 20 && m[4] === 'たべる') return figObjSub(e, a, b);
      if (m[4] === 'もらう') return figTape([{ v: a }, { v: b }], null);
      return figTape([{ v: b, label: b + '（たべた）' }, { v: a - b, label: '□' }], a);
    }
    // □ の 式（たし算・ひき算）→ テープ図
    if ((m = q.match(/^□ ?[+＋] ?(\d+) ?[=＝] ?(\d+)/))) return figTape([{ v: N(m[2]) - N(m[1]), label: '□' }, { v: N(m[1]) }], N(m[2]));
    if ((m = q.match(/^(\d+) ?[+＋] ?□ ?[=＝] ?(\d+)/))) return figTape([{ v: N(m[1]) }, { v: N(m[2]) - N(m[1]), label: '□' }], N(m[2]));
    if ((m = q.match(/^□ ?[−-] ?(\d+) ?[=＝] ?(\d+)/))) return figTape([{ v: N(m[1]), label: m[1] + '（ひく）' }, { v: N(m[2]) }], null);
    if ((m = q.match(/^(\d+) ?[−-] ?□ ?[=＝] ?(\d+)/))) return figTape([{ v: N(m[1]) - N(m[2]), label: '□（ひく）' }, { v: N(m[2]) }], N(m[1]));
    // 1年の たし算・ひき算（数だけ）→ ●
    if (/^m1-(add|sub)/.test(mode) || mode === 'm1-3num') {
      if ((m = q.match(/^(\d+) \+ (\d+) = \?$/)) && N(m[1]) + N(m[2]) <= 20) return figDots(N(m[1]), N(m[2]));
      if ((m = q.match(/^(\d+) − (\d+) = \?$/)) && N(m[1]) <= 20) return figDots(N(m[1]), N(m[2]), true);
    }
    if (mode === 'm1-kazu' && (m = q.match(/^(\d+) と いくつで 10？/))) return figDots(N(m[1]), 0);
    // 2年の 2けた → ブロック
    if (/^m2-(add2|sub2)$/.test(mode) && (m = q.match(/^(\d+) [+−] (\d+) = \?$/))) return '<div style="display:flex;gap:6px;justify-content:center;align-items:center">' + figBlocks(N(m[1])) + '<b>' + (q.indexOf('+') > 0 ? '＋' : '−') + '</b>' + figBlocks(N(m[2])) + '</div>';
    // 位
    if ((m = q.match(/^10が (\d+)こ と 1が (\d+)こ/))) return figBlocks(N(m[1]) * 10 + N(m[2]));
    if ((m = q.match(/^100を (\d)こ、10を (\d)こ、1を (\d)こ/))) return figBlocks(N(m[1]) * 100 + N(m[2]) * 10 + N(m[3]));
    // とけい
    if (mode === 'm1-tokei') {
      if ((m = q.match(/ながい はりが 12、みじかい はりが (\d+)/)) || (m = q.match(/みじかい はりが (\d+)、ながい はりが 12/))) return figClock(N(m[1]), 0);
      if ((m = q.match(/みじかい はりが (\d+) と \d+ の あいだ、ながい はりが 6/))) return figClock(N(m[1]), 30);
      if ((m = q.match(/ながい はりが (\d+) を さして/))) return figClock(12, N(m[1]) * 5).replace(/<line[^>]*stroke="#e11d48" stroke-width="5"\/>/, '');
    }
    if ((m = q.match(/^(?:午前|午後)?(\d+)時(?:(\d+)分)? の (\d+)分後は/))) return figClock(N(m[1]), N(m[2] || 0));
    if ((m = q.match(/^(\d+)時(\d+)分 から (\d+)時(\d+)分 までは/))) return '<div style="display:flex;gap:8px;justify-content:center">' + figClock(N(m[1]), N(m[2])) + figClock(N(m[3]), N(m[4])) + '</div>';
    // 長さ（ものさし）
    if (mode === 'm2-length') {
      if ((m = q.match(/^(\d+)cm (\d+)mm は/))) return figRuler(N(m[1]) * 10 + N(m[2]));
      if ((m = q.match(/^(\d+)mm /)) && N(m[1]) <= 100) return figRuler(N(m[1]), Math.ceil(N(m[1]) / 10) + 1);
    }
    // 道のり
    if ((m = q.match(/^家から 公園まで (\d+)m、公園から 駅まで (\d+)m/))) return svg(300, 70, ln(20, 40, 280, 40, C.line, 3) + dot(20, 40, 6, C.a) + dot(150, 40, 6, C.b) + dot(280, 40, 6, C.blue) + tx(20, 64, '家') + tx(150, 64, '公園') + tx(280, 64, '駅') + tx(85, 32, m[1] + 'm', { b: 1 }) + tx(215, 32, m[2] + 'm', { b: 1 }), 80);
    // 筆算
    if (/^m3-(hissan|kakehissan|mul1)$/.test(mode) || mode === 'm3-large') {
      if ((m = q.match(/^(\d+) ([＋+−×]) (\d+) [＝=] [？?]/))) return figHissan(m[1], m[2].replace('+', '＋'), m[3]);
    }
    if (/^m[45]-dec|^decimal$/.test(mode) && (m = q.match(/^([\d.]+) × ([\d.]+) = \?$/))) return figHissan(m[1], '×', m[2]);
    // わり算（小さい数は まとまりの 図）
    if (mode === 'm3-div0' && (m = q.match(/^(\d+) ÷ (\d+) = \?$/)) && N(m[1]) <= 40) { var A = N(m[1]), B = N(m[2]), s = '', per = A / B; for (var i = 0; i < B; i++) { s += rect(6 + i * 54, 6, 50, 40, '#fff', C.line, 1); } for (var k = 0; k < A; k++) s += dot(14 + (k % 12) * 9, 54 + Math.floor(k / 12) * 9, 3.5, C.blue); return svg(Math.max(120, B * 54 + 12), 90, s + tx(6, 84, A + 'こを ' + B + 'つの さらに 同じ 数ずつ', { fs: 10, a: 'start' }), 100); }
    // 円
    if ((m = q.match(/直径 (\d+)cm の 円の 半径/))) return figCircle(m[1] + 'cm', 'd');
    if ((m = q.match(/半径 (\d+)cm の 円の 直径/))) return figCircle(m[1] + 'cm', 'r');
    if ((m = q.match(/半径 (\d+)cm の ?円の ?(円周|面積)/))) return figCircle(m[1] + 'cm', 'r');
    if ((m = q.match(/直径 (\d+)cm の 円の 円周/))) return figCircle(m[1] + 'cm', 'd');
    // 小数・分数（数直線・テープ）
    if ((m = q.match(/^0\.1を (\d+)こ 集めた/)) && N(m[1]) <= 20) return figNumLine(0, 2, 0.1, [{ v: 0.1, t: '0.1' }], function (v, i) { return i % 10 === 0 ? String(i / 10) : ''; });
    if ((m = q.match(/^1\/(\d+) ＋ 1\/\1 ＝/))) return figFracBar(2, N(m[1]));
    if ((m = q.match(/^1を (\d+)つに 等しく 分けた/))) return figFracBar(1, N(m[1]));
    // 棒グラフ
    if ((m = q.match(/^表：(.+?)。\n/))) { var it = m[1].split('・').map(function (x) { var t = x.match(/^(\S+) (\d+)人$/); return t ? { l: t[1], v: N(t[2]) } : null; }); if (it.every(Boolean)) return figBars(it, '人'); }
    if ((m = q.match(/棒が (\d+)目もりの とき/))) return figBars([{ l: '', v: N(m[1]) }], '人');
    // 重さ・かさ（量の 図は 3年・2年の 単位）
    // 4年 角度
    if ((m = q.match(/一直線（180°）を 2つに 分けた。\n一方が (\d+)°/))) return figAngle('line', N(m[1]));
    if ((m = q.match(/直線が 交わって できた 角の 1つが (\d+)°/)) || (m = q.match(/2直線が交わっています。(\d+)° の角の対頂角/))) return figAngle('cross', N(m[1]));
    // がい数（数直線）
    if (mode === 'rounding' && (m = q.match(/^(\d+) を\n(一|十|百|千|一万) の位(で四捨五入|までのがい数)/))) {
      var U = { '一': 1, '十': 10, '百': 100, '千': 1000, '一万': 10000 }[m[2]], n0 = N(m[1]), unit = /四捨五入/.test(m[3]) ? U * 10 : U, lo = Math.floor(n0 / unit) * unit;
      return figNumLine(lo, lo + unit, unit / 10, [{ v: n0, t: String(n0) }], function (v, i) { return i === 0 || i === 10 ? String(Math.round(v)) : (i === 5 ? '←まん中→' : ''); });
    }
    // 面積・体積
    if ((m = q.match(/底辺 (\d+)cm・高さ (\d+)cm の 平行四辺形/))) return figShape('para', m[1] + 'cm', m[2] + 'cm');
    if ((m = q.match(/面積が (\d+)cm² で、底辺が (\d+)cm の 平行四辺形/))) return figShape('para', m[2] + 'cm', '□');
    if ((m = q.match(/上底 (\d+)cm・下底 (\d+)cm・高さ (\d+)cm の 台形/))) return figShape('trap', m[1] + 'cm', m[2] + 'cm', m[3] + 'cm');
    if ((m = q.match(/対角線が (\d+)cm と (\d+)cm の ひし形/))) return figShape('rhom', m[1] + 'cm', m[2] + 'cm');
    if ((m = q.match(/たて(\d+)cm 横(\d+)cm 高さ(\d+)cm/))) return figBox(m[2] + 'cm', m[1] + 'cm', m[3] + 'cm');
    if ((m = q.match(/1辺 (\d+)cm の立方体/))) return figBox(m[1] + 'cm', m[1] + 'cm', m[1] + 'cm', 1);
    if ((m = q.match(/底面の 半径が (\d+)cm、高さが (\d+)cm の 円柱/)) || (m = q.match(/底面の半径 (\d+)cm、高さ (\d+)cm の円柱/))) return figCyl(m[1] + 'cm', m[2] + 'cm');
    if ((m = q.match(/まわりの 長さが (\d+)cm の 長方形で、たてが □cm/))) return figShape('rect', '○cm', '□cm');
    // 角（三角形・四角形）
    if ((m = q.match(/三角形の ?2つの ?角が ?(\d+)° ?と ?(\d+)°/)) || (m = q.match(/三角形の2つの内角が (\d+)° と (\d+)°/))) return figTriAngles(N(m[1]), N(m[2]));
    // 速さ
    if ((m = q.match(/^(\d+)kmを 時速(\d+)kmで/))) return figTape([{ v: N(m[2]), label: '1時間で ' + m[2] + 'km' }, { v: N(m[1]) - N(m[2]), label: '…' }], N(m[1])).replace('>' + m[1] + '<', '>' + m[1] + 'km<');
    if ((m = q.match(/^時速(\d+)kmで (\d+)時間走ると/))) { var parts = []; for (var t2 = 0; t2 < N(m[2]); t2++) parts.push({ v: N(m[1]), label: m[1] + 'km' }); return figTape(parts, null); }
    // 割合
    if ((m = q.match(/^(\d+)円の (\d+)% は何円/))) return figNumLine(0, 100, 10, [{ v: N(m[2]), t: m[2] + '%' }], function (v) { return v === 0 ? '0円' : (v === 100 ? m[1] + '円' : ''); });
    if ((m = q.match(/^(\d+)人のうち(\d+)人です。/))) return figTape([{ v: N(m[2]), label: m[2] + '人' }, { v: N(m[1]) - N(m[2]), label: '' }], N(m[1]));
    // 比
    if ((m = q.match(/^(\d+)円を 兄と 弟で (\d+)：(\d+) に/))) { var pa = [], i3; for (i3 = 0; i3 < N(m[2]); i3++) pa.push({ v: 1, label: '兄' }); for (i3 = 0; i3 < N(m[3]); i3++) pa.push({ v: 1, label: '弟' }); return figTape(pa, m[1] + '円'); }
    // 6年 データ（ドットプロット）
    if (mode === 'm6-data' && (m = q.match(/\n([\d、]+)\n/))) { var vs = m[1].split('、').map(N), mn2 = Math.min.apply(null, vs), mx2 = Math.max.apply(null, vs), cnt = {}, b3 = ''; var lo2 = mn2 - 1, hi2 = mx2 + 1, W2 = 300, x02 = 16, w2 = 268; b3 += ln(x02, 80, x02 + w2, 80); for (var v2 = lo2; v2 <= hi2; v2++) { var xx = x02 + w2 * (v2 - lo2) / (hi2 - lo2); b3 += ln(xx, 76, xx, 84, C.line, 1); if ((hi2 - lo2) <= 15 || v2 % 5 === 0) b3 += tx(xx, 96, v2, { fs: 9 }); } vs.forEach(function (v) { cnt[v] = (cnt[v] || 0) + 1; var xx = x02 + w2 * (v - lo2) / (hi2 - lo2); b3 += dot(xx, 80 - 9 * cnt[v], 4, C.blue); }); return svg(W2, 104, b3, 110); }

    // かさ・重さ
    if ((m = q.match(/^(\d+)L(\d+)dL は/)) && N(m[1]) <= 6) return figKasa(N(m[1]), N(m[2]));
    if ((m = q.match(/^(\d+)L は 何dL/)) && N(m[1]) <= 6) return figKasa(N(m[1]), 0);
    if ((m = q.match(/^(\d+)kg (\d+)g ＝ □g/))) return figScale(N(m[1]) * 1000 + N(m[2]), N(m[1]) + 1 + (N(m[1]) % 2));
    if ((m = q.match(/^(\d+)g ＝ □kg/)) && N(m[1]) < 6000) return figScale(N(m[1]), 6);
    // あまりの ある わり算
    if ((m = q.match(/^(\d+) ÷ (\d+) ＝ (?:□|\d+) あまり/)) && N(m[1]) <= 60) { var A2 = N(m[1]), B2 = N(m[2]), s2 = ''; for (var k2 = 0; k2 < A2; k2++) s2 += dot(10 + (k2 % 15) * 18, 12 + Math.floor(k2 / 15) * 18, 6, C.blue); return svg(280, 14 + Math.ceil(A2 / 15) * 18, s2, 90) + '<div style="font-size:11px;color:#64748b">' + A2 + 'こを ' + B2 + 'こずつ まとめると…</div>'; }
    // 3つの 数（1年）
    if (mode === 'm1-3num' && (m = q.match(/^(\d+) \+ (\d+) \+ (\d+) = \?$/)) && N(m[1]) + N(m[2]) + N(m[3]) <= 30) return figDots(N(m[1]) + N(m[2]), N(m[3]));
    // 位取り
    if ((m = q.match(/^([\d.]+) を 10倍 した 数は/)) || (m = q.match(/^([\d.]+) を 10で わった 数は/))) { var str = m[1]; var ip = str.split('.')[0], fp = (str.split('.')[1] || ''); var heads = ['百', '十', '一', '1/10', '1/100', '1/1000']; var dg = ['', '', '', '', '', '']; ip.split('').reverse().forEach(function (c, i) { dg[2 - i] = c; }); fp.split('').forEach(function (c, i) { dg[3 + i] = c; }); return figPlace(heads, dg); }
    // 分数（約分・通分・たし算）
    if ((m = q.match(/^(\d+)\/(\d+) を ?約分/)) && N(m[2]) <= 24) return figFracBar(N(m[1]), N(m[2]));
    if ((m = q.match(/^(\d+)\/(\d+) ([＋−]) (\d+)\/(\d+) ＝ ？/)) && N(m[2]) <= 12 && N(m[5]) <= 12) return figFracBar(N(m[1]), N(m[2])) + figFracBar(N(m[4]), N(m[5]));
    if ((m = q.match(/^(\d+)\/(\d+) を 小数で/)) && N(m[2]) <= 20) return figFracBar(N(m[1]), N(m[2]));
    // 帯グラフ・円グラフ
    if ((m = q.match(/帯グラフで、A が (\d+)%、B が (\d+)%、のこりが C/))) { var a1 = N(m[1]), b1 = N(m[2]); return svg(300, 60, rect(10, 14, 280 * a1 / 100, 28, '#93c5fd', C.line, 1.5) + tx(10 + 140 * a1 / 100, 33, 'A ' + a1 + '%', { fs: 11, b: 1 }) + rect(10 + 280 * a1 / 100, 14, 280 * b1 / 100, 28, '#fca5a5', C.line, 1.5) + tx(10 + 280 * a1 / 100 + 140 * b1 / 100, 33, 'B ' + b1 + '%', { fs: 11, b: 1 }) + rect(10 + 280 * (a1 + b1) / 100, 14, 280 * (100 - a1 - b1) / 100, 28, '#fde68a', C.line, 1.5) + tx(10 + 280 * (a1 + b1) / 100 + 140 * (100 - a1 - b1) / 100, 33, 'C □%', { fs: 11, b: 1, c: C.red }) + tx(10, 56, '0%', { fs: 9 }) + tx(290, 56, '100%', { fs: 9 }), 70); }
    if (false) return figPie([{ v: N(m[1]), l: 'A' }, { v: N(m[2]), l: 'B' }, { v: 100 - N(m[1]) - N(m[2]), l: 'C' }]);
    if ((m = q.match(/円グラフで、全体の (\d+)% に あたる/))) return figPie([{ v: N(m[1]), l: m[1] + '%' }, { v: 100 - N(m[1]), l: '' }]);
    // 比例・反比例（表）
    if ((m = q.match(/1こ (\d+)円の あめを □こ 買うと/))) return figTable(['□（こ）', '1', '2', '3', '4'], ['○（円）', m[1], String(2 * m[1]), '', '']);
    if ((m = q.match(/毎分 (\d+)L ずつ 水を 入れます/))) return figTable(['時間（分）', '1', '2', '3', '…'], ['水（L）', m[1], String(2 * m[1]), String(3 * m[1]), '']);
    if ((m = q.match(/yはxに比例し、\nx=1のとき y=(\d+)。\nx=(\d+)のとき/))) return figTable(['x', '1', '2', '3', m[2]], ['y', m[1], String(2 * m[1]), String(3 * m[1]), '□']);
    if ((m = q.match(/yはxに反比例し、\nx=1のとき y=(\d+)。\nx=(\d+)のとき/))) return figTable(['x', '1', '2', '3', m[2]], ['y', m[1], String(m[1] / 2).replace(/\.\d{2,}/, '…'), String(m[1] / 3).replace(/\.\d{2,}/, '…'), '□']);
    if ((m = q.match(/だんを □だん つむと、高さが ○cm に なります（1だん (\d+)cm）/))) return figTable(['□（だん）', '1', '2', '3', '…'], ['○（cm）', m[1], String(2 * m[1]), String(3 * m[1]), '']);
    // 場合の数・確率
    if ((m = q.match(/^(\d)人が 1列に/)) && N(m[1]) <= 3) return figTree(['A', 'B', 'C'].slice(0, N(m[1])));
    if ((m = q.match(/A、B、C の3人が1列に並ぶ/))) return figTree(['A', 'B', 'C']);
    if (/2個のさいころを同時に投げる/.test(q)) return figDiceTable();
    if ((m = q.match(/赤玉 ?(\d+)個(?:と|、)白玉 ?(\d+)個/)) && N(m[1]) + N(m[2]) <= 18) return figBalls([{ n: N(m[1]), c: '#ef4444' }, { n: N(m[2]), c: '#e2e8f0' }]);
    if ((m = q.match(/当たりくじ (\d+) 本、はずれくじ (\d+) 本/)) && N(m[1]) + N(m[2]) <= 18) return figBalls([{ n: N(m[1]), c: '#f59e0b' }, { n: N(m[2]), c: '#e2e8f0' }]);
    // 立体
    if ((m = q.match(/(三|四|五|六)角(柱|すい) ?の/))) { var nn = { '三': 3, '四': 4, '五': 5, '六': 6 }[m[1]]; return figPrismN(nn, m[2] === 'すい'); }
    if (/直方体の|はこの 形の|さいころの 形/.test(q) && /数|形/.test(q)) return figBox('', '', '');
    if (/円すい/.test(q) && !/展開図/.test(q)) return figCone();
    if (/円柱の 底面|円柱の 側面|^【[^】]+】円柱 の/.test(q)) return figCyl('', '');
    if (/半径 \d+cm の球/.test(q)) return figSphere();
    // 正多角形
    if ((m = q.match(/^正(三|五|六|八|九|十)角形の/))) { var n9 = { '三': 3, '五': 5, '六': 6, '八': 8, '九': 9, '十': 10 }[m[1]], pts = []; for (var i9 = 0; i9 < n9; i9++) { var a9 = 2 * Math.PI * i9 / n9 - Math.PI / 2; pts.push([70 + 55 * Math.cos(a9), 66 + 55 * Math.sin(a9)]); } return svg(140, 130, poly(pts, C.fillA, C.a), 120); }
    // 平均
    if ((m = q.match(/てんすう：([\dてん, ]+)\n/))) { var it2 = m[1].split(',').map(function (x, i) { return { l: (i + 1) + '回', v: N(x.replace(/[^\d]/g, '')) }; }); if (it2.length <= 6) return figBars(it2, '点'); }
    // 中学：正負の数
    if (mode === 'm7-seifu') {
      if ((m = q.match(/^【[^】]+】\((-\d+)\) \+ \((-?\d+)\) はいくつ/)) || (m = q.match(/^【[^】]+】\((-\d+)\) \+ (\d+) はいくつ/))) return figSignLine([N(m[1]), N(m[1]) + N(m[2])].slice(0, 1));
      if ((m = q.match(/いちばん(小さい|大きい)数はどれ？\n\s*([-\d ,]+)/))) return figSignLine(m[2].split(',').map(function (x) { return N(x.trim()); }));
      if ((m = q.match(/絶対値 \|(-?\d+)\|/))) return figSignLine([N(m[1])]);
    }
    // 中学：比例・1次関数・2次関数
    if ((m = q.match(/点 \((-?\d+), (-?\d+)\) を通るとき、式は/))) return figGraph(null, Math.max(6, Math.abs(N(m[1])) + 2), Math.max(6, Math.abs(N(m[2])) + 2), [[N(m[1]), N(m[2])]]);
    if ((m = q.match(/1次関数 y = (-?\d*)x([+-]\d+) の切片/))) { var k2 = m[1] === '' ? 1 : m[1] === '-' ? -1 : N(m[1]), c2 = N(m[2]); return figGraph(function (x) { return k2 * x + c2; }, 6, 8); }
    if ((m = q.match(/2直線 y = (-?\d*)x([+-]\d+) と y = (-?\d*)x([+-]\d+) の交点/))) { var f1 = { k: m[1] === '' ? 1 : m[1] === '-' ? -1 : N(m[1]), c: N(m[2]) }, f2 = { k: m[3] === '' ? 1 : m[3] === '-' ? -1 : N(m[3]), c: N(m[4]) }; var g = figGraph(function (x) { return f1.k * x + f1.c; }, 6, 8); var g2 = figGraph(function (x) { return f2.k * x + f2.c; }, 6, 8); var p2 = g2.match(/<path d="[^"]+" fill="none" stroke="#2563eb"[^>]*>/); return p2 ? g.replace('</svg>', p2[0].replace('#2563eb', '#d97706') + '</svg>') : g; }
    if ((m = q.match(/y = (-?\d*)x² ?（(-?\d+) ≦ x ≦ (-?\d+)）/))) { var a9 = m[1] === '' ? 1 : m[1] === '-' ? -1 : N(m[1]); return figGraph(function (x) { return a9 * x * x; }, 4, Math.max(4, Math.abs(a9) * 16)); }
    // 中学：図形
    if ((m = q.match(/直角をはさむ2辺が (\d+) と (\d+) のとき、斜辺/))) return figRightTri(m[1], m[2], '□');
    if ((m = q.match(/斜辺が (\d+)、1辺が (\d+) のとき、残りの辺/))) return figRightTri(m[2], '□', m[1]);
    if ((m = q.match(/同じ弧に対する中心角が (\d+)° のとき、円周角/))) return figInscribed(m[1] + '°', '□');
    if ((m = q.match(/弧に対する円周角が (\d+)° のとき、同じ弧に対する中心角/))) return figInscribed('□', m[1] + '°');
    if ((m = q.match(/半径 (\d+)cm、中心角 (\d+)° のおうぎ形/))) return figSector(m[1] + 'cm', N(m[2]));
    if ((m = q.match(/平行な2直線に1本の直線が交わっています。\n錯角の一方が (\d+)°/))) return svg(240, 120, ln(10, 30, 230, 30, C.line, 2) + ln(10, 95, 230, 95, C.line, 2) + ln(60, 115, 190, 10, C.blue, 2) + tx(176, 46, m[1] + '°', { b: 1, c: C.blue }) + tx(82, 88, '□', { b: 1, c: C.red }), 130);
    return '';
  }
  window.__fmFig = FIG;
  window.__FMH = { svg: svg, tx: tx, ln: ln, rect: rect, poly: poly, dot: dot, C: C, tape: figTape, blocks: figBlocks, clock: figClock, ruler: figRuler, hissan: figHissan, numline: figNumLine, bars: figBars, circle: figCircle, shape: figShape, box: figBox, cyl: figCyl, fracBar: figFracBar, graph: figGraph, sector: figSector, table: figTable, pie: figPie, dots: figDots };

  function installShow() {
    var o = window.__fxShow; if (typeof o !== 'function' || o.__fm) return;
    var w = function (prob) {
      try {
        if (prob && !prob.fig && typeof prob.q === 'string' && !/^\s*</.test(prob.q)) {
          var mode = window.trainingMode || '';
          var f = FIG(String(mode), prob.q.replace(/\r/g, ''));
          if (!f && window.__fmExtra) { try { f = window.__fmExtra(String(mode), prob.q.replace(/\r/g, ''), prob) || ''; } catch (e2) { f = ''; } }
          if (f) prob.fig = f;
        }
      } catch (e) {}
      return o.apply(this, arguments);
    };
    w.__fm = 1; window.__fxShow = w;
  }
  function install() { installQ(); installShow(); }
  install(); setTimeout(install, 0); setTimeout(install, 1600); setTimeout(install, 3500);
  window.addEventListener('load', function () { install(); setTimeout(install, 500); });
})();
