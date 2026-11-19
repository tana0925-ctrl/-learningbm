/* ============================================================
   NETORE_V1（2026-11-20）ネットレの 単元一覧と くらべて、足りない 単元を 足す パック
   ・答え方は 4択（mcq）か 数字（numpad）だけ。問題は すべて オリジナル。
   ・exp（まちがえた ときの かいせつ）と fig（図）を できる ものには つける。
   ・public/index.html は 変えずに window 経由で CURRICULUM に 足す（g3y.js と 同じ しくみ）。
   ============================================================ */
(function () {
  if (window.__GNL__) return; window.__GNL__ = 1;
  var R = function (a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; };
  var P = function (a) { return a[R(0, a.length - 1)]; };
  var bank = function (b) { return (typeof _pickBank === 'function') ? _pickBank(b) : null; };
  var Q = function (q, correct, wrongs, exp) { return { q: q, correct: correct, wrongs: wrongs, exp: exp }; };
  var pickQ = function (arr) { var o = arr[R(0, arr.length - 1)]; var p = bank([o]); if (p && o.exp) p.exp = o.exp; if (p && o.fig) p.fig = o.fig; return p; };
  var H = function () { return window.__FMH || null; };
  var gcd = function (a, b) { a = Math.abs(a); b = Math.abs(b); while (b) { var t = a % b; a = b; b = t; } return a || 1; };
  var r2 = function (x) { return Math.round(x * 1000) / 1000; };
  var shuffleW = function (c, ws) { var o = []; ws.forEach(function (w) { if (String(w) !== String(c) && o.indexOf(String(w)) < 0) o.push(String(w)); }); return o.slice(0, 3); };

  /* ═════════ 1年：なん十・2けたと1けた ═════════ */
  window.genNanju1 = function () {
    var p = R(0, 5), h = H();
    if (p === 0) { var a = R(1, 8), b = R(1, 9 - a); return { q: (a * 10) + ' + ' + (b * 10) + ' = ?', ans: (a + b) * 10, exp: '10の まとまりで 考える：' + a + 'こ＋' + b + 'こ＝' + (a + b) + 'こ → ' + ((a + b) * 10), fig: h ? h.blocks(a * 10) + h.blocks(b * 10) : '' }; }
    if (p === 1) { var c = R(3, 10), d = R(1, c - 1); return { q: (c * 10) + ' − ' + (d * 10) + ' = ?', ans: (c - d) * 10, exp: '10の まとまりで 考える：' + c + 'こ−' + d + 'こ＝' + (c - d) + 'こ → ' + ((c - d) * 10) }; }
    if (p === 2) { var t = R(2, 9) * 10, o = R(1, 9); return { q: t + ' + ' + o + ' = ?', ans: t + o, exp: t + ' と ' + o + ' で ' + (t + o) + '（十の くらいは そのまま）', fig: h ? h.blocks(t + o) : '' }; }
    if (p === 3) { var x = R(2, 9) * 10 + R(1, 5), y = R(1, 9 - x % 10); return { q: x + ' + ' + y + ' = ?', ans: x + y, exp: '一の くらいどうし：' + (x % 10) + '＋' + y + '＝' + (x % 10 + y) + '。十の くらいは そのまま' }; }
    if (p === 4) { var u = R(2, 9) * 10 + R(5, 9), v = R(1, u % 10); return { q: u + ' − ' + v + ' = ?', ans: u - v, exp: '一の くらいどうし：' + (u % 10) + '−' + v + '＝' + (u % 10 - v) + '。十の くらいは そのまま' }; }
    var w = R(2, 9) * 10 + R(1, 9); return { q: w + ' − ' + (w % 10) + ' = ?', ans: w - w % 10, exp: '一の くらいを ぜんぶ ひくと なん十が のこる' };
  };
  window.genBunsho1 = function () {
    var p = R(0, 4);
    if (p === 0) { var a = R(4, 9), b = R(1, a - 1), c = R(1, 9 - (a - b)); return { q: 'バスに ' + a + 'にん のって います。\n' + b + 'にん おりて、' + c + 'にん のりました。\nいま なんにん？', ans: a - b + c, exp: a + '−' + b + '＝' + (a - b) + '、' + (a - b) + '＋' + c + '＝' + (a - b + c) }; }
    if (p === 1) { var r = R(5, 12), w = R(2, r - 1); return { q: 'あかい はなが ' + r + 'ほん、しろい はなが ' + w + 'ほん。\nどちらが なんぼん おおい？\n（なんぼん の ところを こたえよう）', ans: r - w, exp: 'ちがいは ひきざん：' + r + '−' + w + '＝' + (r - w) }; }
    if (p === 2) { var f = R(2, 8), bk = R(2, 8); return { q: 'まえに ' + f + 'にん、うしろに ' + bk + 'にん います。\nあいだに じぶんが います。\nぜんぶで なんにん？', ans: f + bk + 1, exp: f + '＋' + bk + '＋1（じぶん）＝' + (f + bk + 1), fig: (function () { var h = H(); if (!h) return ''; var s = ''; for (var i = 0; i < f + bk + 1; i++) s += h.dot(14 + i * 18, 20, 7, i === f ? '#e11d48' : '#2563eb'); return h.svg(Math.max(80, (f + bk + 1) * 18 + 12), 40, s, 50); })() }; }
    if (p === 3) { var n = R(6, 15), k = R(2, n - 2); return { q: 'こどもが ' + n + 'にん ならんで います。\nまえから ' + k + 'ばんめの 人の うしろには\nなんにん いる？', ans: n - k, exp: n + '−' + k + '＝' + (n - k) + '（じぶんを いれない）' }; }
    var e = R(5, 9), g = R(2, 4); return { q: 'あめを ' + e + 'こ もって います。\nおとうとに ' + g + 'こ あげて、\nおかあさんから ' + (g + 1) + 'こ もらいました。\nいま なんこ？', ans: e - g + g + 1, exp: e + '−' + g + '＋' + (g + 1) + '＝' + (e + 1) };
  };

  /* ═════════ 2年：100を こえる 計算・1万までの数・()と くふう・九九の きまり ═════════ */
  window.genAdd3_2 = function () {
    var p = R(0, 3), h = H();
    if (p === 0) { var a = R(51, 99), b = R(101 - a, 99); return { q: a + ' + ' + b + ' = ?', ans: a + b, exp: '一の くらい、十の くらいの じゅんに たす。十の くらいが 10を こえたら 百の くらいへ くり上がる', fig: h ? h.hissan(a, '＋', b) : '' }; }
    if (p === 1) { var c = R(101, 189), d = R(c - 99, 99); if (d < 10) d = 10 + R(0, 9); return { q: c + ' − ' + d + ' = ?', ans: c - d, exp: '百の くらいから 十の くらいに くり下げて 計算する', fig: h ? h.hissan(c, '−', d) : '' }; }
    if (p === 2) { var e = R(100, 899), f = R(1, 99); if ((e % 100) + f >= 100) f = 99 - e % 100; if (f < 1) f = 1; return { q: e + ' + ' + f + ' = ?', ans: e + f, exp: '百の くらいは そのまま。十・一の くらいを たす', fig: h ? h.hissan(e, '＋', f) : '' }; }
    var g = R(100, 999), k = R(1, Math.min(99, g % 100 || 1)); return { q: g + ' − ' + k + ' = ?', ans: g - k, exp: '百の くらいは そのまま。十・一の くらいを ひく', fig: h ? h.hissan(g, '−', k) : '' };
  };
  window.genMan2 = function () {
    var p = R(0, 5);
    if (p === 0) { var a = R(1, 9), b = R(0, 9), c = R(0, 9), d = R(0, 9); return { q: '1000を ' + a + 'こ、100を ' + b + 'こ、10を ' + c + 'こ、1を ' + d + 'こ\nあわせた 数は？', ans: a * 1000 + b * 100 + c * 10 + d, exp: '千の くらい ' + a + '、百 ' + b + '、十 ' + c + '、一 ' + d + ' → ' + (a * 1000 + b * 100 + c * 10 + d) }; }
    if (p === 1) { var n = R(11, 99) * 100; return { q: n + ' は 100を なんこ あつめた 数？', ans: n / 100, exp: '100が 10こで 1000。' + n + ' は 100が ' + (n / 100) + 'こ' }; }
    if (p === 2) { var s = R(1, 9) * 1000 + R(0, 9) * 100, st = P([10, 100]), m = s + st * R(1, 3); return { q: s + ' から ' + st + 'ずつ ふえる 数の ならびで、\n' + s + '、' + (s + st) + '、' + (s + 2 * st) + '、□\n□に あてはまる 数は？', ans: s + 3 * st, exp: st + 'ずつ ふえるので ' + (s + 2 * st) + '＋' + st + '＝' + (s + 3 * st) }; }
    if (p === 3) { return { q: '9999 より 1 大きい 数は？', ans: 10000, exp: '9999＋1＝10000（一万）。千が 10こで 一万' }; }
    if (p === 4) { var x = R(1000, 9999), y = x + P([-1, 1]) * P([1, 10, 100, 1000]); if (y > 9999 || y < 1000) y = x - 1; return { q: x + ' と ' + y + '、大きいのは どっち？\n（大きい ほうの 数を 答えよう）', ans: Math.max(x, y), exp: '上の くらいから じゅんに くらべる' }; }
    var t = R(2, 9) * 1000; return { q: '1000を ' + (t / 1000) + 'こ あつめた 数は？', ans: t, exp: '1000が ' + (t / 1000) + 'こで ' + t };
  };
  window.genKufu2 = function () {
    var p = R(0, 3);
    if (p === 0) { var a = R(11, 39), b = R(1, 9), c = 10 - b; return { q: a + ' + ' + b + ' + ' + c + ' = ?\n（' + b + ' + ' + c + ' を さきに すると かんたん）', ans: a + 10, exp: b + '＋' + c + '＝10 を さきに。' + a + '＋10＝' + (a + 10) }; }
    if (p === 1) { var d = R(12, 48), e = R(11, 39), f = R(1, 9); return { q: '(' + d + ' + ' + e + ') + ' + f + ' = ?', ans: d + e + f, exp: '( ) の 中を さきに：' + d + '＋' + e + '＝' + (d + e) + '、' + (d + e) + '＋' + f + '＝' + (d + e + f) }; }
    if (p === 2) { var g = R(30, 90), k = R(1, 9), m = R(1, 9); return { q: g + ' − (' + k + ' + ' + m + ') = ?', ans: g - k - m, exp: '( ) の 中を さきに：' + k + '＋' + m + '＝' + (k + m) + '、' + g + '−' + (k + m) + '＝' + (g - k - m) }; }
    var n = R(20, 70), o = R(1, 9) * 1 + 0, q2 = 10 - o; return { q: n + ' + ' + o + ' + ' + q2 + ' = ' + n + ' + □\n□に あてはまる 数は？', ans: 10, exp: o + '＋' + q2 + '＝10 を まとめて たせる' };
  };
  window.genKukuMean2 = function () {
    var p = R(0, 4), d = R(2, 9), k = R(2, 8);
    if (p === 0) return { q: d + 'のだんの 九九は、かける数が 1 ふえると\nこたえは いくつ ふえる？', ans: d, exp: d + '×' + k + '＝' + (d * k) + '、' + d + '×' + (k + 1) + '＝' + (d * (k + 1)) + '。' + d + 'ずつ ふえる' };
    if (p === 1) return { q: d + ' × ' + (k + 1) + ' ＝ ' + d + ' × ' + k + ' ＋ □\n□に あてはまる 数は？', ans: d, exp: 'かける数が 1 ふえると、' + d + ' ふえる' };
    if (p === 2) return { q: d + ' × ' + k + ' ＝ ' + k + ' × □\n□に あてはまる 数は？', ans: d, exp: 'かけられる数と かける数を 入れかえても 答えは 同じ' };
    if (p === 3) { var box = P([3, 4, 5, 6]), n = R(2, 9); return { q: '1はこに ' + box + 'こずつ はいった ケーキが ' + n + 'はこ あります。\nぜんぶで なんこ？', ans: box * n, exp: '1はこ分 × はこの数：' + box + '×' + n + '＝' + (box * n), fig: (function () { var h = H(); if (!h || n > 9) return ''; var s = ''; for (var i = 0; i < n; i++) { s += h.rect(4 + i * 34, 6, 30, 30, '#fef3c7', '#d97706', 1.2); for (var j = 0; j < box; j++) s += h.dot(12 + i * 34 + (j % 3) * 8, 14 + Math.floor(j / 3) * 9, 3, '#e11d48'); } return h.svg(n * 34 + 8, 42, s, 50); })() }; }
    var e = R(2, 5), f = R(2, 9); return { q: e + '人に ' + f + 'まいずつ カードを くばると、\nカードは なんまい いる？', ans: e * f, exp: '1人分 × 人数：' + f + '×' + e + '＝' + (e * f) };
  };

  /* ═════════ 3年：暗算・2けた×2けた・そろばん ═════════ */
  window.genAnzan3 = function () {
    var p = R(0, 3);
    if (p === 0) { var a = R(11, 69), b = R(11, 99 - a); return { q: a + ' + ' + b + ' = ?（あんざんで）', ans: a + b, exp: '十の くらい ' + (Math.floor(a / 10) * 10) + '＋' + (Math.floor(b / 10) * 10) + '＝' + (Math.floor(a / 10) * 10 + Math.floor(b / 10) * 10) + '、一の くらい ' + (a % 10) + '＋' + (b % 10) + '＝' + (a % 10 + b % 10) + '、あわせて ' + (a + b) }; }
    if (p === 1) { var c = R(31, 99), d = R(11, c - 10); return { q: c + ' − ' + d + ' = ?（あんざんで）', ans: c - d, exp: c + '−' + (Math.floor(d / 10) * 10) + '＝' + (c - Math.floor(d / 10) * 10) + '、のこり ' + (d % 10) + ' を ひいて ' + (c - d) }; }
    if (p === 2) { var e = R(11, 49), f = R(2, 4); return { q: e + ' × ' + f + ' = ?（あんざんで）', ans: e * f, exp: (Math.floor(e / 10) * 10) + '×' + f + '＝' + (Math.floor(e / 10) * 10 * f) + '、' + (e % 10) + '×' + f + '＝' + (e % 10 * f) + '、あわせて ' + (e * f) }; }
    var g = P([25, 50, 75, 98, 99]), k = R(11, 60); return { q: k + ' + ' + g + ' = ?（あんざんで）', ans: k + g, exp: g >= 98 ? g + ' は 100−' + (100 - g) + '。' + k + '＋100−' + (100 - g) + '＝' + (k + g) : '十と 一に 分けて たす' };
  };
  window.genMul2x2_3 = function () {
    var p = R(0, 2), h = H();
    if (p === 0) { var a = R(12, 49), b = R(12, 29); return { q: a + ' × ' + b + ' ＝ ？', ans: a * b, exp: a + '×' + (b % 10) + '＝' + (a * (b % 10)) + '、' + a + '×' + (Math.floor(b / 10) * 10) + '＝' + (a * Math.floor(b / 10) * 10) + '、たして ' + (a * b), fig: h ? h.hissan(a, '×', b) : '' }; }
    if (p === 1) { var c = R(101, 299), d = R(12, 39); return { q: c + ' × ' + d + ' ＝ ？', ans: c * d, exp: c + '×' + (d % 10) + '＝' + (c * (d % 10)) + '、' + c + '×' + (Math.floor(d / 10) * 10) + '＝' + (c * Math.floor(d / 10) * 10) + '、たして ' + (c * d), fig: h ? h.hissan(c, '×', d) : '' }; }
    var e = R(2, 9) * 10, f = R(2, 9) * 10; return { q: e + ' × ' + f + ' ＝ ？（0の 数に 注意）', ans: e * f, exp: (e / 10) + '×' + (f / 10) + '＝' + (e * f / 100) + '、0を 2こ つけて ' + (e * f) };
  };
  function figSoroban(n, cols) {
    var h = H(); if (!h) return '';
    var s = h.rect(4, 4, cols * 34 + 12, 120, '#fef3c7', '#92400e', 4) + h.ln(8, 40, cols * 34 + 12, 40, '#92400e', 4);
    var digs = String(n).padStart(cols, '0').split('').map(Number);
    for (var i = 0; i < cols; i++) {
      var x = 26 + i * 34, d = digs[i]; s += h.ln(x, 8, x, 120, '#78350f', 2);
      var five = d >= 5, ones = d % 5;
      s += '<ellipse cx="' + x + '" cy="' + (five ? 32 : 18) + '" rx="13" ry="7" fill="#7c2d12"/>';
      for (var k = 0; k < 4; k++) { var up = k < ones; s += '<ellipse cx="' + x + '" cy="' + (up ? 50 + k * 15 : 64 + k * 15) + '" rx="13" ry="7" fill="#7c2d12"/>'; }
      if ((cols - 1 - i) % 3 === 0) s += h.dot(x, 40, 2.5, '#fff');
    }
    return h.svg(cols * 34 + 20, 128, s, 120);
  }
  window.genSoroban3 = function () {
    var p = R(0, 2);
    if (p === 0) { var n = R(1, 9999), c = 5; return { q: 'そろばんの 数を 読もう。\nいくつ？', ans: n, fig: figSoroban(n, c), exp: '上の 玉（五玉）は 5、下の 玉（一玉）は 1つ 1。はりに よせた 玉を くらいごとに 読む' }; }
    if (p === 1) { var a = R(1, 4), b = R(1, 4); return { q: 'そろばんで ' + a + ' に ' + b + ' を たすと？', ans: a + b, fig: figSoroban(a, 3), exp: '一の くらいに 一玉を ' + b + 'こ 入れる' }; }
    var e = R(11, 45), f = R(1, 4); if (e % 10 + f >= 10) f = 9 - e % 10 || 1; return { q: 'そろばんで ' + e + ' ＋ ' + f + ' ＝ ？', ans: e + f, fig: figSoroban(e, 3), exp: '一の くらいに 一玉を ' + f + 'こ 入れる（五玉を つかう ときは 5を 入れて 5−' + f + '…と 考える）' };
  };

  /* ═════════ 4年：2けたで わる わり算・3けたの かけ算・がい数の 計算・計算の きまり ═════════ */
  window.genDiv2_4 = function () {
    var p = R(0, 3), b = R(12, 39), c = R(2, 9);
    if (p === 0) return { q: (b * c) + ' ÷ ' + b + ' ＝ ？', ans: c, exp: b + 'を 約' + (Math.round(b / 10) * 10) + 'と みて 見当を つける：' + b + '×' + c + '＝' + (b * c) };
    if (p === 1) { var r = R(1, b - 1), a = b * c + r; return { q: a + ' ÷ ' + b + ' ＝ □ あまり ' + r + '\n□に あてはまる 数は？', ans: c, exp: b + '×' + c + '＝' + (b * c) + '、' + a + '−' + (b * c) + '＝' + r }; }
    if (p === 2) { var c2 = R(10, 30), a2 = b * c2; return { q: a2 + ' ÷ ' + b + ' ＝ ？', ans: c2, exp: '商は 2けた。十の くらいから たてる：' + b + '×' + c2 + '＝' + a2 }; }
    var r3 = R(1, b - 1), a3 = b * c + r3; return { q: a3 + ' ÷ ' + b + ' ＝ ' + c + ' あまり □\n□に あてはまる 数は？', ans: r3, exp: a3 + '−' + b + '×' + c + '＝' + r3 + '（あまりは わる数より 小さい）' };
  };
  window.genMul3_4 = function () {
    var p = R(0, 2), h = H();
    if (p === 0) { var a = R(101, 999), b = R(11, 99); return { q: a + ' × ' + b + ' ＝ ？', ans: a * b, exp: a + '×' + (b % 10) + ' と ' + a + '×' + (Math.floor(b / 10) * 10) + ' を たす', fig: h ? h.hissan(a, '×', b) : '' }; }
    if (p === 1) { var c = R(101, 499), d = R(101, 299); return { q: c + ' × ' + d + ' ＝ ？', ans: c * d, exp: '一・十・百の くらいの じゅんに かけて、ずらして たす', fig: h ? h.hissan(c, '×', d) : '' }; }
    var e = R(2, 9) * 100, f = R(2, 9) * 10; return { q: e + ' × ' + f + ' ＝ ？', ans: e * f, exp: (e / 100) + '×' + (f / 10) + '＝' + (e * f / 1000) + '、0を 3こ つけて ' + (e * f) };
  };
  window.genGaisuCalc4 = function () {
    var p = R(0, 2), rd = function (x, u) { return Math.round(x / u) * u; };
    if (p === 0) { var a = R(1000, 9999), b = R(1000, 9999); return { q: a + ' ＋ ' + b + ' を、それぞれ 百の位までの がい数に してから\n計算すると？', ans: rd(a, 100) + rd(b, 100), exp: a + '→' + rd(a, 100) + '、' + b + '→' + rd(b, 100) + '、たして ' + (rd(a, 100) + rd(b, 100)) }; }
    if (p === 1) { var c = R(5000, 9999), d = R(1000, 4999); return { q: c + ' − ' + d + ' を、それぞれ 千の位までの がい数に してから\n計算すると？', ans: rd(c, 1000) - rd(d, 1000), exp: c + '→' + rd(c, 1000) + '、' + d + '→' + rd(d, 1000) + '、ひいて ' + (rd(c, 1000) - rd(d, 1000)) }; }
    var e = R(11, 99) * 10 + R(0, 9), f = R(21, 89); return { q: e + ' × ' + f + ' を、上から1けたの がい数に してから\n見積もると？', ans: rd(e, Math.pow(10, String(e).length - 1)) * rd(f, 10), exp: e + '→' + rd(e, Math.pow(10, String(e).length - 1)) + '、' + f + '→' + rd(f, 10) + '、かけて 見積もる' };
  };
  window.genKimari4 = function () {
    var p = R(0, 3);
    if (p === 0) { var a = R(3, 19); return { q: '25 × ' + a + ' × 4 ＝ ？（くふうして）', ans: 100 * a, exp: '25×4＝100 を さきに。100×' + a + '＝' + (100 * a) }; }
    if (p === 1) { var b = P([98, 99, 101, 102]), c = R(3, 9); return { q: b + ' × ' + c + ' ＝ ？（' + b + ' を 100' + (b < 100 ? '−' + (100 - b) : '＋' + (b - 100)) + ' と みて）', ans: b * c, exp: '(100' + (b < 100 ? '−' + (100 - b) : '＋' + (b - 100)) + ')×' + c + '＝' + (100 * c) + (b < 100 ? '−' : '＋') + (Math.abs(100 - b) * c) + '＝' + (b * c) }; }
    if (p === 2) { var d = R(2, 9), e = R(11, 39), f = 100 - e; return { q: d + ' × ' + e + ' ＋ ' + d + ' × ' + f + ' ＝ ？', ans: d * 100, exp: '同じ ' + d + ' を くくる：' + d + '×(' + e + '＋' + f + ')＝' + d + '×100＝' + (d * 100) }; }
    var g = R(2, 9), k = R(2, 9), m = R(2, 9); return { q: '(' + g + ' ＋ ' + k + ') × ' + m + ' ＝ ' + g + ' × ' + m + ' ＋ □ × ' + m + '\n□に あてはまる 数は？', ans: k, exp: '( ) の 中の それぞれに かけても 同じ（分配の きまり）' };
  };

  /* ═════════ 5年：割合の いろいろ（歩合・増減） ═════════ */
  window.genWariai5b = function () {
    var p = R(0, 4);
    if (p === 0) { var w = R(1, 9), b = R(0, 9); return { q: '0.' + w + b + ' を 歩合で 表すと □割' + b + '分。\n□に あてはまる 数は？', ans: w, exp: '0.1＝1割、0.01＝1分。0.' + w + b + '＝' + w + '割' + b + '分' }; }
    if (p === 1) { var pr = P([1000, 1200, 1500, 2000, 2400, 3000]), wa = R(1, 5); return { q: pr + '円の 品物を ' + wa + '割引きで 買うと、何円？', ans: pr * (10 - wa) / 10, exp: wa + '割引き＝もとの ' + (10 - wa) + '割。' + pr + '×0.' + (10 - wa) + '＝' + (pr * (10 - wa) / 10) }; }
    if (p === 2) { var base = P([200, 300, 400, 500, 800]), pc = P([10, 20, 25, 30, 50]); return { q: base + '人の ' + pc + '%増しは 何人？', ans: base * (100 + pc) / 100, exp: pc + '%増し＝もとの ' + (100 + pc) + '%。' + base + '×' + ((100 + pc) / 100) + '＝' + (base * (100 + pc) / 100) }; }
    if (p === 3) { var x = P([400, 500, 600, 800]), y = x * P([0.8, 0.75, 0.9, 0.6]); return { q: 'もとの ねだん ' + x + '円が ' + y + '円に なりました。\n何%引き？', ans: Math.round((1 - y / x) * 100), exp: (x - y) + '円 安く なった。' + (x - y) + '÷' + x + '＝' + r2((x - y) / x) + '＝' + Math.round((1 - y / x) * 100) + '%' }; }
    var orig = P([500, 800, 1000, 1200]), up = P([10, 20, 25]); return { q: 'ある ねだんの ' + up + '%増しが ' + (orig * (100 + up) / 100) + '円 です。\nもとの ねだんは 何円？', ans: orig, exp: (orig * (100 + up) / 100) + '÷' + ((100 + up) / 100) + '＝' + orig };
  };

  /* ═════════ 6年：速さの 単位・逆数と 大小・円の 面積の 応用 ═════════ */
  window.genSpeedUnit6 = function () {
    var p = R(0, 4);
    if (p === 0) { var kmh = P([36, 54, 60, 72, 90, 120, 180]); return { q: '時速 ' + kmh + 'km は 分速 何m？', ans: kmh * 1000 / 60, exp: kmh + 'km＝' + (kmh * 1000) + 'm。1時間＝60分 なので ' + (kmh * 1000) + '÷60＝' + (kmh * 1000 / 60) }; }
    if (p === 1) { var mpm = P([60, 120, 150, 300, 600, 900]); return { q: '分速 ' + mpm + 'm は 秒速 何m？', ans: mpm / 60, exp: '1分＝60秒。' + mpm + '÷60＝' + (mpm / 60) }; }
    if (p === 2) { var mps = P([5, 10, 15, 20, 25]); return { q: '秒速 ' + mps + 'm は 時速 何km？', ans: mps * 3600 / 1000, exp: mps + '×60×60＝' + (mps * 3600) + 'm＝' + (mps * 3.6) + 'km' }; }
    if (p === 3) { var v = P([40, 50, 60, 80]), mn = P([15, 30, 45, 90]); return { q: '時速 ' + v + 'km で ' + mn + '分 走ると、何km 進む？', ans: v * mn / 60, exp: mn + '分＝' + (mn / 60) + '時間。' + v + '×' + (mn / 60) + '＝' + (v * mn / 60) }; }
    var d = P([3, 6, 9, 12]), s = P([60, 75, 80, 100]); return { q: d + 'km の 道のりを 分速 ' + s + 'm で 歩くと、何分 かかる？', ans: d * 1000 / s, exp: d + 'km＝' + (d * 1000) + 'm。' + (d * 1000) + '÷' + s + '＝' + (d * 1000 / s) };
  };
  window.genGyakusu6 = function () {
    var p = R(0, 3);
    if (p === 0) { var a = R(1, 8), b = R(a + 1, 9); var g = gcd(a, b); a /= g; b /= g; return pickQ([Q(a + '/' + b + ' の 逆数は？', a === 1 ? String(b) : b + '/' + a, [a + '/' + b, a === 1 ? String(b + 1) : (b + 1) + '/' + a, (a + b) + '/' + b], '逆数は 分子と 分母を 入れかえた 数（かけると 1に なる）')]); }
    if (p === 1) { var n = R(2, 9); return pickQ([Q(n + ' の 逆数は？', '1/' + n, [String(n), n + '/' + (n + 1), '0.' + n], n + '＝' + n + '/1 なので 逆数は 1/' + n)]); }
    if (p === 2) { var x = P(['3/4', '5/4', '1', '2/3', '7/5']), cl = { '3/4': '小さく なる', '5/4': '大きく なる', '1': '同じ', '2/3': '小さく なる', '7/5': '大きく なる' }[x]; return pickQ([Q('12 × ' + x + ' の 答えは、12 より\nどう なる？', cl, ['大きく なる', '小さく なる', '同じ'].filter(function (z) { return z !== cl; }), 'かける数が 1より 大きいと 積は 大きく、1より 小さいと 小さく なる')]); }
    var y = P(['3/4', '5/4', '2/3', '7/5']), c2 = { '3/4': '大きく なる', '5/4': '小さく なる', '2/3': '大きく なる', '7/5': '小さく なる' }[y]; return pickQ([Q('12 ÷ ' + y + ' の 答えは、12 より\nどう なる？', c2, ['大きく なる', '小さく なる', '同じ'].filter(function (z) { return z !== c2; }), 'わる数が 1より 小さいと 商は 大きく、1より 大きいと 小さく なる')]);
  };
  window.genCircle2_6 = function () {
    var p = R(0, 3), h = H(), r = R(2, 10);
    if (p === 0) return { q: '半径 ' + r + 'cm の 半円の 面積は 何cm²？\n（円周率＝3.14）', ans: r2(r * r * 3.14 / 2), exp: r + '×' + r + '×3.14÷2＝' + r2(r * r * 3.14 / 2), fig: h ? h.sector(r + 'cm', 180) : '' };
    if (p === 1) return { q: '半径 ' + r + 'cm、中心角 90° の おうぎ形の 面積は 何cm²？\n（円周率＝3.14）', ans: r2(r * r * 3.14 / 4), exp: '円の 1/4：' + r + '×' + r + '×3.14÷4＝' + r2(r * r * 3.14 / 4), fig: h ? h.sector(r + 'cm', 90) : '' };
    if (p === 2) { var d = R(2, 10) * 2; return { q: '直径 ' + d + 'cm の 円の 面積は 何cm²？\n（円周率＝3.14）', ans: r2((d / 2) * (d / 2) * 3.14), exp: '半径は ' + (d / 2) + 'cm。' + (d / 2) + '×' + (d / 2) + '×3.14＝' + r2((d / 2) * (d / 2) * 3.14), fig: h ? h.circle(d + 'cm', 'd') : '' }; }
    var R2 = R(4, 10), r3 = R(1, R2 - 2); return { q: '半径 ' + R2 + 'cm の 円から、同じ 中心で 半径 ' + r3 + 'cm の 円を\nくりぬいた 形の 面積は 何cm²？（円周率＝3.14）', ans: r2((R2 * R2 - r3 * r3) * 3.14), exp: '大きい 円 − 小さい 円：(' + R2 + '×' + R2 + '−' + r3 + '×' + r3 + ')×3.14＝' + r2((R2 * R2 - r3 * r3) * 3.14), fig: h ? h.svg(150, 130, '<circle cx="75" cy="65" r="58" fill="#dbeafe" stroke="#2563eb" stroke-width="2"/><circle cx="75" cy="65" r="' + Math.round(58 * r3 / R2) + '" fill="#fff" stroke="#2563eb" stroke-width="2"/>' + h.ln(75, 65, 133, 65, '#e11d48', 2) + h.tx(110, 60, R2 + 'cm', { b: 1, c: '#e11d48', fs: 11 }) + h.ln(75, 65, 75, 65 - Math.round(58 * r3 / R2), '#d97706', 2) + h.tx(64, 62 - Math.round(29 * r3 / R2), r3 + 'cm', { b: 1, c: '#d97706', fs: 11, a: 'end' }), 130) : '' };
  };

  /* ═════════ 中学 社会：時差・雨温図 ═════════ */
  var CITY = [
    { n: 'ロンドン', l: 0 }, { n: 'パリ', l: 15 }, { n: 'カイロ', l: 30 }, { n: 'ニューデリー', l: 75 }, { n: 'ペキン', l: 120 }, { n: 'シドニー', l: 150 }, { n: 'ニューヨーク', l: -75 }, { n: 'ロサンゼルス', l: -120 }
  ];
  window.genJisa7 = function () {
    var p = R(0, 3), c = P(CITY), dl = 135 - c.l, dh = dl / 15;
    if (p === 0) return { q: '日本の 標準時子午線は 東経 何度？', ans: 135, exp: '兵庫県 明石市を 通る 東経135度の 経線が 日本の 標準時子午線' };
    if (p === 1) return { q: '経度 何度で 1時間の 時差が できる？', ans: 15, exp: '地球は 24時間で 360度 回る。360÷24＝15度' };
    if (p === 2) return { q: '日本（東経135度）と ' + c.n + '（' + (c.l === 0 ? '経度0度' : (c.l > 0 ? '東経' : '西経') + Math.abs(c.l) + '度') + '）の\n時差は 何時間？', ans: Math.abs(dh), exp: '経度の 差 ' + Math.abs(dl) + '度 ÷ 15 ＝ ' + Math.abs(dh) + '時間' + (c.l < 0 ? '（東経と 西経は たし算）' : '') };
    var jh = R(8, 20); var lh = ((jh - dh) % 24 + 24) % 24; return { q: '日本が ' + jh + '時（24時間制）の とき、' + c.n + '（' + (c.l === 0 ? '経度0度' : (c.l > 0 ? '東経' : '西経') + Math.abs(c.l) + '度') + '）は 何時？\n（24時間制で、前の日なら その時こく）', ans: lh, exp: '日本の ほうが 時こくが 進んで いる。' + jh + '−' + dh + '＝' + (jh - dh) + (jh - dh < 0 ? '（前の日の ' + lh + '時）' : '') };
  };
  /* 雨温図（月平均気温℃・降水量mm の およその 平年値） */
  var CLIM = {
    '札幌（北海道の気候）': { t: [-3.2, -2.7, 1.1, 7.3, 13, 17, 21, 22, 18, 11.8, 4.9, -0.9], r: [108, 92, 78, 55, 56, 60, 90, 127, 142, 110, 114, 115], d: '冬の 寒さが きびしく、梅雨が ない' },
    '上越（日本海側の気候）': { t: [2.6, 2.6, 5.6, 11, 16.5, 20.8, 24.9, 26.4, 22.4, 16.6, 10.6, 5.3], r: [440, 280, 200, 110, 100, 140, 210, 150, 210, 200, 330, 470], d: '冬に 雪で 降水量が 多い' },
    '東京（太平洋側の気候）': { t: [5.4, 6.1, 9.4, 14.3, 18.8, 21.9, 25.7, 26.9, 23.3, 18, 12.5, 7.7], r: [60, 56, 117, 125, 138, 168, 154, 168, 210, 198, 93, 58], d: '夏に 降水量が 多く、冬は かんそう' },
    '高松（瀬戸内の気候）': { t: [5.9, 6.3, 9.4, 14.7, 19.8, 23.3, 27.5, 28.6, 24.7, 19, 13.2, 8.3], r: [39, 46, 82, 76, 101, 152, 145, 86, 167, 105, 61, 41], d: '1年じゅう 降水量が 少ない' },
    '松本（内陸の気候）': { t: [-0.4, 0.4, 4.3, 10.6, 16, 19.8, 23.6, 24.7, 20.4, 13.6, 7.4, 2.1], r: [36, 44, 80, 75, 100, 125, 138, 92, 130, 100, 52, 33], d: '降水量が 少なく、夏と 冬の 気温の 差が 大きい' },
    '那覇（南西諸島の気候）': { t: [17.3, 17.5, 19.1, 21.5, 24.2, 27.2, 29.1, 29, 27.9, 25.5, 22.5, 19], r: [101, 115, 142, 161, 245, 284, 188, 240, 275, 179, 119, 110], d: '1年じゅう あたたかく、雨が 多い' }
  };
  function figUonzu(c) {
    var h = H(); if (!h) return '';
    var W = 260, Hh = 170, x0 = 34, y0 = 140, w = 200, b = '', tmin = -10, tmax = 30, rmax = 500;
    for (var g = 0; g <= 4; g++) { var y = y0 - g * 30; b += h.ln(x0, y, x0 + w, y, '#e2e8f0', 1) + h.tx(x0 - 4, y + 4, String(tmin + g * 10), { fs: 9, a: 'end', c: '#dc2626' }) + h.tx(x0 + w + 4, y + 4, String(g * 125), { fs: 9, a: 'start', c: '#2563eb' }); }
    c.r.forEach(function (v, i) { var bh = 120 * v / rmax; b += h.rect(x0 + i * (w / 12) + 2, y0 - bh, w / 12 - 4, bh, '#93c5fd', '#2563eb', 1); });
    var d = ''; c.t.forEach(function (v, i) { var x = x0 + i * (w / 12) + w / 24, y = y0 - 120 * (v - tmin) / (tmax - tmin); d += (i ? ' L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1); });
    b += '<path d="' + d + '" fill="none" stroke="#dc2626" stroke-width="2.5"/>';
    for (var m = 0; m < 12; m += 1) if (m % 2 === 0) b += h.tx(x0 + m * (w / 12) + w / 24, y0 + 13, String(m + 1), { fs: 9 });
    b += h.tx(x0 - 4, 12, '気温℃', { fs: 9, c: '#dc2626', a: 'end' }) + h.tx(x0 + w + 4, 12, '降水量mm', { fs: 9, c: '#2563eb', a: 'start' }) + h.tx(x0 + w / 2, y0 + 26, '（月）', { fs: 9 });
    return h.svg(W + 40, Hh + 10, b, 190);
  }
  window.genUonzu8 = function () {
    var names = Object.keys(CLIM), k = P(names), c = CLIM[k], p = R(0, 2);
    var months = function (m) { var o = [m]; while (o.length < 4) { var z = R(1, 12); if (o.indexOf(z) < 0 && Math.abs(z - m) > 1) o.push(z); } return o.slice(1).map(function (z) { return z + '月'; }); };
    if (p === 0) { var ws = names.filter(function (x) { return x !== k; }).sort(function () { return Math.random() - 0.5; }).slice(0, 3); var o = Q('この 雨温図は どこ？', k, ws, k.replace(/（.*/, '') + '：' + c.d); o.fig = figUonzu(c); return pickQ([o]); }
    if (p === 1) { var mx = 0; c.t.forEach(function (v, i) { if (v > c.t[mx]) mx = i; }); var o1 = Q('この 雨温図で、気温が いちばん 高い 月は？', (mx + 1) + '月', months(mx + 1), '赤い 折れ線の いちばん 高い ところを 読む'); o1.fig = figUonzu(c); return pickQ([o1]); }
    var mr = 0; c.r.forEach(function (v, i) { if (v > c.r[mr]) mr = i; }); var o2 = Q('この 雨温図で、降水量が いちばん 多い 月は？', (mr + 1) + '月', months(mr + 1), '青い 棒の いちばん 高い ところを 読む。' + c.d); o2.fig = figUonzu(c); return pickQ([o2]);
  };


  /* ═════════ 社会：年表・世界の国・縮尺 ═════════ */
  var EV = [['卑弥呼が 中国（魏）に 使いを 送る', 239], ['冠位十二階が 定められる', 603], ['大化の改新が 始まる', 645], ['平城京に 都が うつる', 710], ['東大寺の 大仏が 完成する', 752], ['平安京に 都が うつる', 794], ['源頼朝が 征夷大将軍に なる', 1192], ['元が 九州に せめてくる（文永の役）', 1274], ['応仁の乱が 始まる', 1467], ['鉄砲が 種子島に 伝わる', 1543], ['関ケ原の戦い', 1600], ['江戸幕府が 開かれる', 1603], ['ペリーが 浦賀に 来る', 1853], ['大政奉還', 1867], ['大日本帝国憲法が 発布される', 1889], ['日清戦争が 始まる', 1894], ['日露戦争が 始まる', 1904], ['太平洋戦争が 終わる', 1945], ['日本国憲法が 施行される', 1947], ['東京オリンピックが 開かれる', 1964]];
  function figYears(list) {
    var h = H(); if (!h) return ''; var mn = 200, mx = 2000, W = 330, x0 = 10, w = 310, b = h.ln(x0, 30, x0 + w, 30, '#475569', 2);
    [300, 600, 900, 1200, 1500, 1800].forEach(function (y) { var x = x0 + w * (y - mn) / (mx - mn); b += h.ln(x, 26, x, 34, '#475569', 1) + h.tx(x, 48, y + '年', { fs: 9 }); });
    list.forEach(function (it, i) { var x = x0 + w * (it.y - mn) / (mx - mn); b += h.dot(x, 30, 5, it.c || '#e11d48') + h.tx(x, 18 - (i % 2) * 0, it.t, { fs: 10, b: 1, c: it.c || '#e11d48' }); });
    return h.svg(W, 56, b, 70);
  }
  window.genNenpyo6 = function () {
    var p = R(0, 2), a = P(EV), b = P(EV); while (b === a) b = P(EV);
    if (p === 0) { var first = a[1] < b[1] ? a : b, o = Q('どちらが 先に おきた できごと？\nア：' + a[0] + '\nイ：' + b[0], first === a ? 'ア' : 'イ', [first === a ? 'イ' : 'ア', '同じ年'], a[0] + '（' + a[1] + '年）、' + b[0] + '（' + b[1] + '年）'); var r = pickQ([o]); r.fig = figYears([{ y: a[1], t: 'ア', c: '#2563eb' }, { y: b[1], t: 'イ', c: '#d97706' }]); return r; }
    if (p === 1) { var ws = EV.filter(function (e) { return e !== a && Math.abs(e[1] - a[1]) > 30; }).sort(function () { return Math.random() - 0.5; }).slice(0, 3).map(function (e) { return e[0]; }); return pickQ([Q(a[1] + '年に おきた できごとは？', a[0], ws, a[1] + '年：' + a[0])]); }
    var c3 = [a, b, P(EV)].filter(function (e, i, arr) { return arr.indexOf(e) === i; }); if (c3.length < 3) return window.genNenpyo6(); var sorted = c3.slice().sort(function (x, y) { return x[1] - y[1]; }); var lab = ['ア', 'イ', 'ウ']; var order = sorted.map(function (e) { return lab[c3.indexOf(e)]; }).join('→');
    var all = ['ア→イ→ウ', 'ア→ウ→イ', 'イ→ア→ウ', 'イ→ウ→ア', 'ウ→ア→イ', 'ウ→イ→ア'].filter(function (z) { return z !== order; }).sort(function () { return Math.random() - 0.5; }).slice(0, 3);
    return pickQ([Q('古い じゅんに ならべると？\nア：' + c3[0][0] + '\nイ：' + c3[1][0] + '\nウ：' + c3[2][0], order, all, sorted.map(function (e) { return e[0] + '（' + e[1] + '）'; }).join(' → '))]);
  };
  var CAP = [['アメリカ合衆国', 'ワシントンD.C.', '北アメリカ州'], ['イギリス', 'ロンドン', 'ヨーロッパ州'], ['フランス', 'パリ', 'ヨーロッパ州'], ['ドイツ', 'ベルリン', 'ヨーロッパ州'], ['イタリア', 'ローマ', 'ヨーロッパ州'], ['スペイン', 'マドリード', 'ヨーロッパ州'], ['ロシア', 'モスクワ', 'ヨーロッパ州'], ['中国', 'ペキン', 'アジア州'], ['韓国', 'ソウル', 'アジア州'], ['インド', 'ニューデリー', 'アジア州'], ['タイ', 'バンコク', 'アジア州'], ['ベトナム', 'ハノイ', 'アジア州'], ['インドネシア', 'ジャカルタ', 'アジア州'], ['サウジアラビア', 'リヤド', 'アジア州'], ['トルコ', 'アンカラ', 'アジア州'], ['エジプト', 'カイロ', 'アフリカ州'], ['ケニア', 'ナイロビ', 'アフリカ州'], ['ブラジル', 'ブラジリア', '南アメリカ州'], ['アルゼンチン', 'ブエノスアイレス', '南アメリカ州'], ['カナダ', 'オタワ', '北アメリカ州'], ['メキシコ', 'メキシコシティ', '北アメリカ州'], ['オーストラリア', 'キャンベラ', 'オセアニア州']];
  window.genKuni7 = function () {
    var c = P(CAP), p = R(0, 2), others = CAP.filter(function (x) { return x !== c; }).sort(function () { return Math.random() - 0.5; });
    if (p === 0) return pickQ([Q(c[0] + ' の 首都は？', c[1], others.slice(0, 3).map(function (x) { return x[1]; }), c[0] + ' の 首都は ' + c[1])]);
    if (p === 1) return pickQ([Q(c[1] + ' が 首都の 国は？', c[0], others.slice(0, 3).map(function (x) { return x[0]; }), c[1] + ' は ' + c[0] + ' の 首都')]);
    var sh = ['アジア州', 'ヨーロッパ州', 'アフリカ州', '北アメリカ州', '南アメリカ州', 'オセアニア州'].filter(function (z) { return z !== c[2]; }).sort(function () { return Math.random() - 0.5; }).slice(0, 3);
    return pickQ([Q(c[0] + ' が ある 州は？', c[2], sh, '世界は 6つの 州に 分けられる。' + c[0] + ' は ' + c[2])]);
  };
  window.genShukushaku8 = function () {
    var p = R(0, 3), S = P([25000, 50000]);
    if (p === 0) { var cm = R(1, 8); return { q: (S === 25000 ? '2万5千' : '5万') + '分の1の 地図で ' + cm + 'cm の 長さは、\n実際には 何m？', ans: cm * S / 100, exp: cm + 'cm × ' + S + ' ＝ ' + (cm * S) + 'cm ＝ ' + (cm * S / 100) + 'm' }; }
    if (p === 1) { var km = P([1, 2, 3, 5]); return { q: '実際の きょり ' + km + 'km は、' + (S === 25000 ? '2万5千' : '5万') + '分の1の 地図では\n何cm？', ans: km * 100000 / S, exp: km + 'km ＝ ' + (km * 100000) + 'cm。÷' + S + ' で ' + (km * 100000 / S) + 'cm' }; }
    if (p === 2) return { q: (S === 25000 ? '2万5千' : '5万') + '分の1の 地形図で、主曲線（細い 等高線）は\n何m ごとに ひかれる？', ans: S === 25000 ? 10 : 20, exp: '2万5千分の1は 10mごと、5万分の1は 20mごと', fig: (function () { var h = H(); if (!h) return ''; var b = ''; for (var i = 0; i < 5; i++) b += '<ellipse cx="110" cy="60" rx="' + (100 - i * 18) + '" ry="' + (50 - i * 9) + '" fill="none" stroke="#a16207" stroke-width="' + (i === 0 ? 2 : 1) + '"/>'; return h.svg(220, 120, b, 110); })() };
    var cm2 = R(2, 6), real = cm2 * S / 100; return { q: '地図上で ' + cm2 + 'cm の 道が、実際には ' + real + 'm でした。\nこの 地図の 縮尺は 何分の1？\n（分母の 数を 答えよう）', ans: S, exp: real + 'm ＝ ' + (real * 100) + 'cm。' + (real * 100) + '÷' + cm2 + '＝' + S };
  };
  /* ═════════ CURRICULUM に 足す ═════════ */
  var ADD = {
    math: {
      1: [{ id: 'm1-nanju', name: 'なん十・2けたと1けたのけいさん', icon: '🔟', color: 'blue', gen: 'genNanju1', input: 'numpad', desc: '30＋20・34＋5 など' },
          { id: 'm1-bunsho', name: 'ぶんしょうだい（ふえる・へる・ならぶ）', icon: '📖', color: 'green', gen: 'genBunsho1', input: 'numpad', desc: 'のったり おりたり・ちがい・ならびかた' }],
      2: [{ id: 'm2-add3', name: 'たし算・ひき算（100をこえる）', icon: '💯', color: 'blue', gen: 'genAdd3_2', input: 'numpad', desc: '67＋58・134−58 など' },
          { id: 'm2-man', name: '1万までの数', icon: '🔢', color: 'amber', gen: 'genMan2', input: 'numpad', desc: '千の位・数のならび・大小' },
          { id: 'm2-kufu', name: '( )のある計算・計算のくふう', icon: '🧩', color: 'teal', gen: 'genKufu2', input: 'numpad', desc: '( )を先に・10のまとまり' },
          { id: 'm2-kukumean', name: '九九のきまり・文章題', icon: '✖️', color: 'pink', gen: 'genKukuMean2', input: 'numpad', desc: '□ずつふえる・入れかえ・文章題' }],
      3: [{ id: 'm3-anzan', name: '暗算', icon: '🧠', color: 'purple', gen: 'genAnzan3', input: 'numpad', desc: '2けた±2けた・2けた×1けた' },
          { id: 'm3-mul2', name: 'かけ算（2けた×2けた）', icon: '✖️', color: 'blue', gen: 'genMul2x2_3', input: 'numpad', desc: '筆算・何十×何十' },
          { id: 'm3-soroban', name: 'そろばん', icon: '🧮', color: 'amber', gen: 'genSoroban3', input: 'numpad', desc: '玉を読む・たし算' }],
      4: [{ id: 'm4-div2', name: 'わり算（2けたでわる）', icon: '➗', color: 'blue', gen: 'genDiv2_4', input: 'numpad', desc: '商の見当・あまり' },
          { id: 'm4-mul3', name: 'かけ算（3けた×2けた・3けた）', icon: '✖️', color: 'teal', gen: 'genMul3_4', input: 'numpad', desc: '大きい数のかけ算' },
          { id: 'm4-gaisu2', name: 'がい数の計算（見積もり）', icon: '🎯', color: 'green', gen: 'genGaisuCalc4', input: 'numpad', desc: '和・差・積の見積もり' },
          { id: 'm4-kimari', name: '計算のきまり（くふう）', icon: '🧩', color: 'purple', gen: 'genKimari4', input: 'numpad', desc: '25×4・(100−2)×5・分配' }],
      5: [{ id: 'm5-wariai2', name: '割合の文章題（歩合・増減）', icon: '🏷️', color: 'pink', gen: 'genWariai5b', input: 'numpad', desc: '割引き・%増し・何%引き' }],
      6: [{ id: 'm6-speed2', name: '速さ（単位のかえかた）', icon: '🚄', color: 'blue', gen: 'genSpeedUnit6', input: 'numpad', desc: '時速・分速・秒速' },
          { id: 'm6-gyaku', name: '逆数・積と商の大小', icon: '🔄', color: 'teal', gen: 'genGyakusu6', input: 'mcq', desc: '逆数・1より大きい小さい' },
          { id: 'm6-circle2', name: '円の面積の応用', icon: '🍕', color: 'amber', gen: 'genCircle2_6', input: 'numpad', desc: '半円・おうぎ形・ドーナツ形' }]
    },
    social: {
      6: [{ id: 's6-nenpyo', name: '年表（できごとの順番）', icon: '📜', color: 'amber', gen: 'genNenpyo6', input: 'mcq', desc: 'どちらが先？・何年のできごと？' }],
      7: [{ id: 's7-jisa', name: '時差の計算', icon: '🕐', color: 'blue', gen: 'genJisa7', input: 'numpad', desc: '経度15度で1時間' },
          { id: 's7-kuni', name: '世界の国と首都', icon: '🌐', color: 'green', gen: 'genKuni7', input: 'mcq', desc: '首都・6つの州' }],
      8: [{ id: 's8-uonzu', name: '雨温図を読む', icon: '🌦️', color: 'teal', gen: 'genUonzu8', input: 'mcq', desc: '日本の気候区分' },
          { id: 's8-shukushaku', name: '縮尺と等高線', icon: '🗺️', color: 'amber', gen: 'genShukushaku8', input: 'numpad', desc: '実際のきょり・等高線の間かく' }]
    }
  };
  /* mcq と numpad が まざる 単元は、numpad 単元の なかで 4択が 出たときも そのまま 出せる（_genTrainQ が options を 見る） */
  var DISP = {
    'm1-nanju': { name: 'なん十の おか', emoji: '🔟', desc: 'なん十の けいさん' }, 'm1-bunsho': { name: 'おはなしの もり', emoji: '📖', desc: 'ぶんしょうだい' },
    'm2-add3': { name: '百こえの 山', emoji: '💯', desc: '100を こえる 計算' }, 'm2-man': { name: '一万の とう', emoji: '🔢', desc: '1万までの数' }, 'm2-kufu': { name: 'くふうの 工場', emoji: '🧩', desc: '計算の くふう' }, 'm2-kukumean': { name: '九九の ひみつ基地', emoji: '✖️', desc: '九九の きまり' },
    'm3-anzan': { name: 'あんざんの 道場', emoji: '🧠', desc: '暗算' }, 'm3-mul2': { name: 'かけ算の 城', emoji: '🏯', desc: '2けた×2けた' }, 'm3-soroban': { name: 'そろばん屋', emoji: '🧮', desc: 'そろばん' },
    'm4-div2': { name: 'わり算の 塔', emoji: '🗼', desc: '2けたで わる' }, 'm4-mul3': { name: 'かけ算の 大陸', emoji: '🌏', desc: '3けたの かけ算' }, 'm4-gaisu2': { name: '見積もりの 港', emoji: '⚓', desc: 'がい数の 計算' }, 'm4-kimari': { name: 'きまりの 神殿', emoji: '🏛️', desc: '計算の きまり' },
    'm5-wariai2': { name: 'セールの 市場', emoji: '🏷️', desc: '割合の 文章題' },
    'm6-speed2': { name: '新幹線の 駅', emoji: '🚄', desc: '速さの 単位' }, 'm6-gyaku': { name: 'さかさまの 森', emoji: '🔄', desc: '逆数' }, 'm6-circle2': { name: 'ピザの 店', emoji: '🍕', desc: '円の 面積の 応用' },
    's7-jisa': { name: '時差の 空港', emoji: '🛫', desc: '時差' }, 's6-nenpyo': { name: '年表の 回廊', emoji: '📜', desc: '年表' }, 's7-kuni': { name: '世界の 港町', emoji: '🌐', desc: '世界の国' }, 's8-shukushaku': { name: '地形図の 山', emoji: '🗺️', desc: '縮尺と等高線' }, 's8-uonzu': { name: '気候の 観測所', emoji: '🌦️', desc: '雨温図' }
  };
  var LABEL = { 1: '小1', 2: '小2', 3: '小3', 4: '小4', 5: '小5', 6: '小6', 7: '中1', 8: '中2', 9: '中3' };
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
