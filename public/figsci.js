/* ============================================================
   🔬 FIGSCI_V1（2026-11-20）ネットレの「全問イラスト付き」に ならって、理科・社会の 問題に 図を そえる
   ・図は 修行・復習の 画面だけ（figmath.js の __fmExtra から よばれる）。
   ・答えの 文字は 図に 書かない（名前を 答える 問題で 名前が 見えない ように）。
   ・地図記号は「この 記号は 何？」の 問題も 足す（記号を 見て 名前を えらぶ）。
   ============================================================ */
(function () {
  if (window.__FIGSCI__) return; window.__FIGSCI__ = 1;
  var C = { line: '#334155', a: '#059669', b: '#d97706', red: '#e11d48', blue: '#2563eb', gray: '#94a3b8', fillA: '#dcfce7', fillB: '#fef3c7', fillC: '#dbeafe' };
  function svg(w, h, body, maxh) { return '<svg viewBox="0 0 ' + w + ' ' + h + '" style="width:100%;max-width:' + Math.min(330, Math.round(w * 1.3)) + 'px;max-height:' + (maxh || 140) + 'px" xmlns="http://www.w3.org/2000/svg" font-family="sans-serif">' + body + '</svg>'; }
  function tx(x, y, s, o) { o = o || {}; return '<text x="' + x + '" y="' + y + '" font-size="' + (o.fs || 12) + '" fill="' + (o.c || C.line) + '" text-anchor="' + (o.a || 'middle') + '"' + (o.b ? ' font-weight="bold"' : '') + '>' + s + '</text>'; }
  function ln(x1, y1, x2, y2, c, w, dash) { return '<line x1="' + x1 + '" y1="' + y1 + '" x2="' + x2 + '" y2="' + y2 + '" stroke="' + (c || C.line) + '" stroke-width="' + (w || 2) + '"' + (dash ? ' stroke-dasharray="4 3"' : '') + ' stroke-linecap="round"/>'; }
  function rect(x, y, w, h, f, s, sw, rx) { return '<rect x="' + x + '" y="' + y + '" width="' + w + '" height="' + h + '" rx="' + (rx || 0) + '" fill="' + (f || 'none') + '" stroke="' + (s || C.line) + '" stroke-width="' + (sw || 1.5) + '"/>'; }
  function circ(x, y, r, f, s, sw) { return '<circle cx="' + x + '" cy="' + y + '" r="' + r + '" fill="' + (f || 'none') + '" stroke="' + (s || 'none') + '" stroke-width="' + (sw || 1.5) + '"/>'; }
  function path(d, f, s, sw) { return '<path d="' + d + '" fill="' + (f || 'none') + '" stroke="' + (s || C.line) + '" stroke-width="' + (sw || 2) + '" stroke-linejoin="round" stroke-linecap="round"/>'; }

  /* ── 理科の 絵 ── */
  var PIC = {
    insect: function () { // こん虫（頭・むね・はら、あし6本、はね）
      var b = '<ellipse cx="60" cy="60" rx="16" ry="14" fill="#a3e635" stroke="#3f6212" stroke-width="2"/><ellipse cx="100" cy="60" rx="22" ry="17" fill="#84cc16" stroke="#3f6212" stroke-width="2"/><ellipse cx="160" cy="60" rx="38" ry="20" fill="#65a30d" stroke="#3f6212" stroke-width="2"/>';
      b += path('M50 50 Q35 25 22 20', 'none', '#3f6212', 2) + path('M54 48 Q48 22 40 12', 'none', '#3f6212', 2) + circ(52, 56, 4, '#1e293b');
      [[88, 74, 70, 104], [100, 77, 98, 108], [112, 74, 128, 104], [88, 46, 70, 16], [100, 43, 98, 12], [112, 46, 128, 16]].forEach(function (l, i) { if (i < 3) b += path('M' + l[0] + ' ' + l[1] + ' L' + l[2] + ' ' + l[3], 'none', '#3f6212', 2.5); });
      [[88, 76, 64, 100], [100, 77, 100, 106], [112, 76, 136, 100]].forEach(function () {});
      b += path('M96 48 Q130 0 190 18 Q150 40 104 50', 'rgba(219,234,254,.8)', '#64748b', 1.5);
      return svg(220, 115, b, 120);
    },
    magnet: function () { return svg(220, 70, rect(20, 20, 90, 30, '#ef4444', '#991b1b', 2) + rect(110, 20, 90, 30, '#3b82f6', '#1e3a8a', 2) + tx(65, 42, 'N', { fs: 18, b: 1, c: '#fff' }) + tx(155, 42, 'S', { fs: 18, b: 1, c: '#fff' }), 80); },
    mirror: function () { return svg(220, 110, circ(30, 26, 16, '#fde047', '#ca8a04', 2) + rect(100, 80, 60, 8, '#cbd5e1', '#475569', 2) + ln(42, 36, 130, 80, '#f59e0b', 3) + ln(130, 80, 200, 20, '#f59e0b', 3) + path('M196 16 l4 4 -6 2', 'none', '#f59e0b', 2) + tx(130, 104, 'かがみ', { fs: 11 }), 120); },
    circuit: function (kind) {
      var b = rect(20, 20, 180, 80, 'none', C.line, 2.5);
      var bat = function (x, y) { return rect(x - 18, y - 9, 36, 18, '#fde68a', '#92400e', 2) + rect(x + 18, y - 4, 5, 8, '#92400e', '#92400e', 1) + tx(x, y + 5, '＋　−'.replace('　', ''), { fs: 9 }); };
      if (kind === 'para') { b += ln(70, 20, 70, 100, C.line, 2.5) + rect(30, 30, 30, 60, '#fff', 'none') + rect(80, 30, 30, 60, '#fff', 'none'); b = rect(20, 20, 180, 80, 'none', C.line, 2.5) + ln(80, 20, 80, 100, C.line, 2.5) + bat(50, 100) + bat(50, 20).replace(/y="11"/, 'y="11"'); }
      else if (kind === 'series') b += bat(70, 100) + bat(130, 100);
      else b += bat(110, 100);
      b += circ(110, 20, 13, '#fef9c3', C.line, 2) + path('M102 14 Q110 30 118 14', 'none', '#ca8a04', 1.5);
      return svg(220, 120, b, 120);
    },
    moon: function () {
      var b = '', ph = [0, 0.25, 0.5, 0.75, 1, 1.25, 1.5, 1.75];
      ph.forEach(function (p, i) {
        var x = 26 + i * 40, y = 34, r = 15; b += circ(x, y, r, '#1e293b', '#475569', 1.5);
        var f = p <= 1 ? p : 2 - p, right = p < 1, w = r * Math.abs(1 - 2 * f), sweep = f > 0.5;
        if (f > 0.02) { b += '<path d="M' + x + ' ' + (y - r) + ' A' + r + ' ' + r + ' 0 0 ' + (right ? 1 : 0) + ' ' + x + ' ' + (y + r) + ' A' + w.toFixed(1) + ' ' + r + ' 0 0 ' + (right ? (sweep ? 1 : 0) : (sweep ? 0 : 1)) + ' ' + x + ' ' + (y - r) + '" fill="#fde047"/>'; }
      });
      return svg(330, 60, b, 70);
    },
    lever: function (L, lx, rx, R) {
      var b = path('M110 96 l-14 22 h28 z', '#94a3b8', '#475569', 2) + rect(10, 88, 200, 8, '#d6b38a', '#92400e', 2);
      var U = 15; b += ln(110, 82, 110 - lx.v * U, 82, C.blue, 1.5) + tx(110 - lx.v * U / 2, 78, lx.t, { fs: 11, b: 1, c: lx.t === '□cm' ? C.red : C.blue }) + ln(110, 82, 110 + rx.v * U, 82, C.blue, 1.5) + tx(110 + rx.v * U / 2, 78, rx.t, { fs: 11, b: 1, c: rx.t === '□cm' ? C.red : C.blue });
      b += ln(110 - lx.v * U, 96, 110 - lx.v * U, 110, C.line, 1.5) + rect(110 - lx.v * U - 16, 110, 32, 22, '#cbd5e1', '#475569', 1.5, 3) + tx(110 - lx.v * U, 125, L, { fs: 11, b: 1, c: L === '□kg' ? C.red : C.line });
      b += ln(110 + rx.v * U, 96, 110 + rx.v * U, 110, C.line, 1.5) + rect(110 + rx.v * U - 16, 110, 32, 22, '#cbd5e1', '#475569', 1.5, 3) + tx(110 + rx.v * U, 125, R, { fs: 11, b: 1, c: R === '□kg' ? C.red : C.line });
      return svg(220, 140, b, 140);
    },
    pendulum: function () { return svg(200, 130, ln(40, 10, 160, 10, C.line, 4) + ln(100, 10, 100, 110, C.gray, 1.2, 1) + ln(100, 10, 60, 100, C.line, 2) + circ(60, 104, 10, '#f59e0b', '#92400e', 2) + path('M64 104 Q100 128 136 104', 'none', C.blue, 1.5) + ln(100, 10, 140, 100, C.gray, 1.5, 1) + circ(140, 104, 10, 'none', C.gray, 1.5), 130); },
    strata: function () { var cols = ['#fde68a', '#d6d3d1', '#a8a29e', '#fcd34d', '#78716c', '#e7e5e4'], b = ''; cols.forEach(function (c, i) { b += path('M10 ' + (20 + i * 18) + ' Q110 ' + (12 + i * 18) + ' 210 ' + (22 + i * 18) + ' L210 ' + (40 + i * 18) + ' Q110 ' + (30 + i * 18) + ' 10 ' + (38 + i * 18) + ' Z', c, '#57534e', 1); }); for (var k = 0; k < 14; k++) b += circ(20 + k * 14, 46 + (k % 3), 2.5, '#57534e'); return svg(220, 136, b, 130); },
    beaker: function (col) { return svg(160, 130, path('M40 20 L40 110 Q40 118 48 118 L112 118 Q120 118 120 110 L120 20', '#fff', C.line, 2.5) + rect(42, 60, 76, 56, col || '#bfdbfe', 'none') + ln(30, 20, 130, 20, C.line, 2) + ln(118, 40, 128, 40, C.line, 1) + ln(118, 60, 128, 60, C.line, 1) + ln(118, 80, 128, 80, C.line, 1), 120); },
    plant: function () { return svg(180, 130, path('M90 120 L90 40', 'none', '#15803d', 4) + path('M90 70 Q60 50 50 64 Q70 76 90 70', '#4ade80', '#15803d', 2) + path('M90 56 Q120 36 132 50 Q112 62 90 56', '#4ade80', '#15803d', 2) + circ(90, 32, 10, '#f472b6', '#be185d', 2) + rect(30, 104, 120, 4, '#a16207', 'none') + path('M90 108 Q80 118 70 126 M90 108 Q98 120 108 126 M90 108 L90 128', 'none', '#a16207', 1.5), 130); },
    river: function () { return svg(220, 120, path('M10 20 Q80 20 100 60 Q120 100 210 100', 'none', '#60a5fa', 22) + path('M10 20 Q80 20 100 60 Q120 100 210 100', 'none', '#bfdbfe', 10) + ln(180, 70, 200, 85, C.gray, 1) + circ(70, 40, 3, '#a8a29e') + circ(150, 92, 3, '#a8a29e'), 120); },
    fish: function () { return svg(200, 90, path('M30 45 Q80 10 140 45 Q80 80 30 45 Z', '#fde68a', '#b45309', 2) + path('M140 45 L175 25 L170 45 L175 65 Z', '#fcd34d', '#b45309', 2) + circ(52, 40, 4, '#1e293b') + path('M90 22 Q100 10 112 24', 'none', '#b45309', 1.5) + path('M95 68 Q108 80 118 66', 'none', '#b45309', 1.5), 90); },
    flask: function () { return svg(160, 130, path('M68 14 L68 50 L36 110 Q34 118 44 118 L116 118 Q126 118 124 110 L92 50 L92 14', '#fff', C.line, 2.5) + path('M54 82 L106 82 L122 112 Q124 116 116 116 L44 116 Q36 116 38 112 Z', '#bfdbfe', 'none') + path('M64 124 Q80 112 96 124', '#fb923c', '#ea580c', 1.5), 135); },
    candle: function () { return svg(150, 130, path('M40 20 Q40 10 50 10 L100 10 Q110 10 110 20 L110 120 L40 120 Z', 'rgba(219,234,254,.5)', C.line, 2.5) + rect(66, 76, 18, 44, '#fef9c3', '#ca8a04', 1.5) + path('M75 74 Q68 60 75 48 Q82 60 75 74 Z', '#fb923c', '#ea580c', 1.5) + rect(30, 118, 90, 6, '#cbd5e1', '#475569', 1), 130); },
    weather: function () { return svg(220, 110, circ(50, 40, 18, '#fde047', '#ca8a04', 2) + path('M100 70 Q96 48 120 48 Q128 30 150 38 Q172 32 176 52 Q196 54 192 70 Z', '#e2e8f0', '#64748b', 2) + ln(120, 78, 114, 96, C.blue, 2) + ln(140, 78, 134, 96, C.blue, 2) + ln(160, 78, 154, 96, C.blue, 2) + rect(14, 76, 14, 30, '#fff', C.line, 1.5) + rect(18, 86, 6, 18, C.red, 'none'), 115); },
    front: function () { var b = path('M20 90 Q90 40 200 30', 'none', '#2563eb', 3); for (var i = 0; i < 6; i++) { var x = 40 + i * 28, y = 80 - i * 9; b += path('M' + x + ' ' + y + ' l8 -10 l6 10 z', '#2563eb', '#2563eb', 1); } return svg(220, 100, b, 100); },
    body: function () { return svg(140, 140, circ(70, 22, 16, '#fde7d6', '#b45309', 2) + rect(48, 40, 44, 56, '#fde7d6', '#b45309', 2, 12) + path('M48 50 L28 92 M92 50 L112 92 M58 96 L54 136 M82 96 L86 136', 'none', '#b45309', 6) + path('M62 56 Q70 50 78 56 Q80 70 70 74 Q60 70 62 56', '#fca5a5', '#dc2626', 1.5), 140); },
    star: function () { var b = rect(0, 0, 260, 110, '#0f172a', 'none'), pts = [[40, 30], [70, 50], [110, 40], [150, 70], [190, 30], [220, 60], [90, 85], [180, 90]]; pts.forEach(function (p, i) { b += circ(p[0], p[1], i % 3 ? 2 : 3.5, '#fef9c3'); }); b += path('M190 30 L150 70 L220 60 Z', 'none', '#fde68a', 1); return svg(260, 110, b, 110); },
    thermo: function () { return svg(80, 140, rect(32, 10, 16, 100, '#fff', C.line, 2, 8) + circ(40, 118, 14, '#ef4444', C.line, 2) + rect(36, 50, 8, 64, '#ef4444', 'none') + ln(48, 30, 56, 30, C.line, 1) + ln(48, 50, 56, 50, C.line, 1) + ln(48, 70, 56, 70, C.line, 1) + ln(48, 90, 56, 90, C.line, 1), 130); },
    atom: function () { return svg(160, 130, circ(80, 65, 12, '#fca5a5', '#dc2626', 2) + '<ellipse cx="80" cy="65" rx="60" ry="22" fill="none" stroke="#64748b" stroke-width="1.5"/><ellipse cx="80" cy="65" rx="60" ry="22" fill="none" stroke="#64748b" stroke-width="1.5" transform="rotate(60 80 65)"/><ellipse cx="80" cy="65" rx="60" ry="22" fill="none" stroke="#64748b" stroke-width="1.5" transform="rotate(-60 80 65)"/>' + circ(140, 65, 5, '#3b82f6') + circ(50, 13, 5, '#3b82f6') + circ(50, 117, 5, '#3b82f6'), 130); },
    slope: function () { return svg(220, 110, path('M10 100 L210 100 L210 30 Z', '#e2e8f0', C.line, 2) + '<g transform="rotate(-19.3 120 70)">' + rect(105, 50, 34, 24, '#fcd34d', '#b45309', 2) + '</g>' + ln(150, 55, 150, 95, C.red, 2) + path('M146 90 l4 6 4 -6', 'none', C.red, 2), 110); },
    cell: function () { return svg(200, 110, rect(20, 15, 160, 80, '#dcfce7', '#15803d', 3, 8) + rect(28, 23, 144, 64, '#f0fdf4', '#16a34a', 1.5, 6) + circ(70, 55, 14, '#a78bfa', '#6d28d9', 2) + circ(120, 40, 6, '#22c55e') + circ(140, 66, 6, '#22c55e') + circ(105, 70, 6, '#22c55e'), 110); },
    globe: function () { return svg(150, 130, circ(75, 65, 52, '#bfdbfe', '#2563eb', 2) + path('M45 40 Q60 30 75 45 Q70 60 55 58 Q42 52 45 40 Z', '#86efac', '#15803d', 1.5) + path('M85 70 Q105 62 112 82 Q100 100 88 92 Z', '#86efac', '#15803d', 1.5) + '<ellipse cx="75" cy="65" rx="52" ry="14" fill="none" stroke="#1e3a8a" stroke-width="1" stroke-dasharray="3 3"/>' + ln(75, 6, 75, 124, '#1e3a8a', 1, 1), 130); },
    sun: function () { var b = circ(70, 60, 26, '#fde047', '#ca8a04', 2); for (var i = 0; i < 12; i++) { var a = i * Math.PI / 6; b += ln(70 + 32 * Math.cos(a), 60 + 32 * Math.sin(a), 70 + 44 * Math.cos(a), 60 + 44 * Math.sin(a), '#f59e0b', 3); } return svg(140, 120, b, 110); }
  };
  var UNIT_PIC = {
    'r3-insect': 'insect', 'r3-magnet': 'magnet', 'r3-light': 'mirror', 'r3-more': 'plant',
    'science-weather': 'weather', 'science-seasons': 'plant', 'science-electric': 'circuit', 'science-airwater': 'beaker', 'science-moonstars': 'star', 'science-rainwater': 'river', 'science-body': 'body', 'science-temperature-volume': 'flask', 'science-heat': 'flask', 'science-water-change': 'flask',
    'r5-weather': 'weather', 'r5-pendulum': 'pendulum', 'r5-dissolve': 'beaker', 'r5-magnet2': 'circuit', 'r5-plant': 'plant', 'r5-flow': 'river', 'r5-medaka': 'fish', 'r5-human': 'body',
    'r6-combust': 'candle', 'r6-body': 'body', 'r6-earth': 'strata', 'r6-aqueous': 'beaker', 'r6-moon': 'moon', 'r6-lever': 'lever', 'r6-plant': 'plant', 'r6-electric': 'circuit', 'r6-environment': 'plant',
    'r7-plant': 'plant', 'r7-matter': 'beaker', 'r7-lsf': 'mirror', 'r7-earth': 'strata', 'r8-chem': 'atom', 'r8-body': 'cell', 'r8-elec': 'circuit', 'r8-weather': 'front', 'r9-undou': 'slope', 'r9-ion': 'atom', 'r9-seimei': 'cell', 'r9-uchu': 'sun', 'r9-kankyo': 'plant',
    's7-worldmap': 'globe', 's7-climate': 'globe'
  };

  /* ── 歴史の 年表（その 単元の 時代に 色を つける）── */
  var ERAS = [['縄文', 0, 3], ['弥生', 3, 5], ['古墳', 5, 6.5], ['飛鳥', 6.5, 7.5], ['奈良', 7.5, 8.2], ['平安', 8.2, 11], ['鎌倉', 11, 12.5], ['室町', 12.5, 14.5], ['安土桃山', 14.5, 15], ['江戸', 15, 18], ['明治', 18, 19.2], ['大正', 19.2, 19.6], ['昭和', 19.6, 21.6], ['平成・令和', 21.6, 23]];
  var UNIT_ERA = { 's6-hist-u1': [0, 2], 's6-hist-u2': [3, 4], 's6-hist-u3': [5, 5], 's6-hist-u4': [6, 6], 's6-hist-u5': [7, 7], 's6-hist-u6': [7, 8], 's6-hist-u7': [9, 9], 's6-hist-u8': [9, 9], 's6-hist-u9': [10, 10], 's6-hist-u10': [11, 12], 's6-hist-u11': [12, 13], 's7-civ': [0, 2], 's7-asuka': [3, 5], 's8-kamakura': [6, 8], 's8-edo': [9, 9], 's9-history': [10, 13] };
  function timeline(r) {
    var W = 330, x0 = 6, w = 318, b = '', tot = 23;
    ERAS.forEach(function (e, i) { var x = x0 + w * e[1] / tot, ww = w * (e[2] - e[1]) / tot, on = i >= r[0] && i <= r[1]; b += rect(x, 14, ww, 22, on ? '#fbbf24' : (i % 2 ? '#f1f5f9' : '#e2e8f0'), '#94a3b8', 0.8); if (ww > 16 || on) b += tx(x + ww / 2, 30, e[0].length > 3 && ww < 30 ? e[0].slice(0, 2) : e[0], { fs: on ? 10 : 8, b: on, c: on ? '#7c2d12' : '#475569' }); });
    b += tx(x0, 50, 'むかし', { fs: 9, a: 'start', c: '#64748b' }) + tx(x0 + w, 50, 'いま', { fs: 9, a: 'end', c: '#64748b' }) + path('M' + (x0 + 40) + ' 46 L' + (x0 + w - 30) + ' 46', 'none', '#94a3b8', 1);
    return svg(W, 56, b, 70);
  }

  /* ── 地図記号 ── */
  var SYM = {
    '学校': function (x, y) { return tx(x, y + 10, '文', { fs: 30, b: 1 }); },
    '郵便局': function (x, y) { return circ(x, y, 15, 'none', C.line, 2.5) + tx(x, y + 9, '〒', { fs: 22, b: 1 }); },
    '交番': function (x, y) { return ln(x - 12, y - 12, x + 12, y + 12, C.line, 3.5) + ln(x + 12, y - 12, x - 12, y + 12, C.line, 3.5); },
    '警察署': function (x, y) { return circ(x, y, 16, 'none', C.line, 2.5) + ln(x - 9, y - 9, x + 9, y + 9, C.line, 3) + ln(x + 9, y - 9, x - 9, y + 9, C.line, 3); },
    '消防署': function (x, y) { return path('M' + (x - 10) + ' ' + (y - 14) + ' Q' + (x - 12) + ' ' + (y + 2) + ' ' + x + ' ' + (y + 2) + ' Q' + (x + 12) + ' ' + (y + 2) + ' ' + (x + 10) + ' ' + (y - 14) + ' M' + x + ' ' + (y + 2) + ' L' + x + ' ' + (y + 16), 'none', C.line, 3); },
    '神社': function (x, y) { return path('M' + (x - 18) + ' ' + (y - 10) + ' L' + (x + 18) + ' ' + (y - 10) + ' M' + (x - 14) + ' ' + (y - 3) + ' L' + (x + 14) + ' ' + (y - 3) + ' M' + (x - 9) + ' ' + (y - 10) + ' L' + (x - 9) + ' ' + (y + 16) + ' M' + (x + 9) + ' ' + (y - 10) + ' L' + (x + 9) + ' ' + (y + 16), 'none', C.line, 3); },
    '寺': function (x, y) { return tx(x, y + 10, '卍', { fs: 30, b: 1 }); },
    '病院': function (x, y) { return path('M' + (x - 15) + ' ' + (y - 14) + ' Q' + x + ' ' + (y - 22) + ' ' + (x + 15) + ' ' + (y - 14) + ' L' + (x + 15) + ' ' + (y + 6) + ' Q' + x + ' ' + (y + 20) + ' ' + (x - 15) + ' ' + (y + 6) + ' Z', 'none', C.line, 2.5) + ln(x, y - 10, x, y + 8, C.line, 3) + ln(x - 9, y - 1, x + 9, y - 1, C.line, 3); },
    '市役所': function (x, y) { return circ(x, y, 15, 'none', C.line, 2.5) + circ(x, y, 7, 'none', C.line, 2.5); },
    '工場': function (x, y) { var b = circ(x, y, 9, 'none', C.line, 3); for (var i = 0; i < 8; i++) { var a = i * Math.PI / 4; b += ln(x + 9 * Math.cos(a), y + 9 * Math.sin(a), x + 15 * Math.cos(a), y + 15 * Math.sin(a), C.line, 4); } return b; },
    '田': function (x, y) { return ln(x - 7, y - 12, x - 7, y + 12, C.line, 3) + ln(x + 7, y - 12, x + 7, y + 12, C.line, 3); },
    '畑': function (x, y) { return path('M' + (x - 10) + ' ' + (y - 10) + ' L' + x + ' ' + (y + 6) + ' L' + (x + 10) + ' ' + (y - 10) + ' M' + x + ' ' + (y + 6) + ' L' + x + ' ' + (y + 14), 'none', C.line, 3); },
    '果樹園': function (x, y) { return circ(x, y + 2, 10, 'none', C.line, 3) + ln(x, y - 8, x, y - 16, C.line, 3); },
    '図書館': function (x, y) { return path('M' + x + ' ' + (y + 12) + ' L' + (x - 18) + ' ' + (y + 4) + ' L' + (x - 18) + ' ' + (y - 12) + ' L' + x + ' ' + (y - 4) + ' L' + (x + 18) + ' ' + (y - 12) + ' L' + (x + 18) + ' ' + (y + 4) + ' Z M' + x + ' ' + (y - 4) + ' L' + x + ' ' + (y + 12), 'none', C.line, 2.5); },
    '博物館': function (x, y) { return path('M' + (x - 18) + ' ' + (y - 4) + ' L' + x + ' ' + (y - 16) + ' L' + (x + 18) + ' ' + (y - 4) + ' Z', 'none', C.line, 2.5) + rect(x - 16, y - 4, 32, 18, 'none', C.line, 2.5) + ln(x - 6, y - 4, x - 6, y + 14, C.line, 2) + ln(x + 6, y - 4, x + 6, y + 14, C.line, 2); },
    '老人ホーム': function (x, y) { return path('M' + (x - 16) + ' ' + y + ' L' + x + ' ' + (y - 14) + ' L' + (x + 16) + ' ' + y + ' M' + (x - 12) + ' ' + (y - 3) + ' L' + (x - 12) + ' ' + (y + 14) + ' L' + (x + 12) + ' ' + (y + 14) + ' L' + (x + 12) + ' ' + (y - 3) + ' M' + (x + 4) + ' ' + (y + 14) + ' L' + (x + 4) + ' ' + (y + 2) + ' Q' + (x + 4) + ' ' + (y - 2) + ' ' + (x + 8) + ' ' + (y - 2), 'none', C.line, 2.5); }
  };
  function symFig(name) { return svg(80, 70, rect(4, 4, 72, 62, '#fff', '#cbd5e1', 1.5, 8) + SYM[name](40, 35), 80); }
  function installMap() {
    var o = window.genMapSymbol3; if (typeof o !== 'function' || o.__fs) return;
    var w = function () {
      if (Math.random() < 0.5 && typeof _pickBank === 'function') {
        var names = Object.keys(SYM), k = names[Math.floor(Math.random() * names.length)];
        var ws = names.filter(function (x) { return x !== k; }).sort(function () { return Math.random() - 0.5; }).slice(0, 3);
        var p = _pickBank([{ q: '🗺️ この 地図記号は 何を 表して いる？', correct: k, wrongs: ws }]);
        if (p) { p.fig = symFig(k); p.exp = '「' + k + '」の 地図記号。' + (SYM_EXP[k] || ''); return p; }
      }
      return o.apply(this, arguments);
    };
    w.__fs = 1; window.genMapSymbol3 = w;
  }
  var SYM_EXP = { '学校': '「文」の 字の 形', '郵便局': '〒を ○で かこんだ 形', '交番': '警ぼうを 2本 交わらせた 形', '警察署': '交番の 記号を ○で かこむ', '消防署': 'むかしの 火消しの 道具（さすまた）の 形', '神社': '鳥居の 形', '寺': '仏教の 「卍」', '病院': '赤十字の 形を 元に した 形', '市役所': '二重の ○', '工場': '機械の 歯車の 形', '田': '稲を かりとった あとの 形', '畑': '植物の ふた葉の 形', '果樹園': '果物の 実の 形', '図書館': '本を 開いた 形', '博物館': '建物の 形', '老人ホーム': '建物の 中に つえ' };

  /* ── __fmExtra（figmath から よばれる）── */
  window.__fmExtra = function (mode, q, prob) {
    var m;
    if ((m = q.match(/左：(□|\d+)kg ← (□|\d+)cm →支点← (□|\d+)cm → (□|\d+)kg/))) {
      var v = function (s, d) { return s === '□' ? d : Number(s); };
      var lv = v(m[2], 3), rv = v(m[3], 3); var sc = Math.max(lv, rv) > 6 ? 6 / Math.max(lv, rv) : 1;
      return PIC.lever(m[1] + 'kg', { v: lv * sc, t: m[2] + 'cm' }, { v: rv * sc, t: m[3] + 'cm' }, m[4] + 'kg');
    }
    if (/直列/.test(q) && /電池|つなぎ/.test(q) && !/何という|何と いう/.test(q)) return PIC.circuit('series');
    if (UNIT_ERA[mode]) return timeline(UNIT_ERA[mode]);
    var k = UNIT_PIC[mode];
    if (k && PIC[k]) return k === 'lever' ? '' : PIC[k]();
    return '';
  };
  window.__FIGSCI_PIC = PIC;
  installMap(); setTimeout(installMap, 0); setTimeout(installMap, 1600); window.addEventListener('load', function () { installMap(); setTimeout(installMap, 600); });
})();
