/* __HS_NEXT_RECALL_V1__
   「次、どうすると学びの天気が良くなる？」の入力の すぐ上に、
   まえに じぶんが 書いた「つぎにすること」を 直近3回ぶん（日づけつき）置くだけ。
   ・見せるだけ。ごほうびも 点も つけない
   ・できたかの チェックらんは つけない
   ・書いていない日は とばす。1件も無い子には 何も出さない
*/
(function () {
  'use strict';
  if (window.__HS_NEXT_RECALL_ON__) return;
  window.__HS_NEXT_RECALL_ON__ = true;

  var BOX_ID = 'hsNextRecallBox';
  var DOW = ['日', '月', '火', '水', '木', '金', '土'];

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function parseKey(k) {
    try {
      var p = String(k || '').split('-');
      var y = Number(p[0]), m = Number(p[1]), d = Number(p[2]);
      if (!y || !m || !d) return null;
      return new Date(y, m - 1, d, 0, 0, 0, 0);
    } catch (e) { return null; }
  }

  function dateLabel(k) {
    var d = parseKey(k);
    if (!d) return '';
    return (d.getMonth() + 1) + '/' + d.getDate() + '（' + (DOW[d.getDay()] || '') + '）';
  }

  function todayKey() {
    try {
      if (typeof hsGetDayKey830 === 'function') {
        var k = hsGetDayKey830(new Date());
        if (k) return String(k);
      }
    } catch (e) {}
    var n = new Date();
    var mm = ('0' + (n.getMonth() + 1)).slice(-2);
    var dd = ('0' + n.getDate()).slice(-2);
    return n.getFullYear() + '-' + mm + '-' + dd;
  }

  function readLogs() {
    try {
      if (typeof hsLogs === 'function') {
        var a = hsLogs();
        if (Object.prototype.toString.call(a) === '[object Array]') return a;
      }
    } catch (e) {}
    try {
      var b = window.player && window.player.homeStudy && window.player.homeStudy.logs;
      if (Object.prototype.toString.call(b) === '[object Array]') return b;
    } catch (e) {}
    return [];
  }

  function pick() {
    var tk = todayKey();
    var arr = [];
    var all = readLogs();
    for (var i = 0; i < all.length; i++) {
      var e = all[i];
      if (!e || !e.dayKey) continue;
      if (String(e.dayKey) >= String(tk)) continue;
      var txt = String(e.nextImprove == null ? '' : e.nextImprove).replace(/^\s+|\s+$/g, '');
      if (!txt) continue;
      arr.push({ dayKey: String(e.dayKey), text: txt });
    }
    arr.sort(function (a, b) { return a.dayKey < b.dayKey ? 1 : (a.dayKey > b.dayKey ? -1 : 0); });
    return arr.slice(0, 3);
  }

  function signature(items) {
    var s = '';
    for (var i = 0; i < items.length; i++) {
      s += '[' + items[i].dayKey + ']' + items[i].text + ';;';
    }
    return s;
  }

  function buildHtml(items) {
    var rows = '';
    for (var i = 0; i < items.length; i++) {
      var body = esc(items[i].text).replace(/\r?\n/g, '<br>');
      rows += '<div style="display:flex; gap:6px; align-items:flex-start; margin-top:3px;">'
        + '<span style="flex:0 0 auto; font-size:12px; color:#64748b; padding-top:2px; white-space:nowrap;">'
        + esc(dateLabel(items[i].dayKey)) + '</span>'
        + '<span style="flex:1 1 auto; font-size:14px; line-height:1.45; color:#334155; word-break:break-word;">'
        + body + '</span>'
        + '</div>';
    }
    return '<div style="font-size:12px; font-weight:700; color:#64748b;">'
      + 'まえに じぶんが 書いた「つぎにすること」</div>' + rows;
  }

  function render() {
    try {
      var ta = document.getElementById('hsNextImprove');
      if (!ta || !ta.parentNode) return;
      var host = document.getElementById(BOX_ID);
      var items = pick();
      if (!items.length) {
        if (host && host.parentNode) host.parentNode.removeChild(host);
        return;
      }
      var sig = signature(items);
      if (!host) {
        host = document.createElement('div');
        host.id = BOX_ID;
        host.style.cssText = 'margin:4px 0 2px; padding:5px 8px; background:#f8fafc;'
          + ' border-left:3px solid #cbd5e1; border-radius:8px;';
        ta.parentNode.insertBefore(host, ta);
      }
      if (host.getAttribute('data-sig') === sig) return;
      host.setAttribute('data-sig', sig);
      host.innerHTML = buildHtml(items);
    } catch (e) {}
  }

  function hook() {
    try {
      if (typeof window.hsRender === 'function' && !window.hsRender.__hsNextRecall) {
        var orig = window.hsRender;
        var wrapped = function () {
          var r = orig.apply(this, arguments);
          try { render(); } catch (e) {}
          return r;
        };
        wrapped.__hsNextRecall = true;
        window.hsRender = wrapped;
      }
    } catch (e) {}
  }

  function boot() { hook(); render(); }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
  } else {
    boot();
  }
  setInterval(function () { hook(); render(); }, 1500);
})();
