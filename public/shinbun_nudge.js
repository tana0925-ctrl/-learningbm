/* 📰 __SHINBUN_ZAIRYO_V1__ 来週の 道しるべ新聞の 材料チェック（先生の画面）
 *
 *  ・水曜日から 日曜日まで、今週（月曜〜きょう）の 材料が うすい子を 知らせる カード。
 *  ・新聞は 一度のせた ネタを くり返さないので、材料が 少ない子ほど 紙面が うすくなる。
 *    写真1枚（📸成果物）か メモ1つ（カルテの 先生メモ・「カルテにのせる」）が あれば 記事が 書ける。
 *  ・とじると その日は もう 出さない（localStorage）。数は /api/teacher/shinbun-material（読むだけ）。
 */
(function () {
  'use strict';
  if (window.__SHINBUN_ZAIRYO_V1__) return;
  window.__SHINBUN_ZAIRYO_V1__ = true;
  var ID = 'shinbunZairyoCard', KEY = 'shinbunZairyoV1';

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); }
  function today() { var d = new Date(Date.now() + 9 * 3600000); return d.getUTCFullYear() + '-' + (d.getUTCMonth() + 1) + '-' + d.getUTCDate(); }
  function closedToday() { try { return localStorage.getItem(KEY) === today(); } catch (e) { return false; } }
  function md(dk) { var p = String(dk || '').split('-'); return p.length < 3 ? '' : Number(p[1]) + '/' + Number(p[2]); }
  function nameOf(r) { try { if (typeof window.resolveStudentName === 'function') return window.resolveStudentName(r.loginId, r.name) || r.name; } catch (e) {} return r.name || r.loginId || ''; }

  // うすい：写真も メモも なく、家庭学習の日と アプリの日を あわせても 2日まで
  function classify(rows) {
    var thin = [], noPm = [];
    rows.forEach(function (r) {
      var pm = (r.photos || 0) + (r.notes || 0);
      if (pm > 0) return;
      if ((r.hw || 0) + (r.appDays || 0) <= 2) thin.push(r); else noPm.push(r);
    });
    var key = function (r) { return (r.hw || 0) + (r.appDays || 0); };
    thin.sort(function (a, b) { return key(a) - key(b); });
    return { thin: thin, noPm: noPm };
  }

  function line(r) {
    var bits = ['家庭学習 ' + (r.hw || 0) + '日', 'アプリ ' + (r.appDays || 0) + '日'];
    return '<li style="padding:2px 0;border-bottom:1px dotted #e5e7eb"><b>' + esc(nameOf(r)) + '</b> <span style="color:#6b7280;font-size:12px">' + bits.join('・') + '・写真/メモ なし</span></li>';
  }

  function render(d) {
    var old = document.getElementById(ID); if (old) old.parentNode.removeChild(old);
    var c = classify(d.rows || []);
    if (!c.thin.length && !c.noPm.length) return;
    var el = document.createElement('div');
    el.id = ID;
    el.setAttribute('style', 'position:fixed;left:12px;bottom:12px;z-index:9997;width:min(380px,calc(100vw - 24px));max-height:70vh;overflow:auto;background:#fffdf5;border:2px solid #c8312b;border-radius:14px;box-shadow:0 10px 28px rgba(0,0,0,.2);padding:10px 12px;font-size:13px;color:#1c1c1c');
    var h = '<div style="display:flex;align-items:center;gap:6px"><b style="font-size:14px;flex:1">📰 来週の 新聞の 材料チェック</b>'
      + '<button type="button" id="' + ID + 'Min" style="border:0;background:#f3f4f6;border-radius:8px;padding:2px 8px;cursor:pointer">▾</button></div>'
      + '<div style="color:#6b7280;font-size:12px;margin-top:2px">今週（' + esc(md(d.from)) + '〜' + esc(md(d.to)) + '）の 記録から。写真1枚か メモ1つで、その子の 記事が 書けます。</div>'
      + '<div id="' + ID + 'Body">';
    if (c.thin.length) {
      h += '<div style="margin-top:8px;font-weight:800;color:#c8312b">材料が うすい子　' + c.thin.length + '人</div><ul style="list-style:none;margin:2px 0 0;padding:0">' + c.thin.map(line).join('') + '</ul>';
    }
    if (c.noPm.length) {
      h += '<details style="margin-top:8px"><summary style="cursor:pointer;font-weight:700;color:#92400e">記録は あるが 写真・メモが まだの子　' + c.noPm.length + '人</summary><ul style="list-style:none;margin:2px 0 0;padding:0">' + c.noPm.map(line).join('') + '</ul></details>';
    }
    h += '<div style="margin-top:6px;color:#6b7280;font-size:11.5px">メモは カルテの 先生メモで「カルテにのせる」を オンに。日付は 今週に してください。</div>'
      + '<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap">'
      + (typeof window.PF_OPEN === 'function' ? '<button type="button" id="' + ID + 'Pf" style="background:#c026d3;color:#fff;border:0;border-radius:10px;padding:6px 12px;font-weight:800;cursor:pointer">📸 成果物を ひらく</button>' : '')
      + '<button type="button" id="' + ID + 'Re" style="background:#fff;border:1.5px solid #d1d5db;border-radius:10px;padding:6px 10px;cursor:pointer">🔄 数えなおす</button>'
      + '<button type="button" id="' + ID + 'X" style="background:#fff;border:1.5px solid #d1d5db;border-radius:10px;padding:6px 10px;cursor:pointer">きょうは とじる</button>'
      + '</div></div>';
    el.innerHTML = h;
    document.body.appendChild(el);
    var $ = function (s) { return document.getElementById(ID + s); };
    if ($('Pf')) $('Pf').onclick = function () { try { window.PF_OPEN(); } catch (e) {} };
    $('Re').onclick = function () { load(true); };
    $('X').onclick = function () { try { localStorage.setItem(KEY, today()); } catch (e) {} var x = document.getElementById(ID); if (x) x.parentNode.removeChild(x); };
    $('Min').onclick = function () { var b = $('Body'); if (!b) return; var hid = b.style.display === 'none'; b.style.display = hid ? '' : 'none'; this.textContent = hid ? '▾' : '▸'; };
  }

  function load(force) {
    if (!force && closedToday()) return;
    fetch('/api/teacher/shinbun-material', { credentials: 'include' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d || !d.ok) return;
        if (!force && !(d.weekday >= 2)) return;   // 水曜（月=0 なので 2）から 日曜まで
        render(d);
      })
      .catch(function () {});
  }

  window.__shinbunZairyo = { classify: classify, load: load };
  // 画面が おちついてから 1回だけ
  setTimeout(function () { load(false); }, 4000);
})();
