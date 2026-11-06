/* ⚾⚽ __PJ_ENTRY_V1__ 先生PJ の 入口（子どもの アプリ）
 *  ・先生が クラスで ON にしたときだけ、メニューの「防衛戦」の となりに ボタンを 1つ 出す。OFF なら 何も 出さない。
 *  ・おすと /pj（べつの 軽い ページ）を ひらく。アプリの 画面や データには さわらない。
 */
(function () {
  'use strict';
  if (window.__PJ_ENTRY_V1__) return;
  window.__PJ_ENTRY_V1__ = true;
  var ID = 'btn-pj';
  function place() {
    if (document.getElementById(ID)) return true;
    var def = document.getElementById('btn-defense');
    if (!def || !def.parentNode) return false;
    var b = document.createElement('button');
    b.id = ID;
    b.className = 'nav3d';
    b.setAttribute('style', 'background: linear-gradient(180deg, #34d399, #059669);');
    b.innerHTML = '<span class="nav3d-icon">⚾</span>先生PJ';
    b.onclick = function () { location.href = '/pj'; };
    def.parentNode.insertBefore(b, def.nextSibling);
    return true;
  }
  function start() {
    fetch('/api/pj/status', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) {
        if (!d || !d.on) return;
        var n = 0, t = setInterval(function () { if (place() || ++n > 40) clearInterval(t); }, 500);
      })
      .catch(function () {});
  }
  setTimeout(start, 2500);
})();
