/* 🗓 CHITOSELE_V1 チトセレの 入口（子どもの アプリ）— 2026-11-11
 *  先生が「子どもに出す」に しているクラスだけ、左の メニュー（家庭学習の下）と スマホの 下の メニューに「🗓 チトセレ」を 出す。
 *  おすと /chitosele（計画の 画面）を ひらく。index.html は 手で 編集しない。 */
(function () {
  'use strict';
  if (window.__CHITOSELE_V1__) return; window.__CHITOSELE_V1__ = 1;
  var on = false;
  function go() { location.href = '/chitosele'; }
  function place() {
    if (!on) return;
    var hs = document.getElementById('btn-homestudy');
    if (hs && !document.getElementById('btn-chitosele')) {
      var b = document.createElement('button');
      b.id = 'btn-chitosele'; b.className = 'nav3d relative';
      b.style.background = 'linear-gradient(180deg, #fb923c, #ea580c)';
      b.innerHTML = '<span class="nav3d-icon">🗓</span>チトセレ';
      b.onclick = go;
      hs.parentNode.insertBefore(b, hs.nextSibling);
    }
    var mh = document.getElementById('mobile-btn-homestudy');
    if (mh && !document.getElementById('mobile-btn-chitosele')) {
      var m = document.createElement('button');
      m.id = 'mobile-btn-chitosele'; m.className = 'mnav-btn';
      m.innerHTML = '<span class="mnav-icon">🗓</span><span class="mnav-label" style="color:#ea580c">チトセレ</span>';
      m.onclick = go;
      mh.parentNode.insertBefore(m, mh.nextSibling);
    }
  }
  function check() {
    fetch('/api/chitosele/me', { credentials: 'include', cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (j) { on = !!(j && j.ok && j.on); place(); }).catch(function () {});
  }
  setTimeout(check, 2500);
  setInterval(function () { if (on) place(); }, 3000);
  setInterval(check, 10 * 60000);
})();
