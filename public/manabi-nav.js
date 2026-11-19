/* 💡 MANABI_HINT_V1 学習の ヒントの 入口（子どもの アプリ）— 2026-11-19
 *  左の メニュー（チトセレ／家庭学習の 下）と スマホの 下の メニューに「💡 ヒント」を 出す。
 *  おすと /manabi（9教科の 学び方の ヒント＋MIに 合わせた 学び方）を ひらく。index.html は 手で 編集しない。 */
(function () {
  'use strict';
  if (window.__MANABI_NAV_V1__) return; window.__MANABI_NAV_V1__ = 1;
  function go() { location.href = '/manabi'; }
  function place() {
    var after = document.getElementById('btn-chitosele') || document.getElementById('btn-homestudy');
    if (after && !document.getElementById('btn-manabi')) {
      var b = document.createElement('button');
      b.id = 'btn-manabi'; b.className = 'nav3d relative';
      b.style.background = 'linear-gradient(180deg, #fcd34d, #f59e0b)';
      b.innerHTML = '<span class="nav3d-icon">💡</span>学習の ヒント';
      b.onclick = go;
      after.parentNode.insertBefore(b, after.nextSibling);
    }
    var ma = document.getElementById('mobile-btn-chitosele') || document.getElementById('mobile-btn-homestudy');
    if (ma && !document.getElementById('mobile-btn-manabi')) {
      var m = document.createElement('button');
      m.id = 'mobile-btn-manabi'; m.className = 'mnav-btn';
      m.innerHTML = '<span class="mnav-icon">💡</span><span class="mnav-label" style="color:#b45309">ヒント</span>';
      m.onclick = go;
      ma.parentNode.insertBefore(m, ma.nextSibling);
    }
    // チトセレの ボタンが あとから 出たら、その 下に 入れなおす
    var cs = document.getElementById('btn-chitosele'), bm = document.getElementById('btn-manabi');
    if (cs && bm && cs.nextSibling !== bm) cs.parentNode.insertBefore(bm, cs.nextSibling);
    var mcs = document.getElementById('mobile-btn-chitosele'), mbm = document.getElementById('mobile-btn-manabi');
    if (mcs && mbm && mcs.nextSibling !== mbm) mcs.parentNode.insertBefore(mbm, mcs.nextSibling);
  }
  setTimeout(place, 3000);
  setInterval(place, 3000);
})();
