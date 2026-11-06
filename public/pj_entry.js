/* ⚾⚽ __PJ_ENTRY_V2__ 先生PJ の 入口（子どもの アプリ）
 *  ・先生が クラスで ON にしたときだけ、メニューの「防衛戦」の となりに ボタンを 1つ 出す。OFF なら 何も 出さない。
 *  ・おすと /pj（べつの 軽い ページ）を ひらく。アプリの 画面や データには さわらない。
 *  ⚡ PJ_FAST_V1 アプリを 重くしない：
 *    ・ON/OFF は この端末に おぼえておき、OFF なら 10分は サーバに 聞かない（先生PJを やらない子は ほぼ 何も しない）。
 *    ・聞くのは アプリが おちついてから（ひまな ときに 1回だけ）。
 *    ・ボタンさがしは MutationObserver ではなく 少ない 回数の 見まわりだけ（ボタンが 見つかったら すぐ やめる）。
 */
(function () {
  'use strict';
  if (window.__PJ_ENTRY_V1__) return;
  window.__PJ_ENTRY_V1__ = true;
  var ID = 'btn-pj', OFF_TTL = 10 * 60 * 1000;
  // 同じ 端末を べつの 子が つかっても まざらないように、子どもごとに おぼえる
  function key() { var id = ''; try { if (typeof player !== 'undefined' && player && player.userId) id = String(player.userId); } catch (e) {} if (!id) try { id = String((window.player && window.player.userId) || ''); } catch (e) {} return 'pjEntryOn:' + (id || '?'); }
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
  function unplace() { var b = document.getElementById(ID); if (b && b.parentNode) b.parentNode.removeChild(b); }
  var timer = null;
  function show() { if (timer || place()) return; var n = 0; timer = setInterval(function () { if (place() || ++n > 30) { clearInterval(timer); timer = null; } }, 1000); }
  function read() { try { var v = JSON.parse(localStorage.getItem(key()) || 'null'); return v && typeof v.t === 'number' ? v : null; } catch (e) { return null; } }
  function write(on) { try { localStorage.setItem(key(), JSON.stringify({ on: !!on, t: Date.now() })); } catch (e) {} }
  function ask() {
    fetch('/api/pj/status', { credentials: 'same-origin', cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (d) { var on = !!(d && d.on); write(on); if (on) show(); else unplace(); })
      .catch(function () {});
  }
  function start() {
    var c = read(), age = c ? Date.now() - c.t : Infinity;
    if (c && c.on) show();                       // おぼえている ON は すぐ 出す（そのあと 念のため 聞きなおす）
    if (c && !c.on && age < OFF_TTL) return;     // OFF を おぼえている あいだは 何も しない
    ask();
  }
  var idle = window.requestIdleCallback || function (f) { return setTimeout(f, 1); };
  setTimeout(function () { idle(start, { timeout: 4000 }); }, 3000);
})();
