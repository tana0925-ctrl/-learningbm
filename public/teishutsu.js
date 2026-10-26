/* 📮 TEISHUTSU_V1 提出状況のアドバイス（子どもの画面）— 2026-10-27
 *
 *  A. 今週の家庭学習の提出状況（アプリの記録から自動・月〜日で数える＝週の振り返りの📊今週の記録と同じ数）
 *     ・アプリを開いたとき（1日1回まで）か、💬阪神マンとはじめる の最初（hschat.js が TEISHUTSU_CHAT_LINE() を呼ぶ）に、
 *       阪神マンが前向きに一言。どちらかで出したら、その日はもう出さない。責めない・比較しない。
 *  B. 学校の提出物：自分の「📮 まだの提出物」だけを、ホーム（わたしのカルテの近く）に小さく。しめきりが近い順。
 *     先生が ✓ をつけたら自動で消える。しめきりを過ぎても責めない言い方。ほかの子の状況は一切出さない（サーバーも自分の分しか返さない）。
 *  ・読むだけ（GET）。サーバーに何も書かない。1日1回の記録は この端末だけ（先生の「見るだけ」モードでは その場かぎりのメモリ）。
 *  ・ことばは NGWORD_V1 に合わせる（おそい・少ない・〜しかない・まだ〜ない などは使わない）。コインは付けない。
 *  ・index.html は手で編集しない。
 */
(function () {
  'use strict';
  if (window.__TEISHUTSU_V1__) return; window.__TEISHUTSU_V1__ = 1;

  var SEEN_KEY = 'tsNudgeV1:';
  var WD = ['日', '月', '火', '水', '木', '金', '土'];
  var _d = null, _busy = false, _at = 0;

  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function day830() { var d = new Date(Date.now() + 9 * 3600000 - 8.5 * 3600000); return d.toISOString().slice(0, 10); }
  function seenToday() { try { return localStorage.getItem(SEEN_KEY + day830()) === '1'; } catch (e) { return false; } }
  function markSeen() { try { localStorage.setItem(SEEN_KEY + day830(), '1'); } catch (e) {} }
  function face() { var f = '🐯'; try { if (typeof window.monSpriteHtml === 'function') f = window.monSpriteHtml(154, '🐯'); } catch (e) {} return f; }
  function curP() { try { return (typeof player !== 'undefined') ? player : null; } catch (e) { return null; } }
  function md(ymd) { var p = String(ymd || '').split('-'); if (p.length < 3) return ''; var d = new Date(Date.UTC(+p[0], +p[1] - 1, +p[2])); return (+p[1]) + '/' + (+p[2]) + '（' + WD[d.getUTCDay()] + '）'; }

  // ───────── ことば（ここに集める：テストで NG語を確かめる） ─────────
  function hwLine(d) {
    var h = (d && d.hw) || {}, n = Number(h.days) || 0;
    if (h.submittedToday && n > 0) return '今週は ' + n + '日 出せとるで！ ナイスや！';
    if (n <= 0) return '今週は これからやな、今日の 1回目 いこか！';
    return '今週は ' + n + '日 出せとるで！ あと1日 いけるか？';
  }
  function itemLine(it) {
    var t = '「' + it.title + '」', dl = it.daysLeft;
    if (dl == null || dl < 0) return t + '、出せたら 先生に わたそな';
    if (dl === 0) return t + '、今日までやで。わすれんように 出そな！';
    if (dl === 1) return t + '、明日までやで。いっしょに がんばろ！';
    return t + '、' + md(it.dueDate) + 'までやで。じゅんび しとこか！';
  }
  function dueLabel(it) {
    var dl = it.daysLeft;
    if (dl == null) return '';
    if (dl < 0) return '出せたら 先生に わたそう';
    if (dl === 0) return '今日まで';
    if (dl === 1) return '明日まで';
    return md(it.dueDate) + 'まで';
  }
  function nearest(d) { var p = (d && d.pending) || []; return p.length ? p[0] : null; }
  window.TS_SAY = { hwLine: hwLine, itemLine: itemLine, dueLabel: dueLabel };   // テスト用

  // ───────── 📮 まだの提出物（ホーム・わたしのカルテの近く） ─────────
  function ensureBox() {
    var el = document.getElementById('tsPendingBox');
    if (el) return el;
    var host = document.getElementById('myKarteCard') || document.getElementById('homeReviewSuggest');
    if (!host || !host.parentNode) return null;
    el = document.createElement('div');
    el.id = 'tsPendingBox';
    el.style.display = 'none';
    el.style.marginBottom = '10px';
    host.parentNode.insertBefore(el, host);
    return el;
  }
  function render() {
    var el = ensureBox(); if (!el) return;
    var p = (_d && _d.ok && _d.pending) || [];
    if (!p.length) { el.style.display = 'none'; el.innerHTML = ''; return; }
    var h = '<div style="border:2px solid #bae6fd;background:#f0f9ff;border-radius:14px;padding:8px 10px">'
      + '<div style="font-weight:900;font-size:14px;color:#0369a1">📮 まだの提出物 <span style="font-weight:600;font-size:11px;color:#0c4a6e">（先生に出したら きえるよ）</span></div>';
    for (var i = 0; i < p.length && i < 4; i++) {
      var it = p[i], lb = dueLabel(it);
      h += '<div style="display:flex;gap:6px;align-items:baseline;font-size:13.5px;color:#0f172a;margin-top:3px">'
        + '<span>・' + (it.subject ? '<span style="font-size:11px;color:#0369a1">［' + esc(it.subject) + '］</span>' : '') + esc(it.title) + '</span>'
        + (lb ? '<span style="margin-left:auto;white-space:nowrap;font-size:12px;font-weight:800;color:#0369a1">' + esc(lb) + '</span>' : '') + '</div>';
    }
    if (p.length > 4) h += '<div style="font-size:11.5px;color:#0369a1;margin-top:2px">ほかに ' + (p.length - 4) + 'つ</div>';
    h += '<div style="display:flex;gap:6px;align-items:center;margin-top:5px;font-size:12.5px;color:#0c4a6e"><span style="font-size:22px;line-height:1">' + face() + '</span><span>' + esc(itemLine(p[0])) + '</span></div>';
    h += '</div>';
    el.innerHTML = h;
    el.style.display = '';
  }

  // ───────── 阪神マンの一言（アプリを開いたとき・1日1回まで） ─────────
  function closeNudge() { var el = document.getElementById('tsNudge'); if (el && el.parentNode) el.parentNode.removeChild(el); }
  function showNudge() {
    if (!_d || !_d.ok || seenToday() || document.getElementById('tsNudge')) return false;
    if (document.getElementById('weekRefNudge') || document.getElementById('hsChat') && document.getElementById('hsChat').style.display !== 'none') return false;   // ほかの声かけ・対話と重ねない
    markSeen();
    var lines = [hwLine(_d)];
    var nx = nearest(_d); if (nx && nx.daysLeft != null && nx.daysLeft <= 1) lines.push(itemLine(nx));
    var el = document.createElement('div');
    el.id = 'tsNudge';
    el.setAttribute('style', 'position:fixed;right:12px;top:84px;z-index:9996;width:330px;max-width:calc(100vw - 24px);background:#f0f9ff;border:2px solid #7dd3fc;border-radius:16px;box-shadow:0 8px 24px rgba(0,0,0,.16);padding:10px 12px;color:#0c4a6e');
    el.innerHTML = '<button type="button" id="tsNudgeX" aria-label="とじる" style="position:absolute;right:6px;top:4px;background:none;border:none;font-size:20px;color:#0369a1;cursor:pointer;min-width:36px;min-height:36px">×</button>'
      + '<div style="display:flex;gap:8px;align-items:flex-start"><div style="font-size:30px;line-height:1">' + face() + '</div>'
      + '<div style="flex:1;padding-right:18px">' + lines.map(function (l, i) { return '<div style="font-size:' + (i ? '13' : '14') + 'px;font-weight:' + (i ? '700' : '900') + ';line-height:1.5;margin-top:' + (i ? '3' : '0') + 'px">' + esc(l) + '</div>'; }).join('') + '</div></div>';
    document.body.appendChild(el);
    var x = document.getElementById('tsNudgeX'); if (x) x.onclick = closeNudge;
    setTimeout(closeNudge, 25000);
    return true;
  }
  // 💬 hschat.js の対話の最初に入れる一言（その日まだ出していなければ）。出したら その日は もう出さない。
  window.TEISHUTSU_CHAT_LINE = function () {
    if (!_d || !_d.ok || seenToday()) return '';
    markSeen();
    closeNudge();
    var s = hwLine(_d);
    var nx = nearest(_d); if (nx && nx.daysLeft != null && nx.daysLeft <= 1) s += '\n' + itemLine(nx);
    return s;
  };

  function load(force) {
    if (_busy) return Promise.resolve(_d);
    if (!force && _at && Date.now() - _at < 60000) return Promise.resolve(_d);
    _busy = true; _at = Date.now();
    return fetch('/api/student/teishutsu', { credentials: 'include' })
      .then(function (r) { return r.json(); })
      .then(function (j) { _busy = false; if (j && j.ok) _d = j; render(); return _d; })
      .catch(function () { _busy = false; return _d; });
  }
  window.TEISHUTSU_RELOAD = function () { return load(true); };

  // ホームが描かれるタイミングに相乗りする（わたしのカルテと同じ瞬間）
  function hook() {
    try {
      if (typeof window.loadMiniReview === 'function' && !window.loadMiniReview.__tsHooked) {
        var orig = window.loadMiniReview;
        var wrapped = function () { var r; try { r = orig.apply(this, arguments); } catch (e) {} try { load(); } catch (e) {} return r; };
        wrapped.__tsHooked = true; wrapped.__karteHooked = orig.__karteHooked;
        window.loadMiniReview = wrapped;
        return true;
      }
    } catch (e) {}
    return false;
  }

  var tries = 0, started = false, nudgeTry = 0;
  var timer = setInterval(function () {
    tries++;
    var p = curP();
    hook();
    if (!started && p && p.userId) {
      started = true;
      load(true).then(function () {
        var go = function () { if (!showNudge() && !seenToday() && ++nudgeTry < 3) setTimeout(go, 35000); };
        setTimeout(go, 6000);
      });
    }
    if (started && document.getElementById('homeReviewSuggest') && !document.getElementById('tsPendingBox') && _d) render();
    if ((started && tries > 40) || tries > 120) clearInterval(timer);
  }, 1500);
})();
