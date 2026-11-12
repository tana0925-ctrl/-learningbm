/* 🪜 SAKANOBORI_V1 修行（算数）で つまずいたら、阪神マンが「前に 習った 力」を たしかめに さそう — 2026-11-13
 *  ・算数の 修行で つづけて 2回 まちがえた、または さいごの 5問で 3回 まちがえたら 出る。
 *  ・「🔍 たしかめる」→ 理解度チェック（hscheck.js）を その単元で ひらく。❌の ときは 前の学年の 技へ さかのぼり、
 *    いちばん 根っこの 技の 修行へ 行ける（ここは hscheck の しくみ そのまま）。
 *  ・「このまま がんばる」でも OK。同じ単元では 1日 1回だけ さそう（しつこく しない）。
 *  ・index.html は 手で 編集しない。player と trainingMode（グローバル）を 見ているだけ。
 */
(function () {
  'use strict';
  if (window.__SAKANOBORI_V1__) return; window.__SAKANOBORI_V1__ = 1;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function dayKey() { var d = new Date(Date.now() + 9 * 3600000); return d.toISOString().slice(0, 10); }
  function curMode() { try { return typeof trainingMode !== 'undefined' ? String(trainingMode) : ''; } catch (e) { return ''; } }
  function ra(mode) { try { var tp = player && player.trainingProgress && player.trainingProgress[mode]; return (tp && Array.isArray(tp.recentAnswers)) ? tp.recentAnswers : null; } catch (e) { return null; } }
  function HC() { return window.HSCHECK || null; }
  function goalOf(mode) { var H = HC(); return H && H.UNIT2GOAL ? H.UNIT2GOAL[mode] : null; }
  function skill(id) { var H = HC(); if (!H || !H.S) return null; for (var i = 0; i < H.S.length; i++) if (H.S[i].id === id) return H.S[i]; return null; }
  function asked(mode) { try { return localStorage.getItem('skb1:' + mode + ':' + dayKey()) === '1'; } catch (e) { return !!SEEN[mode]; } }
  function markAsked(mode) { SEEN[mode] = 1; try { localStorage.setItem('skb1:' + mode + ':' + dayKey(), '1'); } catch (e) {} }
  function visible(el) { return !!(el && el.offsetParent !== null); }

  var SEEN = {};
  var seq = {};          // この ページを ひらいてからの 答え（単元ごと）
  var last = { mode: '', len: -1, tail: '' };

  // 新しい 答えが ふえたかを 見る（recentAnswers は 100こで あたまから けされるので、長さと うしろ5つで 見る）
  function poll() {
    var mode = curMode(); if (!mode || !goalOf(mode)) { last = { mode: mode, len: -1, tail: '' }; return; }
    var a = ra(mode); if (!a) return;
    var len = a.length, tail = JSON.stringify(a.slice(-5));
    if (last.mode !== mode || last.len < 0) { last = { mode: mode, len: len, tail: tail }; return; }
    var add = 0;
    if (len > last.len) add = len - last.len; else if (tail !== last.tail) add = 1;
    last = { mode: mode, len: len, tail: tail };
    if (!add) return;
    var s = seq[mode] = seq[mode] || [];
    a.slice(-Math.min(add, 5)).forEach(function (v) { s.push(!!v); });
    if (s.length > 10) s.splice(0, s.length - 10);
    check(mode, s);
  }
  function check(mode, s) {
    if (asked(mode) || document.getElementById('skbPop') || document.getElementById('hkChat') && visible(document.getElementById('hkChat'))) return;
    var n = s.length, two = n >= 2 && !s[n - 1] && !s[n - 2];
    var five = s.slice(-5), wr = five.filter(function (x) { return !x; }).length;
    if (two || (five.length >= 5 && wr >= 3)) setTimeout(function () { offer(mode); }, 1700);   // まちがいの 表示が おわってから
  }

  var CSS = '#skbPop{position:fixed;left:0;right:0;bottom:0;z-index:9989;display:flex;justify-content:center;padding:0 10px 12px;pointer-events:none}'
    + '#skbPop .sk-box{pointer-events:auto;width:100%;max-width:640px;background:#fef9f0;border:3px solid #facc15;border-radius:20px;box-shadow:0 10px 30px rgba(0,0,0,.25);padding:12px 14px}'
    + '#skbPop .sk-row{display:flex;gap:10px;align-items:flex-start}'
    + '#skbPop .sk-face{width:46px;height:46px;flex:0 0 46px;display:flex;align-items:center;justify-content:center;font-size:30px;background:#fff;border-radius:50%;border:2px solid #fde68a;overflow:hidden}'
    + '#skbPop .sk-face img{max-width:42px;max-height:42px}'
    + '#skbPop .sk-b{flex:1;background:#fff;border:2px solid #fde68a;border-radius:16px;border-top-left-radius:6px;padding:9px 12px;font-size:16px;line-height:1.6;color:#1f2937}'
    + '#skbPop .sk-ch{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:10px}'
    + '#skbPop .sk-btn{min-height:52px;border-radius:16px;border:2px solid #f59e0b;background:#fff;color:#78350f;font-size:16px;font-weight:800;cursor:pointer}'
    + '#skbPop .sk-btn.main{background:#0ea5e9;border-color:#0369a1;color:#fff}'
    + '@media (max-width:480px){#skbPop .sk-ch{grid-template-columns:1fr}}';
  function face() { var f = '🐯'; try { if (typeof window.monSpriteHtml === 'function') f = window.monSpriteHtml(154, '🐯'); } catch (e) {} return f; }
  // UNIT_PATH_V1 単元ごとの「もどる道」を そのまま 見せる（ひとつ前の 単元では なく、関係する 技だけ）
  var LINES = [
    'むずかしい 問題やな！「{u}」で つまずく ときは、前に 習った 技に 原因が あることが 多いんや。',
    'まちがいが つづいとるな。あせらんで ええで！「{u}」の 根っこに ある 技を たしかめてみよか。',
    'ここが ふんばりどころや！「{u}」を ささえてる 前の 技、どこまで できてるか 見てみよ。'
  ];
  function offer(mode) {
    if (curMode() !== mode || asked(mode) || document.getElementById('skbPop')) return;
    var H = HC(); if (!H || typeof H.open !== 'function') return;
    var g = skill(goalOf(mode)); if (!g) return;
    var uname = mode; try { var C2 = window.CURRICULUM; var gs = C2 && C2.math && C2.math.grades || {}; for (var gk in gs) (gs[gk].units || []).forEach(function (u) { if (u.id === mode) uname = u.name; }); } catch (e) {}
    var route = ''; try { route = (typeof H.pathText === 'function') ? H.pathText(mode) : ''; } catch (e) {}
    markAsked(mode);
    if (!document.getElementById('skbCss')) { var st = document.createElement('style'); st.id = 'skbCss'; st.textContent = CSS; document.head.appendChild(st); }
    var k = (new Date().getDate() + mode.length) % LINES.length;
    var root = document.createElement('div'); root.id = 'skbPop';
    root.innerHTML = '<div class="sk-box"><div class="sk-row"><span class="sk-face">' + face() + '</span><div class="sk-b">' + esc(LINES[k].replace('{u}', uname))
      + (route ? '<div style="margin:6px 0;background:#fffbeb;border-radius:10px;padding:5px 8px;font-size:14px;font-weight:800;color:#92400e">🛤 もどる道：' + esc(g.name.replace(/（.*?）/g, '')) + ' → ' + esc(route) + '</div>' : '')
      + '阪神マンと いっしょに「どこで つまずいてるか」を 5分くらいで しらべよか？</div></div>'
      + '<div class="sk-ch"><button type="button" class="sk-btn main" id="skbGo">🔍 たしかめる</button><button type="button" class="sk-btn" id="skbNo">💪 このまま がんばる</button></div></div>';
    document.body.appendChild(root);
    document.getElementById('skbGo').onclick = function () { close(); try { H.open(mode, { src: 'auto' }); } catch (e) {} };
    document.getElementById('skbNo').onclick = function () {
      var b = root.querySelector('.sk-b'); if (b) b.textContent = 'ええで！ 1問ずつ ゆっくりな。こまったら 修行の 画面の 🔍 理解度チェック から いつでも たしかめられるで！';
      var ch = root.querySelector('.sk-ch'); if (ch) ch.style.display = 'none';
      setTimeout(close, 3500);
    };
  }
  function close() { var r = document.getElementById('skbPop'); if (r && r.parentNode) r.parentNode.removeChild(r); }

  setInterval(function () { try { poll(); } catch (e) {} }, 600);
  window.SAKANOBORI = { _poll: poll, _offer: offer, _seq: seq };
})();
