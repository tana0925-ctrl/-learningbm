/* 🐯 HSADVICE_CHAT_V1 阪神マンのアドバイス（修行の画面）を 対話の 形に — 2026-11-12
 *  ・これまで：質問 → えらぶ → 答えに 画面が おきかわる（前の やりとりが 消える）。
 *  ・これから：阪神マンと 子どもの ふきだしが 下に つみかさなる。えらんだ ことばも 子どもの ふきだしで のこる。
 *    答えの あとに「わかった！」「ほかのことも 聞く」（算数の 単元なら「🔍 理解度チェック」も）を 出す。
 *  ・中身（HANSHIN_ADVICE_TREE）は そのまま つかう。言い方は 日ごとに すこし かわる。
 *  ・HSADVICE_CHAT_V2（2026-11-13 先生の指示）見た目を 家庭学習の 阪神マン（hschat）と おなじ 画面に：
 *    上に 黄色い 見出し＋とじる、まんなかに 顔つきの ふきだし、下に 大きい えらぶボタン（2れつ）。
 *  ・index.html は 手で 編集しない（window.HanshinManSystem の render などを おきかえる）。
 */
(function () {
  'use strict';
  if (window.__HSADVICE_CHAT_V1__) return; window.__HSADVICE_CHAT_V1__ = 1;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function dayN() { return Math.floor((Date.now() + 9 * 3600000) / 86400000); }
  function vary(list, key) { var h = 0, k = String(key || ''); for (var i = 0; i < k.length; i++) h = (h + k.charCodeAt(i)) % 9973; return list[(dayN() + h) % list.length]; }
  var HELLO = ['おう、どないした？', 'よう来たな！ なんでも 聞いてや', 'お、相談か？ まかしとき！', 'ええとこに 来たな！'];
  var MORE = ['ほかに 気になること ある？', 'ほな、ほかに 何が 聞きたい？', 'まだ ありそうやな。どれや？'];
  var GOT = ['よっしゃ！ その調子で 修行 がんばってな！', 'ええぞ！ わかったら あとは 練習あるのみや！', 'さすがや！ また こまったら いつでも 呼んでな！'];
  var CHECK = ['よし、ほな 理解度チェックで たしかめてみよか！'];

  function patch() {
    var H = window.HanshinManSystem;
    if (!H || typeof H.render !== 'function') return false;
    if (H.__chatV1) return true;
    H.__chatV1 = 1;
    var log = [], open = false, pendingMe = '', skipLog = false;
    var origClose = H.close;

    var root = null, rootKey = '';
    function mode() {   // いまの 修行の 単元（ひらいた ときの 木の 根っこから さがす）
      if (rootKey) return rootKey;
      try { var T = window.HANSHIN_ADVICE_TREE || {}; for (var k in T) if (T[k] === root) { rootKey = k; break; } } catch (e) {}
      return rootKey;
    }
    function rootNode() { return root; }
    function canCheck() { try { return !!(window.HSCHECK && window.HSCHECK.UNIT2GOAL && window.HSCHECK.UNIT2GOAL[mode()]); } catch (e) { return false; } }

    // ── HSADVICE_CHAT_V2 hschat と おなじ 見た目の 画面 ──
    var CSS = '#hsAdv{position:fixed;top:0;right:0;bottom:0;left:0;z-index:9991;background:rgba(15,23,42,.45);display:flex;justify-content:center;align-items:stretch;font-family:inherit}'
      + '#hsAdv .hc-box{width:100%;max-width:780px;background:#fef9f0;display:flex;flex-direction:column;height:100%;box-shadow:0 0 30px rgba(0,0,0,.25)}'
      + '#hsAdv .hc-head{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#facc15;color:#1f2937;font-weight:900;font-size:18px}'
      + '#hsAdv .hc-x{margin-left:auto;background:#fff;border:2px solid #a16207;border-radius:12px;padding:8px 14px;font-size:15px;font-weight:800;color:#713f12;min-height:44px;cursor:pointer}'
      + '#hsAdv .hc-log{flex:1;overflow-y:auto;padding:14px 14px 6px;-webkit-overflow-scrolling:touch}'
      + '#hsAdv .hc-row{display:flex;gap:8px;margin:8px 0;align-items:flex-end}'
      + '#hsAdv .hc-row.me{justify-content:flex-end}'
      + '#hsAdv .hc-face{width:44px;height:44px;flex:0 0 44px;display:flex;align-items:center;justify-content:center;font-size:30px;background:#fff;border-radius:50%;border:2px solid #fde68a;overflow:hidden}'
      + '#hsAdv .hc-face img{max-width:40px;max-height:40px}'
      + '#hsAdv .hc-b{max-width:74%;padding:10px 14px;border-radius:18px;font-size:17px;line-height:1.55;white-space:pre-wrap;word-break:break-word}'
      + '#hsAdv .bot .hc-b{background:#fff;border:2px solid #fde68a;border-bottom-left-radius:6px;color:#1f2937}'
      + '#hsAdv .me .hc-b{background:#86efac;border-bottom-right-radius:6px;color:#14532d;font-weight:700}'
      + '#hsAdv .hc-foot{border-top:2px solid #fde68a;background:#fffbeb;padding:10px 12px 14px;max-height:46vh;overflow-y:auto}'
      + '#hsAdv .hc-ch{display:grid;grid-template-columns:1fr 1fr;gap:8px}'
      + '#hsAdv .hc-ch + .hc-ch{margin-top:8px}'
      + '#hsAdv .hc-ch.one{grid-template-columns:1fr}'
      + '#hsAdv .hc-btn{min-height:56px;border-radius:16px;border:2px solid #f59e0b;background:#fff;color:#78350f;font-size:17px;font-weight:800;padding:8px 10px;text-align:center;cursor:pointer;touch-action:manipulation}'
      + '#hsAdv .hc-btn:active{transform:scale(.98)}'
      + '#hsAdv .hc-btn.main{background:#f97316;border-color:#c2410c;color:#fff}'
      + '#hsAdv .hc-btn.blue{background:#0ea5e9;border-color:#0369a1;color:#fff}'
      + '#hsAdv .hc-btn.sub{background:#f1f5f9;border-color:#cbd5e1;color:#334155;min-height:48px;font-size:15px}'
      + '@media (max-width:520px){#hsAdv .hc-ch{grid-template-columns:1fr}}';
    function face() { var f = '🐯'; try { if (typeof window.monSpriteHtml === 'function') f = window.monSpriteHtml(154, '🐯'); } catch (e) {} return f; }
    function ui() {
      var root = document.getElementById('hsAdv');
      if (!root) {
        if (!document.getElementById('hsAdvCss')) { var st = document.createElement('style'); st.id = 'hsAdvCss'; st.textContent = CSS; document.head.appendChild(st); }
        root = document.createElement('div'); root.id = 'hsAdv';
        root.innerHTML = '<div class="hc-box"><div class="hc-head"><span class="hc-face">' + face() + '</span><span>阪神マン</span><button type="button" class="hc-x" id="hsAdvX">とじる</button></div>'
          + '<div class="hc-log" id="hsAdvLog"></div><div class="hc-foot" id="hsAdvFoot"></div></div>';
        document.body.appendChild(root);
        root.querySelector('#hsAdvX').onclick = function () { H.close(); };
      }
      root.style.display = 'flex';
      return { root: root, log: root.querySelector('#hsAdvLog'), foot: root.querySelector('#hsAdvFoot') };
    }
    function bubble(x) {
      if (x.w === 'm') return '<div class="hc-row me"><div class="hc-b">' + esc(x.t) + '</div></div>';
      return '<div class="hc-row bot"><span class="hc-face">' + face() + '</span><div class="hc-b">' + esc(x.t) + '</div></div>';
    }
    function btn(label, cls, fn) {
      var b = document.createElement('button'); b.type = 'button';
      b.className = 'hc-btn ' + (cls || '');
      b.textContent = label; b.onclick = fn; return b;
    }
    function row(list) { var d = document.createElement('div'); d.className = 'hc-ch'; list.forEach(function (b) { d.appendChild(b); }); return d; }
    function hideOld() { try { var m = document.getElementById('hanshinManModal'); if (m) { m.classList.add('hidden'); m.classList.remove('flex'); m.style.display = 'none'; } } catch (e) {} }

    H.render = function (node) {
      this.currentNode = node;
      var self = this;
      if (!open || (!this.history.length && !skipLog && !pendingMe)) {
        log = [{ w: 'b', t: vary(HELLO, 'h') }, { w: 'b', t: node.question || '' }];
        open = true; root = node; rootKey = '';
      } else if (!skipLog) {
        if (pendingMe) log.push({ w: 'm', t: pendingMe });
        log.push({ w: 'b', t: node.options ? (node.question || vary(MORE, 'm')) : (node.answer || node.question || '') });
      }
      pendingMe = ''; skipLog = false;
      if (log.length > 60) log = log.slice(-60);
      hideOld();
      var v = ui();
      function draw() { v.log.innerHTML = log.map(bubble).join(''); v.log.scrollTop = v.log.scrollHeight; }
      draw();
      v.foot.innerHTML = '';
      if (node.options) {
        v.foot.appendChild(row(node.options.map(function (opt, i) { return btn(opt.text, '', function () { self.selectOption(i); }); })));
        if (this.history.length > 0) v.foot.appendChild(row([btn('↩️ 前の 質問に もどる', 'sub', function () { self.goBack(); }), btn('❓ さいしょから 聞く', 'sub', function () { self.goFirst(); })]));
      } else {
        var main = [btn('🙆 わかった！', 'main', function () {
          log.push({ w: 'm', t: '🙆 わかった！' }); log.push({ w: 'b', t: vary(GOT, 'g') }); draw();
          v.foot.innerHTML = '';
          v.foot.appendChild(row([btn('❓ ほかのことも 聞く', '', function () { self.goFirst(); }), btn('とじる', 'sub', function () { self.close(); })]));
        })];
        if (canCheck()) main.push(btn('🔍 理解度チェックで たしかめる', 'blue', function () { var m = mode(); self.close(); try { window.HSCHECK.open(m); } catch (e) {} }));
        var mr = row(main); if (main.length === 1) mr.className += ' one'; v.foot.appendChild(mr);
        v.foot.appendChild(row([btn('❓ ほかのことも 聞く', 'sub', function () { self.goFirst(); }), btn('↩️ 前の 質問に もどる', 'sub', function () { self.goBack(); })]));
      }
    };
    H.selectOption = function (i) {
      var sel = this.currentNode && this.currentNode.options && this.currentNode.options[i];
      if (!sel) return;
      this.history.push(this.currentNode);
      if (sel.options || sel.question || sel.answer) { pendingMe = sel.text || ''; this.render(sel); }
      else this.close();
    };
    H.goBack = function () {
      if (!this.history.length) return;
      var prev = this.history.pop();
      log.push({ w: 'm', t: '↩️ 前の 質問に もどる' });
      log.push({ w: 'b', t: prev.question || vary(MORE, 'm') });
      skipLog = true; this.render(prev);
    };
    H.goFirst = function () {
      var r = rootNode(); if (!r) return;
      this.history = [];
      log.push({ w: 'm', t: 'ほかのことも 聞きたい' });
      log.push({ w: 'b', t: vary(MORE, 'm') + '\n' + (r.question || '') });
      skipLog = true; this.render(r);
    };
    H.close = function () { open = false; log = []; root = null; rootKey = ''; pendingMe = ''; skipLog = false; try { var r = document.getElementById('hsAdv'); if (r) r.style.display = 'none'; } catch (e) {} return origClose.apply(this, arguments); };
    return true;
  }
  if (!patch()) { var n = 0, t = setInterval(function () { if (patch() || ++n > 120) clearInterval(t); }, 500); }
})();
