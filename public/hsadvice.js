/* 🐯 HSADVICE_CHAT_V1 阪神マンのアドバイス（修行の画面）を 対話の 形に — 2026-11-12
 *  ・これまで：質問 → えらぶ → 答えに 画面が おきかわる（前の やりとりが 消える）。
 *  ・これから：阪神マンと 子どもの ふきだしが 下に つみかさなる。えらんだ ことばも 子どもの ふきだしで のこる。
 *    答えの あとに「わかった！」「ほかのことも 聞く」（算数の 単元なら「🔍 理解度チェック」も）を 出す。
 *  ・中身（HANSHIN_ADVICE_TREE）は そのまま つかう。言い方は 日ごとに すこし かわる。
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

    function bubble(x) {
      if (x.w === 'm') return '<div style="display:flex;justify-content:flex-end;margin:6px 0"><div style="max-width:82%;background:#86efac;color:#14532d;border-radius:14px 14px 4px 14px;padding:7px 11px;font-weight:800">' + esc(x.t) + '</div></div>';
      return '<div style="display:flex;gap:6px;align-items:flex-end;margin:6px 0"><span style="font-size:22px;line-height:1">🐯</span><div style="max-width:86%;background:#fff;border:2px solid #fde68a;color:#1f2937;border-radius:14px 14px 14px 4px;padding:7px 11px;white-space:pre-wrap">' + esc(x.t) + '</div></div>';
    }
    function btn(label, cls, fn) {
      var b = document.createElement('button');
      b.className = cls || 'w-full text-left bg-white p-3 rounded-lg shadow font-bold hover:bg-yellow-200 transition border border-yellow-300 option-btn';
      b.textContent = label; b.onclick = fn; return b;
    }

    H.render = function (node) {
      this.currentNode = node;
      var modal = document.getElementById('hanshinManModal');
      var content = document.getElementById('hanshinManContent');
      var opts = document.getElementById('hanshinManOptions');
      if (!modal || !content || !opts) return;
      var self = this;
      if (!open || (!this.history.length && !skipLog && !pendingMe)) {
        log = [{ w: 'b', t: vary(HELLO, 'h') + '\n' + (node.question || '') }];
        open = true; root = node; rootKey = '';
      } else if (!skipLog) {
        if (pendingMe) log.push({ w: 'm', t: pendingMe });
        log.push({ w: 'b', t: node.options ? (node.question || vary(MORE, 'm')) : (node.answer || node.question || '') });
      }
      pendingMe = ''; skipLog = false;
      if (log.length > 40) log = log.slice(-40);
      content.style.maxHeight = '46vh'; content.style.overflowY = 'auto'; content.style.background = '#fffbeb';
      content.innerHTML = log.map(bubble).join('');
      content.scrollTop = content.scrollHeight;
      opts.innerHTML = '';
      if (node.options) {
        node.options.forEach(function (opt, i) { opts.appendChild(btn(opt.text, '', function () { self.selectOption(i); })); });
      } else {
        opts.appendChild(btn('🙆 わかった！', 'w-full text-center bg-green-500 text-white p-3 rounded-lg shadow font-black hover:bg-green-600 transition', function () {
          log.push({ w: 'm', t: 'わかった！' }); log.push({ w: 'b', t: vary(GOT, 'g') });
          content.innerHTML = log.map(bubble).join(''); content.scrollTop = content.scrollHeight;
          opts.innerHTML = '';
          opts.appendChild(btn('❓ ほかのことも 聞く', 'w-full text-center bg-yellow-400 p-2 rounded-lg shadow font-bold text-yellow-900 hover:bg-yellow-500 transition text-sm', function () { self.goFirst(); }));
          opts.appendChild(btn('とじる', 'w-full text-center bg-gray-200 p-2 rounded-lg shadow font-bold text-gray-600 hover:bg-gray-300 transition text-sm', function () { self.close(); }));
        }));
        if (canCheck()) opts.appendChild(btn('🔍 ほんまに できるか 理解度チェック', 'w-full text-center bg-sky-500 text-white p-2 rounded-lg shadow font-bold hover:bg-sky-600 transition text-sm', function () {
          var m = mode(); self.close(); try { window.HSCHECK.open(m); } catch (e) {}
        }));
        opts.appendChild(btn('❓ ほかのことも 聞く', 'w-full text-center bg-yellow-400 p-2 rounded-lg shadow font-bold text-yellow-900 hover:bg-yellow-500 transition text-sm', function () { self.goFirst(); }));
      }
      if (this.history.length > 0 && node.options) opts.appendChild(btn('↩️ 前の質問に もどる', 'w-full text-center bg-gray-200 p-2 mt-1 rounded-lg shadow font-bold text-gray-600 hover:bg-gray-300 transition text-sm', function () { self.goBack(); }));
      modal.style.display = 'flex'; modal.classList.remove('hidden');
      setTimeout(function () { modal.classList.add('flex'); }, 10);
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
      log.push({ w: 'm', t: '前の 質問に もどる' });
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
    H.close = function () { open = false; log = []; root = null; rootKey = ''; pendingMe = ''; skipLog = false; return origClose.apply(this, arguments); };
    return true;
  }
  if (!patch()) { var n = 0, t = setInterval(function () { if (patch() || ++n > 120) clearInterval(t); }, 500); }
})();
