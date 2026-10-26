/* VIEWAS_V1 見るだけモード（先生が子どもの画面に入っているときだけ、ページの先頭に差しこまれる）
   ・このスクリプトは子どもには届かない（サーバが viewas Cookie を確かめたときだけ差しこむ）
   ・やること:
       1) localStorage / sessionStorage を、その場かぎりのメモリに差しかえる（先生の端末に何も残さない・端末の古いデータを送らない）
       2) fetch の GET/HEAD 以外・sendBeacon・XMLHttpRequest の書きこみ・フォーム送信を止める（サーバでも止めている＝2重）
       3) 画面の上に「見ています（見るだけ）」の帯と「終わる」ボタン
       4) ときどき（60秒ごと）まだ見ているかを確かめ、終わっていたら先生の画面へ戻す
   ・バックスラッシュとバッククォートは使わない（TS の文字列に埋めこむため） */
(function () {
  'use strict';
  var CFG = window.__VIEWAS__ || {};
  if (window.__VIEWAS_ON__) return;
  window.__VIEWAS_ON__ = true;

  /* 1) その場かぎりのストレージ */
  function memStore() {
    var d = Object.create(null);
    var s = {
      getItem: function (k) { k = String(k); return Object.prototype.hasOwnProperty.call(d, k) ? d[k] : null; },
      setItem: function (k, v) { d[String(k)] = String(v); },
      removeItem: function (k) { delete d[String(k)]; },
      clear: function () { d = Object.create(null); },
      key: function (i) { var ks = Object.keys(d); return i < ks.length ? ks[i] : null; }
    };
    Object.defineProperty(s, 'length', { get: function () { return Object.keys(d).length; } });
    return s;
  }
  var LS = memStore(), SS = memStore();
  try { Object.defineProperty(window, 'localStorage', { configurable: true, enumerable: true, get: function () { return LS; } }); } catch (e) {}
  try { Object.defineProperty(window, 'sessionStorage', { configurable: true, enumerable: true, get: function () { return SS; } }); } catch (e) {}

  /* 2) 書きこみの通信を止める */
  var blocked = 0;
  var realFetch = window.fetch ? window.fetch.bind(window) : null;
  window.__VIEWAS_FETCH__ = realFetch;
  function isWrite(m) { m = String(m || 'GET').toUpperCase(); return !(m === 'GET' || m === 'HEAD'); }
  function fakeOk() {
    return new Response(JSON.stringify({ ok: true, viewOnly: true }), { status: 200, headers: { 'content-type': 'application/json' } });
  }
  function bump() { blocked++; try { var el = document.getElementById('__viewas_cnt'); if (el) el.textContent = '止めた保存 ' + blocked; } catch (e) {} }
  if (realFetch) {
    window.fetch = function (input, init) {
      var m = 'GET';
      try {
        if (init && init.method) m = init.method;
        else if (input && typeof input === 'object' && input.method) m = input.method;
      } catch (e) { m = 'POST'; }
      if (isWrite(m)) { bump(); return Promise.resolve(fakeOk()); }
      return realFetch(input, init);
    };
  }
  try {
    var XO = XMLHttpRequest.prototype.open, XS = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (m) { this.__vaM = m; return XO.apply(this, arguments); };
    XMLHttpRequest.prototype.send = function () { if (isWrite(this.__vaM)) { bump(); return; } return XS.apply(this, arguments); };
  } catch (e) {}
  try { if (navigator.sendBeacon) navigator.sendBeacon = function () { bump(); return true; }; } catch (e) {}
  document.addEventListener('submit', function (e) {
    try { var f = e.target; if (f && isWrite(f.method || 'GET')) { e.preventDefault(); bump(); } } catch (x) {}
  }, true);

  /* 3) 帯 */
  var name = String(CFG.name || '');
  function el(tag, css, text) { var x = document.createElement(tag); if (css) x.style.cssText = css; if (text != null) x.textContent = text; return x; }
  var atBottom = false;
  function place(bar) {
    bar.style.top = atBottom ? 'auto' : '0';
    bar.style.bottom = atBottom ? '0' : 'auto';
    bar.style.borderRadius = atBottom ? '10px 10px 0 0' : '0 0 10px 10px';
  }
  function endNow() {
    var go = function () { location.href = '/teacher'; };
    try {
      if (realFetch) realFetch('/api/teacher/view-as/end', { method: 'POST', credentials: 'include' }).then(go, go);
      else go();
    } catch (e) { go(); }
  }
  function buildBar() {
    if (document.getElementById('__viewas_bar')) return;
    var bar = el('div', 'position:fixed;left:50%;transform:translateX(-50%);z-index:2147483647;display:flex;align-items:center;gap:8px;' +
      'padding:4px 6px 4px 12px;background:rgba(124,58,237,0.94);color:#fff;font:700 13px/1.3 system-ui,sans-serif;' +
      'box-shadow:0 2px 8px rgba(0,0,0,0.3);max-width:96vw;white-space:nowrap;pointer-events:auto;');
    bar.id = '__viewas_bar';
    bar.setAttribute('data-viewas', '1');
    var label = el('span', 'overflow:hidden;text-overflow:ellipsis;', '👀 ' + (name ? name + 'さん' : '子ども') + 'の画面を見ています（見るだけ）');
    var cnt = el('span', 'font-weight:600;font-size:11px;opacity:0.85;', '保存はされません');
    cnt.id = '__viewas_cnt';
    var mv = el('button', 'all:unset;cursor:pointer;padding:2px 6px;border-radius:6px;background:rgba(255,255,255,0.18);font-size:12px;', '↕');
    mv.title = '帯を上／下に動かす';
    mv.onclick = function () { atBottom = !atBottom; place(bar); };
    var end = el('button', 'all:unset;cursor:pointer;padding:4px 12px;border-radius:8px;background:#fff;color:#6d28d9;font-weight:900;font-size:13px;', '終わる');
    end.onclick = endNow;
    bar.appendChild(label); bar.appendChild(cnt); bar.appendChild(mv); bar.appendChild(end);
    place(bar);
    (document.body || document.documentElement).appendChild(bar);
  }
  function overlay(msg) {
    if (document.getElementById('__viewas_over')) return;
    var o = el('div', 'position:fixed;inset:0;z-index:2147483647;background:rgba(15,23,42,0.75);display:flex;align-items:center;justify-content:center;font:700 16px/1.6 system-ui,sans-serif;');
    o.id = '__viewas_over';
    var b = el('div', 'background:#fff;color:#1f2937;border-radius:16px;padding:24px;max-width:420px;text-align:center;');
    b.appendChild(el('div', 'margin-bottom:14px;', msg));
    var btn = el('button', 'all:unset;cursor:pointer;padding:8px 18px;border-radius:10px;background:#6d28d9;color:#fff;font-weight:900;', '先生の画面にもどる');
    btn.onclick = function () { location.href = '/teacher'; };
    b.appendChild(btn); o.appendChild(b);
    (document.body || document.documentElement).appendChild(o);
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', buildBar);
  else buildBar();
  /* 子どもの画面の描きかえで消されたら、もう一度出す */
  setInterval(function () { try { if (document.body && !document.getElementById('__viewas_bar')) buildBar(); } catch (e) {} }, 2000);

  /* 4) まだ見ているか */
  function check() {
    if (CFG.until && Date.now() > Number(CFG.until)) { overlay('見る時間（60分）が終わりました。'); return; }
    if (!realFetch) return;
    realFetch('/api/teacher/view-as/status', { credentials: 'include', cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .then(function (j) { if (!j || !j.active) overlay('子どもの画面を見るのは終わりました。'); })
      .catch(function () {});
  }
  setInterval(check, 60000);
})();
