/* 🔁 HW_REDO_V1 差し戻された 家庭学習の やり直し（子ども） — 2026-11-13
 *  ・家庭学習の 画面の 上に「↩ ◯/◯の 家庭学習を やり直す」カードを 出す（差し戻しが あるときだけ）。
 *  ・やり直しの 画面：先生の コメント → タイマー（5分いじょう）→ やったこと・ふりかえり・つぎ → 出す。
 *  ・学校の 時間は できない（サーバでも とめる）。1回だけ。出すと 先生の「未返却」に もどる。
 */
(function () {
  'use strict';
  if (window.__HW_REDO_V1__) return; window.__HW_REDO_V1__ = 1;
  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function md(dk) { var p = String(dk || '').split('-'); return p.length === 3 ? (Number(p[1]) + '/' + Number(p[2])) : dk; }
  function school() { var d = new Date(Date.now() + 9 * 3600000), wd = d.getUTCDay(), m = d.getUTCHours() * 60 + d.getUTCMinutes(); return wd >= 1 && wd <= 5 && m >= 510 && m < (wd === 2 || wd === 5 ? 915 : 850); }   // SCHOOL_END_V1
  function face() { var f = '🐯'; try { if (typeof window.monSpriteHtml === 'function') f = window.monSpriteHtml(154, '🐯'); } catch (e) {} return f; }
  var ITEMS = [], R = null, T = null;   // R: いま やり直している もの、T: タイマー
  var MIN_MS = 5 * 60000;

  function load() {
    return fetch('/api/homework/rejected-mine', { credentials: 'include' }).then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) { ITEMS = (d && d.items) || []; if (d && d.missed && d.missed.dayKey) ITEMS.push({ late: true, id: 'late:' + d.missed.dayKey, dayKey: d.missed.dayKey }); card(); }).catch(function () {});   // HW_LATE_V1 出しわすれ
  }
  function card() {
    var c = $('hsRedoCard');
    if (!ITEMS.length) { if (c) c.remove(); return; }
    var anchor = $('hsTodayInfo'); if (!anchor || !anchor.parentNode) return;
    if (!c) {
      c = document.createElement('button'); c.id = 'hsRedoCard'; c.type = 'button';
      c.setAttribute('style', 'display:flex;align-items:center;gap:10px;width:100%;margin:8px 0;padding:12px 14px;border-radius:14px;border:3px solid #f87171;background:linear-gradient(135deg,#fff1f2,#fff7ed);text-align:left;cursor:pointer');
      c.onclick = function () { open(ITEMS[0]); };
      anchor.parentNode.insertBefore(c, anchor);
    }
    var it = ITEMS[0];
    if (it.late) {   // 📮 HW_LATE_V1
      c.style.borderColor = '#818cf8'; c.style.background = 'linear-gradient(135deg,#eef2ff,#f5f3ff)';
      c.innerHTML = '<span style="font-size:28px">📮</span><span style="flex:1"><span style="display:block;font-weight:900;color:#3730a3;font-size:16px">' + esc(md(it.dayKey)) + ' の 家庭学習、出しわすれてない？</span>'
        + '<span style="display:block;font-size:12.5px;color:#312e81">おうちで いまから やって 出せるよ（きょうの 分とは べつ・1回だけ）。先生が 返してくれたら 先生PJの 練習試合も ひらく。</span></span>'
        + '<span style="background:#6366f1;color:#fff;border-radius:12px;padding:8px 12px;font-weight:900">出す</span>';
      return;
    }
    c.style.borderColor = '#f87171'; c.style.background = 'linear-gradient(135deg,#fff1f2,#fff7ed)';
    c.innerHTML = '<span style="font-size:28px">↩</span><span style="flex:1"><span style="display:block;font-weight:900;color:#b91c1c;font-size:16px">' + esc(md(it.dayKey)) + ' の 家庭学習が 差し戻されたよ</span>'
      + '<span style="display:block;font-size:12.5px;color:#7c2d12">おうちで やり直すと、先生が 見て 返してくれるよ（先生PJの 練習試合も ひらく）。1週間いない・1回だけ。</span></span>'
      + '<span style="background:#ef4444;color:#fff;border-radius:12px;padding:8px 12px;font-weight:900">やり直す</span>';
  }

  var CSS = '#hsRedo{position:fixed;inset:0;z-index:9992;background:rgba(15,23,42,.45);display:flex;justify-content:center;align-items:stretch}'
    + '#hsRedo .rb{width:100%;max-width:780px;background:#fef9f0;display:flex;flex-direction:column;height:100%;box-shadow:0 0 30px rgba(0,0,0,.25)}'
    + '#hsRedo .rh{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#fca5a5;color:#1f2937;font-weight:900;font-size:18px}'
    + '#hsRedo .rx{margin-left:auto;background:#fff;border:2px solid #b91c1c;border-radius:12px;padding:8px 14px;font-size:15px;font-weight:800;color:#7f1d1d;min-height:44px;cursor:pointer}'
    + '#hsRedo .rc{flex:1;overflow-y:auto;padding:14px}'
    + '#hsRedo .face{width:44px;height:44px;flex:0 0 44px;display:flex;align-items:center;justify-content:center;font-size:30px;background:#fff;border-radius:50%;border:2px solid #fde68a;overflow:hidden}'
    + '#hsRedo .face img{max-width:40px;max-height:40px}'
    + '#hsRedo .say{flex:1;background:#fff;border:2px solid #fde68a;border-radius:18px;border-top-left-radius:6px;padding:10px 14px;font-size:16px;line-height:1.6;white-space:pre-wrap}'
    + '#hsRedo label{display:block;font-weight:900;color:#78350f;margin:12px 0 4px;font-size:15px}'
    + '#hsRedo textarea{width:100%;min-height:76px;border:2px solid #fcd34d;border-radius:12px;padding:8px 10px;font-size:16px;box-sizing:border-box;background:#fff}'
    + '#hsRedo .tm{display:flex;align-items:center;gap:10px;background:#fff;border:2px solid #93c5fd;border-radius:14px;padding:10px 12px;margin-top:12px}'
    + '#hsRedo .btn{min-height:52px;border-radius:16px;border:2px solid #f59e0b;background:#fff;color:#78350f;font-size:17px;font-weight:900;padding:8px 14px;cursor:pointer}'
    + '#hsRedo .btn.go{background:#f97316;border-color:#c2410c;color:#fff;width:100%;margin-top:14px}'
    + '#hsRedo .btn:disabled{opacity:.45;cursor:not-allowed}'
    + '#hsRedo .old{margin-top:10px;background:#f1f5f9;border-radius:10px;padding:8px 10px;font-size:12.5px;color:#475569;white-space:pre-wrap}';

  function open(it) {
    if (!it) return;
    R = it;
    if (!$('hsRedoCss')) { var st = document.createElement('style'); st.id = 'hsRedoCss'; st.textContent = CSS; document.head.appendChild(st); }
    var o = $('hsRedo'); if (!o) { o = document.createElement('div'); o.id = 'hsRedo'; document.body.appendChild(o); }
    o.style.display = 'flex';
    var sch = school();
    o.innerHTML = '<div class="rb"><div class="rh"' + (it.late ? ' style="background:#c7d2fe"' : '') + '><span>' + (it.late ? '📮 ' + esc(md(it.dayKey)) + ' の 家庭学習を 出す（出しわすれ）' : '↩ ' + esc(md(it.dayKey)) + ' の 家庭学習を やり直す') + '</span><button type="button" class="rx" id="hrX">とじる</button></div><div class="rc">'
      + '<div style="display:flex;gap:8px;align-items:flex-start"><span class="face">' + face() + '</span><div class="say">'
      + (it.late ? '出しわすれに 気づいて えらいで！ いまから やって 出そか。タイマーを スタートして、やったことを「何を・どこまで」、ふりかえりは「自分の ことば」で 書いてな。' : '')
      + (it.comment ? '先生から：' + esc(it.comment) + '\n\n' : '')
      + (it.late ? '' : 'もう一回 チャレンジや！ タイマーを スタートして、やったことを「何を・どこまで」、ふりかえりは「自分の ことば」で 書いてな。') + '</div></div>'
      + (sch ? '<div style="margin-top:12px;background:#fee2e2;border-radius:12px;padding:10px;font-weight:900;color:#991b1b">🏫 いまは 学校の 時間だよ。やり直しは おうちに 帰ってから してね。</div>' : '')
      + '<div class="tm"><span style="font-size:26px">⏱</span><span style="flex:1"><span id="hrTime" style="display:block;font-size:22px;font-weight:900;color:#1e3a8a">0分00秒</span><span style="font-size:12px;color:#475569">5分いじょう はかると 出せるよ</span></span><button type="button" class="btn" id="hrStart"' + (sch ? ' disabled' : '') + '>▶ スタート</button></div>'
      + '<label>📝 やったこと（何を・どこまで）</label><textarea id="hrTodo" placeholder="れい：算数ドリル 12〜13ページ、まちがえた 3問を やり直した"></textarea>'
      + '<label>💭 ふりかえり（わかったこと・むずかしかったこと）</label><textarea id="hrRef" placeholder="れい：分数の わり算は ひっくり返して かけると わかった。帯分数を 直すのを わすれた"></textarea>'
      + '<label>➡ つぎは どうする？</label><textarea id="hrNext" style="min-height:56px" placeholder="れい：帯分数を 先に 仮分数に してから とく"></textarea>'
      + '<button type="button" class="btn go" id="hrGo" disabled>📮 出す</button><div id="hrMsg" style="margin-top:8px;font-weight:800;color:#b91c1c;font-size:14px"></div>'
      + (it.late ? '' : '<div class="old"><b>前に 出した 中身</b>\nやったこと：' + esc(it.todo || '（なし）') + '\nふりかえり：' + esc(it.reflect || '（なし）') + '</div>')
      + '</div></div>';
    $('hrX').onclick = closeIt;
    $('hrStart').onclick = start;
    ['hrTodo', 'hrRef', 'hrNext'].forEach(function (id) { $(id).addEventListener('input', check); });
    $('hrGo').onclick = send;
    if (T && T.id === it.id) tick();
  }
  function closeIt() { var o = $('hsRedo'); if (o) o.style.display = 'none'; }
  function start() {
    if (school()) { msg('🏫 いまは 学校の 時間だよ。おうちに 帰ってから してね。'); return; }
    if (!T || T.id !== R.id) T = { id: R.id, at: Date.now() };
    var b = $('hrStart'); if (b) { b.disabled = true; b.textContent = 'はかっています'; }
    tick();
  }
  function elapsed() { return T && R && T.id === R.id ? Date.now() - T.at : 0; }
  function tick() {
    var el = elapsed(), t = $('hrTime');
    if (t) { var s = Math.floor(el / 1000); t.textContent = Math.floor(s / 60) + '分' + ('0' + (s % 60)).slice(-2) + '秒'; }
    var b = $('hrStart'); if (b && T && R && T.id === R.id) { b.disabled = true; b.textContent = 'はかっています'; }
    check();
    if ($('hsRedo') && $('hsRedo').style.display !== 'none' && T) setTimeout(tick, 1000);
  }
  function len(id) { var e = $(id); return e ? Array.from(String(e.value || '').trim()).length : 0; }
  function check() {
    var g = $('hrGo'); if (!g) return;
    var okT = elapsed() >= MIN_MS, okW = len('hrTodo') >= 8 && len('hrRef') >= 8;
    g.disabled = !(okT && okW);
    g.textContent = !okT ? '📮 出す（あと ' + Math.max(0, Math.ceil((MIN_MS - elapsed()) / 60000)) + '分）' : (!okW ? '📮 やったこと・ふりかえりを 書いてね' : '📮 出す');
  }
  function msg(t) { var m = $('hrMsg'); if (m) m.textContent = t; }
  function send() {
    var g = $('hrGo'); if (g) g.disabled = true; msg('');
    fetch(R.late ? '/api/homework/late' : '/api/homework/redo', { method: 'POST', credentials: 'include', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ id: R.id, dayKey: R.dayKey, todo: $('hrTodo').value, reflect: $('hrRef').value, next: $('hrNext').value, elapsedMs: elapsed() }) })
      .then(function (r) { return r.json().catch(function () { return null; }); })
      .then(function (j) {
        if (j && j.ok) {
          var c = document.querySelector('#hsRedo .rc');
          if (c) c.innerHTML = '<div style="display:flex;gap:8px;align-items:flex-start"><span class="face">' + face() + '</span><div class="say">' + (R.late ? 'よっしゃ！ 出しわすれの 分、ちゃんと 出せたで！ 👏' : 'よっしゃ！ やり直し、ちゃんと 出せたで！ 👏') + '\n先生が 見て 返してくれたら、先生PJの 練習試合も できるように なるで。</div></div><button type="button" class="btn go" id="hrDone">とじる</button>';
          var d = $('hrDone'); if (d) d.onclick = closeIt;
          T = null; ITEMS = ITEMS.filter(function (x) { return x.id !== R.id; }); card();
          return;
        }
        var e = (j && j.error) || '';
        msg(e === 'school_time' ? '🏫 いまは 学校の 時間だよ。おうちで してね。' : e === 'too_short' ? '⏱ タイマーで 5分いじょう はかってね。' : e === 'too_vague' ? '📝 やったこと・ふりかえりを もう少し くわしく 書いてね。' : e === 'not_rejected' ? 'もう やり直しは 出してあるよ。' : e === 'not_missed' ? 'この 日の 分は もう 出してあるよ。' : '出せませんでした。もう一回 おしてね。');
        if (g) g.disabled = false;
      }).catch(function () { msg('出せませんでした。もう一回 おしてね。'); if (g) g.disabled = false; });
  }

  setTimeout(load, 3000);
  setInterval(function () { try { if (ITEMS.length) card(); } catch (e) {} }, 2500);
  setInterval(load, 15 * 60000);
  window.HW_REDO = { open: open, load: load };
})();
