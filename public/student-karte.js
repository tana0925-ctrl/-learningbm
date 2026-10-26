/* 📒 わたしのカルテ（子ども向け）— 2026-09
 *
 *  ・先生が「公開」したときだけ画面に出る。公開していなければ何も出ない。
 *  ・サーバー側は自分の分しか返さない（ほかの子の user_id を渡すと 403）。
 *  ・テストの点数・得点率・順位・ほかの子との比較は一切出さない。
 *  ・数字は「今週 5日のうち○日」のような実数だけ。パーセントは使わない。
 *  ・文章は「その子自身が書いたことば」と「阪神マンのひとこと」だけ。
 *    阪神マンのひとことは、先生が読んで「公開」を押したものだけが出る（KARTE_HANSHIN_V1）。
 */
(function () {
  'use strict';

  var DOW = ['月', '火', '水', '木', '金'];

  function esc(s) {
    return String(s == null ? '' : s)
      .split('&').join('&amp;')
      .split('<').join('&lt;')
      .split('>').join('&gt;');
  }

  // MICHI_V1 阪神マンの文を ▼ の見出しで分ける
  function splitMsg(text) {
    var out = { main: '', ask: '', tries: [], hint: '', test: '' };
    var lines = String(text || '').replace(/\r/g, '').split('\n');
    var cur = 'main', main = [];
    for (var i = 0; i < lines.length; i++) {
      var t = lines[i].replace(/^[\s\u3000*#>＃＊]+/, '').replace(/[\s\u3000*＊]+$/, '');
      var m = t.match(/^▼[\s\u3000]*(.*)$/);
      if (m) { cur = /考えて/.test(m[1]) ? 'ask' : /やってみる/.test(m[1]) ? 'try' : /出し方|提出/.test(m[1]) ? 'hint' : /テスト/.test(m[1]) ? 'test' : 'skip'; continue; }   /* TEISHUTSU_V1 ▼出し方のヒント・▼テストに向けて */
      if (cur === 'main') main.push(lines[i]);
      else if (cur === 'ask' && t && !out.ask) out.ask = t;
      else if ((cur === 'hint' || cur === 'test') && t && !out[cur]) out[cur] = t.replace(/^[・\-–—•●]+[\s\u3000]*/, '');
      else if (cur === 'try' && t) { var x = t.replace(/^([・\-–—•●○◯□☐]|[0-9０-９]+[.．)）])[\s\u3000]*/, ''); if (x) out.tries.push(x); }
    }
    out.main = main.join('\n').replace(/^\s+|\s+$/g, '');
    return out;
  }

  // ══════ HANSHIN_Q_V1 🐯 阪神マンからのしつもん（答えると しつもん1つにつき1回だけ コイン）══════
  //  ・しつもんは、先生が公開したカルテの「考えてほしいこと」。サーバーが決める。
  //  ・コインはサーバーが台帳を見て足す。ここ（画面）は結果を表示に反映するだけ。
  var _hq = null, _hqBusy = false;
  function ensureQCard() {
    var el = document.getElementById('hanshinQCard');
    if (el) return el;
    var host = document.getElementById('homeReviewSuggest');
    if (!host || !host.parentNode) return null;
    el = document.createElement('div');
    el.id = 'hanshinQCard';
    el.style.display = 'none';
    el.style.marginBottom = '10px';
    host.parentNode.insertBefore(el, host);
    return el;
  }
  function renderQ(d) {
    var el = ensureQCard();
    if (!el) return;
    if (!d || !d.ok || !d.question) { el.style.display = 'none'; return; }
    _hq = d;
    var face = '🐯';
    try { if (typeof window.monSpriteHtml === 'function') face = window.monSpriteHtml(154, '🐯'); } catch (e) {}
    var h = '<div class="rounded-xl border-2 border-amber-300 bg-amber-50 p-3">'
      + '<div class="text-sm font-bold text-amber-800" style="display:flex;align-items:center;gap:6px"><span style="font-size:26px;line-height:1">' + face + '</span><span>阪神マンからの しつもん</span></div>'
      + '<div class="mt-1 text-base font-bold text-gray-800">' + esc(d.question.text) + '</div>'
      + '<textarea id="hanshinQAns" rows="3" maxlength="400" class="mt-2 w-full rounded-lg border border-amber-300 p-2 text-sm" placeholder="思ったことを 書いてみよう（' + (d.minChars || 5) + '文字いじょう）">' + esc(d.answer || '') + '</textarea>'
      + '<div style="display:flex;align-items:center;gap:8px;margin-top:6px;flex-wrap:wrap">'
      + '<button type="button" id="hanshinQBtn" class="rounded-lg bg-amber-500 px-4 py-2 text-sm font-bold text-white">' + (d.answer ? '書きなおす' : 'こたえる') + '</button>'
      + '<span id="hanshinQMsg" class="text-xs text-amber-800">' + (d.rewarded ? '🪙 ' + (d.reward || 30) + 'コイン もらったよ。書きなおしても いいよ' : 'はじめて こたえると 🪙 ' + (d.reward || 30) + 'コイン') + '</span>'
      + '</div></div>';
    el.innerHTML = h;
    el.style.display = '';
    var btn = document.getElementById('hanshinQBtn');
    if (btn) btn.onclick = sendQ;
  }
  function sendQ() {
    if (_hqBusy || !_hq || !_hq.question) return;
    var ta = document.getElementById('hanshinQAns'), msg = document.getElementById('hanshinQMsg');
    var ans = ta ? String(ta.value || '').trim() : '';
    if (!ans) { if (msg) msg.textContent = 'なにか 書いてから おしてね'; return; }
    _hqBusy = true;
    if (msg) msg.textContent = 'おくっています…';
    fetch('/api/student/hanshin-answer', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ questionId: _hq.question.id, answer: ans }) })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        _hqBusy = false;
        if (!j || !j.ok) { if (msg) msg.textContent = 'おくれなかったよ。もう一度 おしてみてね'; return; }
        _hq.answer = ans; _hq.rewarded = !!j.rewarded;
        if (j.rewardedNow) {
          // サーバーが足した分を、この端末の表示にも同じだけ足す（台帳も同じだけ進める＝二重にならない）
          try {
            if (typeof player !== 'undefined' && player) {
              player.coins = (Number(player.coins) || 0) + Number(j.reward || 0);
              player._hanshinCoinsApplied = (Number(player._hanshinCoinsApplied) || 0) + Number(j.reward || 0);
              if (typeof updatePlayerDisplay === 'function') updatePlayerDisplay();
            }
          } catch (e) {}
          if (msg) msg.textContent = '🪙 ' + j.reward + 'コイン ゲット！ ありがとう。阪神マンが 読むで';
        } else if (j.tooShort) {
          if (msg) msg.textContent = 'おくったよ。' + (_hq.minChars || 5) + '文字いじょう 書くと コインが もらえるよ';
        } else {
          if (msg) msg.textContent = 'おくったよ。阪神マンが 読むで';
        }
        var b = document.getElementById('hanshinQBtn'); if (b) b.textContent = '書きなおす';
      })
      .catch(function () { _hqBusy = false; if (msg) msg.textContent = 'おくれなかったよ。もう一度 おしてみてね'; });
  }
  function loadQ() {
    try {
      fetch('/api/student/hanshin-question', { credentials: 'include' })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          // 書いている途中なら描き直さない
          var ta = document.getElementById('hanshinQAns');
          if (ta && document.activeElement === ta) return;
          renderQ(d);
        })
        .catch(function () {});
    } catch (e) {}
  }

  // ══════ MICHI_V2 🧭 えらべる3つの道（紙のカルテと同じおすすめ）＋「このおすすめ、どう思う？」══════
  //  ・おすすめは先生が印刷したときにサーバーへ保存されたもの。ここでは表示して、返事を送るだけ。
  //  ・返事は次の週のおすすめに使う（かんたん→1つ先へ／むずかしい→1つ前へ）。コインは付かない。
  var _rc = null;
  var FBL = [['fit', 'ぴったり'], ['easy', 'かんたんすぎ'], ['hard', 'むずかしすぎ'], ['other', 'ちがうのがいい']];
  function ensureRCard() {
    var el = document.getElementById('michiRecoCard');
    if (el) return el;
    var host = document.getElementById('homeReviewSuggest');
    if (!host || !host.parentNode) return null;
    el = document.createElement('div');
    el.id = 'michiRecoCard';
    el.style.display = 'none';
    el.style.marginBottom = '10px';
    host.parentNode.insertBefore(el, host);
    return el;
  }
  function renderR(d) {
    var el = ensureRCard();
    if (!el) return;
    if (!d || !d.ok || !d.reco || !d.reco.a) { el.style.display = 'none'; return; }
    _rc = d;
    var r = d.reco;
    var h = '<div class="rounded-xl border-2 border-orange-300 bg-orange-50 p-3">'
      + '<div class="text-sm font-bold text-orange-800">🧭 えらべる 3つの道 <span class="text-xs font-normal">（どれでも いいよ）</span></div>'
      + '<div class="mt-1 text-sm text-gray-800"><b>🅰 もう一度 かためる</b>：「' + esc(r.a.name) + '」<div class="text-xs text-orange-900">' + esc(r.a.entry || '') + '</div><div class="text-xs text-orange-800">💡' + esc(r.a.why || '') + '</div></div>';
    if (r.b) h += '<div class="mt-1 text-sm text-gray-800"><b>🅱 つぎに すすむ</b>：「' + esc(r.b.name) + '」<div class="text-xs text-orange-900">' + esc(r.b.entry || '') + '</div><div class="text-xs text-orange-800">💡' + esc(r.b.why || '') + '</div></div>';
    /* MAEJIBUN_V1 振り返りに書いた「来週やってみたいこと」を 🅲 に最初から入れる（紙にのせたもの → なければ その後に書いたもの） */
    var cw = cOf(d);
    if (cw) h += '<div class="mt-1 text-sm text-gray-800"><b>🅲 じぶんで 決める</b>：' + esc(cw.say) + '<div class="text-xs text-orange-800">💬 ' + esc(cw.from) + '（かえても いいよ）</div></div>';
    else h += '<div class="mt-1 text-sm text-gray-800"><b>🅲 じぶんで 決める</b>：やりたい ところから でも OK</div>';
    /* KANTAN_REF_V1 👣 はじめの一歩（紙と同じ。きっかけが ほしそうな子は とくに小さく。見た目は同じ） */
    h += '<div class="mt-1 text-xs text-orange-900">👣 <b>はじめの一歩</b>：' + (d.small ? 'アプリを ひらいて「' + esc(r.a.name) + '」を 1問だけ（5分で おわる 大きさ）。1問 といたら、それで 前進やで' : 'まずは いちばん かんたんな 1問だけ（5分で できる 大きさ）') + '</div>';
    h += '<div class="mt-2 text-xs font-bold text-orange-800">このおすすめ、どう思う？</div><div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:4px">';
    for (var i = 0; i < FBL.length; i++) {
      var on = d.feedback === FBL[i][0];
      h += '<button type="button" data-fb="' + FBL[i][0] + '" class="michiFbBtn rounded-full px-3 py-1 text-xs font-bold ' + (on ? 'bg-orange-500 text-white' : 'bg-white text-orange-700 border border-orange-300') + '">' + FBL[i][1] + '</button>';
    }
    h += '</div><div id="michiFbMsg" class="text-xs text-orange-800 mt-1">' + (d.feedback ? 'おくったよ。つぎの おすすめに いかすね（かえても いいよ）' : '') + '</div></div>';
    el.innerHTML = h;
    el.style.display = '';
    var bs = el.querySelectorAll('.michiFbBtn');
    for (var j = 0; j < bs.length; j++) bs[j].onclick = function () { sendFb(this.getAttribute('data-fb')); };
  }
  // MAEJIBUN_V1 🅲 のことば。reco.c（印刷のときに紙にのせたもの）を先に。なければ紙より前の週に書いた nextTry。
  function cOf(d) {
    var r = d && d.reco, c = r && r.c;
    if (c && c.say) return c;
    var nt = d && d.nextTry;
    if (!nt || (!nt.text && !nt.unit)) return null;
    if (d.weekKey && nt.weekKey && String(nt.weekKey) > String(d.weekKey)) return null;   // 紙より後の週のぶんは、次の紙で
    var say = (nt.unitName ? '「' + nt.unitName + '」' : '') + (nt.text ? (nt.unitName ? ' ' : '') + nt.text : '');
    var q = nt.text || nt.unitName || '';
    return { say: say, from: (d.weekKey && nt.weekKey === d.weekKey ? 'ふりかえりで' : '先週の') + ' あなたが『' + q + '』と 書いていたよ' };
  }
  function sendFb(choice) {
    var msg = document.getElementById('michiFbMsg');
    if (msg) msg.textContent = 'おくっています…';
    fetch('/api/student/karte-reco-feedback', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ choice: choice }) })
      .then(function (r) { return r.json(); })
      .then(function (j) { if (j && j.ok && _rc) { _rc.feedback = choice; renderR(_rc); } else if (msg) msg.textContent = 'おくれなかったよ。もう一度 おしてみてね'; })
      .catch(function () { if (msg) msg.textContent = 'おくれなかったよ。もう一度 おしてみてね'; });
  }
  function loadR() {
    try {
      fetch('/api/student/karte-reco', { credentials: 'include' })
        .then(function (r) { return r.json(); })
        .then(function (d) { renderR(d); })
        .catch(function () {});
    } catch (e) {}
  }

  function ensureCard() {
    var el = document.getElementById('myKarteCard');
    if (el) return el;
    var host = document.getElementById('homeReviewSuggest');
    if (!host || !host.parentNode) return null;
    el = document.createElement('div');
    el.id = 'myKarteCard';
    el.style.display = 'none';
    host.parentNode.insertBefore(el, host);
    return el;
  }

  function hide() {
    var el = document.getElementById('myKarteCard');
    if (el) el.style.display = 'none';
  }

  function render(d) {
    if (!d || !d.ok || !d.published) { hide(); return; }
    var el = ensureCard();
    if (!el) return;

    var w = d.week || {};
    var days = w.days || [];
    var cells = '';
    for (var i = 0; i < 5; i++) {
      var s = days[i];
      var mark = '・';
      if (s) {
        mark = (s.weather === 'sun') ? '☀️'
             : (s.weather === 'cloud') ? '☁️'
             : (s.weather === 'rain') ? '🌧️' : '⭕';
      }
      cells += '<div style="text-align:center;flex:1;min-width:38px">'
             + '<div style="font-size:11px;color:#64748b;font-weight:700">' + DOW[i] + '</div>'
             + '<div style="font-size:22px;line-height:1.2">' + mark + '</div></div>';
    }

    var h = '';
    h += '<div class="font-bold text-amber-700">📒 わたしのカルテ</div>';
    h += '<div class="mt-2 rounded-xl border-2 border-amber-200 bg-amber-50 p-3">';
    h += '<div style="display:flex;gap:6px;align-items:flex-end">' + cells + '</div>';
    h += '<div class="mt-2 text-sm font-bold text-amber-800">今週は 5日のうち ' + (w.done || 0) + '日 とりくめたよ'
       + ((w.minutes) ? '（ぜんぶで ' + w.minutes + '分）' : '') + '</div>';

    /* KANTAN_REF_V1 🌟 できたこと（記録の事実から。空にしない） */
    var kt = d.kantan || {};
    var dk = [];
    /* TEISHUTSU_V1 今週の家庭学習：〇日（月〜日・週の振り返りの📊今週の記録と同じ数）。しめきり前に出せた提出物は あったときだけ。未提出の数は出さない。 */
    var ts = d.teishutsu || null;
    if (ts && Number(ts.hwDays) > 0) dk.push('今週の家庭学習：' + Number(ts.hwDays) + '日');
    else if (!ts && w.done > 0) dk.push('今週は 家庭学習を ' + w.done + '日 出せたよ');
    if (ts && Number(ts.onTime) > 0) dk.push('しめきり前に出せた提出物：' + Number(ts.onTime) + 'つ');
    if (Number(kt.hwDays14) > 0 && Number(kt.hwDays14) > Number(w.done || 0)) dk.push('この2週間で 家庭学習を ' + kt.hwDays14 + '日 出したよ');
    dk.push('この2週間で アプリを ' + Math.max(1, Number(kt.openDays) || 1) + '日 ひらいたよ');
    h += '<div class="mt-2"><div class="text-xs font-bold text-amber-700">🌟 できたこと</div><ul class="text-sm text-gray-700 list-disc pl-5">';
    for (var di = 0; di < dk.length && di < 3; di++) h += '<li>' + esc(dk[di]) + '</li>';
    h += '</ul></div>';

    if (w.voices && w.voices.length) {
      h += '<div class="mt-2"><div class="text-xs font-bold text-amber-700">🗣 じぶんのことば</div>';
      h += '<ul class="text-sm text-gray-700 list-disc pl-5">';
      for (var v = 0; v < w.voices.length; v++) h += '<li>' + esc(w.voices[v]) + '</li>';
      h += '</ul></div>';
    }

    var r = d.reflection;
    if (r && (r.goodPoint || r.improvePoint || r.nextAction)) {
      h += '<div class="mt-2 text-sm text-gray-700"><div class="text-xs font-bold text-amber-700">📝 今週のふりかえり</div>';
      if (r.goodPoint) h += '<div>よかったこと … ' + esc(r.goodPoint) + '</div>';
      if (r.improvePoint) h += '<div>もうすこしなこと … ' + esc(r.improvePoint) + '</div>';
      if (r.nextAction) h += '<div>つぎにやること … ' + esc(r.nextAction) + '</div>';
      h += '</div>';
    }

    if (d.teacherMessage) {
      /* KARTE_HANSHIN_V1 (2026-10-05)
         ここに出る文章は阪神マン（関西弁の応援キャラ）が本人あてに書いたもの。
         先生が読んで「公開」を押したものだけが届く。
         紙のカルテの見出し「🐯 阪神マンからのアドバイス」と言い方をそろえた。
         顔は図鑑の絵（ID:154 阪神マン）。絵が無い・読めないときは 🐯 にもどる。 */
      var face = '🐯';
      try {
        if (typeof window.monSpriteHtml === 'function') face = window.monSpriteHtml(154, '🐯');
      } catch (e) {}
      /* MICHI_V1 ▼の見出しで分けて出す（おうちの人へ は子どもの画面には出さない） */
      var sp = splitMsg(d.teacherMessage);
      h += '<div class="mt-3 rounded-xl bg-white border border-amber-200 p-3">'
         + '<div class="text-xs font-bold text-amber-700" style="display:flex;align-items:center;gap:5px">'
         + '<span style="font-size:24px;line-height:1">' + face + '</span><span>阪神マンから</span></div>'
         + '<div class="text-sm text-gray-800" style="white-space:pre-wrap">' + esc(sp.main) + '</div>';
      if (sp.tries.length) {
        h += '<div class="mt-2 text-xs font-bold text-rose-700">✏️ これやってみる？（1つ えらんでみよう）</div><ul class="text-sm text-gray-800 list-disc pl-5">';
        for (var ti = 0; ti < sp.tries.length; ti++) h += '<li>' + esc(sp.tries[ti]) + '</li>';
        h += '</ul>';
      }
      /* TEISHUTSU_V1 先生が確認して公開した「▼出し方のヒント」「▼テストに向けて」（各1行） */
      if (sp.hint) h += '<div class="mt-2 text-sm text-gray-800"><span class="text-xs font-bold text-sky-700">📮 出し方のヒント</span><br>' + esc(sp.hint) + '</div>';
      if (sp.test) h += '<div class="mt-1 text-sm text-gray-800"><span class="text-xs font-bold text-emerald-700">📝 テストに向けて</span><br>' + esc(sp.test) + '</div>';
      h += '</div>';
    }

    /* KARTE_HANSHIN_V2 (2026-10-05) 注記（※〜）は出さない（先生の指示）。
       見出しの「阪神マンから」と虎の絵はそのまま。 */
    h += '</div>';

    el.innerHTML = h;
    el.style.display = '';
  }

  var _busy = false;
  var _lastAt = 0;
  function load(force) {
    if (_busy) return;
    // ステータス画面は何度も描き直されるので、60秒に1回までにしておく
    if (!force && _lastAt && (Date.now() - _lastAt) < 60000) return;
    _busy = true;
    _lastAt = Date.now();
    try {
      fetch('/api/student/my-karte', { credentials: 'include' })
        .then(function (res) { return res.json(); })
        .then(function (d) { _busy = false; render(d); })
        .then(function () { loadQ(); })   // HANSHIN_Q_V1
        .then(function () { loadR(); })   // MICHI_V2
        .catch(function () { _busy = false; hide(); });
    } catch (e) { _busy = false; }
  }

  // ステータス画面が描かれるタイミングに相乗りする（⚡ミニ復習と同じ瞬間）
  function hook() {
    try {
      if (typeof window.loadMiniReview === 'function' && !window.loadMiniReview.__karteHooked) {
        var orig = window.loadMiniReview;
        var wrapped = function () {
          try { orig.apply(this, arguments); } catch (e) {}
          try { load(); } catch (e) {}
        };
        wrapped.__karteHooked = true;
        window.loadMiniReview = wrapped;
        return true;
      }
    } catch (e) {}
    return false;
  }

  var tries = 0, didFirst = false;
  var timer = setInterval(function () {
    tries++;
    var hooked = hook();
    if (!didFirst && document.getElementById('homeReviewSuggest')) { didFirst = true; load(true); }
    if ((hooked && didFirst) || tries > 30) clearInterval(timer);
  }, 1000);

  try { window.loadMyKarte = load; } catch (e) {}
})();
