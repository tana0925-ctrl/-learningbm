/* 💬 HSWEEKCHAT_V1 阪神マンと ふりかえる（週の振り返りを 対話で）— 2026-10-26
 *
 *  ・いまの週の振り返りの画面（👆かんたんふりかえり＋🔄WEEKREF2）は そのまま。入口「💬 阪神マンとふりかえる」を足すだけ。
 *  ・質問の順番と中身は いまの画面と同じ。1問ずつ 吹き出しで、えらぶボタン＋じぶんのことば（入力）。
 *      （みんなのふりかえりの見本 → ）🤝先週決めたこと → 📊今週の記録（阪神マンが紹介）→ ①◎○△ → ②なんで
 *      → ③次どうする（＋ひとこと）→ ④気もち → 🏫学校での学び → 💭考える問い → まとめを見て「これで出す」
 *  ・答えは いまの画面と同じ入れ物に入れて、いまの画面と同じ「出す」をそのまま呼ぶ（kantanref.js の KANTAN.send）。
 *      structured_reflections の項目欄（good_point「◎ よくできた ／ なんで：…」・next_action「次：…」・free_text）
 *      week_ref_taps（◎○△など）・week_ref2（先週決めたこと・学校での学び・問い）・週の計画の金曜の振り返り
 *    → 先生の📋振り返り一覧・AIの下書き・カルテ・前の自分ページは そのまま使える。
 *  ・コインは いまの 1週1回20コイン（サーバの台帳 week_ref_rewards）のまま。どちらで出しても同じ提出・二重にならない。
 *  ・金曜に開いたとき（まだ出していない子）は、いつもの金曜の声かけ（weekref.js → kantanRefNudge）の箱を
 *    「一緒にふりかえろか！」にする（同じ箱・1日1回・閉じられる。べつの声かけを ふやさない）。
 *  ・ことばは NGWORD_V1 に合わせる（責める・否定的なことばは使わない）。比較・順位・点・パーセントは出さない。
 *  ・先生の「見るだけ」モードでは 出さない（サーバでも止まる）。index.html は手で編集しない。
 */
(function () {
  'use strict';
  if (window.__HSWEEKCHAT_V1__) return; window.__HSWEEKCHAT_V1__ = 1;

  var NUDGE_KEY = 'weekRefNudgeV1';   // weekref.js・kantanref.js と同じ「今日はもう声をかけた」

  // ───────── ことば（ここに集める：テストで NG語を確かめる） ─────────
  var SAY = {
    hello: '今週も おつかれさん！ いっしょに ふりかえろか！',
    again: '今週の ふりかえりは もう 出してあるで。出しなおしても ええで！',
    sample: 'こんなふうに 書いた人が おるで👀',
    promise: '先週 決めたこと、どうだった？',
    promisePlan: '今週の 計画、どうだった？',
    promiseDone: 'やりきったな！ つづけられた 自分に 拍手や！',
    promiseWhy: 'だれにでも ある ことやで。わけが わかると、次の 計画に いかせるで。わけは どれに ちかい？',
    promiseOther: 'ことばで 書いてな',
    facts: '今週の きろく、見てみよか📊',
    self: '今週の 自分の 学びは どうやった？（じぶんの 見立てで ええで）',
    reason: 'なんで そう思う？ アプリの きろくから えらんでも、じぶんの ことばでも ええで',
    next: '次は どうする？',
    how: 'なにを 変えてみる？',
    add: 'ひとこと あったら 書いてな（なくても ええで）',
    mood: '今週の 気もちは？（えらばんでも ええで）',
    school: '学校での 学びも 聞かせてな🏫 今週 いちばん 心に のこった 授業は？',
    learned: 'そこで わかったこと・できるように なったことは？',
    more: 'もっと 知りたい・ためしてみたいことは ある？',
    question: '今週の 考える問いや💭（こたえんでも ええで）',
    confirm: 'まとめると こんな感じや！ これで 出す？',
    sending: '先生に 送ってるで…',
    sentCoin: '🪙{n}コイン ゲット！ ふりかえり、ありがとうな。先生も 読むで！',
    sent: '出したで！ ありがとうな。先生も 読むで！',
    retry: 'うまく 送れんかったみたいや。もう一度 おしてみてな',
    loading: 'ちょっと 待ってな…',
    loadFail: 'いまは よみこめんかった。いつもの ふりかえりの らんも 使えるで',
    viewOnly: '（見るだけモード中なので 提出は しません）',
    nudgeTitle: '一緒に ふりかえろか！',
    nudgeSub: '阪神マンと 話しながら、今週の ふりかえりが できるで。'
  };
  var PR = [{ k: 'done', label: '✅ できた' }, { k: 'some', label: '🌗 ちょっと' }, { k: 'not', label: '🌱 できなかった' }];
  var RS = [{ k: 'time', label: '⏰ 時間が なかった' }, { k: 'forgot', label: '💭 わすれた' }, { k: 'way', label: '🔧 やり方が 合わなかった' }];
  var MORES = ['家で もう一度 ためしたい', 'もっと 調べたい', 'ほかの 問題でも ためしたい'];
  function learnedList(theme) {
    return theme
      ? [{ k: 'know', s: '「' + theme + '」の ことが わかった' }, { k: 'can', s: '「' + theme + '」の 問題が できるように なった' }, { k: 'friend', s: '友だちの 考えで なるほどと 思った' }, { k: 'say', s: '自分の 考えを 言えた' }]
      : [{ k: 'know', s: '新しい ことが わかった' }, { k: 'can', s: '前より できるように なった' }, { k: 'friend', s: '友だちの 考えで なるほどと 思った' }, { k: 'say', s: '自分の 考えを 言えた' }];
  }

  // ───────── 小道具 ─────────
  function esc(s) { return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;'); }
  function cut(s, n) { var a = Array.from(String(s == null ? '' : s).replace(/[\r\n\t]/g, ' ').trim()); return a.length > n ? a.slice(0, n).join('') : a.join(''); }
  function fill(s, o) { s = String(s); Object.keys(o || {}).forEach(function (k) { s = s.split('{' + k + '}').join(String(o[k])); }); return s; }
  function curP() { try { if (typeof player !== 'undefined' && player) return player; } catch (e) {} return window.player || null; }
  function viewOnly() { return !!window.__VIEWAS_ON__; }
  function jget(url) { return fetch(url, { credentials: 'include' }).then(function (r) { return r.json(); }).catch(function () { return null; }); }
  function K() { return window.KANTAN || null; }
  function W() { return window.WEEKREF2 || null; }
  function face() { var f = '🐯'; try { if (typeof window.monSpriteHtml === 'function') f = window.monSpriteHtml(154, '🐯'); } catch (e) {} return f; }
  function jstNow() { var n = new Date(); return new Date(n.getTime() + n.getTimezoneOffset() * 60000 + 9 * 3600000); }
  function dayKey830() {
    try { if (typeof hsGetDayKey830 === 'function') return hsGetDayKey830(new Date()); } catch (e) {}
    var d = new Date(Date.now() - 8.5 * 3600000); var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }
  function unitName(id) { try { return K() ? K().unitName(id) : ''; } catch (e) { return ''; } }

  // ───────── 状態（この画面を開いている間だけ・とじても 同じ日なら つづきから） ─────────
  var C = null, _open = false, _d2 = null, _st = null, _sample = null, _sending = false;
  function fresh() {
    return { step: 'load', log: [], wk: '', a: { pr: '', reason: '', note: '', self: '', rsel: '', why: '', next: '', how: '', add: '', mood: '', subj: '', theme: '', learned: '', more: '', qc: -1, qt: '' }, waiting: '', day: dayKey830() };
  }
  function say(who, t) { C.log.push({ w: who, t: String(t || '') }); if (C.log.length > 120) C.log = C.log.slice(-120); }

  // ───────── 読む（いまの画面と同じ材料） ─────────
  function boot() {
    if (C && C.day === dayKey830() && C.step !== 'done') return Promise.resolve();
    C = fresh();
    say('b', SAY.hello);
    var k = K(), w = W();
    if (!k) { say('b', SAY.loadFail); C.step = 'fail'; return Promise.resolve(); }
    var wk = k.weekKey(); C.wk = wk;
    return Promise.all([
      k.load(),
      w ? w.load(wk, true) : Promise.resolve(null),
      jget('/api/student/minna/posts'),
      jget('/api/student/week-ref-status?weekKey=' + encodeURIComponent(wk))
    ]).then(function (rs) {
      var kd = rs[0];
      _d2 = rs[1] || null;
      _st = (rs[3] && rs[3].ok) ? rs[3] : ((kd && kd.status) || null);
      var ps = (rs[2] && rs[2].ok && rs[2].posts) || [];
      var others = ps.filter(function (p) { return !p.mine && String(p.body || '').trim(); });
      _sample = others.filter(function (p) { return p.kind === 'week'; })[0] || others[0] || null;
      if (!(kd && kd.ok)) { say('b', SAY.loadFail); C.step = 'fail'; return; }
      if (_st && _st.wrote) say('b', SAY.again);
      if (_sample) say('b', SAY.sample + '\n「' + cut(_sample.body, 90) + (Array.from(String(_sample.body)).length > 90 ? '…' : '') + '」' + (_sample.name ? '（' + cut(_sample.name, 12) + '）' : ''));
      goPromise();
    });
  }

  // ───────── 進め方 ─────────
  function goPromise() {
    var d = _d2, pt = d && d.promise && d.promise.text, plan = (d && d.plan) || [];
    if (!d || (!pt && !plan.length)) { goFacts(); return; }
    var t = pt ? SAY.promise + '\n先週の あなた：「' + pt + '」' : SAY.promisePlan;
    if (plan.length) t += '\n📅 今週の 計画：' + plan.map(function (p) { return p.day + ' ' + cut(p.text, 20); }).join('／');
    say('b', t); C.step = 'promise';
  }
  function pickPromise(o) {
    say('m', o.label); C.a.pr = o.k;
    if (o.k === 'done') { C.a.reason = ''; say('b', SAY.promiseDone); goFacts(); }
    else { say('b', SAY.promiseWhy); C.step = 'promiseWhy'; }
  }
  function goFacts() {
    var f = _d2 && _d2.facts;
    if (f) {
      var ls = ['📱 アプリを ひらいた日：' + (Number(f.openDays) || 1) + '日'];
      (f.units || []).forEach(function (u) {
        var nm = unitName(u.unit); if (!nm || !(u.c > 0 || u.n > 0)) return;
        if (u.prevC > 0 && u.c > u.prevC) ls.push('📝「' + nm + '」せいかい：先週 ' + u.prevC + '問 → 今週 ' + u.c + '問');
        else if (u.c > 0) ls.push('📝「' + nm + '」今週 ' + u.c + '問 せいかい');
        else ls.push('📝「' + nm + '」に 今週 ' + u.n + '問 ちょうせん');
      });
      if (f.planDays > 0 && f.doneDays > 0) ls.push('📅 計画を 書いた ' + f.planDays + '日のうち ' + f.doneDays + '日、家庭学習を 出したで');
      else if (f.planDays > 0) ls.push('📅 計画を ' + f.planDays + '日ぶん 書いたで');
      else if (f.hwDays > 0) ls.push('📒 家庭学習を ' + f.hwDays + '日 出したで');
      say('b', SAY.facts + '\n' + ls.join('\n'));
      C.step = 'facts';
    } else goSelf();
  }
  function goSelf() { say('b', SAY.self); C.step = 'self'; }
  function goReason() { say('b', SAY.reason); C.step = 'reason'; }
  function goNext() { say('b', SAY.next); C.step = 'next'; }
  function goAdd() { say('b', SAY.add); C.step = 'add'; }
  function goMood() { say('b', SAY.mood); C.step = 'mood'; }
  function goSchool() {
    if (!_d2) { goQuestion(); return; }
    say('b', SAY.school); C.step = 'school';
  }
  function goQuestion() {
    var q = _d2 && _d2.question;
    if (!q) { goConfirm(); return; }
    say('b', SAY.question + '\n「' + q.q + '」'); C.step = 'q';
  }
  function ovr() { return { why: C.a.why, add: C.a.add }; }
  function apply() {   // いまの画面と同じ入れ物に入れる
    var k = K(), w = W();
    if (k) k.set({ self: C.a.self, reason: C.a.rsel, next: C.a.next, how: C.a.how, mood: C.a.mood });
    if (w && w._state) {
      var A = w._state;
      A.pr = C.a.pr; A.reason = (C.a.pr && C.a.pr !== 'done') ? C.a.reason : ''; A.note = C.a.note;
      A.subj = C.a.subj; A.theme = C.a.theme; A.learned = C.a.learned; A.more = C.a.more;
      A.qc = C.a.qc; A.qt = C.a.qt;
    }
  }
  function goConfirm() {
    apply();
    var txt = ''; try { txt = K().compose(ovr()); } catch (e) {}
    say('b', SAY.confirm + '\n「' + txt + '」');
    C.step = 'confirm';
  }
  function restart() { C = null; boot().then(draw); draw(); }

  function send() {
    if (_sending) return;
    if (viewOnly()) { say('b', SAY.viewOnly); draw(); return; }
    var k = K(); if (!k) return;
    apply();
    // 金曜の らん（週の計画の金曜の振り返り）に 前の文が あれば、うしろに のこるように 先に 入れておく（いまの画面と同じ）
    try {
      var ta = document.getElementById('hwReflectionInput');
      if (ta && !String(ta.value || '').trim() && typeof hwGetPlanForWeek === 'function') {
        var pl = hwGetPlanForWeek(C.wk) || {}, f = pl.fri;
        if (f && typeof f === 'object' && f.reflection) ta.value = f.reflection;
      }
    } catch (e) {}
    var wasRewarded = !!(_st && _st.rewarded);
    var okSend = false; try { okSend = k.send(ovr()); } catch (e) {}
    if (!okSend) { say('b', SAY.retry); draw(); return; }
    _sending = true; say('b', SAY.sending); C.step = 'sending'; draw();
    setTimeout(function () {
      jget('/api/student/week-ref-status?weekKey=' + encodeURIComponent(C.wk)).then(function (s) {
        _sending = false;
        C.log = C.log.filter(function (x) { return x.t !== SAY.sending; });
        if (s && s.ok && s.rewarded && !wasRewarded) { say('b', fill(SAY.sentCoin, { n: s.reward || 20 })); C.step = 'done'; }
        else if (s && s.ok && s.wrote) { say('b', SAY.sent); C.step = 'done'; }
        else { say('b', SAY.retry); C.step = 'confirm'; }
        if (s && s.ok) _st = s;
        draw();
      });
    }, 2200);
  }

  // ───────── 入力された文 ─────────
  function typed(v) {
    v = cut(v, 60); if (!v) return;
    var w = C.waiting; C.waiting = '';
    say('m', v);
    if (w === 'promiseWhy') { C.a.reason = 'other'; C.a.note = cut(v, 40); goFacts(); }
    else if (w === 'reason') { C.a.rsel = ''; C.a.why = v; goNext(); }
    else if (w === 'add') { C.a.add = v; goMood(); }
    else if (w === 'learned') { C.a.learned = v; say('b', SAY.more); C.step = 'more'; }
    else if (w === 'more') { C.a.more = cut(v, 40); goQuestion(); }
    else if (w === 'q') { C.a.qt = v; goQuestion2(); }
    draw();
  }
  function goQuestion2() { goConfirm(); }

  // ───────── 画面 ─────────
  var CSS = '#hsWChat{position:fixed;top:0;right:0;bottom:0;left:0;z-index:9990;background:rgba(15,23,42,.45);display:flex;justify-content:center;align-items:stretch;font-family:inherit}'
    + '#hsWChat .hc-box{width:100%;max-width:780px;background:#fef9f0;display:flex;flex-direction:column;height:100%;box-shadow:0 0 30px rgba(0,0,0,.25)}'
    + '#hsWChat .hc-head{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#fb923c;color:#1f2937;font-weight:900;font-size:18px}'
    + '#hsWChat .hc-head .hc-x{margin-left:auto;background:#fff;border:2px solid #c2410c;border-radius:12px;padding:8px 14px;font-size:15px;font-weight:800;color:#7c2d12;min-height:44px}'
    + '#hsWChat .hc-log{flex:1;overflow-y:auto;padding:14px 14px 6px;-webkit-overflow-scrolling:touch}'
    + '#hsWChat .hc-row{display:flex;gap:8px;margin:8px 0;align-items:flex-end}'
    + '#hsWChat .hc-row.me{justify-content:flex-end}'
    + '#hsWChat .hc-face{width:44px;height:44px;flex:0 0 44px;display:flex;align-items:center;justify-content:center;font-size:30px;background:#fff;border-radius:50%;border:2px solid #fed7aa;overflow:hidden}'
    + '#hsWChat .hc-face img{max-width:40px;max-height:40px}'
    + '#hsWChat .hc-b{max-width:78%;padding:10px 14px;border-radius:18px;font-size:17px;line-height:1.6;white-space:pre-wrap;word-break:break-word}'
    + '#hsWChat .bot .hc-b{background:#fff;border:2px solid #fed7aa;border-bottom-left-radius:6px;color:#1f2937}'
    + '#hsWChat .me .hc-b{background:#86efac;border-bottom-right-radius:6px;color:#14532d;font-weight:700}'
    + '#hsWChat .hc-foot{border-top:2px solid #fed7aa;background:#fff7ed;padding:10px 12px 14px;max-height:52%;overflow-y:auto}'
    + '#hsWChat .hc-ch{display:grid;grid-template-columns:1fr 1fr;gap:8px}'
    + '#hsWChat .hc-ch.one{grid-template-columns:1fr}'
    + '#hsWChat .hc-ch.three{grid-template-columns:1fr 1fr 1fr}'
    + '#hsWChat .hc-ch.four{grid-template-columns:1fr 1fr 1fr 1fr}'
    + '#hsWChat .hc-btn{min-height:54px;border-radius:16px;border:2px solid #fb923c;background:#fff;color:#7c2d12;font-size:16.5px;font-weight:800;padding:8px 10px;text-align:center;cursor:pointer;touch-action:manipulation}'
    + '#hsWChat .hc-btn:active{transform:scale(.98)}'
    + '#hsWChat .hc-btn.main{background:#f97316;border-color:#c2410c;color:#fff}'
    + '#hsWChat .hc-btn.sub{background:#f1f5f9;border-color:#cbd5e1;color:#334155}'
    + '#hsWChat .hc-btn.big{font-size:22px}'
    + '#hsWChat .hc-btn.sm{min-height:46px;font-size:15px}'
    + '#hsWChat .hc-in{display:flex;gap:8px;margin-top:8px}'
    + '#hsWChat .hc-in input{flex:1;min-width:0;min-height:52px;border:2px solid #fb923c;border-radius:14px;padding:0 12px;font-size:17px;background:#fff}'
    + '#hsWChat .hc-in button{min-width:96px}'
    + '#hsWChat .hc-lab{font-size:13px;font-weight:800;color:#9a3412;margin:8px 0 4px}'
    + '.hsWChatEntry{display:block;width:100%;margin:0 0 8px;min-height:54px;border-radius:14px;border:3px solid #c2410c;background:linear-gradient(135deg,#fdba74,#fb923c);color:#431407;font-weight:900;font-size:17px;box-shadow:0 4px 12px rgba(194,65,12,.25);cursor:pointer}';
  function ensureCss() { if (document.getElementById('hsWChatCss')) return; var st = document.createElement('style'); st.id = 'hsWChatCss'; st.textContent = CSS; document.head.appendChild(st); }

  function open() {
    ensureCss();
    var root = document.getElementById('hsWChat');
    if (!root) {
      root = document.createElement('div'); root.id = 'hsWChat';
      root.innerHTML = '<div class="hc-box"><div class="hc-head"><span class="hc-face">' + face() + '</span><span>阪神マンと ふりかえる</span>'
        + '<button type="button" class="hc-x" id="hsWChatX">とじる（あとで つづき）</button></div>'
        + '<div class="hc-log" id="hsWChatLog"></div><div class="hc-foot" id="hsWChatFoot"></div></div>';
      document.body.appendChild(root);
      document.getElementById('hsWChatX').onclick = close;
    }
    root.style.display = 'flex'; _open = true;
    if (C && C.step === 'done') C = null;
    var p = boot(); draw(); p.then(draw);
  }
  function close() { var r = document.getElementById('hsWChat'); if (r) r.style.display = 'none'; _open = false; }

  function bubble(x) {
    if (x.w === 'm') return '<div class="hc-row me"><div class="hc-b">' + esc(x.t) + '</div></div>';
    return '<div class="hc-row bot"><span class="hc-face">' + face() + '</span><div class="hc-b">' + esc(x.t) + '</div></div>';
  }
  function btns(list, cls) {
    return '<div class="hc-ch ' + (cls || '') + '">' + list.map(function (b, i) { return '<button type="button" class="hc-btn ' + (b.cls || '') + '" data-i="' + i + '">' + esc(b.label) + '</button>'; }).join('') + '</div>';
  }
  function inputRow(ph, max) { return '<div class="hc-in"><input id="hsWChatIn" maxlength="' + (max || 60) + '" placeholder="' + esc(ph) + '"><button type="button" class="hc-btn main" id="hsWChatSend">送る</button></div>'; }
  function lab(t) { return '<div class="hc-lab">' + esc(t) + '</div>'; }

  // 1つの問い＝ボタン（えらぶ）＋入力（じぶんのことば）。acts の順に data-i をふる。
  function render(parts) {
    var foot = document.getElementById('hsWChatFoot'); if (!foot) return;
    var h = '', acts = [];
    parts.forEach(function (p) {
      if (p.lab) h += lab(p.lab);
      if (p.btns) {
        var base = acts.length;
        h += '<div class="hc-ch ' + (p.cls || '') + '">' + p.btns.map(function (b, i) { acts.push(b.f); return '<button type="button" class="hc-btn ' + (b.cls || '') + '" data-i="' + (base + i) + '">' + esc(b.label) + '</button>'; }).join('') + '</div>';
      }
      if (p.input) h += inputRow(p.input, p.max);
    });
    foot.innerHTML = h;
    var bs = foot.querySelectorAll('button.hc-btn[data-i]');
    for (var i = 0; i < bs.length; i++) (function (b) { b.onclick = function () { var f = acts[Number(b.getAttribute('data-i'))]; if (f) { f(); draw(); } }; })(bs[i]);
    var inp = document.getElementById('hsWChatIn');
    if (inp) {
      document.getElementById('hsWChatSend').onclick = function () { typed(inp.value); };
      inp.onkeydown = function (e) { if (e.key === 'Enter') typed(inp.value); };
    }
  }
  function waitFor(key, f) { return function () { C.waiting = key; if (f) f(); }; }

  function draw() {
    if (!_open || !C) return;
    var logEl = document.getElementById('hsWChatLog'); if (!logEl) return;
    var html = C.log.map(bubble).join('');
    if (logEl._h !== html) { logEl.innerHTML = html; logEl._h = html; logEl.scrollTop = logEl.scrollHeight; }
    var a = C.a, step = C.step;
    C.waiting = '';
    if (step === 'load' || step === 'sending') { render([{ lab: step === 'load' ? SAY.loading : SAY.sending }]); return; }
    if (step === 'fail') { render([{ btns: [{ label: 'とじる', cls: 'sub', f: close }], cls: 'one' }]); return; }
    if (step === 'promise') {
      render([{ btns: PR.map(function (o) { return { label: o.label, cls: 'big', f: function () { pickPromise(o); } }; }), cls: 'three' },
        { btns: [{ label: '⏭ とばす', cls: 'sub sm', f: function () { say('m', '⏭ とばす'); a.pr = ''; goFacts(); } }], cls: 'one' }]);
    } else if (step === 'promiseWhy') {
      render([{ btns: RS.map(function (o) { return { label: o.label, f: function () { say('m', o.label); a.reason = o.k; goFacts(); } }; }).concat([{ label: '⏭ とばす', cls: 'sub', f: function () { say('m', '⏭ とばす'); a.reason = ''; goFacts(); } }]) },
        { lab: '✏️ ほかの わけ（じぶんの ことばで）', input: 'たとえば：いそがしかった', max: 40 }]);
      C.waiting = 'promiseWhy';
    } else if (step === 'facts') {
      render([{ btns: [{ label: '👀 見た！ つぎへ', cls: 'main', f: function () { say('m', '👀 見た！'); goSelf(); } }], cls: 'one' }]);
    } else if (step === 'self') {
      render([{ btns: K().MARKS.map(function (m) { return { label: m.sym + ' ' + m.label, cls: 'big', f: function () { say('m', m.sym + ' ' + m.label); a.self = m.k; K().set({ self: m.k }); goReason(); } }; }), cls: 'three' }]);
    } else if (step === 'reason') {
      K().set({ self: a.self });
      var rl = K().reasons();
      render([{ btns: rl.map(function (o) { return { label: o.label, f: function () { say('m', o.label); a.rsel = o.k; a.why = ''; goNext(); } }; }) },
        { lab: '✏️ じぶんの ことばで', input: 'たとえば：わり算が はやく できた', max: 60 }]);
      C.waiting = 'reason';
    } else if (step === 'next') {
      render([{ btns: K().nexts().map(function (o) { return { label: o.label, f: function () { say('m', o.label); a.next = o.k; a.how = ''; if (o.k === 'change') { say('b', SAY.how); C.step = 'how'; } else goAdd(); } }; }), cls: 'one' }]);
    } else if (step === 'how') {
      render([{ btns: K().HOWS.map(function (o) { return { label: o.label, cls: 'big', f: function () { say('m', o.label); a.how = o.k; goAdd(); } }; }), cls: 'three' }]);
    } else if (step === 'add') {
      render([{ input: 'たとえば：夜ごはんの前に やる', max: 60 }, { btns: [{ label: '⏭ なし', cls: 'sub', f: function () { say('m', '⏭ なし'); a.add = ''; goMood(); } }], cls: 'one' }]);
      C.waiting = 'add';
    } else if (step === 'mood') {
      render([{ btns: K().MOODS.map(function (m) { return { label: m.icon + ' ' + m.label, cls: 'big', f: function () { say('m', m.icon + ' ' + m.label); a.mood = m.k; goSchool(); } }; }), cls: 'three' },
        { btns: [{ label: '⏭ えらばない', cls: 'sub sm', f: function () { say('m', '⏭ えらばない'); a.mood = ''; goSchool(); } }], cls: 'one' }]);
    } else if (step === 'school') {
      var tp = (_d2 && _d2.topics) || [], sj = (_d2 && _d2.subjects) || [];
      var parts = [];
      if (tp.length) parts.push({ lab: '📝 先生の 授業メモから', btns: tp.map(function (t) { return { label: t.subj + '：' + t.theme, f: function () { say('m', t.subj + '：' + t.theme); a.subj = t.subj; a.theme = t.theme; say('b', SAY.learned); C.step = 'learned'; } }; }) });
      if (sj.length) parts.push({ lab: '📚 教科で えらぶ', btns: sj.map(function (s) { return { label: s, cls: 'sm', f: function () { say('m', s); a.subj = s; a.theme = ''; say('b', SAY.learned); C.step = 'learned'; } }; }), cls: 'four' });
      parts.push({ btns: [{ label: '⏭ とばす', cls: 'sub sm', f: function () { say('m', '⏭ とばす'); a.subj = ''; a.theme = ''; a.learned = ''; a.more = ''; goQuestion(); } }], cls: 'one' });
      render(parts);
    } else if (step === 'learned') {
      render([{ btns: learnedList(a.theme).map(function (x) { return { label: x.s, f: function () { say('m', x.s); a.learned = x.s; say('b', SAY.more); C.step = 'more'; } }; }) },
        { lab: '✏️ じぶんの ことばで', input: 'たとえば：比の 表の 使い方が わかった', max: 60 }]);
      C.waiting = 'learned';
    } else if (step === 'more') {
      render([{ btns: MORES.map(function (m) { return { label: m, f: function () { say('m', m); a.more = m; goQuestion(); } }; }).concat([{ label: '⏭ なし', cls: 'sub', f: function () { say('m', '⏭ なし'); a.more = ''; goQuestion(); } }]) },
        { lab: '✏️ じぶんの ことばで', input: 'たとえば：家で 比の 問題を つくってみたい', max: 40 }]);
      C.waiting = 'more';
    } else if (step === 'q') {
      var q = _d2.question;
      render([{ btns: q.choices.map(function (c, i) { return { label: c, f: function () { say('m', c); a.qc = i; goConfirm(); } }; }).concat([{ label: '⏭ とばす', cls: 'sub', f: function () { say('m', '⏭ とばす'); a.qc = -1; a.qt = ''; goConfirm(); } }]) },
        { lab: '✏️ じぶんの ことばで', input: 'じぶんの 考え', max: 60 }]);
      C.waiting = 'q';
    } else if (step === 'confirm') {
      var rewarded = !!(_st && _st.rewarded);
      render([{ btns: [{ label: '📤 これで 出す' + (rewarded ? '' : '（🪙' + ((_st && _st.reward) || 20) + 'コイン）'), cls: 'main', f: send }, { label: '🔁 さいしょから', cls: 'sub', f: restart }] }]);
    } else if (step === 'done') {
      render([{ btns: [{ label: 'とじる', cls: 'main', f: function () { close(); C = null; } }], cls: 'one' }]);
    }
  }

  // ───────── 入口（週の振り返りの らん：かんたんふりかえりの上） ─────────
  function placeEntry() {
    var box = document.getElementById('kantanRef');
    var b = document.getElementById('hsWChatEntry');
    var area = document.getElementById('hwReflectionArea');
    var show = !!(box && box.parentNode && box.style.display !== 'none' && area && !area.classList.contains('hidden') && K());
    if (!show) { if (b) b.style.display = 'none'; return; }
    ensureCss();
    if (!b) { b = document.createElement('button'); b.type = 'button'; b.id = 'hsWChatEntry'; b.className = 'hsWChatEntry'; b.textContent = '💬 阪神マンとふりかえる'; b.onclick = open; }
    if (b.parentNode !== box.parentNode || b.nextSibling !== box) box.parentNode.insertBefore(b, box);
    b.style.display = 'block';
  }

  // ───────── 金曜の声かけ（いつもの箱を「一緒にふりかえろか！」に。べつの声かけは ふやさない） ─────────
  function isFri() { var j = jstNow(); return j.getDay() === 5 && (j.getHours() * 60 + j.getMinutes()) >= 8 * 60; }
  function closeNudge() { var el = document.getElementById('weekRefNudge'); if (el && el.parentNode) el.parentNode.removeChild(el); }
  function showFriNudge(st) {
    if (document.getElementById('weekRefNudge')) return;
    try { localStorage.setItem(NUDGE_KEY, dayKey830()); } catch (e) {}
    var el = document.createElement('div');
    el.id = 'weekRefNudge';   // いつもの声かけと同じ箱・同じ見た目
    el.setAttribute('style', 'position:fixed;right:12px;top:84px;z-index:9997;width:340px;max-width:calc(100vw - 24px);background:#fff7ed;border:2px solid #fdba74;border-radius:16px;box-shadow:0 8px 24px rgba(0,0,0,.16);padding:10px 12px;color:#7c2d12');
    el.innerHTML =
      '<button type="button" id="weekRefNudgeX" aria-label="とじる" style="position:absolute;right:6px;top:4px;background:none;border:none;font-size:18px;color:#c2410c;cursor:pointer">×</button>' +
      '<div style="display:flex;gap:8px;align-items:flex-start">' +
        '<div style="font-size:30px;line-height:1">' + face() + '</div>' +
        '<div style="flex:1;padding-right:12px">' +
          '<div style="font-weight:900;font-size:15px">' + esc(SAY.nudgeTitle) + '</div>' +
          '<div style="font-size:12.5px;line-height:1.6;margin-top:2px;color:#9a3412">' + esc(SAY.nudgeSub) +
          ((st && !st.rewarded) ? '（' + (st.reward || 20) + 'コインの おまけつき）' : '') + '</div>' +
        '</div>' +
      '</div>' +
      '<div style="display:flex;gap:8px;justify-content:flex-end;margin-top:8px;flex-wrap:wrap">' +
        '<button type="button" id="weekRefNudgeNo" style="background:#fff;border:1px solid #fdba74;color:#9a3412;border-radius:10px;padding:8px 12px;font-size:12.5px;font-weight:700;cursor:pointer">またこんど</button>' +
        '<button type="button" id="weekRefNudgeSelf" style="background:#fff;border:1px solid #f97316;color:#c2410c;border-radius:10px;padding:8px 12px;font-size:12.5px;font-weight:800;cursor:pointer">✍️ 自分で 書く</button>' +
        '<button type="button" id="weekRefNudgeGo" style="background:#f97316;border:none;color:#fff;border-radius:10px;padding:8px 14px;font-size:13px;font-weight:900;cursor:pointer">💬 いっしょに ふりかえる</button>' +
      '</div>';
    document.body.appendChild(el);
    document.getElementById('weekRefNudgeX').onclick = closeNudge;
    document.getElementById('weekRefNudgeNo').onclick = closeNudge;
    document.getElementById('weekRefNudgeSelf').onclick = function () { closeNudge(); try { if (typeof window.kantanRefOpen === 'function') window.kantanRefOpen(); } catch (e) {} };
    document.getElementById('weekRefNudgeGo').onclick = function () { closeNudge(); open(); };
    setTimeout(closeNudge, 30000);
  }
  function hookNudge() {
    var orig = window.kantanRefNudge;
    if (typeof orig !== 'function' || orig.__hsw) return !!(orig && orig.__hsw);
    var wrapped = function (st, fallback) {
      if (isFri() && K()) { showFriNudge(st); return true; }   // 金曜は「一緒にふりかえろか！」（1日1回・同じ箱）
      return orig(st, fallback);
    };
    wrapped.__hsw = true;
    window.kantanRefNudge = wrapped;
    return true;
  }

  // ───────── 起動 ─────────
  hookNudge();
  var tries = 0;
  var t0 = setInterval(function () { tries++; if (hookNudge() || tries > 30) clearInterval(t0); }, 500);
  setInterval(function () { try { placeEntry(); } catch (e) {} }, 1500);

  window.HSWEEKCHAT = {
    open: open,
    _t: { SAY: SAY, PR: PR, RS: RS, MORES: MORES, learnedList: learnedList, state: function () { return C; }, isFri: isFri, showFriNudge: showFriNudge, placeEntry: placeEntry }
  };
})();
