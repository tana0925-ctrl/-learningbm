/* 💬 HSCHAT_V1 阪神マンと はじめる家庭学習（子どもの画面）— 2026-10-26
 *
 *  ・いまの「家庭学習シート」はそのまま。入口「💬 阪神マンとはじめる」を足すだけ（どちらで出してもOK）。
 *  ・LINE のように 吹き出しが上から順に出る。子どもは下のボタンか入力欄で答える。
 *      はじめる前：今日はなにやるん？ → なんでそれにしたん？ → 何分やる？ → よっしゃ、がんばってな！（タイマー開始）
 *      とちゅう  ：時間になったら 音と画面で「時間やで！まだやる？」（もう少し＝延長／おわる）
 *                  時間より前の「おわる」→「もうおわるん？ほかにやれることさがしてみる？」
 *                  一時停止 →「緊急事態か！？ちょっと待ってるな」→ 再開
 *      おわったら：今の気もちは？☀️☁️☂️ → なんで？ → 次もっといい天気にするには？ → おつかれさん！（写真をつけて提出）
 *  ・答えは いつもの家庭学習の下書き（player.homeStudy.sheetSession）の項目にそのまま入れる：
 *      todo＝今日やること／why＝なんで／aim＝めあて（〇分）／endWeather・weatherReason・nextImprove／やった時間＝タイマー
 *    タイマーも いつもの下書きの startTs・elapsedMs を使う（開始時刻から計算するので スリープや画面切り替えでもずれない）。
 *  ・提出は いつもの hsSubmitAndExport() をそのまま呼ぶ（同じコイン・同じ返却・同じ写真。新しいコインの道は作らない）。
 *  ・お知らせ（はじめて開いたとき1回だけ）：端末に記録。先生の「見るだけ」モード中は出さない・記録しない。
 *  ・ことばは NGWORD_V1 に合わせる（責める・否定的なことばは使わない）。
 *  ・index.html は手で編集しない。
 *
 *  📮 TEISHUTSU_V1（2026-10-27）対話の最初（おっ、来たな！の次）に、今週の家庭学習の提出状況を一言（teishutsu.js・1日1回まで・責めない）。
 *
 *  ✍️ HSSIGN_V1（2026-10-26）サポーター（おうちの人）のサイン
 *    おわったら（次どうする？の あと）・提出の前に「おうちの人に見せて、サインもらってきてな！」
 *    →「🏠 おうちの人に見せる」で おうちの方むけの大きい文字の画面（今日やったこと・時間・天気の要約）
 *    →「👍 見たよ」＋ひとこと（任意）→「サインもろたで！ほな提出しよか」→ いつもの提出。
 *    サインは いつもの「🏠サポーターから」（parentComment）にそのまま入る（シートで書くのと同じ欄・同じ形）。
 *    「あとでもらう」で先に提出でき、その日のうちなら「✍️ おうちの人のサインをもらう」から足せる
 *    （/api/homework/parent-sign・欄が空のときだけ）。サインの有無でコインは変えない。シートの欄の動きは そのまま。
 */
(function () {
  'use strict';
  if (window.__HSCHAT_V1__) return; window.__HSCHAT_V1__ = 1;

  var INTRO_KEY = 'hsChatIntroV1:';
  var EXT_MIN = 5;

  // ───────── ことば（ここに集める：テストで NG語を確かめる） ─────────
  var SAY = {
    hello: 'おっ、来たな！ 今日の家庭学習、いっしょに すすめよか！',
    todo: '今日は なにやるん？',
    todoOther: 'ええな！ なにやるか 書いてな',
    why: 'なんで それにしたん？',
    whyOther: 'ほうほう、わけを 書いてな',
    min: '何分 やる？',
    minOther: '何分にする？ 数字で 書いてな（1〜180）',
    go: 'よっしゃ、がんばってな！ タイマー スタートや！',
    running: 'いま がんばり中やで。終わったら「おわる」を おしてな',
    timeUp: '⏰ 時間やで！ まだ やる？',
    extend: 'ええやん！ あと {n}分 いこか！',
    early: 'もう おわるん？ ほかに やれること さがしてみる？',
    search: 'これなんか どうや？',
    searchPick: 'ええな！ それも やってみよか！ タイマーは そのまま つづいてるで',
    searchNone: 'いまは ほかの候補が 見つからへんかった。自分で 書いてもええで',
    pause: '緊急事態か！？ ちょっと 待ってるな',
    resume: 'おかえり！ つづき いこか！',
    done: 'おつかれ！ {m}分 がんばったな！',
    feel: 'やってみて、今の 気もちは？',
    reason: 'なんで？',
    reasonOther: 'ことばで 書いてな',
    nextSun: 'この晴れを 続けるには？',
    nextElse: '次 もっといい天気に するには？',
    nextOther: 'どうする？ 書いてな',
    bye: 'おつかれさん！ 写真が あったら つけて、先生に 出そう！',
    sending: '先生に 送ってるで…',
    sent: '提出できたで！ {msg} また あした 話そな！',
    sendRetry: 'うまく 送れんかったみたいや。もう一度 おしてみてな',
    already: '今日の家庭学習は もう 提出ずみやで！ また あした 話そな！',
    sheetStarted: 'シートで もう はじめてるみたいやな！ このまま つづけよか',
    viewOnly: '（見るだけモード中なので 提出は しません）',
    introTitle: '家庭学習を阪神マンと対話しながらできるようになったで！',
    sign: 'おつかれさん！ おうちの人に見せて、サインもらってきてな！',
    signDone: 'サインもろたで！ ほな提出しよか！ 写真が あったら つけてな',
    signLater: 'オッケー！ サインは 提出したあとでも もらえるで。ほな提出しよか！ 写真が あったら つけてな',
    signAfter: 'サインもろたで！ 先生にも とどけたで。おうちの人に ありがとうって 言うといてな',
    signAgain: 'サインは もう 入ってるで！ ありがとうな',
    signRetry: 'うまく 送れんかったみたいや。また あとで おしてみてな',
    signHead: 'おうちの方へ',
    signLead: 'お子さんの今日の取り組みです',
    signOk: '👍 見たよ',
    signPh: 'ひとこと（なくても大丈夫です）',
    signBtn: '✍️ おうちの人の サインを もらう',
    introSub: 'やることを えらんで、タイマーで がんばって、さいごに ふりかえる。ぜんぶ 話しながら すすめられるで。いつものシートも そのまま 使えるで。'
  };
  var TODO_FIXED = [
    { k: 'school', label: '🏫 学校の宿題（漢字・計算など）' },
    { k: 'app', label: '🎮 アプリの修行', text: 'アプリの修行' },
    { k: 'other', label: '✍️ その他（自分で書く）', other: true }
  ];
  var WHYS = [
    { k: 'test', label: '📝 テストがあるから', text: 'テストがあるから' },
    { k: 'nigate', label: '💪 苦手をなくしたい', text: '苦手をなくしたい' },
    { k: 'plan', label: '📋 計画に書いたから', text: '計画に書いたから' },
    { k: 'fun', label: '😊 楽しいから', text: '楽しいから' },
    { k: 'other', label: '✍️ その他（自分で書く）', other: true }
  ];
  var MINS = [10, 15, 20, 30];
  var WEATHERS = [
    { k: 'sun', icon: '☀️', label: '☀️ はれ' },
    { k: 'cloud', icon: '☁️', label: '☁️ くもり' },
    { k: 'rain', icon: '☂️', label: '☂️ あめ' }
  ];
  var REASONS = {
    sun: ['集中できた', 'わかった', '時間どおりできた'],
    cloud: ['ちょっと集中が切れた', '半分くらいわかった'],
    rain: ['むずかしかった', '気が散った', 'つかれた']
  };
  var NEXTS = ['⏰ 時間を変える', '🏠 場所を変える', '📏 量を変える', '🔧 やり方を変える', '👍 このままでOK'];

  // ───────── 小道具 ─────────
  function esc(s) { return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;'); }
  function cut(s, n) { var a = Array.from(String(s == null ? '' : s)); return a.length > n ? a.slice(0, n).join('') : a.join(''); }
  function fill(s, o) { s = String(s); Object.keys(o || {}).forEach(function (k) { s = s.split('{' + k + '}').join(String(o[k])); }); return s; }
  function stripIcon(label) { return String(label || '').replace(/^[^぀-ヿ一-鿿A-Za-z0-9🅰🅱]+\s*/, '').trim(); }
  function curP() { try { if (typeof player !== 'undefined' && player) return player; } catch (e) {} return window.player || null; }
  function viewOnly() { return !!window.__VIEWAS_ON__; }
  function jget(url) { return fetch(url, { credentials: 'include' }).then(function (r) { return r.ok ? r.json() : null; }).catch(function () { return null; }); }
  // index.html の関数は「名前で」さがす（window にのらない書き方でも見つかるように typeof で）
  function fn(name) {
    try {
      switch (name) {
        case 'hsGetDayKey830': return typeof hsGetDayKey830 === 'function' ? hsGetDayKey830 : null;
        case 'hsLogs': return typeof hsLogs === 'function' ? hsLogs : null;
        case 'hsHasLogForDay': return typeof hsHasLogForDay === 'function' ? hsHasLogForDay : null;
        case 'hsGetSession': return typeof hsGetSession === 'function' ? hsGetSession : null;
        case 'hsSetSession': return typeof hsSetSession === 'function' ? hsSetSession : null;
        case 'hsEnsureSessionForToday': return typeof hsEnsureSessionForToday === 'function' ? hsEnsureSessionForToday : null;
        case 'hsGetElapsedMs': return typeof hsGetElapsedMs === 'function' ? hsGetElapsedMs : null;
        case 'hsStartStudy': return typeof hsStartStudy === 'function' ? hsStartStudy : null;
        case 'hsTogglePause': return typeof hsTogglePause === 'function' ? hsTogglePause : null;
        case 'hsSubmitAndExport': return typeof hsSubmitAndExport === 'function' ? hsSubmitAndExport : null;
        case 'hsPhotosSelected': return typeof hsPhotosSelected === 'function' ? hsPhotosSelected : null;
        case 'hsFetchWeeklyMenu': return typeof hsFetchWeeklyMenu === 'function' ? hsFetchWeeklyMenu : null;
        case 'hsGetWeekKey': return typeof hsGetWeekKey === 'function' ? hsGetWeekKey : null;
        case 'hsGetWeekDayKey830': return typeof hsGetWeekDayKey830 === 'function' ? hsGetWeekDayKey830 : null;
        case 'hwGetPlanForWeek': return typeof hwGetPlanForWeek === 'function' ? hwGetPlanForWeek : null;
        case 'hsParseDayKey': return typeof hsParseDayKey === 'function' ? hsParseDayKey : null;
      }
    } catch (e) {}
    try { var f = window[name]; if (typeof f === 'function') return f; } catch (e) {}
    return null;
  }
  function photoCount() { try { if (typeof _hsPhotoFiles !== 'undefined' && _hsPhotoFiles) return _hsPhotoFiles.length || 0; } catch (e) {} return 0; }
  function call(name) { var f = fn(name); if (!f) return undefined; try { return f.apply(null, Array.prototype.slice.call(arguments, 1)); } catch (e) { return undefined; } }
  function dayKey() { var v = call('hsGetDayKey830', new Date()); if (v) return v; var d = new Date(Date.now() - 8.5 * 3600000); var p = function (n) { return (n < 10 ? '0' : '') + n; }; return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()); }
  function submittedToday() { try { var logs = call('hsLogs') || []; return !!call('hsHasLogForDay', logs, dayKey()); } catch (e) { return false; } }
  function getSess() { var s = call('hsGetSession'); return (s && s.dayKey === dayKey()) ? s : null; }
  function ensureSess() { return call('hsEnsureSessionForToday') || getSess(); }
  function saveSess(s) { call('hsSetSession', s); }
  function elapsedMs(s) { var v = call('hsGetElapsedMs', s); if (typeof v === 'number') return v; if (!s || !s.started) return 0; var b = Number(s.elapsedMs || 0) || 0; return s.paused || !s.startTs ? b : b + (Date.now() - s.startTs); }
  function mmss(ms) { var t = Math.max(0, Math.floor(ms / 1000)); var m = Math.floor(t / 60), r = t % 60; return m + ':' + (r < 10 ? '0' : '') + r; }

  // 答え → いつもの項目（テストでも使う）
  function buildAim(min) { return min + '分 がんばる'; }
  function buildText(main, extra) { main = String(main || '').trim(); extra = String(extra || '').trim(); return cut(extra ? (main ? main + '：' + extra : extra) : main, 480); }
  function targetMs(c) { return ((Number(c.goalMin) || 0) + (Number(c.extMin) || 0)) * 60000; }

  // ───────── 音 ─────────
  var _ac = null;
  function unlockAudio() { try { if (!_ac) { var A = window.AudioContext || window.webkitAudioContext; if (A) _ac = new A(); } if (_ac && _ac.state === 'suspended') _ac.resume(); } catch (e) {} }
  function beep() {
    try {
      unlockAudio(); if (!_ac) return;
      var t0 = _ac.currentTime;
      [0, 0.35, 0.7, 1.4, 1.75, 2.1].forEach(function (d, i) {
        var o = _ac.createOscillator(), g = _ac.createGain();
        o.type = 'sine'; o.frequency.value = i % 3 === 2 ? 1175 : 880;
        g.gain.setValueAtTime(0.0001, t0 + d); g.gain.exponentialRampToValueAtTime(0.35, t0 + d + 0.02); g.gain.exponentialRampToValueAtTime(0.0001, t0 + d + 0.28);
        o.connect(g); g.connect(_ac.destination); o.start(t0 + d); o.stop(t0 + d + 0.3);
      });
    } catch (e) {}
    try { if (navigator.vibrate) navigator.vibrate([300, 150, 300]); } catch (e) {}
  }

  // ───────── 状態（下書きの中に _chat として置く＝端末とサーバの保存にのる） ─────────
  function chat(s) { return s && s._chat && s._chat.v === 1 ? s._chat : null; }
  function newChat() { return { v: 1, step: 'todo', log: [], goalMin: 0, extMin: 0, alarmAt: 0, todoText: '', whyText: '', weather: '', reason: '', next: '', minutes: 0, waiting: '' }; }
  function say(c, who, text) { c.log.push({ w: who, t: cut(text, 300) }); if (c.log.length > 80) c.log = c.log.slice(-80); }

  // ───────── 画面 ─────────
  var CSS = '#hsChat{position:fixed;top:0;right:0;bottom:0;left:0;z-index:9990;background:rgba(15,23,42,.45);display:flex;justify-content:center;align-items:stretch;font-family:inherit}'
    + '#hsChat .hc-box{width:100%;max-width:780px;background:#fef9f0;display:flex;flex-direction:column;height:100%;box-shadow:0 0 30px rgba(0,0,0,.25)}'
    + '#hsChat .hc-head{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#facc15;color:#1f2937;font-weight:900;font-size:18px}'
    + '#hsChat .hc-head .hc-x{margin-left:auto;background:#fff;border:2px solid #a16207;border-radius:12px;padding:8px 14px;font-size:15px;font-weight:800;color:#713f12;min-height:44px}'
    + '#hsChat .hc-log{flex:1;overflow-y:auto;padding:14px 14px 6px;-webkit-overflow-scrolling:touch}'
    + '#hsChat .hc-row{display:flex;gap:8px;margin:8px 0;align-items:flex-end}'
    + '#hsChat .hc-row.me{justify-content:flex-end}'
    + '#hsChat .hc-face{width:44px;height:44px;flex:0 0 44px;display:flex;align-items:center;justify-content:center;font-size:30px;background:#fff;border-radius:50%;border:2px solid #fde68a;overflow:hidden}'
    + '#hsChat .hc-face img{max-width:40px;max-height:40px}'
    + '#hsChat .hc-b{max-width:74%;padding:10px 14px;border-radius:18px;font-size:17px;line-height:1.55;white-space:pre-wrap;word-break:break-word}'
    + '#hsChat .bot .hc-b{background:#fff;border:2px solid #fde68a;border-bottom-left-radius:6px;color:#1f2937}'
    + '#hsChat .me .hc-b{background:#86efac;border-bottom-right-radius:6px;color:#14532d;font-weight:700}'
    + '#hsChat .hc-foot{border-top:2px solid #fde68a;background:#fffbeb;padding:10px 12px 14px}'
    + '#hsChat .hc-ch{display:grid;grid-template-columns:1fr 1fr;gap:8px}'
    + '#hsChat .hc-ch.one{grid-template-columns:1fr}'
    + '#hsChat .hc-ch.three{grid-template-columns:1fr 1fr 1fr}'
    + '#hsChat .hc-btn{min-height:56px;border-radius:16px;border:2px solid #f59e0b;background:#fff;color:#78350f;font-size:17px;font-weight:800;padding:8px 10px;text-align:center;cursor:pointer;touch-action:manipulation}'
    + '#hsChat .hc-btn:active{transform:scale(.98)}'
    + '#hsChat .hc-btn.main{background:#f97316;border-color:#c2410c;color:#fff}'
    + '#hsChat .hc-btn.sub{background:#f1f5f9;border-color:#cbd5e1;color:#334155}'
    + '#hsChat .hc-btn.big{font-size:26px}'
    + '#hsChat .hc-in{display:flex;gap:8px;margin-top:8px}'
    + '#hsChat .hc-in input{flex:1;min-height:52px;border:2px solid #f59e0b;border-radius:14px;padding:0 12px;font-size:17px;background:#fff}'
    + '#hsChat .hc-in button{min-width:96px}'
    + '#hsChat .hc-timer{text-align:center;margin-bottom:10px}'
    + '#hsChat .hc-tnum{font-size:46px;font-weight:900;color:#0f766e;font-variant-numeric:tabular-nums;line-height:1.1}'
    + '#hsChat .hc-tsub{font-size:14px;color:#64748b;font-weight:700}'
    + '#hsChat .hc-bar{height:12px;background:#e2e8f0;border-radius:8px;overflow:hidden;margin:6px auto 0;max-width:420px}'
    + '#hsChat .hc-bar i{display:block;height:100%;background:linear-gradient(90deg,#34d399,#10b981)}'
    + '#hsChat.ring .hc-timer{animation:hcRing .6s ease-in-out infinite alternate}'
    + '@keyframes hcRing{from{background:#fef3c7}to{background:#fecaca}}'
    + '#hsChat .hc-note{font-size:13px;color:#92400e;margin-top:6px;text-align:center;min-height:16px}'
    + '#hsChatPill{position:fixed;right:14px;bottom:16px;z-index:9989;background:#facc15;border:3px solid #a16207;color:#1f2937;border-radius:999px;padding:10px 16px;font-weight:900;font-size:17px;box-shadow:0 6px 18px rgba(0,0,0,.2);cursor:pointer;min-height:52px}'
    + '#hsChatPill.ring{background:#f87171;color:#fff;border-color:#b91c1c;animation:hcPulse .8s ease-in-out infinite alternate}'
    + '@keyframes hcPulse{from{transform:scale(1)}to{transform:scale(1.08)}}'
    + '.hsChatEntry{display:block;width:100%;margin:0 0 8px;min-height:54px;border-radius:14px;border:3px solid #a16207;background:linear-gradient(135deg,#fde047,#facc15);color:#422006;font-weight:900;font-size:17px;box-shadow:0 4px 12px rgba(161,98,7,.25);cursor:pointer}'
    + '.hsSignEntry{background:linear-gradient(135deg,#fbcfe8,#f9a8d4);border-color:#be185d;color:#831843}'
    + '#hsSign{position:fixed;top:0;right:0;bottom:0;left:0;z-index:9996;background:rgba(15,23,42,.55);display:flex;align-items:center;justify-content:center;padding:14px}'
    + '#hsSign .hs-box{background:#fff;border:4px solid #f9a8d4;border-radius:24px;width:100%;max-width:700px;max-height:100%;overflow-y:auto;padding:20px 24px 18px;color:#1f2937;box-shadow:0 12px 40px rgba(0,0,0,.3)}'
    + '#hsSign .hs-h{font-size:30px;font-weight:900;color:#9d174d}'
    + '#hsSign .hs-l{font-size:22px;font-weight:800;margin-top:2px;color:#831843}'
    + '#hsSign .hs-sum{margin-top:12px;background:#fdf2f8;border-radius:16px;padding:10px 16px}'
    + '#hsSign .hs-r{display:flex;gap:12px;padding:7px 0;border-bottom:1px dashed #f9a8d4;font-size:21px;line-height:1.5}'
    + '#hsSign .hs-r:last-child{border-bottom:none}'
    + '#hsSign .hs-k{flex:0 0 205px;font-weight:800;color:#9d174d}'
    + '#hsSign .hs-v{flex:1;word-break:break-word}'
    + '#hsSign textarea{display:block;width:100%;box-sizing:border-box;margin-top:12px;min-height:70px;border:2px solid #f9a8d4;border-radius:14px;padding:10px 12px;font-size:20px;font-family:inherit;resize:none}'
    + '#hsSign .hs-ok{display:block;width:100%;margin-top:12px;min-height:70px;border-radius:18px;border:3px solid #be185d;background:#ec4899;color:#fff;font-size:30px;font-weight:900;cursor:pointer}'
    + '#hsSign .hs-back{display:block;margin:10px auto 0;min-height:44px;padding:6px 22px;border-radius:12px;border:2px solid #cbd5e1;background:#f8fafc;color:#475569;font-size:16px;font-weight:700;cursor:pointer}'
    + '#hsChatIntro{position:fixed;top:0;right:0;bottom:0;left:0;z-index:9995;background:rgba(15,23,42,.5);display:flex;align-items:center;justify-content:center;padding:16px}'
    + '#hsChatIntro .hi-box{background:#fffbeb;border:3px solid #f59e0b;border-radius:22px;max-width:520px;width:100%;padding:18px 18px 16px;box-shadow:0 12px 40px rgba(0,0,0,.3);color:#422006}'
    + '#hsChatIntro .hi-t{font-size:20px;font-weight:900;line-height:1.5}'
    + '#hsChatIntro .hi-s{font-size:15px;line-height:1.7;margin-top:6px;color:#78350f}'
    + '#hsChatIntro .hi-bs{display:flex;gap:10px;margin-top:14px}'
    + '#hsChatIntro .hi-bs button{flex:1;min-height:56px;border-radius:16px;font-size:17px;font-weight:900;cursor:pointer}';
  function ensureCss() { if (document.getElementById('hsChatCss')) return; var st = document.createElement('style'); st.id = 'hsChatCss'; st.textContent = CSS; document.head.appendChild(st); }
  function face() { var f = '🐯'; try { if (typeof window.monSpriteHtml === 'function') f = window.monSpriteHtml(154, '🐯'); } catch (e) {} return f; }

  var _open = false, _cands = null, _candBusy = false, _tick = null, _sending = false;

  function open() {
    ensureCss(); unlockAudio();
    var root = document.getElementById('hsChat');
    if (!root) {
      root = document.createElement('div'); root.id = 'hsChat';
      root.innerHTML = '<div class="hc-box"><div class="hc-head"><span class="hc-face">' + face() + '</span><span>阪神マン</span>'
        + '<button type="button" class="hc-x" id="hsChatX">とじる（あとで つづき）</button></div>'
        + '<div class="hc-log" id="hsChatLog"></div><div class="hc-foot" id="hsChatFoot"></div></div>';
      document.body.appendChild(root);
      document.getElementById('hsChatX').onclick = close;
    }
    root.style.display = 'flex'; _open = true;
    var pill = document.getElementById('hsChatPill'); if (pill) pill.style.display = 'none';
    boot(); loadCands(); draw();
  }
  function close() { var r = document.getElementById('hsChat'); if (r) r.style.display = 'none'; _open = false; drawPill(); }

  // はじめて開いたとき／続きから
  function boot() {
    if (submittedToday()) { var s0 = getSess(); var c0 = chat(s0); if (!c0 || c0.step !== 'done') _static = 'already'; return; }
    _static = '';
    var s = ensureSess(); if (!s) { _static = 'already'; return; }
    var c = chat(s);
    if (!c) {
      c = newChat();
      say(c, 'b', SAY.hello);
      try { var _ts = (typeof window.TEISHUTSU_CHAT_LINE === 'function') ? window.TEISHUTSU_CHAT_LINE() : ''; if (_ts) say(c, 'b', _ts); } catch (_e) {}   /* TEISHUTSU_V1 今週の家庭学習の提出状況（1日1回まで） */
      if (s.started) { c.step = 'run'; c.goalMin = 0; say(c, 'b', SAY.sheetStarted); }
      else say(c, 'b', SAY.todo);
      s._chat = c; saveSess(s);
    } else if (s.started && (c.step === 'todo' || c.step === 'why' || c.step === 'min')) {
      // シートの「スタート」で先に始まっていたら、タイマーはそのまま使う（やり直さない）
      c.step = 'run'; c.waiting = ''; say(c, 'b', SAY.sheetStarted);
      s._chat = c; saveSess(s);
    }
  }
  var _static = '';

  // ───────── 今日やることの候補（カルテのおすすめ・今週の計画・学校の宿題） ─────────
  function planToday() {
    try {
      var wk = call('hsGetWeekKey', call('hsGetWeekDayKey830', new Date()));
      var plan = call('hwGetPlanForWeek', wk) || {};
      var dow = new Date(Date.now() - 8.5 * 3600000).getDay();
      try { var pd = call('hsParseDayKey', dayKey()); if (pd) dow = pd.getDay(); } catch (e) {}
      if (dow < 1 || dow > 5) return '';
      var raw = plan[['mon', 'tue', 'wed', 'thu', 'fri'][dow - 1]] || '';
      return String(typeof raw === 'object' ? (raw.free || '') : raw).trim();
    } catch (e) { return ''; }
  }
  function loadCands() {
    if (_cands || _candBusy) return;
    _candBusy = true;
    var menuP = Promise.resolve(null);
    try { var mf = fn('hsFetchWeeklyMenu'); if (mf) menuP = Promise.resolve(mf(dayKey())).catch(function () { return null; }); } catch (e) {}
    Promise.all([jget('/api/student/my-karte'), jget('/api/student/karte-reco'), menuP]).then(function (a) {
      _candBusy = false;
      var out = [];
      var mk = a[0] || {}, rc = a[1] || {}, m = a[2] || null;
      if (mk.published && rc.reco && rc.reco.a && rc.reco.a.name) {
        out.push({ k: 'ka', label: '🅰「' + rc.reco.a.name + '」を もう一度', text: '🅰「' + rc.reco.a.name + '」をもう一度（カルテのおすすめ）' });
        if (rc.reco.b && rc.reco.b.name) out.push({ k: 'kb', label: '🅱「' + rc.reco.b.name + '」に すすむ', text: '🅱「' + rc.reco.b.name + '」にすすむ（カルテのおすすめ）' });
      }
      var pl = planToday();
      if (pl) out.push({ k: 'plan', label: '📋 計画：' + cut(pl, 24), text: cut(pl, 300) + '（今週の計画）' });
      var parts = [];
      if (m && m.kanjiPage) parts.push('漢字スキル ' + m.kanjiPage);
      if (m && m.keisanPage) parts.push('計算スキル ' + m.keisanPage);
      if (m && m.otherTasks) parts.push(cut(m.otherTasks, 30));
      TODO_FIXED.forEach(function (o) {
        if (o.k === 'school') out.push({ k: 'school', label: parts.length ? '🏫 学校の宿題（' + cut(parts.join('／'), 30) + '）' : o.label, text: '学校の宿題' + (parts.length ? '（' + parts.join('／') + '）' : '（漢字・計算など）') });
        else out.push(o);
      });
      _cands = out;
      draw();
    });
  }
  function todoOpts() {
    if (_cands) return _cands;
    return TODO_FIXED.map(function (o) { return o.k === 'school' ? { k: 'school', label: o.label, text: '学校の宿題（漢字・計算など）' } : o; });
  }

  // ───────── 進め方 ─────────
  function act(fnc) {
    var s = getSess(); var c = chat(s);
    if (!s || !c) { boot(); draw(); return; }
    try { fnc(s, c); } catch (e) { try { console.warn('[hschat]', e); } catch (_) {} }
    s._chat = c; saveSess(s); draw();
  }
  function pickTodo(o) {
    if (o.other) { act(function (s, c) { say(c, 'm', o.label); say(c, 'b', SAY.todoOther); c.waiting = 'todo'; }); return; }
    act(function (s, c) { say(c, 'm', o.label); c.todoText = o.text || stripIcon(o.label); s.todo = c.todoText; c.step = 'why'; say(c, 'b', SAY.why); });
  }
  function pickWhy(o) {
    if (o.other) { act(function (s, c) { say(c, 'm', o.label); say(c, 'b', SAY.whyOther); c.waiting = 'why'; }); return; }
    act(function (s, c) { say(c, 'm', o.label); c.whyText = o.text; s.why = c.whyText; c.step = 'min'; say(c, 'b', SAY.min); });
  }
  function pickMin(n) {
    unlockAudio();
    n = Math.max(1, Math.min(180, parseInt(n, 10) || 0));
    if (!n) return;
    act(function (s, c) {
      say(c, 'm', n + '分');
      c.goalMin = n; c.extMin = 0; c.alarmAt = 0;
      s.todo = c.todoText || s.todo; s.why = c.whyText || s.why; s.aim = buildAim(n);
      saveSess(s);
      call('hsStartStudy');
      var s2 = getSess() || s;
      if (!s2.started) { s2.started = true; s2.elapsedMs = 0; s2.paused = false; s2.startTs = Date.now(); s2.unlocked = false; }
      s2._chat = c;
      c.step = 'run';
      say(c, 'b', SAY.go);
      // act() の最後で保存するのは s。hsStartStudy が同じ物を書きかえているので s2 を正にする
      if (s2 !== s) { for (var k in s2) s[k] = s2[k]; }
    });
  }
  function typed(v) {
    v = String(v || '').trim(); if (!v) return;
    var s0 = getSess(), c0 = chat(s0);
    if (c0 && c0.waiting === 'min') {
      var n = parseInt(String(v).replace(/[^0-9]/g, ''), 10) || 0;
      if (n < 1 || n > 180) { act(function (s, c) { say(c, 'b', SAY.minOther); }); return; }
      c0.waiting = ''; pickMin(n); return;
    }
    act(function (s, c) {
      var w = c.waiting; c.waiting = '';
      say(c, 'm', v);
      if (w === 'todo') { c.todoText = cut(v, 300); s.todo = c.todoText; c.step = 'why'; say(c, 'b', SAY.why); }
      else if (w === 'why') { c.whyText = cut(v, 300); s.why = c.whyText; c.step = 'min'; say(c, 'b', SAY.min); }
      else if (w === 'reason') { c.reason = cut(v, 300); s.weatherReason = c.reason; c.step = 'next'; say(c, 'b', c.weather === 'sun' ? SAY.nextSun : SAY.nextElse); }
      else if (w === 'next') { c.next = cut(v, 300); s.nextImprove = c.next; toBye(s, c); }
      else if (w === 'more') { s.todo = cut(String(s.todo || '') + '＋' + cut(v, 100), 480); c.todoText = s.todo; say(c, 'b', SAY.searchPick); c.step = 'run'; }
    });
  }
  function togglePause() {
    act(function (s, c) {
      var was = !!s.paused;
      call('hsTogglePause');
      var s2 = getSess() || s; for (var k in s2) s[k] = s2[k];
      if (!was && s.paused) say(c, 'b', SAY.pause);
      else if (was && !s.paused) say(c, 'b', SAY.resume);
    });
  }
  function askEnd() {
    act(function (s, c) {
      say(c, 'm', '✅ おわる');
      if (c.goalMin && elapsedMs(s) < targetMs(c)) { c.step = 'early'; say(c, 'b', SAY.early); }
      else finish(s, c);
    });
  }
  function finish(s, c) {
    if (!s.paused) { call('hsTogglePause'); var s2 = getSess() || s; for (var k in s2) s[k] = s2[k]; }
    if (!s.paused) { var base = Number(s.elapsedMs || 0) || 0; if (s.startTs) s.elapsedMs = base + Math.max(0, Date.now() - s.startTs); s.paused = true; s.startTs = null; }
    c.minutes = Math.max(0, Math.floor(elapsedMs(s) / 60000));
    s.minutesManual = String(c.minutes);
    c.step = 'weather'; ring(false);
    say(c, 'b', fill(SAY.done, { m: c.minutes }));
    say(c, 'b', SAY.feel);
  }
  function extend(n) {
    act(function (s, c) { say(c, 'm', '💪 もう少しやる（' + n + '分）'); c.extMin = (Number(c.extMin) || 0) + n; c.step = 'run'; ring(false); say(c, 'b', fill(SAY.extend, { n: n })); });
  }
  function pickWeather(o) {
    act(function (s, c) { say(c, 'm', o.label); c.weather = o.k; s.endWeather = o.k; c.step = 'reason'; say(c, 'b', SAY.reason); });
  }
  function pickReason(t, other) {
    if (other) { act(function (s, c) { say(c, 'm', '✍️ その他'); say(c, 'b', SAY.reasonOther); c.waiting = 'reason'; }); return; }
    act(function (s, c) { say(c, 'm', t); c.reason = t; s.weatherReason = t; c.step = 'next'; say(c, 'b', c.weather === 'sun' ? SAY.nextSun : SAY.nextElse); });
  }
  function pickNext(label, other) {
    if (other) { act(function (s, c) { say(c, 'm', '✍️ その他'); say(c, 'b', SAY.nextOther); c.waiting = 'next'; }); return; }
    act(function (s, c) { say(c, 'm', label); c.next = stripIcon(label); s.nextImprove = c.next; toBye(s, c); });
  }
  function toBye(s, c) {
    if (String((s && s.parentComment) || '').trim()) { c.step = 'photo'; say(c, 'b', SAY.bye); return; }   // シートで もう書いてもらっていたら そのまま
    c.step = 'sign'; say(c, 'b', SAY.sign);
  }

  // ───────── ✍️ HSSIGN_V1 サポーター（おうちの人）のサイン ─────────
  var SIGN_WEATHER = { sun: '☀️ はれ', cloud: '☁️ くもり', rain: '☂️ あめ' };
  function signText(comment) { var t = cut(String(comment || '').replace(/[\r\n\t]+/g, ' ').trim(), 200); return t ? SAY.signOk + '　' + t : SAY.signOk; }
  function sumOf(o) {   // o … 下書き（session）でも 提出ずみの記録（log）でも同じ項目名
    o = o || {};
    var min = (o.minutesManual != null && o.minutesManual !== '') ? o.minutesManual : o.minutes;
    return {
      todo: String(o.todo || o.text || '').trim(),
      min: Math.max(0, parseInt(min, 10) || 0),
      aim: String(o.aim || '').trim(),
      weather: SIGN_WEATHER[String(o.endWeather || o.weather || '')] || '',
      reason: String(o.weatherReason || '').trim(),
      next: String(o.nextImprove || '').trim()
    };
  }
  function openSign(sum, onOk) {
    ensureCss();
    var old = document.getElementById('hsSign'); if (old && old.parentNode) old.parentNode.removeChild(old);
    var row = function (k, v) { return v ? '<div class="hs-r"><span class="hs-k">' + esc(k) + '</span><span class="hs-v">' + esc(v) + '</span></div>' : ''; };
    var el = document.createElement('div'); el.id = 'hsSign';
    el.innerHTML = '<div class="hs-box">'
      + '<div class="hs-h">' + esc(SAY.signHead) + '</div><div class="hs-l">' + esc(SAY.signLead) + '</div>'
      + '<div class="hs-sum">'
      + row('📚 やったこと', sum.todo)
      + row('⏱ 時間', sum.min + '分' + (sum.aim ? '（めあて：' + sum.aim + '）' : ''))
      + row('🌤 やってみた気もち', sum.weather + (sum.reason ? '　' + sum.reason : ''))
      + row('➡️ 次は', sum.next)
      + '</div>'
      + '<textarea id="hsSignTa" maxlength="200" placeholder="' + esc(SAY.signPh) + '"></textarea>'
      + '<button type="button" class="hs-ok" id="hsSignOk">' + esc(SAY.signOk) + '</button>'
      + '<button type="button" class="hs-back" id="hsSignBack">もどる</button>'
      + '</div>';
    document.body.appendChild(el);
    var rm = function () { if (el.parentNode) el.parentNode.removeChild(el); };
    document.getElementById('hsSignBack').onclick = rm;
    document.getElementById('hsSignOk').onclick = function () { var v = String((document.getElementById('hsSignTa') || {}).value || ''); rm(); onOk(signText(v)); };
  }
  function putSheetSign(text) { try { var ta = document.getElementById('hsParentComment'); if (ta && !String(ta.value || '').trim()) ta.value = text; } catch (e) {} }
  function signNow() {   // 提出の前（対話の中）
    var s = getSess(); if (!s) return;
    openSign(sumOf(s), function (text) {
      act(function (s2, c2) {
        say(c2, 'm', '👍 おうちの人が 見たよ');
        s2.parentComment = text; c2.signed = 1;
        putSheetSign(text);
        say(c2, 'b', SAY.signDone); c2.step = 'photo';
      });
    });
  }
  function signSkip() { act(function (s, c) { say(c, 'm', '⏭ あとで もらう'); say(c, 'b', SAY.signLater); c.step = 'photo'; }); }
  function todayLog() {
    try { var logs = call('hsLogs') || [], dk = dayKey(); for (var i = 0; i < logs.length; i++) { var l = logs[i]; if (l && l.dayKey === dk && !l.restDay) return l; } } catch (e) {}
    return null;
  }
  function canSignLater() { var l = todayLog(); return !!(l && !String(l.parentComment || '').trim()); }
  var _signBusy = false;
  function signAfterSubmit() {   // 提出したあと（その日のうち）
    var l = todayLog(); if (!l || _signBusy) return;
    if (String(l.parentComment || '').trim()) { afterSay(SAY.signAgain); return; }
    openSign(sumOf(l), function (text) {
      if (viewOnly()) { afterSay(SAY.viewOnly); return; }
      _signBusy = true;
      fetch('/api/homework/parent-sign', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ dayKey: l.dayKey, text: text }) })
        .then(function (r) { return r.json(); }).catch(function () { return null; })
        .then(function (j) {
          _signBusy = false;
          if (j && j.ok && (j.signed || j.already)) {
            l.parentComment = String(j.parentComment || text);
            try { if (typeof saveData === 'function') saveData(); } catch (e) {}
            putSheetSign(l.parentComment);
            try { if (typeof hsRender === 'function') hsRender(); } catch (e) {}
            afterSay(j.signed ? SAY.signAfter : SAY.signAgain);
          } else afterSay(SAY.signRetry);
          placeEntries();
        });
    });
  }
  function afterSay(t) {   // 提出したあとの ひとこと（対話の画面を ひらいて 見せる）
    if (!_done) { _done = newChat(); _done.step = 'done'; }
    say(_done, 'b', t);
    if (!_open) open(); else draw();
  }

  async function submit() {
    if (_sending) return;
    if (viewOnly()) { act(function (s, c) { say(c, 'b', SAY.viewOnly); }); return; }
    _sending = true;
    act(function (s, c) {
      s.endWeather = c.weather || s.endWeather || 'sun';
      s.weatherReason = c.reason || s.weatherReason || '';
      s.nextImprove = c.next || s.nextImprove || '';
      s.minutesManual = String(c.minutes || 0);
      s.minutes = s.minutes || String(c.minutes || 0);
      s.unlocked = true;
      s.zeroMinAsked = true;   // 時間はタイマーで はかったので「0分のままだよ」の確認は出さない（シートの欄は かくれている）
      say(c, 'b', SAY.sending);
    });
    try { var me = document.getElementById('hsMinutes'); var s0 = getSess(); if (me && s0 && s0._chat) me.value = String(s0._chat.minutes || 0); } catch (e) {}
    var keep = null; try { keep = JSON.parse(JSON.stringify(getSess()._chat)); } catch (e) {}
    try { var f = fn('hsSubmitAndExport'); if (f) await f(); } catch (e) {}
    _sending = false;
    if (submittedToday()) {
      var msg = ''; try { msg = String((document.getElementById('hsRewardMsg') || {}).textContent || '').replace(/^✅\s*/, '').trim(); } catch (e) {}
      _done = keep || newChat();
      _done.step = 'done'; _done.waiting = '';
      _done.log = (_done.log || []).filter(function (x) { return x.t !== SAY.sending; });
      say(_done, 'b', fill(SAY.sent, { msg: msg }));
      draw(); drawPill();
    } else {
      act(function (s, c) { c.log = c.log.filter(function (x) { return x.t !== SAY.sending; }); say(c, 'b', SAY.sendRetry); });
    }
  }
  var _done = null;   // 提出したあと（下書きは消える）の画面はメモリだけ

  // ───────── 描く ─────────
  function bubble(x) {
    if (x.w === 'm') return '<div class="hc-row me"><div class="hc-b">' + esc(x.t) + '</div></div>';
    return '<div class="hc-row bot"><span class="hc-face">' + face() + '</span><div class="hc-b">' + esc(x.t) + '</div></div>';
  }
  function btns(list, cls) {
    return '<div class="hc-ch ' + (cls || '') + '">' + list.map(function (b, i) { return '<button type="button" class="hc-btn ' + (b.cls || '') + '" data-i="' + i + '">' + esc(b.label) + '</button>'; }).join('') + '</div>';
  }
  function inputRow(ph, num) { return '<div class="hc-in"><input id="hsChatIn" ' + (num ? 'inputmode="numeric" pattern="[0-9]*" maxlength="3"' : 'maxlength="120"') + ' placeholder="' + esc(ph) + '"><button type="button" class="hc-btn main" id="hsChatSend">送る</button></div>'; }

  function draw() {
    if (!_open) return;
    var logEl = document.getElementById('hsChatLog'), foot = document.getElementById('hsChatFoot');
    if (!logEl || !foot) return;
    var c, s = null, actions = [], h = '', cls = '';
    if (_done) c = _done;
    else if (_static === 'already') {
      logEl.innerHTML = bubble({ w: 'b', t: SAY.already });
      if (canSignLater()) { foot.innerHTML = btns([{ label: SAY.signBtn, cls: 'main' }, { label: 'とじる', cls: 'sub' }]); bind(foot, [signAfterSubmit, close]); }
      else { foot.innerHTML = btns([{ label: 'とじる', cls: 'sub' }], 'one'); bind(foot, [close]); }
      return;
    }
    else { s = getSess(); c = chat(s); }
    if (!c) { boot(); s = getSess(); c = chat(s); if (!c) { logEl.innerHTML = bubble({ w: 'b', t: SAY.already }); foot.innerHTML = ''; return; } }
    var html = c.log.map(bubble).join('');
    if (logEl._n !== c.log.length || logEl._h !== html.length) { logEl.innerHTML = html; logEl._n = c.log.length; logEl._h = html.length; logEl.scrollTop = logEl.scrollHeight; }
    var step = c.step;
    if (c.waiting) {
      foot.innerHTML = inputRow(c.waiting === 'min' ? '例：25' : 'ここに書いてな', c.waiting === 'min')
        + btns([{ label: 'もどる（ボタンでえらぶ）', cls: 'sub' }], 'one');
      var inp = document.getElementById('hsChatIn');
      document.getElementById('hsChatSend').onclick = function () { typed(inp.value); };
      inp.onkeydown = function (e) { if (e.key === 'Enter') typed(inp.value); };
      bind(foot.querySelector('.hc-ch'), [function () { act(function (s2, c2) { c2.waiting = ''; }); }]);
      setTimeout(function () { try { inp.focus(); } catch (e) {} }, 50);
      return;
    }
    if (step === 'todo') {
      var o = todoOpts();
      h = btns(o) + (_cands ? '' : '<div class="hc-note">カルテと計画を よみこみ中…</div>');
      foot.innerHTML = h; bind(foot, o.map(function (x) { return function () { pickTodo(x); }; }));
    } else if (step === 'why') {
      foot.innerHTML = btns(WHYS); bind(foot, WHYS.map(function (x) { return function () { pickWhy(x); }; }));
    } else if (step === 'min') {
      var ms = MINS.map(function (n) { return { label: n + '分' }; }).concat([{ label: '✍️ その他' }]);
      foot.innerHTML = btns(ms, 'three');
      bind(foot, MINS.map(function (n) { return function () { pickMin(n); }; }).concat([function () { act(function (s2, c2) { say(c2, 'm', '✍️ その他'); say(c2, 'b', SAY.minOther); c2.waiting = 'min'; }); }]));
    } else if (step === 'run' || step === 'alarm' || step === 'early' || step === 'search') {
      var el = elapsedMs(s), tg = targetMs(c), paused = !!(s && s.paused);
      var left = tg ? tg - el : 0;
      var big = tg ? (left >= 0 ? mmss(left) : '+' + mmss(-left)) : mmss(el);
      var sub = tg ? (left >= 0 ? 'のこり（めあて ' + (c.goalMin + (c.extMin || 0)) + '分）' : '時間を こえて がんばり中') : 'がんばった時間';
      var pct = tg ? Math.min(100, Math.round(el / tg * 100)) : 0;
      h = '<div class="hc-timer"><div class="hc-tnum" id="hsChatT">' + big + '</div><div class="hc-tsub" id="hsChatTs">' + esc(sub) + (paused ? '（いま 止まってるで）' : '') + '</div>'
        + (tg ? '<div class="hc-bar"><i id="hsChatBar" style="width:' + pct + '%"></i></div>' : '') + '</div>';
      if (step === 'alarm') {
        actions = [{ label: '💪 もう少しやる（5分）', cls: '', f: function () { extend(EXT_MIN); } }, { label: '💪 もう少しやる（10分）', f: function () { extend(10); } }, { label: '✅ おわる', cls: 'main', f: function () { act(function (s2, c2) { say(c2, 'm', '✅ おわる'); finish(s2, c2); }); } }];
        foot.innerHTML = h + btns(actions, 'three');
      } else if (step === 'early') {
        actions = [{ label: '🔍 さがす', cls: 'main', f: search }, { label: '🌙 今日はここまで', f: function () { act(function (s2, c2) { say(c2, 'm', '🌙 今日はここまで'); finish(s2, c2); }); } }, { label: '↩️ やっぱり つづける', cls: 'sub', f: function () { act(function (s2, c2) { say(c2, 'm', '↩️ やっぱり つづける'); c2.step = 'run'; say(c2, 'b', SAY.resume); }); } }];
        foot.innerHTML = h + btns(actions, 'three');
      } else if (step === 'search') {
        var cs = moreCands(s, c);
        actions = cs.map(function (x) { return { label: x.label, f: function () { pickMore(x); } }; });
        actions.push({ label: '✍️ 自分で書く', f: function () { act(function (s2, c2) { say(c2, 'm', '✍️ 自分で書く'); say(c2, 'b', SAY.todoOther); c2.waiting = 'more'; }); } });
        actions.push({ label: '🌙 今日はここまで', cls: 'sub', f: function () { act(function (s2, c2) { say(c2, 'm', '🌙 今日はここまで'); finish(s2, c2); }); } });
        foot.innerHTML = h + btns(actions);
      } else {
        actions = [{ label: paused ? '▶ 再開' : '⏸ 一時停止', cls: paused ? 'main' : 'sub', f: togglePause }, { label: '✅ おわる', cls: 'main', f: askEnd }];
        foot.innerHTML = h + btns(actions);
      }
      bind(foot.querySelector('.hc-ch'), actions.map(function (a) { return a.f; }));
    } else if (step === 'weather') {
      foot.innerHTML = btns(WEATHERS.map(function (w) { return { label: w.label, cls: 'big' }; }), 'three');
      bind(foot, WEATHERS.map(function (w) { return function () { pickWeather(w); }; }));
    } else if (step === 'reason') {
      var rs = (REASONS[c.weather] || REASONS.sun).map(function (t) { return { label: t }; }).concat([{ label: '✍️ その他' }]);
      foot.innerHTML = btns(rs);
      bind(foot, rs.map(function (r, i) { return function () { if (i === rs.length - 1) pickReason('', true); else pickReason(r.label); }; }));
    } else if (step === 'next') {
      var ns = NEXTS.map(function (t) { return { label: t }; }).concat([{ label: '✍️ その他' }]);
      foot.innerHTML = btns(ns);
      bind(foot, ns.map(function (r, i) { return function () { if (i === ns.length - 1) pickNext('', true); else pickNext(r.label); }; }));
    } else if (step === 'sign') {
      foot.innerHTML = btns([{ label: '🏠 おうちの人に 見せる', cls: 'main' }, { label: '⏭ あとで もらう', cls: 'sub' }]);
      bind(foot, [signNow, signSkip]);
    } else if (step === 'photo') {
      var cnt = photoCount();
      foot.innerHTML = '<div class="hc-ch">'
        + '<label class="hc-btn" style="display:flex;align-items:center;justify-content:center">📷 写真を えらぶ（3まいまで）<input type="file" id="hsChatPhoto" accept="image/*" multiple style="display:none"></label>'
        + '<button type="button" class="hc-btn main" id="hsChatSubmit">' + (_sending ? '送ってるで…' : '📤 先生に 提出') + '</button></div>'
        + '<div class="hc-note" id="hsChatPhotoN">' + (cnt ? '📎 ' + cnt + 'まい つけたで' : '写真は なくても 出せるで') + '</div>';
      var pi = document.getElementById('hsChatPhoto');
      pi.onchange = function () { var f = fn('hsPhotosSelected'); if (f) { try { f(pi); } catch (e) {} } setTimeout(draw, 300); };
      document.getElementById('hsChatSubmit').onclick = submit;
    } else if (step === 'done') {
      if (canSignLater()) { foot.innerHTML = btns([{ label: SAY.signBtn, cls: 'main' }, { label: 'とじる', cls: 'sub' }]); bind(foot, [signAfterSubmit, function () { _done = null; close(); }]); }
      else { foot.innerHTML = btns([{ label: 'とじる', cls: 'main' }], 'one'); bind(foot, [function () { _done = null; close(); }]); }
    } else foot.innerHTML = '';
  }
  function bind(root, fns) {
    if (!root) return;
    var bs = root.querySelectorAll('button.hc-btn[data-i]');
    for (var i = 0; i < bs.length; i++) (function (b) { b.onclick = function () { var f = fns[Number(b.getAttribute('data-i'))]; if (f) f(); }; })(bs[i]);
  }

  // ほかに やれること（えらんだもの以外の候補）
  function moreCands(s, c) {
    var cur = String((s && s.todo) || '');
    return todoOpts().filter(function (o) { return !o.other && cur.indexOf(o.text || stripIcon(o.label)) < 0; }).slice(0, 5);
  }
  function search() {
    act(function (s, c) {
      say(c, 'm', '🔍 さがす');
      var cs = moreCands(s, c);
      say(c, 'b', cs.length ? SAY.search : SAY.searchNone);
      c.step = 'search';
    });
  }
  function pickMore(o) {
    act(function (s, c) { say(c, 'm', o.label); s.todo = cut(String(s.todo || '') + '＋' + (o.text || stripIcon(o.label)), 480); c.todoText = s.todo; say(c, 'b', SAY.searchPick); c.step = 'run'; });
  }

  // ───────── タイマー（1秒ごと・画面にもどったときも すぐ確かめる） ─────────
  function ring(on) { var r = document.getElementById('hsChat'); if (r) r.classList.toggle('ring', !!on); }
  function tick() {
    var s = getSess(), c = chat(s);
    if (!s || !c) { drawPill(); return; }
    if (c.step === 'run' && c.goalMin && s.started && !s.paused) {
      var tg = targetMs(c);
      if (elapsedMs(s) >= tg && c.alarmAt !== tg) {
        c.alarmAt = tg; c.step = 'alarm';
        say(c, 'b', SAY.timeUp);
        s._chat = c; saveSess(s);
        beep();
        if (!_open) open(); else draw();
        ring(true);
        return;
      }
    }
    if (_open && (c.step === 'run' || c.step === 'alarm' || c.step === 'early' || c.step === 'search')) {
      var el = elapsedMs(s), t2 = targetMs(c), left = t2 - el;
      var tn = document.getElementById('hsChatT'); if (tn) tn.textContent = t2 ? (left >= 0 ? mmss(left) : '+' + mmss(-left)) : mmss(el);
      var bar = document.getElementById('hsChatBar'); if (bar && t2) bar.style.width = Math.min(100, Math.round(el / t2 * 100)) + '%';
    }
    drawPill();
  }
  function drawPill() {
    var s = getSess(), c = chat(s);
    var show = !_open && c && s && s.started && ['run', 'alarm', 'early', 'search'].indexOf(c.step) >= 0;
    var p = document.getElementById('hsChatPill');
    if (!show) { if (p) p.style.display = 'none'; return; }
    ensureCss();
    if (!p) { p = document.createElement('button'); p.type = 'button'; p.id = 'hsChatPill'; p.onclick = open; document.body.appendChild(p); }
    p.style.display = 'block';
    var el = elapsedMs(s), tg = targetMs(c);
    p.classList.toggle('ring', c.step === 'alarm');
    p.textContent = c.step === 'alarm' ? '⏰ 時間やで！' : ('🐯 ' + (tg ? 'のこり ' + mmss(Math.max(0, tg - el)) : mmss(el)) + (s.paused ? ' ⏸' : ''));
  }
  function startTick() { if (_tick) return; _tick = setInterval(tick, 1000); document.addEventListener('visibilitychange', function () { if (!document.hidden) tick(); }); window.addEventListener('focus', tick); window.addEventListener('pageshow', tick); }

  // ───────── 入口ボタン（家庭学習の週の画面・今日のシートの上） ─────────
  function entryBtn(id) {
    var b = document.createElement('button'); b.type = 'button'; b.id = id; b.className = 'hsChatEntry';
    b.textContent = '💬 阪神マンとはじめる'; b.onclick = open; return b;
  }
  function placeEntries() {
    ensureCss();
    var sub = submittedToday();
    var label = '💬 阪神マンとはじめる';
    try { var s = getSess(), c = chat(s); if (c && c.step !== 'todo' && !sub) label = '💬 阪神マンと つづきから'; } catch (e) {}
    var wk = document.getElementById('hwOpenTodayBtn');
    if (wk && wk.parentNode) {
      var a = document.getElementById('hsChatEntryW');
      if (!a) { a = entryBtn('hsChatEntryW'); a.style.margin = '0'; a.style.flex = '1'; wk.parentNode.insertBefore(a, wk); }
      var hide = sub || wk.classList.contains('hidden');
      a.style.display = hide ? 'none' : 'block'; if (a.textContent !== label) a.textContent = label;
    }
    var scr = document.getElementById('screen-homestudy');
    if (scr) {
      var b2 = document.getElementById('hsChatEntryS');
      if (!b2) { b2 = entryBtn('hsChatEntryS'); scr.insertBefore(b2, scr.firstChild); }
      b2.style.display = sub ? 'none' : 'block'; if (b2.textContent !== label) b2.textContent = label;
    }
    // ✍️ HSSIGN_V1 提出したあと（その日のうち・サポーター欄が空）は「おうちの人のサインをもらう」
    var later = sub && canSignLater();
    [['hsSignLaterW', wk ? wk.parentNode : null, wk], ['hsSignLaterS', scr, scr ? scr.firstChild : null]].forEach(function (x) {
      var b3 = document.getElementById(x[0]);
      if (!b3 && later && x[1]) { b3 = document.createElement('button'); b3.type = 'button'; b3.id = x[0]; b3.className = 'hsChatEntry hsSignEntry'; b3.textContent = SAY.signBtn; b3.onclick = signAfterSubmit; if (x[0] === 'hsSignLaterW') { b3.style.margin = '0'; b3.style.flex = '1'; } x[1].insertBefore(b3, x[2]); }
      if (b3) b3.style.display = later ? 'block' : 'none';
    });
  }

  // ───────── お知らせ（その子に1回だけ・見るだけモードでは出さない） ─────────
  function introKey() { var p = curP(); return p && p.userId ? INTRO_KEY + p.userId : ''; }
  function introSeen(k) { try { return localStorage.getItem(k) === '1'; } catch (e) { return true; } }
  function introMark(k) { if (viewOnly()) return; try { localStorage.setItem(k, '1'); } catch (e) {} }
  function maybeIntro() {
    if (viewOnly()) return;
    var k = introKey(); if (!k || introSeen(k)) return;
    if (document.getElementById('hsChatIntro')) return;
    introMark(k);
    ensureCss();
    var el = document.createElement('div'); el.id = 'hsChatIntro';
    el.innerHTML = '<div class="hi-box"><div style="display:flex;gap:10px;align-items:flex-start"><span class="hc-face" style="width:52px;height:52px;flex:0 0 52px;display:flex;align-items:center;justify-content:center;font-size:34px;background:#fff;border-radius:50%;border:2px solid #fde68a;overflow:hidden">' + face() + '</span>'
      + '<div><div class="hi-t">' + esc(SAY.introTitle) + '</div><div class="hi-s">' + esc(SAY.introSub) + '</div></div></div>'
      + '<div class="hi-bs"><button type="button" id="hsChatIntroLater" style="background:#fff;border:2px solid #f59e0b;color:#92400e">あとで</button>'
      + '<button type="button" id="hsChatIntroGo" style="background:#f97316;border:2px solid #c2410c;color:#fff">💬 阪神マンとはじめる</button></div></div>';
    document.body.appendChild(el);
    var rm = function () { if (el.parentNode) el.parentNode.removeChild(el); };
    document.getElementById('hsChatIntroLater').onclick = rm;
    document.getElementById('hsChatIntroGo').onclick = function () { rm(); open(); };
  }

  // ───────── 起動 ─────────
  var tries = 0, introDone = false;
  var boot0 = setInterval(function () {
    tries++;
    var p = curP();
    if (p && p.userId && fn('hsGetSession')) {
      startTick();
      if (!introDone) { introDone = true; setTimeout(maybeIntro, 3500); }
    }
    if (_tick && tries > 3) { clearInterval(boot0); setInterval(placeEntries, 1500); }
    placeEntries();
    if (tries > 120) clearInterval(boot0);
  }, 1000);

  window.HSCHAT = {
    open: open,
    _t: { SAY: SAY, TODO_FIXED: TODO_FIXED, WHYS: WHYS, MINS: MINS, WEATHERS: WEATHERS, REASONS: REASONS, NEXTS: NEXTS, buildAim: buildAim, buildText: buildText, signText: signText, sumOf: sumOf, canSignLater: canSignLater, targetMs: targetMs, mmss: mmss, stripIcon: stripIcon, introKey: introKey, maybeIntro: maybeIntro, tick: tick }
  };
})();
