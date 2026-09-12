/* 🏰 __DEF_JOIN_NUDGE_V1__ 防衛戦に まだ一度も とうろくしていない子へのお知らせカード。
 *
 *  ・1日に1回まで。出したら その日は もう出さない（localStorage）。
 *  ・一度でも とうろくした子（持ち越しがある子）には 出さない。
 *  ・防衛戦がやっていない日・クラス未所属・決着後は 出さない。
 *  ・画面のつくりには さわらない。自分で作ったカードを body に足すだけ。
 */
(function () {
  'use strict';

  var KEY = 'defJoinNudgeV1';
  var ID = 'defJoinNudgeCard';

  function ymd() {
    var d = new Date();
    return d.getFullYear() + '-' + (d.getMonth() + 1) + '-' + d.getDate();
  }

  function seenToday() {
    try { return localStorage.getItem(KEY) === ymd(); } catch (e) { return false; }
  }

  function markSeen() {
    try { localStorage.setItem(KEY, ymd()); } catch (e) {}
  }

  function closeCard() {
    var el = document.getElementById(ID);
    if (el && el.parentNode) el.parentNode.removeChild(el);
  }

  function show() {
    if (document.getElementById(ID)) return;
    var el = document.createElement('div');
    el.id = ID;
    el.setAttribute('style', [
      'position:fixed',
      'left:8px',
      'right:8px',
      'bottom:76px',
      'z-index:9998',
      'max-width:520px',
      'margin:0 auto',
      'background:linear-gradient(135deg,#fff1f2,#ffe4e6)',
      'border:2px solid #fda4af',
      'border-radius:16px',
      'box-shadow:0 8px 24px rgba(0,0,0,.18)',
      'padding:12px 14px',
      'color:#881337'
    ].join(';'));
    el.innerHTML =
      '<div style="font-weight:900;font-size:15px;display:flex;align-items:center;gap:6px">' +
        '<span>🏰</span><span>ぼうえいせんに とうろくしよう</span>' +
      '</div>' +
      '<div style="margin-top:6px;font-size:13px;line-height:1.7;color:#9f1239">' +
        'クラスのきちを みんなで まもる たたかいが、まいにち ひらかれているよ。' +
        'クラスの みんなは もう さんかしていて、きみの いちばん上の モンスターも 出ているよ。' +
        'とうろくすると、じぶんで えらんだ モンスターと プログラムで たたかえる。もらえるコインも ふえて、ひょうしょうにも 入れるよ。' +
        /* __DEF_NUDGE_TEXT_V1__ クラス全員が 出るように なったので、文を 事実に あわせた */
      '</div>' +
      '<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">' +
        '<button id="' + ID + 'Go" style="background:#e11d48;color:#fff;font-weight:900;border:none;border-radius:12px;padding:9px 16px;font-size:14px;cursor:pointer">とうろくしにいく</button>' +
        '<button id="' + ID + 'No" style="background:#fff;color:#9f1239;font-weight:800;border:2px solid #fda4af;border-radius:12px;padding:9px 14px;font-size:13px;cursor:pointer">またあとで</button>' +
      '</div>';
    document.body.appendChild(el);
    markSeen();
    var go = document.getElementById(ID + 'Go');
    var no = document.getElementById(ID + 'No');
    if (go) {
      go.onclick = function () {
        closeCard();
        try { if (typeof window.openDefense === 'function') window.openDefense(); } catch (e) {}
      };
    }
    if (no) {
      no.onclick = function () { closeCard(); };
    }
  }

  function check() {
    if (seenToday()) return;
    try {
      fetch('/api/defense/status', { credentials: 'include' })
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (!d || !d.ok) return;
          if (!d.active || d.decided || d.no_class) return;
          if (d.my_entry || d.carried_over || d.carry_over_error) return;
          show();
        })
        .catch(function () {});
    } catch (e) {}
  }

  // ログインして画面が出てから1回だけ見にいく。出ていなければ何もしない。
  var tries = 0;
  var timer = setInterval(function () {
    tries++;
    if (tries > 60) { clearInterval(timer); return; }
    if (seenToday()) { clearInterval(timer); return; }
    var btn = document.getElementById('btn-defense');
    if (!btn || !btn.offsetParent) return;
    if (typeof window.openDefense !== 'function') return;
    clearInterval(timer);
    setTimeout(check, 1500);
  }, 3000);
})();
