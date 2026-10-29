/* 🔁 __DEF_REVIEW_V1__ 防衛戦の「ふりかえり」カード。
 *
 *  ・決戦の 結果画面（#defReplay がある）では「きょうの ふりかえり」
 *  ・出陣の 画面（プログラムの へんしゅう #def2ProgBox がある）では「まえの たたかいの ふりかえり」
 *  ・中身は /api/defense/review（読むだけ）。じぶんの ことと クラス ぜんたいの ことだけ。
 *  ・ほかの子の 名前・じゅんい・％ は 出さない。
 *  ・画面のつくりには さわらない。カードを 1まい 足すだけ。
 */
(function () {
  'use strict';
  var ID = 'defReviewCard';
  var cache = null, cacheAt = 0, busy = false;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]; }); }

  function ekLabel(ek) {
    var m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2})/.exec(String(ek || ''));
    if (!m) return '';
    var d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4]));
    var j = new Date(d.getTime() + 9 * 3600 * 1000);
    return (j.getUTCMonth() + 1) + '/' + j.getUTCDate();
  }

  function bar(left, max, color) {
    if (!max) return '';
    var w = Math.max(0, Math.min(100, Math.round(left / max * 100)));
    return '<div style="height:8px;background:#e2e8f0;border-radius:6px;overflow:hidden;margin-top:3px"><div style="height:100%;width:' + w + '%;background:' + color + '"></div></div>';
  }

  function html(d, mode) {
    var win = d.result === 'win';
    var f = d.facts || {}, me = d.me, pg = d.prog || {};
    var title = mode === 'result' ? (win ? '🎉 きょうの ふりかえり' : '🔁 きょうの ふりかえり — つぎの 作戦を たてよう')
                                  : '🔁 まえの たたかい（' + esc(ekLabel(d.event_key)) + '）の ふりかえり';
    var h = '<div style="font-weight:900;font-size:15px;color:#3730a3">' + title + '</div>';
    h += '<div style="margin-top:8px;display:grid;gap:8px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr))">';
    // クラスの ようす
    h += '<div style="background:#fff;border:1px solid #e0e7ff;border-radius:12px;padding:8px 10px;font-size:13px;line-height:1.7;color:#334155">'
      + '<div style="font-weight:900;color:#4338ca">🏰 クラスの たたかい</div>'
      + '<div>てき ' + (f.foesTotal || 0) + '体のうち <b>' + (f.foesDown || 0) + '体</b> たおした</div>';
    if (f.baseMax) {
      h += '<div style="margin-top:2px">てきの きち のこり <b>' + (f.enemyBaseEnd == null ? '?' : f.enemyBaseEnd) + '</b>（さいしょ ' + f.baseMax + '）' + bar(f.enemyBaseEnd || 0, f.baseMax, '#f97316') + '</div>';
      if (!win && f.enemyBaseEnd != null && f.enemyBaseEnd < f.baseMax) h += '<div style="color:#c2410c;font-weight:800">てきの きちに とどいていたよ！ あと ' + f.enemyBaseEnd + ' けずれば こわせた。</div>';
      h += '<div style="margin-top:2px">みかたの きち のこり <b>' + (f.myBaseEnd == null ? '?' : f.myBaseEnd) + '</b>' + bar(f.myBaseEnd || 0, f.baseMax, '#22c55e') + '</div>';
    }
    h += '</div>';
    // じぶん
    if (me) {
      var when = me.alive ? 'さいごまで のこった！' : (me.fall === 'early' ? 'たたかいの はじめのほうで たおれた' : me.fall === 'mid' ? 'たたかいの まんなかまで がんばった' : 'おわりの ほうまで がんばった');
      h += '<div style="background:#fff;border:1px solid #e0e7ff;border-radius:12px;padding:8px 10px;font-size:13px;line-height:1.7;color:#334155">'
        + '<div style="font-weight:900;color:#4338ca">' + esc(me.sprite || '🐾') + ' きみの ' + esc(me.mon || 'モンスター') + '</div>'
        + '<div>' + when + '</div>'
        + '<div>てきに あたえた ダメージ <b>' + (me.dealt || 0) + '</b></div>'
        + '<div>プログラム：' + (me.auto ? 'おまかせ出陣' : (pg.empty ? 'からっぽ' : 'ブロック ' + (pg.blocks || 0) + 'こ')) + '</div>'
        + '</div>';
    }
    h += '</div>';
    // ヒント
    var tips = d.tips || [];
    if (tips.length) {
      h += '<div style="margin-top:8px;background:#fefce8;border:2px dashed #facc15;border-radius:12px;padding:8px 10px">'
        + '<div style="font-weight:900;color:#854d0e">💡 つぎの 作戦の ヒント</div>';
      tips.forEach(function (t) { h += '<div style="margin-top:4px;font-size:13px;line-height:1.7;color:#713f12">' + esc(t.icon || '・') + ' ' + esc(t.text) + '</div>'; });
      h += '</div>';
    }
    h += '<div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap">'
      + '<button type="button" id="' + ID + 'Go" style="background:#4f46e5;color:#fff;font-weight:900;border:none;border-radius:12px;padding:9px 16px;font-size:14px;cursor:pointer">🛠 プログラムを なおす</button>'
      + '</div>';
    return h;
  }

  function goEdit() {
    var box = document.getElementById('def2ProgBox');
    if (box) { try { box.scrollIntoView({ block: 'start', behavior: 'smooth' }); } catch (e) {} box.style.outline = '3px solid #facc15'; setTimeout(function () { box.style.outline = ''; }, 2500); return; }
    // 結果画面には へんしゅうが 無い → 出陣の 画面を ひらきなおす（決戦の あとは つぎの 回の 出陣画面に なる）
    try { if (typeof window._defRender === 'function') window._defRender(); } catch (e) {}
    setTimeout(function () { var b = document.getElementById('def2ProgBox'); if (b) { try { b.scrollIntoView({ block: 'start', behavior: 'smooth' }); } catch (e) {} } else { var x = document.getElementById(ID + 'Go'); if (x) x.textContent = 'つぎの 出陣の 時間に なったら なおせるよ'; } }, 600);
  }

  function place(d) {
    var body = document.getElementById('defenseBody');
    if (!body || !body.offsetParent || document.getElementById(ID)) return;
    if (!d || !d.ok || d.none || !d.tips) return;
    var rp = document.getElementById('defReplay'), pb = document.getElementById('def2ProgBox');
    var mode = rp ? 'result' : (pb ? 'entry' : null);
    if (!mode) return;
    var el = document.createElement('div');
    el.id = ID;
    el.setAttribute('style', 'background:linear-gradient(135deg,#eef2ff,#f5f3ff);border:2px solid #c7d2fe;border-radius:16px;padding:10px 12px;margin:10px 0;');
    el.innerHTML = html(d, mode);
    if (mode === 'entry') pb.parentNode.insertBefore(el, pb);
    else {
      var btn = body.querySelector('button[onclick*="_defShowReplay"]');
      if (btn && btn.parentNode) btn.parentNode.insertBefore(el, btn); else rp.parentNode.insertBefore(el, rp);
    }
    var go = document.getElementById(ID + 'Go'); if (go) go.onclick = goEdit;
  }

  function tick() {
    var body = document.getElementById('defenseBody');
    if (!body || !body.offsetParent || document.getElementById(ID)) return;
    if (!document.getElementById('defReplay') && !document.getElementById('def2ProgBox')) return;
    if (cache && Date.now() - cacheAt < 60000) { place(cache); return; }
    if (busy) return;
    busy = true;
    fetch('/api/defense/review', { credentials: 'include' })
      .then(function (r) { return r.json(); })
      .then(function (d) { cache = d; cacheAt = Date.now(); busy = false; place(d); })
      .catch(function () { busy = false; });
  }

  window.__defReview = { html: html, place: place };
  setInterval(tick, 1500);
})();
