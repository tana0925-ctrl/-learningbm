/* ===================================================================
   ai-flow.js  —  AIFLOW_V1 「今日のひと往復」に、前の流れを入れる
   ------------------------------------------------------------------
   ・前の回までに先生が公開した返事（カルテ・家庭学習コメント・計画アドバイス…）の書き出しと、
     AIが書いて先生が公開した「流れのメモ」（[FLOW:児童ID]・事実だけ1〜2文）を、
     次のコピーで子どもごとに「先週までの流れ（直近4週）」として入れる。
   ・名前は入れない（束はいまの仕組みどおり符号）。1人あたりの文字数に上限あり。
   ・外部AIは一時チャットで使い捨てでよい（流れはアプリが覚えている）。
   ・teacher-ai.js からは window.AI_FLOW を通してだけ呼ばれる（無ければ今までどおり動く）。
   =================================================================== */
(function () {
  'use strict';
  var PER_CHILD_MAX = 520;   // 1人ぶんの「流れ」の文字数の上限
  var WEEKS = 4;
  var KJA = { FLOW: '変化のメモ', KARTE: 'カルテ', DAILY: '家庭学習コメント', PLAN: '計画アドバイス', REFLECT: '振り返りの返事', SUGGEST: 'おすすめ計画', WORK: '📓成果物へのひとこと', WORKMEMO: '成果物の分析メモ' };
  var _byUser = {}, _cid = '', _ok = false;

  function $(id) { return document.getElementById(id); }
  function mask(t) { t = String(t || ''); try { if (window._qnMask) t = window._qnMask(t); } catch (e) {} return t; }
  function mondayOf(ymd) {
    var p = String(ymd || '').split('-'); if (p.length < 3) return '';
    var d = new Date(Date.UTC(+p[0], +p[1] - 1, +p[2]));
    var wd = (d.getUTCDay() + 6) % 7;
    d = new Date(d.getTime() - wd * 86400000);
    return (d.getUTCMonth() + 1) + '/' + d.getUTCDate();
  }

  function enabled() { var e = $('taiOptFlow'); return e ? !!e.checked : true; }

  async function prefetch(cid) {
    _byUser = {}; _cid = cid; _ok = false;
    try {
      var r = await fetch('/api/teacher/ai-flow?classId=' + encodeURIComponent(cid) + '&days=' + (WEEKS * 7), { credentials: 'include' });
      var d = await r.json().catch(function () { return null; });
      if (d && d.ok) { _byUser = d.byUser || {}; _ok = true; }
    } catch (e) {}
    return _ok;
  }

  function ruleLines(withFlowBlock) {
    var o = [
      '【前の流れをふまえる】',
      '・各児童の【先週までの流れ】は、前の回までに先生が公開した返事の書き出しと、変化のメモです（アプリが残している記録）。',
      '・前の流れをふまえて、くり返しにならないように書いてください。同じ話題・同じほめ方・同じ問いかけは避ける。',
      '  前に言ったことの「つづき」や「その後どうなったか」にふれるのは、くり返しではなく、つながりです。',
      '・流れに書かれていないことを、前に言ったことにしないでください。'
    ];
    if (withFlowBlock) {
      o.push('・=== [FLOW:...] === の欄には、この子の今週の変化を、記録にある事実だけで1〜2文（80字以内）で書いてください。');
      o.push('  先生だけが見るメモで、次回の【先週までの流れ】に入ります。見立て・評価・ほめ言葉・符号は書かない。');
      o.push('  例：「火・木に計算ドリルを各15分。前の週より出した日が1日ふえた。振り返りに『わり算が速くなった』と書いた。」');
    }
    o.push('');
    return o;
  }

  // want.karte のときは、カルテは別の欄（前に渡したカルテ・全文）で渡っているので書き出しは入れない
  function linesFor(uid, want) {
    if (!_ok) return [];
    var recs = (_byUser[String(uid)] || []).slice();
    var head = '【先週までの流れ（アプリに残した記録・直近' + WEEKS + '週・新しい順）】';
    if (!recs.length) return ['', head, '・まだ記録がありません（はじめての回として書いてください）'];
    var byWk = {}, order = [];
    recs.forEach(function (r) {
      if (want && want.karte && r.kind === 'KARTE') return;
      var w = mondayOf(r.at);
      if (!w) return;
      if (!byWk[w]) { byWk[w] = []; order.push(w); }
      byWk[w].push(r);
    });
    var out = ['', head], used = 0, cut = false;
    for (var i = 0; i < order.length && i < WEEKS; i++) {
      var w = order[i], list = byWk[w];
      var flow = list.filter(function (x) { return x.kind === 'FLOW'; });
      var memo = list.filter(function (x) { return x.kind === 'WORKMEMO'; });   /* PORTFOLIO_AI_V1 */
      var rest = list.filter(function (x) { return x.kind !== 'FLOW' && x.kind !== 'WORKMEMO'; });
      var lines = ['・' + w + 'の週'];
      flow.slice(0, 1).forEach(function (x) { lines.push('　変化: ' + mask(x.text)); });
      memo.slice(0, 1).forEach(function (x) { lines.push('　ノート・作品（写真の分析）: ' + mask(x.text)); });
      var seen = {};
      rest.forEach(function (x) {
        if (seen[x.kind]) return;   // 同じ種類は週に1つ（いちばん新しいもの）
        seen[x.kind] = 1;
        lines.push('　' + (KJA[x.kind] || x.kind) + '「' + mask(x.text) + '」');
      });
      for (var j = 0; j < lines.length; j++) {
        if (used + lines[j].length > PER_CHILD_MAX) { cut = true; break; }
        out.push(lines[j]); used += lines[j].length;
      }
      if (cut) break;
    }
    if (out.length === 2) out.push('・（カルテは下の【前に渡したカルテ】を見てください）');
    if (cut) out.push('（長いので ここまで）');
    return out;
  }

  // ④で公開した文を「実際に公開した文」に合わせる
  async function saveFinal(picks, okIds) {
    try {
      var ok = {}; (okIds || []).forEach(function (x) { ok[String(x)] = 1; });
      var items = (picks || []).filter(function (p) { return ok[String(p.id)]; }).map(function (p) { return { id: p.id, body: p.body }; });
      if (!items.length) return;
      await fetch('/api/teacher/ai-flow/final', { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ items: items }) });
    } catch (e) {}
  }

  // 画面：①に「流れを入れる」チェックと、一時チャットのおすすめを1行
  function mountUi() {
    try {
      if ($('taiOptFlow')) return;
      var anchor = $('taiOptSuggest');
      if (!anchor) return;
      var row = anchor.closest ? anchor.closest('div') : anchor.parentNode.parentNode;
      var lab = document.createElement('label');
      lab.className = 'flex items-center gap-1';
      lab.innerHTML = '<input type="checkbox" id="taiOptFlow" checked class="accent-indigo-600"> 🧵 先週までの流れ（直近4週）＋変化のメモ';
      row.appendChild(lab);
      var st = $('taiStatus');
      if (st && st.parentNode) {
        var tip = document.createElement('p');
        tip.id = 'taiFlowTip';
        tip.className = 'text-xs text-slate-500 mt-2';
        tip.textContent = '💡 外部AIは「一時チャット」（履歴に残らないモード）での利用をおすすめします。前の流れはアプリが覚えていて、毎回コピーに入ります。';
        st.parentNode.appendChild(tip);
      }
    } catch (e) {}
  }

  window.AI_FLOW = { enabled: enabled, prefetch: prefetch, ruleLines: ruleLines, linesFor: linesFor, saveFinal: saveFinal, mountUi: mountUi, _set: function (m) { _byUser = m || {}; _ok = true; } };
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mountUi); else mountUi();
})();
