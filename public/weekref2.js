/* 🔄 WEEKREF2_V1 週の振り返りを充実させる（子どもの画面）— 2026-10-26
 *
 *  「👆 かんたんふりかえり」（kantanref.js）の欄の中に足す。ぜんぶで 1回 3分くらいで おわる量。
 *    上：💡 友だちの見本（みんなのふりかえりの 最新の採用分を1つ・名前は同意どおり・無ければ出さない）
 *        🤝 先週 決めたこと、どうだった？（先週の「次どうする？」と今週の計画 → できた／ちょっと／できなかった ＋ わけ）
 *        📊 今週の 自分の きろく（開いた日・単元の正答の変化・計画を書いた日のうち家庭学習を出した日。事実だけ）
 *    下：🏫 学校での学び（教科 → わかったこと → もっと知りたいこと）
 *        💭 今週の 考える問い（週ごとに かわる・任意）
 *  ・提出は かんたんふりかえりの「これで 出す」と ひとまとめ（文は いつもの自由欄へ・コインは いつもの台帳で週1回）。
 *    ここでは コインを 付けない。えらんだものは /api/student/week-ref2 に 1人1週1行で のこす。
 *  ・責めない言い方。比較・順位・点・パーセントは出さない。命令形にしない。
 *  ・index.html は手で編集しない。kantanref.js が描いた欄（#wr2Top・#wr2Bottom）に入れるだけ。
 */
(function () {
  'use strict';
  if (window.__WEEKREF2_V1__) return; window.__WEEKREF2_V1__ = 1;

  var _d = null, _busy = null, _sample = null, _wk = '', _failAt = 0;
  var A = { pr: '', reason: '', note: '', qc: -1, qt: '', subj: '', theme: '', lk: '', learned: '', more: '', mk: '' };
  var _init = false;

  function esc(s) { return String(s == null ? '' : s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;'); }
  function cut(s, n) { var a = Array.from(String(s == null ? '' : s).replace(/[\r\n\t]/g, ' ').trim()); return a.length > n ? a.slice(0, n).join('') : a.join(''); }
  function jget(url) { return fetch(url, { credentials: 'include' }).then(function (r) { return r.json(); }).catch(function () { return null; }); }
  function jpost(url, body) {
    return fetch(url, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json(); }).catch(function () { return null; });
  }
  function $(id) { return document.getElementById(id); }

  // 単元の名前（CURRICULUM は index.html の正本）
  var _uidx = null;
  function unitName(id) {
    if (!_uidx) {
      _uidx = {};
      var C = null; try { if (typeof CURRICULUM !== 'undefined') C = CURRICULUM; } catch (e) {} C = C || window.CURRICULUM;
      if (C) Object.keys(C).forEach(function (sk) {
        var sub = C[sk]; if (!sub || !sub.grades) return;
        Object.keys(sub.grades).forEach(function (g) { (sub.grades[g].units || []).forEach(function (u) { _uidx[u.id] = u.name || ''; }); });
      });
    }
    return String(_uidx[id] || '');
  }

  // ───────── 読む ─────────
  function load(wk, force) {
    if (!wk) return Promise.resolve(null);
    if (!force && _d && _wk === wk) return Promise.resolve(_d);
    if (_busy && _wk === wk) return _busy;
    _wk = wk;
    _busy = Promise.all([jget('/api/student/week-ref2?weekKey=' + encodeURIComponent(wk)), jget('/api/student/minna/posts')]).then(function (rs) {
      _busy = null;
      var d = rs[0];
      if (!(d && d.ok)) _failAt = Date.now();
      if (d && d.ok) {
        _d = d;
        if (!_init && d.mine) {
          _init = true;
          var m = d.mine;
          if (m.promise) { A.pr = m.promise.result || ''; A.reason = m.promise.reason || ''; A.note = m.promise.note || ''; }
          if (m.q && d.question && m.q.id === d.question.id) { A.qc = d.question.choices.indexOf(m.q.choiceJa); A.qt = m.q.text || ''; }
          if (m.school) { A.subj = m.school.subj || ''; A.theme = m.school.theme || ''; A.learned = m.school.learned || ''; A.more = m.school.more || ''; }
        }
      }
      // 💡 友だちの見本：同じクラスの 採用された ふりかえり（自分の分は のぞく）。週の分を先に・無ければ毎日の分。
      var ps = (rs[1] && rs[1].ok && rs[1].posts) || [];
      var others = ps.filter(function (p) { return !p.mine && String(p.body || '').trim(); });
      var wkp = others.filter(function (p) { return p.kind === 'week'; });
      _sample = wkp[0] || others[0] || null;
      return _d;
    });
    return _busy;
  }

  // ───────── 文（いつもの自由欄に入る。かんたんふりかえりの文の うしろに つなぐ） ─────────
  var PR = { done: '✅ できた', some: '🌗 ちょっと', not: '🌱 できなかった' };
  var RS = { time: '⏰ 時間が なかった', forgot: '💭 わすれた', way: '🔧 やり方が 合わなかった', other: '✏️ その他' };
  function learnedList() {
    var t = A.theme;
    return t
      ? [{ k: 'know', s: '「' + t + '」の ことが わかった' }, { k: 'can', s: '「' + t + '」の 問題が できるように なった' }, { k: 'friend', s: '友だちの 考えで なるほどと 思った' }, { k: 'say', s: '自分の 考えを 言えた' }]
      : [{ k: 'know', s: '新しい ことが わかった' }, { k: 'can', s: '前より できるように なった' }, { k: 'friend', s: '友だちの 考えで なるほどと 思った' }, { k: 'say', s: '自分の 考えを 言えた' }];
  }
  var MORES = ['家で もう一度 ためしたい', 'もっと 調べたい', 'ほかの 問題でも ためしたい'];
  function end(s) { return /[。！？!?]$/.test(s) ? s : s + '。'; }
  function composeExtra() {
    if (!_d) return '';
    var out = [];
    if (A.pr) {
      var r = { done: 'できた', some: 'ちょっと できた', not: 'できなかった' }[A.pr];
      out.push('先週 決めたことは ' + r + (A.pr !== 'done' && A.reason ? '（' + RS[A.reason].replace(/^\S+\s/, '') + '）' : '') + '。' + (A.note ? end(cut(A.note, 40)) : ''));
    }
    if (A.subj) {
      var s = '学校では ' + A.subj + (A.theme ? 'の「' + A.theme + '」' : '') + 'が 心に のこった。';
      if (A.learned) s += end(cut(A.learned, 60));
      if (A.more) s += 'これから ' + end(cut(A.more, 40));
      out.push(s);
    }
    var q = _d.question;
    if (q && (A.qc >= 0 || A.qt)) out.push('「' + q.q + '」→ ' + (A.qc >= 0 ? q.choices[A.qc] : '') + (A.qt ? (A.qc >= 0 ? '・' : '') + cut(A.qt, 60) : '') + '。');
    return cut(out.join(''), 220);   // 自由欄（500字）に 本人の文が のこるように 短く。くわしくは week_ref2 に のこる
  }
  function save(wk) {
    if (!_d) return Promise.resolve(null);
    var names = {};
    (((_d.facts || {}).units) || []).forEach(function (u) { var n = unitName(u.unit); if (n) names[u.unit] = n; });
    return jpost('/api/student/week-ref2', {
      weekKey: wk || _wk,
      promise: { result: A.pr, reason: A.pr && A.pr !== 'done' ? A.reason : '', note: A.note },
      q: { id: (_d.question || {}).id || '', choice: A.qc, text: A.qt },
      school: { subj: A.subj, theme: A.theme, learned: A.learned, more: A.more },
      unitNames: names
    });
  }

  // ───────── 描く ─────────
  var CSS = '.wr2 .wbox{background:#fff;border:2px solid #fed7aa;border-radius:12px;padding:8px 10px;margin-top:8px}'
    + '.wr2 .wh{font-weight:900;font-size:14px;color:#9a3412}'
    + '.wr2 .wh small{font-weight:600;font-size:11px;color:#b45309;margin-left:4px}'
    + '.wr2 .wp{font-size:13px;line-height:1.6;color:#7c2d12;background:#fff7ed;border-radius:8px;padding:5px 8px;margin-top:4px}'
    + '.wr2 .wf{font-size:13.5px;line-height:1.75;color:#334155;margin:2px 0}'
    + '.wr2 .wsm{font-size:12px;color:#92400e;margin-top:4px}'
    + '.wr2 .wsample{background:#f0fdf4;border:1.5px dashed #86efac;border-radius:10px;padding:5px 9px;margin-top:6px;font-size:12.5px;line-height:1.55;color:#14532d}'
    + '.wr2 .kb{min-height:40px}'
    + '.wr2 .wsub{min-height:36px;min-width:58px;font-size:13px;padding:4px 8px}';
  function ensureCss() {
    if ($('wr2Css')) return;
    var st = document.createElement('style'); st.id = 'wr2Css'; st.textContent = CSS; document.head.appendChild(st);
  }
  function btn(key, val, label, on, cls) {
    return '<button type="button" class="kb' + (cls ? ' ' + cls : '') + (on ? ' on' : '') + '" data-w2="' + key + '" data-v="' + esc(val) + '">' + esc(label) + '</button>';
  }
  function factsHtml(f) {
    if (!f) return '';
    var ls = [];
    ls.push('📱 アプリを ひらいた日：<b>' + (Number(f.openDays) || 1) + '日</b>');
    (f.units || []).forEach(function (u) {
      var nm = unitName(u.unit); if (!nm || !(u.c > 0 || u.n > 0)) return;
      if (u.prevC > 0 && u.c > u.prevC) ls.push('📝 「' + esc(nm) + '」 せいかい：先週 ' + u.prevC + '問 → <b>今週 ' + u.c + '問</b>');
      else if (u.c > 0) ls.push('📝 「' + esc(nm) + '」 今週 <b>' + u.c + '問</b> せいかい');
      else ls.push('📝 「' + esc(nm) + '」に 今週 ' + u.n + '問 ちょうせん');
    });
    if (f.planDays > 0 && f.doneDays > 0) ls.push('📅 計画を 書いた ' + f.planDays + '日のうち <b>' + f.doneDays + '日</b>、家庭学習を 出したよ');
    else if (f.planDays > 0) ls.push('📅 計画を <b>' + f.planDays + '日ぶん</b> 書いたよ');
    if (f.hwDays > 0) ls.push('📒 今週の家庭学習：<b>' + f.hwDays + '日</b>');   /* TEISHUTSU_V1 カルテ・阪神マンの一言と同じ数（月〜日） */
    return '<div class="wbox"><div class="wh">📊 今週の 自分の きろく <small>（アプリの きろくから。じじつ だけ）</small></div>' + ls.map(function (x) { return '<div class="wf">' + x + '</div>'; }).join('') + '</div>';
  }
  function topHtml() {
    var d = _d; if (!d) return '<div class="wsm">よみこみ中…</div>';
    var h = '';
    if (_sample) {
      h += '<div class="wsample">💡 <b>こんなふうに 書いた人が いるよ</b>' + (_sample.name ? '　' + esc(cut(_sample.name, 12)) : '') + '<br>「' + esc(cut(_sample.body, 70)) + (Array.from(String(_sample.body)).length > 70 ? '…' : '') + '」</div>';
    }
    var pt = d.promise && d.promise.text, plan = d.plan || [];
    if (pt || plan.length) {
      h += '<div class="wbox"><div class="wh">🤝 ' + (pt ? '先週 決めたこと、どうだった？' : '今週の 計画、どうだった？') + ' <small>（どれを えらんでも だいじょうぶ）</small></div>';
      if (pt) h += '<div class="wp">先週の あなた：「' + esc(pt) + '」</div>';
      if (plan.length) h += '<div class="wp" style="background:#f8fafc;color:#334155">📅 今週の 計画：' + plan.map(function (p) { return '<b>' + esc(p.day) + '</b> ' + esc(cut(p.text, 24)); }).join('　') + '</div>';
      h += '<div class="kc" style="margin-top:6px">' + btn('pr', 'done', PR.done, A.pr === 'done', 'kbig') + btn('pr', 'some', PR.some, A.pr === 'some', 'kbig') + btn('pr', 'not', PR.not, A.pr === 'not', 'kbig') + '</div>';
      if (A.pr === 'done') h += '<div class="wsm">🎉 やりきったね。つづけられた じぶんに 拍手！</div>';
      if (A.pr === 'some' || A.pr === 'not') {
        h += '<div class="wsm">だれにでも ある ことだよ。わけが わかると、次の 計画に いかせるよ。</div><div class="kc" style="margin-top:4px">';
        Object.keys(RS).forEach(function (k) { h += btn('reason', k, RS[k], A.reason === k, 'ksm'); });
        h += '</div>';
      }
      if (A.pr) h += '<div class="kx"><input id="wr2Note" type="text" maxlength="40" placeholder="ひとこと（なくても OK）" value="' + esc(A.note) + '"></div>';
      h += '</div>';
    }
    h += factsHtml(d.facts);
    h += '<div class="wh" style="margin-top:10px">🏠 家庭学習の ふりかえり</div>';
    return h;
  }
  function bottomHtml() {
    var d = _d; if (!d) return '';
    var h = '<div class="wbox" style="border-color:#bfdbfe"><div class="wh" style="color:#1e40af">🏫 学校での 学び <small style="color:#2563eb">（今週 いちばん 心に のこった 授業は？）</small></div>';
    var tp = d.topics || [];
    if (tp.length) {
      h += '<div class="wsm" style="color:#1e40af">先生の 授業メモから：</div><div class="kc">';
      tp.forEach(function (t, i) { h += btn('topic', String(i), t.subj + '：' + t.theme, A.subj === t.subj && A.theme === t.theme, 'ksm'); });
      h += '</div>';
    }
    h += '<div class="kc" style="margin-top:4px">';
    (d.subjects || []).forEach(function (s) { h += btn('subj', s, s, A.subj === s && !A.theme, 'wsub'); });
    h += '</div>';
    if (A.subj) {
      h += '<div class="kq" style="color:#1e40af">② そこで わかったこと・できるように なったこと</div><div class="kc">';
      learnedList().forEach(function (x) { h += btn('learned', x.k, x.s, A.learned === x.s, 'ksm'); });
      h += '</div><div class="kx"><input id="wr2Learned" type="text" maxlength="60" placeholder="じぶんの ことばで（なくても OK）" value="' + esc(learnedList().some(function (x) { return x.s === A.learned; }) ? '' : A.learned) + '"></div>';
      h += '<div class="kq" style="color:#1e40af">③ もっと 知りたい・ためしたいこと <small>（なくても OK）</small></div><div class="kc">';
      MORES.forEach(function (m, i) { h += btn('more', String(i), m, A.more === m, 'ksm'); });
      h += '</div><div class="kx"><input id="wr2More" type="text" maxlength="40" placeholder="たとえば：家で 比の 問題を つくってみたい" value="' + esc(MORES.indexOf(A.more) >= 0 ? '' : A.more) + '"></div>';
    }
    h += '</div>';
    var q = d.question;
    if (q) {
      h += '<div class="wbox" style="border-color:#ddd6fe"><div class="wh" style="color:#5b21b6">💭 今週の 考える問い <small style="color:#7c3aed">（こたえなくても OK）</small></div>';
      h += '<div class="wf" style="font-weight:800;color:#4c1d95">' + esc(q.q) + '</div><div class="kc">';
      q.choices.forEach(function (c, i) { h += btn('qc', String(i), c, A.qc === i, 'ksm'); });
      h += '</div><div class="kx"><input id="wr2Qt" type="text" maxlength="60" placeholder="じぶんの ことばで（なくても OK）" value="' + esc(A.qt) + '"></div></div>';
    }
    return h;
  }
  function changed() { try { if (typeof window.__kantanUpd === 'function') window.__kantanUpd(); } catch (e) {} }
  function bind(root) {
    var bs = root.querySelectorAll('[data-w2]');
    for (var i = 0; i < bs.length; i++) bs[i].onclick = function () {
      var k = this.getAttribute('data-w2'), v = this.getAttribute('data-v');
      if (k === 'pr') { A.pr = A.pr === v ? '' : v; if (A.pr === 'done' || !A.pr) A.reason = ''; }
      else if (k === 'reason') A.reason = A.reason === v ? '' : v;
      else if (k === 'topic') { var t = (_d.topics || [])[Number(v)]; if (t) { var same = A.subj === t.subj && A.theme === t.theme; A.subj = same ? '' : t.subj; A.theme = same ? '' : t.theme; A.learned = ''; } }
      else if (k === 'subj') { var on = A.subj === v && !A.theme; A.subj = on ? '' : v; A.theme = ''; A.learned = ''; }
      else if (k === 'learned') { var x = learnedList().filter(function (y) { return y.k === v; })[0]; A.learned = (x && A.learned !== x.s) ? x.s : ''; }
      else if (k === 'more') { var m = MORES[Number(v)]; A.more = A.more === m ? '' : m; }
      else if (k === 'qc') { var n = Number(v); A.qc = A.qc === n ? -1 : n; }
      mount(); changed();
    };
    var map = { wr2Note: 'note', wr2Learned: 'learned', wr2More: 'more', wr2Qt: 'qt' };
    Object.keys(map).forEach(function (id) {
      var el = $(id); if (!el || !root.contains(el)) return;
      el.oninput = function () {
        var v = String(this.value || '').replace(/[\r\n\t]/g, ' ');
        if (id === 'wr2Learned' && !v.trim()) { if (!learnedList().some(function (x) { return x.s === A.learned; })) A.learned = ''; changed(); return; }
        if (id === 'wr2More' && !v.trim()) { if (MORES.indexOf(A.more) < 0) A.more = ''; changed(); return; }
        A[map[id]] = v.trim();
        if (id === 'wr2Learned' || id === 'wr2More') {   // 自分で書いたら ボタンの えらびは はずす（見た目だけ）
          var cls = id === 'wr2Learned' ? 'learned' : 'more';
          var on = root.querySelectorAll('[data-w2="' + cls + '"].on'); for (var j = 0; j < on.length; j++) on[j].classList.remove('on');
        }
        changed();
      };
    });
  }
  function mount(wk) {
    var top = $('wr2Top'), bot = $('wr2Bottom');
    if (!top && !bot) return;
    ensureCss();
    if (wk && wk !== _wk) { _d = null; _init = false; }
    if (!_d) {
      if (Date.now() - _failAt < 30000) { if (top) top.innerHTML = ''; if (bot) bot.innerHTML = ''; return; }   // 読めなかったときは しばらく出さない（いつもの かんたんふりかえりは そのまま使える）
      if (top) top.innerHTML = '<div class="wsm">よみこみ中…</div>';
      load(wk || _wk).then(function () { if (_d) { mount(); changed(); } });
      return;
    }
    if (top) { top.className = 'wr2'; top.innerHTML = topHtml(); bind(top); }
    if (bot) { bot.className = 'wr2'; bot.innerHTML = bottomHtml(); bind(bot); }
  }
  // 月曜の計画（📒 わたしのカルテの要点）に出す：先週の 約束の結果・学校での学び
  function lastHtml() {
    var l = _d && _d.last; if (!l) return '';
    var h = '';
    if (l.promise && l.promise.resultJa) h += '<div style="font-size:12.5px;margin-top:4px">🤝 先週の 約束：<b>' + esc(l.promise.resultJa) + '</b>' + (l.promise.reasonJa ? '（' + esc(l.promise.reasonJa) + '）' : '') + (l.promise.text ? ' ／「' + esc(cut(l.promise.text, 30)) + '」' : '') + '</div>';
    if (l.school && l.school.subj) h += '<div style="font-size:12.5px;margin-top:2px">🏫 学校で 心に のこった：<b>' + esc(l.school.subj) + (l.school.theme ? '「' + esc(l.school.theme) + '」' : '') + '</b>' + (l.school.more ? ' → もっと：' + esc(cut(l.school.more, 30)) : '') + '</div>';
    return h;
  }

  window.WEEKREF2 = { mount: mount, load: load, composeExtra: composeExtra, save: save, lastHtml: lastHtml, _state: A };
})();
