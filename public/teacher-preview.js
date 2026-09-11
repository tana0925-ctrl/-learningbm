/* ===================================================================
   teacher-preview.js — 👀 児童画面プレビュー（先生用）
   -------------------------------------------------------------------
   先生の言葉：「子供の画面にどうでてるかよくわからないんだよね」

   ・児童を1人えらぶと、その子の画面に「先生から届くもの」が
     今どう出ているかを、スマホの幅のまま並べて見せる。
   ・完全に読み取り専用。このファイルは GET しか出さない。
     ボタンもリンクも「閉じる」「再読み込み」以外は置かない。
     コイン消費・受け取り・既読・ミッション達成は一切起こらない。
   ・再現度より正確さを優先。
     「実際には出ていないのにプレビューでは出ている」を作らない。
     公開していない／データが無い場合は、はっきり「出ていません」と書く。
   ・サーバーから見えないもの（端末の localStorage・端末内の学習データ）は
     「ここは先生の画面からは分かりません」と正直に書く。
   ・ポーリングなし。開いたときと「再読み込み」を押したときだけ取りにいく。
   =================================================================== */
(function () {
  'use strict';

  /* ---------------- 読み取り専用の入口（このファイル唯一の通信） ----------------
     method は GET 固定。body も付けない。ここ以外から通信しない。 */
  function getJSON(url) {
    return fetch(url, { method: 'GET', credentials: 'include', cache: 'no-store' })
      .then(function (r) { return r.json(); })
      .catch(function () { return null; });
  }

  function esc(s) {
    return String(s == null ? '' : s)
      .split('&').join('&amp;')
      .split('<').join('&lt;')
      .split('>').join('&gt;')
      .split('"').join('&quot;');
  }
  function nl(s) { return esc(s).split('\n').join('<br>'); }
  function $(id) { return document.getElementById(id); }
  function len(s) { return Array.from(String(s == null ? '' : s)).length; }

  function jdate(v) {
    if (v == null || v === '' || v === 0) return '';
    var d;
    if (typeof v === 'number') d = new Date(v);
    else if (/^\d+$/.test(String(v))) d = new Date(Number(v));
    else d = new Date(String(v).replace(' ', 'T') + (String(v).indexOf('Z') < 0 && String(v).indexOf('+') < 0 ? 'Z' : ''));
    if (isNaN(d.getTime())) return String(v);
    var j = new Date(d.getTime() + 9 * 3600000);
    return (j.getUTCMonth() + 1) + '/' + j.getUTCDate() + ' ' +
      String(j.getUTCHours()).padStart(2, '0') + ':' + String(j.getUTCMinutes()).padStart(2, '0');
  }

  /* ---------------- 状態チップ ---------------- */
  var CHIP = {
    on:      ['bg-emerald-100 text-emerald-800 border-emerald-300', '🟢 出ています'],
    empty:   ['bg-slate-100 text-slate-600 border-slate-300',       '⚪ まだ何も出ていません'],
    unpub:   ['bg-rose-100 text-rose-800 border-rose-300',          '🔒 未公開（子どもには出ていません）'],
    off:     ['bg-rose-100 text-rose-800 border-rose-300',          '🚫 設定でこの画面ごと出ていません'],
    wait:    ['bg-amber-100 text-amber-900 border-amber-300',       '⏳ 子どもが受け取るまで本文は出ません'],
    stale:   ['bg-amber-100 text-amber-900 border-amber-300',       '📅 前の週のものが出ています'],
    unknown: ['bg-violet-100 text-violet-800 border-violet-300',    '❔ 先生の画面からは確かめられません']
  };
  function chip(kind, override) {
    var c = CHIP[kind] || CHIP.empty;
    return '<span class="inline-block border rounded-full px-2 py-0.5 text-[11px] font-bold ' + c[0] + '">' +
      esc(override || c[1]) + '</span>';
  }

  /* 長さの目安。スマホだと 200字を超えると読みにくい。 */
  function lenBadge(s) {
    var n = len(s);
    if (!n) return '';
    var cls = n > 300 ? 'bg-rose-100 text-rose-800 border-rose-300'
      : n > 200 ? 'bg-amber-100 text-amber-900 border-amber-300'
        : 'bg-slate-100 text-slate-600 border-slate-300';
    var note = n > 300 ? '（長すぎ）' : n > 200 ? '（やや長い）' : '';
    return '<span class="inline-block border rounded-full px-2 py-0.5 text-[11px] font-bold ' + cls + '">' +
      n + '字' + note + '</span>';
  }

  /* セクションの外枠。title・状態・補足・中身。 */
  function sec(title, chipHtml, noteHtml, innerHtml) {
    return '<div class="mb-3 rounded-xl border border-slate-200 bg-white overflow-hidden">' +
      '<div class="px-3 py-2 bg-slate-50 border-b border-slate-200 flex items-center gap-2 flex-wrap">' +
      '<span class="font-bold text-sm text-slate-800">' + esc(title) + '</span>' + (chipHtml || '') +
      '</div>' +
      (noteHtml ? '<div class="px-3 py-1.5 text-[11px] text-slate-600 bg-slate-50 border-b border-slate-100">' + noteHtml + '</div>' : '') +
      '<div class="p-3">' + (innerHtml || '') + '</div>' +
      '</div>';
  }
  function nothing(msg) {
    return '<div class="text-sm text-slate-500 py-2 text-center">' + esc(msg || 'まだ何も出ていません。') + '</div>';
  }
  /* 児童画面の見た目に寄せた箱 */
  function card(cls, inner) {
    return '<div class="rounded-xl border-2 p-3 ' + cls + '">' + inner + '</div>';
  }

  /* ---------------- 画面の組み立て ---------------- */

  function renderSettings(d) {
    var k = d.klass;
    if (!k) return sec('⚙️ クラスの設定', chip('unknown'), null, nothing('クラス情報を読めませんでした。'));
    var rows = [];
    rows.push(['家庭学習', k.homeworkEnabled !== 0]);
    rows.push(['連絡帳', k.contactEnabled !== 0]);
    var menus = null;
    try { menus = k.menusEnabled ? (typeof k.menusEnabled === 'string' ? JSON.parse(k.menusEnabled) : k.menusEnabled) : null; } catch (e) {}
    var NAMES = { status: 'ステータス', training: 'トレーニング', mail: 'メール', battle: 'バトル', friend: 'ともだち', shop: 'ショップ', lab: 'けんきゅうじょ', pokedex: 'ずかん', box: 'ボックス', ranking: 'ランキング' };
    var offList = [];
    if (menus) {
      Object.keys(NAMES).forEach(function (key) {
        if (menus[key] === false || menus[key] === 0) offList.push(NAMES[key]);
      });
    }
    var anyOff = (k.homeworkEnabled === 0) || (k.contactEnabled === 0) || offList.length > 0;
    var h = '<div class="grid grid-cols-2 gap-2 text-sm">';
    rows.forEach(function (r) {
      h += '<div class="flex items-center justify-between rounded-lg border px-2 py-1.5 ' +
        (r[1] ? 'border-emerald-200 bg-emerald-50' : 'border-rose-300 bg-rose-50') + '">' +
        '<span class="font-bold text-slate-700">' + esc(r[0]) + '</span>' +
        '<span class="text-xs font-bold ' + (r[1] ? 'text-emerald-700' : 'text-rose-700') + '">' +
        (r[1] ? '出ています' : '出ていません') + '</span></div>';
    });
    h += '</div>';
    if (offList.length) {
      h += '<div class="mt-2 rounded-lg border border-rose-300 bg-rose-50 p-2 text-sm">' +
        '<span class="font-bold text-rose-800">消しているメニュー：</span> ' + esc(offList.join('、')) +
        '<div class="text-[11px] text-rose-700 mt-1">このタブ自体が子どもの画面にありません。</div></div>';
    }
    return sec('⚙️ この子に出ている画面（クラス設定）',
      chip(anyOff ? 'off' : 'on', anyOff ? '🚫 消している画面があります' : '🟢 ぜんぶ出ています'),
      'ここが OFF だと、中身があってもタブごと見えません。「届いていない」の原因になりやすいところです。', h);
  }

  function renderPlanBlock(d) {
    var it = d.items, h = '';
    var weekNote = d.isThisWeek ? '' :
      '<b class="text-rose-700">いま見ているのは今週ではありません。</b>子どもの画面には今週ぶんしか出ないので、この週の内容は子どもからは見えません。';

    /* 📋 先生からの計画アドバイス */
    var p = it.planAiComment;
    h += sec('📋 先生からの計画アドバイス',
      chip(!d.isThisWeek ? 'off' : (p.present ? 'on' : 'empty'), !d.isThisWeek ? '🚫 今週ではないので出ません' : null),
      (weekNote || '家庭学習の「今週の計画」の上に、むらさきの箱で出ます。今週ぶんだけ出ます。') +
      (p.at ? ' <span class="text-slate-500">（書いた時刻 ' + esc(jdate(p.at)) + '）</span>' : ''),
      p.present
        ? card('border-violet-300 bg-violet-50',
          '<div class="font-bold text-violet-700 text-sm">📋 先生からの計画アドバイス</div>' +
          '<div class="text-xs text-slate-700 mt-1" style="white-space:pre-wrap">' + nl(p.text) + '</div>') +
          '<div class="mt-2">' + lenBadge(p.text) + '</div>'
        : nothing('この週の計画アドバイスは入っていません。'));

    /* 🐯 今週の阪神マンのおすすめ */
    var s = it.planSuggestion;
    h += sec('🐯 今週の阪神マンのおすすめ',
      chip(!d.isThisWeek ? 'off' : (s.present ? 'on' : 'empty'), !d.isThisWeek ? '🚫 今週ではないので出ません' : null),
      (weekNote || '計画のすぐ上に、黄色い箱で出ます。今週ぶんだけ出ます。') +
      (s.at ? ' <span class="text-slate-500">（書いた時刻 ' + esc(jdate(s.at)) + '）</span>' : ''),
      s.present
        ? card('border-yellow-400 bg-yellow-50',
          '<div class="font-bold text-yellow-900 text-sm">🐯 今週の阪神マンのおすすめ</div>' +
          '<div class="text-xs text-slate-700 mt-1" style="white-space:pre-wrap">' + nl(s.text) + '</div>' +
          '<div class="text-[10px] text-slate-400 mt-1">※ あくまで参考。自分で計画を立ててみよう！</div>') +
          '<div class="mt-2">' + lenBadge(s.text) + '</div>'
        : nothing('この週のおすすめは入っていません。'));

    /* 🎉 計画の承認 */
    var a = it.planApproved;
    h += sec('🎉 今週の計画が承認されました',
      chip(a.approved ? 'unknown' : 'empty', a.approved ? '❔ 受け取り済みなら消えています' : null),
      '承認するとお祝いの箱が出ますが、<b>子どもが「受け取る！」を押すとその端末から消えます</b>。押したかどうかは端末の中にしか残らないため、先生の画面からは分かりません。',
      a.approved
        ? card('border-emerald-400 bg-emerald-50',
          '<div class="font-bold text-emerald-700 text-sm">🎉 今週の計画が承認されました！</div>' +
          '<div class="text-sm font-bold text-orange-600 mt-1">報酬: コイン300枚 ＋ かけら5個</div>' +
          '<div class="mt-1 text-[11px] text-slate-500">' + (a.at ? '承認 ' + esc(jdate(a.at)) : '') + '</div>')
        : nothing('この週の計画はまだ承認していません。'));

    /* 🎉 振り返りの返却 */
    var r = it.reflectionReturn;
    h += sec('🎉 週の振り返りへの返却',
      chip(r.returnedAt ? (r.present ? 'unknown' : 'empty') : 'empty', r.returnedAt && r.present ? '❔ 受け取り済みなら消えています' : null),
      '返却するとコメント入りの箱が出ますが、<b>子どもが「受け取る！」を押すとコメントごと消えます</b>。押したかどうかは先生の画面からは分かりません。',
      r.returnedAt
        ? card('border-orange-400 bg-orange-50',
          '<div class="font-bold text-orange-700 text-sm">🎉 振り返りが返却されました！</div>' +
          (r.present ? '<div class="text-xs text-emerald-700 bg-emerald-50 rounded p-1.5 border border-emerald-200 mt-1" style="white-space:pre-wrap">💬 ' + nl(r.comment) + '</div>' : '') +
          '<div class="text-sm font-bold text-orange-600 mt-1">報酬: コイン300枚 ＋ かけら5個</div>') +
          (r.present ? '<div class="mt-2">' + lenBadge(r.comment) + '</div>' : '')
        : nothing('この週の振り返りはまだ返していません。'));

    return h;
  }

  function renderKarte(d) {
    var k = d.items.karte;
    if (!k.published) {
      return sec('📒 わたしのカルテ', chip('unpub'),
        'カルテは<b>「公開」した子にだけ</b>出ます。この子はまだ公開していないので、ホーム画面にカルテの箱そのものが出ていません。' +
        (k.teacherMessage ? '<br><b class="text-rose-700">先生からのメッセージは書いてありますが、未公開なので子どもには届いていません。</b>' : ''),
        nothing('カルテは子どもの画面に出ていません。'));
    }
    var DOW = ['月', '火', '水', '木', '金'];
    var cells = '';
    for (var i = 0; i < 5; i++) {
      var s = k.week.days[i], mark = '・';
      if (s) mark = (s.weather === 'sun') ? '☀️' : (s.weather === 'cloud') ? '☁️' : (s.weather === 'rain') ? '🌧️' : '⭕';
      cells += '<div style="text-align:center;flex:1;min-width:38px">' +
        '<div style="font-size:11px;color:#64748b;font-weight:700">' + DOW[i] + '</div>' +
        '<div style="font-size:22px;line-height:1.2">' + mark + '</div></div>';
    }
    var inner = '<div class="font-bold text-amber-700">📒 わたしのカルテ</div>' +
      '<div class="mt-2 rounded-xl border-2 border-amber-200 bg-amber-50 p-3">' +
      '<div style="display:flex;gap:6px;align-items:flex-end">' + cells + '</div>' +
      '<div class="mt-2 text-sm font-bold text-amber-800">今週は 5日のうち ' + k.week.done + '日 とりくめたよ' +
      (k.week.minutes ? '（ぜんぶで ' + k.week.minutes + '分）' : '') + '</div>';
    if (k.week.voices && k.week.voices.length) {
      inner += '<div class="mt-2"><div class="text-xs font-bold text-amber-700">🗣 じぶんのことば</div><ul class="text-sm text-gray-700 list-disc pl-5">';
      k.week.voices.forEach(function (v) { inner += '<li>' + esc(v) + '</li>'; });
      inner += '</ul></div>';
    }
    var r = k.reflection;
    if (r && (r.goodPoint || r.improvePoint || r.nextAction)) {
      inner += '<div class="mt-2 text-sm text-gray-700"><div class="text-xs font-bold text-amber-700">📝 今週のふりかえり</div>';
      if (r.goodPoint) inner += '<div>よかったこと … ' + esc(r.goodPoint) + '</div>';
      if (r.improvePoint) inner += '<div>もうすこしなこと … ' + esc(r.improvePoint) + '</div>';
      if (r.nextAction) inner += '<div>つぎにやること … ' + esc(r.nextAction) + '</div>';
      inner += '</div>';
    }
    if (k.teacherMessage) {
      inner += '<div class="mt-3 rounded-xl bg-white border border-amber-200 p-3">' +
        '<div class="text-xs font-bold text-amber-700">👩‍🏫 先生から</div>' +
        '<div class="text-sm text-gray-800" style="white-space:pre-wrap">' + nl(k.teacherMessage) + '</div></div>';
    }
    inner += '<div class="text-xs text-gray-500 mt-2">※ 先生が読んで、わたしてくれたものだよ。</div></div>';

    return sec('📒 わたしのカルテ', chip('on'),
      '公開 ' + esc(jdate(k.sharedAt)) + '。ホーム（ステータス画面）に出ます。' +
      (k.teacherMessage ? '' : '<br><b>「先生から」の欄は空です。</b>カルテの箱は出ていますが、先生のことばは入っていません。'),
      inner + (k.teacherMessage ? '<div class="mt-2">' + lenBadge(k.teacherMessage) + '</div>' : ''));
  }

  function renderHomework(d) {
    var list = d.items.homework || [];
    var off = d.klass && d.klass.homeworkEnabled === 0;
    if (off) {
      return sec('✍️ 家庭学習の返却コメント', chip('off'),
        'クラス設定で家庭学習を OFF にしているため、この子の画面に家庭学習そのものがありません。',
        nothing('家庭学習の画面が出ていません。'));
    }
    var returned = list.filter(function (r) { return r.returnedAt; });
    if (!returned.length) {
      return sec('✍️ 家庭学習の返却コメント', chip('empty'), '返却するとシートの「先生から」に出ます。',
        nothing('まだ1件も返却していません。'));
    }
    var waiting = returned.filter(function (r) { return !r.rewardClaimed; }).length;
    var h = '';
    returned.forEach(function (r) {
      var seen = !!r.rewardClaimed;
      h += '<div class="mb-2 rounded-xl border-2 ' + (seen ? 'border-emerald-200 bg-emerald-50' : 'border-amber-300 bg-amber-50') + ' p-3">' +
        '<div class="flex items-center justify-between gap-2 flex-wrap">' +
        '<span class="font-bold text-sm text-slate-800">' + esc(r.dayKey) + '</span>' +
        chip(seen ? 'on' : 'wait', seen ? '🟢 本文が出ています' : '⏳ 赤いバッジだけ／本文はまだ') +
        '</div>' +
        (r.teacherComment
          ? '<div class="mt-2 rounded-lg bg-white border border-slate-200 p-2 text-sm text-slate-800" style="white-space:pre-wrap">' + nl(r.teacherComment) + '</div>' +
            '<div class="mt-1">' + lenBadge(r.teacherComment) + '</div>'
          : '<div class="mt-2 text-sm text-slate-500">コメントは空のまま返却しています。</div>') +
        '<div class="mt-1 text-[11px] text-slate-500">返却 ' + esc(jdate(r.returnedAt)) +
        (seen ? '／子どもは受け取り済み' : '／子どもはまだ受け取っていません') + '</div>' +
        '</div>';
    });
    return sec('✍️ 家庭学習の返却コメント',
      chip(waiting ? 'wait' : 'on', waiting ? '⏳ ' + waiting + '件は本文がまだ出ていません' : null),
      '返却した直後は<b>赤いバッジが出るだけ</b>で、コメント本文はまだ読めません。' +
      '子どもが「受け取る」を押した瞬間に、はじめてシートの「先生から」に入ります。', h);
  }

  function renderMessages(d) {
    var list = d.items.messages || [];
    if (!list.length) {
      return sec('📩 先生からのメッセージ', chip('empty'), 'メール画面に出ます。',
        nothing('先生から送ったメッセージはありません。'));
    }
    var unread = list.filter(function (m) { return !m.readAt; }).length;
    var h = '';
    list.forEach(function (m) {
      h += '<div class="mb-2 rounded-xl border ' + (m.readAt ? 'border-slate-200 bg-white' : 'border-sky-300 bg-sky-50') + ' p-3">' +
        '<div class="flex items-center justify-between gap-2 flex-wrap">' +
        '<span class="font-bold text-xs text-slate-600">' + esc(jdate(m.createdAt)) + '</span>' +
        '<span class="text-[11px] font-bold ' + (m.readAt ? 'text-slate-500' : 'text-sky-700') + '">' +
        (m.readAt ? '既読 ' + esc(jdate(m.readAt)) : '未読') + '</span></div>' +
        '<div class="mt-1 text-sm text-slate-800" style="white-space:pre-wrap">' + nl(m.body) + '</div></div>';
    });
    return sec('📩 先生からのメッセージ', chip('on', unread ? '🟢 出ています（未読 ' + unread + '件）' : null),
      'メール画面に出ます。家庭学習コメントを直したときの自動連絡もここに入ります。', h);
  }

  function renderAnnouncements(d) {
    var list = d.items.announcements || [];
    if (!list.length) {
      return sec('📢 おしらせ', chip('empty'), 'おしらせ画面に出ます。',
        nothing('おしらせは1件も作られていません。'));
    }
    var unread = list.filter(function (m) { return !m.readAt; }).length;
    var h = '';
    list.forEach(function (m) {
      h += '<div class="mb-2 rounded-xl border ' + (m.readAt ? 'border-slate-200 bg-white' : 'border-indigo-300 bg-indigo-50') + ' p-3">' +
        '<div class="flex items-center justify-between gap-2 flex-wrap">' +
        '<span class="font-bold text-sm text-slate-800">' + esc(m.title) + (m.wholeSchool ? ' <span class="text-[10px] text-slate-500">(全体)</span>' : '') + '</span>' +
        '<span class="text-[11px] font-bold ' + (m.readAt ? 'text-slate-500' : 'text-indigo-700') + '">' + (m.readAt ? '既読' : '未読') + '</span></div>' +
        '<div class="mt-1 text-sm text-slate-700" style="white-space:pre-wrap">' + nl(m.body) + '</div>' +
        '<div class="mt-1 text-[11px] text-slate-500">' + esc(jdate(m.createdAt)) + '</div></div>';
    });
    return sec('📢 おしらせ', chip('on', unread ? '🟢 出ています（未読 ' + unread + '件）' : null), null, h);
  }

  function renderContactNotes(d) {
    var list = d.items.contactNotes || [];
    if (d.klass && d.klass.contactEnabled === 0) {
      return sec('📮 連絡帳', chip('off'),
        'クラス設定で連絡帳を OFF にしているため、この子の画面に連絡帳がありません。',
        nothing('連絡帳の画面が出ていません。'));
    }
    if (!list.length) {
      return sec('📮 連絡帳', chip('empty'), null, nothing('連絡帳はまだ書かれていません。'));
    }
    var unread = list.filter(function (m) { return !m.readAt; }).length;
    var h = '';
    list.forEach(function (m) {
      h += '<div class="mb-2 rounded-xl border ' + (m.readAt ? 'border-slate-200 bg-white' : 'border-teal-300 bg-teal-50') + ' p-3">' +
        '<div class="flex items-center justify-between gap-2 flex-wrap">' +
        '<span class="font-bold text-sm text-slate-800">' + esc(m.dayKey) + '</span>' +
        '<span class="text-[11px] font-bold ' + (m.readAt ? 'text-slate-500' : 'text-teal-700') + '">' + (m.readAt ? '既読' : '未読') + '</span></div>' +
        '<div class="mt-1 text-sm text-slate-700" style="white-space:pre-wrap">' + nl(m.body) + '</div></div>';
    });
    return sec('📮 連絡帳', chip('on', unread ? '🟢 出ています（未読 ' + unread + '件）' : null), null, h);
  }

  function renderMenu(d) {
    var w = d.items.weeklyMenu;
    var off = d.klass && d.klass.homeworkEnabled === 0;
    if (off) {
      return sec('📋 今週のメニュー', chip('off'), '家庭学習を OFF にしているため、メニューも出ていません。',
        nothing('メニューの画面が出ていません。'));
    }
    if (!w.menu) {
      return sec('📋 今週のメニュー', chip('empty'), null,
        card('border-amber-300 bg-amber-50',
          '<div class="text-amber-700 font-bold text-sm text-center">📋 先生からの今週のメニューがまだ届いていません</div>' +
          '<div class="text-xs text-amber-600 mt-1 text-center">メニューが届くと、計画を書き込めるようになります</div>'));
    }
    var m = w.menu;
    var rows = [['漢字', m.kanjiPage], ['計算', m.keisanPage], ['その他', m.otherTasks], ['テスト', m.tests]];
    var inner = '';
    if (!w.published) {
      inner += card('border-amber-300 bg-amber-50',
        '<div class="text-amber-700 font-bold text-sm text-center">📋 先生からの今週のメニューがまだ届いていません</div>' +
        '<div class="text-xs text-amber-600 mt-1 text-center">前の週（' + esc(w.fallbackWeek) + '）の計画を表示しています</div>') + '<div class="h-2"></div>';
    }
    inner += '<div class="rounded-xl border-2 border-sky-200 bg-sky-50 p-3 text-sm">';
    rows.forEach(function (r) {
      inner += '<div class="flex gap-2 py-0.5"><span class="font-bold text-sky-800 w-14 shrink-0">' + esc(r[0]) + '</span>' +
        '<span class="text-slate-700">' + (r[1] ? nl(r[1]) : '<span class="text-slate-400">（なし）</span>') + '</span></div>';
    });
    inner += '</div>';
    return sec('📋 今週のメニュー', chip(w.published ? 'on' : 'stale'),
      w.published ? null : '<b class="text-rose-700">今週ぶんが未配信です。</b>子どもの画面には前の週の内容がそのまま出ているので、今週の課題と取りちがえることがあります。',
      inner);
  }

  function renderMission(d) {
    var m = d.items.classMission;
    if (!m) return sec('🎯 クラスミッション', chip('empty'), null, nothing('クラスミッションはありません。'));
    var ended = m.endAt && (new Date(String(m.endAt).replace(' ', 'T') + 'Z').getTime() < Date.now());
    var visible = !ended || !m.claimed;
    return sec('🎯 クラスミッション', chip(visible ? 'on' : 'empty', visible ? null : '⚪ 締切済み・受取済みなので出ていません'),
      '進み具合は問題を解いた数から数えるため、ここでは数えません（数えるとD1の読み取りが増えるためです）。',
      card('border-indigo-300 bg-indigo-50',
        '<div class="font-bold text-indigo-800 text-sm">🎯 ' + esc(m.title) + '</div>' +
        '<div class="text-sm text-slate-700 mt-1">目標 ' + m.goalCorrect + '問／ごほうび コイン' + m.rewardCoins + '・かけら' + m.rewardShards + '</div>' +
        '<div class="text-[11px] text-slate-500 mt-1">' +
        (m.endAt ? '締切 ' + esc(jdate(m.endAt)) : '締切なし') +
        (m.claimed ? '／この子は受け取り済み' : '／この子はまだ受け取っていません') + '</div>'));
  }

  function renderRewards(d) {
    var a = d.items.rankingRewardsUnseen, b = d.items.defenseRewardsUnseen;
    if (!a && !b) return '';
    var h = '';
    if (a) h += '<div class="text-sm text-slate-700">🏆 ランキングのごほうび：未確認 ' + a + '件</div>';
    if (b) h += '<div class="text-sm text-slate-700">🛡 ぼうえいせんのごほうび：未確認 ' + b + '件</div>';
    return sec('🎁 ごほうびのお知らせ', chip('on'),
      '先生が書いたものではありませんが、子どもの画面には「先生から届いたもの」と並んで出ます。', h);
  }

  function renderUnknown() {
    return sec('❔ ここは先生の画面からは確かめられません', chip('unknown'), null,
      '<ul class="list-disc pl-5 text-sm text-slate-700 space-y-1">' +
      '<li>お祝いの箱（計画の承認・振り返りの返却）を子どもが<b>もう閉じたかどうか</b>。端末の中にしか残りません。</li>' +
      '<li>家庭学習シートに<b>すでに書き込まれたコメント</b>。受け取ったときに端末へ保存されるので、サーバーからは追えません。</li>' +
      '<li>ずかん・持ち物・コインなど、<b>学習データそのもの</b>。このプレビューでは一切読みません。</li>' +
      '</ul>');
  }

  function renderAll(d) {
    var s = d.student;
    var head = '<div class="mb-3 rounded-xl border border-slate-300 bg-slate-50 p-3">' +
      '<div class="font-bold text-slate-800">' + esc(s.name) + '<span class="text-xs text-slate-500 ml-2">' + esc(s.loginId || '') + '</span></div>' +
      '<div class="text-[11px] text-slate-600 mt-1">' +
      '週 ' + esc(d.weekKey) + (d.isThisWeek ? '（今週）' : '（今週ではありません）') +
      '／最後のログイン ' + (s.lastLoginAt ? esc(jdate(s.lastLoginAt)) : 'きろくなし') +
      '／取得 ' + esc(jdate(d.generatedAt)) + '</div></div>';

    return head +
      renderSettings(d) +
      renderMenu(d) +
      renderPlanBlock(d) +
      renderKarte(d) +
      renderHomework(d) +
      renderMessages(d) +
      renderAnnouncements(d) +
      renderContactNotes(d) +
      renderMission(d) +
      renderRewards(d) +
      renderUnknown();
  }

  /* ---------------- 枠（モーダル） ---------------- */

  var _classes = [], _members = [], _loading = false;

  function buildUI() {
    if ($('tspOverlay')) return;

    var btn = document.createElement('button');
    btn.id = 'tspOpenBtn';
    btn.type = 'button';
    btn.className = 'fixed bottom-4 right-4 z-[9998] bg-sky-600 hover:bg-sky-700 text-white font-black rounded-full shadow-lg px-5 py-3 text-sm';
    btn.textContent = '👀 児童画面プレビュー';
    btn.onclick = openModal;
    document.body.appendChild(btn);

    var ov = document.createElement('div');
    ov.id = 'tspOverlay';
    ov.className = 'fixed inset-0 z-[9999] bg-black/50 hidden';
    ov.innerHTML =
      '<div class="absolute inset-0 flex items-start justify-center p-2 sm:p-6 overflow-auto">' +
      '<div class="bg-white rounded-2xl shadow-2xl w-full max-w-3xl">' +
      '<div class="px-4 py-3 border-b border-slate-200 flex items-center gap-2 flex-wrap">' +
      '<div class="font-black text-slate-800">👀 児童画面プレビュー</div>' +
      '<div class="text-[11px] text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-full px-2 py-0.5 font-bold">読み取り専用</div>' +
      '<div class="ml-auto flex gap-2">' +
      '<button type="button" id="tspReload" class="px-3 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-bold">再読み込み</button>' +
      '<button type="button" id="tspClose" class="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-black text-white text-xs font-bold">閉じる</button>' +
      '</div></div>' +
      '<div class="px-4 py-3 border-b border-slate-200 flex gap-2 flex-wrap items-center">' +
      '<select id="tspClass" class="border border-slate-300 rounded-lg px-2 py-1.5 text-sm"></select>' +
      '<select id="tspStudent" class="border border-slate-300 rounded-lg px-2 py-1.5 text-sm min-w-[10rem]"></select>' +
      '<span class="text-[11px] text-slate-500">この画面からは何も書き換わりません。</span>' +
      '</div>' +
      '<div class="p-3 bg-slate-100">' +
      '<div class="mx-auto bg-white rounded-2xl border-4 border-slate-800 overflow-hidden" style="max-width:375px">' +
      '<div id="tspBody" class="p-3" style="max-height:70vh;overflow:auto"></div>' +
      '</div>' +
      '<div class="text-center text-[11px] text-slate-500 mt-2">スマホと同じ幅（375px）で出しています。文の長さの見え方もこのままです。</div>' +
      '</div></div></div>';
    document.body.appendChild(ov);

    $('tspClose').onclick = closeModal;
    $('tspReload').onclick = function () { load(true); };
    $('tspClass').onchange = function () { loadMembers($('tspClass').value); };
    $('tspStudent').onchange = function () { load(false); };
    ov.addEventListener('click', function (e) { if (e.target === ov) closeModal(); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && ov && !ov.classList.contains('hidden')) closeModal();
    });
  }

  function openModal() {
    buildUI();
    $('tspOverlay').classList.remove('hidden');
    if (!_classes.length) loadClasses();
  }
  function closeModal() {
    var ov = $('tspOverlay');
    if (ov) ov.classList.add('hidden');
  }
  function body(html) { var b = $('tspBody'); if (b) b.innerHTML = html; }

  function loadClasses() {
    body('<div class="text-center text-sm text-slate-500 py-8">クラスを読み込み中…</div>');
    getJSON('/api/teacher/classes').then(function (d) {
      if (!d || !d.ok || !d.classes || !d.classes.length) {
        body('<div class="text-center text-sm text-slate-500 py-8">担任しているクラスがありません。</div>');
        return;
      }
      _classes = d.classes;
      var sel = $('tspClass');
      sel.innerHTML = _classes.map(function (c) {
        return '<option value="' + esc(c.id) + '">' + esc(c.name) + '</option>';
      }).join('');
      loadMembers(_classes[0].id);
    });
  }

  function loadMembers(classId) {
    if (!classId) return;
    body('<div class="text-center text-sm text-slate-500 py-8">名簿を読み込み中…</div>');
    getJSON('/api/teacher/class/' + encodeURIComponent(classId) + '/members').then(function (d) {
      var sel = $('tspStudent');
      if (!d || !d.ok || !d.members || !d.members.length) {
        _members = [];
        sel.innerHTML = '';
        body('<div class="text-center text-sm text-slate-500 py-8">このクラスに児童がいません。</div>');
        return;
      }
      _members = d.members;
      sel.innerHTML = _members.map(function (m) {
        return '<option value="' + esc(m.userId) + '">' + esc(m.name) + '</option>';
      }).join('');
      load(false);
    });
  }

  function load(force) {
    if (_loading) return;
    var sid = $('tspStudent') ? $('tspStudent').value : '';
    if (!sid) return;
    _loading = true;
    body('<div class="text-center text-sm text-slate-500 py-8">読み込み中…</div>');
    getJSON('/api/teacher/student-screen-preview?studentId=' + encodeURIComponent(sid) + (force ? '&t=' + Date.now() : ''))
      .then(function (d) {
        _loading = false;
        if (!d || !d.ok) {
          body('<div class="text-center text-sm text-rose-600 py-8">読み込めませんでした。' +
            (d && d.error ? '<br><span class="text-xs">' + esc(d.error) + '</span>' : '') + '</div>');
          return;
        }
        try { body(renderAll(d)); }
        catch (e) { body('<div class="text-center text-sm text-rose-600 py-8">表示に失敗しました。</div>'); }
      });
  }

  /* ---------------- 起動（/teacher のときだけ） ---------------- */
  function init() {
    try {
      if (location.pathname.indexOf('/teacher') !== 0) return;
      buildUI();
      window.openStudentScreenPreview = openModal;
    } catch (e) {}
  }
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () { setTimeout(init, 400); });
  } else {
    setTimeout(init, 400);
  }
})();
