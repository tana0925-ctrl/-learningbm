/* ===================================================================
   teacher-mi.js : 「MIしらべ」先生用（/teacher-mi ページ専用）
   - サーバー側は requireTeacher の内側。未認証は401。
   - 実名表示は既存の /api/teacher/real-names（admin_settings.real_name_map）を使う。
     児童向けページ(/mi)には実名を一切渡さない。
   =================================================================== */
(function (global) {
  'use strict';

  var DOMAINS = [
    { key: 'lang',   name: '言語・語学',   short: '言語', color: '#f97316' },
    { key: 'logic',  name: '論理・数学',   short: '論理', color: '#3b82f6' },
    { key: 'nature', name: '自然・博物学', short: '自然', color: '#22c55e' },
    { key: 'intra',  name: '内省',         short: '内省', color: '#8b5cf6' },
    { key: 'visual', name: '視覚・空間',   short: '視覚', color: '#ec4899' },
    { key: 'body',   name: '身体・運動',   short: '身体', color: '#ef4444' },
    { key: 'music',  name: '音楽・リズム', short: '音楽', color: '#14b8a6' },
    { key: 'inter',  name: '対人',         short: '対人', color: '#eab308' }
  ];
  var Q = [
    '本を読むのが好きです（マンガ以外）。','算数の問題を解くのが好きです。','おもちゃや虫など、特定の物をたくさん集めるのが好きです。','日記を書きます。',
    '図や絵を描いて説明してもらうとわかりやすいです。','身体を動かすのが好きです。','楽器を演奏するのが好きです。','友だちといっしょに勉強するのが好きです。',
    '作文や物語を書くのが得意です。','ものごとの仕組みが気になります。','家や学校で、動物や植物の世話をしています。','自分の得意なことと、苦手なことがはっきりわかっています。',
    '絵を描くのが好きです。','友だちに話すとき、ジェスチャーをたくさん使います。','歌を歌うのが好きです。','グループのリーダーを任されます。',
    '人や物の名前、場所や日付を覚えることができます。','なぞなぞやパズルなど、頭を使う遊びが好きです。','新しいことや物を、じっくりと調べるのが好きです。','自分の気持ちを、きちんと人に伝えることができます。',
    '物の長さや重さなどが、見ただけでほぼ正確にわかります。','人の動きをまねすることが得意です。','歌のメロディーをすぐに覚えられます。','だれとでもすぐ友だちになれます。',
    '人の話を聞いたり、人前で話をしたりすることが好きです。','計画を立てて、毎日少しずつ勉強しています。','ふしぎに思ったことを、よく図鑑や本で調べます。','その日にあった出来事を、よく夜にふりかえります。',
    'レゴのようなブロックや積木で遊ぶのが好きです。','図工の作品は、できるだけ丁寧に作りたいです。','他の人の声を聞いて、どんな気持ちなのかがわかります。','他の人の表情を見て、どんな気持ちなのかがわかります。'
  ];
  var CHOICE_LABEL = { 1: 'まったくあてはまらない', 2: '少し当てはまる', 3: 'だいたい当てはまる', 4: 'とても当てはまる' };

  var nameMap = {};
  var classes = [];
  var curClassId = '';
  var curData = null;

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }
  function jget(u) {
    return fetch(u, { credentials: 'same-origin' }).then(function (r) {
      return r.json().then(function (j) { j = j || {}; j.__status = r.status; return j; })
        .catch(function () { return { ok: false, __status: r.status }; });
    }).catch(function () { return { ok: false, __status: 0 }; });
  }
  function rn(loginId, fallback) {
    if (loginId && nameMap[loginId]) return nameMap[loginId];
    return fallback || loginId || '';
  }
  function fmtDate(iso) {
    if (!iso) return '';
    try {
      var s = String(iso);
      var d = new Date(s.replace(' ', 'T') + (s.indexOf('Z') < 0 && s.indexOf('+') < 0 ? 'Z' : ''));
      if (isNaN(d.getTime())) return s.slice(0, 16);
      var jp = new Date(d.getTime() + 9 * 3600 * 1000);
      var p = function (n) { return (n < 10 ? '0' : '') + n; };
      return jp.getUTCFullYear() + '/' + p(jp.getUTCMonth() + 1) + '/' + p(jp.getUTCDate()) + ' ' + p(jp.getUTCHours()) + ':' + p(jp.getUTCMinutes());
    } catch (e) { return String(iso).slice(0, 16); }
  }

  // ---------------- クラス一覧 ----------------
  function renderClassSelect() {
    var sel = document.getElementById('miClassSel');
    var h = '<option value="">クラスを選択…</option>';
    for (var i = 0; i < classes.length; i++) {
      h += '<option value="' + esc(classes[i].id) + '">' + esc(classes[i].name) + '</option>';
    }
    sel.innerHTML = h;
    sel.onchange = function () { curClassId = sel.value; loadClass(); };
  }

  function loadClass() {
    var box = document.getElementById('miBody');
    if (!curClassId) { box.innerHTML = '<p class="text-sm text-slate-400">クラスを選んでください。</p>'; return; }
    box.innerHTML = '<p class="text-sm text-slate-400">読み込み中…</p>';
    jget('/api/teacher/mi/class/' + encodeURIComponent(curClassId)).then(function (d) {
      if (!d || !d.ok) {
        box.innerHTML = '<p class="text-sm text-red-600">読み込み失敗（' + (d && d.__status === 401 ? '未認証。ログインし直してください' : (d && d.error) || 'エラー') + '）</p>';
        return;
      }
      curData = d;
      renderClass(d);
    });
  }

  function renderClass(d) {
    var sts = d.students || [];
    var done = 0, notyet = [];
    for (var i = 0; i < sts.length; i++) { if (sts[i].latest) done++; else notyet.push(sts[i]); }

    var h = '';
    // 実施状況
    h += '<div class="flex flex-wrap items-center gap-2 mb-3">';
    h += '<span class="bg-emerald-100 text-emerald-700 rounded-full px-3 py-1 text-xs font-bold">実施ずみ ' + done + '人</span>';
    h += '<span class="bg-slate-100 text-slate-500 rounded-full px-3 py-1 text-xs font-bold">未実施 ' + notyet.length + '人</span>';
    h += '<span class="text-xs text-slate-400">合計 ' + sts.length + '人</span>';
    h += '<button id="miCsv" class="ml-auto bg-slate-800 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-black">⬇ CSVで書き出す</button>';
    h += '</div>';

    if (notyet.length) {
      h += '<div class="bg-amber-50 border border-amber-200 rounded-xl p-3 mb-3">';
      h += '<div class="text-xs font-bold text-amber-800 mb-1">まだ実施していない児童（' + notyet.length + '人）</div>';
      h += '<div class="text-xs text-amber-700">';
      var nn = [];
      for (var n = 0; n < notyet.length; n++) nn.push(esc(rn(notyet[n].loginId, notyet[n].name)));
      h += nn.join('、');
      h += '</div></div>';
    }

    // クラス平均
    if (done > 0) {
      h += '<div class="border border-slate-200 rounded-xl p-3 mb-4">';
      h += '<div class="font-bold text-sm text-slate-700 mb-2">📊 クラス全体の領域別平均（実施ずみ ' + done + '人・各16点満点）</div>';
      for (var a = 0; a < DOMAINS.length; a++) {
        var dm = DOMAINS[a];
        var av = Number((d.average || {})[dm.key] || 0);
        h += '<div class="mb-1.5"><div class="flex justify-between text-xs font-bold"><span class="text-slate-600">' + esc(dm.name) + '</span><span style="color:' + dm.color + '">' + av.toFixed(1) + '</span></div>';
        h += '<div class="h-2.5 rounded-full bg-slate-100 overflow-hidden"><div style="width:' + Math.round(av / 16 * 100) + '%;height:100%;background:' + dm.color + '"></div></div></div>';
      }
      h += '<div class="text-xs text-slate-400 mt-2">左（言語＋論理＋自然＋内省）平均 <b>' + Number(d.averageLeft || 0).toFixed(1) + '</b> ／ 右（視覚＋身体＋音楽＋対人）平均 <b>' + Number(d.averageRight || 0).toFixed(1) + '</b>（各64点満点）</div>';
      h += '</div>';
    }

    // 一覧表
    h += '<div class="overflow-x-auto border border-slate-200 rounded-xl">';
    h += '<table class="w-full text-xs whitespace-nowrap"><thead><tr class="bg-slate-50 text-slate-500">';
    h += '<th class="text-left p-2 sticky left-0 bg-slate-50">児童</th>';
    for (var t = 0; t < DOMAINS.length; t++) h += '<th class="p-2">' + esc(DOMAINS[t].short) + '</th>';
    h += '<th class="p-2">左</th><th class="p-2">右</th><th class="p-2">受検日</th><th class="p-2">回数</th></tr></thead><tbody>';
    for (var s = 0; s < sts.length; s++) {
      var st = sts[s];
      var nm = rn(st.loginId, st.name);
      h += '<tr class="border-t border-slate-100 hover:bg-indigo-50 cursor-pointer" data-uid="' + esc(st.userId) + '" data-nm="' + esc(nm) + '">';
      h += '<td class="p-2 font-bold text-slate-700 sticky left-0 bg-white">' + esc(nm) + '</td>';
      if (!st.latest) {
        h += '<td class="p-2 text-slate-300 text-center" colspan="' + (DOMAINS.length + 2) + '">未実施</td><td class="p-2 text-slate-300">-</td><td class="p-2 text-center text-slate-300">0</td>';
      } else {
        var mx = 0;
        for (var q = 0; q < DOMAINS.length; q++) mx = Math.max(mx, Number(st.latest.scores[DOMAINS[q].key] || 0));
        for (var w = 0; w < DOMAINS.length; w++) {
          var v = Number(st.latest.scores[DOMAINS[w].key] || 0);
          var top = (v === mx);
          h += '<td class="p-2 text-center ' + (top ? 'font-black' : 'text-slate-600') + '" style="' + (top ? 'color:' + DOMAINS[w].color + ';background:' + DOMAINS[w].color + '18' : '') + '">' + v + '</td>';
        }
        h += '<td class="p-2 text-center text-indigo-600 font-bold">' + st.latest.left + '</td>';
        h += '<td class="p-2 text-center text-pink-600 font-bold">' + st.latest.right + '</td>';
        h += '<td class="p-2 text-slate-400">' + esc(fmtDate(st.latest.takenAt)) + '</td>';
        h += '<td class="p-2 text-center text-slate-500">' + st.count + '</td>';
      }
      h += '</tr>';
    }
    h += '</tbody></table></div>';
    h += '<p class="text-xs text-slate-400 mt-2">行をクリックすると、その児童の32問の生回答と履歴が見られます。</p>';
    h += '<div id="miDetail" class="mt-4"></div>';

    document.getElementById('miBody').innerHTML = h;

    var csv = document.getElementById('miCsv');
    if (csv) csv.onclick = function () { downloadCsv(); };

    var rows = document.querySelectorAll('tr[data-uid]');
    for (var r = 0; r < rows.length; r++) {
      rows[r].onclick = function () {
        showStudent(this.getAttribute('data-uid'), this.getAttribute('data-nm'));
      };
    }
  }

  // ---------------- 個人詳細 ----------------
  function showStudent(userId, name) {
    var box = document.getElementById('miDetail');
    box.innerHTML = '<p class="text-sm text-slate-400">読み込み中…</p>';
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
    jget('/api/teacher/mi/student/' + encodeURIComponent(userId)).then(function (d) {
      if (!d || !d.ok) { box.innerHTML = '<p class="text-sm text-red-600">読み込み失敗</p>'; return; }
      var at = d.attempts || [];
      var h = '<div class="border-2 border-indigo-200 rounded-xl p-4 bg-indigo-50/40">';
      h += '<div class="flex items-center justify-between mb-2"><div class="font-black text-indigo-800">🧭 ' + esc(name) + ' さんの MIしらべ（' + at.length + '回）</div>';
      h += '<button id="miDetClose" class="text-xs text-slate-400 underline">閉じる</button></div>';
      if (!at.length) {
        h += '<p class="text-sm text-slate-500">まだ実施していません。</p>';
      } else {
        // 履歴の推移
        if (at.length > 1) {
          h += '<div class="bg-white rounded-xl p-3 mb-3 overflow-x-auto"><div class="font-bold text-xs text-slate-600 mb-1">履歴（新しい順）</div>';
          h += '<table class="w-full text-xs whitespace-nowrap"><thead><tr class="text-slate-400"><th class="text-left p-1">受検日</th>';
          for (var t = 0; t < DOMAINS.length; t++) h += '<th class="p-1">' + esc(DOMAINS[t].short) + '</th>';
          h += '<th class="p-1">左</th><th class="p-1">右</th></tr></thead><tbody>';
          for (var i = 0; i < at.length; i++) {
            h += '<tr class="border-t border-slate-100"><td class="p-1 text-slate-500">' + esc(fmtDate(at[i].takenAt)) + '</td>';
            for (var j = 0; j < DOMAINS.length; j++) h += '<td class="p-1 text-center font-bold text-slate-700">' + Number(at[i].scores[DOMAINS[j].key] || 0) + '</td>';
            h += '<td class="p-1 text-center text-indigo-600 font-bold">' + at[i].left + '</td><td class="p-1 text-center text-pink-600 font-bold">' + at[i].right + '</td></tr>';
          }
          h += '</tbody></table></div>';
        }
        // 最新回の生回答
        var last = at[0];
        h += '<div class="bg-white rounded-xl p-3">';
        h += '<div class="font-bold text-xs text-slate-600 mb-2">最新回（' + esc(fmtDate(last.takenAt)) + '）の32問の回答</div>';
        h += '<div class="grid grid-cols-1 sm:grid-cols-2 gap-x-4">';
        for (var k = 0; k < 32; k++) {
          var v = Number((last.answers || [])[k] || 0);
          var col = v >= 4 ? '#16a34a' : v === 3 ? '#65a30d' : v === 2 ? '#f59e0b' : '#94a3b8';
          h += '<div class="flex items-start gap-2 text-xs border-b border-slate-50 py-1">';
          h += '<span class="shrink-0 text-slate-400 w-5 text-right">' + (k + 1) + '</span>';
          h += '<span class="flex-1 text-slate-600">' + esc(Q[k]) + '</span>';
          h += '<span class="shrink-0 font-black" style="color:' + col + '">' + (v || '-') + '</span></div>';
        }
        h += '</div>';
        h += '<div class="text-[10px] text-slate-400 mt-2">1=' + CHOICE_LABEL[1] + '／2=' + CHOICE_LABEL[2] + '／3=' + CHOICE_LABEL[3] + '／4=' + CHOICE_LABEL[4] + '</div>';
        h += '</div>';
      }
      h += '</div>';
      box.innerHTML = h;
      var cb = document.getElementById('miDetClose');
      if (cb) cb.onclick = function () { box.innerHTML = ''; };
    });
  }

  // ---------------- CSV ----------------
  function downloadCsv() {
    if (!curData) return;
    var sts = curData.students || [];
    var head = ['児童名', 'ログインID', '受検日時', '受検回数'];
    for (var i = 0; i < DOMAINS.length; i++) head.push(DOMAINS[i].name);
    head.push('左脳（言語+論理+自然+内省）', '右脳（視覚+身体+音楽+対人）');
    for (var q = 1; q <= 32; q++) head.push('Q' + q);
    var esq = function (v) {
      var s = (v == null ? '' : String(v));
      if (/[\n\r",]/.test(s)) return '"' + s.replace(/"/g, '""') + '"';
      return s;
    };
    var lines = [head.map(esq).join(',')];
    for (var s = 0; s < sts.length; s++) {
      var st = sts[s];
      var row = [rn(st.loginId, st.name), st.loginId, st.latest ? fmtDate(st.latest.takenAt) : '', st.count || 0];
      for (var d = 0; d < DOMAINS.length; d++) row.push(st.latest ? Number(st.latest.scores[DOMAINS[d].key] || 0) : '');
      row.push(st.latest ? st.latest.left : '', st.latest ? st.latest.right : '');
      for (var a = 0; a < 32; a++) row.push(st.latest && st.latest.answers ? (st.latest.answers[a] || '') : '');
      lines.push(row.map(esq).join(','));
    }
    var cname = '';
    for (var c = 0; c < classes.length; c++) if (classes[c].id === curClassId) cname = classes[c].name;
    var blob = new Blob(['﻿' + lines.join('\r\n')], { type: 'text/csv;charset=utf-8;' });
    var a2 = document.createElement('a');
    a2.href = URL.createObjectURL(blob);
    a2.download = 'MIしらべ_' + (cname || 'class') + '_' + new Date().toISOString().slice(0, 10) + '.csv';
    document.body.appendChild(a2); a2.click(); document.body.removeChild(a2);
    setTimeout(function () { URL.revokeObjectURL(a2.href); }, 3000);
  }

  // ---------------- 起動 ----------------
  function boot() {
    var box = document.getElementById('miBody');
    if (!box) return;
    jget('/api/auth/me').then(function (me) {
      if (!me || !me.user || (me.user.role !== 'teacher' && me.user.role !== 'admin')) {
        document.getElementById('miRoot').innerHTML =
          '<div class="bg-white rounded-xl shadow p-6 text-center"><p class="font-bold text-slate-700 mb-3">先生のアカウントでログインしてください。</p><a href="/login" class="inline-block bg-emerald-600 text-white rounded-lg px-5 py-2 font-bold">ログインへ</a></div>';
        return;
      }
      jget('/api/teacher/real-names').then(function (d) {
        if (d && d.ok) nameMap = d.map || {};
        return jget('/api/teacher/classes');
      }).then(function (d) {
        classes = (d && d.classes) || [];
        renderClassSelect();
        if (classes.length === 1) {
          curClassId = classes[0].id;
          document.getElementById('miClassSel').value = curClassId;
          loadClass();
        }
      });
    });
  }

  if (document.readyState !== 'loading') boot();
  else document.addEventListener('DOMContentLoaded', boot);

})(typeof window !== 'undefined' ? window : globalThis);
