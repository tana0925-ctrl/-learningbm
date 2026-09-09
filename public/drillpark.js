/* ドリルパーク（外部ドリル教材）エクセル取り込み — 教師画面用
 *
 * ・xlsx は ZIP なので、ブラウザの DecompressionStream('deflate-raw') だけで展開する。
 *   （CDN も 900KB のライブラリも足さない。学校の回線・フィルタに依存させないため）
 * ・児童との紐づけは、既存のテスト取り込みと同じ _matchRosterRows() を使う。
 *   ここでは 362 行ではなく「その中に出てくる児童（22人）」だけを照合するので、
 *   先生の確認は1回で済む。
 * ・1問ごとの正誤は answers 文字列（'1101...'）としてそのまま持ち回る。
 *
 * window.DrillPark に公開。/teacher の画面から呼ぶ。
 */
(function () {
  'use strict';

  // ===== 1. ZIP =====
  function u16(b, o) { return b[o] | (b[o + 1] << 8); }
  function u32(b, o) { return ((b[o] | (b[o + 1] << 8) | (b[o + 2] << 16)) + b[o + 3] * 16777216); }

  // 末尾から End Of Central Directory を探し、中央ディレクトリを読む。
  function zipEntries(buf) {
    var b = new Uint8Array(buf);
    var eocd = -1;
    var min = Math.max(0, b.length - 66000);
    for (var i = b.length - 22; i >= min; i--) {
      if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 0x05 && b[i + 3] === 0x06) { eocd = i; break; }
    }
    if (eocd < 0) throw new Error('ZIPとして読めません（xlsxファイルか確認してください）');
    var n = u16(b, eocd + 10);
    var off = u32(b, eocd + 16);
    var out = {};
    var p = off;
    for (var k = 0; k < n; k++) {
      if (b[p] !== 0x50 || b[p + 1] !== 0x4b || b[p + 2] !== 0x01 || b[p + 3] !== 0x02) break;
      var method = u16(b, p + 10);
      var csize = u32(b, p + 20);
      var nlen = u16(b, p + 28);
      var elen = u16(b, p + 30);
      var clen = u16(b, p + 32);
      var lho = u32(b, p + 42);
      var name = new TextDecoder('utf-8').decode(b.subarray(p + 46, p + 46 + nlen));
      out[name] = { method: method, csize: csize, lho: lho };
      p += 46 + nlen + elen + clen;
    }
    return { bytes: b, entries: out };
  }

  async function zipRead(z, name) {
    var e = z.entries[name];
    if (!e) return null;
    var b = z.bytes;
    // ローカルヘッダの可変長を読んでデータ開始位置を出す
    var p = e.lho;
    if (b[p] !== 0x50 || b[p + 1] !== 0x4b || b[p + 2] !== 0x03 || b[p + 3] !== 0x04) throw new Error('ZIPの構造が想定と違います');
    var start = p + 30 + u16(b, p + 26) + u16(b, p + 28);
    var data = b.subarray(start, start + e.csize);
    if (e.method === 0) return new TextDecoder('utf-8').decode(data);
    if (e.method !== 8) throw new Error('未対応の圧縮方式です（' + e.method + '）');
    if (typeof DecompressionStream === 'undefined') throw new Error('このブラウザでは解凍できません。Chrome か Edge の新しい版でお試しください');
    var ds = new DecompressionStream('deflate-raw');
    var stream = new Blob([data]).stream().pipeThrough(ds);
    return await new Response(stream).text();
  }

  // ===== 2. XML =====
  function unesc(s) {
    if (s.indexOf('&') < 0) return s;
    return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'")
      .replace(/&#x([0-9a-fA-F]+);/g, function (_, h) { return String.fromCodePoint(parseInt(h, 16)); })
      .replace(/&#(\d+);/g, function (_, d) { return String.fromCodePoint(parseInt(d, 10)); })
      .replace(/&amp;/g, '&');
  }

  // 共有文字列。<rPh>（ふりがな）の中にも <t> があるので、先に落とす。
  // これを忘れると「伊藤　芽衣」が「伊藤　芽衣イトウメイ」になる。
  function parseSharedStrings(xml) {
    var out = [];
    if (!xml) return out;
    var re = /<si>([\s\S]*?)<\/si>/g, m;
    while ((m = re.exec(xml))) {
      var body = m[1].replace(/<rPh[\s\S]*?<\/rPh>/g, '').replace(/<rPh[^>]*\/>/g, '');
      var s = '', tm, tre = /<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g;
      while ((tm = tre.exec(body))) s += unesc(tm[1]);
      out.push(s);
    }
    return out;
  }

  function colNum(ref) { // 'AB11' -> 28
    var n = 0;
    for (var i = 0; i < ref.length; i++) {
      var ch = ref.charCodeAt(i);
      if (ch < 65 || ch > 90) break;
      n = n * 26 + (ch - 64);
    }
    return n;
  }

  // シートを「行番号 -> 列番号 -> 文字列」に落とす
  function parseSheet(xml, sst) {
    var rows = {};
    var rre = /<row[^>]*\sr="(\d+)"[^>]*>([\s\S]*?)<\/row>/g, rm;
    while ((rm = rre.exec(xml))) {
      var rno = parseInt(rm[1], 10);
      var cells = {};
      var cre = /<c\s([^>]*?)(?:\/>|>([\s\S]*?)<\/c>)/g, cm;
      while ((cm = cre.exec(rm[2]))) {
        var attr = cm[1], inner = cm[2] || '';
        var rf = attr.match(/r="([A-Z]+\d+)"/); if (!rf) continue;
        var t = (attr.match(/t="([^"]*)"/) || [, ''])[1];
        var val = '';
        if (t === 'inlineStr') {
          var im = inner.replace(/<rPh[\s\S]*?<\/rPh>/g, '');
          var tm2, tre2 = /<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g;
          while ((tm2 = tre2.exec(im))) val += unesc(tm2[1]);
        } else {
          var vm = inner.match(/<v>([\s\S]*?)<\/v>/);
          if (!vm) continue;
          var raw = unesc(vm[1]);
          if (t === 's') { var si = parseInt(raw, 10); val = (sst[si] != null) ? sst[si] : ''; }
          else val = raw;
        }
        if (val === '') continue;
        cells[colNum(rf[1])] = val;
      }
      rows[rno] = cells;
    }
    return rows;
  }

  // ===== 3. ドリルパークの形に読む =====
  var HEADER_ROW = 10;   // 10行目が列見出し、11行目以降がデータ
  var COL = { date: 1, time: 2, cls: 3, no: 4, name: 5, subject: 6, drillNo: 7, material: 8, useType: 9, drillKind: 10, sec: 11, rate: 12 };
  var Q_FIRST = 13;      // M列 = 問1

  function half(s) {
    return String(s == null ? '' : s).replace(/[Ａ-Ｚａ-ｚ０-９]/g, function (c) { return String.fromCharCode(c.charCodeAt(0) - 65248); });
  }
  function ymd(s) {
    var t = half(s).trim().replace(/[.\/年月]/g, '-').replace(/日/g, '').replace(/-+$/, '');
    var m = t.match(/^(\d{4})-(\d{1,2})-(\d{1,2})/);
    if (!m) return '';
    var p = function (x) { return (x.length < 2 ? '0' : '') + x; };
    return m[1] + '-' + p(m[2]) + '-' + p(m[3]);
  }
  function hms(s) {
    var t = half(s).trim();
    var m = t.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
    if (m) { var p = function (x) { return (String(x).length < 2 ? '0' : '') + x; }; return p(m[1]) + ':' + m[2] + ':' + (m[3] || '00'); }
    // 数値（1日を1とした割合）で入っていることもある
    var f = parseFloat(t);
    if (!isNaN(f) && f >= 0 && f < 1) {
      var sec = Math.round(f * 86400), q = function (x) { return (x < 10 ? '0' : '') + x; };
      return q(Math.floor(sec / 3600)) + ':' + q(Math.floor(sec / 60) % 60) + ':' + q(sec % 60);
    }
    return '';
  }
  function toSec(s) {
    var t = half(s).trim(); if (!t) return null;
    var m = t.match(/^(\d{1,3}):(\d{2})(?::(\d{2}))?$/);
    if (m) return parseInt(m[1], 10) * 3600 + parseInt(m[2], 10) * 60 + parseInt(m[3] || '0', 10);
    var f = parseFloat(t);
    if (isNaN(f)) return null;
    // 1未満なら「1日あたりの割合」、それ以上なら秒とみなす
    return (f < 1) ? Math.round(f * 86400) : Math.round(f);
  }
  function toPct(s) {
    var t = half(s).trim(); if (!t) return null;
    if (t.charAt(t.length - 1) === '%') { var i = parseInt(t, 10); return isNaN(i) ? null : i; }
    var f = parseFloat(t);
    if (isNaN(f)) return null;
    return (f >= 0 && f <= 1) ? Math.round(f * 100) : Math.round(f);
  }

  // 1行分。answers は 1問目から順に '1'(正答)/'0'(誤答)。未出題は末尾を切り落とす。
  function readRow(cells) {
    var name = String(cells[COL.name] || '').trim();
    var date = ymd(cells[COL.date]);
    if (!name || !date) return null;
    var ans = '', total = 0, correct = 0;
    for (var q = 1; q <= 99; q++) {
      var v = cells[Q_FIRST + q - 1];
      if (v == null || String(v).trim() === '') { ans += '-'; continue; }
      var s = half(String(v)).trim();
      if (s === '1') { ans += '1'; total++; correct++; }
      else if (s === '0') { ans += '0'; total++; }
      else ans += '-';
    }
    ans = ans.replace(/-+$/, '');
    var noRaw = half(cells[COL.no]);
    var noInt = parseInt(noRaw, 10);
    return {
      doneOn: date,
      startedAt: hms(cells[COL.time]),
      classLabel: String(cells[COL.cls] || '').trim(),
      attendanceNo: isNaN(noInt) ? null : noInt,
      rawName: name,
      subject: String(cells[COL.subject] || '').trim(),
      drillNo: String(cells[COL.drillNo] || '').trim(),
      material: String(cells[COL.material] || '').trim(),
      useType: String(cells[COL.useType] || '').trim(),
      drillKind: String(cells[COL.drillKind] || '').trim(),
      answerSec: toSec(cells[COL.sec]),
      ratePct: toPct(cells[COL.rate]),
      answers: ans,
      totalQ: total,
      correctQ: correct
    };
  }

  // 見出し行を探す（10行目固定にせず、ずれても拾えるように）
  function findHeaderRow(rows) {
    for (var r = 1; r <= 30; r++) {
      var c = rows[r]; if (!c) continue;
      var joined = [c[1], c[2], c[5], c[8]].join('|');
      if (joined.indexOf('実施日') >= 0 && joined.indexOf('氏名') >= 0) return r;
    }
    return HEADER_ROW;
  }

  async function readWorkbook(arrayBuffer) {
    var z = zipEntries(arrayBuffer);
    var wb = await zipRead(z, 'xl/workbook.xml');
    var rels = await zipRead(z, 'xl/_rels/workbook.xml.rels');
    var target = 'xl/worksheets/sheet1.xml';
    try {
      // 「ドリル実施状況」シートを名前で引く。無ければ最初のシート。
      var sheets = [], sm, sre = /<sheet\b([^>]*)\/>/g;
      while ((sm = sre.exec(wb || ''))) {
        sheets.push({
          name: unesc((sm[1].match(/name="([^"]*)"/) || [, ''])[1]),
          rid: (sm[1].match(/r:id="([^"]*)"/) || [, ''])[1]
        });
      }
      var pick = null;
      for (var i = 0; i < sheets.length; i++) if (sheets[i].name.indexOf('ドリル実施状況') >= 0) { pick = sheets[i]; break; }
      if (!pick && sheets.length) pick = sheets[0];
      if (pick && pick.rid) {
        var rm = new RegExp('Id="' + pick.rid + '"[^>]*Target="([^"]*)"').exec(rels || '')
          || new RegExp('Target="([^"]*)"[^>]*Id="' + pick.rid + '"').exec(rels || '');
        if (rm) target = 'xl/' + String(rm[1]).replace(/^\/?xl\//, '').replace(/^\//, '');
      }
    } catch (e) { /* 名前で引けなければ sheet1.xml */ }

    var sheetXml = await zipRead(z, target);
    if (!sheetXml) sheetXml = await zipRead(z, 'xl/worksheets/sheet1.xml');
    if (!sheetXml) throw new Error('シートが見つかりません');
    var sst = parseSharedStrings(await zipRead(z, 'xl/sharedStrings.xml'));
    var rows = parseSheet(sheetXml, sst);

    var hr = findHeaderRow(rows);
    var out = [], maxR = 0;
    for (var k in rows) { var kk = parseInt(k, 10); if (kk > maxR) maxR = kk; }
    for (var r = hr + 1; r <= maxR; r++) {
      var c = rows[r]; if (!c) continue;
      var rec = readRow(c);
      if (rec) out.push(rec);
    }
    // ヘッダ部（1〜9行目）に入っている取り込み条件も拾っておく
    var meta = { classLabel: '', period: '' };
    for (var r2 = 1; r2 < hr; r2++) {
      var c2 = rows[r2]; if (!c2) continue;
      var k2 = String(c2[1] || '');
      if (k2.indexOf('クラス') >= 0 && c2[2]) meta.classLabel = String(c2[2]).trim();
      if (k2.indexOf('取り組み日') >= 0 && c2[2]) meta.period = String(c2[2]).trim();
    }
    return { rows: out, meta: meta };
  }

  // ===== 4. 児童ごとにまとめる =====
  function groupStudents(rows) {
    var map = {}, order = [];
    for (var i = 0; i < rows.length; i++) {
      var r = rows[i];
      var key = r.rawName + ' ' + (r.attendanceNo == null ? '' : r.attendanceNo);
      if (!map[key]) { map[key] = { key: key, rawName: r.rawName, attendanceNo: r.attendanceNo, sessions: 0, totalQ: 0, correctQ: 0, days: {} }; order.push(key); }
      var g = map[key];
      g.sessions++; g.totalQ += r.totalQ; g.correctQ += r.correctQ; g.days[r.doneOn] = 1;
    }
    return order.map(function (k) {
      var g = map[k];
      g.dayCount = Object.keys(g.days).length;
      g.ratePct = g.totalQ ? Math.round(g.correctQ / g.totalQ * 100) : null;
      return g;
    });
  }

  // ===== 5. 教師画面 =====
  function esc(s) { return (typeof escH === 'function') ? escH(s) : String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]; }); }
  function classId() { var s = document.getElementById('laClassSelect'); return s ? s.value : ''; }
  function el(id) { return document.getElementById(id); }
  function setStatus(id, t) { var e = el(id); if (e) e.textContent = t; }

  var STATE = { rows: null, students: null, roster: [] };

  async function onFile(input) {
    var f = input && input.files && input.files[0];
    if (!f) return;
    var cid = classId();
    if (!cid) { setStatus('dpStatus', '先に「クラス全体」でクラスを選んでください'); return; }
    setStatus('dpStatus', '読み取り中…');
    var preview = el('dpPreview'); if (preview) preview.innerHTML = '';
    try {
      var buf = await f.arrayBuffer();
      var read = await readWorkbook(buf);
      if (!read.rows.length) { setStatus('dpStatus', 'データ行が見つかりませんでした（「ドリル実施状況」のシートか確認してください）'); return; }
      var groups = groupStudents(read.rows);

      // 名前の別名表を先に読む（既存のテスト取り込みと同じ）
      if (!window._serverFuriganaMap && typeof loadServerNameMap === 'function') { try { await loadServerNameMap(); } catch (e) { } }

      var res = await fetch('/api/teacher/drillpark/parse', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ classId: cid, students: groups.map(function (g) { return { key: g.key, rawName: g.rawName, attendanceNo: g.attendanceNo, sessions: g.sessions, totalQ: g.totalQ, correctQ: g.correctQ }; }) })
      });
      var d = await res.json();
      if (!d || !d.ok) { setStatus('dpStatus', '読み取りに失敗しました（クラスの権限を確認してください）'); return; }

      // v188 の照合（ふりがな・別名・あいまい候補）をそのまま使う。
      // サーバ側で確実に当たったものは残し、当たらなかったものだけ上書きする。
      try {
        if (typeof _matchRosterRows === 'function') {
          var probe = { roster: d.roster || [], rows: d.students.map(function (s) { return { rawName: s.rawName }; }) };
          _matchRosterRows(probe, cid);
          for (var i = 0; i < d.students.length; i++) {
            if (d.students[i].matchStatus === 'auto') continue;
            var p = probe.rows[i];
            if (p && p.matchedUserId) {
              // 出席番号と食い違っていた場合は auto に格上げしない
              var wasConflict = (d.students[i].note || '').indexOf('食い違') >= 0;
              d.students[i].matchedUserId = p.matchedUserId;
              d.students[i].matchedName = p.matchedName;
              d.students[i].matchStatus = (p.matchStatus === 'auto' && !wasConflict) ? 'auto' : 'cand';
            }
          }
        }
      } catch (e) { }

      STATE.rows = read.rows; STATE.students = d.students; STATE.roster = d.roster || [];
      var q = read.rows.reduce(function (a, b) { return a + b.totalQ; }, 0);
      setStatus('dpStatus', '✓ ' + read.rows.length + '件（設問 ' + q + '問ぶん）を読み取りました。'
        + (read.meta.classLabel ? 'ファイル: ' + read.meta.classLabel + ' ' : '') + (read.meta.period || '')
        + ' — 割り当てを確認して保存してください');
      render();
    } catch (e) {
      setStatus('dpStatus', 'エラー: ' + (e && e.message ? e.message : e));
    }
  }

  function render() {
    var box = el('dpPreview'); if (!box) return;
    var sts = STATE.students || [], roster = STATE.roster || [];
    var opts = function (sel) {
      var s = '<option value="">（取り込まない）</option>';
      for (var j = 0; j < roster.length; j++) {
        var rm = roster[j];
        var nm = (typeof resolveStudentName === 'function') ? resolveStudentName(rm.loginId, rm.name) : (rm.name || rm.loginId || '');
        s += '<option value="' + esc(rm.userId) + '"' + (rm.userId === sel ? ' selected' : '') + '>'
          + (rm.rosterNo != null ? esc(String(rm.rosterNo)) + '. ' : '') + esc(nm) + '</option>';
      }
      return s;
    };
    var need = 0, none = 0;
    var h = '<div class="max-h-80 overflow-y-auto"><table class="w-full text-xs"><thead><tr class="text-slate-400">'
      + '<th class="p-1">番</th><th class="text-left p-1">ファイルの氏名</th><th class="text-left p-1">割り当てる児童</th>'
      + '<th class="p-1">実施</th><th class="p-1">設問</th><th class="p-1">正答率</th></tr></thead><tbody>';
    for (var i = 0; i < sts.length; i++) {
      var s = sts[i];
      var ms = s.matchStatus || 'none';
      if (ms === 'cand') need++; if (ms === 'none') none++;
      var badge = (ms === 'auto') ? '<span class="text-[9px] text-green-600">✓自動</span>'
        : (ms === 'cand') ? '<span class="text-[9px] text-amber-600">≈要確認</span>'
          : '<span class="text-[9px] text-red-600">⚠未マッチ</span>';
      var rate = s.totalQ ? Math.round(s.correctQ / s.totalQ * 100) + '%' : '—';
      h += '<tr class="' + (ms === 'auto' ? '' : ms === 'cand' ? 'bg-amber-50' : 'bg-red-50') + '">';
      h += '<td class="p-1 text-center text-slate-500">' + esc(s.attendanceNo == null ? '-' : String(s.attendanceNo)) + '</td>';
      h += '<td class="p-1 font-bold text-slate-700 whitespace-nowrap">' + esc(s.rawName) + ' ' + badge
        + (s.note ? '<div class="text-[9px] text-amber-700">' + esc(s.note) + '</div>' : '') + '</td>';
      h += '<td class="p-1"><select id="dpSel_' + i + '" class="border rounded p-1 w-full">' + opts(s.matchedUserId) + '</select>'
        + (ms === 'cand' ? '<label class="flex items-center gap-1 mt-0.5 text-[10px] text-amber-700"><input type="checkbox" id="dpOk_' + i + '">この子で確定</label>' : '')
        + '</td>';
      h += '<td class="p-1 text-center text-slate-500">' + s.sessions + '</td>';
      h += '<td class="p-1 text-center text-slate-500">' + s.totalQ + '</td>';
      h += '<td class="p-1 text-center text-slate-500">' + rate + '</td>';
      h += '</tr>';
    }
    h += '</tbody></table></div>';
    h += '<div class="flex items-center gap-2 mt-2"><button id="dpSaveBtn" class="bg-rose-600 text-white rounded-lg px-4 py-2 text-sm font-bold hover:bg-rose-700">💾 保存</button>'
      + '<span id="dpSaveStatus" class="text-xs font-bold text-amber-600">'
      + (need ? '要確認 ' + need + '人 は「この子で確定」にチェックすると保存されます。' : '')
      + (none ? '未マッチ ' + none + '人 は児童を選んでください。' : '')
      + '</span></div>';
    box.innerHTML = h;
    var btn = el('dpSaveBtn'); if (btn) btn.onclick = save;
  }

  async function save() {
    if (!STATE.rows) return;
    var cid = classId();
    var sts = STATE.students, assignments = [], byKey = {}, need = 0;
    for (var i = 0; i < sts.length; i++) {
      var s = sts[i];
      var sel = el('dpSel_' + i); var uid = sel ? sel.value : '';
      if (!uid) continue;
      if (s.matchStatus === 'cand' && uid === s.matchedUserId) {
        var ok = el('dpOk_' + i);
        if (!ok || !ok.checked) { need++; continue; }
      }
      assignments.push({ key: s.key, userId: uid });
      byKey[s.key] = uid;
      try { if (typeof _rememberAlias === 'function') _rememberAlias(cid, s.rawName, uid); } catch (e) { }
    }
    if (!assignments.length) { setStatus('dpSaveStatus', '保存できる児童がいません' + (need ? '（要確認 ' + need + '人はチェックを入れてください）' : '')); return; }

    var rows = STATE.rows.filter(function (r) { return byKey[r.rawName + ' ' + (r.attendanceNo == null ? '' : r.attendanceNo)]; })
      .map(function (r) {
        return {
          studentKey: r.rawName + ' ' + (r.attendanceNo == null ? '' : r.attendanceNo),
          doneOn: r.doneOn, startedAt: r.startedAt, classLabel: r.classLabel, attendanceNo: r.attendanceNo,
          rawName: r.rawName, subject: r.subject, drillNo: r.drillNo, material: r.material,
          useType: r.useType, drillKind: r.drillKind, answerSec: r.answerSec, ratePct: r.ratePct,
          answers: r.answers, totalQ: r.totalQ, correctQ: r.correctQ
        };
      });

    setStatus('dpSaveStatus', '保存中…（' + rows.length + '件）');
    try {
      var res = await fetch('/api/teacher/drillpark/save', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ classId: cid, assignments: assignments, rows: rows })
      });
      var d = await res.json();
      if (!d || !d.ok) { setStatus('dpSaveStatus', '保存に失敗しました'); return; }
      var msg = '✓ ' + d.inserted + '件を保存しました';
      if (d.skippedDuplicate) msg += '（すでに取り込み済み ' + d.skippedDuplicate + '件は追加していません）';
      if (d.unassigned) msg += '（未割り当て ' + d.unassigned + '件）';
      if (need) msg += '（要確認 ' + need + '人は未保存）';
      msg += '。個人分析・カルテに反映されます';
      setStatus('dpSaveStatus', msg);
      loadBatches();
    } catch (e) {
      setStatus('dpSaveStatus', 'エラー: ' + (e && e.message ? e.message : e));
    }
  }

  // ===== 6. 取り込みの取り消し =====
  // 児童を取り違えて保存してしまったときの直し方は「その取り込みぶんを消して入れ直す」。
  // 同じ行は同じ指紋になるので、消さずに入れ直しても上書きされないため。
  async function loadBatches() {
    var box = el('dpBatches'); if (!box) return;
    var cid = classId(); if (!cid) { box.innerHTML = ''; return; }
    try {
      var res = await fetch('/api/teacher/drillpark/batches?classId=' + encodeURIComponent(cid));
      var d = await res.json();
      if (!d || !d.ok || !d.batches || !d.batches.length) { box.innerHTML = ''; return; }
      var h = '<div class="text-[10px] text-slate-500 mt-1 mb-1">取り込んだ記録（児童を取り違えたときは、その回を取り消してから入れ直してください）</div>';
      h += '<div class="max-h-40 overflow-y-auto"><table class="w-full text-[11px]"><tbody>';
      for (var i = 0; i < d.batches.length; i++) {
        var b = d.batches[i];
        h += '<tr class="border-b"><td class="p-1 text-slate-600 whitespace-nowrap">' + esc(String(b.importedAt || '').slice(0, 16).replace('T', ' ')) + '</td>'
          + '<td class="p-1 text-slate-500">' + esc(String(b.firstDate || '')) + '〜' + esc(String(b.lastDate || '')) + '</td>'
          + '<td class="p-1 text-slate-500 whitespace-nowrap">' + b.rows + '件 / ' + b.students + '人</td>'
          + '<td class="p-1 text-right"><button class="text-[10px] text-red-600 underline" data-dpundo="' + esc(b.batchId) + '" data-dprows="' + b.rows + '">取り消す</button></td></tr>';
      }
      h += '</tbody></table></div><div id="dpUndoStatus" class="text-xs text-amber-600 mt-1"></div>';
      box.innerHTML = h;
      var btns = box.querySelectorAll('[data-dpundo]');
      for (var k = 0; k < btns.length; k++) btns[k].onclick = function () { undo(this.getAttribute('data-dpundo'), this.getAttribute('data-dprows')); };
    } catch (e) { box.innerHTML = ''; }
  }

  async function undo(batchId, rows) {
    if (!batchId) return;
    if (!window.confirm('この取り込み（' + rows + '件）を取り消します。よろしいですか？\n※ 取り消したあと、同じファイルをもう一度取り込み直せます。')) return;
    setStatus('dpUndoStatus', '取り消し中…');
    try {
      var res = await fetch('/api/teacher/drillpark/undo', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ classId: classId(), batchId: batchId })
      });
      var d = await res.json();
      if (!d || !d.ok) { setStatus('dpUndoStatus', '取り消しに失敗しました'); return; }
      setStatus('dpUndoStatus', '✓ ' + d.deleted + '件を取り消しました。必要ならもう一度取り込んでください');
      loadBatches();
    } catch (e) { setStatus('dpUndoStatus', 'エラー: ' + (e && e.message ? e.message : e)); }
  }

  window.DrillPark = {
    readWorkbook: readWorkbook,
    groupStudents: groupStudents,
    onFile: onFile,
    loadBatches: loadBatches,
    _internal: { zipEntries: zipEntries, zipRead: zipRead, parseSharedStrings: parseSharedStrings, parseSheet: parseSheet, readRow: readRow, ymd: ymd, hms: hms, toSec: toSec, toPct: toPct }
  };
  window.dpPickFile = onFile;
  window.dpLoadBatches = loadBatches;
})();
