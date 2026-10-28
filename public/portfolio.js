/* ===================================================================
   portfolio.js  —  PORTFOLIO_V1 📸 成果物ポートフォリオ（先生の画面だけ）
   ------------------------------------------------------------------
   ・教師ダッシュボード上の「📸 成果物」ボタンで開く全画面のまど。
   ・子どもごと → 月・教科で一覧（小さい写真）→ タップで大きく／2まいを並べてくらべる。
   ・先生が撮ったノート・作品の写真を、子どもを選んで追加（複数まいまとめて可・教科とメモは任意）。
     送る前にこの端末で縮める（長辺1600px・JPEG）。一覧用の小さい版（長辺360px）も作る。
   ・年度末に、その子の分をまとめて ZIP でダウンロード（この端末で作る。サーバに負担をかけない）。
   ・消すのは先生だけ。年度末にまとめて消すときも、先生が確認してから（自動では消さない）。
   ※ 子どもの画面からは読み込まない。写真の道 /api/teacher/portfolio/img/ は先生のログインが要る。
   =================================================================== */
(function () {
  'use strict';
  var SUBJ = ['国語', '算数', '理科', '社会', '英語', '図工', '音楽', '体育', '家庭', '道徳', '総合', '書写', 'その他'];
  var S = { classId: '', sum: null, stu: null, items: [], fM: '', fS: '', cmp: false, pick: [], busy: false };

  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function mb(b) { b = Number(b) || 0; return b >= 1048576 ? (b / 1048576).toFixed(1) + 'MB' : Math.max(1, Math.round(b / 1024)) + 'KB'; }
  function jstToday() { return new Date(Date.now() + 9 * 3600000).toISOString().slice(0, 10); }
  function jaDate(s) { var p = String(s || '').split('-'); return p.length < 3 ? s : (Number(p[1]) + '/' + Number(p[2])); }
  async function getJ(u) { try { var r = await fetch(u, { credentials: 'include' }); return await r.json(); } catch (e) { return null; } }
  async function postJ(u, b) { try { var r = await fetch(u, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); return await r.json(); } catch (e) { return null; } }
  function img(id, thumb) { return '/api/teacher/portfolio/img/' + encodeURIComponent(id) + (thumb ? '?t=1' : ''); }
  function stuLabel(s) { return (s.rosterNo ? s.rosterNo + ' ' : '') + (s.name || s.loginId || ''); }
  var ERR = {
    store_not_ready: '写真の置き場がまだ準備できていません（管理者に連絡してください）',
    view_as_active: '「子どもの画面を見る」の最中は写真を出しません。いったん先生の画面を開きなおしてください',
    photo_too_large: '写真が大きすぎます', forbidden: 'この写真は見られません'
  };
  function errJa(d) { return (d && ERR[d.error]) || ('うまくいきませんでした' + (d && d.error ? '（' + d.error + '）' : '')); }

  // ---------- 写真を縮める（長辺 max px・JPEG） ----------
  function loadImage(blob) {
    return new Promise(function (res, rej) {
      var u = URL.createObjectURL(blob), im = new Image();
      im.onload = function () { res({ im: im, u: u }); };
      im.onerror = function () { try { URL.revokeObjectURL(u); } catch (e) {} rej(new Error('読めない画像')); };
      im.src = u;
    });
  }
  function shrinkFrom(im, max, q) {
    return new Promise(function (res) {
      var w = im.naturalWidth || im.width, h = im.naturalHeight || im.height;
      var sc = Math.min(1, max / Math.max(w, h));
      var cw = Math.max(1, Math.round(w * sc)), ch = Math.max(1, Math.round(h * sc));
      var cv = document.createElement('canvas'); cv.width = cw; cv.height = ch;
      var g = cv.getContext('2d'); g.fillStyle = '#fff'; g.fillRect(0, 0, cw, ch); g.drawImage(im, 0, 0, cw, ch);
      cv.toBlob(function (b) { res(b); }, 'image/jpeg', q);
    });
  }
  async function makeBoth(blob) {
    var L = await loadImage(blob);
    try {
      var big = await shrinkFrom(L.im, 1600, 0.8);
      if (big && big.size > 1800000) big = await shrinkFrom(L.im, 1400, 0.7);
      var th = await shrinkFrom(L.im, 360, 0.7);
      return { big: big, th: th };
    } finally { try { URL.revokeObjectURL(L.u); } catch (e) {} }
  }
  async function upload(fields, big, th) {
    var fd = new FormData();
    Object.keys(fields).forEach(function (k) { fd.append(k, fields[k]); });
    fd.append('photo', new File([big], 'p.jpg', { type: 'image/jpeg' }));
    if (th) fd.append('thumb', new File([th], 't.jpg', { type: 'image/jpeg' }));
    try { var r = await fetch('/api/teacher/portfolio/upload', { method: 'POST', credentials: 'include', body: fd }); return await r.json(); } catch (e) { return null; }
  }

  // ---------- ZIP（無圧縮・この端末で作る） ----------
  var CRC = (function () { var t = new Uint32Array(256); for (var n = 0; n < 256; n++) { var c = n; for (var k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1); t[n] = c >>> 0; } return t; })();
  function crc32(u8) { var c = 0xFFFFFFFF; for (var i = 0; i < u8.length; i++) c = CRC[(c ^ u8[i]) & 0xFF] ^ (c >>> 8); return (c ^ 0xFFFFFFFF) >>> 0; }
  function makeZip(files) {   // files: [{name, data:Uint8Array}]
    var enc = new TextEncoder(), parts = [], cen = [], off = 0;
    var now = new Date();
    var dt = ((now.getHours() << 11) | (now.getMinutes() << 5) | (now.getSeconds() >> 1)) & 0xFFFF;
    var dd = (((now.getFullYear() - 1980) << 9) | ((now.getMonth() + 1) << 5) | now.getDate()) & 0xFFFF;
    files.forEach(function (f) {
      var nm = enc.encode(f.name), d = f.data, crc = crc32(d);
      var h = new DataView(new ArrayBuffer(30));
      h.setUint32(0, 0x04034b50, true); h.setUint16(4, 20, true); h.setUint16(6, 0x0800, true); h.setUint16(8, 0, true);
      h.setUint16(10, dt, true); h.setUint16(12, dd, true); h.setUint32(14, crc, true); h.setUint32(18, d.length, true); h.setUint32(22, d.length, true);
      h.setUint16(26, nm.length, true); h.setUint16(28, 0, true);
      parts.push(h.buffer, nm, d);
      var c = new DataView(new ArrayBuffer(46));
      c.setUint32(0, 0x02014b50, true); c.setUint16(4, 20, true); c.setUint16(6, 20, true); c.setUint16(8, 0x0800, true); c.setUint16(10, 0, true);
      c.setUint16(12, dt, true); c.setUint16(14, dd, true); c.setUint32(16, crc, true); c.setUint32(20, d.length, true); c.setUint32(24, d.length, true);
      c.setUint16(28, nm.length, true); c.setUint16(30, 0, true); c.setUint16(32, 0, true); c.setUint16(34, 0, true); c.setUint16(36, 0, true);
      c.setUint32(38, 0, true); c.setUint32(42, off, true);
      cen.push(c.buffer, nm);
      off += 30 + nm.length + d.length;
    });
    var csz = 0; cen.forEach(function (x) { csz += x.byteLength; });
    var e = new DataView(new ArrayBuffer(22));
    e.setUint32(0, 0x06054b50, true); e.setUint16(8, files.length, true); e.setUint16(10, files.length, true);
    e.setUint32(12, csz, true); e.setUint32(16, off, true);
    return new Blob(parts.concat(cen, [e.buffer]), { type: 'application/zip' });
  }
  try { window.__PF_ZIP = { makeZip: makeZip, crc32: crc32 }; } catch (e) {}

  // ---------- 画面 ----------
  function shell() {
    if ($('pfOverlay')) return $('pfOverlay');
    var o = document.createElement('div');
    o.id = 'pfOverlay';
    o.style.cssText = 'position:fixed;inset:0;z-index:9000;background:#f8fafc;overflow:auto;display:none';
    o.innerHTML =
      '<div style="max-width:1000px;margin:0 auto;padding:12px">' +
      '<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px">' +
      '<b style="font-size:18px">📸 成果物ポートフォリオ</b><span style="font-size:12px;color:#64748b">先生だけが見られます。子どもの画面には出ません。</span>' +
      '<span style="flex:1"></span><select id="pfClass" style="border:1px solid #cbd5e1;border-radius:8px;padding:4px 6px;font-size:13px"></select>' +
      '<button id="pfClose" style="background:#e2e8f0;border-radius:8px;padding:6px 12px;font-weight:bold;font-size:13px">✕ とじる</button></div>' +
      '<div id="pfNotice"></div><div id="pfBody"></div></div>' +
      '<div id="pfLight" style="position:fixed;inset:0;z-index:9100;background:rgba(15,23,42,.92);display:none;overflow:auto"></div>';
    document.body.appendChild(o);
    $('pfClose').onclick = function () { o.style.display = 'none'; document.body.style.overflow = ''; };
    $('pfClass').onchange = function () { S.classId = this.value; S.stu = null; loadSummary(); };
    return o;
  }
  function btn(label, onclick, color) {
    return '<button onclick="' + onclick + '" style="background:' + (color || '#4f46e5') + ';color:#fff;border-radius:8px;padding:6px 10px;font-weight:bold;font-size:12px;margin:2px">' + label + '</button>';
  }

  async function open() {
    var o = shell(); o.style.display = 'block'; document.body.style.overflow = 'hidden';
    if (!S.classId) { try { var cf = $('analyticsClassFilter'); if (cf && cf.value) S.classId = cf.value; } catch (e) {} }
    await loadSummary();
  }

  async function loadSummary() {
    $('pfBody').innerHTML = '<p style="font-size:13px;color:#64748b">読み込み中…</p>';
    var d = await getJ('/api/teacher/portfolio/summary' + (S.classId ? '?classId=' + encodeURIComponent(S.classId) : ''));
    if (!d || !d.ok) { $('pfBody').innerHTML = '<p style="color:#dc2626;font-size:13px">' + esc(errJa(d)) + '</p>'; return; }
    S.sum = d; S.classId = d.classId;
    $('pfClass').innerHTML = (d.classes || []).map(function (c) { return '<option value="' + esc(c.id) + '"' + (c.id === d.classId ? ' selected' : '') + '>' + esc(c.name) + '</option>'; }).join('');
    renderNotice();
    if (S.stu) { var s2 = (d.students || []).filter(function (x) { return x.userId === S.stu.userId; })[0]; if (s2) { S.stu = s2; return loadItems(); } }
    renderHome();
  }

  function renderNotice() {
    var d = S.sum, h = '';
    if (!d.store) h += '<div style="background:#fee2e2;border:1px solid #fca5a5;border-radius:10px;padding:8px;font-size:12px;margin-bottom:6px">⚠ 写真の置き場がまだ準備できていません。追加はできません。</div>';
    if (d.yearEnd) {
      h += '<div style="background:#fef3c7;border:2px solid #f59e0b;border-radius:10px;padding:10px;font-size:13px;margin-bottom:6px">' +
        '<b>📦 年度末のおかたづけ</b>：' + d.yearEnd.upToFy + '年度までの写真が <b>' + d.yearEnd.count + 'まい</b>（' + mb(d.yearEnd.bytes) + '）あります。<br>' +
        '<span style="font-size:12px">必要な子の分は先に「⬇ ZIPでダウンロード」で保存してください。自動では消えません。</span><br>' +
        btn('🗑 ' + d.yearEnd.upToFy + '年度までの写真を消す', 'PF._yearEnd()', '#dc2626') +
        btn('あとで（2週間後にまた知らせる）', 'PF._snooze(14)', '#64748b') +
        btn('ずっと残す設定にする', 'PF._setKeep(\'keep\')', '#64748b') + '</div>';
    }
    if (d.legacy > 0 && d.store) {
      h += '<div style="background:#e0f2fe;border:1px solid #7dd3fc;border-radius:10px;padding:8px;font-size:12px;margin-bottom:6px">' +
        '📥 前からある家庭学習の写真が <b>' + d.legacy + 'まい</b> まだ入っていません。（家庭学習の写真は180日で自動で消えます。残したいときは とりこんでください。もとの写真はそのまま）' +
        btn('📥 とりこむ', 'PF._legacy()', '#0284c7') + '<span id="pfLegacySt"></span></div>';
    }
    $('pfNotice').innerHTML = h;
  }

  function renderHome() {
    var d = S.sum, st = d.settings || {};
    var h = '';
    // 追加
    h += '<div style="background:#fff;border:2px solid #a5b4fc;border-radius:12px;padding:10px;margin-bottom:10px">' +
      '<b style="font-size:14px">➕ 写真を追加（ノート・作品など）</b>' +
      '<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:6px;font-size:13px">' +
      '<select id="pfAddStu" style="border:1px solid #cbd5e1;border-radius:8px;padding:6px"><option value="">子どもをえらぶ</option>' +
      (d.students || []).map(function (s) { return '<option value="' + esc(s.userId) + '">' + esc(stuLabel(s)) + '</option>'; }).join('') + '</select>' +
      '<input id="pfAddDate" type="date" value="' + jstToday() + '" style="border:1px solid #cbd5e1;border-radius:8px;padding:5px">' +
      '<select id="pfAddSubj" style="border:1px solid #cbd5e1;border-radius:8px;padding:6px"><option value="">教科（任意）</option>' + SUBJ.map(function (x) { return '<option>' + x + '</option>'; }).join('') + '</select>' +
      '<input id="pfAddMemo" placeholder="メモ（任意）" maxlength="200" style="border:1px solid #cbd5e1;border-radius:8px;padding:6px;flex:1;min-width:140px">' +
      '</div><div style="margin-top:6px"><label style="display:inline-block;background:#4f46e5;color:#fff;border-radius:8px;padding:8px 14px;font-weight:bold;font-size:13px;cursor:pointer">📷 写真をえらぶ／撮る（何まいでも）' +
      '<input id="pfAddFiles" type="file" accept="image/*" multiple style="display:none"></label> <span id="pfAddSt" style="font-size:12px;font-weight:bold;color:#4338ca"></span></div></div>';
    h += aiPanelHtml(d);
    // 子どもの一覧
    h += '<div style="background:#fff;border-radius:12px;padding:10px;margin-bottom:10px"><b style="font-size:14px">👧👦 子どもごと</b>' +
      '<span style="font-size:12px;color:#64748b;margin-left:6px">ぜんぶで ' + d.total.count + 'まい（' + mb(d.total.bytes) + '）</span>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:6px;margin-top:6px">' +
      (d.students || []).map(function (s) {
        return '<button onclick="PF._stu(\'' + esc(s.userId) + '\')" style="text-align:left;background:#f1f5f9;border:1px solid #e2e8f0;border-radius:10px;padding:8px;font-size:13px">' +
          '<b>' + esc(stuLabel(s)) + '</b><br><span style="font-size:11px;color:#64748b">' + (s.n || 0) + 'まい' + (s.lastOn ? '・さいご ' + jaDate(s.lastOn) : '') + '</span></button>';
      }).join('') + '</div></div>';
    // 設定
    h += '<details style="background:#fff;border-radius:12px;padding:10px;font-size:13px"><summary style="cursor:pointer;font-weight:bold">⚙ 設定（保存期間・家庭学習の写真）</summary>' +
      '<div style="margin-top:6px">保存期間：<select id="pfKeep" style="border:1px solid #cbd5e1;border-radius:8px;padding:4px">' +
      '<option value="fy_end"' + (st.keepMode !== 'keep' ? ' selected' : '') + '>年度末まで（3月に消すかどうか確認を出す）</option>' +
      '<option value="keep"' + (st.keepMode === 'keep' ? ' selected' : '') + '>消さない（確認も出さない）</option></select></div>' +
      '<div style="margin-top:6px"><label><input id="pfAutoHw" type="checkbox"' + (st.autoHw !== false ? ' checked' : '') + '> 家庭学習で子どもが付けた写真を自動で入れる</label></div>' +
      '<div style="margin-top:6px">' + btn('保存', 'PF._saveSettings()', '#0f766e') + '<span id="pfSetSt" style="font-size:12px"></span></div>' +
      '<p style="font-size:11px;color:#64748b;margin-top:6px">※ どの設定でも、自動で消すことはありません。消すのは先生がボタンを押したときだけです。</p></details>';
    $('pfBody').innerHTML = h;
    $('pfAddFiles').onchange = function () { addFiles(this.files); this.value = ''; };
    try { if (S.aiRaw && $('pfAiPaste')) $('pfAiPaste').value = S.aiRaw; } catch (e) {}
  }

  async function addFiles(files) {
    var uid = $('pfAddStu').value;
    var st = $('pfAddSt');
    if (!uid) { st.textContent = '先に子どもをえらんでください'; return; }
    if (!files || !files.length) return;
    if (S.busy) return; S.busy = true;
    var ok = 0, ng = 0;
    for (var i = 0; i < files.length; i++) {
      st.textContent = '📤 ' + (i + 1) + '/' + files.length + 'まい 送っています…';
      try {
        var b = await makeBoth(files[i]);
        var r = await upload({ userId: uid, takenOn: $('pfAddDate').value || jstToday(), subj: $('pfAddSubj').value, memo: $('pfAddMemo').value, src: 'teacher' }, b.big, b.th);
        if (r && r.ok) ok++; else { ng++; st.textContent = errJa(r); if (r && r.error === 'store_not_ready') break; }
      } catch (e) { ng++; }
    }
    S.busy = false;
    st.textContent = '✓ ' + ok + 'まい 入れました' + (ng ? '（' + ng + 'まい できませんでした）' : '');
    var keep = { stu: uid, subj: $('pfAddSubj').value, date: $('pfAddDate').value };
    await loadSummary();
    try { $('pfAddStu').value = keep.stu; $('pfAddSubj').value = keep.subj; $('pfAddDate').value = keep.date; $('pfAddSt').textContent = '✓ ' + ok + 'まい 入れました'; } catch (e) {}
  }

  async function openStu(uid) {
    S.stu = (S.sum.students || []).filter(function (x) { return x.userId === uid; })[0] || null;
    S.fM = ''; S.fS = ''; S.cmp = false; S.pick = [];
    if (S.stu) await loadItems();
  }
  async function loadItems() {
    $('pfBody').innerHTML = '<p style="font-size:13px;color:#64748b">読み込み中…</p>';
    var d = await getJ('/api/teacher/portfolio/items?userId=' + encodeURIComponent(S.stu.userId));
    if (!d || !d.ok) { $('pfBody').innerHTML = '<p style="color:#dc2626">' + esc(errJa(d)) + '</p>'; return; }
    S.items = d.items || [];
    renderStu();
  }
  function filtered() {
    return S.items.filter(function (it) {
      if (S.fM && String(it.takenOn).slice(0, 7) !== S.fM) return false;
      if (S.fS && (it.subj || (it.src === 'hw' ? '家庭学習' : '')) !== S.fS) return false;
      return true;
    });
  }
  function renderStu() {
    var months = [], subs = [];
    S.items.forEach(function (it) {
      var m = String(it.takenOn).slice(0, 7); if (months.indexOf(m) < 0) months.push(m);
      var sj = it.subj || (it.src === 'hw' ? '家庭学習' : ''); if (sj && subs.indexOf(sj) < 0) subs.push(sj);
    });
    var fys = []; S.items.forEach(function (it) { if (fys.indexOf(it.fy) < 0) fys.push(it.fy); });
    var list = filtered();
    var h = '<div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:8px">' +
      btn('← 一覧へ', 'PF._home()', '#64748b') + '<b style="font-size:16px">' + esc(stuLabel(S.stu)) + '</b><span style="font-size:12px;color:#64748b">' + S.items.length + 'まい</span><span style="flex:1"></span>' +
      '<select id="pfFM" style="border:1px solid #cbd5e1;border-radius:8px;padding:4px;font-size:12px"><option value="">すべての月</option>' + months.map(function (m) { return '<option value="' + m + '"' + (m === S.fM ? ' selected' : '') + '>' + Number(m.slice(5)) + '月（' + m.slice(0, 4) + '）</option>'; }).join('') + '</select>' +
      '<select id="pfFS" style="border:1px solid #cbd5e1;border-radius:8px;padding:4px;font-size:12px"><option value="">すべての教科</option>' + subs.map(function (s) { return '<option' + (s === S.fS ? ' selected' : '') + '>' + esc(s) + '</option>'; }).join('') + '</select>' +
      btn(S.cmp ? '✕ くらべるのをやめる' : '🔀 2まいをくらべる', 'PF._cmp()', S.cmp ? '#be123c' : '#0f766e') +
      '<select id="pfZipFy" style="border:1px solid #cbd5e1;border-radius:8px;padding:4px;font-size:12px">' + fys.map(function (f) { return '<option value="' + f + '">' + f + '年度</option>'; }).join('') + '<option value="">ぜんぶ</option></select>' +
      btn('⬇ ZIPでダウンロード', 'PF._zip()', '#1d4ed8') + '<span id="pfZipSt" style="font-size:12px"></span></div>';
    if (S.cmp) h += '<p style="font-size:12px;background:#ccfbf1;border-radius:8px;padding:6px">くらべたい写真を2まい タップしてください（' + S.pick.length + '/2）</p>';
    if (!list.length) h += '<p style="font-size:13px;color:#64748b">まだ写真はありません。</p>';
    var curM = '';
    list.forEach(function (it) {
      var m = String(it.takenOn).slice(0, 7);
      if (m !== curM) { if (curM) h += '</div>'; curM = m; h += '<div style="font-weight:bold;font-size:13px;margin:10px 0 4px">' + Number(m.slice(5)) + '月</div><div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:6px">'; }
      var picked = S.pick.indexOf(it.id) >= 0;
      h += '<button onclick="PF._tap(\'' + it.id + '\')" style="background:#fff;border:' + (picked ? '3px solid #0d9488' : '1px solid #e2e8f0') + ';border-radius:10px;padding:4px;text-align:left">' +
        '<img loading="lazy" src="' + img(it.id, !!it.hasThumb) + '" alt="" style="width:100%;height:110px;object-fit:cover;border-radius:6px;background:#f1f5f9">' +
        '<div style="font-size:11px;margin-top:2px">' + jaDate(it.takenOn) + ' ' + esc(it.subj || (it.src === 'hw' ? '🏠家庭学習' : '')) + '</div>' +
        (it.memo ? '<div style="font-size:10px;color:#64748b;overflow:hidden;white-space:nowrap;text-overflow:ellipsis">' + esc(it.memo) + '</div>' : '') + '</button>';
    });
    if (curM) h += '</div>';
    $('pfBody').innerHTML = h;
    $('pfFM').onchange = function () { S.fM = this.value; renderStu(); };
    $('pfFS').onchange = function () { S.fS = this.value; renderStu(); };
  }

  function itemOf(id) { return S.items.filter(function (x) { return x.id === id; })[0]; }
  function tap(id) {
    if (S.cmp) {
      var i = S.pick.indexOf(id);
      if (i >= 0) S.pick.splice(i, 1); else S.pick.push(id);
      if (S.pick.length > 2) S.pick.shift();
      if (S.pick.length === 2) { showCompare(S.pick[0], S.pick[1]); }
      renderStu(); return;
    }
    showOne(id);
  }
  function lightOpen(h) { var L = $('pfLight'); L.innerHTML = h; L.style.display = 'block'; }
  function lightClose() { var L = $('pfLight'); L.style.display = 'none'; L.innerHTML = ''; }
  function caption(it) { return jaDate(it.takenOn) + '（' + it.takenOn.slice(0, 4) + '）' + (it.subj ? '・' + esc(it.subj) : '') + (it.src === 'hw' ? '・🏠家庭学習' : '・先生が追加'); }
  function showOne(id) {
    var it = itemOf(id); if (!it) return;
    lightOpen('<div style="max-width:1000px;margin:0 auto;padding:10px;color:#fff">' +
      '<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:6px"><b>' + caption(it) + '</b><span style="flex:1"></span>' + btn('✕ とじる', 'PF._lc()', '#475569') + '</div>' +
      '<img src="' + img(it.id) + '" alt="" style="max-width:100%;max-height:75vh;display:block;margin:0 auto;background:#fff;border-radius:8px">' +
      '<div style="background:#1e293b;border-radius:10px;padding:8px;margin-top:8px;font-size:13px">' +
      '日付 <input id="pfEdD" type="date" value="' + esc(it.takenOn) + '" style="color:#000;border-radius:6px;padding:3px"> ' +
      '教科 <select id="pfEdS" style="color:#000;border-radius:6px;padding:3px"><option value="">（なし）</option>' + SUBJ.map(function (x) { return '<option' + (x === it.subj ? ' selected' : '') + '>' + x + '</option>'; }).join('') + '</select> ' +
      'メモ <input id="pfEdM" value="' + esc(it.memo || '') + '" maxlength="200" style="color:#000;border-radius:6px;padding:3px;min-width:200px"> ' +
      btn('💾 直す', 'PF._save(\'' + it.id + '\')', '#0f766e') + btn('🗑 この写真を消す', 'PF._del(\'' + it.id + '\')', '#dc2626') + '<span id="pfEdSt"></span></div></div>');
  }
  function showCompare(a, b) {
    var A = itemOf(a), B = itemOf(b); if (!A || !B) return;
    if (A.takenOn > B.takenOn) { var t = A; A = B; B = t; }
    var col = function (it) { return '<div style="flex:1;min-width:280px"><div style="font-weight:bold;margin-bottom:4px">' + caption(it) + '</div>' +
      '<img src="' + img(it.id) + '" alt="" style="width:100%;max-height:78vh;object-fit:contain;background:#fff;border-radius:8px">' +
      (it.memo ? '<div style="font-size:12px;margin-top:4px">' + esc(it.memo) + '</div>' : '') + '</div>'; };
    lightOpen('<div style="padding:10px;color:#fff"><div style="display:flex;align-items:center;margin-bottom:6px"><b>🔀 くらべる（左が前・右があと）</b><span style="flex:1"></span>' + btn('✕ とじる', 'PF._lc()', '#475569') + '</div>' +
      '<div style="display:flex;gap:10px;flex-wrap:wrap">' + col(A) + col(B) + '</div></div>');
  }

  async function saveItem(id) {
    var r = await postJ('/api/teacher/portfolio/update', { id: id, takenOn: $('pfEdD').value, subj: $('pfEdS').value, memo: $('pfEdM').value });
    if (r && r.ok) { lightClose(); await loadItems(); } else $('pfEdSt').textContent = errJa(r);
  }
  async function delItem(id) {
    if (!confirm('この写真を消します。もとにはもどせません。よろしいですか？')) return;
    var r = await postJ('/api/teacher/portfolio/delete', { ids: [id] });
    if (r && r.ok) { lightClose(); await loadItems(); } else alert(errJa(r));
  }

  async function zip() {
    var fy = $('pfZipFy').value, st = $('pfZipSt');
    var list = S.items.filter(function (it) { return !fy || String(it.fy) === fy; }).slice().sort(function (a, b) { return a.takenOn < b.takenOn ? -1 : 1; });
    if (!list.length) { st.textContent = '写真がありません'; return; }
    var files = [], csv = ['﻿番号,日付,教科,どこから,メモ,ファイル'], n = 0;
    for (var i = 0; i < list.length; i++) {
      var it = list[i];
      st.textContent = '準備中… ' + (i + 1) + '/' + list.length;
      try {
        var r = await fetch(img(it.id), { credentials: 'include' });
        if (!r.ok) continue;
        var u8 = new Uint8Array(await r.arrayBuffer());
        n++;
        var sj = it.subj || (it.src === 'hw' ? '家庭学習' : 'その他');
        var name = String(n).padStart(3, '0') + '_' + it.takenOn + '_' + sj.replace(/[\\/:*?"<>|]/g, '') + '.jpg';
        files.push({ name: name, data: u8 });
        csv.push([n, it.takenOn, sj, it.src === 'hw' ? '家庭学習' : '先生が追加', '"' + String(it.memo || '').replace(/"/g, '""') + '"', name].join(','));
      } catch (e) {}
    }
    files.push({ name: '一覧.csv', data: new TextEncoder().encode(csv.join('\r\n')) });
    var blob = makeZip(files);
    var a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = '成果物_' + stuLabel(S.stu).replace(/[\\/:*?"<>|\s]/g, '') + '_' + (fy ? fy + '年度' : 'ぜんぶ') + '.zip';
    document.body.appendChild(a); a.click();
    setTimeout(function () { try { URL.revokeObjectURL(a.href); a.remove(); } catch (e) {} }, 4000);
    st.textContent = '✓ ' + n + 'まい（' + mb(blob.size) + '）';
  }

  async function legacy() {
    var st = $('pfLegacySt');
    var d = await getJ('/api/teacher/portfolio/legacy?classId=' + encodeURIComponent(S.classId));
    if (!d || !d.ok) { st.textContent = errJa(d); return; }
    var list = d.items || [], ok = 0;
    for (var i = 0; i < list.length; i++) {
      var x = list[i];
      st.textContent = ' 📥 ' + (i + 1) + '/' + list.length + '…';
      try {
        var r = await fetch('/api/photo/' + encodeURIComponent(x.userId) + '/' + encodeURIComponent(x.dayKey) + (x.idx ? '?idx=' + x.idx : ''), { credentials: 'include' });
        if (!r.ok) continue;
        var b = await makeBoth(await r.blob());
        var j = await upload({ userId: x.userId, src: 'hw', hwDayKey: x.dayKey, hwIdx: String(x.idx || 0) }, b.big, b.th);
        if (j && j.ok) ok++;
        else if (j && j.error === 'store_not_ready') break;
      } catch (e) {}
    }
    st.textContent = ' ✓ ' + ok + 'まい とりこみました';
    await loadSummary();
  }

  async function yearEnd() {
    var y = S.sum.yearEnd; if (!y) return;
    if (!confirm(y.upToFy + '年度までの写真 ' + y.count + 'まいを消します。\nZIPでの保存はおわりましたか？\n消すと、もとにはもどせません。')) return;
    var w = prompt('本当に消すときは「けす」と入力してください');
    if (w !== 'けす') return;
    var total = 0;
    for (var k = 0; k < 500; k++) {
      var r = await postJ('/api/teacher/portfolio/year-end', { classId: S.classId, upToFy: y.upToFy, confirm: 'けす' });
      if (!r || !r.ok) { alert(errJa(r)); break; }
      total += r.deleted || 0;
      $('pfNotice').innerHTML = '<p style="font-size:13px">🗑 消しています… ' + total + 'まい</p>';
      if (!r.left || !r.deleted) break;
    }
    alert(total + 'まい消しました');
    await loadSummary();
  }
  async function setSettings(b, msgEl) {
    b.classId = S.classId;
    var r = await postJ('/api/teacher/portfolio/settings', b);
    if (msgEl) msgEl.textContent = (r && r.ok) ? ' ✓ 保存しました' : ' ' + errJa(r);
    await loadSummary();
  }

  // ═════════ 🤖 PORTFOLIO_AI_V1 AIで成果物を分析（外部AI方式：プロンプト＋写真を先生が貼る） ═════════
  //  ①プロンプトをコピー（子どもは C01 などの記号・写真のファイル名も同じ記号）
  //  ②選んだ写真をまとめてダウンロード（ZIP：番号_日付_教科.jpg ／ PDF：1ファイルに見出しつき）
  //  ③AIの返事を貼って取り込む（今日のひと往復と同じ取り込み・同じ ④ 先生が確認して公開）
  //  ※ アプリの中ではAIを動かさない。写真を外部AIに送るかどうかは先生の判断。
  var AI_MAX = 200;
  function ymdAdd(days) { return new Date(Date.now() + 9 * 3600000 + days * 86400000).toISOString().slice(0, 10); }
  function aiPanelHtml(d) {
    var studs = (d.students || []);
    return '<div style="background:#fff;border:2px solid #f0abfc;border-radius:12px;padding:10px;margin-bottom:10px">' +
      '<b style="font-size:14px">🤖 AIで成果物を分析</b><span style="font-size:11px;color:#64748b;margin-left:6px">外部のAI（ChatGPT・Gemini・Claude）に、先生がプロンプトと写真を貼ります。アプリの中ではAIを動かしません。</span>' +
      '<div style="font-size:12px;margin-top:6px"><b>子ども</b> ' + btn('全員', 'PF._aiAll(true)', '#64748b') + btn('はずす', 'PF._aiAll(false)', '#94a3b8') +
      '<div style="display:flex;flex-wrap:wrap;gap:4px 10px;margin-top:4px">' + studs.map(function (s) {
        return '<label style="white-space:nowrap"><input type="checkbox" class="pfAiStu" value="' + esc(s.userId) + '"> ' + esc(stuLabel(s)) + '<span style="color:#94a3b8">（' + (s.n || 0) + '）</span></label>';
      }).join('') + '</div></div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:6px;font-size:12px"><b>期間</b>' +
      '<input id="pfAiFrom" type="date" value="' + ymdAdd(-30) + '" style="border:1px solid #cbd5e1;border-radius:8px;padding:4px">〜' +
      '<input id="pfAiTo" type="date" value="' + jstToday() + '" style="border:1px solid #cbd5e1;border-radius:8px;padding:4px">' +
      '<b style="margin-left:6px">教科</b><select id="pfAiSubj" style="border:1px solid #cbd5e1;border-radius:8px;padding:4px"><option value="">すべて</option><option>家庭学習</option>' + SUBJ.map(function (x) { return '<option>' + x + '</option>'; }).join('') + '</select></div>' +
      '<div style="background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:6px;margin-top:6px;font-size:12px;color:#991b1b"><b>⚠ 名前が写っている写真は外すか、隠してから貼ってね。</b>' +
      '<div style="color:#475569;margin-top:2px">💡 外部AIは「一時チャット」（履歴に残らないモード）がおすすめです。AIによっては一度に貼れる写真の数に上限があります（目安20まい）。多いときは PDF（1つのファイル）を使ってください。</div></div>' +
      '<label style="display:block;margin-top:6px;font-size:12px"><input type="checkbox" id="pfAiRec" checked> <b>📊 評価（3観点 A・B・C と根拠）も いっしょに読ませる</b><span style="color:#64748b">（先生だけ。確かめてから 成績・記録に保存。子どもには出ません。分析タブの「成果物・振り返り」の取り込みは ここに まとめました）</span></label>' +   /* WORKREC_V1 */
      '<div style="margin-top:6px">' + btn('① AIに渡すプロンプトをコピー', 'PF._aiCopy()', '#a21caf') +
      btn('② 写真をまとめてダウンロード（ZIP）', 'PF._aiZip()', '#1d4ed8') + btn('②’ 1つのPDFで', 'PF._aiPdf()', '#1e40af') +
      '<span id="pfAiSt" style="font-size:12px;font-weight:bold;color:#86198f;margin-left:4px"></span></div>' +
      '<textarea id="pfAiCopyBox" readonly style="display:none;width:100%;height:90px;font-size:11px;border:1px solid #cbd5e1;border-radius:8px;margin-top:4px"></textarea>' +
      '<div style="margin-top:8px;font-size:12px"><b>③ AIの返事を貼り付け</b>（=== [ ... ] === の目印ごとに読み取ります）</div>' +
      '<textarea id="pfAiPaste" rows="4" placeholder="AIの返事をぜんぶ貼り付け" style="width:100%;font-size:12px;border:1px solid #cbd5e1;border-radius:8px;padding:6px"></textarea>' +
      '<div>' + btn('🔍 下書きに取り込む', 'PF._aiImport()', '#4f46e5') + '<span id="pfAiImpSt" style="font-size:12px;font-weight:bold;color:#3730a3;margin-left:4px"></span>' +
      '<span id="pfAiGo" style="display:none">' + btn('④ 確認して公開へ →', 'PF._aiGo()', '#e11d48') + '</span></div>' +
      '<div id="pfRecPrev"></div>' +   /* WORKREC_V1 */
      '<p style="font-size:11px;color:#64748b;margin-top:4px">取り込んだ文は「④ 📊分析・カルテ → 📋今日のひと往復 の ④」に下書きとして入ります。先生が確認して公開するまで、子どもには届きません。公開すると「📓 成果物へのひとこと」は子どもの カルテ（アプリ・紙）に、「成果物の分析メモ」は先生だけのメモとして次回のコピーの「先週までの流れ」に入ります。</p>' +
      '</div>';
  }
  function aiSel() {
    var uids = []; var cbs = document.querySelectorAll('.pfAiStu');
    for (var i = 0; i < cbs.length; i++) if (cbs[i].checked) uids.push(cbs[i].value);
    return { classId: S.classId, uids: uids, from: ($('pfAiFrom') || {}).value || ymdAdd(-30), to: ($('pfAiTo') || {}).value || jstToday(), subj: ($('pfAiSubj') || {}).value || '' };
  }
  // 子どもの記号（C01…）。このタブのあいだは同じ子に同じ記号（プロンプトとファイル名をそろえるため）
  function codesFor(uids) {
    var key = 'pfAiCodes:' + S.classId, m = {};
    try { m = JSON.parse(sessionStorage.getItem(key) || '{}') || {}; } catch (e) { m = {}; }
    var used = {}; Object.keys(m).forEach(function (k) { used[m[k]] = 1; });
    var n = Math.max(40, (S.sum && S.sum.students ? S.sum.students.length : 0) + 5);
    uids.forEach(function (u) {
      if (m[u]) return;
      for (var t = 0; t < 500; t++) { var k = 1 + Math.floor(Math.random() * n), c = 'C' + (k < 10 ? '0' + k : '' + k); if (!used[c]) { m[u] = c; used[c] = 1; break; } }
    });
    try { sessionStorage.setItem(key, JSON.stringify(m)); } catch (e) {}
    return m;
  }
  function safeSubj(it) { return String(it.subj || (it.src === 'hw' ? '家庭学習' : 'その他')).replace(/[\\/:*?"<>|\s]/g, ''); }
  async function aiSnap() {
    var sel = aiSel();
    if (!sel.uids.length) throw new Error('子どもを えらんでください');
    if (sel.from > sel.to) throw new Error('期間が逆になっています');
    var k = JSON.stringify(sel);
    if (S.ai && S.ai.key === k) return S.ai;
    var d = await getJ('/api/teacher/portfolio/range?classId=' + encodeURIComponent(sel.classId) + '&from=' + sel.from + '&to=' + sel.to + '&subj=' + encodeURIComponent(sel.subj) + '&userIds=' + encodeURIComponent(sel.uids.join(',')));
    if (!d || !d.ok) throw new Error(errJa(d));
    var items = d.items || [];
    if (!items.length) throw new Error('この期間の写真がありません');
    if (items.length > AI_MAX) throw new Error('写真が ' + items.length + 'まい あります。' + AI_MAX + 'まい以下になるよう、子どもか期間をしぼってください');
    var codes = codesFor(sel.uids);
    var groups = {}, order = [];
    items.forEach(function (it) { var u = String(it.userId); if (!groups[u]) { groups[u] = []; order.push(u); } groups[u].push(it); });
    order.sort(function (a, b) { return codes[a] < codes[b] ? -1 : 1; });
    var entries = [];
    order.forEach(function (u) {
      groups[u].forEach(function (it, i) {
        var no = codes[u] + '-' + (i + 1 < 10 ? '0' + (i + 1) : '' + (i + 1));
        entries.push({ uid: u, code: codes[u], no: no, file: no + '_' + it.takenOn + '_' + safeSubj(it) + '.jpg', it: it });
      });
    });
    S.ai = { key: k, sel: sel, codes: codes, order: order, groups: groups, entries: entries };
    return S.ai;
  }
  function maskFor(t, uid) {
    t = String(t || '');
    try { (S.sum.students || []).forEach(function (s) { [s.name, s.loginId].forEach(function (n) { if (n && String(n).length >= 2) t = t.split(String(n)).join('（名前）'); }); }); } catch (e) {}
    try { if (window._qnMask) t = window._qnMask(t); } catch (e) {}
    return t;
  }
  function aiPromptText(sn, prev) {
    var L = [], NL = String.fromCharCode(10);
    L.push('あなたは小学校の先生のアシスタントです。子どものノート・作品の写真を見て、子どもに返す短いことばと、先生用のメモを書いてください。');
    L.push('');
    L.push('【このあと貼る写真】');
    L.push('・ファイル名（または PDF の各ページの見出し）は「番号_日付_教科」です。番号の「C01-02」は「C01 の子の 2まい目」という意味です。');
    L.push('・C01 などは子どもの名前のかわりの記号です。同じ記号は同じ子です。写真の中に名前が写っていても、読まない・書かないでください。');
    L.push('・同じ子の写真は、日付の古い順にならんでいます。');
    L.push('');
    L.push('【見るポイント】（写真から分かることだけ）');
    L.push('・書く量の変化（同じ子の前の写真とくらべて）');
    L.push('・ていねいさ（字の大きさやそろえ方、行のつかい方、消したあと など）');
    L.push('・考え方の書き方（式・ことば・矢印などで、考えた道すじを書いているか）');
    L.push('・図や表、式の使い方');
    L.push('・前回の分析メモ（下にあれば）からの変化');
    L.push('');
    L.push('【書き方のきまり】');
    L.push('・WORK と WORKMEMO の欄には、評価・点数・◎○△・ABC・順位・「よくできた／できていない」の判定は書かない。ほかの子と比べない。' + (sn.rec ? '（評価は WORKREC の欄だけに書く）' : ''));
    L.push('・否定的なことば（できていない・雑・きたない・読みにくい・〜しかない など）は使わない。見えた事実と前向きな言い方で。');
    L.push('・次に試せる小さな工夫は 1つだけ。本人が「やってみようかな」と選べる言い方で（命令しない）。');
    L.push('・写真から読み取れないことは書かない。推しはかるときは「〜かも」と分かる書き方にする。');
    L.push('・記号（C01 など）は、子どもに返す文の中には書かない。');
    try { (window.TAI_NG_RULE_LINES || []).forEach(function (x) { L.push(x); }); } catch (e) {}
    L.push('【書いてほしい欄】（子どもごとに、下の目印の行のすぐ下に書く）');
    L.push('・WORKMEMO の欄 … 先生用のメモ。事実だけで2〜3文（100字以内）。見えた変化と、次に見たいところ。記号を使ってよい。');
    L.push('・WORK の欄 … 子どもに返すひとこと。やさしい話しことばで3〜4文（120字くらい）。見えたよさ → 前とくらべた変化 → 次に試せる小さな工夫1つ。');
    L.push('・目印の行（=== [...] === ）は1文字も変えずにそのまま残す。行の順番も変えない。前置き・あいさつ・まとめは書かない。');
    L.push('');
    if (sn.rec) recPromptLines(sn).forEach(function (x) { L.push(x); });   /* WORKREC_V1 */
    sn.order.forEach(function (u) {
      var g = sn.groups[u], code = sn.codes[u];
      L.push('--------------------------------------------------');
      L.push('▼ ' + code + '（写真 ' + g.length + 'まい・古い順）');
      sn.entries.filter(function (e) { return e.uid === u; }).forEach(function (e) {
        var memo = e.it.memo ? '／先生のメモ: ' + maskFor(e.it.memo, u) : '';
        L.push('・' + e.file + '（' + (e.it.src === 'hw' ? '家庭学習で本人が出した写真' : '先生が学校で撮った写真') + memo + '）');
      });
      var pv = prev[u];
      L.push('・前回の分析メモ: ' + (pv ? '「' + maskFor(pv.text, u) + '」（' + pv.at + '）' : 'なし（はじめての分析）'));
      L.push('');
      L.push('=== [WORKMEMO:' + u + '] ===');
      L.push('');
      L.push('=== [WORK:' + u + '] ===');
      L.push('');
      if (sn.rec) sn.entries.filter(function (e) { return e.uid === u; }).forEach(function (e) { L.push('=== [WORKREC:' + u + ':' + e.no + '] ==='); L.push(''); });   /* WORKREC_V1 写真1まいごと */
    });
    return L.join(NL);
  }
  async function copyOut(txt) {
    var box = $('pfAiCopyBox');
    try { await navigator.clipboard.writeText(txt); if (box) box.style.display = 'none'; return true; }
    catch (e) { if (box) { box.value = txt; box.style.display = 'block'; box.focus(); box.select(); } return false; }
  }
  async function aiCopy() {
    var st = $('pfAiSt');
    try {
      st.textContent = '作っています…';
      var sn = await aiSnap();
      sn.rec = recOn(); if (sn.rec) sn.grade = await classGrade();   /* WORKREC_V1 */
      var prev = {};
      var f = await getJ('/api/teacher/ai-flow?classId=' + encodeURIComponent(S.classId) + '&days=42');
      if (f && f.ok) Object.keys(f.byUser || {}).forEach(function (u) { var m = (f.byUser[u] || []).filter(function (x) { return x.kind === 'WORKMEMO'; })[0]; if (m) prev[u] = m; });
      var txt = aiPromptText(sn, prev);
      var ok2 = await copyOut(txt);
      st.textContent = (ok2 ? '✓ コピーしました' : '下の枠を全部えらんでコピーしてください') + '（' + sn.order.length + '人・写真 ' + sn.entries.length + 'まい）。次に ② で写真をダウンロードして、AIにプロンプトと写真を貼ってください';
    } catch (e) { st.textContent = String(e && e.message || e); }
  }
  async function aiFetchAll(st, each) {
    var sn = await aiSnap();
    for (var i = 0; i < sn.entries.length; i++) {
      st.textContent = 'ダウンロードの準備… ' + (i + 1) + '/' + sn.entries.length;
      var r = await fetch(img(sn.entries[i].it.id), { credentials: 'include' });
      if (!r.ok) continue;
      await each(sn.entries[i], r);
    }
    return sn;
  }
  function saveBlob(blob, name) {
    var a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(function () { try { URL.revokeObjectURL(a.href); a.remove(); } catch (e) {} }, 4000);
  }
  async function aiZip() {
    var st = $('pfAiSt'), files = [];
    try {
      var sn = await aiFetchAll(st, async function (e, r) { files.push({ name: e.file, data: new Uint8Array(await r.arrayBuffer()) }); });
      if (!files.length) { st.textContent = '写真を読めませんでした'; return; }
      var blob = makeZip(files);
      saveBlob(blob, 'AI用_成果物_' + jstToday() + '.zip');
      st.textContent = '✓ ' + files.length + 'まい（' + mb(blob.size) + '）。ZIPを開いて、中の写真をAIにまとめて貼ってください';
    } catch (e) { st.textContent = String(e && e.message || e); }
  }
  // 写真の上に見出し（番号_日付_教科）をつけて1ページずつ。PDF は JPEG をそのまま入れる最小の形
  async function labeled(blob, label) {
    var L = await loadImage(blob);
    try {
      var im = L.im, w0 = im.naturalWidth || im.width, h0 = im.naturalHeight || im.height;
      var sc = Math.min(1, 1400 / Math.max(w0, h0)), w = Math.max(1, Math.round(w0 * sc)), h = Math.max(1, Math.round(h0 * sc));
      var band = Math.max(40, Math.round(w * 0.05));
      var cv = document.createElement('canvas'); cv.width = w; cv.height = h + band;
      var g = cv.getContext('2d'); g.fillStyle = '#fff'; g.fillRect(0, 0, w, h + band);
      g.fillStyle = '#111'; g.font = 'bold ' + Math.round(band * 0.55) + 'px sans-serif'; g.textBaseline = 'middle'; g.fillText(label, 10, band / 2);
      g.drawImage(im, 0, band, w, h);
      var b = await new Promise(function (res) { cv.toBlob(res, 'image/jpeg', 0.8); });
      return { jpg: new Uint8Array(await b.arrayBuffer()), w: w, h: h + band };
    } finally { try { URL.revokeObjectURL(L.u); } catch (e) {} }
  }
  function makePdf(pages) {   // pages: [{jpg:Uint8Array, w, h}]
    var enc = new TextEncoder(), parts = [], off = 0, offs = [];
    function add(x) { var u = typeof x === 'string' ? enc.encode(x) : x; parts.push(u); off += u.length; }
    var n = pages.length, total = 2 + n * 3;
    add('%PDF-1.4\n%\xE2\xE3\xCF\xD3\n'.replace(/[\u0080-ÿ]/g, 'x'));
    offs[1] = off; add('1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n');
    var kids = []; for (var i = 0; i < n; i++) kids.push((3 + i * 3) + ' 0 R');
    offs[2] = off; add('2 0 obj\n<< /Type /Pages /Count ' + n + ' /Kids [' + kids.join(' ') + '] >>\nendobj\n');
    pages.forEach(function (p, i) {
      var po = 3 + i * 3, co = po + 1, io = po + 2;
      var pw = 595, ph = Math.round(p.h * 595 / p.w * 100) / 100;
      var cs = 'q ' + pw + ' 0 0 ' + ph + ' 0 0 cm /Im0 Do Q';
      offs[po] = off; add(po + ' 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ' + pw + ' ' + ph + '] /Resources << /XObject << /Im0 ' + io + ' 0 R >> >> /Contents ' + co + ' 0 R >>\nendobj\n');
      offs[co] = off; add(co + ' 0 obj\n<< /Length ' + cs.length + ' >>\nstream\n' + cs + '\nendstream\nendobj\n');
      offs[io] = off; add(io + ' 0 obj\n<< /Type /XObject /Subtype /Image /Width ' + p.w + ' /Height ' + p.h + ' /ColorSpace /DeviceRGB /BitsPerComponent 8 /Filter /DCTDecode /Length ' + p.jpg.length + ' >>\nstream\n');
      add(p.jpg); add('\nendstream\nendobj\n');
    });
    var xref = off;
    var x = 'xref\n0 ' + (total + 1) + '\n0000000000 65535 f \n';
    for (var k = 1; k <= total; k++) x += String(offs[k]).padStart(10, '0') + ' 00000 n \n';
    add(x + 'trailer\n<< /Size ' + (total + 1) + ' /Root 1 0 R >>\nstartxref\n' + xref + '\n%%EOF\n');
    return new Blob(parts, { type: 'application/pdf' });
  }
  try { window.__PF_PDF = makePdf; } catch (e) {}
  async function aiPdf() {
    var st = $('pfAiSt'), pages = [];
    try {
      await aiFetchAll(st, async function (e, r) { pages.push(await labeled(await r.blob(), e.file.replace(/\.jpg$/, ''))); });
      if (!pages.length) { st.textContent = '写真を読めませんでした'; return; }
      var blob = makePdf(pages);
      saveBlob(blob, 'AI用_成果物_' + jstToday() + '.pdf');
      st.textContent = '✓ ' + pages.length + 'ページ（' + mb(blob.size) + '）。このPDFを1つ、AIに貼ってください';
    } catch (e) { st.textContent = String(e && e.message || e); }
  }

  // ═════════ 📊 WORKREC_V1 成果物の評価も ここで（分析タブの「成果物・振り返り」の取り込みを まとめた） ═════════
  //  ・同じ写真・同じAIの返事から、子どもへの 📓ひとこと（WORK）・先生のメモ（WORKMEMO）・評価の記録（WORKREC）を作る。
  //  ・WORKREC は 先生だけ。/api/teacher/records/save（分析タブの取り込みと同じ記録）に入る。子どもの画面・紙には出さない。
  //  ・評価のきまり（3観点・B が標準・根拠を書く・読み取れない観点は付けない・先生の印は写すだけ）は 分析タブのプロンプトと同じ。
  function recOn() { var c = $('pfAiRec'); return !c || !!c.checked; }
  async function classGrade() {
    try {
      var d = await getJ('/api/teacher/class/' + encodeURIComponent(S.classId) + '/members');
      var ms = (d && d.members) || [], gc = {}, best = '', bn = 0;
      ms.forEach(function (m) { var g = m.grade; if (g) { gc[g] = (gc[g] || 0) + 1; if (gc[g] > bn) { bn = gc[g]; best = String(g); } } });
      return best;
    } catch (e) { return ''; }
  }
  function recPromptLines(sn) {
    var L = [];
    L.push('【WORKREC の欄】先生用の評価の記録（子どもには出ません）。写真1まいごとに、目印の行のすぐ下に 次の形で書く。');
    L.push('題: （成果物の題。なければ内容を短く要約）');
    L.push('教科: （国語・算数・理科・社会 など。わからなければ空欄）');
    L.push('単元: （わかれば。なければ空欄）');
    L.push('本文: （子どもが書いた中身を、読み取れる範囲で。長いときは要約してよい。複数行でよい）');
    L.push('振り返り: （子どもの振り返りが書いてあれば。なければ空欄）');
    L.push('先生の印: （写真に先生が書いた ◎ / ○ / △ があれば写す。無ければ空欄。あなたが新しく付けないこと）');
    L.push('評価コメント:');
    L.push('知識・技能：A / B / C のどれか');
    L.push('　「そう判断した根拠を、成果物に書かれていることで示す」');
    L.push('思考・判断・表現：A / B / C のどれか');
    L.push('　「そう判断した根拠を、成果物に書かれていることで示す」');
    L.push('主体的に学習に取り組む態度：A / B / C のどれか');
    L.push('　「そう判断した根拠を、成果物に書かれていることで示す」');
    L.push('');
    L.push('【評価のきまり】小学校学習指導要領の観点別学習状況の評価と同じ3観点。');
    L.push('・A … その単元の目標を十分に達成している／B … おおむね達成している／C … 達成に向けて支援が必要');
    L.push('・B が標準。ふつうにできていれば B。A は「ここまでできているのか」と先生が驚くときだけ。A ばかりにしない。');
    L.push('・この写真から読み取れる範囲だけで書く。その観点が読み取れないときは、評定をつけず「この成果物からは分かりません」と書く（計算プリント1枚から 主体的な態度は読み取れない など）。');
    L.push('・評定だけで終わらせず、次の行に かぎかっこ「」で根拠を書く。性格や人柄を否定しない（「雑」「やる気がない」などは使わない）。');
    L.push('・教科と単元が分かるときは、その単元の目標に照らして判断する。');
    try {
      var EK = (typeof window._ekTable === 'function') ? window._ekTable() : null, g = EK && sn.grade ? EK[String(sn.grade)] : null;
      if (g) {
        L.push('【' + sn.grade + '年の評価規準（本校教育課程より）／教科に合うものに照らして判断する】');
        ['国語', '算数', '理科', '社会'].forEach(function (k) { var e = g[k]; if (e) L.push('■' + k + '／知識・技能：' + e.kt + '／思考・判断・表現：' + e.sh + '／主体的に学習に取り組む態度：' + e.st); });
      }
    } catch (e) {}
    L.push('');
    return L;
  }
  var REC_KEYS = { '題': 'title', 'タイトル': 'title', '日付': 'day', '教科': 'subject', '単元': 'unit', '本文': 'body', '振り返り': 'reflection', 'ふりかえり': 'reflection', '先生の印': 'evalRank', '評価': 'evalRank', '評価コメント': 'evalComment' };
  // AIの返事から WORKREC の欄を取り出す（rows）。のこり（rest）は 今日のひと往復の取り込みへ。
  function splitRec(raw) {
    var lines = String(raw || '').replace(/\r/g, '').split('\n'), rest = [], rows = [], cur = null, key = '';
    var mk = /^\s*={2,}\s*\[\s*([A-Za-z]+)\s*[:：]\s*([^\]]*?)\s*\]\s*={2,}\s*$/;
    lines.forEach(function (ln) {
      var m = ln.match(mk);
      if (m) {
        if (cur) rows.push(cur);
        cur = null; key = '';
        if (m[1].toUpperCase() === 'WORKREC') {
          var parts = m[2].split(/[:：]/);
          cur = { userId: String(parts[0] || '').trim(), no: String(parts[1] || '').trim(), title: '', day: '', subject: '', unit: '', body: '', reflection: '', evalRank: '', evalComment: '' };
          return;
        }
        rest.push(ln); return;
      }
      if (!cur) { rest.push(ln); return; }
      var km = ln.match(/^\s*([^:：\s]{1,6})\s*[:：]\s*(.*)$/);
      if (km && REC_KEYS[km[1]] && !(key === 'evalComment' && /^(知識|思考|主体)/.test(km[1]))) { key = REC_KEYS[km[1]]; cur[key] = km[2].trim(); return; }
      if (key) cur[key] = cur[key] ? cur[key] + '\n' + ln.replace(/\s+$/, '') : ln.trim();
    });
    if (cur) rows.push(cur);
    rows = rows.map(function (r) {
      Object.keys(r).forEach(function (k) { r[k] = String(r[k] || '').replace(/^\s+|\s+$/g, ''); });
      var mk2 = r.evalRank.match(/[◎○△]/); r.evalRank = mk2 ? mk2[0] : '';
      if (/^[（(]?(なし|空欄|ない)[)）]?$/.test(r.reflection)) r.reflection = '';
      return r;
    }).filter(function (r) { return r.userId && (r.title || r.body || r.reflection || r.evalComment); });
    return { rows: rows, rest: rest.join('\n') };
  }
  // 写真の 日付・教科で 足りないところを うめる
  function fillFromPhoto(rows) {
    var sn = S.ai, by = {};
    if (sn && sn.entries) sn.entries.forEach(function (e) { by[e.uid + ':' + e.no] = e.it; });
    rows.forEach(function (r) {
      var it = by[r.userId + ':' + r.no];
      if (it) { if (!/^\d{4}-\d{2}-\d{2}$/.test(r.day)) r.day = it.takenOn || ''; if (!r.subject) r.subject = it.subj || (it.src === 'hw' ? '家庭学習' : ''); }
      if (!/^\d{4}-\d{2}-\d{2}$/.test(r.day)) r.day = '';
      r.title = (r.title || r.body.split('\n')[0] || '成果物').slice(0, 200);
    });
    return rows;
  }
  // 3観点を 評価コメントから読む（「この成果物からは分かりません」は 空）
  function kanten(txt) {
    var t = String(txt || ''), o = {};
    [['k', /知識[・･]?技能\s*[：:]\s*([ABCＡＢＣ])/], ['t', /思考[・･]?判断[・･]?表現\s*[：:]\s*([ABCＡＢＣ])/], ['a', /主体的に学習に取り組む態度\s*[：:]\s*([ABCＡＢＣ])/]].forEach(function (x) {
      var m = t.match(x[1]); o[x[0]] = m ? String.fromCharCode(m[1].charCodeAt(0) > 255 ? m[1].charCodeAt(0) - 65248 : m[1].charCodeAt(0)) : '';
    });
    return o;
  }
  // 行き先は 分析タブの取り込みと同じ決まり：観点別（A・B・C）があれば「成績」（通知表が読む表）、なければ「記録」
  function recDest(r) { var k = kanten(r.evalComment); r.k = k.k; r.t = k.t; r.a = k.a; return (k.k || k.t || k.a) ? 'score' : 'record'; }
  function stuName(uid) { try { var s = (S.sum.students || []).filter(function (x) { return String(x.userId) === String(uid); })[0]; return s ? stuLabel(s) : uid; } catch (e) { return uid; } }
  function recPreviewHtml(rows) {
    var h = '<div style="margin-top:8px;border:2px solid #a855f7;border-radius:10px;padding:8px;background:#faf5ff">' +
      '<b style="font-size:13px">📊 評価の記録（先生だけ）… 確かめてから保存</b><span style="font-size:11px;color:#64748b;margin-left:6px">A・B・C が入っている行は「成績」（通知表・分析が読む表）へ、入っていない行は「記録」へ。分析タブの取り込みと同じ決まりです。</span>' +
      '<div style="overflow-x:auto"><table style="border-collapse:collapse;font-size:11.5px;margin-top:4px;width:100%"><tr style="background:#ede9fe">' +
      ['保存', '子ども', '写真', '題', '教科', '知技', '思判表', '主体', '先生の印', '行き先', '根拠（評価コメント）'].map(function (x) { return '<th style="border:1px solid #c4b5fd;padding:2px 4px;white-space:nowrap">' + x + '</th>'; }).join('') + '</tr>';
    rows.forEach(function (r, i) {
      var d = recDest(r), cm = String(r.evalComment || '').replace(/\s+/g, ' ');
      h += '<tr><td style="border:1px solid #ddd;text-align:center"><input type="checkbox" class="pfRecOk" data-i="' + i + '" checked></td>' +
        '<td style="border:1px solid #ddd;padding:2px 4px;white-space:nowrap">' + esc(stuName(r.userId)) + '</td>' +
        '<td style="border:1px solid #ddd;padding:2px 4px;white-space:nowrap">' + esc(r.no) + '</td>' +
        '<td style="border:1px solid #ddd;padding:2px 4px">' + esc(r.title) + '</td>' +
        '<td style="border:1px solid #ddd;padding:2px 4px;white-space:nowrap">' + esc(r.subject) + '</td>' +
        ['k', 't', 'a'].map(function (k) { return '<td style="border:1px solid #ddd;text-align:center;font-weight:bold">' + esc(r[k] || '－') + '</td>'; }).join('') +
        '<td style="border:1px solid #ddd;text-align:center">' + esc(r.evalRank || '') + '</td>' +
        '<td style="border:1px solid #ddd;padding:2px 4px;white-space:nowrap">' + (d === 'score' ? '成績' : '記録') + '</td>' +
        '<td style="border:1px solid #ddd;padding:2px 4px;min-width:240px">' + esc(cm.length > 140 ? cm.slice(0, 139) + '…' : cm) + '</td></tr>';
    });
    return h + '</table></div><div style="margin-top:6px">' + btn('💾 チェックした評価を保存', 'PF._recSave()', '#7c3aed') + '<span id="pfRecSt" style="font-size:12px;font-weight:bold;color:#6d28d9;margin-left:4px"></span></div></div>';
  }
  async function saveRec(rows) {
    var recs = [], groups = {}, order = [], out = { record: 0, score: 0 };
    rows.forEach(function (r) {
      if (recDest(r) === 'record') { recs.push({ userId: r.userId, title: r.title, body: r.body, reflection: r.reflection, evalRank: r.evalRank, evalComment: r.evalComment, subject: r.subject, unit: r.unit, day: r.day }); return; }
      var key = [r.title, r.day, r.subject].join('|');   // 同じ成果物（題・日・教科）ごとに1つの「成績」にまとめる
      if (!groups[key]) { groups[key] = { testName: r.title, testDate: r.day, subject: r.subject, rows: [] }; order.push(key); }
      groups[key].rows.push({ userId: r.userId, score: null, evalRank: r.evalRank || '', evalKnowledge: r.k, evalThinking: r.t, evalAttitude: r.a, comment: r.evalComment });
    });
    for (var i = 0; i < order.length; i++) {
      var g = groups[order[i]];
      var d = await postJ('/api/teacher/test-scores/save', { classId: S.classId, testName: g.testName, testDate: g.testDate, subject: g.subject, maxScore: 100, rows: g.rows });
      if (!d || !d.ok) throw new Error('成績を保存できませんでした' + (d && d.error ? '（' + d.error + '）' : ''));
      out.score += d.saved || 0;
    }
    if (recs.length) {
      var d2 = await postJ('/api/teacher/records/save', { classId: S.classId, rows: recs });
      if (!d2 || !d2.ok) throw new Error('記録を保存できませんでした' + (d2 && d2.error ? '（' + d2.error + '）' : ''));
      out.record += d2.saved || 0;
    }
    return out;
  }
  async function recSave() {
    var st = $('pfRecSt'), rows = S.recRows || [], pick = [];
    var cbs = document.querySelectorAll('.pfRecOk');
    for (var i = 0; i < cbs.length; i++) if (cbs[i].checked) pick.push(rows[Number(cbs[i].getAttribute('data-i'))]);
    if (!pick.length) { st.textContent = '保存する行に チェックを入れてください'; return; }
    st.textContent = '保存中…';
    try {
      var o = await saveRec(pick);
      st.textContent = '✓ 成績に ' + o.score + '件・記録に ' + o.record + '件 保存しました（同じものは 二重に入りません）';
      S.recRows = null;
    } catch (e) { st.textContent = String(e && e.message || e); }
  }
  async function aiImport() {
    var st = $('pfAiImpSt'), ta = $('pfAiPaste');
    var raw = ta ? ta.value : '';
    S.aiRaw = raw;
    if (!raw.trim()) { st.textContent = 'AIの返事を貼り付けてください'; return; }
    if (typeof window.taiImport !== 'function') { st.textContent = 'この画面では取り込めません（今日のひと往復が読み込まれていません）'; return; }
    if (!/\[\s*WORK(MEMO|REC)?\s*[:：]/i.test(raw)) { st.textContent = '成果物の目印（=== [WORK:…] === など）が見つかりません'; return; }
    st.textContent = '読み取り中…';
    /* WORKREC_V1 評価の記録（先生だけ）は ここで保存。のこり（📓ひとこと・メモ）は これまでどおり ひと往復の下書きへ */
    var sp = splitRec(raw), recMsg = '', box = $('pfRecPrev');
    if (sp.rows.length) {
      S.recRows = fillFromPhoto(sp.rows);
      if (box) box.innerHTML = recPreviewHtml(S.recRows);
      recMsg = '📊 評価 ' + S.recRows.length + '件は 下の表で 確かめてから保存してね（先生だけ）';
    } else if (box) box.innerHTML = '';
    var last = '';
    if (/\[\s*WORK(MEMO)?\s*[:：]/i.test(sp.rest)) {
      await window.taiImport({ append: true, raw: sp.rest, classId: S.classId, say: function (m) { last = String(m || ''); st.textContent = last + (recMsg ? '／' + recMsg : ''); } });
    } else { last = '✓'; st.textContent = recMsg || '取り込むものがありませんでした'; }
    if (/^✓/.test(last)) { if (ta) ta.value = ''; S.aiRaw = ''; var go = $('pfAiGo'); if (go && /WORK(MEMO)?\s*[:：]/i.test(sp.rest)) go.style.display = 'inline'; }
  }
  function aiGo() {
    var o = $('pfOverlay'); if (o) o.style.display = 'none'; document.body.style.overflow = '';
    try { var cf = $('analyticsClassFilter'); if (cf && cf.querySelector('option[value="' + S.classId + '"]')) cf.value = S.classId; } catch (e) {}
    try { if (typeof window.switchTab === 'function') window.switchTab('analytics'); } catch (e) {}
    try { if (typeof window.taiLoadDrafts === 'function') window.taiLoadDrafts(); } catch (e) {}
    setTimeout(function () { try { var b = $('taiDraftList'); if (b && b.scrollIntoView) b.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (e) {} }, 300);
  }

  // ── 点数・評価・比べることばも 🟡 で知らせる（今日のひと往復の NG 語に足す。自動では消さない） ──
  try {
    var NGP = ['点数', '得点', '満点', '何点', '点やった', '点だった', '点でした', '点とれ', '点取れ', 'パーセント', '％', '◎', '△', '評価', 'Aランク',
      '下手', 'へた', '汚い', 'きたない', '読みにくい', '雑やな', '雑だ', 'ざつ', '上手じゃない', '上手やない', 'ていねいじゃない', 'ていねいやない', 'ほかの子', '友だちより', 'クラスで一番', 'いちばん上手'];
    var _ngw = window.TAI_NG_WORDS;
    if (_ngw && _ngw.push) NGP.forEach(function (w) { if (_ngw.indexOf(w) < 0) _ngw.push(w); });
  } catch (e) {}

  // ── 📓 紙のカルテ：うらの「🎯 来週の めあて」の前に「📓 ノート・作品から」を入れる ──
  //    MICHI_V1（karte-michi.js）が作りかえたあとの HTML に足す。michi が入ったのを待ってから外側に包む。
  var _work = {}, _workAt = 0;
  async function loadWork(force) {
    if (!force && Date.now() - _workAt < 60000) return;
    _workAt = Date.now();
    var d = await getJ('/api/teacher/portfolio/work-notes');
    if (d && d.ok) _work = d.byUser || {};
  }
  function karteWithWork(html) {
    try {
      var fd = window._faData || {};
      var uid = String((fd.student && fd.student.id) || fd.studentId || '');
      var w = uid && _work[uid];
      if (!w || !w.text) return html;
      var t = String(w.text).replace(/\s+/g, ' ');
      if (t.length > 200) t = t.slice(0, 199) + '…';
      var sec = '<div class="sec" style="border-color:#bae6fd;background:#f0f9ff"><h2>📓 ノート・作品から</h2><div style="font-size:12.5px;color:#334155">' + esc(t) + '</div></div>';
      var anchors = ['<div class="sec" style="border-color:#fcd34d"><h2>🎯', '<div class="foot">', '</body>'];
      for (var i = 0; i < anchors.length; i++) { var k = html.indexOf(anchors[i]); if (k >= 0) return html.slice(0, k) + sec + html.slice(k); }
      return html + sec;
    } catch (e) { return html; }
  }
  function installKarte(force) {
    var cur = window._buildKarteHtml;
    if (typeof cur !== 'function' || cur.__pfwork) return !!(cur && cur.__pfwork);
    if (!cur.__michi && !force) return false;   // michi が先
    var wrapped = function () { return karteWithWork(cur.apply(this, arguments)); };
    wrapped.__pfwork = true; wrapped.__michi = true; wrapped.__orig = cur;
    window._buildKarteHtml = wrapped;
    var oa = window.downloadAllKartes;
    if (typeof oa === 'function' && !oa.__pfwork) {
      var wa = async function () { try { await loadWork(true); } catch (e) {} return oa.apply(this, arguments); };
      wa.__pfwork = true; wa.__michi = true; window.downloadAllKartes = wa;
    }
    return true;
  }
  (function bootKarte() {
    var tries = 0;
    var tm = setInterval(function () { tries++; if (installKarte(tries >= 40) || tries >= 45) clearInterval(tm); }, 1000);
    setTimeout(function () { loadWork(true); }, 1500);
  })();
  try { window.__PF_KARTE = { karteWithWork: karteWithWork, setWork: function (m) { _work = m || {}; }, install: installKarte }; } catch (e) {}

  window.PF = {
    open: open,
    _aiAll: function (on) { var cbs = document.querySelectorAll('.pfAiStu'); for (var i = 0; i < cbs.length; i++) cbs[i].checked = !!on; },
    _aiCopy: aiCopy, _aiZip: aiZip, _aiPdf: aiPdf, _aiImport: aiImport, _aiGo: aiGo,
    _recSave: recSave,
    _rec: { splitRec: splitRec, fillFromPhoto: fillFromPhoto, recPromptLines: recPromptLines, kanten: kanten, recDest: recDest, saveRec: saveRec, recPreviewHtml: recPreviewHtml },   /* WORKREC_V1 テスト用 */
    _home: function () { S.stu = null; renderHome(); },
    _stu: openStu, _tap: tap, _lc: lightClose, _save: saveItem, _del: delItem, _zip: zip,
    _cmp: function () { S.cmp = !S.cmp; S.pick = []; renderStu(); },
    _legacy: legacy, _yearEnd: yearEnd,
    _snooze: function (d) { setSettings({ snoozeDays: d }); },
    _setKeep: function (k) { setSettings({ keepMode: k }); },
    _saveSettings: function () { setSettings({ keepMode: $('pfKeep').value, autoHw: $('pfAutoHw').checked }, $('pfSetSt')); }
  };
  window.PF_OPEN = open;
})();
