/* ===================================================================
   teacher-progress.js : 「習ったところまで」をクラスごとに設定する画面
     ・攻略モードの出題を、習った単元だけにしぼるための設定。
     ・初期値は war-mix.js の DEFAULT_PROGRESS（＝仮の草案）。
     ・修行モード・野生バトルには影響しない。
   src/index.tsx の /teacher ページから読み込む。student-karte.js と同じ形。
   =================================================================== */
(function (global) {
  'use strict';

  var SUBJECT_ORDER = ['math', 'japanese', 'social', 'science', 'english'];
  var GRADE_LABEL = { 1: '小1', 2: '小2', 3: '小3', 4: '小4', 5: '小5', 6: '小6', 7: '中1' };

  function defaults() {
    try { return (global.WARMIX && global.WARMIX.DEFAULT_PROGRESS) || { units: {}, lowConfidence: [] }; }
    catch (e) { return { units: {}, lowConfidence: [] }; }
  }

  function esc(s) {
    return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  // 単元の一覧は児童用ページの CURRICULUM が唯一の正本。
  // 教師ページには CURRICULUM が無いので、サーバーが本番HTMLから切り出したものを取る。
  // （中身は文字列・数値・配列だけのデータ定義。関数呼び出しは含まれない）
  var _cur = null;
  function loadCurriculum() {
    if (_cur) return Promise.resolve(_cur);
    if (global.CURRICULUM) { _cur = global.CURRICULUM; return Promise.resolve(_cur); }
    return fetch('/api/teacher/curriculum-units', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .then(function (j) {
        if (!j || !j.ok || !j.source) throw new Error('no source');
        _cur = (new Function('return (' + j.source + ')'))();
        return _cur;
      });
  }

  function unitsBySubjectGrade() {
    var C = _cur || global.CURRICULUM;
    if (!C) return null;
    var out = [];
    for (var si = 0; si < SUBJECT_ORDER.length; si++) {
      var sk = SUBJECT_ORDER[si]; var sub = C[sk];
      if (!sub || !sub.grades) continue;
      var grades = Object.keys(sub.grades).map(Number).sort(function (a, b) { return a - b; });
      var gs = [];
      for (var gi = 0; gi < grades.length; gi++) {
        var g = grades[gi];
        if (g > 6) continue;                      // 小学校の単元だけ扱う
        var us = sub.grades[g].units || [];
        if (us.length) gs.push({ grade: g, units: us });
      }
      if (gs.length) out.push({ key: sk, name: sub.name, icon: sub.icon, grades: gs });
    }
    return out;
  }

  // ─── 保存されている設定を読む ────────────────────────────────
  function load(classId) {
    return fetch('/api/teacher/class/' + encodeURIComponent(classId) + '/unit-progress', { credentials: 'same-origin' })
      .then(function (r) { return r.json(); })
      .catch(function () { return null; });
  }
  function save(classId, payload) {
    return fetch('/api/teacher/class/' + encodeURIComponent(classId) + '/unit-progress', {
      method: 'PUT', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload)
    }).then(function (r) { return r.json(); });
  }

  // ─── 画面 ─────────────────────────────────────────────────────
  function close() {
    var el = document.getElementById('unitProgOverlay');
    if (el && el.parentNode) el.parentNode.removeChild(el);
  }

  function open(cls) {
    loadCurriculum().then(function () { openWith(cls); })
      .catch(function (e) { alert('単元の一覧が読み込めませんでした。' + e); });
  }

  function openWith(cls) {
    close();
    var tree = unitsBySubjectGrade();
    if (!tree) { alert('単元の一覧が読み込めませんでした。ページを開きなおしてください。'); return; }

    var ov = document.createElement('div');
    ov.id = 'unitProgOverlay';
    ov.style.cssText = 'position:fixed;inset:0;z-index:99999;background:rgba(15,23,42,.6);display:flex;align-items:center;justify-content:center;padding:16px;font-family:system-ui';
    ov.innerHTML =
      '<div style="background:#fff;border-radius:16px;max-width:900px;width:100%;max-height:90vh;display:flex;flex-direction:column;overflow:hidden">' +
      '  <div style="padding:14px 18px;border-bottom:1px solid #e2e8f0">' +
      '    <div style="font-size:18px;font-weight:800;color:#0f172a">📘 習ったところまで — ' + esc(cls.name) + '</div>' +
      '    <div style="font-size:12px;color:#475569;margin-top:4px">チェックを外した単元は<b>攻略モードに出なくなります</b>。修行モード・野生バトルには影響しません。</div>' +
      '    <div id="upNotice" style="margin-top:8px;font-size:12px;background:#fef3c7;border:1px solid #fcd34d;color:#92400e;border-radius:8px;padding:8px 10px"></div>' +
      '  </div>' +
      '  <div id="upBody" style="padding:12px 18px;overflow:auto;flex:1"></div>' +
      '  <div style="padding:12px 18px;border-top:1px solid #e2e8f0;display:flex;gap:8px;align-items:center;justify-content:flex-end">' +
      '    <span id="upStatus" style="font-size:12px;color:#64748b;margin-right:auto"></span>' +
      '    <button id="upReset" style="font-size:13px;padding:8px 14px;border-radius:9px;border:1px solid #cbd5e1;background:#fff;font-weight:700;cursor:pointer">仮の設定に戻す</button>' +
      '    <button id="upCancel" style="font-size:13px;padding:8px 14px;border-radius:9px;border:1px solid #cbd5e1;background:#fff;font-weight:700;cursor:pointer">とじる</button>' +
      '    <button id="upSave" style="font-size:14px;padding:8px 20px;border-radius:9px;border:0;background:#2563eb;color:#fff;font-weight:800;cursor:pointer">保存</button>' +
      '  </div>' +
      '</div>';
    document.body.appendChild(ov);

    var body = ov.querySelector('#upBody');
    var notice = ov.querySelector('#upNotice');
    var status = ov.querySelector('#upStatus');

    function render(units, isDefault) {
      notice.innerHTML = isDefault
        ? '⚠️ <b>まだ設定されていないので、仮の設定を表示しています。</b>' +
          '一般的な年間指導計画から機械的に作ったものです。<b>とくに理科は学校ごとに順序の差が大きく、当てになりません。</b>' +
          '先生の実際の進度にあわせて直してから保存してください。'
        : '✅ このクラスの設定を表示しています。学期の途中でも、いつでも変えられます。';

      var html = '';
      for (var i = 0; i < tree.length; i++) {
        var s = tree[i];
        var low = (defaults().lowConfidence || []).indexOf(s.key) >= 0;
        html += '<div style="margin-bottom:14px">';
        html += '<div style="font-weight:800;color:#0f172a;font-size:15px;margin-bottom:6px">' + esc(s.icon || '') + ' ' + esc(s.name) +
          (low && isDefault ? '<span style="margin-left:8px;font-size:11px;background:#fee2e2;color:#b91c1c;border-radius:999px;padding:2px 8px;font-weight:700">仮の設定の自信が低い教科です</span>' : '') +
          '</div>';
        for (var j = 0; j < s.grades.length; j++) {
          var g = s.grades[j];
          html += '<div style="display:flex;gap:8px;align-items:flex-start;margin-bottom:4px">';
          html += '<div style="min-width:44px;font-size:12px;font-weight:700;color:#64748b;padding-top:5px">' + (GRADE_LABEL[g.grade] || g.grade) + '</div>';
          html += '<div style="display:flex;flex-wrap:wrap;gap:4px;flex:1">';
          for (var k = 0; k < g.units.length; k++) {
            var u = g.units[k];
            var on = units[u.id] !== false;
            html += '<label data-uid="' + esc(u.id) + '" style="display:inline-flex;align-items:center;gap:4px;font-size:12px;border:1px solid ' +
              (on ? '#86efac' : '#fecaca') + ';background:' + (on ? '#f0fdf4' : '#fef2f2') +
              ';border-radius:8px;padding:3px 8px;cursor:pointer">' +
              '<input type="checkbox" class="up-chk" data-uid="' + esc(u.id) + '"' + (on ? ' checked' : '') + '>' +
              '<span>' + esc(u.name) + '</span></label>';
          }
          html += '</div>';
          // 学年まるごとの切りかえ
          html += '<div style="display:flex;gap:4px;padding-top:2px">' +
            '<button class="up-all" data-sub="' + esc(s.key) + '" data-grade="' + g.grade + '" data-on="1" style="font-size:11px;border:1px solid #cbd5e1;background:#fff;border-radius:6px;padding:2px 6px;cursor:pointer">全部出す</button>' +
            '<button class="up-all" data-sub="' + esc(s.key) + '" data-grade="' + g.grade + '" data-on="0" style="font-size:11px;border:1px solid #cbd5e1;background:#fff;border-radius:6px;padding:2px 6px;cursor:pointer">全部出さない</button>' +
            '</div>';
          html += '</div>';
        }
        html += '</div>';
      }
      body.innerHTML = html;

      // 見た目の追従
      body.addEventListener('change', function (ev) {
        var t = ev.target;
        if (!t || !t.classList || !t.classList.contains('up-chk')) return;
        var lab = t.closest('label');
        if (lab) { lab.style.borderColor = t.checked ? '#86efac' : '#fecaca'; lab.style.background = t.checked ? '#f0fdf4' : '#fef2f2'; }
      });
      var alls = body.querySelectorAll('.up-all');
      for (var a = 0; a < alls.length; a++) {
        alls[a].addEventListener('click', function () {
          var sub = this.getAttribute('data-sub'), gr = Number(this.getAttribute('data-grade')), on = this.getAttribute('data-on') === '1';
          var t2 = null;
          for (var x = 0; x < tree.length; x++) if (tree[x].key === sub) t2 = tree[x];
          if (!t2) return;
          for (var y = 0; y < t2.grades.length; y++) {
            if (t2.grades[y].grade !== gr) continue;
            for (var z = 0; z < t2.grades[y].units.length; z++) {
              var id = t2.grades[y].units[z].id;
              var chk = body.querySelector('.up-chk[data-uid="' + id.replace(/"/g, '\\"') + '"]');
              if (chk) { chk.checked = on; var l = chk.closest('label'); if (l) { l.style.borderColor = on ? '#86efac' : '#fecaca'; l.style.background = on ? '#f0fdf4' : '#fef2f2'; } }
            }
          }
        });
      }
    }

    function collect() {
      var units = {};
      var chks = body.querySelectorAll('.up-chk');
      for (var i = 0; i < chks.length; i++) if (!chks[i].checked) units[chks[i].getAttribute('data-uid')] = false;
      return units;
    }

    status.textContent = '読み込み中…';
    load(cls.id).then(function (res) {
      var saved = res && res.ok && res.unitProgress ? res.unitProgress : null;
      var isDefault = !saved;
      render((saved && saved.units) || defaults().units || {}, isDefault);
      status.textContent = isDefault ? '未設定（仮の設定を表示中）' : ('最終更新: ' + (saved.updatedAt || '不明'));
    });

    ov.querySelector('#upCancel').onclick = close;
    ov.onclick = function (e) { if (e.target === ov) close(); };
    ov.querySelector('#upReset').onclick = function () {
      if (!confirm('仮の設定に戻しますか？（保存を押すまで反映されません）')) return;
      render(defaults().units || {}, true);
    };
    ov.querySelector('#upSave').onclick = function () {
      var btn = this; btn.disabled = true; btn.textContent = '保存中…';
      save(cls.id, { units: collect() }).then(function (r) {
        if (r && r.ok) { status.textContent = '保存しました'; btn.textContent = '保存'; btn.disabled = false; close(); }
        else { alert('保存できませんでした。' + ((r && r.error) || '')); btn.textContent = '保存'; btn.disabled = false; }
      }).catch(function (e) { alert('保存できませんでした。' + e); btn.textContent = '保存'; btn.disabled = false; });
    };
  }

  global.TEACHER_UNIT_PROGRESS = { open: open, close: close };
})(typeof window !== 'undefined' ? window : globalThis);
