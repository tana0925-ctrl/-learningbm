# -*- coding: utf-8 -*-
# QUICKNOTE_V1 (2026-10-06)
#
# 先生が授業中に気づいた一言を、1人10秒で入れられる口をつくる。
# あわせて「先生だけ / 阪神マンには渡す / 児童に見せる」の3段階にする。
#
# 背景（実測）
#   ・teacher_student_notes は14件。最新 2026-09-15。全部 karte_material_uses で
#     消費済み（used_at 入り）。9/24以降、材料ゼロで阪神マンに書かせていた。
#   ・9/15 の10件は 04:36→04:54(UTC) = 18分で10人 ＝ 1人1分50秒。
#     目標の10秒の11倍。速い口が無かったのではなく、あった口が遅かった。
#   ・さらに 2026-09-29 の片づけ(C-3)で、その遅い口（授業メモタブの
#     「児童ごとメモ」）も撤去され、個人パネル経由だけになっていた。
#   ・show_in_karte は pick では読まれていなかった。先生が「見せない」つもりで
#     書いた14件が、全部 阪神マン経由で児童に届いていた。
#
# やること
#   S1 pick の観察メモに ai_ok の条件を足す（＝「先生だけ」を外部AIに渡さない）
#      ＋ subject を渡す ＋ 日付が空のとき created_at を使う
#   S2 pick のループ順を「メモ → プリント」に入れ替える（メモが6枠から押し出されない）
#   S3 POST /api/teacher/student-notes が aiOk と subject を受け取る
#   S4 GET /api/teacher/student-notes と student-full-analysis が aiOk と subject を返す
#   S5 貼り付け文の2か所で aiOk=false を外す（pick を通らない別経路。ここが漏れ口だった）
#      ＋ メモ本文の実名を伏せる
#   S6 教師ページに「🖊 きょうの一言」を足す（どのタブからでも1タップ）
#   S7 死んでいた「👤 児童ひとりへのメモ」のカードを、同じ口を開くボタンに差し替える
#   S8 teacher-ai.js で観察メモを独立した見出しで先に渡す ＋ 実名を伏せる
#   S9 teacher-ai.js?v=12 -> 13
#
# D1 の列 ai_ok(INTEGER DEFAULT 1) と subject(TEXT) は 2026-10-05 に適用済み。
# 既存14件は ai_ok=1（＝これまでと同じ動き）。
#
# 児童の画面（配信チェーン）は1件も増減させない。
# public/index.html には一切さわらない。
# アンカーが1件でなければ 1文字も書かずに止まる（fail-closed）。
import os
import sys

TSX = 'src/index.tsx'
TAI = 'public/teacher-ai.js'


def die(msg):
    print('::error::' + msg)
    sys.exit(1)


def chain_count(s):
    a = s.index("app.get('/', async (c) => {")
    b = s.index("app.get('/logout'", a)
    return s[a:b].count('.replace(')


raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if not raw.isdigit():
    die('CHAIN_BEFORE が数字で渡されていません: %r' % raw)
CHAIN_BEFORE = int(raw)

tsx = open(TSX, encoding='utf-8').read()
tai = open(TAI, encoding='utf-8').read()

before = chain_count(tsx)
print('チェーン(前) = %d / 指定 = %d' % (before, CHAIN_BEFORE))
if before != CHAIN_BEFORE:
    die('チェーンが %d 件。流す直前に実測した %d と合わないので止めます。' % (before, CHAIN_BEFORE))

if '\r' in tsx or '\r' in tai:
    die('CR が入っています。中止します。')

for mark in ['QUICKNOTE_V1', 'qnFab', 'teacher-ai.js?v=13']:
    if mark in tsx or mark in tai:
        die('すでに適用済みのようです（%s）' % mark)

# ────────────────────────────────────────────────────────────────
# S2 pick のループ順を「メモ → プリント」に入れ替える。
#   中の字下げに触らないよう、ブロックごと入れ替える（長さは1文字も変わらない）。
# ────────────────────────────────────────────────────────────────
L1 = 'for (const r of rows) {'
L2 = 'for (const r of notes) {'
L3 = "for (const k of Object.keys(out)) { out[k].exhausted = (out[k].materials.length === 0); delete out[k].chars }"
for nm, lit in (('L1', L1), ('L2', L2), ('L3', L3)):
    if tsx.count(lit) != 1:
        die('%s が %d か所（1か所のはず）' % (nm, tsx.count(lit)))
i1 = tsx.index(L1)
i2 = tsx.index(L2)
i3 = tsx.index(L3)
if not (i1 < i2 < i3):
    die('pick の2つのループの並びが想定と違います（%d / %d / %d）' % (i1, i2, i3))
_len0 = len(tsx)
tsx = tsx[:i1] + tsx[i2:i3] + tsx[i1:i2] + tsx[i3:]
if len(tsx) != _len0:
    die('ループ入れ替えで長さが変わりました')
if tsx.index(L2) >= tsx.index(L1):
    die('ループ入れ替えが効いていません')
print('S2 ループ順を メモ→プリント に入れ替えました')

# ────────────────────────────────────────────────────────────────
# ここから先は「行頭から始まり、途中に連続した空白を含まない」文字列だけを
# アンカーにしている（字下げに依存しないため）。
# ────────────────────────────────────────────────────────────────
EDITS = []

# S1 pick の観察メモ SELECT に ai_ok の条件と subject を足す
EDITS.append(('S1_pick_sql',
 "SELECT tn.id, tn.user_id, tn.day_key, tn.body, (kmu.used_at IS NOT NULL) AS used FROM teacher_student_notes tn LEFT JOIN karte_material_uses kmu ON kmu.user_id = tn.user_id AND kmu.source='note' AND kmu.source_id = CAST(tn.id AS TEXT) WHERE tn.user_id IN (SELECT user_id FROM class_members WHERE class_id=?) ORDER BY COALESCE(NULLIF(tn.day_key,''), substr(tn.created_at,1,10)) DESC, tn.id DESC LIMIT 400",
 "SELECT tn.id, tn.user_id, tn.day_key, tn.body, tn.subject, (kmu.used_at IS NOT NULL) AS used FROM teacher_student_notes tn LEFT JOIN karte_material_uses kmu ON kmu.user_id = tn.user_id AND kmu.source='note' AND kmu.source_id = CAST(tn.id AS TEXT) WHERE tn.user_id IN (SELECT user_id FROM class_members WHERE class_id=?) AND COALESCE(tn.ai_ok,1)=1 ORDER BY COALESCE(NULLIF(tn.day_key,''), substr(tn.created_at,1,10)) DESC, tn.id DESC LIMIT 400"))

# S1-b 観察メモの材料に 教科 を乗せ、日付が空のときは取り込み日を使う
EDITS.append(('S1_pick_item',
 "take(uid, 'note', r.id, { kind: '先生の観察メモ', on: String(r.day_key || '').slice(0, 10), unit: '', title: '', evalRank: '', evalComment: '', body, reflection: '' }, body.length + 30)",
 "take(uid, 'note', r.id, { kind: '先生の観察メモ', on: onN, unit: String(r.subject || ''), title: '', evalRank: '', evalComment: '', body, reflection: '' }, body.length + 30)"))

# S3 保存APIが aiOk と subject を受け取る。児童に見せるなら 阪神マンにも渡す。
EDITS.append(('S3_showk',
 "const showK = (body.showInKarte === 1 || body.showInKarte === true || body.showInKarte === '1') ? 1 : 0",
 "const showK = (body.showInKarte === 1 || body.showInKarte === true || body.showInKarte === '1') ? 1 : 0; const aiOk = showK === 1 ? 1 : ((body.aiOk === 0 || body.aiOk === false || body.aiOk === '0') ? 0 : 1); const subj = String(body.subject || '').slice(0, 20)"))

EDITS.append(('S3_insert',
 "await c.env.DB.prepare('INSERT INTO teacher_student_notes (user_id, class_id, day_key, body, show_in_karte, created_by, created_at) VALUES (?,?,?,?,?,?,?)').bind(studentId, String(mem.classId || ''), String(body.dayKey || '').slice(0, 40), txt, showK, u.id, new Date().toISOString()).run()",
 "try { await c.env.DB.prepare('INSERT INTO teacher_student_notes (user_id, class_id, day_key, body, show_in_karte, ai_ok, subject, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?)').bind(studentId, String(mem.classId || ''), String(body.dayKey || '').slice(0, 40), txt, showK, aiOk, subj, u.id, new Date().toISOString()).run() } catch (e) { if (aiOk === 0) { console.error('student-notes: ai_ok の列が無いので「先生だけ」は保存しません', e); return jsonError(c, 500, 'ai_ok_column_missing') } await c.env.DB.prepare('INSERT INTO teacher_student_notes (user_id, class_id, day_key, body, show_in_karte, created_by, created_at) VALUES (?,?,?,?,?,?,?)').bind(studentId, String(mem.classId || ''), String(body.dayKey || '').slice(0, 40), txt, showK, u.id, new Date().toISOString()).run() }"))

# S4 読み出し2か所（GET と student-full-analysis）が ai_ok と subject も返す
EDITS.append(('S4_sql_x2',
 "SELECT day_key, body, show_in_karte FROM teacher_student_notes WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC",
 "SELECT day_key, body, show_in_karte, ai_ok, subject FROM teacher_student_notes WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC", 2))

EDITS.append(('S4_map_x',
 "({ dayKey: x.day_key, body: x.body, showInKarte: !!x.show_in_karte })",
 "({ dayKey: x.day_key, body: x.body, showInKarte: !!x.show_in_karte, aiOk: (x.ai_ok === null || x.ai_ok === undefined) ? true : !!x.ai_ok, subject: x.subject || '' })"))

EDITS.append(('S4_map_r',
 "({ dayKey: r.day_key, body: r.body, showInKarte: !!r.show_in_karte })",
 "({ dayKey: r.day_key, body: r.body, showInKarte: !!r.show_in_karte, aiOk: (r.ai_ok === null || r.ai_ok === undefined) ? true : !!r.ai_ok, subject: r.subject || '' })"))

# S5 貼り付け文の2か所。pick を通らない別経路なので、ここにも ai_ok を効かせる。
#    ここが抜けていると「先生だけ」のメモが別の口から外部AIに出る。
_NOTE_OLD_A = "if(data.teacherNotes && data.teacherNotes.length){ L.push(''); L.push('【先生の観察メモ（授業中の様子・教師向け）】'); for(var tn=0;tn<Math.min(data.teacherNotes.length,15);tn++){ var nt=data.teacherNotes[tn]; L.push('・'+(nt.dayKey||'')+' '+(nt.body||'')); } }"
_NOTE_NEW_A = "if(data.teacherNotes && data.teacherNotes.length){ L.push(''); L.push('【先生の観察メモ（授業中の様子・教師向け）】'); for(var tn=0;tn<Math.min(data.teacherNotes.length,15);tn++){ var nt=data.teacherNotes[tn]; if(nt && nt.aiOk===false) continue; L.push('・'+(nt.dayKey||'')+' '+(nt.subject?'['+nt.subject+'] ':'')+(window._qnMask?window._qnMask(nt.body||''):(nt.body||''))); } }"
EDITS.append(('S5_notes_a', _NOTE_OLD_A, _NOTE_NEW_A))

_NOTE_OLD_B = "if(data.teacherNotes&&data.teacherNotes.length){ L.push(''); L.push('【先生の観察メモ（授業中の様子・教師向け）】'); for(var tn=0;tn<Math.min(data.teacherNotes.length,15);tn++){ var nt=data.teacherNotes[tn]; L.push('・'+(nt.dayKey||'')+' '+(nt.body||'')); } }"
_NOTE_NEW_B = "if(data.teacherNotes&&data.teacherNotes.length){ L.push(''); L.push('【先生の観察メモ（授業中の様子・教師向け）】'); for(var tn=0;tn<Math.min(data.teacherNotes.length,15);tn++){ var nt=data.teacherNotes[tn]; if(nt && nt.aiOk===false) continue; L.push('・'+(nt.dayKey||'')+' '+(nt.subject?'['+nt.subject+'] ':'')+(window._qnMask?window._qnMask(nt.body||''):(nt.body||''))); } }"
EDITS.append(('S5_notes_b', _NOTE_OLD_B, _NOTE_NEW_B))

# クラス全体メモの本文にも実名が書かれうるので同じ扱い（2か所とも同じ文字列）
EDITS.append(('S5_classnotes_x2',
 "L.push('・'+(cnt.dayKey||'')+' '+(cnt.body||'')); } }",
 "L.push('・'+(cnt.dayKey||'')+' '+(window._qnMask?window._qnMask(cnt.body||''):(cnt.body||''))); } }", 2))

# S9 teacher-ai.js の版数
EDITS.append(('S9_ver', 'teacher-ai.js?v=12', 'teacher-ai.js?v=13'))

for e in EDITS:
    tag, old, new = e[0], e[1], e[2]
    want = e[3] if len(e) > 3 else 1
    n = tsx.count(old)
    print('%-20s %d か所（期待 %d）' % (tag, n, want))
    if n != want:
        die('%s のアンカーが %d か所（%d のはず）' % (tag, n, want))
for e in EDITS:
    tag, old, new = e[0], e[1], e[2]
    want = e[3] if len(e) > 3 else 1
    tsx = tsx.replace(old, new, want)

# ────────────────────────────────────────────────────────────────
# S6 教師ページに「🖊 きょうの一言」を足す。
#   ・どのタブからでも右下のボタン1つで開く（新しいタブは増やさない）
#   ・五十音順（出席番号は22人中1人しか登録が無いため使えない）
#   ・先生のアカウントは出ない（名簿APIが role='student' だけを返す）
#   ・空欄は責めない。出すのは「今週 N人に書きました」だけ
#   ・教科は1タップ・必須ではない
#   ・見せ方は1つのボタンで3段階。既定は「阪神マンには渡す」、1タップで「先生だけ」
#   ・テンプレートリテラルの中なので バッククォート・ドル波かっこ・バックスラッシュは使わない
#   ・onclick は使わず addEventListener で付ける（エスケープ事故を構造で避ける）
# ────────────────────────────────────────────────────────────────
UI_ANCHOR = '<script src="/drillpark.js?v=1"></script>'
if tsx.count(UI_ANCHOR) != 1:
    die('UI_ANCHOR が %d か所' % tsx.count(UI_ANCHOR))

UI = '''<!-- ===== QUICKNOTE_V1 (2026-10-06) 先生が授業中に気づいた一言を入れる口 ===== -->
    <button id="qnFab" type="button" title="きょうの一言">🖊 ひとこと</button>
    <div id="qnWrap"><div id="qnSheet">
      <div id="qnHead">
        <span id="qnTitle">🖊 きょうの一言</span>
        <select id="qnClass"></select>
        <input id="qnDate" type="date">
        <span id="qnCount"></span>
        <button id="qnClose" type="button">✕</button>
      </div>
      <div id="qnBar">
        <div id="qnHint">気づいた子だけでいいです。全員ぶん書く必要はありません。</div>
        <div id="qnChips"></div>
      </div>
      <div id="qnList"></div>
    </div></div>
    <style>
      #qnFab{position:fixed;right:18px;bottom:18px;z-index:9998;background:#0d9488;color:#fff;border:none;border-radius:999px;padding:13px 18px;font-size:15px;font-weight:800;box-shadow:0 6px 18px rgba(15,23,42,.28);cursor:pointer}
      #qnWrap{display:none;position:fixed;left:0;right:0;top:0;bottom:0;z-index:9999;background:rgba(15,23,42,.45)}
      #qnSheet{position:absolute;right:0;top:0;bottom:0;width:100%;max-width:580px;background:#fff;display:flex;flex-direction:column}
      #qnHead{padding:9px 12px;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;gap:7px;flex-wrap:wrap}
      #qnTitle{font-weight:800;color:#0f766e;font-size:16px}
      #qnHead select,#qnHead input{border:1px solid #cbd5e1;border-radius:8px;padding:4px 6px;font-size:12px;background:#fff}
      #qnCount{font-size:12px;color:#0f766e;font-weight:800}
      #qnClose{margin-left:auto;border:none;background:none;font-size:20px;color:#94a3b8;cursor:pointer}
      #qnBar{padding:6px 12px;border-bottom:1px solid #f1f5f9}
      #qnHint{font-size:11px;color:#64748b;margin-bottom:4px}
      #qnChips{display:flex;gap:4px;flex-wrap:wrap}
      #qnChips button{border:1px solid #99f6e4;background:#f0fdfa;color:#0f766e;border-radius:999px;padding:3px 9px;font-size:12px;cursor:pointer}
      #qnList{flex:1;overflow-y:auto;padding:4px 10px 24px 10px}
      .qnRow{border-bottom:1px solid #f1f5f9;padding:7px 2px}
      .qnRow.qnOk{background:#f0fdf4}
      .qnName{font-size:13px;font-weight:700;color:#334155;margin-bottom:3px}
      .qnName small{font-weight:400;color:#94a3b8;margin-left:5px}
      .qnIn{display:flex;gap:5px;align-items:center}
      .qnIn input{flex:1;border:1px solid #cbd5e1;border-radius:8px;padding:7px 9px;font-size:14px}
      .qnVis{border:1px solid #cbd5e1;background:#fff;border-radius:8px;padding:6px 8px;font-size:15px;cursor:pointer;line-height:1}
      .qnSub{display:flex;gap:3px;flex-wrap:wrap;margin-top:4px}
      .qnSub button{border:1px solid #e2e8f0;background:#fff;color:#64748b;border-radius:6px;padding:2px 7px;font-size:11px;cursor:pointer}
      .qnSub button.on{background:#0d9488;border-color:#0d9488;color:#fff;font-weight:700}
      .qnSaved{font-size:11px;color:#15803d;margin-top:3px}
    </style>
    <script>
    /* QUICKNOTE_V1  先生が授業中に気づいた一言を、1人10秒で入れる口。
       ・保存は既存の POST /api/teacher/student-notes（aiOk と subject を足した）
       ・名簿は GET /api/teacher/quicknote/roster（クラス指定・読み取り2本）
       ・外部AIに渡す前に、本文に書かれた実名を伏せる（_qnMask）。
         姓だけで書かれることがあるので、わざと広めに伏せる。 */
    (function(){
      var VIS = [
        { k:1, mark:'🐯', tip:'阪神マンには渡す（紙には先生の言葉としては出ません）', karte:0, ai:1 },
        { k:2, mark:'🔒', tip:'先生だけ（阪神マンにも渡しません）',                     karte:0, ai:0 },
        { k:3, mark:'👧', tip:'児童に見せる（紙の「先生からの記録」に出ます）',         karte:1, ai:1 }
      ];
      var SUBJ = ['国','社','算','理','体','他'];
      var PHRASE = ['ふりかえり書こう','ここできてる','自分から動けてた','友だちに説明できてた','もう一歩いける'];
      var St = {};
      var lastInput = null;
      function $(id){ return document.getElementById(id); }
      function esc(s){ return String(s==null?'':s).split('&').join('&amp;').split('<').join('&lt;').split('>').join('&gt;').split('"').join('&quot;'); }
      function today(){ var n=new Date(); var j=new Date(n.getTime()+n.getTimezoneOffset()*60000+9*3600000); var p=function(x){return (x<10?'0':'')+x;}; return j.getFullYear()+'-'+p(j.getMonth()+1)+'-'+p(j.getDate()); }

      /* ── 外部AIに実名を出さないための伏せ字 ──
         実名・ふりがな、さらにその先頭2〜4文字（姓だけで書かれる場合）を消す。
         多めに消えても困らないが、名前が出るのは絶対に困るため、広めにとる。 */
      window._qnMask = function(t){
        var s = String(t==null?'':t);
        try{
          var cand = [];
          var push = function(v, minLen){ v=String(v==null?'':v).trim(); if(v.length>=minLen) cand.push(v); };
          var m = {};
          try{ if(typeof getStudentNameMap==='function') m = getStudentNameMap()||{}; }catch(e1){}
          for(var k in m){ if(!Object.prototype.hasOwnProperty.call(m,k)) continue;
            var v=String(m[k]||'').trim(); push(v,2); push(v.slice(0,3),2); push(v.slice(0,2),2); }
          var f = window._serverFuriganaMap || {};
          for(var k2 in f){ if(!Object.prototype.hasOwnProperty.call(f,k2)) continue;
            var v2=String(f[k2]||'').trim(); push(v2,3); push(v2.slice(0,4),3); push(v2.slice(0,3),3); }
          cand.sort(function(a,b){ return b.length-a.length; });
          for(var i=0;i<cand.length;i++){ if(s.indexOf(cand[i])>=0) s = s.split(cand[i]).join('その子'); }
        }catch(e){}
        return s;
      };

      function classId(){
        var s=$('qnClass'); if(s && s.value) return s.value;
        var ids=['analyticsClassFilter','laClassSelect','activityClassFilter'];
        for(var i=0;i<ids.length;i++){ var e=document.getElementById(ids[i]); if(e && e.value) return e.value; }
        return '';
      }
      function fillClasses(){
        var s=$('qnClass'); if(!s || s.getAttribute('data-init')) return Promise.resolve();
        return fetch('/api/teacher/classes').then(function(r){return r.json();}).then(function(d){
          if(!d || !d.ok) return;
          var pre=''; var ids=['analyticsClassFilter','laClassSelect','activityClassFilter'];
          for(var i=0;i<ids.length;i++){ var e=document.getElementById(ids[i]); if(e && e.value){ pre=e.value; break; } }
          var h=''; for(var j=0;j<d.classes.length;j++){ h+='<option value="'+esc(d.classes[j].id)+'">'+esc(d.classes[j].name)+'</option>'; }
          s.innerHTML=h; if(pre) s.value=pre; s.setAttribute('data-init','1');
        }).catch(function(e){});
      }
      function nameOf(st){
        try{ if(typeof resolveStudentName==='function') return resolveStudentName(st.loginId, st.name); }catch(e){}
        return st.name || st.loginId || '';
      }
      function kanaOf(st){
        var f = window._serverFuriganaMap || {};
        return String(f[st.loginId] || '') || nameOf(st);
      }
      function render(d){
        var list=$('qnList'); if(!list) return;
        var roster=(d.roster||[]).slice();
        roster.sort(function(a,b){ return kanaOf(a).localeCompare(kanaOf(b),'ja'); });
        var wrote=d.wrote||{}; var done=0;
        for(var i=0;i<roster.length;i++){ if(wrote[roster[i].userId]) done++; }
        var cnt=$('qnCount'); if(cnt) cnt.textContent = done ? ('今週 '+done+'人に書きました') : '';
        var h='';
        for(var j=0;j<roster.length;j++){
          var st=roster[j]; var uid=st.userId;
          if(!St[uid]) St[uid]={ vis:1, sub:'' };
          var n=wrote[uid]||0;
          h+='<div class="qnRow" data-uid="'+esc(uid)+'">';
          h+='<div class="qnName">'+esc(nameOf(st))+(n?'<small>今週 '+n+'件</small>':'')+'</div>';
          h+='<div class="qnIn"><input type="text" class="qnText" data-uid="'+esc(uid)+'" placeholder="気づいたことを一言">';
          h+='<button type="button" class="qnVis" data-uid="'+esc(uid)+'" title="'+esc(VIS[0].tip)+'">'+VIS[0].mark+'</button></div>';
          h+='<div class="qnSub">';
          for(var k=0;k<SUBJ.length;k++){ h+='<button type="button" class="qnSubBtn" data-uid="'+esc(uid)+'" data-s="'+esc(SUBJ[k])+'">'+esc(SUBJ[k])+'</button>'; }
          h+='</div><div class="qnSaved" data-uid="'+esc(uid)+'"></div></div>';
        }
        list.innerHTML = h || '<div style="padding:14px;color:#94a3b8;font-size:13px">このクラスの児童が見つかりません</div>';
      }
      function load(){
        var cid=classId();
        var list=$('qnList');
        if(!cid){ if(list) list.innerHTML='<div style="padding:14px;color:#94a3b8;font-size:13px">上でクラスをえらんでください</div>'; return; }
        if(list) list.innerHTML='<div style="padding:14px;color:#94a3b8;font-size:13px">よみこみ中…</div>';
        fetch('/api/teacher/quicknote/roster?classId='+encodeURIComponent(cid))
          .then(function(r){return r.json();})
          .then(function(d){ if(d && d.ok) render(d); else if(list) list.innerHTML='<div style="padding:14px;color:#dc2626;font-size:13px">名簿が読めませんでした</div>'; })
          .catch(function(e){ if(list) list.innerHTML='<div style="padding:14px;color:#dc2626;font-size:13px">エラー: '+esc(e.message)+'</div>'; });
      }
      function save(uid, inp){
        var txt=String(inp.value||'').trim(); if(!txt) return;
        var row=inp.closest('.qnRow'); var sv=row?row.querySelector('.qnSaved'):null;
        var stt=St[uid]||{vis:1,sub:''}; var v=VIS[stt.vis-1]||VIS[0];
        inp.disabled=true;
        fetch('/api/teacher/student-notes',{method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({ studentId:uid, dayKey:($('qnDate')||{}).value||today(), body:txt, showInKarte:v.karte, aiOk:v.ai, subject:stt.sub })})
          .then(function(r){return r.json();})
          .then(function(d){
            inp.disabled=false;
            if(d && d.ok){
              inp.value=''; if(row) row.className='qnRow qnOk';
              if(sv) sv.innerHTML = '✓ '+v.mark+' '+(stt.sub?'['+esc(stt.sub)+'] ':'')+esc(txt) + (sv.innerHTML?'<br>'+sv.innerHTML:'');
              var c=$('qnCount'); var m=/[0-9]+/.exec(c&&c.textContent||''); var cur=m?Number(m[0]):0;
              if(c && !(row && row.getAttribute('data-counted'))){ c.textContent='今週 '+(cur+1)+'人に書きました'; if(row) row.setAttribute('data-counted','1'); }
            } else { if(sv) sv.textContent='保存できませんでした'; }
          })
          .catch(function(e){ inp.disabled=false; if(sv) sv.textContent='エラー: '+e.message; });
      }
      function open_(){
        var w=$('qnWrap'); if(!w) return;
        w.style.display='block';
        var dt=$('qnDate'); if(dt && !dt.value) dt.value=today();
        var chips=$('qnChips');
        if(chips && !chips.getAttribute('data-init')){
          var h=''; for(var i=0;i<PHRASE.length;i++){ h+='<button type="button" data-p="'+esc(PHRASE[i])+'">'+esc(PHRASE[i])+'</button>'; }
          chips.innerHTML=h; chips.setAttribute('data-init','1');
        }
        try{ if(typeof loadServerNameMap==='function' && !window._serverFuriganaMap) loadServerNameMap(); }catch(e){}
        fillClasses().then(load);
      }
      function close_(){ var w=$('qnWrap'); if(w) w.style.display='none'; }

      document.addEventListener('click', function(ev){
        var t=ev.target; if(!t || !t.getAttribute) return;
        if(t.id==='qnFab' || t.id==='qnOpenFromNotes'){ ev.preventDefault(); open_(); return; }
        if(t.id==='qnClose'){ close_(); return; }
        if(t.id==='qnWrap'){ close_(); return; }
        if(t.className==='qnVis'){
          var u=t.getAttribute('data-uid'); if(!St[u]) St[u]={vis:1,sub:''};
          St[u].vis = St[u].vis>=3 ? 1 : St[u].vis+1;
          var v=VIS[St[u].vis-1]; t.textContent=v.mark; t.title=v.tip; return;
        }
        if(t.className && String(t.className).indexOf('qnSubBtn')>=0){
          var u2=t.getAttribute('data-uid'); var s=t.getAttribute('data-s');
          if(!St[u2]) St[u2]={vis:1,sub:''};
          var row=t.closest('.qnRow');
          if(row){ var bs=row.querySelectorAll('.qnSubBtn'); for(var i=0;i<bs.length;i++) bs[i].className='qnSubBtn'; }
          if(St[u2].sub===s){ St[u2].sub=''; } else { St[u2].sub=s; t.className='qnSubBtn on'; }
          return;
        }
        if(t.parentNode && t.parentNode.id==='qnChips'){
          var p=t.getAttribute('data-p');
          if(lastInput){ lastInput.value = (lastInput.value?lastInput.value+' ':'') + p; lastInput.focus(); }
          return;
        }
      });
      document.addEventListener('focusin', function(ev){ if(ev.target && ev.target.className==='qnText') lastInput=ev.target; });
      document.addEventListener('keydown', function(ev){
        if(ev.key==='Enter' && ev.target && ev.target.className==='qnText'){ ev.preventDefault(); save(ev.target.getAttribute('data-uid'), ev.target); }
        if(ev.key==='Escape'){ var w=$('qnWrap'); if(w && w.style.display==='block') close_(); }
      });
      document.addEventListener('focusout', function(ev){
        if(ev.target && ev.target.className==='qnText' && String(ev.target.value||'').trim()) save(ev.target.getAttribute('data-uid'), ev.target);
      });
      document.addEventListener('change', function(ev){ if(ev.target && ev.target.id==='qnClass') load(); });
    })();
    </script>
    '''
tsx = tsx.replace(UI_ANCHOR, UI + UI_ANCHOR, 1)

# S7 死んでいたカードを、同じ口を開くボタンに差し替える
A7 = '<div class="font-bold text-slate-700 mb-1">👤 児童ひとりへのメモ</div>'
B7 = '保存される場所は前とまったく同じです（書いたメモもそのまま残っています）。</div>'
for nm, lit in (('A7', A7), ('B7', B7)):
    if tsx.count(lit) != 1:
        die('%s が %d か所' % (nm, tsx.count(lit)))
a7 = tsx.index(A7)
b7 = tsx.index(B7, a7) + len(B7)
if b7 <= a7:
    die('S7 の範囲がおかしい')
NEW7 = ('<div class="font-bold text-slate-700 mb-1">🖊 児童ひとりへのメモ</div>'
        '<div class="text-xs text-slate-500 mb-2">気づいた子だけでいいです。1人ずつ一言で。'
        '右下の「🖊 ひとこと」からも、どの画面からでも開けます。</div>'
        '<button id="qnOpenFromNotes" type="button" class="bg-teal-600 text-white rounded-lg px-4 py-2 text-xs font-bold hover:opacity-90">🖊 きょうの一言をひらく</button>')
tsx = tsx[:a7] + NEW7 + tsx[b7:]

# S6-b 名簿API（クラス指定・読み取り2本・どちらも既存インデックス内）
API_ANCHOR = "app.post('/api/teacher/student-notes', async (c) => {"
if tsx.count(API_ANCHOR) != 1:
    die('API_ANCHOR が %d か所' % tsx.count(API_ANCHOR))
API = """// ===== QUICKNOTE_V1 名簿と「今週もう書いた人数」 =====
// 読み取りは2本だけ。どちらもクラスで絞っており、全件スキャンは増やさない。
// u2.role='student' なので、クラスに入っている先生自身のアカウントは出ない。
app.get('/api/teacher/quicknote/roster', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = String(c.req.query('classId') || '')
  if (!classId) return jsonError(c, 400, 'classId required')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=? LIMIT 1').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=? LIMIT 1').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class_not_found')
  const roster = (((await c.env.DB.prepare("SELECT u2.id as userId, u2.login_id as loginId, u2.name as name FROM class_members cm JOIN users u2 ON u2.id=cm.user_id WHERE cm.class_id=? AND u2.role='student'").bind(classId).all<any>()).results) || []) as any[]
  const _n = new Date()
  const _j = new Date(_n.getTime() + _n.getTimezoneOffset() * 60000 + 9 * 3600000)
  const _wd = (_j.getDay() + 6) % 7
  const _mon = new Date(_j.getTime() - _wd * 86400000)
  const _p2 = (x: number) => (x < 10 ? '0' : '') + x
  const weekFrom = _mon.getFullYear() + '-' + _p2(_mon.getMonth() + 1) + '-' + _p2(_mon.getDate())
  const wrote: Record<string, number> = {}
  try {
    const r = await c.env.DB.prepare("SELECT user_id as uid, COUNT(*) as n FROM teacher_student_notes WHERE user_id IN (SELECT user_id FROM class_members WHERE class_id=?) AND COALESCE(NULLIF(day_key,''), substr(created_at,1,10)) >= ? GROUP BY user_id").bind(classId, weekFrom).all<any>()
    for (const x of (((r && r.results) || []) as any[])) wrote[String(x.uid)] = Number(x.n) || 0
  } catch (e) { console.error('quicknote/roster: 今週の件数が読めません', e) }
  return c.json({ ok: true, roster, weekFrom, wrote })
})
"""
tsx = tsx.replace(API_ANCHOR, API + API_ANCHOR, 1)

# ────────────────────────────────────────────────────────────────
# S8 teacher-ai.js 観察メモを独立した見出しで先に渡す ＋ 実名を伏せる。
#   見出しは「【先生の観察メモ」で始める。束の圧縮処理と貼り戻し検出
#   （TAI_DATA_HEAD）が、この接頭辞で前方一致しているため。
# ────────────────────────────────────────────────────────────────
T1_OLD = "out.push('【最近の取り込み（' + (pickFreshDays ? 'この' + Math.round(pickFreshDays / 7) + '週以内・' : '') + 'まだ一度もカルテで使っていないもの）】');"
T1_NEW = ("var _mNote = _pk.materials.filter(function (x) { return x.kind === '先生の観察メモ'; });"
          " var _mRec = _pk.materials.filter(function (x) { return x.kind !== '先生の観察メモ'; });"
          " if (_mNote.length) {"
          " out.push('【先生の観察メモ（先生が授業中に気づいたこと。いちばん大事な材料です。ここに書かれていることを必ず一度は使ってください）】');"
          " _mNote.forEach(function (mt) { out.push('・' + (mt.on || '日付不明') + (mt.unit ? '［' + mt.unit + '］' : '') + ' ' + (window._qnMask ? window._qnMask(mt.body || '') : (mt.body || ''))); });"
          " out.push(''); }"
          " if (!_mRec.length) out.push('（この子の取り込み物は、前のカルテでもうほめています。プリントや作品の話は書かないでください）');"
          " if (_mRec.length) out.push('【最近の取り込み（' + (pickFreshDays ? 'この' + Math.round(pickFreshDays / 7) + '週以内・' : '') + 'まだ一度もカルテで使っていないもの）】');")
T2_OLD = "_pk.materials.forEach(function (mt) {"
T2_NEW = "_mRec.forEach(function (mt) {"

for nm, lit in (('T1', T1_OLD), ('T2', T2_OLD)):
    if tai.count(lit) != 1:
        die('teacher-ai.js の %s が %d か所' % (nm, tai.count(lit)))
tai = tai.replace(T1_OLD, T1_NEW, 1)
tai = tai.replace(T2_OLD, T2_NEW, 1)

# ────────────────────────────────────────────────────────────────
# 適用後のたしかめ
# ────────────────────────────────────────────────────────────────
after = chain_count(tsx)
print('チェーン(後) = %d' % after)
if after != CHAIN_BEFORE:
    die('チェーンが %d -> %d に変わりました。中止します。' % (before, after))

bad = False
need = {
    'QUICKNOTE_V1': 3,
    'qnFab': 3,
    "app.get('/api/teacher/quicknote/roster'": 1,
    'window._qnMask': 9,
    'COALESCE(tn.ai_ok,1)=1': 1,
    'teacher-ai.js?v=13': 1,
    'teacher-ai.js?v=12': 0,
    'qnOpenFromNotes': 2,
    '児童ひとりへのメモ': 1,
}
for k, want in need.items():
    got = tsx.count(k)
    print('適用後 tsx %-42s %d 件（期待 %d）' % (k, got, want))
    if got != want:
        bad = True

needT = {'_mNote': 3, '_mRec': 4, '_pk.materials.forEach': 0, 'window._qnMask': 2}
for k, want in needT.items():
    got = tai.count(k)
    print('適用後 tai %-42s %d 件（期待 %d）' % (k, got, want))
    if got != want:
        bad = True

# 9/26に教師画面を2時間落としたエスケープ事故の見張り（増えていないこと）
print('エスケープ事故の見張り（増えていないこと） = %d' % tsx.count("(\\'"))

for k in ['cannot_trade_special', 'genElectric6', 'if (m.uncapturable) continue;', '__WORLD_V3__',
          'WARMIX', '_hash', 'karte_material_uses', '_karteWeekOf', 'KARTE_FRESH_V1', 'KARTE_MATERIAL_V1']:
    if tsx.count(k) < 1:
        print('::error::安全マーカー %r が消えました' % k)
        bad = True

if bad:
    sys.exit(1)

open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
open(TAI, 'w', encoding='utf-8', newline='').write(tai)
print('OK: src/index.tsx %d 文字 / public/teacher-ai.js %d 文字' % (len(tsx), len(tai)))
