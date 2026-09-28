# -*- coding: utf-8 -*-
"""
patch_cleanup_s7.py — 教師ダッシュボードの片づけ 第2便(2/3)
2026-09-29  CLEANUP_S4

C-4 実名の入れかたが2通りあったのを「画面で入力」1本にする
  コードで確かめたこと：
   ・CSVアップロード（uploadStudentCSV）は setStudentNameMap() を呼ぶだけで、
     localStorage('studentNameMap') にしか書かない。サーバへは一切送らない。
     → その先生のそのブラウザでしか実名が出ない（先生の見立てどおり）。
   ・画面入力（saveNameEdits）は localStorage に加えて
     POST /api/teacher/real-names にも送る → 先生みんな・どの端末でも出る。
  よって「📤 直したCSVをアップロード」を撤去し、画面入力に一本化する。

  ★移行の道（必ず用意する、という指示に対して）
   ・画面入力の一覧（loadNameEditor）は getStudentNameMap() で
     「サーバ＋この端末のlocalStorage」を重ねて初期表示するので、
     CSVで入れた実名はすでに入力欄に入った状態で出る。押すだけで移行できる。
   ・さらに、名簿管理を開いた時点で「この端末にしか無い実名」を数え、
     見つかったら黄色い帯で知らせ、ボタン1つでサーバへ移せるようにした
     （nameMigrateCheck / nameMigrateRun）。
   ・CSVの書き出し（📥）は消さない。控え・印刷に使えるので残し、畳んだ。
   ・「クラウド側の名前を空にする」「この端末の古い名簿を消す」も残す。

E-4 「授業メモ（クラス全体メモ）」がどこにも出ていかなかったのを、
    カルテの材料として渡るようにする
  コードで確かめたこと：teacher_class_notes は
  GET /api/teacher/class-notes（授業メモタブの一覧）でしか読まれておらず、
  個人カルテ・AIに渡す材料には1文字も入っていなかった（先生の見立てどおり）。
  → /api/teacher/student-full-analysis に classNotes を足し、
    ・分析の個人パネル「📝 先生の記録」に「🏫 クラス全体のメモ」として出す
    ・AIに渡す文（1人ぶん・まとめて の両方）に【クラス全体の授業メモ】として入れる
  子どもに渡す紙（カルテPDF）には入れない。クラス全体の話で、
  ほかの子のことも書かれているため。

★このパッチも配信チェーン（158件）は増減させない。
"""
import io
import sys

TSX = 'src/index.tsx'
ROOT_ANCHOR = "app.get('/', async (c) => {"
END_ANCHOR = "app.get('/logout'"
CHAIN_WANT = 158


def die(msg):
    sys.stderr.write('NG: ' + msg + '\n')
    sys.exit(1)


def chain_count(s):
    i = s.index(ROOT_ANCHOR)
    j = s.index(END_ANCHOR, i)
    return s[i:j].count('.replace(')


def rep(s, old, new, label):
    n = s.count(old)
    if n != 1:
        die(u'あて先 %s が %d 件（1件のはず）' % (label, n))
    return s.replace(old, new)


# ================================================================== C-4
C4_OLD = (u'        <div class="bg-rose-50 border border-rose-200 rounded-xl p-4 space-y-3">\n'
          u'          <div class="font-bold text-sm text-rose-800">\U0001f512 名簿管理（プライバシー保護）</div>\n'
          u'          <div class="text-xs text-rose-700 leading-relaxed">\n'
          u'            児童の実名をクラウドに保存せず、先生のPCの中だけで管理する仕組みです。<br>\n'
          u'            ① CSVをダウンロード → 表計算ソフトで実名に直す → ② そのCSVをアップロード（先生のブラウザにだけ保存されます）。<br>\n'
          u'            <span class="font-bold">③最後に「クラウド側の名前を空にする」を押すと完全匿名化されます。</span>\n'
          u'          </div>\n'
          u'          <div class="flex gap-2 items-center flex-wrap">\n'
          u'            <button onclick="downloadStudentCSV()" class="bg-rose-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">\U0001f4e5 ① 名簿をCSVでダウンロード</button>\n'
          u'            <label class="bg-rose-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90 cursor-pointer">\n'
          u'              \U0001f4e4 ② 直したCSVをアップロード\n'
          u'              <input type="file" accept=".csv" onchange="uploadStudentCSV(event)" class="hidden"/>\n'
          u'            </label>\n'
          u'            <button onclick="anonymizeCloudNames()" class="bg-red-700 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">\U0001f512 ③ クラウド側の名前を空にする</button>\n'
          u'            <button onclick="clearStudentCSV()" class="bg-slate-400 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">\U0001f5d1 名簿リセット（このブラウザのみ）</button>\n'
          u'          </div>\n'
          u'          <div class="border-t border-rose-200 pt-3">\n'
          u'            <div class="flex items-center gap-2 flex-wrap mb-2">\n'
          u'              <button onclick="loadNameEditor()" class="bg-rose-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">✏️ 表示名（実名）を編集・保存</button>\n'
          u'              <span class="text-[11px] text-rose-700">CSVを使わず、画面で実名を入力・修正できます。保存先はこのブラウザのみ（クラウドには出ません）。</span>\n'
          u'            </div>\n'
          u'            <div id="nameEditList"></div>\n'
          u'          </div>\n'
          u'          <div id="csvStatusMsg" class="text-xs text-rose-700 font-bold"></div>\n'
          u'        </div>\n')

C4_NEW = (u'        <!-- 2026-09-29 整理(C-4): 実名の入れかたが「CSV」と「画面」の2通りあり、CSVで入れた実名は\n'
          u'             その先生のそのブラウザにしか残らなかった（サーバへ送る処理が無い）。\n'
          u'             画面入力の1本にまとめた。CSVの書き出しは控え用に残して畳んである。\n'
          u'             すでにCSVで入れた実名は消えない。開いたときに「この端末にしか無い実名」を\n'
          u'             数えて、ボタン1つでみんなの画面に移せるようにしてある。 -->\n'
          u'        <div class="bg-rose-50 border border-rose-200 rounded-xl p-4 space-y-3">\n'
          u'          <div class="font-bold text-sm text-rose-800">\U0001f512 名簿（実名の入れかた）</div>\n'
          u'          <div class="text-xs text-rose-700 leading-relaxed">\n'
          u'            実名を入れる場所は<b>ここだけ</b>です。下のボタンで一覧を出し、名前を入力して保存してください。<br>\n'
          u'            保存すると<b>先生みんなの画面・どの端末でも</b>同じ実名で出ます（子どもには出ません）。\n'
          u'          </div>\n'
          u'          <div id="nameMigrateBox" class="hidden text-xs bg-amber-100 border-2 border-amber-400 rounded-lg p-3 text-amber-900 leading-relaxed"></div>\n'
          u'          <div class="border-t border-rose-200 pt-3">\n'
          u'            <div class="flex items-center gap-2 flex-wrap mb-2">\n'
          u'              <button onclick="loadNameEditor()" class="bg-rose-600 text-white rounded-lg px-4 py-2 text-xs font-bold shadow hover:opacity-90">✏️ 実名を入力・保存する</button>\n'
          u'              <span class="text-[11px] text-rose-700">押すと児童の一覧が出ます。ふりがなも入れられます。</span>\n'
          u'            </div>\n'
          u'            <div id="nameEditList"></div>\n'
          u'          </div>\n'
          u'          <details class="border-t border-rose-200 pt-3">\n'
          u'            <summary class="cursor-pointer text-xs font-bold text-rose-800 select-none">ふだんは使わないもの（控えの書き出し・匿名化）</summary>\n'
          u'            <div class="mt-2 flex gap-2 items-center flex-wrap">\n'
          u'              <button onclick="downloadStudentCSV()" class="bg-rose-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">\U0001f4e5 名簿をCSVで書き出す（控え・印刷用）</button>\n'
          u'              <button onclick="anonymizeCloudNames()" class="bg-red-700 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">\U0001f512 クラウド側の名前を空にする</button>\n'
          u'              <button onclick="clearStudentCSV()" class="bg-slate-400 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">\U0001f5d1 この端末に残っている古い名簿を消す</button>\n'
          u'            </div>\n'
          u'            <p class="text-[11px] text-rose-700 mt-2">CSVの読み込み（アップロード）は、その端末にしか残らず先生どうしで共有できなかったので やめました。上の「実名を入力・保存する」を使ってください。</p>\n'
          u'          </details>\n'
          u'          <div id="csvStatusMsg" class="text-xs text-rose-700 font-bold"></div>\n'
          u'        </div>\n')

# 開いたときに移行の案内を出す
C4_TOGGLE_OLD = u'        <details id="rosterAdminBox" class="bg-white rounded-xl shadow p-3">\n'
C4_TOGGLE_NEW = u'        <details id="rosterAdminBox" class="bg-white rounded-xl shadow p-3" ontoggle="if(this.open &amp;&amp; typeof nameMigrateCheck===&#39;function&#39;) nameMigrateCheck();">\n'

# 移行の処理を足す（loadNameEditor の直前に入れる）
C4_JS_ANCHOR = u'      async function loadNameEditor(){\n'
C4_JS_NEW = (
    u"      /* 2026-09-29 整理(C-4) 移行の道：\n"
    u"         CSVで入れた実名は localStorage(studentNameMap) にしか無い。\n"
    u"         サーバ側（先生みんなで共有）に無いものを数えて知らせ、1回で移せるようにする。\n"
    u"         数えるだけ・移すだけで、消す処理は一切しない。 */\n"
    u"      async function nameMigrateCheck(){\n"
    u"        var box=document.getElementById('nameMigrateBox'); if(!box) return;\n"
    u"        try{ if(!window._serverNameMap) await loadServerNameMap(); }catch(_e){}\n"
    u"        var local={}; try{ local=JSON.parse(localStorage.getItem('studentNameMap')||'{}'); }catch(_e2){ local={}; }\n"
    u"        var server=(window._serverNameMap&&typeof window._serverNameMap==='object')?window._serverNameMap:{};\n"
    u"        var only=[]; for(var k in local){ if(!Object.prototype.hasOwnProperty.call(local,k)) continue; var v=String(local[k]||'').trim(); if(!v) continue; if(String(server[k]||'').trim()!==v) only.push(k); }\n"
    u"        window._nameMigrateKeys=only;\n"
    u"        if(!only.length){ box.className='hidden'; box.innerHTML=''; return; }\n"
    u"        box.className='text-xs bg-amber-100 border-2 border-amber-400 rounded-lg p-3 text-amber-900 leading-relaxed';\n"
    u"        box.innerHTML='<b>\u26a0 この端末にしか残っていない実名が '+only.length+'名あります。</b><br>むかしCSVで入れたぶんです。このままだと別のパソコンや他の先生の画面では出ません。<br><button onclick=\"nameMigrateRun()\" class=\"mt-2 bg-amber-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90\">\u2b06 みんなの画面でも出るように移す</button> <span id=\"nameMigrateStatus\" class=\"font-bold\"></span>';\n"
    u"      }\n"
    u"      async function nameMigrateRun(){\n"
    u"        var st=document.getElementById('nameMigrateStatus');\n"
    u"        var keys=window._nameMigrateKeys||[];\n"
    u"        var local={}; try{ local=JSON.parse(localStorage.getItem('studentNameMap')||'{}'); }catch(_e){ local={}; }\n"
    u"        var ok=0, ng=0;\n"
    u"        for(var i=0;i<keys.length;i++){\n"
    u"          if(st) st.textContent='移しています…('+(i+1)+'/'+keys.length+')';\n"
    u"          var v=String(local[keys[i]]||'').trim(); if(!v){ continue; }\n"
    u"          try{ await api('/api/teacher/real-names', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({loginId:keys[i], realName:v}) }); ok++; }\n"
    u"          catch(_e2){ ng++; }\n"
    u"        }\n"
    u"        try{ await loadServerNameMap(); }catch(_e3){}\n"
    u"        if(st) st.textContent='\u2713 '+ok+'名を移しました'+(ng?'（'+ng+'名は失敗）':'');\n"
    u"        try{ renderClasses(); }catch(_e4){}\n"
    u"        try{ await nameMigrateCheck(); }catch(_e5){}\n"
    u"      }\n"
    u"      async function loadNameEditor(){\n")

# ================================================================== E-4 サーバ
E4_SRV_OLD = (u"      let teacherNotes: any[] = []\n"
              u"  try { const _tnr = await c.env.DB.prepare(`SELECT day_key, body, show_in_karte FROM teacher_student_notes WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC`).bind(studentId).all<any>(); teacherNotes = (((_tnr && _tnr.results) || []) as any[]).map((r: any) => ({ dayKey: r.day_key, body: r.body, showInKarte: !!r.show_in_karte })) } catch {}\n")
E4_SRV_NEW = (u"      let teacherNotes: any[] = []\n"
              u"  try { const _tnr = await c.env.DB.prepare(`SELECT day_key, body, show_in_karte FROM teacher_student_notes WHERE user_id=? ORDER BY (day_key IS NULL OR day_key=''), day_key DESC, id DESC`).bind(studentId).all<any>(); teacherNotes = (((_tnr && _tnr.results) || []) as any[]).map((r: any) => ({ dayKey: r.day_key, body: r.body, showInKarte: !!r.show_in_karte })) } catch {}\n"
              u"  // 2026-09-29 整理(E-4): 授業メモ（クラス全体メモ）はこれまでどこにも渡っていなかった。\n"
              u"  //   カルテ・AIの材料として渡す。クラス全体の話なので子どもに渡す紙には出さない。\n"
              u"  //   その子が入っているクラスのメモを、新しいものから30件まで。\n"
              u"  let classNotes: any[] = []\n"
              u"  try { const _cnr = await c.env.DB.prepare(`SELECT n.day_key, n.body FROM teacher_class_notes n JOIN class_members cm ON cm.class_id = n.class_id WHERE cm.user_id=? ORDER BY (n.day_key IS NULL OR n.day_key=''), n.day_key DESC, n.id DESC LIMIT 30`).bind(studentId).all<any>(); classNotes = (((_cnr && _cnr.results) || []) as any[]).map((r: any) => ({ dayKey: r.day_key, body: r.body })) } catch {}\n")

E4_RET_OLD = u'\n    teacherNotes,\n'
E4_RET_NEW = u'\n    teacherNotes,\n    classNotes,\n'

# ================================================================== E-4 AIに渡す文（1人ぶん）
E4_AI1_OLD = (u"if(data.teacherNotes && data.teacherNotes.length){ L.push(''); L.push('【先生の観察メモ（授業中の様子・教師向け）】'); "
              u"for(var tn=0;tn<Math.min(data.teacherNotes.length,15);tn++){ var nt=data.teacherNotes[tn]; L.push('・'+(nt.dayKey||'')+' '+(nt.body||'')); } }")
E4_AI1_NEW = (E4_AI1_OLD +
              u" if(data.classNotes && data.classNotes.length){ L.push(''); L.push('【クラス全体の授業メモ（先生が書いた授業の記録・この子だけの話ではありません）】'); "
              u"for(var cn=0;cn<Math.min(data.classNotes.length,10);cn++){ var cnt=data.classNotes[cn]; L.push('・'+(cnt.dayKey||'')+' '+(cnt.body||'')); } }")

E4_AI2_OLD = (u"if(data.teacherNotes&&data.teacherNotes.length){ L.push(''); L.push('【先生の観察メモ（授業中の様子・教師向け）】'); "
              u"for(var tn=0;tn<Math.min(data.teacherNotes.length,15);tn++){ var nt=data.teacherNotes[tn]; L.push('・'+(nt.dayKey||'')+' '+(nt.body||'')); } }")
E4_AI2_NEW = (E4_AI2_OLD +
              u" if(data.classNotes&&data.classNotes.length){ L.push(''); L.push('【クラス全体の授業メモ（先生が書いた授業の記録・この子だけの話ではありません）】'); "
              u"for(var cn=0;cn<Math.min(data.classNotes.length,10);cn++){ var cnt=data.classNotes[cn]; L.push('・'+(cnt.dayKey||'')+' '+(cnt.body||'')); } }")

# ================================================================== E-4 個人パネルに出す
E4_UI_OLD = (u"          } else { html += '<div class=\"text-xs text-slate-400 mb-3\">まだ記録はありません</div>'; }\n")
E4_UI_NEW = (u"          } else { html += '<div class=\"text-xs text-slate-400 mb-3\">まだ記録はありません</div>'; }\n"
             u"          /* 2026-09-29 整理(E-4): 授業メモ（クラス全体メモ）をここにも出す。折りたたまず、そのまま読める形で出す。 */\n"
             u"          if(data.classNotes && data.classNotes.length){\n"
             u"            html += '<div class=\"mt-1 mb-3 border-t border-slate-100 pt-2\">';\n"
             u"            html += '<div class=\"text-[11px] font-bold text-indigo-700 mb-1\">\U0001f3eb クラス全体の授業メモ（分析タブの「6 授業メモ」で書いたもの）</div>';\n"
             u"            for(var cni=0; cni<Math.min(data.classNotes.length,10); cni++){\n"
             u"              var cnn = data.classNotes[cni];\n"
             u"              html += '<div class=\"text-xs bg-indigo-50 rounded p-1.5 border border-indigo-100 mb-1\"><span class=\"text-slate-400\">'+escH(cnn.dayKey||'')+'</span> '+escH(cnn.body||'')+'</div>';\n"
             u"            }\n"
             u"            html += '</div>';\n"
             u"          }\n")


def main():
    s = io.open(TSX, encoding='utf-8').read()
    n0 = chain_count(s)
    if n0 != CHAIN_WANT:
        die(u'チェーンが %d 件（%d 件のはず）。止めます。' % (n0, CHAIN_WANT))

    s = rep(s, C4_OLD, C4_NEW, 'C-4 名簿管理の画面')
    s = rep(s, C4_TOGGLE_OLD, C4_TOGGLE_NEW, 'C-4 開いたときの案内')
    s = rep(s, C4_JS_ANCHOR, C4_JS_NEW, 'C-4 移行の処理')
    s = rep(s, E4_SRV_OLD, E4_SRV_NEW, 'E-4 サーバ側で授業メモを読む')
    s = rep(s, E4_RET_OLD, E4_RET_NEW, 'E-4 返す中身に足す')
    s = rep(s, E4_AI1_OLD, E4_AI1_NEW, 'E-4 AIに渡す文(1)')
    s = rep(s, E4_AI2_OLD, E4_AI2_NEW, 'E-4 AIに渡す文(2)')
    s = rep(s, E4_UI_OLD, E4_UI_NEW, 'E-4 個人パネルに出す')

    n1 = chain_count(s)
    if n1 != n0:
        die(u'チェーンが %d 件になった（%d 件のままでないとだめ）' % (n1, n0))
    io.open(TSX, 'w', encoding='utf-8').write(s)
    print('PATCH OK / chain %d -> %d' % (n0, n1))


main()
