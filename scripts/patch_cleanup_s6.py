# -*- coding: utf-8 -*-
"""
patch_cleanup_s6.py — 教師ダッシュボードの片づけ 第2便(1/3)
2026-09-29  CLEANUP_S3

先生の訴え「ごちゃごちゃしてつかいにくい」に対する第2便の前半。
削除するものは、すべて実際のコードで「動いていない／代替がある」ことを
確かめたうえで消している（確かめられなかったものは消していない）。

A-6 「🔄 更新」「🔄 読み込む」系のボタンを撤去（開いた時点で読み込むようにする）
  ・家庭学習の「🔄 更新」…クラス/表示/期間の3つの選ぶ欄すべてに
    onchange="loadHomework()" が付いており、サブタブを開いたときにも
    switchHomeworkSubTab('daily') が loadHomework() を呼ぶ。完全に重複。撤去。
  ・「📝 生徒の今週の計画」の「🔄 読み込み直す」…<details ontoggle> で
    開いたときに hwPlanOpened() → loadStudentPlans() が走る。撤去。
    あわせて hwPlanOpened() の「一度だけ」制限を外し、開くたびに
    最新を読むようにした（ボタンを消しても古いままにならないように）。
  ・個人カルテの「🔄 児童一覧を表示」…分析タブの「4 AIの結果」を開いた
    ときに自動で読むようにしてから撤去。
  ・直接入力の「🔄 名簿を読み込む」…分析タブの「5 テスト取り込み」を
    開いたときに自動で読むようにしてから撤去。

B-3 🎯 ミッションタブを畳む（消さない）
  ・中身は1つも削っていない。ふだんは閉じておき、使うときだけ開く。

C-3 児童ひとりへのメモの保存ボタンが2か所あったのを1つに
  ・「授業メモ」タブの「👤 児童ごとメモ」と、分析の個人パネル内
    「📝 先生の記録」は、どちらも同じ /api/teacher/student-notes に
    同じ中身を保存していた（保存先は同じ）。
  ・見ている子にそのまま書ける「個人パネルの中」を残し、わざわざ
    児童を選び直す「授業メモ」タブ側を撤去。書いたメモの一覧は
    個人パネルの中にそのまま出るので、読めなくなるものは無い。

E-2 「6年１組」を画面から隠す（消さない）
  ・実データで確認：id bd8b4ede-… / 在籍1人 / 担任は別の先生。
  ・管理画面のクラス一覧から既定で隠す。「隠しているクラスも表示する」
    にチェックを入れれば、いつでも元どおり出る（データは消さない）。

★このパッチは src/index.tsx の /teacher と /admin の画面だけを触る。
  児童ページの配信チェーン（app.get('/') の .replace() 連鎖）は1つも
  増減させない（158件のまま）。
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


# ------------------------------------------------------------------ A-6a
A6A_OLD = u'            <button onclick="loadHomework()" class="bg-slate-200 rounded px-3 py-1 text-sm" title="いまの条件でもう一度読み込みます">\U0001f504 更新</button>\n'
A6A_NEW = u'            <!-- 2026-09-29 整理(A-6): 「\U0001f504 更新」を撤去。上の3つの選ぶ欄すべてが onchange で読み直し、\n                 サブタブを開いたときにも自動で読み込むため、押す必要が無かった。 -->\n'

# ------------------------------------------------------------------ A-6b
A6B_OLD = (u'            <div class="mt-2 flex justify-end">\n'
           u'              <button onclick="loadStudentPlans()" class="bg-blue-600 text-white rounded-lg px-3 py-1 text-xs font-bold shadow hover:opacity-90">\U0001f504 読み込み直す</button>\n'
           u'            </div>\n')
A6B_NEW = u'            <!-- 2026-09-29 整理(A-6): 「\U0001f504 読み込み直す」を撤去。開いたときに毎回いちばん新しいものを読む。 -->\n'

A6B2_OLD = (u'      function hwPlanOpened(){\n'
            u'        if(window._hwPlanLoaded) return;\n'
            u'        window._hwPlanLoaded = true;\n'
            u'        try{ loadStudentPlans(); }catch(e){}\n'
            u'      }')
A6B2_NEW = (u'      function hwPlanOpened(){\n'
            u'        /* 2026-09-29 整理(A-6): 「読み込み直す」ボタンを消したので、\n'
            u'           開くたびに読み直す（前は初回だけで、古いまま見えることがあった）。 */\n'
            u'        try{ loadStudentPlans(); }catch(e){}\n'
            u'      }')

# ------------------------------------------------------------------ A-6c
A6C_OLD = u'            <p class="text-xs text-amber-600">名前をクリックすると、その子の記録をまとめた画面が開きます。<button onclick="taiLoadRoster()" class="ml-1 bg-amber-500 text-white rounded px-2 py-0.5 text-[11px] font-bold hover:bg-amber-600">\U0001f504 児童一覧を表示</button></p>'
A6C_NEW = u'            <p class="text-xs text-amber-600">名前をクリックすると、その子の記録をまとめた画面が開きます。<!-- 2026-09-29 整理(A-6): 「\U0001f504 児童一覧を表示」を撤去。このタブを開いたときに自動で出る。 --></p>'

A6C2_OLD = u'              <p class="text-xs text-slate-400">「児童一覧を表示」を押してください</p>'
A6C2_NEW = u'              <p class="text-xs text-slate-400">上の「クラス」をえらぶと、児童の名前がここに出ます</p>'

# ------------------------------------------------------------------ A-6d
A6D_OLD = u'                <button onclick="recDirLoadRoster()" class="bg-slate-200 text-slate-700 rounded-lg px-2 py-1 text-xs font-bold hover:bg-slate-300">\U0001f504 名簿を読み込む</button>\n'
A6D_NEW = u'                <!-- 2026-09-29 整理(A-6): 「\U0001f504 名簿を読み込む」を撤去。このタブを開いたときに自動で読む。 -->\n'

# ---- 自動読み込みを switchAnalyticsSubTab に足す（ボタンを消す前提の受け皿）
SUB_OLD = (u"        if(sub==='notes' && typeof initNotesTab==='function') initNotesTab();\n"
           u"        if(sub==='ai' && typeof loadAiSummary==='function'){ try{ loadAiSummary(); }catch(_e){} }\n")
SUB_NEW = (u"        if(sub==='notes' && typeof initNotesTab==='function') initNotesTab();\n"
           u"        if(sub==='ai' && typeof loadAiSummary==='function'){ try{ loadAiSummary(); }catch(_e){} }\n"
           u"        /* 2026-09-29 整理(A-6): 「\\u{1F504} 児童一覧を表示」「\\u{1F504} 名簿を読み込む」の2つのボタンを消したので、\n"
           u"           タブを開いた時点で名簿を読む。クラスが選ばれていないときは何もしない（空の注意文を出さない）。 */\n"
           u"        try{\n"
           u"          var _laSel = document.getElementById('laClassSelect');\n"
           u"          var _laCid = _laSel ? _laSel.value : '';\n"
           u"          if(_laCid && sub==='ai' && typeof taiLoadRoster==='function'){ try{ taiLoadRoster(); }catch(_e2){} }\n"
           u"          if(_laCid && sub==='tests' && typeof recDirLoadRoster==='function'){ try{ recDirLoadRoster(); }catch(_e3){} }\n"
           u"        }catch(_e4){}\n")

# ------------------------------------------------------------------ B-3
B3_OPEN_OLD = u'      <div id="tabPaneMissions" class="hidden space-y-3">\n'
B3_OPEN_NEW = (u'      <div id="tabPaneMissions" class="hidden space-y-3">\n'
               u'        <!-- 2026-09-29 整理(B-3): ミッションは毎日は触らないので畳んだ。機能は1つも消していない。 -->\n'
               u'        <details class="bg-white rounded-xl shadow px-4 py-3">\n'
               u'          <summary class="cursor-pointer font-bold text-slate-700 select-none">\U0001f3af ミッション・ひみつのQR<span class="text-xs font-normal text-slate-400 ml-2">ふだんは使いません（使うときだけ開いてください）</span></summary>\n'
               u'          <div class="mt-3 space-y-3">\n')
B3_CLOSE_OLD = (u'          <div id="qrHuntBox" class="text-sm text-slate-400">よみこみ中…</div>\n'
                u'        </div>\n'
                u'      </div>\n')
B3_CLOSE_NEW = (u'          <div id="qrHuntBox" class="text-sm text-slate-400">よみこみ中…</div>\n'
                u'        </div>\n'
                u'          </div>\n'
                u'        </details>\n'
                u'      </div>\n')

# ------------------------------------------------------------------ C-3
C3_OLD = (u'          <div class="bg-white rounded-xl shadow p-4">\n'
          u'            <div class="font-bold text-slate-700 mb-1">\U0001f464 児童ごとメモ</div>\n'
          u'            <div class="text-xs text-slate-500 mb-2">児童を選んで、授業中の様子をサッと一言。チェックを入れたメモだけ「子ども向けカルテPDF」に載ります（既定はオフ＝先生だけが見る）。</div>\n'
          u'            <div class="flex flex-col gap-2">\n'
          u'              <select id="snoteStudent" class="border rounded p-1.5 text-xs bg-white" onchange="loadStudentNotesTab()"></select>\n'
          u'              <input id="snoteDate" type="date" class="border rounded p-1.5 text-xs w-40">\n'
          u'              <input id="snoteBody" class="w-full border rounded-lg p-2 text-xs" placeholder="例：発表でしっかり説明できた">\n'
          u'              <label class="flex items-center gap-1 text-xs text-slate-600"><input id="snoteKarte" type="checkbox"> カルテ（子ども向け）にも載せる</label>\n'
          u'              <div class="flex items-center gap-2"><button onclick="saveStudentNoteTab()" class="bg-teal-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-teal-700">\U0001f4be 児童メモを保存</button><span id="snoteStatus" class="text-xs text-teal-600 font-bold"></span></div>\n'
          u'            </div>\n'
          u'            <div id="snoteList" class="mt-3 space-y-1"></div>\n'
          u'          </div>\n')
C3_NEW = (u'          <!-- 2026-09-29 整理(C-3): 「\U0001f464 児童ごとメモ」はここと、分析の個人パネル内「\U0001f4dd 先生の記録」の\n'
          u'               2か所にあり、どちらも同じ場所（teacher_student_notes）に保存していた。見ている子に\n'
          u'               そのまま書ける個人パネル側を残し、こちらを1つにまとめた。書いたメモは個人パネルの\n'
          u'               中にそのまま一覧で出るので、読めなくなるものは無い。 -->\n'
          u'          <div class="bg-white rounded-xl shadow p-4">\n'
          u'            <div class="font-bold text-slate-700 mb-1">\U0001f464 児童ひとりへのメモ</div>\n'
          u'            <div class="text-xs text-slate-500">「1 クラス全体」で<b>児童の名前をクリック</b>すると開く画面の、<b>\U0001f4dd 先生の記録</b>から書けます。<br>保存される場所は前とまったく同じです（書いたメモもそのまま残っています）。</div>\n'
          u'          </div>\n')

# ------------------------------------------------------------------ E-2
E2_OLD = (u'          const d = await api(&#39;/api/admin/classes&#39;);\n')
E2_OLD_PLAIN = u"          const d = await api('/api/admin/classes');\n          wrap.innerHTML='';\n          if(!d.classes.length){ wrap.textContent='クラスがまだありません'; return; }\n          for(const cls of d.classes){\n"
E2_NEW_PLAIN = (u"          const d = await api('/api/admin/classes');\n"
                u"          wrap.innerHTML='';\n"
                u"          /* 2026-09-29 整理(E-2): 「6年１組」(id bd8b4ede-…) は在籍1人・担任が別の先生で、\n"
                u"             この画面では使わないので既定で隠す。データは消していない。\n"
                u"             下のチェックを入れればいつでも出る。 */\n"
                u"          var _hideIds = ['bd8b4ede-0e2c-4f12-b76a-e28c0a62ce5a'];\n"
                u"          var _showAllEl = document.getElementById('admShowHiddenClasses');\n"
                u"          var _showAll = _showAllEl ? !!_showAllEl.checked : false;\n"
                u"          var _all = d.classes || [];\n"
                u"          var _list = _showAll ? _all : _all.filter(function(x){ return _hideIds.indexOf(x.id) < 0; });\n"
                u"          var _hidden = _all.length - _list.length;\n"
                u"          if(!_list.length){ wrap.textContent='クラスがまだありません'; }\n"
                u"          for(const cls of _list){\n")
E2_TAIL_OLD = (u"            div.onclick = ()=>{ openClassDetail(cls.id, cls.name, cls.classCode, cls.teacherName); };\n"
               u"            wrap.appendChild(div);\n"
               u"          }\n")
E2_TAIL_NEW = (u"            div.onclick = ()=>{ openClassDetail(cls.id, cls.name, cls.classCode, cls.teacherName); };\n"
               u"            wrap.appendChild(div);\n"
               u"          }\n"
               u"          /* 隠しているクラスがあることは必ず画面に出す（黙って消さない） */\n"
               u"          var _note = document.createElement('label');\n"
               u"          _note.className = 'flex items-center gap-1 text-xs text-gray-400 mt-2 cursor-pointer';\n"
               u"          _note.innerHTML = '<input type=\"checkbox\" id=\"admShowHiddenClasses\"' + (_showAll ? ' checked' : '') + '> 使っていないクラスも表示する'\n"
               u"            + (_showAll ? '' : (_hidden ? '（いま ' + _hidden + 'クラスを隠しています）' : ''));\n"
               u"          var _cb = _note.querySelector('input');\n"
               u"          if(_cb) _cb.onchange = ()=>{ renderClassList(); };\n"
               u"          wrap.appendChild(_note);\n")


def main():
    s = io.open(TSX, encoding='utf-8').read()

    n0 = chain_count(s)
    if n0 != CHAIN_WANT:
        die(u'チェーンが %d 件（%d 件のはず）。止めます。' % (n0, CHAIN_WANT))

    s = rep(s, A6A_OLD, A6A_NEW, 'A-6a 家庭学習の更新ボタン')
    s = rep(s, A6B_OLD, A6B_NEW, 'A-6b 今週の計画の読み込み直す')
    s = rep(s, A6B2_OLD, A6B2_NEW, 'A-6b2 hwPlanOpened')
    s = rep(s, A6C_OLD, A6C_NEW, 'A-6c 児童一覧を表示')
    s = rep(s, A6C2_OLD, A6C2_NEW, 'A-6c2 案内文')
    s = rep(s, A6D_OLD, A6D_NEW, 'A-6d 名簿を読み込む')
    s = rep(s, SUB_OLD, SUB_NEW, 'A-6 自動読み込みの受け皿')
    s = rep(s, B3_OPEN_OLD, B3_OPEN_NEW, 'B-3 ミッション畳む(開き)')
    s = rep(s, B3_CLOSE_OLD, B3_CLOSE_NEW, 'B-3 ミッション畳む(閉じ)')
    s = rep(s, C3_OLD, C3_NEW, 'C-3 児童ごとメモ')
    s = rep(s, E2_OLD_PLAIN, E2_NEW_PLAIN, 'E-2 クラス一覧の絞り込み')
    s = rep(s, E2_TAIL_OLD, E2_TAIL_NEW, 'E-2 隠している旨の表示')

    n1 = chain_count(s)
    if n1 != n0:
        die(u'チェーンが %d 件になった（%d 件のままでないとだめ）' % (n1, n0))

    # エスケープ事故の検出（9/26に教師画面を2時間落とした原因）
    bad = s.count("(\\'")
    io.open(TSX, 'w', encoding='utf-8').write(s)
    print('PATCH OK / chain %d -> %d / (\\\' の数 %d' % (n0, n1, bad))


main()
