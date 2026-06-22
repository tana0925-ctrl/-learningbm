import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip'); continue
        if old not in data:
            print('ANCHOR NOT FOUND',repr(old[:60])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old)); sys.exit(1)
        data=data.replace(old,new); print('ok',repr(old[:30]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ('          <div id="csvStatusMsg" class="text-xs text-rose-700 font-bold"></div>',
     '          <div class="border-t border-rose-200 pt-3">\n            <div class="flex items-center gap-2 flex-wrap mb-2">\n              <button onclick="loadNameEditor()" class="bg-rose-500 text-white rounded-lg px-3 py-1.5 text-xs font-bold shadow hover:opacity-90">✏️ 表示名を直接編集（このブラウザに保存）</button>\n              <span class="text-[11px] text-rose-700">CSVを使わず、画面で実名を入力・修正できます。保存先はこのブラウザのみ（クラウドには出ません）。</span>\n            </div>\n            <div id="nameEditList"></div>\n          </div>\n          <div id="csvStatusMsg" class="text-xs text-rose-700 font-bold"></div>'),
    ('      async function downloadStudentCSV(){',
     '      async function loadNameEditor(){\n        var el=document.getElementById(\'nameEditList\'); if(!el) return;\n        el.innerHTML=\'<div class="text-xs text-slate-400">読み込み中...</div>\';\n        try{\n          var data=await api(\'/api/teacher/all-students\');\n          var students=(data.students||[]); var map=getStudentNameMap();\n          window._nameEditRoster=students;\n          var h=\'<div class="max-h-72 overflow-y-auto border rounded-lg bg-white p-2"><table class="w-full text-xs"><thead><tr class="text-slate-400"><th class="text-left p-1">ログインID</th><th class="text-left p-1">学年/クラス</th><th class="text-left p-1">表示名（実名）</th></tr></thead><tbody>\';\n          for(var i=0;i<students.length;i++){ var s=students[i]; var cur=(map[s.loginId]!=null&&map[s.loginId]!==\'\')?map[s.loginId]:((s.name&&s.name!==s.loginId)?s.name:\'\'); h+=\'<tr><td class="p-1 font-mono text-slate-600">\'+escH(s.loginId)+\'</td><td class="p-1 text-slate-400">\'+escH((s.grade||\'\')+(s.className?(\' \'+s.className):\'\'))+\'</td><td class="p-1"><input id="nmEdit_\'+i+\'" class="border rounded p-1 w-full" value="\'+escH(cur)+\'" placeholder="（未設定）"></td></tr>\'; }\n          h+=\'</tbody></table></div><div class="flex items-center gap-2 mt-2"><button onclick="saveNameEdits()" class="bg-rose-600 text-white rounded-lg px-4 py-1.5 text-xs font-bold hover:bg-rose-700">💾 表示名を保存（このブラウザ）</button><span id="nameEditStatus" class="text-xs font-bold text-rose-700"></span></div>\';\n          el.innerHTML=h;\n        }catch(e){ el.innerHTML=\'<div class="text-xs text-red-500">読み込み失敗: \'+escH(String(e.message||e))+\'</div>\'; }\n      }\n      function saveNameEdits(){\n        var students=window._nameEditRoster||[]; var map=getStudentNameMap(); var cnt=0;\n        for(var i=0;i<students.length;i++){ var inp=document.getElementById(\'nmEdit_\'+i); if(!inp) continue; var v=String(inp.value||\'\').trim(); var lid=students[i].loginId; if(v){ map[lid]=v; cnt++; } else { if(map[lid]!=null) delete map[lid]; } }\n        setStudentNameMap(map);\n        var st=document.getElementById(\'nameEditStatus\'); if(st) st.textContent=\'✓ \'+cnt+\'名の表示名を保存しました（このブラウザのみ）\';\n        try{ if(typeof loadClasses===\'function\') loadClasses(); }catch(_e){}\n      }\n      async function downloadStudentCSV(){'),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE QD')
