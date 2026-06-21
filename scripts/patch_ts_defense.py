import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip:',repr(old[:40])); continue
        if old not in data:
            print('ANCHOR NOT FOUND',path,repr(old[:70])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old),repr(old[:70])); sys.exit(1)
        data=data.replace(old,new); print('ok',path,repr(old[:40]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ('      function copyTestPrompt(){',
     "      function _recTypeLabel(t){ if(t==='reflect') return '振り返り'; if(t==='other') return 'その他'; return 'まとめ・レポート'; }\n      function copyRecordPrompt(){\n        var NL=String.fromCharCode(10);\n        var sel=document.getElementById('recType'); var t=sel?sel.value:'report';\n        var label=_recTypeLabel(t);\n        var L=[];\n        L.push('あなたは小学校の先生のアシスタントです。アップロードした（または貼り付けた）児童の'+label+'のPDF・画像から、児童ごとに内容を読み取り、次の「出力形式」だけを、コードブロックに入れずそのまま出力してください。前置きや説明は書かないでください。');\n        L.push('');\n        L.push('【出力形式】児童ごとに次のブロックをくり返す。');\n        L.push('=== [児童ID] 名前 ===');\n        L.push('タイトル: （'+label+'のタイトル。なければ内容を短く要約）');\n        L.push('日付: （YYYY-MM-DD。わからなければ空欄）');\n        L.push('教科: （国語・算数・理科・社会 など。なければ空欄）');\n        L.push('単元: （わかれば。なければ空欄）');\n        L.push('本文:');\n        L.push('（児童が書いた文章をそのまま。複数行でよい）');\n        L.push('');\n        L.push('【ルール】児童IDは名簿のログインID。わからなければ [名前] のように名前を入れる。1人ずつ「=== [..] .. ===」で区切る。本文は「本文:」の次の行からブロックの終わり（次の===）まで。要約や講評を勝手に足さず、児童の記述を尊重する。読み取れない児童は飛ばしてよい。');\n        var txt=L.join(NL);\n        var st=document.getElementById('recPromptStatus');\n        var done=function(){ if(st) st.textContent='✓ コピーしました。AIに貼り付けてください'; };\n        if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done,function(){ _faFallbackCopy(txt); done(); }); } else { _faFallbackCopy(txt); done(); }\n      }\n      function parseRecords(){\n        var ta=document.getElementById('recPaste'); var raw=ta?ta.value:'';\n        var st=document.getElementById('recParseStatus');\n        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';\n        if(!cid){ if(st) st.textContent='先に「クラス」を選んでください'; return; }\n        if(!raw||!raw.trim()){ if(st) st.textContent='AIの出力を貼り付けてください'; return; }\n        if(st) st.textContent='読み取り中...';\n        fetch('/api/teacher/records/parse',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({classId:cid,text:raw})}).then(function(r){return r.json();}).then(function(d){\n          if(!d||!d.ok){ if(st) st.textContent='読み取りに失敗しました（クラス権限などを確認）'; return; }\n          window._recParsed=d;\n          if(st) st.textContent='✓ '+d.rows.length+'件を読み取りました。内容を確認して保存してください';\n          _recRenderPreview(d);\n        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });\n      }\n      function copyTestPrompt(){"),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE P5_funcsA')
