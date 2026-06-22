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
    ("              html += '</div>';\n            }\n\n            card.innerHTML = html;\n            wrap.appendChild(card);",
     '              html += \'</div>\';\n            }\n\n            (function(){ var _dl=[\'月\',\'火\',\'水\',\'木\',\'金\']; var _pl=[]; for(var _di=0;_di<5;_di++){ var _kk=keys[_di]||\'\'; var _vv=_kk?parsed[_kk]:\'\'; var _tt=(typeof _vv===\'object\'&&_vv)?(_vv.free||\'\'):(_vv||\'\'); if(_tt&&String(_tt).trim()) _pl.push(_dl[_di]+\'：\'+_tt); } if(!window._planTextByUser) window._planTextByUser={}; window._planTextByUser[p.userId]={name:__pName, lines:_pl}; })();\n            html += \'<div class="mt-1 border-t border-violet-100 pt-1 space-y-1">\'\n              + \'<div class="flex items-center gap-1 flex-wrap"><button onclick="copyOnePlanForAi(&#39;\'+escH(p.userId)+\'&#39;)" class="bg-emerald-600 text-white rounded px-2 py-0.5 text-[11px] font-bold hover:opacity-90">📋 この子の計画＋履歴をAIにコピー</button><span id="planOneStatus_\'+escH(p.userId)+\'" class="text-[10px] text-violet-700 font-bold"></span></div>\'\n              + \'<div class="flex items-center gap-1"><textarea id="planOnePaste_\'+escH(p.userId)+\'" class="flex-1 border border-violet-300 rounded p-1 text-[11px]" rows="1" placeholder="AIの結果を貼って保存（この子の計画アドバイス）"></textarea><button onclick="saveOnePlanAiComment(&#39;\'+escH(p.userId)+\'&#39;)" class="bg-violet-600 text-white rounded px-2 py-0.5 text-[11px] font-bold hover:opacity-90 shrink-0">保存</button></div>\'\n              + \'</div>\';\n            card.innerHTML = html;\n            wrap.appendChild(card);'),
    ('      async function copyPlansForAi(){',
     "      async function copyOnePlanForAi(uid){ var rec=(window._planTextByUser||{})[uid]; var st=document.getElementById('planOneStatus_'+uid); if(!rec){ if(st) st.textContent='再読み込みしてください'; return; } if(st) st.textContent='学習履歴を取得中...'; var NL=String.fromCharCode(10); var L=[]; L.push('あなたは小学校の先生のサポート役です。次の児童の「今週の計画」と「これまでの学習履歴（今年度4月\\u301C の集計）」の両方を踏まえて、\\u2460よい点 \\u2461もっとよくする点（具体的か・無理のない量か・ふりかえりにつながるか・その子の苦手や得意に合っているか）\\u2462子どもへのひとことアドバイス を、子どもにそのまま返せるやさしい日本語で書いてください。前置きや説明は不要。'); L.push(''); L.push('\\u25A0 児童: '+(rec.name||'')); L.push('【今週の計画】'); if(rec.lines&&rec.lines.length){ for(var i=0;i<rec.lines.length;i++) L.push(rec.lines[i]); } else { L.push('（計画の記入がありません）'); } L.push(''); L.push('【この児童の学習履歴（今年度4月\\u301C の集計）】'); try{ var res=await fetch('/api/teacher/student-full-analysis?studentId='+encodeURIComponent(uid)); var data=await res.json(); if(data&&data.ok&&typeof _aiBodyLines==='function'){ L=L.concat(_aiBodyLines(data)); } else { L.push('（学習履歴の取得に失敗しました）'); } }catch(e){ L.push('（学習履歴の取得エラー）'); } var txt=L.join(NL); var done=function(){ if(st) st.textContent='\\u2713 計画＋履歴をコピーしました。AIに貼り付け→結果を下に貼って保存'; }; if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done,function(){ if(typeof _faFallbackCopy==='function') _faFallbackCopy(txt); done(); }); } else { if(typeof _faFallbackCopy==='function') _faFallbackCopy(txt); done(); } }\n      async function saveOnePlanAiComment(uid){ var st=document.getElementById('planOneStatus_'+uid); var ta=document.getElementById('planOnePaste_'+uid); var raw=ta?ta.value:''; if(!raw||!raw.trim()){ if(st) st.textContent='AIの結果を貼ってください'; return; } if(st) st.textContent='保存中...'; try{ var wk=(typeof getWeekKeyLocal==='function')?getWeekKeyLocal():''; var res=await fetch('/api/teacher/plan-ai-comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({weekKey:wk,comments:[{studentId:uid,comment:raw}]})}); var d=await res.json(); if(d&&d.ok&&d.saved>0){ if(st) st.textContent='\\u2713 保存しました（子ども側に表示）'; } else { if(st) st.textContent='保存できませんでした（今週の計画が必要です）'; } }catch(e){ if(st) st.textContent='エラー: '+(e&&e.message?e.message:e); } }\n      async function copyPlansForAi(){"),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE ONEPLAN')
