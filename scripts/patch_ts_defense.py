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
            print('NOT UNIQUE',data.count(old),repr(old[:40])); sys.exit(1)
        data=data.replace(old,new); print('ok',repr(old[:30]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

# Fix2: suggestC save must be a SIBLING of reflectC (not nested inside if(reflectC.length))
SRC_EDITS = [
    ("'振り返り返却'+fd.saved+'人'); }catch(e){}\n        if(suggestC.length){ try{ var sgr=await fetch('/api/teacher/plan-suggestions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({weekKey:wk,comments:suggestC})}); var sgd=await sgr.json(); if(sgd&&sgd.ok) msgs.push('おすすめ計画'+sgd.saved+'人'); }catch(e){} } }",
     "'振り返り返却'+fd.saved+'人'); }catch(e){} }\n        if(suggestC.length){ try{ var sgr=await fetch('/api/teacher/plan-suggestions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({weekKey:wk,comments:suggestC})}); var sgd=await sgr.json(); if(sgd&&sgd.ok) msgs.push('おすすめ計画'+sgd.saved+'人'); }catch(e){} }"),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE FIX2')
