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

# Fix: edit #7 left if(reflectC.length) unclosed; add one closing brace
SRC_EDITS = [
    ("if(sgd&&sgd.ok) msgs.push('おすすめ計画'+sgd.saved+'人'); }catch(e){} }",
     "if(sgd&&sgd.ok) msgs.push('おすすめ計画'+sgd.saved+'人'); }catch(e){} } }"),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE FIX')
