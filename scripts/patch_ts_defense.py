import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip'); continue
        if old not in data:
            print('ANCHOR NOT FOUND',repr(old[:50])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old)); sys.exit(1)
        data=data.replace(old,new); print('ok',repr(old[:34]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

PUB_EDITS = [
    ('      if (!V.synced) V.synced = true;',
     '      if (!V.synced && evs.length < 50) V.synced = true;'),
]

patch_file('public/typeshoot.js', PUB_EDITS)
print('DONE FIXVS')
