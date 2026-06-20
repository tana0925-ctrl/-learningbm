import sys

def patch_file(path, edits):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        data = f.read()
    for old, new in edits:
        if new in data and old not in data:
            print('skip (already applied):', repr(old[:40]))
            continue
        if old not in data:
            print('ANCHOR NOT FOUND in', path, '::', repr(old[:60]))
            sys.exit(1)
        if data.count(old) != 1:
            print('ANCHOR NOT UNIQUE', data.count(old), repr(old[:60]))
            sys.exit(1)
        data = data.replace(old, new)
        print('ok', path, '::', repr(old[:40]))
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(data)

PUB_EDITS = [
    # _curUnitById must read window.CURRICULUM (CURRICULUM is in a different <script> block, not in this scope)
    ("function _curUnitById(id){ try{ if(typeof CURRICULUM==='undefined'||!CURRICULUM) return null; for(var sk in CURRICULUM){ var sj=CURRICULUM[sk];",
     "function _curUnitById(id){ try{ var C=window.CURRICULUM; if(!C) return null; for(var sk in C){ var sj=C[sk];"),
]

patch_file('public/index.html', PUB_EDITS)
print('DONE')
