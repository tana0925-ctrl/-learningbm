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
    ('  window.pveSelectedGrade = 4;',
     '  try{ window.UNIT_DISPLAY = UNIT_DISPLAY; }catch(e){}\r\n  window.pveSelectedGrade = 4;'),
    ("        var nm=(typeof _modeLabel==='function')?_modeLabel(s.unit):s.unit;",
     "        var nm=null; try{ if(window.UNIT_DISPLAY&&window.UNIT_DISPLAY[s.unit]&&window.UNIT_DISPLAY[s.unit].name) nm=window.UNIT_DISPLAY[s.unit].name; }catch(e){} if(nm==null){ nm=(typeof _modeLabel==='function')?_modeLabel(s.unit):s.unit; }"),
]

patch_file('public/index.html', PUB_EDITS)
print('DONE')
