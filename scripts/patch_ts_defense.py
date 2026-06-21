import sys
def patch_file(path, edits):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        data = f.read()
    for old, new in edits:
        if new in data and old not in data:
            print('skip:', repr(old[:40])); continue
        if old not in data:
            print('ANCHOR NOT FOUND', path, repr(old[:70])); sys.exit(1)
        if data.count(old) != 1:
            print('NOT UNIQUE', data.count(old), repr(old[:70])); sys.exit(1)
        data = data.replace(old, new); print('ok', path, repr(old[:40]))
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(data)

SRV_EDITS = [
    ("window.UNIT_JP = {",
     "window.UNIT_JP = {'kuku':'九九','m3-divR':'わり算(あまりあり)','s6-hist':'歴史(6年)','m6-speed':'速さ(6年)',"),
]
patch_file('src/index.tsx', SRV_EDITS)
print('DONE')
