import sys

def patch_file(path, edits):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        data = f.read()
    for old, new in edits:
        if new in data and old not in data:
            print('skip (already applied):', repr(old[:40]))
            continue
        if old not in data:
            print('ANCHOR NOT FOUND in', path, '::', repr(old[:70]))
            sys.exit(1)
        if data.count(old) != 1:
            print('ANCHOR NOT UNIQUE', data.count(old), repr(old[:70]))
            sys.exit(1)
        data = data.replace(old, new)
        print('ok', path, '::', repr(old[:40]))
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(data)

PUB_EDITS = [
    ('<div class="font-bold text-indigo-700">🔁 そろそろ復習しよう（忘れかけ）</div>',
     '<div class="font-bold text-indigo-700">📚 復習おすすめ</div>'),
]

patch_file('public/index.html', PUB_EDITS)
print('DONE')
