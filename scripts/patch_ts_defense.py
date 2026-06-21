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

PUB_EDITS = [
    ('function startGame() {',
     "function startGame() { try { var _p = window.getPlayer && window.getPlayer(); var _t = _p ? Number(_p.gymTickets || 0) : 0; if (!_p || _t < 1) { alert('タイプシュート（エンドレス）には🎫バトルチケットが必要です！ショップで買ってね。'); return; } _p.gymTickets = _t - 1; if (window.saveData) window.saveData(); if (window.updateDisplay) window.updateDisplay(); } catch(e) {}"),
]

patch_file('public/typeshoot.js', PUB_EDITS)
print('DONE')
