# inject-rt.py
# public/index.html に追加スクリプトのタグ挿入 + window.getPlayer の公開
import sys

HTML_FILE = 'public/index.html'
SCRIPTS = ['/rt-battle.js', '/typeshoot.js']

with open(HTML_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

changed = False
for src in SCRIPTS:
    tag = '<script src="' + src + '"></script>'
    marker = '<script src="' + src + '"'
    if marker in content:
        print('[inject] already present: ' + src)
        continue
    if '</body>' in content:
        content = content.replace('</body>', tag + '</body>', 1)
    elif '</html>' in content:
        content = content.replace('</html>', tag + '</html>', 1)
    else:
        content += tag
    changed = True
    print('[inject] injected: ' + src)

# 外部スクリプト(typeshoot.js等)から player を読めるように公開
anchor = 'window.saveData = saveData;'
helper = ' window.getPlayer = window.getPlayer || function(){ try { return player; } catch(e){ return null; } };'
if anchor in content and 'window.getPlayer = window.getPlayer ||' not in content:
    content = content.replace(anchor, anchor + helper, 1)
    changed = True
    print('[inject] exposed window.getPlayer')

if changed:
    with open(HTML_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

print('[inject] done.')
