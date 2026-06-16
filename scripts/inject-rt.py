# inject-rt.py
# public/index.html に追加スクリプト(rt-battle.js / typeshoot.js)のタグを挿入する
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

if changed:
    with open(HTML_FILE, 'w', encoding='utf-8') as f:
        f.write(content)

print('[inject] done.')
