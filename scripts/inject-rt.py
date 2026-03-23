# inject-rt.py
# learningbm_index.html に RT バトルスクリプトタグを挿入するパッチスクリプト
import re, sys

HTML_FILE = 'public/index.html'
SCRIPT_TAG = '<script src="/rt-battle.js"></script>'
MARKER     = 'rt-battle.js'

with open(HTML_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

if MARKER in content:
    print('[inject-rt] already injected, skipping.')
    sys.exit(0)

# </body> の直前に挿入
if '</body>' in content:
    content = content.replace('</body>', SCRIPT_TAG + '</body>', 1)
    print('[inject-rt] inserted before </body>')
elif '</html>' in content:
    content = content.replace('</html>', SCRIPT_TAG + '</html>', 1)
    print('[inject-rt] inserted before </html>')
else:
    content += SCRIPT_TAG
    print('[inject-rt] appended to end of file')

with open(HTML_FILE, 'w', encoding='utf-8') as f:
    f.write(content)

print('[inject-rt] done.')
