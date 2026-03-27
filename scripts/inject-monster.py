import os

HTML_FILE = 'public/index.html'
SCRIPT_TAG = '<script src="/monster-system.js"></script>'
MARKER = 'monster-system.js'

with open(HTML_FILE, 'r', encoding='utf-8') as f:
    content = f.read()

if MARKER in content:
    print(f'Already injected: {SCRIPT_TAG}')
else:
    if '</body>' in content:
        content = content.replace('</body>', SCRIPT_TAG + '</body>', 1)
        print(f'Injected before </body>: {SCRIPT_TAG}')
    elif '</html>' in content:
        content = content.replace('</html>', SCRIPT_TAG + '</html>', 1)
        print(f'Injected before </html>: {SCRIPT_TAG}')
    else:
        content += SCRIPT_TAG
        print(f'Appended: {SCRIPT_TAG}')

    with open(HTML_FILE, 'w', encoding='utf-8') as f:
        f.write(content)
