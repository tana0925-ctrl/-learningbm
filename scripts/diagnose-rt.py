import re

with open('learningbm_index.html', 'r', encoding='utf-8') as f:
    src = f.read()

# Extract JS section only (between <script> tags)
scripts = re.findall(r'<script[^>]*>(.*?)</script>', src, re.DOTALL)
js = '\n'.join(scripts)
print('Total JS chars:', len(js))

# List all function names
funcs = re.findall(r'(?:function\s+(\w+)|(?:const|let|var|window\.)\s*(\w+)\s*=\s*(?:async\s*)?function|(?:const|let|var)\s*(\w+)\s*=\s*(?:async\s*)?\()', js)
func_names = [f[0] or f[1] or f[2] for f in funcs if any(f)]
print('FUNCTIONS (' + str(len(func_names)) + '):', ', '.join(func_names))

# Find battle-related functions
print()
print('--- battle functions ---')
for name in func_names:
    if any(kw in name.lower() for kw in ['battle','answer','correct','damage','room','ready','hp','start','friend','wild']):
        print(name)

# Find specific patterns
print()
for kw in ['battle.roomId', 'rtRoomId', 'roomId', 'correctAnswer', 'onCorrect', 'handleCorrect', 'dealDamage', 'sendDamage', 'battle.mode', 'battle.type', 'isFriendBattle', 'isRT']:
    cnt = js.count(kw)
    if cnt > 0:
        idx = js.index(kw)
        print(kw + ' x' + str(cnt) + ': ' + repr(js[max(0,idx-60):idx+100]))
    else:
        print(kw + ': NOT FOUND')
