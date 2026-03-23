import re

with open('learningbm_index.html', 'r', encoding='utf-8') as f:
    src = f.read()

print('=== /api/rt/ occurrences:', sum(1 for _ in re.finditer(r'/api/rt/', src)))
for m in re.finditer(r'/api/rt/', src):
    ctx = src[max(0,m.start()-250):min(len(src),m.end()+500)]
    print('--- pos', m.start(), '---')
    print(ctx)
    print()

for kw in ['rtRoom','rtState','rtBattle','friendRoom','hostHp','guestHp','lastEventId','rtPoll','pollRT','startRT','rtTimer','rt_room','friendBattle','wildBattle']:
    matches = list(re.finditer(re.escape(kw), src))
    if matches:
        m = matches[0]
        print('=== ' + kw + ' (x' + str(len(matches)) + ') ===')
        print(src[max(0,m.start()-150):min(len(src),m.end()+400)])
        print()
    else:
        print('NOT FOUND: ' + kw)
