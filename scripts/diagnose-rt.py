import re

with open('learningbm_index.html', 'r', encoding='utf-8') as f:
    src = f.read()

def show(kw, context=600):
    matches = list(re.finditer(re.escape(kw), src))
    if matches:
        m = matches[0]
        print('=== ' + kw + ' (x' + str(len(matches)) + ') ===')
        print(src[max(0,m.start()-100):min(len(src),m.end()+context)])
        print()
    else:
        print('NOT FOUND: ' + kw)

# Find battle creation fetch calls
print('=== fetch calls containing /api/ ===')
for m in re.finditer(r"fetch\(['\"]/api/[^'\"]+", src):
    print(src[max(0,m.start()-30):min(len(src),m.end()+200)])
    print('---')

print()
show('startBattleSequence', 1500)
show('friendBattle', 800)
show('createRoom', 800)
show('joinRoom', 800)
show('rtBattle', 800)
show('battle.roomId', 800)
show('roomId', 400)
show('correctAnswer', 800)
show('onCorrect', 800)
show('answerCorrect', 800)
show('showResult', 400)
