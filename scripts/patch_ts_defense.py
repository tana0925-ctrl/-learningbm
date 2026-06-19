import sys
def patch_remove(path, olds):
    data=open(path,'rb').read().decode('utf-8')
    for old in olds:
        if old not in data:
            print('skip (already removed)', file=sys.stderr); continue
        c=data.count(old)
        if c!=1:
            print('COUNT '+str(c), file=sys.stderr); sys.exit(1)
        data=data.replace(old,'',1)
    open(path,'wb').write(data.encode('utf-8'))
    print('ok', file=sys.stderr)
OLDS=['H.push(\'<div class="sec"><h2>👩\u200d🏫 先生からの ひとこと</h2><div class="note"></div></div>\');']
patch_remove('src/index.tsx', OLDS)
print('DONE', file=sys.stderr)
