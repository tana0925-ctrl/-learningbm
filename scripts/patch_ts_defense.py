import sys
def patch_all(path, edits, label):
    data=open(path,'rb').read().decode('utf-8')
    for old,new,expect in edits:
        c=data.count(old)
        if c==0:
            print('['+label+'] skip (already)', file=sys.stderr); continue
        if c!=expect:
            print('['+label+'] COUNT '+str(c)+' != '+str(expect), file=sys.stderr); sys.exit(1)
        data=data.replace(old,new)
    open(path,'wb').write(data.encode('utf-8'))
    print('['+label+'] ok', file=sys.stderr)
patch_all('src/index.tsx', [
 ('SUM(CASE WHEN correct=1 THEN 1 ELSE 0 END)', 'SUM(CASE WHEN is_correct=1 THEN 1 ELSE 0 END)', 6),
 ('SUM(CASE WHEN lr.correct=1 THEN 1 ELSE 0 END)', 'SUM(CASE WHEN lr.is_correct=1 THEN 1 ELSE 0 END)', 1),
], 'index.tsx')
print('DONE', file=sys.stderr)
