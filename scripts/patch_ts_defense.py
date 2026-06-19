import sys
LF=chr(10); CRLF=chr(13)+chr(10)
def patch_file(path, edits, label):
    data=open(path,'rb').read().decode('utf-8')
    for old,new,guard in edits:
        if guard and guard in data:
            print('['+label+'] skip', file=sys.stderr); continue
        c=data.count(old)
        if c!=1:
            print('['+label+'] ANCHOR x'+str(c), file=sys.stderr); sys.exit(1)
        data=data.replace(old,new,1)
    open(path,'wb').write(data.encode('utf-8'))
    print('['+label+'] ok', file=sys.stderr)
patch_file('public/index.html', [(
 'var _mObj = (player.M && player.M.max) || player.max || {};',
 'var _mObj = (player.metrics && player.metrics.max) || (player.M && player.M.max) || player.max || {};',
 'player.metrics && player.metrics.max')], 'index.html')
patch_file('src/index.tsx', [(
 'const maxObj: any = s.max || (s.M && s.M.max) || {}',
 'const maxObj: any = (s.metrics && s.metrics.max) || s.max || (s.M && s.M.max) || {}',
 '(s.metrics && s.metrics.max) || s.max')], 'index.tsx')
patch_file('public/typeshoot.js', [(
 '  function closeGame() {'+LF+'    S.open = false; S.ready = false; stopLoops();',
 '  function closeGame() {'+LF+'    try { var _pc = window.getPlayer && window.getPlayer(); if (_pc && (S.score||0) > Number(_pc._cachedTypeShootScore||0)) { _pc._cachedTypeShootScore = S.score||0; if (window.saveData) window.saveData(); } } catch(e){}'+LF+'    S.open = false; S.ready = false; stopLoops();',
 'if (_pc && (S.score||0) > Number(_pc._cachedTypeShootScore')], 'typeshoot.js')
print('DONE', file=sys.stderr)
