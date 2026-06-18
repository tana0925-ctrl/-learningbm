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

# typeshoot.js: expose startGame globally
patch_file('public/typeshoot.js', [
 ('  window.startTypeShootVS = startTypeShootVS;',
  '  window.startTypeShootVS = startTypeShootVS;'+LF+'  window.startTypeShoot = startGame;', 'window.startTypeShoot = startGame'),
], 'typeshoot.js')

ts_btn_desktop = '''    <button class="w-full px-4 py-3 text-sm font-bold text-purple-700 hover:bg-purple-50 flex items-center gap-2 whitespace-nowrap border-t border-slate-100" onclick="(window.startTypeShoot&&window.startTypeShoot()); closeBattleMenu()"><span>⌨</span>タイプシュート</button>'''
ts_btn_mobile = '''    <button class="w-full px-4 py-3 text-sm font-bold text-purple-700 hover:bg-purple-50 flex items-center gap-2 whitespace-nowrap border-t border-slate-100" onclick="(window.startTypeShoot&&window.startTypeShoot()); closeBattleMenuMobile()"><span>⌨</span>タイプシュート</button>'''

patch_file('public/index.html', [
 ('''    <button class="w-full px-4 py-3 text-sm font-bold text-amber-600 hover:bg-amber-50 flex items-center gap-2 whitespace-nowrap border-t border-slate-100" onclick="trySetMode('egg_select'); closeBattleMenu()"><span>🥚</span>タマゴバトル</button>''',
  '''    <button class="w-full px-4 py-3 text-sm font-bold text-amber-600 hover:bg-amber-50 flex items-center gap-2 whitespace-nowrap border-t border-slate-100" onclick="trySetMode('egg_select'); closeBattleMenu()"><span>🥚</span>タマゴバトル</button>'''+CRLF+ts_btn_desktop, 'closeBattleMenu()"><span>⌨</span>'),
 ('''    <button class="w-full px-4 py-3 text-sm font-bold text-amber-600 hover:bg-amber-50 flex items-center gap-2 whitespace-nowrap border-t border-slate-100" onclick="trySetMode('egg_select'); closeBattleMenuMobile()"><span>🥚</span>タマゴバトル</button>''',
  '''    <button class="w-full px-4 py-3 text-sm font-bold text-amber-600 hover:bg-amber-50 flex items-center gap-2 whitespace-nowrap border-t border-slate-100" onclick="trySetMode('egg_select'); closeBattleMenuMobile()"><span>🥚</span>タマゴバトル</button>'''+CRLF+ts_btn_mobile, 'closeBattleMenuMobile()"><span>⌨</span>'),
], 'index.html')
print('DONE', file=sys.stderr)
