import sys
target = 'public/index.html'
data = open(target, 'rb').read().decode('utf-8')
done = "saveData(); }catch(e){}\r\n                  }\r\n                }catch(e){}"
if done in data:
    print('already applied')
    sys.exit(0)
search = '                    try{if(typeof player.oldCoinDailyStart!="undefined") player.oldCoinDailyStart=(player.coins||0);}catch(e){}\r\n                  }\r\n                }catch(e){}'
if search not in data:
    print('ERROR: anchor not found')
    sys.exit(1)
repl = '                    try{if(typeof player.oldCoinDailyStart!="undefined") player.oldCoinDailyStart=(player.coins||0);}catch(e){}\r\n                    try{ if(typeof saveData===\'function\') saveData(); }catch(e){}\r\n                  }\r\n                }catch(e){}'
data = data.replace(search, repl, 1)
open(target, 'wb').write(data.encode('utf-8'))
print('coin fix applied')
