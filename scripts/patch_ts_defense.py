import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip:',repr(old[:40])); continue
        if old not in data:
            print('ANCHOR NOT FOUND',path,repr(old[:70])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old),repr(old[:70])); sys.exit(1)
        data=data.replace(old,new); print('ok',path,repr(old[:40]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

PUB_EDITS = [
    ('<div class="mt-3 grid grid-cols-1 lg:grid-cols-2 gap-6">',
     '<div id="homeGrowthCard" class="mt-3"></div> <div class="mt-3 grid grid-cols-1 lg:grid-cols-2 gap-6">'),
    ("try{ if(typeof loadReviewSuggestions==='function') loadReviewSuggestions(); }catch(e){} try{ if(typeof loadMiniReview==='function') loadMiniReview(); }catch(e){}",
     'try{ (function(){ var gc=document.getElementById(\'homeGrowthCard\'); if(!gc) return; var bu=(learn&&learn.byUnit)?learn.byUnit:{}; var nm=function(mode){ try{ var C=window.CURRICULUM; if(C){ for(var sk in C){ var sj=C[sk]; if(!sj||!sj.grades) continue; for(var gk in sj.grades){ var us=sj.grades[gk]&&sj.grades[gk].units; if(!us) continue; for(var qi=0;qi<us.length;qi++){ if(us[qi]&&us[qi].id===mode) return us[qi].name; } } } } }catch(e){} try{ if(window.UNIT_DISPLAY&&window.UNIT_DISPLAY[mode]&&window.UNIT_DISPLAY[mode].name) return window.UNIT_DISPLAY[mode].name; }catch(e){} try{ if(typeof _modeLabel===\'function\') return _modeLabel(mode); }catch(e){} return mode; }; var esc=function(s){ return String(s==null?\'\':s).split(\'&\').join(\'&amp;\').split(\'<\').join(\'&lt;\').split(\'>\').join(\'&gt;\'); }; var master=[], almost=[], challenge=0; Object.keys(bu).forEach(function(mode){ var u=bu[mode]||{}; var t=Number(u.total||0); var c=Number(u.correct||0); challenge+=t; if(t>=10){ var acc=Math.round(c/t*100); if(acc>=80) master.push({mode:mode,acc:acc,total:t}); else if(acc>=60) almost.push({mode:mode,acc:acc,total:t}); } }); master.sort(function(a,b){ return b.acc-a.acc; }); almost.sort(function(a,b){ return b.total-a.total; }); var streak=0; try{ var M=ensureMetrics(); var D=(M&&M.daily)?M.daily:{}; var dd=new Date(); var done=function(dt){ var r=D[_localDateKey(dt.getTime())]; return !!(r&&(Number(r.training||0)>0||Number(r.battles||0)>0)); }; if(!done(dd)){ dd.setDate(dd.getDate()-1); } for(var i=0;i<400;i++){ if(done(dd)){ streak++; dd.setDate(dd.getDate()-1); } else break; } }catch(e){} var html=\'\'; html+=\'<div class="rounded-2xl p-4" style="background:linear-gradient(135deg,#ecfccb,#dbeafe)">\'; html+=\'<div class="font-black text-emerald-800 text-lg flex items-center gap-2"><span>🌱</span>きみの成長きろく</div>\'; html+=\'<div class="mt-3 grid grid-cols-3 gap-2 text-center">\'; html+=\'<div class="bg-white/70 rounded-xl py-2"><div class="text-2xl font-black text-emerald-700">\'+master.length+\'</div><div class="text-xs text-gray-600">マスターした単元</div></div>\'; html+=\'<div class="bg-white/70 rounded-xl py-2"><div class="text-2xl font-black text-blue-700">\'+challenge+\'</div><div class="text-xs text-gray-600">チャレンジした問題</div></div>\'; html+=\'<div class="bg-white/70 rounded-xl py-2"><div class="text-2xl font-black text-orange-700">\'+streak+\'</div><div class="text-xs text-gray-600">れんぞく学習日</div></div>\'; html+=\'</div>\'; if(master.length){ html+=\'<div class="mt-3"><div class="text-xs font-bold text-emerald-800 mb-1">🌟 とくいになった単元</div><div class="flex flex-wrap gap-1">\'; master.slice(0,6).forEach(function(m){ html+=\'<span class="text-xs bg-emerald-100 text-emerald-800 rounded-full px-2 py-1 font-bold">\'+esc(nm(m.mode))+\' \'+m.acc+\'%</span>\'; }); html+=\'</div></div>\'; } if(almost.length){ var g=almost[0]; html+=\'<div class="mt-3 bg-white/70 rounded-xl px-3 py-2"><div class="text-xs font-bold text-orange-700">🎯 つぎのもくひょう</div><div class="font-bold text-gray-800 mt-1">\'+esc(nm(g.mode))+\' <span class="text-orange-600">いま\'+g.acc+\'% → 80%でマスター！</span></div></div>\'; } var msg; if(master.length>=5) msg=\'すごい！マスター単元がどんどん増えてるね🎉\'; else if(master.length>=1) msg=\'いいちょうし！この調子でマスターを増やそう💪\'; else if(challenge>0) msg=\'スタート！まずは同じ単元を10問やってみよう✨\'; else msg=\'修行をはじめると、ここに成長がたまっていくよ！\'; html+=\'<div class="mt-3 text-sm font-bold text-emerald-900">\'+msg+\'</div>\'; html+=\'</div>\'; gc.innerHTML=html; })(); }catch(e){} try{ if(typeof loadReviewSuggestions===\'function\') loadReviewSuggestions(); }catch(e){} try{ if(typeof loadMiniReview===\'function\') loadMiniReview(); }catch(e){}'),
]

patch_file('public/index.html', PUB_EDITS)
print('DONE')
