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
    ('function _genTrainQ_curriculum() {',
     "function _trainAdaptPick(genFn){ try{ if(typeof genFn!=='function') return (typeof generateDecimalProblem==='function'?generateDecimalProblem():{q:'?',ans:0}); var first=genFn(); var eligible=function(pb){ try{ if(!pb) return false; if(pb.inputType==='mcq') return false; if(pb.options) return false; if(typeof pb.ans!=='number') return false; var q=String(pb.q||''); if(q.indexOf('<')>=0) return false; return true; }catch(e){ return false; } }; if(!eligible(first)) return first; var mode=(window.__currUnit&&window.__currUnit.id)?window.__currUnit.id:(typeof trainingMode!=='undefined'?trainingMode:''); var acc=null,n=0; try{ var p=window.getPlayer&&window.getPlayer(); var pr=p&&p.trainingProgress&&p.trainingProgress[mode]; var ra=(pr&&pr.recentAnswers)?pr.recentAnswers.slice(-8):[]; n=ra.length; if(n>=4){ var ok=0; for(var k=0;k<ra.length;k++){ if(ra[k]===true) ok++; } acc=ok/n; } }catch(e){} if(acc==null) return first; var want=(acc>=0.85)?'hard':((acc<=0.5)?'easy':'mid'); if(want==='mid') return first; var cands=[first]; for(var i=0;i<3;i++){ try{ var c=genFn(); if(eligible(c)) cands.push(c); }catch(e){} } if(cands.length<2) return first; var score=function(pb){ var s=0; try{ var a=Math.abs(Number(pb.ans)); var digits=String(a).replace('.','').length; s+=digits*3; s+=(a>0?Math.min(15,Math.log(a+1)):0); var q=String(pb.q||''); s+=Math.min(15,q.length/3); }catch(e){} return s; }; cands.sort(function(a,b){ return score(a)-score(b); }); return (want==='hard')?cands[cands.length-1]:cands[0]; }catch(e){ try{ return genFn(); }catch(_e){ return {q:'?',ans:0}; } } }\n\nfunction _genTrainQ_curriculum() {"),
    ("const prob = (typeof window[genName] === 'function') ? window[genName]() : (typeof generateDecimalProblem === 'function' ? generateDecimalProblem() : {q:'?',ans:0});",
     "const prob = (typeof window[genName] === 'function') ? _trainAdaptPick(window[genName]) : (typeof generateDecimalProblem === 'function' ? generateDecimalProblem() : {q:'?',ans:0});"),
]

patch_file('public/index.html', PUB_EDITS)
print('DONE')
