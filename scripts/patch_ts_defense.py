import sys

def patch_file(path, edits):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        data = f.read()
    for old, new in edits:
        if new in data and old not in data:
            print('skip (already applied):', repr(old[:40]))
            continue
        if old not in data:
            print('ANCHOR NOT FOUND in', path, '::', repr(old[:70]))
            sys.exit(1)
        if data.count(old) != 1:
            print('ANCHOR NOT UNIQUE', data.count(old), repr(old[:70]))
            sys.exit(1)
        data = data.replace(old, new)
        print('ok', path, '::', repr(old[:40]))
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(data)

HOWTO = (
"      function _kHowToLearn(d){ d=d||{}; var ov=d.overview||{}; var sg=(d.student&&d.student.grade)||null; var subj=(d.subjects||[]).slice(); "
"var esc=function(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }; "
"var cl=function(u){ return _gradeClass(sg,_unitGrade(u)); }; "
"var review=subj.filter(function(s){return cl(s.unit)==='review'&&s.total>=10;}).sort(function(a,b){return a.rate-b.rate;}); "
"var reviewWeak=review.filter(function(s){return s.rate<70;}).slice(0,3); "
"var grow=subj.filter(function(s){return s.rate<70&&s.total>=5&&cl(s.unit)==='same';}).sort(function(a,b){return a.rate-b.rate;}); "
"if(!grow.length){ grow=subj.filter(function(s){return s.rate<70&&s.total>=5&&cl(s.unit)!=='review';}).sort(function(a,b){return a.rate-b.rate;}); } grow=grow.slice(0,3); "
"var good=subj.filter(function(s){return s.rate>=80&&s.total>=20&&cl(s.unit)==='same';}).sort(function(a,b){return b.rate-a.rate;}); "
"var uL=function(s){ var g=_unitGrade(s.unit); return (g?g+'年 ':'')+_unitJa(s.unit); }; "
"var methodFor=function(u){ var a=_subjectArea(u); if(a==='math') return '1日3〜5問ずつ、まちがえた問題はやり方を声に出してもう一度'; if(a==='jp') return '音読と漢字を毎日5分、まちがえた言葉はノートに書き出す'; if(a==='soc') return '用語を声に出して説明し、ミニクイズで確かめる'; if(a==='sci') return '図や実験を思い出しながら、用語をクイズで確かめる'; return '少しずつ毎日、まちがい直しを大切に'; }; "
"var spacingFor=function(r){ return (r>=60)?'1回10分 × 週2〜3回、日をあけて（分散学習）':'1回10分を3日つづけて → 数日あけてもう1回'; }; "
"var one=''; if(reviewWeak.length){ var t0=reviewWeak[0]; one='まず土台から。<b>'+esc(uL(t0))+'</b>（いま '+t0.rate+'%）を復習しよう。'+esc(methodFor(t0.unit))+'。'; } "
"else if(grow.length){ var g0=grow[0]; one='<b>'+esc(_unitJa(g0.unit))+'</b>（いまの学年・'+g0.rate+'%）をもう一度ていねいに。'+esc(methodFor(g0.unit))+'。'; } "
"else if(good.length){ one='いまの学年はバッチリ！<b>'+esc(_unitJa(good[0].unit))+'</b>をさらに伸ばすか、上の学年の先取りに挑戦してみよう。'; } "
"else { one='今のペースで、毎日つづけることを大切に。続けることが一番の力だよ。'; } "
"var pool=reviewWeak.concat(grow).slice(0,4); var revList=[]; for(var i=0;i<pool.length;i++){ var p=pool[i]; revList.push('<li style=\"margin:4px 0\"><b>'+esc(uL(p))+'</b>（'+p.rate+'%）… '+esc(spacingFor(p.rate))+'。'+esc(methodFor(p.unit))+'</li>'); } "
"var voices=[]; if((ov.maxStreak||0)>=5) voices.push('毎日つづけられる力がすごいね。続けられること自体が、もう立派な才能だよ。'); "
"voices.push('「できた／できない」より「どうやってできたか」を一緒に話そう。やり方に目を向けると次に活きるよ。'); "
"if(reviewWeak.length) voices.push('むずかしい所に挑戦できたね。まちがいは「のびるチャンス」。直せたら100点と同じだよ。'); else voices.push('ここまでよく積み上げたね。次の一歩を自分で選べたら、もっと強くなるよ。'); voices=voices.slice(0,3); "
"var plans=(d.plans||[]); var refs=(d.reflections||[]); var hasGoal=plans.length>0; var hasDo=(ov.totalSubmissions||0)>0; var hasReflect=refs.filter(function(r){return r.nextAction||r.goodPoint||r.improvePoint;}).length>0; "
"var loopMsg=''; if(!hasGoal){ loopMsg='まず「今週はこれをやる」と一つ決めてから始めると、ぐっと続けやすくなるよ。'; } else if(!hasReflect){ loopMsg='目標→実行はできている。ふりかえりに「次はこうする」を一言足すと、サイクルが回り出すよ。'; } else { loopMsg='目標→実行→ふりかえりがしっかり回っている。この習慣こそ、一番の学ぶ力だよ。'; } "
"var bdg=function(on,txt){ return '<span style=\"display:inline-block;font-size:11px;padding:2px 8px;border-radius:10px;margin:0 4px 4px 0;'+(on?'background:#dcfce7;color:#15803d':'background:#f1f5f9;color:#94a3b8')+'\">'+(on?'✓ ':'')+txt+'</span>'; }; "
"var H=[]; H.push('<div style=\"border:2px solid #c7d2fe;border-radius:14px;padding:12px 14px;margin-bottom:11px;background:#eef2ff\">'); "
"H.push('<div style=\"font-weight:800;font-size:16px;color:#4338ca;margin-bottom:8px\">📚 どう学ぶといいか（おうちでの学び方）</div>'); "
"H.push('<div style=\"background:#fff;border-radius:10px;padding:9px 12px;margin-bottom:8px\"><div style=\"font-weight:800;color:#4338ca;font-size:13px\">🎯 今週の一手（これだけでOK）</div><div style=\"margin-top:3px;color:#334155\">'+one+'</div></div>'); "
"if(revList.length){ H.push('<div style=\"margin-bottom:8px\"><div style=\"font-weight:800;color:#0369a1;font-size:13px\">🔁 復習する単元とやり方（分散学習）</div><ul style=\"margin:4px 0;padding-left:20px;color:#334155\">'+revList.join('')+'</ul></div>'); } "
"H.push('<div style=\"margin-bottom:8px\"><div style=\"font-weight:800;color:#16a34a;font-size:13px\">💬 おうちでの声かけ例（努力・やり方をほめる）</div><ul style=\"margin:4px 0;padding-left:20px;color:#334155\">'); for(var v=0;v<voices.length;v++){ H.push('<li style=\"margin:3px 0\">'+esc(voices[v])+'</li>'); } H.push('</ul></div>'); "
"H.push('<div><div style=\"font-weight:800;color:#b45309;font-size:13px\">🔄 目標 → 実行 → ふりかえり のループ</div><div style=\"margin:5px 0\">'+bdg(hasGoal,'目標を立てる')+bdg(hasDo,'実行する')+bdg(hasReflect,'ふりかえる')+'</div><div style=\"color:#7c2d12\">'+esc(loopMsg)+'</div></div>'); "
"H.push('</div>'); return H.join(''); }\n"
)

SRV_EDITS = [
    # 1) define _kHowToLearn just before _buildKarteHtml
    ("      function _buildKarteHtml(){ var d=window._faData||{};",
     HOWTO + "      function _buildKarteHtml(){ var d=window._faData||{};"),
    # 2) insert into PDF karte before とくいな教科 section
    ("H.push('<div class=\"sec good\"><h2>💪 とくいな教科'+(_sg?'（いまの学年）':'')+'</h2>');",
     "H.push(_kHowToLearn(d)); H.push('<div class=\"sec good\"><h2>💪 とくいな教科'+(_sg?'（いまの学年）':'')+'</h2>');"),
    # 3) insert into on-screen overlay
    ("window._faData = data; window._faName = studentName; window._faId = studentId;",
     "window._faData = data; window._faName = studentName; window._faId = studentId; try{ html += _kHowToLearn(data); }catch(_khl){}"),
]

patch_file('src/index.tsx', SRV_EDITS)
print('DONE')
