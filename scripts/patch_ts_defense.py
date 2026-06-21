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
    ('function handleIncorrectAnswer() {',
     "function _trainHint(u){ u=String(u||''); var T={'m6-circle':'半径×半径×3.14。直径と半径のとりちがえに注意！まず図に半径を書こう。','m6-frac-div':'分数のわり算は「ひっくり返してかける」。約分のし忘れに注意。','m6-frac-mul':'計算の前に約分するとラク。帯分数は仮分数に直してから。','m6-ratio':'比は「何対何」。ジュースと水などでイメージしよう。','m5-dec-div':'小数のわり算は小数点の移動がカギ。わる数を整数にした分だけ、わられる数も動かそう。','m5-dec-mul':'まず整数として計算→小数点を合計けた分つける。','m5-percent':'まず「もとにする量」を見つけよう。0.01＝1%。','m5-frac-eq':'約分・通分は分母の最小公倍数がカギ。九九を使おう。','long-division':'たてる→かける→ひく→おろす。位をそろえて書くとミスが減るよ。','m2-kuku':'九九はリズムで！あやしい段はくり返し言ってみよう。','m1-sub-no':'ひき算は「ぜんぶ から へらす」。ブロックで考えてみよう。','m1-sub-bo':'くり下がりは、上の位から10をかりてくる！','rounding':'どの位で四捨五入するか先に印をつけよう。','j5-keigo':'尊敬語とけんじょう語のとりちがえに注意。「言う→おっしゃる／申す」。','j6-bunpo':'主語・述語・修飾語を色分けして組み立てを見よう。','s6-world':'地図と国旗をセットで思い出そう。'}; if(T[u]) return T[u]; var c=u.charAt(0); var mset=['rounding','division','decimal','area','brackets','long-division','fraction-mixed','kuku']; var jset=['idiom','conjunction','yoji']; if(c==='m'||mset.indexOf(u)>=0) return '計算のとちゅうをもう一度たしかめよう。くり上がり・小数点・約分・位に気をつけて！'; if(c==='j'||jset.indexOf(u)>=0) return '声に出して読んでみよう。にた言葉・送りがな・漢字の読みに注意！'; if(c==='s'||u.indexOf('social')===0) return '地図・年表・絵とむすびつけて、お話のように思い出そう。'; if(c==='r'||u.indexOf('science')===0) return '実験や図を思い出して、「なぜそうなる？」を考えてみよう。'; return 'まちがえた所をもう一度見て、ゆっくりチャレンジ！'; }\n        function handleIncorrectAnswer() {"),
    ("document.getElementById('trainingFeedback').innerText = 'ちがうよ！';",
     'try{ var _fbEl=document.getElementById(\'trainingFeedback\'); var _tq=(window.trainingQ||(typeof trainingQ!==\'undefined\'?trainingQ:null)); var _ansT=\'\'; if(_tq){ if(_tq.options&&typeof _tq.ans===\'number\'&&_tq.options[_tq.ans]!=null) _ansT=String(_tq.options[_tq.ans]); else if(_tq.ans!=null&&_tq.ans!==\'__FM_OK__\') _ansT=String(_tq.ans); } var _hh=\'\'; try{ _hh=_trainHint(trainingMode); }catch(e){} var _es=function(s){ return String(s==null?\'\':s).split(\'&\').join(\'&amp;\').split(\'<\').join(\'&lt;\').split(\'>\').join(\'&gt;\'); }; if(_fbEl){ _fbEl.innerHTML=\'<span class="block" style="color:#dc2626">❌ おしい！</span>\'+(_ansT!==\'\'?\'<span class="block" style="font-size:15px;color:#1e293b">正解は <b>\'+_es(_ansT)+\'</b></span>\':\'\')+(_hh?\'<span class="block" style="font-size:12px;font-weight:700;color:#475569">💡 \'+_es(_hh)+\'</span>\':\'\'); } else { document.getElementById(\'trainingFeedback\').innerText=\'ちがうよ！\'; } }catch(e){ try{ document.getElementById(\'trainingFeedback\').innerText=\'ちがうよ！\'; }catch(_e){} }'),
]

patch_file('public/index.html', PUB_EDITS)
print('DONE')
