#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
中1英語 単元パック v170（ネットレ対応 第2弾）パッチスクリプト
public/index.html に以下を追加する:
  1. CURRICULUM に english 教科（中1・8単元）
  2. 修行の教科選択画面に「英語」ボタン＋正解率表示
  3. 学習分析の教科リストに英語
  4. 野生バトル: 英語地方・エリア8件・深さ・出現プール
  5. 新野生モンスター3体（1126-1128 進化ライン）
  6. 中1英語 問題生成器パック（4択MCQ・基礎40/標準40/発展20）
使い方: python3 scripts/patch_eigo7.py
"""
import sys

target = 'public/index.html'
with open(target, 'rb') as f:
    content = f.read().decode('utf-8')

orig_len = len(content)
applied = 0
failed = []

def patch(name, search, replace, must=True):
    global content, applied
    # CRLF / LF 両対応: そのまま→CRLF化→LF化 の順で一意に一致するものを使う
    cands = [(search, replace),
             (search.replace('\n', '\r\n'), replace.replace('\n', '\r\n')),
             (search.replace('\r\n', '\n'), replace.replace('\r\n', '\n'))]
    for s2, r2 in cands:
        if content.count(s2) == 1:
            content = content.replace(s2, r2, 1)
            applied += 1
            print(f"OK {name}", file=sys.stderr)
            return
    failed.append(f"{name}: anchor count={content.count(search)}")
    print(f"SKIP {name}: anchor not unique", file=sys.stderr)

# ── 1. CURRICULUM に english 教科を追加 ─────────────────────
CURR_ANCHOR = """      {id:'r6-environment',name:'生物と地球環境',icon:'🌍',color:'green',gen:'genEnvironment6',input:'mcq',desc:'食物連鎖・生態系・温暖化'}
    ]}
  }}
};"""
CURR_NEW = """      {id:'r6-environment',name:'生物と地球環境',icon:'🌍',color:'green',gen:'genEnvironment6',input:'mcq',desc:'食物連鎖・生態系・温暖化'}
    ]}
  }},
  english: { name:'英語', icon:'🔤', color:'sky', grades: {
    7:{label:'中1',units:[
      {id:'e7-be',name:'be動詞',icon:'🅱️',color:'blue',gen:'genBe7',input:'mcq',desc:'am・is・are と否定文・疑問文'},
      {id:'e7-verb',name:'一般動詞',icon:'🏃',color:'green',gen:'genVerb7',input:'mcq',desc:'play・like など動詞の文'},
      {id:'e7-3tan',name:'三単現のs',icon:'✍️',color:'red',gen:'gen3tan7',input:'mcq',desc:'plays・does と三人称単数'},
      {id:'e7-pron',name:'代名詞・複数形',icon:'👥',color:'purple',gen:'genPron7',input:'mcq',desc:'I my me mine と名詞の複数形'},
      {id:'e7-question',name:'疑問詞',icon:'❓',color:'orange',gen:'genQword7',input:'mcq',desc:'what・where・when・how'},
      {id:'e7-can',name:'canと命令文',icon:'💪',color:'teal',gen:'genCan7',input:'mcq',desc:'can の文と命令文'},
      {id:'e7-ing',name:'現在進行形',icon:'🏊',color:'cyan',gen:'genIng7',input:'mcq',desc:'be動詞＋ing の文'},
      {id:'e7-past',name:'過去形',icon:'⏰',color:'amber',gen:'genPast7',input:'mcq',desc:'played・went と過去の文'}
    ]}
  }}
};"""
patch('1 CURRICULUM english', CURR_ANCHOR, CURR_NEW)

# ── 2a. 修行 教科選択画面に「英語」ボタン ───────────────────
BTN_ANCHOR = """<div class="text-xs opacity-90 font-bold">観察と実験で強くなる！<br/><span class="text-yellow-200" id="acc-subject-science"></span></div>
</button>"""
BTN_NEW = BTN_ANCHOR + """
<button class="text-white p-5 rounded-2xl text-center relative overflow-hidden group" style="background: linear-gradient(180deg, #38bdf8, #0284c7); box-shadow: 0 6px 0 #0369a1, 0 8px 20px rgba(2,132,199,0.3); border: 3px solid rgba(255,255,255,0.4); transition: transform 0.12s, box-shadow 0.12s;" onmousedown="this.style.transform='translateY(3px)';this.style.boxShadow='0 2px 0 #0369a1, 0 3px 8px rgba(2,132,199,0.2)'" onmouseup="this.style.transform='';this.style.boxShadow=''" onmouseleave="this.style.transform='';this.style.boxShadow=''" id="btn-subject-english" onclick="showSubjectModes('english')">
<div class="text-6xl mb-2">🔤</div>
<div class="text-2xl font-black mb-1">英語</div>
<div class="text-xs opacity-90 font-bold">英語にチャレンジ！<br/><span class="text-yellow-200" id="acc-subject-english"></span></div>
</button>"""
patch('2a 英語ボタン', BTN_ANCHOR, BTN_NEW)

# ── 2b. updateSubjectButtons に ENGLISH 集計 ────────────────
ACC_ANCHOR = """            const sciEl = document.getElementById('acc-subject-science');
            if (sciEl) sciEl.innerText = `直近100問の正解率 ${sciAcc}%`;

        }"""
ACC_NEW = """            const sciEl = document.getElementById('acc-subject-science');
            if (sciEl) sciEl.innerText = `直近100問の正解率 ${sciAcc}%`;

            // ENGLISH
            const engModes = [..._collectCurriculumIds('english')];
            const engUniq = [...new Set(engModes)];
            const engRes = _aggregateAccuracy(engUniq);
            const engAcc = engRes.total > 0 ? Math.round((engRes.correct / engRes.total) * 100) : 0;
            const engEl = document.getElementById('acc-subject-english');
            if (engEl) engEl.innerText = `直近100問の正解率 ${engAcc}%`;

        }"""
patch('2b ENGLISH集計', ACC_ANCHOR, ACC_NEW)

# ── 3a. _CURRICULUM_SUBJ_MAP に english ─────────────────────
SUBJ_ANCHOR = """  science:  { subject:'science', subjectName:'理科' },
};"""
SUBJ_NEW = """  science:  { subject:'science', subjectName:'理科' },
  english:  { subject:'eng',     subjectName:'英語' },
};"""
patch('3a SUBJ_MAP', SUBJ_ANCHOR, SUBJ_NEW)

# ── 3b. 学習分析の教科リストに英語 ──────────────────────────
ANA_ANCHOR = "{key:'science',  name:'理科', icon:'🔬'}];"
ANA_NEW = "{key:'science',  name:'理科', icon:'🔬'},\n      {key:'eng',  name:'英語', icon:'🔤'}];"
patch('3b 学習分析リスト', ANA_ANCHOR, ANA_NEW)

# ── 4a. PVE_DISTRICTS に英語地方 ────────────────────────────
DIST_ANCHOR = "{ id:'sci',  name:'理科地方', emoji:'🔬', desc:'理科のエリアを選ぼう', disabled:false }];"
DIST_NEW = "{ id:'sci',  name:'理科地方', emoji:'🔬', desc:'理科のエリアを選ぼう', disabled:false },\n            { id:'eng',  name:'英語地方', emoji:'🔤', desc:'英語のエリアを選ぼう' }];"
patch('4a 英語地方', DIST_ANCHOR, DIST_NEW)

# ── 4b. DISTRICT_TO_CURRICULUM_KEY に eng ───────────────────
DKEY_ANCHOR = """    'sci':  'science'
  };"""
DKEY_NEW = """    'sci':  'science',
    'eng':  'english'
  };"""
patch('4b DISTRICT_KEY', DKEY_ANCHOR, DKEY_NEW)

# ── 4c. PVE_AREAS に中1英語エリア8件 ────────────────────────
AREA_ANCHOR = "{ id: 'm7-shiryo', subject:'math', grade:7, name: 'データの塔',     emoji: '📊', desc: '資料の活用の問題が出るよ（1〜4を入力）' }];"
AREA_NEW = """{ id: 'm7-shiryo', subject:'math', grade:7, name: 'データの塔',     emoji: '📊', desc: '資料の活用の問題が出るよ（1〜4を入力）' },

            // === 中1英語 ===
            { id: 'e7-be',       subject:'eng', grade:7, name: 'be動詞の草原',   emoji: '🅱️', desc: 'be動詞の問題が出るよ（1〜4を入力）' },
            { id: 'e7-verb',     subject:'eng', grade:7, name: '一般動詞の街道', emoji: '🏃', desc: '一般動詞の問題が出るよ（1〜4を入力）' },
            { id: 'e7-3tan',     subject:'eng', grade:7, name: '三単現の関所',   emoji: '✍️', desc: '三単現のsの問題が出るよ（1〜4を入力）' },
            { id: 'e7-pron',     subject:'eng', grade:7, name: '代名詞の鏡の間', emoji: '👥', desc: '代名詞・複数形の問題が出るよ（1〜4を入力）' },
            { id: 'e7-question', subject:'eng', grade:7, name: '疑問詞の迷宮',   emoji: '❓', desc: '疑問詞の問題が出るよ（1〜4を入力）' },
            { id: 'e7-can',      subject:'eng', grade:7, name: 'canと命令の砦',  emoji: '💪', desc: 'canと命令文の問題が出るよ（1〜4を入力）' },
            { id: 'e7-ing',      subject:'eng', grade:7, name: '進行形の急流',   emoji: '🏊', desc: '現在進行形の問題が出るよ（1〜4を入力）' },
            { id: 'e7-past',     subject:'eng', grade:7, name: '過去形の遺跡',   emoji: '⏰', desc: '過去形の問題が出るよ（1〜4を入力）' }];"""
patch('4c PVE_AREAS', AREA_ANCHOR, AREA_NEW)

# ── 4d. UNIT_DISPLAY に中1英語 ──────────────────────────────
UD_ANCHOR = "'m7-shiryo': { name: 'データの塔',       emoji: '📊', desc: '資料の活用（中1）' },"
UD_NEW = """'m7-shiryo': { name: 'データの塔',       emoji: '📊', desc: '資料の活用（中1）' },
    // 中1英語
    'e7-be':       { name: 'be動詞の草原',   emoji: '🅱️', desc: 'be動詞（中1英語）' },
    'e7-verb':     { name: '一般動詞の街道', emoji: '🏃', desc: '一般動詞（中1英語）' },
    'e7-3tan':     { name: '三単現の関所',   emoji: '✍️', desc: '三単現のs（中1英語）' },
    'e7-pron':     { name: '代名詞の鏡の間', emoji: '👥', desc: '代名詞・複数形（中1英語）' },
    'e7-question': { name: '疑問詞の迷宮',   emoji: '❓', desc: '疑問詞（中1英語）' },
    'e7-can':      { name: 'canと命令の砦',  emoji: '💪', desc: 'canと命令文（中1英語）' },
    'e7-ing':      { name: '進行形の急流',   emoji: '🏊', desc: '現在進行形（中1英語）' },
    'e7-past':     { name: '過去形の遺跡',   emoji: '⏰', desc: '過去形（中1英語）' },"""
patch('4d UNIT_DISPLAY', UD_ANCHOR, UD_NEW)

# ── 4e. getPveDepths に中1英語 ──────────────────────────────
DEP_ANCHOR = "'m7-shiryo': { labels: ['データ受付', '度数の階段', '中央値の間'], emojis: ['📊','🪜','👑'] },"
DEP_NEW = """'m7-shiryo': { labels: ['データ受付', '度数の階段', '中央値の間'], emojis: ['📊','🪜','👑'] },
                // 中1英語
                'e7-be':       { labels: ['amの入口', 'isの広場', 'areの大草原'], emojis: ['🌱','🅱️','🌾'] },
                'e7-verb':     { labels: ['playの小道', 'studyの坂', 'likeの広場'], emojis: ['🏃','📖','⚽'] },
                'e7-3tan':     { labels: ['sの門', 'esの門', '不規則の奥'], emojis: ['✍️','🚪','👑'] },
                'e7-pron':     { labels: ['I my me の間', '複数形の廊下', 'mineの宝物庫'], emojis: ['👥','🚪','💎'] },
                'e7-question': { labels: ['whatの入口', 'whereの分かれ道', 'howの最深部'], emojis: ['❓','🌀','🧩'] },
                'e7-can':      { labels: ['canの門', 'めいれいの回廊', '大魔王の玉座'], emojis: ['💪','🏯','👑'] },
                'e7-ing':      { labels: ['ingのふち', '進行中の瀬', 'どしゃぶりの滝'], emojis: ['🏊','🌊','⛰️'] },
                'e7-past':     { labels: ['きのうの間', 'last weekの回廊', '不規則動詞の墓場'], emojis: ['⏰','🏛️','🪦'] },"""
patch('4e getPveDepths', DEP_ANCHOR, DEP_NEW)

# ── 4f. WILD_AREA_POOLS に中1英語 ───────────────────────────
POOL_ANCHOR = "'m7-shiryo': { 1: [NW(19), NW(22), 1123], 2: [NW(20), NW(23), 1124],  3: [NW(21), NW(26), 1125] },\n};"
POOL_NEW = """'m7-shiryo': { 1: [NW(19), NW(22), 1123], 2: [NW(20), NW(23), 1124],  3: [NW(21), NW(26), 1125] },

    // === 中1英語 ===
    'e7-be':       { 1: [NW(0), NW(3), 1126],   2: [NW(1), NW(4), 1126],    3: [NW(2), NW(10), 1127] },
    'e7-verb':     { 1: [NW(5), NW(6), 1126],   2: [NW(7), NW(9), 1127],    3: [NW(10), NW(2), 1127] },
    'e7-3tan':     { 1: [NW(11), NW(14), 1126], 2: [NW(15), NW(33), 1127],  3: [NW(13), NW(36), 1128] },
    'e7-pron':     { 1: [NW(14), NW(16), 1126], 2: [NW(15), NW(33), 1127],  3: [NW(36), NW(13), 1128] },
    'e7-question': { 1: [NW(19), NW(22), 1126], 2: [NW(20), NW(23), 1127],  3: [NW(21), NW(26), 1128] },
    'e7-can':      { 1: [NW(27), NW(28), 1126], 2: [NW(29), NW(30), 1127],  3: [NW(30), NW(28), 1128] },
    'e7-ing':      { 1: [NW(5), NW(31), 1126],  2: [NW(7), NW(8), 1127],    3: [NW(9), NW(2), 1128] },
    'e7-past':     { 1: [NW(16), NW(33), 1126], 2: [NW(17), NW(34), 1127],  3: [NW(18), NW(35), 1128] },
};"""
patch('4f WILD_AREA_POOLS', POOL_ANCHOR, POOL_NEW)

# ── 5. 新野生モンスター3体（1126-1128） ─────────────────────
MON_ANCHOR = """    desc: '右肩上がりの人生をきわめた大王。調子に乗りすぎると、反比例のカーブでちゃんと落ちてくる。'
});"""
MON_NEW = """    desc: '右肩上がりの人生をきわめた大王。調子に乗りすぎると、反比例のカーブでちゃんと落ちてくる。'
});

// === 中1英語系（中1英語エリア：野生限定）===
MONSTERS.push({
    id: 1126,
    name: 'アルファベッ太',
    sprite: '🅰️',
    hp: 190, atk: 50, def: 40, spd: 55,
    buff: 'guard',
    elementType: 'fairy',
    stage: 1,
    gacha: false,
    evoLevel: 24,
    nextId: 1127,
    skills: [
        { name: 'エービーシー連打', type: 'normal', pow: 14, acc: 0.96, element: 'fairy', desc: 'AからZまで休まず唱える' },
        { name: 'スペルミスさそい', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'fairy', desc: '相手の防御を下げる' },
        { name: '大文字ガード', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'fairy', desc: '自分の防御を上げる' }
    ],
    desc: 'be動詞の草原に住む見習いモンスター。AからZまでは完ぺきに言えるが、Zの次を聞かれると泣く。'
});

MONSTERS.push({
    id: 1127,
    name: 'ビーどうしマン',
    sprite: '🅱️',
    hp: 330, atk: 88, def: 62, spd: 80,
    buff: 'attack',
    elementType: 'fairy',
    stage: 2,
    gacha: false,
    evoLevel: 46,
    nextId: 1128,
    skills: [
        { name: 'イズ・パンチ', type: 'normal', pow: 18, acc: 0.96, element: 'fairy', desc: 'is の一撃を打ちこむ' },
        { name: 'アムアーラッシュ', type: 'heavy', pow: 40, acc: 0.78, element: 'fairy', desc: 'am と are の連続攻撃' },
        { name: '主語チェンジ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'fairy', desc: '自分の防御を上げる' }
    ],
    desc: 'am・is・are を使い分ける正義のヒーロー。だが自己しょうかいは毎回「I is ビーどうしマン！」と言ってしまい、こっそり直されている。'
});

MONSTERS.push({
    id: 1128,
    name: 'ペラペーラ大魔王',
    sprite: '💬',
    hp: 540, atk: 122, def: 88, spd: 100,
    buff: 'lucky',
    elementType: 'fairy',
    stage: 3,
    gacha: false,
    evoLevel: null,
    nextId: null,
    skills: [
        { name: 'マシンガントーク', type: 'normal', pow: 22, acc: 0.95, effect: 'buff_atk_self', element: 'fairy', desc: 'しゃべるほど調子が上がる' },
        { name: 'ネイティブ発音', type: 'heavy', pow: 50, acc: 0.74, element: 'fairy', desc: '巻き舌の衝撃波でふっとばす' },
        { name: 'サイレントe', type: 'unique', pow: 0, acc: 1.0, effect: 'heal_self', element: 'fairy', desc: '発音しないeのように気配を消して回復' }
    ],
    desc: '英語がペラペラすぎる大魔王。あまりに流ちょうなため、家来はだれも命令を聞き取れず、城はいつも平和である。'
});"""
patch('5 モンスター3体', MON_ANCHOR, MON_NEW)

# ── 6. 友達対戦・RT対戦の教科リストに英語 ───────────────────
patch('6a friend order',
      "var _subjectOrder = ['math','japanese','social','science'];",
      "var _subjectOrder = ['math','japanese','social','science','english'];")
patch('6b friend labels',
      "var _subjectLabels = {math:'🔢算数', japanese:'📝国語', social:'🌏社会', science:'🔬理科'};",
      "var _subjectLabels = {math:'🔢算数', japanese:'📝国語', social:'🌏社会', science:'🔬理科', english:'🔤英語'};")
patch('6c rt order',
      "var _rtSubjectOrder = ['math','japanese','social','science'];",
      "var _rtSubjectOrder = ['math','japanese','social','science','english'];")
patch('6d rt labels',
      "var _rtSubjectLabels = {math:'🔢算数', japanese:'📝国語', social:'🌏社会', science:'🔬理科'};",
      "var _rtSubjectLabels = {math:'🔢算数', japanese:'📝国語', social:'🌏社会', science:'🔬理科', english:'🔤英語'};")

# ── 7. 中1英語 問題生成器パック ─────────────────────────────
GEN_PACK = r"""<script>
// ================================================================
// 中1英語 単元パック v170（ネットレ対応 第2弾）
// be動詞・一般動詞・三単現のs・代名詞と複数形・疑問詞・canと命令文・現在進行形・過去形
// 各単元とも基礎/標準/発展を混合ランダム出題（問題文の【】で難易度表示）
// 出題形式: 4択MCQ {q, ans:正解index, options, inputType:'mcq'}
// ================================================================
(function(){
  var R = function(a,b){ return Math.floor(Math.random()*(b-a+1))+a; };
  function _e7pick(arr){ return arr[R(0,arr.length-1)]; }
  function _e7shuffle(arr){ for(var i=arr.length-1;i>0;i--){ var j=R(0,i); var t=arr[i]; arr[i]=arr[j]; arr[j]=t; } return arr; }
  // 4択問題を組み立てる（重複除去・不足時は？で補完）
  function _e7q(diff,q,correct,wrongs){
    var c=String(correct), ws=[], i, w;
    for(i=0;i<wrongs.length&&ws.length<3;i++){ w=String(wrongs[i]); if(w!==c&&ws.indexOf(w)<0) ws.push(w); }
    var k=1;
    while(ws.length<3&&k<10){ w=c+Array(k+1).join('？'); if(ws.indexOf(w)<0) ws.push(w); k++; }
    var options=_e7shuffle([c,ws[0],ws[1],ws[2]]);
    return { q:'【'+diff+'】'+q, ans:options.indexOf(c), options:options, inputType:'mcq' };
  }

  // ---------------- be動詞 ----------------
  var _BE_S=[['I','am',['is','are']],['You','are',['am','is']],['He','is',['am','are']],
    ['She','is',['am','are']],['It','is',['am','are']],['We','are',['am','is']],
    ['They','are',['am','is']],['Ken','is',['am','are']],['My mother','is',['am','are']],
    ['Tom and Ken','are',['am','is']],['This','is',['am','are']],['That bird','is',['am','are']]];
  var _BE_C=['busy','happy','kind','from Osaka','hungry','sleepy'];
  function genBe7(){
    var r=R(1,10),t,s;
    if(r<=4){ // 基礎
      t=R(0,2);
      if(t===0){ s=_e7pick(_BE_S);
        return _e7q('基礎','（　）に入る語はどれ？\n'+s[0]+' （　） '+_e7pick(_BE_C)+'.', s[1], [s[2][0], s[2][1], 'be']); }
      if(t===1){ var sh=_e7pick([['is not',"isn't",["aren't","don't","not is"]],['are not',"aren't",["isn't","don't",'no are']],['I am',"I'm",['Im',"I's",'I am not']],['you are',"you're",['youre','your',"you'am"]],['that is',"that's",['thats',"that're","this's"]]]);
        return _e7q('基礎','「'+sh[0]+'」の短縮形はどれ？', sh[1], sh[2]); }
      var ex=_e7pick([['彼は先生です。','He is a teacher.',['He am a teacher.','He are a teacher.','His is a teacher.']],
        ['わたしはユミです。','I am Yumi.',['I is Yumi.','I are Yumi.','Me is Yumi.']],
        ['これはリンゴです。','This is an apple.',['This is a apple.','This am an apple.','These is an apple.']],
        ['わたしたちは友だちです。','We are friends.',['We is friends.','We am friends.','We are friend.']]]);
      return _e7q('基礎','「'+ex[0]+'」を英語にすると？', ex[1], ex[2]);
    }
    if(r<=8){ // 標準
      t=R(0,3);
      if(t===0){ var qa=_e7pick([['あなたは学生ですか。','Are you a student?',['You are a student?','Do you a student?','Is you a student?']],
        ['ケンはサッカーファンですか。','Is Ken a soccer fan?',['Ken is a soccer fan?','Does Ken a soccer fan?','Are Ken a soccer fan?']],
        ['あれはあなたの自転車ですか。','Is that your bike?',['That is your bike?','Does that your bike?','Are that your bike?']]]);
        return _e7q('標準','「'+qa[0]+'」を英語にすると？', qa[1], qa[2]); }
      if(t===1){ return _e7q('標準','Are you from Tokyo? に「はい」と答えるときは？','Yes, I am.',['Yes, you are.','Yes, I do.','Yes, am I.']); }
      if(t===2){ return _e7q('標準','Is this your pen? に「はい」と答えるときは？','Yes, it is.',['Yes, this is.','Yes, it does.','Yes, I am.']); }
      var pair=_e7pick([['Ken and I','are'],['You and Tom','are'],['My father','is'],['That tall boy','is'],['Those girls','are']]);
      var w2=(pair[1]==='are')?['is','am']:['are','am'];
      return _e7q('標準','（　）に入る語はどれ？\n'+pair[0]+' （　） '+_e7pick(_BE_C)+'.', pair[1], [w2[0], w2[1], 'be']);
    }
    // 発展
    t=R(0,3);
    if(t===0){ return _e7q('発展','「I am a tennis fan.」を否定文にすると？','I am not a tennis fan.',["I don't a tennis fan.",'I am a not tennis fan.','I not am a tennis fan.']); }
    if(t===1){ return _e7q('発展','「That is your bike.」を疑問文にすると？','Is that your bike?',['That is your bike?','Does that your bike?','Are that your bike?']); }
    if(t===2){ return _e7q('発展','Who is that girl? への答えとして正しいのは？','She is my sister.',['Yes, she is.','That girl is who.','I am my sister.']); }
    return _e7q('発展','Is Ken a baseball fan? に「いいえ」と答えるときは？',"No, he isn't.",['No, he is.',"No, I'm not.","No, Ken isn't he."]);
  }

  // ---------------- 一般動詞 ----------------
  var _VB=[['テニスをする','play tennis',['do tennis','make tennis','go tennis']],
    ['テレビを見る','watch TV',['see TV','look TV','watch on TV']],
    ['朝食を食べる','eat breakfast',['take breakfast','do breakfast','eat a breakfast']],
    ['英語を話す','speak English',['say English','talk English','speak in English']],
    ['音楽を聞く','listen to music',['listen music','hear to music','sound music']],
    ['本を読む','read a book',['look a book','read book a','see a book']]];
  var _VB2=[['〜が好きだ','like',['play','eat','watch']],['〜を勉強する','study',['play','like','go']],
    ['走る','run',['walk','swim','fly']],['泳ぐ','swim',['run','sing','ski']],
    ['〜を作る','make',['take','give','look']],['〜を使う','use',['make','have','see']]];
  function genVerb7(){
    var r=R(1,10),t;
    if(r<=4){ // 基礎
      t=R(0,2);
      if(t===0){ var v=_e7pick(_VB); return _e7q('基礎','「'+v[0]+'」を英語にすると？', v[1], v[2]); }
      if(t===1){ var v2=_e7pick(_VB2); return _e7q('基礎','「'+v2[0]+'」という意味の動詞はどれ？', v2[1], v2[2]); }
      var sv=_e7pick([['I','play','soccer','します'],['You','like','dogs','好き'],['I','study','English','勉強します'],['You','speak','Japanese','話します']]);
      return _e7q('基礎','（　）に入る語はどれ？\n'+sv[0]+' （　） '+sv[2]+'.（'+sv[3]+'）', sv[1], [sv[1]+'s', sv[1]+'ing', 'is']);
    }
    if(r<=8){ // 標準
      t=R(0,3);
      if(t===0){ return _e7q('標準','「わたしは数学が好きではありません。」\nI （　） like math.',"don't",['am not',"doesn't",'not']); }
      if(t===1){ return _e7q('標準','（　）に入る語はどれ？\n（　） you play the piano?','Do',['Are','Does','Is']); }
      if(t===2){ return _e7q('標準','Do you like dogs? に「はい」と答えるときは？','Yes, I do.',['Yes, I am.','Yes, I like.','Yes, do I.']); }
      return _e7q('標準','「あなたは英語を話しますか。」を英語にすると？','Do you speak English?',['Are you speak English?','You speak English?','Does you speak English?']);
    }
    // 発展
    t=R(0,2);
    if(t===0){ return _e7q('発展','「わたしはピアノを弾きません。」を英語にすると？',"I don't play the piano.",['I am not play the piano.',"I don't the piano play.",'I not play the piano.']); }
    if(t===1){ return _e7q('発展','「わたしは犬を2ひき飼っています。」\nI （　） two dogs.','have',['has','am','having']); }
    return _e7q('発展','「わたしは毎日英語を勉強します。」を英語にすると？','I study English every day.',['I English study every day.','I am study English every day.','I study every day English.']);
  }

  // ---------------- 三単現のs ----------------
  var _3T=[['play','plays',['playes','plaies']],['study','studies',['studys','studyes']],
    ['watch','watches',['watchs','watchies']],['go','goes',['gos','goies']],
    ['have','has',['haves','having']],['teach','teaches',['teachs','teachies']],
    ['wash','washes',['washs','washies']],['like','likes',['likies','likees']]];
  function gen3tan7(){
    var r=R(1,10),t;
    if(r<=4){ // 基礎
      t=R(0,1);
      if(t===0){ var f=_e7pick(_3T);
        return _e7q('基礎','三人称単数（he・she など）が主語のとき、「'+f[0]+'」はどの形になる？', f[1], [f[2][0], f[2][1], f[0]]); }
      var sv=_e7pick([['He','plays','tennis','play'],['She','likes','music','like'],['Ken','studies','English','study'],['My father','watches','TV','watch'],['It','goes','fast','go']]);
      return _e7q('基礎','（　）に入る語はどれ？\n'+sv[0]+' （　） '+sv[2]+' every day.', sv[1], [sv[3], sv[3]+'ing', 'is '+sv[3]]);
    }
    if(r<=8){ // 標準
      t=R(0,3);
      if(t===0){ return _e7q('標準','「彼女は数学が好きではありません。」\nShe （　） like math.',"doesn't",["don't","isn't",'not']); }
      if(t===1){ return _e7q('標準','（　）に入る語はどれ？\n（　） he play soccer?','Does',['Do','Is','Are']); }
      if(t===2){ return _e7q('標準','Does she play the piano? に「はい」と答えるときは？','Yes, she does.',['Yes, she plays.','Yes, she do.','Yes, she is.']); }
      return _e7q('標準','「ケンは毎週日曜日にテニスをします。」を英語にすると？','Ken plays tennis on Sundays.',['Ken play tennis on Sundays.','Ken is plays tennis on Sundays.','Ken playing tennis on Sundays.']);
    }
    // 発展
    t=R(0,3);
    if(t===0){ return _e7q('発展','（　）に入る語はどれ？（疑問文では動詞は原形！）\nDoes he （　） soccer?','play',['plays','playing','played']); }
    if(t===1){ return _e7q('発展','（　）に入る語はどれ？（主語は複数！）\nKen and Yumi （　） English every day.','study',['studies','studys','is study']); }
    if(t===2){ return _e7q('発展','（　）に入る語はどれ？\nMy brother （　） two dogs.','has',['have','haves','is have']); }
    return _e7q('発展','（　）に入る語はどれ？（否定文では動詞は原形！）\nShe doesn’t （　） TV.','watch',['watches','watching','watched']);
  }

  // ---------------- 代名詞・複数形 ----------------
  var _PL=[['book','books',['bookes','bookies']],['box','boxes',['boxs','boxies']],
    ['city','cities',['citys','cityes']],['bus','buses',['buss','busies']],
    ['watch','watches',['watchs','watchies']],['child','children',['childs','childrens']],
    ['man','men',['mans','manes']],['woman','women',['womans','womanes']],
    ['country','countries',['countrys','countryes']]];
  var _PR=[['Tom','he',['she','him','his']],['Yumi','she',['he','her','hers']],
    ['Tom and Ken','they',['them','he','we']],['this book','it',['this','they','its']],
    ['you and I','we',['us','they','you']]];
  function genPron7(){
    var r=R(1,10),t;
    if(r<=4){ // 基礎
      t=R(0,1);
      if(t===0){ var p=_e7pick(_PL);
        return _e7q('基礎','「'+p[0]+'」の複数形はどれ？', p[1], [p[2][0], p[2][1], p[0]]); }
      var pr=_e7pick(_PR);
      return _e7q('基礎','「'+pr[0]+'」を1語の代名詞（主語の形）で言いかえると？', pr[1], pr[2]);
    }
    if(r<=8){ // 標準
      t=R(0,3);
      if(t===0){ return _e7q('標準','「これはわたしの本です。」\nThis is （　） book.','my',['I','me','mine']); }
      if(t===1){ return _e7q('標準','「彼を手伝いなさい。」\nHelp （　）.','him',['he','his','her']); }
      if(t===2){ return _e7q('標準','「彼らはわたしのクラスメートです。」\n（　） are my classmates.','They',['Them','Their','He']); }
      return _e7q('標準','「これらはわたしの本です。」を英語にすると？','These are my books.',['This are my books.','These is my books.','These are my book.']);
    }
    // 発展
    t=R(0,2);
    if(t===0){ return _e7q('発展','「このかばんはわたしのものです。」\nThis bag is （　）.','mine',['my','me','I']); }
    if(t===1){ return _e7q('発展','Whose notebook is this?\n「彼女のものです」と答えるとき、It’s （　）. の（　）は？','hers',['her','she','shes']); }
    return _e7q('発展','「わたしには子どもが3人います。」\nI have three （　）.','children',['childs','childrens','child']);
  }

  // ---------------- 疑問詞 ----------------
  var _QW=[['なに','what'],['だれ','who'],['どこ','where'],['いつ','when'],['だれの','whose'],['どちら・どれ','which']];
  function genQword7(){
    var r=R(1,10);
    if(r<=4){ // 基礎
      var qw=_e7pick(_QW);
      var others=_QW.filter(function(x){return x[1]!==qw[1];});
      _e7shuffle(others);
      return _e7q('基礎','「'+qw[0]+'」とたずねるときに使う疑問詞はどれ？', qw[1], [others[0][1], others[1][1], others[2][1]]);
    }
    if(r<=8){ // 標準
      var qa=_e7pick([["（　） is your birthday? — It's May 5th.",'When',['Where','What','Who']],
        ['（　） is that boy? — He is my brother.','Who',['What','Which','Whose']],
        ['（　） do you live? — I live in Nagoya.','Where',['When','Who','What']],
        ['（　） many CDs do you have? — I have ten.','How',['What','Which','Many']],
        ["（　） bag is this? — It's Ken's.",'Whose',['Who','Which','What']],
        ['（　） time do you get up? — At six.','What',['When','How','Which']]]);
      return _e7q('標準','（　）に入る疑問詞はどれ？\n'+qa[0], qa[1], qa[2]);
    }
    // 発展
    var ans=_e7pick([['Where does Ken live?','He lives in Osaka.',['Yes, he does.','He is Osaka.','He live in Osaka.']],
      ['How many brothers do you have?','I have two.',['Yes, I do.','I am two.','Two brothers is I.']],
      ['Whose bike is that?',"It's my brother's.",['He is my brother.','Yes, it is.',"It's my brother."]],
      ['What time is it now?',"It's ten thirty.",["I'm ten.","It's May 5th.",'Yes, it is.']]]);
    return _e7q('発展',ans[0]+' への答えとして正しいのは？', ans[1], ans[2]);
  }

  // ---------------- canと命令文 ----------------
  function genCan7(){
    var r=R(1,10),t;
    if(r<=4){ // 基礎
      t=R(0,1);
      if(t===0){ var cv=_e7pick([['泳ぐ','swim'],['速く走る','run fast'],['じょうずに歌う','sing well'],['ギターを弾く','play the guitar'],['料理する','cook']]);
        var head=cv[1].split(' ')[0];
        return _e7q('基礎','「わたしは'+cv[0]+'ことができます。」\nI can （　）.', cv[1], [head+'s'+cv[1].slice(head.length), head+'ing'+cv[1].slice(head.length), 'to '+cv[1]]); }
      return _e7q('基礎','「彼は速く走ることができます。」を英語にすると？','He can run fast.',['He cans run fast.','He can runs fast.','He is can run fast.']);
    }
    if(r<=8){ // 標準
      t=R(0,3);
      if(t===0){ return _e7q('標準','「わたしはスキーができません。」\nI （　） ski.',"can't",["don't",'am not','can']); }
      if(t===1){ return _e7q('標準','「あなたはギターを弾けますか。」\n（　） you play the guitar?','Can',['Do','Are','Is']); }
      if(t===2){ return _e7q('標準','Can Ken cook? に「はい」と答えるときは？','Yes, he can.',['Yes, he cooks.','Yes, he does.','Yes, he is.']); }
      return _e7q('標準','Can you help me? はどんな意味？','手伝ってくれませんか（お願い）',['手伝ってはいけません（禁止）','手伝いましょう（さそい）','手伝うことができました（過去）']);
    }
    // 発展（命令文）
    t=R(0,2);
    if(t===0){ var im=_e7pick([['窓を開けなさい。','Open the window.',['Opens the window.','Opening the window.','To open the window.']],
      ['ここで英語を話しなさい。','Speak English here.',['Speaks English here.','You speaking English here.','To speak English here.']],
      ['手を洗いなさい。','Wash your hands.',['Washes your hands.','Washing your hands.','You washes your hands.']]]);
      return _e7q('発展','「'+im[0]+'」を英語にすると？', im[1], im[2]); }
    if(t===1){ return _e7q('発展','「ここで走ってはいけません。」\n（　） run here.',"Don't",["Doesn't",'Not',"Isn't"]); }
    return _e7q('発展','「サッカーをしましょう。」\n（　） play soccer.',"Let's",['Let','We','Do']);
  }

  // ---------------- 現在進行形 ----------------
  var _ING=[['play','playing',['plaing','playeing']],['make','making',['makeing','maiking']],
    ['run','running',['runing','runnning']],['swim','swimming',['swiming','swimning']],
    ['write','writing',['writeing','writting']],['study','studying',['studing','studiing']],
    ['use','using',['useing','ussing']],['sit','sitting',['siting','sittting']]];
  function genIng7(){
    var r=R(1,10),t;
    if(r<=4){ // 基礎
      t=R(0,1);
      if(t===0){ var g=_e7pick(_ING);
        return _e7q('基礎','「'+g[0]+'」の ing形はどれ？', g[1], [g[2][0], g[2][1], g[0]+'s']); }
      return _e7q('基礎','「わたしは今、テレビを見ています。」\nI （　） TV now.','am watching',['watch','watching','am watch']);
    }
    if(r<=8){ // 標準
      t=R(0,3);
      if(t===0){ return _e7q('標準','（　）に入る語はどれ？\nHe is （　） in the park now.','running',['run','runing','runs']); }
      if(t===1){ return _e7q('標準','「彼女は今、歌っていません。」\nShe （　） not singing now.','is',['does','do','am']); }
      if(t===2){ return _e7q('標準','「あなたは今、勉強していますか。」\n（　） you studying now?','Are',['Do','Is','Am']); }
      return _e7q('標準','「彼女は今、本を読んでいます。」を英語にすると？','She is reading a book now.',['She reads a book now.','She is read a book now.','She reading a book now.']);
    }
    // 発展
    t=R(0,1);
    if(t===0){ return _e7q('発展','（　）に入る語はどれ？\nKen （　） soccer now.','is playing',['plays','playing','is play']); }
    return _e7q('発展','What are you doing? への答えとして正しいのは？',"I'm doing my homework.",['Yes, I am.','I do my homework every day.',"I'm do my homework."]);
  }

  // ---------------- 過去形 ----------------
  var _PS=[['play','played',['plaied','playd']],['study','studied',['studyed','studdied']],
    ['watch','watched',['watchd','watchied']],['stop','stopped',['stoped','stopt']],
    ['go','went',['goed','wented']],['come','came',['comed','commed']],
    ['have','had',['haved','haded']],['see','saw',['seed','sees']],
    ['eat','ate',['eated','eatted']],['make','made',['maked','maded']],
    ['get','got',['getted','goted']],['buy','bought',['buyed','boughted']],
    ['run','ran',['runned','ranned']],['write','wrote',['writed','wroted']]];
  function genPast7(){
    var r=R(1,10),t;
    if(r<=4){ // 基礎
      var p=_e7pick(_PS);
      return _e7q('基礎','「'+p[0]+'」の過去形はどれ？', p[1], [p[2][0], p[2][1], p[0]+'ing']);
    }
    if(r<=8){ // 標準
      t=R(0,3);
      if(t===0){ return _e7q('標準','「わたしは昨夜、テレビを見ました。」\nI （　） TV last night.','watched',['watch','watches','watching']); }
      if(t===1){ return _e7q('標準','「彼は昨日、学校へ行きました。」\nHe （　） to school yesterday.','went',['goes','go','gone']); }
      if(t===2){ return _e7q('標準','「わたしは昨日、テニスをしませんでした。」\nI （　） play tennis yesterday.',"didn't",["don't","doesn't","wasn't"]); }
      return _e7q('標準','Did you see the movie? に「はい」と答えるときは？','Yes, I did.',['Yes, I saw.','Yes, I do.','Yes, I was.']);
    }
    // 発展
    t=R(0,2);
    if(t===0){ return _e7q('発展','（　）に入る語はどれ？（疑問文では動詞は原形！）\nDid you （　） the movie yesterday?','see',['saw','sees','seeing']); }
    if(t===1){ return _e7q('発展','（　）に入る語はどれ？（否定文では動詞は原形！）\nShe didn’t （　） breakfast this morning.','eat',['ate','eats','eating']); }
    return _e7q('発展','「わたしは先週、京都へ行きました。」を英語にすると？','I went to Kyoto last week.',['I go to Kyoto last week.','I goed to Kyoto last week.','I was go to Kyoto last week.']);
  }

  // window に公開（_genTrainQ_curriculum / _genPvE_curriculum が window[gen名] で参照）
  try{
    window.genBe7=genBe7;
    window.genVerb7=genVerb7;
    window.gen3tan7=gen3tan7;
    window.genPron7=genPron7;
    window.genQword7=genQword7;
    window.genCan7=genCan7;
    window.genIng7=genIng7;
    window.genPast7=genPast7;
  }catch(e){}
})();

</script>

"""
PACK_ANCHOR = "<!-- おしらせモーダル -->"
patch('7 生成器パック', PACK_ANCHOR, GEN_PACK + PACK_ANCHOR)

# ── 保存 ────────────────────────────────────────────────────
if failed:
    print('FAILED anchors: ' + '; '.join(failed), file=sys.stderr)
    sys.exit(1)

with open(target, 'wb') as f:
    f.write(content.encode('utf-8'))
print(f"Applied {applied} changes. Size {orig_len} -> {len(content)}", file=sys.stderr)
