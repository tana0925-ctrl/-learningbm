# -*- coding: utf-8 -*-
# IMPEVAL_H_V1 (2026-10-08)  成果物プロンプトに「評定(A/B/C)＋根拠の言葉」を書かせる
#
# 先生の依頼：「成果物のとりこみ。評価なければ空欄じゃなく、教育課程や
#              学習指導要領にてらしあわせて評価して」→「評定＆ことば」
#
# いまのプロンプトは「先生の評価があれば写す／なければ空欄」と書いてあり、
# AI が評価することを明確に禁じていた。そこを変える。
#
# やること
#   H1 本校教育課程の評価規準の表 _EK を、copyTestPrompt の中から
#      関数 _ekTable() に出して、成果物プロンプト側からも使えるようにする。
#      表の中身は1文字も変えない。copyTestPrompt は var _EK=_ekTable() に変わるだけ。
#   H2 copyRecordPrompt を作り直す。
#      ・評価コメント欄に 3観点の評定(A/B/C)と、その根拠の言葉を書かせる
#      ・A/B/C の基準と「B が標準」を明記（書かないと A ばかりになる）
#      ・読み取れない観点は評定をつけず「この成果物からは分かりません」
#      ・成果物から読み取れる範囲だけ。見ていないことは書かせない
#      ・人格を否定する言い方を禁じる。児童が読んでも傷つかない言葉で
#      ・「そのまま通信簿になるものではない／最終判断は先生」を冒頭に明記
#      ・クラスの在籍学年を自動判定し、その学年の本校教育課程の評価規準を渡す
#      ・点数: を 評価コメント: の前に移す（評価コメントは複数行になるので
#        ブロックの最後に置かないと、後ろの見出しを飲み込む）
#
# 前提：IMPEVAL_G_V1（受け皿の修正）が当たっていること。
#   当たっていないと、この書式は通信簿側へ振り分けられ根拠の言葉が消える。
#   本番のパーサで実測ずみ。だから当たっていなければ止まる。
#
# さわるのは src/index.tsx の教師画面だけ。児童の配信チェーンは増減させない。
# public/teacher-ai.js はさわらないので ?v= の繰り上げは不要。
# アンカーが想定数でなければ1文字も書かずに止まる（fail-closed）。
import os
import sys

TSX = 'src/index.tsx'


def die(msg):
    print('::error::' + msg)
    sys.exit(1)


def chain_count(s):
    a = s.index("app.get('/', async (c) => {")
    b = s.index("app.get('/logout'", a)
    return s[a:b].count('.replace(')


raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if not raw.isdigit():
    die('CHAIN_BEFORE が数字で渡されていません: %r' % raw)
CHAIN_BEFORE = int(raw)

tsx = open(TSX, encoding='utf-8').read()
chain0 = chain_count(tsx)
if chain0 != CHAIN_BEFORE:
    die('チェーン件数が合いません 実測=%d 申告=%d' % (chain0, CHAIN_BEFORE))
if tsx.count('IMPEVAL_G_V1') < 4:
    die('IMPEVAL_G_V1（受け皿の便）が当たっていません。先に便 g を流してください')
if tsx.count('IMPEVAL_H_V1') != 0:
    die('IMPEVAL_H_V1 はすでに当たっています')

# ---- H1 _EK を _ekTable() に出す ----
if tsx.count('var _EK={') != 1:
    die('var _EK={ が %d 件（1件のはず）' % tsx.count('var _EK={'))
i = tsx.index('var _EK={')
k = tsx.index('{', i)
d = 0
end = -1
for p in range(k, len(tsx)):
    if tsx[p] == '{':
        d += 1
    elif tsx[p] == '}':
        d -= 1
        if d == 0:
            end = p
            break
if end < 0:
    die('_EK の終端が見つかりません')
if tsx[end + 1] != ';':
    die('_EK の終端のあとが ; ではありません: %r' % tsx[end + 1:end + 8])
LIT = tsx[k:end + 1]
if len(LIT) < 3000 or len(LIT) > 8000:
    die('_EK リテラルの大きさが想定外: %d 文字' % len(LIT))
if "'6'" not in LIT or "'国語'" not in LIT:
    die('_EK リテラルの中身が想定と違います')
tsx = tsx[:i] + 'var _EK=_ekTable();' + tsx[end + 2:]

ANCHOR_T = '      function copyTestPrompt(){'
if tsx.count(ANCHOR_T) != 1:
    die('copyTestPrompt のアンカーが %d 件（1件のはず）' % tsx.count(ANCHOR_T))
HOIST = ('      /* IMPEVAL_H_V1 本校教育課程の評価規準。テスト用プロンプトの中にあったものを\n'
         '         関数に出しただけで、中身は1文字も変えていない。成果物プロンプトからも使う。 */\n'
         '      function _ekTable(){ return ' + LIT + '; }\n')
tsx = tsx.replace(ANCHOR_T, HOIST + ANCHOR_T, 1)

# ---- H2 copyRecordPrompt を作り直す ----
HEAD = '      /* IMPNAME_A_V1 名簿を渡していなかったので'
TAILM = '      // \U0001F4CC __IMPORT_AUTO_V1__ 入口は1つ。'
if tsx.count(HEAD) != 1:
    die('copyRecordPrompt のアンカーが %d 件（1件のはず）' % tsx.count(HEAD))
a = tsx.index(HEAD)
b = tsx.index(TAILM, a)
OLD = tsx[a:b]
if 'function copyTestPrompt(){' in OLD or len(OLD) > 5000:
    die('切り出し範囲がおかしい（%d 文字）' % len(OLD))

NEW = """      /* IMPEVAL_H_V1 評価の欄を「先生が書いたものを写すだけ」から
         「AI が3観点で評定(A/B/C)と根拠を書く」に変える。
         名簿と学年別の評価規準はクラスから自動で入れる。
         この書式が通信簿側へ流れないことは IMPEVAL_G_V1 の受け皿で担保している。 */
      function copyRecordPrompt(){
        var NL=String.fromCharCode(10);
        var label='成果物・振り返り';
        var st=document.getElementById('recPromptStatus');
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';
        if(!cid){ if(st) st.textContent='先に「クラス」を選んでください'; return; }
        if(st) st.textContent='名簿を読み込み中...';
        var _build=function(names, grade){
          var L=[];
          L.push('あなたは小学校の先生のアシスタントです。アップロードした（または貼り付けた）児童の'+label+'のPDF・画像から、児童ごとに内容を読み取り、さらに下の基準で評価をつけて、次の「出力形式」だけを、コードブロックに入れずそのまま出力してください。前置きや説明は書かないでください。');
          L.push('この評価は、先生が確認して使うための材料です。そのまま通信簿になるものではありません。最終的な判断は先生がします。ですから、無難にぼかさず、成果物から読み取れたことをはっきり書いてください。');
          L.push('');
          L.push('【出力形式】児童ごとに次のブロックをくり返す。');
          L.push('=== [児童ID] 名前 ===');
          L.push('タイトル: （'+label+'のタイトル。なければ内容を短く要約）');
          L.push('日付: （YYYY-MM-DD。わからなければ空欄）');
          L.push('教科: （国語・算数・理科・社会 など。なければ空欄）');
          L.push('単元: （わかれば。なければ空欄）');
          L.push('本文:');
          L.push('（児童が書いた文章・成果物をそのまま。複数行でよい）');
          L.push('振り返り: （児童の振り返りがあれば。なければ空欄。複数行でよい）');
          L.push('評価: （先生が紙に書いた ◎ / ○ / △ があれば、それを写す。無ければ空欄のまま。あなたが新しく付けないこと）');
          L.push('点数: （テストの点数があれば数字だけ。成果物なら空欄のまま）');
          L.push('評価コメント:');
          L.push('知識・技能：A / B / C のどれか');
          L.push('　「そう判断した根拠を、成果物に書かれていることで示す」');
          L.push('思考・判断・表現：A / B / C のどれか');
          L.push('　「そう判断した根拠を、成果物に書かれていることで示す」');
          L.push('主体的に学習に取り組む態度：A / B / C のどれか');
          L.push('　「そう判断した根拠を、成果物に書かれていることで示す」');
          L.push('');
          if(names.length){ L.push('【このクラスの名簿（児童名は必ずこの中の表記に合わせる）】'); L.push(names.join('、')); L.push(''); }
          L.push('【名前の読み取り】手書きの名前が崩れて読みにくいときも、安易に飛ばさないでください。上の名簿の中から最も近い児童名を選んで（予測して）記入します。確信が低い予測は、名前のうしろに「※名前推定」と付けてください。どうしても判断できないときだけ飛ばします。');
          L.push('');
          L.push('【評価の3観点】小学校学習指導要領の観点別学習状況の評価と同じ3つです。');
          L.push('・知識・技能 … 用語・事実・計算・手順・技能が身についているか');
          L.push('・思考・判断・表現 … 考え方、理由の説明、資料の読み取り、図や式や文章での表現ができているか');
          L.push('・主体的に学習に取り組む態度 … 粘り強さ、工夫、見直し、自分で調整した跡が、この成果物に現れているか');
          L.push('');
          L.push('【評定の基準】');
          L.push('A … その単元の目標を十分に達成している');
          L.push('B … その単元の目標をおおむね達成している');
          L.push('C … 達成に向けて支援が必要');
          L.push('※ B が標準です。ふつうにできていれば B です。A は「ここまでできているのか」と先生が驚くときだけにしてください。A ばかりにしないこと。');
          L.push('');
          L.push('【評価コメントの約束】');
          L.push('(1) 3つの観点を必ず3行とも出す。空欄にしない。');
          L.push('(2) この成果物から読み取れる範囲だけで書く。書かれていないこと、見ていない授業中の様子は、推測で書かない。');
          L.push('(3) その観点がこの成果物から読み取れないときは、評定をつけず「この成果物からは分かりません」と書く。計算プリント1枚から「主体的に学習に取り組む態度」は読み取れないことが多いはずです。無理に B をつけないでください。');
          L.push('(4) 評定だけで終わらせない。必ず次の行に、かぎかっこ「」で根拠を書く。根拠は、成果物のどこを見てそう判断したかが分かるように、具体的に書く。');
          L.push('(5) できていないことは、事実として書いてよい。ただし「学習の事実」と「次にできること」で書き、性格や人柄を否定しない。「雑」「やる気がない」「いいかげん」のような人を決めつける言葉は使わない。');
          L.push('(6) この文は先生が読むためのものですが、あとで児童向けの文章の材料にもなります。児童が読んでも傷つかない言葉で書く。');
          L.push('(7) 教科と単元が分かるときは、その単元の目標に照らして判断する。');
          L.push('');
          var _EKg=null; try{ _EKg=_ekTable()[String(grade)]||null; }catch(_ek0){ _EKg=null; }
          if(grade&&_EKg){
            L.push('【'+grade+'年の評価規準（本校教育課程より）／この成果物の教科に合うものに照らして判断する】');
            var _so=['国語','算数','理科','社会'];
            for(var si=0;si<_so.length;si++){ var sn=_so[si]; var ee=_EKg[sn]; if(!ee) continue; L.push('■'+sn+'／知識・技能：'+ee.kt+'／思考・判断・表現：'+ee.sh+'／主体的に学習に取り組む態度：'+ee.st); }
            L.push('※土台は学習指導要領の観点別評価です。具体的な判断は上の本校教育課程の評価規準を優先してください。教科がこの4つ以外のときは、学習指導要領の'+grade+'年の目標に照らして同じ3観点で書いてください。');
            L.push('');
          } else {
            L.push('【評価規準】この成果物の教科と単元を見て、小学校学習指導要領のその学年・その教科の目標に照らして、上の3観点で判断してください。');
            L.push('');
          }
          L.push('【ルール】児童IDは名簿のログインID。わからなければ [名前] のように名前を入れる。名前は必ず上の名簿の表記で書く。1人ずつ「=== [..] .. ===」で区切る。本文・振り返りはそれぞれの見出しの次の行から次の見出しか次の===まで。成果物と振り返りがセットなら両方入れる。本文と振り返りは児童の記述をそのまま写し、要約や講評を勝手に足さない（講評は評価コメントの欄にだけ書く）。評価コメントはブロックの最後に置き、そのあとに別の見出しを書かない。読み取れない児童は飛ばしてよい。');
          var txt=L.join(NL);
          var done=function(){ if(st) st.textContent='✓ コピーしました（名簿'+names.length+'人つき'+(grade?('・'+grade+'年の評価規準つき'):'')+'）。AIに貼り付けてください'; };
          if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done,function(){ _faFallbackCopy(txt); done(); }); } else { _faFallbackCopy(txt); done(); }
        };
        (async function(){
          var names=[]; var grade='';
          try{ if(!window._serverFuriganaMap){ await loadServerNameMap(); } }catch(_e0){}
          try{
            var _r=await fetch('/api/teacher/class/'+encodeURIComponent(cid)+'/members');
            var _d=await _r.json();
            var _ms=(_d&&_d.members)||[];
            for(var i=0;i<_ms.length;i++){ var m=_ms[i]; var dn=(typeof resolveStudentName==='function')?resolveStudentName(m.loginId,m.name):(m.name||m.loginId||''); if(dn) names.push(dn); }
            var gc={}, best='', bn=0;
            for(var j=0;j<_ms.length;j++){ var gg=_ms[j].grade; if(gg){ gc[gg]=(gc[gg]||0)+1; if(gc[gg]>bn){ bn=gc[gg]; best=String(gg); } } }
            grade=best;
          }catch(_e1){}
          _build(names, grade);
        })();
      }
"""
tsx = tsx.replace(OLD, NEW, 1)

bad = False
chain1 = chain_count(tsx)
print('チェーン件数 前=%d 後=%d' % (chain0, chain1))
if chain0 != chain1:
    print('::error::チェーン件数が変わった')
    bad = True

need = {
    'IMPEVAL_H_V1': 2,
    'function _ekTable(){ return ': 1,
    'var _EK=_ekTable();': 1,
    'var _EK={': 0,
    'function copyRecordPrompt(){': 1,
    '【評定の基準】': 1,
    '※ B が標準です。': 1,
    'この成果物からは分かりません': 1,
    'そのまま通信簿になるものではありません': 1,
    '年の評価規準（本校教育課程より）': 1,
    'の主要教科の評価規準（本校教育課程より）': 1,
    '【このクラスの名簿（児童名は必ずこの中の表記に合わせる）】': 2,
    'IMPEVAL_G_V1': 5,
}
for k2, want in need.items():
    got = tsx.count(k2)
    print('適用後 %-46s %d 件（期待 %d）' % (k2, got, want))
    if got != want:
        bad = True

print('エスケープ事故の見張り（増えていないこと） = %d' % tsx.count("(\\'"))
for k2 in ['IMPNAME_A_V1', 'IMPNAME_B_V1', 'IMPNAME_D_V1', 'IMPNAME_E_V1', 'IMPNAME_E2_V1',
           '__IMPORT_AUTO_V1__', '__IMPORT_CHECK_V1__', 'QUICKNOTE_V1', '_qnMask', 'KARTE_TEST_V1',
           'karte_material_uses', 'WARMIX', '__WORLD_V3__', '_hash', 'cannot_trade_special']:
    if tsx.count(k2) < 1:
        print('::error::安全マーカー %r が消えました' % k2)
        bad = True
if bad:
    sys.exit(1)

open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK: src/index.tsx %d 文字' % len(tsx))
