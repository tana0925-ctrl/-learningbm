# -*- coding: utf-8 -*-
# IMPNAME_A_V1 (2026-10-06)  成果物プロンプトに名簿を入れる
#
# 調べて分かったこと（実測）
#   ・このアプリは OCR をしていない。手書きを読むのは外部AI（ChatGPT等）で、
#     アプリの仕事は返ってきたテキストの名前を22人に当てることだけ。
#   ・テスト用 copyTestPrompt には【このクラスの名簿】と【名前の読み取り】が
#     入っているのに、成果物用 copyRecordPrompt には両方とも無い。
#     名簿を見ていない外部AIは、22人の表記に寄せる機会がない。
#   ・さらに /api/teacher/class/:id/members の name は実名ではない
#     （"444" "CR7" "我を殿と呼べ" 等のニックネーム／ログインID）。
#     実名は admin_settings.real_name_map 側にしかないので、
#     テスト側も名簿としてニックネームを渡していた。ここも同時に直す。
#
# やること
#   S1 copyRecordPrompt を作り直す。名簿（実名）と【名前の読み取り】を足す。
#      プロンプト本文はテスト側で実績のある文章をそのまま流用する。
#   S2 copyTestPrompt の名簿の作り方を resolveStudentName 経由にする。
#
# さわるのは src/index.tsx の教師画面だけ。児童の配信チェーンは増減させない。
# public/index.html には一切さわらない。
# アンカーが1件でなければ1文字も書かずに止まる（fail-closed）。
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

if tsx.count('IMPNAME_A_V1') != 0:
    die('IMPNAME_A_V1 はすでに当たっています')


def cut(s, head, tail_marker):
    i = s.index(head)
    j = s.index(tail_marker, i)
    return s[i:j]


# ---- S1 copyRecordPrompt をまるごと差し替える ----
HEAD = '      function copyRecordPrompt(){'
TAILM = '      // \U0001F4CC __IMPORT_AUTO_V1__ 入口は1つ。'
if tsx.count(HEAD) != 1:
    die('copyRecordPrompt のアンカーが %d 件（1件のはず）' % tsx.count(HEAD))
OLD_A = cut(tsx, HEAD, TAILM)
if 'copyTestPrompt' in OLD_A:
    die('切り出し範囲がおかしい（copyTestPrompt を巻き込んだ）')
if len(OLD_A) > 4000:
    die('切り出し範囲が大きすぎる: %d 文字' % len(OLD_A))

NEW_A = """      /* IMPNAME_A_V1 名簿を渡していなかったので、外部AIは手書きを読んだままの字を返し、
         22人の表記に寄せる機会がなかった。テスト側(copyTestPrompt)と同じ作法に合わせる。
         名前は users.name（ニックネーム）ではなく実名マップ側を使う。 */
      function copyRecordPrompt(){
        var NL=String.fromCharCode(10);
        var label='成果物・振り返り';
        var st=document.getElementById('recPromptStatus');
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';
        if(!cid){ if(st) st.textContent='先に「クラス」を選んでください'; return; }
        if(st) st.textContent='名簿を読み込み中...';
        var _build=function(names){
          var L=[];
          L.push('あなたは小学校の先生のアシスタントです。アップロードした（または貼り付けた）児童の'+label+'のPDF・画像から、児童ごとに内容を読み取り、次の「出力形式」だけを、コードブロックに入れずそのまま出力してください。前置きや説明は書かないでください。');
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
          L.push('評価: （先生の評価があれば ◎ / ○ / △ のどれか。なければ空欄）');
          L.push('評価コメント: （先生の評価コメントがあれば。なければ空欄）');
          L.push('点数: （テストの点数があれば数字だけ。成果物なら空欄のまま）');
          L.push('');
          if(names.length){ L.push('【このクラスの名簿（児童名は必ずこの中の表記に合わせる）】'); L.push(names.join('、')); L.push(''); }
          L.push('【名前の読み取り】手書きの名前が崩れて読みにくいときも、安易に飛ばさないでください。上の名簿の中から最も近い児童名を選んで（予測して）記入します。確信が低い予測は、名前のうしろに「※名前推定」と付けてください。どうしても判断できないときだけ飛ばします。');
          L.push('');
          L.push('【ルール】児童IDは名簿のログインID。わからなければ [名前] のように名前を入れる。名前は必ず上の名簿の表記で書く。1人ずつ「=== [..] .. ===」で区切る。本文・振り返りはそれぞれの見出しの次の行から次の見出しか次の===まで。成果物と振り返りがセットなら両方入れる。評価・振り返りが無ければ空欄でよい。要約や講評を勝手に足さず、児童の記述を尊重する。読み取れない児童は飛ばしてよい。');
          var txt=L.join(NL);
          var done=function(){ if(st) st.textContent='✓ コピーしました（名簿'+names.length+'人つき）。AIに貼り付けてください'; };
          if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(done,function(){ _faFallbackCopy(txt); done(); }); } else { _faFallbackCopy(txt); done(); }
        };
        (async function(){
          var names=[];
          try{ if(!window._serverFuriganaMap){ await loadServerNameMap(); } }catch(_e0){}
          try{
            var _r=await fetch('/api/teacher/class/'+encodeURIComponent(cid)+'/members');
            var _d=await _r.json();
            var _ms=(_d&&_d.members)||[];
            for(var i=0;i<_ms.length;i++){ var m=_ms[i]; var dn=(typeof resolveStudentName==='function')?resolveStudentName(m.loginId,m.name):(m.name||m.loginId||''); if(dn) names.push(dn); }
          }catch(_e1){}
          _build(names);
        })();
      }
"""
tsx = tsx.replace(OLD_A, NEW_A, 1)

# ---- S2 copyTestPrompt の名簿を実名にする ----
OLD_B = "            for(var i=0;i<d.members.length;i++){ var m=d.members[i]; if(m.name) names.push(m.name); }"
if tsx.count(OLD_B) != 1:
    die('copyTestPrompt の名簿行が %d 件（1件のはず）' % tsx.count(OLD_B))
NEW_B = "            /* IMPNAME_A_V1 members の name はニックネーム。実名マップ側を使う。 */\n            for(var i=0;i<d.members.length;i++){ var m=d.members[i]; var dn=(typeof resolveStudentName==='function')?resolveStudentName(m.loginId,m.name):(m.name||''); if(dn) names.push(dn); }"
tsx = tsx.replace(OLD_B, NEW_B, 1)

OLD_C = "        if(st) st.textContent='名簿を読み込み中...';\n        fetch('/api/teacher/class/'+encodeURIComponent(cid)+'/members').then(function(r){return r.json();}).then(function(d){"
if tsx.count(OLD_C) != 1:
    die('copyTestPrompt の fetch 行が %d 件（1件のはず）' % tsx.count(OLD_C))
NEW_C = "        if(st) st.textContent='名簿を読み込み中...';\n        /* IMPNAME_A_V1 実名マップが未ロードだと名簿がニックネームになるので先に読む。 */\n        (window._serverFuriganaMap?Promise.resolve():loadServerNameMap()).catch(function(){}).then(function(){\n        return fetch('/api/teacher/class/'+encodeURIComponent(cid)+'/members').then(function(r){return r.json();}).then(function(d){"
tsx = tsx.replace(OLD_C, NEW_C, 1)

# copyTestPrompt の .then(...) の閉じを 1 段ふやす
OLD_D = "        }).catch(function(e){ if(st) st.textContent='名簿の読み込みに失敗しました（クラス選択を確認）'; });"
n_d = tsx.count(OLD_D)
if n_d != 1:
    die('copyTestPrompt の catch 行が %d 件（1件のはず）' % n_d)
NEW_D = "        });\n        }).catch(function(e){ if(st) st.textContent='名簿の読み込みに失敗しました（クラス選択を確認）'; });"
tsx = tsx.replace(OLD_D, NEW_D, 1)

bad = False
chain1 = chain_count(tsx)
print('チェーン件数 前=%d 後=%d' % (chain0, chain1))
if chain0 != chain1:
    print('::error::チェーン件数が変わった')
    bad = True

need = {
    'IMPNAME_A_V1': 3,
    'function copyRecordPrompt(){': 1,
    '【このクラスの名簿（児童名は必ずこの中の表記に合わせる）】': 2,
    '【名前の読み取り】手書きの名前が崩れて': 2,
    '名簿'+"'+names.length+'"+'人つき': 1,
}
for k, want in need.items():
    got = tsx.count(k)
    print('適用後 %-52s %d 件（期待 %d）' % (k, got, want))
    if got != want:
        bad = True

print('エスケープ事故の見張り（増えていないこと） = %d' % tsx.count("(\\'"))

for k in ['cannot_trade_special', 'genElectric6', '__WORLD_V3__', 'WARMIX', '_hash',
          'karte_material_uses', '__IMPORT_AUTO_V1__', '__IMPORT_CHECK_V1__', 'QUICKNOTE_V1', '_qnMask']:
    if tsx.count(k) < 1:
        print('::error::安全マーカー %r が消えました' % k)
        bad = True

if bad:
    sys.exit(1)

open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK: src/index.tsx %d 文字' % len(tsx))
