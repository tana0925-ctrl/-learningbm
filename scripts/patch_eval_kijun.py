#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Patch: copyTestPrompt() の◎○△評価基準を、本校教育課程(kyouikukatei)の
学年×教科の評価規準に差し替える。土台は学習指導要領の観点別評価フレーム、
具体は名古屋市版教育課程の3観点規準を優先。該当データが無い学年×教科は
既存の汎用ヒント(_skMap=指導要領観点)へ自動フォールバック。
既存機能(名簿注入・名前予測・点数抽出・出力形式・保存/UI)は不変更。
"""
import sys, io

PATH = "src/index.tsx"

with io.open(PATH, "r", encoding="utf-8") as f:
    src = f.read()

# ---- Anchor A: _sk 定義の直後に _EK データと _ek ルックアップを挿入 ----
OLD_A = "          var _sk=_skMap[subject]||'';"

EK_JS = """
          var _EK={
          '1':{'国語':{kt:'助詞「は・へ・を」、句読点、かぎ「」の使い方を理解して使い、語のまとまりや響きに気を付けて音読できる。',sh:'事柄の順序を考えて内容の大体を捉え、場面の様子や人物の行動を想像する。経験から書くことを見付け順序を考えて短く書く。',st:'進んで音読や説明の順序を捉え、分かったことを伝えたり身近な人に手紙を書いたりしようとする。'},'算数':{kt:'20・100までの数の構成・大小・読み書き、繰り上がり繰り下がりのある加減、時刻の読み、長さ・かさ・広さの比べ方、形の構成を理解している。',sh:'「10と幾つ」や10の補数に着目して計算の仕方を考え、合併・増加や求差などの場面をブロック操作で捉え説明できる。',st:'数量や形に親しみ進んで計算や形づくりに取り組み、計算のよさに気付いて用いようとする。'}},
          '2':{'国語':{kt:'配当漢字や対義語・類義語、丁寧な言葉（敬体）、順序や理由を表す言葉を理解して語彙を増やし文中で使える。',sh:'理由や時間的順序を読み取り重要な語や文を選ぶ。観察の視点を明確にし事柄の順序に沿って組み立てて書く。相手の話をつなげて聞く。',st:'粘り強く言葉や順序を考え、友達と交流しながら記録・説明・お話づくり等に進んで生かそうとする。'},'算数':{kt:'（2位数）±（1位数）の暗算、繰り上がり繰り下がりの筆算、九九、1万までの数、長さ(cm/mm/m)・かさ(L/dL/mL)、三角形・四角形、簡単な分数を理解している。',sh:'十進位取りや数のまとまりを基に計算や大小比較を考え、テープ図で場面を捉え、図形の構成要素に着目して特徴や演算を説明できる。',st:'筆算・九九・図形などのよさに気付き、身の回りの数量や形を進んで調べ工夫して用いようとする。'}},
          '3':{'国語':{kt:'様子・行動・気持ち・性格を表す語句を増やし、段落の役割や全体と中心など情報の関係、漢字・句読点・改行を理解して使える。',sh:'段落相互の関係に着目し考えと理由・事例の関係を捉える。人物の気持ちの変化を場面と結び付けて想像する。目的に応じて書く事柄を選び明確に書く。',st:'進んで叙述を基に読んだり書いたりし、学習課題に沿って感想や考えを伝え合おうとする。'},'算数':{kt:'除法・分数・小数の意味、（2,3位数）×（1,2位数）や余りのある除法の筆算・暗算、円/球・三角形の性質、重さ・長さ・時間の単位を理解し正しく計算・作図・測定できる。',sh:'数量関係や図形を数学的な見方・考え方で捉え、既習と関連付けて計算や作図の仕方を考え、図・式・言葉で筋道立てて説明できる。',st:'除法・分数・小数などのよさに気付き、日常の問題解決に進んで用い粘り強く考えようとする。'},'理科':{kt:'昆虫・植物の育ち方と体のつくり、風とゴム・光・音・磁石・電気・物の重さ・太陽と地面の性質を理解し、虫眼鏡・方位磁針・温度計・はかり等を正しく扱い記録できる。',sh:'主に差異点や共通点を基に問題を見いだし、予想・計画・観察実験・考察を通して結果を基に妥当な考えを表現できる。',st:'自然の事物・現象に進んで関わり他者と関わりながら問題解決し、生物を愛護し学びを生活に生かそうとする。'},'社会':{kt:'身近な地域や市の地形・土地利用・交通、生産や販売の仕事、消防・警察の働き、市の移り変わりを観察・調査・地図資料で調べ白地図や年表にまとめ理解している。',sh:'位置・地形・工程・時期に着目して問いを見いだし、比較・関連付けて特色や工夫を考え、自分たちにできることを選択・判断して表現できる。',st:'予想や学習計画を立て振り返りながら学習問題を追究し、地域社会の一員として協力できることを考えようとする。'}},
          '4':{'国語':{kt:'言葉の働きに気付き、様子・行動・気持ち・性格を表す語句を増やして使い、文章全体の構成や大体を意識して音読できる。',sh:'中学年の重点「中心に気を付けて話す・聞く・読む」「段落相互の関係に注意して書く・読む」。書く内容の中心を明確に構成し、読んで感想や考えをもつ。',st:'進んで自分の考えをもち、見通しをもって人物の気持ち・情景を想像したり、経験や想像から書くことを選んで書こうとする。'},'算数':{kt:'大きな数の仕組み、わり算の筆算・角の測定・面積公式・小数の乗除・分数の加減・概数(四捨五入)などの意味と手順を理解し、正しく計算・作図・測定・処理できる。',sh:'数量や図形に着目し既習を基に筋道立てて考え、求め方やきまりを図・式・言葉で説明・表現できる。',st:'数のよさに気付き進んで工夫し、生活や学習に生かそうとする。'},'理科':{kt:'電流・空気と水・温度と体積・温まり方・水の三態・月や星の位置・体のつくり等の性質を理解し、検流計・温度計・星座早見・ガスこんろ等を正しく扱い過程と結果を記録できる。',sh:'既習や生活経験を基に根拠のある予想・仮説を発想して表現し、結果を基に考察して表現できる。',st:'進んで関わり他者と関わりながら問題解決し、学んだことを生活に生かそうとする。'},'社会':{kt:'地図帳・写真・統計・年表で調べ白地図等にまとめ、県の地理／水・ごみ／自然災害／伝統文化・先人／特色ある地域の様子を理解している。',sh:'分布・位置・協力・歴史的背景に着目して問いを見いだし、特色や関連を考え、調べる視点を偏りなく用いて表現している。',st:'疑問をもち予想・計画を立て振り返って学習問題を追究し、自分たちにできることを考えようとする。'}},
          '5':{'国語':{kt:'心情を表す表現の工夫や比喩・反復などの技法に気付き、原因と結果の関係・文章の構成や展開を理解し、敬語を理解して語彙を充実させる。',sh:'高学年の重点「目的や意図に応じて話す・聞く・書く」「人物像や全体像を想像し表現の効果を考えて読む」。事実と感想・意見を区別して構成し、考えを広げまとめる。',st:'進んで意図に応じて内容を捉え、見通しをもって想像したことを伝え合ったり既習漢字を生かして書こうとする。'},'算数':{kt:'小数・分数の四則、体積・面積・多角形、平均・単位量あたり・速さ・割合(百分率)、合同・角柱円柱・円周率などの意味と計算・作図の技能を習得している。',sh:'既習を基に数学的な見方・考え方を働かせ、計算や求積の仕方・公式を考え、比例や割合の関係に着目して筋道立てて説明・判断できる。',st:'公式や単位量あたり等のよさに気付き進んで用い、粘り強く問題解決しようとする。'},'理科':{kt:'天気の変化、植物の発芽・成長・結実、メダカ/人の誕生、流れる水の働き、もののとけ方、振り子、電磁石の規則性を理解し、顕微鏡・電子てんびん・メスシリンダー等を正しく扱い記録できる。',sh:'見いだした問題について予想や仮説を基に条件を制御して解決方法を発想し、結果を基に考察して表現できる。',st:'進んで関わり粘り強く他者と関わりながら問題解決し、学んだことを生活に生かそうとする。'},'社会':{kt:'国土(位置・地形・気候)、食料生産(農業・水産業)、工業生産・貿易、情報産業、自然災害/森林/環境保全について地図帳・統計・写真等で調べ概要を理解しまとめている。',sh:'位置・地形・産業・情報・環境に着目して問いを見いだし、事象を関連付けて考え、社会への関わり方を選択・判断して表現している。',st:'予想や学習計画を立て振り返って学習問題を追究し、学んだことを生活に生かそうとする。'}},
          '6':{'国語':{kt:'言葉が相手とのつながりをつくる働きに気付き、語句の関係・構成・変化を理解して語彙を豊かにし、情報と情報の関係付けや図での表し方を理解する。',sh:'高学年の重点「目的や意図に応じて話す・聞く・書く」「人物像や全体像を想像し表現の効果を考えて読む」。事実と意見を区別して構成し、叙述を基に要旨を捉え考えをまとめる。',st:'進んで語感や言葉の使い方を意識し、これまでの学習を生かして見通しをもって書いたり音読したりしようとする。'},'算数':{kt:'対称な図形・拡大縮小・比・比例反比例・円や柱体の求積・分数の乗除・場合の数・データ(代表値・ヒストグラム)などの意味や性質を理解し作図・計算・作表を正しく行える。',sh:'図形の構成要素や数量の関係に着目し既習を基に求め方・計算の仕方・きまりを考え、図・式・言葉を関連付けて説明したり目的に応じてデータを分析・判断できる。',st:'事象に関心をもち対称性・比・比例などを進んで用い、統計的解決などに粘り強く取り組もうとする。'},'理科':{kt:'燃焼、水溶液の性質、てこの規則性、電気の性質・変換、人や動物の体、植物と光・水、生物と環境、土地のつくりと変化、月と太陽を理解し、気体検知管・顕微鏡・手回し発電機等を目的に応じて操作し記録できる。',sh:'自然の事物・現象から問題を見いだし、予想や仮説を基に解決方法を発想し、多面的に調べてより妥当な考えをつくりだし表現できる。',st:'進んで関わり粘り強く他者と関わりながら問題解決し、学んだことを生活に生かそうとする。'},'社会':{kt:'日本国憲法と政治の仕組み・働き、縄文から現代までの歴史(人物・文化遺産・世の中の変化)、日本とつながりの深い国々や国際連合・国際協力を理解し、調べてまとめられる。',sh:'政治の働き・歴史の展開・国際社会での役割に着目して問いを見いだし、社会事象の意味を多角的に考え表現している。',st:'予想や学習計画を立て振り返って追究・解決し、我が国の歴史や伝統を大切にし世界の人々と共に生きる大切さを多角的に考えようとする。'}}
          };
          var _ek=(_EK[String(grade)]&&_EK[String(grade)][subject])||null;"""

NEW_A = OLD_A + EK_JS

# ---- Anchor A2: stxt の既定を「教科自動判定」に ----
OLD_A2 = "          var stxt=subject||'この教科';"
NEW_A2 = "          var stxt=subject||'（教科はテスト内容からAIが判定）';"

# ---- Anchor B: 汎用ヒント push を、自動(全教科)/手動(単一教科)モードに差し替え ----
OLD_B = "          if(_sk) L.push(_sk);"
NEW_B = (
"          if(subject){\n"
"            if(_ek){ L.push('【この学年・教科の評価規準（本校教育課程より）】'+gtxt+' '+stxt); L.push('・知識・技能：'+_ek.kt); L.push('・思考・判断・表現：'+_ek.sh); L.push('・主体的に学習に取り組む態度：'+_ek.st); L.push('※土台は学習指導要領の観点別評価（学年が上がるほど到達度が上がる）。具体的な判断は上の本校教育課程の評価規準を優先。'); }\n"
"            else if(_sk){ L.push(_sk); }\n"
"          } else {\n"
"            var _EKg=_EK[String(grade)]||null; var _so=['国語','算数','理科','社会'];\n"
"            if(_EKg){\n"
"              L.push('【教科は自動判定】このプリントの教科をテスト内容（設問・語句・図・単元名）から判定し、下の該当教科の評価規準に照らして◎○△を付けてください。1枚に複数教科が混在する場合は、各答案の内容から教科を判定して評価します。');\n"
"              L.push('【'+gtxt+'の主要教科の評価規準（本校教育課程より）】');\n"
"              for(var _si=0;_si<_so.length;_si++){ var _sn=_so[_si]; var _ee=_EKg[_sn]; if(!_ee) continue; L.push('■'+_sn+'／知識・技能：'+_ee.kt+'／思考・判断・表現：'+_ee.sh+'／主体的に学習に取り組む態度：'+_ee.st); }\n"
"              L.push('※土台は学習指導要領の観点別評価（学年が上がるほど到達度が上がる）。具体的な判断は上の本校教育課程の評価規準を優先。');\n"
"            } else {\n"
"              L.push('【教科は自動判定】このプリントの教科（国語・算数・理科・社会など）をテスト内容から判定し、その教科の①知識・技能②思考・判断・表現③主体的に学習に取り組む態度に照らして◎○△を付けてください。学年が上がるほど求める到達度も上がります。');\n"
"            }\n"
"          }"
)

def apply(src, old, new, label):
    n = src.count(old)
    if n != 1:
        sys.stderr.write("FATAL: anchor %s found %d times (expected 1)\n" % (label, n))
        sys.exit(1)
    return src.replace(old, new, 1)

# 冪等性: 既に適用済みなら何もしない
if "var _EK=" in src and "report-card" in src and "教科は自動判定" in src:
    print("Already patched. Skipping.")
    sys.exit(0)

src = apply(src, OLD_A, NEW_A, "A(_sk def)")
src = apply(src, OLD_A2, NEW_A2, "A2(stxt)")
src = apply(src, OLD_B, NEW_B, "B(_sk push)")

# ---- 児童向けカルテは ◎○△ 非表示・コメントのみ（先生用データ eval_rank は保持。表示の切り分けのみ）----
# C: 子ども向けカルテPDF(_buildKarteHtml)のテスト行に、先生コメント（評価記号なし）を表示
OLD_C = """H.push('<li>'+esc(tt.testDate||'')+' '+esc(tt.subject||'')+' '+esc(tt.testName||'')+' \u2026 '+(tt.score==null?'-':tt.score)+'/'+(tt.maxScore||100)+'\u70b9'+tp+'</li>');"""
NEW_C = """H.push('<li>'+esc(tt.testDate||'')+' '+esc(tt.subject||'')+' '+esc(tt.testName||'')+' \u2026 '+(tt.score==null?'-':tt.score)+'/'+(tt.maxScore||100)+'\u70b9'+tp+(tt.comment?' <span style="color:#0369a1">\U0001f4ac'+esc(tt.comment)+'</span>':'')+'</li>');"""

# D: 阪神マン（児童向けAIコメント）本文に◎○△を出さないガード
OLD_D = "\u6210\u679c\u7269\uff08\u30dd\u30fc\u30c8\u30d5\u30a9\u30ea\u30aa\uff09\u306b\u306f\u5148\u751f\u306e\u8a55\u4fa1\uff08\u25ce\u25cb\u25b3\uff09\u3068\u8a55\u4fa1\u30b3\u30e1\u30f3\u30c8\u3082\u4ed8\u3044\u3066\u3044\u307e\u3059\u3002\u8a55\u4fa1\u3082\u8e0f\u307e\u3048\u3066\u30b3\u30e1\u30f3\u30c8\u30fb\u30a2\u30c9\u30d0\u30a4\u30b9\u3057\u3066\u304f\u3060\u3055\u3044\u3002"
NEW_D = OLD_D + "\u305f\u3060\u3057\u3001\u5150\u7ae5\u306b\u6e21\u3059\u6587\u7ae0\u306b\u306f\u25ce\u25cb\u25b3\u306a\u3069\u306e\u8a55\u4fa1\u8a18\u53f7\u306f\u66f8\u304b\u305a\u3001\u307b\u3081\u8a00\u8449\u3084\u30a2\u30c9\u30d0\u30a4\u30b9\u306e\u8a00\u8449\u3067\u4f1d\u3048\u3066\u304f\u3060\u3055\u3044\u3002"

# E: まとめてコピーのKARTE（児童向け所見）にも同ガード
OLD_E = "\u4eca\u5e74\u5ea6\uff084\u6708\u301c\uff09\u5168\u671f\u9593\u306e\u50be\u5411\u3068\u6210\u679c\u7269\u306e\u8a55\u4fa1\uff08\u25ce\u25cb\u25b3\uff09\u3082\u8e0f\u307e\u3048\u3001\u8ab2\u984c\u306f\u6b63\u76f4\u306b\uff0b\u6b21\u306e\u4e00\u6b69\u3068\u30bb\u30c3\u30c8\u3067\u3002"
NEW_E = OLD_E + "\u203b\u5150\u7ae5\u5411\u3051\u30ab\u30eb\u30c6\u672c\u6587\u306b\u306f\u25ce\u25cb\u25b3\u306a\u3069\u306e\u8a18\u53f7\u306f\u66f8\u304b\u305a\u3001\u8a00\u8449\u3067\u52b1\u307e\u3059\u3002"

src = apply(src, OLD_C, NEW_C, "C(child-karte comment)")
src = apply(src, OLD_D, NEW_D, "D(hanshin child guard)")
src = apply(src, OLD_E, NEW_E, "E(karte child guard)")


# ===== 観点別(3観点)評価 + 教師専用 通知表(番号順×教科×3観点) + 出席番号 =====

# P1: 出力形式ヘッダに観点別の説明
OLD_P1 = "          L.push('【出力形式】');"
NEW_P1 = "          L.push('【出力形式】（評価は観点別に3つ。知技=知識・技能／思判表=思考・判断・表現／主体=主体的に学習に取り組む態度。各観点は ◎○△ で、そのテストで測っていない観点は空欄にします）');"

# P2: 出力例の列を 6列(3観点)に
OLD_P2 = "          L.push('児童名, 点数, 評価, コメント');\n          L.push('児童名, 点数, 評価, コメント');"
NEW_P2 = "          L.push('児童名, 点数, 知技, 思判表, 主体, コメント');\n          L.push('児童名, 点数, 知技, 思判表, 主体, コメント');"

# P3: ルール行を観点別に
OLD_P3 = "          L.push('【ルール】各項目はカンマ（,）で区切り、1行に1人。点数は数字のみ（不明は空欄）。評価は ◎ ○ △ のいずれか。コメントは20文字以内で、'+gtxt+'の評価基準に照らして「できている観点／次に伸ばす観点」を一言で（例：計算は正確、理由の説明を伸ばそう）。児童名は必ず上の名簿の表記に合わせる。合計・平均などの余計な行は入れない。');"
NEW_P3 = "          L.push('【ルール】各項目はカンマ（,）で区切り、1行に1人。点数は数字のみ（不明は空欄）。知技・思判表・主体はそれぞれ ◎ ○ △ か空欄（そのテストで測れない観点は空欄）。コメントは20文字以内で、'+gtxt+'の評価規準に照らして「できている観点／次に伸ばす観点」を一言で。児童名は必ず上の名簿の表記に合わせる。合計・平均などの余計な行は入れない。');"

# S1: server _tsParseText 行パースを 6列(3観点)対応
OLD_S1 = """    var ev=''; var cm='';
    if(parts.length>=4){ ev=_recNormRank(parts[2]); cm=parts.slice(3).join(',').trim(); }
    else if(parts.length===3){ var _mb=_recNormRank(parts[2]); if(_mb){ ev=_mb; } else { cm=String(parts[2]).trim(); } }
    if(sc===null && !ev) continue;
    rows.push({rawName:nm, score:sc, evalRank:ev, comment:cm});"""
NEW_S1 = """    var ek='',et='',ea='',ev='',cm='';
    if(parts.length>=6){ ek=_recNormRank(parts[2]); et=_recNormRank(parts[3]); ea=_recNormRank(parts[4]); cm=parts.slice(5).join(',').trim(); }
    else if(parts.length>=4){ ev=_recNormRank(parts[2]); cm=parts.slice(3).join(',').trim(); }
    else if(parts.length===3){ var _mb=_recNormRank(parts[2]); if(_mb){ ev=_mb; } else { cm=String(parts[2]).trim(); } }
    var _repr=ev||ek||et||ea;
    if(sc===null && !_repr) continue;
    rows.push({rawName:nm, score:sc, evalRank:_repr, evalKnowledge:ek, evalThinking:et, evalAttitude:ea, comment:cm});"""

# S2: parse route の返却行に観点フィールド追加
OLD_S2 = "    return { rawName: r.rawName, score: r.score, evalRank: r.evalRank || '', comment: r.comment, matchedUserId: uid, matchedName: mm ? mm.name : null }"
NEW_S2 = "    return { rawName: r.rawName, score: r.score, evalRank: r.evalRank || '', evalKnowledge: r.evalKnowledge || '', evalThinking: r.evalThinking || '', evalAttitude: r.evalAttitude || '', comment: r.comment, matchedUserId: uid, matchedName: mm ? mm.name : null }"

# S3: save route スキーマに観点別カラムを非破壊追加
OLD_S3 = '  try { await c.env.DB.prepare("CREATE TABLE IF NOT EXISTS student_test_scores (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, test_name TEXT, test_date TEXT, subject TEXT, max_score INTEGER DEFAULT 100, score INTEGER, comment TEXT, eval_rank TEXT, created_by TEXT, created_at TEXT)").run() } catch {}'
NEW_S3 = OLD_S3 + '\n  try { await c.env.DB.prepare("ALTER TABLE student_test_scores ADD COLUMN eval_knowledge TEXT").run() } catch {}\n  try { await c.env.DB.prepare("ALTER TABLE student_test_scores ADD COLUMN eval_thinking TEXT").run() } catch {}\n  try { await c.env.DB.prepare("ALTER TABLE student_test_scores ADD COLUMN eval_attitude TEXT").run() } catch {}'

# S4: save route insert を観点別に
OLD_S4 = """    const evalRank = _recNormRank(String((it && it.evalRank) || ''))
    let sc: number | null = parseInt(String(it && it.score), 10)
    if (isNaN(sc as any)) sc = null
    if (sc === null && !evalRank) continue
    await c.env.DB.prepare('INSERT INTO student_test_scores (user_id, test_name, test_date, subject, max_score, score, comment, eval_rank, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)').bind(uid, testName, testDate, subject, maxScore, sc, String((it && it.comment) || ''), evalRank, u.id, nowIso).run()"""
NEW_S4 = """    const evalKnowledge = _recNormRank(String((it && it.evalKnowledge) || ''))
    const evalThinking = _recNormRank(String((it && it.evalThinking) || ''))
    const evalAttitude = _recNormRank(String((it && it.evalAttitude) || ''))
    const evalRank = _recNormRank(String((it && it.evalRank) || '')) || evalKnowledge || evalThinking || evalAttitude
    let sc: number | null = parseInt(String(it && it.score), 10)
    if (isNaN(sc as any)) sc = null
    if (sc === null && !evalRank) continue
    await c.env.DB.prepare('INSERT INTO student_test_scores (user_id, test_name, test_date, subject, max_score, score, comment, eval_rank, eval_knowledge, eval_thinking, eval_attitude, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(uid, testName, testDate, subject, maxScore, sc, String((it && it.comment) || ''), evalRank, evalKnowledge, evalThinking, evalAttitude, u.id, nowIso).run()"""

src = apply(src, OLD_P1, NEW_P1, "P1(output-header)")
src = apply(src, OLD_P2, NEW_P2, "P2(output-cols)")
src = apply(src, OLD_P3, NEW_P3, "P3(rules)")
src = apply(src, OLD_S1, NEW_S1, "S1(parse-row)")
src = apply(src, OLD_S2, NEW_S2, "S2(parse-return)")
src = apply(src, OLD_S3, NEW_S3, "S3(schema)")
src = apply(src, OLD_S4, NEW_S4, "S4(insert)")



# S5: 取り込みプレビューの thead を 3観点列に
OLD_S5 = '<th class="p-1">点数</th><th class="p-1">評価</th>'
NEW_S5 = '<th class="p-1">点数</th><th class="p-1">知技</th><th class="p-1">思判表</th><th class="p-1">主体</th>'

# S6: プレビューの評価セルを 3観点セレクトに
OLD_S6 = """          var _evv=r.evalRank||''; var _eo=function(vv){ var a=[['',''],['◎','◎'],['○','○'],['△','△']]; var o=''; for(var _z=0;_z<a.length;_z++){ o+='<option value="'+a[_z][0]+'"'+(a[_z][0]===vv?' selected':'')+'>'+a[_z][1]+'</option>'; } return o; };
          h+='<td class="p-1 text-center"><select id="tsRow_'+i+'_eval" class="border rounded p-1">'+_eo(_evv)+'</select></td>';"""
NEW_S6 = """          var _eo=function(vv){ var a=[['',''],['◎','◎'],['○','○'],['△','△']]; var o=''; for(var _z=0;_z<a.length;_z++){ o+='<option value="'+a[_z][0]+'"'+(a[_z][0]===vv?' selected':'')+'>'+a[_z][1]+'</option>'; } return o; };
          var _ekv=r.evalKnowledge||r.evalRank||''; var _etv=r.evalThinking||''; var _eav=r.evalAttitude||'';
          h+='<td class="p-1 text-center"><select id="tsRow_'+i+'_ek" class="border rounded p-1">'+_eo(_ekv)+'</select></td>';
          h+='<td class="p-1 text-center"><select id="tsRow_'+i+'_et" class="border rounded p-1">'+_eo(_etv)+'</select></td>';
          h+='<td class="p-1 text-center"><select id="tsRow_'+i+'_ea" class="border rounded p-1">'+_eo(_eav)+'</select></td>';"""

# S7: saveTestScores を 3観点対応
OLD_S7 = """          var _ev=gv('tsRow_'+i+'_eval'); var _cm=gv('tsRow_'+i+'_comment');
          var _hasScore=!(score===''||score==null);
          if(!_hasScore && !_ev){ skipped++; continue; }
          try{ _rememberAlias(cid, (d.rows[i]&&d.rows[i].rawName)||'', uid); }catch(_e){}
          rows.push({userId:uid, score:(_hasScore?parseInt(score,10):null), evalRank:_ev, comment:_cm});"""
NEW_S7 = """          var _ek=gv('tsRow_'+i+'_ek'); var _et=gv('tsRow_'+i+'_et'); var _ea=gv('tsRow_'+i+'_ea'); var _cm=gv('tsRow_'+i+'_comment');
          var _ev=_ek||_et||_ea;
          var _hasScore=!(score===''||score==null);
          if(!_hasScore && !_ev){ skipped++; continue; }
          try{ _rememberAlias(cid, (d.rows[i]&&d.rows[i].rawName)||'', uid); }catch(_e){}
          rows.push({userId:uid, score:(_hasScore?parseInt(score,10):null), evalRank:_ev, evalKnowledge:_ek, evalThinking:_et, evalAttitude:_ea, comment:_cm});"""

# F: 教師専用 通知表(report-card) + 出席番号(roster-no) ルートを members ルート直後に追加
OLD_F = "  return c.json({ ok: true, members: rows.results })\n})\n// クラス削除"
NEW_F = """  return c.json({ ok: true, members: rows.results })
})

app.get('/api/teacher/class/:classId/report-card', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=?').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class not found')
  try { await c.env.DB.prepare('ALTER TABLE users ADD COLUMN roster_no INTEGER').run() } catch (_) {}
  try { await c.env.DB.prepare('ALTER TABLE student_test_scores ADD COLUMN eval_knowledge TEXT').run() } catch (_) {}
  try { await c.env.DB.prepare('ALTER TABLE student_test_scores ADD COLUMN eval_thinking TEXT').run() } catch (_) {}
  try { await c.env.DB.prepare('ALTER TABLE student_test_scores ADD COLUMN eval_attitude TEXT').run() } catch (_) {}
  const mem = await c.env.DB.prepare('SELECT u.id as userId, u.login_id as loginId, u.name, u.grade, u.roster_no as rosterNo FROM class_members cm JOIN users u ON u.id=cm.user_id WHERE cm.class_id=? ORDER BY (u.roster_no IS NULL), u.roster_no, u.name').bind(classId).all<any>()
  const members = (mem && mem.results) || []
  let tests: any[] = []
  try {
    const tr = await c.env.DB.prepare('SELECT sts.user_id as userId, sts.subject, sts.eval_rank as evalRank, sts.eval_knowledge as evalKnowledge, sts.eval_thinking as evalThinking, sts.eval_attitude as evalAttitude, sts.score, sts.max_score as maxScore, sts.test_name as testName, sts.test_date as testDate, sts.comment, sts.created_at as createdAt FROM student_test_scores sts JOIN class_members cm ON cm.user_id=sts.user_id WHERE cm.class_id=? ORDER BY sts.created_at DESC').bind(classId).all<any>()
    tests = (tr && tr.results) || []
  } catch (_) {}
  const byUser: any = {}
  for (const m of members as any[]) byUser[m.userId] = { userId: m.userId, loginId: m.loginId, name: m.name, grade: m.grade, rosterNo: m.rosterNo, subjects: {}, tests: [] }
  for (const t of tests as any[]) {
    const bu = byUser[t.userId]; if (!bu) continue
    bu.tests.push(t)
    const sj = t.subject || 'その他'
    if (!bu.subjects[sj]) bu.subjects[sj] = { knowledge: '', thinking: '', attitude: '', count: 0 }
    const sJ = bu.subjects[sj]; sJ.count++
    if (!sJ.knowledge && (t.evalKnowledge || t.evalRank)) sJ.knowledge = t.evalKnowledge || t.evalRank || ''
    if (!sJ.thinking && t.evalThinking) sJ.thinking = t.evalThinking
    if (!sJ.attitude && t.evalAttitude) sJ.attitude = t.evalAttitude
  }
  const students = (members as any[]).map((m: any) => byUser[m.userId])
  return c.json({ ok: true, students })
})

app.post('/api/teacher/class/:classId/roster-no', async (c) => {
  const u = requireTeacher(c)
  if (!u) return jsonError(c, 401, 'unauthorized')
  const classId = c.req.param('classId')
  const cls = u.role === 'admin'
    ? await c.env.DB.prepare('SELECT id FROM classes WHERE id=?').bind(classId).first<any>()
    : await c.env.DB.prepare('SELECT id FROM classes WHERE id=? AND teacher_id=?').bind(classId, u.id).first<any>()
  if (!cls) return jsonError(c, 404, 'class not found')
  const body = await c.req.json().catch(() => null)
  if (!body || !Array.isArray(body.items)) return jsonError(c, 400, 'invalid')
  try { await c.env.DB.prepare('ALTER TABLE users ADD COLUMN roster_no INTEGER').run() } catch (_) {}
  const mem = (((await c.env.DB.prepare('SELECT user_id as uid FROM class_members WHERE class_id=?').bind(classId).all<any>()).results) || [])
  const allowed = new Set((mem as any[]).map((r: any) => String(r.uid)))
  let saved = 0
  for (const it of body.items) {
    const uid = String((it && it.userId) || '')
    if (!uid || !allowed.has(uid)) continue
    let n: number | null = parseInt(String(it && it.rosterNo), 10)
    if (isNaN(n as any)) n = null
    await c.env.DB.prepare('UPDATE users SET roster_no=? WHERE id=?').bind(n, uid).run()
    saved++
  }
  return c.json({ ok: true, saved })
})

// クラス削除"""

# G: 教師ダッシュボードに 通知表カードを追加（個人カルテの直前）
OLD_G = "          <!-- 個人カルテ -->"
NEW_G = """          <!-- 通知表（先生用・観点別◎○△） -->
          <div class="bg-white border border-indigo-200 rounded-xl p-4 space-y-3 mb-4" id="reportCardPanel">
            <div class="flex items-center justify-between flex-wrap gap-2">
              <div class="font-bold text-sm text-indigo-800">📋 通知表（先生用・観点別）</div>
              <div class="flex gap-2">
                <button onclick="loadReportCard()" class="bg-indigo-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-indigo-700">📋 評価一覧</button>
                <button onclick="loadRosterEditor()" class="bg-slate-200 text-slate-700 rounded-lg px-3 py-1.5 text-xs font-bold hover:bg-slate-300">🔢 出席番号を編集</button>
              </div>
            </div>
            <p class="text-xs text-indigo-600">テスト採点でつけた観点別評価（◎○△）を、児童（出席番号順）×教科×3観点で集約します。<b>先生だけが見る画面です（児童には表示されません）。</b>「クラス全体」で選んだクラスが対象。</p>
            <div id="reportCardContent" class="text-sm text-slate-600"><p class="text-xs text-slate-400">クラスを選んで「評価一覧」を押してください</p></div>
          </div>
          <!-- 個人カルテ -->"""

# H: 通知表/出席番号の描画・保存関数（parseTestScores の直前に追加）
OLD_H = "      function parseTestScores(){"
NEW_H = """      function _rcRankGlyph(r){ return r==='◎'?'<span class="text-pink-600 font-black">◎</span>':r==='○'?'<span class="text-green-600 font-black">○</span>':r==='△'?'<span class="text-orange-600 font-black">△</span>':'<span class="text-slate-300">・</span>'; }
      function _rcName(s){ return (typeof resolveStudentName==='function')?resolveStudentName(s.loginId,s.name):(s.name||''); }
      function loadReportCard(){
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';
        var box=document.getElementById('reportCardContent');
        if(!cid){ if(box) box.innerHTML='<p class="text-xs text-red-500">先に「クラス全体」でクラスを選んでください</p>'; return; }
        if(box) box.innerHTML='<p class="text-xs text-indigo-500 animate-pulse">集計中...</p>';
        fetch('/api/teacher/class/'+encodeURIComponent(cid)+'/report-card').then(function(r){return r.json();}).then(function(d){
          if(!d||!d.ok){ if(box) box.innerHTML='<p class="text-xs text-red-500">取得に失敗しました（クラス権限などを確認）</p>'; return; }
          if(box) box.innerHTML=_rcRender(d);
        }).catch(function(e){ if(box) box.innerHTML='<p class="text-xs text-red-500">エラー: '+(e&&e.message?e.message:e)+'</p>'; });
      }
      function _rcRender(d){
        var sts=d.students||[]; if(!sts.length) return '<p class="text-xs text-slate-400">児童がいません。</p>';
        var subs=['国語','算数','理科','社会']; var kk=[['knowledge','知技'],['thinking','思判'],['attitude','主体']];
        var h='<div class="text-[10px] text-slate-400 mb-1">◎十分/○おおむね/△要支援・「・」=未評価。教科ごとに 知技=知識技能／思判=思考判断表現／主体=主体的態度。直近テストの評価。児童は出席番号順。</div>';
        h+='<div class="overflow-x-auto"><table class="text-xs border-collapse" style="min-width:620px"><thead>';
        h+='<tr class="text-slate-500"><th rowspan="2" class="p-1 border">No</th><th rowspan="2" class="p-1 border text-left">児童</th>';
        for(var si=0;si<subs.length;si++){ h+='<th colspan="3" class="p-1 border text-center bg-slate-50">'+subs[si]+'</th>'; }
        h+='<th rowspan="2" class="p-1 border">テスト数</th></tr><tr class="text-[9px] text-slate-400">';
        for(var si2=0;si2<subs.length;si2++){ for(var ki=0;ki<kk.length;ki++){ h+='<th class="p-1 border">'+kk[ki][1]+'</th>'; } }
        h+='</tr></thead><tbody>';
        for(var i=0;i<sts.length;i++){ var s=sts[i]; if(!s) continue;
          h+='<tr class="border"><td class="p-1 border text-center text-slate-500">'+(s.rosterNo!=null?escH(String(s.rosterNo)):'-')+'</td><td class="p-1 border font-bold text-slate-700 whitespace-nowrap">'+escH(_rcName(s))+(s.grade?' <span class="text-[9px] text-slate-400">'+escH(String(s.grade))+'年</span>':'')+'</td>';
          for(var j=0;j<subs.length;j++){ var sj=s.subjects&&s.subjects[subs[j]]; for(var k=0;k<kk.length;k++){ h+='<td class="p-1 border text-center">'+(sj?_rcRankGlyph(sj[kk[k][0]]):'<span class="text-slate-300">・</span>')+'</td>'; } }
          h+='<td class="p-1 border text-center text-slate-500">'+((s.tests&&s.tests.length)||0)+'</td></tr>';
        }
        h+='</tbody></table></div>';
        return h;
      }
      function loadRosterEditor(){
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:'';
        var box=document.getElementById('reportCardContent');
        if(!cid){ if(box) box.innerHTML='<p class="text-xs text-red-500">先に「クラス全体」でクラスを選んでください</p>'; return; }
        fetch('/api/teacher/class/'+encodeURIComponent(cid)+'/report-card').then(function(r){return r.json();}).then(function(d){
          if(!d||!d.ok){ if(box) box.innerHTML='<p class="text-xs text-red-500">取得に失敗しました</p>'; return; }
          var sts=d.students||[]; window._rcStudents=sts;
          var h='<div class="text-[10px] text-slate-500 mb-1">各児童の出席番号を入力して保存すると、通知表がその番号順に並びます（空欄は名前順）。</div>';
          h+='<div class="max-h-72 overflow-y-auto"><table class="w-full text-xs"><tbody>';
          for(var i=0;i<sts.length;i++){ var s=sts[i]; if(!s) continue; h+='<tr class="border-b"><td class="p-1 w-20"><input id="rn_'+escH(s.userId)+'" type="number" min="1" class="border rounded p-1 w-16 text-center" value="'+escH(s.rosterNo!=null?String(s.rosterNo):'')+'"></td><td class="p-1 font-bold text-slate-700">'+escH(_rcName(s))+'</td></tr>'; }
          h+='</tbody></table></div><div class="mt-2"><button onclick="saveRosterNo()" class="bg-indigo-600 text-white rounded-lg px-4 py-2 text-xs font-bold hover:bg-indigo-700">💾 出席番号を保存</button> <span id="rnSaveStatus" class="text-xs text-amber-600"></span></div>';
          if(box) box.innerHTML=h;
        }).catch(function(e){ if(box) box.innerHTML='<p class="text-xs text-red-500">エラー: '+(e&&e.message?e.message:e)+'</p>'; });
      }
      function saveRosterNo(){
        var sel=document.getElementById('laClassSelect'); var cid=sel?sel.value:''; var st=document.getElementById('rnSaveStatus');
        var sts=window._rcStudents||[]; var items=[];
        for(var i=0;i<sts.length;i++){ var s=sts[i]; if(!s) continue; var el=document.getElementById('rn_'+s.userId); if(!el) continue; var v=el.value; items.push({userId:s.userId, rosterNo:(v===''?null:parseInt(v,10))}); }
        if(st) st.textContent='保存中...';
        fetch('/api/teacher/class/'+encodeURIComponent(cid)+'/roster-no',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({items:items})}).then(function(r){return r.json();}).then(function(res){
          if(res&&res.ok){ if(st) st.textContent='✓ '+res.saved+'人分の番号を保存しました'; loadReportCard(); } else { if(st) st.textContent='保存に失敗しました'; }
        }).catch(function(e){ if(st) st.textContent='エラー: '+e.message; });
      }
      function parseTestScores(){"""

src = apply(src, OLD_S5, NEW_S5, "S5(preview-thead)")
src = apply(src, OLD_S6, NEW_S6, "S6(preview-eval-cell)")
src = apply(src, OLD_S7, NEW_S7, "S7(save-3kanten)")
src = apply(src, OLD_F, NEW_F, "F(report-card+roster routes)")
src = apply(src, OLD_G, NEW_G, "G(report-card UI)")
src = apply(src, OLD_H, NEW_H, "H(report-card JS)")


with io.open(PATH, "w", encoding="utf-8") as f:
    f.write(src)

print("Patched OK: _EK(1-6/国算理社) + auto subject-detect + manual override preserved.")
