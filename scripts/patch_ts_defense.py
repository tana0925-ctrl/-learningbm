import sys

def patch_file(path, edits):
    with open(path,'r',encoding='utf-8',newline='') as f:
        data=f.read()
    for old,new in edits:
        if new in data and old not in data:
            print('skip'); continue
        if old not in data:
            print('ANCHOR NOT FOUND',repr(old[:60])); sys.exit(1)
        if data.count(old)!=1:
            print('NOT UNIQUE',data.count(old)); sys.exit(1)
        data=data.replace(old,new); print('ok',repr(old[:30]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ("渡せる文章にしてください。なお、データが見せる課題は正直に伝えてええ。提出率がひくい・さいきん下がってる・学年そうとうの単元が未定着のときは、ぼかさず具体的に言うたって（例：さいきん提出が◯％に下がってるで）、かならず次の一歩（例：まずは週◯回を目標にしよ）とセットにする。相手は小学生やから、正直でも突き放さず前向きに。ええときは今までどおりしっかりほめる。');",
     "渡せる文章にしてください。なお、データが見せる課題は正直に伝えてええ。提出率がひくい・さいきん下がってる・学年そうとうの単元が未定着のときは、ぼかさず具体的に言うたって（例：さいきん提出が◯％に下がってるで）、かならず次の一歩（例：まずは週◯回を目標にしよ）とセットにする。相手は小学生やから、正直でも突き放さず前向きに。ええときは今までどおりしっかりほめる。以下のデータは今年度（4月1日〜現在）の全期間の集計です。一時的な直近だけでなく、年度を通した成長・傾向を踏まえてコメントしてください。成果物（ポートフォリオ）には先生の評価（◎○△）と評価コメントも付いています。評価も踏まえてコメント・アドバイスしてください。');"),
    ("        L.push('');\n        L.push('※先生がそのまま使えるよう、具体的でやさしい言葉でお願いします。');",
     "        if(data.testScores && data.testScores.length){ L.push(''); L.push('【テストの記録（今年度・全期間）】'); for(var tsx=0;tsx<data.testScores.length;tsx++){ var tt2=data.testScores[tsx]; L.push('・' + (tt2.testDate||'') + ' ' + (tt2.subject||'') + ' ' + (tt2.testName||'') + '：' + (tt2.score==null?'-':tt2.score) + '/' + (tt2.maxScore||100) + (tt2.pct!=null?'（'+tt2.pct+'%）':'') + (tt2.comment?' 先生:'+tt2.comment:'')); } }\n        if(data.records && data.records.length){ L.push(''); L.push('【ポートフォリオ（成果物・振り返り・先生の評価◎○△）／今年度・全期間】'); var _rkj=function(k){ return k==='test'?'テスト':k==='report'?'まとめ':k==='reflect'?'振り返り':'その他'; }; for(var rpx=0;rpx<data.records.length;rpx++){ var rc2=data.records[rpx]; var _ev2=rc2.evalRank?('／評価:'+rc2.evalRank+((rc2.evalComment&&String(rc2.evalComment).trim())?'／評価コメント:'+rc2.evalComment:'')):''; var _ln2='・[' + _rkj(rc2.type) + '] ' + (rc2.title||'(無題)') + '（' + (rc2.dayKey||'') + (rc2.unit?'／'+rc2.unit:'') + _ev2 + '）'; if(rc2.body && String(rc2.body).trim()) _ln2 += ' 本文:' + rc2.body; if(rc2.reflection && String(rc2.reflection).trim()) _ln2 += ' ／振り返り:' + rc2.reflection; L.push(_ln2); } }\n        L.push('');\n        L.push('※先生がそのまま使えるよう、具体的でやさしい言葉でお願いします。');"),
    ("if(rs.weather_reason) line+=' ふりかえり:'+rs.weather_reason; L.push(line); } } return L; }",
     "if(rs.weather_reason) line+=' ふりかえり:'+rs.weather_reason; L.push(line); } } if(data.testScores&&data.testScores.length){ L.push(''); L.push('【テストの記録（今年度・全期間）】'); for(var tsx=0;tsx<data.testScores.length;tsx++){ var tt2=data.testScores[tsx]; L.push('・'+(tt2.testDate||'')+' '+(tt2.subject||'')+' '+(tt2.testName||'')+'：'+(tt2.score==null?'-':tt2.score)+'/'+(tt2.maxScore||100)+(tt2.pct!=null?'（'+tt2.pct+'%）':'')+(tt2.comment?' 先生:'+tt2.comment:'')); } } if(data.records&&data.records.length){ L.push(''); L.push('【ポートフォリオ（成果物・振り返り・先生の評価◎○△）／今年度・全期間】'); var _rkj=function(k){ return k==='test'?'テスト':k==='report'?'まとめ':k==='reflect'?'振り返り':'その他'; }; for(var rpx=0;rpx<data.records.length;rpx++){ var rc2=data.records[rpx]; var _ev2=rc2.evalRank?('／評価:'+rc2.evalRank+((rc2.evalComment&&String(rc2.evalComment).trim())?'／評価コメント:'+rc2.evalComment:'')):''; var _ln2='・['+_rkj(rc2.type)+'] '+(rc2.title||'(無題)')+'（'+(rc2.dayKey||'')+(rc2.unit?'／'+rc2.unit:'')+_ev2+'）'; if(rc2.body&&String(rc2.body).trim()) _ln2+=' 本文:'+rc2.body; if(rc2.reflection&&String(rc2.reflection).trim()) _ln2+=' ／振り返り:'+rc2.reflection; L.push(_ln2); } } return L; }"),
    ('(2) 続けて各児童ごとに「=== [児童ID] 名前 ===」の行をそのまま残し、その下に阪神マン風（関西弁・前向き）で ①ええところ ②気になるところ ③おすすめの学習・声かけ を、児童本人が読んで前向きになれるように。学年に合わせて声かけを変える。',
     '(2) 続けて各児童ごとに「=== [児童ID] 名前 ===」の行をそのまま残し、その下に阪神マン風（関西弁・前向き）で ①ええところ ②気になるところ ③おすすめの学習・声かけ を、児童本人が読んで前向きになれるように。学年に合わせて声かけを変える。なお、以下のデータは各児童とも今年度（4月1日〜現在）の全期間の集計です。直近だけでなく年度を通した成長・傾向を踏まえること。成果物（ポートフォリオ）には先生の評価（◎○△）と評価コメントも付くので、評価も踏まえてコメントすること。'),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE FY')
