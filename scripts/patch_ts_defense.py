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
        data=data.replace(old,new); print('ok',repr(old[:34]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    ("        L.push('本文:');\n        L.push('（児童が書いた文章をそのまま。複数行でよい）');\n        L.push('');\n        L.push('【ルール】児童IDは名簿のログインID。わからなければ [名前] のように名前を入れる。1人ずつ「=== [..] .. ===」で区切る。本文は「本文:」の次の行からブロックの終わり（次の===）まで。要約や講評を勝手に足さず、児童の記述を尊重する。読み取れない児童は飛ばしてよい。');",
     "        L.push('本文:');\n        L.push('（児童が書いた文章・成果物をそのまま。複数行でよい）');\n        L.push('振り返り: （児童の振り返りがあれば。なければ空欄。複数行でよい）');\n        L.push('評価: （先生の評価があれば ◎ / ○ / △ のどれか。なければ空欄）');\n        L.push('評価コメント: （先生の評価コメントがあれば。なければ空欄）');\n        L.push('');\n        L.push('【ルール】児童IDは名簿のログインID。わからなければ [名前] のように名前を入れる。1人ずつ「=== [..] .. ===」で区切る。本文・振り返りはそれぞれの見出しの次の行から次の見出しか次の===まで。成果物と振り返りがセットなら両方入れる。評価・振り返りが無ければ空欄でよい。要約や講評を勝手に足さず、児童の記述を尊重する。読み取れない児童は飛ばしてよい。');"),
    ("          var uid=gv('recRow_'+i+'_user');\n          var title=gv('recRow_'+i+'_title'); var bodyTxt=gv('recRow_'+i+'_body');\n          if(!uid){ skipped++; continue; }\n          if((!title||!title.trim())&&(!bodyTxt||!bodyTxt.trim())){ skipped++; continue; }\n          rows.push({userId:uid, title:title, body:bodyTxt, subject:gv('recRow_'+i+'_subject'), unit:gv('recRow_'+i+'_unit'), day:gv('recRow_'+i+'_day')});",
     "          var uid=gv('recRow_'+i+'_user');\n          var title=gv('recRow_'+i+'_title'); var bodyTxt=gv('recRow_'+i+'_body');\n          var refl=gv('recRow_'+i+'_reflection'); var er=gv('recRow_'+i+'_eval'); var ec=gv('recRow_'+i+'_evalc');\n          if(!uid){ skipped++; continue; }\n          if((!title||!title.trim())&&(!bodyTxt||!bodyTxt.trim())&&(!refl||!refl.trim())&&!er&&(!ec||!ec.trim())){ skipped++; continue; }\n          rows.push({userId:uid, title:title, body:bodyTxt, reflection:refl, evalRank:er, evalComment:ec, subject:gv('recRow_'+i+'_subject'), unit:gv('recRow_'+i+'_unit'), day:gv('recRow_'+i+'_day')});"),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE PD')
