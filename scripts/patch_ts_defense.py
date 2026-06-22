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
    ("          rows.push({userId:uid, title:title, body:bodyTxt, reflection:refl, evalRank:er, evalComment:ec, subject:gv('recRow_'+i+'_subject'), unit:gv('recRow_'+i+'_unit'), day:gv('recRow_'+i+'_day')});",
     "          try{ _rememberAlias(cid, (d.rows[i]&&d.rows[i].nameRaw)||'', uid); }catch(_e){}\n          rows.push({userId:uid, title:title, body:bodyTxt, reflection:refl, evalRank:er, evalComment:ec, subject:gv('recRow_'+i+'_subject'), unit:gv('recRow_'+i+'_unit'), day:gv('recRow_'+i+'_day')});"),
    ("          rows.push({userId:uid, score:parseInt(score,10), comment:(d.rows[i].comment||'')});",
     "          try{ _rememberAlias(cid, (d.rows[i]&&d.rows[i].rawName)||'', uid); }catch(_e){}\n          rows.push({userId:uid, score:parseInt(score,10), comment:(d.rows[i].comment||'')});"),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE QC')
