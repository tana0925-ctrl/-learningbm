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
    ("            for(var ri=0; ri<rcs.length; ri++){ var rc=rcs[ri]; pf.push({kind:(rc.type||'other'), day:(rc.dayKey||''), subject:(rc.subject||''), unit:(rc.unit||''), title:(rc.title||''), body:(rc.body||'')}); }",
     "            for(var ri=0; ri<rcs.length; ri++){ var rc=rcs[ri]; pf.push({kind:(rc.type||'other'), day:(rc.dayKey||''), subject:(rc.subject||''), unit:(rc.unit||''), title:(rc.title||''), body:(rc.body||''), reflection:(rc.reflection||''), evalRank:(rc.evalRank||''), evalComment:(rc.evalComment||'')}); }"),
    ('                if(it.body && it.body.trim()){ html += \'<div class="mt-1 text-xs text-slate-600 whitespace-pre-wrap border-t border-slate-200 pt-1">\'+escH(it.body)+\'</div>\'; }',
     '                if(it.body && it.body.trim()){ html += \'<div class="mt-1 text-xs text-slate-600 whitespace-pre-wrap border-t border-slate-200 pt-1">\'+escH(it.body)+\'</div>\'; }\n                if(it.reflection && it.reflection.trim()){ html += \'<div class="mt-1 text-xs text-amber-700 whitespace-pre-wrap"><span class="font-bold">🪞 振り返り:</span> \'+escH(it.reflection)+\'</div>\'; }\n                if(it.evalRank || (it.evalComment && it.evalComment.trim())){ var _ec=(it.evalRank===\'◎\')?\'bg-pink-100 text-pink-700\':(it.evalRank===\'○\')?\'bg-green-100 text-green-700\':(it.evalRank===\'△\')?\'bg-orange-100 text-orange-700\':\'bg-slate-100 text-slate-600\'; html += \'<div class="mt-1 text-xs"><span class="\'+_ec+\' px-1.5 rounded font-bold">評価 \'+escH(it.evalRank||\'-\')+\'</span>\'+((it.evalComment&&it.evalComment.trim())?\' <span class="text-slate-600">\'+escH(it.evalComment)+\'</span>\':\'\')+\'</div>\'; }'),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE PG')
