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
    ('      function _recRenderPreview(d){',
     '      function _recEvalOpts(sel){ var o=[[\'\',\'評価なし\'],[\'◎\',\'◎\'],[\'○\',\'○\'],[\'△\',\'△\']]; var s=\'\'; for(var i=0;i<o.length;i++){ s+=\'<option value="\'+o[i][0]+\'"\'+(o[i][0]===(sel||\'\')?\' selected\':\'\')+\'>\'+o[i][1]+\'</option>\'; } return s; }\n      function _recRenderPreview(d){'),
    ('          h+=\'<textarea id="recRow_\'+i+\'_body" rows="3" class="w-full border rounded p-1 text-xs" placeholder="本文">\'+escH(r.body||\'\')+\'</textarea>\';',
     '          h+=\'<textarea id="recRow_\'+i+\'_body" rows="3" class="w-full border rounded p-1 text-xs" placeholder="本文（成果物）">\'+escH(r.body||\'\')+\'</textarea>\';\n          h+=\'<textarea id="recRow_\'+i+\'_reflection" rows="2" class="w-full border rounded p-1 text-xs mt-1" placeholder="振り返り（任意）">\'+escH(r.reflection||\'\')+\'</textarea>\';\n          h+=\'<div class="flex items-center gap-1 mt-1"><span class="text-[10px] text-slate-500">評価:</span><select id="recRow_\'+i+\'_eval" class="border rounded p-1 text-xs">\'+_recEvalOpts(r.evalRank)+\'</select><input id="recRow_\'+i+\'_evalc" class="border rounded p-1 text-xs flex-1" placeholder="評価コメント（任意）" value="\'+escH(r.evalComment||\'\')+\'"></div>\';'),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE PE')
