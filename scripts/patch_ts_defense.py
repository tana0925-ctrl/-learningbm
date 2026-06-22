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
    ('          window._recParsed=d;',
     '          window._recParsed=d;\n          try{ _matchRosterRows(d, cid); }catch(_e){}'),
    ('          var r=d.rows[i]; var warn=!r.matchedUserId; if(warn) unmatched++;\n          h+=\'<div class="border rounded-lg p-2 \'+(warn?\'bg-amber-50\':\'bg-slate-50\')+\'">\';\n          h+=\'<div class="flex items-center gap-1 flex-wrap mb-1">\';\n          h+=\'<span class="text-[10px] text-slate-400">読取: \'+escH(r.idRaw||\'\')+\' \'+escH(r.nameRaw||\'\')+(warn?\' <span class="text-amber-600">⚠未マッチ</span>\':\'\')+\'</span>\';',
     '          var r=d.rows[i]; var ms=r.matchStatus||(r.matchedUserId?\'auto\':\'none\'); if(ms===\'none\') unmatched++;\n          var _bg=(ms===\'auto\')?\'bg-slate-50\':(ms===\'cand\')?\'bg-amber-50\':\'bg-red-50\'; var _bd=(ms===\'auto\')?\'<span class="text-green-600">✓自動</span>\':(ms===\'cand\')?\'<span class="text-amber-600">≈候補(要確認)</span>\':\'<span class="text-red-600">⚠未マッチ</span>\';\n          h+=\'<div class="border rounded-lg p-2 \'+_bg+\'">\';\n          h+=\'<div class="flex items-center gap-1 flex-wrap mb-1">\';\n          h+=\'<span class="text-[10px] text-slate-400">読取: \'+escH(r.idRaw||\'\')+\' \'+escH(r.nameRaw||\'\')+\' \'+_bd+\'</span>\';'),
    ('          var r=d.rows[i]; var warn=!r.matchedUserId; if(warn) unmatched++;\n          h+=\'<tr class="\'+(warn?\'bg-amber-50\':\'\')+\'">\';\n          h+=\'<td class="p-1 font-bold text-slate-700">\'+escH(r.rawName||\'\')+(warn?\' <span class="text-[9px] text-amber-600">⚠未マッチ</span>\':\'\')+\'</td>\';',
     '          var r=d.rows[i]; var ms=r.matchStatus||(r.matchedUserId?\'auto\':\'none\'); if(ms===\'none\') unmatched++;\n          var _bd=(ms===\'auto\')?\' <span class="text-[9px] text-green-600">✓自動</span>\':(ms===\'cand\')?\' <span class="text-[9px] text-amber-600">≈候補(要確認)</span>\':\' <span class="text-[9px] text-red-600">⚠未マッチ</span>\';\n          h+=\'<tr class="\'+((ms===\'auto\')?\'\':(ms===\'cand\')?\'bg-amber-50\':\'bg-red-50\')+\'">\';\n          h+=\'<td class="p-1 font-bold text-slate-700">\'+escH(r.rawName||\'\')+_bd+\'</td>\';'),
]

patch_file('src/index.tsx', SRC_EDITS)
print('DONE QB')
