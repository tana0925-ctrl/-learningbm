import sys
def patch_file(path, edits):
    data=open(path,'rb').read().decode('utf-8')
    for old,new,g in edits:
        if new in data and old not in data:
            print('skip '+g, file=sys.stderr); continue
        c=data.count(old)
        if c!=1:
            print('ANCHOR x'+str(c)+' '+g, file=sys.stderr); sys.exit(1)
        data=data.replace(old,new,1)
    open(path,'wb').write(data.encode('utf-8'))
    print('ok', file=sys.stderr)
EDITS=[
  ('      function copyTestPrompt(){', "      function _tsDispName(rm){ return (typeof resolveStudentName==='function')?resolveStudentName(rm.loginId, rm.name):(rm.name||rm.loginId||''); }\n      function _tsRematch(d){\n        var roster=d.roster||[]; var idx={};\n        for(var j=0;j<roster.length;j++){ var rm=roster[j]; var dn=_tsDispName(rm); if(dn) idx[_normId(dn)]=rm; if(rm.name) idx[_normId(rm.name)]=rm; if(rm.loginId) idx[_normId(rm.loginId)]=rm; }\n        for(var i=0;i<d.rows.length;i++){ var r=d.rows[i]; var key=_normId(r.rawName||''); var hit=idx[key]||null;\n          if(!hit){ for(var k=0;k<roster.length;k++){ var rm2=roster[k]; var dn2=_normId(_tsDispName(rm2)); if(dn2 && (dn2.indexOf(key)>=0||key.indexOf(dn2)>=0)){ hit=rm2; break; } } }\n          r.matchedUserId = hit? hit.userId : null; r.matchedName = hit? _tsDispName(hit) : null;\n        }\n      }\n      function copyTestPrompt(){", 'T11_rematch_helpers'),
  ("          window._tsParsed=d;\n          if(st) st.textContent='✓ '+d.rows.length+'件を読み取りました。内容を確認して保存してください';\n          _tsRenderPreview(d);", "          _tsRematch(d);\n          window._tsParsed=d;\n          if(st) st.textContent='✓ '+d.rows.length+'件を読み取りました。内容を確認して保存してください';\n          _tsRenderPreview(d);", 'T12_call_rematch'),
  ('+escH(rm.name||rm.loginId||rm.userId)+', '+escH(_tsDispName(rm))+', 'T13_opts_label'),
]
patch_file('src/index.tsx', EDITS)
print('DONE', file=sys.stderr)
