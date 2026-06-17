import sys

# ---- 1) server: accept battleType 'shoot' (src/index.tsx) ----
tp='src/index.tsx'
ts=open(tp,'rb').read().decode('utf-8')
old_ts="  const battleType = (body.battleType === 'egg') ? 'egg' : (body.battleType === 'gym') ? 'gym' : 'normal'"
new_ts="  const battleType = (body.battleType === 'egg') ? 'egg' : (body.battleType === 'gym') ? 'gym' : (body.battleType === 'shoot') ? 'shoot' : 'normal'"
if "battleType === 'shoot') ? 'shoot'" in ts:
    print("server: already patched", file=sys.stderr)
elif old_ts in ts:
    ts=ts.replace(old_ts,new_ts,1)
    open(tp,'wb').write(ts.encode('utf-8'))
    print("server: patched", file=sys.stderr)
else:
    print("server: ANCHOR MISSING", file=sys.stderr); sys.exit(1)

# ---- 2) index.html: radio + launch branch (CRLF, binary-safe) ----
hp='public/index.html'
h=open(hp,'rb').read().decode('utf-8')
changed=False

sR="""<label class="text-xs flex items-center gap-1 mb-2">\r\n          <input name="rtBattleType" type="radio" value="gym" onchange="document.getElementById('rtGradeSubjectArea').style.display='none'"/> ジムバトル形式\r\n        </label>"""
rR=sR+"""\r\n        <label class="text-xs flex items-center gap-1 mb-2">\r\n          <input name="rtBattleType" type="radio" value="shoot" onchange="document.getElementById('rtGradeSubjectArea').style.display='none'"/> ⌨ タイプシュート形式\r\n        </label>"""
if 'value="shoot"' in h:
    print("radio: already", file=sys.stderr)
elif sR in h:
    h=h.replace(sR,rR,1); changed=True; print("radio: patched", file=sys.stderr)
else:
    print("radio: ANCHOR MISSING", file=sys.stderr); sys.exit(1)

sB="""} else {\r\n                    battle.friendGym = false;\r\n                    battle.pveArea = _rt.area || 'rounding';"""
rB="""} else if (_rt.battleType === 'shoot') {\r\n                    _rt.isBattling = true;\r\n                    try { if (typeof window.startTypeShootVS === 'function') window.startTypeShootVS(_rt.roomId, _rt.myRole, _rt.opponentParty, _rt.opponentName); } catch(e) { console.error('shoot start error', e); }\r\n                } else {\r\n                    battle.friendGym = false;\r\n                    battle.pveArea = _rt.area || 'rounding';"""
if "_rt.battleType === 'shoot'" in h:
    print("branch: already", file=sys.stderr)
elif sB in h:
    h=h.replace(sB,rB,1); changed=True; print("branch: patched", file=sys.stderr)
else:
    print("branch: ANCHOR MISSING", file=sys.stderr); sys.exit(1)

if changed:
    open(hp,'wb').write(h.encode('utf-8'))
    print("index.html written", file=sys.stderr)
print("DONE", file=sys.stderr)
