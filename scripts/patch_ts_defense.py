import sys

def patch_file(path, edits):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        data = f.read()
    for old, new in edits:
        if new in data and old not in data:
            print('skip (already applied):', repr(old[:40]))
            continue
        if old not in data:
            print('ANCHOR NOT FOUND in', path, '::', repr(old[:60]))
            sys.exit(1)
        if data.count(old) != 1:
            print('ANCHOR NOT UNIQUE', data.count(old), repr(old[:60]))
            sys.exit(1)
        data = data.replace(old, new)
        print('ok', path, '::', repr(old[:40]))
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(data)

PUB_EDITS = [
    # 1) CURRICULUM lookup helper + filter to only launchable (in-curriculum) units
    ("      var list=(d.suggestions||[]).filter(function(s){ return s.launchable && (typeof _isNewCurrId!=='function' || _isNewCurrId(s.unit)); }).slice(0,4);",
     "      function _curUnitById(id){ try{ if(typeof CURRICULUM==='undefined'||!CURRICULUM) return null; for(var sk in CURRICULUM){ var sj=CURRICULUM[sk]; if(!sj||!sj.grades) continue; for(var gk in sj.grades){ var us=sj.grades[gk]&&sj.grades[gk].units; if(!us) continue; for(var qi=0;qi<us.length;qi++){ if(us[qi]&&us[qi].id===id) return us[qi]; } } } }catch(e){} return null; } var list=(d.suggestions||[]).map(function(s){ s.__u=_curUnitById(s.unit); return s; }).filter(function(s){ return s.launchable && s.__u; }).slice(0,4);"),
    # 2) label: prefer the curriculum unit's own name
    ("        var nm=null; try{ if(window.UNIT_DISPLAY&&window.UNIT_DISPLAY[s.unit]&&window.UNIT_DISPLAY[s.unit].name) nm=window.UNIT_DISPLAY[s.unit].name; }catch(e){} if(nm==null){ nm=(typeof _modeLabel==='function')?_modeLabel(s.unit):s.unit; }",
     "        var nm=(s.__u&&s.__u.name)?s.__u.name:null; if(nm==null){ try{ if(window.UNIT_DISPLAY&&window.UNIT_DISPLAY[s.unit]&&window.UNIT_DISPLAY[s.unit].name) nm=window.UNIT_DISPLAY[s.unit].name; }catch(e){} } if(nm==null){ nm=(typeof _modeLabel==='function')?_modeLabel(s.unit):s.unit; }"),
    # 3) onclick: set window.__currUnit so the curriculum quiz actually launches
    ("        btn.onclick=function(){ try{ trySetMode('training'); }catch(e){} try{ selectTrainingMode(s.unit); }catch(e){} };",
     "        btn.onclick=function(){ try{ trySetMode('training'); }catch(e){} try{ if(s.__u) window.__currUnit=s.__u; }catch(e){} try{ selectTrainingMode(s.unit); }catch(e){} };"),
]

patch_file('public/index.html', PUB_EDITS)
print('DONE')
