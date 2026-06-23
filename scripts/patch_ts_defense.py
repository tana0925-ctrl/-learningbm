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
            print('NOT UNIQUE',data.count(old),repr(old[:40])); sys.exit(1)
        data=data.replace(old,new); print('ok',repr(old[:30]))
    with open(path,'w',encoding='utf-8',newline='') as f:
        f.write(data)

SRC_EDITS = [
    # 1) toggle UI: add SUGGEST checkbox
    ('<input type="checkbox" id="uniOptReflect" checked> 振り返り返却</label></div>',
     '<input type="checkbox" id="uniOptReflect" checked> 振り返り返却</label><label class="flex items-center gap-1"><input type="checkbox" id="uniOptSuggest" checked> 計画おすすめ</label></div>'),
    # 2) optSuggest var in copyUnifiedAi
    ("var optClass=_opt('uniOptClass'), optKarte=_opt('uniOptKarte'), optPlan=_opt('uniOptPlan'), optReflect=_opt('uniOptReflect');",
     "var optClass=_opt('uniOptClass'), optKarte=_opt('uniOptKarte'), optPlan=_opt('uniOptPlan'), optReflect=_opt('uniOptReflect'); var optSuggest=_opt('uniOptSuggest');"),
    # 3) SUGGEST instruction line
    ("        if(optReflect) L.push('・=== [REFLECT:児童ID] 名前 === … その子の「今週の振り返り」への返却コメント。がんばりを認めつつ次につながる一言を、やさしい言葉で。');",
     "        if(optReflect) L.push('・=== [REFLECT:児童ID] 名前 === … その子の「今週の振り返り」への返却コメント。がんばりを認めつつ次につながる一言を、やさしい言葉で。');\n        if(optSuggest) L.push('・=== [SUGGEST:児童ID] 名前 === … あなたは関西弁の応援キャラ「阪神マン」。この子の苦手・復習どきの単元・今週のテスト予定・学習履歴をもとに、今週の家庭学習の「おすすめ計画」を曜日ごとに何をどれくらい（合計3〜5項目）。子どもがそのまま参考にできるやさしい関西弁で。目印の行は変えずに残してください。');"),
    # 4) SUGGEST block generation (between karte blocks and plan/reflect)
    ("        for(var b=0;b<karteBlocks.length;b++){ L=L.concat(karteBlocks[b]); L.push(''); }\n        if(optPlan||optReflect){",
     "        for(var b=0;b<karteBlocks.length;b++){ L=L.concat(karteBlocks[b]); L.push(''); }\n        if(optSuggest){ if(st) st.textContent='おすすめ計画用データを収集中...'; for(var si=0;si<roster.length;si++){ var ss=roster[si]; var snm=(typeof resolveStudentName==='function')?resolveStudentName(ss.loginId,ss.name):(ss.name||''); var sid2=ss.loginId||ss.userId; var sblk=['=== [SUGGEST:'+sid2+'] '+snm+' ==='];\n          try{ var sres=await fetch('/api/teacher/student-full-analysis?studentId='+encodeURIComponent(ss.userId)); var sdata=await sres.json(); if(sdata&&sdata.ok){ var subs=(sdata.subjects||[]).slice(); subs.sort(function(a,b){ return (a.rate||0)-(b.rate||0); }); var weak=[]; for(var wi=0;wi<Math.min(subs.length,4);wi++){ if(subs[wi].rate!=null) weak.push((typeof _unitJa==='function'?_unitJa(subs[wi].unit):subs[wi].unit)+'('+subs[wi].rate+'%)'); } sblk.push('【苦手・復習どきの単元（正答率の低い順）】'); sblk.push(weak.length?weak.join('、'):'（データ不足）'); sblk=sblk.concat(_aiBodyLines(sdata)); } else { sblk.push('(データ取得失敗)'); } }catch(e){ sblk.push('(エラー)'); }\n          L=L.concat(sblk); L.push(''); if(st) st.textContent='おすすめ計画データ収集中...('+(si+1)+'/'+n+')'; } }\n        if(optPlan||optReflect){"),
    # 5) saveUnifiedAi: declare suggestC
    ("var blocks=_parseAiBlocks(raw); var karteC=[]; var planC=[]; var reflectC=[]; var classOverview=''; var unmatched=[];",
     "var blocks=_parseAiBlocks(raw); var karteC=[]; var planC=[]; var reflectC=[]; var suggestC=[]; var classOverview=''; var unmatched=[];"),
    # 6) saveUnifiedAi: routing add SUGGEST
    ("if(typ==='PLAN'){ planC.push({studentId:uid,comment:body}); } else if(typ==='REFLECT'){ reflectC.push({studentId:uid,comment:body}); } else { karteC.push({studentId:uid,comment:body}); }",
     "if(typ==='PLAN'){ planC.push({studentId:uid,comment:body}); } else if(typ==='REFLECT'){ reflectC.push({studentId:uid,comment:body}); } else if(typ==='SUGGEST'){ suggestC.push({studentId:uid,comment:body}); } else { karteC.push({studentId:uid,comment:body}); }"),
    # 7) saveUnifiedAi: POST suggestC
    ("if(reflectC.length){ try{ var fr=await fetch('/api/teacher/reflection-comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({weekKey:wk,comments:reflectC})}); var fd=await fr.json(); if(fd&&fd.ok) msgs.push('振り返り返却'+fd.saved+'人'); }catch(e){} }",
     "if(reflectC.length){ try{ var fr=await fetch('/api/teacher/reflection-comments',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({weekKey:wk,comments:reflectC})}); var fd=await fr.json(); if(fd&&fd.ok) msgs.push('振り返り返却'+fd.saved+'人'); }catch(e){}\n        if(suggestC.length){ try{ var sgr=await fetch('/api/teacher/plan-suggestions',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({weekKey:wk,comments:suggestC})}); var sgd=await sgr.json(); if(sgd&&sgd.ok) msgs.push('おすすめ計画'+sgd.saved+'人'); }catch(e){} }"),
    # 8) weekly-plan-status: merge planSuggestion
    ("  let planAiComment: any = null\n  try { const _pc = await c.env.DB.prepare('SELECT plan_ai_comment as planAiComment FROM student_weekly_plans WHERE user_id=? AND week_key=?').bind(u.id, weekKey).first<any>(); if (_pc) planAiComment = _pc.planAiComment || null } catch {}\n  const status2 = row ? { ...row, planAiComment } : (planAiComment ? { planAiComment } : null)",
     "  let planAiComment: any = null\n  try { const _pc = await c.env.DB.prepare('SELECT plan_ai_comment as planAiComment FROM student_weekly_plans WHERE user_id=? AND week_key=?').bind(u.id, weekKey).first<any>(); if (_pc) planAiComment = _pc.planAiComment || null } catch {}\n  let planSuggestion: any = null\n  try { const _ps = await c.env.DB.prepare('SELECT plan_suggestion as planSuggestion FROM student_weekly_plans WHERE user_id=? AND week_key=?').bind(u.id, weekKey).first<any>(); if (_ps) planSuggestion = _ps.planSuggestion || null } catch {}\n  const status2 = row ? { ...row, planAiComment, planSuggestion } : ((planAiComment || planSuggestion) ? { planAiComment, planSuggestion } : null)"),
    # 9) new endpoint plan-suggestions (before weekly-plans GET)
    ("app.get('/api/teacher/weekly-plans', async (c) => {\n  const u = c.get('user')\n  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')\n  const classId = c.req.query('classId')\n  const weekKey = c.req.query('weekKey') || getWeekKey()",
     "app.post('/api/teacher/plan-suggestions', async (c) => {\n  const u = c.get('user'); if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')\n  try { await c.env.DB.prepare('ALTER TABLE student_weekly_plans ADD COLUMN plan_suggestion TEXT').run() } catch {}\n  try { await c.env.DB.prepare('ALTER TABLE student_weekly_plans ADD COLUMN plan_suggestion_at TEXT').run() } catch {}\n  const body = await c.req.json<any>().catch(() => null)\n  if (!body || !Array.isArray(body.comments)) return jsonError(c, 400, 'invalid')\n  const weekKey = String(body.weekKey || getWeekKey()).slice(0, 10)\n  let saved = 0\n  for (const it of body.comments) {\n    const sid = String(it.studentId || '')\n    const comment = String(it.comment || '').slice(0, 4000)\n    if (!sid || !comment) continue\n    const own = u.role === 'admin'\n      ? await c.env.DB.prepare('SELECT 1 FROM class_members WHERE user_id=? LIMIT 1').bind(sid).first<any>()\n      : await c.env.DB.prepare('SELECT 1 FROM class_members cm JOIN classes cl ON cl.id=cm.class_id AND cl.teacher_id=? WHERE cm.user_id=? LIMIT 1').bind(u.id, sid).first<any>()\n    if (!own) continue\n    const ex = await c.env.DB.prepare('SELECT id FROM student_weekly_plans WHERE user_id=? AND week_key=? LIMIT 1').bind(sid, weekKey).first<any>()\n    if (ex) {\n      await c.env.DB.prepare(\"UPDATE student_weekly_plans SET plan_suggestion=?, plan_suggestion_at=datetime('now') WHERE user_id=? AND week_key=?\").bind(comment, sid, weekKey).run()\n    } else {\n      await c.env.DB.prepare(\"INSERT INTO student_weekly_plans (user_id, week_key, plans_json, updated_at, plan_suggestion, plan_suggestion_at) VALUES (?,?,?,?,?,datetime('now'))\").bind(sid, weekKey, '{}', Date.now(), comment).run()\n    }\n    saved++\n  }\n  return c.json({ ok: true, saved })\n})\n\napp.get('/api/teacher/weekly-plans', async (c) => {\n  const u = c.get('user')\n  if (!u || (u.role !== 'teacher' && u.role !== 'admin')) return jsonError(c, 403, 'forbidden')\n  const classId = c.req.query('classId')\n  const weekKey = c.req.query('weekKey') || getWeekKey()"),
]

PUB_EDITS_RAW = [
    ('  <div id="hwPlanArea" class="bg-white border-2 border-emerald-300 rounded-xl p-3 space-y-2 hidden">',
     '  <div id="hwPlanSuggestBox" class="hidden mb-2"></div>\n  <div id="hwPlanArea" class="bg-white border-2 border-emerald-300 rounded-xl p-3 space-y-2 hidden">'),
    ('    if(isPastWeek){\n      const notice = document.getElementById(\'hwRewardNotice\');\n      if(notice){ notice.classList.add(\'hidden\'); notice.innerHTML = \'\'; }\n    }',
     '    if(isPastWeek){\n      const notice = document.getElementById(\'hwRewardNotice\');\n      if(notice){ notice.classList.add(\'hidden\'); notice.innerHTML = \'\'; }\n      const sugBoxP = document.getElementById(\'hwPlanSuggestBox\');\n      if(sugBoxP){ sugBoxP.classList.add(\'hidden\'); sugBoxP.innerHTML = \'\'; }\n    }'),
    ('      const statusRes = await fetch(\'/api/student/weekly-plan-status?weekKey=\'+encodeURIComponent(weekKey)).then(r=>r.json()).catch(()=>null);\n      const st = statusRes && statusRes.status;',
     '      const statusRes = await fetch(\'/api/student/weekly-plan-status?weekKey=\'+encodeURIComponent(weekKey)).then(r=>r.json()).catch(()=>null);\n      const st = statusRes && statusRes.status;\n      const sugBox = document.getElementById(\'hwPlanSuggestBox\');\n      if(sugBox){ if(st && st.planSuggestion){ sugBox.innerHTML = \'<div class="bg-yellow-50 border-2 border-yellow-400 rounded-xl p-3 space-y-1"><div class="font-bold text-yellow-900 text-sm">\\uD83D\\uDC2F 今週の阪神マンのおすすめ</div><div class="text-xs text-slate-700 whitespace-pre-wrap">\'+escapeHtml(st.planSuggestion)+\'</div><div class="text-[10px] text-slate-400">\\u203B あくまで参考。自分で計画を立ててみよう！</div></div>\'; sugBox.classList.remove(\'hidden\'); } else { sugBox.innerHTML=\'\'; sugBox.classList.add(\'hidden\'); } }'),
]
PUB_EDITS = [(o.replace('\n','\r\n'), n.replace('\n','\r\n')) for (o,n) in PUB_EDITS_RAW]

patch_file('src/index.tsx', SRC_EDITS)
patch_file('public/index.html', PUB_EDITS)
print('DONE SUGGEST')
