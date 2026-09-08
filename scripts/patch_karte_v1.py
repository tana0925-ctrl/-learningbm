#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_karte_v1.py --- 家庭学習カルテ 2026-09 改修

K1 印刷カルテを「直前に終わった週（＝先週）」に切り替え、見出しに日付を入れる。
   カルテは月曜に印刷して配るため。window._faKarteBaseDate に 'YYYY-MM-DD' を
   入れると、その日から見た直前の週に手で切り替えられる。
K2 バグ修正: 「今週のふりかえり」がこれまで一度も表示されていなかった。
   structured_reflections.week_key は '2026-W37' 形式なのに、日付形式
   （'2026-09-01'）と比べていたため、照合が絶対に成立していなかった。
K3 A4裏表に収める。同じ単元が3か所に出ていた重複を整理する。
   ・横棒グラフ3本（とくい／のばす／復習）→ 色分けした1本に統合
   ・「とくいな教科」のリスト（グラフと完全重複）を削除
   ・「これから もっと のびるところ」を「どう学ぶといいか」へ寄せる
   ・「今年度の積み上げ」5枚のカード → 1行に圧縮
   ・「さいきんのふりかえり」を削除（先週分に一本化）
   ・中身が空の節は出さない
   ※ グラフは消していない（レーダー・月別棒・ドーナツはそのまま残す）
K4 「今週の一手」を、先生が④で確認した「今週のおすすめ」に差し替える。
   無いときは従来の自動生成文にフォールバックする。
K5 student-full-analysis に planSuggestion と MI（自己認識の材料）を追加。
K6 teacher-ai.js のキャッシュを v=7 に。

public/index.html は触りません。
"""
import io, json, os, sys

NEW_KARTE = r"""function _buildKarteHtml(){ var d=window._faData||{}; var ov=d.overview||{}; var name=window._faName||'あなた'; var esc=function(s){ return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }; var subjects=(d.subjects||[]).slice(); var _sg=(d.student&&d.student.grade)||null; var _cl=function(u){return _gradeClass(_sg,_unitGrade(u));}; var good=subjects.filter(function(s){return s.rate>=80&&s.total>=20&&_cl(s.unit)==='same';}).sort(function(a,b){return (b.rate-a.rate)||(b.total-a.total);}).slice(0,5); if(!good.length){ good=subjects.filter(function(s){return s.rate>=80&&s.total>=20&&_cl(s.unit)!=='review';}).sort(function(a,b){return (b.rate-a.rate)||(b.total-a.total);}).slice(0,5); } var _rev=subjects.filter(function(s){return _cl(s.unit)==='review'&&s.total>=10;}).sort(function(a,b){return a.rate-b.rate;}); var reviewGood=_rev.filter(function(s){return s.rate>=80;}).slice(0,3); var reviewWeak=_rev.filter(function(s){return s.rate<70;}).slice(0,3); var ahead=subjects.filter(function(s){return _cl(s.unit)==='ahead'&&s.rate>=70&&s.total>=10;}).sort(function(a,b){return (b.rate-a.rate);}).slice(0,3); var grow=subjects.filter(function(s){return s.rate<70&&s.total>=5&&_cl(s.unit)==='same';}).sort(function(a,b){return a.rate-b.rate;}).slice(0,3); if(!grow.length){ grow=subjects.filter(function(s){return s.rate<70&&s.total>=5&&_cl(s.unit)!=='review';}).sort(function(a,b){return a.rate-b.rate;}).slice(0,3); } var period=(ov.firstDate? (ov.firstDate+' 〜 '+ov.lastDate) : ''); var hours=Math.round((ov.totalMinutes||0)/60); var praise='よく がんばっているね！この調子で つづけていこう！'; if((ov.maxStreak||0)>=5) praise='なんと '+ov.maxStreak+'日も つづけて べんきょうできたね！すごい力だよ！'; else if((ov.totalSubmissions||0)>=10) praise='たくさん べんきょうを つづけているね！その努力は きっと力になるよ！'; var H=[]; H.push('<!doctype html><html lang="ja"><head><meta charset="utf-8"><title>家庭学習カルテ</title>'); H.push('<style>'); H.push('@page{size:A4;margin:12mm;} *{box-sizing:border-box;-webkit-print-color-adjust:exact;print-color-adjust:exact;}'); H.push('body{font-family:"Hiragino Maru Gothic ProN","Hiragino Sans","Yu Gothic","Meiryo",sans-serif;color:#334155;margin:0;font-size:13px;line-height:1.6;}'); H.push('.wrap{max-width:186mm;margin:0 auto;}'); H.push('.head{text-align:center;background:linear-gradient(135deg,#fef3c7,#fde68a);border-radius:16px;padding:14px;margin-bottom:12px;}'); H.push('.head h1{margin:0;font-size:24px;color:#b45309;} .head .nm{font-size:18px;font-weight:800;color:#92400e;margin-top:4px;} .head .pd{font-size:12px;color:#a16207;margin-top:2px;}'); H.push('.sec{border:2px solid #e2e8f0;border-radius:14px;padding:13px 15px;margin-bottom:13px;} .sec h2{margin:0 0 8px;font-size:16px;}'); H.push('.chips{display:flex;flex-wrap:wrap;gap:8px;} .chip{background:#eff6ff;border-radius:10px;padding:8px 12px;text-align:center;flex:1;min-width:84px;} .chip .v{font-size:20px;font-weight:900;color:#2563eb;} .chip .l{font-size:10px;color:#64748b;}'); H.push('.msg{background:#ecfdf5;border-radius:10px;padding:9px 12px;margin-top:9px;color:#047857;font-weight:700;}'); H.push('.good .b{font-weight:800;color:#16a34a;} .grow .it{background:#fff7ed;border-radius:10px;padding:8px 11px;margin:6px 0;} .grow .t{font-weight:800;color:#ea580c;} .grow .tip{font-size:12px;color:#7c2d12;margin-top:2px;}'); H.push('.refl{font-size:12px;color:#475569;} .refl li{margin:3px 0;} .note{border:2px dashed #cbd5e1;border-radius:12px;min-height:70px;padding:10px;} ul{margin:4px 0;padding-left:20px;} .foot{text-align:center;font-size:10px;color:#cbd5e1;margin-top:6px;}'); H.push('.oneline{font-size:12px;color:#475569;} .lg{color:#94a3b8;font-size:11px;margin-top:5px;}'); H.push('</style></head><body><div class="wrap">'); H.push('<div class="head"><h1>📒 家庭学習カルテ</h1><div class="nm">'+esc(name)+' さん'+(_sg?'（'+_sg+'年生）':'')+'</div>'+(period?'<div class="pd">'+esc(period)+'</div>':'')+'</div>'); /* 📅 2026-09 方針: カルテは月曜に印刷して配るため「直前に終わった週（＝先週）」を主役にする（先生の指示）。 */ /* window._faKarteBaseDate に 'YYYY-MM-DD' を入れると、その日から見た直前の週に切り替えられる。 */ var _kJst=function(){ var n=new Date(); return new Date(n.getTime()+n.getTimezoneOffset()*60000+9*3600000); }; var _kFmt=function(dt){ var p=function(x){return (x<10?'0':'')+x;}; return dt.getFullYear()+'-'+p(dt.getMonth()+1)+'-'+p(dt.getDate()); }; var _kBase=(function(){ var s=String(window._faKarteBaseDate||''); var m=s.match(/^(\d{4})-(\d{2})-(\d{2})$/); if(m) return new Date(Number(m[1]),Number(m[2])-1,Number(m[3])); return _kJst(); })(); var _kWd=(_kBase.getDay()+6)%7; var _kMon=new Date(_kBase.getTime()-_kWd*86400000-7*86400000); var _kDays=[]; for(var kd=0;kd<5;kd++){ _kDays.push(_kFmt(new Date(_kMon.getTime()+kd*86400000))); } var _kJa=function(s){ var p=String(s).split('-'); return Number(p[1])+'月'+Number(p[2])+'日'; }; var _kIso=function(dt){ var x=new Date(dt.getFullYear(),dt.getMonth(),dt.getDate()); var dn=(x.getDay()+6)%7; x.setDate(x.getDate()-dn+3); var f=new Date(x.getFullYear(),0,4); var fn=(f.getDay()+6)%7; f.setDate(f.getDate()-fn+3); var w=1+Math.round((x.getTime()-f.getTime())/(7*86400000)); return x.getFullYear()+'-W'+(w<10?'0'+w:''+w); }; var _kWk=_kIso(_kMon); var _kSub={}; (d.recentSubmissions||[]).forEach(function(s){ if(s&&s.day_key) _kSub[s.day_key]=s; }); var _kDone=0,_kMin=0,_kCells='',_kVoice=[]; var _kDn=['月','火','水','木','金']; for(var kd2=0;kd2<5;kd2++){ var _kk=_kDays[kd2]; var _ks=_kSub[_kk]; var _kw=_ks?((_ks.end_weather==='sun')?'☀️':(_ks.end_weather==='cloud')?'☁️':(_ks.end_weather==='rain')?'🌧️':'⭕'):'・'; if(_ks){ _kDone++; _kMin+=(_ks.minutes||0); if(_ks.weather_reason) _kVoice.push(_kDn[kd2]+' '+_ks.weather_reason); } _kCells+='<div style="text-align:center;flex:1;min-width:44px"><div style="font-size:11px;color:#64748b;font-weight:700">'+_kDn[kd2]+'</div><div style="font-size:24px;line-height:1.2">'+_kw+'</div></div>'; } /* 🐛 2026-09 修正: 振り返りの週キーは '2026-W37' 形式。以前は日付形式と比べていたため一度も表示されなかった。 */ var _kRef=null; (d.reflections||[]).forEach(function(r){ if(!r) return; var rk=String(r.weekKey||''); if(rk===_kWk||rk===_kDays[0]) _kRef=r; }); var _kH='<div class="sec" style="border-color:#fcd34d;background:#fffbeb"><h2>📅 '+_kJa(_kDays[0])+'〜'+_kJa(_kDays[4])+'のようす</h2>'; _kH+='<div style="display:flex;gap:6px;align-items:flex-end;margin-bottom:6px">'+_kCells+'</div>'; _kH+='<div style="font-size:12px;color:#92400e;font-weight:700">この週は 5日のうち '+_kDone+'日 とりくめました（合計 '+_kMin+'分）</div>'; if(_kVoice.length){ _kH+='<div style="margin-top:8px"><div style="font-size:11px;font-weight:800;color:#b45309">🗣 自分のことば</div><ul class="refl">'; for(var kv=0;kv<_kVoice.length;kv++){ _kH+='<li>'+esc(_kVoice[kv])+'</li>'; } _kH+='</ul></div>'; } if(_kRef&&(_kRef.goodPoint||_kRef.improvePoint||_kRef.nextAction)){ _kH+='<div style="margin-top:6px;font-size:12px;color:#475569"><div style="font-size:11px;font-weight:800;color:#b45309">📝 この週のふりかえり</div>'; if(_kRef.goodPoint) _kH+='<div>よかったこと … '+esc(_kRef.goodPoint)+'</div>'; if(_kRef.improvePoint) _kH+='<div>もうすこしなこと … '+esc(_kRef.improvePoint)+'</div>'; if(_kRef.nextAction) _kH+='<div>つぎにやること … '+esc(_kRef.nextAction)+'</div>'; _kH+='</div>'; } _kH+='<div style="margin-top:9px;border:2px dashed #fcd34d;border-radius:10px;min-height:58px;padding:8px"><div style="font-size:10px;color:#b45309;font-weight:700">✏️ 先生から</div></div>'; _kH+='</div>'; H.push(_kH); /* 🌟 2026-09: 今年度の積み上げは5枚のカードをやめて1行に圧縮（先生の判断）。 */ H.push('<div class="sec" style="padding:10px 15px"><div class="oneline"><b style="font-size:14px">🌟 今年度の積み上げ</b> … 提出 '+(ov.totalSubmissions||0)+'回 ／ 合計 '+hours+'時間 ／ 1日の平均 '+(ov.avgMinutes||0)+'分 ／ 最長れんぞく '+(ov.maxStreak||0)+'日 ／ きもち☀️ '+(ov.sunRate||0)+'%</div><div class="msg">'+praise+'</div></div>'); var _areas=[{key:'jp',label:'国語'},{key:'math',label:'算数'},{key:'sci',label:'理科'},{key:'soc',label:'社会'}]; var _agg=function(arr){ var tot=0,cor=0; for(var ai=0;ai<arr.length;ai++){ var it=arr[ai]; var cc=(typeof it.correct==='number')?it.correct:Math.round((it.rate||0)/100*(it.total||0)); tot+=(it.total||0); cor+=cc; } return tot? Math.round(cor/tot*100):null; }; var _radar=_areas.map(function(a){ var same=subjects.filter(function(s){ return _subjectArea(s.unit)===a.key && _cl(s.unit)==='same'; }); var all=subjects.filter(function(s){ return _subjectArea(s.unit)===a.key; }); var v=_agg(same); var nd=false; if(v==null){ v=_agg(all); } if(v==null){ v=0; nd=true; } return {label:a.label, value:v, noData:nd}; }); var _mt=(d.monthlyTrends||[]).slice(-6); var _barItems=_mt.map(function(m){ return {label:String(m.month||'').slice(5), value:m.count||0}; }); H.push('<div class="sec"><h2>📊 今年度の学習の見える化</h2><div style="display:flex;flex-wrap:wrap;gap:8px;align-items:flex-start;justify-content:space-around">'); H.push('<div style="text-align:center"><div style="font-size:11px;font-weight:700;color:#475569;margin-bottom:2px">教科の定着（いまの学年）</div>'+_kRadar(_radar)+'</div>'); H.push('<div style="text-align:center"><div style="font-size:11px;font-weight:700;color:#475569;margin-bottom:2px">月ごとの提出回数</div>'+_kBars(_barItems)+'</div>'); H.push('<div style="text-align:center"><div style="font-size:11px;font-weight:700;color:#475569;margin-bottom:2px">きもちの割合</div>'+_kDonut(ov.sunCount,ov.cloudCount,ov.rainCount)+'</div>'); H.push('</div>'); /* 📌 2026-09: 同じ単元が「横棒3本」「どう学ぶといいか」「のびるところ」の3か所に出ていたため、 */ /* グラフは1本に統合し、文章側（のびるところ）は「どう学ぶといいか」へ寄せた。 */ var _mix=[]; for(var gi=0;gi<good.length&&_mix.length<2;gi++){ _mix.push({label:_unitJa(good[gi].unit),rate:good[gi].rate,total:good[gi].total,color:'#22c55e'}); } for(var wi=0;wi<grow.length&&_mix.length<5;wi++){ _mix.push({label:_unitJa(grow[wi].unit),rate:grow[wi].rate,total:grow[wi].total,color:'#f97316'}); } for(var ri=0;ri<reviewWeak.length&&_mix.length<6;ri++){ var _rgn=_unitGrade(reviewWeak[ri].unit); _mix.push({label:(_rgn?_rgn+'年 ':'')+_unitJa(reviewWeak[ri].unit),rate:reviewWeak[ri].rate,total:reviewWeak[ri].total,color:'#3b82f6'}); } if(_mix.length){ var _mw=520,_mlw=150,_mbx=_mlw+6,_mbw=_mw-_mbx-92,_mrh=24,_mh=_mix.length*_mrh+4; var _ms='<svg width="'+_mw+'" height="'+_mh+'" viewBox="0 0 '+_mw+' '+_mh+'" xmlns="http://www.w3.org/2000/svg" style="max-width:100%">'; for(var mi=0;mi<_mix.length;mi++){ var _mit=_mix[mi]; var _mr=Math.max(0,Math.min(100,_mit.rate||0)); var _my=mi*_mrh+_mrh/2; var _mbv=Math.max(_mbw*_mr/100,2); var _mlb=String(_mit.label||''); if(_mlb.length>12) _mlb=_mlb.slice(0,11)+'…'; _ms+='<text x="'+_mlw+'" y="'+(_my+4)+'" font-size="11" font-weight="700" fill="#334155" text-anchor="end">'+_mlb+'</text>'; _ms+='<rect x="'+_mbx+'" y="'+(_my-8)+'" width="'+_mbw+'" height="16" rx="8" fill="#f1f5f9"/>'; _ms+='<rect x="'+_mbx+'" y="'+(_my-8)+'" width="'+_mbv.toFixed(1)+'" height="16" rx="8" fill="'+_mit.color+'"/>'; _ms+='<text x="'+(_mbx+_mbw+5)+'" y="'+(_my+4)+'" font-size="10" font-weight="700" fill="'+_mit.color+'" text-anchor="start">'+_mr+'%（'+(_mit.total||0)+'問）</text>'; } _ms+='</svg>'; H.push('<div style="margin-top:8px;border-top:1px dashed #e2e8f0;padding-top:7px"><div style="font-size:12px;font-weight:800;margin-bottom:3px"><span style="color:#16a34a">💪 とくい</span> ／ <span style="color:#ea580c">🌱 のばす</span> ／ <span style="color:#0369a1">🔁 下の学年の復習</span></div>'+_ms+'</div>'); } H.push('</div>'); /* 📌 2026-09 方針: 子どもに渡す紙から「提出率(%)」を外した（先生の判断）。 */ H.push(_kHowToLearn(d)); var _extra=[]; if(reviewGood.length){ var _rg=[]; for(var rgi=0;rgi<reviewGood.length;rgi++){ var _rgu=reviewGood[rgi]; var _rgg=_unitGrade(_rgu.unit); _rg.push((_rgg?_rgg+'年 ':'')+esc(_unitJa(_rgu.unit))+'('+_rgu.rate+'%)'); } _extra.push('<div style="font-size:12px;color:#0369a1;font-weight:700">🔁 下の学年の復習もバッチリ … '+_rg.join('、')+'</div>'); } if(ahead.length){ var _ag=[]; for(var agi=0;agi<ahead.length;agi++){ var _agu=ahead[agi]; var _agg=_unitGrade(_agu.unit); _ag.push((_agg?_agg+'年 ':'')+esc(_unitJa(_agu.unit))+'('+_agu.rate+'%)'); } _extra.push('<div style="margin-top:5px;font-size:12px;color:#7c3aed;font-weight:700">🚀 先取りもチャレンジ … '+_ag.join('、')+'</div>'); } if(_extra.length){ H.push('<div class="sec good" style="padding:10px 15px"><h2 style="margin-bottom:6px">💪 とくいなところ</h2>'+_extra.join('')+'</div>'); } /* 2026-09 方針: 子どもに渡すカルテにはテストの点数・得点率を載せない（先生の指示） */ var _tn=(d.teacherNotes||[]).filter(function(n){return n.showInKarte&&String(''+(n.body||'')).trim();}); if(_tn.length){ H.push('<div class="sec"><h2>📝 先生からの記録</h2><ul>'); for(var ni=0;ni<_tn.length;ni++){ var nn=_tn[ni]; H.push('<li>'+esc(nn.dayKey||'')+' '+esc(nn.body||'')+'</li>'); } H.push('</ul></div>'); } if(d.aiComment&&String(d.aiComment).trim()){ H.push('<div class="sec"><h2>🐯 阪神マンからのアドバイス</h2><div style="font-size:12px;color:#475569;white-space:pre-wrap">'+esc(d.aiComment)+'</div></div>'); } H.push('<div class="foot">LearningBM ／ 家庭学習カルテ</div>'); H.push('</div></body></html>'); return H.join(''); }"""

STEPS = [
 {
  "tag": "K4 おすすめの取り込み（変数）",
  "sentinel": "var _psT=_ps?",
  "old": "var H=[]; H.push('<div style=\"border:2px solid #c7d2fe;",
  "new": "var _ps=String((d&&d.planSuggestion)||'').trim(); var _psT=_ps?'🎯 今週のおすすめ（先生が確認したもの）':'🎯 今週の一手（これだけでOK）'; var _psB=_ps?esc(_ps).split(String.fromCharCode(10)).join('<br>'):one; var H=[]; H.push('<div style=\"border:2px solid #c7d2fe;"
 },
 {
  "tag": "K4 おすすめの表示",
  "sentinel": "'+_psT+'</div>",
  "old": "🎯 今週の一手（これだけでOK）</div><div style=\"margin-top:3px;color:#334155\">'+one+'</div>",
  "new": "'+_psT+'</div><div style=\"margin-top:3px;color:#334155\">'+_psB+'</div>"
 },
 {
  "tag": "K5 週プランに plan_suggestion を追加",
  "sentinel": "reflection_reward_coins, plan_suggestion",
  "old": "reflection_returned_at, reflection_reward_coins",
  "new": "reflection_returned_at, reflection_reward_coins, plan_suggestion, plan_suggestion_at"
 },
 {
  "tag": "K5 plans に planSuggestion を載せる",
  "sentinel": "approved: !!p.plan_approved, planSuggestion",
  "old": "plans: allPlans.map((p: any) => ({ weekKey: p.week_key, revisionCount: p.revision_count || 0, approved: !!p.plan_approved })),",
  "new": "plans: allPlans.map((p: any) => ({ weekKey: p.week_key, revisionCount: p.revision_count || 0, approved: !!p.plan_approved, planSuggestion: p.plan_suggestion || '' })),"
 },
 {
  "tag": "K5 planSuggestion と MI の取得",
  "sentinel": "let planSuggestion =",
  "old": "let teacherNotes: any[] = []",
  "new": "let planSuggestion = ''\n      for (const _p of (allPlans as any[])) { const _v = String((_p && _p.plan_suggestion) || '').trim(); if (_v) { planSuggestion = _v; break } }\n      let miInfo: any = null\n      try { const _mir = await c.env.DB.prepare('SELECT scores_json, left_total, right_total, taken_at FROM mi_results WHERE user_id=? ORDER BY taken_at DESC LIMIT 1').bind(studentId).first<any>(); if (_mir) miInfo = { scores: _mir.scores_json || '', leftTotal: _mir.left_total, rightTotal: _mir.right_total, takenAt: _mir.taken_at } } catch {}\n      let teacherNotes: any[] = []"
 },
 {
  "tag": "K5 レスポンスに planSuggestion と mi を追加",
  "sentinel": "planSuggestion, mi: miInfo",
  "old": "aiComment: aiComment2",
  "new": "planSuggestion, mi: miInfo, aiComment: aiComment2"
 },
 {
  "tag": "K6 teacher-ai.js のキャッシュ更新",
  "sentinel": "/teacher-ai.js?v=7",
  "old": "<script src=\"/teacher-ai.js?v=6\"></script>",
  "new": "<script src=\"/teacher-ai.js?v=7\"></script>"
 }
]

MUST = [
 "function _buildKarteHtml(",
 "function downloadKartePdf(",
 "function downloadAllKartes(",
 "function _kHowToLearn(",
 "function _kRadar(",
 "function _kBars(",
 "function _kDonut(",
 "function _kHBar(",
 "function _kStudyTip(",
 "id=\"taiDraftList\"",
 "app.get('/api/student/my-karte'",
 "app.post('/api/teacher/karte-share'",
 "app.get('/api/teacher/student-full-analysis'",
 "/teacher-ai.js",
 "@page{size:A4",
 "📒 家庭学習カルテ",
 "📊 今年度の学習の見える化",
 "🌟 今年度の積み上げ",
 "🐯 阪神マンからのアドバイス",
 "📝 先生からの記録",
 "✏️ 先生から",
 "planSuggestion"
]

BAD = [
 "📝 さいきんの ふりかえり",
 "これから もっと のびるところ</h2>",
 "テストの記録</h2>"
]


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tsx = os.path.join(root, 'src', 'index.tsx')
    src = io.open(tsx, encoding='utf-8').read()
    orig = src
    changes = []

    def fail(msg):
        print('\u274c 中止: ' + msg)
        sys.exit(1)

    # ---- K1〜K3: 印刷カルテ本体をまるごと差し替え ----
    if 'カルテは月曜に印刷して配るため' in src:
        print('\u23ed K1-K3 印刷カルテの差し替えは適用済み（スキップ）')
    else:
        a, b = 'function _buildKarteHtml(){', 'function downloadKartePdf(){'
        if src.count(a) != 1: fail('_buildKarteHtml のアンカーが1箇所ではありません')
        if src.count(b) != 1: fail('downloadKartePdf のアンカーが1箇所ではありません')
        i, j = src.index(a), src.index(b)
        if i >= j: fail('_buildKarteHtml と downloadKartePdf の順序が想定と違います')
        src = src[:i] + NEW_KARTE + ' ' + src[j:]
        changes.append('K1-K3 印刷カルテを差し替え')

    # ---- K4〜K6: 個別の置換（アンカーは必ず1箇所） ----
    for st in STEPS:
        if st['sentinel'] in src:
            print('\u23ed %s は適用済み（スキップ）' % st['tag']); continue
        n = src.count(st['old'])
        if n == 0: fail('%s のアンカーが見つかりません' % st['tag'])
        if n != 1: fail('%s のアンカーが %d 箇所（1箇所のはず）' % (st['tag'], n))
        src = src.replace(st['old'], st['new'], 1)
        changes.append(st['tag'])

    # ---- 検証 ----
    def root_replace_count(text):
        a = text.index("app.get('/', async (c) => {")
        b = text.index("app.get('/logout'", a)
        return text[a:b].count('.replace(')

    if root_replace_count(orig) != root_replace_count(src):
        fail('本番HTMLの置換チェーンの数が変わりました（%d -> %d）'
             % (root_replace_count(orig), root_replace_count(src)))
    print('\U0001f50e 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

    for m in MUST:
        if m not in src: fail('必須の要素が失われました: %s' % m)
    for x in BAD:
        if x in src: fail('整理したはずの要素が残っています: %s' % x)
    if src.count('function _buildKarteHtml(') != 1: fail('_buildKarteHtml が重複しています')

    if src != orig:
        io.open(tsx, 'w', encoding='utf-8', newline='').write(src)
        print('\u2705 src/index.tsx を更新しました')
    else:
        print('… 変更なし')
    print('---- 適用した項目 ----')
    for c in changes: print(' \u30fb' + c)
    if not changes: print(' （なし）')


if __name__ == '__main__':
    main()
