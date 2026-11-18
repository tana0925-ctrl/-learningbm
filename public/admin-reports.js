(function(){
  var _rptData=[];
  function esc(s){ return String(s==null?'':s).replace(/[&<>"]/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c];}); }
  var STT={open:'未対応',in_progress:'対応中',resolved:'対応済み',closed:'クローズ'};
  var CAT={bug:'🐛 バグ',request:'💡 要望',other:'💬 その他'};
  window.rptAdminLoad=async function(){
    var list=document.getElementById('rptAdminList'); if(!list) return;
    list.innerHTML='<p style="color:#94a3b8;font-size:13px;">読み込み中...</p>';
    try{
      var url='/api/admin/reports';   /* ADMINRPT_V2 ぜんぶ よんで、画面で しぼる */
      var r=await fetch(url,{credentials:'include'});
      var j=await r.json();
      _rptData=(j.reports||[]);
      window.rptAdminRender();
    }catch(e){ list.innerHTML='<p style="color:#dc2626;font-size:13px;">読み込みに失敗しました</p>'; }
  };
  window.rptAdminRender=function(){
    var list=document.getElementById('rptAdminList'); if(!list) return;
    var cs=document.getElementById('rptFilterCat'); var cat=cs?cs.value:'all';
    var ss=document.getElementById('rptFilterStatus'); var st=ss?ss.value:'todo';
    var rows=_rptData.filter(function(x){ return (cat==='all'||x.category===cat) && (st==='all' || (st==='todo' ? (x.status==='open'||x.status==='in_progress') : x.status===st)); });
    rows.sort(function(a,b){ var o={open:0,in_progress:1,resolved:2,closed:3}; return (o[a.status]-o[b.status]) || String(b.createdAt).localeCompare(String(a.createdAt)); });
    /* ADMINRPT_V2 状態ごとの 数（おすと しぼれる） */
    var cnt={open:0,in_progress:0,resolved:0,closed:0}; _rptData.forEach(function(x){ if(cnt[x.status]!=null) cnt[x.status]++; });
    var sumEl=document.getElementById('rptSum'); if(!sumEl){ sumEl=document.createElement('div'); sumEl.id='rptSum'; sumEl.style.cssText='display:flex;gap:6px;flex-wrap:wrap;margin-bottom:8px;font-size:12px'; list.parentNode.insertBefore(sumEl,list); }
    sumEl.innerHTML=[['todo','まだ',cnt.open+cnt.in_progress,'#fee2e2','#b91c1c'],['open','未対応',cnt.open,'#fff7ed','#c2410c'],['in_progress','対応中',cnt.in_progress,'#eff6ff','#1d4ed8'],['resolved','対応済み',cnt.resolved,'#f0fdf4','#15803d'],['closed','クローズ',cnt.closed,'#f1f5f9','#475569']].map(function(a){ return '<button type="button" data-st="'+a[0]+'" style="border:2px solid '+(st===a[0]?a[4]:'transparent')+';background:'+a[3]+';color:'+a[4]+';border-radius:999px;padding:3px 10px;font-weight:bold;cursor:pointer">'+a[1]+' '+a[2]+'</button>'; }).join('');
    Array.prototype.forEach.call(sumEl.querySelectorAll('button'),function(b){ b.onclick=function(){ if(ss) ss.value=b.getAttribute('data-st'); window.rptAdminRender(); }; });
    var ago=function(t){ var ms=Date.parse(String(t||'').replace(' ','T')+'Z'); if(!isFinite(ms)) return ''; var d=Math.floor((Date.now()-ms)/86400000); return d<=0?'きょう':d+'日前'; };
    var openN=_rptData.filter(function(x){return x.status==='open';}).length;
    var badge=document.getElementById('rptBadge'); if(badge) badge.textContent=openN>0?('未対応 '+openN+'件'):'';
    if(!rows.length){ list.innerHTML='<p style="color:#94a3b8;font-size:13px;">報告はありません</p>'; return; }
    list.innerHTML=rows.map(function(x){
      var sttSel=['open','in_progress','resolved','closed'].map(function(s){ return '<option value="'+s+'"'+(x.status===s?' selected':'')+'>'+STT[s]+'</option>'; }).join('');
      return '<div style="border:1px solid #e2e8f0;border-radius:10px;padding:10px;margin-bottom:8px;background:'+(x.status==='open'?'#fff7ed':'#f8fafc')+';">'
        +'<div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;align-items:center;">'
        +'<span style="font-weight:bold;font-size:13px;">'+(CAT[x.category]||esc(x.category))+' ・ '+esc(x.displayName||'?')+'</span>'
        +'<span style="font-size:11px;color:#94a3b8;">'+esc(String(x.createdAt||'').slice(0,16))+'（'+ago(x.createdAt)+'）</span></div>'
        +'<div style="font-size:13px;margin:6px 0;white-space:pre-wrap;word-break:break-word;">'+esc(x.body||'')+'</div>'
        +'<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">'
        +'<select id="rptst_'+x.id+'" style="border:1px solid #cbd5e1;border-radius:6px;padding:3px 6px;font-size:12px;">'+sttSel+'</select>'
        +'<input id="rptnt_'+x.id+'" value="'+esc(x.adminNote||'')+'" placeholder="管理メモ" style="flex:1;min-width:140px;border:1px solid #cbd5e1;border-radius:6px;padding:3px 6px;font-size:12px;"/>'
        +'<button onclick="rptAdminSave(\''+x.id+'\')" style="background:#2563eb;color:#fff;border:0;border-radius:6px;padding:4px 10px;font-size:12px;font-weight:bold;cursor:pointer;">保存</button>'
        +'<span id="rptmsg_'+x.id+'" style="font-size:11px;"></span></div></div>';
    }).join('');
  };
  window.rptAdminSave=async function(id){
    var ss=document.getElementById('rptst_'+id); var st=ss?ss.value:'open';
    var ni=document.getElementById('rptnt_'+id); var nt=ni?ni.value:'';
    var msg=document.getElementById('rptmsg_'+id);
    try{
      var r=await fetch('/api/admin/report/'+id,{method:'PUT',headers:{'content-type':'application/json'},credentials:'include',body:JSON.stringify({status:st,adminNote:nt,admin_note:nt})});
      if(!r.ok) throw new Error('bad');
      if(msg){ msg.textContent='✓ 保存'; msg.style.color='#16a34a'; }
      var it=_rptData.find(function(x){return x.id===id;}); if(it){ it.status=st; it.adminNote=nt; }
      var openN=_rptData.filter(function(x){return x.status==='open';}).length; var badge=document.getElementById('rptBadge'); if(badge) badge.textContent=openN>0?('未対応 '+openN+'件'):'';
    }catch(e){ if(msg){ msg.textContent='保存失敗'; msg.style.color='#dc2626'; } }
  };
  function init(){ if(document.getElementById('rptAdminList')) window.rptAdminLoad(); }
  if(document.readyState!=='loading') setTimeout(init,200); else document.addEventListener('DOMContentLoaded', function(){ setTimeout(init,200); });
})();
