/* defense2.js - learning-bm defense-battle enhancement (injected before </body>).
   Reuses window.autoBattleRT (+spec.raw enemies) and window._defRenderBattle (animated _gc renderer).
   IMPORTANT: the index.html inline script re-exposes window._def* AFTER this file loads, so we
   RE-INSTALL our overrides on an interval (guarded by a __def2 flag) so they always win. Each override
   captures the current (original) fn as fallback and falls back on any error, so the live defense
   flow is never broken. */
(function(){
  'use strict';
  if(window.__defense2Loaded) return; window.__defense2Loaded = true;

  function fnv(str){ str=String(str==null?'':str); var h=2166136261>>>0; for(var i=0;i<str.length;i++){ h^=str.charCodeAt(i); h=Math.imul(h,16777619); } return h>>>0; }
  function seedFromKey(k){ return ((fnv(k)^0x9e3779b9)>>>0); }

  var COND = [
    {v:'always',   label:'いつも'},
    {v:'selfHpBelow', label:'自分のHPが少ない', num:true, dflt:30},
    {v:'allyBaseBelow', label:'みかたの基地が危ない', num:true, dflt:40},
    {v:'openPointNear', label:'近くにポイントがある'}
  ];
  var ACT = [
    {v:'attackBase', label:'相手の基地をせめる'},
    {v:'returnBase', label:'みかたの基地をまもる'},
    {v:'fleeLane',   label:'にげる'},
    {v:'laneC',      label:'まん中のレーンへ'},
    {v:'goPoint',    label:'ポイントをとりに行く'}
  ];
  var DEFAULT_PROG = [{c:'always',a:'attackBase'}];
  var ENEMY_PROG   = [{c:'always',a:'attackBase'}];

  function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c];}); }
  function jget(u){ return fetch(u,{cache:'no-store'}).then(function(r){return r.json();}).catch(function(){return null;}); }

  /* ---- program authoring state ---- */
  var _progRules = null;
  function ensureRules(){ if(!Array.isArray(_progRules)||!_progRules.length){ _progRules=[{c:'always',cn:null,a:'attackBase'}]; } return _progRules; }
  function progFromRules(){ return ensureRules().map(function(r){ var o={c:r.c,a:r.a}; var cd=COND.filter(function(x){return x.v===r.c;})[0]; if(cd&&cd.num){ o.cn=Number(r.cn!=null?r.cn:(cd.dflt||0)); } return o; }); }
  function optionsHtml(list,cur){ return list.map(function(o){ return '<option value="'+o.v+'"'+(o.v===cur?' selected':'')+'>'+esc(o.label)+'</option>'; }).join(''); }
  function renderEditor(){
    var box=document.getElementById('def2ProgBox'); if(!box) return; ensureRules();
    var rows=_progRules.map(function(r,i){
      var cd=COND.filter(function(x){return x.v===r.c;})[0]; var showNum=cd&&cd.num;
      return '<div style="display:flex;gap:4px;align-items:center;margin-bottom:4px;flex-wrap:wrap;">'
        +'<span style="font-size:11px;color:#64748b;">もし</span>'
        +'<select data-i="'+i+'" data-k="c" class="def2sel" style="font-size:12px;padding:2px;border:1px solid #cbd5e1;border-radius:6px;">'+optionsHtml(COND,r.c)+'</select>'
        +(showNum?'<input data-i="'+i+'" data-k="cn" type="number" value="'+esc(r.cn!=null?r.cn:(cd.dflt||0))+'" style="width:52px;font-size:12px;padding:2px;border:1px solid #cbd5e1;border-radius:6px;">%':'')
        +'<span style="font-size:11px;color:#64748b;">なら</span>'
        +'<select data-i="'+i+'" data-k="a" class="def2sel" style="font-size:12px;padding:2px;border:1px solid #cbd5e1;border-radius:6px;">'+optionsHtml(ACT,r.a)+'</select>'
        +'<button data-i="'+i+'" class="def2del" style="font-size:11px;color:#dc2626;background:none;border:0;cursor:pointer;">✕</button>'
        +'</div>';
    }).join('');
    box.innerHTML='<div style="font-weight:800;font-size:12px;color:#334155;margin-bottom:4px;">🧩 さくせん（上から順にチェック）</div>'+rows
      +'<button id="def2add" style="font-size:12px;color:#2563eb;background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:3px 8px;cursor:pointer;">＋ ルールを追加</button>';
    box.querySelectorAll('.def2sel').forEach(function(sel){ sel.addEventListener('change',function(){ var i=+this.getAttribute('data-i'),k=this.getAttribute('data-k'); _progRules[i][k]=this.value; if(k==='c'){ var v=this.value; var cd=COND.filter(function(x){return x.v===v;})[0]; _progRules[i].cn=(cd&&cd.num)?(cd.dflt||0):null; } renderEditor(); }); });
    box.querySelectorAll('input[data-k="cn"]').forEach(function(inp){ inp.addEventListener('input',function(){ var i=+this.getAttribute('data-i'); _progRules[i].cn=Number(this.value); }); });
    box.querySelectorAll('.def2del').forEach(function(b){ b.addEventListener('click',function(){ var i=+this.getAttribute('data-i'); if(_progRules.length>1){ _progRules.splice(i,1); renderEditor(); } }); });
    var add=document.getElementById('def2add'); if(add) add.addEventListener('click',function(){ _progRules.push({c:'always',cn:null,a:'attackBase'}); renderEditor(); });
  }
  function tryMountEditor(){
    if(document.getElementById('def2ProgBox')) return;
    var anchor=document.getElementById('defStratRow')||document.getElementById('defenseBody')||document.getElementById('defenseModal');
    if(!anchor) return;
    var box=document.createElement('div'); box.id='def2ProgBox'; box.style.cssText='background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:8px;margin:8px 0;';
    anchor.appendChild(box); renderEditor();
  }

  /* ---- MVP + battle ---- */
  
  /* ===== hype features: shared finale + MVP spotlight + class contribution gauge ===== */
  function def2Contrib(log){
    try{
      var list = (log && log.contrib && log.contrib.length) ? log.contrib.slice() : null;
      if(!list){
        var A = (log && log.replay && log.replay.teams && log.replay.teams.A) ? log.replay.teams.A : [];
        var ent = (log && log.entrants) || [];
        list = A.map(function(f,i){
          var dealt = (f.dmgDealt!=null)? f.dmgDealt : Math.max(0,(f.maxHp||0)-(f.hp||0));
          var e = ent[i]||{};
          return { name:e.name||f.name||'?', sprite:e.sprite||f.sprite||'', mon:e.mon||f.name||'', dealt:Math.round(dealt||0), alive:!!f.alive };
        });
      }
      var total = list.reduce(function(s,x){return s+(x.dealt||0);},0);
      var denom = (log && log.enemyTotalHp) ? log.enemyTotalHp : (function(){ try{ return (log.enemy_squad||[]).reduce(function(s,en){return s+(en.hp||0);},0);}catch(e){return total;} })();
      if(!denom) denom = total || 1;
      var pct = Math.max(0, Math.min(100, Math.round(total/denom*100)));
      list = list.slice().sort(function(a,b){return (b.dealt||0)-(a.dealt||0);});
      return {list:list, total:total, denom:denom, pct:pct};
    }catch(e){ return {list:[],total:0,denom:1,pct:0}; }
  }
  function def2EnhanceReplay(log){
  try{
    window.__def2Rep = (log && log.replay) || null;
    if(!document.getElementById('def2UxCss')){
      var st=document.createElement('style'); st.id='def2UxCss';
      st.textContent='#def2Anim .gc-now{font-size:8px !important;line-height:1.05 !important;opacity:.55 !important;max-width:52px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;pointer-events:none;}';
      document.head.appendChild(st);
    }
    var host=document.getElementById('def2Anim'); if(!host) return;
    var label=host.previousElementSibling;
    if(!document.getElementById('def2ReplayBar')){
      var bar=document.createElement('div'); bar.id='def2ReplayBar'; bar.style.cssText='text-align:center;margin:10px 0 6px;';
      bar.innerHTML='<button id="def2ReplayBtn" style="background:linear-gradient(135deg,#4f46e5,#6366f1);color:#fff;border:none;border-radius:12px;padding:12px 22px;font-weight:900;font-size:15px;cursor:pointer;box-shadow:0 3px 10px rgba(79,70,229,.45);">▶ リプレイをもう一度見る</button>';
      (label||host).parentNode.insertBefore(bar,(label||host));
    }
    function fit(){ try{
      var wrapW=host.clientWidth||360;
      var cands=host.querySelectorAll('*'); var map=null,mw=0;
      for(var i=0;i<cands.length;i++){ var w=cands[i].offsetWidth; if(w>mw){mw=w;map=cands[i];} }
      if(map && mw>wrapW+4){ var sc=wrapW/mw; map.style.transformOrigin='top left'; map.style.transform='scale('+sc+')'; map.style.marginBottom=(-(map.offsetHeight*(1-sc)))+'px'; }
      else if(map){ map.style.transform=''; map.style.marginBottom=''; }
    }catch(e){} }
    function toBattle(){ try{ (document.getElementById('def2ReplayBar')||host).scrollIntoView({block:'start',behavior:'smooth'}); }catch(e){} }
    var btn=document.getElementById('def2ReplayBtn');
    if(btn) btn.onclick=function(){ var h=document.getElementById('def2Anim'); if(h){ try{ relocateGymInto(h); }catch(e){} try{ window._defRenderBattle(window.__def2Rep); }catch(e){} setTimeout(function(){fit();toBattle();},90); } };
    setTimeout(function(){ fit(); toBattle(); },350);
    if(!window.__def2Rsz){ window.__def2Rsz=1; window.addEventListener('resize',function(){try{fit();}catch(e){}}); }
  }catch(e){ try{console.error('def2 enhance',e);}catch(_){} }
}

function def2HypeHtml(log, st){
    try{
      var rep = (log && log.replay) || {};
      var baseMax = (st && st.base_hp) || rep.baseHpMaxA || null;
      var baseEnd = (rep.baseHpA!=null) ? rep.baseHpA : null;
      var win = (rep.winner!=null) ? (rep.winner==='A') : (baseEnd!=null ? baseEnd>0 : true);
      var c = def2Contrib(log);
      var mvp = log && log.mvp;
      var hero = '<div style="position:relative;overflow:hidden;border-radius:14px;padding:16px;margin:6px 0 10px;text-align:center;background:linear-gradient(135deg,'+(win?'#1e3a8a,#2563eb':'#7f1d1d,#b91c1c')+');color:#fff;box-shadow:0 6px 20px rgba(0,0,0,.25);">'
        + '<div style="font-size:12px;letter-spacing:3px;opacity:.85;">CLASS DEFENSE - 決戦</div>'
        + '<div style="font-size:30px;font-weight:900;margin:4px 0;text-shadow:0 2px 8px rgba(0,0,0,.4);">'+(win?'🎉 まもりきった！':'💥 とっぱされた…')+'</div>'
        + '<div style="font-size:13px;opacity:.9;">みんなの きち防衛 けっか</div>';
      if(baseMax){
        var bpct = Math.max(0,Math.min(100,Math.round((baseEnd||0)/baseMax*100)));
        hero += '<div style="margin:10px auto 2px;max-width:340px;background:rgba(255,255,255,.25);border-radius:999px;height:14px;overflow:hidden;"><div style="width:'+bpct+'%;height:100%;background:'+(win?'#4ade80':'#fca5a5')+';"></div></div>'
          + '<div style="font-size:11px;opacity:.9;">きちHP のこり '+Math.max(0,Math.round(baseEnd||0))+' / '+baseMax+'</div>';
      }
      hero += '</div>';
      var top = c.list[0]||{};
      var mvpSprite = (mvp && mvp.sprite) || top.sprite || '⭐';
      var mvpName = (mvp && mvp.name) || top.name || '';
      var mvpMon = (mvp && mvp.mon) || top.mon || '';
      var mvpDealt = (mvp && mvp.dealt!=null) ? mvp.dealt : (top.dealt!=null?top.dealt:null);
      var spot = '<div style="border-radius:14px;padding:14px;margin:10px 0;text-align:center;background:radial-gradient(circle at 50% 0%,#fff7d6,#fde68a 60%,#fcd34d);border:2px solid #f59e0b;box-shadow:0 4px 14px rgba(245,158,11,.35);">'
        + '<div style="font-size:12px;font-weight:900;color:#b45309;letter-spacing:2px;">👑 今日の主役 MVP</div>'
        + '<div style="font-size:56px;line-height:1;margin:6px 0;filter:drop-shadow(0 4px 6px rgba(0,0,0,.2));">'+esc(mvpSprite)+'</div>'
        + '<div style="font-size:18px;font-weight:900;color:#7c2d12;">'+esc(mvpName)+'</div>'
        + '<div style="font-size:12px;color:#92400e;">'+esc(mvpMon)+(mvpDealt!=null?(' ・ あたえたダメージ '+mvpDealt):'')+'</div>'
        + '</div>';
      var maxD = c.list.length? Math.max(1, c.list[0].dealt||1) : 1;
      var bars = c.list.map(function(x,idx){
        var w = Math.max(3, Math.round((x.dealt||0)/maxD*100));
        var medal = idx===0?'🥇':idx===1?'🥈':idx===2?'🥉':'　';
        return '<div style="display:flex;align-items:center;gap:6px;margin:3px 0;">'
          + '<span style="width:20px;text-align:center;">'+medal+'</span>'
          + '<span style="width:20px;text-align:center;">'+esc(x.sprite||'')+'</span>'
          + '<span style="flex:0 0 84px;font-size:12px;color:#334155;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">'+esc(x.name||'')+'</span>'
          + '<span style="flex:1;background:#e2e8f0;border-radius:999px;height:12px;overflow:hidden;"><span style="display:block;width:'+w+'%;height:100%;background:'+(x.alive?'#3b82f6':'#94a3b8')+';"></span></span>'
          + '<span style="flex:0 0 44px;text-align:right;font-size:11px;color:#475569;">'+(x.dealt||0)+'</span>'
          + '</div>';
      }).join('');
      var gauge = '<div style="border-radius:14px;padding:14px;margin:10px 0;background:#f8fafc;border:1px solid #e2e8f0;">'
        + '<div style="font-weight:900;font-size:13px;color:#334155;margin-bottom:6px;">📊 クラス貢献ゲージ</div>'
        + '<div style="background:#e2e8f0;border-radius:999px;height:18px;overflow:hidden;position:relative;"><div style="width:'+c.pct+'%;height:100%;background:linear-gradient(90deg,#22c55e,#16a34a);"></div><div style="position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:900;color:#0f172a;">クラス合計ダメージ '+c.total+' （'+c.pct+'%）</div></div>'
        + '<div style="margin-top:8px;">'+bars+'</div></div>';
      return hero + spot + gauge;
    }catch(e){ console.error('def2 hype',e); return ''; }
  }

  function computeMVP(rep, entrants){
    try{
      var A = rep.teams && rep.teams.A ? rep.teams.A : []; var best=null;
      A.forEach(function(f,i){
        var dealt = (f.dmgDealt!=null)? f.dmgDealt : ((f.atk||0)*(f.alive?2:1));
        var ent = entrants && entrants[i] ? entrants[i] : null;
        var score = dealt + (f.alive?50:0);
        if(!best || score>best.score){ best={score:score, name:(ent&&ent.name)||f.name, sprite:f.sprite, mon:f.name}; }
      });
      return best;
    }catch(e){ return null; }
  }
  function buildBattle(st){
    var entries = (st.entries||[]).filter(function(e){return e && e.monster && e.monster.id;});
    var defenders = entries.map(function(e){ return {id:e.monster.id, level:e.monster.level||1, strategy:e.monster.strategy||e.strategy||'balance'}; });
    var programsA = entries.map(function(e){ return (e.monster.prog && e.monster.prog.length)? e.monster.prog : DEFAULT_PROG; });
    var enemies = (st.enemy_squad||[]).map(function(en){ return {raw:{name:en.name,sprite:en.sprite,hp:en.hp,atk:en.atk,def:en.def,buff:en.buff,skillPow:en.skillPow}, strategy:'attack'}; });
    var seed = seedFromKey(st.event_key);
    var rep = window.autoBattleRT(defenders, enemies, {bases:true,lanes:true,laneCount:3,seed:seed,program:true,programsA:programsA,programB:ENEMY_PROG,forts:false,tactics:true,contact:true});
    return {rep:rep, entries:entries, seed:seed};
  }

  /* ---- override implementations (each takes the captured original) ---- */
  function makeResolve(orig){
    var f = async function(){
      try{
        var st = await jget('/api/defense/status'); if(!st || !st.event_key || !st.decided){ if(typeof orig==='function') return orig.apply(this,arguments); return; }
        var built = buildBattle(st); var rep=built.rep;
        var result = (rep.winner==='A') ? 'win' : 'lose';
        var baseHpEnd = (rep.baseHpA!=null)? Math.max(0,Math.floor(rep.baseHpA)) : (result==='win'? (st.base_hp||0):0);
        var mvp = computeMVP(rep, built.entries.map(function(e){return {name:e.name};}));
        var log = { v:2, seed:built.seed, enemy_squad:st.enemy_squad, entrants: built.entries.map(function(e){ return {name:e.name, sprite:(e.monster&&e.monster.sprite)||'', mon:(e.monster&&e.monster.name)||'', prog:(e.monster&&e.monster.prog)||null}; }), mvp:mvp, contrib:((rep.teams&&rep.teams.A)?rep.teams.A:[]).map(function(f,i){var d=(f.dmgDealt!=null)?f.dmgDealt:Math.max(0,(f.maxHp||0)-(f.hp||0));var e=built.entries[i]||{};return {name:e.name||f.name,sprite:(e.monster&&e.monster.sprite)||f.sprite||'',mon:(e.monster&&e.monster.name)||f.name,dealt:Math.round(d||0),alive:!!f.alive};}), enemyTotalHp:(st.enemy_squad||[]).reduce(function(s,en){return s+(en.hp||0);},0), replay:rep };
        var r = await fetch('/api/defense/resolve',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({event_key:st.event_key,class_id:st.class_id,result:result,base_hp_end:baseHpEnd,log:log})});
        await r.json().catch(function(){});
        if(typeof window.openDefense==='function'){ try{ window.openDefense(); }catch(e){} }
      }catch(e){ console.error('def2 resolve',e); if(typeof orig==='function') return orig.apply(this,arguments); }
    };
    f.__def2 = true; return f;
  }

  var _gcHome = null;
  function relocateGymInto(host){ var g=document.getElementById('gymChallengeBody'); if(!g) return null; if(!_gcHome){ _gcHome={parent:g.parentNode, next:g.nextSibling}; } host.appendChild(g); return g; }
  function restoreGym(){ try{ var g=document.getElementById('gymChallengeBody'); if(g&&_gcHome&&_gcHome.parent){ _gcHome.parent.insertBefore(g,_gcHome.next); } }catch(e){} }
  function makeReplay(orig){
    var f = function(){
      var args=arguments, self=this;
      try{
        var rp=document.getElementById('defReplay'); if(!rp){ if(typeof orig==='function') return orig.apply(self,args); return; }
        jget('/api/defense/status').then(function(st){
          var log = st && st.result ? st.result.log : null;
          if(!log || (Array.isArray(log)) || log.v!==2){ if(typeof orig==='function'){ try{ return orig.apply(self,args); }catch(e){} } if(rp){ rp.textContent='リプレイデータがありません。'; } return; }
          var entrantsHtml = (log.entrants||[]).map(function(e){ return '<span style="display:inline-block;background:#eef2ff;border:1px solid #c7d2fe;border-radius:999px;padding:2px 8px;margin:2px;font-size:12px;">'+esc(e.sprite)+esc(e.name)+'</span>'; }).join('');
          var mvpHtml = log.mvp ? '<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:8px;margin:8px 0;font-weight:900;color:#b45309;">🏆 MVP：'+esc(log.mvp.sprite||'')+esc(log.mvp.name||'')+'</div>' : '';
          rp.innerHTML=def2HypeHtml(log,st)+'<div style="margin-bottom:6px;"><div style="font-weight:900;font-size:13px;color:#334155;margin-bottom:4px;">🙋 エントリーした人（'+((log.entrants||[]).length)+'人）</div><div>'+entrantsHtml+'</div></div>'+''
            +'<div style="font-weight:900;font-size:13px;color:#334155;margin:6px 0;">⚔️ みんなで見る決戦リプレイ</div><div id="def2Anim" style="position:relative;width:100%;min-height:320px;background:#0b1220;border-radius:10px;overflow:hidden;"></div>';
          var host=document.getElementById('def2Anim'); if(host && window._defRenderBattle){ relocateGymInto(host); try{ window._defRenderBattle(log.replay); try{def2EnhanceReplay(log);}catch(_e){} }catch(e){ console.error(e); } }
        });
      }catch(e){ console.error('def2 replay',e); if(typeof orig==='function') return orig.apply(self,args); }
    };
    f.__def2 = true; return f;
  }

  function makeSubmit(orig){
    var f = async function(){
      try{
        if(typeof orig!=='function') return;
        var prog = progFromRules(); var _f = window.fetch;
        window.fetch = function(u,opt){
          try{ if(typeof u==='string' && u.indexOf('/api/defense/entry')>=0 && opt && opt.body){ var b=JSON.parse(opt.body); if(b && b.monster && typeof b.monster==='object'){ b.monster.prog=prog; opt.body=JSON.stringify(b); } } }catch(e){}
          return _f.apply(this,arguments);
        };
        try{ return await orig.apply(this,arguments); } finally{ window.fetch=_f; }
      }catch(e){ console.error('def2 submit',e); if(typeof orig==='function') return orig.apply(this,arguments); }
    };
    f.__def2 = true; return f;
  }

  function makeClose(orig){ var f=function(){ try{ restoreGym(); }catch(e){} if(typeof orig==='function') return orig.apply(this,arguments); }; f.__def2=true; return f; }

  /* ---- (re)install overrides; re-run so the inline exposure block can't win ---- */
  function install(){
    try{
      if(typeof window._defStartResolve==='function' && !window._defStartResolve.__def2) window._defStartResolve = makeResolve(window._defStartResolve);
      if(typeof window._defShowReplay==='function' && !window._defShowReplay.__def2) window._defShowReplay = makeReplay(window._defShowReplay);
      if(typeof window._defDoSubmit==='function' && !window._defDoSubmit.__def2) window._defDoSubmit = makeSubmit(window._defDoSubmit);
      if(typeof window.closeDefense==='function' && !window.closeDefense.__def2) window.closeDefense = makeClose(window.closeDefense);
    }catch(e){}
    tryMountEditor();
  }
  install();
  if(document.readyState!=='complete') window.addEventListener('load', install);
  setInterval(install, 700);
})();
