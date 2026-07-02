/* defense2.js - learning-bm defense-battle enhancement (injected before </body>).
   Reuses window.autoBattleRT (+spec.raw enemies) and window._defRenderBattle (animated _gc renderer).
   All overrides capture the original fn and fall back on any error, so existing defense flow is never broken.
   Data: /api/defense/status -> {event_key,class_id,base_hp,enemy_squad,entries:[{user_id,name,monster,strategy}],my_entry,decided,result}
   Program stored in monster.prog (monster_json <=4000 chars). Rich replay+entrants+mvp stored in resolve log (<=100000). */
(function(){
  'use strict';
  if(window.__defense2Loaded) return; window.__defense2Loaded = true;

  function fnv(str){ str=String(str==null?'':str); var h=2166136261>>>0; for(var i=0;i<str.length;i++){ h^=str.charCodeAt(i); h=Math.imul(h,16777619); } return h>>>0; }
  function seedFromKey(k){ return ((fnv(k)^0x9e3779b9)>>>0); }

  /* PB block-program vocabulary (understood by autoBattleRT). c=condition, cn=number, a=action. */
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

  /* ---- current program authoring state (per entry session) ---- */
  var _progRules = null; /* array of {c,cn,a} */
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
    box.querySelectorAll('.def2sel').forEach(function(sel){ sel.addEventListener('change',function(){ var i=+this.getAttribute('data-i'),k=this.getAttribute('data-k'); _progRules[i][k]=this.value; if(k==='c'){ var cd=COND.filter(function(x){return x.v===this.value;}.bind(this))[0]; _progRules[i].cn=(cd&&cd.num)?(cd.dflt||0):null; } renderEditor(); }); });
    box.querySelectorAll('input[data-k="cn"]').forEach(function(inp){ inp.addEventListener('input',function(){ var i=+this.getAttribute('data-i'); _progRules[i].cn=Number(this.value); }); });
    box.querySelectorAll('.def2del').forEach(function(b){ b.addEventListener('click',function(){ var i=+this.getAttribute('data-i'); if(_progRules.length>1){ _progRules.splice(i,1); renderEditor(); } }); });
    var add=document.getElementById('def2add'); if(add) add.addEventListener('click',function(){ _progRules.push({c:'always',cn:null,a:'attackBase'}); renderEditor(); });
  }
  /* Inject the editor box into the defense entry area when present. */
  function tryMountEditor(){
    if(document.getElementById('def2ProgBox')) return;
    var anchor=document.getElementById('defStratRow')||document.getElementById('defenseBody')||document.getElementById('defenseModal');
    if(!anchor) return;
    var box=document.createElement('div'); box.id='def2ProgBox'; box.style.cssText='background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:8px;margin:8px 0;';
    anchor.appendChild(box); renderEditor();
  }

  /* ---- override _defDoSubmit: embed program into monster.prog ---- */
  var _origDoSubmit = window._defDoSubmit;
  window._defDoSubmit = async function(){
    try{
      if(typeof _origDoSubmit!=='function') return;
      /* Patch fetch once to inject prog into the entry monster body. */
      var prog = progFromRules();
      var _f = window.fetch;
      window.fetch = function(u,opt){
        try{
          if(typeof u==='string' && u.indexOf('/api/defense/entry')>=0 && opt && opt.body){
            var b=JSON.parse(opt.body); if(b && b.monster && typeof b.monster==='object'){ b.monster.prog=prog; opt.body=JSON.stringify(b); }
          }
        }catch(e){}
        return _f.apply(this,arguments);
      };
      try{ return await _origDoSubmit.apply(this,arguments); }
      finally{ window.fetch=_f; }
    }catch(e){ console.error('def2 submit',e); if(typeof _origDoSubmit==='function') return _origDoSubmit.apply(this,arguments); }
  };

  /* ---- MVP + result from replay ---- */
  function computeMVP(rep, entrants){
    try{
      var A = rep.teams && rep.teams.A ? rep.teams.A : [];
      /* damage dealt approximated by (enemy total maxHp - final hp) is global; per-defender we use survival + remaining/So use dealt tracker if present, else fallback to atk*alive */
      var best=null;
      A.forEach(function(f,i){
        var dealt = (f.dmgDealt!=null)? f.dmgDealt : ((f.maxHp||0)-(f.hp||0)>=0 ? (f.atk||0)*(f.alive?2:1) : 0);
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

  /* ---- override _defStartResolve: deterministic battle + rich log; keeps win/lose (20-coin) contract ---- */
  var _origResolve = window._defStartResolve;
  window._defStartResolve = async function(){
    try{
      var st = await jget('/api/defense/status'); if(!st || !st.event_key || !st.decided){ if(typeof _origResolve==='function') return _origResolve.apply(this,arguments); return; }
      var built = buildBattle(st); var rep=built.rep;
      var result = (rep.winner==='A') ? 'win' : 'lose';
      var baseHpEnd = (rep.baseHpA!=null)? Math.max(0,Math.floor(rep.baseHpA)) : (result==='win'? (st.base_hp||0):0);
      var mvp = computeMVP(rep, built.entries.map(function(e){return {name:e.name};}));
      var log = { v:2, seed:built.seed, enemy_squad:st.enemy_squad, entrants: built.entries.map(function(e){ return {name:e.name, sprite:(e.monster&&e.monster.sprite)||'', mon:(e.monster&&e.monster.name)||'', prog:(e.monster&&e.monster.prog)||null}; }), mvp:mvp, replay:rep };
      var r = await fetch('/api/defense/resolve',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({event_key:st.event_key,class_id:st.class_id,result:result,base_hp_end:baseHpEnd,log:log})});
      await r.json().catch(function(){});
      if(typeof window.openDefense==='function'){ try{ window.openDefense(); }catch(e){} }
    }catch(e){ console.error('def2 resolve',e); if(typeof _origResolve==='function') return _origResolve.apply(this,arguments); }
  };

  /* ---- override _defShowReplay: entrants list + MVP + animated battle ---- */
  var _origShowReplay = window._defShowReplay;
  var _gcHome = null;
  function relocateGymInto(host){
    var g=document.getElementById('gymChallengeBody'); if(!g) return null;
    if(!_gcHome){ _gcHome={parent:g.parentNode, next:g.nextSibling}; }
    host.appendChild(g); return g;
  }
  function restoreGym(){ try{ var g=document.getElementById('gymChallengeBody'); if(g&&_gcHome&&_gcHome.parent){ _gcHome.parent.insertBefore(g,_gcHome.next); } }catch(e){} }
  window._defShowReplay = function(){
    try{
      var rp=document.getElementById('defReplay'); if(!rp) { if(typeof _origShowReplay==='function') return _origShowReplay.apply(this,arguments); return; }
      jget('/api/defense/status').then(function(st){
        var log = st && st.result ? st.result.log : null;
        if(!log || (Array.isArray(log)) || log.v!==2){ if(typeof _origShowReplay==='function'){ try{ return _origShowReplay.apply(window,arguments); }catch(e){} } if(rp){ rp.textContent='リプレイデータがありません。'; } return; }
        var entrantsHtml = (log.entrants||[]).map(function(e){ return '<span style="display:inline-block;background:#eef2ff;border:1px solid #c7d2fe;border-radius:999px;padding:2px 8px;margin:2px;font-size:12px;">'+esc(e.sprite)+esc(e.name)+'</span>'; }).join('');
        var mvpHtml = log.mvp ? '<div style="background:#fffbeb;border:1px solid #fde68a;border-radius:10px;padding:8px;margin:8px 0;font-weight:900;color:#b45309;">🏆 MVP：'+esc(log.mvp.sprite||'')+esc(log.mvp.name||'')+'</div>' : '';
        rp.innerHTML='<div style="margin-bottom:6px;"><div style="font-weight:900;font-size:13px;color:#334155;margin-bottom:4px;">🙋 エントリーした人（'+((log.entrants||[]).length)+'人）</div><div>'+entrantsHtml+'</div></div>'+mvpHtml
          +'<div id="def2Anim" style="position:relative;width:100%;min-height:320px;background:#0b1220;border-radius:10px;overflow:hidden;"></div>';
        var host=document.getElementById('def2Anim'); if(host && window._defRenderBattle){ relocateGymInto(host); try{ window._defRenderBattle(log.replay); }catch(e){ console.error(e); } }
      });
    }catch(e){ console.error('def2 replay',e); if(typeof _origShowReplay==='function') return _origShowReplay.apply(this,arguments); }
  };

  /* Restore the borrowed #gymChallengeBody when the defense modal closes. */
  var _origClose = window.closeDefense;
  window.closeDefense = function(){ try{ restoreGym(); }catch(e){} if(typeof _origClose==='function') return _origClose.apply(this,arguments); };

  /* Mount the program editor whenever the defense body is (re)rendered. */
  try{ var mo=new MutationObserver(function(){ tryMountEditor(); }); mo.observe(document.body,{childList:true,subtree:true}); }catch(e){}
  setInterval(tryMountEditor, 1500);
  if(document.readyState!=='loading') tryMountEditor();
})();
