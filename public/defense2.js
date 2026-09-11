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
  /* DEF_PROG_UX_V1
     プログラムづくりが 防衛戦の学びの中心。だから
     ①出陣ボタンの上に置く ②ほぞんする ③うごかない行を その場で知らせる。 */
  var _progRules = null;
  var _progLoaded = false;
  var _progTouched = false;
  var _progTimer = null;

  function progPlayer(){
    try{ if(window.player && typeof window.player === 'object') return window.player; }catch(e){}
    try{
      var p = new Function('try{ return (typeof player !== "undefined") ? player : null; }catch(e){ return null; }')();
      if(p && typeof p === 'object') return p;
    }catch(e){}
    return null;
  }
  function progClean(list){
    if(!Array.isArray(list) || !list.length) return null;
    var out = [];
    for(var i=0; i<list.length && out.length<12; i++){
      var r = list[i] || {};
      var cd = COND.filter(function(x){ return x.v === r.c; })[0];
      var ac = ACT.filter(function(x){ return x.v === r.a; })[0];
      if(!cd || !ac) continue;
      out.push({ c: cd.v, cn: (cd.num ? Number(r.cn != null ? r.cn : (cd.dflt || 0)) : null), a: ac.v });
    }
    return out.length ? out : null;
  }
  function progLoadOnce(){
    /* player は loadData で まるごと入れかわるので、
       見つかるまで 何度でも さがす。子が さわったら もう上書きしない。 */
    if(_progLoaded || _progTouched) return;
    var p = progPlayer(); if(!p) return;
    var saved = progClean(p.defProgram);
    if(saved){ _progLoaded = true; _progRules = saved; }
  }
  function progSaveNow(){
    try{
      var p = progPlayer(); if(!p) return;
      p.defProgram = JSON.parse(JSON.stringify(ensureRules()));
      if(typeof window.saveData === 'function') window.saveData();
    }catch(e){}
  }
  function progSaveSoon(){
    _progTouched = true;
    try{ if(_progTimer) clearTimeout(_progTimer); }catch(e){}
    _progTimer = setTimeout(progSaveNow, 700);
  }
  function ensureRules(){
    progLoadOnce();
    if(!Array.isArray(_progRules) || !_progRules.length){ _progRules = [{c:'always',cn:null,a:'attackBase'}]; }
    return _progRules;
  }
  function progDeadFrom(){
    var rs = ensureRules();
    for(var i=0; i<rs.length; i++){ if(rs[i].c === 'always') return i + 1; }
    return -1;
  }
  function progFromRules(){ return ensureRules().map(function(r){ var o={c:r.c,a:r.a}; var cd=COND.filter(function(x){return x.v===r.c;})[0]; if(cd&&cd.num){ o.cn=Number(r.cn!=null?r.cn:(cd.dflt||0)); } return o; }); }
  function optionsHtml(list,cur){ return list.map(function(o){ return '<option value="'+o.v+'"'+(o.v===cur?' selected':'')+'>'+esc(o.label)+'</option>'; }).join(''); }
  function renderEditor(){
    var box=document.getElementById('def2ProgBox'); if(!box) return; ensureRules();
    var dead=progDeadFrom();
    var rows=_progRules.map(function(r,i){
      var cd=COND.filter(function(x){return x.v===r.c;})[0]; var showNum=cd&&cd.num;
      var isDead=(dead>=0 && i>=dead);
      var note=(dead>=0 && i===dead)
        ? '<div style="margin:7px 0 5px;padding:6px 8px;background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;font-size:11px;color:#9a3412;line-height:1.6;">⬇ この下は うごきません<br>「いつも」は どんなときも あてはまるので、ここで とまります。下の ルールも うごかしたいときは、▲▼で 「いつも」を いちばん下に うつしてね。</div>'
        : '';
      return note
        +'<div style="display:flex;gap:4px;align-items:center;margin-bottom:4px;flex-wrap:wrap;'+(isDead?'opacity:0.45;background:#f1f5f9;border-radius:8px;padding:3px 4px;':'')+'">'
        +'<span style="font-size:11px;color:#94a3b8;min-width:12px;">'+(i+1)+'</span>'
        +'<span style="font-size:11px;color:#64748b;">もし</span>'
        +'<select data-i="'+i+'" data-k="c" class="def2sel" style="font-size:12px;padding:2px;border:1px solid #cbd5e1;border-radius:6px;">'+optionsHtml(COND,r.c)+'</select>'
        +(showNum?'<input data-i="'+i+'" data-k="cn" type="number" value="'+esc(r.cn!=null?r.cn:(cd.dflt||0))+'" style="width:52px;font-size:12px;padding:2px;border:1px solid #cbd5e1;border-radius:6px;">%':'')
        +'<span style="font-size:11px;color:#64748b;">なら</span>'
        +'<select data-i="'+i+'" data-k="a" class="def2sel" style="font-size:12px;padding:2px;border:1px solid #cbd5e1;border-radius:6px;">'+optionsHtml(ACT,r.a)+'</select>'
        +'<button data-i="'+i+'" class="def2up" style="font-size:11px;color:#475569;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:1px 5px;cursor:pointer;">▲</button>'
        +'<button data-i="'+i+'" class="def2dn" style="font-size:11px;color:#475569;background:#fff;border:1px solid #cbd5e1;border-radius:6px;padding:1px 5px;cursor:pointer;">▼</button>'
        +'<button data-i="'+i+'" class="def2del" style="font-size:11px;color:#dc2626;background:none;border:0;cursor:pointer;">✕</button>'
        +(isDead?'<span style="font-size:10px;color:#9a3412;font-weight:700;">うごきません</span>':'')
        +'</div>';
    }).join('');
    box.innerHTML='<div style="font-weight:800;font-size:12px;color:#334155;">🧩 ③ うごきかたを プログラムする</div>'
      +'<div style="font-size:11px;color:#64748b;margin:2px 0 6px;">上から じゅんに チェックして、さいしょに あてはまった 1つだけ うごくよ。</div>'
      +rows
      +'<button id="def2add" style="font-size:12px;color:#2563eb;background:#eff6ff;border:1px solid #bfdbfe;border-radius:6px;padding:3px 8px;cursor:pointer;">＋ ルールを追加</button>'
      +'<span style="font-size:10px;color:#94a3b8;margin-left:8px;">じどうで ほぞんされるよ</span>';
    box.querySelectorAll('.def2sel').forEach(function(sel){ sel.addEventListener('change',function(){ var i=+this.getAttribute('data-i'),k=this.getAttribute('data-k'); _progRules[i][k]=this.value; if(k==='c'){ var v=this.value; var cd=COND.filter(function(x){return x.v===v;})[0]; _progRules[i].cn=(cd&&cd.num)?(cd.dflt||0):null; } progSaveSoon(); renderEditor(); }); });
    box.querySelectorAll('input[data-k="cn"]').forEach(function(inp){ inp.addEventListener('input',function(){ var i=+this.getAttribute('data-i'); _progRules[i].cn=Number(this.value); progSaveSoon(); }); });
    box.querySelectorAll('.def2del').forEach(function(b){ b.addEventListener('click',function(){ var i=+this.getAttribute('data-i'); if(_progRules.length>1){ _progRules.splice(i,1); progSaveSoon(); renderEditor(); } }); });
    box.querySelectorAll('.def2up').forEach(function(b){ b.addEventListener('click',function(){ var i=+this.getAttribute('data-i'); if(i>0){ var t=_progRules[i]; _progRules[i]=_progRules[i-1]; _progRules[i-1]=t; progSaveSoon(); renderEditor(); } }); });
    box.querySelectorAll('.def2dn').forEach(function(b){ b.addEventListener('click',function(){ var i=+this.getAttribute('data-i'); if(i<_progRules.length-1){ var t=_progRules[i]; _progRules[i]=_progRules[i+1]; _progRules[i+1]=t; progSaveSoon(); renderEditor(); } }); });
    var add=box.querySelector('#def2add'); if(add) add.addEventListener('click',function(){ if(_progRules.length>=12) return; _progRules.push({c:'always',cn:null,a:'attackBase'}); progSaveSoon(); renderEditor(); });
  }
  function tryMountEditor(){
    if(document.getElementById('def2ProgBox')) return;
    var anchor=document.getElementById('defenseBody')||document.getElementById('defenseModal');
    if(!anchor) return;
    var btn=null;
    try{ btn=anchor.querySelector('button[onclick*="_defDoSubmit"]'); }catch(e){}
    if(!btn||!btn.parentNode) return;
    var box=document.createElement('div'); box.id='def2ProgBox'; box.style.cssText='background:#f8fafc;border:1px solid #e2e8f0;border-radius:10px;padding:8px;margin:8px 0;';
    btn.parentNode.insertBefore(box, btn); renderEditor();
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

  /* DEF2_STAGE0A_REASON_20260911
     autoBattleRT returns reason = 'wipe' | 'base' | 'judge' | 'timeout'.
     'wipe' = one side was knocked out completely. Wording only; no balance
     or difficulty change. */
  function def2ReasonText(win, reason, baseEnd, baseMax){
    try{
      var noDmg = (baseMax!=null && baseEnd!=null && Math.round(baseEnd) >= Math.round(baseMax));
      if(reason==='wipe'){
        return win ? ('てきを ぜんぶ たおした！' + (noDmg ? 'きちは むきず！' : 'きちを まもりきったよ'))
                   : 'みんな たおれてしまった…';
      }
      if(reason==='base'){ return win ? 'あいての きちを こわした！' : 'きちを こわされた…'; }
      if(reason==='timeout' || reason==='judge'){ return win ? 'じかんぎれ！ はんていで かち！' : 'じかんぎれ… はんていで まけ'; }
      return '';
    }catch(e){ return ''; }
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
      /* DEF2_STAGE0A_HERO_20260911 */
      var _rsn = def2ReasonText(win, rep && rep.reason, baseEnd, baseMax);
      if(_rsn){ hero += '<div style="margin-top:8px;display:inline-block;background:rgba(255,255,255,.20);border-radius:999px;padding:5px 14px;font-size:13px;font-weight:800;">'+esc(_rsn)+'</div>'; }
      if(baseMax){
        var bpct = Math.max(0,Math.min(100,Math.round((baseEnd||0)/baseMax*100)));
        hero += '<div style="margin:10px auto 2px;max-width:340px;background:rgba(255,255,255,.25);border-radius:999px;height:14px;overflow:hidden;"><div style="width:'+bpct+'%;height:100%;background:'+(win?'#4ade80':'#fca5a5')+';"></div></div>'
          + '<div style="font-size:11px;opacity:.9;">きちHP のこり '+Math.max(0,Math.round(baseEnd||0))+' / '+baseMax+'</div>';
      }
      hero += '</div>';
      /* DEFSTAGE_CHARS_V1 ステージ初クリアのごほうび。
         出すのは /api/defense/status が返した stage_bonus だけ。
         金額もキャラもサーバが決めた値で、ここでは1つも足さない。 */
      try {
        var _sb = st && st.stage_bonus;
        if (win && _sb && _sb.stage) {
          var _sbLines = '';
          if (_sb.coins > 0) {
            _sbLines += '<div style="font-size:15px;font-weight:900;">🪙 ボーナス ' + Number(_sb.coins) + ' コイン</div>';
          }
          if (_sb.monster_id) {
            var _sbM = null;
            try { _sbM = window.getMonster ? window.getMonster(Number(_sb.monster_id)) : null; } catch (e2) { _sbM = null; }
            var _sbHit = !!(_sbM && Number(_sbM.id) === Number(_sb.monster_id));
            var _sbNm = _sbHit ? _sbM.name : 'げんていキャラ';
            var _sbSp = _sbHit ? (_sbM.sprite || '🎁') : '🎁';
            _sbLines += '<div style="font-size:15px;font-weight:900;margin-top:2px;">' + esc(_sbSp) + ' げんてい ' + esc(_sbNm) + ' をゲット！</div>';
          }
          hero += '<div style="border-radius:14px;padding:12px;margin:8px 0 10px;text-align:center;background:linear-gradient(135deg,#fef3c7,#fde68a);border:2px solid #f59e0b;color:#7c2d12;">'
            + '<div style="font-size:20px;font-weight:900;">🏁 ステージ' + Number(_sb.stage) + ' クリア！</div>'
            + '<div style="font-size:13px;font-weight:800;margin:2px 0 6px;">つぎは ステージ' + Number(_sb.next || (Number(_sb.stage) + 1)) + '</div>'
            + _sbLines
            + '</div>';
        }
      } catch (e) {}
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
  /* DEF2FIX_FROZEN_STATS_20260909
     出陣時に保存されたステータスで戦わせる。決戦ボタンを押した児童の
     isDailyFatigued / getStarMultiplier が他人のモンスターに適用されるのを防ぐ。
     autoBattleRT は同期実行なので、finally で必ず元に戻る。 */
  function withFrozenStats(entries, fn){
    var g = window;
    var oGS = g.getStats, oFat = g.isDailyFatigued, oStar = g.getStarMultiplier;
    var q = {};
    (entries || []).forEach(function(e){
      var m = (e && e.monster) || null; if(!m) return;
      var k = Number(m.id) + '@' + Number(m.level || 1);
      (q[k] = q[k] || []).push(m);
    });
    try{
      if(typeof oFat  === 'function') g.isDailyFatigued  = function(){ return false; };
      if(typeof oStar === 'function') g.getStarMultiplier = function(){ return 1; };
      if(typeof oGS   === 'function') g.getStats = function(mon, lvl){
        var neutral = oGS.apply(this, arguments) || {};
        var k = Number(mon && mon.id) + '@' + Number(lvl || 1);
        var list = q[k];
        if(list && list.length){
          var m = list.shift();
          var hp = Number(m.hp || neutral.hp || neutral.maxHp || 1);
          return { hp: hp, maxHp: hp,
                   atk: Number(m.atk || neutral.atk || 1),
                   def: Number(m.def || neutral.def || 1),
                   spd: Number(neutral.spd || 10) };
        }
        return neutral;
      };
      return fn();
    } finally {
      if(typeof oGS   === 'function') g.getStats          = oGS;
      if(typeof oFat  === 'function') g.isDailyFatigued   = oFat;
      if(typeof oStar === 'function') g.getStarMultiplier = oStar;
    }
  }
  function buildBattle(st){
    var entries = (st.entries||[]).filter(function(e){return e && e.monster && e.monster.id;});
    var defenders = entries.map(function(e){ return {id:e.monster.id, level:e.monster.level||1, strategy:e.monster.strategy||e.strategy||'balance'}; });
    var programsA = entries.map(function(e){ return (e.monster.prog && e.monster.prog.length)? e.monster.prog : DEFAULT_PROG; });
    var enemies = (st.enemy_squad||[]).map(function(en){ return {raw:{name:en.name,sprite:en.sprite,hp:en.hp,atk:en.atk,def:en.def,buff:en.buff,skillPow:en.skillPow,elementType:en.elementType,skills:en.skills}, strategy:'attack'}; });
    var seed = seedFromKey(st.event_key);
    var rep = withFrozenStats(entries, function(){ return window.autoBattleRT(defenders, enemies, {bases:true,lanes:true,laneCount:3,seed:seed,program:true,programsA:programsA,programB:ENEMY_PROG,forts:false,tactics:true,contact:true}); });
    return {rep:rep, entries:entries, seed:seed};
  }

  /* ---- override implementations (each takes the captured original) ---- */
  function makeResolve(orig){
    var f = async function(){
      try{
        var st = await jget('/api/defense/status'); if(!st || !st.event_key || !st.decided){ if(typeof orig==='function') return orig.apply(this,arguments); return; }
        /* __DEF2_SKIP_LOCAL_V1__ すでに結果があるなら、端末で戦闘を回さずリプレイ再生に回す */
        if(st.result){ if(typeof window.openDefense==='function'){ try{ window.openDefense(); }catch(e){} } return; }
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
  /* DEF2_STAGE0A_GCHOME_20260911
     restoreGym() never cleared _gcHome, so a stale parent/next pair survived a
     re-render: insertBefore() then threw NotFoundError, was swallowed by catch,
     and gymChallengeBody stayed orphaned inside the replay area. */
  function restoreGym(){
    try{
      var g=document.getElementById('gymChallengeBody');
      var h=_gcHome;
      if(g && h && h.parent && document.contains(h.parent)){
        var nx=(h.next && h.next.parentNode===h.parent) ? h.next : null;
        h.parent.insertBefore(g, nx);
      }
    }catch(e){}
    _gcHome = null;
  }
  /* DEF2_STAGE0A_REPLAYEP_20260911
     Forward-compat: a later stage adds GET /api/defense/replay. Until it exists
     (404, or the SPA HTML returned with 200) fall back to the current
     /api/defense/status path, so today's behaviour is unchanged. */
  function def2GetReplayData(){
    function viaStatus(){
      return jget('/api/defense/status').then(function(st){
        return {st:st, log:(st && st.result) ? st.result.log : null};
      });
    }
    try{
      return fetch('/api/defense/replay',{cache:'no-store'}).then(function(r){
        if(!r || !r.ok) return null;
        var ct=(r.headers && r.headers.get && r.headers.get('content-type')) || '';
        if(ct.indexOf('json')<0) return null;
        return r.json();
      }).catch(function(){ return null; }).then(function(j){
        var lg = j && (j.log || (j.result && j.result.log));
        if(lg && !Array.isArray(lg) && lg.v===2){ return {st:(j.status||j), log:lg}; }
        return viaStatus();
      }).catch(function(){ return viaStatus(); });
    }catch(e){ return viaStatus(); }
  }

  function makeReplay(orig){
    var f = function(){
      var args=arguments, self=this;
      try{
        var rp=document.getElementById('defReplay'); if(!rp){ if(typeof orig==='function') return orig.apply(self,args); return; }
        /* DEF2_STAGE0A_CALLSITE_20260911 */
        def2GetReplayData().then(function(d){
          var st = d && d.st, log = d && d.log;
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
  /* ===== DEF2TRY_V1_MARK : 🧪 ためしバトル ==================================
     組んだ プログラムを、その場で なんかいでも ためす ところ。
     ・サーバには 1文字も かかない（よむのは GET /api/defense/status だけ）
     ・本番の きろく（けっか表）・コイン・ステージには いっさい さわらない
     ・たね は まいかい ランダム（本番と おなじ たね には しない）
     ・回数の せいげんは ない
     ・画面は 3だん（何も えらばなくても 1つの ボタンで はじまる）
     ======================================================================== */
  var TB = { allies:1, foes:1, power:'weak', move:'stop', open2:false, open3:false, busy:false, st:null };
  var TB_STAND = [{c:'always', a:'standStill'}];
  var TB_MENU = [
    {k:'mato',   t:'🎯 うごかない的と 1たい1', s:'さいしょは これ',  v:{allies:1,foes:1,power:'weak',  move:'stop'}},
    {k:'solo',   t:'⚔ ふつうの敵と 1たい1',   s:'',               v:{allies:1,foes:1,power:'normal',move:'go'}},
    {k:'team',   t:'🛡 みかた3・てき5',        s:'',               v:{allies:3,foes:5,power:'normal',move:'go'}},
    {k:'honban', t:'🔥 きょうの本番と おなじ', s:'みかた1・てき8',  v:{allies:1,foes:8,power:'normal',move:'go'}}
  ];
  var TB_ACTJA = {
    wait:'ようすを 見る', standStill:'うごかない', attackNearest:'近くの てきを こうげき',
    gather:'まん中に あつまる', scatter:'ちらばる', charge:'とつげき',
    advanceFront:'前に 出る', retreatBack:'下がる', defendPoint:'ポイントを まもる'
  };

  function tbActLabel(a){
    for(var i=0;i<ACT.length;i++){ if(ACT[i].v===a) return ACT[i].label; }
    return TB_ACTJA[a] || String(a);
  }

  function tbStatus(){
    if(TB.st) return Promise.resolve(TB.st);
    return jget('/api/defense/status').then(function(st){ if(st) TB.st=st; return st; });
  }

  /* いま えらばれている モンスターと さくせんを 画面から よむ。
     えらばれていなければ もっている 1ぴきめで ためす。 */
  function tbPick(){
    var id=null, strat=null, i, sty, bs, ss, mm, p, ks, inst, lvl=1;
    try{ if(window._defSelId!=null && Number(window._defSelId)>0) id=Number(window._defSelId); }catch(e){}
    try{ if(typeof window._defSelStrat==='string' && window._defSelStrat) strat=window._defSelStrat; }catch(e){}
    try{
      bs=document.querySelectorAll('button[onclick^="_defPick("]');
      if(!(id>0)){
        for(i=0;i<bs.length;i++){
          sty=bs[i].getAttribute('style')||'';
          if(sty.indexOf('#e11d48')>=0){ id=Number(String(bs[i].getAttribute('onclick')).replace(/[^0-9]/g,'')); break; }
        }
        if(!(id>0) && bs.length) id=Number(String(bs[0].getAttribute('onclick')).replace(/[^0-9]/g,''));
      }
      if(!strat){
        ss=document.querySelectorAll('button[onclick^="_defSetStrat("]');
        for(i=0;i<ss.length;i++){
          sty=ss[i].getAttribute('style')||'';
          if(sty.indexOf('#e11d48')>=0){ mm=String(ss[i].getAttribute('onclick')).match(/'([a-z]+)'/); if(mm) strat=mm[1]; break; }
        }
      }
    }catch(e){}
    if(!strat) strat='balance';
    if(!(id>0)){
      try{ p=progPlayer(); ks=(p && p.monsters) ? Object.keys(p.monsters) : []; if(ks.length) id=Number(ks[0]); }catch(e){}
    }
    if(!(id>0)) return null;
    try{ p=progPlayer(); inst=p && p.monsters && (p.monsters[id] || p.monsters[String(id)]); if(inst && inst.level) lvl=Math.max(1,Number(inst.level)); }catch(e){}
    return {id:id, level:lvl, strategy:strat};
  }

  /* あいて。「とまっている」を えらんだ ときは
     ふるまい（standStill）だけでなく 数も 下げて、ほんとうに 無害な 的にする。
     どちらか かたほうだけだと 半分 動いてしまい、
     「じぶんの プログラムの せいか あいての せいか」が 切りわけられない。 */
  function tbFoes(){
    var sq=(TB.st && TB.st.enemy_squad && TB.st.enemy_squad.length) ? TB.st.enemy_squad : null;
    var out=[], i, en, hp, atk, df, pw, sk, nm, sp;
    for(i=0;i<TB.foes;i++){
      en = sq ? (sq[i % sq.length] || sq[0])
              : {name:'まと', sprite:'🎯', hp:260, atk:18, def:8, buff:'lucky', elementType:'normal', skillPow:10, skills:[]};
      hp=Number(en.hp||200); atk=Number(en.atk||10); df=Number(en.def||5); pw=Number(en.skillPow||10);
      sk=Array.isArray(en.skills)?en.skills.slice():en.skills;
      nm=en.name; sp=en.sprite;
      if(TB.power==='weak'){ hp=Math.max(40,Math.round(hp*0.35)); df=Math.round(df*0.3); }
      if(TB.move==='stop'){ atk=1; pw=0; sk=[]; nm='うごかない まと'; sp='🎯'; }
      out.push({raw:{name:nm,sprite:sp,hp:hp,atk:atk,def:df,buff:en.buff,skillPow:pw,elementType:en.elementType,skills:sk}, strategy:'attack'});
    }
    return out;
  }

  /* ジムの アニメ置き場を こわさないための 見はり。
     もとの 場所が 消えていたら、見えない 置き場に あずける。 */
  function tbReleaseGym(){
    try{
      restoreGym();
      var g=document.getElementById('gymChallengeBody');
      var ov=document.getElementById('def2TryOverlay');
      if(g && ov && ov.contains(g)){
        var park=document.getElementById('def2GymPark');
        if(!park){ park=document.createElement('div'); park.id='def2GymPark'; park.style.cssText='display:none;'; document.body.appendChild(park); }
        park.appendChild(g);
      }
    }catch(e){}
  }

  function tbOverlay(html){
    tbReleaseGym();
    var ov=document.getElementById('def2TryOverlay');
    if(!ov){
      ov=document.createElement('div'); ov.id='def2TryOverlay';
      ov.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;z-index:99999;background:rgba(15,23,42,0.55);display:flex;align-items:center;justify-content:center;padding:10px;';
      ov.addEventListener('click', function(e){ if(e.target===ov) tbClose(); });
      var inner=document.createElement('div'); inner.id='def2TryPanel';
      inner.style.cssText='background:#fff;border-radius:14px;max-width:720px;width:100%;max-height:92vh;overflow:auto;box-shadow:0 18px 50px rgba(0,0,0,0.35);';
      ov.appendChild(inner); document.body.appendChild(ov);
    }
    document.getElementById('def2TryPanel').innerHTML=html;
    return ov;
  }

  function tbClose(){
    tbReleaseGym();
    var ov=document.getElementById('def2TryOverlay');
    if(ov && ov.parentNode) ov.parentNode.removeChild(ov);
  }

  function tbSorry(msg){
    tbOverlay('<div style="padding:18px;text-align:center;font-size:14px;color:#334155;">'+esc(msg)
      +'</div><div style="padding:0 18px 18px;"><button id="def2TryClose" style="width:100%;border:0;background:#e2e8f0;border-radius:10px;padding:10px;font-weight:900;cursor:pointer;">とじる</button></div>');
    var c=document.getElementById('def2TryClose'); if(c) c.addEventListener('click', tbClose);
  }

  /* DEF2TRY_RULETALLY_V1_MARK
     じぶんが 書いた ルール 1本ずつに 見えない ばんごうを つける。
     たたかいの まいコマには、そのとき うごいた ルールの ばんごうが
     もともと のこっているので、それを かぞえるだけで
     「どの めいれいが 何かい うごいたか」が わかる。
     0かいの めいれいを めだたせるのが ねらい。
     まえの わりあいバーは、この ひょうに まとめた。 */
  function tbNumberRules(prog){
    var out=[], i, r, o;
    for(i=0;i<(prog||[]).length;i++){
      r=prog[i]||{}; o={c:r.c,a:r.a,_id:(i+1)};
      if(r.cn!=null) o.cn=r.cn;
      out.push(o);
    }
    return out;
  }

  function tbCondLabel(r){
    var i, cd=null;
    for(i=0;i<COND.length;i++){ if(COND[i].v===r.c){ cd=COND[i]; break; } }
    if(!cd) return String(r.c||'');
    if(cd.num) return cd.label+' '+(r.cn!=null?r.cn:(cd.dflt||0))+'%';
    return cd.label;
  }

  function tbRuleLine(r){ return 'もし '+tbCondLabel(r)+' なら → '+tbActLabel(r.a); }

  function tbTallyHtml(rep, prog){
    var evs=(rep&&rep.events)||[], rules=prog||[], i, k, pa, p;
    var cnt={}, none=0, total=0, mx=1, zero=0, n, pct, on, out;
    for(i=0;i<evs.length;i++){
      pa=evs[i].posA; if(!pa) continue;
      for(k=0;k<pa.length;k++){
        p=pa[k]; if(!p||!p.act) continue;
        total++;
        if(p.n!=null&&p.n>0){ cnt[p.n]=(cnt[p.n]||0)+1; } else { none++; }
      }
    }
    if(!total||!rules.length) return '';
    for(i=0;i<rules.length;i++){ n=cnt[rules[i]._id]||0; if(n>mx) mx=n; }
    out='<div style="font-weight:900;font-size:13px;color:#334155;margin:10px 0 2px;">🧭 じぶんの めいれいは 何かい うごいた？</div>'
      +'<div style="font-size:11px;color:#64748b;margin-bottom:5px;">上から じゅんに 見て、さいしょに あてはまった 1つだけ うごくよ。</div>';
    for(i=0;i<rules.length;i++){
      n=cnt[rules[i]._id]||0; on=(n>0); pct=Math.round(n*100/mx); if(!on) zero++;
      out+='<div style="display:flex;align-items:center;gap:6px;margin:4px 0;font-size:12px;'
        +(on?'':'background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:4px 6px;')+'">'
        +'<div style="flex:0 0 20px;height:20px;line-height:20px;text-align:center;border-radius:999px;font-weight:900;color:#fff;background:'+(on?'#0d9488':'#f97316')+';">'+(i+1)+'</div>'
        +'<div style="flex:1;color:'+(on?'#334155':'#9a3412')+';font-weight:'+(on?'400':'900')+';">'+esc(tbRuleLine(rules[i]))
        +(on?'':'<br><span style="font-size:11px;font-weight:400;">1かいも うごかなかった</span>')+'</div>'
        +'<div style="flex:0 0 56px;background:#e2e8f0;border-radius:999px;height:9px;overflow:hidden;"><div style="width:'+pct+'%;height:100%;background:'+(on?'#0d9488':'#fdba74')+';"></div></div>'
        +'<div style="flex:0 0 58px;text-align:right;font-weight:900;color:'+(on?'#0f766e':'#9a3412')+';">'+n+'かい</div>'
        +'</div>';
    }
    if(none>0){
      out+='<div style="display:flex;align-items:center;gap:6px;margin:4px 0;font-size:12px;color:#64748b;">'
        +'<div style="flex:0 0 20px;text-align:center;">－</div>'
        +'<div style="flex:1;">どの めいれいにも あてはまらなかった とき</div>'
        +'<div style="flex:0 0 56px;"></div>'
        +'<div style="flex:0 0 58px;text-align:right;font-weight:900;">'+none+'かい</div></div>';
    }
    if(zero>0){
      out+='<div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:10px;padding:8px;font-size:12px;color:#9a3412;margin-top:6px;line-height:1.6;">'
        +'⚠ '+zero+'本の めいれいが 1かいも うごかなかったよ。<br>'
        +'じょうけんが あてはまらなかったのかも。上の ほうに 「いつも」が あると、そこで とまるよ。▲▼で じゅんばんを かえて、もういちど ためしてみよう。</div>';
    }
    return out;
  }

  function tbInfoHtml(rep, prog){
    var win=(rep && rep.winner==='A');
    var bmax=Number(rep.baseMax||380), ba=Number(rep.baseHpA), bb=Number(rep.baseHpB);
    var s='<div style="font-weight:900;font-size:16px;margin-bottom:4px;">'
      + (win ? '<span style="color:#047857;">🎉 かった！</span>' : '<span style="color:#b91c1c;">💧 まけた…</span>')
      + '<span style="font-size:11px;font-weight:400;color:#94a3b8;">　（れんしゅうです）</span></div>';
    if(TB.move==='stop'){
      s+='<div style="background:#ecfeff;border:1px solid #a5f3fc;border-radius:10px;padding:8px;font-size:12px;color:#155e75;margin-bottom:8px;">あいては うごきません。かちまけより、<b>じぶんの プログラムが モンスターを どう うごかしたか</b>を 見てね。</div>';
    }
    s+='<div style="font-size:12px;color:#334155;">みかたの 基地 '+(isFinite(ba)?Math.round(ba):'-')
      +' ／ あいての 基地 '+(isFinite(bb)?Math.round(bb):'-')
      +'（さいしょは '+bmax+'）　ターン '+(rep.ticks||0)+'</div>';
    s+=tbTallyHtml(rep, prog);
    s+='<div style="font-size:11px;color:#94a3b8;margin-top:8px;">たね '+((rep.seed||0)>>>0)+'（まいかい ランダム）。本番とは ちがう たねなので、ここで かてても 本番で かてるとは かぎりません。</div>';
    return s;
  }

  /* DEF2TRY_NOWCSS_V1_MARK
     ためしバトルの わくの 中だけ、あたまの上の 「いま：」を 大きく する。
     えらび方を #def2TryAnim に かぎっているので、
     みんなで見る 本番の リプレイ（#def2Anim）には あたらない。
     あいて（B）の ふきだしは 小さいままに して、
     じぶんの モンスターの ほうが 先に 目に入るようにする。 */
  function tbInjectNowCss(){
    if(document.getElementById('def2TryNowCss')) return;
    var st=document.createElement('style'); st.id='def2TryNowCss';
    st.textContent='#def2TryAnim .gc-now{font-size:12px !important;line-height:1.3 !important;opacity:1 !important;max-width:none !important;overflow:visible !important;text-overflow:clip !important;white-space:nowrap !important;padding:2px 7px !important;top:-19px !important;background:rgba(15,23,42,.95) !important;box-shadow:0 1px 4px rgba(0,0,0,.35) !important;z-index:9 !important;}'
      +'#def2TryAnim [id^="gc-now-B-"]{font-size:9px !important;opacity:.5 !important;top:-15px !important;box-shadow:none !important;z-index:8 !important;}';
    document.head.appendChild(st);
  }

  function tbShow(rep, prog){
    tbOverlay(
      '<div style="display:flex;align-items:center;gap:8px;padding:10px 12px;border-bottom:1px solid #e2e8f0;position:sticky;top:0;background:#fff;">'
      +'<div style="font-weight:900;color:#0f766e;">🧪 ためしバトル</div>'
      +'<div style="font-size:11px;color:#64748b;">きろくにも コインにも のこりません</div>'
      +'<div style="flex:1;"></div>'
      +'<button id="def2TryClose" style="border:0;background:#e2e8f0;border-radius:8px;padding:6px 12px;font-weight:900;cursor:pointer;">とじる</button></div>'
      +'<div id="def2TryAnim" style="position:relative;width:100%;min-height:320px;background:#0b1220;"></div>'
      +'<div id="def2TryInfo" style="padding:10px 12px;"></div>'
      +'<div style="padding:0 12px 12px;display:flex;gap:8px;">'
      +'<button id="def2TryAgain" style="flex:1;border:0;background:#0d9488;color:#fff;border-radius:10px;padding:10px;font-weight:900;cursor:pointer;">🧪 もういちど ためす</button>'
      +'<button id="def2TryBack" style="flex:1;border:2px solid #e2e8f0;background:#fff;border-radius:10px;padding:10px;font-weight:900;cursor:pointer;">プログラムを なおす</button></div>'
    );
    try{ document.getElementById('def2TryInfo').innerHTML=tbInfoHtml(rep, prog); }catch(e){}
    try{
      tbInjectNowCss();
      var host=document.getElementById('def2TryAnim');
      if(host && typeof window._defRenderBattle==='function'){ relocateGymInto(host); window._defRenderBattle(rep); }
    }catch(e){}
    var c=document.getElementById('def2TryClose'); if(c) c.addEventListener('click', tbClose);
    var b=document.getElementById('def2TryBack'); if(b) b.addEventListener('click', tbClose);
    var a=document.getElementById('def2TryAgain'); if(a) a.addEventListener('click', function(){ tbRun(); });
  }

  /* ここが 本体。autoBattleRT は 端末の中だけで うごき、
     サーバへは なにも おくらない（ジムの たたかいと おなじ しくみ）。 */
  function tbRun(){
    if(TB.busy) return;
    var pick=tbPick();
    if(!pick){ tbSorry('さきに モンスターを えらんでね。'); return; }
    if(typeof window.autoBattleRT!=='function'){ tbSorry('いま ためせません。ページを もういちど ひらいてね。'); return; }
    TB.busy=true;
    tbStatus().then(function(){
      var prog=progFromRules(); if(!prog || !prog.length) prog=DEFAULT_PROG;
      prog=tbNumberRules(prog);
      var A=[], pa=[], i, rep=null;
      for(i=0;i<TB.allies;i++){ A.push({id:pick.id, level:pick.level, strategy:pick.strategy}); pa.push(prog); }
      var pb=(TB.move==='stop') ? TB_STAND : ENEMY_PROG;
      var seed=(Math.floor(Math.random()*4294967296)>>>0);
      try{
        rep=window.autoBattleRT(A, tbFoes(), {bases:true,lanes:true,laneCount:3,seed:seed,program:true,programsA:pa,programsB:[pb],forts:false,tactics:true,contact:true});
      }catch(e){ rep=null; }
      TB.busy=false;
      if(!rep){ tbSorry('うまく うごきませんでした。もういちど ためしてね。'); return; }
      tbShow(rep, prog);
    }).catch(function(){ TB.busy=false; tbSorry('うまく うごきませんでした。もういちど ためしてね。'); });
  }

  function tbIsPreset(v){ return TB.allies===v.allies && TB.foes===v.foes && TB.power===v.power && TB.move===v.move; }

  function tbRow(label, id, opts, cur){
    var o='', i;
    for(i=0;i<opts.length;i++) o+='<option value="'+opts[i][0]+'"'+(opts[i][0]===cur?' selected':'')+'>'+opts[i][1]+'</option>';
    return '<div style="display:flex;align-items:center;gap:8px;"><div style="width:112px;color:#334155;">'+label+'</div>'
      +'<select id="'+id+'" style="flex:1;padding:6px;border:1px solid #cbd5e1;border-radius:8px;font-size:13px;">'+o+'</select></div>';
  }

  function tbUiHtml(){
    var i, it, on, s='';
    s+='<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px;">'
      +'<div style="font-weight:900;font-size:13px;color:#0f766e;">🧪 ためす</div>'
      +'<div style="font-size:11px;color:#64748b;">れんしゅう。きろくにも コインにも のこりません</div></div>';
    s+='<button id="def2TryGo" style="width:100%;border:0;background:#0d9488;color:#fff;border-radius:12px;padding:14px;font-weight:900;font-size:17px;cursor:pointer;">🧪 ためしてみる</button>';
    s+='<div style="text-align:center;margin-top:6px;"><button id="def2TryMore" style="border:0;background:transparent;color:#64748b;font-size:12px;cursor:pointer;text-decoration:underline;">くわしく えらぶ '+(TB.open2?'▲':'▼')+'</button></div>';
    if(TB.open2){
      s+='<div style="margin-top:6px;display:grid;gap:6px;">';
      for(i=0;i<TB_MENU.length;i++){
        it=TB_MENU[i]; on=tbIsPreset(it.v);
        s+='<button class="def2TryPre" data-k="'+it.k+'" style="text-align:left;border:2px solid '+(on?'#0d9488':'#e2e8f0')+';background:'+(on?'#f0fdfa':'#fff')+';border-radius:10px;padding:8px 10px;cursor:pointer;font-weight:900;font-size:13px;">'+it.t
          +(it.s?'<span style="font-weight:400;font-size:11px;color:#64748b;">　'+it.s+'</span>':'')+'</button>';
      }
      s+='</div>';
      s+='<div style="text-align:center;margin-top:6px;"><button id="def2TryTune" style="border:0;background:transparent;color:#94a3b8;font-size:11px;cursor:pointer;text-decoration:underline;">つまみを ひらく '+(TB.open3?'▲':'▼')+'</button></div>';
      if(TB.open3){
        s+='<div style="margin-top:6px;background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:8px;display:grid;gap:6px;font-size:13px;">'
          + tbRow('みかたの数','def2TryAllies',[['1','1'],['2','2'],['3','3']],String(TB.allies))
          + tbRow('てきの数','def2TryFoes',[['1','1'],['3','3'],['5','5'],['8','8']],String(TB.foes))
          + tbRow('てきの つよさ','def2TryPower',[['weak','よわい'],['normal','ふつう（本番とおなじ）']],TB.power)
          + tbRow('てきの うごき','def2TryMove',[['stop','とまっている'],['go','うごく']],TB.move)
          +'</div>';
        if(TB.allies>1) s+='<div style="font-size:11px;color:#64748b;margin-top:4px;">みかたは ぜんいんに コピーした おなじ プログラムで うごきます。</div>';
      }
    }
    return s;
  }

  function tbBind(id, fn){
    var el=document.getElementById(id);
    if(el) el.addEventListener('change', function(){ fn(this.value); tbRenderUi(); });
  }

  function tbRenderUi(){
    var box=document.getElementById('def2TryBox'); if(!box) return;
    box.innerHTML=tbUiHtml();
    var g=document.getElementById('def2TryGo'); if(g) g.addEventListener('click', function(){ tbRun(); });
    var m=document.getElementById('def2TryMore'); if(m) m.addEventListener('click', function(){ TB.open2=!TB.open2; tbRenderUi(); });
    var t=document.getElementById('def2TryTune'); if(t) t.addEventListener('click', function(){ TB.open3=!TB.open3; tbRenderUi(); });
    var ps=box.querySelectorAll('.def2TryPre'), i;
    for(i=0;i<ps.length;i++){
      ps[i].addEventListener('click', function(){
        var k=this.getAttribute('data-k'), j;
        for(j=0;j<TB_MENU.length;j++){
          if(TB_MENU[j].k===k){ TB.allies=TB_MENU[j].v.allies; TB.foes=TB_MENU[j].v.foes; TB.power=TB_MENU[j].v.power; TB.move=TB_MENU[j].v.move; }
        }
        tbRenderUi();
      });
    }
    tbBind('def2TryAllies', function(v){ TB.allies=Number(v)||1; });
    tbBind('def2TryFoes',   function(v){ TB.foes=Number(v)||1; });
    tbBind('def2TryPower',  function(v){ TB.power=v; });
    tbBind('def2TryMove',   function(v){ TB.move=v; });
  }

  /* プログラム欄の すぐ下に おく。出陣ボタンとは 点線で はっきり 分ける。 */
  function tryMountTryBattle(){
    if(document.getElementById('def2TryBox')) return;
    var prog=document.getElementById('def2ProgBox');
    if(!prog || !prog.parentNode) return;
    var box=document.createElement('div'); box.id='def2TryBox';
    box.style.cssText='background:#f0fdfa;border:1px solid #99f6e4;border-radius:10px;padding:10px;margin:8px 0 0;';
    prog.parentNode.insertBefore(box, prog.nextSibling);
    var sep=document.createElement('div'); sep.id='def2TrySep';
    sep.style.cssText='border-top:2px dashed #cbd5e1;margin:14px 0 8px;padding-top:8px;text-align:center;font-size:11px;color:#94a3b8;font-weight:900;';
    sep.textContent='ここから下は ほんばん';
    prog.parentNode.insertBefore(sep, box.nextSibling);
    tbRenderUi();
  }

  function install(){
    try{
      if(typeof window._defStartResolve==='function' && !window._defStartResolve.__def2) window._defStartResolve = makeResolve(window._defStartResolve);
      if(typeof window._defShowReplay==='function' && !window._defShowReplay.__def2) window._defShowReplay = makeReplay(window._defShowReplay);
      if(typeof window._defDoSubmit==='function' && !window._defDoSubmit.__def2) window._defDoSubmit = makeSubmit(window._defDoSubmit);
      if(typeof window.closeDefense==='function' && !window.closeDefense.__def2) window.closeDefense = makeClose(window.closeDefense);
    }catch(e){}
    tryMountEditor(); tryMountTryBattle();
  }
  install();
  if(document.readyState!=='complete') window.addEventListener('load', install);
  setInterval(install, 700);
})();
