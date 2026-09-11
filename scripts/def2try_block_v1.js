  /* ===== DEF2TRY_V1_MARK : 🧪 ためしバトル ==================================
     組んだ プログラムを、その場で なんかいでも ためす ところ。
     ・サーバには 1文字も かかない（よむのは GET /api/defense/status だけ）
     ・本番の きろく・コイン・ステージ・defense_results には いっさい さわらない
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

  function tbTallyHtml(rep, prog){
    var m={}, total=0, evs=(rep && rep.events) || [], i, k, pa, a, keys, pct, out, used, never;
    for(i=0;i<evs.length;i++){
      pa=evs[i].posA; if(!pa) continue;
      for(k=0;k<pa.length;k++){ a=pa[k] && pa[k].act; if(!a) continue; m[a]=(m[a]||0)+1; total++; }
    }
    keys=Object.keys(m);
    if(!total || !keys.length) return '';
    keys.sort(function(x,y){ return m[y]-m[x]; });
    out='<div style="font-weight:900;font-size:13px;color:#334155;margin:10px 0 4px;">🧭 じぶんの モンスターが した こと</div>';
    for(i=0;i<keys.length;i++){
      pct=Math.round(m[keys[i]]*100/total);
      out+='<div style="display:flex;align-items:center;gap:6px;margin:3px 0;font-size:12px;">'
        +'<div style="width:150px;color:#334155;">'+esc(tbActLabel(keys[i]))+'</div>'
        +'<div style="flex:1;background:#e2e8f0;border-radius:999px;height:10px;overflow:hidden;"><div style="width:'+pct+'%;height:100%;background:#0d9488;"></div></div>'
        +'<div style="width:42px;text-align:right;color:#64748b;">'+pct+'%</div></div>';
    }
    used={}; for(i=0;i<keys.length;i++) used[keys[i]]=1;
    never=[];
    for(i=0;i<(prog||[]).length;i++){ if(!used[prog[i].a] && never.indexOf(prog[i].a)<0) never.push(prog[i].a); }
    if(never.length){
      out+='<div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:10px;padding:8px;font-size:12px;color:#9a3412;margin-top:6px;">⚠ 1かいも つかわれなかった めいれい: '
        + never.map(function(x){ return esc(tbActLabel(x)); }).join('、')
        + '<br>じょうけんが 当てはまらなかったのかも。上の行から じゅんに 見られていくよ。</div>';
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

