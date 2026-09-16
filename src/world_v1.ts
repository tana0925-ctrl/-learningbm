// __WORLD_V1__ 3周目「世界編」第1段（あそべる箱だけ）
// キャラ10体と ごほうびは 第2段。ここでは1体も配らない。
//
// やくそく
//  - public/index.html は手で編集しない。ここの文字列を src/index.tsx のチェーンが当てる。
//  - アンカーが見つからないときは throw せず console.error して飛ばす。
//    （チェーンは try/catch に包まれていて、throw すると全件が黙って消えるため）
//  - 書いてよい進行データは worldCurrent / worldCleared / worldAllCleared の3つだけ。
//    current / clearedMax / unlocked / zombieCleared は読むだけ。
//  - むずかしさは 実効idx = 23 + i（i は 0〜23 → 23〜46。clamp上限46にちょうど収まる）

export type WorldPatch = { tag: string, a: string, b: string }

// ---- 1) 24ステージのデータと 世界編の関数いっしき --------------------------
const A_DATA = '  const ZOMBIE_ALLCLEAR_MONSTER_ID = 1201;'

const B_DATA = A_DATA + `
  /* __WORLD_V1__ 3周目「世界編」。自前の24ステージ（都道府県の使い回しではない） */
  (function(){
    try{
      var WS = [
        { city:'ソウル', country:'かんこく', flag:'🇰🇷', icon:'🏙️', color:'#60a5fa' },
        { city:'ペキン', country:'ちゅうごく', flag:'🇨🇳', icon:'🐼', color:'#ef4444' },
        { city:'バンコク', country:'タイ', flag:'🇹🇭', icon:'🐘', color:'#f59e0b' },
        { city:'デリー', country:'インド', flag:'🇮🇳', icon:'🕌', color:'#f97316' },
        { city:'シドニー', country:'オーストラリア', flag:'🇦🇺', icon:'🐨', color:'#84cc16' },
        { city:'オークランド', country:'ニュージーランド', flag:'🇳🇿', icon:'🌋', color:'#10b981' },
        { city:'なんきょくてん', country:'なんきょく', flag:'🇦🇶', icon:'🐧', color:'#38bdf8' },
        { city:'ドバイ', country:'アラブしゅちょうこくれんぽう', flag:'🇦🇪', icon:'🐫', color:'#eab308' },
        { city:'カイロ', country:'エジプト', flag:'🇪🇬', icon:'🏜️', color:'#d97706' },
        { city:'ナイロビ', country:'ケニア', flag:'🇰🇪', icon:'🦁', color:'#ca8a04' },
        { city:'ケープタウン', country:'みなみアフリカ', flag:'🇿🇦', icon:'🏔️', color:'#0ea5e9' },
        { city:'モスクワ', country:'ロシア', flag:'🇷🇺', icon:'⛄', color:'#93c5fd' },
        { city:'イスタンブール', country:'トルコ', flag:'🇹🇷', icon:'🌉', color:'#f43f5e' },
        { city:'ローマ', country:'イタリア', flag:'🇮🇹', icon:'🏛️', color:'#22c55e' },
        { city:'ベルリン', country:'ドイツ', flag:'🇩🇪', icon:'🎭', color:'#a16207' },
        { city:'パリ', country:'フランス', flag:'🇫🇷', icon:'🗼', color:'#6366f1' },
        { city:'ロンドン', country:'イギリス', flag:'🇬🇧', icon:'🕰️', color:'#3b82f6' },
        { city:'リマ', country:'ペルー', flag:'🇵🇪', icon:'🏺', color:'#b45309' },
        { city:'リオデジャネイロ', country:'ブラジル', flag:'🇧🇷', icon:'🎡', color:'#16a34a' },
        { city:'ブエノスアイレス', country:'アルゼンチン', flag:'🇦🇷', icon:'💃', color:'#06b6d4' },
        { city:'メキシコシティ', country:'メキシコ', flag:'🇲🇽', icon:'🌵', color:'#65a30d' },
        { city:'トロント', country:'カナダ', flag:'🇨🇦', icon:'🍁', color:'#dc2626' },
        { city:'サンフランシスコ', country:'アメリカ', flag:'🇺🇸', icon:'🌁', color:'#8b5cf6' },
        { city:'ニューヨーク', country:'アメリカ', flag:'🇺🇸', icon:'🗽', color:'#0891b2' }
      ];
      window.WORLD_STAGES = WS;
      window.WORLD_TOTAL = 24;
      window.WORLD_CONTS = [
        { name:'アジア', icon:'🌏', from:0, to:3 },
        { name:'オセアニア・南きょく', icon:'🌊', from:4, to:6 },
        { name:'中東・アフリカ', icon:'🌍', from:7, to:10 },
        { name:'ヨーロッパ', icon:'🏰', from:11, to:16 },
        { name:'南アメリカ', icon:'🌴', from:17, to:19 },
        { name:'北アメリカ', icon:'🌎', from:20, to:23 }
      ];

      function P(){ try{ return (typeof player !== 'undefined' && player) ? player : (window.player || null); }catch(e){ return window.player || null; } }
      function WP(){ var p = P(); return (p && p.warProgress) ? p.warProgress : null; }

      /* 世界編だけの入れもの。ここで作るのは worldCurrent / worldCleared / worldAllCleared の3つだけ */
      window.worldEnsure = function(){
        var wp = WP();
        if(!wp) return null;
        if(typeof wp.worldCurrent !== 'number') wp.worldCurrent = 0;
        if(!wp.worldCleared || typeof wp.worldCleared !== 'object') wp.worldCleared = {};
        if(typeof wp.worldAllCleared !== 'boolean') wp.worldAllCleared = false;
        if(wp.worldCurrent < 0) wp.worldCurrent = 0;
        if(wp.worldCurrent > 23) wp.worldCurrent = 23;
        return wp;
      };
      window.worldGetCurrent = function(){ var wp = window.worldEnsure(); return wp ? (Number(wp.worldCurrent) || 0) : 0; };
      /* むずかしさ：実効idx = 23 + i（0〜23 → 23〜46） */
      window.worldEffIdx = function(i){ var n = Number(i) || 0; if(n < 0) n = 0; if(n > 23) n = 23; return 23 + n; };

      /* --- 解放条件：1周目47県クリア かつ ゾンビ襲来10ステージクリア（読むだけ） --- */
      window.worldJpCleared = function(){ var wp = WP(); return wp ? (Number(wp.clearedMax) || 0) : 0; };
      window.worldZombieCount = function(){
        var wp = WP(); if(!wp) return 0;
        var zc = (wp.zombieCleared && typeof wp.zombieCleared === 'object') ? wp.zombieCleared : {};
        var n = 0; for(var k = 0; k < 47; k++){ if(zc[String(k)]) n++; }
        return n;
      };
      window.WORLD_NEED_JP = 47;
      window.WORLD_NEED_ZOMBIE = 10;
      window.warWorldUnlocked = function(){
        try{ return (window.worldJpCleared() >= window.WORLD_NEED_JP) && (window.worldZombieCount() >= window.WORLD_NEED_ZOMBIE); }
        catch(e){ console.error('[__WORLD_V1__] unlockCheck', e); return false; }
      };

      window.worldClearedCount = function(){
        var wp = window.worldEnsure(); if(!wp) return 0;
        var n = 0; for(var k = 0; k < 24; k++){ if(wp.worldCleared[String(k)]) n++; }
        return n;
      };
      /* 順番にひらく：まだクリアしていない いちばん手前まで */
      window.worldOpenCount = function(){
        var wp = window.worldEnsure(); if(!wp) return 1;
        var c = 0; while(c < 24 && wp.worldCleared[String(c)]) c++;
        return Math.min(24, c + 1);
      };
      window.worldStageLabel = function(){
        try{ var w = WS[window.worldGetCurrent()]; return w ? (w.flag + ' ' + w.city) : ''; }
        catch(e){ return ''; }
      };

      /* --- 🗾日本 / 🌍世界編 のタブ（未解放でも鍵つきで見せる） --- */
      window.worldTabsHtml = function(isWorld){
        var un = window.warWorldUnlocked();
        var base = 'flex-1 px-2 py-2 rounded-xl font-black text-xs border-2 ';
        var onCls = base + 'bg-gradient-to-r from-pink-500 to-purple-600 text-white border-white shadow';
        var offCls = base + 'bg-white text-gray-600 border-gray-300';
        var lockCls = base + 'bg-gray-100 text-gray-500 border-gray-200';
        var wLabel = un
          ? ('🌍 世界編 ' + window.worldClearedCount() + '/24')
          : ('🌍 世界編 🔒 1周目 ' + window.worldJpCleared() + '/47・ゾンビ ' + window.worldZombieCount() + '/10');
        var h = '<div id="worldTabBar" class="flex gap-2 mb-2">';
        h += '<button type="button" class="' + (isWorld ? offCls : onCls) + '" onclick="worldSwitchTab(false)">🗾 日本</button>';
        h += '<button type="button" class="' + (isWorld ? onCls : (un ? offCls : lockCls)) + '" onclick="worldSwitchTab(true)">' + wLabel + '</button>';
        h += '</div>';
        return h;
      };
      window.worldMountTabs = function(modal, isWorld){
        try{
          if(!modal) return;
          var host = modal.querySelector('.flex.flex-col.h-full') || modal.firstElementChild;
          if(!host) return;
          if(host.querySelector('#worldTabBar')) return;
          var box = document.createElement('div');
          box.innerHTML = window.worldTabsHtml(!!isWorld);
          if(box.firstChild) host.insertBefore(box.firstChild, host.firstChild);
        }catch(e){ console.error('[__WORLD_V1__] mountTabs', e); }
      };
      window.worldSwitchTab = function(toWorld){
        try{
          if(toWorld && !window.warWorldUnlocked()){
            try{ alert('🌍 世界編は、1周目の47県ぜんぶクリア と 🧟ゾンビ襲来 10ステージクリア でひらくよ！ いま 1周目 ' + window.worldJpCleared() + '/47・ゾンビ ' + window.worldZombieCount() + '/10'); }catch(e){}
            return;
          }
          if(window.warState){
            window.warState.worldMode = !!toWorld;
            if(toWorld) window.warState.zombieMode = false;
          }
          try{ if(typeof warApplyZombieBg === 'function') warApplyZombieBg(); }catch(e){}
          if(window.renderWarStageList) window.renderWarStageList();
          else console.error('[__WORLD_V1__] renderWarStageList not found');
        }catch(e){ console.error('[__WORLD_V1__] switchTab', e); }
      };

      /* --- 大陸別のステージ一覧（日本の地方別カードと同じ見た目） --- */
      window.worldRenderList = function(modal){
        try{
          if(!modal) return;
          var wp = window.worldEnsure();
          var open = window.worldOpenCount();
          var done = window.worldClearedCount();
          var gf = (typeof warGetStageConfig === 'function') ? warGetStageConfig : (window.warGetStageConfig || null);
          var h = '<div class="flex flex-col h-full min-h-0">';
          h += window.worldTabsHtml(true);
          h += '<div class="bg-gradient-to-r from-indigo-600 to-sky-500 rounded-xl px-3 py-2 mb-2 shadow-lg">';
          h += '<div class="flex items-center justify-between text-white">';
          h += '<div><h2 class="text-base font-black" style="font-family: var(--rpg-font);">🌍 世界の都市をえらぶ</h2>';
          h += '<p class="text-[9px] leading-none opacity-90">3周目「世界編」ぜんぶで24ステージ!</p></div>';
          h += '<div class="text-right"><div class="text-lg leading-none font-black">' + done + '/<span>24</span></div>';
          h += '<div class="text-[9px] leading-none opacity-90">クリア済み</div></div></div>';
          h += '<div class="mt-1 h-1 bg-white/30 rounded-full overflow-hidden"><div class="h-full bg-gradient-to-r from-yellow-300 to-yellow-500" style="width: ' + (done / 24 * 100) + '%"></div></div>';
          h += '</div>';
          h += '<div class="flex-1 overflow-y-auto pr-1 min-h-0" style="scrollbar-width: thin;">';
          var CS = window.WORLD_CONTS;
          for(var c = 0; c < CS.length; c++){
            var g = CS[c];
            var gd = 0;
            for(var k = g.from; k <= g.to; k++){ if(wp && wp.worldCleared[String(k)]) gd++; }
            h += '<div class="mb-4">';
            h += '<div class="bg-gradient-to-r from-white to-sky-50 rounded-lg p-2 mb-2 border-l-4 border-sky-400 flex items-center justify-between">';
            h += '<div class="font-black text-sm text-gray-800">' + g.icon + ' ' + g.name + '</div>';
            h += '<div class="text-xs font-bold text-gray-500">' + gd + '/' + (g.to - g.from + 1) + '</div>';
            h += '</div>';
            h += '<div class="overflow-x-auto pb-2" style="scrollbar-width: thin;"><div class="flex gap-3 px-1">';
            for(var i = g.from; i <= g.to; i++){
              var s = WS[i];
              var isCleared = !!(wp && wp.worldCleared[String(i)]);
              var isLocked = (i >= open);
              var isCurrent = !!(wp && Number(wp.worldCurrent) === i);
              var cls = 'war-stage-card' + (isCleared ? ' cleared' : '') + (isLocked ? ' locked' : '') + (isCurrent ? ' current' : '');
              var cfg = null;
              try{ if(gf) cfg = gf(window.worldEffIdx(i)); }catch(e){ cfg = null; }
              var lv = cfg ? Math.ceil((cfg.diff || 1) * 10) : (24 + i);
              h += '<div class="' + cls + '" data-index="' + i + '"' + (isLocked ? '' : (' onclick="selectWorldStage(' + i + ')"')) + ' style="background: linear-gradient(135deg, ' + s.color + '20, ' + s.color + '40); border-color: ' + s.color + ';">';
              if(isCleared) h += '<div class="war-stage-clear-badge">⭐</div>';
              if(isLocked) h += '<div class="war-stage-lock-overlay">🔒</div>';
              h += '<div class="war-stage-icon">' + s.icon + '</div>';
              h += '<div class="war-stage-name">' + s.flag + ' ' + s.city + '</div>';
              h += '<div class="war-stage-difficulty">';
              h += '<div class="flex items-center justify-between text-xs mb-1"><span class="text-gray-600">' + s.country + '</span><span class="font-bold text-gray-800">Lv.' + lv + '</span></div>';
              h += '<div class="h-1 bg-gray-200 rounded-full overflow-hidden"><div class="h-full bg-gradient-to-r from-sky-400 to-indigo-600" style="width: ' + Math.min(100, (i + 1) / 24 * 100) + '%"></div></div>';
              h += '</div>';
              h += '<div class="war-stage-reward">🎁 コイン＆ひでんの書</div>';
              h += '</div>';
            }
            h += '</div></div></div>';
          }
          h += '</div></div>';
          modal.innerHTML = h;
        }catch(e){ console.error('[__WORLD_V1__] renderList', e); }
      };

      /* --- ステージをえらぶ。書くのは worldCurrent だけ --- */
      window.selectWorldStage = function(i){
        try{
          if(!window.warWorldUnlocked()) return;
          var wp = window.worldEnsure(); if(!wp) return;
          var n = Number(i) || 0;
          if(n < 0 || n > 23) return;
          if(n >= window.worldOpenCount()) return;
          wp.worldCurrent = n;
          if(window.warState){ window.warState.worldMode = true; window.warState.zombieMode = false; }
          try{ (window.saveData || saveData)(); }catch(e){ console.error('[__WORLD_V1__] save', e); }
          try{ var up = document.getElementById('warUpgradePanel'); if(up) up.classList.add('hidden'); }catch(e){}
          try{ if(typeof recordLimitedUseForParty === 'function') recordLimitedUseForParty('war'); }catch(e){}
          try{ if(window.closeWarStageSelect) window.closeWarStageSelect(); }catch(e){}
          try{ if(window.showWarEnemyPreview){ window.showWarEnemyPreview(window.worldEffIdx(n)); return; } }catch(e){ console.error('[__WORLD_V1__] preview', e); }
        }catch(e){ console.error('[__WORLD_V1__] selectWorldStage', e); }
      };
      window.selectWorldStageFromUI = function(i){ try{ return window.selectWorldStage(i); }catch(e){ console.error('[__WORLD_V1__] fromUI', e); } };

      /* --- 勝ったときの記録。worldCleared / worldAllCleared だけ書く --- */
      window.worldRecordClear = function(){
        try{
          var wp = window.worldEnsure(); if(!wp) return;
          var i = window.worldGetCurrent();
          wp.worldCleared[String(i)] = true;
          if(window.worldClearedCount() >= 24) wp.worldAllCleared = true;
          try{ (window.saveData || saveData)(); }catch(e){ console.error('[__WORLD_V1__] save', e); }
        }catch(e){ console.error('[__WORLD_V1__] recordClear', e); }
      };
    }catch(e){ console.error('[__WORLD_V1__] init', e); }
  })();
`

// ---- 2) ステージ一覧：世界編なら大陸別カードを描いて return ----------------
const A_LIST = '    // 都道府県データを地域別に整理'

const B_LIST = `    /* __WORLD_V1__ 世界編のときは 大陸別の一覧を出して おわり */
    try{
      if(window.warState && window.warState.worldMode){
        if(window.worldRenderList){ window.worldRenderList(modal); return; }
        else console.error('[__WORLD_V1__] worldRenderList not found');
      }
    }catch(e){ console.error('[__WORLD_V1__] listBranch', e); }
` + A_LIST

// ---- 3) 🗾日本 / 🌍世界編 のタブを 一覧の上にのせる -------------------------
const A_TABS = '    modal.innerHTML = html;'

const B_TABS = A_TABS + `
    /* __WORLD_V1__ 日本の一覧の上に タブをのせる（未解放でも鍵つきで見える） */
    try{ if(window.worldMountTabs) window.worldMountTabs(modal, false); }catch(e){ console.error('[__WORLD_V1__] tabs', e); }`

// ---- 4) 戦闘の中身：ステージ名は都市名、むずかしさは 23+i ------------------
const A_APPLY = `    warState.stageName = WAR_PREFS[idx] || '---';

    const cfg = warGetStageConfig(idx);`

const B_APPLY = `    warState.stageName = WAR_PREFS[idx] || '---';

    /* __WORLD_V1__ 世界編は自前の24ステージ。実効idx = 23 + i（23〜46） */
    var __wEff = idx;
    try{
      if(window.warState && window.warState.worldMode && window.worldGetCurrent){
        var __wi = window.worldGetCurrent();
        warState.worldIndex = __wi;
        warState.stageIndex = __wi;
        warState.stageName = (window.worldStageLabel && window.worldStageLabel()) || '---';
        __wEff = window.worldEffIdx(__wi);
      }
    }catch(e){ console.error('[__WORLD_V1__] applyStage', e); }

    const cfg = warGetStageConfig(__wEff);`

// ---- 5) 日本のステージをえらんだら 世界編からぬける ------------------------
const A_SELJP = '  window.selectWarStage = function(i){'

const B_SELJP = A_SELJP + `
    /* __WORLD_V1__ 日本のステージをえらんだら 世界編モードを おりる */
    try{ if(window.warState) window.warState.worldMode = false; }catch(e){ console.error('[__WORLD_V1__] exitWorld', e); }`

// ---- 6) 敵プレビューの見出しを 都市名にする -------------------------------
const A_PVNAME = "  document.getElementById('previewStageName').textContent = stageName + ' ステージ';"

const B_PVNAME = `  /* __WORLD_V1__ 世界編のときは 県名ではなく 都市名を出す */
  var __pvName = stageName + ' ステージ';
  try{
    if(window.warState && window.warState.worldMode && window.worldStageLabel){
      var __wl = window.worldStageLabel();
      var __wsNow = window.WORLD_STAGES ? window.WORLD_STAGES[window.worldGetCurrent()] : null;
      if(__wl) __pvName = __wl + '（' + (__wsNow ? __wsNow.country : '') + '）';
    }
  }catch(e){ console.error('[__WORLD_V1__] previewName', e); }
  document.getElementById('previewStageName').textContent = __pvName;`

// ---- 7) 世界編では 県ボスの紹介を出さない ---------------------------------
const A_PVBOSS = '  if (cfg.boss && cfg.boss.monsterId) {'

const B_PVBOSS = '  if (cfg.boss && cfg.boss.monsterId && !(window.warState && window.warState.worldMode)) {'

// ---- 8) 世界編では 🧟ゾンビ襲来ボタンを出さない ---------------------------
const A_ZBTN = '      const canZombie = (stageIndex < cleared);'

const B_ZBTN = '      const canZombie = (stageIndex < cleared) && !(window.warState && window.warState.worldMode);'

// ---- 9) 勝ったら worldCleared に記録（勝つたびに必ず通る場所） -------------
const A_WIN = '        let gotBossId = null;'

const B_WIN = A_WIN + `
        /* __WORLD_V1__ 世界編のクリアを記録する。ここは勝ったとき必ず通る */
        try{
          if(window.warState && window.warState.worldMode){
            if(window.worldRecordClear) window.worldRecordClear();
            else console.error('[__WORLD_V1__] worldRecordClear not found');
          }
        }catch(e){ console.error('[__WORLD_V1__] winRecord', e); }`

// ---- 10) 世界編では 県ボスの報酬を配らない -------------------------------
const A_BOSS = '          const boss = stageName ? (WAR_PREF_BOSS[stageName]||null) : null;'

const B_BOSS = '          const boss = (window.warState && window.warState.worldMode) ? null : (stageName ? (WAR_PREF_BOSS[stageName]||null) : null);'

export const WORLD_V1_PATCHES: WorldPatch[] = [
  { tag: 'W01_data', a: A_DATA, b: B_DATA },
  { tag: 'W02_list', a: A_LIST, b: B_LIST },
  { tag: 'W03_tabs', a: A_TABS, b: B_TABS },
  { tag: 'W04_apply', a: A_APPLY, b: B_APPLY },
  { tag: 'W05_seljp', a: A_SELJP, b: B_SELJP },
  { tag: 'W06_pvname', a: A_PVNAME, b: B_PVNAME },
  { tag: 'W07_pvboss', a: A_PVBOSS, b: B_PVBOSS },
  { tag: 'W08_zbtn', a: A_ZBTN, b: B_ZBTN },
  { tag: 'W09_win', a: A_WIN, b: B_WIN },
  { tag: 'W10_boss', a: A_BOSS, b: B_BOSS }
]
