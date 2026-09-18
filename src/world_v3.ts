// __WORLD_V3__ 3周目「世界編」第3段（宇宙人化＝青い敵 ＋ 洗脳）
//
// やくそく（第1段・第2段と同じ）
//  - public/index.html は手で編集しない。ここの文字列を src/index.tsx のチェーンが当てる。
//  - アンカーが見つからないときは throw せず console.error して飛ばす。
//  - 既存の進行データ（current / clearedMax / unlocked / zombieCleared）は読むだけ。
//
// 宇宙人化は「敵の種類」ではなく「どのキャラにも乗せられる状態」。
//  - MONSTERS を1体も増やさない → 図鑑は1体も増えない
//  - 見た目は CSS のフィルタ（色違い .shiny-mon と同じ作法）。絵文字は差し替えない
//  - 窓口は worldAlienApply / worldAlienRelease
//
// 洗脳（先生の確定仕様）
//  - 宇宙人の攻撃を受けると 確率で洗脳される。敵になり 元の仲間を攻撃する。
//  - ⚠️ その戦いのあいだ 解けない。寝返った味方は 倒されて そのまま消える。
//    子どもから見ると「自分のキャラが青くなって敵に回り、戦力が1体減る」。はっきりした罰。
//    戻す関数（worldAlienRelease / worldMindRelease）は 残してあるが 自動では呼ばれない。
//  - 強化は 攻撃力ではなく HP。1.2倍の攻撃力は 生存時間に効かず、1秒前後で倒れてしまうため。
//  - 洗脳された瞬間、敵陣がわへ 数歩ぶん引き寄せる（味方のかたまりの外に出す）。
//    ダメージ軽減のような 新しいルールは足さない。位置を動かすだけ。
//  - 洗脳の瞬間だけ 0.5秒 止めて、画面の真ん中に大きく知らせる。
//  - 判定の乱数は warSeeded の系列から引く（Math.random は1つも足さない）。

export type WorldPatch3 = { tag: string, a: string, b: string }

// ---- 1) 青い見た目と、知らせの出しかた（CSS）------------------------------
const A_CSS = '/* War judge pop (〇 / ちがうよ) */'

const B_CSS = `/* __WORLD_V3__ 宇宙人に支配された姿。元の絵文字のまま 色だけ変える（色違いと同じ作法） */
.war-unit.war-alien .war-sprite{
  filter: hue-rotate(185deg) saturate(2.6) brightness(0.92) drop-shadow(0 0 5px #38bdf8);
}
.war-unit.war-alien .war-name{ color:#7dd3fc; }
.war-unit.war-alien::after{
  content:'👽';
  position:absolute;
  top:-0.30em;
  right:-0.35em;
  font-size:0.46em;
  filter:none;
  pointer-events:none;
}
/* __WORLD_V3__ 洗脳された瞬間の知らせ。1秒で倒れても 何が起きたかは必ず伝わるように。 */
.world-mind-shout{
  position:absolute;
  left:50%;
  top:44%;
  transform:translate(-50%,-50%);
  font-size:26px;
  font-weight:900;
  line-height:1.3;
  text-align:center;
  color:#e0f2fe;
  background:rgba(2,6,23,0.72);
  border:3px solid #38bdf8;
  border-radius:16px;
  padding:12px 18px;
  box-shadow:0 10px 30px rgba(0,0,0,0.5);
  pointer-events:none;
  z-index:70;
  animation: worldMindShout 1500ms ease-out forwards;
}
@keyframes worldMindShout{
  0%   { opacity:0; transform:translate(-50%,-50%) scale(0.7); }
  12%  { opacity:1; transform:translate(-50%,-50%) scale(1.06); }
  20%  { transform:translate(-50%,-50%) scale(1.0); }
  80%  { opacity:1; }
  100% { opacity:0; }
}

` + A_CSS

// ---- 2) 宇宙人化と洗脳の窓口いっしき --------------------------------------
const A_API = '      window.WORLD_NEED_ZOMBIE = 10;'

const B_API = A_API + `

      /* __WORLD_V3__ 数字は ぜんぶ ここの定数。あとから 1つ書きかえるだけで変わる。 */
      window.WORLD_ALIEN_MUL   = 1.35;  /* 世界編の敵として出る宇宙人の倍率（体力・攻撃・防御） */
      window.WORLD_MIND_HPMUL  = 1.5;   /* 洗脳された味方の 体力の倍率（攻撃力は上げない） */
      window.WORLD_MIND_RATE   = 0.05;  /* 宇宙人の攻撃1発あたりの洗脳確率。
                                          実測：判定が回るのは 1戦(65秒)で約12回。5% なら 1戦に1〜2回。
                                          寝返ったキャラは 味方に狙われないまま自城まで歩くので 低めから始める。
                                          人数が増えたら ここの数字だけ上げる。 */
      window.WORLD_MIND_MAX    = 1;     /* 同時に洗脳されるのは1体まで */
      window.WORLD_MIND_PULL   = 8;     /* 洗脳された瞬間、敵陣がわへ 何%ぶん引き寄せるか */
      window.WORLD_MIND_FREEZE = 500;   /* 洗脳の瞬間に 止める ミリ秒 */
      window.WORLD_MIND_MS     = 0;     /* 0 = 解けない（先生の確定仕様）。自動解除の呼び出しは入れていない。 */
      window.WORLD_ALIEN_P0    = 0.12;  /* 青の割合：W1（暫定） */
      window.WORLD_ALIEN_P1    = 0.45;  /* 青の割合：W24（暫定） */

      /* ステージが進むほど 青が増える */
      window.worldAlienRate = function(i){
        try{
          var n = Number(i) || 0; if(n < 0) n = 0; if(n > 23) n = 23;
          var p0 = Number(window.WORLD_ALIEN_P0), p1 = Number(window.WORLD_ALIEN_P1);
          if(!isFinite(p0)) p0 = 0.12;
          if(!isFinite(p1)) p1 = 0.45;
          return p0 + (p1 - p0) * (n / 23);
        }catch(e){ console.error('[__WORLD_V3__] alienRate', e); return 0.12; }
      };

      /* 見た目を いまの u の状態に合わせる。陣営が変わったときの クラスの貼りかえも ここでやる。
         （createUnitEl は作るとき1回しか書かないので、寝返っても player のままになってしまう） */
      window.worldAlienPaint = function(u){
        try{
          if(!u || !u.el) return;
          var el = u.el;
          el.classList.remove('player');
          el.classList.remove('enemy');
          el.classList.remove('war-spawning-player');
          el.classList.remove('war-spawning-enemy');
          el.classList.add(u.team === 'player' ? 'player' : 'enemy');
          if(u.alien) el.classList.add('war-alien'); else el.classList.remove('war-alien');
          var nm = el.querySelector('.war-name');
          if(nm) nm.textContent = (u.isBoss ? '👑' : '') + String(u.name || '');
        }catch(e){ console.error('[__WORLD_V3__] alienPaint', e); }
      };

      /* 宇宙人化を 1体に乗せる。mode: 'enemy'（はじめから敵）/ 'mind'（洗脳された味方） */
      window.worldAlienApply = function(u, mode){
        try{
          if(!u || u.alien) return false;
          u._preName = u.name;
          u._preAtk = u.atk;
          u._preDef = u.def;
          u._preHpMax = u.hpMax;
          u.alien = true;
          u.alienMode = mode || 'enemy';
          u.name = '宇宙人' + String(u.name || '');
          if(u.alienMode === 'mind'){
            /* 洗脳は 体力だけ上げる。攻撃力を上げても 1秒で倒れるので 意味がなかった。 */
            var hm = Number(window.WORLD_MIND_HPMUL);
            if(!isFinite(hm) || hm <= 0) hm = 1.5;
            u.hpMax = Math.max(1, Math.round(Number(u.hpMax || 1) * hm));
            u.hp = Math.max(1, Math.round(Number(u.hp || 1) * hm));
          }else{
            var am = Number(window.WORLD_ALIEN_MUL);
            if(!isFinite(am) || am <= 0) am = 1.35;
            u.atk = Math.round(Number(u.atk || 0) * am);
            u.def = Math.round(Number(u.def || 0) * am);
            u.hpMax = Math.max(1, Math.round(Number(u.hpMax || 1) * am));
            u.hp = Math.max(1, Math.round(Number(u.hp || 1) * am));
          }
          window.worldAlienPaint(u);
          return true;
        }catch(e){ console.error('[__WORLD_V3__] alienApply', e); return false; }
      };

      /* 宇宙人化を はずす。いまは自動では呼ばれない（解けない仕様）。 */
      window.worldAlienRelease = function(u){
        try{
          if(!u || !u.alien) return false;
          var ratio = (Number(u.hpMax) > 0) ? (Number(u.hp || 0) / Number(u.hpMax)) : 1;
          if(u._preName != null) u.name = u._preName;
          if(u._preAtk != null) u.atk = u._preAtk;
          if(u._preDef != null) u.def = u._preDef;
          if(u._preHpMax != null){
            u.hpMax = u._preHpMax;
            u.hp = Math.max(1, Math.round(Number(u.hpMax) * ratio));
          }
          u.alien = false;
          u.alienMode = null;
          u._preName = null; u._preAtk = null; u._preDef = null; u._preHpMax = null;
          window.worldAlienPaint(u);
          return true;
        }catch(e){ console.error('[__WORLD_V3__] alienRelease', e); return false; }
      };

      window.worldMindRelease = function(u, ps){
        try{
          if(!u || !u.alien || u.alienMode !== 'mind') return false;
          if(!window.worldAlienRelease(u)) return false;
          u.team = 'player';
          u.target = null;
          window.worldAlienPaint(u);
          return true;
        }catch(e){ console.error('[__WORLD_V3__] mindRelease', e); return false; }
      };

      /* いま洗脳されている味方の数。数え直す形にして 増減の記録ちがいが起きないようにする。 */
      window.worldMindCount = function(ps){
        var n = 0;
        try{
          var us = (ps && ps.units) ? ps.units : [];
          for(var i = 0; i < us.length; i++){
            var u = us[i];
            if(u && u.alien && u.alienMode === 'mind' && Number(u.hp) > 0) n++;
          }
        }catch(e){ console.error('[__WORLD_V3__] mindCount', e); }
        return n;
      };

      /* 画面の真ん中に 大きく知らせる。1秒で倒れても 何が起きたかは伝わるように。 */
      window.worldMindShout = function(name){
        try{
          var host = document.getElementById('warField');
          if(!host) return;
          var d = document.createElement('div');
          d.className = 'world-mind-shout';
          d.textContent = '👽 ' + String(name || '') + ' が うちゅうじんに あやつられた！';
          host.appendChild(d);
          setTimeout(function(){ try{ d.remove(); }catch(e){} }, 1600);
        }catch(e){ console.error('[__WORLD_V3__] mindShout', e); }
      };

      /* 洗脳する。宇宙人の攻撃が 味方に当たったときだけ呼ばれる。成功したら true。 */
      window.worldMindControl = function(att, def, ps){
        try{
          if(!ps || !ps.worldMode) return false;
          if(!att || !att.alien || att.team !== 'enemy') return false;
          if(!def || def.team !== 'player') return false;
          if(def.alien || !(Number(def.hp) > 0)) return false;
          if(!ps._mcRng) return false;
          var cap = Number(window.WORLD_MIND_MAX);
          if(!isFinite(cap) || cap < 1) cap = 1;
          if(window.worldMindCount(ps) >= cap) return false;
          var rate = Number(window.WORLD_MIND_RATE);
          if(!isFinite(rate) || rate <= 0) return false;
          if(ps._mcRng() >= rate) return false;
          var wasName = def.name;
          if(!window.worldAlienApply(def, 'mind')) return false;
          def.team = 'enemy';
          def.target = null;
          /* 味方のかたまりのど真ん中だと 6体に囲まれて即死するので、敵陣がわへ 少し引き寄せる。 */
          var pull = Number(window.WORLD_MIND_PULL);
          if(isFinite(pull) && pull > 0){
            def.x = Math.max(9, Number(def.x || 50) - pull);
          }
          ps.mindFreezeUntil = Date.now() + (Number(window.WORLD_MIND_FREEZE) || 0);
          window.worldAlienPaint(def);
          window.worldMindShout(wasName);
          try{
            var fb = document.getElementById('warFeedback');
            if(fb){ fb.textContent = '👽 ' + String(wasName || '') + ' が あやつられた！'; fb.className = 'font-bold text-sky-200'; }
          }catch(e2){}
          return true;
        }catch(e){ console.error('[__WORLD_V3__] mindControl', e); return false; }
      };`

// ---- 3) ステージごとに 種をまきなおす＋青の枠を先に決める -------------------
const A_RESET = `  ps.bossSpawned = false;
  ps.waveScriptWave = 0;
  ps.waveEventIdx = 0;
}`

const B_RESET = `  ps.bossSpawned = false;
  ps.waveScriptWave = 0;
  ps.waveEventIdx = 0;
  /* __WORLD_V3__ 宇宙人化と洗脳の乱数は ステージ番号から作る（Math.random は足さない）。
     同じステージなら 毎回おなじ出かたになる。 */
  ps.mindFreezeUntil = 0;
  try{
    var __wi3 = (window.worldGetCurrent) ? window.worldGetCurrent() : 0;
    var __ci3 = Number(cfg && cfg.idx) || 0;
    ps._alRng = warSeeded((0x00A11E4 ^ (__ci3 * 2654435761) ^ (__wi3 * 40503)) >>> 0);
    ps._mcRng = warSeeded((0x05EED17 ^ (__ci3 * 2246822519) ^ (__wi3 * 66826526)) >>> 0);
    /* 青にする枠を さきに決めておく。1体ずつ振ると ステージあたり11体前後しかいないので
       当たり外れが大きすぎた（設定12%のW2が0/11、設定34%のW16が8/12）。
       台本の何番目を青にするかを シードから選ぶので、同じステージなら 毎回おなじ。 */
    ps._alSet = {};
    if(warState.worldMode && window.worldAlienRate){
      var __n3 = (cfg && cfg.spawns && cfg.spawns.length) ? cfg.spawns.length : 0;
      var __want3 = Math.round(__n3 * window.worldAlienRate(__wi3));
      var __ix3 = [];
      for(var __q3 = 0; __q3 < __n3; __q3++) __ix3.push(__q3);
      for(var __q3b = __n3 - 1; __q3b > 0; __q3b--){
        var __r3 = Math.floor(ps._alRng() * (__q3b + 1));
        var __t3 = __ix3[__q3b]; __ix3[__q3b] = __ix3[__r3]; __ix3[__r3] = __t3;
      }
      for(var __q3c = 0; __q3c < __want3; __q3c++) ps._alSet[String(__ix3[__q3c])] = true;
    }
  }catch(e){ ps._alRng = null; ps._mcRng = null; ps._alSet = {}; console.error('[__WORLD_V3__] seed', e); }
}`

// ---- 4) 世界編の ふつうの敵を 何体かに1体 青くする -------------------------
const A_ENEMY = `      skill3Name: m3 ? (m3.name||'') : '',
      skill3Effect: m3 ? (m3.effect||'') : ''
    };
    warApplyRoleTweak(tpl, role);
    spawnUnit('enemy', tpl);`

const B_ENEMY = A_ENEMY + `
    /* __WORLD_V3__ 世界編だけ：何体かに1体を 宇宙人に支配された姿にする。
       ぜんぶ青くしない（ふつうの敵が混ざっているから 青が目立つ）。 */
    try{
      if(warState.worldMode && ps._alSet && window.worldAlienApply){
        var __nu3 = ps.units[ps.units.length - 1];
        if(__nu3 && __nu3.team === 'enemy' && !__nu3.isBoss){
          var __pt3 = String(Number(ps.spawnPtr) || 0);
          if(ps._alSet[__pt3]) window.worldAlienApply(__nu3, 'enemy');
        }
      }
    }catch(e){ console.error('[__WORLD_V3__] alienSpawn', e); }`

// ---- 5) 世界編のボスは かならず青 -----------------------------------------
const A_BOSS = '  ps.bossSpawned = true;'

const B_BOSS = `  /* __WORLD_V3__ 世界編のボスは かならず 宇宙人に支配された姿にする（親玉） */
  try{
    if(warState.worldMode && window.worldAlienApply){
      var __bu3 = ps.units[ps.units.length - 1];
      if(__bu3 && __bu3.isBoss && __bu3.team === 'enemy') window.worldAlienApply(__bu3, 'enemy');
    }
  }catch(e){ console.error('[__WORLD_V3__] alienBoss', e); }
` + A_BOSS

// ---- 6) 宇宙人の攻撃が当たったら 確率で洗脳 --------------------------------
const A_DMG = '  def.hp = num(def && def.hp, num(def && def.hpMax, 100)) - dmg;'

const B_DMG = A_DMG + `
  /* __WORLD_V3__ 宇宙人の攻撃が 味方に当たったとき、確率で洗脳される。
     成功したら その場に文字を出して 画面をゆらす（強さやダメージは 1つも変えない）。 */
  try{
    if(def && Number(def.hp) > 0 && window.worldMindControl){
      if(window.worldMindControl(att, def, warState)){
        try{ warFloatText((typeof def.x === 'number' ? def.x : 50), 34, '👽 あやつられた！'); }catch(e2){}
        try{ warScreenShake(); }catch(e3){}
      }
    }
  }catch(e){ console.error('[__WORLD_V3__] mindHit', e); }`

// ---- 7) 洗脳の瞬間だけ 0.5秒 止める ----------------------------------------
const A_TICK = `function tick(dt){
    const ps = warState;
    ps.elapsed += dt;`

const B_TICK = `function tick(dt){
    const ps = warState;
    /* __WORLD_V3__ 洗脳の瞬間だけ 止める。elapsed も進めない（時間を損しないように）。 */
    try{
      if(ps.mindFreezeUntil && Date.now() < ps.mindFreezeUntil) return;
    }catch(e){ console.error('[__WORLD_V3__] freeze', e); }
    ps.elapsed += dt;`

export const WORLD_V3_PATCHES: WorldPatch3[] = [
  { tag: 'X01_css', a: A_CSS, b: B_CSS },
  { tag: 'X02_api', a: A_API, b: B_API },
  { tag: 'X03_reset', a: A_RESET, b: B_RESET },
  { tag: 'X04_enemy', a: A_ENEMY, b: B_ENEMY },
  { tag: 'X05_boss', a: A_BOSS, b: B_BOSS },
  { tag: 'X06_dmg', a: A_DMG, b: B_DMG },
  { tag: 'X07_freeze', a: A_TICK, b: B_TICK }
]
