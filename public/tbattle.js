/* tbattle.js  TB_V1  2026-10-06
 *
 * オマケ機能：ターン制バトル（ジムチャレンジ・解答なし）
 *
 * 設計メモ
 *  - 問題に答えません。技を選んで殴り合うだけ。1回3〜4分。
 *  - 入場にターン制バトルチケット（player.tb.tk）が1枚必要。
 *  - 相手はこのモード専用のジムリーダー（既存のジムリーダー 400〜419 は使いません）。
 *  - 両軍ともレベル50固定＋種族値を全キャラの順位で帯に圧縮。
 *    技の威力も規定値（通常14／強撃30／特殊12）。
 *    → ガチャで強いキャラを引けた子だけが勝つ形にしないため。
 *  - 技の属性は skill.type から決める（データは1件も書き換えない）。
 *      type 'normal'  → ノーマル（どのタイプにも等倍）
 *      type 'heavy'   → そのキャラの属性（相性が乗る）
 *      type 'unique'  → そのキャラの属性・低威力・効果が主役
 *    さらに tbsub.js の表があれば、その技だけ属性を差し替える。
 *  - じょうたい（やけど・どく・しびれ）は、つよい技が当たったときだけ 20% でかかる。
 *    ふつうの技では ぜったいに かからない。1体に1つ、なおったあと3ターンは かからない。
 *    「動けなくなる」効果は入れていない（運だけが増えて、読み合いにならなかったため）。
 *  - 技の効果は window.__zwarNormEffect で正規化してから使う。
 *    正規化が空文字を返すもの（instant_kill / revive / stun / counter /
 *    reflect / evade / shield）は通常攻撃として処理する＝勝ち確定を作らない。
 *
 * 既存のバトル（野生・ジム・友達3対3・友達クイズ・防衛戦・ゾンビ・タマゴ・
 * タイプシュート）には手を入れていません。読んでいるだけです：
 *   MONSTERS / getMonster / monSpriteHtml / monShinyClass /
 *   __hasShinyOf / __zwarNormEffect / saveData / setMode / player
 * （getStats は星や日替わりの補正が入るので、あえて使っていません）
 * 画面は実行時に自分で作ります（index.html に足すのは script タグ1行だけ）。
 */
(function () {
  'use strict';

  /* ===================== 定数 ===================== */

  // 本番の TYPE_CHART（index.html 内）から、効果抜群 s / いまひとつ w / 無効 z を写したもの。
  // 倍率そのものは下の SE / RES / IMM を使う（このモードだけの値）。
  var CHART = {
    fire:     { s: ['grass', 'ice', 'bug', 'steel'], w: ['fire', 'water', 'rock', 'dragon'], z: [] },
    water:    { s: ['fire', 'ground', 'rock'], w: ['water', 'grass', 'dragon'], z: [] },
    grass:    { s: ['water', 'ground', 'rock'], w: ['fire', 'grass', 'poison', 'flying', 'bug', 'dragon', 'steel'], z: [] },
    electric: { s: ['water', 'flying'], w: ['electric', 'grass', 'dragon'], z: ['ground'] },
    ice:      { s: ['grass', 'ground', 'flying', 'dragon'], w: ['fire', 'water', 'ice', 'steel'], z: [] },
    fighting: { s: ['normal', 'ice', 'rock', 'dark', 'steel'], w: ['poison', 'flying', 'psychic', 'bug', 'fairy'], z: ['ghost'] },
    poison:   { s: ['grass', 'fairy'], w: ['poison', 'ground', 'rock', 'ghost'], z: ['steel'] },
    ground:   { s: ['fire', 'electric', 'poison', 'rock', 'steel'], w: ['grass', 'bug'], z: ['flying'] },
    flying:   { s: ['grass', 'fighting', 'bug'], w: ['electric', 'rock', 'steel'], z: [] },
    psychic:  { s: ['fighting', 'poison'], w: ['psychic', 'steel'], z: ['dark'] },
    bug:      { s: ['grass', 'psychic', 'dark'], w: ['fire', 'fighting', 'poison', 'flying', 'ghost', 'steel', 'fairy'], z: [] },
    rock:     { s: ['fire', 'ice', 'flying', 'bug'], w: ['fighting', 'ground', 'steel'], z: [] },
    ghost:    { s: ['psychic', 'ghost'], w: ['dark'], z: ['normal'] },
    dragon:   { s: ['dragon'], w: ['steel'], z: ['fairy'] },
    dark:     { s: ['psychic', 'ghost'], w: ['fighting', 'dark', 'fairy'], z: [] },
    steel:    { s: ['ice', 'rock', 'fairy'], w: ['fire', 'water', 'electric', 'steel'], z: [] },
    fairy:    { s: ['fighting', 'dragon', 'dark'], w: ['fire', 'poison', 'steel'], z: [] },
    normal:   { s: [], w: [], z: [] }
  };

  var SE = 1.3;     // こうかばつぐん（既存バトルと同じ倍率。上げない）
  var RES = 0.77;   // こうかいまひとつ
  var IMM = 0.6;    // 本来は無効。0 だと手が無くなるので弱い倍率にしてある
                    // （0.4 だと ゴーストのリーダーが ノーマルに ほとんど勝てなくなった）
  var K = 11;       // ダメージ係数（これより小さいと時間切ればかりになった）
  var BUFF = 0.30;  // 強化1段あたり +30%
  var HEAL = 0.25;  // 回復は最大HPの25%
  var HEALCAP = 2;  // 1体が回復できるのは2回まで（回復で粘って時間切れにしない）
  var MAXSTACK = 2; // 強化はこうげき＋ぼうぎょ合わせて2段まで
  var CAP = 20;     // 20ターンで打ち切り、残りHPの割合が多いほうの勝ち
  var BLEND = 0.58; // リーダーの強さを、その子の手持ちに58%だけ合わせる
  var POW = { normal: 14, heavy: 30, unique: 12 };

  /* ----- じょうたい（やけど・どく・しびれ）TB_V2 -----
     ・つよい技（強撃技）だけが STRATE の確率でかける。ふつうの技では ぜったいに かからない。
     ・1体に1つだけ。なおったあと ST_IMM ターンは 同じ子に かからない（止め続けられないように）。
     ・行動できなくなる効果は 入れていない。
       「2ターンだけ 25%で 動けない」を入れて測ったが、勝率はほとんど動かず、運だけが増えたため。
     ・自分と同じ系統には かからない（ほのおは やけどしない、など）。 */
  var STRATE = 0.20;
  var ST_IMM = 3;
  var ST_EARLY = 0.25; // 毎ターン、この確率で ターン数より はやく なおる
  var PARA_SKIP = 0.25; // しびれているとき、この確率で うごけない（こうたいは できる）
  // ※ はやく なおるぶん、1回あたりの 効き目は 少し強くしてある
  //   （やけど 6%→8%、どく 8%→10%。平均の ダメージ量が だいたい 同じになるように）
  var ST = {
    burn:   { label: 'やけど', icon: '🔥', turns: 3, dot: 0.08, atk: 0.85, spd: 1,
              from: ['fire'], immune: ['fire'] },
    poison: { label: 'どく',   icon: '☠',  turns: 3, dot: 0.10, atk: 1,    spd: 1,
              from: ['grass', 'poison', 'bug'], immune: ['grass', 'poison', 'bug', 'steel'] },
    para:   { label: 'しびれ', icon: '⚡', turns: 2, dot: 0,    atk: 1,    spd: 0.5,
              from: ['electric', 'ice'], immune: ['electric', 'ice'] }
  };
  var ST_BY_EL = (function () {
    var m = {}, k, i;
    for (k in ST) for (i = 0; i < ST[k].from.length; i++) m[ST[k].from[i]] = k;
    return m;
  })();

  var BAND = { hp: [1012, 1138], atk: [110, 130], def: [100, 116], spd: [104, 122] };
  // ともだち たいせんは、ジムより さらに つよさを そろえる（両方に 同じように かける）。
  // そろえないと、強い手持ちの子の勝率が 99% になった（実測）。
  var FBAND = { hp: [1065, 1085], atk: [118, 122], def: [107, 109], spd: [112, 114] };
  var CURBAND = BAND;

  var JEL = {
    normal: 'ノーマル', fire: 'ほのお', water: 'みず', grass: 'くさ', electric: 'でんき',
    ice: 'こおり', fighting: 'かくとう', poison: 'どく', ground: 'じめん', flying: 'ひこう',
    psychic: 'エスパー', bug: 'むし', rock: 'いわ', ghost: 'ゴースト', dragon: 'ドラゴン',
    dark: 'あく', steel: 'はがね', fairy: 'フェアリー'
  };
  var COL = {
    normal: '#9ca3af', fire: '#ef4444', water: '#3b82f6', grass: '#22c55e', electric: '#eab308',
    ice: '#67e8f9', fighting: '#b45309', poison: '#a855f7', ground: '#a16207', flying: '#60a5fa',
    psychic: '#ec4899', bug: '#84cc16', rock: '#78716c', ghost: '#6366f1', dragon: '#7c3aed',
    dark: '#475569', steel: '#94a3b8', fairy: '#f472b6'
  };

  /* ===================== 専用ジムリーダー ===================== */
  /* 既存のジムリーダー（id 400〜419）とは別。手持ちは主タイプ2体＋サブ1体の混成。
     単色3体にすると「相性が合えばほぼ勝ち」の一本道になったため混成にしている。 */
  var LEADERS = [
    { key: 'fire',  name: 'ほのおの ヒノミヤ', emoji: '🔥', badge: 'ほのおバッジ',
      party: [1053, 224, 1161], style: 'buff',
      say: 'あついぞ！ねっしん は まもるぞ！' },
    { key: 'water', name: 'みずの ナギサ', emoji: '🌊', badge: 'みずバッジ',
      party: [1161, 938, 1403], style: 'heal',
      say: 'あわてない。ゆっくり いこう。' },
    { key: 'grass', name: 'くさの モリタ', emoji: '🌿', badge: 'くさバッジ',
      party: [1403, 991, 36], style: 'heal',
      say: 'そだてた ものは つよいよ。' },
    { key: 'electric', name: 'でんきの ライカ', emoji: '⚡', badge: 'でんきバッジ',
      party: [1146, 953, 938], style: 'spd',
      say: 'はやさで きめる！' },
    { key: 'rock',  name: 'いわの ガンテツ', emoji: '🪨', badge: 'いわバッジ',
      party: [1112, 1613, 1176], style: 'def',
      say: 'かたいぞ。くずせるか？' },
    { key: 'ghost', name: 'ゴーストの ヨイヤミ', emoji: '👻', badge: 'ゴーストバッジ',
      party: [1210, 1206, 1201], style: 'debuff',
      say: 'ふふ、なにが くるか わかるかな。' },
    { key: 'steel', name: 'はがねの テツロウ', emoji: '⚙️', badge: 'はがねバッジ',
      party: [1062, 2114, 942], style: 'def',
      say: 'きみの いちげき、うけとめる。' },
    { key: 'fairy', name: 'フェアリーの コトハ', emoji: '🎀', badge: 'フェアリーバッジ',
      party: [2101, 1152, 1504], style: 'buff',
      say: 'たのしく いこうね！' }
  ];
  // 試運転が終わったので、8人ぜんいんを出す。
  var ACTIVE = LEADERS.length;

  /* ===================== 小道具 ===================== */

  function log() { try { console.log.apply(console, ['[TB]'].concat([].slice.call(arguments))); } catch (e) {} }
  function esc(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function P() { try { return (typeof player !== 'undefined' && player) ? player : (window.player || null); } catch (e) { return null; } }
  function save() { try { if (typeof saveData === 'function') saveData(); } catch (e) { log('save失敗', e); } }
  function today() {
    var d = new Date();
    return d.getFullYear() + '-' + ('0' + (d.getMonth() + 1)).slice(-2) + '-' + ('0' + d.getDate()).slice(-2);
  }
  function monOf(id) {
    try {
      if (typeof getMonster === 'function') { var m = getMonster(id); if (m) return m; }
    } catch (e) {}
    try {
      var arr = window.MONSTERS || [];
      for (var i = 0; i < arr.length; i++) if (Number(arr[i].id) === Number(id)) return arr[i];
    } catch (e) {}
    return null;
  }
  function normId(x) {
    if (x == null) return null;
    if (typeof x === 'number' || typeof x === 'string') { var n = Number(x); return isFinite(n) && n > 0 ? n : null; }
    if (typeof x === 'object') {
      var k = ['id', 'monster_id', 'monsterId', 'mid'];
      for (var i = 0; i < k.length; i++) if (x[k[i]] != null) { var v = Number(x[k[i]]); if (isFinite(v) && v > 0) return v; }
    }
    return null;
  }
  function myParty() {
    var p = P(), out = [];
    try {
      var arr = (p && (p.party || p.partyIds)) || [];
      for (var i = 0; i < arr.length && out.length < 3; i++) {
        var id = normId(arr[i]);
        if (id && monOf(id)) out.push(id);
      }
    } catch (e) {}
    return out;
  }
  function shinyClassOf(id) {
    try {
      if (typeof __hasShinyOf === 'function' && __hasShinyOf(id)) {
        return (typeof monShinyClass === 'function') ? (monShinyClass(id) || 'shiny-mon') : 'shiny-mon';
      }
    } catch (e) {}
    return '';
  }
  function spriteHtml(id, px) {
    var m = monOf(id), emo = (m && m.sprite) || '❓';
    var inner;
    try {
      inner = (typeof monSpriteHtml === 'function') ? monSpriteHtml(id, emo, 'mon-img-shadow') : emo;
    } catch (e) { inner = emo; }
    var sc = shinyClassOf(id);
    return '<span class="' + sc + '" style="font-size:' + (px || 48) + 'px;line-height:1;display:inline-block">' + inner + '</span>';
  }
  function badge(el) {
    return '<span style="display:inline-block;padding:1px 6px;border-radius:999px;font-size:11px;font-weight:800;color:#fff;background:' +
      (COL[el] || '#9ca3af') + '">' + esc(JEL[el] || el) + '</span>';
  }

  /* ===================== 効果の正規化 ===================== */

  var FALLBACK_NORM = {
    buff_atk_self: 'buff_atk', buff_def_self: 'buff_def', buff_spd_self: 'buff_spd',
    buff_speed: 'buff_spd', attack: 'buff_atk',
    instant_kill: '', revive: '', stun: '', counter: '', reflect: '', evade: '', shield: ''
  };
  var BANNED = { instant_kill: 1, revive: 1, stun: 1, counter: 1, reflect: 1, evade: 1, shield: 1 };

  function normEffect(e) {
    if (!e) return null;
    var out = null;
    try {
      if (typeof __zwarNormEffect === 'function') out = __zwarNormEffect(e);
    } catch (x) { out = null; }
    if (out == null) out = (FALLBACK_NORM.hasOwnProperty(e) ? FALLBACK_NORM[e] : e);
    if (!out) return null;            // 正規化が空＝実装しない効果
    if (BANNED[out]) return null;     // 念のため二重に止める
    return out;
  }

  /* ===================== 種族値の圧縮 ===================== */

  var PCT = null; // {hp:[...sorted], atk:[], def:[], spd:[]}

  function buildPct() {
    if (PCT) return PCT;
    var keys = ['hp', 'atk', 'def', 'spd'], acc = { hp: [], atk: [], def: [], spd: [] };
    var arr = window.MONSTERS || [];
    for (var i = 0; i < arr.length; i++) {
      var st = rawStats(arr[i]);
      if (!st) continue;
      for (var k = 0; k < keys.length; k++) acc[keys[k]].push(st[keys[k]]);
    }
    for (var k2 = 0; k2 < keys.length; k2++) acc[keys[k2]].sort(function (a, b) { return a - b; });
    PCT = acc;
    return PCT;
  }
  // わざと getStats() を使っていません。
  // getStats は星（stars）や その日のつかれ（isDailyFatigued）を見るので、
  // 同じキャラでも子によって・日によって数字が変わります。
  // ここは「種（しゅ）としての強さの順番」だけが欲しいので、素の数値を使います。
  function rawStats(m) {
    if (!m) return null;
    return {
      hp: Number(m.hp || 0), atk: Number(m.atk || 0),
      def: Number(m.def || 0), spd: Number(m.spd || 0)
    };
  }
  function pctRank(key, v) {
    var a = buildPct()[key];
    if (!a || !a.length) return 0.5;
    var lo = 0, hi = a.length - 1;
    while (lo < hi) { var mid = (lo + hi) >> 1; if (a[mid] < v) lo = mid + 1; else hi = mid; }
    return a.length > 1 ? lo / (a.length - 1) : 0.5;
  }
  function fromPct(key, p) {
    var b = CURBAND[key];
    if (p < 0) p = 0; if (p > 1) p = 1;
    return Math.round(b[0] + (b[1] - b[0]) * p);
  }
  // そのキャラが全490体の中でどのあたりか（4つの数値の平均）
  function avgPctOf(id) {
    var m = monOf(id);
    if (!m) return 0.5;
    var raw = rawStats(m), keys = ['hp', 'atk', 'def', 'spd'], s = 0;
    for (var i = 0; i < keys.length; i++) s += pctRank(keys[i], raw[keys[i]]);
    return s / keys.length;
  }

  /* ===================== ユニット組み立て ===================== */

  function subElFor(id, skillName) {
    try {
      var t = window.TB_SUB_V1 || [];
      for (var i = 0; i < t.length; i++) {
        if (Number(t[i].id) === Number(id) && t[i].skill === skillName) {
          var el = t[i].el;
          if (el && CHART[el]) return el;
        }
      }
    } catch (e) {}
    return null;
  }

  // shift が数値のとき（リーダー側）、その子の手持ちの強さに BLEND の分だけ寄せる。
  // 弱い手持ちの子が 2% しか勝てない相手にならないようにするため。
  // 寄せるのは半分以下なので、強い手持ちを集めた子のほうが有利なのは残る。
  function buildUnit(id, side, shift) {
    var m = monOf(id);
    if (!m) return null;
    var raw = rawStats(m);
    var own = m.elementType && CHART[m.elementType] ? m.elementType : 'normal';
    var keys = ['hp', 'atk', 'def', 'spd'], pr = {};
    for (var q = 0; q < keys.length; q++) {
      var p = pctRank(keys[q], raw[keys[q]]);
      if (typeof shift === 'number') {
        p = (1 - BLEND) * p + BLEND * shift;
        if (p < 0.12) p = 0.12; if (p > 0.92) p = 0.92;
      }
      pr[keys[q]] = p;
    }
    var u = {
      id: Number(id), side: side, name: m.name || ('No.' + id), el: own,
      hp: fromPct('hp', pr.hp), maxHp: fromPct('hp', pr.hp),
      atk: fromPct('atk', pr.atk), def: fromPct('def', pr.def), spd: fromPct('spd', pr.spd),
      ab: 0, db: 0, heals: 0, st: null, stT: 0, stImm: 0, stNew: false, alive: true, sk: []
    };
    var src = (m.skills || []).slice(0, 4);
    for (var i = 0; i < src.length; i++) {
      var s = src[i] || {};
      // 技の type は 'normal' / 'heavy' / 'unique' のほかに、属性名が入っているものが 52 件ある
      // （カボチャ頭の「ジャッククラッシュ」は type:'ghost' など）。
      // それを 'normal' 扱いにすると、そのキャラから強い技が消えてしまうので、別に見る。
      var ty, el;
      if (s.type === 'heavy') { ty = 'heavy'; el = own; }
      else if (s.type === 'unique') { ty = 'unique'; el = own; }
      else if (s.type === 'normal') { ty = 'normal'; el = 'normal'; }
      else if (CHART[s.type]) { ty = (Number(s.pow) >= 20 ? 'heavy' : 'normal'); el = s.type; }
      else { ty = 'normal'; el = 'normal'; }
      var pow = ty === 'normal' ? POW.normal : (ty === 'heavy' ? POW.heavy : (Number(s.pow) > 0 ? POW.unique : 0));
      var sub = subElFor(id, s.name);
      if (sub) el = sub;
      u.sk.push({
        name: s.name || 'こうげき', pow: pow, el: el, ty: ty,
        acc: (s.acc == null ? 0.95 : Number(s.acc)),
        eff: normEffect(s.effect), desc: s.desc || ''
      });
    }
    if (!u.sk.length) u.sk.push({ name: 'たいあたり', pow: POW.normal, el: 'normal', acc: 0.95, eff: null, desc: '' });
    return u;
  }

  /* ===================== 相性とダメージ ===================== */

  function mult(atkEl, defEl) {
    var row = CHART[atkEl];
    if (!row) return 1;
    if (row.z.indexOf(defEl) >= 0) return IMM;
    if (row.s.indexOf(defEl) >= 0) return SE;
    if (row.w.indexOf(defEl) >= 0) return RES;
    return 1;
  }
  function multLabel(v) {
    if (v >= SE) return 'こうか ばつぐん！';
    if (v <= IMM) return 'ほとんど きかない';
    if (v < 1) return 'こうか いまひとつ';
    return '';
  }
  function expDmg(a, d, s) { return s.pow * mult(s.el, d.el) * s.acc * (1 + BUFF * a.ab); }

  function doHit(a, d, s) {
    if (!s.pow) return { dmg: 0, m: 1, miss: false };
    if (Math.random() > s.acc) return { dmg: 0, m: mult(s.el, d.el), miss: true };
    var m = mult(s.el, d.el);
    var atk = a.atk * (1 + BUFF * a.ab) * stAtkRate(a);
    var def = d.def * (1 + BUFF * d.db);
    var x = Math.max(1, Math.round(s.pow * K * (atk / def) * m * (0.94 + 0.12 * Math.random())));
    d.hp = Math.max(0, d.hp - x);
    if (d.hp === 0) d.alive = false;
    var st = (d.alive && s.ty === 'heavy') ? stTryInflict(d, s.el) : '';
    return { dmg: x, m: m, miss: false, st: st };
  }
  function stOf(u) { return (u && u.st && ST[u.st]) ? ST[u.st] : null; }
  function stAtkRate(u) { var c = stOf(u); return c ? c.atk : 1; }
  function effSpd(u) { var c = stOf(u); return u.spd * (c ? c.spd : 1); }
  function stLabel(u) { var c = stOf(u); return c ? (c.icon + c.label) : ''; }

  // 強撃技が当たったときだけ、その技の属性に応じて かかる
  function stTryInflict(d, el) {
    var kind = ST_BY_EL[el];
    if (!kind) return '';
    if (d.st) return '';          // すでに かかっている
    if (d.stImm > 0) return '';   // なおった直後は かからない
    var c = ST[kind];
    if (c.immune.indexOf(d.el) >= 0) return '';
    if (Math.random() >= STRATE) return '';
    d.st = kind; d.stT = c.turns; d.stNew = true;
    return d.name + ' は ' + c.icon + c.label + ' に なった！（あと ' + c.turns + 'ターンまで。はやく なおることも ある）';
  }

  // ターンの おわりに ダメージ・ターン数・なおり を処理する
  function stTick(u, push) {
    if (!u || !u.alive) return;
    var c = stOf(u);
    if (c && u.stNew) { u.stNew = false; return; } // かかった そのターンは 数えない
    if (c) {
      if (c.dot > 0) {
        var dmg = Math.max(1, Math.round(u.maxHp * c.dot));
        u.hp = Math.max(0, u.hp - dmg);
        push(u.name + ' は ' + c.icon + c.label + ' で ' + dmg + ' の ダメージ！');
        if (u.hp === 0) { u.alive = false; push(u.name + ' は たおれた！'); }
      }
      if (u.alive && Math.random() < ST_EARLY) {
        u.st = null; u.stImm = ST_IMM;
        push(u.name + ' の ' + c.icon + c.label + ' が はやく なおった！');
      } else {
        u.stT--;
        if (u.stT <= 0) { u.st = null; u.stImm = ST_IMM; push(u.name + ' の ' + c.icon + c.label + ' が なおった！'); }
      }
    } else if (u.stImm > 0) {
      u.stImm--;
    }
  }

  function applyEffect(a, d, eff, dealt) {
    if (!eff) return '';
    var msg = '';
    if (eff === 'heal_self' || eff === 'heal_party' || eff === 'heal_full_sleep') {
      if (a.heals >= HEALCAP) {
        msg = a.name + ' は もう かいふく できない！';
      } else {
        a.heals++;
        var h = Math.round(a.maxHp * HEAL);
        a.hp = Math.min(a.maxHp, a.hp + h);
        msg = a.name + ' は HPを かいふく した！（のこり ' + (HEALCAP - a.heals) + 'かい）';
      }
    } else if (eff === 'drain') {
      var g = Math.round(dealt * 0.3);
      if (g > 0) { a.hp = Math.min(a.maxHp, a.hp + g); msg = a.name + ' は すこし かいふく した！'; }
    }
    var want = [];
    if (/^buff_(atk|all)/.test(eff)) want.push('a');
    if (/^buff_(def|all)/.test(eff)) want.push('d');
    for (var i = 0; i < want.length; i++) {
      if (a.ab + a.db >= MAXSTACK) break;
      if (want[i] === 'a') { a.ab++; msg = a.name + ' の こうげき が あがった！'; }
      else { a.db++; msg = a.name + ' の ぼうぎょ が あがった！'; }
    }
    if (eff === 'buff_spd') { a.spd = Math.round(a.spd * 1.08); msg = a.name + ' の すばやさ が あがった！'; }
    if (eff === 'debuff_enemy' || /^debuff_atk/.test(eff)) {
      if (d.ab > -2) { d.ab--; msg = d.name + ' の こうげき が さがった！'; }
    }
    if (/^debuff_def/.test(eff)) {
      if (d.db > -2) { d.db--; msg = d.name + ' の ぼうぎょ が さがった！'; }
    }
    return msg;
  }


  /* ===================== きょうのジム（第4便） =====================
     日付から1人を決める。計算だけなので、全員の端末で同じ相手になる。
     ほかのリーダーにも ふつうに挑める。きょうのジムは「今日の推し」。 */
  function tbDayNum(ymd) {
    var s = String(ymd || today()), n = 0;
    for (var i = 0; i < s.length; i++) n = (n * 31 + s.charCodeAt(i)) % 100000;
    return n;
  }
  function todayLeaderIdx() {
    var n = Math.max(1, Math.min(ACTIVE, LEADERS.length));
    return tbDayNum(today()) % n;
  }

  /* ===================== ショップの わりびき（第5便） =====================
     その週（月〜日）に 家庭学習を出した日数で決める。連続日数は使わない。
     週が変われば 自動的に 0 から数え直す（休んだ子が 戻れなくなるのを さけるため）。
       3日 → 1わりびき / 5日 → 2わりびき
     既存の SHOP_ITEMS の price を書きかえるだけ。買う処理・表示の処理には 手を入れていない。 */
  function tbWeekStart(d) {
    var x = new Date(d.getTime());
    var w = x.getDay();              // 0=日
    var back = (w === 0) ? 6 : (w - 1); // 月曜はじまり
    x.setDate(x.getDate() - back);
    x.setHours(0, 0, 0, 0);
    return x;
  }
  function tbWeekStudyDays() {
    try {
      var logs = (typeof hsLogs === 'function') ? (hsLogs() || []) : [];
      var start = tbWeekStart(new Date());
      var seen = {}, cnt = 0;
      for (var i = 0; i < logs.length; i++) {
        var l = logs[i];
        if (!l || !l.dayKey || l.restDay) continue;
        var p = String(l.dayKey).split('-');
        if (p.length !== 3) continue;
        var d = new Date(Number(p[0]), Number(p[1]) - 1, Number(p[2]));
        if (d < start) continue;
        if (seen[l.dayKey]) continue;
        seen[l.dayKey] = 1; cnt++;
      }
      return cnt;
    } catch (e) { return 0; }
  }
  function tbShopRate(days) {
    if (days >= 5) return 0.8;
    if (days >= 3) return 0.9;
    return 1;
  }
  function tbApplyShopDiscount() {
    try {
      if (typeof SHOP_ITEMS === 'undefined' || !SHOP_ITEMS || !SHOP_ITEMS.length) return;
      var days = tbWeekStudyDays(), rate = tbShopRate(days), changed = false;
      for (var i = 0; i < SHOP_ITEMS.length; i++) {
        var it = SHOP_ITEMS[i];
        if (!it) continue;
        if (typeof it._tbBase !== 'number') it._tbBase = Number(it.price) || 0;
        var np = Math.max(1, Math.ceil(it._tbBase * rate));
        if (it.price !== np) { it.price = np; changed = true; }
      }
      tbShopBanner(days, rate);
      return changed;
    } catch (e) { log('わりびきの反映に失敗', e); }
  }
  function tbShopBanner(days, rate) {
    try {
      var sc = document.getElementById('screen-shop');
      if (!sc) return;
      var el = document.getElementById('tbShopBanner');
      if (!el) {
        el = document.createElement('div');
        el.id = 'tbShopBanner';
        el.style.cssText = 'margin:4px 6px;padding:6px 10px;border-radius:10px;font-size:12px;font-weight:800';
        sc.insertBefore(el, sc.firstChild);
      }
      if (rate < 1) {
        el.style.background = '#fef3c7'; el.style.color = '#92400e';
        el.textContent = '今週 ' + days + '日 がんばったから ' + (rate === 0.8 ? '2わりびき' : '1わりびき') + '！（月よう日に リセット）';
      } else {
        el.style.background = '#f1f5f9'; el.style.color = '#475569';
        el.textContent = '今週 ' + days + '日。あと ' + Math.max(0, 3 - days) + '日で 1わりびき！（家庭学習を 3日で 1わり、5日で 2わり）';
      }
    } catch (e) {}
  }

  /* ===================== 状態 ===================== */

  var S = null; // 進行中のバトル

  function ensureTb() {
    var p = P();
    if (!p) return null;
    if (!p.tb || typeof p.tb !== 'object') p.tb = {};
    var tb = p.tb;
    if (typeof tb.tk !== 'number') tb.tk = 0;
    if (!tb.badges || typeof tb.badges !== 'object') tb.badges = {};
    if (typeof tb.grantDay !== 'string') tb.grantDay = '';
    if (typeof tb.grantCount !== 'number') tb.grantCount = 0;
    if (!tb.init) { tb.init = 1; tb.tk = Math.max(tb.tk, 2); } // 初回だけ2枚（お試し用）
    return tb;
  }

  function grantTicket(n) {
    var tb = ensureTb();
    if (!tb) return 0;
    var d = today();
    if (tb.grantDay !== d) { tb.grantDay = d; tb.grantCount = 0; }
    var room = Math.max(0, 2 - tb.grantCount); // 1日2枚まで
    var give = Math.min(room, Math.max(0, n | 0));
    if (give > 0) { tb.tk += give; tb.grantCount += give; save(); }
    return give;
  }

  // 家庭学習のごほうびに相乗り（既存関数は書き換えず、包むだけ）
  function hookHomestudy() {
    try {
      if (typeof window.hsGrantRewards !== 'function' || window.hsGrantRewards.__tbWrapped) return;
      var orig = window.hsGrantRewards;
      var wrapped = function () {
        var r;
        try { r = orig.apply(this, arguments); } finally {
          try { grantTicket(1); } catch (e) { log('チケット付与失敗', e); }
        }
        return r;
      };
      wrapped.__tbWrapped = true;
      window.hsGrantRewards = wrapped;
    } catch (e) { log('hook失敗', e); }
  }

  /* ===================== 画面づくり ===================== */

  var EL = {}; // DOM参照

  // 野生バトルの screen-battle は .lbm-main（まんなかの広い枠）の中にある。
  // ジムの screen-gym は その外（右の細い列）にある。
  // ここを間違えると、画面の右はじの細い列に 全部が入ってしまう。
  function host() {
    var main = document.querySelector('.lbm-main');
    if (main) return main;
    var wild = document.getElementById('screen-battle');
    if (wild && wild.parentNode) return wild.parentNode;
    var gym = document.getElementById('screen-gym');
    return (gym && gym.parentNode) ? gym.parentNode : document.body;
  }

  function buildScreen() {
    var exist = document.getElementById('screen-tbattle');
    if (exist) {
      // 置き場所が ちがっていたら 直す（古い版が のこっている場合）
      var h0 = host();
      if (exist.parentNode !== h0) h0.appendChild(exist);
      exist.className = 'hidden h-full w-full flex flex-col relative';
      if (EL.root === exist) return exist;
    }
    if (EL.root && document.body.contains(EL.root)) return EL.root;
    var d = exist || document.createElement('div');
    d.id = 'screen-tbattle';
    d.className = 'hidden h-full w-full flex flex-col relative';
    d.innerHTML =
      '<div id="tbTop" class="flex items-center justify-between px-2 py-1">' +
        '<div class="font-bold text-sm text-slate-700">ジムチャレンジ（ターンせい）</div>' +
        '<div class="flex items-center gap-2">' +
          '<div id="tbTicket" class="text-xs font-bold text-amber-600"></div>' +
          '<button id="tbClose" class="px-3 py-1 rounded-lg bg-slate-200 text-slate-700 text-xs font-bold">とじる</button>' +
        '</div>' +
      '</div>' +
      '<div id="tbLobby" class="flex-1 overflow-y-auto px-2 pb-2"></div>' +
      '<div id="tbField" class="hidden flex-1 flex flex-col min-h-0">' +
        '<div id="tbScene" class="battle-scene" style="height:46%;min-height:200px">' +
          '<div id="tbFoe" class="battle-enemy">' +
            '<div class="battle-status-box">' +
              '<div id="tbFoeName" style="font-weight:800"></div>' +
              '<div id="tbFoeType" style="margin:2px 0"></div>' +
              '<div style="width:100px;height:8px;background:#333;border-radius:4px;overflow:hidden">' +
                '<div id="tbFoeBar" style="height:100%;width:100%;background:#22c55e;transition:width .3s"></div>' +
              '</div>' +
              '<div id="tbFoeHp" style="font-size:10px"></div>' +
              '<div id="tbFoeBalls" style="font-size:10px"></div>' +
            '</div>' +
            '<div id="tbFoeSprite"></div>' +
          '</div>' +
          '<div id="tbMe" class="battle-player">' +
            '<div id="tbMeSprite"></div>' +
            '<div class="battle-status-box">' +
              '<div id="tbMeName" style="font-weight:800"></div>' +
              '<div id="tbMeType" style="margin:2px 0"></div>' +
              '<div style="width:100px;height:8px;background:#333;border-radius:4px;overflow:hidden">' +
                '<div id="tbMeBar" style="height:100%;width:100%;background:#22c55e;transition:width .3s"></div>' +
              '</div>' +
              '<div id="tbMeHp" style="font-size:10px"></div>' +
              '<div id="tbMeBalls" style="font-size:10px"></div>' +
            '</div>' +
          '</div>' +
          '<div id="tbTurn" style="position:absolute;top:4px;left:8px;color:#fff;font-weight:800;font-size:12px;text-shadow:0 1px 3px #000"></div>' +
        '</div>' +
        '<div id="tbWho" class="px-2 pt-1 text-xs font-bold"></div>' +
        '<div id="tbMsg" class="px-2 pb-1 text-sm font-bold" style="min-height:3.2em;line-height:1.35;color:#0f172a;display:flex;align-items:center"></div>' +
        '<div id="tbCmd" class="battle-choice-grid px-2 pb-2" style="flex:0 0 auto;align-content:start;max-height:46%"></div>' +
      '</div>' +
      '<div id="tbResult" class="hidden flex-1 overflow-y-auto px-3 py-2"></div>';
    if (d.parentNode !== host()) host().appendChild(d);
    EL.root = d;
    EL.lobby = d.querySelector('#tbLobby');
    EL.field = d.querySelector('#tbField');
    EL.result = d.querySelector('#tbResult');
    EL.cmd = d.querySelector('#tbCmd');
    EL.msg = d.querySelector('#tbMsg');
    EL.who = d.querySelector('#tbWho');
    EL.ticket = d.querySelector('#tbTicket');
    d.querySelector('#tbClose').addEventListener('click', function () { exit(); });
    return d;
  }

  function addMenuButton() {
    try {
      var menus = ['battle-menu', 'battle-menu-mobile'];
      for (var i = 0; i < menus.length; i++) {
        var m = document.getElementById(menus[i]);
        if (!m || m.querySelector('.tb-entry')) continue;
        var b = document.createElement('button');
        b.className = 'tb-entry w-full px-4 py-3 text-sm font-bold text-indigo-600 hover:bg-indigo-50 flex items-center gap-2 whitespace-nowrap border-t border-slate-100';
        b.innerHTML = '<span>🏅</span>ジムチャレンジ';
        b.addEventListener('click', function () {
          try { if (typeof closeBattleMenu === 'function') closeBattleMenu(); } catch (e) {}
          open();
        });
        m.appendChild(b);
      }
    } catch (e) { log('メニュー追加失敗', e); }
  }

  function hideOthers() {
    try {
      var all = document.querySelectorAll('[id^="screen-"]');
      for (var i = 0; i < all.length; i++) if (all[i].id !== 'screen-tbattle') all[i].classList.add('hidden');
      var bs = document.getElementById('battleScene');
      if (bs) { bs.style.display = 'none'; bs.style.pointerEvents = 'none'; }
      var bc = document.getElementById('battleContainer');
      if (bc) { bc.classList.add('hidden'); bc.style.display = 'none'; bc.style.pointerEvents = 'none'; }
    } catch (e) {}
  }

  /* ===================== ロビー ===================== */

  function open() {
    try {
      buildScreen();
      hideOthers();
      EL.root.classList.remove('hidden');
      try { window.mode = 'tbattle'; } catch (e) {}
      showLobby();
    } catch (e) { log('open失敗', e); alert('ジムチャレンジを ひらけませんでした。'); }
  }
  function exit() {
    try {
      vsStopTimers();
      S = null;
      if (EL.root) EL.root.classList.add('hidden');
      if (typeof setMode === 'function') setMode('status');
    } catch (e) {}
  }

  function showLobby() {
    var tb = ensureTb();
    EL.field.classList.add('hidden');
    EL.result.classList.add('hidden');
    EL.lobby.classList.remove('hidden');
    EL.ticket.textContent = 'チケット ' + (tb ? tb.tk : 0) + 'まい';

    var party = myParty();
    var h = '';
    // きょうのジム（日付で決まる・全員同じ）
    var todayIdx = todayLeaderIdx();
    if (ACTIVE > 0 && LEADERS[todayIdx]) {
      h += '<div class="rounded-xl p-2 mb-2" style="background:linear-gradient(90deg,#fde68a,#fca5a5)">' +
        '<div class="text-xs font-bold text-amber-900">★ きょうの ジム</div>' +
        '<div class="text-sm font-bold text-slate-800">' + LEADERS[todayIdx].emoji + ' ' + esc(LEADERS[todayIdx].name) + '</div>' +
        '<div class="text-[11px] text-amber-900">クラスの みんなが 今日は この人に いどめます。かつと コインが +20。</div>' +
        '<button class="tb-go mt-1 w-full py-2 rounded-lg text-white font-bold text-sm" data-lv="' + todayIdx + '" style="background:linear-gradient(180deg,#f59e0b,#d97706)">★ きょうの ジムに いどむ（チケット1まい）</button>' +
        '</div>';
    }

    h += '<div class="text-xs text-slate-500 mb-2">こたえなくていい バトル。わざを えらんで たたかう。チケット1まい。' +
      '<button id="tbHelpBtn" class="underline text-indigo-600 ml-1">くわしく</button></div>';
    h += '<div id="tbHelp" class="hidden text-xs text-slate-400 mb-2">' +
      'みんな レベル50・つよさも そろえて たたかう。あいしょうと わざの えらびかたで きまる。' +
      'リーダーの つよさは きみの てもちに すこし あわせる。' +
      'つよい わざは あいてを 🔥やけど ☠どく ⚡しびれ に することが ある（ふつうの わざでは ならない）。じょうたいは 何ターンかで なおる。' +
      '</div>';

    // バッジ
    h += '<div class="flex flex-wrap gap-1 mb-2">';
    for (var i = 0; i < LEADERS.length; i++) {
      var got = tb && tb.badges[LEADERS[i].key];
      h += '<div title="' + esc(LEADERS[i].badge) + '" style="width:34px;height:34px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:18px;' +
        (got ? 'background:#fef3c7;border:2px solid #f59e0b' : 'background:#f1f5f9;border:2px dashed #cbd5e1;filter:grayscale(1);opacity:.6') + '">' +
        (i < ACTIVE || got ? LEADERS[i].emoji : '？') + '</div>';
    }
    h += '</div>';
    var have = 0;
    for (var b2 = 0; b2 < LEADERS.length; b2++) if (tb && tb.badges[LEADERS[b2].key]) have++;
    h += '<div class="text-xs font-bold text-amber-700 mb-2">バッジ ' + have + ' / ' + ACTIVE + '</div>';

    // 自分の手持ち
    h += '<div class="rounded-xl bg-white border border-slate-200 p-2 mb-2">';
    h += '<div class="text-xs font-bold text-slate-600 mb-1">きみの 3びき（ボックスで かえられます）</div>';
    if (!party.length) {
      h += '<div class="text-xs text-red-600">てもちが ありません。</div>';
    } else {
      h += '<div class="flex gap-3">';
      for (var j = 0; j < party.length; j++) {
        var mm = monOf(party[j]);
        h += '<div class="text-center">' + spriteHtml(party[j], 34) +
          '<div class="text-[10px] font-bold">' + esc(mm.name) + '</div>' +
          '<div>' + badge(mm.elementType) + '</div></div>';
      }
      h += '</div>';
    }
    h += '</div>';

    // ともだちと たいせん
    h += '<div class="rounded-xl bg-white border-2 border-emerald-200 p-2 mb-2">';
    h += '<div class="text-sm font-bold text-emerald-700">🤝 ともだちと たいせん</div>';
    h += '<div class="text-[11px] text-slate-500 mb-1">おなじ ターンせいで、ともだちと たたかえます。チケットは いりません（かつと コイン30）。</div>';
    h += '<div class="flex gap-2">';
    h += '<button id="tbVsCreate" class="flex-1 py-2 rounded-lg text-white font-bold text-sm" style="background:linear-gradient(180deg,#34d399,#059669)">へやを つくる</button>';
    h += '<button id="tbVsJoin" class="flex-1 py-2 rounded-lg text-white font-bold text-sm" style="background:linear-gradient(180deg,#60a5fa,#2563eb)">あいことばで はいる</button>';
    h += '</div></div>';

    // リーダー一覧
    var order = [];
    for (var oi = 0; oi < ACTIVE && oi < LEADERS.length; oi++) order.push(oi);
    order.sort(function (a, b) {
      if (a === todayIdx) return -1;
      if (b === todayIdx) return 1;
      return a - b;
    });
    for (var ok = 0; ok < order.length; ok++) {
      var k = order[ok];
      var L = LEADERS[k];
      h += '<div class="rounded-xl bg-white border-2 border-indigo-200 p-2 mb-2">';
      h += '<div class="flex items-center gap-2">';
      h += '<div style="font-size:30px">' + L.emoji + '</div>';
      h += '<div class="flex-1"><div class="font-bold text-sm">' + esc(L.name) + '</div>';
      h += '<div class="text-[11px] text-slate-500">' + esc(L.say) + '</div></div>';
      if (k === todayLeaderIdx()) h += '<div class="text-xs font-bold text-amber-700">★きょう</div>';
      h += (tb && tb.badges[L.key]) ? '<div class="text-xs font-bold text-amber-600">バッジ ○</div>' : '';
      h += '</div>';
      h += '<div class="flex items-center gap-2 mt-1 flex-wrap">';
      h += '<span class="text-[11px] font-bold text-slate-600">あいての タイプ</span>';
      for (var q = 0; q < L.party.length; q++) {
        var pm = monOf(L.party[q]);
        if (pm) h += badge(pm.elementType);
      }
      h += '</div>';
      // 相性の目安
      h += '<div class="text-[11px] text-slate-500 mt-1">' + esc(advice(party, L)) + '</div>';
      h += '<button class="tb-go mt-2 w-full py-2 rounded-lg text-white font-bold text-sm" data-lv="' + k + '" style="background:linear-gradient(180deg,#818cf8,#4f46e5)">いどむ（チケット1まい）</button>';
      h += '</div>';
    }
    if (ACTIVE < LEADERS.length) {
      h += '<div class="text-xs text-slate-400">ほかの ジムリーダーは じゅんびちゅうです。</div>';
    }
    EL.lobby.innerHTML = h;
    var vc = EL.lobby.querySelector('#tbVsCreate');
    if (vc) vc.addEventListener('click', function () { vsCreate(); });
    var vj = EL.lobby.querySelector('#tbVsJoin');
    if (vj) vj.addEventListener('click', function () {
      var c = window.prompt('あいことばを いれてね（ともだちの がめんに 出ている 6もじ）');
      if (c) vsJoin(c);
    });
    var hb = EL.lobby.querySelector('#tbHelpBtn');
    if (hb) hb.addEventListener('click', function () {
      var hp = EL.lobby.querySelector('#tbHelp');
      if (hp) hp.classList.toggle('hidden');
    });
    var gos = EL.lobby.querySelectorAll('.tb-go');
    for (var g = 0; g < gos.length; g++) {
      gos[g].addEventListener('click', function (ev) {
        start(Number(ev.currentTarget.getAttribute('data-lv')) || 0);
      });
    }
  }

  function advice(party, L) {
    if (!party.length) return '';
    var best = 0, bestName = '';
    for (var i = 0; i < party.length; i++) {
      var me = monOf(party[i]); if (!me) continue;
      var sc = 0;
      for (var j = 0; j < L.party.length; j++) {
        var fo = monOf(L.party[j]); if (!fo) continue;
        var m = mult(me.elementType, fo.elementType);
        sc += (m > 1 ? 1 : (m < 1 ? -1 : 0));
      }
      if (sc > best) { best = sc; bestName = me.name; }
    }
    if (best > 0) return 'あいしょうが よさそう: ' + bestName;
    return 'いまの 3びきでは あいしょうを とりにくいかも。ボックスで いれかえると かわります。';
  }

  /* ===================== バトル ===================== */

  function start(idx) {
    var tb = ensureTb();
    if (!tb) { alert('データが よみこまれていません。'); return; }
    if (tb.tk < 1) { alert('チケットが ありません。かていがくしゅうを だすと もらえます。'); return; }
    var party = myParty();
    if (party.length < 1) { alert('てもちが ありません。'); return; }
    var L = LEADERS[idx] || LEADERS[0];

    // その子の手持ちの平均位置を出して、リーダーの強さを少しだけ寄せる
    var cp = 0;
    for (var c = 0; c < party.length; c++) cp += avgPctOf(party[c]);
    cp = party.length ? (cp / party.length) : 0.5;

    var mine = [], foes = [];
    for (var i = 0; i < party.length; i++) { var u = buildUnit(party[i], 'me'); if (u) mine.push(u); }
    for (var j = 0; j < L.party.length; j++) { var f = buildUnit(L.party[j], 'foe', cp); if (f) foes.push(f); }
    if (!mine.length || !foes.length) { alert('バトルを じゅんびできませんでした。'); return; }

    tb.tk -= 1; save();

    S = {
      L: L, lv: idx, mine: mine, foes: foes, mi: 0, fi: 0, turn: 0,
      busy: false, over: false,
      stat: { myMultSum: 0, myMultN: 0, spdLoss: 0, spdN: 0 }
    };
    EL.lobby.classList.add('hidden');
    EL.result.classList.add('hidden');
    EL.field.classList.remove('hidden');
    EL.ticket.textContent = 'チケット ' + tb.tk + 'まい';
    clearLog();
    say(L.name + ' が しょうぶを しかけてきた！');
    renderField();
    lockCmd(false);
    setWho(true);
  }

  function cur(side) { return side === 'me' ? S.mine[S.mi] : S.foes[S.fi]; }
  function foeSideName() { return (S && S.vs) ? (S.vs.oppName || 'あいて') : ((S && S.L) ? S.L.name : 'あいて'); }
  function aliveList(arr) { var o = []; for (var i = 0; i < arr.length; i++) if (arr[i].alive) o.push(i); return o; }

  // 1行ずつ 出して、次の行で 消える。
  // 新しい行が 出たことが わかるように、出るたびに ちいさく ふわっとさせる。
  function say(t) {
    if (!EL.msg) return;
    EL.msg.textContent = t;
    try {
      EL.msg.style.transition = 'none';
      EL.msg.style.opacity = '0.25';
      EL.msg.style.transform = 'translateY(2px)';
      void EL.msg.offsetWidth;
      EL.msg.style.transition = 'opacity .18s, transform .18s';
      EL.msg.style.opacity = '1';
      EL.msg.style.transform = 'translateY(0)';
    } catch (e) {}
  }
  function clearLog() { if (EL.msg) EL.msg.textContent = ''; }

  // だれの番か（ターン制だと ひと目で わかるように）
  function setWho(mine) {
    if (!EL.who) return;
    if (mine) {
      EL.who.textContent = '▶ きみの ばん！ わざを えらぼう';
      EL.who.style.color = '#1d4ed8';
    } else {
      EL.who.textContent = '… あいての ばん';
      EL.who.style.color = '#b45309';
    }
  }

  // 演出のあいだは ボタンを押せなくする（押せるのに 反応しない、を なくす）
  function lockCmd(on) {
    if (!EL.cmd) return;
    EL.cmd.style.opacity = on ? '0.45' : '1';
    EL.cmd.style.pointerEvents = on ? 'none' : 'auto';
    var bs = EL.cmd.querySelectorAll('button');
    for (var i = 0; i < bs.length; i++) bs[i].disabled = !!on;
  }

  function balls(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) s += arr[i].alive ? '●' : '○';
    return s;
  }

  // その時点の HP・じょうたいを ひかえておく（文と 画面を そろえるため）
  function snapshot() {
    var f = function (u) { return { hp: u.hp, st: u.st, stT: u.stT, ab: u.ab, db: u.db, alive: u.alive }; };
    return { mi: S.mi, fi: S.fi, me: S.mine.map(f), fo: S.foes.map(f) };
  }
  function viewOf(unit, snapUnit) {
    if (!snapUnit) return unit;
    return {
      id: unit.id, name: unit.name, el: unit.el, maxHp: unit.maxHp,
      hp: snapUnit.hp, st: snapUnit.st, stT: snapUnit.stT, ab: snapUnit.ab, db: snapUnit.db, alive: snapUnit.alive
    };
  }
  function ballsOf(arr, snapArr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) s += ((snapArr ? snapArr[i].alive : arr[i].alive) ? '●' : '○');
    return s;
  }

  function renderField(snap) {
    if (!S) return;
    var mi = snap ? snap.mi : S.mi, fi = snap ? snap.fi : S.fi;
    var me = viewOf(S.mine[mi], snap ? snap.me[mi] : null);
    var fo = viewOf(S.foes[fi], snap ? snap.fo[fi] : null);
    var d = EL.root;
    d.querySelector('#tbTurn').textContent = 'のこり ' + Math.max(0, CAP - S.turn) + 'ターン';
    d.querySelector('#tbFoeName').textContent = fo.name;
    d.querySelector('#tbFoeType').innerHTML = badge(fo.el) + statArrows(fo);
    d.querySelector('#tbFoeBar').style.width = Math.round(100 * fo.hp / fo.maxHp) + '%';
    d.querySelector('#tbFoeBar').style.background = hpColor(fo);
    d.querySelector('#tbFoeHp').textContent = fo.hp + ' / ' + fo.maxHp;
    d.querySelector('#tbFoeBalls').textContent = ballsOf(S.foes, snap ? snap.fo : null);
    d.querySelector('#tbFoeSprite').innerHTML = spriteHtml(fo.id, tbSpritePx(true));
    d.querySelector('#tbMeName').textContent = me.name;
    d.querySelector('#tbMeType').innerHTML = badge(me.el) + statArrows(me);
    d.querySelector('#tbMeBar').style.width = Math.round(100 * me.hp / me.maxHp) + '%';
    d.querySelector('#tbMeBar').style.background = hpColor(me);
    d.querySelector('#tbMeHp').textContent = me.hp + ' / ' + me.maxHp;
    d.querySelector('#tbMeBalls').textContent = ballsOf(S.mine, snap ? snap.me : null);
    d.querySelector('#tbMeSprite').innerHTML = spriteHtml(me.id, tbSpritePx(false));
    if (!snap) renderCmd();
  }
  // 画面の広さに合わせて 絵の大きさを決める（iPad 横 1024 でも 大きすぎないように）
  function tbSpritePx(isFoe) {
    var w = 0;
    try { w = (EL.root ? EL.root.getBoundingClientRect().width : 0) || window.innerWidth || 1024; } catch (e) { w = 1024; }
    var base = w >= 1400 ? 112 : (w >= 1000 ? 92 : (w >= 700 ? 76 : 60));
    return isFoe ? Math.round(base * 0.9) : base;
  }

  function hpColor(u) {
    var r = u.hp / u.maxHp;
    return r > 0.5 ? '#22c55e' : (r > 0.2 ? '#f59e0b' : '#ef4444');
  }
  // この技が じょうたいを かけられるか（かからない相手なら出さない）
  function skillStHint(s, foe) {
    if (!s || s.ty !== 'heavy') return '';
    var kind = ST_BY_EL[s.el];
    if (!kind) return '';
    var c = ST[kind];
    if (!foe || c.immune.indexOf(foe.el) >= 0) return '';
    if (foe.st || foe.stImm > 0) return '';
    return c.icon + c.label + 'に することがある';
  }

  function statArrows(u) {
    var s = '';
    if (u.st && ST[u.st]) {
      s += '<span style="display:inline-block;padding:0 4px;border-radius:999px;background:#fff;color:#7c2d12;font-size:10px;font-weight:800">' +
        ST[u.st].icon + ST[u.st].label + ' あと' + Math.max(0, u.stT) + 'まで</span> ';
    }
    if (u.ab > 0) s += '<span style="color:#fca5a5;font-size:10px">こう↑' + u.ab + '</span>';
    if (u.ab < 0) s += '<span style="color:#93c5fd;font-size:10px">こう↓' + (-u.ab) + '</span>';
    if (u.db > 0) s += '<span style="color:#fcd34d;font-size:10px">ぼう↑' + u.db + '</span>';
    if (u.db < 0) s += '<span style="color:#93c5fd;font-size:10px">ぼう↓' + (-u.db) + '</span>';
    return s ? ' ' + s : '';
  }

  function renderCmd() {
    if (!S || !EL.cmd) return;
    var me = cur('me'), fo = cur('foe'), h = '';
    for (var i = 0; i < me.sk.length; i++) {
      var s = me.sk[i], m = mult(s.el, fo.el), lab = multLabel(m);
      var note = s.pow ? ('いりょく ' + s.pow) : 'こうかわざ';
      h += '<button class="battle-choice-btn tb-sk" data-i="' + i + '" style="position:relative;border-radius:10px;border:2px solid #cbd5e1;background:#fff;color:#1f2937;text-align:left;padding:4px 8px">' +
        '<div style="font-weight:800;font-size:13px">' + esc(s.name) + '</div>' +
        '<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap">' + badge(s.el) +
        '<span style="font-size:10px;color:#64748b">' + note + '</span>' +
        (lab ? '<span style="font-size:10px;font-weight:800;color:' + (m > 1 ? '#dc2626' : '#2563eb') + '">' + lab + '</span>' : '') +
        (skillStHint(s, fo) ? '<span style="font-size:10px;font-weight:800;color:#9333ea">' + skillStHint(s, fo) + '</span>' : '') +
        '</div></button>';
    }
    var others = [];
    for (var j = 0; j < S.mine.length; j++) if (j !== S.mi && S.mine[j].alive) others.push(j);
    h += '<button class="battle-choice-btn tb-sw" style="border-radius:10px;border:2px solid #cbd5e1;background:#f8fafc;color:#1f2937;font-weight:800;font-size:13px"' +
      (others.length ? '' : ' disabled') + '>こうたい' + (others.length ? '<span style="font-size:10px;font-weight:600"> （1ターン つかう）</span>' : '（できない）') + '</button>';
    EL.cmd.innerHTML = h;
    var sks = EL.cmd.querySelectorAll('.tb-sk');
    for (var k = 0; k < sks.length; k++) {
      sks[k].addEventListener('click', function (ev) {
        var i = Number(ev.currentTarget.getAttribute('data-i'));
        turn({ kind: 'skill', i: i });
      });
    }
    var sw = EL.cmd.querySelector('.tb-sw');
    if (sw && others.length) sw.addEventListener('click', function () { showSwap(others); });
  }

  function showSwap(others) {
    if (!S || S.busy) return;
    var fo = cur('foe'), h = '';
    h += '<div style="grid-column:1/-1" class="text-xs font-bold text-slate-600">だれと こうたいする？（1ターン つかいます）</div>';
    for (var i = 0; i < others.length; i++) {
      var u = S.mine[others[i]], m = mult(u.el, fo.el), lab = multLabel(m);
      h += '<button class="battle-choice-btn tb-do" data-j="' + others[i] + '" style="border-radius:10px;border:2px solid #cbd5e1;background:#fff;color:#1f2937">' +
        '<div style="font-weight:800;font-size:13px">' + esc(u.name) + '</div>' +
        '<div style="display:flex;gap:4px;align-items:center">' + badge(u.el) +
        '<span style="font-size:10px">HP ' + u.hp + '</span>' +
        (lab ? '<span style="font-size:10px;font-weight:800;color:' + (m > 1 ? '#dc2626' : '#2563eb') + '">' + lab + '</span>' : '') +
        '</div></button>';
    }
    h += '<button class="battle-choice-btn tb-cancel" style="border-radius:10px;border:2px solid #cbd5e1;background:#f1f5f9;color:#1f2937;font-weight:800">やめる</button>';
    EL.cmd.innerHTML = h;
    var ds = EL.cmd.querySelectorAll('.tb-do');
    for (var k = 0; k < ds.length; k++) {
      ds[k].addEventListener('click', function (ev) {
        turn({ kind: 'swap', j: Number(ev.currentTarget.getAttribute('data-j')) });
      });
    }
    EL.cmd.querySelector('.tb-cancel').addEventListener('click', function () { renderCmd(); });
  }

  function aiChoose() {
    var a = cur('foe'), f = cur('me'), L = S.L;
    var sloppy = Math.random() < 0.3; // ときどき最適を外す（かたすぎないように）
    // 不利なら交代
    if (!sloppy) {
      var curM = mult(a.el, f.el);
      if (curM < 1 && a.hp > a.maxHp * 0.5) {
        var bestJ = -1, bestV = curM + 0.2; // はっきり良くなるときだけ交代する
        for (var j = 0; j < S.foes.length; j++) {
          if (j === S.fi || !S.foes[j].alive) continue;
          var v = mult(S.foes[j].el, f.el);
          if (v > bestV) { bestV = v; bestJ = j; }
        }
        if (bestJ >= 0) return { kind: 'swap', j: bestJ };
      }
      // 回復
      for (var h = 0; h < a.sk.length; h++) {
        var e = a.sk[h].eff;
        if ((e === 'heal_self' || e === 'heal_party') && a.hp < a.maxHp * 0.35 && a.heals < HEALCAP) return { kind: 'skill', i: h };
      }
      // 強化（リーダーの個性）
      if (S.turn <= CAP * 0.55 && a.ab + a.db < MAXSTACK && a.hp > a.maxHp * 0.6) {
        for (var b = 0; b < a.sk.length; b++) {
          var e2 = a.sk[b].eff;
          if (!e2) continue;
          if (L.style === 'heal' && /heal/.test(e2)) return { kind: 'skill', i: b };
          if (L.style === 'def' && /^buff_(def|all)/.test(e2)) return { kind: 'skill', i: b };
          if (L.style === 'spd' && /^buff_spd/.test(e2)) return { kind: 'skill', i: b };
          if (L.style === 'debuff' && /^debuff/.test(e2)) return { kind: 'skill', i: b };
          if (L.style === 'buff' && /^buff_(atk|all)/.test(e2)) return { kind: 'skill', i: b };
        }
      }
    }
    // 期待ダメージ最大
    var bi = 0, bv = -1;
    for (var i = 0; i < a.sk.length; i++) {
      var v2 = expDmg(a, f, a.sk[i]) * (sloppy ? (0.6 + Math.random() * 0.8) : 1);
      if (!sloppy && skillStHint(a.sk[i], f)) v2 *= 1.15;
      if (v2 > bv) { bv = v2; bi = i; }
    }
    return { kind: 'skill', i: bi };
  }

  function turn(myAct) {
    if (!S || S.over) return;
    if (S.vs) { vsPlay(myAct); return; }
    if (S.busy) return;
    S.busy = true;
    lockCmd(true);
    setWho(false);
    S.turn++;
    var lines = resolveTurn(myAct, aiChoose());
    playLines(lines, function () { checkEnd(); });
  }

  // 1ターン分を計算して、出す文と そのときの画面を返す。
  // ともだち たいせんでは、ホストだけが これを動かし、結果を ゲストに おくる。
  function resolveTurn(myAct, foeAct) {
    var me = cur('me'), fo = cur('foe');

    // 記録（敗因カード用）
    if (myAct.kind === 'skill') {
      var ms = me.sk[myAct.i];
      if (ms && ms.pow) { S.stat.myMultSum += mult(ms.el, fo.el); S.stat.myMultN++; }
    }
    S.stat.spdN++;
    if (me.spd < fo.spd) S.stat.spdLoss++;

    var meFirst = effSpd(me) >= effSpd(fo);
    var lines = [];
    function pushLine(t) { lines.push({ t: t, s: snapshot() }); }

    function actMe() {
      var u = cur('me'), v = cur('foe');
      if (myAct.kind === 'swap') {
        S.mi = myAct.j;
        pushLine('がんばれ！ ' + cur('me').name + '！');
        return;
      }
      if (u.st === 'para' && Math.random() < PARA_SKIP) {
        pushLine(u.name + ' は ' + ST.para.icon + 'しびれて うごけない！');
        return;
      }
      var s = u.sk[myAct.i] || u.sk[0];
      var r = doHit(u, v, s);
      if (r.miss) pushLine(u.name + ' の ' + s.name + '！ しかし はずれた！');
      else if (s.pow) {
        var lab = multLabel(r.m);
        pushLine(u.name + ' の ' + s.name + '！ ' + (lab ? lab + ' ' : '') + v.name + ' に ' + r.dmg + ' のダメージ！');
      } else pushLine(u.name + ' の ' + s.name + '！');
      if (r.st) pushLine(r.st);
      var em = applyEffect(u, v, s.eff, r.dmg);
      if (em) pushLine(em);
      if (!v.alive) pushLine(v.name + ' は たおれた！');
    }
    function actFoe() {
      var u = cur('foe'), v = cur('me');
      if (foeAct.kind === 'swap') {
        S.fi = foeAct.j;
        pushLine(foeSideName() + ' は ' + cur('foe').name + ' を だした！');
        return;
      }
      if (u.st === 'para' && Math.random() < PARA_SKIP) {
        pushLine(u.name + ' は ' + ST.para.icon + 'しびれて うごけない！');
        return;
      }
      var s = u.sk[foeAct.i] || u.sk[0];
      var r = doHit(u, v, s);
      if (r.miss) pushLine(u.name + ' の ' + s.name + '！ しかし はずれた！');
      else if (s.pow) {
        var lab2 = multLabel(r.m);
        pushLine(u.name + ' の ' + s.name + '！ ' + (lab2 ? lab2 + ' ' : '') + v.name + ' に ' + r.dmg + ' のダメージ！');
      } else pushLine(u.name + ' の ' + s.name + '！');
      if (r.st) pushLine(r.st);
      var em2 = applyEffect(u, v, s.eff, r.dmg);
      if (em2) pushLine(em2);
      if (!v.alive) pushLine(v.name + ' は たおれた！');
    }

    // 2ばんめに動くのは「2ばんめの子が まだ たおれていないとき」だけ。
    // ここを 自分がわ／あいてがわ で 取りちがえていたため、
    // たおれた子が そのターンに こうげきしていた。
    if (meFirst) { actMe(); if (cur('foe').alive) actFoe(); }
    else { actFoe(); if (cur('me').alive) actMe(); }

    // ターンの おわり：やけど・どくの ダメージと、ターン数の へらし
    stTick(cur('me'), pushLine);
    stTick(cur('foe'), pushLine);

    // たおれたら次を出す
    if (!cur('me').alive) {
      var al = aliveList(S.mine);
      if (al.length) { S.mi = al[0]; pushLine('いけ！ ' + cur('me').name + '！'); }
    }
    if (!cur('foe').alive) {
      var al2 = aliveList(S.foes);
      if (al2.length) { S.fi = al2[0]; pushLine(foeSideName() + ' は ' + cur('foe').name + ' を だした！'); }
    }

    return lines;
  }

  // 1行ずつ 出す（出た文と そのときのHPが そろうように）
  function playLines(lines, done) {
    var step = 0;
    function next() {
      if (step < lines.length) {
        var it = lines[step++];
        say(it.t); renderField(it.s);
        setTimeout(next, 900); return;
      }
      setTimeout(function () {
        S.busy = false;
        renderField();
        if (!S.over) { lockCmd(false); setWho(true); }
        if (done) done();
      }, 350);
    }
    next();
  }

  function hpRate(arr) {
    var a = 0, b = 0;
    for (var i = 0; i < arr.length; i++) { a += Math.max(0, arr[i].hp); b += arr[i].maxHp; }
    return b ? a / b : 0;
  }

  function checkEnd() {
    if (!S || S.over) return;
    var meAlive = aliveList(S.mine).length, foAlive = aliveList(S.foes).length;
    if (foAlive === 0) return finish(true, 'あいての てもちを すべて たおした！');
    if (meAlive === 0) return finish(false, 'きみの てもちは ぜんめつ した…');
    if (S.turn >= CAP) {
      var a = hpRate(S.mine), b = hpRate(S.foes);
      if (a > b) return finish(true, 'じかんぎれ！ のこりHPが おおい きみの かち！');
      return finish(false, 'じかんぎれ。のこりHPで まけ…');
    }
  }

  function lossCard() {
    var avg = S.stat.myMultN ? (S.stat.myMultSum / S.stat.myMultN) : 1;
    var foLeft = hpRate(S.foes);
    if (foLeft < 0.2) return 'あと ちょっとだった！ もう1かい いけば かてそう。';
    if (avg < 0.95) return 'あいしょうを はずしていた みたい。あいての タイプを みて、わざを かえてみよう。';
    if (S.stat.spdN && S.stat.spdLoss / S.stat.spdN > 0.6) return 'すばやさで まけていた。さきに うてる キャラか、すばやさを あげる わざを つかおう。';
    if (aliveList(S.foes).length === 1) return 'あと 1ぴき だった！ かいふくや きょうかを つかうと のこれるかも。';
    return 'つぎは きょうかわざや こうたいを つかってみよう。';
  }

  function finish(win, msg) {
    S.over = true;
    lockCmd(true);
    if (EL.who) EL.who.textContent = '';
    var tb = ensureTb(), p = P();
    var coins = 0, shards = 0, gotBadge = false;
    try {
      if (win) {
        coins = 40;
        if (S.lv === todayLeaderIdx()) { coins += 20; S.todayBonus = true; }
        if (tb && !tb.badges[S.L.key]) { tb.badges[S.L.key] = 1; gotBadge = true; }
        if (Math.random() < 0.15) shards = 3;
      } else {
        coins = 10 + Math.round(10 * (1 - hpRate(S.foes)));
      }
      if (p && coins > 0 && !p.coinBanned) p.coins = Number(p.coins || 0) + coins;
      if (p && shards > 0 && !p.shardBanned) {
        if (!p.lab || typeof p.lab !== 'object') p.lab = { shards: 0, use: {} };
        if (typeof p.lab.shards !== 'number') p.lab.shards = 0;
        p.lab.shards += shards;
      }
      save();
    } catch (e) { log('ごほうび付与に失敗', e); }

    var h = '';
    h += '<div class="text-center">';
    h += '<div style="font-size:40px">' + (win ? '🏅' : '💧') + '</div>';
    h += '<div class="font-bold text-lg ' + (win ? 'text-amber-600' : 'text-slate-600') + '">' + (win ? 'かった！' : 'まけた…') + '</div>';
    h += '<div class="text-xs text-slate-500 mb-2">' + esc(msg) + '</div>';
    h += '</div>';
    h += '<div class="rounded-xl bg-white border border-slate-200 p-2 mb-2">';
    h += '<div class="text-sm font-bold">もらったもの</div>';
    h += '<div class="text-sm">コイン +' + coins + (S.todayBonus ? '（★きょうの ジム ボーナス +20）' : '') + '</div>';
    if (shards) h += '<div class="text-sm">かけら +' + shards + '</div>';
    if (gotBadge) h += '<div class="text-sm font-bold text-amber-600">' + esc(S.L.badge) + ' を もらった！</div>';
    h += '</div>';
    if (!win) {
      h += '<div class="rounded-xl bg-indigo-50 border border-indigo-200 p-2 mb-2">';
      h += '<div class="text-xs font-bold text-indigo-700 mb-1">つぎの ヒント</div>';
      h += '<div class="text-sm">' + esc(lossCard()) + '</div>';
      h += '</div>';
    }
    h += '<div class="flex gap-2">';
    h += '<button id="tbAgain" class="flex-1 py-2 rounded-lg text-white font-bold" style="background:linear-gradient(180deg,#818cf8,#4f46e5)">もどる</button>';
    h += '</div>';
    EL.field.classList.add('hidden');
    EL.result.classList.remove('hidden');
    EL.result.innerHTML = h;
    EL.result.querySelector('#tbAgain').addEventListener('click', function () { S = null; showLobby(); });
  }


  /* ===================== ともだち たいせん（第6便） =====================
     通信は 既存の「ともだちバトルの部屋」を そのまま使う。
       おくる：POST /api/rt/damage/{あいことば}  {eventType:'tb', meta:{...}}
       うけとる：GET /api/rt/room/{あいことば}?after=N  の events
     これは public/rt-battle.js（タマゴ）が すでに やっている形。
     サーバは1行も変えていない。新しいクエリも 増やしていない。

     ホストが しんぱん：
       ゲストは 自分の手を おくるだけ。ホストが 1ターン分を計算して、
       出す文と そのときのHPを そのまま おくる。
       → 両方が べつべつに計算して 結果が ちがう、という事故が 起きない。

     かならず 終わるように、止まりどころを 4つ：
       1) 自分が 15秒 考えたら じどうで わざを えらぶ（まけにはしない）
       2) ゲストの手が 来ない → ホストが じどうで すすめる。3ターン続けて
          来なければ 引き分けで おわり
       3) ホストの結果が 来ない → ゲストが 20秒 待って 引き分けで おわり
       4) 20ターン、または 5分で うちきり（のこりHPの わりあいで 判定）
  */
  var VS_TURN_MS = 15000;   // 1ターンの もちじかん
  var VS_WAIT_MS = 20000;   // あいての結果を 待つ上限
  var VS_MAX_MS = 300000;   // 1戦ぜんたいの上限（5分）
  var VS_NOMOVE_MAX = 3;    // ゲストの手が 来ないのを ゆるす回数

  function vsApi(path, body) {
    var opt = body ? { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) } : {};
    return fetch(path, opt).then(function (r) { return r.json(); });
  }
  function vsSend(meta) {
    var v = S && S.vs; if (!v || !v.code) return;
    vsApi('/api/rt/damage/' + v.code, { damage: 0, monsterId: 0, eventType: 'tb', meta: meta })
      .then(function (d) { if (d && d.eventId) v.mine[d.eventId] = 1; })
      .catch(function () {});
  }
  function vsMyPartyPayload() {
    var ids = myParty(), p = P(), out = [];
    for (var i = 0; i < ids.length; i++) {
      var md = (p && p.monsters && (p.monsters[ids[i]] || p.monsters[String(ids[i])])) || null;
      out.push({ i: ids[i], l: md ? Number(md.level || 1) : 1 });
    }
    return out;
  }
  function vsMyName() {
    var p = P();
    var n = (p && (p.name || p.displayName)) ? String(p.name || p.displayName) : 'プレイヤー';
    return n.slice(0, 20);
  }
  function vsCode() {
    var s = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789', o = 'TB';
    for (var i = 0; i < 4; i++) o += s.charAt(Math.floor(Math.random() * s.length));
    return o;
  }
  function vsOppIds(oppParty) {
    var out = [];
    try {
      for (var i = 0; i < (oppParty || []).length && out.length < 3; i++) {
        var it = oppParty[i], id = normId(it && (it.i != null ? it.i : it));
        if (id && monOf(id)) out.push(id);
      }
    } catch (e) {}
    return out;
  }

  // --- 部屋をつくる（ホスト）---
  function vsCreate() {
    var party = vsMyPartyPayload();
    if (!party.length) { alert('てもちが ありません。'); return; }
    var code = vsCode();
    vsWaitPanel('あいことばを つくっています…', '');
    vsApi('/api/rt/create', { party: party, name: vsMyName(), area: 'tb', battleType: 'gym', code: code })
      .then(function (res) {
        if (!res || !res.ok) { vsWaitPanel('つくれませんでした', String((res && res.error) || '')); return; }
        var rid = res.roomId || res.id || code;
        vsWaitPanel('あいことば', rid);
        vsHostWait(rid);
      })
      .catch(function () { vsWaitPanel('つうしんに しっぱい しました', ''); });
  }
  function vsHostWait(code) {
    var tries = 0;
    var iv = setInterval(function () {
      tries++;
      if (tries > 240) { clearInterval(iv); vsWaitPanel('あいてが きませんでした', ''); return; }
      vsApi('/api/rt/room/' + code).then(function (d) {
        if (!d || !d.ok || !d.room) return;
        var r = d.room;
        if (r.guestName) {
          clearInterval(iv);
          vsWaitPanel(r.guestName + ' が きた！ はじめます', code);
          vsApi('/api/rt/ready/' + code, {}).then(function () {
            vsWaitPlaying(code, 'host', r.guestName, d.room.opponentParty || []);
          });
        }
      }).catch(function () {});
    }, 1000);
    S_vsTimers.push(iv);
  }
  // --- あいことばで はいる（ゲスト）---
  function vsJoin(code) {
    code = String(code || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (code.length < 4) { alert('あいことばを いれてね'); return; }
    var party = vsMyPartyPayload();
    if (!party.length) { alert('てもちが ありません。'); return; }
    vsWaitPanel('はいっています…', code);
    vsApi('/api/rt/join/' + code, { party: party, name: vsMyName() })
      .then(function (res) {
        if (!res || !res.ok) {
          var m = { room_not_found: 'その あいことばの へやが ありません', room_not_available: 'もう はいれません', cannot_join_own_room: '自分の へやには はいれません' };
          vsWaitPanel(m[res && res.error] || 'はいれませんでした', '');
          return;
        }
        vsApi('/api/rt/ready/' + code, {}).then(function () {
          vsWaitPlaying(code, 'guest', res.hostName || 'あいて', res.opponentParty || []);
        });
      })
      .catch(function () { vsWaitPanel('つうしんに しっぱい しました', ''); });
  }
  // --- 両方 ready になるのを 待つ ---
  function vsWaitPlaying(code, role, oppName, oppParty) {
    var tries = 0;
    var iv = setInterval(function () {
      tries++;
      if (tries > 120) { clearInterval(iv); vsWaitPanel('はじめられませんでした', ''); return; }
      vsApi('/api/rt/room/' + code).then(function (d) {
        if (!d || !d.ok || !d.room) return;
        var r = d.room;
        var ids = vsOppIds(r.opponentParty && r.opponentParty.length ? r.opponentParty : oppParty);
        var nm = (role === 'host') ? (r.guestName || oppName) : (r.hostName || oppName);
        if (r.status === 'playing' && ids.length) {
          clearInterval(iv);
          vsBattleStart(code, role, nm, ids);
        }
      }).catch(function () {});
    }, 700);
    S_vsTimers.push(iv);
  }

  var S_vsTimers = [];
  function vsStopTimers() {
    for (var i = 0; i < S_vsTimers.length; i++) { try { clearInterval(S_vsTimers[i]); } catch (e) {} }
    S_vsTimers = [];
  }

  // --- バトル開始 ---
  function vsBattleStart(code, role, oppName, oppIds) {
    vsStopTimers();
    var myIds = myParty();
    var mine = [], foes = [];
    CURBAND = FBAND;                 // ともだち たいせんは もっと そろえた帯で
    try {
      for (var i = 0; i < myIds.length; i++) { var u = buildUnit(myIds[i], 'me'); if (u) mine.push(u); }
      for (var j = 0; j < oppIds.length; j++) { var f = buildUnit(oppIds[j], 'foe'); if (f) foes.push(f); }
    } finally { CURBAND = BAND; }
    if (!mine.length || !foes.length) { alert('バトルを じゅんびできませんでした。'); showLobby(); return; }

    S = {
      L: null, lv: -1, mine: mine, foes: foes, mi: 0, fi: 0, turn: 0,
      busy: false, over: false,
      stat: { myMultSum: 0, myMultN: 0, spdLoss: 0, spdN: 0 },
      vs: {
        code: code, role: role, oppName: oppName, mine: {}, lastId: 0,
        myAct: null, foeAct: null, resolving: false, turnStart: 0,
        noMove: 0, lastRes: Date.now(), t0: Date.now(), ended: false
      }
    };
    EL.lobby.classList.add('hidden');
    EL.result.classList.add('hidden');
    EL.field.classList.remove('hidden');
    clearLog();
    say(oppName + ' との たいせん！');
    renderField();
    vsBeginTurn();
    var iv = setInterval(vsTick, 400);
    S_vsTimers.push(iv);
  }

  function vsBeginTurn() {
    if (!S || !S.vs || S.over) return;
    S.vs.turnStart = Date.now();
    S.vs.myAct = null;
    lockCmd(false);
    setWho(true);
  }

  function vsAutoAct(side) {
    var T = (side === 'me') ? S.mine : S.foes, q = (side === 'me') ? S.mi : S.fi;
    var a = T[q], f = (side === 'me') ? cur('foe') : cur('me');
    var bi = 0, bv = -1;
    for (var i = 0; i < a.sk.length; i++) {
      var v = expDmg(a, f, a.sk[i]);
      if (v > bv) { bv = v; bi = i; }
    }
    return { kind: 'skill', i: bi };
  }

  // プレイヤーが わざを えらんだとき
  function vsPlay(myAct) {
    var v = S.vs;
    if (S.busy || S.over || v.myAct) return;
    v.myAct = myAct;
    S.busy = true;
    lockCmd(true);
    setWho(false);
    if (v.role === 'guest') {
      vsSend({ k: 'mv', t: S.turn + 1, a: myAct });
      say('あいてを まっています…');
    } else {
      say('あいてを まっています…');
      vsHostTry();
    }
  }

  function vsHostTry() {
    var v = S.vs;
    if (!v || v.role !== 'host' || v.resolving || S.over) return;
    if (!v.myAct) return;
    var waited = Date.now() - v.turnStart;
    if (!v.foeAct && waited < VS_TURN_MS) return;
    v.resolving = true;
    var foeAct = v.foeAct || vsAutoAct('foe');
    if (v.foeAct) v.noMove = 0; else v.noMove++;
    var myAct = v.myAct;
    v.myAct = null; v.foeAct = null;
    S.turn++;
    var lines = resolveTurn(myAct, foeAct);
    var w = vsVerdict();
    vsSend({ k: 'res', t: S.turn, L: lines, end: w ? 1 : 0, w: w || '' });
    v.resolving = false;
    playLines(lines, function () {
      if (w) { vsFinish(w); return; }
      if (v.noMove >= VS_NOMOVE_MAX) { vsSend({ k: 'bye' }); vsFinish('d', 'あいてが いなくなった みたい'); return; }
      vsBeginTurn();
    });
  }

  function vsVerdict() {
    var meAlive = aliveList(S.mine).length, foAlive = aliveList(S.foes).length;
    if (foAlive === 0 && meAlive > 0) return 'h';
    if (meAlive === 0 && foAlive > 0) return 'g';
    if (meAlive === 0 && foAlive === 0) return 'd';
    if (S.turn >= CAP || (Date.now() - S.vs.t0) > VS_MAX_MS) {
      var a = hpRate(S.mine), b = hpRate(S.foes);
      return a > b ? 'h' : (b > a ? 'g' : 'd');
    }
    return '';
  }

  // ホストの snapshot は ホストから見た形。ゲストは 左右を入れかえて使う。
  function vsFlipSnap(sn) {
    if (!sn) return sn;
    return { mi: sn.fi, fi: sn.mi, me: sn.fo, fo: sn.me };
  }
  function vsApplySnap(sn) {
    if (!sn) return;
    S.mi = sn.mi; S.fi = sn.fi;
    var f = function (arr, sa) {
      for (var i = 0; i < arr.length && i < sa.length; i++) {
        arr[i].hp = sa[i].hp; arr[i].st = sa[i].st; arr[i].stT = sa[i].stT;
        arr[i].ab = sa[i].ab; arr[i].db = sa[i].db; arr[i].alive = sa[i].alive;
      }
    };
    f(S.mine, sn.me); f(S.foes, sn.fo);
  }

  function vsOnEvent(meta) {
    var v = S && S.vs; if (!v || S.over) return;
    if (!meta || !meta.k) return;
    if (meta.k === 'mv' && v.role === 'host') { v.foeAct = meta.a || { kind: 'skill', i: 0 }; vsHostTry(); return; }
    if (meta.k === 'bye') { vsFinish('d', 'あいてが いなくなった みたい'); return; }
    if (meta.k === 'res' && v.role === 'guest') {
      v.lastRes = Date.now();
      S.turn = Number(meta.t || S.turn + 1);
      var L = (meta.L || []).map(function (it) { return { t: it.t, s: vsFlipSnap(it.s) }; });
      S.busy = true; lockCmd(true); setWho(false);
      playLines(L, function () {
        if (L.length) vsApplySnap(L[L.length - 1].s);
        renderField();
        if (meta.end) { vsFinish(meta.w === 'h' ? 'g_lose' : (meta.w === 'g' ? 'g_win' : 'd')); return; }
        vsBeginTurn();
      });
    }
  }

  function vsTick() {
    if (!S || !S.vs) { return; }
    var v = S.vs;
    if (S.over) return;
    // 通信
    vsApi('/api/rt/room/' + v.code + '?after=' + v.lastId).then(function (d) {
      if (!d || !d.ok) return;
      var evs = d.events || [];
      for (var i = 0; i < evs.length; i++) {
        var ev = evs[i];
        if (ev.id > v.lastId) v.lastId = ev.id;
        if (ev.event_type !== 'tb') continue;
        if (v.mine[ev.id]) continue;
        var meta = null;
        try { meta = typeof ev.meta_json === 'string' ? JSON.parse(ev.meta_json) : ev.meta_json; } catch (e) { meta = null; }
        if (meta) vsOnEvent(meta);
      }
    }).catch(function () {});
    // じかんぎれ：自分が えらばない
    if (!S.busy && !v.myAct && v.turnStart && (Date.now() - v.turnStart) > VS_TURN_MS) {
      say('じかんぎれ！ じどうで えらんだよ');
      vsPlay(vsAutoAct('me'));
      return;
    }
    // ホスト：ゲストの手が 来なくても すすめる
    if (v.role === 'host') vsHostTry();
    // ゲスト：結果が 来ない
    if (v.role === 'guest' && (Date.now() - v.lastRes) > VS_WAIT_MS) {
      vsFinish('d', 'あいてが いなくなった みたい');
      return;
    }
    // ぜんたいの上限
    if ((Date.now() - v.t0) > VS_MAX_MS + 20000) vsFinish('d', 'じかんぎれ');
    // のこり秒
    if (!S.busy && v.turnStart) {
      var left = Math.max(0, Math.ceil((VS_TURN_MS - (Date.now() - v.turnStart)) / 1000));
      if (EL.who) EL.who.textContent = '▶ きみの ばん！ わざを えらぼう（あと ' + left + 'びょう）';
    }
  }

  function vsFinish(w, msg) {
    if (!S || S.over) return;
    S.over = true;
    vsStopTimers();
    lockCmd(true);
    if (EL.who) EL.who.textContent = '';
    var win = (w === 'h' && S.vs.role === 'host') || (w === 'g' && S.vs.role === 'guest') || w === 'g_win';
    var lose = (w === 'h' && S.vs.role === 'guest') || (w === 'g' && S.vs.role === 'host') || w === 'g_lose';
    var draw = !win && !lose;
    var p = P(), coins = 0;
    try {
      if (win) coins = 30;
      else if (lose) coins = 10 + Math.round(10 * (1 - hpRate(S.foes)));
      else coins = 10;
      if (p && coins > 0 && !p.coinBanned) p.coins = Number(p.coins || 0) + coins;
      save();
    } catch (e) { log('ごほうび付与に失敗', e); }

    var h = '';
    h += '<div class="text-center">';
    h += '<div style="font-size:40px">' + (win ? '🎉' : (draw ? '🤝' : '💧')) + '</div>';
    h += '<div class="font-bold text-lg ' + (win ? 'text-amber-600' : 'text-slate-600') + '">' + (win ? 'かった！' : (draw ? 'ひきわけ' : 'まけた…')) + '</div>';
    h += '<div class="text-xs text-slate-500 mb-2">' + esc(msg || (S.vs.oppName + ' との たいせん')) + '</div>';
    h += '</div>';
    h += '<div class="rounded-xl bg-white border border-slate-200 p-2 mb-2">';
    h += '<div class="text-sm font-bold">もらったもの</div>';
    h += '<div class="text-sm">コイン +' + coins + '</div>';
    h += '<div class="text-[11px] text-slate-400">ともだち たいせんでは バッジと かけらは もらえません</div>';
    h += '</div>';
    if (lose) {
      h += '<div class="rounded-xl bg-indigo-50 border border-indigo-200 p-2 mb-2">';
      h += '<div class="text-xs font-bold text-indigo-700 mb-1">つぎの ヒント</div>';
      h += '<div class="text-sm">' + esc(lossCard()) + '</div>';
      h += '</div>';
    }
    h += '<button id="tbAgain" class="w-full py-2 rounded-lg text-white font-bold" style="background:linear-gradient(180deg,#818cf8,#4f46e5)">もどる</button>';
    EL.field.classList.add('hidden');
    EL.result.classList.remove('hidden');
    EL.result.innerHTML = h;
    EL.result.querySelector('#tbAgain').addEventListener('click', function () { S = null; showLobby(); });
  }

  // --- 待ちうけの画面 ---
  function vsWaitPanel(title, code) {
    EL.field.classList.add('hidden');
    EL.result.classList.add('hidden');
    EL.lobby.classList.remove('hidden');
    var h = '';
    h += '<div class="rounded-xl bg-white border-2 border-indigo-200 p-3 text-center">';
    h += '<div class="text-sm font-bold text-slate-700 mb-1">' + esc(title) + '</div>';
    if (code) h += '<div style="font-size:30px;font-weight:900;letter-spacing:4px;color:#4f46e5">' + esc(code) + '</div>';
    h += '<div class="text-xs text-slate-400 mt-1">この あいことばを ともだちに おしえてね</div>';
    h += '<button id="tbVsCancel" class="mt-3 px-4 py-2 rounded-lg bg-slate-200 text-slate-700 text-sm font-bold">やめる</button>';
    h += '</div>';
    EL.lobby.innerHTML = h;
    EL.lobby.querySelector('#tbVsCancel').addEventListener('click', function () { vsStopTimers(); S = null; showLobby(); });
  }

  /* ===================== 起動 ===================== */

  function boot() {
    try {
      buildScreen();
      addMenuButton();
      hookHomestudy();
      tbApplyShopDiscount();
      window.tbOpen = open;
      window.TB = {
        ver: 'TB_V2', open: open, leaders: LEADERS, chart: CHART,
        param: {
          SE: SE, RES: RES, IMM: IMM, K: K, BUFF: BUFF, HEAL: HEAL, HEALCAP: HEALCAP,
          MAXSTACK: MAXSTACK, CAP: CAP, BLEND: BLEND, BAND: BAND, POW: POW,
          STRATE: STRATE, ST_IMM: ST_IMM, ST_EARLY: ST_EARLY, PARA_SKIP: PARA_SKIP
        },
        ST: ST, ST_BY_EL: ST_BY_EL,
        avgPctOf: avgPctOf,
        todayLeaderIdx: todayLeaderIdx,
        weekStudyDays: tbWeekStudyDays,
        shopRate: tbShopRate,
        applyShopDiscount: tbApplyShopDiscount,
        vsCreate: vsCreate, vsJoin: vsJoin, FBAND: FBAND,
        buildUnit: buildUnit, mult: mult, grantTicket: grantTicket
      };
      log('ready');
    } catch (e) { log('boot失敗', e); }
  }

  setInterval(function () { try { tbApplyShopDiscount(); } catch (e) {} }, 60000);

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
  // ログイン後にメニューが作り直される場合に備えて、数回だけ追いかける
  var tries = 0;
  var iv = setInterval(function () {
    tries++;
    try { addMenuButton(); hookHomestudy(); tbApplyShopDiscount(); } catch (e) {}
    if (tries > 20) clearInterval(iv);
  }, 1500);
})();
