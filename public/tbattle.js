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
  var ST = {
    burn:   { label: 'やけど', icon: '🔥', turns: 3, dot: 0.06, atk: 0.85, spd: 1,
              from: ['fire'], immune: ['fire'] },
    poison: { label: 'どく',   icon: '☠',  turns: 3, dot: 0.08, atk: 1,    spd: 1,
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
    var b = BAND[key];
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
      ab: 0, db: 0, heals: 0, st: null, stT: 0, stImm: 0, alive: true, sk: []
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
    d.st = kind; d.stT = c.turns;
    return d.name + ' は ' + c.icon + c.label + ' に なった！';
  }

  // ターンの おわりに ダメージ・ターン数・なおり を処理する
  function stTick(u, lines) {
    if (!u || !u.alive) return;
    var c = stOf(u);
    if (c) {
      if (c.dot > 0) {
        var dmg = Math.max(1, Math.round(u.maxHp * c.dot));
        u.hp = Math.max(0, u.hp - dmg);
        lines.push(u.name + ' は ' + c.icon + c.label + ' で ' + dmg + ' の ダメージ！');
        if (u.hp === 0) { u.alive = false; lines.push(u.name + ' は たおれた！'); }
      }
      u.stT--;
      if (u.stT <= 0) { u.st = null; u.stImm = ST_IMM; lines.push(u.name + ' の ' + c.icon + c.label + ' が なおった！'); }
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

  function host() {
    var ref = document.getElementById('screen-gym') || document.getElementById('screen-battle');
    return (ref && ref.parentNode) ? ref.parentNode : document.body;
  }

  function buildScreen() {
    if (EL.root && document.body.contains(EL.root)) return EL.root;
    var d = document.createElement('div');
    d.id = 'screen-tbattle';
    d.className = 'hidden h-full flex flex-col relative flex-1 min-w-0';
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
        '<div id="tbScene" class="battle-scene">' +
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
        '<div id="tbMsg" class="px-2 py-1 text-sm font-bold text-slate-700" style="min-height:2.6em"></div>' +
        '<div id="tbCmd" class="battle-choice-grid px-2 pb-2" style="flex:0 0 auto;align-content:start;max-height:46%"></div>' +
      '</div>' +
      '<div id="tbResult" class="hidden flex-1 overflow-y-auto px-3 py-2"></div>';
    host().appendChild(d);
    EL.root = d;
    EL.lobby = d.querySelector('#tbLobby');
    EL.field = d.querySelector('#tbField');
    EL.result = d.querySelector('#tbResult');
    EL.cmd = d.querySelector('#tbCmd');
    EL.msg = d.querySelector('#tbMsg');
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
    h += '<div class="text-xs text-slate-500 mb-1">こたえなくていい バトルです。わざを えらんで たたかいます。チケット1まい つかいます。</div>';
    h += '<div class="text-xs text-slate-400 mb-2">みんな レベル50・つよさも そろえて たたかいます。あいしょうと わざの えらびかたで きまります。リーダーの つよさは きみの てもちに すこし あわせます。</div>';
    h += '<div class="text-xs text-slate-400 mb-2">つよい わざは、あいてを 🔥やけど ☠どく ⚡しびれ に することが あります（ふつうの わざでは なりません）。</div>';

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

    // リーダー一覧
    for (var k = 0; k < ACTIVE && k < LEADERS.length; k++) {
      var L = LEADERS[k];
      h += '<div class="rounded-xl bg-white border-2 border-indigo-200 p-2 mb-2">';
      h += '<div class="flex items-center gap-2">';
      h += '<div style="font-size:30px">' + L.emoji + '</div>';
      h += '<div class="flex-1"><div class="font-bold text-sm">' + esc(L.name) + '</div>';
      h += '<div class="text-[11px] text-slate-500">' + esc(L.say) + '</div></div>';
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
    say(L.name + ' が しょうぶを しかけてきた！');
    renderField();
  }

  function cur(side) { return side === 'me' ? S.mine[S.mi] : S.foes[S.fi]; }
  function aliveList(arr) { var o = []; for (var i = 0; i < arr.length; i++) if (arr[i].alive) o.push(i); return o; }

  function say(t) { if (EL.msg) EL.msg.textContent = t; }

  function balls(arr) {
    var s = '';
    for (var i = 0; i < arr.length; i++) s += arr[i].alive ? '●' : '○';
    return s;
  }

  function renderField() {
    if (!S) return;
    var me = cur('me'), fo = cur('foe');
    var d = EL.root;
    d.querySelector('#tbTurn').textContent = 'のこり ' + Math.max(0, CAP - S.turn) + 'ターン';
    d.querySelector('#tbFoeName').textContent = fo.name;
    d.querySelector('#tbFoeType').innerHTML = badge(fo.el) + statArrows(fo);
    d.querySelector('#tbFoeBar').style.width = Math.round(100 * fo.hp / fo.maxHp) + '%';
    d.querySelector('#tbFoeBar').style.background = hpColor(fo);
    d.querySelector('#tbFoeHp').textContent = fo.hp + ' / ' + fo.maxHp;
    d.querySelector('#tbFoeBalls').textContent = balls(S.foes);
    d.querySelector('#tbFoeSprite').innerHTML = spriteHtml(fo.id, 56);
    d.querySelector('#tbMeName').textContent = me.name;
    d.querySelector('#tbMeType').innerHTML = badge(me.el) + statArrows(me);
    d.querySelector('#tbMeBar').style.width = Math.round(100 * me.hp / me.maxHp) + '%';
    d.querySelector('#tbMeBar').style.background = hpColor(me);
    d.querySelector('#tbMeHp').textContent = me.hp + ' / ' + me.maxHp;
    d.querySelector('#tbMeBalls').textContent = balls(S.mine);
    d.querySelector('#tbMeSprite').innerHTML = spriteHtml(me.id, 64);
    renderCmd();
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
        ST[u.st].icon + ST[u.st].label + ' のこり' + Math.max(0, u.stT) + '</span> ';
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
      (others.length ? '' : ' disabled') + '>こうたい' + (others.length ? '' : '（できない）') + '</button>';
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
    if (!S || S.busy || S.over) return;
    S.busy = true;
    S.turn++;
    var foeAct = aiChoose();
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

    function actMe() {
      var u = cur('me'), v = cur('foe');
      if (myAct.kind === 'swap') {
        S.mi = myAct.j;
        lines.push('がんばれ！ ' + cur('me').name + '！');
        return;
      }
      var s = u.sk[myAct.i] || u.sk[0];
      var r = doHit(u, v, s);
      if (r.miss) lines.push(u.name + ' の ' + s.name + '！ しかし はずれた！');
      else if (s.pow) {
        var lab = multLabel(r.m);
        lines.push(u.name + ' の ' + s.name + '！ ' + (lab ? lab + ' ' : '') + v.name + ' に ' + r.dmg + ' のダメージ！');
      } else lines.push(u.name + ' の ' + s.name + '！');
      if (r.st) lines.push(r.st);
      var em = applyEffect(u, v, s.eff, r.dmg);
      if (em) lines.push(em);
      if (!v.alive) lines.push(v.name + ' は たおれた！');
    }
    function actFoe() {
      var u = cur('foe'), v = cur('me');
      if (foeAct.kind === 'swap') {
        S.fi = foeAct.j;
        lines.push(S.L.name + ' は ' + cur('foe').name + ' を だした！');
        return;
      }
      var s = u.sk[foeAct.i] || u.sk[0];
      var r = doHit(u, v, s);
      if (r.miss) lines.push(u.name + ' の ' + s.name + '！ しかし はずれた！');
      else if (s.pow) {
        var lab2 = multLabel(r.m);
        lines.push(u.name + ' の ' + s.name + '！ ' + (lab2 ? lab2 + ' ' : '') + v.name + ' に ' + r.dmg + ' のダメージ！');
      } else lines.push(u.name + ' の ' + s.name + '！');
      if (r.st) lines.push(r.st);
      var em2 = applyEffect(u, v, s.eff, r.dmg);
      if (em2) lines.push(em2);
      if (!v.alive) lines.push(v.name + ' は たおれた！');
    }

    if (meFirst) { actMe(); if (cur('me').alive) actFoe(); }
    else { actFoe(); if (cur('foe').alive) actMe(); }

    // ターンの おわり：やけど・どくの ダメージと、ターン数の へらし
    stTick(cur('me'), lines);
    stTick(cur('foe'), lines);

    // たおれたら次を出す
    if (!cur('me').alive) {
      var al = aliveList(S.mine);
      if (al.length) { S.mi = al[0]; lines.push('いけ！ ' + cur('me').name + '！'); }
    }
    if (!cur('foe').alive) {
      var al2 = aliveList(S.foes);
      if (al2.length) { S.fi = al2[0]; lines.push(S.L.name + ' は ' + cur('foe').name + ' を だした！'); }
    }

    // 演出（1行ずつ）
    var step = 0;
    function next() {
      if (step < lines.length) { say(lines[step++]); renderField(); setTimeout(next, 750); return; }
      S.busy = false;
      renderField();
      checkEnd();
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
    var tb = ensureTb(), p = P();
    var coins = 0, shards = 0, gotBadge = false;
    try {
      if (win) {
        coins = 40;
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
    h += '<div class="text-sm">コイン +' + coins + '</div>';
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

  /* ===================== 起動 ===================== */

  function boot() {
    try {
      buildScreen();
      addMenuButton();
      hookHomestudy();
      window.tbOpen = open;
      window.TB = {
        ver: 'TB_V2', open: open, leaders: LEADERS, chart: CHART,
        param: {
          SE: SE, RES: RES, IMM: IMM, K: K, BUFF: BUFF, HEAL: HEAL, HEALCAP: HEALCAP,
          MAXSTACK: MAXSTACK, CAP: CAP, BLEND: BLEND, BAND: BAND, POW: POW,
          STRATE: STRATE, ST_IMM: ST_IMM
        },
        ST: ST, ST_BY_EL: ST_BY_EL,
        avgPctOf: avgPctOf,
        buildUnit: buildUnit, mult: mult, grantTicket: grantTicket
      };
      log('ready');
    } catch (e) { log('boot失敗', e); }
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
  // ログイン後にメニューが作り直される場合に備えて、数回だけ追いかける
  var tries = 0;
  var iv = setInterval(function () {
    tries++;
    try { addMenuButton(); hookHomestudy(); } catch (e) {}
    if (tries > 20) clearInterval(iv);
  }, 1500);
})();
