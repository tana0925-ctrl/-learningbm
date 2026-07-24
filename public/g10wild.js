/* ============================================================
   高校 野生モンスター＆出現テーブル v181（隠し最上級エリア）
   教科ごとに進化ライン1本（ID 1168〜1176・野生限定／通常トレード可）
   最上級エリアなので既存最強帯より少し強め。最初からオリジナル技3つ。
   図鑑の入手方法は desc の【入手】から自動表示（実条件と矛盾しないヒント）
   ============================================================ */
(function () {
  var G10 = window.G10; if (!G10) return;
  var M = window.MONSTERS; if (!M || !M.push) return;
  if (window.__G10WILD__) return; window.__G10WILD__ = 1;

  var have = {};
  try { M.forEach(function (m) { if (m && m.id != null) have[m.id] = 1; }); } catch (e) {}
  function add(mon) { if (!have[mon.id]) { M.push(mon); have[mon.id] = 1; } }
  var HINT = '【入手】中3をやりこむと開く隠しの「高校エリア」にまれに出現';

  // ---- 数学ライン（1168→1169→1170）----
  add({ id: 1168, name: 'パイこぞう', sprite: 'π', hp: 210, atk: 54, def: 48, spd: 60, buff: 'guard', elementType: 'psychic', stage: 1, gacha: false, evoLevel: 26, nextId: 1169,
    skills: [
      { name: 'てんかいスラッシュ', type: 'normal', pow: 15, acc: 0.96, element: 'psychic', desc: '乗法公式でまとめて斬る' },
      { name: 'いんすうぶんかい', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_self', element: 'psychic', desc: '式をきれいに分けて力をためる' },
      { name: 'たすきがけ', type: 'heavy', pow: 36, acc: 0.78, element: 'psychic', desc: 'ななめに掛けて一気に打つ' }
    ], desc: '円周率πを小数第100位まで暗唱できる小僧。ただし自分の身長は測れない。' + HINT });
  add({ id: 1169, name: 'サンカク卿', sprite: '🔺', hp: 360, atk: 96, def: 68, spd: 86, buff: 'attack', elementType: 'psychic', stage: 2, gacha: false, evoLevel: 50, nextId: 1170,
    skills: [
      { name: 'サインコサイン', type: 'normal', pow: 19, acc: 0.96, element: 'psychic', desc: '対辺と隣辺の比で切りこむ' },
      { name: 'タンジェント突き', type: 'heavy', pow: 44, acc: 0.76, element: 'psychic', desc: '傾きをのせた鋭い一突き' },
      { name: 'そうごかんけい', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'psychic', desc: 'sin²+cos²=1でガードを固める' }
    ], desc: '三角形さえあれば高さも距離も測れる貴族。平地では手持ちぶさたでそわそわする。' + HINT });
  add({ id: 1170, name: 'カクリツ大魔王', sprite: '🎰', hp: 600, atk: 134, def: 96, spd: 106, buff: 'lucky', elementType: 'psychic', stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: 'じゅんれつラッシュ', type: 'normal', pow: 24, acc: 0.95, effect: 'buff_atk_self', element: 'psychic', desc: '並べ方の数だけ手数がふえる' },
      { name: 'よじしょうクラッシュ', type: 'heavy', pow: 54, acc: 0.72, element: 'psychic', desc: '余事象からの逆転の一撃' },
      { name: 'きたいちシフト', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'psychic', desc: '確率をずらして相手の運を下げる' }
    ], desc: 'あらゆる勝負の確率を一瞬で計算する大魔王。なのにスロットで全財産をすった過去がある。' + HINT });

  // ---- 理科ライン（1171→1172→1173）----
  add({ id: 1171, name: 'カソクボルト', sprite: '🔩', hp: 208, atk: 54, def: 50, spd: 58, buff: 'speed', elementType: 'steel', stage: 1, gacha: false, evoLevel: 26, nextId: 1172,
    skills: [
      { name: 'とうかそくアタック', type: 'normal', pow: 15, acc: 0.96, element: 'steel', desc: '一定の割合で加速して突っこむ' },
      { name: 'かんせいガード', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'steel', desc: '止まりたがらない体で受け流す' },
      { name: 'さようはんさよう', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'steel', desc: '押した力がそのまま返る' }
    ], desc: '止まると死ぬと思っているので、いつも等加速度で走り続ける。宿題も加速して溜める。' + HINT });
  add({ id: 1172, name: 'モルけがく師', sprite: '🎇', hp: 362, atk: 96, def: 66, spd: 84, buff: 'attack', elementType: 'fire', stage: 2, gacha: false, evoLevel: 50, nextId: 1173,
    skills: [
      { name: 'さんかバースト', type: 'normal', pow: 19, acc: 0.96, element: 'fire', desc: '電子をうばって酸化させる' },
      { name: 'モルばくはつ', type: 'heavy', pow: 44, acc: 0.76, element: 'fire', desc: '6×10²³個ぶんの粒で爆撃' },
      { name: 'かんげんチャージ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_self', element: 'fire', desc: '電子を受け取って力をためる' }
    ], desc: '何を見ても「これは何mol？」と数えたがる化学者。アボガドロ定数を毎晩子守歌にしている。' + HINT });
  add({ id: 1173, name: 'イデンシ大王', sprite: '🩻', hp: 600, atk: 132, def: 98, spd: 100, buff: 'lucky', elementType: 'grass', stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: 'DNAらせん斬り', type: 'normal', pow: 24, acc: 0.95, effect: 'buff_atk_self', element: 'grass', desc: '二重らせんでからめとる' },
      { name: 'ATPフルパワー', type: 'heavy', pow: 54, acc: 0.72, element: 'grass', desc: 'エネルギーの通貨を一気に使う' },
      { name: 'さいぼうぶんれつ', type: 'unique', pow: 0, acc: 1.0, effect: 'heal_self', element: 'grass', desc: '細胞をふやしてHP回復' }
    ], desc: '自分のDNAを暗記している大王。ただしA・T・G・Cの並びが長すぎて、毎回とちゅうで寝る。' + HINT });

  // ---- 社会ライン（1174→1175→1176）----
  add({ id: 1174, name: 'チリグラフ丸', sprite: '📊', hp: 212, atk: 52, def: 50, spd: 56, buff: 'guard', elementType: 'ground', stage: 1, gacha: false, evoLevel: 26, nextId: 1175,
    skills: [
      { name: 'いどけいどショット', type: 'normal', pow: 15, acc: 0.96, element: 'ground', desc: '緯度経度でねらいを定める' },
      { name: 'メルカトルずほう', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'ground', desc: '地図をゆがめて相手をまどわす' },
      { name: 'とうおんせんガード', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'ground', desc: '同じ気温の線でかこって守る' }
    ], desc: '世界中の統計をグラフにするのが趣味。ただしどの図法もゆがむので、正しい地図はあきらめている。' + HINT });
  add({ id: 1175, name: 'レキシタイセン侯', sprite: '🆚', hp: 360, atk: 94, def: 70, spd: 82, buff: 'attack', elementType: 'ground', stage: 2, gacha: false, evoLevel: 50, nextId: 1176,
    skills: [
      { name: 'さんぎょうかくめい', type: 'normal', pow: 19, acc: 0.96, element: 'ground', desc: '機械の力でまとめて攻撃' },
      { name: 'せかいきょうこう', type: 'heavy', pow: 44, acc: 0.76, element: 'ground', desc: '大恐慌の波で一気に押し流す' },
      { name: 'れいせんにらみあい', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'ground', desc: '東西で にらみ合って守りを固める' }
    ], desc: '近現代の戦争や革命をぜんぶ実況できる侯爵。話が「対決」ばかりで、平和な時代は早口で飛ばす。' + HINT });
  add({ id: 1176, name: 'コウキョウ大魔王', sprite: '⚖️', hp: 605, atk: 130, def: 100, spd: 96, buff: 'lucky', elementType: 'ground', stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: 'さんけんぶんりつ', type: 'normal', pow: 24, acc: 0.95, effect: 'buff_atk_self', element: 'ground', desc: '力を三つに分けて手数を増やす' },
      { name: 'じんけんジャッジ', type: 'heavy', pow: 54, acc: 0.72, element: 'ground', desc: '基本的人権の名のもとに裁く一撃' },
      { name: 'こうせいとこうりつ', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'ground', desc: '公正と効率で相手の主張をくずす' }
    ], desc: '「みんなが納得できるか（公正）」と「むだがないか（効率）」を秤にかける大魔王。会議は必ず長びく。' + HINT });

  G10.addWild = G10.addWild || function (map) { return window.G8.addWild(map); };
  G10.addWild({
    // 数学
    'm10-suushiki':   { 1: [1168], 2: [1168, 1169], 3: [1169, 1170] },
    'm10-futoushiki': { 1: [1168], 2: [1169], 3: [1170] },
    'm10-niji':       { 1: [1168], 2: [1169], 3: [1169, 1170] },
    'm10-sankaku':    { 1: [1168], 2: [1169], 3: [1170] },
    'm10-junretsu':   { 1: [1168], 2: [1169], 3: [1169, 1170] },
    'm10-kakuritsu':  { 1: [1168], 2: [1169], 3: [1170] },
    // 理科
    'r10-butsuri':    { 1: [1171], 2: [1171, 1172], 3: [1172, 1173] },
    'r10-kagaku':     { 1: [1171], 2: [1172], 3: [1173] },
    'r10-seibutsu':   { 1: [1171], 2: [1172], 3: [1172, 1173] },
    // 社会
    's10-rekishi':    { 1: [1174], 2: [1174, 1175], 3: [1175, 1176] },
    's10-chiri':      { 1: [1174], 2: [1175], 3: [1176] },
    's10-koukyou':    { 1: [1174], 2: [1175], 3: [1175, 1176] }
  });
})();
