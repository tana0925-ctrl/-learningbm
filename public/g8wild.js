/* ============================================================
   中2 野生モンスター＆出現テーブル v178（ネットレ対応 第5弾）
   教科ごとに進化ライン1本（ID 1138〜1152・すべて野生限定／通常トレード可）
   ============================================================ */
(function () {
  var G8 = window.G8; if (!G8) return;
  var M = window.MONSTERS; if (!M || !M.push) return;
  if (window.__G8WILD__) return; window.__G8WILD__ = 1;

  var have = {};
  try { M.forEach(function (m) { if (m && m.id != null) have[m.id] = 1; }); } catch (e) {}
  function add(mon) { if (!have[mon.id]) { M.push(mon); have[mon.id] = 1; } }

  // ---- 中2数学ライン（1138→1139→1140）----
  add({
    id: 1138, name: 'タンコウ式部', sprite: '➕',
    hp: 195, atk: 52, def: 42, spd: 56, buff: 'guard', elementType: 'psychic',
    stage: 1, gacha: false, evoLevel: 24, nextId: 1139,
    skills: [
      { name: 'どうるいこう整理', type: 'normal', pow: 14, acc: 0.96, element: 'psychic', desc: '同じ仲間だけまとめて殴る' },
      { name: '係数アップ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_self', element: 'psychic', desc: '自分の攻撃を上げる' },
      { name: 'カッコはずし', type: 'heavy', pow: 34, acc: 0.78, element: 'psychic', desc: '符号ごとひっくり返す' }
    ],
    desc: '式を見ると同類項をまとめずにいられない。部屋のかたづけは苦手。'
  });
  add({
    id: 1139, name: 'レンリツ二刀流', sprite: '✖️',
    hp: 335, atk: 90, def: 64, spd: 82, buff: 'attack', elementType: 'psychic',
    stage: 2, gacha: false, evoLevel: 46, nextId: 1140,
    skills: [
      { name: '加減法チョップ', type: 'normal', pow: 18, acc: 0.96, element: 'psychic', desc: '2本の式を足したり引いたり' },
      { name: '代入ラッシュ', type: 'heavy', pow: 42, acc: 0.76, element: 'psychic', desc: 'まるごと入れかえて攻撃' },
      { name: '解はひとつ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_self', element: 'psychic', desc: 'ねらいを定める' }
    ],
    desc: '式を必ず2本持ち歩く二刀流。1本だと落ち着かず、3本だと泣く。'
  });
  add({
    id: 1140, name: 'イチジ関数王', sprite: '📉',
    hp: 545, atk: 124, def: 90, spd: 102, buff: 'lucky', elementType: 'psychic',
    stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: '傾きスラッシュ', type: 'normal', pow: 22, acc: 0.95, element: 'psychic', desc: '一定の割合で切りつける' },
      { name: '切片ドロップ', type: 'heavy', pow: 50, acc: 0.74, element: 'psychic', desc: 'y軸まで落として叩く' },
      { name: '交点でつかまえる', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'psychic', desc: '相手の動きを止める' }
    ],
    desc: '人生は右肩上がりが好み。ただし傾きがマイナスの日は、静かに沈んでいく。'
  });

  // ---- 中2英語ライン（1141→1142→1143）----
  add({
    id: 1141, name: 'パスト小僧', sprite: '🔡',
    hp: 190, atk: 50, def: 40, spd: 58, buff: 'speed', elementType: 'water',
    stage: 1, gacha: false, evoLevel: 24, nextId: 1142,
    skills: [
      { name: 'edパンチ', type: 'normal', pow: 14, acc: 0.96, element: 'water', desc: 'なんでも過去にしてしまう' },
      { name: '不規則へんげ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_spd_self', element: 'water', desc: '形を変えて素早くなる' },
      { name: 'was・wereビーム', type: 'heavy', pow: 33, acc: 0.78, element: 'water', desc: '主語を見てから撃つ' }
    ],
    desc: '語尾に ed をつけるのが口ぐせ。go を goed と言って先輩に直される毎日。'
  });
  add({
    id: 1142, name: 'ヒカクキュウ番長', sprite: '🔠',
    hp: 330, atk: 88, def: 66, spd: 80, buff: 'attack', elementType: 'water',
    stage: 2, gacha: false, evoLevel: 46, nextId: 1143,
    skills: [
      { name: 'er連打', type: 'normal', pow: 18, acc: 0.96, element: 'water', desc: '相手よりちょっと強く殴る' },
      { name: 'thanアッパー', type: 'heavy', pow: 41, acc: 0.77, element: 'water', desc: '比べてから打ち上げる' },
      { name: 'as〜asの構え', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'water', desc: '相手と同じ強さになる' }
    ],
    desc: '何を見ても「オレのほうが〜er」と言う番長。最上級を出されると急に静かになる。'
  });
  add({
    id: 1143, name: 'フテイシ大魔王', sprite: '🗣️',
    hp: 540, atk: 122, def: 88, spd: 100, buff: 'attack', elementType: 'water',
    stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: 'to+原形ソード', type: 'normal', pow: 22, acc: 0.95, element: 'water', desc: '三つの用法を使い分ける' },
      { name: '名詞的用法クラッシュ', type: 'heavy', pow: 50, acc: 0.74, element: 'water', desc: '「〜すること」で押しつぶす' },
      { name: '目的でいくぞ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_self', element: 'water', desc: '「〜するために」燃える' }
    ],
    desc: '三つの用法を使い分ける大魔王。動名詞とは仲が良いが、ときどき役割でもめる。'
  });

  // ---- 中2理科ライン（1144→1145→1146）----
  add({
    id: 1144, name: 'ゲンシくん', sprite: '⚛️',
    hp: 188, atk: 51, def: 43, spd: 54, buff: 'guard', elementType: 'electric',
    stage: 1, gacha: false, evoLevel: 24, nextId: 1145,
    skills: [
      { name: 'それ以上われない', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'electric', desc: 'これ以上は分けられない' },
      { name: '元素記号タッチ', type: 'normal', pow: 14, acc: 0.96, element: 'electric', desc: 'アルファベットで小突く' },
      { name: '結びつきアタック', type: 'heavy', pow: 33, acc: 0.78, element: 'electric', desc: '相手とくっついて衝撃を出す' }
    ],
    desc: '「ぼくはこれ以上分けられません」が決めぜりふ。分子になると急におしゃべり。'
  });
  add({
    id: 1145, name: 'ブンシ博士', sprite: '🧫',
    hp: 332, atk: 86, def: 68, spd: 78, buff: 'guard', elementType: 'electric',
    stage: 2, gacha: false, evoLevel: 46, nextId: 1146,
    skills: [
      { name: '化学反応式ビーム', type: 'normal', pow: 18, acc: 0.96, element: 'electric', desc: '左右の数をそろえて撃つ' },
      { name: '酸化バースト', type: 'heavy', pow: 42, acc: 0.76, element: 'electric', desc: '酸素と結びついて発熱' },
      { name: '質量保存のちかい', type: 'unique', pow: 0, acc: 1.0, effect: 'heal_self', element: 'electric', desc: '減った分はどこかにある' }
    ],
    desc: '反応式の係数を合わせるまで眠れない博士。左と右がそろうと拍手する。'
  });
  add({
    id: 1146, name: 'オームの雷神', sprite: '🌩️',
    hp: 550, atk: 126, def: 86, spd: 104, buff: 'speed', elementType: 'electric',
    stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: 'V=RIサンダー', type: 'normal', pow: 23, acc: 0.95, element: 'electric', desc: '電圧＝抵抗×電流' },
      { name: '直列ドカン', type: 'heavy', pow: 52, acc: 0.72, element: 'electric', desc: '一本道に電流を集める' },
      { name: '電磁誘導チャージ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_self', element: 'electric', desc: '磁石を動かして力をためる' }
    ],
    desc: '抵抗されるほど燃えるタイプ。並列につながれると、実力が分散してしょんぼり。'
  });

  // ---- 中2社会ライン（1147→1148→1149）----
  add({
    id: 1147, name: 'チホウめぐり丸', sprite: '🗾',
    hp: 192, atk: 49, def: 44, spd: 55, buff: 'lucky', elementType: 'ground',
    stage: 1, gacha: false, evoLevel: 24, nextId: 1148,
    skills: [
      { name: '地形クイズ', type: 'normal', pow: 14, acc: 0.96, element: 'ground', desc: '山地か平野かを問いつめる' },
      { name: 'やませブロー', type: 'heavy', pow: 32, acc: 0.79, element: 'ground', desc: '冷たい風で相手を冷やす' },
      { name: '名産品じまん', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'ground', desc: '地元の力で守りを固める' }
    ],
    desc: '七地方を旅する案内役。おみやげの話が長く、まだ二地方目で日が暮れる。'
  });
  add({
    id: 1148, name: 'カンゴウ貿易商', sprite: '🏞️',
    hp: 334, atk: 87, def: 65, spd: 81, buff: 'lucky', elementType: 'ground',
    stage: 2, gacha: false, evoLevel: 46, nextId: 1149,
    skills: [
      { name: '勘合札チェック', type: 'normal', pow: 18, acc: 0.97, element: 'ground', desc: '本物かどうか確かめる' },
      { name: '楽市楽座セール', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'ground', desc: '関所をなくして運を上げる' },
      { name: '検地の一撃', type: 'heavy', pow: 41, acc: 0.76, element: 'ground', desc: 'ものさしで正確に測って打つ' }
    ],
    desc: 'にせものを見分けるために札を持ち歩く商人。買い物のレシートも全部とってある。'
  });
  add({
    id: 1149, name: 'バクハン体制将軍', sprite: '🎌',
    hp: 548, atk: 120, def: 94, spd: 96, buff: 'defense', elementType: 'ground',
    stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: '武家諸法度', type: 'normal', pow: 22, acc: 0.96, element: 'ground', desc: 'ルールで相手をしばる' },
      { name: '参勤交代マーチ', type: 'heavy', pow: 49, acc: 0.75, element: 'ground', desc: '長い行列で体力をけずる' },
      { name: '鎖国のかまえ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'ground', desc: '出島だけ開けて守りを固める' }
    ],
    desc: '守りは天下一。ただし黒船が来ると、二百年ぶんの慌てぶりを一気に見せる。'
  });

  // ---- 中2国語ライン（1150→1151→1152）----
  add({
    id: 1150, name: 'ヨミガナ小町', sprite: '🈁',
    hp: 190, atk: 50, def: 41, spd: 57, buff: 'speed', elementType: 'fairy',
    stage: 1, gacha: false, evoLevel: 24, nextId: 1151,
    skills: [
      { name: '音読み訓読み', type: 'normal', pow: 14, acc: 0.96, element: 'fairy', desc: '二通りの読みで攻める' },
      { name: '難読ふりがな', type: 'heavy', pow: 32, acc: 0.79, element: 'fairy', desc: '読めない字で混乱させる' },
      { name: 'すらすら音読', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_spd_self', element: 'fairy', desc: 'リズムよく素早くなる' }
    ],
    desc: 'どんな字にもふりがなをふる小町。自分の名前にもふってあるので迷子にならない。'
  });
  add({
    id: 1151, name: 'ジュクゴ職人', sprite: '📚',
    hp: 331, atk: 85, def: 69, spd: 77, buff: 'guard', elementType: 'fairy',
    stage: 2, gacha: false, evoLevel: 46, nextId: 1152,
    skills: [
      { name: '同音異義シュート', type: 'normal', pow: 18, acc: 0.96, element: 'fairy', desc: '意味ちがいで惑わせる' },
      { name: '対義語カウンター', type: 'heavy', pow: 41, acc: 0.77, element: 'fairy', desc: '反対の意味で打ち返す' },
      { name: '熟語くみたて', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'fairy', desc: '二字を組み合わせて固める' }
    ],
    desc: '熟語を組み立てるのが仕事。「保証」と「保障」を取りちがえた日は、無言で作り直す。'
  });
  add({
    id: 1152, name: 'コジセイゴ仙人', sprite: '🏮',
    hp: 542, atk: 118, def: 92, spd: 99, buff: 'lucky', elementType: 'fairy',
    stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: '矛盾つき', type: 'normal', pow: 22, acc: 0.95, element: 'fairy', desc: 'つじつまの合わない一撃' },
      { name: '背水の陣', type: 'heavy', pow: 51, acc: 0.73, element: 'fairy', desc: 'あとがない覚悟で打つ' },
      { name: '温故知新', type: 'unique', pow: 0, acc: 1.0, effect: 'heal_self', element: 'fairy', desc: '昔を学んで元気になる' }
    ],
    desc: '昔話でたとえないと話せない仙人。「蛇足だが」と言ってから話が三十分のびる。'
  });

  // ---- 出現テーブル（中2エリア）----
  G8.addWild({
    // 数学
    'm8-shiki':     { 1: [1138], 2: [1138, 1139], 3: [1139, 1140] },
    'm8-renritsu':  { 1: [1138], 2: [1139], 3: [1139, 1140] },
    'm8-ichiji':    { 1: [1138], 2: [1139], 3: [1140] },
    'm8-zukei':     { 1: [1138], 2: [1138, 1139], 3: [1140] },
    'm8-kakuritsu': { 1: [1138], 2: [1139], 3: [1140] },
    // 英語
    'e8-past':    { 1: [1141], 2: [1141, 1142], 3: [1142, 1143] },
    'e8-future':  { 1: [1141], 2: [1142], 3: [1143] },
    'e8-modal':   { 1: [1141], 2: [1142], 3: [1142, 1143] },
    'e8-toinf':   { 1: [1141], 2: [1142], 3: [1143] },
    'e8-gerund':  { 1: [1141], 2: [1142], 3: [1143] },
    'e8-compare': { 1: [1141], 2: [1142], 3: [1142, 1143] },
    'e8-conj':    { 1: [1141], 2: [1142], 3: [1143] },
    // 理科
    'r8-chem':    { 1: [1144], 2: [1144, 1145], 3: [1145, 1146] },
    'r8-body':    { 1: [1144], 2: [1145], 3: [1146] },
    'r8-elec':    { 1: [1144], 2: [1145], 3: [1146] },
    'r8-weather': { 1: [1144], 2: [1145], 3: [1145, 1146] },
    // 社会
    's8-japan':    { 1: [1147], 2: [1147, 1148], 3: [1148, 1149] },
    's8-region':   { 1: [1147], 2: [1148], 3: [1149] },
    's8-kamakura': { 1: [1147], 2: [1148], 3: [1148, 1149] },
    's8-edo':      { 1: [1147], 2: [1148], 3: [1149] },
    // 国語
    'j8-yomi':   { 1: [1150], 2: [1150, 1151], 3: [1151, 1152] },
    'j8-kaki':   { 1: [1150], 2: [1151], 3: [1152] },
    'j8-goi':    { 1: [1150], 2: [1151], 3: [1151, 1152] },
    'j8-kanyou': { 1: [1150], 2: [1151], 3: [1152] }
  });
})();
