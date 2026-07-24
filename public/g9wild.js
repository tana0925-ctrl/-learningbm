/* ============================================================
   中3 野生モンスター＆出現テーブル v180（ネットレ対応 第6弾）
   教科ごとに進化ライン1本（ID 1153〜1167・すべて野生限定／通常トレード可）
   最初からオリジナル技を設定（デフォルト技フォールバックにしない）
   ============================================================ */
(function () {
  var G9 = window.G9; if (!G9) return;
  var M = window.MONSTERS; if (!M || !M.push) return;
  if (window.__G9WILD__) return; window.__G9WILD__ = 1;

  var have = {};
  try { M.forEach(function (m) { if (m && m.id != null) have[m.id] = 1; }); } catch (e) {}
  function add(mon) { if (!have[mon.id]) { M.push(mon); have[mon.id] = 1; } }

  // ---- 数学ライン（1153→1154→1155）----
  add({ id: 1153, name: 'ルートこぞう', sprite: '🟰', hp: 196, atk: 50, def: 44, spd: 56, buff: 'guard', elementType: 'psychic', stage: 1, gacha: false, evoLevel: 24, nextId: 1154,
    skills: [
      { name: 'ルートしぼり', type: 'normal', pow: 14, acc: 0.96, element: 'psychic', desc: '√の中をどんどん簡単にする' },
      { name: 'ゆうりかスプレー', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_self', element: 'psychic', desc: '分母を整えて調子を上げる' },
      { name: '平方たたき', type: 'heavy', pow: 34, acc: 0.78, element: 'psychic', desc: '2乗して一気に打つ' }
    ], desc: '√の中身を見ると、つい簡単な形に直したくなる小僧。整理しすぎて何の数か忘れる。' });
  add({ id: 1154, name: 'インスウ番長', sprite: '🔢', hp: 336, atk: 90, def: 64, spd: 82, buff: 'attack', elementType: 'psychic', stage: 2, gacha: false, evoLevel: 46, nextId: 1155,
    skills: [
      { name: '因数分解チョップ', type: 'normal', pow: 18, acc: 0.96, element: 'psychic', desc: '式をきれいに2つに割る' },
      { name: '乗法公式ラッシュ', type: 'heavy', pow: 42, acc: 0.76, element: 'psychic', desc: '(x+a)(x+b)で連続攻撃' },
      { name: '共通因数まとめ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'psychic', desc: '共通部分でくくって守る' }
    ], desc: 'どんな式もかならず「かけ算の形」に分けたがる番長。分けられないと不機嫌。' });
  add({ id: 1155, name: 'サンペイ大王', sprite: '➗', hp: 548, atk: 124, def: 92, spd: 100, buff: 'lucky', elementType: 'psychic', stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: '斜辺スラッシュ', type: 'normal', pow: 22, acc: 0.95, effect: 'buff_atk_self', element: 'psychic', desc: '直角の向こうへ一直線' },
      { name: 'ピタゴラクラッシュ', type: 'heavy', pow: 50, acc: 0.74, element: 'psychic', desc: 'a²+b²=c²の一撃' },
      { name: '相似でうつす', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'psychic', desc: '相手を縮小コピーして弱らせる' }
    ], desc: '三角形を見れば辺の長さを一瞬で当てる大王。ただし正方形は苦手で、いつも対角線でつまずく。' });

  // ---- 英語ライン（1156→1157→1158）----
  add({ id: 1156, name: 'ビーピーピー', sprite: '🔤', hp: 190, atk: 50, def: 42, spd: 58, buff: 'speed', elementType: 'fairy', stage: 1, gacha: false, evoLevel: 24, nextId: 1157,
    skills: [
      { name: 'うけみタックル', type: 'normal', pow: 14, acc: 0.96, element: 'fairy', desc: '「される」側から反撃する' },
      { name: 'バイ・ショット', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'fairy', desc: 'by で相手をしぼる' },
      { name: 'かこぶんしガード', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'fairy', desc: '過去分詞でしっかり守る' }
    ], desc: 'be動詞＋過去分詞が口ぐせ。「ぼくはやられ役？」といつも受け身なモンスター。' });
  add({ id: 1157, name: 'カンリョウ伯爵', sprite: '🆎', hp: 334, atk: 88, def: 64, spd: 80, buff: 'attack', elementType: 'fairy', stage: 2, gacha: false, evoLevel: 46, nextId: 1158,
    skills: [
      { name: 'ハブ・パンチ', type: 'normal', pow: 18, acc: 0.96, element: 'fairy', desc: 'have+過去分詞で打ちこむ' },
      { name: 'エバー・ラッシュ', type: 'heavy', pow: 42, acc: 0.76, element: 'fairy', desc: '「〜したことがある」経験の連打' },
      { name: 'シンス・キープ', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_self', element: 'fairy', desc: 'since で気合いを継続' }
    ], desc: '「もう終わった？」「ずっと続けてる？」と現在完了ばかり気にする伯爵。過去の話には少しうるさい。' });
  add({ id: 1158, name: 'カンケイ大公', sprite: '📡', hp: 542, atk: 122, def: 90, spd: 98, buff: 'lucky', elementType: 'fairy', stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: 'フー・ウィッチ連撃', type: 'normal', pow: 22, acc: 0.95, effect: 'buff_atk_self', element: 'fairy', desc: 'who と which で文をつなぐ' },
      { name: 'せんこうしクラッシュ', type: 'heavy', pow: 50, acc: 0.74, element: 'fairy', desc: '先行詞をまるごと巻きこむ' },
      { name: 'ザット省略', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'fairy', desc: 'that を消して相手をまどわす' }
    ], desc: '2つの文を関係代名詞でつなぐ達人。話が長くなりすぎて、結局主語がどれか分からなくなる。' });

  // ---- 理科ライン（1159→1160→1161）----
  add({ id: 1159, name: 'イオンぼうや', sprite: '🪐', hp: 194, atk: 48, def: 46, spd: 52, buff: 'guard', elementType: 'water', stage: 1, gacha: false, evoLevel: 24, nextId: 1160,
    skills: [
      { name: 'プラマイビリビリ', type: 'normal', pow: 14, acc: 0.96, element: 'water', desc: '＋と−の電気でしびれさせる' },
      { name: 'ちゅうわバリア', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'water', desc: '酸とアルカリを打ち消して守る' },
      { name: 'でんかいドレイン', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'water', desc: '電流を流して相手を弱らせる' }
    ], desc: '電子を1個もらったり失ったりで、気分がプラスになったりマイナスになったりする。' });
  add({ id: 1160, name: 'エネルギー博士', sprite: '🌌', hp: 336, atk: 88, def: 62, spd: 80, buff: 'attack', elementType: 'water', stage: 2, gacha: false, evoLevel: 46, nextId: 1161,
    skills: [
      { name: 'いちエネこうげき', type: 'normal', pow: 18, acc: 0.96, element: 'water', desc: '高い所から位置エネルギーで落とす' },
      { name: 'うんどうエネラッシュ', type: 'heavy', pow: 42, acc: 0.76, element: 'water', desc: '速さをのせて連続で当てる' },
      { name: 'エネルギー保存', type: 'unique', pow: 0, acc: 1.0, effect: 'heal_self', element: 'water', desc: '力学的エネルギーを保ってHP回復' }
    ], desc: '位置エネルギーと運動エネルギーの合計はいつも一定、が信条。ジェットコースターが大好き。' });
  add({ id: 1161, name: 'ウチュウ大帝', sprite: '🌠', hp: 546, atk: 122, def: 92, spd: 96, buff: 'lucky', elementType: 'water', stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: 'こうせいフレア', type: 'normal', pow: 22, acc: 0.95, effect: 'buff_atk_self', element: 'water', desc: '自ら光る恒星の力で攻撃' },
      { name: '日周運動クラッシュ', type: 'heavy', pow: 50, acc: 0.74, element: 'water', desc: '天を一周する勢いで叩く' },
      { name: '金星のみちかけ', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'water', desc: '見かけの大きさを変えて幻惑' }
    ], desc: '恒星・惑星・衛星のちがいを熱く語る大帝。ただし真夜中には金星の話ができず、そわそわする。' });

  // ---- 社会ライン（1162→1163→1164）----
  add({ id: 1162, name: 'イシンこぞう', sprite: '🗳️', hp: 196, atk: 46, def: 46, spd: 54, buff: 'guard', elementType: 'ground', stage: 1, gacha: false, evoLevel: 24, nextId: 1163,
    skills: [
      { name: 'はいはんちけん', type: 'normal', pow: 14, acc: 0.96, element: 'ground', desc: '藩をなくし県にして攻める' },
      { name: 'ごかじょうのごせいもん', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_atk_self', element: 'ground', desc: '新しい方針で気合いを入れる' },
      { name: 'ちそかいせいガード', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'ground', desc: '税のしくみを整えて守る' }
    ], desc: '「ご一新！」が口ぐせ。古いやり方を見つけると、すぐ新しくしたくなる。' });
  add({ id: 1163, name: 'ケンポウ奉行', sprite: '💴', hp: 334, atk: 84, def: 66, spd: 80, buff: 'attack', elementType: 'ground', stage: 2, gacha: false, evoLevel: 46, nextId: 1164,
    skills: [
      { name: 'じんけんチョップ', type: 'normal', pow: 18, acc: 0.96, element: 'ground', desc: '基本的人権をふりかざす一撃' },
      { name: 'さんけんぶんりつ', type: 'heavy', pow: 42, acc: 0.76, element: 'ground', desc: '力を三つに分けて連続で抑える' },
      { name: 'へいわしゅぎバリア', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'ground', desc: '第9条の理念で身を守る' }
    ], desc: '「国民主権・基本的人権・平和主義！」と三大原則を暗唱する奉行。条文の番号にもくわしい。' });
  add({ id: 1164, name: 'レキシ大魔王ケイザイ', sprite: '🏦', hp: 546, atk: 122, def: 92, spd: 94, buff: 'lucky', elementType: 'ground', stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: 'じゅようきょうきゅう', type: 'normal', pow: 22, acc: 0.95, effect: 'buff_atk_self', element: 'ground', desc: '需要と供給のバランスで攻める' },
      { name: 'インフレクラッシュ', type: 'heavy', pow: 50, acc: 0.74, element: 'ground', desc: '物価を一気に押し上げる大技' },
      { name: 'きんゆうせいさく', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'ground', desc: '世の中のお金を調整して相手を弱らせる' }
    ], desc: '明治から現代まで、政治も経済もぜんぶ見てきた大魔王。日本銀行のしくみを語り出すと止まらない。' });

  // ---- 国語ライン（1165→1166→1167）----
  add({ id: 1165, name: 'ヨミがな小僧', sprite: '✒️', hp: 188, atk: 48, def: 44, spd: 56, buff: 'speed', elementType: 'psychic', stage: 1, gacha: false, evoLevel: 24, nextId: 1166,
    skills: [
      { name: 'おんくんスラッシュ', type: 'normal', pow: 14, acc: 0.96, element: 'psychic', desc: '音読み訓読みを使い分けて斬る' },
      { name: 'なんどくよみ', type: 'unique', pow: 0, acc: 0.9, effect: 'debuff_enemy', element: 'psychic', desc: '読めない漢字で相手をまどわす' },
      { name: 'とめはねガード', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'psychic', desc: 'きれいに書いて防御を上げる' }
    ], desc: '難しい漢字の読みを次々に当てる小僧。ただし自分の名前だけは、いつも読み方をまちがえる。' });
  add({ id: 1166, name: 'ジュクゴ番長', sprite: '🖍️', hp: 330, atk: 86, def: 62, spd: 78, buff: 'attack', elementType: 'psychic', stage: 2, gacha: false, evoLevel: 46, nextId: 1167,
    skills: [
      { name: 'るいぎたいぎ打ち', type: 'normal', pow: 18, acc: 0.96, element: 'psychic', desc: '似た意味・反対の意味で切り返す' },
      { name: 'こうせいクラッシュ', type: 'heavy', pow: 42, acc: 0.76, element: 'psychic', desc: '熟語の組み立てを見ぬいて連打' },
      { name: 'どうおんいぎガード', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_def_self', element: 'psychic', desc: '同音異義語で守りをかためる' }
    ], desc: '二字熟語の組み立てを一瞬で見ぬく番長。会話でもつい「今のは修飾の関係な」と解説してしまう。' });
  add({ id: 1167, name: 'コジ大魔王セイゴ', sprite: '🎋', hp: 542, atk: 122, def: 90, spd: 94, buff: 'lucky', elementType: 'psychic', stage: 3, gacha: false, evoLevel: null, nextId: null,
    skills: [
      { name: 'がりょうてんせい', type: 'normal', pow: 22, acc: 0.95, effect: 'buff_atk_self', element: 'psychic', desc: '最後の仕上げの一撃で決める' },
      { name: 'がしんしょうたん', type: 'heavy', pow: 50, acc: 0.74, element: 'psychic', desc: '苦労にたえた執念の大技' },
      { name: 'たざんのいし', type: 'unique', pow: 0, acc: 1.0, effect: 'heal_self', element: 'psychic', desc: '他人の失敗を学びに変えて回復' }
    ], desc: '故事成語をすべて由来つきで語れる大魔王。話が長く、家来はいつも「画竜点睛」まで聞く前に眠る。' });

  G9.addWild({
    // 数学
    'm9-tenkai':   { 1: [1153], 2: [1153, 1154], 3: [1154, 1155] },
    'm9-heihokon': { 1: [1153], 2: [1154], 3: [1155] },
    'm9-niji':     { 1: [1153], 2: [1154], 3: [1154, 1155] },
    'm9-nijikansu':{ 1: [1153], 2: [1154], 3: [1155] },
    'm9-soji':     { 1: [1153], 2: [1153, 1154], 3: [1155] },
    'm9-enshu':    { 1: [1153], 2: [1154], 3: [1155] },
    'm9-sanpei':   { 1: [1153], 2: [1154], 3: [1154, 1155] },
    'm9-hyohon':   { 1: [1153], 2: [1154], 3: [1155] },
    // 英語
    'e9-passive':  { 1: [1156], 2: [1156, 1157], 3: [1157, 1158] },
    'e9-perfect':  { 1: [1156], 2: [1157], 3: [1158] },
    'e9-toinf':    { 1: [1156], 2: [1157], 3: [1157, 1158] },
    'e9-bunshi':   { 1: [1156], 2: [1157], 3: [1158] },
    'e9-kankei':   { 1: [1156], 2: [1157], 3: [1158] },
    'e9-kansetsu': { 1: [1156], 2: [1157], 3: [1157, 1158] },
    // 理科
    'r9-undou':    { 1: [1159], 2: [1159, 1160], 3: [1160, 1161] },
    'r9-ion':      { 1: [1159], 2: [1160], 3: [1161] },
    'r9-seimei':   { 1: [1159], 2: [1160], 3: [1160, 1161] },
    'r9-uchu':     { 1: [1159], 2: [1160], 3: [1161] },
    // 社会
    's9-history':  { 1: [1162], 2: [1162, 1163], 3: [1163, 1164] },
    's9-kenpo':    { 1: [1162], 2: [1163], 3: [1164] },
    's9-seiji':    { 1: [1162], 2: [1163], 3: [1163, 1164] },
    's9-keizai':   { 1: [1162], 2: [1163], 3: [1164] },
    // 国語
    'j9-yomi':     { 1: [1165], 2: [1165, 1166], 3: [1166, 1167] },
    'j9-kaki':     { 1: [1165], 2: [1166], 3: [1167] },
    'j9-goi':      { 1: [1165], 2: [1166], 3: [1166, 1167] },
    'j9-kanyou':   { 1: [1165], 2: [1166], 3: [1167] }
  });
})();
