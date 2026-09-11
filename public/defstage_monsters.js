/* DEFSTAGE_CHARS_V1 : 防衛戦ステージ初クリアの げんていキャラ（4体）
   ------------------------------------------------------------------
   - クラスで ステージ 3 / 5 / 7 / 10 を はじめて クリアしたとき、
     そのクラスに在籍している全員に 1体ずつ 配られる。
     配るのはサーバ（defense_stage_rewards 台帳）。このファイルは
     「名前・すがた・つよさ」を MONSTERS に足すだけで、配布には関わらない。
   - ID は 1601 / 1602 / 1604 / 1605。
     どれも public/index.html と src/index.tsx に一度も出てこないことを
     確かめてから決めた（1603 は社会の問題文「1603年」で使われているので避けた）。
   - すでに同じ ID がいたら push しない。getMonster() は先勝ちなので、
     だまって捨てられていることに気づけないのを防ぐためのガード。
   - public/index.html は手で編集しない。このファイルは </body> の直前で読み込まれる。
   - 何体入ったかは window.__DEFSTAGE_CHARS_V1 で確認できる。
*/
(function () {
  try {
    if (!window.MONSTERS || !Array.prototype.some) return;

    var defs = [
      {
        id: 1601, name: 'タテマモル', sprite: '🛡️',
        hp: 300, atk: 70, def: 135, spd: 55,
        buff: 'guard', elementType: 'steel',
        stage: 1, gacha: false, nextId: null, evoLevel: null,
        rarity: 5, cannot_trade_special: true,
        desc: 'クラスのきちの門に、だれに たのまれたわけでもなく 立っている たての せいれい。だれかを かばうたびに 体が かたくなる。じつは たての うらがわに、まもった人の 名前を こっそり ぜんぶ きざんでいる。【防衛戦 ステージ3 クリア げんてい】',
        skills: [
          { name: 'たてうち', type: 'normal', pow: 26, acc: 0.95, element: 'steel', desc: 'たてごと 体ごと ぶつかる。いたくないのか 聞いてはいけない。' },
          { name: 'シールドバッシュ', type: 'heavy', pow: 52, acc: 0.80, element: 'steel', desc: 'たてのふちで 思いきり なぐる。音が ろうかまで ひびく。' },
          { name: 'ぜんいん うしろへ', type: 'unique', pow: 0, acc: 1.0, effect: 'shield', element: 'steel', desc: 'みんなの前に 出て かべになる。こう見えて 声は 小さい。' }
        ]
      },
      {
        id: 1602, name: 'ハンゲキナイト', sprite: '⚔️',
        hp: 340, atk: 120, def: 110, spd: 95,
        buff: 'attack', elementType: 'fighting',
        stage: 1, gacha: false, nextId: null, evoLevel: null,
        rarity: 6, cannot_trade_special: true,
        desc: 'きちを こわそうとした ものには かならず やりかえす、と ちかった きし。まもりが かたいほど つぎの 一げきが 重くなる。ねる前に よろいを みがくのが 日課で、みがきすぎて たまに まぶしい。【防衛戦 ステージ5 クリア げんてい】',
        skills: [
          { name: 'せいぎのつるぎ', type: 'normal', pow: 32, acc: 0.95, element: 'fighting', desc: 'まっすぐ ふりおろす。まよいが ない。' },
          { name: 'ちかいのいちげき', type: 'heavy', pow: 62, acc: 0.78, element: 'fighting', desc: 'まもると ちかった 相手の 顔を 思いうかべて はなつ。' },
          { name: 'カウンターブレード', type: 'unique', pow: 0, acc: 0.90, effect: 'counter', element: 'fighting', desc: 'うけた こうげきを そのまま おかえしする。おつりは 出ない。' }
        ]
      },
      {
        id: 1604, name: 'ライガード', sprite: '⚡',
        hp: 360, atk: 130, def: 105, spd: 145,
        buff: 'speed', elementType: 'electric',
        stage: 1, gacha: false, nextId: null, evoLevel: null,
        rarity: 6, cannot_trade_special: true,
        desc: 'きちの まわりに かみなりの かきねを はりめぐらす まもりがみ。てきが 近づくより 先に 動けるほど すばやい。ただし はやすぎて、よく じぶんの かみなりに おいついて ビリッとしている。【防衛戦 ステージ7 クリア げんてい】',
        skills: [
          { name: 'スパークダッシュ', type: 'normal', pow: 34, acc: 0.95, element: 'electric', desc: '光る線に なって つっこむ。見えたときには もう もどっている。' },
          { name: 'サンダーブレイク', type: 'heavy', pow: 66, acc: 0.76, element: 'electric', desc: '空から 一本 落とす。ねらいを つけるのに 少し かかる。' },
          { name: 'かみなりのかきね', type: 'unique', pow: 0, acc: 0.95, effect: 'shield', element: 'electric', desc: 'きちの まわりを 電気の かきねで かこむ。さわると ビリッ。' }
        ]
      },
      {
        id: 1605, name: 'ガーディオン', sprite: '🐲',
        hp: 520, atk: 150, def: 140, spd: 115,
        buff: 'all', elementType: 'steel',
        stage: 1, gacha: false, nextId: null, evoLevel: null,
        rarity: 7, cannot_trade_special: true,
        desc: '10このステージを ぜんぶ まもりぬいた クラスにだけ すがたを見せる でんせつの まもり竜。せなかの とりでには、これまで まもってきた みんなの 思い出が しまってある。よばれると すぐ 来るが、とちゅうで 一回だけ ふりかえって ポーズを きめる。【防衛戦 ステージ10 クリア げんてい】',
        skills: [
          { name: 'ガーディアンブレス', type: 'normal', pow: 40, acc: 0.95, element: 'dragon', desc: 'まもるための いぶき。あたたかいが、あたると とても いたい。' },
          { name: 'じゅうそうほうげき', type: 'heavy', pow: 76, acc: 0.75, element: 'dragon', desc: 'せなかの とりでが ひらいて 一せいに うつ。地面が ゆれる。' },
          { name: 'クラスのきずな', type: 'unique', pow: 0, acc: 1.0, effect: 'reflect', element: 'fairy', desc: 'みんなの 思い出で かべを つくり、うけた ぶんを はねかえす。' }
        ]
      }
    ];

    var added = [];
    var skipped = [];
    for (var i = 0; i < defs.length; i++) {
      var d = defs[i];
      var dup = window.MONSTERS.some(function (m) { return m && m.id === d.id; });
      if (dup) { skipped.push(d.id); continue; }
      window.MONSTERS.push(d);
      added.push(d.id);
    }
    window.__DEFSTAGE_CHARS_V1 = { added: added, skipped: skipped, total: window.MONSTERS.length };
    if (skipped.length) { try { console.warn('[DEFSTAGE_CHARS_V1] ID が すでに使われていて 追加できなかった:', skipped); } catch (e) {} }
  } catch (e) {
    try { console.warn('[DEFSTAGE_CHARS_V1] 失敗', e); } catch (e2) {}
  }
})();
