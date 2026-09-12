/* DEFBOSS_V1 : 防衛戦ステージ 12 / 15 / 18 / 21 のボス（4体）
   ------------------------------------------------------------------
   - クラスで ステージ 12 / 15 / 18 / 21 を はじめて クリアしたとき、
     そのクラスに在籍している全員に 1体ずつ 配られる。
     配るのはサーバ（defense_stage_rewards 台帳）。このファイルは
     「名前・すがた・つよさ」を MONSTERS に足すだけで、配布には関わらない。
   - ID は 1611 / 1612 / 1613 / 1614。
     どれも public/index.html・src/index.tsx・public/defstage_monsters.js に
     一度も出てこないこと、本番の window.MONSTERS にも いないことを
     確かめてから決めた（世界編が つかう予定の 2101〜 / 2111〜 は避けた）。
   - すでに同じ ID がいたら push しない。getMonster() は先勝ちなので、
     だまって捨てられていることに気づけないのを防ぐためのガード。
   - public/index.html は手で編集しない。このファイルは </body> の直前で読み込まれる。
   - 何体入ったかは window.__DEFBOSS_V1 で確認できる。
   - ステージ 3 / 5 / 7 / 10 の「守り手」4体（1601 / 1602 / 1604 / 1605）と
     対になる「攻め手」。1605 ガーディオンと同じく いちばん上は buff: 'all'。
*/
(function () {
  try {
    if (!window.MONSTERS || !Array.prototype.some) return;
    var DEFS = [
      {
        id: 1611, name: 'モンヤブリ', sprite: '🪓',
        hp: 380, atk: 145, def: 95, spd: 70,
        buff: 'attack', elementType: 'rock',
        stage: 1, gacha: false, nextId: null, evoLevel: null,
        rarity: 5, cannot_trade_special: true,
        desc: 'きちの 門だけを ねらって、何百年も たたきつづけてきた おに。一げきが とても 重く、門の まえに 立たれると ひやりとする。ただし 門を こわしたあとは、かならず「入って いい?」と きいてくる。',
        skills: [
          { name: 'かどうち', type: 'normal', pow: 30, acc: 0.95, element: 'rock', desc: '門の かどを ねらって たたく。そこが いちばん もろい。' },
          { name: 'もんやぶり', type: 'heavy', pow: 66, acc: 0.74, element: 'rock', desc: 'ありったけの 体重を のせた 一げき。音が 校庭まで ひびく。' },
          { name: 'いいですか', type: 'unique', pow: 0, acc: 1.0, effect: 'debuff_def', element: 'rock', desc: 'まもりを くずしてから きいてくる。順番が ぎゃく。' }
        ]
      },
      {
        id: 1612, name: 'カゲハヤテ', sprite: '🌪️',
        hp: 340, atk: 135, def: 90, spd: 165,
        buff: 'speed', elementType: 'dark',
        stage: 1, gacha: false, nextId: null, evoLevel: null,
        rarity: 6, cannot_trade_special: true,
        desc: '3つの 道を 同時に かけぬける、と うわさされる 影の つかい手。じっさいは ただ ものすごく 速いだけ。じぶんの ざんぞうに 話しかけて、へんじが ないと すこし さみしい。',
        skills: [
          { name: 'かげばしり', type: 'normal', pow: 28, acc: 0.97, element: 'dark', desc: '見えたときには もう よこに いる。' },
          { name: 'みっつのみち', type: 'heavy', pow: 60, acc: 0.78, element: 'dark', desc: '3本の 道を まとめて かけぬけた、ように 見える。' },
          { name: 'ざんぞうとはなす', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_speed', element: 'dark', desc: 'じぶんの かげに 話しかけて さらに 速くなる。へんじは ない。' }
        ]
      },
      {
        id: 1613, name: 'イワヨロイ', sprite: '🗿',
        hp: 560, atk: 120, def: 175, spd: 50,
        buff: 'guard', elementType: 'rock',
        stage: 1, gacha: false, nextId: null, evoLevel: null,
        rarity: 6, cannot_trade_special: true,
        desc: '山を そのまま きて 歩いてくる 巨人。たいていの こうげきは、あたっても ぽろりと おちる。かたすぎて こまかい ものが つかめず、ねこじゃらしを 一本だけ そっと もっている。',
        skills: [
          { name: 'いわおとし', type: 'normal', pow: 26, acc: 0.95, element: 'rock', desc: '体の かけらが 落ちる。それでも いたい。' },
          { name: 'やまなり', type: 'heavy', pow: 70, acc: 0.70, element: 'rock', desc: '山ごと ふみこむ。じめんが 少し ずれる。' },
          { name: 'ねこじゃらし', type: 'unique', pow: 0, acc: 1.0, effect: 'shield', element: 'rock', desc: '一本だけ そっと もつ。まわりが やさしい 気もちに なる。' }
        ]
      },
      {
        id: 1614, name: 'ヨルオウガ', sprite: '🌑',
        hp: 600, atk: 165, def: 145, spd: 125,
        buff: 'all', elementType: 'dark',
        stage: 1, gacha: false, nextId: null, evoLevel: null,
        rarity: 7, cannot_trade_special: true,
        desc: 'まよなかの あいだだけ 国を おさめる という 王。きちの まえに 立つと、まわりの あかりが ゆっくり 消えていく。ほんとうは 朝が いちばん すきで、まける前に 一回だけ 日の出の 話を する。',
        skills: [
          { name: 'よいのいちげき', type: 'normal', pow: 38, acc: 0.95, element: 'dark', desc: 'くらくなった ほうから とんでくる。' },
          { name: 'まよなかのごうれい', type: 'heavy', pow: 78, acc: 0.72, element: 'dark', desc: '国ぜんぶに とどく 声。ききたくなくても きこえる。' },
          { name: 'ひのでのはなし', type: 'unique', pow: 0, acc: 1.0, effect: 'buff_all', element: 'fairy', desc: 'まける前に 一回だけ する。ほんとうは 朝が すきらしい。' }
        ]
      }
    ];
    var added = [];
    var skipped = [];
    for (var i = 0; i < DEFS.length; i++) {
      var d = DEFS[i];
      var dup = window.MONSTERS.some(function (m) { return m && Number(m.id) === Number(d.id); });
      if (dup) { skipped.push(d.id); continue; }
      window.MONSTERS.push(d);
      added.push(d.id);
    }
    window.__DEFBOSS_V1 = { added: added, skipped: skipped, total: window.MONSTERS.length };
    if (skipped.length) {
      try { console.warn('[DEFBOSS_V1] ID が すでに使われていて 追加できなかった:', skipped); } catch (e) {}
    }
  } catch (e) {
    try { console.warn('[DEFBOSS_V1] 失敗', e); } catch (e2) {}
  }
})();
