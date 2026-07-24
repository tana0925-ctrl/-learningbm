/* ============================================================
   中2英語 単元パック v174（ネットレ対応 第5弾）
   過去形・過去進行形 / 未来表現 / 助動詞 / 不定詞 / 動名詞 / 比較 / 接続詞・There is
   基礎40%・標準40%・発展20%の混合ランダム出題（4択）
   ============================================================ */
(function () {
  var G8 = window.G8; if (!G8) return;
  var R = G8.R, pick = G8.pick, Q = G8.q;

  // ---------------- be動詞の過去・過去進行形 ----------------
  var _PASTV = [
    ['play', 'played', ['plaied', 'playd', 'playied']],
    ['study', 'studied', ['studyed', 'studys', 'studdied']],
    ['stop', 'stopped', ['stoped', 'stopd', 'stopping']],
    ['live', 'lived', ['livd', 'liveed', 'liveing']],
    ['visit', 'visited', ['visitted', 'visitd', 'visits']],
    ['carry', 'carried', ['carryed', 'carrys', 'carriedd']]
  ];
  var _IRREG = [
    ['go', 'went', ['goed', 'gone', 'goes']],
    ['see', 'saw', ['seed', 'seen', 'sees']],
    ['eat', 'ate', ['eated', 'eaten', 'eats']],
    ['get', 'got', ['getted', 'gotted', 'gets']],
    ['write', 'wrote', ['writed', 'written', 'writes']],
    ['take', 'took', ['taked', 'taken', 'takes']],
    ['come', 'came', ['comed', 'come', 'comes']],
    ['buy', 'bought', ['buyed', 'boughted', 'buys']],
    ['make', 'made', ['maked', 'maden', 'makes']],
    ['have', 'had', ['haved', 'hadden', 'has']]
  ];
  var _ING = [
    ['run', 'running', ['runing', 'runnning', 'runed']],
    ['swim', 'swimming', ['swiming', 'swimmming', 'swimed']],
    ['write', 'writing', ['writeing', 'writting', 'writed']],
    ['make', 'making', ['makeing', 'makking', 'maked']],
    ['study', 'studying', ['studing', 'studyeing', 'studiing']],
    ['sit', 'sitting', ['siting', 'sittting', 'sited']]
  ];

  function genPastBe8() {
    var r = R(1, 10), t, v;
    if (r <= 4) { // 基礎
      t = R(0, 3);
      if (t === 0) { v = pick(_PASTV); return Q('基礎', '「' + v[0] + '」の過去形はどれ？', v[1], v[2]); }
      if (t === 1) { v = pick(_IRREG); return Q('基礎', '「' + v[0] + '」の過去形はどれ？（不規則動詞）', v[1], v[2]); }
      if (t === 2) {
        var s = pick([['I', 'was'], ['He', 'was'], ['She', 'was'], ['It', 'was'], ['You', 'were'], ['We', 'were'], ['They', 'were'], ['Ken and Tom', 'were']]);
        return Q('基礎', '（　）に入る語はどれ？\n' + s[0] + ' （　） busy yesterday.', s[1], [(s[1] === 'was' ? 'were' : 'was'), 'am', 'is']);
      }
      v = pick(_ING);
      return Q('基礎', '「' + v[0] + '」に ing をつけた形はどれ？', v[1], v[2]);
    }
    if (r <= 8) { // 標準
      t = R(0, 3);
      if (t === 0) return Q('標準', '「わたしは昨日サッカーをしました。」を英語にすると？',
        'I played soccer yesterday.', ['I play soccer yesterday.', 'I was play soccer yesterday.', 'I am played soccer yesterday.']);
      if (t === 1) return Q('標準', '「彼は昨日テレビを見ませんでした。」\nHe （　） watch TV yesterday.',
        "didn't", ["doesn't", "wasn't", "isn't"]);
      if (t === 2) return Q('標準', '（　）に入る語はどれ？（過去の疑問文）\n（　） you go to the park last Sunday?',
        'Did', ['Do', 'Were', 'Was']);
      return Q('標準', '「わたしはそのとき本を読んでいました。」を英語にすると？',
        'I was reading a book then.', ['I am reading a book then.', 'I read a book then.', 'I was read a book then.']);
    }
    // 発展
    t = R(0, 3);
    if (t === 0) return Q('発展', 'Did you play tennis yesterday? に「はい」と答えるときは？',
      'Yes, I did.', ['Yes, I was.', 'Yes, I do.', 'Yes, I played.']);
    if (t === 1) return Q('発展', '過去進行形の否定文はどれ？',
      'She was not cooking then.', ["She didn't cooking then.", 'She was not cooked then.', "She doesn't cooking then."]);
    if (t === 2) return Q('発展', '「彼らはそのとき何をしていましたか。」を英語にすると？',
      'What were they doing then?', ['What did they doing then?', 'What were they do then?', 'What they were doing then?']);
    return Q('発展', '過去進行形が表すのはどんな意味？',
      '過去のあるときに進行中だった動作', ['過去に何度もくり返した習慣', 'これからする予定', '今の状態']);
  }

  // ---------------- 未来表現 ----------------
  function genFuture8() {
    var r = R(1, 10), t;
    if (r <= 4) { // 基礎
      t = R(0, 3);
      if (t === 0) return Q('基礎', 'will のあとに続く動詞の形は？',
        '原形', ['過去形', 'ing形', '三単現のs がついた形']);
      if (t === 1) return Q('基礎', '「わたしは明日彼に会うつもりです。」\nI （　） meet him tomorrow.',
        'will', ['willed', 'am will', 'wills']);
      if (t === 2) return Q('基礎', '「be going to」のあとに続く動詞の形は？',
        '原形', ['ing形', '過去形', 'to + 過去形']);
      return Q('基礎', '「I will」の短縮形はどれ？', "I'll", ["I'will", "Ill", "I'l"]);
    }
    if (r <= 8) { // 標準
      t = R(0, 3);
      if (t === 0) return Q('標準', '「彼女は明日、京都を訪れる予定です。」を英語にすると？',
        'She is going to visit Kyoto tomorrow.',
        ['She is going to visits Kyoto tomorrow.', 'She is going visit Kyoto tomorrow.', 'She will going to visit Kyoto tomorrow.']);
      if (t === 1) return Q('標準', 'will の否定文で使う短縮形はどれ？',
        "won't", ["willn't", "will'nt", "don't will"]);
      if (t === 2) return Q('標準', '（　）に入る語はどれ？\n（　） you help me tomorrow?',
        'Will', ['Do', 'Are', 'Did']);
      return Q('標準', '「明日は雨が降るでしょう。」を英語にすると？',
        'It will be rainy tomorrow.', ['It will rainy tomorrow.', 'It will is rainy tomorrow.', 'It is will rainy tomorrow.']);
    }
    // 発展
    t = R(0, 3);
    if (t === 0) return Q('発展', 'Will you open the window? はどんな意味で使われる？',
      '窓を開けてくれませんか（依頼）', ['窓を開けましたか（過去の質問）', '窓を開けてはいけません（禁止）', '窓は開いています（説明）']);
    if (t === 1) return Q('発展', 'Are you going to study tonight? に「いいえ」と答えるときは？',
      "No, I'm not.", ['No, I don\'t.', "No, I won't going.", 'No, I didn\'t.']);
    if (t === 2) return Q('発展', '前から決めていた予定を表すときによく使う表現はどちら？',
      'be going to', ['will', 'was going', 'used to']);
    return Q('発展', '「彼は来週、東京に行かないでしょう。」を英語にすると？',
      "He won't go to Tokyo next week.", ["He doesn't go to Tokyo next week.", "He won't goes to Tokyo next week.", "He isn't go to Tokyo next week."]);
  }

  // ---------------- 助動詞 ----------------
  function genModal8() {
    var r = R(1, 10), t;
    if (r <= 4) { // 基礎
      t = R(0, 3);
      if (t === 0) return Q('基礎', 'must の意味はどれ？',
        '〜しなければならない', ['〜してもよい', '〜できる', '〜したい']);
      if (t === 1) return Q('基礎', 'may の意味として正しいのはどれ？',
        '〜してもよい', ['〜しなければならない', '〜すべきでない', '〜したことがある']);
      if (t === 2) return Q('基礎', 'should の意味はどれ？',
        '〜すべきだ', ['〜してはいけない', '〜できる', '〜だろう']);
      return Q('基礎', '助動詞のあとに続く動詞の形は？',
        '原形', ['ing形', '過去形', 'to + 原形']);
    }
    if (r <= 8) { // 標準
      t = R(0, 3);
      if (t === 0) return Q('標準', '「あなたは早く起きなければなりません。」\nYou （　） get up early.',
        'must', ['must to', 'musts', 'are must']);
      if (t === 1) return Q('標準', 'must とほぼ同じ意味を表す表現はどれ？',
        'have to', ['be able to', 'be going to', 'used to']);
      if (t === 2) return Q('標準', '「彼は英語を話さなければなりません。」\nHe （　） speak English.',
        'has to', ['have to', 'has', 'is have to']);
      return Q('標準', 'can とほぼ同じ意味を表す表現はどれ？',
        'be able to', ['have to', 'be going to', 'would like to']);
    }
    // 発展
    t = R(0, 3);
    if (t === 0) return Q('発展', 'must not はどんな意味？',
      '〜してはいけない（禁止）', ['〜しなくてよい', '〜しなければならない', '〜かもしれない']);
    if (t === 1) return Q('発展', "don't have to はどんな意味？",
      '〜しなくてよい（不必要）', ['〜してはいけない', '〜しなければならない', '〜できない']);
    if (t === 2) return Q('発展', '「窓を開けてもいいですか。」をていねいにたずねると？',
      'May I open the window?', ['May you open the window?', 'Do I may open the window?', 'I may open the window?']);
    return Q('発展', '「あなたはもっと野菜を食べるべきです。」を英語にすると？',
      'You should eat more vegetables.', ['You should to eat more vegetables.', 'You shoulds eat more vegetables.', 'You are should eat more vegetables.']);
  }

  // ---------------- 不定詞 ----------------
  function genToInf8() {
    var r = R(1, 10), t;
    if (r <= 4) { // 基礎
      t = R(0, 3);
      if (t === 0) return Q('基礎', '不定詞の形はどれ？',
        'to + 動詞の原形', ['to + 動詞のing形', 'to + 動詞の過去形', '動詞の原形だけ']);
      if (t === 1) return Q('基礎', '「わたしはサッカーをすることが好きです。」\nI like （　） soccer.',
        'to play', ['to played', 'to playing', 'play to']);
      if (t === 2) return Q('基礎', 'I want to be a teacher. の意味はどれ？',
        'わたしは先生になりたい。', ['わたしは先生です。', 'わたしは先生になりました。', 'わたしは先生に会いたい。']);
      return Q('基礎', '「読むための本」を英語にすると？',
        'a book to read', ['a book read', 'a book reading to', 'to read a book']);
    }
    if (r <= 8) { // 標準
      t = R(0, 3);
      if (t === 0) return Q('標準', '「わたしは英語を勉強するために早く起きました。」\nI got up early （　） study English.',
        'to', ['for', 'of', 'that']);
      if (t === 1) return Q('標準', 'I have a lot of homework to do. の to do のはたらきは？',
        '名詞をうしろから説明する（形容詞的用法）', ['「〜するために」（副詞的用法）', '「〜すること」（名詞的用法）', '過去を表す']);
      if (t === 2) return Q('標準', 'He came here to see you. の to see のはたらきは？',
        '「〜するために」（副詞的用法）', ['「〜すること」（名詞的用法）', '名詞を説明する（形容詞的用法）', '進行中の動作を表す']);
      return Q('標準', 'To read books is fun. の To read のはたらきは？',
        '「〜すること」（名詞的用法）', ['「〜するために」（副詞的用法）', '名詞を説明する（形容詞的用法）', '命令を表す']);
    }
    // 発展
    t = R(0, 3);
    if (t === 0) return Q('発展', '「英語を話すことは楽しい。」を It で始めて英語にすると？',
      'It is fun to speak English.', ['It is fun speak English.', 'It is fun speaking to English.', 'It is to speak fun English.']);
    if (t === 1) return Q('発展', '「わたしは飲み物が欲しい（何か飲むもの）。」を英語にすると？',
      'I want something to drink.', ['I want something drink.', 'I want to something drink.', 'I want drinking something.']);
    if (t === 2) return Q('発展', 'I was glad to hear the news. の to hear のはたらきは？',
      '感情の原因を表す（副詞的用法）', ['名詞を説明する（形容詞的用法）', '「〜すること」（名詞的用法）', '未来を表す']);
    return Q('発展', '「彼女はテニスをするために公園へ行きました。」を英語にすると？',
      'She went to the park to play tennis.', ['She went to the park for play tennis.', 'She went to the park to playing tennis.', 'She went to play the park tennis.']);
  }

  // ---------------- 動名詞 ----------------
  function genGerund8() {
    var r = R(1, 10), t;
    if (r <= 4) { // 基礎
      t = R(0, 3);
      if (t === 0) return Q('基礎', '動名詞の形はどれ？',
        '動詞のing形', ['動詞の原形', 'to + 動詞の原形', '動詞の過去形']);
      if (t === 1) return Q('基礎', '動名詞はどんな意味を表す？',
        '〜すること', ['〜するために', '〜されている', '〜しなければならない']);
      if (t === 2) return Q('基礎', '「わたしは泳ぐことが好きです。」\nI like （　）.',
        'swimming', ['swim', 'to swimming', 'swimed']);
      return Q('基礎', 'Playing the piano is fun. の Playing のはたらきは？',
        '主語（〜することは）', ['動詞', '目的語（〜することを）', '形容詞']);
    }
    if (r <= 8) { // 標準
      t = R(0, 3);
      if (t === 0) return Q('標準', 'enjoy のあとに続く形はどれ？',
        'ing形（動名詞）', ['to + 原形', '原形だけ', '過去形']);
      if (t === 1) return Q('標準', '「彼は読書を楽しみました。」を英語にすると？',
        'He enjoyed reading.', ['He enjoyed to read.', 'He enjoyed read.', 'He was enjoy reading.']);
      if (t === 2) return Q('標準', '前置詞のあとに動詞を続けるときの形は？',
        'ing形（動名詞）', ['原形', 'to + 原形', '過去形']);
      return Q('標準', '「サッカーをすることは楽しい。」を動名詞で始めて英語にすると？',
        'Playing soccer is fun.', ['Play soccer is fun.', 'To playing soccer is fun.', 'Played soccer is fun.']);
    }
    // 発展
    t = R(0, 3);
    if (t === 0) return Q('発展', 'stop のあとに動名詞が続くとどんな意味になる？',
      '〜するのをやめる', ['〜するために立ち止まる', '〜し始める', '〜し続ける']);
    if (t === 1) return Q('発展', '「彼女は音楽を聞くのが得意です。」\nShe is good at （　） to music.',
      'listening', ['listen', 'to listen', 'listened']);
    if (t === 2) return Q('発展', '不定詞と動名詞の両方を目的語にできる動詞はどれ？',
      'like', ['enjoy', 'finish', 'want']);
    return Q('発展', '「わたしは宿題を終えました。」\nI finished （　） my homework.',
      'doing', ['to do', 'do', 'did']);
  }

  // ---------------- 比較 ----------------
  var _CMP = [
    ['tall', 'taller', 'tallest'],
    ['old', 'older', 'oldest'],
    ['long', 'longer', 'longest'],
    ['fast', 'faster', 'fastest'],
    ['small', 'smaller', 'smallest'],
    ['young', 'younger', 'youngest']
  ];
  function genCompare8() {
    var r = R(1, 10), t, c;
    if (r <= 4) { // 基礎
      t = R(0, 3);
      c = pick(_CMP);
      if (t === 0) return Q('基礎', '「' + c[0] + '」の比較級はどれ？', c[1], [c[0] + 'est', 'more ' + c[0], c[0] + 'ier']);
      if (t === 1) return Q('基礎', '「' + c[0] + '」の最上級はどれ？', c[2], [c[1], 'most ' + c[0], c[0] + 'iest']);
      if (t === 2) return Q('基礎', '比較級のあとに「〜より」と続けるときに使う語は？',
        'than', ['then', 'that', 'as']);
      return Q('基礎', '最上級の前によく置く語はどれ？', 'the', ['a', 'an', 'to']);
    }
    if (r <= 8) { // 標準
      t = R(0, 4);
      if (t === 0) return Q('標準', '「big」の比較級はどれ？', 'bigger', ['biger', 'more big', 'bigest']);
      if (t === 1) return Q('標準', '「busy」の最上級はどれ？', 'busiest', ['busyest', 'most busy', 'busier']);
      if (t === 2) return Q('標準', '「beautiful」の比較級はどれ？', 'more beautiful', ['beautifuler', 'beautifullest', 'most beautiful']);
      if (t === 3) return Q('標準', '「わたしはケンと同じくらい速く走ります。」\nI run （　） fast （　） Ken.',
        'as / as', ['as / than', 'more / than', 'so / as']);
      return Q('標準', '「good」の比較級・最上級の組み合わせはどれ？',
        'better / best', ['gooder / goodest', 'more good / most good', 'better / bestest']);
    }
    // 発展
    t = R(0, 3);
    if (t === 0) return Q('発展', '「この本はあの本よりおもしろい。」を英語にすると？',
      'This book is more interesting than that one.',
      ['This book is interestinger than that one.', 'This book is more interesting as that one.', 'This book is the most interesting than that one.']);
    if (t === 1) return Q('発展', '「富士山は日本でいちばん高い山です。」を英語にすると？',
      'Mt. Fuji is the highest mountain in Japan.',
      ['Mt. Fuji is the higher mountain in Japan.', 'Mt. Fuji is highest mountain of Japan.', 'Mt. Fuji is more high mountain in Japan.']);
    if (t === 2) return Q('発展', '「わたしは彼ほど背が高くありません。」を英語にすると？',
      "I am not as tall as he is.", ['I am not taller as he is.', 'I am not so tall than he is.', 'I am not as taller as he is.']);
    return Q('発展', 'Which do you like better, tea or coffee? の意味はどれ？',
      '紅茶とコーヒーではどちらが好きですか。', ['紅茶とコーヒーのどちらがおいしいですか。', '紅茶とコーヒーを両方好きですか。', '紅茶とコーヒーのどちらがいちばん好きですか。']);
  }

  // ---------------- 接続詞・There is ----------------
  function genConj8() {
    var r = R(1, 10), t;
    if (r <= 4) { // 基礎
      t = R(0, 3);
      if (t === 0) return Q('基礎', 'when の意味はどれ？', '〜するとき', ['もし〜ならば', '〜なので', '〜だけれども']);
      if (t === 1) return Q('基礎', 'because の意味はどれ？', '〜なので（理由）', ['〜するとき', 'もし〜ならば', '〜する前に']);
      if (t === 2) return Q('基礎', 'if の意味はどれ？', 'もし〜ならば', ['〜なので', '〜したあと', '〜するとき']);
      return Q('基礎', '「机の上に本が1冊あります。」\n（　） is a book on the desk.',
        'There', ['It', 'That', 'This']);
    }
    if (r <= 8) { // 標準
      t = R(0, 3);
      if (t === 0) return Q('標準', '「テーブルの上にりんごが3つあります。」を英語にすると？',
        'There are three apples on the table.',
        ['There is three apples on the table.', 'There have three apples on the table.', 'It is three apples on the table.']);
      if (t === 1) return Q('標準', '「わたしは疲れていたので早く寝ました。」\nI went to bed early （　） I was tired.',
        'because', ['but', 'if', 'when']);
      if (t === 2) return Q('標準', 'I think （　） he is kind. の（　）に入る語は？',
        'that', ['what', 'if', 'because']);
      return Q('標準', '「公園に子どもは何人いますか。」を英語にすると？',
        'How many children are there in the park?',
        ['How many children is there in the park?', 'How many children there are in the park?', 'How many child are there in the park?']);
    }
    // 発展
    t = R(0, 3);
    if (t === 0) return Q('発展', '「明日晴れたら、公園へ行きます。」の英語で正しいのは？',
      "If it is sunny tomorrow, I will go to the park.",
      ['If it will be sunny tomorrow, I will go to the park.', 'If it is sunny tomorrow, I go to the park yesterday.', 'If it was sunny tomorrow, I will go to the park.']);
    if (t === 1) return Q('発展', 'There was no water in the bottle. の意味はどれ？',
      'びんの中に水はありませんでした。', ['びんの中に水がありました。', 'びんの中に水を入れました。', 'びんは水ではありませんでした。']);
    if (t === 2) return Q('発展', '「わたしが家に帰ったとき、母は料理をしていました。」を英語にすると？',
      'When I came home, my mother was cooking.',
      ['When I came home, my mother is cooking.', 'When I come home, my mother was cook.', 'When I came home, my mother cooking was.']);
    return Q('発展', 'There is / There are の使い分けで正しいのはどれ？',
      'あとに続く名詞が単数なら is、複数なら are',
      ['いつも is を使う', 'あとの名詞が単数なら are、複数なら is', '場所が近ければ is、遠ければ are']);
  }

  try {
    window.genPastBe8 = genPastBe8;
    window.genFuture8 = genFuture8;
    window.genModal8 = genModal8;
    window.genToInf8 = genToInf8;
    window.genGerund8 = genGerund8;
    window.genCompare8 = genCompare8;
    window.genConj8 = genConj8;
  } catch (e) {}

  G8.addUnits('english', [
    { id: 'e8-past', name: '過去形・過去進行形', icon: '⏳', color: 'amber', gen: 'genPastBe8', input: 'mcq', desc: 'was/were・過去形・過去進行形' },
    { id: 'e8-future', name: '未来表現', icon: '🔮', color: 'purple', gen: 'genFuture8', input: 'mcq', desc: 'will と be going to' },
    { id: 'e8-modal', name: '助動詞', icon: '🛡️', color: 'blue', gen: 'genModal8', input: 'mcq', desc: 'must・have to・may・should' },
    { id: 'e8-toinf', name: '不定詞', icon: '➡️', color: 'green', gen: 'genToInf8', input: 'mcq', desc: 'to+原形の3つの用法' },
    { id: 'e8-gerund', name: '動名詞', icon: '🎣', color: 'teal', gen: 'genGerund8', input: 'mcq', desc: '〜ing で「〜すること」' },
    { id: 'e8-compare', name: '比較', icon: '📊', color: 'orange', gen: 'genCompare8', input: 'mcq', desc: '比較級・最上級・as〜as' },
    { id: 'e8-conj', name: '接続詞・There is', icon: '🔗', color: 'cyan', gen: 'genConj8', input: 'mcq', desc: 'when・if・because・There is/are' }
  ]);

  G8.addDisplay({
    'e8-past': { name: '過去進行形の砂時計塔', emoji: '⏳', desc: '過去形・過去進行形（中2英語）' },
    'e8-future': { name: '未来予知の水晶宮', emoji: '🔮', desc: '未来表現（中2英語）' },
    'e8-modal': { name: '助動詞の防壁', emoji: '🛡️', desc: '助動詞（中2英語）' },
    'e8-toinf': { name: '不定詞の三叉路', emoji: '➡️', desc: '不定詞（中2英語）' },
    'e8-gerund': { name: '動名詞の釣り堀', emoji: '🎣', desc: '動名詞（中2英語）' },
    'e8-compare': { name: '比較級の階段', emoji: '📊', desc: '比較（中2英語）' },
    'e8-conj': { name: '接続詞のつり橋', emoji: '🔗', desc: '接続詞・There is（中2英語）' }
  });
})();
