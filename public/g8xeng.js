/* ============================================================
   中2英語 増量パック g8xeng v186
   ・既存 genPastBe8/genFuture8/genModal8/genToInf8/genGerund8/
     genCompare8/genConj8 を window 経由でラップして新パターンを追加
     （既存ファイル非改変）
   ・全問題に patternId を付与（既存パターンは問題文から分類）
   ・基礎40/標準40/発展20 は新旧プールとも維持
   ・単語・例文バンクを新規テンプレート内に大幅追加
   ============================================================ */
(function () {
  var G8 = window.G8; if (!G8) return;
  if (window.__G8XENG__) return; window.__G8XENG__ = 1;
  var R = G8.R, Q = G8.q;
  function pk(a) { return a[R(0, a.length - 1)]; }

  // pool = { b:[[key,fn],...], s:[...], h:[...] }, rules=[[regex,key],...]
  var WRAP = window.__G8X_WRAP = window.__G8X_WRAP || function (origName, unitId, pool, rules, nOld) {
    var orig = window[origName];
    if (typeof orig !== 'function' || orig.__x) return;
    var nNew = pool.b.length + pool.s.length + pool.h.length;
    function classify(q) {
      for (var i = 0; i < rules.length; i++) { if (rules[i][0].test(q)) return unitId + ':' + rules[i][1]; }
      return null;
    }
    var f = function () {
      var p, pid = null;
      if (Math.random() < nNew / (nNew + nOld)) {
        var r = R(1, 10);
        var arr = (r <= 4) ? pool.b : (r <= 8 ? pool.s : pool.h);
        var tpl = arr[R(0, arr.length - 1)];
        p = tpl[1]();
        pid = unitId + ':' + tpl[0];
      } else {
        p = orig();
        pid = classify((p && p.q) || '');
      }
      if (p && pid) p.patternId = pid;
      return p;
    };
    f.__x = 1;
    window[origName] = f;
  };

  /* ================================================================
     過去形・過去進行形（e8-past）12 → 21パターン
     ================================================================ */
  var PST_IRR2 = [
    ['run', 'ran', ['runned', 'runed', 'runs']],
    ['speak', 'spoke', ['speaked', 'spoken', 'speaks']],
    ['say', 'said', ['sayed', 'saied', 'says']],
    ['tell', 'told', ['telled', 'tolded', 'tells']],
    ['know', 'knew', ['knowed', 'known', 'knows']],
    ['give', 'gave', ['gived', 'given', 'gives']],
    ['find', 'found', ['finded', 'founded', 'finds']],
    ['leave', 'left', ['leaved', 'lefted', 'leaves']],
    ['meet', 'met', ['meeted', 'metted', 'meets']],
    ['sing', 'sang', ['singed', 'sung', 'sings']],
    ['swim', 'swam', ['swimmed', 'swum', 'swims']],
    ['drink', 'drank', ['drinked', 'drunk', 'drinks']],
    ['sit', 'sat', ['sitted', 'sited', 'sits']],
    ['stand', 'stood', ['standed', 'stooded', 'stands']],
    ['teach', 'taught', ['teached', 'thought', 'teaches']],
    ['think', 'thought', ['thinked', 'taught', 'thinks']],
    ['send', 'sent', ['sended', 'sends', 'sending']],
    ['sleep', 'slept', ['sleeped', 'sleept', 'sleeps']],
    ['win', 'won', ['winned', 'wan', 'wins']],
    ['hear', 'heard', ['heared', 'hearded', 'hears']],
    ['break', 'broke', ['breaked', 'broken', 'breaks']],
    ['do', 'did', ['doed', 'done', 'does']]
  ];
  var PST_SUBJ = [
    ['I', 'was'], ['Ken', 'was'], ['My father', 'was'], ['She', 'was'], ['The book', 'was'],
    ['We', 'were'], ['They', 'were'], ['You', 'were'], ['My parents', 'were'], ['Ken and Yumi', 'were']
  ];
  var PST_PLACE = ['in the library', 'at home', 'in Tokyo', 'at school', 'in the park'];
  var PST_KAKO = [
    ['They', 'play soccer', 'played soccer', 'playing soccer'],
    ['We', 'watch TV', 'watched TV', 'watching TV'],
    ['I', 'clean my room', 'cleaned my room', 'cleaning my room'],
    ['They', 'study English', 'studied English', 'studying English'],
    ['We', 'visit the museum', 'visited the museum', 'visiting the museum'],
    ['I', 'walk to school', 'walked to school', 'walking to school'],
    ['They', 'help their mother', 'helped their mother', 'helping their mother'],
    ['We', 'use this computer', 'used this computer', 'using this computer']
  ];
  var PST_EIYAKU = [
    ['彼女は先週、京都を訪れました。', 'She visited Kyoto last week.',
      ['She visits Kyoto last week.', 'She was visit Kyoto last week.', 'She is visited Kyoto last week.']],
    ['わたしたちは昨夜、テレビを見ました。', 'We watched TV last night.',
      ['We watch TV last night.', 'We were watch TV last night.', 'We watching TV last night.']],
    ['彼は2年前、大阪に住んでいました。', 'He lived in Osaka two years ago.',
      ['He lives in Osaka two years ago.', 'He was live in Osaka two years ago.', 'He living in Osaka two years ago.']],
    ['わたしは昨日、図書館で英語を勉強しました。', 'I studied English in the library yesterday.',
      ['I studyed English in the library yesterday.', 'I was study English in the library yesterday.', 'I study English in the library yesterday.']],
    ['ケンはこの前の日曜日に新しいくつを買いました。', 'Ken bought new shoes last Sunday.',
      ['Ken buyed new shoes last Sunday.', 'Ken buys new shoes last Sunday.', 'Ken was buy new shoes last Sunday.']],
    ['わたしたちは昨日、公園へ行きました。', 'We went to the park yesterday.',
      ['We goed to the park yesterday.', 'We go to the park yesterday.', 'We were go to the park yesterday.']]
  ];
  var PST_WAYAKU = [
    ['I got up at six yesterday.', 'わたしは昨日6時に起きました。',
      ['わたしは毎日6時に起きます。', 'わたしは明日6時に起きるつもりです。', 'わたしは昨日6時に寝ました。']],
    ['She was listening to music then.', '彼女はそのとき音楽を聞いていました。',
      ['彼女はそのとき音楽を聞き終えました。', '彼女はいつも音楽を聞いています。', '彼女はこれから音楽を聞くところです。']],
    ["They didn't come to school yesterday.", '彼らは昨日学校に来ませんでした。',
      ['彼らは昨日学校に来ました。', '彼らはふだん学校に来ません。', '彼らは明日学校に来ないでしょう。']],
    ['We saw a famous singer at the station.', 'わたしたちは駅で有名な歌手を見ました。',
      ['わたしたちは駅で有名な歌手に会うつもりです。', 'わたしたちは駅で有名な歌手を見るでしょう。', 'わたしたちは駅で有名な歌手をよく見かけます。']],
    ['He was doing his homework at eight.', '彼は8時に宿題をしていました。',
      ['彼は8時に宿題をするつもりでした。', '彼は8時に宿題を終えました。', '彼は毎日8時に宿題をします。']]
  ];
  var PST_SHINKOU = [
    ['He', 'was', 'playing soccer'], ['She', 'was', 'cooking dinner'], ['Ken', 'was', 'reading a book'],
    ['My brother', 'was', 'watching TV'], ['They', 'were', 'studying math'], ['We', 'were', 'swimming in the river'],
    ['You', 'were', 'listening to music'], ['The children', 'were', 'running in the park']
  ];
  var PST_SEIBUN = [
    ["She didn't eat breakfast this morning.",
      ["She didn't ate breakfast this morning.", "She doesn't ate breakfast this morning.", "She didn't eats breakfast this morning."]],
    ['Did he play the guitar last night?',
      ['Did he played the guitar last night?', 'Does he played the guitar last night?', 'Was he play the guitar last night?']],
    ['I was watching TV at nine last night.',
      ['I was watch TV at nine last night.', 'I watching TV at nine last night.', 'I was watched TV at nine last night.']],
    ["We didn't go shopping yesterday.",
      ["We didn't went shopping yesterday.", "We don't went shopping yesterday.", "We weren't go shopping yesterday."]],
    ['Were you studying at that time?',
      ['Was you studying at that time?', 'Did you studying at that time?', 'Were you study at that time?']]
  ];
  var PST_TAIWA = [
    ['What did you do last Sunday?', 'I played baseball with my friends.',
      ['Yes, I did.', 'I play baseball every Sunday.', 'I will play baseball next Sunday.']],
    ['Where were you at seven last night?', 'I was in my room.',
      ['Yes, I was.', 'I am in my room.', 'I were in my room.']],
    ['Did you watch the soccer game last night?', 'Yes, I did.',
      ['Yes, I do.', 'Yes, I was.', 'No, I am not.']],
    ['What was Ken doing then?', "He was washing his father's car.",
      ['Yes, he was.', 'He is washing the car now.', 'He was wash the car.']],
    ['How was the weather in Tokyo yesterday?', 'It was sunny.',
      ['Yes, it was.', 'It is sunny now.', 'It were sunny.']]
  ];
  var PST_NARABE = [
    ['彼女はそのときピアノを弾いていました。', 'She was playing the piano then.',
      ['She playing was the piano then.', 'She was the piano playing then.', 'Was she playing the piano then.']],
    ['あなたは昨日、何を作りましたか。', 'What did you make yesterday?',
      ['What you did make yesterday?', 'Did what you make yesterday?', 'What did you made yesterday?']],
    ['わたしは昨夜、英語を勉強しませんでした。', "I didn't study English last night.",
      ["I didn't studied English last night.", 'I studied not English last night.', "Didn't I study English last night."]],
    ['彼らは川で泳いでいましたか。', 'Were they swimming in the river?',
      ['They were swimming in the river?', 'Were they swim in the river?', 'Did they swimming in the river?']]
  ];
  var pastPool = {
    b: [
      ['n-kako-irr2', function () {
        var v = pk(PST_IRR2);
        return Q('基礎', '「' + v[0] + '」の過去形はどれ？（不規則動詞）', v[1], v[2]);
      }],
      ['n-waswere-basho', function () {
        var s = pk(PST_SUBJ), pl = pk(PST_PLACE);
        var w = (s[1] === 'was') ? ['were', 'are', 'did'] : ['was', 'is', 'did'];
        return Q('基礎', '（　）に入る語はどれ？\n' + s[0] + ' （　） ' + pl + ' yesterday.', s[1], w);
      }],
      ['n-genzai-kako', function () {
        var v = pk(PST_KAKO), be = (v[0] === 'I') ? 'was' : 'were';
        return Q('基礎', '次の文を過去の文（〜しました）に書きかえると？\n' + v[0] + ' ' + v[1] + '.',
          v[0] + ' ' + v[2] + '.',
          [v[0] + ' ' + be + ' ' + v[1] + '.', v[0] + ' ' + v[3] + '.', v[0] + ' did ' + v[2] + '.']);
      }]
    ],
    s: [
      ['n-eiyaku2', function () {
        var v = pk(PST_EIYAKU);
        return Q('標準', '「' + v[0] + '」を英語にすると？', v[1], v[2]);
      }],
      ['n-wayaku', function () {
        var v = pk(PST_WAYAKU);
        return Q('標準', v[0] + ' の意味はどれ？', v[1], v[2]);
      }],
      ['n-shinkou-kuho', function () {
        var v = pk(PST_SHINKOU);
        var w = (v[1] === 'was') ? ['were', 'is', 'did'] : ['was', 'are', 'did'];
        return Q('標準', '（　）に入る語はどれ？（過去進行形）\n' + v[0] + ' （　） ' + v[2] + ' at that time.', v[1], w);
      }],
      ['n-tadashii-bun', function () {
        var v = pk(PST_SEIBUN);
        return Q('標準', '英語として正しい文はどれ？', v[0], v[1]);
      }]
    ],
    h: [
      ['n-taiwa', function () {
        var v = pk(PST_TAIWA);
        return Q('発展', v[0] + ' への応答として最も適切なのは？', v[1], v[2]);
      }],
      ['n-narabe', function () {
        var v = pk(PST_NARABE);
        return Q('発展', '「' + v[0] + '」を表す正しい語順の文はどれ？', v[1], v[2]);
      }]
    ]
  };
  var pastRules = [
    [/の過去形はどれ？（不規則動詞）/, 'o-kako-fukisoku'],
    [/の過去形はどれ？/, 'o-kako-kisoku'],
    [/busy yesterday/, 'o-waswere'],
    [/に ing をつけた形はどれ？/, 'o-ing-kei'],
    [/昨日サッカーをしました/, 'o-eibun-kako'],
    [/テレビを見ませんでした/, 'o-hitei-didnt'],
    [/過去の疑問文/, 'o-gimon-did'],
    [/そのとき本を読んでいました/, 'o-shinkou-eibun'],
    [/Did you play tennis yesterday/, 'o-kotae-did'],
    [/過去進行形の否定文はどれ？/, 'o-shinkou-hitei'],
    [/何をしていましたか/, 'o-shinkou-gimon'],
    [/過去進行形が表すのは/, 'o-shinkou-imi']
  ];

  /* ================================================================
     未来表現（e8-future）12 → 21パターン
     ================================================================ */
  var FUT_GENKEI = [
    ['He will （　） tennis tomorrow.', 'play', ['plays', 'played', 'playing']],
    ['She will （　） her homework after dinner.', 'do', ['does', 'did', 'doing']],
    ['I will （　） my grandmother next week.', 'visit', ['visited', 'visiting', 'visits']],
    ['Ken will （　） a new bike next month.', 'buy', ['buys', 'bought', 'buying']],
    ['They will （　） to the museum next Sunday.', 'go', ['goes', 'went', 'going']],
    ['It will （　） cold tomorrow.', 'be', ['is', 'was', 'been']]
  ];
  var FUT_BE = [
    ['I', 'am'], ['He', 'is'], ['She', 'is'], ['Ken', 'is'], ['My sister', 'is'],
    ['We', 'are'], ['They', 'are'], ['You', 'are'], ['My friends', 'are']
  ];
  var FUT_VP = ['play tennis', 'clean the room', 'make lunch', 'watch a movie', 'study math'];
  var FUT_TAN = [
    ['She will', "She'll", ["She'l", "She'wil", "She'will"]],
    ['He will', "He'll", ["He'l", "He'wil", "He'will"]],
    ['They will', "They'll", ["They'l", "They'will", 'Theyll']],
    ['We will', "We'll", ["We'l", "We'will", 'Wewill']],
    ['will not', "won't", ["willn't", "wo'nt", 'won not']],
    ['It will', "It'll", ["It'l", "It'will", 'Itwill']]
  ];
  var FUT_EIYAKU = [
    ['わたしは今夜、宿題をするつもりです。', 'I will do my homework tonight.',
      ['I will doing my homework tonight.', 'I am will do my homework tonight.', 'I will did my homework tonight.']],
    ['彼女は明日、部屋をそうじする予定です。', 'She is going to clean her room tomorrow.',
      ['She is going to cleans her room tomorrow.', 'She going to clean her room tomorrow.', 'She is go to clean her room tomorrow.']],
    ['わたしたちは来週、沖縄を訪れる予定です。', 'We are going to visit Okinawa next week.',
      ['We is going to visit Okinawa next week.', 'We are going to visited Okinawa next week.', 'We are go to visit Okinawa next week.']],
    ['彼は明日、早く起きるでしょう。', 'He will get up early tomorrow.',
      ['He will gets up early tomorrow.', 'He wills get up early tomorrow.', 'He is will get up early tomorrow.']],
    ['今度の土曜日は晴れるでしょう。', 'It will be sunny next Saturday.',
      ['It will sunny next Saturday.', 'It will is sunny next Saturday.', 'It is will be sunny next Saturday.']]
  ];
  var FUT_WAYAKU = [
    ['She is going to buy a new bike next week.', '彼女は来週、新しい自転車を買う予定です。',
      ['彼女は先週、新しい自転車を買いました。', '彼女は今、新しい自転車を買っています。', '彼女は新しい自転車を買ったところです。']],
    ["I won't watch TV tonight.", 'わたしは今夜、テレビを見ないつもりです。',
      ['わたしは今夜、テレビを見るつもりです。', 'わたしは昨夜、テレビを見ませんでした。', 'わたしは今、テレビを見ていません。']],
    ['Will he come to the party?', '彼はパーティーに来るでしょうか。',
      ['彼はパーティーに来ましたか。', '彼はパーティーに来ていますか。', '彼はパーティーに来たがっていますか。']],
    ['We are going to have a birthday party for Yumi.', 'わたしたちはユミのために誕生日パーティーを開く予定です。',
      ['わたしたちはユミの誕生日パーティーに行きました。', 'わたしたちはユミと誕生日パーティーを楽しみました。', 'わたしたちはユミの誕生日パーティーに招待されました。']]
  ];
  var FUT_KAKIKAE = [
    ['He will visit Osaka next month.', 'He is going to visit Osaka next month.',
      ['He is going to visits Osaka next month.', 'He is go to visit Osaka next month.', 'He was going to visit Osaka next month.']],
    ['I will make dinner tonight.', 'I am going to make dinner tonight.',
      ['I am going to made dinner tonight.', 'I am going make dinner tonight.', 'I will going to make dinner tonight.']],
    ['They are going to study in the library.', 'They will study in the library.',
      ['They will studying in the library.', 'They will studies in the library.', 'They are will study in the library.']],
    ['She is going to leave home at seven.', 'She will leave home at seven.',
      ['She wills leave home at seven.', 'She will leaves home at seven.', 'She will left home at seven.']]
  ];
  var FUT_HITEI = [
    ['I will watch TV tonight.', 'I will not watch TV tonight.',
      ['I will watch not TV tonight.', "I don't will watch TV tonight.", 'I not will watch TV tonight.']],
    ['He is going to swim tomorrow.', 'He is not going to swim tomorrow.',
      ['He is going to not swim tomorrow.', 'He does not going to swim tomorrow.', 'He not is going to swim tomorrow.']],
    ['She will play the piano today.', 'She will not play the piano today.',
      ["She doesn't will play the piano today.", 'She will plays not the piano today.', 'She not will play the piano today.']],
    ['We are going to use this room.', 'We are not going to use this room.',
      ["We don't going to use this room.", 'We are going to not use this room.', 'We not are going to use this room.']]
  ];
  var FUT_TAIWA = [
    ['What are you going to do this weekend?', "I'm going to visit my grandmother.",
      ['Yes, I am.', 'I visited my grandmother last weekend.', 'I am visit my grandmother.']],
    ['Will you carry this bag for me?', 'Sure.',
      ['Yes, you will.', "No, you won't.", 'I carried it yesterday.']],
    ['How long will you stay in Nara?', 'For three days.',
      ['Three times.', 'By bus.', 'With my family.']],
    ['Will it be rainy tomorrow?', "No, it won't.",
      ["No, it isn't.", "No, it doesn't.", "No, it wasn't."]]
  ];
  var FUT_NARABE = [
    ['あなたは明日、ひまですか。', 'Will you be free tomorrow?',
      ['Will you free tomorrow?', 'Will be you free tomorrow?', 'You will be free tomorrow?']],
    ['彼はいつ日本を出発する予定ですか。', 'When is he going to leave Japan?',
      ['When he is going to leave Japan?', 'When is he going to leaves Japan?', 'Is he when going to leave Japan?']],
    ['わたしは今日、彼に電話をしないつもりです。', 'I will not call him today.',
      ['I will call not him today.', 'I not will call him today.', 'I will not calling him today.']],
    ['あなたたちは何を食べるつもりですか。', 'What are you going to eat?',
      ['What you are going to eat?', 'What are you going to ate?', 'Are what you going to eat?']]
  ];
  var futPool = {
    b: [
      ['n-will-kuho', function () {
        var v = pk(FUT_GENKEI);
        return Q('基礎', '（　）に入る語はどれ？\n' + v[0], v[1], v[2]);
      }],
      ['n-bgt-be', function () {
        var s = pk(FUT_BE), vp = pk(FUT_VP);
        var w = (s[1] === 'am') ? ['is', 'are', 'be'] : (s[1] === 'is' ? ['am', 'are', 'be'] : ['am', 'is', 'be']);
        return Q('基礎', '（　）に入る語はどれ？\n' + s[0] + ' （　） going to ' + vp + ' tomorrow.', s[1], w);
      }],
      ['n-tanshuku2', function () {
        var v = pk(FUT_TAN);
        return Q('基礎', '「' + v[0] + '」の短縮形はどれ？', v[1], v[2]);
      }]
    ],
    s: [
      ['n-eiyaku2', function () {
        var v = pk(FUT_EIYAKU);
        return Q('標準', '「' + v[0] + '」を英語にすると？', v[1], v[2]);
      }],
      ['n-wayaku', function () {
        var v = pk(FUT_WAYAKU);
        return Q('標準', v[0] + ' の意味はどれ？', v[1], v[2]);
      }],
      ['n-kakikae', function () {
        var v = pk(FUT_KAKIKAE);
        return Q('標準', '次の文とほぼ同じ内容の文はどれ？\n' + v[0], v[1], v[2]);
      }],
      ['n-hitei', function () {
        var v = pk(FUT_HITEI);
        return Q('標準', '次の文を否定文にすると？\n' + v[0], v[1], v[2]);
      }]
    ],
    h: [
      ['n-taiwa', function () {
        var v = pk(FUT_TAIWA);
        return Q('発展', v[0] + ' への応答として最も適切なのは？', v[1], v[2]);
      }],
      ['n-narabe', function () {
        var v = pk(FUT_NARABE);
        return Q('発展', '「' + v[0] + '」を表す正しい語順の文はどれ？', v[1], v[2]);
      }]
    ]
  };
  var futRules = [
    [/will のあとに続く動詞の形/, 'o-will-genkei'],
    [/明日彼に会うつもり/, 'o-will-anaume'],
    [/「be going to」のあとに続く動詞の形/, 'o-bgt-genkei'],
    [/「I will」の短縮形/, 'o-ill-tanshuku'],
    [/京都を訪れる予定です/, 'o-bgt-eibun'],
    [/will の否定文で使う短縮形/, 'o-wont'],
    [/you help me tomorrow/, 'o-will-gimon'],
    [/明日は雨が降るでしょう/, 'o-willbe-eibun'],
    [/Will you open the window/, 'o-willyou-irai'],
    [/Are you going to study tonight/, 'o-bgt-kotae'],
    [/前から決めていた予定/, 'o-tsukaiwake'],
    [/東京に行かないでしょう/, 'o-wont-eibun']
  ];

  /* ================================================================
     助動詞（e8-modal）12 → 21パターン
     ================================================================ */
  var MOD_IMI = [
    ['〜できる', 'can', ['must', 'may', 'will']],
    ['〜だろう、〜するつもりだ', 'will', ['can', 'must', 'should']],
    ['〜すべきだ', 'should', ['may', 'can', 'will']],
    ['〜してもよい', 'may', ['must', 'should', 'will']],
    ['〜しなければならない', 'must', ['may', 'can', 'will']]
  ];
  var MOD_GENKEI = [
    ['She can （　） the piano well.', 'play', ['plays', 'playing', 'played']],
    ['You must （　） your room today.', 'clean', ['cleans', 'cleaning', 'cleaned']],
    ['He should （　） to bed early.', 'go', ['goes', 'going', 'went']],
    ['May I （　） your dictionary?', 'use', ['uses', 'using', 'used']],
    ['Tom can （　） fast.', 'run', ['runs', 'running', 'ran']],
    ['You should （　） kind to old people.', 'be', ['are', 'is', 'being']]
  ];
  var MOD_HASTO = [
    ['He', 'has to'], ['She', 'has to'], ['Ken', 'has to'], ['My brother', 'has to'],
    ['I', 'have to'], ['You', 'have to'], ['They', 'have to'], ['We', 'have to'], ['My parents', 'have to']
  ];
  var MOD_VP = ['wash the dishes', 'get up at six', 'practice the piano', 'finish the work today', 'wear a uniform'];
  var MOD_EIYAKU = [
    ['あなたはここで泳いではいけません。', 'You must not swim here.',
      ["You don't have to swim here.", 'You must not to swim here.', 'You not must swim here.']],
    ['彼女は今日、夕食を作らなければなりません。', 'She has to cook dinner today.',
      ['She have to cook dinner today.', 'She has to cooks dinner today.', 'She is have to cook dinner today.']],
    ['わたしは母を手伝わなければなりません。', 'I must help my mother.',
      ['I must to help my mother.', 'I musts help my mother.', 'I am must help my mother.']],
    ['あなたはこの本を読むべきです。', 'You should read this book.',
      ['You should to read this book.', 'You should reads this book.', 'You are should read this book.']],
    ['彼は上手に泳ぐことができます。', 'He can swim well.',
      ['He can swims well.', 'He cans swim well.', 'He can swimming well.']]
  ];
  var MOD_WAYAKU = [
    ["You don't have to come early tomorrow.", 'あなたは明日、早く来なくてもよい。',
      ['あなたは明日、早く来てはいけない。', 'あなたは明日、早く来なければならない。', 'あなたは明日、早く来ることができない。']],
    ['You must not use your phone here.', 'ここで電話を使ってはいけません。',
      ['ここで電話を使わなくてもよいです。', 'ここで電話を使わなければなりません。', 'ここで電話を使うことができます。']],
    ['He may be in the library.', '彼は図書館にいるかもしれません。',
      ['彼は図書館にいなければなりません。', '彼は図書館にいることができます。', '彼は図書館にいるべきです。']],
    ['She had to stay home yesterday.', '彼女は昨日、家にいなければなりませんでした。',
      ['彼女は昨日、家にいたかもしれません。', '彼女は昨日、家にいるべきでした。', '彼女は昨日、家にいませんでした。']],
    ['Could you help me with my homework?', '宿題を手伝っていただけませんか。',
      ['宿題を手伝ってもいいですか。', '宿題を手伝うべきですか。', '宿題を手伝うことができましたか。']]
  ];
  var MOD_GIMON = [
    ['He can ski well.', 'Can he ski well?',
      ['Does he can ski well?', 'Can he skis well?', 'He can ski well?']],
    ['She will help us.', 'Will she help us?',
      ['Does she will help us?', 'Will she helps us?', 'She will help us?']],
    ['They must leave now.', 'Must they leave now?',
      ['Do they must leave now?', 'Must they leaves now?', 'They must leave now?']],
    ['He has to work today.', 'Does he have to work today?',
      ['Does he has to work today?', 'Is he have to work today?', 'Do he have to work today?']]
  ];
  var MOD_HITEI = [
    ['She can speak French.', "She can't speak French.",
      ["She doesn't can speak French.", 'She can speaks not French.', "She isn't can speak French."]],
    ['You should open the window.', 'You should not open the window.',
      ["You don't should open the window.", 'You should opens not the window.', 'You not should open the window.']],
    ['He will come tomorrow.', "He won't come tomorrow.",
      ["He doesn't will come tomorrow.", "He won't comes tomorrow.", "He isn't will come tomorrow."]],
    ['I have to go now.', "I don't have to go now.",
      ["I don't has to go now.", 'I not have to go now.', "I have to don't go now."]]
  ];
  var MOD_TAIWA = [
    ['May I use your pen?', 'Sure. Here you are.',
      ['Yes, you do.', 'No, I am not.', 'Yes, I can.']],
    ['Must I finish this today?', "No, you don't have to.",
      ["No, you aren't.", "Yes, you don't.", 'No, I must not.']],
    ['Should I bring my lunch?', 'Yes, you should.',
      ['Yes, I should.', 'Yes, you bring.', 'Yes, you are.']],
    ['Could you open the window?', 'Sure, no problem.',
      ['Yes, I could.', "No, you can't.", 'You are welcome.']]
  ];
  var MOD_NARABE = [
    ['わたしは今日、宿題をしなければなりません。', 'I have to do my homework today.',
      ['I have to my homework do today.', 'I do have to my homework today.', 'I have do to my homework today.']],
    ['あなたはこの部屋で食べてはいけません。', 'You must not eat in this room.',
      ['You not must eat in this room.', 'You must eat not in this room.', 'Must you not eat in this room.']],
    ['彼女は英語で手紙を書くことができます。', 'She can write a letter in English.',
      ['She can a letter write in English.', 'Can she write a letter in English.', 'She write can a letter in English.']],
    ['ここで写真をとってもいいですか。', 'May I take a picture here?',
      ['May take I a picture here?', 'Do I may take a picture here?', 'May I taking a picture here?']]
  ];
  var modPool = {
    b: [
      ['n-imi-erabi', function () {
        var v = pk(MOD_IMI);
        return Q('基礎', '「' + v[0] + '」という意味を表す助動詞はどれ？', v[1], v[2]);
      }],
      ['n-kuho-genkei', function () {
        var v = pk(MOD_GENKEI);
        return Q('基礎', '（　）に入る語はどれ？\n' + v[0], v[1], v[2]);
      }],
      ['n-hasto-erabi', function () {
        var s = pk(MOD_HASTO), vp = pk(MOD_VP);
        var w = (s[1] === 'has to') ? ['have to', 'having to', 'to have'] : ['has to', 'having to', 'to have'];
        return Q('基礎', '（　）に入る語句はどれ？\n' + s[0] + ' （　） ' + vp + '.', s[1], w);
      }]
    ],
    s: [
      ['n-eiyaku2', function () {
        var v = pk(MOD_EIYAKU);
        return Q('標準', '「' + v[0] + '」を英語にすると？', v[1], v[2]);
      }],
      ['n-wayaku', function () {
        var v = pk(MOD_WAYAKU);
        return Q('標準', v[0] + ' の意味はどれ？', v[1], v[2]);
      }],
      ['n-gimon', function () {
        var v = pk(MOD_GIMON);
        return Q('標準', '次の文を疑問文にすると？\n' + v[0], v[1], v[2]);
      }],
      ['n-hitei', function () {
        var v = pk(MOD_HITEI);
        return Q('標準', '次の文を否定文にすると？\n' + v[0], v[1], v[2]);
      }]
    ],
    h: [
      ['n-taiwa', function () {
        var v = pk(MOD_TAIWA);
        return Q('発展', v[0] + ' への応答として最も適切なのは？', v[1], v[2]);
      }],
      ['n-narabe', function () {
        var v = pk(MOD_NARABE);
        return Q('発展', '「' + v[0] + '」を表す正しい語順の文はどれ？', v[1], v[2]);
      }]
    ]
  };
  var modRules = [
    [/must の意味はどれ/, 'o-must-imi'],
    [/may の意味として/, 'o-may-imi'],
    [/should の意味はどれ/, 'o-should-imi'],
    [/助動詞のあとに続く動詞の形/, 'o-genkei'],
    [/早く起きなければなりません/, 'o-must-anaume'],
    [/must とほぼ同じ意味/, 'o-haveto'],
    [/英語を話さなければなりません/, 'o-hasto-anaume'],
    [/can とほぼ同じ意味/, 'o-beableto'],
    [/must not はどんな意味/, 'o-mustnot-imi'],
    [/have to はどんな意味/, 'o-donthaveto-imi'],
    [/窓を開けてもいいですか/, 'o-mayi'],
    [/野菜を食べるべきです/, 'o-should-eibun']
  ];

  /* ================================================================
     不定詞（e8-toinf）12 → 21パターン
     ================================================================ */
  var INF_WANT = [
    ['I want （　） a new bike.', 'to buy', ['buy', 'buying', 'to buying']],
    ['She wants （　） the movie.', 'to see', ['see', 'seeing', 'to seeing']],
    ['They want （　） soccer after school.', 'to play', ['play', 'playing', 'to playing']],
    ['He wants （　） English hard.', 'to study', ['study', 'studying', 'to studying']],
    ['I want （　） some water.', 'to drink', ['drink', 'drinking', 'to drinking']]
  ];
  var INF_JOB = ['doctor', 'singer', 'nurse', 'pilot', 'scientist', 'cook', 'soccer player'];
  var INF_IMI = [
    ['I like to swim.', 'わたしは泳ぐことが好きです。',
      ['わたしは泳ぎに行きました。', 'わたしは泳ぐのが得意です。', 'わたしは泳がなければなりません。']],
    ['She began to cry.', '彼女は泣き始めました。',
      ['彼女は泣きやみました。', '彼女は泣きたいです。', '彼女は泣くところでした。']],
    ['I tried to open the box.', 'わたしはその箱を開けようとしました。',
      ['わたしはその箱を開けてしまいました。', 'わたしはその箱を開けるのをやめました。', 'わたしはその箱を開けたいです。']],
    ['He hopes to visit America.', '彼はアメリカを訪れることを望んでいます。',
      ['彼はアメリカを訪れたことがあります。', '彼はアメリカを訪れなければなりません。', '彼はアメリカを訪れているところです。']],
    ['I need to wash my hands.', 'わたしは手を洗う必要があります。',
      ['わたしは手を洗いたくないです。', 'わたしは手を洗ったところです。', 'わたしは手を洗ってもよいです。']]
  ];
  var INF_MEISHI = '「〜すること」（名詞的用法）';
  var INF_KEIYO = '名詞をうしろから説明する（形容詞的用法）';
  var INF_FUKUSHI = '「〜するために」（副詞的用法）';
  var INF_DUMMY = '過去の動作を表す用法';
  var INF_YOUHOU = [
    ['I want something to eat. の to eat', INF_KEIYO, [INF_MEISHI, INF_FUKUSHI, INF_DUMMY]],
    ['She studies hard to be a nurse. の to be', INF_FUKUSHI, [INF_MEISHI, INF_KEIYO, INF_DUMMY]],
    ['My dream is to be a singer. の to be', INF_MEISHI, [INF_KEIYO, INF_FUKUSHI, INF_DUMMY]],
    ['He has no time to watch TV. の to watch', INF_KEIYO, [INF_MEISHI, INF_FUKUSHI, INF_DUMMY]],
    ['I use this computer to learn English. の to learn', INF_FUKUSHI, [INF_MEISHI, INF_KEIYO, INF_DUMMY]],
    ['To swim in the sea is fun. の To swim', INF_MEISHI, [INF_KEIYO, INF_FUKUSHI, INF_DUMMY]],
    ['Nara has many places to visit. の to visit', INF_KEIYO, [INF_MEISHI, INF_FUKUSHI, INF_DUMMY]],
    ['I went to the store to buy some eggs. の to buy', INF_FUKUSHI, [INF_MEISHI, INF_KEIYO, INF_DUMMY]],
    ['I like to take pictures. の to take', INF_MEISHI, [INF_KEIYO, INF_FUKUSHI, INF_DUMMY]]
  ];
  var INF_EIYAKU = [
    ['わたしには読むべき本がたくさんあります。', 'I have many books to read.',
      ['I have many books read.', 'I have many to read books.', 'I have many reading books.']],
    ['彼女は音楽を聞くために早く起きます。', 'She gets up early to listen to music.',
      ['She gets up early to listening to music.', 'She gets up early for listen to music.', 'She gets up early listen to music.']],
    ['わたしは友だちと話すことが好きです。', 'I like to talk with my friends.',
      ['I like to talking with my friends.', 'I like talk with my friends.', 'I like to talked with my friends.']],
    ['彼はサッカー選手になるために毎日練習しています。', 'He practices every day to be a soccer player.',
      ['He practices every day to is a soccer player.', 'He practices every day for be a soccer player.', 'He practices every day to being a soccer player.']],
    ['何か食べるものを持っていますか。', 'Do you have anything to eat?',
      ['Do you have anything eat?', 'Do you have anything eating?', 'Do you have anything to eating?']]
  ];
  var INF_WAYAKU = [
    ['He went to the library to study math.', '彼は数学を勉強するために図書館へ行きました。',
      ['彼は図書館で数学を勉強することが好きです。', '彼は数学を勉強するための図書館を建てました。', '彼は図書館へ行って数学の本を借りました。']],
    ['I was happy to get your letter.', 'わたしはあなたの手紙を受け取ってうれしかったです。',
      ['わたしはあなたに手紙を書きたいです。', 'わたしはあなたの手紙を受け取るつもりです。', 'わたしはうれしくてあなたに手紙を書きました。']],
    ['She has a lot of work to do today.', '彼女は今日するべき仕事がたくさんあります。',
      ['彼女は今日たくさん働きたいです。', '彼女は今日仕事をするために出かけました。', '彼女は今日仕事をやり終えました。']],
    ['To help each other is important.', 'たがいに助け合うことは大切です。',
      ['たがいに助け合うために大切です。', '助けてくれる大切な人がいます。', 'たがいに助け合ったので大切でした。']]
  ];
  var INF_SEIBUN = [
    ['She wants to go home.',
      ['She wants to goes home.', 'She wants go home.', 'She wants to going home.']],
    ['I got up early to make breakfast.',
      ['I got up early to made breakfast.', 'I got up early to making breakfast.', 'I got up early make breakfast.']],
    ['There are many things to see in Kyoto.',
      ['There are many things to seeing in Kyoto.', 'There are many things see in Kyoto.', 'There are many things to saw in Kyoto.']],
    ['It is fun to play games with friends.',
      ['It is fun to plays games with friends.', 'It is fun play games with friends.', 'It is fun to playing games with friends.']]
  ];
  var INF_TAIWA = [
    ['Why did you go to the station?', 'To meet my uncle.',
      ['Yes, I did.', 'To met my uncle.', 'I go there every day.']],
    ['Why do you study English every day?', 'To talk with people from other countries.',
      ['Yes, I do.', 'To talking with people from other countries.', 'I am study English.']],
    ['Why did she get up so early?', 'To make lunch for her family.',
      ['To made lunch for her family.', 'Yes, she did.', 'She is get up early.']]
  ];
  var INF_NARABE = [
    ['わたしは何か冷たい飲み物が欲しいです。', 'I want something cold to drink.',
      ['I want cold something to drink.', 'I want something to cold drink.', 'I want to something cold drink.']],
    ['彼女には今日すべきことがたくさんあります。', 'She has a lot of things to do today.',
      ['She has a lot of to do things today.', 'She has a lot of things do to today.', 'She to do has a lot of things today.']],
    ['わたしは音楽を聞くために公園へ行きました。', 'I went to the park to listen to music.',
      ['I went to listen to the park to music.', 'I went to the park listen to music.', 'I to listen to music went the park.']],
    ['英語を学ぶことはおもしろいです。', 'It is interesting to learn English.',
      ['It is to learn English interesting.', 'It is interesting learn to English.', 'It interesting is to learn English.']]
  ];
  var infPool = {
    b: [
      ['n-want-kuho', function () {
        var v = pk(INF_WANT);
        return Q('基礎', '（　）に入る語句はどれ？\n' + v[0], v[1], v[2]);
      }],
      ['n-tobe', function () {
        var j = pk(INF_JOB);
        return Q('基礎', '「わたしは' + ({ doctor: '医者', singer: '歌手', nurse: '看護師', pilot: 'パイロット', scientist: '科学者', cook: '料理人', 'soccer player': 'サッカー選手' }[j]) + 'になりたいです。」\nI want to （　） a ' + j + '.',
          'be', ['am', 'is', 'do']);
      }],
      ['n-imi-kihon', function () {
        var v = pk(INF_IMI);
        return Q('基礎', v[0] + ' の意味はどれ？', v[1], v[2]);
      }]
    ],
    s: [
      ['n-youhou2', function () {
        var v = pk(INF_YOUHOU);
        return Q('標準', v[0] + ' のはたらきは？', v[1], v[2]);
      }],
      ['n-eiyaku2', function () {
        var v = pk(INF_EIYAKU);
        return Q('標準', '「' + v[0] + '」を英語にすると？', v[1], v[2]);
      }],
      ['n-wayaku', function () {
        var v = pk(INF_WAYAKU);
        return Q('標準', v[0] + ' の意味はどれ？', v[1], v[2]);
      }],
      ['n-tadashii-bun', function () {
        var v = pk(INF_SEIBUN);
        return Q('標準', '英語として正しい文はどれ？', v[0], v[1]);
      }]
    ],
    h: [
      ['n-taiwa', function () {
        var v = pk(INF_TAIWA);
        return Q('発展', v[0] + ' への応答として最も適切なのは？', v[1], v[2]);
      }],
      ['n-narabe', function () {
        var v = pk(INF_NARABE);
        return Q('発展', '「' + v[0] + '」を表す正しい語順の文はどれ？', v[1], v[2]);
      }]
    ]
  };
  var infRules = [
    [/不定詞の形はどれ/, 'o-katachi'],
    [/I like （　） soccer/, 'o-like-kuho'],
    [/I want to be a teacher/, 'o-wanttobe-imi'],
    [/「読むための本」/, 'o-keiyoushi-kuho'],
    [/勉強するために早く起きました/, 'o-tame-kuho'],
    [/homework to do/, 'o-keiyoushi-youhou'],
    [/He came here to see you/, 'o-fukushi-youhou'],
    [/To read books is fun/, 'o-meishi-youhou'],
    [/It で始めて/, 'o-it-koubun'],
    [/飲み物が欲しい/, 'o-something'],
    [/glad to hear/, 'o-kanjou'],
    [/テニスをするために公園へ/, 'o-tame-eibun']
  ];

  /* ================================================================
     動名詞（e8-gerund）12 → 21パターン
     ================================================================ */
  var GER_ING2 = [
    ['get', 'getting', ['geting', 'gettting', 'getted']],
    ['put', 'putting', ['puting', 'puttting', 'puted']],
    ['come', 'coming', ['comeing', 'comming', 'comed']],
    ['use', 'using', ['useing', 'ussing', 'used']],
    ['take', 'taking', ['takeing', 'takking', 'taked']],
    ['begin', 'beginning', ['begining', 'beginnning', 'begined']],
    ['have', 'having', ['haveing', 'havving', 'haved']],
    ['give', 'giving', ['giveing', 'givving', 'gived']],
    ['plan', 'planning', ['planing', 'plannning', 'planed']],
    ['cut', 'cutting', ['cuting', 'cuttting', 'cuted']],
    ['stop', 'stopping', ['stoping', 'stoppping', 'stoped']]
  ];
  var GER_LIKE = [
    ['彼は写真をとることが好きです。', 'He likes （　） pictures.', 'taking', ['take', 'takes', 'to taking']],
    ['わたしは歌を歌うことが好きです。', 'I like （　） songs.', 'singing', ['sing', 'sings', 'to singing']],
    ['彼女は料理をすることが好きです。', 'She likes （　）.', 'cooking', ['cook', 'cooks', 'to cooking']],
    ['わたしは絵をかくことが好きです。', 'I like （　） pictures.', 'drawing', ['draw', 'draws', 'to drawing']]
  ];
  var GER_IMI2 = [
    ['Swimming is fun.', '泳ぐことは楽しい。',
      ['泳ぐために楽しい。', '泳いだので楽しかった。', '泳ぎに行きましょう。']],
    ['My hobby is collecting stamps.', 'わたしの趣味は切手を集めることです。',
      ['わたしは切手を集めるつもりです。', 'わたしの趣味のために切手を集めます。', 'わたしは切手を集めたことがあります。']],
    ['Speaking English is not easy.', '英語を話すことは簡単ではありません。',
      ['英語を話すことは簡単です。', '英語を話すために簡単ではありません。', '英語を話してはいけません。']],
    ['Reading books is important for us.', '本を読むことはわたしたちにとって大切です。',
      ['本を読むためにわたしたちは大切です。', 'わたしたちは大切な本を読んでいます。', '本を読んだのでわたしたちは大切です。']]
  ];
  var GER_MOKUTEKI = [
    ['We enjoyed （　） in the sea.', 'swimming', ['to swim', 'swim', 'swam']],
    ['He finished （　） the book last night.', 'reading', ['to read', 'read', 'reads']],
    ['The baby stopped （　）.', 'crying', ['cry', 'cried', 'cries']],
    ['They enjoyed （　） to music together.', 'listening', ['to listen', 'listen', 'listened']],
    ['I finished （　） my room.', 'cleaning', ['to clean', 'clean', 'cleaned']]
  ];
  var GER_ZENCHI = [
    ['Thank you for （　） me.', 'helping', ['help', 'to help', 'helped']],
    ['He is good at （　） soccer.', 'playing', ['play', 'to play', 'plays']],
    ['How about （　） tennis this afternoon?', 'playing', ['play', 'to play', 'played']],
    ['She left the room without （　） anything.', 'saying', ['say', 'to say', 'said']],
    ['Wash your hands before （　） lunch.', 'eating', ['eat', 'to eat', 'ate']]
  ];
  var GER_EIYAKU = [
    ['わたしの趣味は音楽を聞くことです。', 'My hobby is listening to music.',
      ['My hobby is listen to music.', 'My hobby is to listening music.', 'My hobby listening to music.']],
    ['彼は宿題をやり終えました。', 'He finished doing his homework.',
      ['He finished to do his homework.', 'He finished do his homework.', 'He finished did his homework.']],
    ['わたしたちはテレビゲームをして楽しみました。', 'We enjoyed playing video games.',
      ['We enjoyed to play video games.', 'We enjoyed play video games.', 'We enjoyed played video games.']],
    ['雨がやみました。', 'It stopped raining.',
      ['It stopped to rain.', 'It stopped rain.', 'It stopping rained.']],
    ['エミは英語を教えることが得意です。', 'Emi is good at teaching English.',
      ['Emi is good at teach English.', 'Emi is good at to teach English.', 'Emi is good teaching at English.']]
  ];
  var GER_ERABI = [
    ['目的語に動名詞（ing形）だけをとる動詞はどれ？', 'enjoy', ['want', 'hope', 'plan']],
    ['目的語に動名詞（ing形）だけをとる動詞はどれ？', 'finish', ['want', 'hope', 'plan']],
    ['目的語に「to+動詞の原形」だけをとる動詞はどれ？', 'want', ['enjoy', 'finish', 'stop']],
    ['目的語に「to+動詞の原形」だけをとる動詞はどれ？', 'hope', ['enjoy', 'finish', 'stop']]
  ];
  var GER_WAYAKU = [
    ['Taking pictures of birds is his hobby.', '鳥の写真をとることが彼の趣味です。',
      ['鳥の写真をとるために彼は趣味を持っています。', '彼は趣味で鳥を飼っています。', '彼は鳥に写真をとられました。']],
    ['She is interested in learning Japanese.', '彼女は日本語を学ぶことに興味があります。',
      ['彼女は日本語を学ばなければなりません。', '彼女は日本語を学んだことがあります。', '彼女は日本語のおもしろい話をします。']],
    ['Getting up early is good for your health.', '早起きすることは健康によいです。',
      ['早起きするために健康になりました。', '健康な人は早く起きます。', '早く起きてはいけません。']],
    ['We talked about going camping this summer.', 'わたしたちはこの夏キャンプに行くことについて話しました。',
      ['わたしたちはこの夏キャンプに行きました。', 'わたしたちはこの夏キャンプで話しました。', 'わたしたちはこの夏キャンプに行くつもりです。']]
  ];
  var GER_NARABE = [
    ['わたしは手紙を書き終えました。', 'I finished writing the letter.',
      ['I finished the letter writing.', 'I writing finished the letter.', 'I finished to writing the letter.']],
    ['彼はギターをひくことが得意です。', 'He is good at playing the guitar.',
      ['He is playing good at the guitar.', 'He is good at the guitar playing.', 'He is good playing at the guitar.']],
    ['英語の歌を歌うことは楽しいです。', 'Singing English songs is fun.',
      ['English songs singing is fun.', 'Sing English songs is fun.', 'Singing English is songs fun.']],
    ['わたしたちは公園を走って楽しみました。', 'We enjoyed running in the park.',
      ['We enjoyed in the park running.', 'We running enjoyed in the park.', 'Running we enjoyed in the park.']]
  ];
  var gerPool = {
    b: [
      ['n-ing-kei2', function () {
        var v = pk(GER_ING2);
        return Q('基礎', '「' + v[0] + '」の ing形（動名詞）はどれ？', v[1], v[2]);
      }],
      ['n-like-kuho2', function () {
        var v = pk(GER_LIKE);
        return Q('基礎', '「' + v[0] + '」\n' + v[1], v[2], v[3]);
      }],
      ['n-imi2', function () {
        var v = pk(GER_IMI2);
        return Q('基礎', v[0] + ' の意味はどれ？', v[1], v[2]);
      }]
    ],
    s: [
      ['n-mokutekigo-kuho', function () {
        var v = pk(GER_MOKUTEKI);
        return Q('標準', '（　）に入る語はどれ？\n' + v[0], v[1], v[2]);
      }],
      ['n-zenchishi-kuho', function () {
        var v = pk(GER_ZENCHI);
        return Q('標準', '（　）に入る語はどれ？\n' + v[0], v[1], v[2]);
      }],
      ['n-eiyaku2', function () {
        var v = pk(GER_EIYAKU);
        return Q('標準', '「' + v[0] + '」を英語にすると？', v[1], v[2]);
      }],
      ['n-doushi-erabi', function () {
        var v = pk(GER_ERABI);
        return Q('標準', v[0], v[1], v[2]);
      }]
    ],
    h: [
      ['n-wayaku', function () {
        var v = pk(GER_WAYAKU);
        return Q('発展', v[0] + ' の意味はどれ？', v[1], v[2]);
      }],
      ['n-narabe', function () {
        var v = pk(GER_NARABE);
        return Q('発展', '「' + v[0] + '」を表す正しい語順の文はどれ？', v[1], v[2]);
      }]
    ]
  };
  var gerRules = [
    [/動名詞の形はどれ/, 'o-katachi'],
    [/動名詞はどんな意味/, 'o-imi'],
    [/泳ぐことが好きです/, 'o-like-kuho'],
    [/Playing the piano is fun/, 'o-shugo-hataraki'],
    [/enjoy のあとに続く形/, 'o-enjoy-kei'],
    [/読書を楽しみました/, 'o-enjoy-eibun'],
    [/前置詞のあとに動詞/, 'o-zenchishi'],
    [/サッカーをすることは楽しい/, 'o-shugo-eibun'],
    [/stop のあとに動名詞/, 'o-stop-imi'],
    [/She is good at/, 'o-goodat'],
    [/不定詞と動名詞の両方/, 'o-ryouhou'],
    [/I finished （　） my homework/, 'o-finish-kuho']
  ];

  /* ================================================================
     比較（e8-compare）13 → 23パターン
     ================================================================ */
  var CMP_Y = [
    ['easy', 'easier', ['easyer', 'more easy', 'easiest']],
    ['happy', 'happier', ['happyer', 'more happy', 'happiest']],
    ['early', 'earlier', ['earlyer', 'more early', 'earliest']],
    ['heavy', 'heavier', ['heavyer', 'more heavy', 'heaviest']],
    ['hot', 'hotter', ['hoter', 'more hot', 'hottest']],
    ['pretty', 'prettier', ['prettyer', 'more pretty', 'prettiest']]
  ];
  var CMP_SAIJOU = [
    ['new', 'newest', ['newer', 'most new', 'newst']],
    ['high', 'highest', ['higher', 'most high', 'highst']],
    ['cold', 'coldest', ['colder', 'most cold', 'coldst']],
    ['strong', 'strongest', ['stronger', 'most strong', 'strongst']],
    ['easy', 'easiest', ['easier', 'easyest', 'most easy']],
    ['hot', 'hottest', ['hotter', 'hotest', 'most hot']]
  ];
  var CMP_THAN = [
    ['river', 'long', 'longer', 'longest'],
    ['bag', 'heavy', 'heavier', 'heaviest'],
    ['question', 'easy', 'easier', 'easiest'],
    ['building', 'old', 'older', 'oldest'],
    ['box', 'big', 'bigger', 'biggest'],
    ['car', 'new', 'newer', 'newest']
  ];
  var CMP_MORE = [
    ['popular', '比較級', 'more popular', ['popularer', 'most popular', 'popularest']],
    ['famous', '最上級', 'most famous', ['famousest', 'more famous', 'famouser']],
    ['difficult', '比較級', 'more difficult', ['difficulter', 'most difficult', 'difficultest']],
    ['important', '最上級', 'most important', ['importantest', 'more important', 'importanter']],
    ['useful', '比較級', 'more useful', ['usefuler', 'most useful', 'usefulest']],
    ['exciting', '最上級', 'most exciting', ['excitingest', 'more exciting', 'excitinger']]
  ];
  var CMP_FUKISOKU = [
    ['many', '比較級', 'more', ['manyer', 'manier', 'most']],
    ['much', '比較級', 'more', ['mucher', 'more much', 'most']],
    ['well', '比較級', 'better', ['weller', 'more well', 'best']],
    ['good', '最上級', 'best', ['goodest', 'most good', 'better']],
    ['bad', '比較級', 'worse', ['badder', 'more bad', 'worst']],
    ['many', '最上級', 'most', ['manyest', 'maniest', 'more']]
  ];
  var CMP_INOF = [
    ['the three', 'of'], ['the five', 'of'], ['all', 'of'], ['the four', 'of'],
    ['his class', 'in'], ['Japan', 'in'], ['this city', 'in'], ['my family', 'in'], ['our school', 'in']
  ];
  var CMP_EIYAKU = [
    ['この問題はあの問題よりやさしいです。', 'This question is easier than that one.',
      ['This question is easyer than that one.', 'This question is more easy than that one.', 'This question is easier that that one.']],
    ['トムはクラスの中でいちばん背が高いです。', 'Tom is the tallest in his class.',
      ['Tom is the taller in his class.', 'Tom is the most tall in his class.', 'Tom is the tallest of his class.']],
    ['この花はあの花と同じくらい美しいです。', 'This flower is as beautiful as that one.',
      ['This flower is as more beautiful as that one.', 'This flower is beautiful as that one.', 'This flower is as beautiful than that one.']],
    ['サッカーは野球より人気があります。', 'Soccer is more popular than baseball.',
      ['Soccer is popularer than baseball.', 'Soccer is the most popular than baseball.', 'Soccer is more popular as baseball.']],
    ['わたしの犬はあなたの犬より速く走ります。', 'My dog runs faster than yours.',
      ['My dog runs fast than yours.', 'My dog runs more fast than yours.', 'My dog runs the fastest than yours.']]
  ];
  var CMP_WAYAKU = [
    ['Soccer is the most popular sport in my class.', 'サッカーはわたしのクラスでいちばん人気のあるスポーツです。',
      ['サッカーはわたしのクラスで野球より人気があります。', 'サッカーはわたしのクラスであまり人気がありません。', 'わたしのクラスの人はみなサッカーがじょうずです。']],
    ['This question is not as difficult as that one.', 'この問題はあの問題ほど難しくありません。',
      ['この問題はあの問題と同じくらい難しいです。', 'この問題はあの問題より難しいです。', 'この問題はあの問題ほどやさしくありません。']],
    ['Ken can swim better than Tom.', 'ケンはトムよりじょうずに泳げます。',
      ['ケンはトムと同じくらいじょうずに泳げます。', 'トムはケンよりじょうずに泳げます。', 'ケンはクラスでいちばんじょうずに泳げます。']],
    ['I like dogs better than cats.', 'わたしはネコよりイヌのほうが好きです。',
      ['わたしはイヌよりネコのほうが好きです。', 'わたしはイヌがいちばん好きです。', 'わたしはイヌもネコも同じくらい好きです。']]
  ];
  var CMP_KAKIKAE = [
    ['Tom is taller than Ken.', 'Ken is not as tall as Tom.',
      ['Ken is taller than Tom.', 'Tom is not as tall as Ken.', 'Ken is as tall as Tom.']],
    ['This bike is older than that one.', 'That bike is newer than this one.',
      ['That bike is older than this one.', 'This bike is newer than that one.', 'That bike is as old as this one.']],
    ['Yumi is younger than Emi.', 'Emi is older than Yumi.',
      ['Emi is younger than Yumi.', 'Yumi is older than Emi.', 'Emi is as young as Yumi.']],
    ['My bag is not as big as yours.', 'Your bag is bigger than mine.',
      ['My bag is bigger than yours.', 'Your bag is smaller than mine.', 'Your bag is as big as mine.']]
  ];
  var CMP_TAIWA = [
    ['Which do you like better, summer or winter?', 'I like summer better.',
      ['I like better summer.', 'Yes, I do.', 'I like summer well than winter.']],
    ['Which is higher, Mt. Fuji or Mt. Aso?', 'Mt. Fuji is.',
      ['Yes, it is.', 'Mt. Fuji does.', 'Mt. Fuji is high than Mt. Aso.']],
    ['What sport do you like the best?', 'I like tennis the best.',
      ['Yes, I do.', 'I like tennis the better.', 'I like the best tennis than.']],
    ['Who is the oldest in your family?', 'My grandfather is.',
      ['Yes, he is.', 'My grandfather does.', 'My grandfather likes the oldest.']]
  ];
  var cmpPool = {
    b: [
      ['n-hikaku-y', function () {
        var v = pk(CMP_Y);
        return Q('基礎', '「' + v[0] + '」の比較級はどれ？', v[1], v[2]);
      }],
      ['n-saijou2', function () {
        var v = pk(CMP_SAIJOU);
        return Q('基礎', '「' + v[0] + '」の最上級はどれ？', v[1], v[2]);
      }],
      ['n-kuho-than', function () {
        var v = pk(CMP_THAN);
        return Q('基礎', '（　）に入る語はどれ？\nThis ' + v[0] + ' is （　） than that one.',
          v[2], [v[1], v[3], 'more ' + v[1]]);
      }]
    ],
    s: [
      ['n-more-most', function () {
        var v = pk(CMP_MORE);
        return Q('標準', '「' + v[0] + '」の' + v[1] + 'はどれ？', v[2], v[3]);
      }],
      ['n-fukisoku', function () {
        var v = pk(CMP_FUKISOKU);
        return Q('標準', '「' + v[0] + '」の' + v[1] + 'はどれ？（不規則変化）', v[2], v[3]);
      }],
      ['n-in-of', function () {
        var v = pk(CMP_INOF);
        var w = (v[1] === 'of') ? ['in', 'at', 'than'] : ['of', 'at', 'than'];
        return Q('標準', '（　）に入る語はどれ？\nHe is the tallest （　） ' + v[0] + '.', v[1], w);
      }],
      ['n-eiyaku2', function () {
        var v = pk(CMP_EIYAKU);
        return Q('標準', '「' + v[0] + '」を英語にすると？', v[1], v[2]);
      }],
      ['n-wayaku', function () {
        var v = pk(CMP_WAYAKU);
        return Q('標準', v[0] + ' の意味はどれ？', v[1], v[2]);
      }]
    ],
    h: [
      ['n-kakikae', function () {
        var v = pk(CMP_KAKIKAE);
        return Q('発展', '次の文とほぼ同じ内容の文はどれ？\n' + v[0], v[1], v[2]);
      }],
      ['n-taiwa', function () {
        var v = pk(CMP_TAIWA);
        return Q('発展', v[0] + ' への応答として最も適切なのは？', v[1], v[2]);
      }]
    ]
  };
  var cmpRules = [
    [/「big」の比較級/, 'o-big'],
    [/「beautiful」の比較級/, 'o-beautiful'],
    [/「busy」の最上級/, 'o-busy'],
    [/「good」の比較級・最上級/, 'o-good'],
    [/の比較級はどれ？/, 'o-hikaku-kihon'],
    [/の最上級はどれ？/, 'o-saijou-kihon'],
    [/「〜より」と続けるとき/, 'o-than'],
    [/最上級の前によく置く語/, 'o-the'],
    [/ケンと同じくらい速く/, 'o-asas'],
    [/あの本よりおもしろい/, 'o-more-eibun'],
    [/富士山/, 'o-saijou-eibun'],
    [/彼ほど背が高くありません/, 'o-notasas'],
    [/Which do you like better/, 'o-whichbetter']
  ];

  /* ================================================================
     接続詞・There is（e8-conj）12 → 21パターン
     ================================================================ */
  var CNJ_KUHO = [
    ['I was watching TV （　） my mother came home.', 'when', ['that', 'or', 'to']],
    ['We stayed home （　） it was rainy.', 'because', ['that', 'or', 'to']],
    ['（　） you are busy, I will help you.', 'If', ['That', 'Or', 'To']],
    ['I know （　） she likes music.', 'that', ['or', 'to', 'so']],
    ['She was reading a book （　） I visited her.', 'when', ['that', 'or', 'to']]
  ];
  var CNJ_THERE = [
    ['a cat', 'is', 'under the chair'],
    ['a ball', 'is', 'in the box'],
    ['an old temple', 'is', 'near my house'],
    ['some milk', 'is', 'in the glass'],
    ['two dogs', 'are', 'in the garden'],
    ['some books', 'are', 'on the desk'],
    ['many children', 'are', 'in the park'],
    ['a lot of stars', 'are', 'in the sky']
  ];
  var CNJ_IMI2 = [
    ['before（接続詞）の意味はどれ？', '〜する前に', ['〜したあとで', '〜するとき', '〜なので']],
    ['after（接続詞）の意味はどれ？', '〜したあとで', ['〜する前に', 'もし〜ならば', '〜だけれども']],
    ['that（接続詞）の意味はどれ？', '〜ということ', ['〜する前に', 'もし〜ならば', '〜なので']],
    ['but の意味はどれ？', 'しかし', ['だから', 'または', 'そして']],
    ['so（接続詞）の意味はどれ？', 'だから', ['しかし', 'または', 'もし〜ならば']]
  ];
  var CNJ_IF = [
    ['If it （　） tomorrow, I will stay home.', 'rains', ['will rain', 'rain', 'rained']],
    ["If you （　） free next Sunday, let's go to the zoo.", 'are', ['will be', 'is', 'were']],
    ['If he （　） up early, he will catch the bus.', 'gets', ['will get', 'get', 'got']],
    ['When my father （　） home, we will have dinner.', 'comes', ['will come', 'come', 'came']],
    ['I will call you if I （　） time tomorrow.', 'have', ['will have', 'has', 'had']]
  ];
  var CNJ_EIYAKU = [
    ['わたしのかばんの中に2冊の本があります。', 'There are two books in my bag.',
      ['There is two books in my bag.', 'There are two book in my bag.', 'It is two books in my bag.']],
    ['わたしは子どものとき、大阪に住んでいました。', 'When I was a child, I lived in Osaka.',
      ['When I am a child, I lived in Osaka.', 'When I was a child, I live in Osaka.', 'If I child was, I lived in Osaka.']],
    ['疲れているなら、早く寝なさい。', 'If you are tired, go to bed early.',
      ['If you tired, go to bed early.', 'If you are tired, goes to bed early.', 'If you will be tired, go to bed early.']],
    ['彼が親切だということをわたしは知っています。', 'I know that he is kind.',
      ['I know that is he kind.', 'I knowing that he is kind.', 'I know that he kind is.']],
    ['壁に1枚の絵がかかっています。', 'There is a picture on the wall.',
      ['There are a picture on the wall.', 'It is a picture on the wall.', 'There is a pictures on the wall.']]
  ];
  var CNJ_WAYAKU = [
    ['I was taking a bath when you called me.', 'あなたが電話をくれたとき、わたしはおふろに入っていました。',
      ['あなたが電話をくれたので、わたしはおふろに入りました。', 'もしあなたが電話をくれたら、わたしはおふろに入ります。', 'あなたが電話をくれる前に、わたしはおふろに入っていました。']],
    ['There are thirty-five students in our class.', 'わたしたちのクラスには35人の生徒がいます。',
      ['わたしたちのクラスには35人の先生がいます。', 'わたしたちの学校には35人の生徒がいます。', 'わたしたちのクラスに生徒は35人いませんでした。']],
    ['I stayed home because I had a cold.', 'かぜをひいていたので、わたしは家にいました。',
      ['家にいたので、わたしはかぜをひきました。', 'かぜをひいたら、わたしは家にいるつもりです。', 'かぜをひく前に、わたしは家にいました。']],
    ['I hope that you will like this present.', 'あなたがこのプレゼントを気に入ってくれるといいなと思います。',
      ['あなたがこのプレゼントを気に入ったのでうれしいです。', 'あなたはこのプレゼントを気に入らなければなりません。', 'わたしはこのプレゼントが気に入りました。']]
  ];
  var CNJ_KOTAE = [
    ['Is there a park near your house?', 'Yes, there is.',
      ['Yes, it is.', 'Yes, there does.', 'Yes, I am.']],
    ['Are there any dogs in the garden?', "No, there aren't.",
      ["No, they aren't.", "No, there isn't.", "No, there don't."]],
    ['How many students are there in your class?', 'There are forty.',
      ['Yes, there are.', 'They are forty students.', 'It is forty.']],
    ['Is there any water in the bottle?', "No, there isn't.",
      ["No, it isn't.", "No, there aren't.", 'No, there is.']]
  ];
  var CNJ_NARABE = [
    ['もし明日晴れたら、つりに行きましょう。', "If it is sunny tomorrow, let's go fishing.",
      ["If it will be sunny tomorrow, let's go fishing.", "If it is sunny tomorrow, let's going fishing.", "It is sunny if tomorrow, let's go fishing."]],
    ['わたしは彼が正直だと思います。', 'I think that he is honest.',
      ['I think that is he honest.', 'I that think he is honest.', 'I think he that is honest.']],
    ['その知らせを聞いたとき、わたしはうれしかったです。', 'I was happy when I heard the news.',
      ['I was happy when I hear the news.', 'I was happy when did I hear the news.', 'I happy was when I heard the news.']],
    ['この近くに図書館はありますか。', 'Is there a library near here?',
      ['There is a library near here?', 'Is a library there near here?', 'Does there a library near here?']]
  ];
  var CNJ_TAIWA = [
    ['How many people are there in your family?', 'There are four.',
      ['Yes, there are.', 'It is four people.', 'They are my family.']],
    ['What were you doing when I called you?', 'I was doing my homework.',
      ['Yes, I was.', 'I am doing my homework.', 'I do my homework every day.']],
    ['Why were you late for school?', 'Because I got up late.',
      ['Yes, I was.', 'If I got up late.', 'To got up late.']],
    ['Is there anything in the box?', "No, there isn't. It's empty.",
      ["No, there don't.", 'Yes, it is.', 'No, I am not.']]
  ];
  var cnjPool = {
    b: [
      ['n-setsuzoku-kuho', function () {
        var v = pk(CNJ_KUHO);
        return Q('基礎', '（　）に入る語はどれ？\n' + v[0], v[1], v[2]);
      }],
      ['n-thereis-erabi', function () {
        var v = pk(CNJ_THERE);
        var w = (v[1] === 'is') ? ['are', 'am', 'have'] : ['is', 'am', 'have'];
        return Q('基礎', '（　）に入る語はどれ？\nThere （　） ' + v[0] + ' ' + v[2] + '.', v[1], w);
      }],
      ['n-imi2', function () {
        var v = pk(CNJ_IMI2);
        return Q('基礎', v[0], v[1], v[2]);
      }]
    ],
    s: [
      ['n-if-genzai', function () {
        var v = pk(CNJ_IF);
        return Q('標準', '（　）に入る語はどれ？\n' + v[0], v[1], v[2]);
      }],
      ['n-eiyaku2', function () {
        var v = pk(CNJ_EIYAKU);
        return Q('標準', '「' + v[0] + '」を英語にすると？', v[1], v[2]);
      }],
      ['n-wayaku', function () {
        var v = pk(CNJ_WAYAKU);
        return Q('標準', v[0] + ' の意味はどれ？', v[1], v[2]);
      }],
      ['n-there-kotae', function () {
        var v = pk(CNJ_KOTAE);
        return Q('標準', v[0] + ' への答えとして正しいのは？', v[1], v[2]);
      }]
    ],
    h: [
      ['n-narabe', function () {
        var v = pk(CNJ_NARABE);
        return Q('発展', '「' + v[0] + '」を表す正しい語順の文はどれ？', v[1], v[2]);
      }],
      ['n-taiwa', function () {
        var v = pk(CNJ_TAIWA);
        return Q('発展', v[0] + ' への応答として最も適切なのは？', v[1], v[2]);
      }]
    ]
  };
  var cnjRules = [
    [/when の意味はどれ/, 'o-when-imi'],
    [/because の意味はどれ/, 'o-because-imi'],
    [/if の意味はどれ/, 'o-if-imi'],
    [/机の上に本が1冊/, 'o-thereis-kuho'],
    [/りんごが3つあります/, 'o-thereare-eibun'],
    [/疲れていたので早く寝ました/, 'o-because-kuho'],
    [/I think （　） he is kind/, 'o-that-kuho'],
    [/公園に子どもは何人/, 'o-howmany-eibun'],
    [/明日晴れたら、公園へ/, 'o-if-mirai'],
    [/There was no water/, 'o-therewas-imi'],
    [/母は料理をしていました/, 'o-when-eibun'],
    [/使い分けで正しいのはどれ/, 'o-tsukaiwake']
  ];

  WRAP('genPastBe8', 'e8-past', pastPool, pastRules, 12);
  WRAP('genFuture8', 'e8-future', futPool, futRules, 12);
  WRAP('genModal8', 'e8-modal', modPool, modRules, 12);
  WRAP('genToInf8', 'e8-toinf', infPool, infRules, 12);
  WRAP('genGerund8', 'e8-gerund', gerPool, gerRules, 12);
  WRAP('genCompare8', 'e8-compare', cmpPool, cmpRules, 13);
  WRAP('genConj8', 'e8-conj', cnjPool, cnjRules, 12);
})();
