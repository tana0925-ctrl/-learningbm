/* ============================================================
   小学校 修行 追加パック g4y v1（2026-11-19）4年の 足りない 単元を 追加 ＋ 外国語活動（3・4年）の 英語
   算数4年：大きい数（億・兆）・角の大きさ・折れ線グラフと整理・垂直と平行と四角形・直方体と立方体・小数のしくみ・変わり方
   英語（小3・小4・新設）：あいさつと気持ち・数と色と形・アルファベット・曜日と時こく と 好きなもの
   ※ 問題文は すべて オリジナル。public/index.html は 変えずに window 経由で 足す
   ============================================================ */
(function () {
  if (window.__G4Y__) return;
  window.__G4Y__ = 1;
  var R = function (a, b) { return Math.floor(Math.random() * (b - a + 1)) + a; };
  var P = function (a) { return a[R(0, a.length - 1)]; };
  var bank = function (b) { return (typeof _pickBank === 'function') ? _pickBank(b) : null; };
  var Q = function (q, correct, wrongs) { return { q: q, correct: correct, wrongs: wrongs }; };

  /* ═════════════ 算数 4年 ═════════════ */
  window.genOku4 = function () {
    var p = R(0, 6), a;
    if (p === 0) { a = R(2, 9); return bank([Q('1億を ' + a + 'こ 集めた 数を 数字で 書くと？', a + '00000000', [a + '0000000', a + '000000000', a + '000000'])]); }
    if (p === 1) return bank([P([Q('1000万を 10こ 集めた 数は？', '1億', ['1000万', '10億', '100万']), Q('1億を 10こ 集めた 数は？', '10億', ['1億', '100億', '1兆']), Q('1000億を 10こ 集めた 数は？', '1兆', ['100億', '1000億', '10兆']), Q('一億は 0が いくつ つく 数？', '8こ', ['6こ', '7こ', '9こ'])])]);
    if (p === 2) { a = R(2, 9); var b = R(1, 9); return bank([Q(a + '億' + b + '000万 を 数字で 書くと？', a + '' + b + '0000000', [a + '' + b + '000000', a + '0' + b + '000000', a + '' + b + '00000000'])]); }
    if (p === 3) { a = R(2, 9); return { q: a + '0億 は 1億を 何こ 集めた 数？', ans: a * 10 }; }
    if (p === 4) { a = R(2, 9); return bank([Q(a + '00万 を 10倍 した 数は？', a + '000万', [a + '0万', a + '億', a + '00万'])]); }
    if (p === 5) { a = R(2, 9) * 10; return bank([Q(a + '億 を 10で わった 数は？', (a / 10) + '億', [(a * 10) + '億', a + '00万', a + '万'])]); }
    var x = R(2, 9), y = R(2, 9); return { q: x + '万 × ' + y + '00 は 何万？', ans: x * y * 100 };
  };

  window.genKakudo4 = function () {
    var p = R(0, 6), a;
    if (p === 0) return bank([P([Q('直角は 何度？', '90°', ['180°', '45°', '360°']), Q('半回転の 角は 何度？', '180°', ['90°', '360°', '270°']), Q('1回転の 角は 何度？', '360°', ['180°', '90°', '270°']), Q('角の 大きさを はかる 道具は？', '分度器', ['コンパス', '三角定規', 'ものさし']), Q('三角定規の 2まいの 角を 合わせて できない 角は？', '50°', ['75°', '105°', '135°'])])]);
    if (p === 1) { a = R(20, 160); return { q: '一直線（180°）を 2つに 分けた。\n一方が ' + a + '° のとき、もう一方は 何度？', ans: 180 - a }; }
    if (p === 2) { a = R(10, 350); return { q: '1回転（360°）の うち ' + a + '° を ひいた のこりの 角は 何度？', ans: 360 - a }; }
    if (p === 3) { a = P([30, 45, 60]); var b = P([30, 45, 60, 90]); return { q: '三角定規の ' + a + '° と ' + b + '° の 角を 合わせると 何度？', ans: a + b }; }
    if (p === 4) { a = R(181, 350); return bank([Q(a + '° の 角を はかる くふうとして よいのは？', '360° から のこりの 角を ひく', ['90° を たす', 'はかれない', '180° で わる'])]); }
    if (p === 5) { a = R(2, 5); return { q: '時計の 長い はりが ' + a * 5 + '分 進むと、何度 回る？', ans: a * 30 }; }
    a = R(20, 70); return { q: '2本の 直線が 交わって できた 角の 1つが ' + a + '° です。\n向かい合う 角（対頂角）は 何度？', ans: a };
  };

  var GRAPH4 = [
    Q('気温の 変わり方を 表すのに いちばん よい グラフは？', '折れ線グラフ', ['棒グラフ', '円グラフ', '絵グラフ']),
    Q('すきな 遊びの 人数を くらべるのに よい グラフは？', '棒グラフ', ['折れ線グラフ', '帯グラフ', '線グラフ']),
    Q('折れ線グラフで、線の かたむきが 急な ところは？', '変わり方が 大きい', ['変わり方が 小さい', '変わらない', '数が 0']),
    Q('折れ線グラフで、線が 右下がりの ところは？', 'へっている', ['ふえている', '変わらない', 'わからない']),
    Q('折れ線グラフで、線が 横に まっすぐ の ところは？', '変わらない', ['ふえている', 'へっている', '急に ふえた']),
    Q('折れ線グラフで、目もりの とちゅうを 省く ときに 使う 印は？', '〰（波線）', ['矢印', '星印', '丸印']),
    Q('2つの ことがらを 同時に 整理する 表を 何と いう？', '二次元の 表', ['帯グラフ', '折れ線グラフ', '時間割']),
    Q('グラフの 表題に 書く ことは？', '何を 表した グラフか', ['かいた 人の 名前だけ', '色の 名前', '日付だけ']),
    Q('折れ線グラフの 横の じくに 書く ことが 多いのは？', '時こくや 月など 時間', ['人数', '気温', '重さ']),
    Q('「月ごとの 気温」と「月ごとの 降水量」を 1つに かく とき よく 使うのは？', '折れ線グラフと 棒グラフの 組み合わせ', ['円グラフ', '絵グラフ', '帯グラフだけ'])
  ];
  window.genGraph4 = function () { return bank(GRAPH4); };

  var SHIKAKU4 = [
    Q('2本の 直線が 直角に 交わる とき、2本の 直線は どう なっている？', '垂直', ['平行', 'ねじれ', '対角']),
    Q('1本の 直線に 垂直な 2本の 直線は どう なっている？', '平行', ['垂直', '交わる', '重なる']),
    Q('平行な 2本の 直線の はばは？', 'どこも 等しい', ['だんだん 広く なる', 'だんだん せまく なる', 'ばらばら']),
    Q('向かい合った 1組の 辺が 平行な 四角形は？', '台形', ['平行四辺形', 'ひし形', '長方形']),
    Q('向かい合った 2組の 辺が それぞれ 平行な 四角形は？', '平行四辺形', ['台形', '三角形', '五角形']),
    Q('4つの 辺の 長さが みんな 等しい 四角形で、正方形 以外は？', 'ひし形', ['長方形', '台形', '平行四辺形']),
    Q('平行四辺形の 向かい合った 角の 大きさは？', '等しい', ['足すと 90°', 'ちがう', '2倍']),
    Q('ひし形の 2本の 対角線は どう 交わる？', '垂直に 交わる', ['平行', '交わらない', '45°で 交わる']),
    Q('長方形の 2本の 対角線の 長さは？', '等しい', ['ちがう', '一方が 2倍', '交わらない']),
    Q('正方形の 対角線の 特ちょうで 正しいのは？', '長さが 等しく、垂直に 交わる', ['長さが ちがう', '平行', '交わらない']),
    Q('四角形の 向かい合った 頂点を むすんだ 直線を 何と いう？', '対角線', ['辺', '垂線', '平行線']),
    Q('平行四辺形の 向かい合った 辺の 長さは？', '等しい', ['ちがう', '2倍', '必ず 4cm'])
  ];
  window.genShikaku4 = function () {
    if (R(0, 3)) return bank(SHIKAKU4);
    var a = R(40, 140); return { q: '平行四辺形の 1つの 角が ' + a + '° です。\nとなりの 角は 何度？', ans: 180 - a };
  };

  var RIPPOU4 = [
    Q('直方体の 面の 数は？', '6', ['8', '12', '4']), Q('直方体の 辺の 数は？', '12', ['6', '8', '10']), Q('直方体の 頂点の 数は？', '8', ['6', '12', '4']),
    Q('正方形だけで かこまれた 箱の 形は？', '立方体', ['直方体', '三角柱', '円柱']),
    Q('直方体で、1つの 面に 平行な 面は いくつ？', '1つ', ['2つ', '4つ', '0']),
    Q('直方体で、1つの 面に 垂直な 面は いくつ？', '4つ', ['1つ', '2つ', '6つ']),
    Q('直方体を 切り開いて 平面に 広げた 図を 何と いう？', '展開図', ['見取図', '設計図', '地図']),
    Q('直方体の 全体の 形が わかる ように かいた 図を 何と いう？', '見取図', ['展開図', '平面図', '略図']),
    Q('平面上の 点の 位置を 表す のに 必要な ものは？', '横と たての 2つの 数', ['1つの 数', '3つの 数', '色']),
    Q('空間の 点の 位置を 表す のに 必要な ものは？', '横・たて・高さ の 3つの 数', ['横と たて の 2つ', '1つの 数', '方位だけ']),
    Q('立方体の 展開図で、向かい合う 面は 展開図で どう なる？', 'となり合わない', ['かならず となり合う', '重なる', 'ない']),
    Q('直方体の 1つの 頂点に 集まる 辺の 数は？', '3', ['2', '4', '6'])
  ];
  window.genRippou4 = function () { return bank(RIPPOU4); };

  window.genShosu4 = function () {
    var p = R(0, 5), a;
    if (p === 0) return bank([P([Q('0.01を 10こ 集めた 数は？', '0.1', ['1', '0.001', '0.01']), Q('0.1を 10こ 集めた 数は？', '1', ['0.01', '10', '0.1']), Q('0.001は 0.01の 何分の1？', '10分の1', ['100分の1', '10倍', '同じ']), Q('2.35 の「5」は 何の位？', '100分の1の位', ['10分の1の位', '一の位', '1000分の1の位'])])]);
    if (p === 1) { a = R(101, 999); return { q: '0.001を ' + a + 'こ 集めた 数は？', ans: a / 1000 }; }
    if (p === 2) { a = R(11, 99) / 100; return { q: a + ' を 10倍 した 数は？', ans: Math.round(a * 1000) / 100 }; }
    if (p === 3) { a = R(11, 99) / 10; return { q: a + ' を 10で わった 数は？', ans: Math.round(a * 100) / 1000 }; }
    if (p === 4) { a = R(1001, 9999); return { q: a + 'm は 何km？', ans: a / 1000 }; }
    var x = R(11, 99) / 100, y = R(11, 99) / 100; return { q: x + ' ＋ ' + y + ' ＝ ？', ans: Math.round((x + y) * 100) / 100 };
  };

  window.genKawari4 = function () {
    var p = R(0, 3), n = R(3, 9), k;
    if (p === 0) { k = R(10, 20); return { q: '全部で ' + k + 'この あめを 2人で 分けます。\n姉が □こ のとき 妹は ○こ。□が ' + Math.min(n, k - 1) + ' のとき ○は？', ans: k - Math.min(n, k - 1) }; }
    if (p === 1) return { q: '1辺 □cm の 正方形の まわりの 長さは ○cm。\n□が ' + n + ' のとき ○は？', ans: n * 4 };
    if (p === 2) { k = R(2, 5); return { q: 'だんを □だん つむと、高さが ○cm に なります（1だん ' + k + 'cm）。\n□が ' + n + ' のとき ○は？', ans: n * k }; }
    k = R(5, 9); return { q: 'まわりの 長さが ' + (k * 4) + 'cm の 長方形で、たてが □cm、横が ○cm。\nたてが ' + Math.min(n, k * 2 - 1) + 'cm のとき 横は？', ans: k * 2 - Math.min(n, k * 2 - 1) };
  };

  /* ═════════════ 英語 3・4年（外国語活動）═════════════ */
  var GREET = [
    Q('朝の あいさつは？', 'Good morning.', ['Good night.', 'Goodbye.', 'Thank you.']),
    Q('昼の あいさつ（こんにちは）は？', 'Good afternoon.', ['Good morning.', 'Good night.', 'See you.']),
    Q('ねる 前の あいさつは？', 'Good night.', ['Good morning.', 'Hello.', 'Good afternoon.']),
    Q('「元気ですか？」は？', 'How are you?', ['What\'s this?', 'Who are you?', 'Where are you?']),
    Q('How are you?　に「元気です」と 答える', 'I\'m fine.', ['I\'m Ken.', 'I\'m ten.', 'Yes, I do.']),
    Q('I\'m hungry. の 意味は？', 'おなかが すいた。', ['ねむい。', 'うれしい。', 'のどが かわいた。']),
    Q('I\'m sleepy. の 意味は？', 'ねむい。', ['うれしい。', 'かなしい。', 'つかれた。']),
    Q('I\'m happy. の 意味は？', 'うれしい。', ['かなしい。', 'ねむい。', 'こわい。']),
    Q('「さようなら」は？', 'Goodbye.', ['Hello.', 'Good morning.', 'Thank you.']),
    Q('「ありがとう」は？', 'Thank you.', ['Sorry.', 'Hello.', 'Please.']),
    Q('「わたしの 名前は ゆきです。」', 'My name is Yuki.', ['I like Yuki.', 'This is Yuki name.', 'Yuki is name.']),
    Q('「はじめまして。」', 'Nice to meet you.', ['See you.', 'How are you?', 'Good night.'])
  ];
  window.genGreet34E = function () { return bank(GREET); };
  var NUM = ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten', 'eleven', 'twelve', 'thirteen', 'fourteen', 'fifteen', 'sixteen', 'seventeen', 'eighteen', 'nineteen', 'twenty'];
  var COL = [['🔴', 'red', '赤'], ['🔵', 'blue', '青'], ['🟡', 'yellow', '黄色'], ['🟢', 'green', '緑'], ['⚫', 'black', '黒'], ['⚪', 'white', '白'], ['🟣', 'purple', 'むらさき'], ['🟠', 'orange', 'オレンジ色'], ['🟤', 'brown', '茶色'], ['🩷', 'pink', 'ピンク']];
  var SHAPE = [['⭕', 'circle', '丸'], ['🔺', 'triangle', '三角'], ['⬛', 'square', '四角'], ['⭐', 'star', '星'], ['❤️', 'heart', 'ハート'], ['💎', 'diamond', 'ひし形']];
  var three = function (arr, k, ok) { var c = arr.filter(function (x) { return x[k] !== ok; }), o = []; while (o.length < 3) o.push(c.splice(R(0, c.length - 1), 1)[0][k]); return o; };
  window.genNumCol34E = function () {
    var p = R(0, 3);
    if (p === 0) { var n = R(1, 20), w = []; while (w.length < 3) { var z = NUM[R(1, 20)]; if (z !== NUM[n] && w.indexOf(z) < 0) w.push(z); } return bank([Q(n + ' を 英語で 言うと？', NUM[n], w)]); }
    if (p === 1) { var c = P(COL); return bank([Q('この 色は 英語で？\n' + c[0], c[1], three(COL, 1, c[1]))]); }
    if (p === 2) { var s = P(SHAPE); return bank([Q('この 形は 英語で？\n' + s[0], s[1], three(SHAPE, 1, s[1]))]); }
    var a = R(1, 9), b = R(1, 10 - a), ww = []; while (ww.length < 3) { var y = NUM[R(1, 20)]; if (y !== NUM[a + b] && ww.indexOf(y) < 0) ww.push(y); } return bank([Q(NUM[a] + ' plus ' + NUM[b] + ' is ？', NUM[a + b], ww)]);
  };
  window.genAbc34E = function () {
    var U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', i = R(0, 25), p = R(0, 3), L = U[i], l = L.toLowerCase();
    var other = function (s, ok) { var o = []; while (o.length < 3) { var z = s[R(0, 25)]; if (z !== ok && o.indexOf(z) < 0) o.push(z); } return o; };
    if (p === 0) return bank([Q('大文字「' + L + '」の 小文字は？', l, other(U.toLowerCase(), l))]);
    if (p === 1) return bank([Q('小文字「' + l + '」の 大文字は？', L, other(U, L))]);
    if (p === 2 && i < 25) return bank([Q('「' + L + '」の 次の アルファベットは？', U[i + 1], other(U, U[i + 1]))]);
    var pairs = [['b', 'd'], ['p', 'q'], ['m', 'n'], ['u', 'n'], ['h', 'n']], pr = P(pairs), ex = 'acefgijkrstvwxyz'.split('').sort(function () { return Math.random() - 0.5; }); return bank([Q('小文字の「' + pr[0] + '」は どれ？（にている 文字に 注意）', pr[0], [pr[1], ex[0], ex[1]])]);
  };
  var DAY = [['月曜日', 'Monday'], ['火曜日', 'Tuesday'], ['水曜日', 'Wednesday'], ['木曜日', 'Thursday'], ['金曜日', 'Friday'], ['土曜日', 'Saturday'], ['日曜日', 'Sunday']];
  var LIKE = [
    Q('「わたしは いちごが 好きです。」', 'I like strawberries.', ['I have strawberries.', 'I am strawberries.', 'I want go strawberries.']),
    Q('Do you like apples?　に「はい」で 答える', 'Yes, I do.', ['Yes, I am.', 'No, I don\'t.', 'Yes, it is.']),
    Q('What do you like?　の 意味は？', '何が 好きですか？', ['これは 何ですか？', 'どこが 好き？', 'だれが 好き？']),
    Q('What\'s this?　の 意味は？', 'これは 何ですか？', ['これは だれ？', 'どこですか？', '何時ですか？']),
    Q('What time is it?　の 意味は？', '何時ですか？', ['何曜日ですか？', '何才ですか？', 'いくつですか？']),
    Q('It\'s 3 o\'clock. の 意味は？', '3時です。', ['3才です。', '3こです。', '3日です。']),
    Q('What day is it today?　の 意味は？', '今日は 何曜日？', ['今日は 何日？', '今日は 何時？', '今日は 晴れ？']),
    Q('「〜を ください。」と たのむ ことば', '〜, please.', ['Thank you.', 'Sorry.', 'Hello.'])
  ];
  window.genDayLike34E = function () {
    if (R(0, 1)) { var d = P(DAY), wr = DAY.filter(function (x) { return x !== d; }).map(function (x) { return x[1]; }).sort(function () { return Math.random() - 0.5; }).slice(0, 3); return R(0, 1) ? bank([Q(d[0] + 'は 英語で？', d[1], wr)]) : bank([Q('「' + d[1] + '」は 何曜日？', d[0], DAY.filter(function (x) { return x !== d; }).map(function (x) { return x[0]; }).slice(0, 3))]); }
    return bank(LIKE);
  };

  var ADD = {
    math: { 4: [
      { id: 'm4-oku', name: '大きい数（億・兆）', icon: '🌌', color: 'indigo', gen: 'genOku4', input: 'numpad', desc: '億・兆の しくみ' },
      { id: 'm4-kakudo', name: '角の大きさ', icon: '📐', color: 'orange', gen: 'genKakudo4', input: 'numpad', desc: '分度器・直角・180°・360°' },
      { id: 'm4-graph', name: '折れ線グラフと整理', icon: '📉', color: 'green', gen: 'genGraph4', input: 'mcq', desc: '変わり方・二次元の表' },
      { id: 'm4-shikaku', name: '垂直・平行と四角形', icon: '▱', color: 'teal', gen: 'genShikaku4', input: 'numpad', desc: '台形・平行四辺形・ひし形・対角線' },
      { id: 'm4-rippou', name: '直方体と立方体', icon: '📦', color: 'amber', gen: 'genRippou4', input: 'mcq', desc: '面・辺・頂点・展開図・位置' },
      { id: 'm4-shosu', name: '小数のしくみ', icon: '🔟', color: 'blue', gen: 'genShosu4', input: 'numpad', desc: '0.01・0.001・10倍・1/10' },
      { id: 'm4-kawari', name: '変わり方', icon: '🔁', color: 'pink', gen: 'genKawari4', input: 'numpad', desc: '□と○の 関係' }
    ] },
    english: {
      3: [
        { id: 'e3-greet', name: 'あいさつ・気持ち', icon: '👋', color: 'orange', gen: 'genGreet34E', input: 'mcq', desc: 'Hello / How are you?' },
        { id: 'e3-numcol', name: '数・色・形', icon: '🎨', color: 'pink', gen: 'genNumCol34E', input: 'mcq', desc: 'one〜twenty / red / circle' }
      ],
      4: [
        { id: 'e4-abc', name: 'アルファベット', icon: '🔠', color: 'sky', gen: 'genAbc34E', input: 'mcq', desc: '大文字・小文字' },
        { id: 'e4-daylike', name: '曜日・時こく・好きなもの', icon: '🗓️', color: 'green', gen: 'genDayLike34E', input: 'mcq', desc: 'Monday / What time is it? / I like 〜' }
      ]
    }
  };
  var DISP = {
    'm4-oku': { name: '星空の 大数', emoji: '🌌', desc: '大きい数' }, 'm4-kakudo': { name: '角度の 風車', emoji: '📐', desc: '角の大きさ' }, 'm4-graph': { name: 'グラフの 牧場', emoji: '📉', desc: '折れ線グラフ' },
    'm4-shikaku': { name: '四角形の 城壁', emoji: '▱', desc: '垂直・平行と四角形' }, 'm4-rippou': { name: '箱の 倉庫', emoji: '📦', desc: '直方体と立方体' }, 'm4-shosu': { name: '小数の 川', emoji: '🔟', desc: '小数のしくみ' }, 'm4-kawari': { name: '変わり方の 坂', emoji: '🔁', desc: '変わり方' },
    'e3-greet': { name: 'あいさつの 門', emoji: '👋', desc: 'あいさつ' }, 'e3-numcol': { name: 'いろかずの 花畑', emoji: '🎨', desc: '数・色・形' }, 'e4-abc': { name: 'ABCの 小道', emoji: '🔠', desc: 'アルファベット' }, 'e4-daylike': { name: 'まいにちの 時計台', emoji: '🗓️', desc: '曜日・時こく' }
  };
  var LABEL = { 1: '小1', 2: '小2', 3: '小3', 4: '小4', 5: '小5', 6: '小6' };
  function addAll() {
    try {
      var C = window.CURRICULUM; if (!C) return false;
      Object.keys(ADD).forEach(function (sk) {
        var S = C[sk]; if (!S) return; S.grades = S.grades || {};
        Object.keys(ADD[sk]).forEach(function (g) {
          var G = S.grades[g]; if (!G) G = S.grades[g] = { label: LABEL[g] || g, units: [] };
          var have = {}; G.units.forEach(function (u) { have[u.id] = 1; });
          ADD[sk][g].forEach(function (u) { if (!have[u.id]) G.units.push(u); });
        });
      });
      window.UNIT_DISPLAY = window.UNIT_DISPLAY || {};
      Object.keys(DISP).forEach(function (k) { if (!window.UNIT_DISPLAY[k]) window.UNIT_DISPLAY[k] = DISP[k]; });
      return true;
    } catch (e) { return false; }
  }
  if (!addAll()) { var tries = 0, t = setInterval(function () { if (addAll() || ++tries > 40) clearInterval(t); }, 250); }
})();
