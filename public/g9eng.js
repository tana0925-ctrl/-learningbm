/* ============================================================
   中3英語 単元パック v180（ネットレ対応 第6弾）
   受け身 / 現在完了 / 不定詞の応用 / 分詞(後置修飾) / 関係代名詞 / 間接疑問文
   基礎40%・標準40%・発展20% 混合ランダム（4択）
   ============================================================ */
(function () {
  var G9 = window.G9; if (!G9) return;
  var R = G9.R, pick = G9.pick, Q = G9.q;

  // ① 受け身
  function genPassive9() {
    var r = R(1, 10), t;
    if (r <= 4) {
      t = R(0, 2);
      if (t === 0) return Q('基礎', '受け身（受動態）の基本の形はどれ？', 'be動詞 + 過去分詞', ['be動詞 + 現在分詞(ing)', 'have + 過去分詞', 'do + 動詞の原形']);
      if (t === 1) return Q('基礎', '「英語は世界中で話されています。」\nEnglish （　） all over the world.', 'is spoken', ['speaks', 'is speaking', 'spoke']);
      return Q('基礎', 'This letter （　） by Ken.（この手紙はケンによって書かれました）', 'was written', ['wrote', 'is writing', 'writes']);
    }
    if (r <= 8) {
      t = R(0, 2);
      if (t === 0) return Q('標準', '受け身で「〜によって」を表す語はどれ？', 'by', ['with', 'of', 'to']);
      if (t === 1) return Q('標準', '「この本は多くの人に読まれています。」\nThis book （　） by many people.', 'is read', ['reads', 'is reading', 'read']);
      return Q('標準', 'The window was broken. の意味はどれ？', '窓は割られた', ['窓を割った', '窓が割れている最中だ', '窓を割るだろう']);
    }
    t = R(0, 1);
    if (t === 0) return Q('発展', '「その山は雪でおおわれています。」\nThe mountain is covered （　） snow.', 'with', ['by', 'of', 'in']);
    return Q('発展', 'Is this picture painted by him? への答えとして正しいのは？', 'Yes, it is.', ['Yes, he is.', 'Yes, he does.', 'Yes, it does.']);
  }

  // ② 現在完了
  function genPerfect9() {
    var r = R(1, 10), t;
    if (r <= 4) {
      t = R(0, 2);
      if (t === 0) return Q('基礎', '現在完了の形はどれ？', 'have(has) + 過去分詞', ['be動詞 + 過去分詞', 'have + 現在分詞', 'did + 過去分詞']);
      if (t === 1) return Q('基礎', '「私は3回京都を訪れたことがあります。」\nI have （　） Kyoto three times.', 'visited', ['visit', 'visiting', 'visits']);
      return Q('基礎', '主語が He のとき、現在完了は「（　）+過去分詞」。（　）に入るのは？', 'has', ['have', 'had', 'is']);
    }
    if (r <= 8) {
      t = R(0, 3);
      if (t === 0) return Q('標準', '「もう宿題を終えましたか。」\n（　） you finished your homework yet?', 'Have', ['Do', 'Are', 'Did']);
      if (t === 1) return Q('標準', '経験用法でよく使う「一度も〜ない」を表す語はどれ？', 'never', ['just', 'already', 'yet']);
      if (t === 2) return Q('標準', '「私は2010年からずっと東京に住んでいます。」\nI have lived in Tokyo （　） 2010.', 'since', ['for', 'from', 'in']);
      return Q('標準', '「私は5年間ずっと英語を勉強しています。」\nI have studied English （　） five years.', 'for', ['since', 'during', 'ago']);
    }
    t = R(0, 1);
    if (t === 0) return Q('発展', 'I have just finished lunch. の「just」の意味・用法はどれ？', '完了（ちょうど〜したところ）', ['経験（〜したことがある）', '継続（ずっと〜している）', '過去（〜した）']);
    return Q('発展', 'Have you ever been to Okinawa? の意味はどれ？', '沖縄に行ったことがありますか', ['沖縄にいますか', '沖縄に行きますか', '沖縄はどこですか']);
  }

  // ③ 不定詞の応用
  function genToinf9() {
    var r = R(1, 10), t;
    if (r <= 4) {
      t = R(0, 2);
      if (t === 0) return Q('基礎', '「英語を勉強することは大切です。」\n（　） is important to study English.', 'It', ['That', 'This', 'There']);
      if (t === 1) return Q('基礎', '「私はあなたに手伝ってほしい。」\nI want you （　） help me.', 'to', ['for', 'of', 'that']);
      return Q('基礎', 'It is fun to play soccer. の It が指すのはどれ？', 'to play soccer（形式主語）', ['soccer', 'fun', '天気']);
    }
    if (r <= 8) {
      t = R(0, 2);
      if (t === 0) return Q('標準', '「その問題を解くことは私には難しい。」\nIt is difficult （　） me to solve the problem.', 'for', ['to', 'of', 'with']);
      if (t === 1) return Q('標準', '「母は私に部屋をそうじするように言った。」\nMy mother told me （　） clean my room.', 'to', ['for', 'that', 'of']);
      return Q('標準', '「私は次に何をすべきか分からない。」\nI don’t know what （　） do next.', 'to', ['for', 'of', 'that']);
    }
    t = R(0, 1);
    if (t === 0) return Q('発展', '「先生は私たちに静かにするように頼んだ。」\nThe teacher asked us （　） quiet.', 'to be', ['being', 'be', 'to being']);
    return Q('発展', 'It is kind of you to help me. で of が使われる理由はどれ？', '人の性質を表す形容詞(kind)だから', ['難しさを表す形容詞だから', '主語が物だから', '過去の文だから']);
  }

  // ④ 分詞（後置修飾）
  function genBunshi9() {
    var r = R(1, 10), t;
    if (r <= 4) {
      t = R(0, 2);
      if (t === 0) return Q('基礎', '「走っている少年」を英語にすると？（後ろから修飾）', 'the boy running', ['the boy run', 'the running boy over', 'the boy to run']);
      if (t === 1) return Q('基礎', '「〜している」と能動的に名詞を修飾するのはどちらの分詞？', '現在分詞（-ing）', ['過去分詞', '原形不定詞', 'to不定詞']);
      return Q('基礎', '「〜された」と受動的に名詞を修飾するのはどちらの分詞？', '過去分詞', ['現在分詞（-ing）', '原形', '動名詞']);
    }
    if (r <= 8) {
      t = R(0, 2);
      if (t === 0) return Q('標準', '「これは英語で書かれた本です。」\nThis is a book （　） in English.', 'written', ['writing', 'write', 'wrote']);
      if (t === 1) return Q('標準', '「向こうで泳いでいる女の子はメアリーです。」\nThe girl （　） over there is Mary.', 'swimming', ['swum', 'swim', 'to swim']);
      return Q('標準', '「木の下でねむっているねこ」を英語にすると？', 'the cat sleeping under the tree', ['the cat slept under the tree', 'the sleeping cat under to the tree', 'the cat sleep under the tree']);
    }
    t = R(0, 1);
    if (t === 0) return Q('発展', 'the language spoken in Canada の意味はどれ？', 'カナダで話されている言語', ['カナダを話す言語', 'カナダで話す言語', 'カナダが話した言語']);
    return Q('発展', 'a girl playing the piano と a piano played by a girl のちがいの説明で正しいのは？', '前者は現在分詞で能動、後者は過去分詞で受動', ['どちらも同じ意味', '前者は過去、後者は未来', '前者が受動、後者が能動']);
  }

  // ⑤ 関係代名詞
  function genKankei9() {
    var r = R(1, 10), t;
    if (r <= 4) {
      t = R(0, 2);
      if (t === 0) return Q('基礎', '先行詞が「人」で主格のとき使う関係代名詞はどれ？', 'who', ['which', 'whose', 'where']);
      if (t === 1) return Q('基礎', '先行詞が「物・動物」で主格のとき使う関係代名詞はどれ？', 'which', ['who', 'whom', 'when']);
      return Q('基礎', '「これは京都へ行くバスです。」\nThis is the bus （　） goes to Kyoto.', 'which', ['who', 'whose', 'where']);
    }
    if (r <= 8) {
      t = R(0, 2);
      if (t === 0) return Q('標準', '「私には音楽が好きな友達がいます。」\nI have a friend （　） likes music.', 'who', ['which', 'what', 'whose']);
      if (t === 1) return Q('標準', '人・物どちらの先行詞にも使え、目的格にもなる関係代名詞はどれ？', 'that', ['who', 'which', 'whose']);
      return Q('標準', '「これは私が昨日読んだ本です。」\nThis is the book （　） I read yesterday.', 'which', ['who', 'whose', 'where']);
    }
    t = R(0, 1);
    if (t === 0) return Q('発展', '目的格の関係代名詞が省略できるのはどんなとき？', '関係代名詞のあとに〈主語＋動詞〉が続くとき', ['先行詞が人のとき', '関係代名詞が主格のとき', '文が疑問文のとき']);
    return Q('発展', '「私には父が医者である友達がいます。」\nI have a friend （　） father is a doctor.', 'whose', ['who', 'which', 'that']);
  }

  // ⑥ 間接疑問文
  function genKansetsu9() {
    var r = R(1, 10), t;
    if (r <= 4) {
      t = R(0, 2);
      if (t === 0) return Q('基礎', '間接疑問文では、疑問詞のあとの語順はどうなる？', '〈主語＋動詞〉の順（ふつうの文の語順）', ['〈動詞＋主語〉の順', '疑問文の語順のまま', '語順は自由']);
      if (t === 1) return Q('基礎', '「私は彼がどこに住んでいるか知っています。」\nI know where （　）.', 'he lives', ['does he live', 'lives he', 'he live']);
      return Q('基礎', 'Do you know what this is? の下線部 what this is の語順として正しいのは？', 'what + 主語(this) + 動詞(is)', ['what + 動詞(is) + 主語(this)', 'what is this のまま', 'this what is']);
    }
    if (r <= 8) {
      t = R(0, 2);
      if (t === 0) return Q('標準', '「あなたは彼が何時に来るか知っていますか。」\nDo you know what time （　）?', 'he will come', ['will he come', 'does he come', 'come he']);
      if (t === 1) return Q('標準', '「私は彼女が何歳か知りません。」\nI don’t know how old （　）.', 'she is', ['is she', 'she does', 'old she is']);
      return Q('標準', '2つの文をつなぐ:\nI don’t know. + Where does he live? を1文にすると？', 'I don’t know where he lives.', ['I don’t know where does he live.', 'I don’t know where he live.', 'I don’t know where lives he.']);
    }
    t = R(0, 1);
    if (t === 0) return Q('発展', 'Tell me. + What did you buy? を間接疑問文にすると？', 'Tell me what you bought.', ['Tell me what did you buy.', 'Tell me what you buy.', 'Tell me what bought you.']);
    return Q('発展', 'I wonder if he is at home. の if の意味はどれ？', '〜かどうか', ['もし〜なら', '〜のとき', '〜だから']);
  }

  try {
    window.genPassive9 = genPassive9;
    window.genPerfect9 = genPerfect9;
    window.genToinf9 = genToinf9;
    window.genBunshi9 = genBunshi9;
    window.genKankei9 = genKankei9;
    window.genKansetsu9 = genKansetsu9;
  } catch (e) {}

  G9.addUnits('english', [
    { id: 'e9-passive', name: '受け身', icon: '🔄', color: 'blue', gen: 'genPassive9', input: 'mcq', desc: 'be動詞+過去分詞' },
    { id: 'e9-perfect', name: '現在完了', icon: '⏳', color: 'green', gen: 'genPerfect9', input: 'mcq', desc: '経験・継続・完了' },
    { id: 'e9-toinf', name: '不定詞の応用', icon: '🎯', color: 'orange', gen: 'genToinf9', input: 'mcq', desc: 'It is...to / want 人 to' },
    { id: 'e9-bunshi', name: '分詞（後置修飾）', icon: '✂️', color: 'purple', gen: 'genBunshi9', input: 'mcq', desc: '現在分詞・過去分詞' },
    { id: 'e9-kankei', name: '関係代名詞', icon: '🔗', color: 'red', gen: 'genKankei9', input: 'mcq', desc: 'who / which / that' },
    { id: 'e9-kansetsu', name: '間接疑問文', icon: '❓', color: 'teal', gen: 'genKansetsu9', input: 'mcq', desc: '疑問詞+主語+動詞' }
  ]);
  G9.addDisplay({
    'e9-passive': { name: '受け身の工房', emoji: '🔄', desc: '受け身（中3英語）' },
    'e9-perfect': { name: '現在完了の時計塔', emoji: '⏳', desc: '現在完了（中3英語）' },
    'e9-toinf': { name: '不定詞の的当て場', emoji: '🎯', desc: '不定詞の応用（中3英語）' },
    'e9-bunshi': { name: '分詞の裁縫室', emoji: '✂️', desc: '分詞（中3英語）' },
    'e9-kankei': { name: '関係代名詞の連結橋', emoji: '🔗', desc: '関係代名詞（中3英語）' },
    'e9-kansetsu': { name: '間接疑問の迷宮', emoji: '❓', desc: '間接疑問文（中3英語）' }
  });
})();
