/* 🐯 HSADVICE_CHAT_V1 阪神マンのアドバイス（修行の画面）を 対話の 形に — 2026-11-12
 *  ・これまで：質問 → えらぶ → 答えに 画面が おきかわる（前の やりとりが 消える）。
 *  ・これから：阪神マンと 子どもの ふきだしが 下に つみかさなる。えらんだ ことばも 子どもの ふきだしで のこる。
 *    答えの あとに「わかった！」「ほかのことも 聞く」（算数の 単元なら「🔍 理解度チェック」も）を 出す。
 *  ・中身（HANSHIN_ADVICE_TREE）は そのまま つかう。言い方は 日ごとに すこし かわる。
 *  ・HSADVICE_CHAT_V2（2026-11-13 先生の指示）見た目を 家庭学習の 阪神マン（hschat）と おなじ 画面に：
 *    上に 黄色い 見出し＋とじる、まんなかに 顔つきの ふきだし、下に 大きい えらぶボタン（2れつ）。
 *  ・index.html は 手で 編集しない（window.HanshinManSystem の render などを おきかえる）。
 */
(function () {
  'use strict';
  if (window.__HSADVICE_CHAT_V1__) return; window.__HSADVICE_CHAT_V1__ = 1;

  function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); }
  function dayN() { return Math.floor((Date.now() + 9 * 3600000) / 86400000); }
  function vary(list, key) { var h = 0, k = String(key || ''); for (var i = 0; i < k.length; i++) h = (h + k.charCodeAt(i)) % 9973; return list[(dayN() + h) % list.length]; }
  var HELLO = ['おう、どないした？', 'よう来たな！ なんでも 聞いてや', 'お、相談か？ まかしとき！', 'ええとこに 来たな！'];
  var MORE = ['ほかに 気になること ある？', 'ほな、ほかに 何が 聞きたい？', 'まだ ありそうやな。どれや？'];
  var GOT = ['よっしゃ！ その調子で 修行 がんばってな！', 'ええぞ！ わかったら あとは 練習あるのみや！', 'さすがや！ また こまったら いつでも 呼んでな！'];
  var CHECK = ['よし、ほな 理解度チェックで たしかめてみよか！'];
  /* 🌳 HSADVICE_MORE_V1（2026-11-18 先生の指示）分岐を もっと ふやす。
     答えの あとに「🤔 まだ ちょっと わからん」→「どこで ひっかかってる？」（教科ごと）→ さらに 2つ ずつ 深く。
     いちばん 下でも わからんかったら「✏️ 阪神マンと 先生に しつもんする」（自由記述）。 */
  var A = function (text, answer, sub) { var o = { text: text, answer: answer }; if (sub) o.more = sub; return o; };
  var FOLLOW = {
    math: { question: 'よし、もうちょい いっしょに 考えよか。どこで ひっかかってる？', options: [
      A('問題文の 意味が わからん', '問題文は 3つに 分けて 読むんや！\n①わかってる こと（数字に ○）\n②聞かれてる こと（＿＿を 引く）\n③その 2つの 関係\n声に 出して ゆっくり 読むだけでも ずいぶん ちがうで。', [
        A('図に したら ええの？', 'そうや！ 線分図や 表に すると 一気に 見えるで。わかってる 数を 線の 上に、聞かれてる ところに「？」を 書く。長さの くらべっこが 目で わかるんや。'),
        A('式が 立てられへん', 'まず「ことばの 式」を 作るんや。たとえば「1こ の ねだん × こ数 ＝ 代金」。そこに わかってる 数を あてはめたら 式に なるで。いきなり 数字で 考えんでええ。')
      ]),
      A('やり方（公式）を わすれた', '公式は 丸おぼえより「なんで そうなるか」を 1回 たしかめると わすれにくいで。教科書の まとめの ページを 開いて、例題を 1つ まねして といてみ。', [
        A('おぼえ方の コツは？', '「自分の ことばで 説明」が 最強や。だれかに 教える つもりで 声に 出してみ。説明できたら、もう 忘れへんで。ノートの 1ページめに 自分だけの 公式集を 作るのも ええな。'),
        A('どこから 思い出せばええ？', '1つ 前の 学年の 技に もどるのも 作戦や。修行の 画面の「🔍 理解度チェック」で、どこまで できてるか たしかめられるで。')
      ]),
      A('計算で まちがえる', '計算ミスは「くせ」が あるんや。まちがえた 問題を 3つ 見くらべると、くせが 見えてくるで。くり上がり？ 0の 数？ 小数点？', [
        A('どこを 見直せば ええ？', '見直しは 3点 セットや！\n①小数点・単位\n②くり上がり・くり下がり\n③答えが だいたい 合ってるか（見積もり）\nとくに ③は 強いで。「だいたい いくつ」を 先に 考えとくんや。'),
        A('いそいで しまう', 'ゆっくり 1問 正かいの 方が、はやく 3問 まちがうより ずっと 力に なる。とき終わったら「1回 深呼吸 → 見直し」を セットに してみ。')
      ]),
      A('答えは 合うけど 説明できへん', 'それは あと 一歩の ところや！「まず〜、次に〜、だから〜」の 3つの ことばで 説明してみ。図を 指さしながら 言うと もっと 伝わるで。', [
        A('説明の 練習は どうやる？', '家の 人や 友だちに「この 問題、どう やると 思う？」って 聞いてから、自分の やり方を 話すんや。ちがう やり方が 出てきたら ラッキーやで。')
      ])
    ] },
    jp: { question: 'よし、もうちょい いっしょに 考えよか。どこで ひっかかってる？', options: [
      A('文章が 長くて 読めへん', '長い 文章は、まず 段落ごとに 番号を ふるんや。それから 各段落で いちばん 大事な 1文に 線を 引く。全部を 一気に わかろうと せんで ええ。', [
        A('大事な 文の 見つけ方は？', '段落の さいしょか さいごに あることが 多いで。「つまり」「このように」「だから」の あとは 大事な ことが 来る 合図や。'),
        A('とちゅうで あきてしまう', '1段落 読んだら「何の 話やった？」と 自分に 1行で 言ってみ。小さな ゴールを 作ると 読みきれるで。')
      ]),
      A('答えの 書き方が わからん', '問いの さいごの ことばを 見るんや！「なぜ」なら「〜から。」、「どんな こと」なら「〜こと。」で 終わる。聞かれ方に 答え方を 合わせるんや。', [
        A('本文の どこを 使えばええ？', '問いに 出てくる ことばを 本文で さがして、その 前後を 読むんや。答えは たいてい その 近くに かくれてるで。'),
        A('字数が あるときは？', '本文の ことばを そのまま ぬき出せるか 先に 見てみ。足りんときは 自分の ことばで 短く まとめる。字数の 8わりは うめるのが めやすや。')
      ]),
      A('漢字・言葉が おぼえられへん', 'ただ 何回も 書くより、熟語ごと・文ごと 書く方が おぼえるで。「意味」と セットに すると 忘れにくい。', [
        A('もっと 楽な 方法は？', 'テストの 前の 日だけ やるより、1日 3つずつ の 方が ずっと 残る。ねる 前に 1回 見ると 頭の 中で せいりされるで。'),
        A('にてる 漢字が ごちゃまぜ', 'ちがう ところだけ 赤で 書いて くらべるんや。部首の 意味（さんずい＝水 など）から 考えると 区別しやすいで。')
      ]),
      A('自分の 考えが 書けへん', '考えは「思った ことの たね」からで ええんや。「〜が 気に なった」「〜に びっくりした」から 書きはじめて、「なぜなら」で つなげてみ。', [
        A('理由が うまく 書けへん', '「本文の ここに 〜と 書いてあるから」と、文章の 中の しょうこを 使うんや。自分の 体験と つなげても ええで。')
      ])
    ] },
    soc: { question: 'よし、もうちょい いっしょに 考えよか。どこで ひっかかってる？', options: [
      A('言葉（用語）が おぼえられへん', '用語は「だれが・いつ・何を・なぜ」と セットで おぼえるんや。それだけで ばらばらの 言葉が つながるで。', [
        A('もっと おぼえやすく するには？', '人物なら「その人が いなかったら 何が ちがった？」と 考えてみ。ストーリーに なると 頭に 残るんや。'),
        A('にてる 言葉が まざる', '2つを 表に して「ちがう ところ」を 書き出すんや。時代・人物・目的の どれが ちがうか 見るとええで。')
      ]),
      A('「なぜ そうなったか」が わからん', '社会は「原因 → できごと → その後」の つながりで 考えるんや。矢印で 3つ つないで 図に してみ。', [
        A('原因の 見つけ方は？', 'その 時代の 人が「こまってた こと」を さがすんや。こまりごとを 解決しようと して、できごとが 起きることが 多いで。'),
        A('今の くらしと どう つながる？', '「今も のこってる もの」を さがしてみ。ことば・行事・しくみ・建物。むかしと 今が つながると 一気に おもしろく なるで。')
      ]),
      A('地図・グラフの 読み方', 'まず タイトル・たて じく・よこ じく・単位を 見るんや。それから「いちばん 多い・少ない」「ふえてる・へってる」を 1つ 言ってみ。', [
        A('グラフから 何を 書けばええ？', '「〜が ふえている（へっている）」＋「その 理由は 〜だと 考えられる」の 2文で 書くと ばっちりや。')
      ]),
      A('年代や 順番が ごちゃまぜ', '時代ごとに 1行で「どんな 時代か」を 言えるように するんや。そこに できごとを ぶらさげると 順番が くずれへんで。')
    ] },
    sci: { question: 'よし、もうちょい いっしょに 考えよか。どこで ひっかかってる？', options: [
      A('実験の 結果の 理由が わからん', '理科は「予想 → 実験 → 結果 → 考察」の 流れや。結果は「何が 起きたか」、考察は「なぜ 起きたか」。まずは 結果と 考察を 分けて 書いてみ。', [
        A('考察の 書き方は？', '「〜という 結果から、〜と いえる」が 基本の 形や。予想と くらべて、合ってたか ちがってたかも 書くと ええで。'),
        A('条件って 何？', 'くらべる ときは 1つの ことだけ 変えて、ほかは 同じに するんや。変えた ものが 原因かどうか、それで はっきりするで。')
      ]),
      A('用語が おぼえられへん', '実験の 写真や 図と セットで おぼえるんや。「この 道具で 何を した ときの 言葉か」が わかると 忘れへんで。', [
        A('図を かくと ええの？', 'そうや！ 自分で 図を かいて、矢印と 言葉を 書きこむと 一番 残る。教科書の 図を まねするだけでも ちがうで。')
      ]),
      A('グラフ・表の 読み方', '「何が ふえると 何が どう 変わるか」を 1文で 言うんや。比例してる？ ある ところで 変わらなく なる？ 形を よく 見てみ。'),
      A('計算（てこ・電流など）が にがて', '理科の 計算は きまった 式が 1つ あることが 多いで。てこなら「重さ × きょり」が 左右で 同じ。式を 先に 書いて、わかる 数を 入れるんや。')
    ] },
    gen: { question: 'よし、もうちょい いっしょに 考えよか。どこで ひっかかってる？', options: [
      A('何が わからんかも わからん', 'それ、いちばん よくある ことやで！ まずは 教科書の まとめの ページを 開いて、知ってる 言葉に ○、知らん 言葉に △ を つけてみ。△が スタート地点や。', [
        A('△が いっぱい ある', '1つずつ で ええ。△の 中から 1つ だけ えらんで 調べてみ。1つ わかると、となりの △も わかりやすく なるで。')
      ]),
      A('やる気が でえへん', '気持ちは あとから ついてくるで。「とりあえず 1問だけ」「5分だけ」で はじめてみ。はじめた 人の 勝ちや。', [
        A('つづかへん', '時間と 場所を 決めると つづくで。「ごはんの 前に 10分」みたいに。できた 日に ○を つけると、だんだん 楽しく なるんや。')
      ])
    ] }
  };
  function subjOf(k) { k = String(k || ''); var c = k.charAt(0); if (c === 'm') return 'math'; if (c === 'j' || /kanji|kokugo/.test(k)) return 'jp'; if (c === 's') return 'soc'; if (c === 'r') return 'sci'; return 'gen'; }
  // 教科の 木に「ふつうの こまりごと」を たして、ぜんぶに 印（_f）を つける
  function followFor(k) {
    var t = FOLLOW[subjOf(k)] || FOLLOW.gen, g = FOLLOW.gen;
    var opts = t.options.slice(); if (t !== g) opts = opts.concat(g.options);
    function mark(n) { n._f = 1; (n.options || []).forEach(mark); (n.more || []).forEach(mark); return n; }
    return mark({ question: t.question, options: opts });
  }

  function apiQ(url, o) { o = o || {}; o.credentials = 'include'; if (o.body) o.headers = { 'Content-Type': 'application/json' }; return fetch(url, o).then(function (r) { return r.json(); }).catch(function () { return null; }); }

  function patch() {
    var H = window.HanshinManSystem;
    if (!H || typeof H.render !== 'function') return false;
    if (H.__chatV1) return true;
    H.__chatV1 = 1;
    var log = [], open = false, pendingMe = '', skipLog = false;
    var origClose = H.close;

    var root = null, rootKey = '';
    function mode() {   // いまの 修行の 単元（ひらいた ときの 木の 根っこから さがす）
      if (rootKey) return rootKey;
      try { var T = window.HANSHIN_ADVICE_TREE || {}; for (var k in T) if (T[k] === root) { rootKey = k; break; } } catch (e) {}
      return rootKey;
    }
    function rootNode() { return root; }
    function canCheck() { try { return !!(window.HSCHECK && window.HSCHECK.UNIT2GOAL && window.HSCHECK.UNIT2GOAL[mode()]); } catch (e) { return false; } }

    // ── HSADVICE_CHAT_V2 hschat と おなじ 見た目の 画面 ──
    var CSS = '#hsAdv{position:fixed;top:0;right:0;bottom:0;left:0;z-index:9991;background:rgba(15,23,42,.45);display:flex;justify-content:center;align-items:stretch;font-family:inherit}'
      + '#hsAdv .hc-box{width:100%;max-width:780px;background:#fef9f0;display:flex;flex-direction:column;height:100%;box-shadow:0 0 30px rgba(0,0,0,.25)}'
      + '#hsAdv .hc-head{display:flex;align-items:center;gap:10px;padding:10px 14px;background:#facc15;color:#1f2937;font-weight:900;font-size:18px}'
      + '#hsAdv .hc-x{margin-left:auto;background:#fff;border:2px solid #a16207;border-radius:12px;padding:8px 14px;font-size:15px;font-weight:800;color:#713f12;min-height:44px;cursor:pointer}'
      + '#hsAdv .hc-log{flex:1;overflow-y:auto;padding:14px 14px 6px;-webkit-overflow-scrolling:touch}'
      + '#hsAdv .hc-row{display:flex;gap:8px;margin:8px 0;align-items:flex-end}'
      + '#hsAdv .hc-row.me{justify-content:flex-end}'
      + '#hsAdv .hc-face{width:44px;height:44px;flex:0 0 44px;display:flex;align-items:center;justify-content:center;font-size:30px;background:#fff;border-radius:50%;border:2px solid #fde68a;overflow:hidden}'
      + '#hsAdv .hc-face img{max-width:40px;max-height:40px}'
      + '#hsAdv .hc-b{max-width:74%;padding:10px 14px;border-radius:18px;font-size:17px;line-height:1.55;white-space:pre-wrap;word-break:break-word}'
      + '#hsAdv .bot .hc-b{background:#fff;border:2px solid #fde68a;border-bottom-left-radius:6px;color:#1f2937}'
      + '#hsAdv .me .hc-b{background:#86efac;border-bottom-right-radius:6px;color:#14532d;font-weight:700}'
      + '#hsAdv .hc-foot{border-top:2px solid #fde68a;background:#fffbeb;padding:10px 12px 14px;max-height:46vh;overflow-y:auto}'
      + '#hsAdv .hc-ch{display:grid;grid-template-columns:1fr 1fr;gap:8px}'
      + '#hsAdv .hc-ch + .hc-ch{margin-top:8px}'
      + '#hsAdv .hc-ch.one{grid-template-columns:1fr}'
      + '#hsAdv .hc-btn{min-height:56px;border-radius:16px;border:2px solid #f59e0b;background:#fff;color:#78350f;font-size:17px;font-weight:800;padding:8px 10px;text-align:center;cursor:pointer;touch-action:manipulation}'
      + '#hsAdv .hc-btn:active{transform:scale(.98)}'
      + '#hsAdv .hc-btn.main{background:#f97316;border-color:#c2410c;color:#fff}'
      + '#hsAdv .hc-btn.blue{background:#0ea5e9;border-color:#0369a1;color:#fff}'
      + '#hsAdv .hc-btn.sub{background:#f1f5f9;border-color:#cbd5e1;color:#334155;min-height:48px;font-size:15px}'
      + '@media (max-width:520px){#hsAdv .hc-ch{grid-template-columns:1fr}}';
    function face() { var f = '🐯'; try { if (typeof window.monSpriteHtml === 'function') f = window.monSpriteHtml(154, '🐯'); } catch (e) {} return f; }
    function ui() {
      var root = document.getElementById('hsAdv');
      if (!root) {
        if (!document.getElementById('hsAdvCss')) { var st = document.createElement('style'); st.id = 'hsAdvCss'; st.textContent = CSS; document.head.appendChild(st); }
        root = document.createElement('div'); root.id = 'hsAdv';
        root.innerHTML = '<div class="hc-box"><div class="hc-head"><span class="hc-face">' + face() + '</span><span>阪神マン</span><button type="button" class="hc-x" id="hsAdvX">とじる</button></div>'
          + '<div class="hc-log" id="hsAdvLog"></div><div class="hc-foot" id="hsAdvFoot"></div></div>';
        document.body.appendChild(root);
        root.querySelector('#hsAdvX').onclick = function () { H.close(); };
      }
      root.style.display = 'flex';
      return { root: root, log: root.querySelector('#hsAdvLog'), foot: root.querySelector('#hsAdvFoot') };
    }
    function bubble(x) {
      if (x.w === 'm') return '<div class="hc-row me"><div class="hc-b">' + esc(x.t) + '</div></div>';
      return '<div class="hc-row bot"><span class="hc-face">' + face() + '</span><div class="hc-b">' + esc(x.t) + '</div></div>';
    }
    function btn(label, cls, fn) {
      var b = document.createElement('button'); b.type = 'button';
      b.className = 'hc-btn ' + (cls || '');
      b.textContent = label; b.onclick = fn; return b;
    }
    function row(list) { var d = document.createElement('div'); d.className = 'hc-ch'; list.forEach(function (b) { d.appendChild(b); }); return d; }
    function hideOld() { try { var m = document.getElementById('hanshinManModal'); if (m) { m.classList.add('hidden'); m.classList.remove('flex'); m.style.display = 'none'; } } catch (e) {} }

    /* HSQ_V1 自由記述の しつもん。先生と 阪神マンが 読んで、あとで へんじ（AIの 一往復でも 下書きが できる） */
    function askForm(node) {
      var v = ui();
      log.push({ w: 'm', t: '✏️ しつもんしたい' });
      log.push({ w: 'b', t: vary(['よっしゃ、なんでも 書いてみ！「どの 問題の」「どこが」わからんかを 書いてくれると、先生と ちゃんと 答えられるで。', 'ええで！ わからん ところを 自分の ことばで 書いてみ。先生と いっしょに 読んで、あとで へんじするからな。'], 'ask') });
      v.log.innerHTML = log.map(bubble).join(''); v.log.scrollTop = v.log.scrollHeight;
      v.foot.innerHTML = '<textarea id="hsqText" rows="3" maxlength="400" placeholder="れい：「5:2＝□:16」で、□の 出し方が わからない" style="width:100%;border:2px solid #f59e0b;border-radius:12px;padding:8px;font-size:16px;box-sizing:border-box"></textarea><div id="hsqMsg" style="font-size:13px;color:#b91c1c;min-height:18px"></div>';
      var send = btn('📮 おくる', 'main', function () {
        var t = (document.getElementById('hsqText') || {}).value || '';
        if (t.replace(/\s/g, '').length < 4) { document.getElementById('hsqMsg').textContent = 'もう少し くわしく 書いてね（4文字いじょう）'; return; }
        send.disabled = true;
        var ctx = log.slice(-10).map(function (x) { return (x.w === 'm' ? '子：' : '阪神マン：') + String(x.t).replace(/\n/g, ' ').slice(0, 120); }).join('\n');
        apiQ('/api/student/hs-question', { method: 'POST', body: JSON.stringify({ unit: mode(), unitName: (root && root.question) || '', ctx: ctx, text: t }) }).then(function (r) {
          if (r && r.ok) {
            log.push({ w: 'm', t: t }); log.push({ w: 'b', t: 'しつもん、とどいたで！ 先生と 読んで、あとで へんじするからな。へんじは この 阪神マンの 画面を ひらくと 読めるで。それまで ほかの 問題で 修行しとこか！' });
            v.log.innerHTML = log.map(bubble).join(''); v.log.scrollTop = v.log.scrollHeight;
            v.foot.innerHTML = ''; v.foot.appendChild(row([btn('❓ ほかのことも 聞く', '', function () { H.goFirst(); }), btn('とじる', 'sub', function () { H.close(); })]));
          } else { send.disabled = false; document.getElementById('hsqMsg').textContent = (r && r.error === 'too_many') ? '今日は もう たくさん しつもんしたね。続きは あした 聞いてな。' : 'おくれませんでした。もう一回 おしてね。'; }
        });
      });
      v.foot.appendChild(row([send, btn('やめる', 'sub', function () { H.render(node); })]));
    }
    // へんじが とどいていたら、ひらいた ときに さいしょに 見せる
    var repliesShown = false;
    function showReplies() {
      if (repliesShown) return; repliesShown = true;
      apiQ('/api/student/hs-questions').then(function (r) {
        var news = ((r && r.items) || []).filter(function (x) { return x.answer && !x.seenAt; });
        if (!news.length || !open) { repliesShown = false; return; }
        news.reverse().forEach(function (x) { log.splice(1, 0, { w: 'b', t: '📮 前の しつもんの へんじや！\n「' + x.text + '」\n\n' + x.answer }); });
        var v = ui(); v.log.innerHTML = log.map(bubble).join('');
        apiQ('/api/student/hs-questions/seen', { method: 'POST', body: '{}' });
      });
    }

    H.render = function (node) {
      this.currentNode = node;
      var self = this;
      if (!open || (!this.history.length && !skipLog && !pendingMe)) {
        log = [{ w: 'b', t: vary(HELLO, 'h') }, { w: 'b', t: node.question || '' }];
        open = true; root = node; rootKey = ''; repliesShown = false; setTimeout(showReplies, 300);
      } else if (!skipLog) {
        if (pendingMe) log.push({ w: 'm', t: pendingMe });
        log.push({ w: 'b', t: node.options ? (node.question || vary(MORE, 'm')) : (node.answer || node.question || '') });
      }
      pendingMe = ''; skipLog = false;
      if (log.length > 60) log = log.slice(-60);
      hideOld();
      var v = ui();
      function draw() { v.log.innerHTML = log.map(bubble).join(''); v.log.scrollTop = v.log.scrollHeight; }
      draw();
      v.foot.innerHTML = '';
      if (node.options) {
        v.foot.appendChild(row(node.options.map(function (opt, i) { return btn(opt.text, '', function () { self.selectOption(i); }); })));
        if (this.history.length > 0) v.foot.appendChild(row([btn('↩️ 前の 質問に もどる', 'sub', function () { self.goBack(); }), btn('❓ さいしょから 聞く', 'sub', function () { self.goFirst(); })]));
        v.foot.appendChild(row([btn('✏️ ここに ない ことを しつもんする', 'sub', function () { askForm(node); })]));
      } else {
        var main = [btn('🙆 わかった！', 'main', function () {
          log.push({ w: 'm', t: '🙆 わかった！' }); log.push({ w: 'b', t: vary(GOT, 'g') }); draw();
          v.foot.innerHTML = '';
          v.foot.appendChild(row([btn('❓ ほかのことも 聞く', '', function () { self.goFirst(); }), btn('とじる', 'sub', function () { self.close(); })]));
        })];
        // HSADVICE_MORE_V1 まだ わからん → もっと 深く（いちばん 下なら しつもん）
        main.push(btn('🤔 まだ ちょっと わからん', 'blue', function () {
          var nx = node.more ? { question: vary(['どこが まだ ひっかかる？', 'ほな、どの へんが むずかしい？', 'もうちょい くわしく いこか。どれや？'], 'q2'), options: node.more, _f: 1 }
            : (node._f ? null : followFor(mode()));
          if (!nx) { askForm(node); return; }
          self.history.push(node); pendingMe = '🤔 まだ ちょっと わからん'; self.render(nx);
        }));
        if (canCheck()) main.push(btn('🔍 理解度チェックで たしかめる', '', function () { var m = mode(); self.close(); try { window.HSCHECK.open(m); } catch (e) {} }));
        var mr = row(main); v.foot.appendChild(mr);
        if (node._f) v.foot.appendChild(row([btn('✏️ 阪神マンと 先生に しつもんする', 'sub', function () { askForm(node); })]));
        v.foot.appendChild(row([btn('❓ ほかのことも 聞く', 'sub', function () { self.goFirst(); }), btn('↩️ 前の 質問に もどる', 'sub', function () { self.goBack(); })]));
      }
    };
    // HSQ_V1 へんじだけ 読む 画面（とどいた おしらせから ひらく）
    H.openReplies = function () {
      open = true; root = null; log = [{ w: 'b', t: vary(HELLO, 'h') }]; repliesShown = false;
      var v = ui(); hideOld(); v.log.innerHTML = log.map(bubble).join('');
      v.foot.innerHTML = ''; v.foot.appendChild(row([btn('🙆 わかった！', 'main', function () { H.close(); })]));
      showReplies();
    };
    H.selectOption = function (i) {
      var sel = this.currentNode && this.currentNode.options && this.currentNode.options[i];
      if (!sel) return;
      this.history.push(this.currentNode);
      if (sel.options || sel.question || sel.answer) { pendingMe = sel.text || ''; this.render(sel); }
      else this.close();
    };
    H.goBack = function () {
      if (!this.history.length) return;
      var prev = this.history.pop();
      log.push({ w: 'm', t: '↩️ 前の 質問に もどる' });
      log.push({ w: 'b', t: prev.question || vary(MORE, 'm') });
      skipLog = true; this.render(prev);
    };
    H.goFirst = function () {
      var r = rootNode(); if (!r) return;
      this.history = [];
      log.push({ w: 'm', t: 'ほかのことも 聞きたい' });
      log.push({ w: 'b', t: vary(MORE, 'm') + '\n' + (r.question || '') });
      skipLog = true; this.render(r);
    };
    H.close = function () { open = false; log = []; root = null; rootKey = ''; pendingMe = ''; skipLog = false; try { var r = document.getElementById('hsAdv'); if (r) r.style.display = 'none'; } catch (e) {} return origClose.apply(this, arguments); };
    return true;
  }
  if (!patch()) { var n = 0, t = setInterval(function () { if (patch() || ++n > 120) clearInterval(t); }, 500); }
  // HSQ_V1 へんじが とどいたら、画面の すみに おしらせ（ひらくと 読める）
  setTimeout(function () {
    try {
      if (/teacher|pj|chitosele/.test(location.pathname)) return;
      fetch('/api/student/hs-questions', { credentials: 'include' }).then(function (r) { return r.json(); }).then(function (r) {
        var news = ((r && r.items) || []).filter(function (x) { return x.answer && !x.seenAt; });
        if (!news.length || document.getElementById('hsqNote')) return;
        var b = document.createElement('button'); b.id = 'hsqNote'; b.type = 'button';
        b.style.cssText = 'position:fixed;left:12px;bottom:12px;z-index:9980;background:#facc15;color:#78350f;border:3px solid #a16207;border-radius:16px;padding:10px 14px;font-weight:900;font-size:16px;box-shadow:0 6px 18px rgba(0,0,0,.25);cursor:pointer';
        b.textContent = '📮 阪神マンから しつもんの へんじが とどいたで！（' + news.length + '）';
        b.onclick = function () { b.remove(); try { window.HanshinManSystem.openReplies(); } catch (e) {} };
        document.body.appendChild(b);
      }).catch(function () {});
    } catch (e) {}
  }, 6000);
})();
