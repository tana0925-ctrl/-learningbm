# -*- coding: utf-8 -*-
# DEF2TPL_LEARN_V1 --- お手本の つかわせかたを 学習の サイクルに する。
#
# いままで: お手本を えらぶと いきなり 丸ごと 上書きしていた。読む ひまが なかった。
# これから: 読む → よそうする → うごかす → けっかを 見る → 1か所だけ なおす。
#
#   ① えらぶと まず「この プログラムは 何を する？」を 日本語の 文で 見せる
#   ② うごかす まえに「どうなると 思う？」を 一度だけ きく（あたり はずれは 言わない）
#   ③「つかってみる」で 入れて、すぐ ためしバトルの ところへ つれていく
#   ④ バトルの あと、何かい うごいた ひょうの 下に
#     「ここを 1つだけ かえてみよう」を 1〜2つ 出す
#
# さわるのは public/defense2.js と、src/index.tsx の よみこみ番号 1か所 だけ。
# 一つでも あてはまらなければ 何も 書かずに 止まる（fail-closed）。

import io
import sys

D2 = 'public/defense2.js'
TSX = 'src/index.tsx'

MARK = 'DEF2TPL_LEARN_V1_MARK'          # 検証で 数える 番兵
ALREADY = 'function d2tProgJa(prog)'     # 冪等の 見わけ（検証条件とは 別もの）


def die(msg):
    print(u'NG: ' + msg)
    sys.exit(1)


d2 = io.open(D2, encoding='utf-8').read()
tsx = io.open(TSX, encoding='utf-8').read()

if ALREADY in d2:
    print(u'すでに 適用ずみ。何も しない。')
    sys.exit(0)

if MARK in d2:
    die(u'番兵だけ のこっている。人の目で 見てほしい。')

if 'function tbRowCount(row, cnt)' not in d2:
    die(u'さきに DEF2TALLY_TREE_V2 を 流してから。')


OLD_VARS = u"""  var _d2tTplOpen = false;"""

NEW_VARS = u"""  var _d2tTplOpen = false;
  /* DEF2TPL_LEARN_V1_MARK
     お手本は いきなり 入れない。
     読む → よそうする → うごかす → けっかを 見る → 1か所だけ なおす。 */
  var _d2tTplPrev = null;
  var _d2tGuess = null;"""

OLD_TPL = u"""  window._def2TreeTpl = function (i) {
    var tp = D2T_TPL[i];
    if (!tp) return;
    d2tReplace(d2tProg(), JSON.parse(JSON.stringify(tp.prog)));
    _d2tTplOpen = false;
    try { window._pbPersist(); } catch (e) { }
    progSaveSoon();
    d2tRepaint();
  };"""

NEW_TPL = u"""  window._def2TreeTpl = function (i) {
    var tp = D2T_TPL[i];
    if (!tp) return;
    _d2tTplPrev = i;
    _d2tGuess = null;
    _d2tTplOpen = true;
    d2tRepaint();
  };"""

OLD_TOG = u"""  window._def2TreeTplToggle = function () {
    _d2tTplOpen = !_d2tTplOpen;
    d2tRepaint();
  };"""

NEW_FNS = u"""  /* DEF2TPL_LEARN_V1 ここから ------------------------------------- */

  /* プログラムを 日本語の 文に する。入れ子は 段差で あらわす。 */
  function d2tProgJa(prog) {
    var out = [];
    (function rec(arr, dep) {
      var j, n, lb;
      for (j = 0; j < (arr || []).length; j++) {
        n = arr[j];
        if (!n || typeof n !== 'object') continue;
        if (n.t === 'a' || (!n.t && n.a)) { out.push({ d: dep, s: '→ ' + tbActLabel(n.a), b: false }); continue; }
        lb = d2tBlockJa(n);
        out.push({ d: dep, s: lb, b: true });
        if (n.body) rec(n.body, dep + 1);
        if (n.els) {
          out.push({ d: dep, s: (n.t === 'if') ? 'でなければ' : (lb + ' で ないとき'), b: true });
          rec(n.els, dep + 1);
        }
      }
    })(prog, 0);
    return out;
  }

  function d2tJaHtml(prog) {
    var ls = d2tProgJa(prog), i, s = '';
    for (i = 0; i < ls.length; i++) {
      s += '<div style="margin-left:' + (ls[i].d * 16) + 'px;font-size:13px;line-height:1.8;color:'
        + (ls[i].b ? '#0f766e' : '#334155') + ';font-weight:' + (ls[i].b ? '900' : '400') + ';">'
        + esc(ls[i].s) + '</div>';
    }
    return s;
  }

  function d2tGuessJa(g) {
    if (g === 'win') return 'あいての きちを たくさん こうげきしそう';
    if (g === 'keep') return 'じぶんの きちを まもりそう';
    if (g === 'mix') return 'どちらも ほどほど';
    return '';
  }

  /* つかった あと、ためしバトルの ところへ つれていく */
  function d2tGoTry() {
    setTimeout(function () {
      var b = document.getElementById('def2TryBox'), g;
      if (!b) return;
      try { b.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (e) { try { b.scrollIntoView(); } catch (e2) { } }
      g = document.getElementById('def2TryGo');
      if (!g) return;
      g.style.boxShadow = '0 0 0 4px #fde047';
      setTimeout(function () { try { g.style.boxShadow = ''; } catch (e) { } }, 2600);
    }, 260);
  }

  /* お手本の カード: 読む → よそう → つかってみる */
  function d2tTplPrevHtml() {
    var tp = D2T_TPL[_d2tTplPrev], i, s, G, on;
    if (!tp) return '';
    G = [['win', d2tGuessJa('win')], ['keep', d2tGuessJa('keep')], ['mix', d2tGuessJa('mix')]];
    s = '<div style="background:#ecfeff;border:2px solid #22d3ee;border-radius:12px;padding:10px;margin-bottom:8px;">'
      + '<div style="font-weight:900;font-size:13px;color:#0e7490;margin-bottom:5px;">' + esc(tp.name) + '</div>'
      + '<div style="font-size:11px;color:#155e75;margin-bottom:5px;">① この プログラムは 何を する？ 声に出して 読んでみよう。</div>'
      + '<div style="background:#fff;border-radius:8px;padding:8px;margin-bottom:9px;">' + d2tJaHtml(tp.prog) + '</div>'
      + '<div style="font-size:11px;color:#155e75;margin-bottom:4px;">② うごかす まえに よそう。どうなると 思う？</div>';
    for (i = 0; i < G.length; i++) {
      on = (_d2tGuess === G[i][0]);
      s += '<button onclick="_def2TreeTplGuess(' + "'" + G[i][0] + "'" + ')" style="display:block;width:100%;text-align:left;margin-bottom:4px;border:1px solid '
        + (on ? '#0891b2' : '#cbd5e1') + ';background:' + (on ? '#cffafe' : '#fff')
        + ';border-radius:8px;padding:6px 8px;font-size:12px;font-weight:' + (on ? '900' : '400') + ';cursor:pointer;">'
        + (on ? '◉ ' : '○ ') + esc(G[i][1]) + '</button>';
    }
    s += '<div style="font-size:11px;color:#64748b;margin:5px 0 9px;line-height:1.6;">あたっても はずれても 大じょうぶ。よそうしてから 見ると、けっかの 見えかたが かわるよ。</div>'
      + '<button onclick="_def2TreeTplUse()" style="width:100%;background:#0891b2;color:#fff;border:0;border-radius:10px;padding:9px;font-weight:900;font-size:13px;cursor:pointer;box-shadow:0 3px 0 #0e7490;">③ つかってみる → 🧪 ためしバトルへ</button>'
      + '<button onclick="_def2TreeTplBack()" style="width:100%;margin-top:5px;background:#e2e8f0;color:#334155;border:0;border-radius:10px;padding:7px;font-weight:900;font-size:12px;cursor:pointer;">ほかの お手本を 見る</button>'
      + '</div>';
    return s;
  }

  /* ひょうの あとに「ここを 1つだけ かえてみよう」 */
  function d2tNextStepHtml(rules, cnt, prog) {
    var i, r, n, zero = null, zeroB = null, top = null, tn = -1, s, tips = [];
    for (i = 0; i < (rules || []).length; i++) {
      r = rules[i]; n = tbRowCount(r, cnt);
      if (r.kind === 'b') { if (n === 0 && !zeroB) zeroB = r; continue; }
      if (n === 0 && !zero) zero = r;
      if (n > tn) { tn = n; top = r; }
    }
    if (zero) tips.push('「' + zero.line + '」が 1かいも うごかなかったよ。この すぐ上の じょうけんの すうじを 1つだけ かえて、もういちど ためそう。');
    if (zeroB && tips.length < 2) tips.push('「' + zeroB.line + '」の 中が 1かいも うごかなかったよ。この ブロックの じょうけんを 見なおそう。');
    if (!tips.length && top) tips.push('「' + top.line + '」が いちばん おおく うごいたね。くりかえしの かずか、じょうけんの すうじを 1つだけ かえると どう かわるかな？');
    if (!tips.length) return '';
    s = '';
    if (_d2tGuess) {
      s += '<div style="background:#f0f9ff;border:1px solid #7dd3fc;border-radius:10px;padding:8px;margin-top:8px;font-size:12px;color:#075985;line-height:1.7;">'
        + '🔮 きみの よそうは「' + esc(d2tGuessJa(_d2tGuess)) + '」だったね。上の ひょうと くらべて どうだった？</div>';
    }
    s += '<div style="background:#fefce8;border:2px solid #fde047;border-radius:10px;padding:9px;margin-top:8px;">'
      + '<div style="font-weight:900;font-size:13px;color:#854d0e;margin-bottom:5px;">✏ ここを 1つだけ かえてみよう</div>';
    for (i = 0; i < tips.length && i < 2; i++) {
      s += '<div style="font-size:12px;color:#713f12;line-height:1.7;margin-bottom:3px;">・' + esc(tips[i]) + '</div>';
    }
    s += '<div style="font-size:11px;color:#a16207;margin-top:5px;line-height:1.6;">2つ いっぺんに かえると、どっちが きいたか わからなく なるよ。1つだけね。</div></div>';
    return s;
  }

  window._def2TreeTplGuess = function (g) { _d2tGuess = g; d2tRepaint(); };

  window._def2TreeTplBack = function () { _d2tTplPrev = null; _d2tGuess = null; d2tRepaint(); };

  window._def2TreeTplUse = function () {
    var tp = D2T_TPL[_d2tTplPrev];
    if (!tp) return;
    d2tReplace(d2tProg(), JSON.parse(JSON.stringify(tp.prog)));
    _d2tTplPrev = null;
    _d2tTplOpen = false;
    try { window._pbPersist(); } catch (e) { }
    progSaveSoon();
    d2tRepaint();
    d2tGoTry();
  };

  /* DEF2TPL_LEARN_V1 ここまで ------------------------------------- */

"""

NEW_TOG = NEW_FNS + u"""  window._def2TreeTplToggle = function () {
    _d2tTplOpen = !_d2tTplOpen;
    _d2tTplPrev = null;
    _d2tGuess = null;
    d2tRepaint();
  };"""

OLD_BAR = u"""    if (!_d2tTplOpen) return out;"""

NEW_BAR = u"""    if (_d2tTplPrev != null && D2T_TPL[_d2tTplPrev]) return out + d2tTplPrevHtml();
    if (!_d2tTplOpen) return out;"""

OLD_TAIL = u"""    return out;
  }

  function tbInfoHtml(rep"""

NEW_TAIL = u"""    out += d2tNextStepHtml(rules, cnt, prog);
    return out;
  }

  function tbInfoHtml(rep"""

EDITS = [
    # 1) 見ている お手本と、よそうを おぼえる ばしょ
    (OLD_VARS, NEW_VARS),
    # 2) えらんでも いきなり 入れない。まず 見せる。
    (OLD_TPL, NEW_TPL),
    # 3) 読む・よそう・つれていく・つぎの 一手 の ぶひんを 足す
    (OLD_TOG, NEW_TOG),
    # 4) お手本の ならびの かわりに カードを 出す
    (OLD_BAR, NEW_BAR),
    # 5) ボタンの 名まえ。いきなり 入れないので「読んでみる」。
    (u">これにする</button>'", u">読んでみる</button>'"),
    # 6) 何かい うごいた ひょうの 下に つぎの 一手を そえる
    (OLD_TAIL, NEW_TAIL),
]

for idx, pair in enumerate(EDITS):
    old, new = pair
    c = d2.count(old)
    if c != 1:
        die(u'%d ばんめの あて先が %d 件（1件で ないと 流さない）' % (idx + 1, c))
    if new in d2:
        die(u'%d ばんめの 新しい 中みが すでに ある' % (idx + 1))

if tsx.count('/defense2.js' + '?v' + '=12') != 1:
    die(u'よみこみ番号 v12 が 1件で ない')
if tsx.count('/defense2.js' + '?v' + '=13') != 0:
    die(u'よみこみ番号 v13 が すでに ある')

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
chain_before = tsx[i:j].count('.replace(')
if chain_before != 82:
    die(u'チェーンが %d 件（82 件の はず）' % chain_before)

for pair in EDITS:
    old, new = pair
    d2 = d2.replace(old, new, 1)

tsx = tsx.replace('/defense2.js' + '?v' + '=12', '/defense2.js' + '?v' + '=13', 1)

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
chain_after = tsx[i:j].count('.replace(')
if chain_after != chain_before:
    die(u'チェーンが %d 件に なった（%d 件の ままで ないと だめ）' % (chain_after, chain_before))

if d2.count(MARK) != 1:
    die(u'番兵が 1件で ない')
if d2.count(u'1かいも うごかなかった') != 4:
    die(u'0かいの 文が 4件で ない')

io.open(D2, 'w', encoding='utf-8').write(d2)
io.open(TSX, 'w', encoding='utf-8').write(tsx)
print(u'PATCH OK / chain %d -> %d' % (chain_before, chain_after))
