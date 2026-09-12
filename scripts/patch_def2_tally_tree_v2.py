# -*- coding: utf-8 -*-
# DEF2TALLY_TREE_V2 --- ためしバトルの「何かい うごいた ひょう」を ツリーに 合わせる。
#
# いままで: 一ばん 外がわの ならびだけを ばんごう じゅんに ならべていた。
# これから: 入れ子の 中みも、段差（右へ ずらす）を つけて ならべる。
#
# くりかえし・もし〜なら の ブロック そのものは、たたかいの コマに
# ばんごうが のこらない（うごきの ときだけ のこる）。
# だから ブロックの 回数は「その 中に ある うごきの 回数の 合計」で だす。
#
# さわるのは public/defense2.js と、src/index.tsx の よみこみ番号 1か所 だけ。
# 一つでも あてはまらなければ 何も 書かずに 止まる（fail-closed）。

import io
import sys

D2 = 'public/defense2.js'
TSX = 'src/index.tsx'

MARK = 'DEF2TALLY_TREE_V2_MARK'        # 検証で 数える 番兵
ALREADY = 'function d2tLeafIds(arr)'    # 冪等の 見わけ（検証条件とは 別もの）


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


NEWFN = u"""  /* DEF2TALLY_TREE_V2_MARK
     ブロックの 中に ある「うごき」の ばんごうを ぜんぶ あつめる。
     くりかえす・もし〜なら の ブロック じたいは、たたかいの コマに
     ばんごうが のこらない。だから 中の うごきの 回数を たして
     「この ブロックは 何かい うごいたか」に する。 */
  function d2tLeafIds(arr) {
    var out = [];
    (function rec(a) {
      var j, n;
      for (j = 0; j < (a || []).length; j++) {
        n = a[j];
        if (!n || typeof n !== 'object') continue;
        if (n.t === 'a' || (!n.t && n.a)) { if (n._id != null) out.push(n._id); continue; }
        if (n.body) rec(n.body);
        if (n.els) rec(n.els);
      }
    })(arr);
    return out;
  }

  /* ひょうの 1ぎょう分の 回数。ブロックの ぎょうは 中みの 合計。 */
  function tbRowCount(row, cnt) {
    var s = 0, j;
    if (row && row.kind === 'b') {
      for (j = 0; j < (row.ids || []).length; j++) { s += (cnt[row.ids[j]] || 0); }
      return s;
    }
    return cnt[row._id] || 0;
  }

"""

OLD_ROW = u"""      out+='<div style="display:flex;align-items:center;gap:6px;margin:4px 0;font-size:12px;'
        +(on?'':'background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:4px 6px;')+'">'
        +'<div style="flex:0 0 20px;height:20px;line-height:20px;text-align:center;border-radius:999px;font-weight:900;color:#fff;background:'+(on?'#0d9488':'#f97316')+';">'+(i+1)+'</div>'
        +'<div style="flex:1;color:'+(on?'#334155':'#9a3412')+';font-weight:'+(on?'400':'900')+';">'+esc(rules[i].line!=null?rules[i].line:tbRuleLine(rules[i]))
        +(on?'':'<br><span style="font-size:11px;font-weight:400;">1かいも うごかなかった</span>')+'</div>'
        +'<div style="flex:0 0 56px;background:#e2e8f0;border-radius:999px;height:9px;overflow:hidden;"><div style="width:'+pct+'%;height:100%;background:'+(on?'#0d9488':'#fdba74')+';"></div></div>'
        +'<div style="flex:0 0 58px;text-align:right;font-weight:900;color:'+(on?'#0f766e':'#9a3412')+';">'+n+'かい</div>'
        +'</div>';"""

NEW_ROW = u"""      out+='<div style="display:flex;align-items:center;gap:6px;margin:4px 0;font-size:12px;margin-left:'+(_dp*16)+'px;'
        +((on||_bk)?'':'background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:4px 6px;')
        +(_bk?'background:#f1f5f9;border-radius:8px;padding:3px 6px;':'')+'">'
        +'<div style="flex:0 0 20px;height:20px;line-height:20px;text-align:center;border-radius:999px;font-weight:900;color:#fff;background:'+(_bk?'#94a3b8':(on?'#0d9488':'#f97316'))+';">'+(_bk?'▸':_num)+'</div>'
        +'<div style="flex:1;color:'+(_bk?'#475569':(on?'#334155':'#9a3412'))+';font-weight:'+((_bk||!on)?'900':'400')+';">'+esc(rules[i].line!=null?rules[i].line:tbRuleLine(rules[i]))
        +((on||_bk)?'':'<br><span style="font-size:11px;font-weight:400;">1かいも うごかなかった</span>')+'</div>'
        +'<div style="flex:0 0 56px;background:#e2e8f0;border-radius:999px;height:9px;overflow:hidden;"><div style="width:'+pct+'%;height:100%;background:'+(_bk?'#cbd5e1':(on?'#0d9488':'#fdba74'))+';"></div></div>'
        +'<div style="flex:0 0 58px;text-align:right;font-weight:900;color:'+(_bk?'#475569':(on?'#0f766e':'#9a3412'))+';">'+n+'かい</div>'
        +'</div>';"""

OLD_BLK = u"""          lb = d2tBlockJa(n);
          if (n.body) rec(n.body, path ? (path + ' / ' + lb) : lb);
          if (n.els) {
            eb = (n.t === 'if') ? ('もし ' + d2tCondJa(n) + ' で ないとき') : (lb + ' で ないとき');
            rec(n.els, path ? (path + ' / ' + eb) : eb);
          }"""

NEW_BLK = u"""          lb = d2tBlockJa(n);
          out.push({ _id: null, depth: (dep || 0), kind: 'b', line: lb, ids: d2tLeafIds(n.body) });
          if (n.body) rec(n.body, path ? (path + ' / ' + lb) : lb, (dep || 0) + 1);
          if (n.els) {
            eb = (n.t === 'if') ? ('もし ' + d2tCondJa(n) + ' で ないとき') : (lb + ' で ないとき');
            out.push({ _id: null, depth: (dep || 0), kind: 'b', line: eb, ids: d2tLeafIds(n.els) });
            rec(n.els, path ? (path + ' / ' + eb) : eb, (dep || 0) + 1);
          }"""

OLD_HEAD = u"""      n=cnt[rules[i]._id]||0; on=(n>0); pct=Math.round(n*100/mx); if(!on) zero++;"""

NEW_HEAD = u"""      _bk=(rules[i].kind==='b'); _dp=(rules[i].depth||0); if(!_bk) _num++;
      n=tbRowCount(rules[i],cnt); on=(n>0); pct=Math.min(100,Math.round(n*100/mx)); if(!_bk&&!on) zero++;"""

EDITS = [
    # 1) あつめる 部品を d2tTallyRules の 手まえに おく
    (u"  function d2tTallyRules(prog) {",
     NEWFN + u"  function d2tTallyRules(prog) {"),
    # 2) さいきの 中で 深さを もちまわる
    (u"      (function rec(arr, path) {",
     u"      (function rec(arr, path, dep) {"),
    # 3) うごきの ぎょう: 道すじは 文字ではなく 段差で 見せる
    (u"            out.push({ _id: n._id, line: (path ? path + ' → ' : '') + tbActLabel(n.a) });",
     u"            out.push({ _id: n._id, depth: (dep || 0), kind: 'a', line: tbActLabel(n.a) });"),
    # 4) ブロックの ぎょうも ひょうに ならべる（いままでは 出していなかった）
    (OLD_BLK, NEW_BLK),
    # 5) さいきの はじめの よびだしに 深さ 0 を わたす
    (u"      })(prog, '');",
     u"      })(prog, '', 0);"),
    # 6) ふるい ひょう形式（入れ子なし）は いままで どおり。深さ 0 の うごき。
    (u"      out.push({ _id: r._id, c: r.c, a: r.a, cn: r.cn, line: tbRuleLine(r) });",
     u"      out.push({ _id: r._id, c: r.c, a: r.a, cn: r.cn, depth: 0, kind: 'a', line: tbRuleLine(r) });"),
    # 7) ばんごう用の かぞえと、ぎょうの しゅるいを 入れもの に くわえる
    (u"    var cnt={}, none=0, total=0, mx=1, zero=0, n, pct, on, out;",
     u"    var cnt={}, none=0, total=0, mx=1, zero=0, n, pct, on, out, _num=0, _bk, _dp;"),
    # 8) バーの ながさの きじゅんは「うごき」の ぎょうから とる
    (u"    for(i=0;i<rules.length;i++){ n=cnt[rules[i]._id]||0; if(n>mx) mx=n; }",
     u"    for(i=0;i<rules.length;i++){ if(rules[i].kind==='b') continue; n=cnt[rules[i]._id]||0; if(n>mx) mx=n; }"),
    # 9) 1ぎょうずつ かぞえる。ブロックは 中みの 合計。0かいの けいこくは うごきだけ。
    (OLD_HEAD, NEW_HEAD),
    # 10) みため: 深さのぶん 右へ ずらす。ブロックは はい色の ぎょう。
    (OLD_ROW, NEW_ROW),
    # 11) 読みかたの ひとこと。段差の いみを そえる。
    (u"'ブロックを 上から じゅんに 実行して、いちばん下まで いったら また 上に もどるよ。'",
     u"'ブロックを 上から じゅんに 実行して、いちばん下まで いったら また 上に もどるよ。右に ずれている ぎょうは、その 上の ブロックの 中みだよ。'"),
]

for idx, pair in enumerate(EDITS):
    old, new = pair
    c = d2.count(old)
    if c != 1:
        die(u'%d ばんめの あて先が %d 件（1件で ないと 流さない）' % (idx + 1, c))
    if new in d2:
        die(u'%d ばんめの 新しい 中みが すでに ある' % (idx + 1))

if tsx.count('/defense2.js' + '?v' + '=11') != 1:
    die(u'よみこみ番号 v11 が 1件で ない')
if tsx.count('/defense2.js' + '?v' + '=12') != 0:
    die(u'よみこみ番号 v12 が すでに ある')

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
chain_before = tsx[i:j].count('.replace(')
if chain_before != 82:
    die(u'チェーンが %d 件（82 件の はず）' % chain_before)

for pair in EDITS:
    old, new = pair
    d2 = d2.replace(old, new, 1)

tsx = tsx.replace('/defense2.js' + '?v' + '=11', '/defense2.js' + '?v' + '=12', 1)

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
chain_after = tsx[i:j].count('.replace(')
if chain_after != chain_before:
    die(u'チェーンが %d 件に なった（%d 件の ままで ないと だめ）' % (chain_after, chain_before))

if d2.count(MARK) != 1:
    die(u'番兵が 1件で ない')
if d2.count(u'1かいも うごかなかった') != 2:
    die(u'0かいの おしらせが 2件で ない')

io.open(D2, 'w', encoding='utf-8').write(d2)
io.open(TSX, 'w', encoding='utf-8').write(tsx)
print(u'PATCH OK / chain %d -> %d' % (chain_before, chain_after))
