# -*- coding: utf-8 -*-
"""
patch_gcgid_fix_v1.py — 防衛戦のリプレイが「ジムチャレンジのクリア」を勝手に書きこむのを止める
2026-09-25  GCGID_FIX_V1   (チェーン 156 -> 158)

■ 何が起きていたか

  ジムチャレンジ（ブロックで作戦を組むほう）で どれかのジムを開くと `_gcGid` に
  そのジム番号が入る。ところが `_gcGid` を null に戻す処理が どこにも無い。

  いっぽう 防衛戦のリプレイは、ジムチャレンジと同じ描画コードで描かれている：

      window._defRenderBattle = function(rep){ _gcReplay=rep; ... _gcRenderBattle(); }

  リプレイが終わると `_gcFinishReplay()` が走り、その中で

      var coins = _gcReward(_gcGid, win);
      ...
      function _gcReward(gymId,win){ if(!win) return 0; ...
        player.gymChallengeCleared[gymId] = true;   // ← ここ
        saveData(); }

  が呼ばれる。つまり

    ・`_gcGid` が数字のまま      → 遊んでもいないジムチャレンジが「クリア済み」になる
    ・`_gcGid` が null のまま    → `gymChallengeCleared["null"]` という ゴミのキーが増える

  本番データに証拠があった：`gymChallengeCleared` の `"null"` キーが 11人ぶん。
  （コイン報酬は「お試し期間」でコード上 0 に止めてあるので、コインは増えていない）

  同じことが 友達対戦のプログラム対戦（_gcPbLaunch）でも起きる。
  こちらは準備画面が `_gcOpenGym(1)` を通るので `_gcGid` が 1 に固定され、
  勝つと「ジムチャレンジ1」が勝手にクリア済みになる。

■ 直し方（3か所・どれも1行の挿入）

  P1  _defRenderBattle の先頭で `_gcGid = null`
      ⚠️ 「退避して後で戻す」形にしてはいけない。`_gcFinishReplay()` は
         再生が終わったあと（非同期）に走るので、戻すと結局そこで拾われる。
         null にしたまま にするのが正解。
         （ジムチャレンジ画面に戻るときは setMode('gymchallenge') が
           必ず一覧から描き直すので、実害はない）

  P2  _gcReward に「gymId が null/undefined なら何もしない」ガード
      → `"null"` キーが新しく増えることが無くなる。
         P1 だけだと `_gcReward(null, win)` は依然として呼ばれ、ゴミのキーを書き続ける。

  P3  _gcPbLaunch（友達対戦のプログラム対戦）でも `_gcGid = null`
      → 友達対戦に勝ったら「ジムチャレンジ1」がクリアになる、を止める。

  この3つで、`gymChallengeCleared` に書きこむのは 本物の `_gcFight()` だけになる。

■ ついでに直るもの
  リプレイの背景。`_gcPickTheme` は `_gcGid && _gcStageThemes[_gcGid]` を見るので、
  null に戻れば 対戦ごとの乱数で背景が選ばれる（本来の動き）。

⚠️ public/index.html は 1バイトも変えない
⚠️ progress（児童のデータ）には書きこまない。すでに入っている `"null"` キーの
   掃除は このパッチでは やらない（先生の判断待ち）
⚠️ テンプレートリテラルの中の onclick で 1段だけの \\' を使わない（2026-09-25 朝の事故）
   → このパッチは onclick を1つも作らないが、念のため最後に全体を点検する
"""
import io
import json
import os
import re
import shutil
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'
SELF_COPY = 'scripts/patch_gcgid_fix_v1.py'
TAG = 'GCGID_FIX_V1'

CHAIN_ADDS = 2   # P2 と P3 が新しい .replace()。P1 は既存の置きかえ文字列の中身を直すので ±0
CHAIN_EXPECT_BEFORE = int((os.environ.get('CHAIN_BEFORE') or '156').strip())
CHAIN_EXPECT_AFTER = CHAIN_EXPECT_BEFORE + CHAIN_ADDS

# ── P1: src/index.tsx の中の「注入する文字列」そのものを直す（チェーン増減なし） ──
P1_OLD = (u'window._defShowReplay=_defShowReplay;window._defRenderBattle=function(rep){'
          u'try{_gcReplay=rep;_gcPlayIdx=0;if(!_gcSpeed)_gcSpeed=1;_gcRenderBattle();}catch(e){}};')
P1_NEW = (u'window._defShowReplay=_defShowReplay;window._defRenderBattle=function(rep){'
          u'try{_gcGid=null;_gcReplay=rep;_gcPlayIdx=0;if(!_gcSpeed)_gcSpeed=1;_gcRenderBattle();}catch(e){}};')

# ── P2/P3: public/index.html にあてる 新しい .replace() ──
A2 = u'function _gcReward(gymId,win){ if(!win) return 0; if(!player.gymChallengeCleared) player.gymChallengeCleared={};'
B2 = (u'function _gcReward(gymId,win){ if(!win) return 0; '
      u'if(gymId===null||gymId===undefined) return 0; '
      u'if(!player.gymChallengeCleared) player.gymChallengeCleared={};')

A3 = u"if(typeof trySetMode==='function') trySetMode('gymchallenge'); _gcReplay=autoBattleRT(A.specs, B.specs,"
B3 = u"if(typeof trySetMode==='function') trySetMode('gymchallenge'); _gcGid=null; _gcReplay=autoBattleRT(A.specs, B.specs,"

PAIRS = [
    ('P2_GCREWARD_GUARD', A2, B2),
    ('P3_PB_LAUNCH', A3, B3),
]

INSERT_ANCHOR = u'\n    _rootHtmlCache = t\n    }\n'


def ts_str(s):
    out = s.replace(u'\\', u'\\\\').replace(u"'", u"\\'")
    out = out.replace(u'\r', u'\\r').replace(u'\n', u'\\n')
    assert u'`' not in out
    assert u'${' not in out
    return u"'" + out + u"'"


def chain_count(src):
    i = src.index(u"app.get('/', async (c) => {")
    j = src.index(u"app.get('/logout'")
    return src[i:j].count(u'.replace(')


def main():
    html = io.open(HTML, encoding='utf-8').read()
    src = io.open(TSX, encoding='utf-8').read()

    before = chain_count(src)
    print('chain before = %d (expect %d)' % (before, CHAIN_EXPECT_BEFORE))
    if before != CHAIN_EXPECT_BEFORE:
        print('::error::chain mismatch. expected %d, got %d' % (CHAIN_EXPECT_BEFORE, before))
        sys.exit(1)

    if TAG in src:
        print('::error::%s already present' % TAG)
        sys.exit(1)

    # ── P1 ──
    n1 = src.count(P1_OLD)
    print('P1 anchor in tsx = %d' % n1)
    if n1 != 1:
        print('::error::P1 anchor not unique (%d)' % n1)
        sys.exit(1)
    if src.count(P1_NEW):
        print('::error::P1 already applied')
        sys.exit(1)
    new_src = src.replace(P1_OLD, P1_NEW, 1)

    # ── P2 / P3 の目印が public/index.html に ちょうど1つずつ ──
    for tag, a, b in PAIRS:
        n = html.count(a)
        print('%-18s anchor in html = %d' % (tag, n))
        if n != 1:
            print('::error::%s anchor not unique in html (%d)' % (tag, n))
            sys.exit(1)
        if html.count(b) != 0:
            print('::error::%s already applied?' % tag)
            sys.exit(1)

    # ── 差しこみ ──
    if new_src.count(INSERT_ANCHOR) != 1:
        print('::error::insert anchor not unique')
        sys.exit(1)

    block = [u'\n']
    block.append(u'      // \u2550\u2550\u2550\u2550\u2550\u2550 %s \u9632\u885B\u6226\u306E\u30EA\u30D7\u30EC\u30A4\u304C\u30B8\u30E0\u30C1\u30E3\u30EC\u30F3\u30B8\u306E\u30AF\u30EA\u30A2\u3092\u66F8\u304D\u3053\u3080\u306E\u3092\u6B62\u3081\u308B \u2550\u2550\u2550\u2550\u2550\u2550\n' % TAG)
    block.append(u'      // \u4E2D\u8EAB\u306F scripts/patch_gcgid_fix_v1.py\u3002public/index.html \u306F \u624B\u3067 \u66F8\u304D\u304B\u3048\u306A\u3044\u3002\n')
    block.append(u'      // P1 \u306F _defRenderBattle \u306E\u6CE8\u5165\u6587\u5B57\u5217\u3092\u76F4\u63A5\u76F4\u3057\u3066\u3044\u308B\uFF08\u30C1\u30A7\u30FC\u30F3\u5897\u6E1B\u306A\u3057\uFF09\u3002\n')
    block.append(u'      // \u2757 _gcGid \u306F null \u306B\u3057\u305F\u307E\u307E\u306B\u3059\u308B\u3002_gcFinishReplay() \u306F\u975E\u540C\u671F\u306A\u306E\u3067\u3001\n')
    block.append(u'      //    \u9000\u907F\u3057\u3066\u623B\u3059\u5F62\u306B\u3059\u308B\u3068 \u7D50\u5C40\u305D\u3053\u3067\u62FE\u308F\u308C\u308B\u3002\n')
    for tag, a, b in PAIRS:
        block.append(u'      t = t.replace(%s, () => %s)   // %s %s\n' % (ts_str(a), ts_str(b), TAG, tag))
    new_src = new_src.replace(INSERT_ANCHOR, u''.join(block) + INSERT_ANCHOR, 1)

    after = chain_count(new_src)
    print('chain after = %d (expect %d)' % (after, CHAIN_EXPECT_AFTER))
    if after != CHAIN_EXPECT_AFTER:
        print('::error::chain after mismatch. expected %d, got %d' % (CHAIN_EXPECT_AFTER, after))
        sys.exit(1)

    # ── 配信後のイメージで、狙いどおりになっているか確認 ──
    served = html
    for tag, a, b in PAIRS:
        served = served.replace(a, b, 1)
    # P1 が当たったあとの _defRenderBattle は src 側にしかないので、そこを確認
    checks = [
        ('_defRenderBattle \u3067 _gcGid \u3092 null \u306B\u3057\u3066\u3044\u308B',
         new_src.count(u'window._defRenderBattle=function(rep){try{_gcGid=null;') == 1),
        ('_gcGid \u3092 \u623B\u3059\u30B3\u30FC\u30C9\u304C\u7121\u3044\uFF08\u9000\u907F\u30FB\u5FA9\u5E30\u3092\u3057\u3066\u3044\u306A\u3044\uFF09',
         (u'_gcGid=_sv' not in new_src) and (u'_gcGid = _sv' not in new_src)),
        ('_gcReward \u306B null \u30AC\u30FC\u30C9\u304C\u5165\u3063\u305F',
         served.count(u'if(gymId===null||gymId===undefined) return 0;') == 1),
        ('_gcPbLaunch \u3067 _gcGid \u3092 null \u306B\u3057\u3066\u3044\u308B',
         served.count(u"trySetMode('gymchallenge'); _gcGid=null; _gcReplay=autoBattleRT") == 1),
        ('_gcGid \u3078\u306E\u4EE3\u5165\u306F html \u5074\u3067 3\u304B\u6240\uFF08\u5BA3\u8A00\u30FB_gcOpenGym\u30FB_gcPbLaunch\uFF09',
         len(re.findall(r'_gcGid\s*=[^=]', served)) == 3),
    ]
    ok = True
    for label, res in checks:
        print('  %s : %s' % (label, 'OK' if res else '*** NG ***'))
        ok = ok and res
    if not ok:
        print('::error::self-check failed')
        sys.exit(1)

    # ── 2026-09-25 \u306E\u4E8B\u6545\u306E\u518D\u767A\u9632\u6B62\u70B9\u691C ──
    bad = re.findall(r'onclick="[^"]*?[^\\]\\\'[^"]*?"', new_src)
    bad = [x for x in bad if '\\\\\'' not in x]
    print('1\u6BB5\u3060\u3051\u306E \\\' \u3092\u4F7F\u3063\u3066\u3044\u308B onclick: %d' % len(bad))
    if bad:
        for x in bad[:5]:
            print('   ', x[:120])
        print('::error::\u5371\u306A\u3044 onclick \u304C\u3042\u308A\u307E\u3059')
        sys.exit(1)

    io.open(TSX, 'w', encoding='utf-8').write(new_src)
    print('patched %s (%d -> %d chars)' % (TSX, len(src), len(new_src)))

    try:
        me = os.path.abspath(__file__)
        if not os.path.isdir('scripts'):
            os.makedirs('scripts')
        if os.path.abspath(SELF_COPY) != me:
            shutil.copyfile(me, SELF_COPY)
        print('kept a copy at %s' % SELF_COPY)
    except Exception as e:
        print('could not self-copy: %s' % e)

    try:
        io.open('/tmp/gcgid_pairs.json', 'w', encoding='utf-8').write(
            json.dumps([{'tag': t_, 'a': a_, 'b': b_} for t_, a_, b_ in PAIRS], ensure_ascii=False))
        print('wrote /tmp/gcgid_pairs.json')
    except Exception:
        pass

    if io.open(HTML, encoding='utf-8').read() != html:
        print('::error::public/index.html changed')
        sys.exit(1)
    print('public/index.html untouched: OK')
    print('DONE %s' % TAG)


if __name__ == '__main__':
    main()
