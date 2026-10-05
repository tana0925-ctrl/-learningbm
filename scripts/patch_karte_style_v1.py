#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_karte_style_v1.py --- KARTE_STYLE_V1 「どう学ぶといいか」の3単元が同じ文になるのを直す

別のセッションが 2026-09-25 に見つけていた不具合（scripts/patch_karte_slim_v1.py のメモ）:
  「『出会ったばかり』の一文が3単元とも同じになっていた」

これは今回ずっと直してきたものと同じ種類の不具合（同じ文がくり返される）。
styleFor() は 1問あたりの反復回数だけで文を選ぶので、3単元とも同じ帯に入ると
3行とも一字一句おなじになる。

💡 どう学ぶといいか は 第1便で子どもに渡す紙からは外したが、
先生の「📊 個人分析」画面では いまも使われている（_kHowToLearn(data) の呼び出しが残っている）。
だから直す価値がある。

直し方:
  styleFor(p) -> styleFor(p, i) にして、単元の位置でも言い方を変える。
    i===0 … いま効くところ
    i===1 … つぎ
    i===2 … ならし
  反復回数での3つの分かれ道（周回ぎみ／出会ったばかり／ふつう）は そのまま残し、
  それぞれに3通りの言い方を用意する。

※ 別セッションの scripts/patch_karte_slim_v1.py には一切さわらない。
  あちらは未実行で、ほかに グラフを残す方針の変更が入っているため、流すと今回の便と衝突する。
  ここでは この不具合だけを こちらの便として直す。

さわるファイル: src/index.tsx の _kHowToLearn だけ。
  .replace( チェーンは1本も増やさない。D1には触らない。
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
SENTINEL = 'KARTE_STYLE_V1'


def fail(msg):
    print('NG 中止: ' + msg)
    sys.exit(1)


def chain_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')


def rep1(text, old, new, label):
    n = text.count(old)
    if n != 1:
        fail('%s が %d 箇所（1箇所のはず）' % (label, n))
    return text.replace(old, new, 1)


tsx = io.open(TSX, encoding='utf-8', newline='').read()
chain_before = chain_count(tsx)
want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want or not want.isdigit():
    fail('CHAIN_BEFORE が渡されていない/数字でない: %r' % want)
if chain_before != int(want):
    fail('置換チェーンが %d 件（期待 %s 件）。ほかの便が入った可能性があるので中止' % (chain_before, want))
print('OK 置換チェーン: %d 件（期待どおり）' % chain_before)

if SENTINEL in tsx:
    print('-- すでに適用済み（目印あり）。何もしません')
    sys.exit(0)
if 'function _kHowToLearn' not in tsx:
    fail('_kHowToLearn が無い')
if '_kHowToLearn(data)' not in tsx:
    fail('先生の個人分析で _kHowToLearn が使われていない。直す意味が無いので中止')

NL = '\n'

OLD = (
    "var styleFor=function(p){" + NL +
    "          var r=Number(p.repeatPer);" + NL +
    "          if(r&&r>=5) return '同じ問題をなん回も解いとる単元やから、答えを覚えてるだけかもしれん。新しい問題のほうに行ってみよう';" + NL +
    "          if(r&&r>0&&r<2) return 'まだ1問を1回ずつ。出会ったばかりやから、まちがえた問題をその場でもう一度だけ解き直すところから';" + NL +
    "          return 'まちがえた問題に印をつけて、次の日にもう一度だけ解き直す';" + NL +
    "        };"
)
NEW = (
    "/* KARTE_STYLE_V1 反復回数だけで選んでいたので、3単元が同じ帯に入ると" + NL +
    "           3行とも一字一句おなじ文になっていた（別セッションが2026-09-25に見つけたもの）。" + NL +
    "           同じ文がくり返される、という今回ずっと直してきたのと同じ種類の不具合。" + NL +
    "           単元の位置（1番目＝いま効く／2番目＝つぎ／3番目＝ならし）でも言い方を変える。 */" + NL +
    "        var styleFor=function(p, i){" + NL +
    "          var r=Number(p.repeatPer);" + NL +
    "          if(r&&r>=5){" + NL +
    "            if(i===0) return '同じ問題をなん回も解いとるな。答えを覚えてるだけかもしれんから、新しい問題に当たってみよう';" + NL +
    "            if(i===1) return 'ここも回数が多い。数をこなすより、1問をていねいに見るほうが効くと思うで';" + NL +
    "            return '回数は十分や。たまに別の問題で試して、ほんまに分かってるか確かめてみ';" + NL +
    "          }" + NL +
    "          if(r&&r>0&&r<2){" + NL +
    "            if(i===0) return 'まだ1問を1回ずつ。出会ったばかりやから、まちがえた1問をその場で解き直すところから';" + NL +
    "            if(i===1) return 'ここも始めたばかり。答えを見てからでええから、もう一度自分で書いてみよう';" + NL +
    "            return 'まだ数が少ない単元や。今週は1問でも当たれたら上出来やで';" + NL +
    "          }" + NL +
    "          if(i===0) return 'まちがえた問題に印をつけて、次の日にもう一度だけ解き直す';" + NL +
    "          if(i===1) return '前にまちがえた問題だけ、さっと見直す';" + NL +
    "          return '思い出せるかどうかだけ、ためしてみる';" + NL +
    "        };"
)
tsx = rep1(tsx, OLD, NEW, 'styleFor の定義')
tsx = rep1(tsx, "esc(styleFor(p))", "esc(styleFor(p, i))", 'styleFor の呼び出し')

chain_after = chain_count(tsx)
if chain_after != chain_before:
    fail('置換チェーンが %d -> %d 件に変わった。書かずに中止' % (chain_before, chain_after))
print('OK 置換チェーン（後）: %d 件（変化なし）' % chain_after)

if 'var styleFor=function(p){' in tsx:
    fail('古い styleFor が残っている')
if 'esc(styleFor(p))' in tsx:
    fail('古い呼び出しが残っている')
if tsx.count(SENTINEL) < 1:
    fail('目印が無い')

io.open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK 書き込み完了: src/index.tsx')
print('   styleFor(p) -> styleFor(p, i)。3単元で言い方が変わるようにした')
