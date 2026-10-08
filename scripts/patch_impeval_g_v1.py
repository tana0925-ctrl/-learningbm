# -*- coding: utf-8 -*-
# IMPEVAL_G_V1 (2026-10-08)  成果物の「評価」を受け取れるようにする配管
#
# 先生の希望：成果物の取り込みで、評定(A/B/C)と根拠の言葉を3観点ぶん書かせたい。
#   知識・技能：B
#   　「〜ができている。ただし〜」
#
# 本番のパーサにこの書式をそのまま通して確かめたところ（読み取りのみ）、
#   dest          = "score"   → 通信簿(student_test_scores)行き。カルテの材料にならない
#   evalKnowledge = "○"       → B が ◎○△ に変換されて観点別評価の列へ
#   evalComment   = ""        → 根拠の言葉が1文字も残らない
# となった。先生の「そのまま通信簿になるものではない」と正反対なので、
# プロンプトを変える前に、受け皿のほうを直す。
#
# やること（プロンプト本体 S1 は次の便）
#   S2 _recParseText：評価コメントの中にいる間は、知識/思考/主体/態度 を
#      観点別評価の見出しとして拾わない。コメントの続きとして取り込む。
#      → 行き先が「記録」のまま、根拠の言葉も残る。
#      ブロック形式で 知識・技能： を出すものは現状ひとつも無い
#      （テスト用プロンプトは「児童名, 点数, 知技, 思判表, 主体, コメント」の
#        カンマ区切りで、こことは別経路）。
#   S3 評定が空のとき評価コメントが丸ごと落ちていたのを直す（2か所）。
#      いまの三項演算子は evalRank が空だと '' を返すため、
#      「評価なければ」の今回の用途でコメントが阪神マンに届かない。
#   S4 カルテ材料に渡す評価コメントの 120字 を 500字 に広げる。
#      3観点＋根拠は確実に 120字 を超える。
#   S5 阪神マンに渡す前に A/B/C と ◎○△ を落とし、言葉だけ渡す。
#      KARTE_TEST_V1「子どもの紙に評価記号が出る事故を構造で防ぐ」を迂回させない。
#      先生の画面（個人分析のポートフォリオ）は別経路なので A/B/C はそのまま出る。
#   S6 先生の画面で評価コメントの改行が見えるようにする（3行になるため）。
#
# さわるのは src/index.tsx の教師画面とサーバAPIだけ。
# 児童の配信チェーンは増減させない。public/index.html には一切さわらない。
# アンカーが想定数でなければ1文字も書かずに止まる（fail-closed）。
import os
import sys

TSX = 'src/index.tsx'


def die(msg):
    print('::error::' + msg)
    sys.exit(1)


def chain_count(s):
    a = s.index("app.get('/', async (c) => {")
    b = s.index("app.get('/logout'", a)
    return s[a:b].count('.replace(')


raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if not raw.isdigit():
    die('CHAIN_BEFORE が数字で渡されていません: %r' % raw)
CHAIN_BEFORE = int(raw)

tsx = open(TSX, encoding='utf-8').read()
chain0 = chain_count(tsx)
if chain0 != CHAIN_BEFORE:
    die('チェーン件数が合いません 実測=%d 申告=%d' % (chain0, CHAIN_BEFORE))
if tsx.count('IMPEVAL_G_V1') != 0:
    die('IMPEVAL_G_V1 はすでに当たっています')


def one(old, new, label):
    global tsx
    if tsx.count(old) != 1:
        die('%s のアンカーが %d 件（1件のはず）' % (label, tsx.count(old)))
    tsx = tsx.replace(old, new, 1)


# ---- S2 評価コメントの中では観点別の見出しとして拾わない ----
one("      else if(k.indexOf('知技')>=0||k.indexOf('知識')>=0){ cur.evalKnowledge=_recNormRank(v); sec=null; handled=true; }",
    "      // \U0001F4CC IMPEVAL_G_V1 評価コメントの中にいる間は観点別の見出しとして拾わない。\n"
    "      //    拾うと _impDest が通信簿側へ振り分け、根拠の言葉もそこで打ち切られる。\n"
    "      else if(sec!=='evalComment'&&(k.indexOf('知技')>=0||k.indexOf('知識')>=0)){ cur.evalKnowledge=_recNormRank(v); sec=null; handled=true; }",
    'S2a')
one("      else if(k.indexOf('思判表')>=0||k.indexOf('思考')>=0){ cur.evalThinking=_recNormRank(v); sec=null; handled=true; }",
    "      else if(sec!=='evalComment'&&(k.indexOf('思判表')>=0||k.indexOf('思考')>=0)){ cur.evalThinking=_recNormRank(v); sec=null; handled=true; }",
    'S2b')
one("      else if(k.indexOf('主体')>=0||k.indexOf('態度')>=0){ cur.evalAttitude=_recNormRank(v); sec=null; handled=true; }",
    "      else if(sec!=='evalComment'&&(k.indexOf('主体')>=0||k.indexOf('態度')>=0)){ cur.evalAttitude=_recNormRank(v); sec=null; handled=true; }",
    'S2c')

# ---- S3 評定が空でも評価コメントを出す（2か所） ----
OLD3 = "var _ev2=rc2.evalRank?('／評価:'+rc2.evalRank+((rc2.evalComment&&String(rc2.evalComment).trim())?'／評価コメント:'+rc2.evalComment:'')):''"
if tsx.count(OLD3) != 2:
    die('S3 のアンカーが %d 件（2件のはず）' % tsx.count(OLD3))
NEW3 = ("var _ev2=((rc2.evalRank?'／評価:'+rc2.evalRank:'')+((rc2.evalComment&&String(rc2.evalComment).trim())?'／評価コメント:'+rc2.evalComment:''))"
        " /* IMPEVAL_G_V1 評定が空でも評価コメントは渡す */")
tsx = tsx.replace(OLD3, NEW3, 2)

# ---- S4+S5 カルテ材料：500字に広げ、評定記号を落としてから渡す ----
one("evalComment: String(r.eval_comment || '').slice(0, 120)",
    "evalComment: _evalNoRank(r.eval_comment).slice(0, 500)",
    'S4/S5')

# _evalNoRank を _recNormRank の直前に置く（同じ取り込みまわりの関数群のところ）
ANCHOR = "function _recNormRank(v){"
if tsx.count(ANCHOR) != 1:
    die('_recNormRank のアンカーが %d 件（1件のはず）' % tsx.count(ANCHOR))
HELPER = (
    "// \U0001F4CC IMPEVAL_G_V1 阪神マンに渡す前に評定記号を落とす。言葉はそのまま残す。\n"
    "//    KARTE_TEST_V1「子どもの紙に評価記号が出る事故を構造で防ぐ」を迂回させないため。\n"
    "//    先生の画面（個人分析のポートフォリオ）は別経路なので A/B/C はそのまま出る。\n"
    "function _evalNoRank(v: any): string {\n"
    "  let t = String(v == null ? '' : v)\n"
    "  t = t.replace(/(\u77e5\u8b58\u30fb\u6280\u80fd|\u601d\u8003\u30fb\u5224\u65ad\u30fb\u8868\u73fe|\u4e3b\u4f53\u7684\u306b\u5b66\u7fd2\u306b\u53d6\u308a\u7d44\u3080\u614b\u5ea6|\u77e5\u6280|\u601d\u5224\u8868|\u4e3b\u4f53|\u614b\u5ea6)(\\s*[\uff1a:\uff1d=]\\s*)[ABCabc\uff21\uff22\uff23\uff41\uff42\uff43\u25ce\u25cb\u3007\u25b3]+/g, '$1$2')\n"
    "  t = t.replace(/[\u25ce\u25cb\u3007\u25b3]/g, '')\n"
    "  return t\n"
    "}\n"
)
tsx = tsx.replace(ANCHOR, HELPER + ANCHOR, 1)

# ---- S6 先生の画面で改行が見えるように ----
one("""((it.evalComment&&it.evalComment.trim())?' <span class="text-slate-600">'+escH(it.evalComment)+'</span>':'')""",
    """((it.evalComment&&it.evalComment.trim())?' <span class="text-slate-600 whitespace-pre-line align-top">'+escH(it.evalComment)+'</span>':'')""",
    'S6')

bad = False
chain1 = chain_count(tsx)
print('チェーン件数 前=%d 後=%d' % (chain0, chain1))
if chain0 != chain1:
    print('::error::チェーン件数が変わった')
    bad = True

need = {
    'IMPEVAL_G_V1': 4,
    "sec!=='evalComment'&&(k.indexOf('知技')": 1,
    "sec!=='evalComment'&&(k.indexOf('思判表')": 1,
    "sec!=='evalComment'&&(k.indexOf('主体')": 1,
    "function _evalNoRank(v: any): string {": 1,
    "_evalNoRank(r.eval_comment).slice(0, 500)": 1,
    "slice(0, 120)": 2,
    "String(r.eval_comment || '').slice": 0,
    "var _ev2=((rc2.evalRank?": 2,
    "whitespace-pre-line align-top": 1,
    # 既存の歯止めが消えていないこと
    "KARTE_TEST_V1": 1,
}
for k, want in need.items():
    got = tsx.count(k)
    print('適用後 %-50s %d 件（期待 %d）' % (k, got, want))
    if got != want:
        bad = True

print('エスケープ事故の見張り（増えていないこと） = %d' % tsx.count("(\\'"))
for k in ['IMPNAME_A_V1', 'IMPNAME_B_V1', 'IMPNAME_D_V1', 'IMPNAME_E_V1', 'IMPNAME_E2_V1',
          '__IMPORT_AUTO_V1__', '__IMPORT_CHECK_V1__', 'QUICKNOTE_V1', '_qnMask',
          'karte_material_uses', 'WARMIX', '__WORLD_V3__', '_hash', 'cannot_trade_special']:
    if tsx.count(k) < 1:
        print('::error::安全マーカー %r が消えました' % k)
        bad = True
if bad:
    sys.exit(1)

open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK: src/index.tsx %d 文字' % len(tsx))
