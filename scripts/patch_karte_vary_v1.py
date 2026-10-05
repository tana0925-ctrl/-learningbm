#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_karte_vary_v1.py --- KARTE_VARY_V1 「つながりのあるカルテ」の便

先生のことば（2つ）:
  1) 「4月からのこと言ったり、最近のこと言ったり、判断してほしいんだよね」
  2) 「これまでに、なんて言ったかもふまえて言ってくれるといいのかなー」

(A) 4月からの話を必須にしない
    いまは「次の4つを必ず全部入れる」の (2) で【4月からの移りかわり】を必須にし、
    さらに「そのうえで【4月からの移りかわり】に、かならず一度は触れる」と二重に要求している。
    そこは月ごとの集計なので、週が変わってもほとんど動かない。
    結果、同じ児童に4週つづけて「4月からずっと〜続いとる」が出ていた（実測）。
      W39「4月からずっと満足度が高いまま続いとる」
      W40「4月から、やった日は50分前後じっくり取り組む流れが続いとる」
      W41「4月からずっと、一回50分前後じっくり学ぶ流れが続いとる」
    → 必須をやめ、「長い話」と「最近の話」のどちらを書くかを判断させる。

(F) 前に渡したカルテを「つながり」のために使う
    いまは published_at の新しい順に2本・各260字。
    先生は同じ週に何度も作り直されるので（実測：2026-W40 は62本）、2本とも同じ週のものに
    なり、外部AIには「先週」しか見えていなかった。
    さらに260字で切ると、末尾の問いかけが落ちる。そこが今回いちばん使う部分。
    → 週ごとに1本・直近4週・全文・いつの文か分かる形。
      そのうえで指示文に
        ・前の問いかけが どうなったかに触れる（やっていれば認める／やっていなくても責めない）
        ・前に言ったことから変わったことがあれば、その変化を言う
        ・ただし毎回むりに触れない。ふさわしい週かどうかはAIが判断する
      を入れる。

(その他)
    ・見立ての語尾の例を散らす（「〜かもしれんな」が95%。語尾を1つだけ例示した副作用）
    ・「書くことが少ない週は短くてよい」を実際に効かせる（(2)必須のせいで効いていなかった）

さわるファイル:
  public/teacher-ai.js   … 指示文と、過去カルテの出力
  src/index.tsx          … pick の過去カルテの取り方 ＋ teacher-ai.js の ?v= を 10→11
  ※ public/index.html・public/student-karte.js・防衛戦まわりには一切さわらない。
  ※ src/index.tsx の app.get('/') 〜 app.get('/logout') の .replace( チェーンは1本も増やさない
     （書きかえるのは 9786行より後ろの2か所だけ）。

安全策:
  - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
  - 冪等: 目印 SENTINEL があれば何もしない
  - チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
  - 置換後にチェーン件数が変わっていないことを再確認する
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
TAI  = os.path.join(ROOT, 'public', 'teacher-ai.js')

SENTINEL = 'KARTE_VARY_V1'


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


# -- チェーン照合（1文字も書く前に） --------------------------------
tsx = io.open(TSX, encoding='utf-8', newline='').read()
chain_before = chain_count(tsx)
want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want or not want.isdigit():
    fail('CHAIN_BEFORE が渡されていない/数字でない: %r' % want)
if chain_before != int(want):
    fail('置換チェーンが %d 件（期待 %s 件）。ほかの便が入った可能性があるので中止'
         % (chain_before, want))
print('OK 置換チェーン: %d 件（期待どおり）' % chain_before)

tai = io.open(TAI, encoding='utf-8', newline='').read()

if SENTINEL in tai or SENTINEL in tsx:
    print('-- すでに適用済み（目印あり）。何もしません')
    sys.exit(0)

for mark, where, name in (
    ('karte-materials/pick', tai, 'teacher-ai.js の KARTE_MATERIAL_V1'),
    ('KARTE_FRESH_V1', tsx, 'src/index.tsx の KARTE_FRESH_V1'),
):
    if mark not in where:
        fail('%s が入っていない' % name)

NL = '\n'

# ============================================================
# (A) 指示文
# ============================================================

A1_OLD = (
    "      out.push('      - 次の4つを必ず全部入れる（順番は自由。1文に2つ入れてもよい）:');" + NL +
    "      out.push('        (1) 先週の事実を1つ。本人が書いたことばを「 」でそのまま引用する');" + NL +
    "      out.push('        (2) 【4月からの移りかわり】から1つ（のびた／夏休みで落ちた／ずっと続いている）');" + NL +
    "      out.push('        (3) 見立てを1つ。「〜かもしれん」「〜ちゃうか？」と、見立てと分かる語尾で');" + NL +
    "      out.push('        (4) 本人が決められる問いかけで終わる');" + NL
)
A1_NEW = (
    "      out.push('      - 次の4つを入れる（順番は自由。1文に2つ入れてもよい）:');  /* KARTE_VARY_V1 */" + NL +
    "      out.push('        (1) 先週の事実を1つ。本人が書いたことばを「 」でそのまま引用する');" + NL +
    "      out.push('        (2) 「4月からの長い話」と「ここ最近の話」のどちらかを1つ。');" + NL +
    "      out.push('            ★どちらを書くかは、あなたがこの子の今週を見て判断してください。');" + NL +
    "      out.push('              決め方は下の「長い話と最近の話、どちらを書くか」を読むこと。');" + NL +
    "      out.push('        (3) 見立てを1つ。言い切らない語尾で書く。語尾は毎回変える。');" + NL +
    "      out.push('            例：〜なんちゃうか？／〜みたいやな／〜っぽいな／〜なんやろな／');" + NL +
    "      out.push('                〜そうやな／〜のかもしれん／〜ってことやろか。');" + NL +
    "      out.push('            【前に渡したカルテ】と同じ語尾をくり返さない。');" + NL +
    "      out.push('        (4) 本人が決められる問いかけで終わる');" + NL
)
tai = rep1(tai, A1_OLD, A1_NEW, 'A-1 4点の見出しと(2)(3)')

A2_OLD = (
    "      out.push('      - そのうえで【4月からの移りかわり】に、かならず一度は触れる。');" + NL +
    "      out.push('        のびたところ／夏休みで落ちたところ／ずっと続いていること のどれか一つでよい。');" + NL +
    "      out.push('        1週間だけでは言えない話が、その子にはいちばん効きます。');" + NL
)
A2_NEW = (
    "      out.push('      - ★長い話と最近の話、どちらを書くか（ここを判断してほしい）');  /* KARTE_VARY_V1 */" + NL +
    "      out.push('        【4月からの移りかわり】に毎回触れる必要はありません。必須ではありません。');" + NL +
    "      out.push('        「4月からの長い話」と「ここ最近の話」の、その子の今週にふさわしいほうを選ぶ。');" + NL +
    "      out.push('        ・先週に新しい動きがあった子（やり方が変わった・つまずいた・新しい単元に出会った・');" + NL +
    "      out.push('          止まっていた記録が再開した）→ 最近の話。長期の話は書かない。');" + NL +
    "      out.push('        ・先週は大きな動きがなく、長い目で見ると変化が見える子 → 4月からの話。');" + NL +
    "      out.push('        ・どちらも書けるときは、前の週に書かなかったほうを選ぶ。');" + NL +
    "      out.push('        毎回おなじほうを選ばないこと。これがいちばん大事です。');" + NL +
    "      out.push('      - 【前に渡したカルテ】を先に読んでください。');" + NL +
    "      out.push('        そこに「4月から」「ずっと続いとる」「夏休みで落ちた」「◯月は◯回」のような');" + NL +
    "      out.push('        長い期間の言い方があれば、その子には もう長期の話をしています。');" + NL +
    "      out.push('        その場合、今週は長期の話を書かない。最近の話だけで書く。');" + NL +
    "      out.push('        直近4週ぶんが入っているので、4週とも長期の話だったら、必ず最近の話にする。');" + NL
)
tai = rep1(tai, A2_OLD, A2_NEW, 'A-2 判断の指示')

A3_OLD = (
    "      out.push('        280字は上限であって目標ではない。書くことが少ない週は150字でもよい。');" + NL +
    "      out.push('        長くするために、同じことの言いかえを増やさない。');" + NL +
    "      out.push('        「がんばろう」「大事だよ」のような、だれにでも言える文を足さない。');" + NL
)
A3_NEW = (
    "      out.push('        280字は上限であって目標ではない。書くことが少ない週は150字でもよい。');" + NL +
    "      out.push('        長くするために、同じことの言いかえを増やさない。');" + NL +
    "      out.push('        「がんばろう」「大事だよ」のような、だれにでも言える文を足さない。');" + NL +
    "      out.push('      - 書く材料が少ない週は、この下に出てくる4つを むりに全部入れなくてよい。');  /* KARTE_VARY_V1 */" + NL +
    "      out.push('        (1)先週の事実 と (4)問いかけ だけの70〜100字でよいです。');" + NL +
    "      out.push('        足りないぶんを、長い期間の話や「だれにでも言える文」でうめないこと。');" + NL +
    "      out.push('        うめるくらいなら短くする。短い文は手ぬきではありません。');" + NL
)
tai = rep1(tai, A3_OLD, A3_NEW, 'A-3 短く書ける')

A4_OLD = (
    "      out.push('        先週の家庭学習・本人のことば・4月からの移りかわり だけで書く。');" + NL +
    "      out.push('        むりに掘り返さない。書くことが少ない週は、短くてよいです。');" + NL
)
A4_NEW = (
    "      out.push('        先週の家庭学習と、本人が書いたことばで書く。');  /* KARTE_VARY_V1 */" + NL +
    "      out.push('        それでも書けないときだけ【4月からの移りかわり】を使う。');" + NL +
    "      out.push('        むりに掘り返さない。書くことが少ない週は、短くてよいです。');" + NL
)
tai = rep1(tai, A4_OLD, A4_NEW, 'A-4 取り込みなしのときの書き方')

# ============================================================
# (F) つながり ― 前に言ったことを踏まえる
# ============================================================
A5_OLD = (
    "      out.push('      - 【前に渡したカルテ】には、前にこの子へ渡した文が入っています。');" + NL +
    "      out.push('        同じ話題・同じほめ方・同じ問いかけをくり返さない。');" + NL +
    "      out.push('        前の文の続きとして書く（例：先週言うてた◯◯、その後どうなった？）か、別の角度から書く。');" + NL
)
A5_NEW = (
    "      out.push('      - ★前に言ったことを踏まえる（ここも判断してほしい）');  /* KARTE_VARY_V1 */" + NL +
    "      out.push('        【前に渡したカルテ】には、この子へ渡した文が 週ごとに1本・直近4週ぶん・');" + NL +
    "      out.push('        いつの文か分かる形で・全文 入っています。新しい順です。');" + NL +
    "      out.push('        阪神マンは、毎週バラバラのことを言う相手ではありません。');" + NL +
    "      out.push('        先週この子に何と言ったかを覚えている相手として書いてください。');" + NL +
    "      out.push('        (a) 前のカルテは、最後が問いかけで終わっています。その問いかけが');" + NL +
    "      out.push('            どうなったかを、今週の記録から確かめて、ひとこと触れる。');" + NL +
    "      out.push('            ・やっていたら、それを見つけて認める');" + NL +
    "      out.push('              （例：先週「どっちからいく？」て聞いたやつ、ちゃんと漢字から始めとったな）');" + NL +
    "      out.push('            ・やっていなくても責めない。まだこれから、として置いておく');" + NL +
    "      out.push('              （例：先週聞いたやつ、まだ答えは出てへんみたいやな。今週はどうする？）');" + NL +
    "      out.push('            ・記録からは分からないときは、分かったふりをしない。触れない。');" + NL +
    "      out.push('        (b) 前に言ったことから変わったことがあれば、その変化を言う。');" + NL +
    "      out.push('            （例：先週は時間が短かったけど、今週は40分まで伸びとるな）');" + NL +
    "      out.push('        (c) ただし毎回むりに触れない。触れることが不自然な週もあります。');" + NL +
    "      out.push('            今週の中身と前の問いかけがつながらないときは、触れずに今週の話を書く。');" + NL +
    "      out.push('            触れるかどうかは、あなたがこの子の今週を見て判断してください。');" + NL +
    "      out.push('        (d) 同じ話題・同じほめ方・同じ語尾・同じ問いかけはくり返さない。');" + NL +
    "      out.push('            4週ぶんを見わたして、くり返しになっている言い方を見つけ、それを避ける。');" + NL +
    "      out.push('            (a)で前の問いかけに触れるのは「くり返し」ではありません。つながりです。');" + NL
)
tai = rep1(tai, A5_OLD, A5_NEW, 'A-5 つながりの指示')

A6_OLD = "    out.push('・【4月からの移りかわり】…月ごとの動きと、前期(4〜7月)→後期(8月〜)のくらべ。カルテで一度は触れる。');"
A6_NEW = "    out.push('・【4月からの移りかわり】…月ごとの動きと、前期(4〜7月)→後期(8月〜)のくらべ。/* KARTE_VARY_V1 */ カルテでは必須ではない。最近の話とどちらを書くか判断する材料。');"
tai = rep1(tai, A6_OLD, A6_NEW, 'A-6 並びの説明（移りかわり）')

A7_OLD = "    out.push('・【前に渡したカルテ】…前にこの子へ渡した文。同じことを書かないための参考。');"
A7_NEW = "    out.push('・【前に渡したカルテ】…この子へ渡した文。週ごとに1本・直近4週・全文・いつの文か分かる形。くり返しを避けるためと、前に言ったことを踏まえるための材料。');"
tai = rep1(tai, A7_OLD, A7_NEW, 'A-7 並びの説明（前に渡したカルテ）')

# -- 出力（いつの文か分かる形にする） ------------------------------
F1_OLD = (
    "        if (_pk && _pk.pastKartes && _pk.pastKartes.length) {" + NL +
    "          out.push('');" + NL +
    "          out.push('【前に渡したカルテ（同じことを書かないための参考）】');" + NL +
    "          _pk.pastKartes.forEach(function (pkx) { out.push('・' + (pkx.on || '') + ' に渡した文：' + pkx.text); });" + NL +
    "        }" + NL
)
F1_NEW = (
    "        if (_pk && _pk.pastKartes && _pk.pastKartes.length) {   /* KARTE_VARY_V1 */" + NL +
    "          out.push('');" + NL +
    "          out.push('【前に渡したカルテ（新しい順・週ごとに1本・' + _pk.pastKartes.length + '週ぶん・全文）】');" + NL +
    "          out.push('※いちばん上が、前回この子に渡した文です。最後の問いかけまで全部あります。');" + NL +
    "          _pk.pastKartes.forEach(function (pkx, _pki) {" + NL +
    "            out.push('・' + _karteAgoLabel(pkx.week, wk, _pki) + '（' + (pkx.on || '日付不明') + ' に渡した／対象の週キー ' + (pkx.week || '不明') + '）：' + pkx.text);" + NL +
    "          });" + NL +
    "        }" + NL
)
tai = rep1(tai, F1_OLD, F1_NEW, 'F-1 過去カルテの出力')

# -- ラベルを作る小さな関数（isoWeekOf のすぐ後ろに足す） ----------
F0_OLD = "function isoWeekOf(ymd) {"
F0_NEW = (
    "/* KARTE_VARY_V1 前に渡したカルテが「いつの文か」を日本語にする。" + NL +
    "   週キー（2026-W40 のような形）どうしの差で数える。差が出せないときは順番で言う。" + NL +
    "   カルテは月曜に作って配るので、作った週の1つ前の週について書いてある。" + NL +
    "   ここで言う「前回」は、前に作って渡した文のこと。 */" + NL +
    "function _karteWkNum(k) {" + NL +
    "  var m = String(k || '').match(/^(\\d{4})-W(\\d{1,2})$/);" + NL +
    "  if (!m) return null;" + NL +
    "  return Number(m[1]) * 53 + Number(m[2]);" + NL +
    "}" + NL +
    "function _karteAgoLabel(pastWk, nowWk, idx) {" + NL +
    "  var a = _karteWkNum(pastWk), b = _karteWkNum(nowWk);" + NL +
    "  if (a != null && b != null && b - a >= 1) {" + NL +
    "    var d = b - a;" + NL +
    "    return (d === 1) ? '前回（先週つくった文）' : (d + '週前につくった文');" + NL +
    "  }" + NL +
    "  return (idx === 0) ? '前回（いちばん新しい文）' : ((idx + 1) + '本前の文');" + NL +
    "}" + NL +
    "function isoWeekOf(ymd) {"
)
tai = rep1(tai, F0_OLD, F0_NEW, 'F-0 いつの文かのラベル')

# ============================================================
# (F) 取り方（src/index.tsx）
# ============================================================
F2_OLD = (
    "  // 前に渡したカルテ（同じことを書かせないための参考）。クラスで1本・約200行。" + NL +
    "  try {" + NL +
    "    const r = await c.env.DB.prepare(`SELECT target_id, body, published_at FROM ai_review_drafts WHERE class_id=? AND kind='KARTE' AND status='published' ORDER BY published_at DESC LIMIT 200`).bind(classId).all<any>()" + NL +
    "    for (const d of (((r && r.results) || []) as any[])) {" + NL +
    "      const o = out[String(d.target_id || '')]" + NL +
    "      if (!o || o.pastKartes.length >= 2) continue" + NL +
    "      o.pastKartes.push({ on: String(d.published_at || '').slice(0, 10), text: String(d.body || '').slice(0, 260) })" + NL +
    "    }" + NL +
    "  } catch (e) {}" + NL
)
F2_NEW = (
    "  // 前に渡したカルテ。クラスで1本。" + NL +
    "  // KARTE_VARY_V1 週ごとに1本・直近4週・全文・週キーつき。" + NL +
    "  //   ねらいは2つ。(1)くり返しを避ける (2)前に言ったことを踏まえて書けるようにする。" + NL +
    "  //   これまでは published_at の新しい順に2本だった。先生は同じ週に何度も作り直されるので" + NL +
    "  //   （実測：2026-W40 は62本）、2本とも同じ週のものになり、外部AIには「先週」しか" + NL +
    "  //   見えていなかった。4週つづけて同じ長期傾向を書いていても気づけない。" + NL +
    "  //   同じ週に何本もあるときは、いちばん新しい1本だけを残す。" + NL +
    "  //   全文にするのは、カルテの最後の問いかけが260字で切れていたため。" + NL +
    "  //   次の週に「あれ、どうなった？」と書くには、その問いかけが要る。" + NL +
    "  //   300字で切るのは念のため（本文の上限は280字なので実質は全文）。" + NL +
    "  try {" + NL +
    "    const r = await c.env.DB.prepare(`SELECT target_id, week_key, body, published_at FROM ai_review_drafts WHERE class_id=? AND kind='KARTE' AND status='published' ORDER BY published_at DESC LIMIT 600`).bind(classId).all<any>()" + NL +
    "    const seenWeek: Record<string, number> = {}" + NL +
    "    for (const d of (((r && r.results) || []) as any[])) {" + NL +
    "      const uid = String(d.target_id || '')" + NL +
    "      const o = out[uid]" + NL +
    "      if (!o) continue" + NL +
    "      const wkk = String(d.week_key || '')" + NL +
    "      const seenKey = uid + '|' + wkk" + NL +
    "      if (seenWeek[seenKey]) continue          // 同じ週は いちばん新しい1本だけ" + NL +
    "      seenWeek[seenKey] = 1" + NL +
    "      if (o.pastKartes.length >= 4) continue   // 直近4週ぶん" + NL +
    "      o.pastKartes.push({ on: String(d.published_at || '').slice(0, 10), week: wkk, text: String(d.body || '').slice(0, 300) })" + NL +
    "    }" + NL +
    "  } catch (e) {}" + NL
)
tsx = rep1(tsx, F2_OLD, F2_NEW, 'F-2 過去カルテの取り方')

V_OLD = '<script src="/teacher-ai.js?v=10"></script>'
V_NEW = '<script src="/teacher-ai.js?v=11"></script>'
tsx = rep1(tsx, V_OLD, V_NEW, '?v= の更新')

# -- 置換後の確認 --------------------------------------------------
chain_after = chain_count(tsx)
if chain_after != chain_before:
    fail('置換チェーンが %d -> %d 件に変わった。書かずに中止' % (chain_before, chain_after))
print('OK 置換チェーン（後）: %d 件（変化なし）' % chain_after)

if '必ず全部入れる' in tai:
    fail('「必ず全部入れる」が残っている')
if 'かならず一度は触れる' in tai:
    fail('「かならず一度は触れる」が残っている')
if '_karteAgoLabel' not in tai:
    fail('ラベル関数が入っていない')
if tai.count(SENTINEL) < 8:
    fail('目印が %d 個しかない（8個以上のはず）' % tai.count(SENTINEL))
if tsx.count(SENTINEL) < 1:
    fail('src/index.tsx に目印が無い')

io.open(TAI, 'w', encoding='utf-8', newline='').write(tai)
io.open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK 書き込み完了: public/teacher-ai.js, src/index.tsx')
print('   A: 4月からの話を必須から外し、最近の話とどちらを書くか判断させる')
print('   F: 前に渡したカルテを 週ごとに1本・直近4週・全文・いつの文か分かる形 に')
print('   F: 前の問いかけがどうなったかに触れる（毎回ではなく、ふさわしい週に）')
print('   他: 見立ての語尾を7つに散らす / 材料が少ない週は70〜100字で出せる')
print('   teacher-ai.js ?v=10 -> ?v=11')
