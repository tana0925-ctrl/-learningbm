#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_karte_vary_v2.py --- KARTE_VARY_V2 参照を6週にして、それより前は「たな卸し」

先生のことば:
  「前の週だけじゃなくもっとたくさんでもいいね」

V1 では【前に渡したカルテ】を 週ごとに1本・直近4週・全文 で渡すようにした。
もっと増やしたいが、全部を全文で渡すと年度末に破綻する。

  実測（6年2組・published カルテを週ごと1本に畳んだもの）
    1本あたり平均160字（最長217字）、ラベルで+45字。
    いまは5週ぶん109本＝17,383字。
    3月まで約29週になるので、全部を全文にすると約137,000字。
    束（いま約57,000字）の7割が過去カルテになり、肝心の先週の記録が埋もれる。

  → 直近6週は全文。それより前は本文を渡さず「どの手をもう使ったか」だけ残す。
     くり返しを避けるのに本当に要るのは「前に何を言ったか」ではなく
     「長期ネタをいつ使ったか」と「問いかけの型」だから。
     これは週が何週に増えても長さが変わらない（1人400字以内）。

この便でやること:
  1) pastKartes を 4週 → 6週。
  2) 6週より前のぶんから、本文を渡さずに次だけ集める（たな卸し）:
       ・長期の言い方（4月から／ずっと／夏休み／◯月は／前期）を含む週キー（最大12）
       ・末尾の問いかけ文（重複を除いて最大8件・各40字）
       ・何週ぶんあるか
  3) 束では、6本の全文のすぐ下に たな卸しを置く。
     （長い束ほど真ん中が読み飛ばされやすいので、関係するものを隣に置く）
  4) 指示文の「4週」を「6週」に直し、
     「6週より前は要点だけで本文はない。そこから問いかけを探さないこと」を明記する。

さわるファイル:
  public/teacher-ai.js   … 指示文と、たな卸しの出力
  src/index.tsx          … pick の集め方 ＋ teacher-ai.js の ?v= を 11→12
  ※ public/index.html・public/student-karte.js・防衛戦まわりには一切さわらない。
  ※ .replace( チェーンは1本も増やさない。
  ※ D1には書き込まない。karte_material_uses にも触らない。

安全策:
  - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
  - 冪等: 目印 SENTINEL があれば何もしない
  - V1 が入っていることを確かめる
  - チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
  - 置換後にチェーン件数が変わっていないことを再確認する
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
TAI  = os.path.join(ROOT, 'public', 'teacher-ai.js')

SENTINEL = 'KARTE_VARY_V2'


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
    fail('置換チェーンが %d 件（期待 %s 件）。ほかの便が入った可能性があるので中止'
         % (chain_before, want))
print('OK 置換チェーン: %d 件（期待どおり）' % chain_before)

tai = io.open(TAI, encoding='utf-8', newline='').read()

if SENTINEL in tai or SENTINEL in tsx:
    print('-- すでに適用済み（目印あり）。何もしません')
    sys.exit(0)

if 'KARTE_VARY_V1' not in tai or 'KARTE_VARY_V1' not in tsx:
    fail('KARTE_VARY_V1 が入っていない。先にそちらを流すこと')

NL = '\n'

# ============================================================
# src/index.tsx  集め方
# ============================================================

# 入れ物に たな卸し用の欄を足す
S1_OLD = "  for (const m of mem) out[String(m.uid)] = { materials: [], pastKartes: [], exhausted: true, heldBack: 0, dropped: 0, tooOld: 0 }"
S1_NEW = (
    "  // KARTE_VARY_V2 pastAsks / longWeeks / olderWeeks は「6週より前のたな卸し」。本文は入れない。" + NL +
    "  for (const m of mem) out[String(m.uid)] = { materials: [], pastKartes: [], pastAsks: [], longWeeks: [], olderWeeks: 0, exhausted: true, heldBack: 0, dropped: 0, tooOld: 0 }"
)
tsx = rep1(tsx, S1_OLD, S1_NEW, 'S-1 入れ物')

S2_OLD = "  // KARTE_VARY_V1 週ごとに1本・直近4週・全文・週キーつき。"
S2_NEW = "  // KARTE_VARY_V1 週ごとに1本・全文・週キーつき。KARTE_VARY_V2 で直近6週に広げた。"
tsx = rep1(tsx, S2_OLD, S2_NEW, 'S-2 見出しコメント')

S3_OLD = (
    "      if (o.pastKartes.length >= 4) continue   // 直近4週ぶん" + NL +
    "      o.pastKartes.push({ on: String(d.published_at || '').slice(0, 10), week: wkk, text: String(d.body || '').slice(0, 300) })" + NL
)
S3_NEW = (
    "      // KARTE_VARY_V2 直近6週は全文。それより前は本文を渡さず「どの手を使ったか」だけ残す。" + NL +
    "      //   全部を全文にすると年度末で約137,000字になり、束の大半が過去カルテになるため。" + NL +
    "      //   ここで集めるものは週が増えても長さが変わらない。" + NL +
    "      if (o.pastKartes.length >= 6) {" + NL +
    "        const ob = String(d.body || '')" + NL +
    "        o.olderWeeks = (o.olderWeeks || 0) + 1" + NL +
    "        // 長い期間の言い方を使った週（この子に もう長期の話をしたか）" + NL +
    "        if (/4月から|ずっと|夏休み|[0-9]+月は|前期/.test(ob) && o.longWeeks.length < 12) o.longWeeks.push(wkk)" + NL +
    "        // 末尾の問いかけ（同じ聞き方をくり返さないため）" + NL +
    "        const qi = ob.lastIndexOf('？')" + NL +
    "        if (qi > 0) {" + NL +
    "          let st = 0" + NL +
    "          for (const mk of ['。', '！', '？', '\\n']) { const p = ob.lastIndexOf(mk, qi - 1); if (p + 1 > st) st = p + 1 }" + NL +
    "          const q = ob.slice(st, qi + 1).trim().slice(0, 40)" + NL +
    "          if (q.length >= 6 && o.pastAsks.indexOf(q) < 0 && o.pastAsks.length < 8) o.pastAsks.push(q)" + NL +
    "        }" + NL +
    "        continue" + NL +
    "      }" + NL +
    "      o.pastKartes.push({ on: String(d.published_at || '').slice(0, 10), week: wkk, text: String(d.body || '').slice(0, 300) })" + NL
)
tsx = rep1(tsx, S3_OLD, S3_NEW, 'S-3 6週＋たな卸し')

V_OLD = '<script src="/teacher-ai.js?v=11"></script>'
V_NEW = '<script src="/teacher-ai.js?v=12"></script>'
tsx = rep1(tsx, V_OLD, V_NEW, '?v= の更新')

# ============================================================
# public/teacher-ai.js  出力
# ============================================================
T1_OLD = (
    "          _pk.pastKartes.forEach(function (pkx, _pki) {" + NL +
    "            out.push('・' + _karteAgoLabel(pkx.week, wk, _pki) + '（' + (pkx.on || '日付不明') + ' に渡した／対象の週キー ' + (pkx.week || '不明') + '）：' + pkx.text);" + NL +
    "          });" + NL +
    "        }" + NL
)
T1_NEW = (
    "          _pk.pastKartes.forEach(function (pkx, _pki) {" + NL +
    "            out.push('・' + _karteAgoLabel(pkx.week, wk, _pki) + '（' + (pkx.on || '日付不明') + ' に渡した／対象の週キー ' + (pkx.week || '不明') + '）：' + pkx.text);" + NL +
    "          });" + NL +
    "        }" + NL +
    "        /* KARTE_VARY_V2 6週より前の「たな卸し」。本文は渡さない。" + NL +
    "           全文のすぐ下に置く。長い束ほど真ん中が読み飛ばされるので、" + NL +
    "           同じ「前に何をしたか」の話は離さない。 */" + NL +
    "        if (_pk && (_pk.olderWeeks || 0) > 0) {" + NL +
    "          var _olderFrom = (_pk.pastKartes && _pk.pastKartes.length) ? (_pk.pastKartes.length + '週') : 'ここ';" + NL +
    "          out.push('');" + NL +
    "          out.push('【これまでの手の たな卸し（上の' + _olderFrom + 'より前・4月から全部を数えたもの）】');" + NL +
    "          out.push('※ここには本文はありません。「どの手をもう使ったか」だけです。問いかけの中身を探さないでください。');" + NL +
    "          out.push('・上より前に渡した文：' + _pk.olderWeeks + '週ぶん');" + NL +
    "          if (_pk.longWeeks && _pk.longWeeks.length) {" + NL +
    "            out.push('・そのうち「4月から〜」のような長い期間の話をした週：' + _pk.longWeeks.join('、') + '（' + _pk.longWeeks.length + '回）');" + NL +
    "          } else {" + NL +
    "            out.push('・そのうち長い期間の話をした週：なし');" + NL +
    "          }" + NL +
    "          if (_pk.pastAsks && _pk.pastAsks.length) {" + NL +
    "            out.push('・これまでの終わり方（重複をのぞく・新しい順）:');" + NL +
    "            _pk.pastAsks.forEach(function (q) { out.push('　「' + q + '」'); });" + NL +
    "          }" + NL +
    "        }" + NL
)
tai = rep1(tai, T1_OLD, T1_NEW, 'T-1 たな卸しの出力')

# ============================================================
# public/teacher-ai.js  指示文
# ============================================================
T2_OLD = "      out.push('        直近4週ぶんが入っているので、4週とも長期の話だったら、必ず最近の話にする。');"
T2_NEW = (
    "      out.push('        直近6週ぶんの全文と、それより前の【たな卸し】が入っています。');  /* KARTE_VARY_V2 */" + NL +
    "      out.push('        6週とも長期の話だったら、必ず最近の話にする。');" + NL +
    "      out.push('        【たな卸し】の「長い期間の話をした週」が多い子ほど、長期の話はもう足りています。')"
)
tai = rep1(tai, T2_OLD, T2_NEW, 'T-2 判断の指示（週数）')

T3_OLD = (
    "      out.push('        【前に渡したカルテ】には、この子へ渡した文が 週ごとに1本・直近4週ぶん・');" + NL +
    "      out.push('        いつの文か分かる形で・全文 入っています。新しい順です。');" + NL
)
T3_NEW = (
    "      out.push('        【前に渡したカルテ】には、この子へ渡した文が 週ごとに1本・直近6週ぶん・');  /* KARTE_VARY_V2 */" + NL +
    "      out.push('        いつの文か分かる形で・全文 入っています。新しい順です。');" + NL +
    "      out.push('        それより前（4月から全部）は【これまでの手の たな卸し】にまとめてあります。');" + NL +
    "      out.push('        たな卸しに本文はありません。長い期間の話をした週と、これまでの終わり方だけです。');" + NL +
    "      out.push('        たな卸しから問いかけの中身を探さないでください。見つかりません。');" + NL +
    "      out.push('        たな卸しは「同じ手をもう一度使わない」ためだけに読んでください。');" + NL
)
tai = rep1(tai, T3_OLD, T3_NEW, 'T-3 つながりの説明（週数と たな卸し）')

T4_OLD = "      out.push('            4週ぶんを見わたして、くり返しになっている言い方を見つけ、それを避ける。');"
T4_NEW = (
    "      out.push('            6週ぶんの全文と【たな卸し】を見わたして、くり返しになっている言い方を');  /* KARTE_VARY_V2 */" + NL +
    "      out.push('            見つけ、それを避ける。終わり方は たな卸しに出ているものを使い回さない。');"
)
tai = rep1(tai, T4_OLD, T4_NEW, 'T-4 くり返し回避（週数）')

T5_OLD = "    out.push('・【前に渡したカルテ】…この子へ渡した文。週ごとに1本・直近4週・全文・いつの文か分かる形。くり返しを避けるためと、前に言ったことを踏まえるための材料。');"
T5_NEW = (
    "    out.push('・【前に渡したカルテ】…この子へ渡した文。週ごとに1本・直近6週・全文・いつの文か分かる形。くり返しを避けるためと、前に言ったことを踏まえるための材料。');" + NL +
    "    out.push('・【これまでの手の たな卸し】…6週より前（4月から全部）。本文はなく、長い期間の話をした週と、これまでの終わり方だけ。');  /* KARTE_VARY_V2 */"
)
tai = rep1(tai, T5_OLD, T5_NEW, 'T-5 並びの説明')

# ── 置換後の確認 ────────────────────────────────────────────
chain_after = chain_count(tsx)
if chain_after != chain_before:
    fail('置換チェーンが %d -> %d 件に変わった。書かずに中止' % (chain_before, chain_after))
print('OK 置換チェーン（後）: %d 件（変化なし）' % chain_after)

if '直近4週' in tai or '4週ぶん' in tai:
    fail('「4週」の記述が残っている')
if 'pastKartes.length >= 4' in tsx:
    fail('pastKartes の上限が4のまま')
if tai.count(SENTINEL) < 5:
    fail('teacher-ai.js の目印が %d 個しかない（5個以上のはず）' % tai.count(SENTINEL))
if tsx.count(SENTINEL) < 3:
    fail('src/index.tsx の目印が %d 個しかない（3個以上のはず）' % tsx.count(SENTINEL))

io.open(TAI, 'w', encoding='utf-8', newline='').write(tai)
io.open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK 書き込み完了: public/teacher-ai.js, src/index.tsx')
print('   前に渡したカルテ: 直近4週 -> 直近6週（全文・日付つき）')
print('   6週より前: 本文を渡さず「たな卸し」（長期ネタの週・終わり方8件まで）')
print('   指示文: 6週に直し、たな卸しに本文が無いことを明記')
print('   teacher-ai.js ?v=11 -> ?v=12')
