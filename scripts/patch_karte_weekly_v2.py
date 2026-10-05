#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_karte_weekly_v2.py --- KARTE_WEEKLY_V2 見える化を 子どもの紙から先生の画面へ移す

先生のことば:
  「そうだよねー。このレーダーはじめ毎週かわらないのもあるよね」
  「外した欄は消すのではなく、置き場所を変えるだけにしてください」

第1便（KARTE_WEEKLY_V1）で、年度累計の欄を毎週の紙から外した。
残っていたのは 📊 今年度の学習の見える化（レーダー＋月ごとの提出回数）。
これも年度累計なので、毎週渡す紙では動かない。

  実測（直近5週・各月曜時点を D1 から再現）
    児童A … 国語90.8% 算数86.0% 社会97.0% 理科90.9% が5週とも小数第1位まで同じ。
    児童B … 先週1,024問解いて 算数 43.7%→45.1%（1.4pt）。
    クラス23人のうち先週アプリをやったのは10人。残り13人は前週と文字単位で同一。
    月ごとの棒グラフは、そもそも月に1回しか動かない。

この便でやること:
  1) カルテ（子どもに渡す紙）から 📊 今年度の学習の見える化 を外す。
     実測で、第1便のあと 255.2mm だったものが 約181mm になる見込み。
  2) 消すのではなく、同じ3つのグラフ（レーダー／月ごとの提出回数／きもちの割合）を
     先生の「📊 個人分析」画面に出す。置き場所を変えるだけ。
     ・年度を通して見るぶんには意味があるので、先生からは見えるようにしておく。
     ・ドーナツ（きもちの割合）は第1便で紙から外したぶん。ここで先生側に戻す。
     ・レーダーは第1便と同じで、データのない軸は描かない（軸が3本未満なら図ごと出さない）。

「🌱 今週かわったこと」について:
  この便で入れる予定だったが、先に入れられないことが分かったので第2便（足す側）に回す。
  理由は材料がないため。「とくい／のばす の顔ぶれが変わった」を言うには
  『先週その単元をやったか』が要るが、カルテが使っている student-full-analysis は
  年度累計（subjects）と前期/後期の比較しか返していない。
  第2便で「先週アプリで解いたぶん」を渡すようにするので、そこで同時に入れるのが筋。
  先に入れると、前期/後期（2か月幅）で「今週かわった」と書くことになり、
  いま直そうとしている不具合をもう一度作ることになる。

さわるファイル:
  src/index.tsx だけ（_buildKarteHtml と、先生の個人分析の描画）。
  ※ public/teacher-ai.js・public/student-karte.js・public/index.html・防衛戦には触らない。
  ※ scripts/patch_karte_slim_v1.py（別セッションのぶん）には触らない。
  ※ .replace( チェーンは1本も増やさない。
  ※ D1には書き込まない。読み取りも増やさない（渡しているデータは今までと同じ）。

安全策:
  - アンカーはすべて「ちょうど1箇所」であることを確認してから置換する
  - 冪等: 目印 SENTINEL があれば何もしない
  - 第1便が入っていることを確かめる
  - チェーン件数を CHAIN_BEFORE と照合し、合わなければ1文字も書かずに中止
  - 置換後にチェーン件数が変わっていないことを再確認する
  - 数えるときは grep -c を使わない（src/index.tsx は巨大な1行なので行数では数えられない）
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

SENTINEL = 'KARTE_WEEKLY_V2'


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


def rep_span(text, start, end, new, label):
    if text.count(start) != 1:
        fail('%s の始点が %d 箇所（1箇所のはず）' % (label, text.count(start)))
    i = text.index(start)
    if text.count(end, i) < 1:
        fail('%s の終点が見つからない' % label)
    j = text.index(end, i) + len(end)
    return text[:i] + new + text[j:]


tsx = io.open(TSX, encoding='utf-8', newline='').read()
chain_before = chain_count(tsx)
want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want or not want.isdigit():
    fail('CHAIN_BEFORE が渡されていない/数字でない: %r' % want)
if chain_before != int(want):
    fail('置換チェーンが %d 件（期待 %s 件）。ほかの便が入った可能性があるので中止'
         % (chain_before, want))
print('OK 置換チェーン: %d 件（期待どおり）' % chain_before)

if SENTINEL in tsx:
    print('-- すでに適用済み（目印あり）。何もしません')
    sys.exit(0)
if 'KARTE_WEEKLY_V1' not in tsx:
    fail('KARTE_WEEKLY_V1 が入っていない。先にそちらを流すこと')

NL = '\n'

# ------------------------------------------------------------------
# (1) カルテから 📊 今年度の学習の見える化 を外す
# ------------------------------------------------------------------
tsx = rep_span(
    tsx,
    "var _areas=[{key:'jp',label:'国語'}",
    "/* KARTE_WEEKLY_V1 横棒（💪とくい／🌱のばす／🔁復習）を外した。"
    " 年度累計の正答率で選ぶので顔ぶれが動かない。しかも『◯%（◯問）』が紙に8本並んでいた。"
    " 先生は提出率%を紙から外されたのに、正答率%は残っていた。"
    " 単元ごとの正答率は先生の『📊 個人分析』の教科別成績に出ている。"
    " 『顔ぶれが変わった週だけ1行で出す』のは第3便で入れる。 */ H.push('</div>');",
    "/* KARTE_WEEKLY_V2 📊 今年度の学習の見える化（レーダー＋月ごとの提出回数）を"
    " 毎週の紙から外した。どちらも年度累計で、週では動かない。"
    " 実測：児童Aのレーダーは5週とも小数第1位まで同じ。月ごとの棒は月に1回しか動かない。"
    " 消したのではなく、同じ3つのグラフを先生の『📊 個人分析』に出している"
    "（下の _faKarteGraphs）。年度を通して見るぶんには意味があるため。 */",
    '(1) 見える化をカルテから外す')

# ------------------------------------------------------------------
# (2) 先生の個人分析にグラフを置く（関数を足す）
# ------------------------------------------------------------------
GRAPH_FN = (
    "/* KARTE_WEEKLY_V2 子どもの紙から外したグラフ3つを、先生の「📊 個人分析」に出すための組み立て。" + NL +
    "   レーダー／月ごとの提出回数／きもちの割合。どれも年度累計なので、毎週の紙では動かないが、" + NL +
    "   年度を通して見るぶんには意味がある。消すのではなく置き場所を変えるだけ、という方針。" + NL +
    "   データのない教科は軸ごと描かない（軸が3本未満なら図ごと出さない）のは第1便と同じ。 */" + NL +
    "function _faKarteGraphs(d){" + NL +
    "  d = d || {};" + NL +
    "  var ov = d.overview || {};" + NL +
    "  var subjects = (d.subjects || []).slice();" + NL +
    "  var sg = (d.student && d.student.grade) || null;" + NL +
    "  var cl = function(u){ return _gradeClass(sg, _unitGrade(u)); };" + NL +
    "  var areas = [{key:'jp',label:'国語'},{key:'math',label:'算数'},{key:'sci',label:'理科'},{key:'soc',label:'社会'}];" + NL +
    "  var agg = function(arr){ var tot=0,cor=0; for(var i=0;i<arr.length;i++){ var it=arr[i]; var cc=(typeof it.correct==='number')?it.correct:Math.round((it.rate||0)/100*(it.total||0)); tot+=(it.total||0); cor+=cc; } return tot? Math.round(cor/tot*100):null; };" + NL +
    "  var radar = areas.map(function(a){" + NL +
    "    var same = subjects.filter(function(s){ return _subjectArea(s.unit)===a.key && cl(s.unit)==='same'; });" + NL +
    "    var all  = subjects.filter(function(s){ return _subjectArea(s.unit)===a.key; });" + NL +
    "    var v = agg(same); var nd = false;" + NL +
    "    if(v==null) v = agg(all);" + NL +
    "    if(v==null){ v = 0; nd = true; }" + NL +
    "    return { label:a.label, value:v, noData:nd };" + NL +
    "  });" + NL +
    "  var radarShow = radar.filter(function(x){ return !x.noData; });" + NL +
    "  var mt = (d.monthlyTrends || []).slice(-6);" + NL +
    "  var bars = mt.map(function(m){ return { label:String(m.month||'').slice(5), value:m.count||0 }; });" + NL +
    "  var tw = (ov.sunCount||0)+(ov.cloudCount||0)+(ov.rainCount||0);" + NL +
    "  if(!radarShow.length && !bars.length && !tw) return '';" + NL +
    "  var h = '<div class=\"rounded-xl border border-slate-200 p-3 mb-4\">';" + NL +
    "  h += '<div class=\"font-bold text-sm text-slate-600 mb-2\">📊 今年度の見える化</div>';" + NL +
    "  h += '<div class=\"text-xs text-slate-400 mb-2\">子どもに毎週渡す紙からは外しました（年度累計なので週では動かないため）。先生が年度を通して見るためのものです。</div>';" + NL +
    "  h += '<div style=\"display:flex;flex-wrap:wrap;gap:8px;align-items:flex-start;justify-content:space-around\">';" + NL +
    "  if(radarShow.length>=3) h += '<div style=\"text-align:center\"><div style=\"font-size:11px;font-weight:700;color:#475569\">教科の定着（いまの学年）</div>'+_kRadar(radarShow)+'</div>';" + NL +
    "  if(bars.length) h += '<div style=\"text-align:center\"><div style=\"font-size:11px;font-weight:700;color:#475569\">月ごとの提出回数</div>'+_kBars(bars)+'</div>';" + NL +
    "  if(tw) h += '<div style=\"text-align:center\"><div style=\"font-size:11px;font-weight:700;color:#475569\">きもちの割合</div>'+_kDonut(ov.sunCount,ov.cloudCount,ov.rainCount)+'</div>';" + NL +
    "  h += '</div></div>';" + NL +
    "  return h;" + NL +
    "}" + NL +
    "      function _kRadar(vals){"
)
tsx = rep1(tsx, "function _kRadar(vals){", GRAPH_FN, '(2) グラフ組み立ての関数')

# ------------------------------------------------------------------
# (3) 先生の個人分析で呼ぶ（期間情報のすぐ下）
# ------------------------------------------------------------------
CALL_OLD = (
    "            html += '<span>✅ 計画承認率: '+ov.planCompletionRate+'%</span>';" + NL +
    "            html += '</div>';" + NL +
    "          }" + NL
)
CALL_NEW = (
    CALL_OLD +
    "          /* KARTE_WEEKLY_V2 カルテから外したグラフ3つは ここに出す。消さずに置き場所を変えるだけ。 */" + NL +
    "          try { html += _faKarteGraphs(data); } catch(e) {}" + NL
)
tsx = rep1(tsx, CALL_OLD, CALL_NEW, '(3) 個人分析での呼び出し')

# ── 置換後の確認 ────────────────────────────────────────────
chain_after = chain_count(tsx)
if chain_after != chain_before:
    fail('置換チェーンが %d -> %d 件に変わった。書かずに中止' % (chain_before, chain_after))
print('OK 置換チェーン（後）: %d 件（変化なし）' % chain_after)

_fa = tsx.index('function _buildKarteHtml(){')
_fb = tsx.index('function downloadKartePdf(){', _fa)
body = tsx[_fa:_fb]
for bad, label in (
    ('<h2>📊 今年度の学習の見える化</h2>', 'カルテの見える化の見出し'),
    ('_kRadar(', 'カルテのレーダー'),
    ('_kBars(', 'カルテの棒グラフ'),
    ('_kDonut(', 'カルテのドーナツ'),
):
    if bad in body:
        fail('カルテ側に %s が残っている' % label)

for need, label in (
    ('function _faKarteGraphs(d){', 'グラフ組み立ての関数'),
    ('html += _faKarteGraphs(data);', '個人分析での呼び出し'),
    ('function _kRadar(vals){', '_kRadar の定義'),
    ('function _kBars(', '_kBars の定義'),
    ('function _kDonut(', '_kDonut の定義'),
):
    if need not in tsx:
        fail('%s が無い' % label)

for need, label in (
    ('🗣 自分のことば', '自分のことば'),
    ('📝 先生からの記録', '先生からの記録'),
    ('この週は 5日のうち ', '週のようす'),
    ('🐯 阪神マンからのアドバイス', '阪神マンの欄'),
):
    if need not in body:
        fail('カルテから %s が無くなっている' % label)

if tsx.count(SENTINEL) < 3:
    fail('目印が %d 個しかない（3個以上のはず）' % tsx.count(SENTINEL))

i_week = body.index('この週は 5日のうち ')
i_ai = body.index('🐯 阪神マンからのアドバイス')
i_note = body.index('📝 先生からの記録')
if not (i_week < i_ai < i_note):
    fail('並び順が思ったとおりでない')
print('OK 並び順: 先週のようす → 阪神マン → 先生からの記録')

io.open(TSX, 'w', encoding='utf-8', newline='').write(tsx)
print('OK 書き込み完了: src/index.tsx')
print('   カルテ: 📊 今年度の学習の見える化 を外した')
print('   先生の個人分析: レーダー／月ごとの提出回数／きもちの割合 を出すようにした')
