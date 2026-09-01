#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_analysis_v2.py --- リスク予測の「判定不可」の直し

やること（すべて「必ず1回だけ一致」を確認してから適用。合わなければ中止）
  src/index.tsx
    V1 /api/teacher/risk-scores : 学習記録と提出記録を別々に見る（AND → 2軸判定）
    V2 /api/teacher/risk-scores : 提出記録が無い子でも学習側のサインは見る（素通り修正）
    V3 /api/teacher/risk-scores : level に 'partial'（データ不足）を追加・並び順・件数・注記
    V4 _riskRender : ⚠️データ不足 の表示を追加
    V5 教師ダッシュボードの teacher-ai.js を ?v=2 に（キャッシュ更新）
  public/index.html は触りません。
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

src = io.open(TSX, encoding='utf-8').read()
orig = src
changes = []

def fail(msg):
    print('❌ 中止: ' + msg); sys.exit(1)

def rep(old, new, tag, sentinel=None):
    global src
    if sentinel is not None and sentinel in src:
        print('⏭  %s は適用済み（スキップ）' % tag); return
    n = src.count(old)
    if n == 0:
        if new in src:
            print('⏭  %s は適用済み（スキップ）' % tag); return
        fail('%s のアンカーが見つかりません' % tag)
    if n != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, n))
    src = src.replace(old, new, 1)
    changes.append(tag)

# ---------------- V1: 2軸でデータの足りかたを見る ----------------
rep(
"""    const total = (lr && lr.total) ? lr.total : 0
    const dataLow = (total < 10 && days.length < 3)
""",
"""    const total = (lr && lr.total) ? lr.total : 0
    // 📊 2026-09 修正: 「データが足りない子」と「本当に低リスクの子」を見分けられるようにする。
    //   以前は (問題10問未満 かつ 提出3日未満) の AND だけを判定不可にしていたため、
    //   「12問解いたが提出は0日」の子が提出系のサインを1つも立てられず 🟢低リスク に混ざっていた。
    //   学習・提出の2軸を別々に見て、片方でも足りない子は 🟢 にしない。
    const learnOk = total >= 10
    const subOk = days.length >= 3
    const dataLow = (!learnOk && !subOk)
    const missing: string[] = []
    if (!learnOk) missing.push('アプリの学習記録が少ない(' + total + '問)')
    if (!subOk) missing.push('家庭学習の提出記録が少ない(' + days.length + '日)')
""",
'V1 2軸のデータ判定', sentinel='const learnOk = total >= 10')

# ---------------- V2 + V3: 素通り修正 / partial / 並び順 ----------------
rep(
"""      if (sunRecent != null && sunRecent < 30) bump(8, '最近の満足度が低い', 'sun')
    }
    score = Math.min(100, score)
    const level = dataLow ? 'unknown' : (score >= 50 ? 'high' : score >= 25 ? 'mid' : 'low')
    list.push({ userId: uid, loginId: m.loginId, name: m.name, riskScore: score, level, signals, suggestion: dataLow ? '' : sugFor(topKind), dataLow, problems: total, submissions: days.length })
""",
"""      if (sunRecent != null && sunRecent < 30) bump(8, '最近の満足度が低い', 'sun')
    }
    // 提出の記録が1日も無い子は、以前はサイン判定そのものを素通りしていた（＝必ず0点＝緑）。
    // 提出が無くてもアプリの学習記録だけで分かるサインは見る。しきい値は既存と同じ。
    if (!dataLow && !days.length && lr && total >= 20) {
      if (lr.early != null && lr.late != null && (lr.early - lr.late) >= 15) bump(20, '正答率が急落(' + lr.early + '%→' + lr.late + '%)', 'accdrop')
      if (lr.acc != null && lr.acc < 50) bump(10, '全体の正答率が低い(' + lr.acc + '%)', 'lowacc')
    }
    score = Math.min(100, score)
    // どちらかの記録が足りない子には、その事実をサイン欄に明示する
    if (!dataLow && !(learnOk && subOk)) { for (const ms of missing) signals.push('※' + ms) }
    // 記録が片方しか無く、サインも立っていない子は「低リスク」ではなく「データ不足」にする
    const partial = (!dataLow && !(learnOk && subOk) && score < 25)
    const level = dataLow ? 'unknown' : (score >= 50 ? 'high' : score >= 25 ? 'mid' : (partial ? 'partial' : 'low'))
    list.push({ userId: uid, loginId: m.loginId, name: m.name, riskScore: score, level, signals, suggestion: (dataLow || partial) ? '' : sugFor(topKind), dataLow, partial, missing, problems: total, submissions: days.length })
""",
'V2/V3 素通り修正とデータ不足', sentinel="const partial = (!dataLow && !(learnOk && subOk) && score < 25)")

rep(
"""  const order = (s: any) => s.dataLow ? -1 : s.riskScore
  list.sort((a, b) => order(b) - order(a))
  const counts = { high: list.filter(s => s.level === 'high').length, mid: list.filter(s => s.level === 'mid').length, low: list.filter(s => s.level === 'low').length, unknown: list.filter(s => s.level === 'unknown').length }
  const note = '※これは「兆候のスコア化」であり、確実な予測ではありません。記録が少ない子は判定できないため別表示にしています。気になる子はタップして個人カルテで確かめてください。'
""",
"""  // データ不足の子は「低リスクの子より上」に置いて、先生の目に入るようにする
  const order = (s: any) => s.level === 'unknown' ? -2 : (s.level === 'partial' ? 24.5 : s.riskScore)
  list.sort((a, b) => order(b) - order(a))
  const counts = { high: list.filter(s => s.level === 'high').length, mid: list.filter(s => s.level === 'mid').length, low: list.filter(s => s.level === 'low').length, partial: list.filter(s => s.level === 'partial').length, unknown: list.filter(s => s.level === 'unknown').length }
  const note = '※これは「兆候のスコア化」であり、確実な予測ではありません。⚠️データ不足＝学習記録と提出記録のどちらかが少なく、サインも立っていない子です（低リスクとは限りません）。⚪判定不可＝どちらの記録もほとんど無い子です。気になる子はタップして個人カルテで確かめてください。'
""",
'V3b 並び順・件数・注記', sentinel="s.level === 'partial' ? 24.5")

# ---------------- V4: 画面表示 ----------------
rep(
"""'+(cc.low||0)+'</span>'+((cc.unknown)?""",
"""'+(cc.low||0)+'</span>'+((cc.partial)?'<span class="bg-orange-100 text-orange-700 rounded-full px-2 py-0.5 font-bold">⚠️ データ不足 '+cc.partial+'</span>':'')+((cc.unknown)?""",
'V4a 件数バッジ', sentinel='⚠️ データ不足 ')

rep(
"""var bg=lv==='high'?'bg-red-50 border-red-200':lv==='mid'?'bg-amber-50 border-amber-200':'bg-emerald-50 border-emerald-200'; var dot=lv==='high'?'🔴':lv==='mid'?'🟡':'🟢'; var bar=lv==='high'?'#ef4444':lv==='mid'?'#f59e0b':'#10b981';""",
"""var bg=lv==='high'?'bg-red-50 border-red-200':lv==='mid'?'bg-amber-50 border-amber-200':lv==='partial'?'bg-orange-50 border-orange-200':'bg-emerald-50 border-emerald-200'; var dot=lv==='high'?'🔴':lv==='mid'?'🟡':lv==='partial'?'⚠️':'🟢'; var bar=lv==='high'?'#ef4444':lv==='mid'?'#f59e0b':lv==='partial'?'#f97316':'#10b981';""",
'V4b 色とアイコン', sentinel="lv==='partial'?'bg-orange-50")

rep(
"""'</span><span class="text-xs font-black" style="color:'+bar+'">リスク '+s.riskScore+'</span></div>'""",
"""'</span><span class="text-xs font-black" style="color:'+bar+'">'+(lv==='partial'?'データ不足':('リスク '+s.riskScore))+'</span></div>'""",
'V4c スコア表示', sentinel="lv==='partial'?'データ不足'")

# ---------------- V5: teacher-ai.js のキャッシュ更新 ----------------
rep('<script src="/teacher-ai.js?v=1"></script>',
    '<script src="/teacher-ai.js?v=2"></script>',
    'V5 teacher-ai.js のキャッシュ更新', sentinel='/teacher-ai.js?v=2')

# ---------------- 検証 ----------------
def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')

if root_replace_count(orig) != root_replace_count(src):
    fail('本番HTMLの置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

for must in ["app.get('/api/teacher/risk-scores'", "app.post('/api/teacher/ai-drafts'", 'id="taiDraftList"', '/teacher-ai.js']:
    if must not in src: fail('必須の要素が失われました: %s' % must)

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました')
else:
    print('… 変更なし')
print('---- 適用した項目 ----')
for c in changes: print(' ・' + c)
if not changes: print(' （なし）')
