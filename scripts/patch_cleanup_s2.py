#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_cleanup_s2.py --- 第2段階: 家庭学習タブの古い入口（B1〜B9）を消す

  B1 🤖 AIで一括コメント生成（毎日の振り返り）
  B2 📋 Geminiでも手動で返却できます（折りたたみ）
  B3 🤖 AI計画チェック ボタン
  B4 📋 外部AIで計画チェック（全員分まとめて）
  B5 1人ずつの計画コピー／貼付欄 … 「今日のひと往復」の④へ移設ずみ。ここでは旧側だけ消す
  B6 🤖 AIコメント一括生成（週の振り返り）
  B7 📋 Geminiでも手動で返却できます（週）
  B8 📋 外部AIで今週の振り返りにコメント
  B9 💡 今週の自動フィードバック

消すのは「画面の入口（HTML）」だけです。
JavaScriptの関数本体は、第4段階でサーバー側のAPIと一緒に消します
（先に関数だけ消すと消し漏れの確認がしづらいため）。

安全のため、消す範囲はタグの開き／閉じを数えて決めています。
最後にファイル全体で <div> と </div> の差が変わっていないことを確かめます。
"""
import io, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

src = io.open(TSX, encoding='utf-8').read()
orig = src
cuts = []

def fail(msg):
    print('❌ 中止: ' + msg); sys.exit(1)

def balance(text):
    return len(re.findall(r'<div\b', text)) - len(re.findall(r'</div>', text))

BAL0 = balance(orig)

def cut_block(marker, open_re, close_tag, tag, must_have, must_not=('<script', 'function ')):
    """marker の位置から open_re で始まる要素を、開き／閉じを数えて丸ごと消す"""
    global src
    if marker not in src:
        print('⏭  %s は適用済み（スキップ）' % tag); return
    if src.count(marker) != 1:
        fail('%s の目印が %d 個（1個のはず）' % (tag, src.count(marker)))
    start = src.index(marker)
    m = re.compile(re.escape(open_re)).search(src, start)
    if not m: fail('%s の開始タグが見つかりません' % tag)
    generic_open = r'<details\b' if close_tag == '</details>' else r'<div\b'
    token = re.compile(r'(' + generic_open + r')|(' + re.escape(close_tag) + r')')
    depth = 0
    end = None
    for mm in token.finditer(src, m.start()):
        if mm.group(1): depth += 1
        else:
            depth -= 1
            if depth == 0:
                end = mm.end(); break
    if end is None: fail('%s の閉じタグが見つかりません' % tag)
    block = src[start:end]
    if must_have not in block:
        fail('%s の範囲がおかしいです（%s が入っていません）' % (tag, must_have))
    for bad in must_not:
        if bad in block: fail('%s の範囲に %s が入っています（広すぎ）' % (tag, bad))
    if balance(block) != 0:
        fail('%s の範囲のタグが釣り合っていません' % tag)
    src = src[:start] + src[end:]
    cuts.append((tag, len(block)))

# ---- B1: 毎日の振り返りのアプリ内AIパネル ----
cut_block('<!-- アプリ内AIコメント生成パネル -->', '<div class="bg-emerald-50 border border-emerald-200 rounded-xl p-3 space-y-2">',
          '</div>', 'B1 AIで一括コメント生成（毎日）', 'generateHWAIComments()')

# ---- B2: 毎日の Gemini 連携（折りたたみ） ----
cut_block('<!-- Gemini連携パネル（折りたたみ） -->', '<details', '</details>',
          'B2 Geminiでも手動で返却（毎日）', 'pasteAndBulkReturn()')

# ---- B6 + B7: 週の振り返りの一括AI返却パネル ----
cut_block('<!-- 振り返り一括AI返却 -->', '<div id="bulkRefPanel"', '</div>',
          'B6/B7 週の振り返りの一括AI返却', 'generateWeeklyAIComments()')

# ---- B9: 今週の自動フィードバック ----
cut_block('<!-- 自動フィードバック（週間） -->', '<div class="bg-yellow-50 border border-yellow-200 rounded-xl p-4 space-y-3">',
          '</div>', 'B9 今週の自動フィードバック', 'loadAutoFeedback()')

# ---- B8: 外部AIで今週の振り返りに返却 ----
cut_block('<!-- 外部AIで今週の振り返りに返却 -->', '<div class="bg-violet-50 border border-violet-200 rounded-xl p-4 space-y-2">',
          '</div>', 'B8 外部AIで今週の振り返りにコメント', 'saveReflectionAiComments()')

# ---- B4: 外部AIで計画チェック（全員分） ----
cut_block('<div class="bg-white border border-violet-200 rounded-lg p-2 space-y-2 mt-2">',
          '<div class="bg-white border border-violet-200 rounded-lg p-2 space-y-2 mt-2">',
          '</div>', 'B4 外部AIで計画チェック（全員分）', '📋 外部AIで計画チェック（全員分まとめて）')

# ---- B3: AI計画チェック ボタン（小さいので文字列で指定） ----
B3_OLD = ('<button onclick="aiPlanCheck()" class="bg-red-500 text-white rounded-lg px-3 py-1 text-xs font-bold shadow hover:opacity-90" '
          'id="aiPlanCheckBtn">🤖 AI計画チェック</button>\n          </div>\n'
          '          <div id="aiPlanCheckResult" class="hidden bg-white border border-red-200 rounded-lg p-2 space-y-1"></div>')
B3_NEW = '</div>'
if B3_OLD in src:
    if src.count(B3_OLD) != 1: fail('B3 のアンカーが %d 箇所' % src.count(B3_OLD))
    src = src.replace(B3_OLD, B3_NEW, 1)
    cuts.append(('B3 AI計画チェック ボタン', len(B3_OLD) - len(B3_NEW)))
else:
    print('⏭  B3 AI計画チェック ボタン は適用済み（スキップ）')

# ---- B5: 児童ごとの「この子の計画をAIにコピー」欄（旧側） ----
B5_START = "            html += '<div class=\"mt-1 border-t border-violet-100 pt-1 space-y-1\">'"
B5_END   = "              + '</div>';\n"
if B5_START in src:
    if src.count(B5_START) != 1: fail('B5 の開始アンカーが %d 箇所' % src.count(B5_START))
    a = src.index(B5_START)
    b = src.index(B5_END, a)
    if b < 0 or b - a > 1200: fail('B5 の範囲がおかしいです')
    b += len(B5_END)
    block = src[a:b]
    for need in ['copyOnePlanForAi', 'saveOnePlanAiComment', 'planOnePaste_']:
        if need not in block: fail('B5 の範囲に %s がありません' % need)
    src = src[:a] + src[b:]
    cuts.append(('B5 旧「1人ずつの計画コピー」欄（新パネルへ移設ずみ）', len(block)))
else:
    print('⏭  B5 旧「1人ずつの計画コピー」欄 は適用済み（スキップ）')

# ---- 空になったサブタブ④に、行き先の案内を入れる ----
W_OLD = ('        <!-- サブタブ④: 今週の振り返り -->\n'
         '        <div id="hwPane_weekly" class="hidden space-y-3">')
W_NEW = ('        <!-- サブタブ④: 今週の振り返り -->\n'
         '        <div id="hwPane_weekly" class="hidden space-y-3">\n'
         '          <div class="bg-slate-50 border border-slate-200 rounded-xl p-4">\n'
         '            <div class="font-bold text-sm text-slate-700">今週の振り返りへの返却は、分析タブに移りました</div>\n'
         '            <p class="text-xs text-slate-500 mt-1">分析タブの「📋 今日のひと往復」で、「今回ふくめるもの」の'
         '<b>週の振り返りの返却</b>にチェックを入れてください。金曜日は自動でチェックが入ります。</p>\n'
         '          </div>')
if 'hwPane_weekly' in src and '今週の振り返りへの返却は、分析タブに移りました' not in src:
    if src.count(W_OLD) != 1: fail('サブタブ④の案内の差し込み位置が %d 箇所' % src.count(W_OLD))
    src = src.replace(W_OLD, W_NEW, 1)
    cuts.append(('（追加）空になったサブタブ④に案内を表示', 0))
else:
    print('⏭  サブタブ④の案内 は適用済み（スキップ）')

# ============================================================ 検証
if balance(src) != BAL0:
    fail('<div> と </div> の釣り合いが変わりました（%d → %d）' % (BAL0, balance(src)))
print('🔎 <div> と </div> の釣り合い: 変化なし')

def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')
if root_replace_count(src) != root_replace_count(orig):
    fail('置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（変化なし）' % root_replace_count(src))

# 消えたはずの入口
for bad in ['generateHWAIComments()', 'pasteAndBulkReturn()', 'generateWeeklyAIComments()',
            'loadAutoFeedback()', 'saveReflectionAiComments()', 'savePlanAiComments()',
            'aiPlanCheck()', 'copyOnePlanForAi(&#39;']:
    if 'onclick="' + bad in src:
        fail('入口が残っています: %s' % bad)
print('🔎 家庭学習タブの古いボタンはすべて消えました')

# 残さなければいけないもの
for must in ['id="hwPane_plan"', 'id="hwPane_daily"', 'id="hwPane_weekly"',
             'id="studentPlansList"', 'id="hwList"', 'id="hwClassFilter"', 'id="hwDateTabs"',
             'id="hwSummaryBar"', 'id="hwUnsubmittedList"',
             'onclick="loadStudentPlans(', 'onclick="loadHomework(', 'onclick="bulkReturnNoComment(',
             'function _buildKarteHtml', 'function downloadAllKartes', 'function updateKarteStudentList',
             'async function showStudentKarte', 'taiOneStu', '/teacher-ai.js?v=6',
             '今週の振り返りへの返却は、分析タブに移りました',
             "app.get('/api/student/my-karte'", 'id="tabPaneMissions"']:
    if must not in src: fail('残すはずのものが失われました: %s' % must)
print('🔎 家庭学習タブの本体（計画・毎日の一覧・返却）とミッションタブは残っています')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
print('---- 消したもの ----')
for tag, n in cuts: print(' ・%s（%d文字）' % (tag, n))
if not cuts: print(' （なし）')
