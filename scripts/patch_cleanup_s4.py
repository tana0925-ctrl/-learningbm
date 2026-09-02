#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_cleanup_s4.py --- 第4段階: サーバー側の内蔵AI（C1〜C8）と、行き場のなくなった関数を消す

  手順（この順でないと消し漏れの確認ができません）
    ① 画面から呼ばれなくなった JavaScript の関数を消す（第2・第3段階でボタンを消したもの）
    ② それで呼び出し元がゼロになった 7 つの API を消す
    ③ 最後に callGemini() 本体と generateFeedback() を消す
       ※ 消す直前に「呼び出し元が本当にゼロか」を機械的に確かめます

  GitHub の Secrets（GEMINI_API_KEY など）には触りません。コードが呼ばなくなるだけです。
"""
import io, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

src = io.open(TSX, encoding='utf-8').read()
orig = src
cuts = []

def fail(msg):
    print('❌ 中止: ' + msg); sys.exit(1)

def brace_end(text, start):
    """start 以降の最初の { から対応する } までの位置（}の次）を返す"""
    i = text.index('{', start)
    depth = 0
    while i < len(text):
        c = text[i]
        if c == '{': depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0: return i + 1
        i += 1
    return -1

def del_function(name, must_have=None, toplevel=False):
    """function name( ... ) をまるごと消す
       toplevel=True のときは、型注釈に { } を含む TypeScript の関数向けに
       「行頭の }」を終わりとみなす（波かっこ数えだと型の { を拾ってしまうため）"""
    global src
    pats = ['async function %s(' % name, 'function %s(' % name]
    hit = None
    for p in pats:
        if p in src:
            if src.count(p) != 1: fail('%s の定義が %d 個' % (name, src.count(p)))
            hit = p; break
    if hit is None:
        print('⏭  %s は削除ずみ（スキップ）' % name); return
    j = src.index(hit)
    if toplevel:
        e = src.find('\n}\n', j)
        if e < 0: fail('%s の終わり（行頭の }）が見つかりません' % name)
        end = e + 3
    else:
        end = brace_end(src, j)
    if end < 0: fail('%s の終わりが見つかりません' % name)
    if toplevel and (src[j:end].count('{') != src[j:end].count('}')):
        fail('%s の範囲の波かっこが釣り合っていません' % name)
    body = src[j:end]
    if must_have and must_have not in body:
        fail('%s の範囲がおかしいです（%s が無い）' % (name, must_have))
    js = j
    while js > 0 and src[js-1] in ' \t': js -= 1
    src = src[:js] + src[end:]
    cuts.append(('関数 %s()' % name, len(body)))

def del_route(path, must_have=None):
    """app.get/post('path', ...) をまるごと消す"""
    global src
    hit = None
    for m in ["app.get('%s'" % path, "app.post('%s'" % path]:
        if m in src:
            if src.count(m) != 1: fail('%s の定義が %d 個' % (path, src.count(m)))
            hit = m; break
    if hit is None:
        print('⏭  %s は削除ずみ（スキップ）' % path); return
    j = src.index(hit)
    end = src.find('\n})\n', j)
    if end < 0: fail('%s の終わりが見つかりません' % path)
    end += len('\n})\n')
    block = src[j:end]
    if block.count("app.get('") + block.count("app.post('") != 1:
        fail('%s の範囲に別のAPIが入っています' % path)
    if block.count('{') != block.count('}'):
        fail('%s の範囲の括弧が釣り合っていません' % path)
    if must_have and must_have not in block:
        fail('%s の範囲がおかしいです（%s が無い）' % (path, must_have))
    # 直前のコメント行も一緒に落とす
    js = j
    ls = src.rfind('\n', 0, js-1)
    if ls >= 0 and src[ls+1:js].lstrip().startswith('//'):
        js = ls + 1
    src = src[:js] + src[end:]
    cuts.append(('API %s' % path, len(block)))

# ================= ① 行き場のなくなった画面側の関数 =================
for fn, mark in [
    ('aiPlanCheck', '/api/teacher/ai-plan-check'),
    ('copyPlansForAi', None),
    ('savePlanAiComments', '/api/teacher/plan-ai-comments'),
    ('copyOnePlanForAi', None),
    ('saveOnePlanAiComment', '/api/teacher/plan-ai-comments'),
    ('generateWeeklyAIComments', '/api/teacher/weekly-ai-comments'),
    ('copyWeeklyReflections', None),
    ('bulkReturnReflections', None),
    ('generateHWAIComments', '/api/teacher/homework-ai-comments'),
    ('toggleGemPrompt', None),
    ('copyGemPrompt', None),
    ('pasteAndBulkReturn', None),
    ('loadAutoFeedback', '/api/teacher/auto-feedback'),
    ('copyReflectionsForAi', None),
    ('saveReflectionAiComments', '/api/teacher/reflection-comments'),
    ('loadAIAnalysis', '/api/teacher/class-ai-analysis'),
    ('loadWeeklyReport', '/api/teacher/weekly-report'),
    ('copyReflections', None),
]:
    del_function(fn, mark)

# ================= ② 呼び出し元ゼロになったAPI =================
for path, mark in [
    ('/api/teacher/class-ai-analysis', 'callGemini'),
    ('/api/teacher/student-karte', 'callGemini'),
    ('/api/teacher/weekly-report', 'callGemini'),
    ('/api/teacher/homework-ai-comments', 'callGemini'),
    ('/api/teacher/auto-feedback', 'callGemini'),
    ('/api/teacher/ai-plan-check', 'callGemini'),
    ('/api/teacher/weekly-ai-comments', 'callGemini'),
]:
    # 消す前に、画面から呼ばれていないことを確認（コメント行は数えない）
    n = 0
    for line in src.split('\n'):
        if path in line and not line.strip().startswith('//'):
            n += line.count(path)
    if n > 1:
        fail('%s はまだ %d 箇所から参照されています（画面側が残っています）' % (path, n))
    del_route(path, mark)

# ---- 第1段階で書いた説明が古くなるので直しておく ----
STALE = '//   この中で使っていた generateFeedback() は /api/teacher/auto-feedback がまだ使うので残しています。\n'
FRESH = '//   ここで使っていた generateFeedback() は、第4段階で auto-feedback ごと削除しました。\n'
if STALE in src:
    src = src.replace(STALE, FRESH, 1)
    cuts.append(('（説明の更新）第1段階のコメントを現状に合わせた', 0))

# ================= ③ callGemini と generateFeedback =================
for name in ['callGemini', 'generateFeedback']:
    code = '\n'.join(l for l in src.split('\n') if not l.strip().startswith('//'))
    n = len(re.findall(re.escape(name) + r'\s*\(', code))
    defs = len(re.findall(r'function\s+' + re.escape(name) + r'\s*\(', code))
    if defs == 0:
        print('⏭  %s は削除ずみ（スキップ）' % name); continue
    if n != defs:
        fail('%s の呼び出し元がまだ %d 箇所あります（定義 %d）。ここで中止します。' % (name, n - defs, defs))
    print('🔎 %s の呼び出し元はゼロです。削除します。' % name)
    del_function(name, toplevel=True)

# ================= 検証 =================
def used(name):
    for line in src.split('\n'):
        if name in line and not line.strip().startswith('//'):
            return True
    return False

for bad in ['callGemini', 'generateFeedback', 'gemini-3.5-flash',
            '/api/teacher/class-ai-analysis', '/api/teacher/homework-ai-comments',
            '/api/teacher/auto-feedback', '/api/teacher/ai-plan-check',
            '/api/teacher/weekly-ai-comments', '/api/teacher/student-karte',
            '/api/teacher/weekly-report',
            'function aiPlanCheck', 'function generateHWAIComments', 'function loadAutoFeedback',
            'function loadAIAnalysis', 'function loadWeeklyReport']:
    if used(bad): fail('消したはずのものが残っています: %s' % bad)
print('🔎 内蔵AI（callGemini とその7つのAPI）は1つも残っていません')

for must in ['function downloadAllKartes', 'function updateKarteStudentList', 'window._lastStudentSummaries',
             'function _buildKarteHtml', 'function downloadKartePdf', 'async function showStudentKarte',
             'id="studentKartePanel"', 'id="karteStudentList"',
             'onclick="taiPrintKartes()"', 'onclick="taiCopyAll()"', 'onclick="taiPublish()"',
             'taiOneStu', '/teacher-ai.js?v=6', 'id="hwPane_plan"', 'id="tabPaneMissions"',
             "app.get('/api/student/my-karte'", "app.post('/api/teacher/karte-share'",
             "app.post('/api/teacher/student-ai-comments'", "app.post('/api/teacher/class-ai-summary'",
             "app.post('/api/teacher/plan-ai-comments'", "app.post('/api/teacher/plan-suggestions'",
             "app.post('/api/teacher/reflection-comments'", "app.post('/api/teacher/ai-drafts'",
             "app.get('/api/teacher/student-full-analysis'", "app.get('/api/teacher/risk-scores'",
             "app.get('/api/teacher/learning-analytics'", "app.get('/api/teacher/early-alerts'",
             "app.get('/api/teacher/factor-analysis'", "app.post('/api/teacher/records/parse'",
             'async function stuUnitAgg(', 'function fyStartYMD()']:
    if must not in src: fail('★残すはずのものが失われました: %s' % must)
print('🔎 新しい「ひと往復」の公開先API・分析系API・印刷まわりはすべて残っています')

def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')
if root_replace_count(src) != root_replace_count(orig):
    fail('置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（変化なし）' % root_replace_count(src))

bal = len(re.findall(r'<div\b', src)) - len(re.findall(r'</div>', src))
bal0 = len(re.findall(r'<div\b', orig)) - len(re.findall(r'</div>', orig))
if bal != bal0: fail('<div> の釣り合いが変わりました')
print('🔎 <div> と </div> の釣り合い: 変化なし')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
print('---- 消したもの ----')
tot = 0
for tag, n in cuts:
    print(' ・%s（%d文字）' % (tag, n)); tot += n
print('  合計 %d 文字' % tot)
if not cuts: print(' （なし）')
