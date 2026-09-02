#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_cleanup_s3.py --- 第3段階: 分析タブの古い入口（A1〜A5）を消す

  A1〜A4  「🗂 以前の画面（そのうち無くなります）」の折りたたみを丸ごと削除
          （🤖AI分析ワンストップ / 🤖AIクラス分析 / 📋週報レポート / 🤖全員分のAI分析）
  A5      「🤖 AIカルテを表示」ボタンと openStudentKarte()（Geminiを呼ぶ方）を削除
          ※ AIを使わない showStudentKarte() と表示枠 #studentKartePanel は残す

  安全対策  updateKarteStudentList() の中で、名簿を window._lastStudentSummaries に
            入れる処理を「画面要素が無くても実行される」位置へ移動。
            これで「📄 全員分のカルテを印刷」が確実に動きます。

  ★ 消してはいけないもの（残っていることを最後に確認します）
     downloadAllKartes / updateKarteStudentList / _lastStudentSummaries /
     _buildKarteHtml / downloadKartePdf / showStudentKarte / #studentKartePanel /
     #karteStudentList
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

# ---------------- A1〜A4: 「以前の画面」の折りたたみを丸ごと ----------------
MARK = '🗂 以前の画面（そのうち無くなります）'
if MARK in src:
    if src.count(MARK) != 1: fail('「以前の画面」の目印が %d 個' % src.count(MARK))
    i = src.index(MARK)
    start = src.rindex('<details', 0, i)
    depth = 0; end = None
    for m in re.finditer(r'(<details\b)|(</details>)', src[start:]):
        if m.group(1): depth += 1
        else:
            depth -= 1
            if depth == 0: end = start + m.end(); break
    if end is None: fail('「以前の画面」の閉じタグが見つかりません')
    block = src[start:end]
    # 中身の確認：4つのパネルが入っていて、スクリプトや関数は入っていないこと
    for need in ['🤖 AI分析（まとめて）', 'downloadAllKartes()']:
        if need not in block: fail('「以前の画面」の範囲がおかしいです（%s が無い）' % need)
    for bad in ['<script', 'function ', 'karteStudentList', 'studentKartePanel']:
        if bad in block: fail('「以前の画面」の範囲に %s が入っています（広すぎ）' % bad)
    if balance(block) != 0: fail('「以前の画面」の範囲のタグが釣り合っていません')
    # 直前の改行・空白も一緒に落とす
    js = start
    while js > 0 and src[js-1] in ' \t': js -= 1
    src = src[:js] + src[end:]
    cuts.append(('A1〜A4 「以前の画面」の折りたたみ', len(block)))
else:
    print('⏭  A1〜A4 は適用済み（スキップ）')

# ---------------- A5a: 「🤖 AIカルテを表示」ボタン ----------------
A5_BTN = ("html += '<button onclick=\"closeStudentFullAnalysis();openStudentKarte(&#39;'+escH(studentId)+"
          "'&#39;,&#39;'+escH(studentName)+'&#39;)\" class=\"bg-purple-600 text-white rounded-lg px-4 py-2 "
          "text-sm font-bold hover:bg-purple-700\">🤖 AIカルテを表示</button>';\n")
if A5_BTN in src:
    if src.count(A5_BTN) != 1: fail('A5 のボタンが %d 箇所' % src.count(A5_BTN))
    a = src.index(A5_BTN)
    b = a + len(A5_BTN)
    js = a
    while js > 0 and src[js-1] in ' \t': js -= 1
    if js > 0 and src[js-1] == '\n': js -= 1
    src = src[:js] + src[b-1:]  # 末尾の改行は残す
    cuts.append(('A5 「🤖 AIカルテを表示」ボタン', len(A5_BTN)))
else:
    print('⏭  A5 ボタン は適用済み（スキップ）')

# ---------------- A5b: openStudentKarte() 本体 ----------------
A5_HEAD = 'async function openStudentKarte(studentId, studentName){'
if A5_HEAD in src:
    if src.count(A5_HEAD) != 1: fail('openStudentKarte の定義が %d 個' % src.count(A5_HEAD))
    j = src.index(A5_HEAD)
    depth = 0; pos = src.index('{', j)
    while True:
        ch = src[pos]
        if ch == '{': depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0: break
        pos += 1
        if pos >= len(src): fail('openStudentKarte の終わりが見つかりません')
    body = src[j:pos+1]
    if '/api/teacher/student-karte' not in body:
        fail('openStudentKarte の範囲がおかしいです')
    if 'function showStudentKarte' in body:
        fail('openStudentKarte の範囲に showStudentKarte が入っています（広すぎ）')
    js = j
    while js > 0 and src[js-1] in ' \t': js -= 1
    note = ('/* 🗑 2026-09: openStudentKarte()（Geminiで個人カルテを書く方）は削除しました。\n'
            '         AIを使わない showStudentKarte() と表示枠はそのまま残しています。 */')
    src = src[:js] + note + src[pos+1:]
    cuts.append(('A5 openStudentKarte()（Geminiを呼ぶ個人カルテ）', len(body)))
else:
    print('⏭  A5 openStudentKarte は適用済み（スキップ）')

# ---------------- 安全対策: 名簿の保存を先にする ----------------
OLD_UK = """function updateKarteStudentList(students, classId){
        const wrap = document.getElementById('karteStudentList');
        if(!wrap) return;
        if(!students.length){ wrap.innerHTML='<p class="text-xs text-slate-400">児童データがありません</p>'; return; }
        wrap.innerHTML = '';
        // ヒートマップ用データも保持
        window._lastStudentSummaries = students;
        window._lastAnalyticsClassId = classId;"""
NEW_UK = """function updateKarteStudentList(students, classId){
        // 📌 2026-09: 名簿の保存は画面要素の有無より先に行う。
        //   「📄 全員分のカルテを印刷」がこの値を使うため、
        //   一覧を表示していない状態でも印刷できるようにしておく。
        window._lastStudentSummaries = students;
        window._lastAnalyticsClassId = classId;
        const wrap = document.getElementById('karteStudentList');
        if(!wrap) return;
        if(!students.length){ wrap.innerHTML='<p class="text-xs text-slate-400">児童データがありません</p>'; return; }
        wrap.innerHTML = '';"""
if NEW_UK.split('\n')[1].strip() in src:
    print('⏭  名簿の保存位置の修正 は適用済み（スキップ）')
elif OLD_UK in src:
    if src.count(OLD_UK) != 1: fail('updateKarteStudentList のアンカーが %d 箇所' % src.count(OLD_UK))
    src = src.replace(OLD_UK, NEW_UK, 1)
    cuts.append(('（安全対策）名簿の保存を先に行うよう修正', 0))
else:
    fail('updateKarteStudentList のアンカーが見つかりません')

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

# ★ 消してはいけないもの
for must in ['function downloadAllKartes', 'function updateKarteStudentList', 'window._lastStudentSummaries',
             'function _buildKarteHtml', 'function downloadKartePdf', 'async function showStudentKarte',
             'id="studentKartePanel"', 'id="karteStudentList"', 'id="karteContent"', 'id="karteStudentName"',
             'onclick="taiPrintKartes()"', 'onclick="taiCopyAll()"', 'onclick="taiCopyFresh()"',
             'onclick="taiPublish()"', 'taiOneStu', '/teacher-ai.js?v=6',
             "app.get('/api/student/my-karte'", 'id="tabPaneMissions"', 'id="hwPane_plan"']:
    if must not in src: fail('★残すはずのものが失われました: %s' % must)
print('🔎 印刷ボタン・showStudentKarte・ひと往復パネルはすべて残っています')

# 消えたはずのもの
for bad in ['🗂 以前の画面', '🤖 AIカルテを表示', 'async function openStudentKarte',
            'onclick="generateAllAiText()"', '🤖 AI分析（まとめて）— ワンストップ']:
    if bad in src: fail('消したはずのものが残っています: %s' % bad)
print('🔎 分析タブの古い入口は消えました')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
print('---- 消したもの ----')
for tag, n in cuts: print(' ・%s（%d文字）' % (tag, n))
if not cuts: print(' （なし）')
