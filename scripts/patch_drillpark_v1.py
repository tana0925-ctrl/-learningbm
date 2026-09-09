# scripts/patch_drillpark_v1.py
# ドリルパーク（外部ドリル教材）のエクセル取り込みを src/index.tsx に追加する。
#
#   1. 挿入する中身は scripts/drillpark_block.ts（素のTS）から読む
#   2. そのブロックの SHA-256 を照合（1文字でも違えば中止）
#   3. アンカーが想定どおり1か所だけ存在するか検証
#   4. すでに適用済みなら何もしない（冪等）
#   5. 挿入後、挿入分を取り除くと元ファイルと完全一致することを検証（非破壊）
#   6. app.get('/') 内の .replace() チェーン25件の生存確認（増減させない）
#   7. 追加コードに DDL / state_json が無いか自己チェック
#   8. 「結果そのもの」の検証 — 追加した4つの入口が適用後のファイルに実在するか
#
# どれか一つでも失敗したら、ファイルを一切書き換えずに異常終了する。
import sys, os, re, hashlib

SRC = 'src/index.tsx'
BLOCK_FILE = 'scripts/drillpark_block.ts'

# 冪等の目印。検証には使わない（目印の有無ではなく結果を見る）
SENTINEL = '__DRILLPARK_V1__'
BLOCK_SHA256 = '55b97a7a87a629cdd479bc1a2497d6a5cc952e00f873cbe3f464fc6bba9b5e9d'

EXPECTED_REPLACE_CHAIN = 25

# --- 1) APIブロックの挿入位置 ---
ANCHOR_API = "// ===== テスト結果の取り込みAPI（外部AIの出力を貼り付け→パース→保存・集計値は再利用可能） ====="

# --- 2) 教師画面のカード ---
ANCHOR_PANE = '<div id="anPane_tests" class="hidden space-y-3">'
PANE_ADD = '''
          <div class="bg-white rounded-xl shadow p-4">
            <div class="font-bold text-slate-700 mb-1">📘 ドリルパークの取り込み（エクセル）</div>
            <div class="text-xs text-slate-500 mb-2">ドリルパークから書き出した「ドリル実施状況」のエクセルを、そのまま選ぶだけで取り込めます。<b>1問ごとの正誤</b>まで取り込むので、「どの教材の何問目でつまずいたか」まで個人分析・カルテに出ます。同じファイルを二度取り込んでも二重には入りません。</div>
            <div class="flex items-center gap-2 flex-wrap">
              <input id="dpFile" type="file" accept=".xlsx" class="text-xs" onchange="dpPickFile(this)">
              <span id="dpStatus" class="text-xs text-slate-500"></span>
              <button onclick="dpLoadBatches()" class="text-[10px] text-slate-500 underline">取り込んだ記録を見る</button>
            </div>
            <div id="dpPreview" class="mt-3"></div>
            <div id="dpBatches" class="mt-2 border-t pt-2"></div>
          </div>'''
PANE_NEW = ANCHOR_PANE + PANE_ADD

# --- 3) 教師画面から drillpark.js を読む ---
ANCHOR_SCRIPT = '    <script src="/teacher-ai.js?v=7"></script>'
SCRIPT_NEW = '    <script src="/drillpark.js?v=1"></script>\n' + ANCHOR_SCRIPT

# --- 4) 個人分析（カルテ／おすすめの材料）に渡す ---
ANCHOR_ANALYSIS = """  return c.json({
    ok: true,
    student: { id: member.id, name: member.name, loginId: member.login_id, grade: member.grade },"""
ANALYSIS_ADD = """  // 📘 ドリルパーク（1問ごとの正誤つき）。単元ごとの正答率より具体的な助言の材料になる。
  let drill: any = null
  try {
    const _dpr = await c.env.DB.prepare(`SELECT done_on, started_at, subject, drill_no, material, answer_sec, total_q, correct_q, rate_pct, answers FROM drill_sessions WHERE user_id=? AND done_on >= ? ORDER BY done_on DESC, started_at DESC LIMIT 600`).bind(studentId, _fy).all<any>()
    drill = _dpAnalyze((((_dpr && _dpr.results) || []) as any[]))
  } catch { }
"""
ANALYSIS_NEW = ANALYSIS_ADD + ANCHOR_ANALYSIS

ANCHOR_RETURN = """    testScores,
    records,
    teacherNotes,
  })"""
RETURN_NEW = """    testScores,
    records,
    teacherNotes,
    drill,
  })"""


def die(msg):
    print('[patch] NG: ' + msg)
    sys.exit(1)


def replace_count_in_root_route(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'")
    return s[i:j].count('.replace(')


def main():
    if not os.path.exists(BLOCK_FILE):
        die('挿入するブロックファイルが無い: ' + BLOCK_FILE)
    with open(BLOCK_FILE, 'r', encoding='utf-8') as f:
        BLOCK = f.read()

    got = hashlib.sha256(BLOCK.encode('utf-8')).hexdigest()
    print('[patch] block sha256 expected: ' + BLOCK_SHA256)
    print('[patch] block sha256 actual  : ' + got)
    if got != BLOCK_SHA256:
        die('ブロックファイルの SHA-256 が一致しない（転記ミス・改行コードの混入など）')

    with open(SRC, 'r', encoding='utf-8') as f:
        orig = f.read()
    print('[patch] src/index.tsx before sha256: ' + hashlib.sha256(orig.encode('utf-8')).hexdigest())

    if SENTINEL in orig:
        print('[patch] already applied (idempotent). nothing to do.')
        return

    # --- アンカーの一意性 ---
    for name, a in [('API挿入位置', ANCHOR_API), ('教師画面のペイン', ANCHOR_PANE),
                    ('teacher-ai.jsのscriptタグ', ANCHOR_SCRIPT),
                    ('student-full-analysisのreturn', ANCHOR_ANALYSIS),
                    ('student-full-analysisの返り値', ANCHOR_RETURN)]:
        n = orig.count(a)
        if n != 1:
            die('アンカー「%s」が %d 個（1個であるべき）' % (name, n))

    # --- 既存の必要関数 ---
    for name in ['function jsonError', 'function fyStartYMD', 'function _matchRosterRows(',
                 'function escH(', 'function resolveStudentName(', 'function _rememberAlias(']:
        if name not in orig:
            die('必要な既存関数が見つからない: ' + name)

    # --- 追加しようとしているものが既に無いか ---
    for route in ["app.post('/api/teacher/drillpark/parse'", "app.post('/api/teacher/drillpark/save'",
                  "app.get('/drillpark.js'", "app.post('/api/teacher/drillpark/undo'",
                  "app.get('/api/teacher/drillpark/batches'", 'function _dpAnalyze', 'drill_sessions']:
        if route in orig:
            die('追加しようとしている物が既に存在する: ' + route)

    before_chain = replace_count_in_root_route(orig)
    print("[patch] .replace() chain in app.get('/') before: %d" % before_chain)
    if before_chain != EXPECTED_REPLACE_CHAIN:
        die('.replace() チェーンが %d 件ではない（%d 件）。想定外のファイルなので中止'
            % (EXPECTED_REPLACE_CHAIN, before_chain))

    # --- 危険パターンの自己チェック（コメント行は除外して実コードだけ見る） ---
    code = '\n'.join([ln for ln in BLOCK.split('\n') if not ln.strip().startswith('//')])
    if 'state_json' in code:
        die('追加コードが state_json に触れている')
    for ddl in ['CREATE TABLE', 'ALTER TABLE', 'DROP TABLE', 'CREATE INDEX', 'CREATE UNIQUE',
                'DB.exec(', 'PRAGMA']:
        if ddl in code:
            die('追加コードに DDL が含まれている: ' + ddl)
    for danger in ['UPDATE users', 'UPDATE classes', 'UPDATE class_members',
                   'UPDATE admin_settings', 'INSERT INTO admin_settings']:
        if danger in code:
            die('追加コードに危険な文が含まれている: ' + danger)
    # 書き込みは drill_sessions だけ。他のテーブルへの INSERT / DELETE / UPDATE は許さない。
    for m in re.finditer(r'INSERT\s+INTO\s+(\w+)', code):
        if m.group(1) != 'drill_sessions':
            die('drill_sessions 以外に INSERT している: ' + m.group(1))
    for m in re.finditer(r'DELETE\s+FROM\s+(\w+)', code):
        if m.group(1) != 'drill_sessions':
            die('drill_sessions 以外を DELETE している: ' + m.group(1))
    for m in re.finditer(r'UPDATE\s+(\w+)\s+SET', code):
        die('追加コードに UPDATE がある: ' + m.group(1))
    # DELETE は必ずクラスで絞り、ドリルパーク取り込みぶんに限ること
    n_del = len(re.findall(r'DELETE\s+FROM\s+drill_sessions', code))
    if n_del != 1:
        die('DELETE が %d 個ある（1個であるべき）' % n_del)
    if "DELETE FROM drill_sessions WHERE import_batch=? AND class_id=? AND source='drillpark'" not in code:
        die('DELETE がバッチ・クラス・取り込み元で絞られていない')
    if 'ON CONFLICT(row_key) DO NOTHING' not in code:
        die('二重取り込みを防ぐ ON CONFLICT(row_key) DO NOTHING が無い')

    # --- 適用 ---
    out = orig
    out = out.replace(ANCHOR_API, BLOCK + '\n' + ANCHOR_API, 1)
    out = out.replace(ANCHOR_PANE, PANE_NEW, 1)
    out = out.replace(ANCHOR_SCRIPT, SCRIPT_NEW, 1)
    out = out.replace(ANCHOR_ANALYSIS, ANALYSIS_NEW, 1)
    out = out.replace(ANCHOR_RETURN, RETURN_NEW, 1)

    # --- 非破壊検証（挿入分を取り除くと元に戻るか） ---
    check = out
    check = check.replace(BLOCK + '\n', '', 1)
    check = check.replace(PANE_NEW, ANCHOR_PANE, 1)
    check = check.replace(SCRIPT_NEW, ANCHOR_SCRIPT, 1)
    check = check.replace(ANALYSIS_NEW, ANCHOR_ANALYSIS, 1)
    check = check.replace(RETURN_NEW, ANCHOR_RETURN, 1)
    if check != orig:
        die('非破壊検証に失敗（元ファイルを復元できない）。中止')

    after_chain = replace_count_in_root_route(out)
    print("[patch] .replace() chain in app.get('/') after : %d" % after_chain)
    if after_chain != before_chain:
        die('.replace() チェーンの件数が変わった（%d -> %d）' % (before_chain, after_chain))

    # --- 結果そのものの検証（目印ではなく、実際に出来上がった物を見る） ---
    checks = [
        ("app.post('/api/teacher/drillpark/parse'", 1),
        ("app.post('/api/teacher/drillpark/save'", 1),
        ("app.get('/drillpark.js'", 1),
        ("app.post('/api/teacher/drillpark/undo'", 1),
        ("app.get('/api/teacher/drillpark/batches'", 1),
        ('function _dpAnalyze', 1),
        ('ON CONFLICT(row_key) DO NOTHING', 1),
        ("DELETE FROM drill_sessions WHERE import_batch=? AND class_id=? AND source='drillpark'", 1),
        ('<script src="/drillpark.js?v=1"></script>', 1),
        ('id="dpFile"', 1),
        ('id="dpBatches"', 1),
        ('onchange="dpPickFile(this)"', 1),
        ('FROM drill_sessions WHERE user_id=?', 1),
        ('    drill,\n  })', 1),
        ("app.get('/teacher-ai.js'", 1),
        ("app.post('/api/teacher/test-scores/save'", 1),
    ]
    for needle, want in checks:
        n = out.count(needle)
        if n != want:
            die('適用後の検証に失敗: %r が %d 個（%d 個であるべき）' % (needle[:60], n, want))

    # 元からあった重要な入口が消えていないか
    for keep in ["app.get('/', async (c) => {", "app.get('/teacher'", "app.get('/logout'",
                 "app.get('/api/teacher/student-full-analysis'"]:
        if orig.count(keep) != out.count(keep):
            die('既存の入口の件数が変わった: ' + keep)

    with open(SRC, 'w', encoding='utf-8') as f:
        f.write(out)
    print('[patch] src/index.tsx after  sha256: ' + hashlib.sha256(out.encode('utf-8')).hexdigest())
    print('[patch] OK: applied (+%d bytes)' % (len(out) - len(orig)))


main()
