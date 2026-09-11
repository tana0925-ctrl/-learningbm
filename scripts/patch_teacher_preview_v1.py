# scripts/patch_teacher_preview_v1.py
# 👀 児童画面プレビュー（先生用・読み取り専用）を src/index.tsx に追加する。
#
# src/index.tsx への変更は 2 か所だけ:
#   (A) registerMi(app) の手前に、API ブロック（scripts/teacher_preview_block.ts）を挿入
#   (B) /teacher ページの <script src="/teacher-ai.js?v=N"></script> の直後に
#       <script src="/teacher-preview.js?v=1"></script> を 1 行追加
#
# 安全装置:
#   1. 挿入する中身は scripts/teacher_preview_block.ts（素のTS）から読む
#   2. そのブロックの SHA-256 を照合（1文字でも違えば中止）
#   3. アンカーが想定どおり1か所だけ存在するか検証（0個でも2個でも中止）
#   4. すでに適用済みなら何もしない（冪等）。番兵は MARK_SENTINEL。
#      ※ 番兵と「適用できたかの検証」は別物にしてある。
#         検証は番兵ではなく「実際に増えたルート文字列・scriptタグ」そのものを数える。
#   5. 挿入後、挿入分を取り除くと元ファイルと完全一致することを検証（非破壊）
#   6. app.get('/') 内の .replace() チェーンの件数が、適用の前後で変わっていないことを検証
#      （絶対値は EXPECT_REPLACE_CHAIN が指定されたときだけ照合する。
#        チェーンは別セッションが増やしている最中なので、流す直前に実測した値を渡すこと）
#   7. 追加コードに 書き込み / DDL / state_json が無いか自己チェック
#   8. public/teacher-preview.js が「GET しかしない」ことを自己チェック
# どれか一つでも失敗したら、ファイルを一切書き換えずに異常終了する。

import sys, os, re, hashlib

SRC = 'src/index.tsx'
BLOCK_FILE = 'scripts/teacher_preview_block.ts'
JS_FILE = 'public/teacher-preview.js'

MARK_SENTINEL = '__TEACHER_SCREEN_PREVIEW_V1__'

BLOCK_SHA256 = 'c9cdddfa2af8febcf3540a784ff1a6dce9440586391fc8b0bab0075be79ee57e'
JS_SHA256 = '772110f7bab36e189b789a61046c35e67ca3da86b6fe2d8569b755fdb79c8a3a'

# (A) ブロックの挿入位置
ANCHOR_MI = '// \U0001F9ED MIしらべ（/mi, /teacher-mi, /api/mi/*, /api/teacher/mi/*）を登録'

# (B) /teacher ページの script タグ（teacher-ai.js のバージョンは上がることがあるので正規表現で拾う）
TAG_RE = re.compile(r'<script src="/teacher-ai\.js\?v=\d+"></script>')
TAG_ADD = '\n    <script src="/teacher-preview.js?v=1"></script>'

# --- 「適用できたか」の検証に使う実物（番兵とは別の文字列であること） ---
RESULT_ROUTE_API = "app.get('/api/teacher/student-screen-preview'"
RESULT_ROUTE_JS = "app.get('/teacher-preview.js'"
RESULT_TAG = '<script src="/teacher-preview.js?v=1"></script>'


def die(msg):
    print('[patch] NG: ' + msg)
    sys.exit(1)


def replace_count_in_root_route(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'")
    return s[i:j].count('.replace(')


def sha256(s):
    return hashlib.sha256(s.encode('utf-8')).hexdigest()


def main():
    for f in (BLOCK_FILE, JS_FILE, SRC):
        if not os.path.exists(f):
            die('必要なファイルが無い: ' + f)

    with open(BLOCK_FILE, 'r', encoding='utf-8') as f:
        BLOCK = f.read()
    with open(JS_FILE, 'r', encoding='utf-8') as f:
        JS = f.read()

    got = sha256(BLOCK)
    print('[patch] block sha256 expected: ' + BLOCK_SHA256)
    print('[patch] block sha256 actual  : ' + got)
    if got != BLOCK_SHA256:
        die('ブロックファイルの SHA-256 が一致しない（転記ミス・改行コードの混入など）')

    gotjs = sha256(JS)
    print('[patch] js    sha256 expected: ' + JS_SHA256)
    print('[patch] js    sha256 actual  : ' + gotjs)
    if gotjs != JS_SHA256:
        die('public/teacher-preview.js の SHA-256 が一致しない')

    with open(SRC, 'r', encoding='utf-8') as f:
        orig = f.read()
    print('[patch] src/index.tsx before sha256: ' + sha256(orig))
    print('[patch] src/index.tsx before lines : %d' % orig.count('\n'))

    # --- 4. 冪等（番兵） ---
    if MARK_SENTINEL in orig:
        print('[patch] already applied (idempotent). nothing to do.')
        for needle in (RESULT_ROUTE_API, RESULT_ROUTE_JS, RESULT_TAG):
            if orig.count(needle) != 1:
                die('適用済みのはずなのに %s が %d 個（1個であるべき）' % (needle, orig.count(needle)))
        return

    # --- 3. アンカー一意性 ---
    if orig.count(ANCHOR_MI) != 1:
        die('registerMi のアンカーが %d 個（1個であるべき）' % orig.count(ANCHOR_MI))
    tags = TAG_RE.findall(orig)
    if len(tags) != 1:
        die('/teacher の teacher-ai.js の script タグが %d 個（1個であるべき）' % len(tags))
    ANCHOR_TAG = tags[0]
    print('[patch] anchor script tag: ' + ANCHOR_TAG)

    for name in ["function requireTeacher(c: any)", "function jsonError",
                 "function getWeekKey", "function getPrevWeekKey"]:
        if name not in orig:
            die('必要な既存関数が見つからない: ' + name)

    for needle in (RESULT_ROUTE_API, RESULT_ROUTE_JS, 'teacher-preview.js'):
        if needle in orig:
            die('追加しようとしているものが既に存在する: ' + needle)

    before_chain = replace_count_in_root_route(orig)
    print("[patch] .replace() chain in app.get('/') before: %d" % before_chain)
    expect = os.environ.get('EXPECT_REPLACE_CHAIN', '').strip()
    if expect:
        if before_chain != int(expect):
            die('.replace() チェーンが %s 件ではない（%d 件）。想定外のファイルなので中止' % (expect, before_chain))
    else:
        print('[patch] (EXPECT_REPLACE_CHAIN 未指定。前後で変わらないことだけを見る)')

    # --- 7. 追加コードの自己チェック（コメント行を除いた実コードだけ見る） ---
    code = '\n'.join([ln for ln in BLOCK.split('\n') if not ln.strip().startswith('//')])
    if 'state_json' in code:
        die('追加コードが state_json に触れている')
    for ddl in ['CREATE TABLE', 'ALTER TABLE', 'DROP TABLE', 'CREATE INDEX', 'DB.exec(']:
        if ddl in code:
            die('追加コードに DDL が含まれている: ' + ddl)
    for w in ['INSERT INTO', 'DELETE FROM', 'UPDATE ', 'REPLACE INTO']:
        if w in code:
            die('追加コードに書き込み文が含まれている: ' + w)
    if '.run()' in code:
        die('追加コードが .run() を呼んでいる（D1 の書き込み経路なので禁止）')
    if 'requireTeacher' not in code:
        die('追加コードが requireTeacher を通っていない')
    # SELECT 以外の SQL が混ざっていないか（クォートの直後の語を見る）
    for m in re.finditer(r"['\"\`]\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|PRAGMA)\b", code, re.I):
        if m.group(1).upper() != 'SELECT':
            die('SELECT 以外の SQL が含まれている: ' + m.group(1))

    # --- 8. public/teacher-preview.js の自己チェック ---
    jscode = '\n'.join([ln for ln in JS.split('\n') if not ln.strip().startswith('*') and not ln.strip().startswith('/*')])
    for w in ["method: 'POST'", 'method:"POST"', "method: 'PUT'", "method: 'DELETE'", 'XMLHttpRequest', 'navigator.sendBeacon']:
        if w in jscode:
            die('teacher-preview.js に書き込みの通信がある: ' + w)
    if jscode.count('fetch(') != 1:
        die('teacher-preview.js の fetch( が %d 個（読み取り専用の入口 1 個だけであるべき）' % jscode.count('fetch('))
    for api in ['/api/teacher/student-screen-preview', '/api/teacher/classes', '/api/teacher/class/']:
        if api not in jscode:
            die('teacher-preview.js が呼ぶはずの API が無い: ' + api)

    # --- 適用 ---
    out = orig.replace(ANCHOR_MI, BLOCK + ANCHOR_MI, 1)
    out = out.replace(ANCHOR_TAG, ANCHOR_TAG + TAG_ADD, 1)

    # --- 5. 非破壊検証（挿入分を取り除くと元に戻るか） ---
    check = out.replace(BLOCK, '', 1).replace(ANCHOR_TAG + TAG_ADD, ANCHOR_TAG, 1)
    if check != orig:
        die('非破壊検証に失敗（元ファイルを復元できない）。中止')

    # --- 「実物」による適用後検証（番兵ではなく結果そのものを見る） ---
    for needle in (RESULT_ROUTE_API, RESULT_ROUTE_JS, RESULT_TAG):
        n = out.count(needle)
        if n != 1:
            die('適用後に %s が %d 個（1個であるべき）' % (needle, n))
    if out.count(MARK_SENTINEL) != 2:
        die('番兵の開始/終了が 2 個になっていない（%d 個）' % out.count(MARK_SENTINEL))

    # --- 6. チェーンの生存確認 ---
    after_chain = replace_count_in_root_route(out)
    print("[patch] .replace() chain in app.get('/') after : %d" % after_chain)
    if after_chain != before_chain:
        die('.replace() チェーンの件数が変わった（%d -> %d）' % (before_chain, after_chain))

    with open(SRC, 'w', encoding='utf-8') as f:
        f.write(out)
    print('[patch] src/index.tsx after  sha256: ' + sha256(out))
    print('[patch] src/index.tsx after  lines : %d' % out.count('\n'))
    print('[patch] OK: applied (+%d bytes, +%d lines)' % (len(out) - len(orig), out.count('\n') - orig.count('\n')))


main()
