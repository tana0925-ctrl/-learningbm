# scripts/patch_teacher_recovery_v1.py
# 教師用ログイン復旧（/teacher-recovery）を src/index.tsx に追加する。
#
#   1. 挿入する中身は scripts/teacher_recovery_block.ts（素のTS）から読む
#   2. そのブロックの SHA-256 を照合（1文字でも違えば中止）
#   3. アンカーが想定どおり1か所だけ存在するか検証
#   4. すでに適用済みなら何もしない（冪等）
#   5. 挿入後、挿入分を取り除くと元ファイルと完全一致することを検証（非破壊）
#   6. app.get('/') 内の .replace() チェーン23件の生存確認
#   7. 追加コードに DDL / state_json / 許可外カラムのUPDATE が無いか自己チェック
#
# どれか一つでも失敗したら、ファイルを一切書き換えずに異常終了する。
import sys, os, re, hashlib

SRC = 'src/index.tsx'
BLOCK_FILE = 'scripts/teacher_recovery_block.ts'
MARK = '__TEACHER_RECOVERY_V1__'
BLOCK_SHA256 = '4c0f8ed8b475ac8324aed815370a900828cce89c26cfcf0076682b3aba00d18f'

ANCHOR_MI = '// 🧭 MIしらべ（/mi, /teacher-mi, /api/mi/*, /api/teacher/mi/*）を登録'

ANCHOR_PANEL = '<h2 class="font-bold mb-3">🔑 児童のパスワード再設定</h2>'

PANEL_ADD = '\n        <div class="mb-3 bg-amber-50 border-2 border-amber-300 rounded-lg p-3">\n          <div class="font-bold text-amber-800 text-sm">🆘 何人もまとめて直したいとき</div>\n          <p class="text-xs text-amber-700 mt-1">「2学期に入ってからログインしていない子」などでしぼりこみ → まとめてパスワードを作り直し → 切って配れるカードを印刷、まで1つの画面でできます。</p>\n          <a href="/teacher-recovery" class="inline-block mt-2 bg-amber-500 hover:bg-amber-600 text-white rounded-lg px-3 py-1.5 text-xs font-bold">ログイン復旧の画面をひらく →</a>\n        </div>'

PANEL_NEW = ANCHOR_PANEL + PANEL_ADD


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

    if MARK in orig:
        print('[patch] already applied (idempotent). nothing to do.')
        return

    if orig.count(ANCHOR_MI) != 1:
        die('registerMi のアンカーが %d 個（1個であるべき）' % orig.count(ANCHOR_MI))
    if orig.count(ANCHOR_PANEL) != 1:
        die('教師ダッシュボードのパネルのアンカーが %d 個（1個であるべき）' % orig.count(ANCHOR_PANEL))
    for name in ["function requireTeacher(c: any)", "function genKidPassword()",
                 "function randomHex", "function jsonError", "function pbkdf2Hash"]:
        if name not in orig:
            die('必要な既存関数が見つからない: ' + name)
    for route in ["app.get('/teacher-recovery'", "/api/teacher/recovery/students",
                  "/api/teacher/recovery/bulk-reset"]:
        if route in orig:
            die('追加しようとしているルートが既に存在する: ' + route)

    before_chain = replace_count_in_root_route(orig)
    print("[patch] .replace() chain in app.get('/') before: %d" % before_chain)
    if before_chain != 23:
        die('.replace() チェーンが 23 件ではない（%d 件）。想定外のファイルなので中止' % before_chain)

    # --- 危険パターンの自己チェック（コメント行は除外して実コードだけ見る） ---
    code = '\n'.join([ln for ln in BLOCK.split('\n') if not ln.strip().startswith('//')])
    if 'state_json' in code:
        die('追加コードが state_json に触れている')
    for ddl in ['CREATE TABLE', 'ALTER TABLE', 'DROP TABLE', 'CREATE INDEX', 'DB.exec(']:
        if ddl in code:
            die('追加コードに DDL が含まれている: ' + ddl)
    for danger in ['DELETE FROM', 'INSERT INTO', 'UPDATE classes', 'UPDATE class_members']:
        if danger in code:
            die('追加コードに危険な文が含まれている: ' + danger)
    allowed = ['password_hash', 'password_salt', 'password_updated_at', 'must_change_password']
    for m in re.finditer(r'UPDATE\s+(\w+)\s+SET([^`]*)', code):
        if m.group(1) != 'users':
            die('users 以外を UPDATE している: ' + m.group(1))
        for col in re.findall(r'(\w+)\s*=', m.group(2).split('WHERE')[0]):
            if col not in allowed and col != 'datetime':
                die('許可されていないカラムを UPDATE している: ' + col)

    # --- 適用 ---
    out = orig.replace(ANCHOR_PANEL, PANEL_NEW, 1)
    out = out.replace(ANCHOR_MI, BLOCK + ANCHOR_MI, 1)

    # --- 非破壊検証 ---
    check = out.replace(BLOCK, '', 1).replace(PANEL_NEW, ANCHOR_PANEL, 1)
    if check != orig:
        die('非破壊検証に失敗（元ファイルを復元できない）。中止')

    after_chain = replace_count_in_root_route(out)
    print("[patch] .replace() chain in app.get('/') after : %d" % after_chain)
    if after_chain != before_chain:
        die('.replace() チェーンの件数が変わった（%d -> %d）' % (before_chain, after_chain))

    with open(SRC, 'w', encoding='utf-8') as f:
        f.write(out)
    print('[patch] src/index.tsx after  sha256: ' + hashlib.sha256(out.encode('utf-8')).hexdigest())
    print('[patch] OK: applied (+%d bytes)' % (len(out) - len(orig)))


main()
