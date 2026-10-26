# VIEWAS_V1 👀 子どもの画面に入る（見るだけ）を src/index.tsx に3か所だけ足す。
#   (A) import 1行   (B) 既存の認証ミドルウェアの直後に installViewAs(...) 1行   (C) /teacher に <script> 1行
#   + scripts/viewas_client.js から src/viewas_client.ts を作る
# 安全装置: アンカーが1か所だけ・冪等・非破壊（足した分を除くと元どおり）・app.get('/') の .replace() 件数が不変。
import sys, json

SRC = 'src/index.tsx'
MARK = 'VIEWAS_V1'

A_ANCHOR = "import { registerMinna } from './minna'"
A_ADD = "\nimport { installViewAs } from './viewas'   // VIEWAS_V1"
B_ANCHOR = '// -------------------- NGワードフィルター --------------------'
B_ADD = ("// 👀 VIEWAS_V1 先生が子どもの画面に「見るだけ」で入る（src/viewas.ts）。認証ミドルウェアの直後でなければならない。\n"
         "installViewAs(app, { readSession, makeSession, getCookie, setCookie, deleteCookie })\n\n")
C_ANCHOR = '<script src="/teacher-preview.js?v=1"></script>'
C_ADD = '\n    <script src="/viewas-teacher.js?v=1"></script>'


def die(m):
    print('[viewas] NG: ' + m); sys.exit(1)


def chain(s):
    i = s.index("app.get('/', async (c) => {"); j = s.index("app.get('/logout'")
    return s[i:j].count('.replace(')


js = open('scripts/viewas_client.js', encoding='utf-8').read()
ts = ('// 自動生成（scripts/apply_viewas_v1.py が scripts/viewas_client.js から作る）。手で直さない。VIEWAS_V1\n'
      'export const VIEWAS_CLIENT_JS: string = ' + json.dumps(js, ensure_ascii=False) + '\n')
open('src/viewas_client.ts', 'w', encoding='utf-8', newline='\n').write(ts)

s = open(SRC, encoding='utf-8', newline='').read()
if "from './viewas'" in s:
    print('[viewas] already applied'); sys.exit(0)
for a in (A_ANCHOR, B_ANCHOR, C_ANCHOR):
    if s.count(a) != 1:
        die('anchor count %d: %s' % (s.count(a), a))
if s.index(B_ANCHOR) < s.index("app.use('/api/*', async (c, next) => {\n  const token = getCookie(c, 'session')"):
    die('B が認証ミドルウェアより前にある')
before = chain(s)
o = s.replace(A_ANCHOR, A_ANCHOR + A_ADD, 1).replace(B_ANCHOR, B_ADD + B_ANCHOR, 1).replace(C_ANCHOR, C_ANCHOR + C_ADD, 1)
back = o.replace(A_ADD, '', 1).replace(B_ADD, '', 1).replace(C_ANCHOR + C_ADD, C_ANCHOR, 1)
if back != s:
    die('非破壊検証に失敗')
if chain(o) != before:
    die('.replace() チェーンの件数が変わった')
open(SRC, 'w', encoding='utf-8', newline='').write(o)
print('[viewas] OK +%d bytes, chain=%d' % (len(o) - len(s), before))
