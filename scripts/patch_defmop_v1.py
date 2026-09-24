# -*- coding: utf-8 -*-
# DEFMOP_V1（防衛戦：全滅で即終了せず、生き残りが基地まで歩く）
#   src/defmop_v1.ts の 3件の置きかえを、src/index.tsx のチェーンに「1件のループ」として足すだけ。
#   ⚠️ この便だけでは 挙動は1つも変わらない。
#      opts.mopTicks の既定が 0 で、いまは誰も渡していないため。
#      有効になるのは src/def_resolve.ts が mopTicks を渡したとき（次の便）。
#   public/index.html は手で編集しない。
#   アンカーが1件でなければ 1文字も書かずに止まる（fail-closed）。
import io
import os
import sys
import hashlib

SRC = 'src/index.tsx'
MOD = 'src/defmop_v1.ts'
HTML = 'public/index.html'
SENTINEL = '__DEFMOP_V1__'
NL = chr(10)


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s（期待 %s）' % (label, got, want))
        ok[0] = False


def need(label, text, s, want):
    got = s.count(text)
    if got != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, got, want))
        sys.exit(1)


raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if not raw.isdigit():
    print('NG: CHAIN_BEFORE が数字でない（渡された値: %r）' % raw)
    sys.exit(1)
CHAIN_BEFORE = int(raw)
CHAIN_AFTER = CHAIN_BEFORE + 1

A_IMPORT = "import { WORLD_V3_PATCHES } from './world_v3'" + NL
N_IMPORT = (A_IMPORT
            + '// __DEFMOP_V1__ 防衛戦：全滅で即終了しない。当てる中身は src/defmop_v1.ts。' + NL
            + "import { DEFMOP_V1_PATCHES } from './defmop_v1'" + NL)

A_LOOP = ("    for (const _wp3 of WORLD_V3_PATCHES) {" + NL
          + "      if (t.indexOf(_wp3.a) !== -1) { t = t.replace(_wp3.a, () => _wp3.b) } else { console.error('[__WORLD_V3__] anchor not found: ' + _wp3.tag) }" + NL
          + '    }' + NL)

N_LOOP = (A_LOOP
          + '    // __DEFMOP_V1__ 防衛戦の掃討フェーズ。既定（mopTicks=0）では 何も変わらない。' + NL
          + '    for (const _dm of DEFMOP_V1_PATCHES) {' + NL
          + "      if (t.indexOf(_dm.a) !== -1) { t = t.replace(_dm.a, () => _dm.b) } else { console.error('[__DEFMOP_V1__] anchor not found: ' + _dm.tag) }" + NL
          + '    }' + NL)

# 配信後も生きていないと困るもの
KEEP = [
    ('捕獲不可を敵プールから外す', 'if (m.isBoss) continue; if (m.uncapturable) continue;'),
    ('交換の特別扱い', 'cannot_trade_special'),
    ('電気の問題', 'function genElectric6'),
    ('せまい画面の交戦', '__ZWAR_REACH_FIX_V1__'),
    ('防衛戦のレーン配分', '__DEFLANE_MIX_V1__'),
    ('世界編 第3段', '__WORLD_V3__'),
]

# --------------------------------------------------------------------------
s = io.open(SRC, encoding='utf-8').read()
h = io.open(HTML, encoding='utf-8').read()
try:
    m = io.open(MOD, encoding='utf-8').read()
except IOError:
    print('NG: %s が無い。先にファイルを置いてから流す。' % MOD)
    sys.exit(1)

before = chain_count(s)
print('chain(before) =', before, '（CHAIN_BEFORE =', CHAIN_BEFORE, '）')
print('public/index.html sha256 =', hashlib.sha256(h.encode('utf-8')).hexdigest())
print('src/defmop_v1.ts sha256 =', hashlib.sha256(m.encode('utf-8')).hexdigest())

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。何も書かない。chain =', before)
    sys.exit(0)

if before != CHAIN_BEFORE:
    print('NG: 流す前のチェーンが %d 件（渡された %d と違う）。並行作業の可能性。止める。' % (before, CHAIN_BEFORE))
    sys.exit(1)

need('defmop_v1 の書き出し', 'export const DEFMOP_V1_PATCHES', m, 1)
if m.count("tag: 'M") != 3:
    print('NG: defmop_v1.ts のパッチが %d 件（期待 3）' % m.count("tag: 'M"))
    sys.exit(1)

# 既定が 0 であること（この便を無害にしている条件そのもの）
if 'Number(opts.mopTicks) || 0' not in m:
    print('NG: mopTicks の既定が 0 になっていない。この便は無害でなければならない。')
    sys.exit(1)

for label, text in KEEP:
    if text not in h and text not in s:
        print('NG: 安全マーカー「%s」が見あたらない' % label)
        sys.exit(1)

need('world_v3 の import', A_IMPORT, s, 1)
need('world_v3 のループ', A_LOOP, s, 1)

s = s.replace(A_IMPORT, N_IMPORT, 1)
s = s.replace(A_LOOP, N_LOOP, 1)

after = chain_count(s)

chk('チェーン', after, CHAIN_AFTER)
chk('増えた件数', after - before, 1)
chk('defmop_v1 の import', s.count("from './defmop_v1'"), 1)
chk('当てるループ', s.count('for (const _dm of DEFMOP_V1_PATCHES) {'), 1)

# 壊してはいけないもの
chk('world_v1 のループ', s.count('for (const _wp of WORLD_V1_PATCHES) {'), 1)
chk('world_v2 のループ', s.count('for (const _wp2 of WORLD_V2_PATCHES) {'), 1)
chk('world_v3 のループ', s.count('for (const _wp3 of WORLD_V3_PATCHES) {'), 1)
chk('def_engine の import', s.count("from './def_engine'"), 1)
chk('def_resolve の import', s.count("from './def_resolve'"), 1)
chk('logout ルート', s.count("app.get('/logout'"), 1)
chk('チェーンの入口', s.count("app.get('/', async (c) => {"), 1)
chk('_rootHtmlCache の締め', s.count('_rootHtmlCache = t'), 1)

if not ok[0]:
    print('検証に落ちたので何も書かない')
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('OK: 適用した。chain =', before, '->', after)
print('※ この便では 挙動は変わらない（mopTicks 既定 0）。')
