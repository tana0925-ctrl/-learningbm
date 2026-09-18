# -*- coding: utf-8 -*-
# WORLD_V3（3周目「世界編」第3段：宇宙人化＝青い敵 ＋ 洗脳）
#   src/world_v3.ts の 7件の置きかえを、src/index.tsx のチェーンに「1件のループ」として足すだけ。
#   world_v2 のループより後ろに置く。
#   サーバ側は 1文字も変えない（この段はぜんぶ画面の中の話）。
#   public/index.html は手で編集しない。
#   アンカーが1件でなければ 1文字も書かずに止まる（fail-closed）。
#   既存の進行データ（current / clearedMax / unlocked / zombieCleared）への書き込みが
#   追加コードに1つも無いことも、ここで確かめる。
import io
import os
import sys
import hashlib

SRC = 'src/index.tsx'
MOD = 'src/world_v3.ts'
HTML = 'public/index.html'
SENTINEL = '__WORLD_V3__'
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

A_IMPORT = "import { WORLD_V2_PATCHES } from './world_v2'" + NL
N_IMPORT = (A_IMPORT
            + '// __WORLD_V3__ 3周目「世界編」第3段。当てる中身は src/world_v3.ts。' + NL
            + "import { WORLD_V3_PATCHES } from './world_v3'" + NL)

A_LOOP = ("    for (const _wp2 of WORLD_V2_PATCHES) {" + NL
          + "      if (t.indexOf(_wp2.a) !== -1) { t = t.replace(_wp2.a, () => _wp2.b) } else { console.error('[__WORLD_V2__] anchor not found: ' + _wp2.tag) }" + NL
          + '    }' + NL)

N_LOOP = (A_LOOP
          + '    // __WORLD_V3__ 世界編 第3段（宇宙人化＝青い敵 と 洗脳）。中身は src/world_v3.ts。' + NL
          + '    for (const _wp3 of WORLD_V3_PATCHES) {' + NL
          + "      if (t.indexOf(_wp3.a) !== -1) { t = t.replace(_wp3.a, () => _wp3.b) } else { console.error('[__WORLD_V3__] anchor not found: ' + _wp3.tag) }" + NL
          + '    }' + NL)

BAD = ['warProgress.current =', 'clearedMax =', 'unlocked =', 'zombieCleared[']

# 配信後も生きていないと困るもの（この便で壊していないことを確かめる）
KEEP = [
    ('捕獲不可を敵プールから外す', 'if (m.isBoss) continue; if (m.uncapturable) continue;'),
    ('交換の特別扱い', 'cannot_trade_special'),
    ('電気の問題', 'function genElectric6'),
    ('ジムの種を固定', 'var _seed=((_hash(String(_gcGid))^0x9e3779b9)>>>0);'),
    ('せまい画面の交戦', '__ZWAR_REACH_FIX_V1__'),
    ('出撃コスト上限400', '/6), 30, 400)'),
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
print('src/world_v3.ts  sha256 =', hashlib.sha256(m.encode('utf-8')).hexdigest())

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。何も書かない。chain =', before)
    sys.exit(0)

if before != CHAIN_BEFORE:
    print('NG: 流す前のチェーンが %d 件（渡された %d と違う）。並行作業の可能性。止める。' % (before, CHAIN_BEFORE))
    sys.exit(1)

need('world_v3 の書き出し', 'export const WORLD_V3_PATCHES', m, 1)
if m.count("tag: 'X") != 7:
    print('NG: world_v3.ts のパッチが %d 件（期待 7）' % m.count("tag: 'X"))
    sys.exit(1)

# 乱数は warSeeded から引くこと（Math.random を足していないこと）
if 'Math.random(' in m:
    print('NG: world_v3.ts に Math.random( がある。乱数は warSeeded から引くこと。')
    sys.exit(1)

for w in BAD:
    if w in m:
        print('NG: 追加コードに既存の進行データへの書き込み「%s」がある' % w)
        sys.exit(1)
    if w in (N_IMPORT + N_LOOP):
        print('NG: つなぎ目に「%s」がある' % w)
        sys.exit(1)

# 配信前の public/index.html に 安全マーカーの土台があること
for label, text in KEEP:
    if text not in h and text not in s:
        print('NG: 安全マーカー「%s」が見あたらない' % label)
        sys.exit(1)

need('world_v2 の import', A_IMPORT, s, 1)
need('world_v2 のループ', A_LOOP, s, 1)

s = s.replace(A_IMPORT, N_IMPORT, 1)
s = s.replace(A_LOOP, N_LOOP, 1)

after = chain_count(s)

chk('チェーン', after, CHAIN_AFTER)
chk('増えた件数', after - before, 1)
chk('world_v3 の import', s.count("from './world_v3'"), 1)
chk('当てるループ', s.count('for (const _wp3 of WORLD_V3_PATCHES) {'), 1)

# 壊してはいけないもの
chk('world_v1 の import', s.count("from './world_v1'"), 1)
chk('world_v2 の import', s.count("from './world_v2'"), 1)
chk('world_v1 のループ', s.count('for (const _wp of WORLD_V1_PATCHES) {'), 1)
chk('world_v2 のループ', s.count('for (const _wp2 of WORLD_V2_PATCHES) {'), 1)
chk('def_engine の import', s.count("from './def_engine'"), 1)
chk('logout ルート', s.count("app.get('/logout'"), 1)
chk('チェーンの入口', s.count("app.get('/', async (c) => {"), 1)
chk('_rootHtmlCache の締め', s.count('_rootHtmlCache = t'), 1)
chk('世界編のごほうび台帳', s.count('async function applyWorldStageGrants'), 1)
chk('防衛戦の台帳', s.count('async function applyDefStageGrants'), 1)

if not ok[0]:
    print('検証に落ちたので何も書かない')
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('OK: 適用した。chain =', before, '->', after)
