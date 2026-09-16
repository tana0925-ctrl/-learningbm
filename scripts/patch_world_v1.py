# -*- coding: utf-8 -*-
# WORLD_V1（3周目「世界編」第1段：あそべる箱だけ。キャラとごほうびは第2段）
#   src/world_v1.ts に入れた 10件のアンカー置きかえを、src/index.tsx の
#   .replace チェーンに「1件のループ」として足すだけ。
#   public/index.html は手で編集しない。
#   アンカーが1件でなければ 1文字も書かずに止まる（fail-closed）。
#   既存の進行データ（current / clearedMax / unlocked / zombieCleared）への
#   書き込みが追加コードに1つも無いことも、ここで確かめる。
import io
import sys
import hashlib

SRC = 'src/index.tsx'
MOD = 'src/world_v1.ts'
HTML = 'public/index.html'
SENTINEL = '__WORLD_V1__'
CHAIN_BEFORE = 104
CHAIN_AFTER = 105
NL = chr(10)


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


def need(label, text, s, want):
    got = s.count(text)
    if got != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, got, want))
        sys.exit(1)


A_IMPORT = "import { defDexEntry } from './def_dex'" + NL
N_IMPORT = (A_IMPORT
            + '// __WORLD_V1__ 3周目「世界編」第1段。当てる中身は src/world_v1.ts。' + NL
            + "import { WORLD_V1_PATCHES } from './world_v1'" + NL)

A_CHAIN = NL + '    _rootHtmlCache = t' + NL
N_CHAIN = (NL
           + '    // __WORLD_V1__ 3周目「世界編」第1段（あそべる箱だけ）。中身は src/world_v1.ts。' + NL
           + '    // アンカーが無ければ console.error して飛ばす（throw するとチェーン全件が消えるため）。' + NL
           + '    for (const _wp of WORLD_V1_PATCHES) {' + NL
           + "      if (t.indexOf(_wp.a) !== -1) { t = t.replace(_wp.a, () => _wp.b) } else { console.error('[__WORLD_V1__] anchor not found: ' + _wp.tag) }" + NL
           + '    }' + NL
           + '    _rootHtmlCache = t' + NL)

ANCHORS = [
    ('1 世界編データの置き場', '  const ZOMBIE_ALLCLEAR_MONSTER_ID = 1201;'),
    ('2 ステージ一覧の分岐', '    // 都道府県データを地域別に整理'),
    ('3 タブの取りつけ', '    modal.innerHTML = html;'),
    ('4a ステージ名', "    warState.stageName = WAR_PREFS[idx] || '---';"),
    ('4b むずかしさ', '    const cfg = warGetStageConfig(idx);'),
    ('5 日本のステージ選択', '  window.selectWarStage = function(i){'),
    ('6 プレビューの見出し', "  document.getElementById('previewStageName').textContent = stageName + ' ステージ';"),
    ('7 プレビューのボス紹介', '  if (cfg.boss && cfg.boss.monsterId) {'),
    ('8 ゾンビ襲来ボタン', '      const canZombie = (stageIndex < cleared);'),
    ('9 勝ったときの記録', '        let gotBossId = null;'),
    ('10 県ボスの報酬', '          const boss = stageName ? (WAR_PREF_BOSS[stageName]||null) : null;'),
]

BAD = ['warProgress.current =', 'clearedMax =', 'unlocked =', 'zombieCleared[']

# ------------------------------------------------------------------
s = io.open(SRC, encoding='utf-8').read()
h = io.open(HTML, encoding='utf-8').read()
try:
    m = io.open(MOD, encoding='utf-8').read()
except IOError:
    print('NG: %s が無い。先にファイルを置いてから流す。' % MOD)
    sys.exit(1)

before = chain_count(s)
print('chain(before) =', before)
print('public/index.html sha256 =', hashlib.sha256(h.encode('utf-8')).hexdigest())
print('src/world_v1.ts  sha256 =', hashlib.sha256(m.encode('utf-8')).hexdigest())

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。何も書かない。chain =', before)
    sys.exit(0)

if before != CHAIN_BEFORE:
    print('NG: 流す前のチェーンが %d 件（期待 %d）。並行作業の可能性。止める。' % (before, CHAIN_BEFORE))
    sys.exit(1)

# --- 世界編モジュールの中身 ---
need('world_v1 の書き出し', 'export const WORLD_V1_PATCHES', m, 1)
if m.count("tag: 'W") != 10:
    print('NG: world_v1.ts のパッチが %d 件（期待 10）' % m.count("tag: 'W"))
    sys.exit(1)

# --- 追加コードに 既存の進行データへの書き込みが1つも無いこと ---
for w in BAD:
    if w in m:
        print('NG: 追加コードに既存の進行データへの書き込み「%s」がある' % w)
        sys.exit(1)
    if w in (N_IMPORT + N_CHAIN):
        print('NG: つなぎ目に「%s」がある' % w)
        sys.exit(1)

# --- public/index.html の アンカーが ぜんぶ 1件ずつ あること ---
for label, a in ANCHORS:
    need(label, a, h, 1)

# --- src/index.tsx の つなぎ目 ---
need('def_dex の import', A_IMPORT, s, 1)
need('_rootHtmlCache の締め', A_CHAIN, s, 1)

s = s.replace(A_IMPORT, N_IMPORT, 1)
s = s.replace(A_CHAIN, N_CHAIN, 1)

after = chain_count(s)

# --- 増えたのは自分の1件だけ ---
chk('チェーン', after, CHAIN_AFTER)
chk('増えた件数', after - before, 1)
chk('番兵(src)', s.count(SENTINEL), 3)
chk('world_v1 の import', s.count("from './world_v1'"), 1)
chk('当てるループ', s.count('for (const _wp of WORLD_V1_PATCHES) {'), 1)
chk('_rootHtmlCache の締め', s.count('_rootHtmlCache = t'), 1)

# --- 壊してはいけないもの ---
chk('def_engine の import', s.count("from './def_engine'"), 1)
chk('logout ルート', s.count("app.get('/logout'"), 1)
chk('チェーンの入口', s.count("app.get('/', async (c) => {"), 1)

if not ok[0]:
    print('検証に落ちたので何も書かない')
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('OK: 適用した。chain =', before, '->', after)
