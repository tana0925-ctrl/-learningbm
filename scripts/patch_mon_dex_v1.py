#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# キャラの絵 第2便: 図鑑だけ。絵があれば絵、無ければ今までの絵文字。
#
# 触るのは図鑑の4か所だけ。
#   1. 図鑑の一覧（490体がならぶところ）
#   2. 進化のならび（詳細画面の中・ふつうの枝）
#   3. 進化のならび（詳細画面の中・もう1本の枝）
#   4. 詳細画面の大きい絵
# ほかに 見た目をそろえるCSSを1つ足す。
#
# 触らないもの: バトル、ガチャ、ショップ、トレード、防衛戦、ゾンビ、
#   タマゴバトル、タイプシュート、教師画面、ボックス、ジムリーダーの一覧。
#
# id 154「阪神マン」は 図鑑で隠されたまま（しぼりこみの行には一切さわらない）。
#
# 遅延読み込みは monSpriteHtml が loading=lazy を付けるので自動で効く。
#
# 守り（どれか1つでも合わなければ 何も書かずに止まる）:
#   - src/index.tsx の チェーン数 が 158 であること
#   - public/index.html に MON_IMG_V1（第1便の受け皿）が入っていること
#   - MON_DEX_V1 が まだ入っていないこと
#   - あて先が それぞれ ちょうど1件 であること
#   - src/index.tsx を 1文字も変えないこと

import sys

SRC = 'src/index.tsx'
PUB = 'public/index.html'
CHAIN_BEFORE = 158

CALL = "((typeof monSpriteHtml === 'function') ? monSpriteHtml(m.id, (m.sprite || '？')) : (m.sprite || '？'))"

PAIRS = []

# 1. 図鑑の一覧
PAIRS.append((
    r'''    const badgeHtml = inParty ? '<div class="party-badge">PT</div>' : '';
    const sprite = unlocked ? (m.sprite || '？') : '？';''',
    r'''    const badgeHtml = inParty ? '<div class="party-badge">PT</div>' : '';
    /* MON_DEX_V1 図鑑の一覧: 絵があれば絵、無ければ絵文字 */
    const sprite = unlocked ? ''' + CALL + " : '？';",
    '図鑑の一覧',
))

# 2. 進化のならび（ふつうの枝）
PAIRS.append((
    r'''                const sprite = unlocked ? (m.sprite || '？') : '？';
                const name = unlocked ? (m.name || '???') : '???';''',
    '                /* MON_DEX_V1 進化のならび */\n'
    '                const sprite = unlocked ? ' + CALL + " : '？';\n"
    r'''                const name = unlocked ? (m.name || '???') : '???';''',
    '進化のならび（ふつうの枝）',
))

# 3. 進化のならび（もう1本の枝）
PAIRS.append((
    r'''                const sprite = (m.sprite || '？');
                const name = (m.name || '???');''',
    '                /* MON_DEX_V1 進化のならび2 */\n'
    '                const sprite = ' + CALL + ';\n'
    r'''                const name = (m.name || '???');''',
    '進化のならび（もう1本の枝）',
))

# 4. 詳細画面の大きい絵
PAIRS.append((
    "document.getElementById('detailSprite').innerText = m.sprite;",
    "/* MON_DEX_V1 詳細の大きい絵 */ try { document.getElementById('detailSprite').innerHTML = "
    "(typeof monSpriteHtml === 'function') ? monSpriteHtml(m.id, m.sprite) "
    ": String(m.sprite == null ? '' : m.sprite); } "
    "catch (e) { document.getElementById('detailSprite').innerText = m.sprite; }",
    '詳細画面の大きい絵',
))

# 5. 見た目をそろえるCSS（第1便の style のすぐ後ろに足す）
PAIRS.append((
    '.mon-img-shadow{ filter: drop-shadow(0 1px 2px rgba(0,0,0,0.45)); }\n</style>',
    '.mon-img-shadow{ filter: drop-shadow(0 1px 2px rgba(0,0,0,0.45)); }\n</style>\n'
    '<style>/* MON_DEX_V1 図鑑で 絵と絵文字の大きさをそろえる */\n'
    '.pdx-sprite .mon-img, .evo-sprite .mon-img{ flex:0 0 auto; }\n'
    '#detailSprite .mon-img{ width:1em; height:1em; }\n'
    '</style>',
    '見た目をそろえるCSS',
))


def die(msg):
    print('### 中止: ' + msg)
    sys.exit(1)


with open(SRC, encoding='utf-8', newline='') as f:
    src_before = f.read()

a = src_before.find("app.get('/',")
b = src_before.find("app.get('/logout'")
if a < 0 or b < 0 or b <= a:
    die('src/index.tsx の目印が見つからない')
chain = src_before.count('.replace(', a, b)
if chain != CHAIN_BEFORE:
    die('チェーン数が ' + str(chain) + ' 件。' + str(CHAIN_BEFORE) + ' 件のはず。')
print('チェーン数 ' + str(chain) + ' 件を確認')

with open(PUB, encoding='utf-8', newline='') as f:
    html = f.read()

if 'MON_IMG_V1' not in html:
    die('第1便の受け皿(MON_IMG_V1)が入っていない。先に第1便を流すこと。')
if 'MON_DEX_V1' in html:
    die('MON_DEX_V1 がすでに入っている。二重に入れない。')

for old, new, label in PAIRS:
    n = html.count(old)
    if n != 1:
        die('あて先「' + label + '」が ' + str(n) + ' 件。1件のはず。')

before_len = len(html)
for old, new, label in PAIRS:
    html = html.replace(old, new, 1)
    print('差し替えた: ' + label)

if html.count('MON_DEX_V1') != 5:
    die('入れた印が ' + str(html.count('MON_DEX_V1')) + ' 個。5個のはず。')

with open(PUB, 'w', encoding='utf-8', newline='') as f:
    f.write(html)

print('public/index.html: ' + str(before_len) + ' -> ' + str(len(html)) + ' 文字')

with open(SRC, encoding='utf-8', newline='') as f:
    src_after = f.read()
if src_after != src_before:
    die('src/index.tsx が変わってしまった')

print('src/index.tsx は無変更。チェーン ' + str(CHAIN_BEFORE) + ' -> ' + str(CHAIN_BEFORE))
print('OK: 図鑑だけ差し替えた。絵が1枚も無いうちは 今までどおり絵文字が出る。')
