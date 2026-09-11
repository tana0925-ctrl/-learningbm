# -*- coding: utf-8 -*-
# DEF_STAGE_V1（第1便）
#   1) GET /api/defense/status の返り値に stage を足す（読み取りだけ。status は書き込みゼロのまま）
#   2) 子どもの敵一覧の見出しを「ステージN ／ てき Nたい」にする（.replace チェーン 72 -> 73）
# 敵の強さも報酬も変えない（第2便・第3便でやる）。
# アンカーが一致しなければ何も書かずに止まる（fail-closed）。
import io
import sys

PATH = 'src/index.tsx'
HTML = 'public/index.html'
SENTINEL = '__DEFSTAGE_SENTINEL_V1__'

A_ROOT   = "app.get('/', async (c) => {"
A_LOGOUT = "app.get('/logout'"
A_OUT    = 'my_reward: null }'
A_DEC    = '\n  out.decided = decided'
A_CHAIN  = 't = t.replace(SUDDEN_OLD, SUDDEN_NEW)'

UI_OLD = "\U0001F47E 敵軍団（'+d.enemy_squad.length+'体）"
UI_NEW = "\U0001F47E ステージ'+(d.stage||1)+' ／ てき '+d.enemy_squad.length+'たい"

s = io.open(PATH, encoding='utf-8').read()

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。何も書かない。')
    sys.exit(0)


def need(label, text, hay, want):
    n = hay.count(text)
    if n != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, n, want))
        sys.exit(1)


need('root', A_ROOT, s, 1)
need('logout', A_LOGOUT, s, 1)
need('out-literal', A_OUT, s, 1)
need('out.decided', A_DEC, s, 1)
need('chain-head', A_CHAIN, s, 1)

i = s.index(A_ROOT)
j = s.index(A_LOGOUT, i)
before = s[i:j].count('.replace(')
print('chain before =', before)
if before != 72:
    print('NG: 流す前のチェーンが 72 件でない')
    sys.exit(1)

h = io.open(HTML, encoding='utf-8').read()
need('ui-heading(public/index.html)', UI_OLD, h, 1)
if UI_NEW in h:
    print('NG: 置換後の見出しがすでに public/index.html にある')
    sys.exit(1)

# 1) status の返り値に stage の既定値を足す（行が無ければ 1）
s = s.replace(A_OUT, 'my_reward: null, stage: 1 }', 1)

# 2) クラスのステージを読むだけ。INSERT はしない（status は書き込みゼロのまま）
DEC_NEW = (
    '\n  // DEF_STAGE_V1 ' + SENTINEL + ' 読むだけ。行が無ければ stage=1。status では絶対に書き込まない\n'
    '  try {\n'
    '    const sgRow: any = await c.env.DB.prepare("SELECT stage FROM defense_stage WHERE class_id = ? LIMIT 1").bind(classId).first()\n'
    '    const sgN = Number(sgRow && sgRow.stage)\n'
    '    if (Number.isFinite(sgN) && sgN >= 1) out.stage = Math.floor(sgN)\n'
    '  } catch (e) { /* テーブルが読めなくても stage=1 のまま返す */ }\n'
    '  out.decided = decided'
)
s = s.replace(A_DEC, DEC_NEW, 1)

# 3) 見出しの置換をチェーンの先頭に足す（72 -> 73）
CHAIN_NEW = 't = t.replace("' + UI_OLD + '", "' + UI_NEW + '").replace(SUDDEN_OLD, SUDDEN_NEW)'
s = s.replace(A_CHAIN, CHAIN_NEW, 1)

i = s.index(A_ROOT)
j = s.index(A_LOGOUT, i)
after = s[i:j].count('.replace(')
print('chain after =', after)
if after != 73:
    print('NG: 適用後のチェーンが 73 件でない')
    sys.exit(1)
if s.count(SENTINEL) != 1:
    print('NG: 番兵が 1 件でない')
    sys.exit(1)
if 'INSERT INTO defense_stage' in s or 'UPDATE defense_stage' in s:
    print('NG: status 側に書き込みが入っている')
    sys.exit(1)

io.open(PATH, 'w', encoding='utf-8').write(s)
print('OK: DEF_STAGE_V1 を適用した（チェーン %d -> %d）' % (before, after))
