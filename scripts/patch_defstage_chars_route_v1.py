# -*- coding: utf-8 -*-
# DEFSTAGE_CHARS_ROUTE_V1（第3便・第2段の追い）
#   public/defstage_monsters.js を配信する道を1本足す。
#   このアプリは dist/_routes.json が include:["/*"] なので、
#   public/ に置いただけのファイルは Worker に吸われて 404 になる
#   （実際に本番で 404 を確認した）。defense2.js / student-karte.js と
#   まったく同じ形の app.get を1行足すだけ。
#   .replace チェーンは触らない（74 のまま）。
# アンカーが一致しなければ何も書かずに止まる（fail-closed）。
import io
import sys

PATH = 'src/index.tsx'
SENTINEL = '__DEFSTAGE_CHARS_ROUTE_V1__'
CHAIN_EXPECT = 74


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


A = '''app.get('/student-karte.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/student-karte.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })
'''

N = A + '''// __DEFSTAGE_CHARS_ROUTE_V1__ げんていキャラの定義ファイルを配る道。student-karte.js とまったく同じ形。
app.get('/defstage_monsters.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/defstage_monsters.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })
'''

s = io.open(PATH, encoding='utf-8').read()
before = chain_count(s)

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。何も書かない。chain =', before)
    sys.exit(0)

if before != CHAIN_EXPECT:
    print('NG: チェーンが %d 件（期待 %d）' % (before, CHAIN_EXPECT))
    sys.exit(1)

if s.count(A) != 1:
    print('NG: student-karte.js の道が %d 件（期待 1）' % s.count(A))
    sys.exit(1)

if s.count("app.get('/defstage_monsters.js'") != 0:
    print('NG: もう道がある')
    sys.exit(1)

if '<script src="/defstage_monsters.js?v=1"></script>' not in s:
    print('NG: 第2段（読み込みの1行）がまだ入っていない')
    sys.exit(1)

s = s.replace(A, N, 1)

after = chain_count(s)
ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


chk('チェーン', after, CHAIN_EXPECT)
chk('番兵', s.count(SENTINEL), 1)
chk('足した道', s.count("app.get('/defstage_monsters.js'"), 1)
chk('student-karte の道', s.count("app.get('/student-karte.js'"), 1)
chk('defense2 の道', s.count("app.get('/defense2.js'"), 1)
chk('読み込みの1行', s.count('<script src="/defstage_monsters.js?v=1"></script>'), 1)
chk('__DEFSTAGE_BONUS_V1__', s.count('__DEFSTAGE_BONUS_V1__'), 7)
chk('__DEFSTAGE_CHARS_V1__', s.count('__DEFSTAGE_CHARS_V1__'), 1)
chk('__DEFSTAGE_SENTINEL_V1__', s.count('__DEFSTAGE_SENTINEL_V1__'), 1)
chk('__DEF_SNAP_SPDSKILLS_V1__', s.count('__DEF_SNAP_SPDSKILLS_V1__'), 1)
chk('__DEF_RESOLVE_VERIFY_V1__', s.count('__DEF_RESOLVE_VERIFY_V1__'), 1)
chk('retry true', s.count('retry: true'), 2)
chk('log の 900000 上限', s.count('900000'), 1)
chk('defense_standing', s.count('defense_standing'), 4)
chk('defense_carry_lock', s.count('defense_carry_lock'), 1)
chk('defAutoAdvanceV1', s.count('defAutoAdvanceV1'), 3)
chk('ensureDefenseTables() の呼び出し', s.count('ensureDefenseTables()'), 0)
chk('基地HP 380', s.count('DEFENSE_BASE_HP = 380'), 1)
chk('勝利コイン 20', s.count('DEFENSE_WIN_COINS = 20'), 1)
chk('ステージ前進の UPDATE', s.count('UPDATE defense_stage SET stage = stage + 1'), 2)
chk('降格の経路', s.count('stage - 1'), 0)

_a = s.index("app.get('/api/teacher/defense/dry-run'")
_b = s.index("app.post('/api/defense/resolve'", _a)
for _w in ('INSERT', 'UPDATE', 'DELETE', '.run()', '.batch('):
    if _w in s[_a:_b]:
        print('NG: dry-run に書き込み %s が入っている' % _w)
        ok[0] = False

if not ok[0]:
    print('検証に落ちたので何も書かない')
    sys.exit(1)

io.open(PATH, 'w', encoding='utf-8').write(s)
print('OK: 道を1本足した。chain =', after, '（変化なし）')
