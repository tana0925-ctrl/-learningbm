# -*- coding: utf-8 -*-
# DEFBOSS_V1（防衛戦にボス4体：12 / 15 / 18 / 21 段）
#   1) その段だけ、8体目の まおう を ボスの顔に 入れかえる。体数は 8体のまま 増やさない。
#      さわるのは 名前・すがた と HP だけ。atk / def / spd / skillPow は 段の式のまま。
#      12 / 15 / 18 は その段の HP の 1.3倍。21 は 1.0（据え置き）。
#   2) たおしたときの ごほうびは、既存の DEFSTAGE_BONUS_MONSTERS に 4行 足すだけ。
#      台帳も 配る しくみも 既存のまま（初クリアの1回だけ・クラス全員）。
#   3) キャラの 名前・すがた・つよさは public/defboss_monsters.js（別コミットで先に置く）。
#      public/index.html は手で編集しない。読みこむ1行を replace チェーンに足し、
#      配る道（app.get）を1本 足す。足さないと 404 になる。
# アンカーが一致しなければ何も書かずに止まる（fail-closed）。
import io
import os
import sys

SRC = 'src/index.tsx'
JS = 'public/defboss_monsters.js'
SENTINEL = '__DEFBOSS_V1__'
CHAIN_BEFORE = 88
CHAIN_AFTER = 89


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def need(label, text, s, want):
    got = s.count(text)
    if got != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, got, want))
        sys.exit(1)


# ---------------- アンカー（いまの本文）と 入れかえ後の本文 ----------------

A_MON = """const DEFSTAGE_BONUS_MONSTERS: any = {
  '3': { id: 1601, level: 20 },
  '5': { id: 1602, level: 30 },
  '7': { id: 1604, level: 40 },
  '10': { id: 1605, level: 50 }
}"""

N_MON = """const DEFSTAGE_BONUS_MONSTERS: any = {
  '3': { id: 1601, level: 20 },
  '5': { id: 1602, level: 30 },
  '7': { id: 1604, level: 40 },
  '10': { id: 1605, level: 50 },
  // 👹 __DEFBOSS_V1__ ボスを たおした 段の ごほうび。配る しくみは 上の 4体と まったく同じ。
  //    初クリアの1回だけ・そのクラスに在籍している全員・台帳ごしに 1体ずつ。
  '12': { id: 1611, level: 55 },
  '15': { id: 1612, level: 60 },
  '18': { id: 1613, level: 65 },
  '21': { id: 1614, level: 70 }
}"""

A_FOE = r"""  { name: 'まおう',       sprite: '\u{1F608}', hp: 520, atk: 60, def: 24, buff: 'guard', skillPow: 12 },
]
const DEFENSE_WIN_COINS = 20"""

N_FOE = r"""  { name: 'まおう',       sprite: '\u{1F608}', hp: 520, atk: 60, def: 24, buff: 'guard', skillPow: 12 },
]
// 👹 __DEFBOSS_V1__ 防衛戦のボス。12 / 15 / 18 / 21 の段だけ、8体目の まおう を ボスに 入れかえる。
//   体数は 8体のまま 増やさない（エンジンは 毎tick 全員×全員を 見るので 体数は CPU に 二乗で 効く）。
//   さわるのは 名前・すがた と HP だけ。atk / def / spd / skillPow は 段の式（def_stage.ts）の まま。
//   12 / 15 / 18 は その段の HP の 1.3倍。21 は 1.0（最後の1段は そこに 立てること じたいが 達成）。
//   DEFENSE_ENEMIES は 1文字も 書きかえない。かならず コピーを 返す。
const DEFBOSS_FACE: any = {
  '12': { name: 'モンヤブリ', sprite: '\u{1FA93}', hpMul: 1.3 },
  '15': { name: 'カゲハヤテ', sprite: '\u{1F32A}\u{FE0F}', hpMul: 1.3 },
  '18': { name: 'イワヨロイ', sprite: '\u{1F5FF}', hpMul: 1.3 },
  '21': { name: 'ヨルオウガ', sprite: '\u{1F311}', hpMul: 1 }
}
function defBossApply(squad: any, stage: any): any {
  try {
    if (!Array.isArray(squad) || !squad.length) return squad
    const n = Math.floor(Number(stage))
    if (!Number.isFinite(n)) return squad
    const b = DEFBOSS_FACE[String(n)]
    if (!b) return squad
    const out = squad.slice()
    const last = out[out.length - 1]
    if (!last) return squad
    const o: any = {}
    for (const p in last) o[p] = last[p]
    o.name = String(b.name)
    o.sprite = String(b.sprite)
    const mul = Number(b.hpMul) || 1
    const hp = Math.round(Number(last.hp || 0) * mul)
    o.hp = (Number.isFinite(hp) && hp > 0) ? hp : Math.floor(Number(last.hp || 0))
    o.boss = true
    out[out.length - 1] = o
    return out
  } catch (_e) { return squad }
}
const DEFENSE_WIN_COINS = 20"""

A_ST = "out.enemy_squad = defStageEnemies(DEFENSE_ENEMIES, out.stage, await defEntryCount(c.env, st.eventKey, classId))"
N_ST = "out.enemy_squad = defBossApply(defStageEnemies(DEFENSE_ENEMIES, out.stage, await defEntryCount(c.env, st.eventKey, classId)), out.stage)"

A_DR = "const _drEnemies = defStageEnemies(DEFENSE_ENEMIES, _drStage, _drList.length)"
N_DR = "const _drEnemies = defBossApply(defStageEnemies(DEFENSE_ENEMIES, _drStage, _drList.length), _drStage)"

A_RS = "const _srv = await defServerResolve(c.env, st, classId, defStageEnemies(DEFENSE_ENEMIES, _dsStage, await defEntryCount(c.env, st.eventKey, classId)))"
N_RS = "const _srv = await defServerResolve(c.env, st, classId, defBossApply(defStageEnemies(DEFENSE_ENEMIES, _dsStage, await defEntryCount(c.env, st.eventKey, classId)), _dsStage))"

A_ROUTE = "app.get('/defstage_monsters.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/defstage_monsters.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })"

N_ROUTE = A_ROUTE + """
// 👹 __DEFBOSS_V1__ ボスのキャラ定義ファイルを配る道。上の1本と まったく同じ形。
app.get('/defboss_monsters.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/defboss_monsters.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })"""

A_CHAIN = """      t = t.replace('</body>', '<script src="/defstage_monsters.js?v=1"></script></body>')"""

N_CHAIN = A_CHAIN + """
      // 👹 __DEFBOSS_V1__ 防衛戦のボス4体の 名前・すがた・つよさ。中身は public/defboss_monsters.js。
      t = t.replace('</body>', '<script src="/defboss_monsters.js?v=1"></script></body>')"""


# ---------------- 適用前チェック（ここで止まればファイルに触れない） ----------------

s = io.open(SRC, encoding='utf-8').read()
before = chain_count(s)

if '--look' in sys.argv:
    print('chain =', before, '（期待 %d）' % CHAIN_BEFORE)
    print('番兵 =', s.count(SENTINEL), '（0 なら まだ 適用していない）')
    print('キャラ定義ファイル =', os.path.exists(JS))
    for _label, _text in (
        ('ごほうびの表', A_MON), ('てきの素の おわり', A_FOE), ('status の てき', A_ST),
        ('空打ちの てき', A_DR), ('サーバ計算の てき', A_RS),
        ('defstage_monsters を配る道', A_ROUTE), ('defstage_monsters を読む1行', A_CHAIN),
    ):
        print('アンカー %s = %d 件' % (_label, s.count(_text)))
    for _id in ('1611', '1612', '1613', '1614'):
        print('ID %s の すでにある数 = %d' % (_id, s.count(_id)))
    sys.exit(0)

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。何も書かない。chain =', before)
    sys.exit(0)

if not os.path.exists(JS):
    print('NG: %s が無い。キャラ定義ファイルを先に置いてから流す。' % JS)
    sys.exit(1)

j = io.open(JS, encoding='utf-8').read()
for _id in ('1611', '1612', '1613', '1614'):
    if ('id: ' + _id) not in j:
        print('NG: %s に id: %s が無い' % (JS, _id))
        sys.exit(1)
if '__DEFBOSS_V1' not in j:
    print('NG: %s に 投入数を のこす しるしが 無い' % JS)
    sys.exit(1)

if before != CHAIN_BEFORE:
    print('NG: 流す前のチェーンが %d 件（期待 %d）' % (before, CHAIN_BEFORE))
    sys.exit(1)

need('ごほうびの表', A_MON, s, 1)
need('てきの素の おわり', A_FOE, s, 1)
need('status の てき', A_ST, s, 1)
need('空打ちの てき', A_DR, s, 1)
need('サーバ計算の てき', A_RS, s, 1)
need('defstage_monsters を配る道', A_ROUTE, s, 1)
need('defstage_monsters を読む1行', A_CHAIN, s, 1)
need('defboss がまだ無いこと', 'defboss', s, 0)
need('1611 がまだ無いこと', '1611', s, 0)
need('1612 がまだ無いこと', '1612', s, 0)
need('1613 がまだ無いこと', '1613', s, 0)
need('1614 がまだ無いこと', '1614', s, 0)

# ---------------- 入れかえ（各1件ずつ） ----------------

s = s.replace(A_MON, N_MON, 1)
s = s.replace(A_FOE, N_FOE, 1)
s = s.replace(A_ST, N_ST, 1)
s = s.replace(A_DR, N_DR, 1)
s = s.replace(A_RS, N_RS, 1)
s = s.replace(A_ROUTE, N_ROUTE, 1)
s = s.replace(A_CHAIN, N_CHAIN, 1)

after = chain_count(s)
ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


# --- 増えたのは自分の1件だけ ---
chk('チェーン', after, CHAIN_AFTER)
chk('増えた件数', after - before, 1)
chk('番兵', s.count(SENTINEL), 4)
chk('読みこむ1行', s.count('<script src="/defboss_monsters.js?v=1"></script>'), 1)
chk('配る道', s.count("app.get('/defboss_monsters.js'"), 1)
chk('defBossApply の定義と呼び出し', s.count('defBossApply('), 4)
chk('ボスの表', s.count('DEFBOSS_FACE'), 2)

# --- ボスの中身 ---
chk('モンヤブリ', s.count('モンヤブリ'), 1)
chk('カゲハヤテ', s.count('カゲハヤテ'), 1)
chk('イワヨロイ', s.count('イワヨロイ'), 1)
chk('ヨルオウガ', s.count('ヨルオウガ'), 1)
chk('ID 1611', s.count('1611'), 1)
chk('ID 1612', s.count('1612'), 1)
chk('ID 1613', s.count('1613'), 1)
chk('ID 1614', s.count('1614'), 1)
chk('HP 1.3倍が 3件', s.count('hpMul: 1.3'), 3)
chk('21段は 据え置き', s.count('hpMul: 1 }'), 1)
chk('まおう の素', s.count("{ name: 'まおう',"), 1)
chk('てきの素は 8体のまま', s.count("\n  { name: '"), 8)

# --- 壊してはいけないもの（src） ---
chk('__DEFSTAGE_BONUS_V1__', s.count('__DEFSTAGE_BONUS_V1__'), 7)
chk('__DEFSTAGE_SENTINEL_V1__', s.count('__DEFSTAGE_SENTINEL_V1__'), 1)
chk('__DEF_SNAP_SPDSKILLS_V1__', s.count('__DEF_SNAP_SPDSKILLS_V1__'), 1)
chk('__DEF_RESOLVE_VERIFY_V1__', s.count('__DEF_RESOLVE_VERIFY_V1__'), 1)
chk('log の v===2 条件', s.count('Number(_dvLog.v) === 2'), 1)
chk('baseHpA の有限数条件', s.count('Number.isFinite(Number(_dvRep.baseHpA))'), 1)
chk('retry true', s.count('retry: true'), 2)
chk('log の 900000 上限', s.count('900000'), 1)
chk('__DEF_MVP_V1__', s.count('__DEF_MVP_V1__'), 6)
chk('defMvpMakeLedger', s.count('defMvpMakeLedger'), 2)
chk('_defMvpCoinsApplied', s.count('_defMvpCoinsApplied'), 8)
chk('_defStageCoinsApplied', s.count('_defStageCoinsApplied'), 8)
chk('defStageMakeLedger', s.count('defStageMakeLedger'), 3)
chk('applyDefStageGrants', s.count('applyDefStageGrants'), 2)
chk('defEntryOk', s.count('defEntryOk'), 4)
chk('defNorm', s.count('defNorm'), 2)
chk('needs_reselect', s.count('needs_reselect'), 3)
chk('foeLaneMix', s.count('foeLaneMix'), 2)
chk('defense_standing', s.count('defense_standing'), 4)
chk('defense_carry_lock', s.count('defense_carry_lock'), 1)
chk('defAutoAdvanceV1', s.count('defAutoAdvanceV1'), 3)
chk('DEF_LV50_V1', s.count('DEF_LV50_V1'), 2)
chk('DEF_LV50_V2', s.count('DEF_LV50_V2'), 2)
chk('DEF2_LV50_SAME_V1', s.count('DEF2_LV50_SAME_V1'), 1)
chk('DEF2_LV50_ENTRYFIX_V1', s.count('DEF2_LV50_ENTRYFIX_V1'), 1)
chk('__S6WORLD_50__', s.count('__S6WORLD_50__'), 1)
chk('__H6MERGE_SRC_V1__', s.count('__H6MERGE_SRC_V1__'), 1)
chk('__H6BANK_LIVE_V1__', s.count('__H6BANK_LIVE_V1__'), 1)
chk('__H6U11_BOOST_V1__', s.count('__H6U11_BOOST_V1__'), 1)
chk('HS_NEXT_RECALL_V1', s.count('HS_NEXT_RECALL_V1'), 2)
chk('def_join_nudge.js', s.count('def_join_nudge.js'), 5)
chk('defstage_monsters', s.count('defstage_monsters'), 4)
chk('ensureDefenseTables() の呼び出し', s.count('ensureDefenseTables()'), 0)
chk('基地HP 380', s.count('DEFENSE_BASE_HP = 380'), 1)
chk('勝利コイン 20', s.count('DEFENSE_WIN_COINS = 20'), 1)
chk('defStageEnemies の呼び出し', s.count('defStageEnemies('), 3)
chk('ステージ前進の書きこみ', s.count('UPDATE defense_stage SET stage = stage + 1'), 2)
chk('降格の書きこみ', s.count('UPDATE defense_stage SET stage - 1'), 0)
chk('降格の式', s.count('stage - 1'), 0)
chk('台帳の予約', s.count("UPDATE defense_stage_rewards SET applied_at = datetime('now')"), 1)
chk('台帳の解放', s.count('UPDATE defense_stage_rewards SET applied_at = NULL'), 1)
chk('ごほうびの表', s.count('DEFSTAGE_BONUS_MONSTERS'), 5)

# --- 空打ちは 書きこみゼロ ---
_a = s.index("app.get('/api/teacher/defense/dry-run'")
_b = s.index("app.post('/api/defense/resolve'", _a)
_blk = s[_a:_b]
for _w in ('INSERT', 'UPDATE', 'DELETE', '.run()', '.batch('):
    if _w in _blk:
        print('NG: 空打ちに 書きこみ %s が 入っている' % _w)
        ok[0] = False

# --- ジムチャレンジ側の エンジンは さわっていない ---
if 'def_engine' not in s:
    print('NG: def_engine の import が 消えている')
    ok[0] = False

if not ok[0]:
    print('検証に落ちたので何も書かない')
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('OK: 適用した。chain =', before, '->', after)
# -*- coding: utf-8 -*-
# DEFBOSS_V1（防衛戦にボス4体：12 / 15 / 18 / 21 段）
#   1) その段だけ、8体目の まおう を ボスの顔に 入れかえる。体数は 8体のまま 増やさない。
#      さわるのは 名前・すがた と HP だけ。atk / def / spd / skillPow は 段の式のまま。
#      12 / 15 / 18 は その段の HP の 1.3倍。21 は 1.0（据え置き）。
#   2) たおしたときの ごほうびは、既存の DEFSTAGE_BONUS_MONSTERS に 4行 足すだけ。
#      台帳も 配る しくみも 既存のまま（初クリアの1回だけ・クラス全員）。
#   3) キャラの 名前・すがた・つよさは public/defboss_monsters.js（別コミットで先に置く）。
#      public/index.html は手で編集しない。読みこむ1行を replace チェーンに足し、
#      配る道（app.get）を1本 足す。足さないと 404 になる。
# アンカーが一致しなければ何も書かずに止まる（fail-closed）。
import io
import os
import sys

SRC = 'src/index.tsx'
JS = 'public/defboss_monsters.js'
SENTINEL = '__DEFBOSS_V1__'
CHAIN_BEFORE = 88
CHAIN_AFTER = 89


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def need(label, text, s, want):
    got = s.count(text)
    if got != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, got, want))
        sys.exit(1)


# ---------------- アンカー（いまの本文）と 入れかえ後の本文 ----------------

A_MON = """const DEFSTAGE_BONUS_MONSTERS: any = {
  '3': { id: 1601, level: 20 },
  '5': { id: 1602, level: 30 },
  '7': { id: 1604, level: 40 },
  '10': { id: 1605, level: 50 }
}"""

N_MON = """const DEFSTAGE_BONUS_MONSTERS: any = {
  '3': { id: 1601, level: 20 },
  '5': { id: 1602, level: 30 },
  '7': { id: 1604, level: 40 },
  '10': { id: 1605, level: 50 },
  // \U0001F479 __DEFBOSS_V1__ ボスを たおした 段の ごほうび。配る しくみは 上の 4体と まったく同じ。
  //    初クリアの1回だけ・そのクラスに在籍している全員・台帳ごしに 1体ずつ。
  '12': { id: 1611, level: 55 },
  '15': { id: 1612, level: 60 },
  '18': { id: 1613, level: 65 },
  '21': { id: 1614, level: 70 }
}"""

A_FOE = """  { name: 'まおう',       sprite: '\u{1F608}', hp: 520, atk: 60, def: 24, buff: 'guard', skillPow: 12 },
]
const DEFENSE_WIN_COINS = 20"""

N_FOE = """  { name: 'まおう',       sprite: '\u{1F608}', hp: 520, atk: 60, def: 24, buff: 'guard', skillPow: 12 },
]
// \U0001F479 __DEFBOSS_V1__ 防衛戦のボス。12 / 15 / 18 / 21 の段だけ、8体目の まおう を ボスに 入れかえる。
//   体数は 8体のまま 増やさない（エンジンは 毎tick 全員×全員を 見るので 体数は CPU に 二乗で 効く）。
//   さわるのは 名前・すがた と HP だけ。atk / def / spd / skillPow は 段の式（def_stage.ts）の まま。
//   12 / 15 / 18 は その段の HP の 1.3倍。21 は 1.0（最後の1段は そこに 立てること じたいが 達成）。
//   DEFENSE_ENEMIES は 1文字も 書きかえない。かならず コピーを 返す。
const DEFBOSS_FACE: any = {
  '12': { name: 'モンヤブリ', sprite: '\u{1FA93}', hpMul: 1.3 },
  '15': { name: 'カゲハヤテ', sprite: '\u{1F32A}\u{FE0F}', hpMul: 1.3 },
  '18': { name: 'イワヨロイ', sprite: '\u{1F5FF}', hpMul: 1.3 },
  '21': { name: 'ヨルオウガ', sprite: '\u{1F311}', hpMul: 1 }
}
function defBossApply(squad: any, stage: any): any {
  try {
    if (!Array.isArray(squad) || !squad.length) return squad
    const n = Math.floor(Number(stage))
    if (!Number.isFinite(n)) return squad
    const b = DEFBOSS_FACE[String(n)]
    if (!b) return squad
    const out = squad.slice()
    const last = out[out.length - 1]
    if (!last) return squad
    const o: any = {}
    for (const p in last) o[p] = last[p]
    o.name = String(b.name)
    o.sprite = String(b.sprite)
    const mul = Number(b.hpMul) || 1
    const hp = Math.round(Number(last.hp || 0) * mul)
    o.hp = (Number.isFinite(hp) && hp > 0) ? hp : Math.floor(Number(last.hp || 0))
    o.boss = true
    out[out.length - 1] = o
    return out
  } catch (_e) { return squad }
}
const DEFENSE_WIN_COINS = 20"""

A_ST = "out.enemy_squad = defStageEnemies(DEFENSE_ENEMIES, out.stage, await defEntryCount(c.env, st.eventKey, classId))"
N_ST = "out.enemy_squad = defBossApply(defStageEnemies(DEFENSE_ENEMIES, out.stage, await defEntryCount(c.env, st.eventKey, classId)), out.stage)"

A_DR = "const _drEnemies = defStageEnemies(DEFENSE_ENEMIES, _drStage, _drList.length)"
N_DR = "const _drEnemies = defBossApply(defStageEnemies(DEFENSE_ENEMIES, _drStage, _drList.length), _drStage)"

A_RS = "const _srv = await defServerResolve(c.env, st, classId, defStageEnemies(DEFENSE_ENEMIES, _dsStage, await defEntryCount(c.env, st.eventKey, classId)))"
N_RS = "const _srv = await defServerResolve(c.env, st, classId, defBossApply(defStageEnemies(DEFENSE_ENEMIES, _dsStage, await defEntryCount(c.env, st.eventKey, classId)), _dsStage))"

A_ROUTE = "app.get('/defstage_monsters.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/defstage_monsters.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })"

N_ROUTE = A_ROUTE + """
// \U0001F479 __DEFBOSS_V1__ ボスのキャラ定義ファイルを配る道。上の1本と まったく同じ形。
app.get('/defboss_monsters.js', async (c) => { try { const a = await c.env.ASSETS?.fetch(new Request(new URL('https://assets/defboss_monsters.js'))); if (a && a.status === 200) return new Response(await a.text(), { headers: { 'content-type': 'application/javascript; charset=utf-8', 'cache-control': 'public, max-age=300' } }); } catch (e) {} return c.text('not found', 404) })"""

A_CHAIN = """      t = t.replace('</body>', '<script src="/defstage_monsters.js?v=1"></script></body>')"""

N_CHAIN = A_CHAIN + """
      // \U0001F479 __DEFBOSS_V1__ 防衛戦のボス4体の 名前・すがた・つよさ。中身は public/defboss_monsters.js。
      t = t.replace('</body>', '<script src="/defboss_monsters.js?v=1"></script></body>')"""


# ---------------- 適用前チェック（ここで止まればファイルに触れない） ----------------

s = io.open(SRC, encoding='utf-8').read()
before = chain_count(s)

if '--look' in sys.argv:
    print('chain =', before, '（期待 %d）' % CHAIN_BEFORE)
    print('番兵 =', s.count(SENTINEL), '（0 なら まだ 適用していない）')
    print('キャラ定義ファイル =', os.path.exists(JS))
    for _label, _text in (
        ('ごほうびの表', A_MON), ('てきの素の おわり', A_FOE), ('status の てき', A_ST),
        ('空打ちの てき', A_DR), ('サーバ計算の てき', A_RS),
        ('defstage_monsters を配る道', A_ROUTE), ('defstage_monsters を読む1行', A_CHAIN),
    ):
        print('アンカー %s = %d 件' % (_label, s.count(_text)))
    for _id in ('1611', '1612', '1613', '1614'):
        print('ID %s の すでにある数 = %d' % (_id, s.count(_id)))
    sys.exit(0)

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。何も書かない。chain =', before)
    sys.exit(0)

if not os.path.exists(JS):
    print('NG: %s が無い。キャラ定義ファイルを先に置いてから流す。' % JS)
    sys.exit(1)

j = io.open(JS, encoding='utf-8').read()
for _id in ('1611', '1612', '1613', '1614'):
    if ('id: ' + _id) not in j:
        print('NG: %s に id: %s が無い' % (JS, _id))
        sys.exit(1)
if '__DEFBOSS_V1' not in j:
    print('NG: %s に 投入数を のこす しるしが 無い' % JS)
    sys.exit(1)

if before != CHAIN_BEFORE:
    print('NG: 流す前のチェーンが %d 件（期待 %d）' % (before, CHAIN_BEFORE))
    sys.exit(1)

need('ごほうびの表', A_MON, s, 1)
need('てきの素の おわり', A_FOE, s, 1)
need('status の てき', A_ST, s, 1)
need('空打ちの てき', A_DR, s, 1)
need('サーバ計算の てき', A_RS, s, 1)
need('defstage_monsters を配る道', A_ROUTE, s, 1)
need('defstage_monsters を読む1行', A_CHAIN, s, 1)
need('defboss がまだ無いこと', 'defboss', s, 0)
need('1611 がまだ無いこと', '1611', s, 0)
need('1612 がまだ無いこと', '1612', s, 0)
need('1613 がまだ無いこと', '1613', s, 0)
need('1614 がまだ無いこと', '1614', s, 0)

# ---------------- 入れかえ（各1件ずつ） ----------------

s = s.replace(A_MON, N_MON, 1)
s = s.replace(A_FOE, N_FOE, 1)
s = s.replace(A_ST, N_ST, 1)
s = s.replace(A_DR, N_DR, 1)
s = s.replace(A_RS, N_RS, 1)
s = s.replace(A_ROUTE, N_ROUTE, 1)
s = s.replace(A_CHAIN, N_CHAIN, 1)

after = chain_count(s)
ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


# --- 増えたのは自分の1件だけ ---
chk('チェーン', after, CHAIN_AFTER)
chk('増えた件数', after - before, 1)
chk('番兵', s.count(SENTINEL), 4)
chk('読みこむ1行', s.count('<script src="/defboss_monsters.js?v=1"></script>'), 1)
chk('配る道', s.count("app.get('/defboss_monsters.js'"), 1)
chk('defBossApply の定義と呼び出し', s.count('defBossApply('), 4)
chk('ボスの表', s.count('DEFBOSS_FACE'), 2)

# --- ボスの中身 ---
chk('モンヤブリ', s.count('モンヤブリ'), 1)
chk('カゲハヤテ', s.count('カゲハヤテ'), 1)
chk('イワヨロイ', s.count('イワヨロイ'), 1)
chk('ヨルオウガ', s.count('ヨルオウガ'), 1)
chk('ID 1611', s.count('1611'), 1)
chk('ID 1612', s.count('1612'), 1)
chk('ID 1613', s.count('1613'), 1)
chk('ID 1614', s.count('1614'), 1)
chk('HP 1.3倍が 3件', s.count('hpMul: 1.3'), 3)
chk('21段は 据え置き', s.count('hpMul: 1 }'), 1)
chk('まおう の素', s.count("{ name: 'まおう',"), 1)
chk('てきの素は 8体のまま', s.count("\n  { name: '"), 8)

# --- 壊してはいけないもの（src） ---
chk('__DEFSTAGE_BONUS_V1__', s.count('__DEFSTAGE_BONUS_V1__'), 7)
chk('__DEFSTAGE_SENTINEL_V1__', s.count('__DEFSTAGE_SENTINEL_V1__'), 1)
chk('__DEF_SNAP_SPDSKILLS_V1__', s.count('__DEF_SNAP_SPDSKILLS_V1__'), 1)
chk('__DEF_RESOLVE_VERIFY_V1__', s.count('__DEF_RESOLVE_VERIFY_V1__'), 1)
chk('log の v===2 条件', s.count('Number(_dvLog.v) === 2'), 1)
chk('baseHpA の有限数条件', s.count('Number.isFinite(Number(_dvRep.baseHpA))'), 1)
chk('retry true', s.count('retry: true'), 2)
chk('log の 900000 上限', s.count('900000'), 1)
chk('__DEF_MVP_V1__', s.count('__DEF_MVP_V1__'), 6)
chk('defMvpMakeLedger', s.count('defMvpMakeLedger'), 2)
chk('_defMvpCoinsApplied', s.count('_defMvpCoinsApplied'), 8)
chk('_defStageCoinsApplied', s.count('_defStageCoinsApplied'), 8)
chk('defStageMakeLedger', s.count('defStageMakeLedger'), 3)
chk('applyDefStageGrants', s.count('applyDefStageGrants'), 2)
chk('defEntryOk', s.count('defEntryOk'), 4)
chk('defNorm', s.count('defNorm'), 2)
chk('needs_reselect', s.count('needs_reselect'), 3)
chk('foeLaneMix', s.count('foeLaneMix'), 2)
chk('defense_standing', s.count('defense_standing'), 4)
chk('defense_carry_lock', s.count('defense_carry_lock'), 1)
chk('defAutoAdvanceV1', s.count('defAutoAdvanceV1'), 3)
chk('DEF_LV50_V1', s.count('DEF_LV50_V1'), 2)
chk('DEF_LV50_V2', s.count('DEF_LV50_V2'), 2)
chk('DEF2_LV50_SAME_V1', s.count('DEF2_LV50_SAME_V1'), 1)
chk('DEF2_LV50_ENTRYFIX_V1', s.count('DEF2_LV50_ENTRYFIX_V1'), 1)
chk('__S6WORLD_50__', s.count('__S6WORLD_50__'), 1)
chk('__H6MERGE_SRC_V1__', s.count('__H6MERGE_SRC_V1__'), 1)
chk('__H6BANK_LIVE_V1__', s.count('__H6BANK_LIVE_V1__'), 1)
chk('__H6U11_BOOST_V1__', s.count('__H6U11_BOOST_V1__'), 1)
chk('HS_NEXT_RECALL_V1', s.count('HS_NEXT_RECALL_V1'), 2)
chk('def_join_nudge.js', s.count('def_join_nudge.js'), 5)
chk('defstage_monsters', s.count('defstage_monsters'), 4)
chk('ensureDefenseTables() の呼び出し', s.count('ensureDefenseTables()'), 0)
chk('基地HP 380', s.count('DEFENSE_BASE_HP = 380'), 1)
chk('勝利コイン 20', s.count('DEFENSE_WIN_COINS = 20'), 1)
chk('defStageEnemies の呼び出し', s.count('defStageEnemies('), 3)
chk('ステージ前進の書きこみ', s.count('UPDATE defense_stage SET stage = stage + 1'), 2)
chk('降格の書きこみ', s.count('UPDATE defense_stage SET stage - 1'), 0)
chk('降格の式', s.count('stage - 1'), 0)
chk('台帳の予約', s.count("UPDATE defense_stage_rewards SET applied_at = datetime('now')"), 1)
chk('台帳の解放', s.count('UPDATE defense_stage_rewards SET applied_at = NULL'), 1)
chk('ごほうびの表', s.count('DEFSTAGE_BONUS_MONSTERS'), 5)

# --- 空打ちは 書きこみゼロ ---
_a = s.index("app.get('/api/teacher/defense/dry-run'")
_b = s.index("app.post('/api/defense/resolve'", _a)
_blk = s[_a:_b]
for _w in ('INSERT', 'UPDATE', 'DELETE', '.run()', '.batch('):
    if _w in _blk:
        print('NG: 空打ちに 書きこみ %s が 入っている' % _w)
        ok[0] = False

# --- ジムチャレンジ側の エンジンは さわっていない ---
if 'def_engine' not in s:
    print('NG: def_engine の import が 消えている')
    ok[0] = False

if not ok[0]:
    print('検証に落ちたので何も書かない')
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('OK: 適用した。chain =', before, '->', after)
