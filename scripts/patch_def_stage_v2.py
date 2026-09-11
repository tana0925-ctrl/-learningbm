# -*- coding: utf-8 -*-
# DEF_STAGE_V2（第2便）
#   1) src/def_stage.ts を作る（ステージ倍率の純関数だけ。敵の体数は増やさない）
#   2) status / dry-run / resolve の3箇所に、倍率をかけた敵配列を渡す
#   3) 勝ったときだけ defense_stage を 1つ進める（楽観ロック）。負けても下げない。
# 敵の定数 DEFENSE_ENEMIES（src/index.tsx）は書き換えない。ステージ1の素として残す。
# アンカーが一致しなければ何も書かずに止まる（fail-closed）。
import io
import sys

PATH = 'src/index.tsx'
STAGE_PATH = 'src/def_stage.ts'
SENTINEL = '__DEFSTAGE_V2_SENTINEL__'

STAGE_TS = '''
// DEF_STAGE_V2 ステージに応じて敵を強くする純関数だけを置くファイル。
// 敵の体数は絶対に増やさない（エンジンは毎tick全員×全員を見るので体数はCPUに二乗で効く）。
// ステージ1の素は src/index.tsx の DEFENSE_ENEMIES。ここでは受け取るだけで、元の配列には触らない。
// @ts-nocheck
/* eslint-disable */

export const DEF_STAGE_MAX = 10

// 1 〜 DEF_STAGE_MAX に丸める。壊れた値は 1 とみなす。
export function defStageClamp(stage) {
  const n = Math.floor(Number(stage))
  if (!Number.isFinite(n) || n < 1) return 1
  return n > DEF_STAGE_MAX ? DEF_STAGE_MAX : n
}

// base（ステージ1の素）のコピーに倍率をかけた新しい配列を返す。base は書き換えない。
//   hp  x (1 + 0.25 x (stage - 1))
//   atk x (1 + 0.12 x (stage - 1))
//   def + 2 x (stage - 1)
export function defStageEnemies(base, stage) {
  if (!Array.isArray(base)) return []
  const k = defStageClamp(stage) - 1
  return base.map(function (e) {
    const o = {}
    for (const p in e) o[p] = e[p]
    o.hp = Math.round(Number(e.hp || 0) * (1 + 0.25 * k))
    o.atk = Math.round(Number(e.atk || 0) * (1 + 0.12 * k))
    o.def = Number(e.def || 0) + 2 * k
    return o
  })
}

'''

A_IMPORT = "import { defServerResolve, defEntryOk } from './def_resolve'"

A_DEC = '''  } catch (e) { /* テーブルが読めなくても stage=1 のまま返す */ }
  out.decided = decided'''

A_DRY = '''  const _drRes = await defServerResolve(c.env, _drSt, _drCid, DEFENSE_ENEMIES)
'''

A_SRV = '''  const _srv = await defServerResolve(c.env, st, classId, DEFENSE_ENEMIES)
'''

A_SRVWIN = '''    if (_srv.result === 'win') {
      try {
        const _srvEs = await'''

A_CLIWIN = '''  if (result === 'win') {
    try {
      const es = await'''

N_DEC = '''  } catch (e) { /* テーブルが読めなくても stage=1 のまま返す */ }
  // DEF_STAGE_V2 __DEFSTAGE_V2_SENTINEL__ ステージに応じて敵を強くする。体数は8体のまま増やさない。
  out.enemy_squad = defStageEnemies(DEFENSE_ENEMIES, out.stage)
  out.decided = decided'''

N_DRY = '''  // DEF_STAGE_V2 dry-run にステージを足す（?stage=N で上書きできる）。ここでは何も書き込まない。
  let _drStage = 1
  try {
    const _drQ = Number(c.req.query('stage'))
    if (Number.isFinite(_drQ) && _drQ >= 1) {
      _drStage = Math.floor(_drQ)
    } else {
      const _drSg: any = await c.env.DB.prepare("SELECT stage FROM defense_stage WHERE class_id = ? LIMIT 1").bind(_drCid).first()
      const _drSgN = Number(_drSg && _drSg.stage)
      if (Number.isFinite(_drSgN) && _drSgN >= 1) _drStage = Math.floor(_drSgN)
    }
  } catch (_e) {}
  const _drEnemies = defStageEnemies(DEFENSE_ENEMIES, _drStage)
  _drOut.stage = _drStage
  _drOut.enemy_squad = _drEnemies
  const _drRes = await defServerResolve(c.env, _drSt, _drCid, _drEnemies)
'''

N_SRV = '''  // DEF_STAGE_V2 いまのステージを読む（行が無ければ 1）。この値を勝ったときの楽観ロックの条件に使う。
  let _dsStage = 1
  try {
    const _dsRow: any = await c.env.DB.prepare("SELECT stage FROM defense_stage WHERE class_id = ? LIMIT 1").bind(classId).first()
    const _dsN = Number(_dsRow && _dsRow.stage)
    if (Number.isFinite(_dsN) && _dsN >= 1) _dsStage = Math.floor(_dsN)
  } catch (_e) {}
  const _srv = await defServerResolve(c.env, st, classId, defStageEnemies(DEFENSE_ENEMIES, _dsStage))
'''

N_SRVWIN = '''    if (_srv.result === 'win') {
      // DEF_STAGE_V2 勝ったときだけ 1つ進める。読んだ値を条件に入れる（楽観ロック）。負けても下げない。
      try {
        await c.env.DB.prepare("INSERT OR IGNORE INTO defense_stage (class_id, stage, updated_at) VALUES (?, 1, datetime('now'))").bind(classId).run()
        await c.env.DB.prepare("UPDATE defense_stage SET stage = stage + 1, updated_at = datetime('now') WHERE class_id = ? AND stage = ?").bind(classId, _dsStage).run()
      } catch (_e) {}
      try {
        const _srvEs = await'''

N_CLIWIN = '''  if (result === 'win') {
    // DEF_STAGE_V2 勝ったときだけ 1つ進める。読んだ値を条件に入れる（楽観ロック）。負けても下げない。
    try {
      await c.env.DB.prepare("INSERT OR IGNORE INTO defense_stage (class_id, stage, updated_at) VALUES (?, 1, datetime('now'))").bind(classId).run()
      await c.env.DB.prepare("UPDATE defense_stage SET stage = stage + 1, updated_at = datetime('now') WHERE class_id = ? AND stage = ?").bind(classId, _dsStage).run()
    } catch (_e) {}
    try {
      const es = await'''


def need(label, text, hay, want):
    n = hay.count(text)
    if n != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, n, want))
        sys.exit(1)


def chain_count(text):
    i = text.index("app.get('/', async (c) => {")
    j = text.index("app.get('/logout'", i)
    return text[i:j].count('.replace(')


# 1) 純関数のファイルは毎回同じ中身を書く（冪等）
io.open(STAGE_PATH, 'w', encoding='utf-8').write(STAGE_TS.lstrip('\n'))

s = io.open(PATH, encoding='utf-8').read()
before = chain_count(s)

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。src/index.tsx には何も書かない。chain =', before)
    sys.exit(0)

if before != 73:
    print('NG: 流す前のチェーンが %d 件（期待 73）' % before)
    sys.exit(1)

need('import', A_IMPORT, s, 1)
need('status の catch', A_DEC, s, 1)
need('dry-run の resolve 呼び出し', A_DRY, s, 1)
need('resolve の呼び出し', A_SRV, s, 1)
need('サーバ経路の勝ち', A_SRVWIN, s, 1)
need('申告経路の勝ち', A_CLIWIN, s, 1)
need('敵の定数', 'const DEFENSE_ENEMIES = [', s, 1)
need('DEFENSE_ENEMIES の参照', 'DEFENSE_ENEMIES', s, 4)

s = s.replace(A_IMPORT, A_IMPORT + "\nimport { defStageEnemies } from './def_stage'", 1)
s = s.replace(A_DEC, N_DEC, 1)
s = s.replace(A_DRY, N_DRY, 1)
s = s.replace(A_SRV, N_SRV, 1)
s = s.replace(A_SRVWIN, N_SRVWIN, 1)
s = s.replace(A_CLIWIN, N_CLIWIN, 1)

after = chain_count(s)
ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


chk('チェーン', after, 73)
chk('番兵', s.count(SENTINEL), 1)
chk('defStageEnemies の呼び出し', s.count('defStageEnemies('), 3)
chk('DEFENSE_ENEMIES の参照', s.count('DEFENSE_ENEMIES'), 5)
chk('ステージ前進の UPDATE', s.count('UPDATE defense_stage SET stage = stage + 1'), 2)
chk('ステージ行の作成', s.count('INSERT OR IGNORE INTO defense_stage'), 2)
chk('敵の定数は1つ', s.count('const DEFENSE_ENEMIES = ['), 1)
if 'stage - 1' in s or 'stage-1' in s or 'stage = stage -' in s:
    print('NG: 降格の経路が入っている')
    ok[0] = False

# 敵は8体のまま（定数の中身に触っていないこと）
_i = s.index('const DEFENSE_ENEMIES = [')
_j = s.index('\n]', _i)
chk('敵の体数', s[_i:_j].count('{ name:'), 8)

# dry-run のブロックは書き込みゼロ
_a = s.index("app.get('/api/teacher/defense/dry-run'")
_b = s.index("app.post('/api/defense/resolve'", _a)
_blk = s[_a:_b]
for _w in ('INSERT', 'UPDATE', 'DELETE', '.run()', '.batch('):
    if _w in _blk:
        print('NG: dry-run に書き込み %s が入っている' % _w)
        ok[0] = False

if not ok[0]:
    print('NG: 検証に落ちたので src/index.tsx は書き換えない')
    sys.exit(1)

io.open(PATH, 'w', encoding='utf-8').write(s)
print('OK: DEF_STAGE_V2 を適用した（チェーン %d -> %d・敵は8体のまま）' % (before, after))
