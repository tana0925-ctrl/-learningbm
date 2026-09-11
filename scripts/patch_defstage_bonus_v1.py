# -*- coding: utf-8 -*-
# DEFSTAGE_BONUS_V1（第3便・第1段：台帳と付与）
#   1) ステージを初めてクリアした1回だけ、クラス全員ぶんの台帳行（defense_stage_rewards）を作る。
#      ここでは progress を1文字も触らない。
#   2) 児童が progress を読むときに、台帳の未適用ぶんだけを配る。
#      applyMakeupGrants と同じ「枠を先に予約 → 加算 → 失敗したら解放」。
#      progress の書き換えは json_set で該当箇所だけ。state_json の全置換はしない。
#   3) PUT /api/student/progress に _defStageCoinsApplied の照合を足す。
#      _contactCoinsApplied / _hwCoinsApplied とまったく同じ形。
#      クライアントの台帳が水増しされていてもコインは1枚も動かさない。
#   4) GET /api/defense/status に stage_bonus を足す（読むだけ。書き込みはしない）。
# 金額も資格もサーバ側だけで決める。クライアントの申告は一切使わない。
# DDL はここでは流さない（migrations/0033 を D1 MCP から直接流してある）。
# 限定キャラの中身（MONSTERS への追加）は第2段。ここに出てくるのは ID だけ。
# アンカーが一致しなければ何も書かずに止まる（fail-closed）。
import io
import sys

PATH = 'src/index.tsx'
SENTINEL = '__DEFSTAGE_BONUS_V1__'
CHAIN_EXPECT = 73


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def need(label, text, s, want):
    got = s.count(text)
    if got != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, got, want))
        sys.exit(1)


# ------------------------------------------------------------------
# アンカー（すべて1件でなければ止まる）
# ------------------------------------------------------------------
A_CONST = 'const DEFENSE_WIN_COINS = 20'

A_GET = '''  if (_stateJson) {
    try { const _mk = await applyMakeupGrants(c.env, u.id, _stateJson); if (_mk) _stateJson = _mk } catch (_e) {}
  }
'''

A_PUT = '''      } else if (_cliHw > _srvHw) {
        // 台帳の水増し（次回以降の補填を殺すための細工）。コインは足さず、台帳だけサーバの値に戻す。
        _inc._hwCoinsApplied = _srvHw
        saveJson = JSON.stringify(_inc)
      }
'''

A_STATUS_END = '''  return c.json(out)
})

// 児童：出陣（1体＋さくせん）を保存
'''

# resolve は勝ち経路が2つある（サーバ判定とクライアント申告）。
# 中身は同じで字下げだけが違うので、先頭の改行＋空白まで含めて一意にする。
A_WIN_SRV = '''
        await c.env.DB.prepare("UPDATE defense_stage SET stage = stage + 1, updated_at = datetime('now') WHERE class_id = ? AND stage = ?").bind(classId, _dsStage).run()
'''

A_WIN_CLI = '''
      await c.env.DB.prepare("UPDATE defense_stage SET stage = stage + 1, updated_at = datetime('now') WHERE class_id = ? AND stage = ?").bind(classId, _dsStage).run()
'''

# ------------------------------------------------------------------
# 追加するもの
# ------------------------------------------------------------------
N_CONST = '''const DEFENSE_WIN_COINS = 20

// __DEFSTAGE_BONUS_V1__ ステージ初クリアのボーナス。
//   コイン    : 勝利コイン 20 とは別に、初クリアした1回だけ 30 + 10 * stage
//               （ステージ1クリア=40枚、5クリア=80枚）
//   限定キャラ: ステージ 3 / 5 / 7 / 10 の初クリアで1体ずつ
//   配る相手  : そのクラスに在籍している全員（defense_entries に出していない子もふくむ）
// 金額も資格もここだけで決まる。クライアントから来た値は一切使わない。
// 敵の強さが 10 で頭打ちなのに合わせて、ボーナスの計算も 10 で頭打ちにする
// （11回目以降のクリアで台帳が増え続けないようにするため）。
const DEFSTAGE_BONUS_COIN_BASE = 30
const DEFSTAGE_BONUS_COIN_PER_STAGE = 10
const DEFSTAGE_BONUS_MAX_STAGE = 10
const DEFSTAGE_BONUS_MONSTERS: any = {
  '3': { id: 1601, level: 20 },
  '5': { id: 1602, level: 30 },
  '7': { id: 1604, level: 40 },
  '10': { id: 1605, level: 50 }
}

function defStageBonusStage(stage: any): number {
  const n = Math.floor(Number(stage))
  if (!Number.isFinite(n) || n < 1) return 0
  return n > DEFSTAGE_BONUS_MAX_STAGE ? DEFSTAGE_BONUS_MAX_STAGE : n
}

function defStageBonusCoins(stage: any): number {
  const n = defStageBonusStage(stage)
  if (!n) return 0
  return DEFSTAGE_BONUS_COIN_BASE + DEFSTAGE_BONUS_COIN_PER_STAGE * n
}

function defStageBonusMonsterId(stage: any): number {
  const n = defStageBonusStage(stage)
  const m = n ? DEFSTAGE_BONUS_MONSTERS[String(n)] : null
  return (m && Number(m.id)) || 0
}

function defStageBonusMonsterSeed(monsterId: number): any {
  let level = 20
  for (const k of Object.keys(DEFSTAGE_BONUS_MONSTERS)) {
    if (Number(DEFSTAGE_BONUS_MONSTERS[k].id) === monsterId) { level = Number(DEFSTAGE_BONUS_MONSTERS[k].level) || 20; break }
  }
  return { level: level, exp: 0, nextExp: Math.floor(100 + Math.pow(level, 2.2) * 10) }
}

// __DEFSTAGE_BONUS_V1__ 初クリアの1回だけ呼ばれる。クラス全員ぶんの台帳行を作るだけで、progress は触らない。
// PRIMARY KEY(class_id, stage, user_id) + INSERT OR IGNORE なので、二重に呼ばれても行は増えない。
async function defStageMakeLedger(env: any, classId: string, clearedStage: number): Promise<number> {
  try {
    const stage = defStageBonusStage(clearedStage)
    if (!stage || !classId) return 0
    const coins = defStageBonusCoins(stage)
    const monsterId = defStageBonusMonsterId(stage)
    if (coins <= 0 && !monsterId) return 0
    const ms = await env.DB.prepare('SELECT user_id FROM class_members WHERE class_id = ? LIMIT 200').bind(classId).all<any>()
    const rows = ((ms && ms.results) || []).filter((r: any) => r && r.user_id)
    if (!rows.length) return 0
    const ins = env.DB.prepare('INSERT OR IGNORE INTO defense_stage_rewards (class_id, stage, user_id, coins, monster_id, applied_at) VALUES (?, ?, ?, ?, ?, NULL)')
    await env.DB.batch(rows.map((r: any) => ins.bind(classId, stage, String(r.user_id), coins, monsterId || null)))
    return rows.length
  } catch (_e) { return 0 }
}

// __DEFSTAGE_BONUS_V1__ 台帳の未適用ぶんを、この子の progress に配る。
// applyMakeupGrants とまったく同じ作法：
//   1) applied_at を先に立てて枠を予約する（同時アクセスでも changes===1 になるのは1回だけ）
//   2) 予約できたときだけ json_set で該当箇所だけ書き換える（state_json の全置換はしない）
//   3) 途中で例外が出たら applied_at=NULL に戻して解放する（次回また配られる）
async function applyDefStageGrants(env: any, userId: string): Promise<any> {
  const _dsApplied: any = { coins: 0, monsters: [] }
  let list: any[] = []
  try {
    const rows = await env.DB.prepare('SELECT class_id, stage, coins, monster_id FROM defense_stage_rewards WHERE user_id = ? AND applied_at IS NULL ORDER BY stage ASC LIMIT 20').bind(userId).all<any>()
    list = ((rows && rows.results) || [])
  } catch (_e) { return _dsApplied }
  if (!list.length) return _dsApplied
  // progress の行がまだ無い子は、台帳を未適用のまま残す（枠だけ消えて配られないのを防ぐ）。
  try {
    const p = await env.DB.prepare('SELECT 1 AS x FROM progress WHERE user_id = ? LIMIT 1').bind(userId).first<any>()
    if (!p) return _dsApplied
  } catch (_e) { return _dsApplied }
  for (const g of list) {
    const classId = String(g.class_id || '')
    const stage = Math.floor(Number(g.stage))
    const coins = Math.max(0, Math.floor(Number(g.coins) || 0))
    const monsterId = Math.floor(Number(g.monster_id) || 0)
    if (!classId || !Number.isFinite(stage) || stage < 1) continue
    // SQL のパスに差し込むのは自分のテーブルから読んだ整数だけ。念のためここでも整数であることを確かめる。
    const monOk = Number.isInteger(monsterId) && monsterId > 0 && monsterId < 100000
    let claimed = false
    try {
      const claim = await env.DB.prepare("UPDATE defense_stage_rewards SET applied_at = datetime('now') WHERE class_id = ? AND stage = ? AND user_id = ? AND applied_at IS NULL").bind(classId, stage, userId).run()
      if (!claim.meta || claim.meta.changes !== 1) continue
      claimed = true
      if (coins > 0) {
        const _c = await env.DB.prepare("UPDATE progress SET state_json = json_set(state_json, '$.coins', COALESCE(CAST(json_extract(state_json, '$.coins') AS INTEGER), 0) + ?, '$._defStageCoinsApplied', COALESCE(CAST(json_extract(state_json, '$._defStageCoinsApplied') AS INTEGER), 0) + ?), updated_at = datetime('now') WHERE user_id = ? AND json_valid(state_json)").bind(coins, coins, userId).run()
        if (!_c.meta || Number(_c.meta.changes || 0) !== 1) throw new Error('defstage_coins_not_applied')
      }
      if (monOk) {
        const cur = await env.DB.prepare('SELECT state_json AS sj FROM progress WHERE user_id = ? LIMIT 1').bind(userId).first<any>()
        let hasMon = false
        let dex: any = null
        let party: any = null
        try {
          const stt = JSON.parse((cur && cur.sj) || '{}')
          hasMon = !!(stt && stt.monsters && stt.monsters[String(monsterId)])
          dex = stt ? stt.pokedex : null
          party = stt ? stt.party : null
        } catch (_e2) {}
        const mPath = '$.monsters."' + String(monsterId) + '"'
        const gPath = '$._defStageMonsterGranted."' + String(monsterId) + '"'
        if (!hasMon) {
          const _m = await env.DB.prepare("UPDATE progress SET state_json = json_set(state_json, '" + mPath + "', json(?)), updated_at = datetime('now') WHERE user_id = ? AND json_valid(state_json)").bind(JSON.stringify(defStageBonusMonsterSeed(monsterId)), userId).run()
          if (!_m.meta || Number(_m.meta.changes || 0) !== 1) throw new Error('defstage_monster_not_applied')
        }
        await env.DB.prepare("UPDATE progress SET state_json = json_set(state_json, '" + gPath + "', ?), updated_at = datetime('now') WHERE user_id = ? AND json_valid(state_json)").bind(stage, userId).run()
        if (!Array.isArray(dex)) {
          await env.DB.prepare("UPDATE progress SET state_json = json_set(state_json, '$.pokedex', json('[]')), updated_at = datetime('now') WHERE user_id = ? AND json_valid(state_json) AND COALESCE(json_type(state_json, '$.pokedex'), 'x') <> 'array'").bind(userId).run()
          dex = []
        }
        if (dex.map(Number).indexOf(monsterId) < 0) {
          await env.DB.prepare("UPDATE progress SET state_json = json_insert(state_json, '$.pokedex[#]', ?), updated_at = datetime('now') WHERE user_id = ? AND json_type(state_json, '$.pokedex') = 'array'").bind(monsterId, userId).run()
        }
        if (Array.isArray(party) && party.length < 3 && party.map(Number).indexOf(monsterId) < 0) {
          await env.DB.prepare("UPDATE progress SET state_json = json_insert(state_json, '$.party[#]', ?), updated_at = datetime('now') WHERE user_id = ? AND json_type(state_json, '$.party') = 'array' AND json_array_length(state_json, '$.party') < 3").bind(monsterId, userId).run()
        }
      }
      _dsApplied.coins += coins
      if (monOk) _dsApplied.monsters.push({ id: monsterId, stage: stage })
    } catch (_e) {
      // 途中で失敗したら枠を解放する。次に progress を読んだときにまた配られる。
      if (claimed) {
        try { await env.DB.prepare('UPDATE defense_stage_rewards SET applied_at = NULL WHERE class_id = ? AND stage = ? AND user_id = ?').bind(classId, stage, userId).run() } catch (_e3) {}
      }
    }
  }
  return _dsApplied
}
'''

N_GET = A_GET + '''  // __DEFSTAGE_BONUS_V1__ ステージ初クリアのボーナス（コイン＋限定キャラ）。台帳の未適用ぶんだけを配る。
  if (_stateJson) {
    try {
      const _dsg = await applyDefStageGrants(c.env, u.id)
      if (_dsg && (_dsg.coins > 0 || (_dsg.monsters && _dsg.monsters.length))) {
        // DB 側はもう json_set で書き換わっている。ここは返す JSON をそれに合わせるだけ。
        // progress を読み直すと、この上でメモリ上だけ足したトレード受け取りが消えるのでやらない。
        const _dsSt = JSON.parse(_stateJson)
        if (_dsg.coins > 0) {
          _dsSt.coins = (Number(_dsSt.coins) || 0) + _dsg.coins
          _dsSt._defStageCoinsApplied = (Number(_dsSt._defStageCoinsApplied) || 0) + _dsg.coins
        }
        for (const _dsM of (_dsg.monsters || [])) {
          const _dsMid = Number(_dsM.id)
          if (!Number.isFinite(_dsMid) || _dsMid <= 0) continue
          if (!_dsSt.monsters || typeof _dsSt.monsters !== 'object') _dsSt.monsters = {}
          if (!_dsSt.monsters[String(_dsMid)]) _dsSt.monsters[String(_dsMid)] = defStageBonusMonsterSeed(_dsMid)
          if (!Array.isArray(_dsSt.pokedex)) _dsSt.pokedex = []
          if (!_dsSt.pokedex.includes(_dsMid)) _dsSt.pokedex.push(_dsMid)
          if (Array.isArray(_dsSt.party) && _dsSt.party.length < 3 && !_dsSt.party.includes(_dsMid)) _dsSt.party.push(_dsMid)
          if (!_dsSt._defStageMonsterGranted || typeof _dsSt._defStageMonsterGranted !== 'object') _dsSt._defStageMonsterGranted = {}
          _dsSt._defStageMonsterGranted[String(_dsMid)] = Number(_dsM.stage) || 0
        }
        _stateJson = JSON.stringify(_dsSt)
      }
    } catch (_e) {}
  }
'''

N_PUT = A_PUT + '''      // 👾 ステージ初クリアのボーナスコイン：サーバが付与済みなら、古い端末の全置換保存でも必ず補填。
      //    金額は defense_stage_rewards 台帳とサーバの定数だけで決まる（クライアントの申告は不使用）。
      //    _contactCoinsApplied / _hwCoinsApplied とまったく同じ形。
      const _srvDs = Number(_srv._defStageCoinsApplied) || 0
      const _cliDs = Number(_inc._defStageCoinsApplied) || 0
      if (_srvDs > _cliDs) {
        _inc.coins = (Number(_inc.coins) || 0) + (_srvDs - _cliDs)
        _inc._defStageCoinsApplied = _srvDs
        saveJson = JSON.stringify(_inc)
      } else if (_cliDs > _srvDs) {
        // 台帳の水増し。コインは1枚も動かさず、台帳だけサーバの値に戻す。
        _inc._defStageCoinsApplied = _srvDs
        saveJson = JSON.stringify(_inc)
      }
      // 👾 ステージ初クリアの限定キャラ：サーバが配った子からは、全置換保存でも消えないようにする。
      const _srvDsm = (_srv && _srv._defStageMonsterGranted) || null
      if (_srvDsm && typeof _srvDsm === 'object') {
        let _dsmChanged = false
        for (const _mid of Object.keys(_srvDsm)) {
          const _mn = Number(_mid)
          if (!Number.isFinite(_mn) || _mn <= 0) continue
          if (!_inc.monsters || typeof _inc.monsters !== 'object') { _inc.monsters = {}; _dsmChanged = true }
          if (!_inc.monsters[_mid]) {
            _inc.monsters[_mid] = (_srv.monsters && _srv.monsters[_mid]) || defStageBonusMonsterSeed(_mn)
            _dsmChanged = true
          }
          if (!Array.isArray(_inc.pokedex)) { _inc.pokedex = []; _dsmChanged = true }
          if (!_inc.pokedex.includes(_mn)) { _inc.pokedex.push(_mn); _dsmChanged = true }
          if (!_inc._defStageMonsterGranted || typeof _inc._defStageMonsterGranted !== 'object') { _inc._defStageMonsterGranted = {}; _dsmChanged = true }
          if (_inc._defStageMonsterGranted[_mid] !== _srvDsm[_mid]) { _inc._defStageMonsterGranted[_mid] = _srvDsm[_mid]; _dsmChanged = true }
        }
        if (_dsmChanged) saveJson = JSON.stringify(_inc)
      }
'''

N_STATUS_END = '''  // __DEFSTAGE_BONUS_V1__ 直前に勝った回のステージボーナス（この子ぶん）。読むだけ。ここでは絶対に書かない。
  //   out.stage はもう1つ進んだあとの値なので、クリアしたステージは out.stage - 1。
  try {
    if (out.result && out.result.result === 'win') {
      const _dsbCleared = Math.floor(Number(out.stage)) - 1
      if (Number.isFinite(_dsbCleared) && _dsbCleared >= 1) {
        const _dsb = await c.env.DB.prepare('SELECT stage, coins, monster_id FROM defense_stage_rewards WHERE class_id = ? AND stage = ? AND user_id = ? LIMIT 1').bind(classId, _dsbCleared, u.id).first<any>()
        if (_dsb) out.stage_bonus = { stage: Number(_dsb.stage), next: Number(_dsb.stage) + 1, coins: Number(_dsb.coins || 0), monster_id: (_dsb.monster_id != null) ? Number(_dsb.monster_id) : null }
      }
    }
  } catch (_e) {}
''' + A_STATUS_END

N_WIN_SRV = '''
        const _dsUp = await c.env.DB.prepare("UPDATE defense_stage SET stage = stage + 1, updated_at = datetime('now') WHERE class_id = ? AND stage = ?").bind(classId, _dsStage).run()
        // __DEFSTAGE_BONUS_V1__ この UPDATE が通った1回だけが「ステージ _dsStage の初クリア」。台帳を作るのはここだけ。
        if (_dsUp && _dsUp.meta && Number(_dsUp.meta.changes || 0) === 1) await defStageMakeLedger(c.env, classId, _dsStage)
'''

N_WIN_CLI = '''
      const _dsUp2 = await c.env.DB.prepare("UPDATE defense_stage SET stage = stage + 1, updated_at = datetime('now') WHERE class_id = ? AND stage = ?").bind(classId, _dsStage).run()
      // __DEFSTAGE_BONUS_V1__ この UPDATE が通った1回だけが「ステージ _dsStage の初クリア」。台帳を作るのはここだけ。
      if (_dsUp2 && _dsUp2.meta && Number(_dsUp2.meta.changes || 0) === 1) await defStageMakeLedger(c.env, classId, _dsStage)
'''

# ------------------------------------------------------------------
s = io.open(PATH, encoding='utf-8').read()
before = chain_count(s)

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。src/index.tsx には何も書かない。chain =', before)
    sys.exit(0)

if before != CHAIN_EXPECT:
    print('NG: 流す前のチェーンが %d 件（期待 %d）' % (before, CHAIN_EXPECT))
    sys.exit(1)

need('DEFENSE_WIN_COINS', A_CONST, s, 1)
need('GET progress の補填', A_GET, s, 1)
need('PUT progress の宿題コイン照合', A_PUT, s, 1)
need('status のおわり', A_STATUS_END, s, 1)
need('サーバ経路のステージ前進', A_WIN_SRV, s, 1)
need('申告経路のステージ前進', A_WIN_CLI, s, 1)
need('defense_stage_rewards がまだ無いこと', 'defense_stage_rewards', s, 0)

s = s.replace(A_CONST, N_CONST, 1)
s = s.replace(A_GET, N_GET, 1)
s = s.replace(A_PUT, N_PUT, 1)
s = s.replace(A_STATUS_END, N_STATUS_END, 1)
s = s.replace(A_WIN_SRV, N_WIN_SRV, 1)
s = s.replace(A_WIN_CLI, N_WIN_CLI, 1)

after = chain_count(s)
ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


# --- チェーンは1件も増えない（第1段は .replace を足さない） ---
chk('チェーン', after, CHAIN_EXPECT)
# --- 今回入れたもの ---
chk('番兵', s.count(SENTINEL), 7)
chk('台帳を作る関数の定義', s.count('async function defStageMakeLedger('), 1)
chk('台帳を作る関数の呼び出し', s.count('await defStageMakeLedger(c.env, classId, _dsStage)'), 2)
chk('付与関数の定義', s.count('async function applyDefStageGrants('), 1)
chk('付与関数の呼び出し', s.count('await applyDefStageGrants(c.env, u.id)'), 1)
chk('付与の戻り値', s.count('const _dsApplied: any = { coins: 0, monsters: [] }'), 1)
chk('GET で progress を読み直していない', s.count('SELECT state_json as sj FROM progress'), 0)
chk('枠の予約', s.count("UPDATE defense_stage_rewards SET applied_at = datetime('now')"), 1)
chk('枠の解放', s.count('UPDATE defense_stage_rewards SET applied_at = NULL'), 1)
chk('コインの json_set', s.count("json_set(state_json, '$.coins'"), 1)
chk('全員に配る（class_members）', s.count('SELECT user_id FROM class_members WHERE class_id = ? LIMIT 200'), 1)
chk('水増しガード', s.count('} else if (_cliDs > _srvDs) {'), 1)
chk('サーバ累計の読み取り', s.count('_srv._defStageCoinsApplied'), 1)
chk('限定キャラの ID 表', s.count('id: 1601'), 1)
chk('限定キャラの ID 表 1602', s.count('id: 1602'), 1)
chk('限定キャラの ID 表 1604', s.count('id: 1604'), 1)
chk('限定キャラの ID 表 1605', s.count('id: 1605'), 1)
chk('もとからある全置換の数が変わっていない', s.count('UPDATE progress SET state_json=?'), 11)
# --- 壊してはいけないもの ---
chk('__DEFSTAGE_SENTINEL_V1__', s.count('__DEFSTAGE_SENTINEL_V1__'), 1)
chk('__DEF_SNAP_SPDSKILLS_V1__', s.count('__DEF_SNAP_SPDSKILLS_V1__'), 1)
chk('__DEF_RESOLVE_VERIFY_V1__', s.count('__DEF_RESOLVE_VERIFY_V1__'), 1)
chk('log の v===2 条件', s.count('Number(_dvLog.v) === 2'), 1)
chk('baseHpA の有限数条件', s.count('Number.isFinite(Number(_dvRep.baseHpA))'), 1)
chk('retry true', s.count('retry: true'), 2)
chk('log の 900000 上限', s.count('900000'), 1)
chk('defense_standing', s.count('defense_standing'), 4)
chk('defense_carry_lock', s.count('defense_carry_lock'), 1)
chk('defAutoAdvanceV1', s.count('defAutoAdvanceV1'), 3)
chk('ensureDefenseTables() の呼び出し', s.count('ensureDefenseTables()'), 0)
chk('基地HP 380', s.count('DEFENSE_BASE_HP = 380'), 1)
chk('勝利コイン 20', s.count('DEFENSE_WIN_COINS = 20'), 1)
chk('defStageEnemies の呼び出し', s.count('defStageEnemies('), 3)
chk('def_stage の import', s.count("from './def_stage'"), 1)
chk('ステージを下げる経路が無いこと', s.count('stage - 1'), 0)
chk('ステージ前進の UPDATE', s.count('UPDATE defense_stage SET stage = stage + 1'), 2)

# --- dry-run は書き込みゼロのまま ---
_a = s.index("app.get('/api/teacher/defense/dry-run'")
_b = s.index("app.post('/api/defense/resolve'", _a)
_blk = s[_a:_b]
for _w in ('INSERT', 'UPDATE', 'DELETE', '.run()', '.batch('):
    if _w in _blk:
        print('NG: dry-run に書き込み %s が入っている' % _w)
        ok[0] = False

if not ok[0]:
    print('検証に落ちたので何も書かない')
    sys.exit(1)

io.open(PATH, 'w', encoding='utf-8').write(s)
print('OK: 適用した。chain =', after, '（変化なし）')
