# -*- coding: utf-8 -*-
# WORLD_V2（3周目「世界編」第2段：ごほうびキャラ10体と、その配り先）
#   1) src/world_v2.ts の 2件の置きかえを、src/index.tsx のチェーンに「1件のループ」として足す。
#      world_v1 のループより後ろに置く（V02_card は world_v1 が入れた文字列に当てるため）。
#   2) サーバ側に 台帳 world_stage_rewards を足す。
#      作法は defense_stage_rewards と まったく同じ：
#        枠を予約（applied_at を先に立てる）→ changes===1 のときだけ配る → 例外なら NULL に戻す。
#      資格の元は その子自身が保存した warProgress.worldCleared だけ。
#      クライアントから送られてきた数値は 一切つかわない。
#   public/index.html は手で編集しない。
#   アンカーが1件でなければ 1文字も書かずに止まる（fail-closed）。
#   既存の進行データ（current / clearedMax / unlocked / zombieCleared）への書き込みが
#   追加コードに1つも無いことも、ここで確かめる。
import io
import os
import sys
import hashlib

SRC = 'src/index.tsx'
MOD = 'src/world_v2.ts'
MOD1 = 'src/world_v1.ts'
HTML = 'public/index.html'
SENTINEL = '__WORLD_V2__'
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


# ---- チェーン件数は 流す直前に実測した値を workflow から渡す ----------------
raw = (os.environ.get('CHAIN_BEFORE') or '').strip()
if not raw.isdigit():
    print('NG: CHAIN_BEFORE が数字でない（渡された値: %r）' % raw)
    sys.exit(1)
CHAIN_BEFORE = int(raw)
CHAIN_AFTER = CHAIN_BEFORE + 1

# ---- 1) import ------------------------------------------------------------
A_IMPORT = "import { WORLD_V1_PATCHES } from './world_v1'" + NL
N_IMPORT = (A_IMPORT
            + '// __WORLD_V2__ 3周目「世界編」第2段。当てる中身は src/world_v2.ts。' + NL
            + "import { WORLD_V2_PATCHES } from './world_v2'" + NL)

# ---- 2) チェーン（world_v1 のループの すぐ後ろ） ---------------------------
A_LOOP = ("    for (const _wp of WORLD_V1_PATCHES) {" + NL
          + "      if (t.indexOf(_wp.a) !== -1) { t = t.replace(_wp.a, () => _wp.b) } else { console.error('[__WORLD_V1__] anchor not found: ' + _wp.tag) }" + NL
          + '    }' + NL)

N_LOOP = (A_LOOP
          + '    // __WORLD_V2__ 世界編 第2段（ごほうびキャラ10体）。中身は src/world_v2.ts。' + NL
          + '    // world_v1 のループより後ろであること（V02_card は world_v1 が入れた文字列に当てる）。' + NL
          + '    for (const _wp2 of WORLD_V2_PATCHES) {' + NL
          + "      if (t.indexOf(_wp2.a) !== -1) { t = t.replace(_wp2.a, () => _wp2.b) } else { console.error('[__WORLD_V2__] anchor not found: ' + _wp2.tag) }" + NL
          + '    }' + NL)

# ---- 3) サーバ側の 台帳いっしき -------------------------------------------
A_FNS = 'async function ensureDefenseTables(env: any) {'

N_FNS = r'''// __WORLD_V2__ 3周目「世界編」ステージ初クリアのごほうび（キャラ1体ずつ・初クリアのみ）。
//   資格の元 : その子自身が保存した warProgress.worldCleared だけ。クライアントの申告は使わない。
//   配る相手 : その子だけ（防衛戦とちがってクラス全員ではない）。
//   二重防止 : defense_stage_rewards と まったく同じ作法。
//              1) applied_at を先に立てて枠を予約（changes===1 のときだけ先へ進む）
//              2) 予約できたときだけ json_set で該当箇所だけ書き換える（state_json の全置換はしない）
//              3) 途中で例外が出たら applied_at=NULL に戻して解放する（次回また配られる）
//   public/index.html 側の WORLD_REWARD_BY_STAGE と 同じ表であること。
const WORLD_STAGE_REWARDS: any = {
  '3': { id: 2103, level: 35 },
  '6': { id: 2112, level: 38 },
  '8': { id: 2111, level: 40 },
  '10': { id: 2117, level: 42 },
  '13': { id: 2114, level: 45 },
  '16': { id: 2102, level: 48 },
  '18': { id: 2113, level: 50 },
  '21': { id: 2115, level: 52 },
  '22': { id: 2116, level: 55 },
  '23': { id: 2101, level: 60 }
}

function worldRewardSeed(monsterId: number): any {
  let level = 35
  for (const k of Object.keys(WORLD_STAGE_REWARDS)) {
    if (Number(WORLD_STAGE_REWARDS[k].id) === monsterId) { level = Number(WORLD_STAGE_REWARDS[k].level) || 35; break }
  }
  return { level: level, exp: 0, nextExp: Math.floor(100 + Math.pow(level, 2.2) * 10) }
}

async function worldEnsureTable(env: any) {
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS world_stage_rewards (user_id TEXT NOT NULL, stage INTEGER NOT NULL, monster_id INTEGER, applied_at TEXT, PRIMARY KEY(user_id, stage))").run()
}

// __WORLD_V2__ クリア済みのぶんだけ 台帳行を作る。ここでは progress を1文字も触らない。
// PRIMARY KEY(user_id, stage) + INSERT OR IGNORE なので、二重に呼ばれても行は増えない。
async function worldMakeLedger(env: any, userId: string, stateJson: string): Promise<number> {
  try {
    const st = JSON.parse(stateJson)
    const wp = (st && st.warProgress) ? st.warProgress : null
    const wc = (wp && wp.worldCleared && typeof wp.worldCleared === 'object') ? wp.worldCleared : null
    if (!wc) return 0
    const rows: any[] = []
    for (const k of Object.keys(WORLD_STAGE_REWARDS)) {
      if (!wc[k]) continue
      const stage = Math.floor(Number(k))
      if (!Number.isInteger(stage) || stage < 0 || stage > 23) continue
      const mid = Math.floor(Number(WORLD_STAGE_REWARDS[k].id) || 0)
      if (!(mid > 0)) continue
      rows.push([stage, mid])
    }
    if (!rows.length) return 0
    await worldEnsureTable(env)
    const ins = env.DB.prepare('INSERT OR IGNORE INTO world_stage_rewards (user_id, stage, monster_id, applied_at) VALUES (?, ?, ?, NULL)')
    await env.DB.batch(rows.map((r: any) => ins.bind(userId, r[0], r[1])))
    return rows.length
  } catch (_e) { return 0 }
}

// __WORLD_V2__ 台帳の未適用ぶんを、この子の progress に配る。
async function applyWorldStageGrants(env: any, userId: string): Promise<any> {
  const _wsApplied: any = { monsters: [] }
  let list: any[] = []
  try {
    const rows = await env.DB.prepare('SELECT stage, monster_id FROM world_stage_rewards WHERE user_id = ? AND applied_at IS NULL ORDER BY stage ASC LIMIT 24').bind(userId).all<any>()
    list = ((rows && rows.results) || [])
  } catch (_e) { return _wsApplied }
  if (!list.length) return _wsApplied
  for (const g of list) {
    const stage = Math.floor(Number(g.stage))
    const monsterId = Math.floor(Number(g.monster_id) || 0)
    if (!Number.isInteger(stage) || stage < 0 || stage > 23) continue
    // SQL のパスに差し込むのは 自分のテーブルから読んだ整数だけ。ここでも整数であることを確かめる。
    if (!(Number.isInteger(monsterId) && monsterId > 0 && monsterId < 100000)) continue
    let claimed = false
    try {
      const claim = await env.DB.prepare("UPDATE world_stage_rewards SET applied_at = datetime('now') WHERE user_id = ? AND stage = ? AND applied_at IS NULL").bind(userId, stage).run()
      if (!claim.meta || claim.meta.changes !== 1) continue
      claimed = true
      const cur = await env.DB.prepare('SELECT state_json as sj FROM progress WHERE user_id = ? LIMIT 1').bind(userId).first<any>()
      let hasMon = false
      let dex: any = null
      try {
        const stt = JSON.parse((cur && cur.sj) || '{}')
        hasMon = !!(stt && stt.monsters && stt.monsters[String(monsterId)])
        dex = stt ? stt.pokedex : null
      } catch (_e2) {}
      const mPath = '$.monsters."' + String(monsterId) + '"'
      if (!hasMon) {
        const _m = await env.DB.prepare("UPDATE progress SET state_json = json_set(state_json, '" + mPath + "', json(?)), updated_at = datetime('now') WHERE user_id = ? AND json_valid(state_json)").bind(JSON.stringify(worldRewardSeed(monsterId)), userId).run()
        if (!_m.meta || Number(_m.meta.changes || 0) !== 1) throw new Error('world_monster_not_applied')
      }
      if (!Array.isArray(dex)) {
        await env.DB.prepare("UPDATE progress SET state_json = json_set(state_json, '$.pokedex', json('[]')), updated_at = datetime('now') WHERE user_id = ? AND json_valid(state_json) AND COALESCE(json_type(state_json, '$.pokedex'), 'x') <> 'array'").bind(userId).run()
        dex = []
      }
      if (dex.map(Number).indexOf(monsterId) < 0) {
        await env.DB.prepare("UPDATE progress SET state_json = json_insert(state_json, '$.pokedex[#]', ?), updated_at = datetime('now') WHERE user_id = ? AND json_type(state_json, '$.pokedex') = 'array'").bind(monsterId, userId).run()
      }
      _wsApplied.monsters.push({ id: monsterId, stage: stage })
    } catch (_e) {
      if (claimed) {
        try { await env.DB.prepare('UPDATE world_stage_rewards SET applied_at = NULL WHERE user_id = ? AND stage = ?').bind(userId, stage).run() } catch (_e3) {}
      }
    }
  }
  return _wsApplied
}


'''

# ---- 4) 進捗の読み出しで 台帳を作って配る ---------------------------------
A_ROUTE = '  // __DEF_MVP_V1__ 部門べつ ベスト3のコイン。台帳の未適用ぶんだけを配る。' + NL

N_ROUTE = r'''  // __WORLD_V2__ 世界編ステージ初クリアのごほうび（キャラ1体）。台帳を作ってから、未適用ぶんだけを配る。
  if (_stateJson) {
    try {
      await worldMakeLedger(c.env, u.id, _stateJson)
      const _wsg = await applyWorldStageGrants(c.env, u.id)
      if (_wsg && _wsg.monsters && _wsg.monsters.length) {
        // DB 側はもう json_set で書き換わっている。ここは返す JSON をそれに合わせるだけ。
        const _wsSt = JSON.parse(_stateJson)
        for (const _wsM of _wsg.monsters) {
          const _wsMid = Number(_wsM.id)
          if (!Number.isFinite(_wsMid) || _wsMid <= 0) continue
          if (!_wsSt.monsters || typeof _wsSt.monsters !== 'object') _wsSt.monsters = {}
          if (!_wsSt.monsters[String(_wsMid)]) _wsSt.monsters[String(_wsMid)] = worldRewardSeed(_wsMid)
          if (!Array.isArray(_wsSt.pokedex)) _wsSt.pokedex = []
          if (!_wsSt.pokedex.includes(_wsMid)) _wsSt.pokedex.push(_wsMid)
          if (!_wsSt._worldRewardGranted || typeof _wsSt._worldRewardGranted !== 'object') _wsSt._worldRewardGranted = {}
          _wsSt._worldRewardGranted[String(_wsMid)] = Number(_wsM.stage)
        }
        _stateJson = JSON.stringify(_wsSt)
      }
    } catch (_e) {}
  }
''' + A_ROUTE

BAD = ['warProgress.current =', 'clearedMax =', 'unlocked =', 'zombieCleared[']

# --------------------------------------------------------------------------
s = io.open(SRC, encoding='utf-8').read()
h = io.open(HTML, encoding='utf-8').read()
try:
    m = io.open(MOD, encoding='utf-8').read()
except IOError:
    print('NG: %s が無い。先にファイルを置いてから流す。' % MOD)
    sys.exit(1)
try:
    m1 = io.open(MOD1, encoding='utf-8').read()
except IOError:
    print('NG: %s が無い。' % MOD1)
    sys.exit(1)

before = chain_count(s)
print('chain(before) =', before, '（CHAIN_BEFORE =', CHAIN_BEFORE, '）')
print('public/index.html sha256 =', hashlib.sha256(h.encode('utf-8')).hexdigest())
print('src/world_v2.ts  sha256 =', hashlib.sha256(m.encode('utf-8')).hexdigest())

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。何も書かない。chain =', before)
    sys.exit(0)

if before != CHAIN_BEFORE:
    print('NG: 流す前のチェーンが %d 件（渡された %d と違う）。並行作業の可能性。止める。' % (before, CHAIN_BEFORE))
    sys.exit(1)

# --- world_v2 の中身 ---
need('world_v2 の書き出し', 'export const WORLD_V2_PATCHES', m, 1)
if m.count("tag: 'V") != 2:
    print('NG: world_v2.ts のパッチが %d 件（期待 2）' % m.count("tag: 'V"))
    sys.exit(1)

# --- 追加コードに 既存の進行データへの書き込みが1つも無いこと ---
for w in BAD:
    if w in m:
        print('NG: 追加コードに既存の進行データへの書き込み「%s」がある' % w)
        sys.exit(1)
    if w in (N_IMPORT + N_LOOP + N_FNS + N_ROUTE):
        print('NG: つなぎ目に「%s」がある' % w)
        sys.exit(1)

# --- ID が 既存とぶつからないこと（世界編の10体） ---
for mid in ['2101', '2102', '2103', '2111', '2112', '2113', '2114', '2115', '2116', '2117']:
    pat = 'id: ' + mid + ','
    if pat in h:
        print('NG: public/index.html に すでに %s がある' % mid)
        sys.exit(1)

# --- 当てる先が 1件ずつ あること ---
need('キャラを足す場所(html)', '        // --- 属性タイプが未設定のモンスター補完（表示・相性計算用） ---', h, 1)
need('カードのごほうび欄(world_v1)', "          h += '<div class=\"war-stage-reward\">🎁 コイン＆ひでんの書</div>';", m1, 1)
need('world_v1 の import', A_IMPORT, s, 1)
need('world_v1 のループ', A_LOOP, s, 1)
need('台帳を置く場所', A_FNS, s, 1)
need('進捗の読み出し', A_ROUTE, s, 1)

s = s.replace(A_IMPORT, N_IMPORT, 1)
s = s.replace(A_LOOP, N_LOOP, 1)
s = s.replace(A_FNS, N_FNS + A_FNS, 1)
s = s.replace(A_ROUTE, N_ROUTE, 1)

after = chain_count(s)

chk('チェーン', after, CHAIN_AFTER)
chk('増えた件数', after - before, 1)
chk('world_v2 の import', s.count("from './world_v2'"), 1)
chk('当てるループ', s.count('for (const _wp2 of WORLD_V2_PATCHES) {'), 1)
chk('ごほうびの表', s.count('const WORLD_STAGE_REWARDS'), 1)
chk('台帳を作る関数', s.count('async function worldMakeLedger'), 1)
chk('台帳を配る関数', s.count('async function applyWorldStageGrants'), 1)
chk('台帳を配る呼び出し', s.count('await applyWorldStageGrants(c.env, u.id)'), 1)
chk('テーブル作成', s.count('CREATE TABLE IF NOT EXISTS world_stage_rewards'), 1)

# --- 壊してはいけないもの ---
chk('world_v1 の import', s.count("from './world_v1'"), 1)
chk('world_v1 のループ', s.count('for (const _wp of WORLD_V1_PATCHES) {'), 1)
chk('def_engine の import', s.count("from './def_engine'"), 1)
chk('logout ルート', s.count("app.get('/logout'"), 1)
chk('チェーンの入口', s.count("app.get('/', async (c) => {"), 1)
chk('_rootHtmlCache の締め', s.count('_rootHtmlCache = t'), 1)
chk('防衛戦の台帳', s.count('async function applyDefStageGrants'), 1)
chk('防衛戦の呼び出し', s.count('await applyDefStageGrants(c.env, u.id)'), 1)

if not ok[0]:
    print('検証に落ちたので何も書かない')
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('OK: 適用した。chain =', before, '->', after)
