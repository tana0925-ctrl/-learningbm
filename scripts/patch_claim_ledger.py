#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_claim_ledger.py --- ごほうびの受け取りを「台帳＋一意制約」方式に揃える

  C1  POST /api/homework/:id/claim
      いまは reward_claimed フラグだけがガード。台帳が無い。
      同時に2回押されると、両方が SELECT を通過してごほうびが二重に渡る。
      （コインの加算は児童の端末側で行われるため、サーバが弾けなければそのまま増える）
      → homework_claims(submission_id PRIMARY KEY) を作り、
        「INSERT が通ったときだけ渡す」形にする。
        既存の reward_claimed チェックは残す（台帳が無い過去ぶんを守るため）。

  C2  POST /api/student/class-mission/:id/claim
      同じ型の穴。しかも順番が逆で、
        ①SELECTで確認 → ②progressにコイン加算 → ③INSERT OR IGNORE
      になっている。同時に2回来ると①を両方通り、②が2回走り、③の2回目だけ無視される。
      → homework_rewards / mi_rewards と同じ順番に直す。
        ①先に INSERT OR IGNORE で枠を確保（changes=0 なら受け取り済み）
        ②確保できたときだけ加算
        ③加算に失敗したら枠を解放して次回やり直せるようにする

  ★ 方針
    ・DDL はリクエスト経路の「その API の中」でだけ実行する。
      起動時ミドルウェアには絶対に置かない（9/3の事故の再発防止）。
    ・reward_claimed は消さない。表示用フラグとして残す。
    ・受け取り済みのときの応答は変えない（児童の画面は already_claimed を
      「✅ 受け取り済みです」と表示する作りなので、そのまま動く）。
"""
import io, os, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')
src = io.open(TSX, encoding='utf-8').read()
orig = src
done = []

def fail(m):
    print('❌ 中止: ' + m); sys.exit(1)

def sub(tag, old, new, sentinel):
    global src
    if sentinel in src:
        print('⏭  %s は適用ずみ（スキップ）' % tag); return
    if src.count(old) != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, src.count(old)))
    src = src.replace(old, new, 1)
    done.append(tag)

# ══════════════════════════════════════════════════════════
# C0 台帳テーブルを用意する関数（ensureHomeworkRewardTable の隣に置く）
# ══════════════════════════════════════════════════════════
C0_OLD = "async function ensureHomeworkRewardTable(env: any) {"
C0_NEW = """// 🧾 家庭学習の「ごほうび受け取り」台帳。submission_id を PRIMARY KEY にすることで
//    「同じ提出に2回目」が構造的に INSERT できない。
//    homework_rewards（先生ボーナス）や mi_rewards と同じ考え方。
//    ⚠ ここを起動時ミドルウェアで呼ばないこと。使う API の中でだけ呼ぶ。
let _hwClaimTableReady = false
async function ensureHomeworkClaimTable(env: any) {
  if (_hwClaimTableReady) return
  try {
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS homework_claims (submission_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, coins INTEGER NOT NULL DEFAULT 0, shards INTEGER NOT NULL DEFAULT 0, reward_kind TEXT, created_at TEXT)").run()
    _hwClaimTableReady = true
  } catch (_e) {}
}

async function ensureHomeworkRewardTable(env: any) {"""
sub('C0 homework_claims 台帳を用意する関数', C0_OLD, C0_NEW, 'async function ensureHomeworkClaimTable(')

# ══════════════════════════════════════════════════════════
# C1 homework claim を「台帳が通ったときだけ渡す」形に
# ══════════════════════════════════════════════════════════
C1_OLD = """  // 受け取り済みにマーク
  await c.env.DB.prepare(`
    UPDATE homework_submissions SET reward_claimed=1, reward_claimed_at=? WHERE id=?
  `).bind(Date.now(), hwId).run()

  return c.json({ ok: true, coins, shards, rewardKind, hasPhysical: !!row.has_physical })"""
C1_NEW = """  // 🧾 2026-09: ここが「reward_claimed フラグだけ」で守られていた。
  //   コインの加算は児童の端末側で行われるため、サーバが弾けないと素通りで増える。
  //   台帳に先に枠を確保し、INSERT が通ったときだけ渡す。
  //   （上の reward_claimed チェックは残してある。台帳が無い過去ぶんはそちらで止まる）
  await ensureHomeworkClaimTable(c.env)
  let claimed = false
  try {
    await c.env.DB.prepare(
      "INSERT INTO homework_claims (submission_id, user_id, coins, shards, reward_kind, created_at) VALUES (?,?,?,?,?,datetime('now'))"
    ).bind(hwId, u.id, coins, shards, rewardKind).run()
    claimed = true
  } catch (_e) { claimed = false }
  if (!claimed) return jsonError(c, 400, 'already_claimed')

  // 表示用フラグ。ここが失敗しても台帳が二重受け取りを止める。
  try {
    await c.env.DB.prepare(`
      UPDATE homework_submissions SET reward_claimed=1, reward_claimed_at=? WHERE id=?
    `).bind(Date.now(), hwId).run()
  } catch (e) { console.error('reward_claimed flag update failed:', e) }

  return c.json({ ok: true, coins, shards, rewardKind, hasPhysical: !!row.has_physical })"""
sub('C1 homework claim を台帳方式に', C1_OLD, C1_NEW, 'INSERT INTO homework_claims')

# ══════════════════════════════════════════════════════════
# C2 クラスミッションの受け取りを「枠を先に確保」する順番に
# ══════════════════════════════════════════════════════════
C2_OLD = """  const rewardCoins = Number(m.reward_coins) || 0
  const rewardShards = Number(m.reward_shards) || 0
  let applyOk = false
  try {"""
C2_NEW = """  const rewardCoins = Number(m.reward_coins) || 0
  const rewardShards = Number(m.reward_shards) || 0
  // 🧾 2026-09: 順番を homework_rewards / mi_rewards に合わせた。
  //   もとは「①SELECTで確認 → ②コイン加算 → ③INSERT OR IGNORE」で、
  //   同時に2回来ると①を両方通り、②が2回走ってしまう構造だった。
  //   先に台帳の枠を確保し、確保できたときだけ加算する。
  const _cmLock = await c.env.DB.prepare(
    `INSERT OR IGNORE INTO class_mission_claims (mission_id, user_id, reward_coins, reward_shards) VALUES (?,?,?,?)`
  ).bind(missionId, u.id, rewardCoins, rewardShards).run()
  if (!_cmLock.meta || _cmLock.meta.changes === 0) {
    return c.json({ ok: true, alreadyClaimed: true, rewardCoins: 0, rewardShards: 0 })
  }
  let applyOk = false
  try {"""
sub('C2a ミッション受け取りの枠を先に確保', C2_OLD, C2_NEW, 'const _cmLock = await c.env.DB.prepare')

C2B_OLD = """  if (!applyOk) return jsonError(c, 500, 'reward_apply_failed')
  await c.env.DB.prepare(
    `INSERT OR IGNORE INTO class_mission_claims (mission_id, user_id, reward_coins, reward_shards) VALUES (?,?,?,?)`
  ).bind(missionId, u.id, rewardCoins, rewardShards).run()
  return c.json({ ok: true, rewardCoins, rewardShards })"""
C2B_NEW = """  // 加算できなかったら枠を解放して、次回やり直せるようにする（ごほうびを失わせない）
  if (!applyOk) {
    try {
      await c.env.DB.prepare(`DELETE FROM class_mission_claims WHERE mission_id=? AND user_id=?`).bind(missionId, u.id).run()
    } catch (_e) {}
    return jsonError(c, 500, 'reward_apply_failed')
  }
  return c.json({ ok: true, rewardCoins, rewardShards })"""
sub('C2b 加算に失敗したら枠を解放', C2B_OLD, C2B_NEW, '枠を解放して、次回やり直せるように')

# ══════════════════════════════════════════════════════════
# 検証 ── 合言葉とは別に「結果そのもの」を見る
# ══════════════════════════════════════════════════════════
def route(path, method='post'):
    a = src.index("app.%s('%s'" % (method, path))
    return src[a:src.index('\n})\n', a)]

# --- C1 の結果検証 ---
r1 = route('/api/homework/:id/claim')
if "if (row.reward_claimed) return jsonError(c, 400, 'already_claimed')" not in r1:
    fail('過去ぶんを守る reward_claimed のチェックが消えています')
i_ins = r1.index('INSERT INTO homework_claims')
i_ret = r1.index("return c.json({ ok: true, coins, shards")
i_upd = r1.index('SET reward_claimed=1')
if not (i_ins < i_upd < i_ret):
    fail('台帳INSERT → フラグ更新 → 応答 の順番になっていません')
if 'INSERT OR IGNORE INTO homework_claims' in r1:
    fail('homework_claims は OR IGNORE にしないこと（失敗を検知できなくなります）')
if r1.count("jsonError(c, 400, 'already_claimed')") != 2:
    fail('already_claimed の返し方が想定と違います（過去ぶん用と台帳用の2箇所のはず）')
print('🔎 C1: 台帳INSERTが通ったときだけ渡す順番になっています（過去ぶんのフラグ判定も残存）')

# --- C2 の結果検証 ---
r2 = route('/api/student/class-mission/:id/claim')
i_lock = r2.index('INSERT OR IGNORE INTO class_mission_claims')
i_apply = r2.index('state.coins = (Number(state.coins) || 0) + rewardCoins')
if not (i_lock < i_apply):
    fail('ミッション: 枠の確保がコイン加算より後ろにあります')
if r2.count('INSERT OR IGNORE INTO class_mission_claims') != 1:
    fail('ミッション: 台帳への INSERT が %d 箇所（1箇所のはず）' % r2.count('INSERT OR IGNORE INTO class_mission_claims'))
if 'DELETE FROM class_mission_claims' not in r2:
    fail('ミッション: 加算失敗時の枠の解放がありません')
print('🔎 C2: 枠の確保 → 加算 → 失敗時は解放、の順番になっています')

# --- DDL がリクエスト経路の外（起動時）に漏れていないこと ---
g0 = src.index('let _adminChecked = false')
g1 = src.index('// -------------------- DB migration', g0)
mid = src[g0:g1]
for bad in ['CREATE INDEX', 'homework_claims', 'ensureHomeworkClaimTable']:
    for l in mid.split('\n'):
        if bad in l and not l.strip().startswith('//'):
            fail('起動時ミドルウェアに %s が入っています' % bad)
print('🔎 起動時ミドルウェアに DDL は入っていません')

if src.count('async function ensureHomeworkClaimTable(') != 1:
    fail('ensureHomeworkClaimTable の定義が %d 個' % src.count('async function ensureHomeworkClaimTable('))
if src.count('await ensureHomeworkClaimTable(') != 1:
    fail('ensureHomeworkClaimTable の呼び出しが %d 箇所（claim の中だけのはず）' % src.count('await ensureHomeworkClaimTable('))
print('🔎 台帳テーブルの用意は claim の中でだけ呼ばれます')

# --- 壊していないこと ---
for must in ["app.post('/api/homework/:id/claim'", "app.post('/api/student/class-mission/:id/claim'",
             'async function ensureHomeworkRewardTable(', 'INSERT INTO homework_rewards',
             "app.post('/api/teacher/homework/:id/return'", 'const editOnly = (body && body.editOnly === true)',
             "c.req.query('unreturned')", 'id="hwAllUnreturnedBtn"',
             'reward_claimed', 'not_returned_yet']:
    if must not in src: fail('★残すはずのものが失われました: %s' % must)
print('🔎 先生ボーナスの台帳・返却まわり・家庭学習の新機能は無傷です')

# --- 防衛戦には触っていないこと（別セッションの担当） ---
import hashlib
def defense_area(t):
    a = t.index("async function ensureDefenseTables")
    b = t.index("app.post('/api/defense/reward-claim'")
    b = t.index('\n})\n', b) + 4
    return hashlib.md5(t[a:b].encode('utf-8')).hexdigest()
if defense_area(src) != defense_area(orig):
    fail('防衛戦のコードが変わっています（このパッチでは触らない約束です）')
print('🔎 防衛戦のコードには触れていません（md5 一致）')

def rc(t):
    a = t.index("app.get('/', async (c) => {"); b = t.index("app.get('/logout'", a)
    return t[a:b].count('.replace(')
if rc(src) != rc(orig): fail('置換チェーンの数が変わりました（%d → %d）' % (rc(orig), rc(src)))
print('🔎 置換チェーン: %d 件（変化なし）' % rc(src))

bal  = len(re.findall(r'<div\b', src))  - len(re.findall(r'</div>', src))
bal0 = len(re.findall(r'<div\b', orig)) - len(re.findall(r'</div>', orig))
if bal != bal0: fail('<div> の釣り合いが変わりました')
print('🔎 <div> の釣り合い: 変化なし')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました（%d → %d 文字）' % (len(orig), len(src)))
else:
    print('… 変更なし')
print('---- 入れたもの ----')
for t in done: print(' ・' + t)
if not done: print(' （なし）')
