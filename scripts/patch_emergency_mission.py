#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_emergency_mission.py --- 【緊急】クラス共同ミッションの進捗集計がD1を食い尽くしている件

■ 何が起きていたか
  児童がアプリを開くと 4.2 秒後に updateRewardBadge() が自動で走り、
  /api/student/class-mission を呼ぶ。この API は countMissionProgress() で

      SELECT COUNT(*) FROM learning_results lr
        JOIN class_members cm ON cm.user_id = lr.user_id AND cm.class_id = ?
        WHERE lr.is_correct = 1 AND lr.answered_at >= ?

  を実行する。これは「クラス全員 × ミッション開始日以降の全学習ログ」を読む。
  1クラス22人・1人2,000行なら 1回で約5万行。しかも条件によっては1リクエストで2回走る。
  → アプリを開くたびに数万行。書き込みが少ないのに読み取りだけ膨らむ形。

■ 応急処置（この修正）
  E1 進捗を D1 の小さなキャッシュ表に持たせ、10分以内なら再集計しない（isolateをまたいで効く）
  E2 いちど目標に到達したミッションは、以後いっさい再集計しない（done フラグ）
  E3 同じリクエスト内で2回集計していたのをやめる
  E4 isolate 内メモリにも60秒だけ持つ（連打対策）
  E5 起動時に不足している索引を作る（class_members には索引が1つも無かった）

  進捗の表示が最大10分古くなりますが、止まるよりずっとましなので応急処置として入れます。
"""
import io, os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSX  = os.path.join(ROOT, 'src', 'index.tsx')

src = io.open(TSX, encoding='utf-8').read()
orig = src
changes = []

def fail(msg):
    print('❌ 中止: ' + msg); sys.exit(1)

def rep(old, new, tag, sentinel=None):
    global src
    if sentinel is not None and sentinel in src:
        print('⏭  %s は適用済み（スキップ）' % tag); return
    n = src.count(old)
    if n == 0:
        if new and new in src:
            print('⏭  %s は適用済み（スキップ）' % tag); return
        fail('%s のアンカーが見つかりません' % tag)
    if n != 1:
        fail('%s のアンカーが %d 箇所（1箇所のはず）' % (tag, n))
    src = src.replace(old, new, 1)
    changes.append(tag)

# ---------------- E1〜E4: countMissionProgress をキャッシュ化 ----------------
OLD_FN = """async function countMissionProgress(c: any, classId: string, startAt: string, endAt: string | null): Promise<number> {
  let sql = `SELECT COUNT(*) AS cnt FROM learning_results lr
    JOIN class_members cm ON cm.user_id = lr.user_id AND cm.class_id = ?
    WHERE lr.is_correct = 1 AND lr.answered_at >= ?`
  const binds: any[] = [classId, startAt]
  if (endAt) { sql += ` AND lr.answered_at <= ?`; binds.push(endAt) }
  const row = await c.env.DB.prepare(sql).bind(...binds).first<any>()
  return Number(row?.cnt || 0)
}"""

NEW_FN = """// 🚨 2026-09-03 緊急対応: ここが D1 の読み取りを食い尽くしていた。
//   もとは「クラス全員 × ミッション開始日以降の全学習ログ」を毎回数える作りで、
//   児童がアプリを開くたび（updateRewardBadge が自動で走る）に数万行を読んでいた。
//   → ①10分キャッシュ ②達成後は二度と数えない ③同一リクエストで2回数えない、に変更。
const MISSION_TTL_MS = 600000
const _missionMem = new Map<string, { at: number, cnt: number }>()

async function ensureMissionCacheTable(env: any) {
  try {
    await env.DB.prepare(
      'CREATE TABLE IF NOT EXISTS class_mission_progress (mission_id TEXT PRIMARY KEY, cnt INTEGER, done INTEGER DEFAULT 0, updated_at TEXT)'
    ).run()
  } catch (e) {}
}

async function countMissionProgressRaw(c: any, classId: string, startAt: string, endAt: string | null): Promise<number> {
  let sql = `SELECT COUNT(*) AS cnt FROM learning_results lr
    JOIN class_members cm ON cm.user_id = lr.user_id AND cm.class_id = ?
    WHERE lr.is_correct = 1 AND lr.answered_at >= ?`
  const binds: any[] = [classId, startAt]
  if (endAt) { sql += ` AND lr.answered_at <= ?`; binds.push(endAt) }
  const row = await c.env.DB.prepare(sql).bind(...binds).first<any>()
  return Number(row?.cnt || 0)
}

//  missionId と goal を渡すと、キャッシュを使って進捗を返す。
//  goal に到達済みのミッションは、以後いっさい数え直さない。
async function countMissionProgress(c: any, classId: string, startAt: string, endAt: string | null,
                                    missionId?: string, goal?: number): Promise<number> {
  if (!missionId) return await countMissionProgressRaw(c, classId, startAt, endAt)

  const memKey = missionId
  const hit = _missionMem.get(memKey)
  if (hit && (Date.now() - hit.at) < 60000) return hit.cnt

  await ensureMissionCacheTable(c.env)
  let row: any = null
  try {
    row = await c.env.DB.prepare('SELECT cnt, done, updated_at FROM class_mission_progress WHERE mission_id=? LIMIT 1')
      .bind(missionId).first<any>()
  } catch (e) {}

  if (row) {
    // すでに目標に到達しているなら、もう数える必要がない
    if (Number(row.done) === 1) {
      const c1 = Number(row.cnt || 0)
      _missionMem.set(memKey, { at: Date.now(), cnt: c1 })
      return c1
    }
    const age = Date.now() - Date.parse(String(row.updated_at || '') + 'Z')
    if (isFinite(age) && age >= 0 && age < MISSION_TTL_MS) {
      const c2 = Number(row.cnt || 0)
      _missionMem.set(memKey, { at: Date.now(), cnt: c2 })
      return c2
    }
  }

  const cnt = await countMissionProgressRaw(c, classId, startAt, endAt)
  const done = (typeof goal === 'number' && goal > 0 && cnt >= goal) ? 1 : 0
  try {
    await c.env.DB.prepare(
      "INSERT INTO class_mission_progress (mission_id, cnt, done, updated_at) VALUES (?,?,?,datetime('now')) " +
      "ON CONFLICT(mission_id) DO UPDATE SET cnt=excluded.cnt, done=excluded.done, updated_at=datetime('now')"
    ).bind(missionId, cnt, done).run()
  } catch (e) {}
  if (_missionMem.size > 200) _missionMem.clear()
  _missionMem.set(memKey, { at: Date.now(), cnt })
  return cnt
}"""
rep(OLD_FN, NEW_FN, 'E1〜E4 ミッション進捗にキャッシュと達成後の打ち切りを追加',
    sentinel='const MISSION_TTL_MS')

# ---------------- E3: 同一リクエストで2回数えない ----------------
OLD_CALL = """    if (latest) {
      const prog = await countMissionProgress(c, cm.class_id, latest.startAt, latest.endAt)
      const alreadyClaimed = await c.env.DB.prepare(`SELECT 1 FROM class_mission_claims WHERE mission_id=? AND user_id=? LIMIT 1`).bind(latest.id, u.id).first<any>()
      if (prog >= latest.goalCorrect && !alreadyClaimed) {
        m = latest // 達成済み＆未受取 → 表示する
      }
    }
  }

  if (!m) return c.json({ ok: true, mission: null })
  const progress = await countMissionProgress(c, cm.class_id, m.startAt, m.endAt)"""
NEW_CALL = """    if (latest) {
      const prog = await countMissionProgress(c, cm.class_id, latest.startAt, latest.endAt, latest.id, latest.goalCorrect)
      const alreadyClaimed = await c.env.DB.prepare(`SELECT 1 FROM class_mission_claims WHERE mission_id=? AND user_id=? LIMIT 1`).bind(latest.id, u.id).first<any>()
      if (prog >= latest.goalCorrect && !alreadyClaimed) {
        m = latest // 達成済み＆未受取 → 表示する
        _preProgress = prog   // 🚨 同じリクエストで2回数えないように取っておく
      }
    }
  }

  if (!m) return c.json({ ok: true, mission: null })
  const progress = (_preProgress != null) ? _preProgress
    : await countMissionProgress(c, cm.class_id, m.startAt, m.endAt, m.id, m.goalCorrect)"""
rep(OLD_CALL, NEW_CALL, 'E3 同一リクエストで2回数えないようにする', sentinel='_preProgress')

rep("""app.get('/api/student/class-mission', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')""",
    """app.get('/api/student/class-mission', async (c) => {
  const u = c.get('user')
  if (!u) return jsonError(c, 401, 'unauthorized')
  let _preProgress: number | null = null""",
    'E3b 変数を用意', sentinel='let _preProgress')

# ---------------- E5: 足りない索引を起動時に作る ----------------
OLD_IDX = """  try {
    await c.env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_learning_results_user_time ON learning_results(user_id, answered_at)').run()
  } catch (e) {
    console.error('index ensure skipped:', (e as any)?.message || e)
  }"""
NEW_IDX = """  try {
    await c.env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_learning_results_user_time ON learning_results(user_id, answered_at)').run()
    // 🚨 2026-09-03: class_members には索引が1つも無かった。
    //    クラス全体を見る問い合わせ（ミッション進捗・リスク予測・分析）が全部ここを通る。
    await c.env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_class_members_class ON class_members(class_id, user_id)').run()
    await c.env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_class_members_user ON class_members(user_id)').run()
    await c.env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_contact_notes_class ON contact_notes(class_id, created_at)').run()
    await c.env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id, read_at)').run()
    await c.env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)').run()
  } catch (e) {
    console.error('index ensure skipped:', (e as any)?.message || e)
  }"""
rep(OLD_IDX, NEW_IDX, 'E5 足りない索引を起動時に作る', sentinel='idx_class_members_class')

# ---------------- 検証 ----------------
for must in ['const MISSION_TTL_MS = 600000', 'async function countMissionProgressRaw(',
             'async function countMissionProgress(', 'class_mission_progress',
             'idx_class_members_class', 'let _preProgress',
             "app.get('/api/student/class-mission'", "app.post('/api/student/class-mission/:id/claim'"]:
    if must not in src: fail('必須の要素がありません: %s' % must)

# 重い集計を直接呼んでいる箇所が、キャッシュ経由になっているか
raw = src.count('countMissionProgressRaw(c,')
if raw != 2:   # 定義の中の呼び出し1 + キャッシュ無しフォールバック1
    fail('countMissionProgressRaw の呼び出しが %d 箇所（2箇所のはず）' % raw)
print('🔎 重い集計 countMissionProgressRaw は、キャッシュ関数の中からしか呼ばれません')

# class-mission ルートの中で、missionId を渡さずに呼んでいないこと
j = src.index("app.get('/api/student/class-mission'")
e = src.find('\n})\n', j)
route = src[j:e]
import re as _re
for m in _re.finditer(r'countMissionProgress\(([^)]*)\)', route):
    args = m.group(1)
    if args.count(',') < 4:
        fail('class-mission の中に、キャッシュを使わない呼び出しが残っています: %s' % args[:80])
print('🔎 class-mission API の集計は、すべてキャッシュ付きで呼ばれています')

def root_replace_count(text):
    a = text.index("app.get('/', async (c) => {")
    b = text.index("app.get('/logout'", a)
    return text[a:b].count('.replace(')
if root_replace_count(src) != root_replace_count(orig):
    fail('置換チェーンの数が変わりました')
print('🔎 置換チェーン: %d 件（変化なし）' % root_replace_count(src))

bal = lambda s: len(_re.findall(r'<div\b', s)) - len(_re.findall(r'</div>', s))
if bal(src) != bal(orig): fail('<div> の釣り合いが変わりました')
print('🔎 <div> の釣り合い: 変化なし')

if src != orig:
    io.open(TSX, 'w', encoding='utf-8', newline='').write(src)
    print('✅ src/index.tsx を更新しました')
else:
    print('… 変更なし')
print('---- 適用 ----')
for c in changes: print(' ・' + c)
if not changes: print(' （なし）')
