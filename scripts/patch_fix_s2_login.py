#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
patch_fix_s2_login.py --- 総点検 第2陣(4) ログインの保護

【背景】
 ・/api/auth/login に試行回数の制限がまったく無い（rateLimit の対象外）。
 ・先生が配る仮パスワードは「単語15種 × 2桁 = 1,350通り」しかない。
   ログインIDが分かれば総当たりで他の子のアカウントに入れる＝その子の
   ゲームデータ・家庭学習・ふりかえり・先生とのやりとりが全部見える。

【この修正】
 V1 仮パスワードを「単語1つ + 3桁」にする。形は今までどおりで通り数だけ増やす。
    ・単語を15→30語に増やす（すべて小文字ローマ字。l は無い）
    ・数字は 2〜9 だけを使う（0/1 を出さないので o/0・l/1 の取り違えが起きない）
    ・rn が m に見える並びを持つ単語は入れない
    → 30 × 8^3 = 15,360通り（旧 1,350通りの約11倍）
    既存のパスワードには一切触らない。次に先生がリセットしたときから新しい形になる。

 V2 試行制限のヘルパーを追加する。台帳は D1 の login_attempts。
    ★ このパッチはテーブルを作らない。DDL は人が別途流す。
      ログインは全児童が毎朝叩く経路なので、リクエストの中で DDL を走らせない
      （2026-09 に app.use('*') の CREATE INDEX の await で本番が落ちた事故と同じ型を避ける）。
    ★ テーブルが無い/読めない場合は必ず「ロックしない」側に倒す（fail open）。
      ロックが効かないことより、ログインできないことのほうが実害が大きい。

 V3 login 本体に組み込む。順番が大事:
      アカウントを特定 → ロック確認 → （ロック中なら照合せずに返す）→ 照合 → 失敗を記録／成功で消す
    ロック中は照合そのものを行わないので、子どもが何回押してもロックは延びない。
    数えるキーは入力値ではなく保存側の login_id。全角/半角のゆれで別カウントになるのを防ぐ。

 V4 児童の画面に「あと何分待てばよいか」を出す。
    「入れません」だけだと繰り返し押してしまうので、待ち時間と
    「押してもここは延びない」ことを明示する。

 V5-V7 パスワードを再設定したらロックも解除する。
    これが無いと、先生が「パスワードを直したのに入れない」で詰まる。
    ・管理者の再設定 /api/admin/reset-password/:id
    ・先生の再設定   /api/teacher/reset-student-password/:studentId
    ・先生の一括復旧 /api/teacher/recovery/bulk-reset  ← 一番使われる導線

public/index.html は触りません。
冪等（2回流しても安全）。sentinel と検証用アンカーは別文字列。
"""
import io, os, sys

STEPS = [
 {
  "tag": "V1 仮パスワードを 単語1つ+3桁(2-9) にする",
  "sen": "LOGIN_PW_WORDS",
  "old": """function genKidPassword(): string {
  const words = ['sora','hana','mori','kaze','yama','umi','tori','hoshi','niji','yuki','tuki','kawa','sakura','ringo','nami']
  const a = new Uint32Array(2); crypto.getRandomValues(a)
  return words[a[0] % words.length] + String(10 + (a[1] % 90))
}
""",
  "new": """// 子どもが読めて打てることを最優先にした単語リスト（30語）。
// ・すべて小文字のローマ字。l（エル）は使わない＝1 と見間違えない
// ・rn（m に見える）が並ぶ語を入れない
const LOGIN_PW_WORDS = [
  'sora', 'hana', 'mori', 'kaze', 'yama', 'umi', 'tori', 'hoshi', 'niji', 'yuki',
  'tsuki', 'kawa', 'sakura', 'ringo', 'nami', 'kumo', 'hato', 'sakana', 'kame', 'usagi',
  'tanuki', 'kitsune', 'momo', 'ichigo', 'budou', 'mikan', 'panda', 'koara', 'zou', 'kirin'
]
function genKidPassword(): string {
  // 数字は 2〜9 のみ。0 と 1 を出さないので o/0・l/1 の取り違えが起きない。
  // 30語 × 8^3 = 15,360通り（旧: 15語 × 90 = 1,350通り）
  const a = new Uint32Array(4); crypto.getRandomValues(a)
  const d = (n: number) => String(2 + (a[n] % 8))
  return LOGIN_PW_WORDS[a[0] % LOGIN_PW_WORDS.length] + d(1) + d(2) + d(3)
}
""",
 },
 {
  "tag": "V2 試行制限のヘルパーを追加（fail open）",
  "sen": "async function loginLockRemainingMs(",
  "old": """const _recoverAttempts = new Map<string, { n: number, t: number }>()
""",
  "new": """const _recoverAttempts = new Map<string, { n: number, t: number }>()

// -------------------- ログインの試行制限（総当たり対策） --------------------
// 台帳は D1 の login_attempts。DDL はこのコードでは作らない（人が別途適用する）。
// ログインは全児童が毎朝叩く経路なので、リクエストの中で DDL を走らせない。
// テーブルが無い・読めない場合は必ず「ロックしない」側に倒す（fail open）。
const LOGIN_MAX_FAILS = 10                       // 打ち間違いの多い低学年でも届かない回数
const LOGIN_LOCK_MS = 15 * 60 * 1000             // ロックする長さ
const LOGIN_FAIL_WINDOW_MS = 60 * 60 * 1000      // 失敗を数えるさかのぼり範囲

// ロック中なら残りミリ秒、そうでなければ 0。何かあっても 0（＝通す）。
async function loginLockRemainingMs(env: any, loginId: string): Promise<number> {
  try {
    const r = await env.DB.prepare('SELECT locked_until FROM login_attempts WHERE login_id=? LIMIT 1')
      .bind(loginId).first<any>()
    const until = Number(r && r.locked_until) || 0
    const left = until - Date.now()
    return left > 0 ? left : 0
  } catch (e) { return 0 }
}

// 失敗を1件数える。しきい値に達したらロックする。何かあっても握りつぶす。
async function loginRecordFail(env: any, loginId: string): Promise<void> {
  try {
    const now = Date.now()
    const r = await env.DB.prepare('SELECT fail_count, first_fail_at, locked_until FROM login_attempts WHERE login_id=? LIMIT 1')
      .bind(loginId).first<any>()
    // 前のロックが明けていたら、そこで数え直す。
    // これをしないと「ロックが明けた直後の1回の打ち間違い」で即また15分ロックされる。
    const prevLocked = Number(r && r.locked_until) || 0
    const lockExpired = prevLocked > 0 && prevLocked <= now
    const firstAt = Number(r && r.first_fail_at) || 0
    const inWindow = !!r && !lockExpired && (now - firstAt < LOGIN_FAIL_WINDOW_MS)
    const count = inWindow ? (Number(r.fail_count) || 0) + 1 : 1
    const startedAt = inWindow ? (firstAt || now) : now
    const lockedUntil = count >= LOGIN_MAX_FAILS ? now + LOGIN_LOCK_MS : 0
    await env.DB.prepare(
      `INSERT INTO login_attempts (login_id, fail_count, first_fail_at, last_fail_at, locked_until)
       VALUES (?,?,?,?,?)
       ON CONFLICT(login_id) DO UPDATE SET
         fail_count=excluded.fail_count, first_fail_at=excluded.first_fail_at,
         last_fail_at=excluded.last_fail_at, locked_until=excluded.locked_until`
    ).bind(loginId, count, startedAt, now, lockedUntil).run()
  } catch (e) {}
}

// ログインできた／パスワードを直した。台帳を消す。何かあっても握りつぶす。
async function loginClearFails(env: any, loginId: string): Promise<void> {
  try {
    if (!loginId) return
    await env.DB.prepare('DELETE FROM login_attempts WHERE login_id=?').bind(loginId).run()
  } catch (e) {}
}
""",
 },
 {
  "tag": "V3 login 本体にロック確認と記録を組み込む",
  "sen": "const _lockLeft = await loginLockRemainingMs(",
  "old": """  if (!row) return jsonError(c, 401, 'invalid_credentials')

  const calc = await pbkdf2Hash(password, row.salt)
  if (calc !== row.hash) return jsonError(c, 401, 'invalid_credentials')
""",
  "new": """  if (!row) return jsonError(c, 401, 'invalid_credentials')

  // 数えるキーは入力値ではなく保存側の login_id。
  // 全角「１３２８」と半角「1328」で別カウントになるのを防ぐ。
  const _lockKey = String(row.loginId || loginId)
  const _lockLeft = await loginLockRemainingMs(c.env, _lockKey)
  if (_lockLeft > 0) {
    // ロック中は照合そのものを行わない＝何回押してもロックは延びない
    return c.json({
      ok: false, error: 'too_many_attempts',
      retryAfterSec: Math.ceil(_lockLeft / 1000),
      retryAfterMin: Math.max(1, Math.ceil(_lockLeft / 60000)),
    }, 429)
  }

  const calc = await pbkdf2Hash(password, row.salt)
  if (calc !== row.hash) {
    await loginRecordFail(c.env, _lockKey)
    return jsonError(c, 401, 'invalid_credentials')
  }
  await loginClearFails(c.env, _lockKey)
""",
 },
 {
  "tag": "V4 ログイン画面に「あと何分」を出す",
  # sentinel は V3 の挿入内容（too_many_attempts）と重ならない、V4 固有の文言にする
  "sen": "まちがえた回数が おおいので",
  "old": """          const errMap = {
            invalid_credentials: 'IDまたはパスワードが間違っています',
            pending_approval: '承認待ちです。管理者の承認をお待ちください',
            missing_credentials: 'IDとパスワードを入力してください',
          };
          msg.textContent = errMap[j.error] || (j.error || 'ログインに失敗しました');
""",
  "new": """          const errMap = {
            invalid_credentials: 'IDまたはパスワードが間違っています',
            pending_approval: '承認待ちです。管理者の承認をお待ちください',
            missing_credentials: 'IDとパスワードを入力してください',
          };
          if(j.error === 'too_many_attempts'){
            const m = Number(j.retryAfterMin) || 15;
            msg.textContent = 'まちがえた回数が おおいので、いまは ログインできません。'
              + 'あと ' + m + ' 分 まってから、もう一度 ためしてね。'
              + '（ここで なんかい おしても、まつ時間は のびません）'
              + ' いそぐときは 先生に 言ってね。';
            return;
          }
          msg.textContent = errMap[j.error] || (j.error || 'ログインに失敗しました');
""",
 },
 {
  "tag": "V5 管理者のパスワード再設定でロックも解除",
  "sen": "// 直したのに入れない、を作らない（管理者）",
  "old": """    .bind(hash, salt, id)
    .run()

  return c.json({ ok: true, tempPassword: temp })
})
""",
  "new": """    .bind(hash, salt, id)
    .run()

  // 直したのに入れない、を作らない（管理者）
  try {
    const _t = await c.env.DB.prepare(`SELECT login_id as loginId FROM users WHERE id=? LIMIT 1`).bind(id).first<any>()
    if (_t && _t.loginId) await loginClearFails(c.env, String(_t.loginId))
  } catch (e) {}

  return c.json({ ok: true, tempPassword: temp })
})
""",
 },
 {
  "tag": "V6 先生のパスワード再設定でロックも解除",
  "sen": "// 直したのに入れない、を作らない（先生・個別）",
  "old": """  const target = await c.env.DB.prepare(`SELECT id, role FROM users WHERE id = ? LIMIT 1`).bind(studentId).first<any>()""",
  "new": """  const target = await c.env.DB.prepare(`SELECT id, role, login_id as loginId FROM users WHERE id = ? LIMIT 1`).bind(studentId).first<any>()
  // 直したのに入れない、を作らない（先生・個別）※解除は下の UPDATE の後""",
 },
 {
  "tag": "V6b 先生のパスワード再設定：解除の実行",
  "sen": "await loginClearFails(c.env, String(target.loginId))",
  "old": """  ).bind(hash, salt, studentId).run()
  return c.json({ ok: true, tempPassword: newPassword })
})
""",
  "new": """  ).bind(hash, salt, studentId).run()
  if (target.loginId) await loginClearFails(c.env, String(target.loginId))
  return c.json({ ok: true, tempPassword: newPassword })
})
""",
 },
 {
  "tag": "V7 先生の一括復旧でロックも解除",
  "sen": "// 直したのに入れない、を作らない（先生・一括）",
  "old": """    ).bind(hash, salt, s.userId).run()
    results.push({ userId: s.userId, loginId: String(s.loginId == null ? '' : s.loginId), name: s.name || '', newPassword })
""",
  "new": """    ).bind(hash, salt, s.userId).run()
    // 直したのに入れない、を作らない（先生・一括）
    await loginClearFails(c.env, String(s.loginId == null ? '' : s.loginId))
    results.push({ userId: s.userId, loginId: String(s.loginId == null ? '' : s.loginId), name: s.name || '', newPassword })
""",
 },
]

MUST = [
 "app.post('/api/auth/login'",
 "app.post('/api/admin/reset-password/:id'",
 "app.post('/api/teacher/reset-student-password/:studentId'",
 "app.post('/api/teacher/recovery/bulk-reset'",
 "function genKidPassword(): string {",
 "const calc = await pbkdf2Hash(password, row.salt)",
 "pending_approval: '承認待ちです。管理者の承認をお待ちください',",
 "LOGIN_MAX_FAILS = 10",
 "LOGIN_LOCK_MS = 15 * 60 * 1000",
]

BAD = [
 # DDL をリクエスト経路で作らないこと（今回の一番大事な約束）
 "CREATE TABLE IF NOT EXISTS login_attempts",
 "CREATE INDEX IF NOT EXISTS idx_login_attempts",
 # 旧パスワード生成
 "String(10 + (a[1] % 90))",
 "'tuki'",
 # 旧: 失敗を記録せずに返していた行
 "if (calc !== row.hash) return jsonError(c, 401, 'invalid_credentials')",
]


def main():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tsx = os.path.join(root, 'src', 'index.tsx')
    src = io.open(tsx, encoding='utf-8', newline='').read()
    orig = src
    changes = []

    def fail(msg):
        print('❌ 中止: ' + msg)
        sys.exit(1)

    if '\r\n' in src:
        fail('src/index.tsx に CRLF が混ざっています（LF のはず）')

    for st in STEPS:
        if st['sen'] in src:
            print('⏭ %s は適用済み（スキップ）' % st['tag']); continue
        n = src.count(st['old'])
        if n == 0: fail('%s のアンカーが見つかりません' % st['tag'])
        if n != 1: fail('%s のアンカーが %d 箇所（1箇所のはず）' % (st['tag'], n))
        src = src.replace(st['old'], st['new'], 1)
        changes.append(st['tag'])

    def root_replace_count(text):
        a = text.index("app.get('/', async (c) => {")
        b = text.index("app.get('/logout'", a)
        return text[a:b].count('.replace(')

    if root_replace_count(orig) != root_replace_count(src):
        fail('本番HTMLの置換チェーンの数が変わりました（%d -> %d）'
             % (root_replace_count(orig), root_replace_count(src)))
    print('\U0001f50e 置換チェーン: %d 件（適用前後で同数）' % root_replace_count(src))

    for m in MUST:
        if m not in src: fail('必須の要素が失われました: %s' % m)
    for x in BAD:
        if x in src: fail('あってはいけないコードが入っています: %s' % x)

    # login_attempts に触るのは、追加した3つのヘルパーの中だけであること
    helper_names = ['loginLockRemainingMs', 'loginRecordFail', 'loginClearFails']
    # 見出しコメント1 + SELECT2 + INSERT1 + DELETE1 = 5。
    # これ以外の場所（＝ヘルパーの外）から login_attempts に触っていないことの確認。
    if src.count('login_attempts') != 5:
        fail('login_attempts に触る箇所が 5 ではありません（%d）。ヘルパー外から触っていないか確認' % src.count('login_attempts'))
    if src.count('async function loginLockRemainingMs(') != 1: fail('loginLockRemainingMs の定義が1つではない')
    if src.count('async function loginRecordFail(') != 1: fail('loginRecordFail の定義が1つではない')
    if src.count('async function loginClearFails(') != 1: fail('loginClearFails の定義が1つではない')
    # 解除の呼び出しは 4 箇所（login成功 / 管理者 / 先生個別 / 先生一括）＋定義1
    if src.count('loginClearFails(') != 5:
        fail('loginClearFails の呼び出し数がおかしい（%d、定義1+呼び出し4のはず）' % src.count('loginClearFails('))
    # 単語リストは30語
    import re as _re
    m = _re.search(r'const LOGIN_PW_WORDS = \[(.*?)\]', src, _re.S)
    if not m: fail('LOGIN_PW_WORDS が見つかりません')
    words = _re.findall(r"'([a-z]+)'", m.group(1))
    if len(words) != 30: fail('単語が30語ではありません（%d）' % len(words))
    if len(set(words)) != 30: fail('単語に重複があります')
    for w in words:
        if 'l' in w: fail('l を含む単語があります: %s' % w)
        if 'rn' in w: fail('rn を含む単語があります: %s' % w)

    if src != orig:
        io.open(tsx, 'w', encoding='utf-8', newline='').write(src)
        print('✅ src/index.tsx を更新しました')
    else:
        print('… 変更なし')
    print('---- 適用した項目 ----')
    for ch in changes: print(' ・' + ch)
    if not changes: print(' （なし）')


if __name__ == '__main__':
    main()
