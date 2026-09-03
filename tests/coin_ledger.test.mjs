// コイン台帳の統合テスト
//   - D1 は node:sqlite で再現する（本番DBには一切つながない）
//   - 実際のハンドラ（src/index.tsx を esbuild でバンドルしたもの）を app.fetch でそのまま呼ぶ
//
//   使い方:  node tests/coin_ledger.test.mjs ./app.after.mjs
//            node tests/coin_ledger.test.mjs ./app.before.mjs   ← 修正前の再現用
import { FakeD1, SCHEMA } from './d1.mjs'

const BUNDLE = process.argv[2] || './app.after.mjs'
const SECRET = 'test-session-secret'
let _instance = 0

// ── セッション Cookie を本物と同じ形式で作る（v1.<payloadB64u>.<sigB64u>）──
function b64u(buf) {
  return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
async function makeSession(payload) {
  const enc = new TextEncoder()
  const data = b64u(enc.encode(JSON.stringify(payload)))
  const key = await crypto.subtle.importKey('raw', enc.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data))
  return `v1.${data}.${b64u(new Uint8Array(sig))}`
}

// ── 1テスト＝1つの新しい世界（DBもモジュールの状態も使い回さない）──
async function newWorld() {
  const db = new FakeD1()
  db.db.exec(SCHEMA)
  const mod = await import(`${BUNDLE}?i=${++_instance}`)
  const app = mod.default
  const env = { DB: db, SESSION_SECRET: SECRET, ADMIN_LOGIN_ID: '', ADMIN_PASSWORD: '', AI: null }

  async function call(method, path, { user, body } = {}) {
    const headers = { 'content-type': 'application/json' }
    if (user) headers['cookie'] = 'session=' + (await makeSession({ id: user.id, role: user.role, loginId: user.loginId || user.id, isActive: true, iat: Math.floor(Date.now() / 1000) }))
    const req = new Request('https://test.local' + path, {
      method, headers, body: body === undefined ? undefined : JSON.stringify(body),
    })
    const res = await app.fetch(req, env, { waitUntil() {}, passThroughOnException() {} })
    let json = null
    try { json = await res.clone().json() } catch (_e) {}
    return { status: res.status, json }
  }

  // 児童・先生・クラス・提出をひととおり用意する
  const student = { id: 'stu-1', role: 'student', loginId: 'kid1' }
  const teacher = { id: 'tea-1', role: 'teacher', loginId: 'sensei' }
  db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", student.id, 'student', 'kid1', 'たろう', 3, '3-1')
  db._run("INSERT INTO teacher_accounts (id, login_id, name, school) VALUES (?,?,?,?)", teacher.id, 'sensei', 'せんせい', 'テスト小')
  db._run("INSERT INTO classes (id, teacher_id, name) VALUES (?,?,?)", 'cls-1', teacher.id, '3年1組')
  db._run("INSERT INTO class_members (class_id, user_id) VALUES (?,?)", 'cls-1', student.id)
  db._run("INSERT INTO homework_submissions (id, user_id, class_id, title) VALUES (?,?,?,?)", 'hw-1', student.id, 'cls-1', 'さんすう')

  function setState(obj) {
    db._run("INSERT INTO progress (user_id, state_json, updated_at) VALUES (?,?,datetime('now')) ON CONFLICT(user_id) DO UPDATE SET state_json=excluded.state_json", student.id, JSON.stringify(obj))
  }
  function getState() {
    const r = db._get('SELECT state_json FROM progress WHERE user_id=?', student.id)
    return r ? JSON.parse(r.state_json) : null
  }
  return { db, call, student, teacher, setState, getState }
}

// 「本物のプレイ済みデータ」の形（回帰ガードの条件 pokedex>=15 かつ length>=40000 を満たす）
function bigState(extra = {}) {
  return {
    coins: 1000, level: 20,
    pokedex: Array.from({ length: 30 }, (_, i) => i + 1),
    filler: 'x'.repeat(45000),
    ...extra,
  }
}
// 小さいデータ（回帰ガードの対象外。コイン処理そのものを見るとき用）
function smallState(extra = {}) {
  return { coins: 1000, level: 20, pokedex: [1, 2, 3], ...extra }
}

// ── テスト本体 ────────────────────────────────────────────────
const results = []
async function t(name, fn) {
  try { await fn(); results.push({ name, ok: true, note: '' }) }
  catch (e) { results.push({ name, ok: false, note: String(e && e.message || e).split('\n')[0].slice(0, 140) }) }
}
function eq(actual, expected, what) {
  if (actual !== expected) throw new Error(`${what}: expected ${expected}, got ${actual}`)
}
function ok(cond, what) { if (!cond) throw new Error(what) }

// 1) シール券：正常に1回使う
await t('1 シール券を300コインで1回買える（コイン-300・台帳300・券1枚）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const r = await w.call('POST', '/api/shop/sticker/buy', { user: w.student })
  eq(r.status, 200, 'status')
  eq(r.json.coins, 700, 'レスポンスのコイン')
  eq(r.json.serverSpentCoins, 300, 'レスポンスの支払い台帳')
  const s = w.getState()
  eq(s.coins, 700, 'DBのコイン')
  eq(s._serverSpentCoins, 300, 'DBの支払い台帳')
  eq(w.db._all('SELECT id FROM sticker_vouchers').length, 1, '券の枚数')
})

// 2) 宿題返却：正常に1回付与される
await t('2 宿題返却で150コイン付与（成果物ありは250）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const r = await w.call('POST', '/api/teacher/homework/hw-1/return', { user: w.teacher, body: { comment: 'よくできました' } })
  eq(r.status, 200, 'status')
  const s = w.getState()
  eq(s.coins, 1150, 'DBのコイン')
  eq(s._hwCoinsApplied, 150, 'DBの付与台帳')

  const w2 = await newWorld()
  w2.setState(smallState({ coins: 1000 }))
  await w2.call('POST', '/api/teacher/homework/hw-1/return', { user: w2.teacher, body: { comment: 'ok', hasPhysical: true } })
  eq(w2.getState().coins, 1250, '成果物ありのコイン')
  eq(w2.getState()._hwCoinsApplied, 250, '成果物ありの台帳')
})

// 3) 古い端末がコイン残高を巻き戻して保存（シール券）
await t('3 古い端末が購入前の残高で保存 → サーバが300を引き直す（シール券）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  await w.call('POST', '/api/shop/sticker/buy', { user: w.student })
  eq(w.getState().coins, 700, '購入直後')
  // 購入を知らない端末が「coins:1000・台帳なし」で全置換保存してくる
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1000 }) } })
  const s = w.getState()
  eq(s.coins, 700, '巻き戻し後のコイン（復活していないこと）')
  eq(s._serverSpentCoins, 300, '台帳が保持されていること')
})

// 4) 古い端末がコイン残高を巻き戻して保存（宿題ボーナス）
await t('4 古い端末が付与前の残高で保存 → サーバが150を補填する（宿題）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  await w.call('POST', '/api/teacher/homework/hw-1/return', { user: w.teacher, body: { comment: 'ok' } })
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1000 }) } })
  const s = w.getState()
  eq(s.coins, 1150, '補填後のコイン')
  eq(s._hwCoinsApplied, 150, '台帳')
  // 何度保存してもズレない（同じ端末が2回保存しても加算が積み上がらない）
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1010 }) } })
  eq(w.getState().coins, 1160, '2回目の保存でも積み上がらない')
})

// 5) 台帳の水増し（シール券）— サーバは何も返金しない
await t('5 クライアントが支払い台帳を水増し → 返金されない・台帳はサーバ値に戻る', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  await w.call('POST', '/api/shop/sticker/buy', { user: w.student })
  // 「もう99999払った」と申告して、コインを取り戻そうとする
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 700, _serverSpentCoins: 99999 }) } })
  const s = w.getState()
  eq(s.coins, 700, 'コインが増えていないこと')
  eq(s._serverSpentCoins, 300, '台帳がサーバの値に戻っていること')
})

// 6) 台帳の水増し（宿題）— サーバは何も足さない
await t('6 クライアントが付与台帳を水増し → コインは足されない・台帳はサーバ値に戻る', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  await w.call('POST', '/api/teacher/homework/hw-1/return', { user: w.teacher, body: { comment: 'ok' } })
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1150, _hwCoinsApplied: 99999 }) } })
  const s = w.getState()
  eq(s.coins, 1150, 'コインが増えていないこと')
  eq(s._hwCoinsApplied, 150, '台帳がサーバの値に戻っていること')
})

// 7) 連打・二重購入（シール券）
await t('7 シール券を同じ日に2回買えない（連打しても300しか引かれない）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const rs = await Promise.all([0, 1, 2, 3].map(() => w.call('POST', '/api/shop/sticker/buy', { user: w.student })))
  eq(rs.filter((r) => r.status === 200).length, 1, '成功した回数')
  eq(w.db._all('SELECT id FROM sticker_vouchers').length, 1, '券の枚数')
  eq(w.getState().coins, 700, 'コイン')
  eq(w.getState()._serverSpentCoins, 300, '台帳')
})

// 8) 連打・二重付与（宿題返却）
await t('8 宿題返却を2回押しても150しか付かない（台帳は1行）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  await w.call('POST', '/api/teacher/homework/hw-1/return', { user: w.teacher, body: { comment: 'ok' } })
  await w.call('POST', '/api/teacher/homework/hw-1/return', { user: w.teacher, body: { comment: 'なおしました' } })
  await w.call('POST', '/api/teacher/homework/hw-1/return', { user: w.teacher, body: { comment: 'もういちど' } })
  const s = w.getState()
  eq(s.coins, 1150, 'コイン')
  eq(s._hwCoinsApplied, 150, '台帳の累計')
  eq(w.db._all('SELECT submission_id FROM homework_rewards').length, 1, 'homework_rewards の行数')
})

// 9) 既存の回帰ガード（後退保存のスキップ）が依然として働く
await t('9 既存の回帰ガード：後退した保存はスキップされ、本物のデータが守られる', async () => {
  const w = await newWorld()
  w.setState(bigState({ coins: 1000 }))
  const r = await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: { coins: 5, level: 1, pokedex: [1] } } })
  eq(r.status, 200, 'status')
  eq(r.json.skipped, 'regression_guard', 'ガードが働いたこと')
  const s = w.getState()
  eq(s.pokedex.length, 30, 'ずかんが守られたこと')
  eq(s.coins, 1000, 'コインが守られたこと')
})

// 10) 回帰ガードとコイン補填の共存（ガードが先・コインは二重処理されない）
await t('10 回帰ガードとコイン処理の共存：ガード発動時にコインが二重に動かない', async () => {
  const w = await newWorld()
  w.setState(bigState({ coins: 1000 }))
  await w.call('POST', '/api/shop/sticker/buy', { user: w.student })
  eq(w.getState().coins, 700, '購入直後')
  // 大幅に後退した保存 → ガードでスキップされ、コインも台帳もそのまま
  const r = await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: { coins: 1000, level: 1, pokedex: [1] } } })
  eq(r.json.skipped, 'regression_guard', 'ガードが働いたこと')
  eq(w.getState().coins, 700, 'コインが二重に引かれていないこと')
  eq(w.getState()._serverSpentCoins, 300, '台帳')
  // 後退していない普通の保存では、ちゃんと支払いが反映される
  const s2 = bigState({ coins: 1000 })
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: s2 } })
  eq(w.getState().coins, 700, '通常保存では支払いが反映されること')
})

// 11) 購入した端末が二重に引かれない（sticker.js の台帳ミラーを再現）
await t('11 購入した端末は二重に引かれない（購入直後の台帳ミラーが効く）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const r = await w.call('POST', '/api/shop/sticker/buy', { user: w.student })
  // sticker.js は applyCoins(res.coins) と _serverSpentCoins のミラーを行う
  const client = smallState({ coins: r.json.coins, _serverSpentCoins: r.json.serverSpentCoins })
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: client } })
  eq(w.getState().coins, 700, '二重に引かれていないこと')
})

// 12) 既存の台帳（連絡帳コイン・MI・ランキングかけら）の補填が壊れていない
await t('12 既存の補填（連絡帳・MI・かけら）が壊れていない', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000, _contactCoinsApplied: 50, _miCoinsApplied: 200, _rankShardsApplied: 7, lab: { shards: 7, use: {} } }))
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1000, lab: { shards: 0, use: {} } }) } })
  const s = w.getState()
  eq(s.coins, 1250, '連絡帳50 + MI200 が補填されたコイン')
  eq(s._contactCoinsApplied, 50, '連絡帳台帳')
  eq(s._miCoinsApplied, 200, 'MI台帳')
  eq(s.lab.shards, 7, 'かけらの補填')
})

// ── 結果表 ────────────────────────────────────────────────────
const pass = results.filter((r) => r.ok).length
console.log('\n=== ' + BUNDLE + ' ===')
for (const r of results) console.log((r.ok ? 'PASS' : 'FAIL') + ' | ' + r.name + (r.note ? ' | ' + r.note : ''))
console.log(`\n${pass}/${results.length} passed`)
console.log('JSONRESULT ' + JSON.stringify(results))
process.exit(pass === results.length ? 0 : 1)
