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

// ── 🐯 阪神マンのしつもん（HANSHIN_Q_V1）────────────────────────
//   公開したカルテの「▼考えてほしいこと」に答えると、しつもん1つにつき1回だけ 30コイン。
function publishKarte(w, id = 'kq-1', who = null) {
  const body = 'よう がんばったな。\n\n▼考えてほしいこと\n木曜にとけたとき、9月と何がちがったんやろ？\n▼これやってみる？\n・水曜に わり算 3問 やってみる？'
  w.db._run("INSERT INTO ai_review_drafts (id, teacher_id, class_id, week_key, kind, target_id, body, status, created_at, published_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'),datetime('now'))",
    id, w.teacher.id, 'cls-1', '2026-W42', 'KARTE', who || w.student.id, body, 'published')
}

await t('13 しつもんに5文字以上で答える → 30コイン・台帳1行・しつもんは▼から取る', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  publishKarte(w)
  const q = await w.call('GET', '/api/student/hanshin-question', { user: w.student })
  eq(q.status, 200, 'status')
  eq(q.json.question.text, '木曜にとけたとき、9月と何がちがったんやろ？', 'しつもんの文')
  const r = await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: 'ゆっくり書いたから' } })
  eq(r.status, 200, 'status')
  eq(r.json.rewardedNow, true, '今回付与')
  const s = w.getState()
  eq(s.coins, 1030, 'DBのコイン')
  eq(s._hanshinCoinsApplied, 30, 'DBの付与台帳')
  eq(w.db._all('SELECT * FROM hanshin_answer_rewards').length, 1, '台帳の行数')
})

await t('14 連打・書きなおし・同時送信でも30しか付かない（答えは最新に上書き）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  publishKarte(w)
  await Promise.all([0, 1, 2, 3].map((i) => w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: 'こたえ その' + i } })))
  await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: 'かきなおした こたえ' } })
  const s = w.getState()
  eq(s.coins, 1030, 'コイン')
  eq(s._hanshinCoinsApplied, 30, '台帳の累計')
  eq(w.db._all('SELECT * FROM hanshin_answer_rewards').length, 1, '台帳の行数')
  eq(w.db._get('SELECT answer FROM hanshin_answers WHERE question_id=?', 'kq-1').answer, 'かきなおした こたえ', '答えは最新')
})

await t('15 4文字以下は保存だけ（コインなし）→ あとで5文字以上にすると1回だけ付く', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  publishKarte(w)
  const r1 = await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: 'う ん' } })
  eq(r1.json.rewardedNow, false, '短いときは付与なし')
  eq(r1.json.tooShort, true, 'tooShort')
  eq(w.getState().coins, 1000, '短いときのコイン')
  const r0 = await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: '   ' } })
  eq(r0.status, 400, '空欄は400')
  await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: 'じぶんで かんがえた' } })
  eq(w.getState().coins, 1030, '5文字以上で付与')
})

await t('16 古い端末の全置換保存 → 補填される／台帳の水増しは元に戻る', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  publishKarte(w)
  await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: 'ゆっくり書いたから' } })
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1000 }) } })
  eq(w.getState().coins, 1030, '補填後のコイン')
  eq(w.getState()._hanshinCoinsApplied, 30, '台帳')
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1030, _hanshinCoinsApplied: 99999 }) } })
  eq(w.getState().coins, 1030, '水増しでコインが増えない')
  eq(w.getState()._hanshinCoinsApplied, 30, '台帳がサーバの値に戻る')
  // 同じしつもんにもう一度答えても、補填後に二重にならない
  await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: 'もういちど こたえる' } })
  eq(w.getState().coins, 1030, '二重付与なし')
})

await t('17 ほかの子のカルテ・未公開・クライアントの金額申告では付かない', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  publishKarte(w, 'kq-other', 'stu-999')
  w.db._run("INSERT INTO ai_review_drafts (id, teacher_id, class_id, week_key, kind, target_id, body, status, created_at) VALUES (?,?,?,?,?,?,?,?,datetime('now'))",
    'kq-draft', w.teacher.id, 'cls-1', '2026-W42', 'KARTE', w.student.id, '▼考えてほしいこと\nなにが ちがった？', 'draft')
  const a = await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-other', answer: 'ほかの子のしつもん' } })
  eq(a.status, 404, 'ほかの子のカルテは404')
  const b = await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-draft', answer: 'みこうかいの しつもん' } })
  eq(b.status, 404, '未公開は404')
  publishKarte(w)
  await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: 'たくさんください', coins: 99999, reward: 99999 } })
  eq(w.getState().coins, 1030, '申告した金額は使われない')
  eq(w.db._all('SELECT * FROM hanshin_answer_rewards').length, 1, '台帳の行数')
})

await t('18 先生は答えられない・既存の返却ボーナスと共存する', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  publishKarte(w)
  const r = await w.call('POST', '/api/student/hanshin-answer', { user: w.teacher, body: { questionId: 'kq-1', answer: 'せんせいが こたえる' } })
  eq(r.status, 403, '先生は403')
  await w.call('POST', '/api/teacher/homework/hw-1/return', { user: w.teacher, body: { comment: 'ok' } })
  await w.call('POST', '/api/student/hanshin-answer', { user: w.student, body: { questionId: 'kq-1', answer: 'ゆっくり書いたから' } })
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1000 }) } })
  const s = w.getState()
  eq(s.coins, 1180, '150 + 30 が両方補填される')
  eq(s._hwCoinsApplied, 150, '宿題台帳')
  eq(s._hanshinCoinsApplied, 30, 'しつもん台帳')
})

// ── 🧭 えらべる3つの道（MICHI_V2）：おすすめの保存と「どう思う？」──────────
const RECO = { v: 2, subj: 'math', subjName: '算数', anchor: 'm6-ratio', a: { id: 'm6-ratio', name: '比' }, b: { id: 'm6-circle', name: '円の面積' }, weekKey: '2026-W43' }

await t('19 先生が自分のクラスの子のおすすめを保存 → 子どもが読めて「どう思う？」を送れる（上書き1行・コインなし）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const s1 = await w.call('POST', '/api/teacher/karte-recos', { user: w.teacher, body: { items: [{ userId: w.student.id, weekKey: '2026-W43', reco: RECO, source: 'auto' }] } })
  eq(s1.json.saved, 1, '保存した数')
  const g = await w.call('GET', '/api/student/karte-reco', { user: w.student })
  eq(g.json.reco.a.name, '比', 'おすすめが読める')
  const f1 = await w.call('POST', '/api/student/karte-reco-feedback', { user: w.student, body: { choice: 'easy' } })
  eq(f1.status, 200, 'status')
  await w.call('POST', '/api/student/karte-reco-feedback', { user: w.student, body: { choice: 'hard' } })
  const rows = w.db._all('SELECT * FROM karte_reco_feedback')
  eq(rows.length, 1, '1週1行')
  eq(rows[0].choice, 'hard', '最新に上書き')
  eq(rows[0].unit, 'm6-ratio', 'どの単元への返事か')
  eq(w.getState().coins, 1000, 'コインは動かない')
  const bad = await w.call('POST', '/api/student/karte-reco-feedback', { user: w.student, body: { choice: 'coins' } })
  eq(bad.status, 400, 'ほかの値は400')
})

await t('20 ほかの先生のクラスの子には保存できない・おすすめが無ければ返事は404', async () => {
  const w = await newWorld()
  const other = { id: 'tea-2', role: 'teacher', loginId: 'other' }
  w.db._run("INSERT INTO teacher_accounts (id, login_id, name, school) VALUES (?,?,?,?)", other.id, 'other', 'ほか', 'テスト小')
  const r = await w.call('POST', '/api/teacher/karte-recos', { user: other, body: { items: [{ userId: w.student.id, weekKey: '2026-W43', reco: RECO }] } })
  eq(r.json.saved, 0, '保存されない')
  eq(w.db._all('SELECT * FROM karte_recos').length, 0, '表は空')
  const f = await w.call('POST', '/api/student/karte-reco-feedback', { user: w.student, body: { choice: 'fit' } })
  eq(f.status, 404, 'おすすめが無いと404')
})

await t('21 先生が差しかえたおすすめは、印刷の自動保存で上書きされない', async () => {
  const w = await newWorld()
  await w.call('POST', '/api/teacher/karte-recos', { user: w.teacher, body: { items: [{ userId: w.student.id, weekKey: '2026-W43', reco: { ...RECO, anchor: 'm6-circle' }, source: 'teacher' }] } })
  const r = await w.call('POST', '/api/teacher/karte-recos', { user: w.teacher, body: { items: [{ userId: w.student.id, weekKey: '2026-W43', reco: RECO, source: 'auto' }] } })
  eq(r.json.skipped, 1, '自動は見送り')
  const row = w.db._get('SELECT source, reco_json FROM karte_recos WHERE user_id=?', w.student.id)
  eq(row.source, 'teacher', '先生のまま')
  eq(JSON.parse(row.reco_json).anchor, 'm6-circle', '先生が選んだ単元のまま')
})

// ── ✍️ 週の振り返りのボーナス（WEEKREF_V1）────────────────────────
//   1週につき1回・5文字以上・いまの週（日本時間・朝8:30前は前の日）だけ 20コイン。
function wrIsoKey(d) {
  const tmp = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()))
  tmp.setUTCDate(tmp.getUTCDate() + 4 - (tmp.getUTCDay() || 7))
  const ys = new Date(Date.UTC(tmp.getUTCFullYear(), 0, 1))
  const wn = Math.ceil((((tmp.getTime() - ys.getTime()) / 86400000) + 1) / 7)
  return `${tmp.getUTCFullYear()}-W${String(wn).padStart(2, '0')}`
}
const WR_NOW = wrIsoKey(new Date(Date.now() + 9 * 3600000 - 8.5 * 3600000))
const WR_OLD = wrIsoKey(new Date(Date.now() + 9 * 3600000 - 8.5 * 3600000 - 21 * 86400000))
const sendRef = (w, text, weekKey = WR_NOW, user = null) =>
  w.call('POST', '/api/student/weekly-reflection', { user: user || w.student, body: { weekKey, dayKey: '2026-10-23', freeText: text } })

await t('22 週の振り返りを5文字以上で出す → 20コイン・台帳1行・自由欄が保存される', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const r = await sendRef(w, '今週は漢字をがんばった')
  eq(r.status, 200, 'status')
  eq(r.json.weekRefBonus.rewardedNow, true, '今回付与')
  eq(r.json.weekRefBonus.reward, 20, '金額は定数')
  const s = w.getState()
  eq(s.coins, 1020, 'DBのコイン')
  eq(s._weekRefCoinsApplied, 20, 'DBの付与台帳')
  eq(w.db._all('SELECT * FROM week_ref_rewards').length, 1, '台帳の行数')
  eq(w.db._get('SELECT free_text FROM structured_reflections WHERE user_id=? AND week_key=?', w.student.id, WR_NOW).free_text, '今週は漢字をがんばった', '自由欄')
  const st = await w.call('GET', '/api/student/week-ref-status?weekKey=' + WR_NOW, { user: w.student })
  eq(st.json.wrote, true, '書いた'); eq(st.json.rewarded, true, 'もらった')
})

await t('23 連打・書きなおし・同時送信でも20しか付かない（1週1回）', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  await Promise.all([0, 1, 2, 3].map((i) => sendRef(w, 'ふりかえり その' + i + ' です')))
  const r = await sendRef(w, 'かきなおした ふりかえり')
  eq(r.json.weekRefBonus.rewardedNow, false, '2回目は付与なし')
  eq(r.json.weekRefBonus.rewarded, true, 'もらいずみ')
  const s = w.getState()
  eq(s.coins, 1020, 'コイン')
  eq(s._weekRefCoinsApplied, 20, '台帳の累計')
  eq(w.db._all('SELECT * FROM week_ref_rewards').length, 1, '台帳の行数')
})

await t('24 4文字以下は保存だけ（コインなし）→ あとで5文字以上にすると1回だけ付く', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const r1 = await sendRef(w, 'た の し')
  eq(r1.json.weekRefBonus.rewardedNow, false, '短いときは付与なし')
  eq(r1.json.weekRefBonus.tooShort, true, 'tooShort')
  eq(w.getState().coins, 1000, '短いときのコイン')
  eq(w.db._all('SELECT * FROM week_ref_rewards').length, 0, '台帳は空')
  await sendRef(w, 'たのしかった 算数')
  eq(w.getState().coins, 1020, '5文字以上で付与')
})

await t('25 昔の週・おかしな週キー・先生・金額の申告では付かない', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const a = await sendRef(w, '3週間まえの ふりかえり', WR_OLD)
  eq(a.json.weekRefBonus.rewardedNow, false, '昔の週は付かない')
  const b = await sendRef(w, '日付の形の ふりかえり', '2026-10-23')
  eq(b.json.weekRefBonus.rewardedNow, false, '日付キーは付かない')
  const c = await sendRef(w, 'せんせいが かいた ふりかえり', WR_NOW, w.teacher)
  eq(c.json.weekRefBonus.rewardedNow, false, '先生は付かない')
  eq(w.getState().coins, 1000, 'ここまでコインは動かない')
  await w.call('POST', '/api/student/weekly-reflection', { user: w.student, body: { weekKey: WR_NOW, freeText: 'たくさん ください', coins: 99999, reward: 99999 } })
  eq(w.getState().coins, 1020, '申告した金額は使われない')
  eq(w.db._all('SELECT * FROM week_ref_rewards').length, 1, '台帳の行数')
})

await t('26 古い端末の全置換保存 → 補填される／台帳の水増しは元に戻る／ほかのボーナスと共存', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  await sendRef(w, '今週は計算をがんばった')
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1000 }) } })
  eq(w.getState().coins, 1020, '補填後のコイン')
  eq(w.getState()._weekRefCoinsApplied, 20, '台帳')
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1020, _weekRefCoinsApplied: 99999 }) } })
  eq(w.getState().coins, 1020, '水増しでコインが増えない')
  eq(w.getState()._weekRefCoinsApplied, 20, '台帳がサーバの値に戻る')
  // 画面がサーバの返事を写した端末（coins+20・台帳20）が保存しても二重にならない
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1020, _weekRefCoinsApplied: 20 }) } })
  eq(w.getState().coins, 1020, '写した端末の保存で二重にならない')
  // 宿題の返却ボーナスと同時に補填される
  await w.call('POST', '/api/teacher/homework/hw-1/return', { user: w.teacher, body: { comment: 'ok' } })
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1000 }) } })
  const s = w.getState()
  eq(s.coins, 1170, '150 + 20 が両方補填される')
  eq(s._hwCoinsApplied, 150, '宿題台帳')
  eq(s._weekRefCoinsApplied, 20, '振り返り台帳')
})

await t('27 先生：先週の振り返り（自由欄・🌟）を読める → 先週の週へ返せる・ほかの先生は読めない', async () => {
  const w = await newWorld()
  const lastWk = wrIsoKey(new Date(Date.now() + 9 * 3600000 - 7 * 86400000))
  w.db._run("INSERT INTO structured_reflections (user_id, week_key, free_text, created_at) VALUES (?,?,?,?)", w.student.id, lastWk, '先週は毎日やれた', Date.now())
  w.db._run("INSERT INTO student_weekly_plans (user_id, week_key, plans_json, updated_at) VALUES (?,?,?,?)", w.student.id, lastWk, JSON.stringify({ mon: 'かんじ', fri: { free: '', reflection: '先週は毎日やれた' } }), Date.now())
  // 家庭学習シートの🌟（その週の金曜の提出）
  const _m = lastWk.match(/^(\d{4})-W(\d{2})$/); const _j4 = new Date(Date.UTC(Number(_m[1]), 0, 4)); const _dw = _j4.getUTCDay() || 7
  const friDay = new Date(_j4.getTime() + ((1 - _dw) + (Number(_m[2]) - 1) * 7 + 4) * 86400000).toISOString().slice(0, 10)
  w.db._run("INSERT INTO homework_submissions (id, user_id, class_id, title, day_key, weekly_reflection) VALUES (?,?,?,?,?,?)", 'hw-fri', w.student.id, 'cls-1', 'しゅくだい', friDay, '金曜に書いた🌟')
  const r = await w.call('GET', '/api/teacher/week-reflections?classId=cls-1&weeks=' + lastWk, { user: w.teacher })
  eq(r.status, 200, 'status')
  eq(r.json.items.length, 1, '1人ぶん')
  eq(r.json.items[0].hw && r.json.items[0].hw.text, '金曜に書いた🌟', '🌟も読む')
  eq(r.json.items[0].hw && r.json.items[0].hw.returnedAt, 0, '🌟はまだ返していない')
  eq(r.json.items[0].freeText, '先週は毎日やれた', '自由欄を読む')
  eq(r.json.items[0].planReflection, '先週は毎日やれた', '計画の画面の振り返り')
  eq(r.json.items[0].returnedAt, 0, 'まだ返していない')
  const p = await w.call('POST', '/api/teacher/reflection-comments', { user: w.teacher, body: { weekKey: WR_NOW, comments: [{ studentId: w.student.id, comment: 'よくがんばったね', weekKey: lastWk }] } })
  eq(p.json.saved, 1, '先週へ返せた')
  const row = w.db._get('SELECT reflection_comment, reflection_returned_at FROM student_weekly_plans WHERE user_id=? AND week_key=?', w.student.id, lastWk)
  eq(row.reflection_comment, 'よくがんばったね', '返事')
  ok(Number(row.reflection_returned_at) > 0, '返却ずみ')
  const p2 = await w.call('POST', '/api/teacher/reflection-comments', { user: w.teacher, body: { comments: [{ studentId: w.student.id, comment: 'にどめ', weekKey: lastWk }] } })
  eq(p2.json.saved, 0, '二重に返さない')
  const other = { id: 'tea-2', role: 'teacher', loginId: 'other' }
  w.db._run("INSERT INTO teacher_accounts (id, login_id, name, school) VALUES (?,?,?,?)", other.id, 'other', 'ほか', 'テスト小')
  const o = await w.call('GET', '/api/teacher/week-reflections?classId=cls-1&weeks=' + lastWk, { user: other })
  eq(o.status, 404, 'ほかの先生は404')
  eq(w.getState(), null, 'コインは動かない（progress 行なし）')
})

// ── 🪞 前の自分とくらべる・来週やってみたいこと（MAEJIBUN_V1）──────────
await t('28 来週やってみたいこと：単元と一言を保存→読める・上書き1行・40字まで・空で消える・コインなし', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const r1 = await w.call('POST', '/api/student/next-try', { user: w.student, body: { weekKey: WR_NOW, unit: 'm6-ratio', unitName: '比', text: '比を10問とく' } })
  eq(r1.status, 200, 'status')
  eq(r1.json.weekKey, WR_NOW, 'いまの週')
  await w.call('POST', '/api/student/next-try', { user: w.student, body: { weekKey: WR_NOW, unit: 'bad unit<>', text: 'あ'.repeat(80) } })
  const rows = w.db._all('SELECT * FROM week_next_try')
  eq(rows.length, 1, '1週1行')
  eq(rows[0].unit, '', 'おかしな単元idは入れない')
  eq(Array.from(rows[0].text).length, 40, '40字まで')
  const g = await w.call('GET', '/api/student/next-try?weekKey=' + WR_NOW, { user: w.student })
  eq(g.json.nextTry.text.length, 40, '読める')
  const old = await w.call('POST', '/api/student/next-try', { user: w.student, body: { weekKey: WR_OLD, text: 'むかし' } })
  eq(old.json.weekKey, WR_NOW, '昔の週には書けない（いまの週になる）')
  await w.call('POST', '/api/student/next-try', { user: w.student, body: { weekKey: WR_NOW, unit: '', text: '' } })
  eq(w.db._all('SELECT * FROM week_next_try').length, 0, '空で消える')
  eq(w.getState().coins, 1000, 'コインは動かない')
})

await t('29 前の自分：未ログイン401・ほかの子のid指定403・自分の分だけ新しい順', async () => {
  const w = await newWorld()
  const other = 'stu-2'
  w.db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", other, 'student', 'kid2', 'はなこ', 3, '3-1')
  const wk1 = wrIsoKey(new Date(Date.now() + 9 * 3600000 - 7 * 86400000))
  const wk3 = wrIsoKey(new Date(Date.now() + 9 * 3600000 - 21 * 86400000))
  w.db._run("INSERT INTO structured_reflections (user_id, week_key, free_text, created_at) VALUES (?,?,?,?)", w.student.id, wk3, '3週まえのわたし', Date.now())
  w.db._run("INSERT INTO structured_reflections (user_id, week_key, free_text, created_at) VALUES (?,?,?,?)", w.student.id, wk1, '先週のわたし', Date.now())
  w.db._run("INSERT INTO structured_reflections (user_id, week_key, free_text, created_at) VALUES (?,?,?,?)", other, wk1, 'ほかの子の文', Date.now())
  w.db._run("INSERT INTO student_weekly_plans (user_id, week_key, plans_json, updated_at, reflection_comment, reflection_returned_at) VALUES (?,?,?,?,?,?)", w.student.id, wk1, '{}', Date.now(), 'いいね', Date.now())
  w.db._run("INSERT INTO week_next_try (user_id, week_key, unit, unit_name, text) VALUES (?,?,?,?,?)", w.student.id, wk3, 'm6-ratio', '比', '比をやる')
  const n = await w.call('GET', '/api/student/my-growth')
  eq(n.status, 401, '未ログイン401')
  const f = await w.call('GET', '/api/student/my-growth?userId=' + other, { user: w.student })
  eq(f.status, 403, 'ほかの子は403')
  const r = await w.call('GET', '/api/student/my-growth', { user: w.student })
  eq(r.status, 200, 'status')
  eq(r.json.cards.length, 2, '自分の2週ぶん')
  eq(r.json.cards[0].text, '先週のわたし', '新しい順')
  eq(r.json.cards[0].reply, 'いいね', '返してもらった返事')
  eq(r.json.cards[1].nextTry.text, '比をやる', '来週やってみたいこと')
  ok(JSON.stringify(r.json).indexOf('ほかの子') < 0, 'ほかの子の文は入らない')
  const self = await w.call('GET', '/api/student/my-growth?userId=' + w.student.id, { user: w.student })
  eq(self.status, 200, '自分のidならOK')
})

await t('30 のびたこと：同じ単元で 10問中4問→8問 だけを出す（へった単元・少ない単元は出さない）', async () => {
  const w = await newWorld()
  const at = (d) => new Date(Date.now() - d * 86400000).toISOString()
  for (let i = 0; i < 10; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', w.student.id, at(20), 'm6-ratio', i < 4 ? 1 : 0)
  for (let i = 0; i < 10; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', w.student.id, at(3), 'm6-ratio', i < 8 ? 1 : 0)
  for (let i = 0; i < 10; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', w.student.id, at(20), 'm6-circle', i < 9 ? 1 : 0)
  for (let i = 0; i < 10; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', w.student.id, at(3), 'm6-circle', i < 5 ? 1 : 0)
  for (let i = 0; i < 5; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', w.student.id, at(3), 'm6-frac-mul', 1)
  for (let i = 0; i < 10; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', 'stu-9', at(20), 'm6-frac-div', 0)
  for (let i = 0; i < 10; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', 'stu-9', at(3), 'm6-frac-div', 1)
  const r = await w.call('GET', '/api/student/my-growth', { user: w.student })
  eq(r.json.facts.units.length, 1, '1つだけ')
  eq(r.json.facts.units[0].unit, 'm6-ratio', '比')
  eq(r.json.facts.units[0].before, 4, 'まえ 10問中4問')
  eq(r.json.facts.units[0].after, 8, 'いま 10問中8問')
  ok(!/rank|avg|percent|score/i.test(JSON.stringify(r.json)), '順位・平均・％・点は返さない')
})

await t('31 先生：今日のひと往復の材料に「来週やってみたいこと」が入る・カルテの材料にも入る', async () => {
  const w = await newWorld()
  const lastWk = wrIsoKey(new Date(Date.now() + 9 * 3600000 - 7 * 86400000))
  w.db._run("INSERT INTO structured_reflections (user_id, week_key, free_text, created_at) VALUES (?,?,?,?)", w.student.id, lastWk, '漢字をがんばった', Date.now())
  w.db._run("INSERT INTO week_next_try (user_id, week_key, unit, unit_name, text) VALUES (?,?,?,?,?)", w.student.id, lastWk, 'm6-ratio', '比', '比をマスターしたい')
  const r = await w.call('GET', '/api/teacher/week-reflections?classId=cls-1&weeks=' + lastWk, { user: w.teacher })
  eq(r.json.items[0].nextTry && r.json.items[0].nextTry.text, '比をマスターしたい', 'ひと往復に入る')
  eq(r.json.items[0].nextTry.unit, 'm6-ratio', '単元も')
  const k = await w.call('GET', '/api/student/karte-reco', { user: w.student })
  eq(k.status, 200, 'karte-reco は動く')
})


// ── 👆 かんたんふりかえり・自動検出（KANTAN_REF_V1）──────────────────
//   コインは既存の週の振り返りの台帳（week_ref_rewards）だけ。かんたんふりかえりそのものはコインを動かさない。
function kDay(daysAgo) { return new Date(Date.now() + 9 * 3600000 - 8.5 * 3600000 - daysAgo * 86400000).toISOString().slice(0, 10) }
const K_TEXT = '今週の 自分の 学びは ◎よくできた。そう思うのは、アプリを 3日 ひらけたから。次は このまま つづけてみる。'
async function sendKantan(w) {
  await w.call('POST', '/api/student/kantan-ref', { user: w.student, body: { weekKey: WR_NOW, self: 'good', reason: 'open', next: 'keep', how: '', mood: 'sun', addedChars: 0 } })
  return w.call('POST', '/api/student/weekly-reflection', { user: w.student, body: { weekKey: WR_NOW, dayKey: kDay(0), freeText: K_TEXT, goodPoint: '◎ よくできた ／ なんで：アプリを 3日 ひらけた', improvePoint: '', nextAction: '次：このまま つづける' } })
}

await t('32 かんたんふりかえりで出す → 既存の20コインが1回だけ・項目欄に◎・タップの記録はコインを動かさない', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  const t0 = await w.call('POST', '/api/student/kantan-ref', { user: w.student, body: { weekKey: WR_NOW, self: 'good', reason: 'open', next: 'keep' } })
  eq(t0.status, 200, 'status')
  eq(w.getState().coins, 1000, 'タップの記録だけではコインは動かない')
  const r = await sendKantan(w)
  eq(r.json.weekRefBonus.rewardedNow, true, '既存のボーナスが付く')
  eq(w.getState().coins, 1020, '20コイン')
  const r2 = await sendKantan(w)
  eq(r2.json.weekRefBonus.rewardedNow, false, '2回目は付かない')
  eq(w.getState().coins, 1020, '二重にならない')
  eq(w.db._all('SELECT * FROM week_ref_rewards').length, 1, '台帳1行')
  const sr = w.db._get('SELECT good_point, next_action, free_text FROM structured_reflections WHERE user_id=? AND week_key=?', w.student.id, WR_NOW)
  ok(sr.good_point.indexOf('◎ よくできた') === 0, '◎が項目欄の先頭に')
  eq(sr.next_action, '次：このまま つづける', '次どうする')
  eq(sr.free_text, K_TEXT, '文')
  const tp = w.db._get('SELECT self_mark, reason_key, next_key, mood FROM week_ref_taps WHERE user_id=?', w.student.id)
  eq(tp.self_mark, 'good', '見立て'); eq(tp.next_key, 'keep', '次'); eq(tp.mood, 'sun', '気もち')
  eq(w.db._all('SELECT * FROM week_ref_taps').length, 1, '1週1行')
})

await t('33 あとで自由欄だけ出しなおしても◎と「次」は消えない・おかしな値は入らない', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  await sendKantan(w)
  await sendRef(w, '自由欄だけ書きなおしたよ')
  const sr = w.db._get('SELECT good_point, next_action, free_text FROM structured_reflections WHERE user_id=? AND week_key=?', w.student.id, WR_NOW)
  ok(sr.good_point.indexOf('◎') === 0, '◎は残る')
  eq(sr.next_action, '次：このまま つづける', '次も残る')
  eq(sr.free_text, '自由欄だけ書きなおしたよ', '自由欄は新しく')
  await w.call('POST', '/api/student/kantan-ref', { user: w.student, body: { weekKey: WR_OLD, self: 'best!!', reason: '<script>', next: 'keep', how: 'xx', mood: 'snow' } })
  const tp = w.db._all('SELECT * FROM week_ref_taps')
  eq(tp.length, 1, '昔の週には書けない（いまの週の1行のまま）')
  eq(tp[0].self_mark, '', 'おかしな見立ては空'); eq(tp[0].reason_key, '', 'おかしな目印は空'); eq(tp[0].next_how, '', 'おかしな変え方は空'); eq(tp[0].mood, '', 'おかしな気もちは空')
  eq(w.getState().coins, 1020, 'コインは20のまま')
})

await t('34 かんたんふりかえりの材料：未ログイン401・ほかの子403・記録から候補・前の週の◎・順位や点は返さない', async () => {
  const w = await newWorld()
  const n = await w.call('GET', '/api/student/kantan-ref')
  eq(n.status, 401, '未ログイン401')
  const f = await w.call('GET', '/api/student/kantan-ref?userId=stu-2', { user: w.student })
  eq(f.status, 403, 'ほかの子は403')
  const at = new Date(Date.now() - 3600000).toISOString()
  for (let i = 0; i < 10; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', w.student.id, at, 'm6-ratio', i < 8 ? 1 : 0)
  for (let i = 0; i < 6; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', w.student.id, at, 'm6-circle', i < 1 ? 1 : 0)
  for (let i = 0; i < 10; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', 'stu-9', at, 'm6-frac-div', 1)
  const lastWk = wrIsoKey(new Date(Date.now() + 9 * 3600000 - 8.5 * 3600000 - 7 * 86400000))
  w.db._run("INSERT INTO week_ref_taps (user_id, week_key, self_mark, next_key) VALUES (?,?,?,?)", w.student.id, lastWk, 'more', 'change')
  w.db._run("INSERT INTO structured_reflections (user_id, week_key, next_action, created_at) VALUES (?,?,?,?)", w.student.id, lastWk, '次：やり方を 変える（時間）', Date.now())
  const r = await w.call('GET', '/api/student/kantan-ref?weekKey=' + WR_NOW, { user: w.student })
  eq(r.status, 200, 'status')
  eq(r.json.week.best.unit, 'm6-ratio', 'いちばん せいかいした単元')
  eq(r.json.week.best.c, 8, '8問')
  eq(r.json.week.questions, 16, '自分の分だけ数える')
  eq(r.json.hard[0].unit, 'm6-circle', 'まちがいが多かった単元')
  eq(r.json.prev.self, 'more', '前の週の見立て')
  eq(r.json.prev.nextText, '次：やり方を 変える（時間）', '前の週の 次どうする')
  ok(!/rank|avg|percent|score/i.test(JSON.stringify(r.json)), '順位・平均・％・点は返さない')
})

await t('35 自動検出：開いた日が少ない＋振り返りなし＋家庭学習なし → 1タップ案内・よく来る子は案内なし', async () => {
  const w = await newWorld()
  const r1 = await w.call('GET', '/api/student/kantan-ref', { user: w.student })
  eq(r1.json.oneTap, true, '記録が少ない子は1タップ案内')
  for (let i = 0; i < 6; i++) w.db._run('INSERT INTO app_open_days (user_id, day_key) VALUES (?,?)', w.student.id, kDay(i))
  for (let i = 0; i < 3; i++) w.db._run("INSERT INTO homework_submissions (id, user_id, class_id, title, day_key) VALUES (?,?,?,?,?)", 'hwk-' + i, w.student.id, 'cls-1', 't', kDay(i))
  const r2 = await w.call('GET', '/api/student/kantan-ref', { user: w.student })
  eq(r2.json.oneTap, false, 'よく来ている子は案内なし')
})

await t('36 アプリを開いた日：1日1行・何回でも重複しない・コインなし・先生は記録しない', async () => {
  const w = await newWorld()
  w.setState(smallState({ coins: 1000 }))
  for (let i = 0; i < 3; i++) await w.call('POST', '/api/student/app-open', { user: w.student })
  eq(w.db._all('SELECT * FROM app_open_days').length, 1, '1日1行')
  eq(w.getState().coins, 1000, 'コインは動かない')
  await w.call('POST', '/api/student/app-open', { user: w.teacher })
  eq(w.db._all('SELECT * FROM app_open_days').length, 1, '先生は記録しない')
  const n = await w.call('POST', '/api/student/app-open')
  eq(n.json.student, false, '未ログインは何もしない')
})

await t('37 先生：対象の子の人数と一覧（見るだけ）・ほかの先生は404・前の自分ページに◎', async () => {
  const w = await newWorld()
  const kid2 = 'stu-2'
  w.db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", kid2, 'student', 'kid2', 'はなこ', 3, '3-1')
  w.db._run("INSERT INTO class_members (class_id, user_id) VALUES (?,?)", 'cls-1', kid2)
  for (let i = 0; i < 6; i++) w.db._run('INSERT INTO app_open_days (user_id, day_key) VALUES (?,?)', kid2, kDay(i))
  for (let i = 0; i < 3; i++) w.db._run("INSERT INTO homework_submissions (id, user_id, class_id, title, day_key) VALUES (?,?,?,?,?)", 'hwk2-' + i, kid2, 'cls-1', 't', kDay(i))
  const r = await w.call('GET', '/api/teacher/class/cls-1/kantan-watch', { user: w.teacher })
  eq(r.status, 200, 'status')
  eq(r.json.total, 2, 'クラス2人')
  eq(r.json.count, 1, '対象1人')
  eq(r.json.items[0].userId, w.student.id, '記録が少ない子')
  const other = { id: 'tea-2', role: 'teacher', loginId: 'other' }
  w.db._run("INSERT INTO teacher_accounts (id, login_id, name, school) VALUES (?,?,?,?)", other.id, 'other', 'ほか', 'テスト小')
  const o = await w.call('GET', '/api/teacher/class/cls-1/kantan-watch', { user: other })
  eq(o.status, 404, 'ほかの先生は404')
  const s = await w.call('GET', '/api/teacher/class/cls-1/kantan-watch', { user: w.student })
  eq(s.status, 403, '児童は403')
  await sendKantan(w)
  const g = await w.call('GET', '/api/student/my-growth', { user: w.student })
  eq(g.json.cards[0].mark, 'good', '前の自分ページに◎')
  eq(g.json.cards[0].how, '次：このまま つづける', '次どうする')
})

// ── MINNA_FURI_V1 みんなのふりかえり（採用で300コイン・1つの振り返りにつき1回）／📋振り返り一覧 ──
const MF_DAY = new Date(Date.now() + 9 * 3600000 - 8.5 * 3600000).toISOString().slice(0, 10)
function mfWorld(w) {
  w.db.db.exec(`CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, class_id TEXT NOT NULL, sender_id TEXT NOT NULL, sender_role TEXT NOT NULL, recipient_id TEXT NOT NULL, body TEXT NOT NULL, read_at TEXT, created_at TEXT DEFAULT (datetime('now')))`)
  for (const col of ['submitted_at INTEGER', 'todo TEXT', 'why TEXT', 'aim TEXT', 'minutes INTEGER', 'end_weather TEXT', 'weather_reason TEXT', 'next_improve TEXT', 'rest_day INTEGER', 'parent_comment TEXT', 'work_photo_analysis TEXT']) {
    try { w.db.db.exec('ALTER TABLE homework_submissions ADD COLUMN ' + col) } catch (_e) {}
  }
  // 架空の2人目（同じクラス）と、べつのクラス（べつの先生・べつの子）
  w.db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", 'stu-2', 'student', 'kid2', 'はなこ', 3, '3-1')
  w.db._run("INSERT INTO class_members (class_id, user_id) VALUES (?,?)", 'cls-1', 'stu-2')
  w.db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", 'stu-x', 'student', 'kidx', 'よそのこ', 3, '3-2')
  w.db._run("INSERT INTO teacher_accounts (id, login_id, name, school) VALUES (?,?,?,?)", 'tea-2', 'sensei2', 'べつのせんせい', 'テスト小')
  w.db._run("INSERT INTO classes (id, teacher_id, name) VALUES (?,?,?)", 'cls-2', 'tea-2', '3年2組')
  w.db._run("INSERT INTO class_members (class_id, user_id) VALUES (?,?)", 'cls-2', 'stu-x')
  w.db._run("UPDATE homework_submissions SET day_key=?, submitted_at=?, weather_reason=?, next_improve=?, end_weather='sun' WHERE id='hw-1'", MF_DAY, Date.now(), '九九の7のだんが言えた', 'まちがい直しから')
  w.db._run("INSERT INTO homework_submissions (id, user_id, title, day_key, submitted_at, weather_reason) VALUES (?,?,?,?,?,?)", 'hw-2', 'stu-2', 'こくご', MF_DAY, Date.now(), '音読をがんばった')
  w.db._run("INSERT INTO homework_submissions (id, user_id, title, day_key, submitted_at, weather_reason) VALUES (?,?,?,?,?,?)", 'hw-x', 'stu-x', 'りか', MF_DAY, Date.now(), 'よそのクラスの文')
  return {
    s2: { id: 'stu-2', role: 'student', loginId: 'kid2' },
    sx: { id: 'stu-x', role: 'student', loginId: 'kidx' },
    t2: { id: 'tea-2', role: 'teacher', loginId: 'sensei2' },
  }
}
const mfConsent = (w, user, mode, ref = MF_DAY, kind = 'day') => w.call('POST', '/api/student/minna/consent', { user, body: { kind, ref, mode } })
const mfCid = (w, uid) => (w.db._get("SELECT id FROM minna_consents WHERE user_id=?", uid) || {}).id

await t('38 のせてもいいよ→先生が直して採用 → 300コイン・台帳1行・お知らせ1通・文面は別に保存（元の振り返りはそのまま）', async () => {
  const w = await newWorld(); mfWorld(w)
  w.setState(smallState({ coins: 1000 }))
  const c1 = await mfConsent(w, w.student, 'anon')
  eq(c1.json.saved, true, '同意が保存される')
  const id = mfCid(w, w.student.id)
  const r = await w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: id, body: '九九のだんが言えた（先生がなおした）' } })
  eq(r.status, 200, 'status'); eq(r.json.rewardedNow, true, '今回付与'); eq(r.json.coins, 300, '金額は定数')
  const s = w.getState()
  eq(s.coins, 1300, 'DBのコイン'); eq(s._minnaCoinsApplied, 300, 'DBの付与台帳')
  eq(w.db._all('SELECT * FROM minna_rewards').length, 1, '台帳の行数')
  eq(w.db._all("SELECT * FROM messages WHERE recipient_id='stu-1'").length, 1, 'お知らせ1通')
  ok(/みんなのふりかえり/.test(w.db._get("SELECT body FROM messages WHERE recipient_id='stu-1'").body), 'お知らせの文')
  eq(w.db._get("SELECT body FROM minna_posts WHERE consent_id=?", id).body, '九九のだんが言えた（先生がなおした）', '直した文面')
  eq(w.db._get("SELECT weather_reason FROM homework_submissions WHERE id='hw-1'").weather_reason, '九九の7のだんが言えた', '元の振り返りは書きかえない')
})

await t('39 連打・同時採用・取り消し→再採用・文面の直しでも 300 しか付かない（回収もしない）', async () => {
  const w = await newWorld(); mfWorld(w)
  w.setState(smallState({ coins: 1000 }))
  await mfConsent(w, w.student, 'named')
  const id = mfCid(w, w.student.id)
  await Promise.all([0, 1, 2, 3].map((i) => w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: id, body: 'ぶん ' + i } })))
  await w.call('POST', '/api/teacher/minna/unadopt', { user: w.teacher, body: { consentId: id } })
  eq(w.getState().coins, 1300, '取り消しても回収しない')
  const r = await w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: id, body: 'もういちど' } })
  eq(r.json.rewardedNow, false, '再採用は付与なし')
  // 子どもが一度とりけして、もう一度のせてもいいよ にしても同じ振り返り
  await mfConsent(w, w.student, '')
  await mfConsent(w, w.student, 'anon')
  await w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: mfCid(w, w.student.id), body: 'さらにもう一度' } })
  const s = w.getState()
  eq(s.coins, 1300, 'コイン'); eq(s._minnaCoinsApplied, 300, '台帳の累計')
  eq(w.db._all('SELECT * FROM minna_rewards').length, 1, '台帳の行数')
  eq(w.db._all("SELECT * FROM messages").length, 1, 'お知らせも1通だけ')
})

await t('40 同意なし・とりけし後・ほかの先生・子ども・金額の申告では採用できない／付かない', async () => {
  const w = await newWorld(); const o = mfWorld(w)
  w.setState(smallState({ coins: 1000 }))
  await mfConsent(w, w.student, 'anon')
  const id = mfCid(w, w.student.id)
  const a = await w.call('POST', '/api/teacher/minna/adopt', { user: o.t2, body: { consentId: id, body: 'よそのせんせい' } })
  eq(a.status, 404, 'ほかの先生は404')
  const b = await w.call('POST', '/api/teacher/minna/adopt', { user: w.student, body: { consentId: id, body: 'じぶんで' } })
  eq(b.status, 403, '子どもは403')
  await mfConsent(w, w.student, '')
  const c = await w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: id, body: 'とりけしたあと' } })
  eq(c.status, 400, 'とりけし後は採用できない')
  eq(w.getState().coins, 1000, 'ここまでコインは動かない')
  await mfConsent(w, w.student, 'anon')
  await w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: id, body: 'ok', coins: 99999 } })
  eq(w.getState().coins, 1300, '申告した金額は使われない')
})

await t('41 古い端末の全置換保存 → 補填される／台帳の水増しは元に戻る／週の振り返りボーナスと共存', async () => {
  const w = await newWorld(); mfWorld(w)
  w.setState(smallState({ coins: 1000 }))
  await mfConsent(w, w.student, 'anon')
  await w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: mfCid(w, w.student.id), body: 'ok' } })
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1000 }) } })
  eq(w.getState().coins, 1300, '補填後のコイン'); eq(w.getState()._minnaCoinsApplied, 300, '台帳')
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1300, _minnaCoinsApplied: 99999 }) } })
  eq(w.getState().coins, 1300, '水増しでコインが増えない'); eq(w.getState()._minnaCoinsApplied, 300, '台帳がサーバの値に戻る')
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1300, _minnaCoinsApplied: 300 }) } })
  eq(w.getState().coins, 1300, '写した端末の保存で二重にならない')
  await sendRef(w, '今週は計算をがんばった')
  await w.call('PUT', '/api/student/progress', { user: w.student, body: { state: smallState({ coins: 1000 }) } })
  eq(w.getState().coins, 1320, '300 + 20 が両方補填される')
})

await t('42 子どもの「みんなのふりかえり」：同じクラスだけ・名前なしは名前を出さない・とりけしで即非表示・ログインなしは見えない', async () => {
  const w = await newWorld(); const o = mfWorld(w)
  w.setState(smallState({ coins: 1000 }))
  await mfConsent(w, w.student, 'anon'); await mfConsent(w, o.s2, 'named'); await mfConsent(w, o.sx, 'named')
  await w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: mfCid(w, 'stu-1'), body: 'たろうの文' } })
  await w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: mfCid(w, 'stu-2'), body: 'はなこの文' } })
  await w.call('POST', '/api/teacher/minna/adopt', { user: o.t2, body: { consentId: mfCid(w, 'stu-x'), body: 'よそのクラスの文' } })
  const r = await w.call('GET', '/api/student/minna/posts', { user: o.s2 })
  eq(r.json.posts.length, 2, '同じクラスの2件だけ')
  const anon = r.json.posts.find((p) => p.body === 'たろうの文'), named = r.json.posts.find((p) => p.body === 'はなこの文')
  eq(anon.name, '', '名前なしは名前を出さない'); eq(named.name, 'はなこ', '名前ありは名前だけ')
  ok(!JSON.stringify(r.json).includes('stu-1') && !JSON.stringify(r.json).includes('kid1'), 'だれの分かのIDも返さない')
  ok(!/rank|score|like|point/i.test(JSON.stringify(r.json)), '順位・点数・いいねは返さない')
  const x = await w.call('GET', '/api/student/minna/posts', { user: o.sx })
  eq(x.json.posts.length, 1, 'よそのクラスの子には、そのクラスの分だけ'); eq(x.json.posts[0].body, 'よそのクラスの文', 'よそのクラス')
  await mfConsent(w, w.student, '')
  const r2 = await w.call('GET', '/api/student/minna/posts', { user: o.s2 })
  eq(r2.json.posts.length, 1, 'とりけしたら即非表示')
  const n = await w.call('GET', '/api/student/minna/posts', {})
  ok(n.status === 401 || n.status === 403, 'ログインなしは見えない')
  const tt = await w.call('GET', '/api/student/minna/posts', { user: w.teacher })
  eq(tt.status, 403, '先生アカウントでは子ども用は開かない')
})

await t('43 同意できるのは「いまの日」の出した振り返りだけ（過去・まだ出していないものは不可）', async () => {
  const w = await newWorld(); const o = mfWorld(w)
  w.db._run("INSERT INTO homework_submissions (id, user_id, title, day_key, submitted_at) VALUES (?,?,?,?,?)", 'hw-old', 'stu-1', 'むかし', '2026-09-01', 1)
  const a = await mfConsent(w, w.student, 'anon', '2026-09-01')
  eq(a.json.saved, false, '過去の振り返りは同意できない')
  w.db._run("DELETE FROM homework_submissions WHERE id='hw-2'")
  const b = await mfConsent(w, o.s2, 'anon')
  eq(b.json.saved, false, 'まだ出していない'); eq(b.json.reason, 'not_submitted', '理由')
  eq(w.db._all('SELECT * FROM minna_consents').length, 0, '1行も入らない')
  const g = await w.call('GET', '/api/student/minna/consent?kind=day&ref=' + MF_DAY, { user: w.student })
  eq(g.json.mode, '', 'まだ同意なし')
})

await t('44 AIの掲載候補：1回あたり5件まで（こえた分は無視）・よそのクラス／同意なしのIDは入らない・材料に名前もIDも出さない', async () => {
  const w = await newWorld(); const o = mfWorld(w)
  const ids = []
  for (let i = 3; i <= 9; i++) {
    const uid = 'stu-' + i
    w.db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", uid, 'student', 'k' + i, 'かそう' + i, 3, '3-1')
    w.db._run("INSERT INTO class_members (class_id, user_id) VALUES (?,?)", 'cls-1', uid)
    w.db._run("INSERT INTO homework_submissions (id, user_id, title, day_key, submitted_at, weather_reason) VALUES (?,?,?,?,?,?)", 'hw-' + i, uid, 't', MF_DAY, Date.now(), 'はなこと いっしょに がんばった ' + i)
    await mfConsent(w, { id: uid, role: 'student', loginId: 'k' + i }, 'anon')
    ids.push(mfCid(w, uid))
  }
  await mfConsent(w, o.sx, 'anon')
  const src = await w.call('GET', '/api/teacher/minna/pick-source?classId=cls-1', { user: w.teacher })
  eq(src.json.periods.length, 1, '1回ぶん'); eq(src.json.periods[0].items.length, 7, '同意した7件')
  const js = JSON.stringify(src.json)
  ok(!js.includes('かそう') && !js.includes('stu-') && !js.includes('はなこ'), '名前・児童IDは渡さない（ほかの子の名前は〇〇）')
  ok(js.includes('〇〇'), '名前は〇〇に')
  const picks = ids.map((id) => ({ id, reason: 'りゆう' })).concat([{ id: mfCid(w, 'stu-x'), reason: 'よそ' }, { id: 'mfnotexist', reason: 'x' }])
  const r = await w.call('POST', '/api/teacher/minna/picks', { user: w.teacher, body: { classId: 'cls-1', picks } })
  eq(r.json.saved, 5, '5件まで'); eq(r.json.overLimit.length, 2, 'こえた2件は無視'); eq(r.json.unknown.length, 2, 'よそ・ないIDは入らない')
  eq(w.db._all('SELECT * FROM minna_picks').length, 5, '台帳は5件')
  const t2 = await w.call('POST', '/api/teacher/minna/picks', { user: o.t2, body: { classId: 'cls-1', picks } })
  eq(t2.status, 404, 'ほかの先生は取り込めない')
})

await t('45 📋振り返り一覧：その日の分だけ・同意/候補/採用が付く・ほかの先生は404・子どもは403', async () => {
  const w = await newWorld(); const o = mfWorld(w)
  w.setState(smallState({ coins: 1000 }))
  w.db._run("INSERT INTO homework_submissions (id, user_id, title, day_key, submitted_at, weather_reason) VALUES (?,?,?,?,?,?)", 'hw-prev', 'stu-1', 'まえ', '2026-01-05', 1, 'まえのひ')
  await mfConsent(w, w.student, 'named')
  await w.call('POST', '/api/teacher/minna/picks', { user: w.teacher, body: { classId: 'cls-1', picks: [{ id: mfCid(w, 'stu-1'), reason: 'くふうが書けている' }] } })
  const before = w.db.counter.reads
  const r = await w.call('GET', '/api/teacher/teibako?classId=cls-1&mode=day&date=' + MF_DAY, { user: w.teacher })
  eq(r.status, 200, 'status')
  eq(r.json.roster.length, 2, '名簿はクラスの2人'); eq(r.json.items.length, 2, 'その日の提出2件')
  const me = r.json.items.find((x) => x.userId === 'stu-1')
  eq(me.id, 'hw-1', 'その日の提出（前の日の分は入らない）')
  eq(me.consent.mode, 'named', '同意'); eq(me.pick.reason, 'くふうが書けている', 'AIの理由')
  ok(w.db.counter.reads - before < 20, '読む回数が少ない')
  const pv = await w.call('GET', '/api/teacher/teibako/prev?classId=cls-1&userId=stu-1&mode=day&ref=' + MF_DAY, { user: w.teacher })
  eq(pv.json.prev.dayKey, '2026-01-05', '前回のふりかえり')
  const a = await w.call('GET', '/api/teacher/teibako?classId=cls-1&mode=day&date=' + MF_DAY, { user: o.t2 })
  eq(a.status, 404, 'ほかの先生は404')
  const b = await w.call('GET', '/api/teacher/teibako?classId=cls-1&mode=day&date=' + MF_DAY, { user: w.student })
  eq(b.status, 403, '子どもは403')
  const c = await w.call('GET', '/api/teacher/teibako/prev?classId=cls-1&userId=stu-x&mode=day&ref=' + MF_DAY, { user: w.teacher })
  eq(c.status, 404, 'よそのクラスの子は見られない')
  // 返却は既存のAPIのまま（コインも既存のまま150）
  await w.call('POST', '/api/teacher/homework/hw-1/return', { user: w.teacher, body: { comment: 'よくできました' } })
  const r2 = await w.call('GET', '/api/teacher/teibako?classId=cls-1&mode=day&date=' + MF_DAY, { user: w.teacher })
  ok(r2.json.items.find((x) => x.userId === 'stu-1').returnedAt > 0, '返却ずみになる')
  eq(w.getState().coins, 1150, '返却のコインは既存どおり')
})

await t('46 週の振り返り：いまの週だけ同意できる → 📋一覧（週）に出る・返却は既存の reflection-comments・採用で300', async () => {
  const w = await newWorld(); const o = mfWorld(w)
  w.setState(smallState({ coins: 1000 }))
  const pre = await mfConsent(w, w.student, 'anon', WR_NOW, 'week')
  eq(pre.json.reason, 'not_submitted', '書く前は同意できない')
  await sendRef(w, '今週は漢字を毎日5こ書いた')
  const c = await mfConsent(w, w.student, 'named', WR_NOW, 'week')
  eq(c.json.saved, true, '書いたあとは同意できる')
  const old = await mfConsent(w, w.student, 'named', WR_OLD, 'week')
  eq(old.json.saved, false, '昔の週は同意できない')
  const r = await w.call('GET', '/api/teacher/teibako?classId=cls-1&mode=week&week=' + WR_NOW, { user: w.teacher })
  const me = r.json.items.find((x) => x.userId === 'stu-1')
  eq(me.freeText, '今週は漢字を毎日5こ書いた', '週の自由欄'); eq(me.submitted, true, '提出あつかい'); eq(me.consent.mode, 'named', '同意')
  eq(r.json.items.filter((x) => x.submitted).length, 1, 'ほかの子は未提出')
  w.db._run("UPDATE structured_reflections SET good_point=? WHERE user_id='stu-1'", '○ まあまあ ／ なんで：毎日書けたから')
  const rk = await w.call('GET', '/api/teacher/teibako?classId=cls-1&mode=week&week=' + WR_NOW, { user: w.teacher })
  eq(rk.json.items.find((x) => x.userId === 'stu-1').kantan, '○まあまあ', 'かんたんふりかえりの ◎○△ が見える')
  const rc = await w.call('POST', '/api/teacher/reflection-comments', { user: w.teacher, body: { weekKey: WR_NOW, comments: [{ studentId: 'stu-1', comment: 'よく書けたね', weekKey: WR_NOW }] } })
  eq(rc.json.saved, 1, '既存の週の返却')
  const r2 = await w.call('GET', '/api/teacher/teibako?classId=cls-1&mode=week&week=' + WR_NOW, { user: w.teacher })
  ok(r2.json.items.find((x) => x.userId === 'stu-1').returnedAt > 0, '返却ずみになる')
  const ad = await w.call('POST', '/api/teacher/minna/adopt', { user: w.teacher, body: { consentId: mfCid(w, 'stu-1'), body: '漢字を毎日5こ書いた' } })
  eq(ad.json.rewardedNow, true, '週の振り返りでも採用で付与')
  eq(w.getState().coins, 1000 + 20 + 300, '週のボーナス20 + 採用300')
  const p = await w.call('GET', '/api/student/minna/posts', { user: o.s2 })
  eq(p.json.posts[0].weekKey, WR_NOW, '週のフォルダ'); eq(p.json.posts[0].name, 'たろう', '名前あり')
})

// ── 🔄 WEEKREF2_V1 週の振り返りを充実（先週決めたこと・今週の記録・考える問い・学校での学び）──
//   コインは既存の週の振り返りの台帳（week_ref_rewards）だけ。week-ref2 そのものはコインを動かさない。
function w2Monday(wk) {
  const m = String(wk).match(/^(\d{4})-W(\d{2})$/); const j4 = new Date(Date.UTC(+m[1], 0, 4)); const dw = j4.getUTCDay() || 7
  return new Date(j4.getTime() + ((1 - dw) + (+m[2] - 1) * 7) * 86400000)
}
const W2_MON = w2Monday(WR_NOW)
const W2_PREV = wrIsoKey(new Date(W2_MON.getTime() - 7 * 86400000))
const W2_MONDAY = W2_MON.toISOString().slice(0, 10)
function w2Seed(w) {
  // 先週の自分が決めたこと（次どうする？・来週やってみたいこと）
  w.db._run("INSERT INTO structured_reflections (user_id, week_key, good_point, next_action, free_text, created_at) VALUES (?,?,?,?,?,?)", 'stu-1', W2_PREV, '◎ よくできた ／ なんで：…', '次：このまま つづける　夜にやる', '先週の ふりかえり', Date.now() - 7 * 86400000)
  w.db._run("INSERT INTO week_next_try (user_id, week_key, unit, unit_name, text) VALUES (?,?,?,?,?)", 'stu-1', W2_PREV, 'm6-ratio', '比', '比をマスターしたい')
  // 今週の計画（月曜に立てたもの）と、月曜の家庭学習
  w.db._run("INSERT INTO student_weekly_plans (user_id, week_key, plans_json, updated_at) VALUES (?,?,?,?)", 'stu-1', WR_NOW, JSON.stringify({ mon: '漢字ドリル', tue: '計算スキル', wed: 'なし', fri: { free: '', reflection: '' } }), Date.now())
  w.db._run("UPDATE homework_submissions SET day_key=? WHERE id='hw-1'", W2_MONDAY)
  // 修行：先週 比を6問・今週 9問 せいかい（UTC の ISO。日本時間の月曜0:00 = 前の日の15:00Z）
  const mon0 = W2_MON.getTime() - 9 * 3600000
  for (let i = 0; i < 8; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', 'stu-1', new Date(mon0 - 3 * 86400000 + i * 60000).toISOString(), 'm6-ratio', i < 6 ? 1 : 0)
  for (let i = 0; i < 10; i++) w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', 'stu-1', new Date(mon0 + 1800000 + i * 60000).toISOString(), 'm6-ratio', i < 9 ? 1 : 0)
  // よその子の修行（数に入らない）
  w.db._run('INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?,?,?,?)', 'stu-2', new Date(mon0 + 3600000).toISOString(), 'm6-ratio', 1)
  // ⑥授業メモ：「教科：単元」の行だけが子どもに出る。名前の入った行・ふつうのメモは出ない
  w.db._run('INSERT INTO teacher_class_notes (class_id, day_key, body, created_by, created_at) VALUES (?,?,?,?,?)', 'cls-1', W2_MONDAY, '算数：比の利用\n今日は発表が活発だった。グループの声かけを工夫したい\n国語：たろうの音読がよかった\n【理科】てこのはたらき\n社会：はなこさんの発表', 'tea-1', new Date().toISOString())
  w.db._run('INSERT INTO teacher_class_notes (class_id, day_key, body, created_by, created_at) VALUES (?,?,?,?,?)', 'cls-2', W2_MONDAY, '算数：よそのクラスの単元', 'tea-2', new Date().toISOString())
}

await t('47 週の振り返りの材料：先週決めたこと・今週の計画・記録（比 6問→9問）・計画を書いた日・授業メモの「教科：単元」だけ・問い', async () => {
  const w = await newWorld(); const o = mfWorld(w); w2Seed(w)
  const n = await w.call('GET', '/api/student/week-ref2')
  eq(n.status, 401, '未ログイン')
  const f = await w.call('GET', '/api/student/week-ref2?userId=stu-2', { user: w.student })
  eq(f.status, 403, 'ほかの子')
  const tch = await w.call('GET', '/api/student/week-ref2', { user: w.teacher })
  eq(tch.status, 403, '先生は子どもの道を使えない')
  const r = await w.call('GET', '/api/student/week-ref2?weekKey=' + WR_NOW, { user: w.student })
  eq(r.status, 200, 'status')
  const d = r.json
  ok(d.promise.text.indexOf('このまま つづける') >= 0 && d.promise.text.indexOf('比をマスターしたい') >= 0, '先週決めたこと：' + d.promise.text)
  eq(d.plan.length, 2, '計画の日（「なし」と空は数えない）'); eq(d.plan[0].day, '月', '月曜')
  eq(d.facts.units[0].unit, 'm6-ratio', '単元'); eq(d.facts.units[0].c, 9, '今週のせいかい'); eq(d.facts.units[0].prevC, 6, '先週のせいかい')
  eq(d.facts.doneDays, 1, '計画した日のうち出した日'); ok(d.facts.planDays >= 1, '計画を書いた日')
  ok(d.facts.openDays >= 1, '開いた日')
  eq(d.topics.length, 2, '授業メモの候補は「教科：単元」の行だけ（名前の行は出ない）')
  eq(d.topics[0].subj + '|' + d.topics[0].theme, '算数|比の利用', '候補1'); eq(d.topics[1].subj + '|' + d.topics[1].theme, '理科|てこのはたらき', '候補2')
  ok(JSON.stringify(d).indexOf('発表が活発') < 0 && JSON.stringify(d).indexOf('たろう') < 0 && JSON.stringify(d).indexOf('よそのクラス') < 0, 'ふつうのメモ・名前・よそのクラスは出ない')
  ok(/^q\d\d$/.test(d.question.id) && d.question.choices.length >= 3, '今週の問い')
  const s = JSON.stringify(d)
  ok(!/rank|順位|average|平均|percent|%/.test(s), '順位・平均・パーセントは返さない')
})

await t('48 ひとまとめで出す → 既存の20コインが1回だけ・week-ref2 は連打・同時送信でもコインを動かさない・1人1週1行', async () => {
  const w = await newWorld(); const o = mfWorld(w); w2Seed(w)
  w.setState(smallState({ coins: 1000 }))
  const g = await w.call('GET', '/api/student/week-ref2?weekKey=' + WR_NOW, { user: w.student })
  const q = g.json.question
  const body = { weekKey: WR_NOW, promise: { result: 'some', reason: 'forgot', note: '夜に わすれた' }, q: { id: q.id, choice: 1, text: '声に出した' }, school: { subj: '算数', theme: '比の利用', learned: '「比の利用」の 問題が できるように なった', more: '家で もう一度 ためしたい' }, unitNames: { 'm6-ratio': '比' } }
  await Promise.all([0, 1, 2].map(() => w.call('POST', '/api/student/week-ref2', { user: w.student, body })))
  eq(w.getState().coins, 1000, 'week-ref2 だけではコインは動かない')
  eq(w.db._all('SELECT * FROM week_ref2').length, 1, '1人1週1行')
  const r = await sendKantan(w)
  eq(r.json.weekRefBonus.rewardedNow, true, 'いつもの提出で20')
  await w.call('POST', '/api/student/week-ref2', { user: w.student, body })
  await sendKantan(w)
  eq(w.getState().coins, 1020, '20コインは1回だけ'); eq(w.getState()._weekRefCoinsApplied, 20, '台帳')
  eq(w.db._all('SELECT * FROM week_ref_rewards').length, 1, '台帳の行数')
  const row = w.db._get('SELECT * FROM week_ref2 WHERE user_id=?', 'stu-1')
  eq(row.promise_result, 'some', '結果'); eq(row.promise_reason, 'forgot', 'わけ'); eq(row.school_subj, '算数', '教科'); eq(row.q_choice, '1', '問いの答え')
  ok(row.promise_text.indexOf('このまま つづける') >= 0, '先週決めたことを写しておく')
  const facts = JSON.parse(row.facts_json)
  eq(facts.units[0].c, 9, '記録はサーバーで数えたもの'); eq(facts.units[0].name, '比', '単元の名前')
})

await t('49 おかしな値・ほかの子・昔の週・金額の申告は入らない／問いのIDがちがえば答えは入らない', async () => {
  const w = await newWorld(); const o = mfWorld(w); w2Seed(w)
  w.setState(smallState({ coins: 1000 }))
  const bad = await w.call('POST', '/api/student/week-ref2', { user: w.student, body: { userId: 'stu-2', weekKey: WR_NOW } })
  eq(bad.status, 403, 'ほかの子のid')
  const tch = await w.call('POST', '/api/student/week-ref2', { user: w.teacher, body: { weekKey: WR_NOW } })
  eq(tch.status, 403, '先生')
  await w.call('POST', '/api/student/week-ref2', { user: w.student, body: { weekKey: WR_OLD, coins: 99999, promise: { result: 'perfect', reason: 'time', note: '<b>x</b>' }, q: { id: 'q99', choice: 9, text: 'ちがう問い' }, school: { subj: '<script>', theme: 'x', learned: 'わかった' }, facts: { openDays: 999 } } })
  const row = w.db._get('SELECT * FROM week_ref2 WHERE user_id=?', 'stu-1')
  eq(row.week_key, WR_NOW, '昔の週は いまの週に'); eq(row.promise_result, '', 'おかしな結果は入らない'); eq(row.promise_reason, '', '結果が無ければ わけも入らない')
  ok(row.promise_note.indexOf('<') < 0, '山かっこは消す'); eq(row.q_id, '', 'ちがう問いは入らない'); eq(row.school_subj, '', 'おかしな教科は入らない'); eq(row.school_theme, '', '教科が無ければテーマも入らない')
  ok(JSON.parse(row.facts_json).openDays < 999, '記録の申告は使わない')
  eq(w.getState().coins, 1000, 'コインは動かない')
  const done = await w.call('POST', '/api/student/week-ref2', { user: w.student, body: { weekKey: WR_NOW, promise: { result: 'done', reason: 'time' } } })
  eq(done.status, 200, 'できた')
  eq(w.db._get('SELECT promise_reason FROM week_ref2 WHERE user_id=?', 'stu-1').promise_reason, '', '「できた」に わけは付けない')
})

await t('50 先生：ひと往復の材料・📋振り返り一覧（週）に 先週の約束の結果と学校での学び・下書きの時刻・個人のカルテ（ほかの先生は404）', async () => {
  const w = await newWorld(); const o = mfWorld(w); w2Seed(w)
  w.setState(smallState({ coins: 1000 }))
  const g = await w.call('GET', '/api/student/week-ref2?weekKey=' + WR_NOW, { user: w.student })
  await w.call('POST', '/api/student/week-ref2', { user: w.student, body: { weekKey: WR_NOW, promise: { result: 'not', reason: 'time' }, q: { id: g.json.question.id, choice: 0 }, school: { subj: '理科', theme: 'てこのはたらき', learned: 'つりあいが わかった', more: 'もっと 調べたい' } } })
  await sendKantan(w)
  const r = await w.call('GET', '/api/teacher/week-reflections?classId=cls-1&weeks=' + WR_NOW, { user: w.teacher })
  const it = r.json.items.find((x) => x.userId === 'stu-1')
  eq(it.wr2.promise.resultJa, 'できなかった', 'ひと往復：結果'); eq(it.wr2.promise.reasonJa, '時間がなかった', 'ひと往復：わけ'); eq(it.wr2.school.subj, '理科', 'ひと往復：学校'); eq(it.wr2.facts.units[0].c, 9, 'ひと往復：記録')
  ok(it.wr2.q && it.wr2.q.choiceJa, 'ひと往復：問いの答え')
  w.db._run("INSERT INTO ai_review_drafts (id, teacher_id, class_id, week_key, kind, target_id, ref_key, body, status, created_at) VALUES (?,?,?,?,?,?,?,?,'draft',datetime('now','-1 hour'))", 'aid_1', 'tea-1', 'cls-1', WR_NOW, 'REFLECT', 'stu-1', WR_NOW, 'てこのはたらき、つりあいが わかったんやな！')
  const tb = await w.call('GET', '/api/teacher/teibako?classId=cls-1&mode=week&week=' + WR_NOW, { user: w.teacher })
  const me = tb.json.items.find((x) => x.userId === 'stu-1')
  eq(me.wr2.school.theme, 'てこのはたらき', '一覧：学校での学び'); eq(me.wr2.promise.result, 'not', '一覧：約束の結果')
  ok(me.draft && me.draft.createdAt > 0 && me.submittedAt > me.draft.createdAt, '下書きの時刻（書き直しの見分け）')
  // まとめて返却＝既存の reflection-comments（同じ先生のクラスの子だけ）
  const rc = await w.call('POST', '/api/teacher/reflection-comments', { user: w.teacher, body: { weekKey: WR_NOW, comments: [{ studentId: 'stu-1', comment: me.draft.body, weekKey: WR_NOW }, { studentId: 'stu-x', comment: 'よその子', weekKey: WR_NOW }] } })
  eq(rc.json.saved, 1, 'よそのクラスの子には返せない')
  const k = await w.call('GET', '/api/teacher/week-ref2?studentId=stu-1', { user: w.teacher })
  eq(k.json.items[0].school.subj, '理科', 'カルテに学校での学び'); eq(k.json.items[0].promise.resultJa, 'できなかった', 'カルテに約束の結果')
  const k2 = await w.call('GET', '/api/teacher/week-ref2?studentId=stu-1', { user: o.t2 })
  eq(k2.status, 404, 'ほかの先生は見られない')
  const k3 = await w.call('GET', '/api/teacher/week-ref2?studentId=stu-1', { user: w.student })
  eq(k3.status, 403, '子どもは先生の道を使えない')
})

await t('51 前の自分ページ：自分の分だけ（未ログイン401・ほかの子403）・約束の結果と学校での学びが週ごとに並ぶ', async () => {
  const w = await newWorld(); const o = mfWorld(w); w2Seed(w)
  w.db._run("INSERT INTO week_ref2 (user_id, week_key, promise_result, school_subj, school_theme) VALUES (?,?,?,?,?)", 'stu-1', W2_PREV, 'done', '算数', '比')
  w.db._run("INSERT INTO week_ref2 (user_id, week_key, promise_result, school_subj) VALUES (?,?,?,?)", 'stu-2', W2_PREV, 'some', '国語')
  const n = await w.call('GET', '/api/student/week-ref2/history')
  eq(n.status, 401, '未ログイン')
  const f = await w.call('GET', '/api/student/week-ref2/history?userId=stu-2', { user: w.student })
  eq(f.status, 403, 'ほかの子')
  const h = await w.call('GET', '/api/student/week-ref2/history', { user: w.student })
  eq(h.json.items.length, 1, '自分の分だけ'); eq(h.json.items[0].promise.resultJa, 'できた', '結果'); eq(h.json.items[0].school.theme, '比', '学校')
  const m = await w.call('GET', '/api/student/week-ref2?weekKey=' + WR_NOW, { user: w.student })
  eq(m.json.last.school.subj, '算数', '月曜の計画画面に出す先週の分')
})

// ── HSCHAT_V1 阪神マンと はじめる家庭学習：提出は いつもの /api/homework/submit（新しいコインの道は作らない）──
function hsCols(w) {
  const cols = ['submitted_at INTEGER', 'todo TEXT', 'why TEXT', 'aim TEXT', 'minutes INTEGER', 'end_weather TEXT', 'weather_reason TEXT', 'next_improve TEXT', 'rest_day INTEGER', 'streak_after INTEGER',
    'reward_kind TEXT', 'reward_coins INTEGER', 'reward_shards INTEGER', 'bonus_coins INTEGER', 'bonus_shards INTEGER', 'self_study_plan TEXT', 'weekly_plan TEXT',
    'work_photo_analysis TEXT', 'parent_comment TEXT', 'reward_claimed INTEGER DEFAULT 0', 'reward_claimed_at INTEGER']
  const have = w.db._all('PRAGMA table_info(homework_submissions)').map((r) => r.name)
  cols.forEach((c) => { if (have.indexOf(c.split(' ')[0]) < 0) w.db.db.exec('ALTER TABLE homework_submissions ADD COLUMN ' + c) })
  try { w.db.db.exec('ALTER TABLE users ADD COLUMN last_login_at TEXT') } catch (_e) {}
}
const HSCHAT_BODY = { dayKey: '2026-10-27', todo: '🅰「分数のかけ算」をもう一度（カルテのおすすめ）', why: 'テストがあるから', aim: '15分 がんばる', minutes: 20,
  endWeather: 'sun', weatherReason: '集中できた', nextImprove: 'このままでOK', selfStudyPlan: '🅰「分数のかけ算」をもう一度（カルテのおすすめ）', weeklyPlan: '', weeklyReflection: '',
  restDay: false, streakAfter: 1, rewardKind: 'coin', rewardCoins: 200, rewardShards: 0, bonusCoins: 0, bonusShards: 1, workPhotoAnalysis: '', parentComment: '' }

await t('52 HSCHAT 対話で出した家庭学習 → いつもの項目にそのまま保存（今日やること・なんで・めあて・時間・天気・理由・次）・先生の一覧に出る', async () => {
  const w = await newWorld(); hsCols(w)
  w.setState(smallState({ coins: 1000 }))
  const r = await w.call('POST', '/api/homework/submit', { user: w.student, body: HSCHAT_BODY })
  eq(r.status, 200, '提出できる'); eq(r.json.instantReward, true, 'いつもの即コインの印')
  const row = w.db._get("SELECT * FROM homework_submissions WHERE user_id=? AND day_key=?", 'stu-1', '2026-10-27')
  eq(row.todo, HSCHAT_BODY.todo, '今日やること'); eq(row.why, 'テストがあるから', 'なんで'); eq(row.aim, '15分 がんばる', 'めあて')
  eq(row.minutes, 20, 'やった時間（タイマー）'); eq(row.end_weather, 'sun', '天気'); eq(row.weather_reason, '集中できた', '天気の理由'); eq(row.next_improve, 'このままでOK', '次にするには')
  eq(row.reward_claimed, 1, 'いつもどおり受け取り済みの印（返却で二重に付かない）')
  eq(w.getState().coins, 1000, 'サーバはコインを動かさない（いつもどおり端末で1回だけ）')
  const l = await w.call('GET', '/api/teacher/homework', { user: w.teacher })
  const it = (l.json.submissions || l.json.items || l.json.rows || []).find((x) => x.dayKey === '2026-10-27')
  ok(it, '先生の一覧に出る'); eq(it.weatherReason, '集中できた', '一覧に理由'); eq(it.nextImprove, 'このままでOK', '一覧に次')
})

await t('53 HSCHAT シートと対話の両方から・連打・同時送信でも 1日1行（2回目は alreadySubmitted・コインの基の行はふえない）', async () => {
  const w = await newWorld(); hsCols(w)
  w.setState(smallState({ coins: 1000 }))
  const rs = await Promise.all([0, 1, 2].map(() => w.call('POST', '/api/homework/submit', { user: w.student, body: HSCHAT_BODY })))
  const sheet = await w.call('POST', '/api/homework/submit', { user: w.student, body: { ...HSCHAT_BODY, todo: 'シートから', rewardCoins: 300 } })
  eq(sheet.json.alreadySubmitted, true, 'シートから2回目は alreadySubmitted')
  eq(w.db._all("SELECT * FROM homework_submissions WHERE user_id=? AND day_key=?", 'stu-1', '2026-10-27').length, 1, '1日1行')
  eq(w.db._get("SELECT reward_coins FROM homework_submissions WHERE user_id=? AND day_key=?", 'stu-1', '2026-10-27').reward_coins, 200, '最初の分のまま')
  eq(w.getState().coins, 1000, 'サーバでコインは動かない')
  ok(rs.filter((r) => r.status === 200).length === 3, 'どれもエラーにはならない')
  const t2 = await w.call('POST', '/api/homework/submit', { user: w.teacher, body: HSCHAT_BODY })
  eq(t2.status, 403, '先生は出せない')
  const n = await w.call('POST', '/api/homework/submit', { body: HSCHAT_BODY })
  ok(n.status === 401 || n.status === 403, 'ログインなしは出せない')
})

// ── HSSIGN_V1 サポーター（おうちの人）のサインを あとから足す：parent_comment だけ・コインの道は作らない ──
function studyDay(ms) { return new Date((ms || Date.now()) + 30 * 60 * 1000).toISOString().slice(0, 10) }
function tableCounts(w) {
  const out = {}
  w.db._all("SELECT name FROM sqlite_master WHERE type='table'").forEach((r) => { if (r.name !== 'homework_submissions') out[r.name] = w.db._get('SELECT COUNT(*) AS n FROM "' + r.name + '"').n })
  return JSON.stringify(out)
}
await t('54 HSSIGN あとからサイン → その日の提出の「サポーターから」に入る・先生の一覧に出る・コイン/台帳/ほかの表は動かない・2回目は上書きしない', async () => {
  const w = await newWorld(); hsCols(w)
  w.setState(smallState({ coins: 1000 }))
  const dk = studyDay()
  await w.call('POST', '/api/homework/submit', { user: w.student, body: { ...HSCHAT_BODY, dayKey: dk } })
  const before = tableCounts(w); const row0 = w.db._get('SELECT * FROM homework_submissions WHERE user_id=? AND day_key=?', 'stu-1', dk)
  const rs = await Promise.all([0, 1, 2].map((i) => w.call('POST', '/api/homework/parent-sign', { user: w.student, body: { dayKey: dk, text: '👍 見たよ　' + i } })))
  eq(rs.filter((r) => r.json && r.json.signed).length, 1, '同時に押しても 入るのは1回')
  const row = w.db._get('SELECT * FROM homework_submissions WHERE user_id=? AND day_key=?', 'stu-1', dk)
  ok(/^👍 見たよ　[012]$/.test(row.parent_comment), 'サポーター欄に入る')
  const again = await w.call('POST', '/api/homework/parent-sign', { user: w.student, body: { dayKey: dk, text: '👍 見たよ　べつの文' } })
  eq(again.json.already, true, '2回目は already'); eq(w.db._get('SELECT parent_comment AS p FROM homework_submissions WHERE user_id=? AND day_key=?', 'stu-1', dk).p, row.parent_comment, '上書きしない')
  ;['reward_coins', 'bonus_coins', 'reward_shards', 'bonus_shards', 'reward_claimed', 'streak_after', 'todo', 'minutes', 'returned_at', 'teacher_comment'].forEach((k) => eq(row[k], row0[k], k + ' は そのまま'))
  eq(w.db._all('SELECT * FROM homework_submissions WHERE user_id=? AND day_key=?', 'stu-1', dk).length, 1, '1日1行のまま')
  eq(tableCounts(w), before, 'ほかの表（コインの台帳など）は1行もふえない')
  eq(w.getState().coins, 1000, 'コインは動かない')
  const l = await w.call('GET', '/api/teacher/homework', { user: w.teacher })
  const it = (l.json.submissions || l.json.items || l.json.rows || []).find((x) => x.dayKey === dk)
  eq(it.parentComment, row.parent_comment, '先生の一覧の「サポーターから」に出る')
})

await t('55 HSSIGN その日の分だけ・提出なしは404・シートで書いた文は上書きしない・先生/ログインなし/空文は入らない', async () => {
  const w = await newWorld(); hsCols(w)
  const dk = studyDay(); const old = studyDay(Date.now() - 86400000)
  const none = await w.call('POST', '/api/homework/parent-sign', { user: w.student, body: { dayKey: dk, text: '👍 見たよ' } })
  eq(none.status, 404, 'まだ提出していない日は404')
  await w.call('POST', '/api/homework/submit', { user: w.student, body: { ...HSCHAT_BODY, dayKey: old } })
  const o = await w.call('POST', '/api/homework/parent-sign', { user: w.student, body: { dayKey: old, text: '👍 見たよ' } })
  eq(o.status, 400, '前の日の提出には足せない'); eq(w.db._get('SELECT parent_comment AS p FROM homework_submissions WHERE day_key=?', old).p, '', '前の日はそのまま')
  await w.call('POST', '/api/homework/submit', { user: w.student, body: { ...HSCHAT_BODY, dayKey: dk, parentComment: 'シートに書きました' } })
  const s2 = await w.call('POST', '/api/homework/parent-sign', { user: w.student, body: { dayKey: dk, text: '👍 見たよ' } })
  eq(s2.json.already, true, 'シートで書いた日は already'); eq(w.db._get('SELECT parent_comment AS p FROM homework_submissions WHERE day_key=?', dk).p, 'シートに書きました', '上書きしない')
  w.db._run("UPDATE homework_submissions SET parent_comment='' WHERE day_key=?", dk)
  eq((await w.call('POST', '/api/homework/parent-sign', { user: w.student, body: { dayKey: dk, text: '   ' } })).status, 400, '空の文は入らない')
  eq((await w.call('POST', '/api/homework/parent-sign', { user: w.teacher, body: { dayKey: dk, text: '👍 見たよ' } })).status, 403, '先生は入れられない')
  const n = await w.call('POST', '/api/homework/parent-sign', { body: { dayKey: dk, text: '👍 見たよ' } })
  ok(n.status === 401 || n.status === 403, 'ログインなしは入れられない')
  eq(w.db._get('SELECT parent_comment AS p FROM homework_submissions WHERE day_key=?', dk).p, '', 'どれも入っていない')
  const long = await w.call('POST', '/api/homework/parent-sign', { user: w.student, body: { dayKey: dk, text: '👍 見たよ　' + 'あ'.repeat(800) } })
  eq(long.json.signed, true, '長い文は'); eq(Array.from(w.db._get('SELECT parent_comment AS p FROM homework_submissions WHERE day_key=?', dk).p).length, 500, '500字まで（シートと同じ）')
})

// ── HSWEEKCHAT_V1 阪神マンと ふりかえる：対話で出しても いまの画面と同じ道（weekly-reflection・week-ref2・kantan-ref）──
await t('56 HSWEEKCHAT 対話で出す（じぶんの ことばの わけ）→ 項目欄・week-ref2 に入る → 画面から出しなおしても 20コインは週1回・台帳1行', async () => {
  const w = await newWorld(); const o = mfWorld(w); w2Seed(w)
  w.setState(smallState({ coins: 1000 }))
  const g = await w.call('GET', '/api/student/week-ref2?weekKey=' + WR_NOW, { user: w.student })
  const q = g.json.question
  // 対話（hsweekchat.js → KANTAN.send）が送るのと同じ形（tests/hsweekchat.test.mjs の 3 で 画面と同じことを確かめている）
  await Promise.all([
    w.call('POST', '/api/student/kantan-ref', { user: w.student, body: { weekKey: WR_NOW, self: 'more', reason: '', next: 'keep', how: '', mood: '', addedChars: 9 } }),
    w.call('POST', '/api/student/week-ref2', { user: w.student, body: { weekKey: WR_NOW, promise: { result: 'not', reason: 'other', note: 'いそがしかった' }, q: { id: q.id, choice: -1, text: '声に 出すと おぼえやすい' }, school: { subj: '国語', theme: '', learned: '音読が すらすら できた', more: '' }, unitNames: {} } }),
  ])
  const r1 = await w.call('POST', '/api/student/weekly-reflection', { user: w.student, body: { weekKey: WR_NOW, dayKey: kDay(0), freeText: '今週の 自分の 学びは △もう少し。そう思うのは、時間が つくりにくかったから。', goodPoint: '△ もう少し ／ なんで：時間が つくりにくかった', improvePoint: '', nextAction: '次：このまま つづける　朝に やる' } })
  eq(r1.json.weekRefBonus.rewardedNow, true, '対話から出して 20')
  const r2 = await sendKantan(w)   // いまの画面から 出しなおし
  ok(!(r2.json.weekRefBonus && r2.json.weekRefBonus.rewardedNow), '画面から出しなおしても 付かない')
  await w.call('POST', '/api/student/weekly-reflection', { user: w.student, body: { weekKey: WR_NOW, dayKey: kDay(0), freeText: '今週の 自分の 学びは ○まあまあ。もう一度 対話から。', goodPoint: '○ まあまあ ／ なんで：x', improvePoint: '', nextAction: '次：x' } })
  eq(w.getState().coins, 1020, '20コインは1回だけ'); eq(w.db._all('SELECT * FROM week_ref_rewards').length, 1, '台帳1行')
  const sr = w.db._get('SELECT * FROM structured_reflections WHERE user_id=? AND week_key=?', 'stu-1', WR_NOW)
  ok(sr && sr.good_point.indexOf('○ まあまあ') === 0 && sr.next_action === '次：x', '項目欄は 最後に出した分（いつもの上書き）')
  const row = w.db._get('SELECT * FROM week_ref2 WHERE user_id=?', 'stu-1')
  eq(row.promise_result, 'not', '先週決めたこと'); eq(row.promise_reason, 'other', 'わけ（その他）'); eq(row.promise_note, 'いそがしかった', 'じぶんの ことば'); eq(row.school_subj, '国語', '学校での学び'); eq(row.q_text, '声に 出すと おぼえやすい', '問い（ことばだけ）')
  eq(w.db._all('SELECT * FROM week_ref2').length, 1, '1人1週1行')
})

// ── 結果表 ────────────────────────────────────────────────────
const pass = results.filter((r) => r.ok).length
console.log('\n=== ' + BUNDLE + ' ===')
for (const r of results) console.log((r.ok ? 'PASS' : 'FAIL') + ' | ' + r.name + (r.note ? ' | ' + r.note : ''))
console.log(`\n${pass}/${results.length} passed`)
console.log('JSONRESULT ' + JSON.stringify(results))
process.exit(pass === results.length ? 0 : 1)
