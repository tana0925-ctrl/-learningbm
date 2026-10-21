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

// ── 結果表 ────────────────────────────────────────────────────
const pass = results.filter((r) => r.ok).length
console.log('\n=== ' + BUNDLE + ' ===')
for (const r of results) console.log((r.ok ? 'PASS' : 'FAIL') + ' | ' + r.name + (r.note ? ' | ' + r.note : ''))
console.log(`\n${pass}/${results.length} passed`)
console.log('JSONRESULT ' + JSON.stringify(results))
process.exit(pass === results.length ? 0 : 1)
