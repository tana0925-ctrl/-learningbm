// 📮 TEISHUTSU_V1 提出状況のアドバイス — テスト
//   - サーバー：実際のハンドラ（src/index.tsx を esbuild でバンドルしたもの）を app.fetch で呼ぶ。D1 は node:sqlite（本番DBには触らない）
//   - 画面：public/teishutsu.js・student-karte.js・karte-michi.js・teishutsu-teacher.js・teacher-ai.js を jsdom で動かす
//   使い方: node tests/teishutsu.test.mjs ./app.after.mjs   （jsdom が必要: npm i --no-save jsdom）
import { FakeD1, SCHEMA } from './d1.mjs'
import { readFileSync } from 'node:fs'
import { JSDOM } from 'jsdom'

const ROOT = new URL('..', import.meta.url).pathname
const BUNDLE = process.argv[2] || './app.after.mjs'
const SECRET = 'test-session-secret'
const MIG = readFileSync(ROOT + 'migrations/0049_school_assignments.sql', 'utf8')
const rd = (p) => readFileSync(ROOT + p, 'utf8')
let _i = 0

function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }
async function sign(payload) {
  const enc = new TextEncoder()
  const data = b64u(enc.encode(JSON.stringify(payload)))
  const key = await crypto.subtle.importKey('raw', enc.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data))
  return `v1.${data}.${b64u(new Uint8Array(sig))}`
}
const EXTRA = `
CREATE TABLE IF NOT EXISTS makeup_grants (grant_key TEXT PRIMARY KEY, user_id TEXT, coins INTEGER, applied_at TEXT);
CREATE TABLE IF NOT EXISTS login_attempts (login_id TEXT PRIMARY KEY, fail_count INTEGER, first_fail_at INTEGER, last_fail_at INTEGER, locked_until INTEGER);
CREATE TABLE IF NOT EXISTS student_test_scores (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id TEXT NOT NULL, test_name TEXT, test_date TEXT, subject TEXT, max_score INTEGER DEFAULT 100, score INTEGER, comment TEXT, created_by TEXT, created_at TEXT, eval_rank TEXT, eval_knowledge TEXT, eval_thinking TEXT, eval_attitude TEXT);
CREATE TABLE IF NOT EXISTS homework_photos2 (user_id TEXT NOT NULL, day_key TEXT NOT NULL, idx INTEGER NOT NULL DEFAULT 0, mime_type TEXT, bytes BLOB, byte_size INTEGER, created_at TEXT, PRIMARY KEY (user_id, day_key, idx));
CREATE TABLE IF NOT EXISTS student_karte_shared (user_id TEXT PRIMARY KEY, class_id TEXT, shared_at TEXT, shared_by TEXT);
CREATE TABLE IF NOT EXISTS student_ai_comments (user_id TEXT PRIMARY KEY, comment TEXT);
ALTER TABLE homework_submissions ADD COLUMN submitted_at INTEGER;
ALTER TABLE homework_submissions ADD COLUMN minutes INTEGER DEFAULT 0;
ALTER TABLE homework_submissions ADD COLUMN end_weather TEXT DEFAULT 'sun';
ALTER TABLE homework_submissions ADD COLUMN weather_reason TEXT DEFAULT '';
ALTER TABLE homework_submissions ADD COLUMN rest_day INTEGER DEFAULT 0;
`
const jst = (ms) => new Date(ms + 9 * 3600000).toISOString().slice(0, 10)
const addD = (ymd, n) => new Date(Date.parse(ymd + 'T00:00:00Z') + n * 86400000).toISOString().slice(0, 10)

async function world() {
  const db = new FakeD1()
  db.db.exec(SCHEMA); db.db.exec(EXTRA); db.db.exec(MIG)
  const app = (await import(`${BUNDLE}?i=${++_i}`)).default
  const env = { DB: db, SESSION_SECRET: SECRET, ADMIN_LOGIN_ID: '', ADMIN_PASSWORD: '', AI: null, ASSETS: { fetch: async () => new Response('nf', { status: 404 }) } }
  async function call(method, path, { user, body } = {}) {
    const headers = { 'content-type': 'application/json' }
    if (user) headers.cookie = 'session=' + await sign({ id: user.id, role: user.role, loginId: user.loginId || user.id, isActive: true, iat: Math.floor(Date.now() / 1000) })
    const res = await app.fetch(new Request('https://test.local' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }), env, { waitUntil() {}, passThroughOnException() {} })
    let json = null; try { json = await res.clone().json() } catch (_e) {}
    return { status: res.status, json }
  }
  const kid = { id: 'stu-1', role: 'student', loginId: 'kid1' }, kid2 = { id: 'stu-2', role: 'student', loginId: 'kid2' }, kid3 = { id: 'stu-3', role: 'student', loginId: 'kid3' }
  const teacher = { id: 'tea-1', role: 'teacher', loginId: 'sensei' }, other = { id: 'tea-2', role: 'teacher', loginId: 'sensei2' }, admin = { id: 'adm-1', role: 'admin', loginId: 'admin' }
  for (const [u, n, no] of [[kid, 'テストA', 2], [kid2, 'テストB', 1], [kid3, 'テストC', 1]]) db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active, roster_no) VALUES (?,?,?,?,6,'6-2',1,?)", u.id, 'student', u.loginId, n, no)
  db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,0,'-',1)", admin.id, 'admin', 'admin', 'かんり')
  db._run("INSERT INTO teacher_accounts (id, login_id, name, school) VALUES (?,?,?,?)", teacher.id, 'sensei', 'A', 'テスト小')
  db._run("INSERT INTO teacher_accounts (id, login_id, name, school) VALUES (?,?,?,?)", other.id, 'sensei2', 'B', 'テスト小')
  db._run("INSERT INTO classes (id, teacher_id, name) VALUES ('cls-1', ?, '6年2組')", teacher.id)
  db._run("INSERT INTO classes (id, teacher_id, name) VALUES ('cls-2', ?, '6年1組')", other.id)
  db._run("INSERT INTO class_members (class_id, user_id) VALUES ('cls-1', ?)", kid.id)
  db._run("INSERT INTO class_members (class_id, user_id) VALUES ('cls-1', ?)", kid2.id)
  db._run("INSERT INTO class_members (class_id, user_id) VALUES ('cls-2', ?)", kid3.id)
  return { db, call, kid, kid2, kid3, teacher, other, admin }
}

const results = []
async function t(name, fn) {
  try { await fn(); results.push({ name, ok: true }); console.log('PASS | ' + name) }
  catch (e) { results.push({ name, ok: false }); console.log('FAIL | ' + name + '\n   ' + (e && e.stack || e)) }
}
function eq(a, b, m) { if (a !== b) throw new Error((m || 'eq') + ': ' + JSON.stringify(a) + ' !== ' + JSON.stringify(b)) }
function ok(v, m) { if (!v) throw new Error(m || 'not ok') }

// ───────── サーバー ─────────
await t('S1 先生が作る→名簿の格子（出席番号順）→✓→取り消し→全員✓→完了→けす', async () => {
  const w = await world()
  const today = jst(Date.now())
  const c1 = await w.call('POST', '/api/teacher/teishutsu/create', { user: w.teacher, body: { classId: 'cls-1', title: '漢字ドリル p.30〜31', dueDate: addD(today, 1), subject: '国語' } })
  eq(c1.status, 200); ok(c1.json.ok && c1.json.id)
  let g = await w.call('GET', '/api/teacher/teishutsu?classId=cls-1', { user: w.teacher })
  eq(g.json.roster.map((r) => r.userId).join(','), 'stu-2,stu-1', '出席番号順'); eq(g.json.items.length, 1)
  let k = await w.call('POST', '/api/teacher/teishutsu/check', { user: w.teacher, body: { id: c1.json.id, userId: w.kid.id, on: true } })
  ok(k.json.ok && k.json.on); eq(k.json.day, today)
  g = await w.call('GET', '/api/teacher/teishutsu?classId=cls-1', { user: w.teacher }); eq(g.json.items[0].checked[w.kid.id], today)
  await w.call('POST', '/api/teacher/teishutsu/check', { user: w.teacher, body: { id: c1.json.id, userId: w.kid.id, on: false } })
  g = await w.call('GET', '/api/teacher/teishutsu?classId=cls-1', { user: w.teacher }); eq(Object.keys(g.json.items[0].checked).length, 0, '取り消し')
  const all = await w.call('POST', '/api/teacher/teishutsu/check', { user: w.teacher, body: { id: c1.json.id, all: true } })
  eq(all.json.added, 2, '全員✓はそのクラスの2人だけ')
  eq(w.db._get('SELECT COUNT(*) AS n FROM school_assignment_checks').n, 2)
  await w.call('POST', '/api/teacher/teishutsu/update', { user: w.teacher, body: { id: c1.json.id, done: true } })
  g = await w.call('GET', '/api/teacher/teishutsu?classId=cls-1', { user: w.teacher }); ok(g.json.items[0].doneAt, '完了で畳む')
  await w.call('POST', '/api/teacher/teishutsu/update', { user: w.teacher, body: { id: c1.json.id, deleted: true } })
  g = await w.call('GET', '/api/teacher/teishutsu?classId=cls-1', { user: w.teacher }); eq(g.json.items.length, 0, 'けす')
})

await t('S2 担任は自分のクラスだけ（ほかの先生 404・子ども 403・管理者は全クラス・ほかのクラスの子に✓できない）', async () => {
  const w = await world()
  eq((await w.call('GET', '/api/teacher/teishutsu?classId=cls-1', { user: w.other })).status, 404)
  eq((await w.call('GET', '/api/teacher/teishutsu?classId=cls-1', { user: w.kid })).status, 403)
  eq((await w.call('POST', '/api/teacher/teishutsu/create', { user: w.other, body: { classId: 'cls-1', title: 'x' } })).status, 404)
  eq((await w.call('GET', '/api/teacher/teishutsu?classId=cls-2', { user: w.admin })).status, 200, '管理者')
  const c = await w.call('POST', '/api/teacher/teishutsu/create', { user: w.teacher, body: { classId: 'cls-1', title: 'プリント' } })
  eq((await w.call('POST', '/api/teacher/teishutsu/check', { user: w.teacher, body: { id: c.json.id, userId: w.kid3.id, on: true } })).status, 404, '別クラスの子')
  eq((await w.call('POST', '/api/teacher/teishutsu/check', { user: w.other, body: { id: c.json.id, userId: w.kid.id, on: true } })).status, 404, 'ほかの先生')
  eq((await w.call('POST', '/api/teacher/teishutsu/update', { user: w.other, body: { id: c.json.id, deleted: true } })).status, 404)
  eq((await w.call('GET', '/api/teacher/teishutsu/student?studentId=' + w.kid.id, { user: w.other })).status, 404)
  eq((await w.call('GET', '/api/teacher/teishutsu/student?studentId=' + w.kid.id, { user: w.teacher })).status, 200)
})

await t('S3 子ども：自分の まだの提出物だけ（しめきりが近い順・出したら消える・完了で消える・ほかの子の状況は返さない）', async () => {
  const w = await world()
  const today = jst(Date.now())
  const mk = async (title, due) => (await w.call('POST', '/api/teacher/teishutsu/create', { user: w.teacher, body: { classId: 'cls-1', title, dueDate: due } })).json.id
  const a = await mk('計算ドリル', addD(today, 3)), b = await mk('漢字ノート', addD(today, 1)), c = await mk('作文', addD(today, -2))
  await w.call('POST', '/api/teacher/teishutsu/create', { user: w.other, body: { classId: 'cls-2', title: 'ほかのクラス' } })
  await w.call('POST', '/api/teacher/teishutsu/check', { user: w.teacher, body: { id: a, userId: w.kid2.id, on: true } })
  let r = await w.call('GET', '/api/student/teishutsu', { user: w.kid })
  eq(r.status, 200); eq(r.json.pending.map((x) => x.title).join(','), '作文,漢字ノート,計算ドリル', '近い順（過ぎたものが先）')
  eq(r.json.pending[1].daysLeft, 1)
  const s = JSON.stringify(r.json); ok(s.indexOf('stu-2') < 0 && s.indexOf('テストB') < 0 && s.indexOf('ほかのクラス') < 0, 'ほかの子・ほかのクラスの情報なし')
  ok(!('checked' in r.json.pending[0]) && !('roster' in r.json), '名簿や✓の一覧は返さない')
  await w.call('POST', '/api/teacher/teishutsu/check', { user: w.teacher, body: { id: b, userId: w.kid.id, on: true } })
  await w.call('POST', '/api/teacher/teishutsu/update', { user: w.teacher, body: { id: c, done: true } })
  r = await w.call('GET', '/api/student/teishutsu', { user: w.kid })
  eq(r.json.pending.map((x) => x.title).join(','), '計算ドリル', '出したら・完了なら消える')
  eq(r.json.onTimeWeek, 1, 'しめきり前に出せた（今週）')
  eq((await w.call('GET', '/api/student/teishutsu?userId=' + w.kid2.id, { user: w.kid })).status, 403, '他人を指定したら 403')
  eq((await w.call('GET', '/api/student/teishutsu')).status, 401)
})

await t('S4 今週の家庭学習の日数＝週の振り返りの📊今週の記録（hwDays）・わたしのカルテ と同じ数', async () => {
  const w = await world()
  const now = Date.now()
  const r0 = await w.call('GET', '/api/student/week-ref2', { user: w.kid })
  const wk = r0.json.weekKey
  const m = wk.match(/^(\d{4})-W(\d{2})$/); const j4 = new Date(Date.UTC(+m[1], 0, 4)); const dw = j4.getUTCDay() || 7
  const mon = new Date(j4.getTime() + ((1 - dw) + (+m[2] - 1) * 7) * 86400000).toISOString().slice(0, 10)
  let n = 0
  for (const d of [0, 2, 6, -1, 7]) {   // 月・水・日（＋前の週の日曜・次の週の月曜は数えない）
    w.db._run("INSERT INTO homework_submissions (id, user_id, day_key, submitted_at, minutes) VALUES (?,?,?,?,20)", 'h' + d, w.kid.id, addD(mon, d), now)
    if (d >= 0 && d <= 6 && addD(mon, d) <= jst(now + 86400000 * 7)) n++
  }
  const a = await w.call('GET', '/api/student/teishutsu', { user: w.kid })
  const b = await w.call('GET', '/api/student/week-ref2', { user: w.kid })
  eq(a.json.hw.days, 3); eq(b.json.facts.hwDays, a.json.hw.days, '📊今週の記録と同じ')
  w.db._run("INSERT INTO student_karte_shared (user_id, class_id) VALUES (?, 'cls-1')", w.kid.id)
  const k = await w.call('GET', '/api/student/my-karte', { user: w.kid })
  eq(k.json.teishutsu.hwDays, a.json.hw.days, 'わたしのカルテと同じ')
})

await t('S5 個人分析（student-full-analysis）に teishutsu：カルテの週・提出のようす・テストの傾向（点数なし・通知表は除く）', async () => {
  const w = await world()
  const today = jst(Date.now())
  w.db._run("INSERT INTO student_test_scores (user_id, test_name, test_date, subject, max_score, score, created_at, eval_knowledge, eval_thinking) VALUES (?, 'たしかめテスト ⑤ 分数÷分数', '', '算数', 100, 72, ?, '○', '△')", w.kid.id, today + 'T00:00:00Z')
  w.db._run("INSERT INTO student_test_scores (user_id, test_name, test_date, subject, max_score, score, created_at, eval_knowledge) VALUES (?, '通知表 観点別評価（学習データ確定 v1・知技）', ?, '算数', 100, 90, ?, '◎')", w.kid.id, today, today)
  w.db._run("INSERT INTO student_test_scores (user_id, test_name, test_date, subject, max_score, score, created_at) VALUES (?, '点だけのテスト', ?, '国語', 100, 50, ?)", w.kid.id, today, today)
  w.db._run("INSERT INTO learning_results (user_id, answered_at, unit, is_correct) VALUES (?, ?, 'm6-frac-div', 1)", w.kid.id, new Date(Date.now() - 2 * 86400000).toISOString())
  const r = await w.call('GET', '/api/teacher/student-full-analysis?studentId=' + w.kid.id, { user: w.teacher })
  eq(r.status, 200); const tp = r.json.teishutsu; ok(tp, 'teishutsu あり'); ok(tp.karteWeek && tp.karteWeek.from, 'カルテの週')
  eq(tp.tests.length, 1, '観点のついたテストだけ（通知表・点だけは除く）')
  const s = JSON.stringify(tp.tests); ok(s.indexOf('72') < 0 && s.indexOf('score') < 0 && s.indexOf('max') < 0, '点数を返さない')
  eq(tp.tests[0].t, '△'); eq(tp.tests[0].dateFrom, 'import'); eq(tp.tests[0].prep[0].unit, 'm6-frac-div')
  eq((await w.call('GET', '/api/teacher/student-full-analysis?studentId=' + w.kid3.id, { user: w.teacher })).status, 404, 'ほかのクラスの子')
})

await t('S6 提出のようす：しめきりの前の日に出す回数・教科ごと・写真の日と学習時間（事実だけ）', async () => {
  const w = await world()
  const today = jst(Date.now())
  for (let i = 0; i < 3; i++) {
    const id = (await w.call('POST', '/api/teacher/teishutsu/create', { user: w.teacher, body: { classId: 'cls-1', title: '計算ドリル' + i, dueDate: addD(today, 1), subject: '算数' } })).json.id
    await w.call('POST', '/api/teacher/teishutsu/check', { user: w.teacher, body: { id, userId: w.kid.id, on: true } })
  }
  const d830 = new Date(Date.now() + 9 * 3600000 - 8.5 * 3600000).toISOString().slice(0, 10)
  for (let i = 0; i < 4; i++) {
    const dk = addD(d830, -i)
    w.db._run("INSERT INTO homework_submissions (id, user_id, day_key, submitted_at, minutes, end_weather) VALUES (?,?,?,?,?, 'sun')", 'hh' + i, w.kid.id, dk, Date.parse(dk + 'T10:30:00Z'), i < 2 ? 40 : 15)
    if (i < 2) w.db._run("INSERT INTO homework_photos2 (user_id, day_key, idx, bytes) VALUES (?,?,0,x'00')", w.kid.id, dk)
  }
  const r = await w.call('GET', '/api/teacher/teishutsu/student?lite=1&studentId=' + w.kid.id, { user: w.teacher })
  const h = r.json.habits
  eq(h.school.before, 3); eq(h.school.lead['1日前'], 3); eq(h.school.bySubject['算数'].onTime, 3)
  eq(h.hw.n, 4); eq(h.hw.photoDays, 2); eq(h.hw.minPhoto, 40); eq(h.hw.minNoPhoto, 15); eq(h.hw.band['夕方〜夜（18〜21時）'], 4)
  eq(r.json.tests, null, 'lite はテストを読まない')
})

await t('S7 DDL はリクエスト経路に無い（migrations だけ）', async () => {
  const src = rd('src/teishutsu.ts') + rd('src/index.tsx')
  ok(!/CREATE TABLE[^;]*school_assign/i.test(src) && !/ALTER TABLE[^;]*school_assign/i.test(src), 'DDL なし')
  const ts = rd('src/teishutsu.ts').replace(/\/\/[^\n]*/g, '')
  ok(!/\b(CREATE|ALTER|DROP)\s+(TABLE|INDEX)/i.test(ts), 'teishutsu.ts に DDL なし')
})

// ───────── 画面 ─────────
const taiDom = new JSDOM('<!doctype html><body></body>', { runScripts: 'dangerously' })
{ const s = taiDom.window.document.createElement('script'); s.textContent = rd('public/teacher-ai.js'); taiDom.window.document.body.appendChild(s) }
const ng = (x) => taiDom.window.taiNgHits(x)

await t('U1 NG の黄色い印：数字＋点／%／位 を見つける（3日・10問 は見つけない）', async () => {
  ok(ng('テスト80点やったな').length, '80点'); ok(ng('クラスで1位').length, '1位'); ok(ng('正答率75%やで').length, '75%'); ok(ng('９０％').length, '全角')
  eq(ng('今週は3日出せとるで！10問といたな').length, 0, '日・問は印なし')
})

async function kidDom(api, { ls = {}, hello = false } = {}) {
  const dom = new JSDOM('<!doctype html><body><div id="homeReviewSuggest"></div></body>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/' })
  const w = dom.window
  for (const k of Object.keys(ls)) w.localStorage.setItem(k, ls[k])
  w.eval('var player = { userId: "stu-1" };')
  w.fetch = async (url) => ({ ok: true, json: async () => api })
  const s = w.document.createElement('script'); s.textContent = rd('public/teishutsu.js'); w.document.body.appendChild(s)
  return w
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

await t('U2 子ども：📮まだの提出物（近い順・小さく）＋阪神マンの一言は1日1回まで（対話と合わせて）', async () => {
  const api = { ok: true, hw: { days: 3, submittedToday: false }, onTimeWeek: 1, pending: [{ id: 'a', title: '漢字ドリル p.30', subject: '国語', dueDate: '2026-10-28', daysLeft: 1 }, { id: 'b', title: '計算プリント', subject: '', dueDate: '', daysLeft: null }] }
  const w = await kidDom(api)
  await sleep(1800)
  const box = w.document.getElementById('tsPendingBox'); ok(box && box.style.display !== 'none', '箱が出る')
  ok(/漢字ドリル p\.30/.test(box.textContent) && /明日まで/.test(box.textContent), '明日まで')
  ok(/明日までやで。いっしょに がんばろ！/.test(box.textContent), '阪神マンの一言')
  const line = w.TEISHUTSU_CHAT_LINE()
  ok(/今週は 3日 出せとるで！ あと1日 いけるか？/.test(line) && /明日まで/.test(line), '対話の一言')
  eq(w.TEISHUTSU_CHAT_LINE(), '', '同じ日は2回目なし')
})

await t('U3 ことばに NG語なし（いろいろな場合）・しめきりを過ぎても責めない', async () => {
  const w = await kidDom({ ok: true, hw: { days: 0 }, pending: [] })
  await sleep(100)
  const S = w.TS_SAY, out = []
  for (const h of [{ days: 0 }, { days: 1 }, { days: 4, submittedToday: true }, { days: 2, submittedToday: false }]) out.push(S.hwLine({ hw: h }))
  for (const dl of [null, -5, -1, 0, 1, 2, 6]) { const it = { title: 'ノート', dueDate: '2026-11-02', daysLeft: dl }; out.push(S.itemLine(it)); out.push(S.dueLabel(it)) }
  out.forEach((x) => eq(ng(x).length, 0, 'NG: ' + x))
  ok(out.indexOf('今週は これからやな、今日の 1回目 いこか！') >= 0)
  ok(/出せたら 先生に わたそな/.test(S.itemLine({ title: 'x', daysLeft: -3 })), '過ぎても責めない')
})

await t('U4 わたしのカルテ（画面）：今週の家庭学習：〇日・しめきり前の提出物・📮出し方のヒント・📝テストに向けて（未提出の数は出さない）', async () => {
  const dom = new JSDOM('<!doctype html><body><div id="homeReviewSuggest"></div></body>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/' })
  const w = dom.window
  const msg = '先週は3日やったな。\n▼考えてほしいこと\nどうやった？\n▼これやってみる？\n・分数を1問\n▼出し方のヒント\nしめきりの前の日に出すことが多いな。あと1日早めると よゆうができるで\n▼テストに向けて\n計算はばっちりやな。文章題は、式を言葉で説明する練習をしてみよか'
  const api = { ok: true, published: true, week: { days: [], done: 2, minutes: 40, voices: [] }, teacherMessage: msg, kantan: { openDays: 5, hwDays14: 6 }, teishutsu: { hwDays: 4, onTime: 3 } }
  w.fetch = async () => ({ ok: true, json: async () => api })
  const s = w.document.createElement('script'); s.textContent = rd('public/student-karte.js'); w.document.body.appendChild(s)
  await sleep(1300)
  const t0 = w.document.getElementById('myKarteCard').textContent
  ok(t0.indexOf('今週の家庭学習：4日') >= 0, '今週の家庭学習'); ok(t0.indexOf('しめきり前に出せた提出物：3つ') >= 0)
  ok(t0.indexOf('今週は 家庭学習を') < 0, '重複させない')
  ok(t0.indexOf('📮 出し方のヒント') >= 0 && t0.indexOf('あと1日早めると') >= 0, 'ヒント'); ok(t0.indexOf('📝 テストに向けて') >= 0 && t0.indexOf('説明する練習') >= 0, 'テスト')
  ok(t0.indexOf('未提出') < 0, '未提出の数なし')
})

await t('U5 印刷カルテ：AIの▼出し方のヒント／▼テストに向けて を阪神マン欄に・無い週は事実の一言・グラフから省く（data-opt）', async () => {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/teacher' })
  const w = dom.window
  w.eval("window._buildKarteHtml = function(){ return '<html><head><style>.x{}</style></head><body><div class=\"head\"><div class=\"nm\">A</div><div class=\"pd\">p</div></div><div class=\"sec\"><h2>🐯 阪神マンから</h2>x</div></body></html>' }")
  const s = w.document.createElement('script'); s.textContent = rd('public/karte-michi.js'); w.document.body.appendChild(s)
  await sleep(50)
  const sp = w.michiSplitAi('本文\n▼出し方のヒント\n・前の日に出すことが多いな\n▼テストに向けて\n説明の練習してみよか')
  eq(sp.hint, '前の日に出すことが多いな'); eq(sp.test, '説明の練習してみよか'); eq(sp.main, '本文')
  w._faData = { aiComment: '本文です。\n▼出し方のヒント\n前の日に出すことが多いな', teishutsu: { karteWeek: { from: '2026-10-19', to: '2026-10-25', hwDays: 4, onTime: 2 } } }
  const h1 = w._buildKarteHtml()
  ok(h1.indexOf('出し方のヒント') >= 0 && h1.indexOf('前の日に出すことが多いな') >= 0, 'ヒントが阪神マン欄に')
  w._faData = { aiComment: '本文です。', teishutsu: { karteWeek: { from: '2026-10-19', to: '2026-10-25', hwDays: 4, onTime: 2 } } }
  const h2 = w._buildKarteHtml()
  ok(h2.indexOf('この週の家庭学習：4日') >= 0 && h2.indexOf('しめきり前に出せた提出物：2つ') >= 0, '事実の一言')
  w._faData = { aiComment: '', teishutsu: { karteWeek: { from: '2026-10-19', to: '2026-10-25', hwDays: 3, onTime: 0 } } }
  const h3 = w._buildKarteHtml()
  ok(h3.indexOf('この週の家庭学習：3日') >= 0, 'AIが無い週も事実の一言'); ok(h3.indexOf('しめきり前に出せた提出物') < 0, '0 は出さない')
  const km = rd('public/karte-michi.js'); ok(km.indexOf('data-opt="1"><h2>📊') >= 0 && km.indexOf('data-opt="2"') >= 0 && km.indexOf('[data-opt]') >= 0, '省ける欄の印（📊→💡の順）')
  ok(h1.indexOf('未提出') < 0 && h2.indexOf('未提出') < 0, '未提出の数なし')
})

await t('U6 ひと往復のコピー：提出のようす（事実）・テストの傾向（言葉だけ・点数／％なし・名前なし）・テストが無ければ何も言わない', async () => {
  const dom = new JSDOM('<!doctype html><body><div id="fullAnalysisContent"></div></body>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/teacher' })
  const w = dom.window
  w.eval("window.UNIT_JP = { 'm6-frac-div': '分数÷分数', 'm6-ratio': '比とその利用' }")
  const s = w.document.createElement('script'); s.textContent = rd('public/teishutsu-teacher.js'); w.document.body.appendChild(s)
  const base = { ok: true, student: { id: 'stu-1', name: 'テストA' }, subjects: [{ unit: 'm6-frac-div', total: 42, rate: 88 }, { unit: 'm6-ratio', total: 3, rate: 33 }],
    teishutsu: { habits: { school: { n: 5, before: 4, same: 0, after: 1, lead: { '1日前': 3, '2日前': 1, 'あと': 1 }, bySubject: { '算数': { n: 3, onTime: 3 }, '国語': { n: 2, onTime: 1 } }, kinds: { 'ドリル': { n: 3, onTime: 2, late: 1, open: 1 } } },
      hw: { n: 8, dow: [0, 1, 3, 0, 3, 1, 0], band: { '夕方〜夜（18〜21時）': 6, '21時より後': 2 }, photoDays: 3, physicalDays: 2, minPhoto: 35, minNoPhoto: 20, minAvg: 25, weather: { sun: 5, cloud: 2, rain: 1 } }, promise: [{ weekKey: '2026-W43', text: '計算を見直す', result: 'some', reason: 'time' }] },
      tests: [{ name: 'たしかめテスト ⑤ 分数÷分数', subject: '算数', date: '2026-07-08', dateFrom: 'import', k: '○', t: '△', prep: [{ unit: 'm6-frac-div', n: 12, c: 10 }] }, { name: '比とその利用', subject: '算数', date: '2026-10-01', dateFrom: 'test', k: '△', t: '○', prep: [] }] } }
  const L = w.TS_T.copyLines(base).join('\n')
  ok(/【提出・成果物のようす/.test(L) && /しめきりの前の日（3回）/.test(L), '出し方のくせ'); ok(/よく出す曜日 火・木/.test(L), '曜日')
  ok(/写真のある日の学習時間 平均35分・ない日 平均20分/.test(L), '写真と学習時間')
  ok(/ためやすい種類/.test(L), 'ためやすい種類'); ok(/「計算を見直す」→ちょっと（時間がなかった）/.test(L), '先週決めたこと')
  ok(/【テストから見える傾向/.test(L) && /思考・判断・表現 もう少し/.test(L), '観点の言葉'); ok(/説明する練習/.test(L), 'くいちがい（アプリはよく正解・思考がもう少し）')
  ok(/少しずつ練習/.test(L), 'くいちがい（アプリであまり解いていない）')
  ok(!/[0-9０-９]+\s*(点|％|%|位)/.test(L), '点・％・位なし'); ok(L.indexOf('◎') < 0 && L.indexOf('△') < 0, '記号は言葉に'); ok(L.indexOf('テストA') < 0, '名前なし')
  const L2 = w.TS_T.copyLines({ ok: true, teishutsu: { habits: { school: { n: 0 }, hw: { n: 0 }, promise: [] }, tests: [] } })
  eq(L2.length, 0, 'データが無ければ何も言わない')
  // 個人ページ
  w._faData = base; w._faId = 'stu-1'
  w.document.getElementById('fullAnalysisContent').innerHTML = '<div id="stat">stat</div><div>rest</div>'
  await sleep(1400)
  const p = w.document.getElementById('tsFaPanel'); ok(p, '個人ページに出る'); ok(/テストの傾向（先生用・点数は出しません）/.test(p.textContent))
})

await t('U7 先生の📮提出物チェック：家庭学習タブのサブタブ・名前タップで✓（すぐ反映）', async () => {
  const dom = new JSDOM('<!doctype html><body><select id="hwClassFilter"><option value="">-</option><option value="cls-1" selected>6-2</option></select><div><button id="hwSubTab_daily">d</button></div><div id="hwPane_daily"></div></body>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/teacher' })
  const w = dom.window
  const items = [{ id: 'a1', title: '漢字ドリル p.30〜31', subject: '国語', dueDate: '2026-10-28', createdAt: '', doneAt: '', checked: { 'stu-2': '2026-10-27' } }]
  const posts = []
  w.fetch = async (url, opt) => { if (opt && opt.method === 'POST') { posts.push({ url, body: JSON.parse(opt.body) }); return { ok: true, json: async () => ({ ok: true, on: true, day: '2026-10-27' }) } } return { ok: true, json: async () => ({ ok: true, today: '2026-10-27', roster: [{ userId: 'stu-2', name: 'テストB', rosterNo: 1 }, { userId: 'stu-1', name: 'テストA', rosterNo: 2 }], items }) } }
  w.confirm = () => true
  const s = w.document.createElement('script'); s.textContent = rd('public/teishutsu-teacher.js'); w.document.body.appendChild(s)
  await sleep(1400)
  const tab = w.document.getElementById('hwSubTab_teishutsu'); ok(tab, 'サブタブ'); tab.click(); await sleep(50)
  const kids = w.document.querySelectorAll('.tsKid'); eq(kids.length, 2); ok(kids[0].classList.contains('on'), '出した子は✓')
  kids[1].click(); await sleep(30)
  ok(w.document.querySelectorAll('.tsKid.on').length === 2, 'すぐ反映'); eq(posts[0].body.userId, 'stu-1'); eq(posts[0].body.on, true)
  ok(/出した 2 \/ 2人/.test(w.document.getElementById('tsSel').textContent), '人数')
})

const pass = results.filter((r) => r.ok).length
console.log(`${pass}/${results.length} passed`)
// jsdom の setInterval（画面のスクリプト）が残ってプロセスが終わらないので、ここで終える
process.exit(pass === results.length ? 0 : 1)
