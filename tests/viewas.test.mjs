// VIEWAS_V1 👀 子どもの画面に入る（見るだけ）の統合テスト
//   - D1 は node:sqlite（本番DBには一切つながない）
//   - 実際のハンドラ（src/index.tsx を esbuild でバンドルしたもの）を app.fetch でそのまま呼ぶ
//   - いちばん大事なこと：見ているあいだ、子どものデータ（state_json ほか全テーブル）が1バイトも変わらない
//   使い方: node tests/viewas.test.mjs ./app.after.mjs ./viewas.mod.mjs
import { FakeD1, SCHEMA } from './d1.mjs'
import { readFileSync } from 'node:fs'

const BUNDLE = process.argv[2] || './app.after.mjs'
const VMOD = process.argv[3] || './viewas.mod.mjs'
const SECRET = 'test-session-secret'
const MIGRATION = readFileSync(new URL('../migrations/0046_view_as_log.sql', import.meta.url), 'utf8')
let _instance = 0

function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }
async function sign(payload) {
  const enc = new TextEncoder()
  const data = b64u(enc.encode(JSON.stringify(payload)))
  const key = await crypto.subtle.importKey('raw', enc.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data))
  return `v1.${data}.${b64u(new Uint8Array(sig))}`
}
async function sessionFor(u) {
  return sign({ id: u.id, role: u.role, loginId: u.loginId || u.id, isActive: true, iat: Math.floor(Date.now() / 1000) })
}

const EXTRA = `
CREATE TABLE IF NOT EXISTS makeup_grants (grant_key TEXT PRIMARY KEY, user_id TEXT, coins INTEGER, applied_at TEXT);
CREATE TABLE IF NOT EXISTS login_attempts (login_id TEXT PRIMARY KEY, fail_count INTEGER, first_fail_at INTEGER, last_fail_at INTEGER, locked_until INTEGER);
`
const ROOT_HTML = '<!doctype html><html><head><meta charset="utf-8"><title>LBM</title></head><body><div id="app">こどもの画面</div></body></html>'

async function newWorld({ migrate = true } = {}) {
  const db = new FakeD1()
  db.db.exec(SCHEMA)
  db.db.exec(EXTRA)
  if (migrate) db.db.exec(MIGRATION)
  const mod = await import(`${BUNDLE}?i=${++_instance}`)
  const app = mod.default
  const env = {
    DB: db, SESSION_SECRET: SECRET, ADMIN_LOGIN_ID: '', ADMIN_PASSWORD: '', AI: null,
    ASSETS: { fetch: async (req) => {
      const p = new URL(req.url).pathname
      if (p === '/index.html') return new Response(ROOT_HTML, { status: 200, headers: { 'content-type': 'text/html' } })
      if (p === '/viewas-teacher.js') return new Response(readFileSync(new URL('../public/viewas-teacher.js', import.meta.url), 'utf8'), { status: 200 })
      return new Response('nf', { status: 404 })
    } },
  }
  async function call(method, path, { user, body, cookies = {}, raw = false } = {}) {
    const headers = { 'content-type': 'application/json' }
    const jar = { ...cookies }
    if (user) jar.session = await sessionFor(user)
    const ck = Object.entries(jar).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join('; ')
    if (ck) headers.cookie = ck
    const req = new Request('https://test.local' + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) })
    const res = await app.fetch(req, env, { waitUntil() {}, passThroughOnException() {} })
    const setCookie = res.headers.getSetCookie ? res.headers.getSetCookie() : []
    let json = null, text = null
    if (raw) text = await res.clone().text()
    try { json = await res.clone().json() } catch (_e) {}
    return { status: res.status, json, text, setCookie, headers: res.headers }
  }

  const kid = { id: 'stu-1', role: 'student', loginId: 'kid1' }
  const kid2 = { id: 'stu-2', role: 'student', loginId: 'kid2' }
  const teacher = { id: 'tea-1', role: 'teacher', loginId: 'sensei' }
  const other = { id: 'tea-2', role: 'teacher', loginId: 'sensei2' }
  const admin = { id: 'adm-1', role: 'admin', loginId: 'admin' }
  db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", kid.id, 'student', 'kid1', 'テストA', 3, '3-1')
  db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", kid2.id, 'student', 'kid2', 'テストB', 3, '3-2')
  db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", admin.id, 'admin', 'admin', 'かんりしゃ', 0, '-')
  db._run("INSERT INTO teacher_accounts (id, login_id, name, school) VALUES (?,?,?,?)", teacher.id, 'sensei', 'せんせいA', 'テスト小')
  db._run("INSERT INTO teacher_accounts (id, login_id, name, school) VALUES (?,?,?,?)", other.id, 'sensei2', 'せんせいB', 'テスト小')
  db._run("INSERT INTO classes (id, teacher_id, name) VALUES (?,?,?)", 'cls-1', teacher.id, '3年1組')
  db._run("INSERT INTO classes (id, teacher_id, name) VALUES (?,?,?)", 'cls-2', other.id, '3年2組')
  db._run("INSERT INTO class_members (class_id, user_id) VALUES (?,?)", 'cls-1', kid.id)
  db._run("INSERT INTO class_members (class_id, user_id) VALUES (?,?)", 'cls-2', kid2.id)
  db._run("INSERT INTO homework_submissions (id, user_id, class_id, title, teacher_comment, returned_at) VALUES (?,?,?,?,?,?)", 'hw-1', kid.id, 'cls-1', 'さんすう', 'よくできました', Date.now())
  const big = { coins: 1234, level: 20, pokedex: Array.from({ length: 30 }, (_, i) => i + 1), filler: 'x'.repeat(45000), _contactCoinsApplied: 0 }
  db._run("INSERT INTO progress (user_id, state_json, updated_at) VALUES (?,?,datetime('now'))", kid.id, JSON.stringify(big))
  db._run("INSERT INTO makeup_grants (grant_key, user_id, coins, applied_at) VALUES ('mk-1', ?, 500, NULL)", kid.id)

  // 子どものデータの「指紋」：view_as_log 以外の全テーブルの全行
  function snapshot() {
    const tabs = db._all("SELECT name FROM sqlite_master WHERE type='table' AND name NOT IN ('view_as_log') AND name NOT LIKE 'sqlite_%' ORDER BY name")
    const o = {}
    for (const t of tabs) o[t.name] = db._all(`SELECT * FROM "${t.name}" ORDER BY rowid`)
    return JSON.stringify(o)
  }
  async function startAs(who, studentId) {
    const r = await call('POST', '/api/teacher/view-as/start', { user: who, body: { studentId } })
    const c = (r.setCookie || []).find((x) => x.startsWith('viewas='))
    const tok = c ? c.split(';')[0].slice('viewas='.length) : ''
    return { ...r, tok }
  }
  return { db, call, kid, kid2, teacher, other, admin, snapshot, startAs, big }
}

const results = []
async function t(name, fn) {
  try { await fn(); results.push({ name, ok: true }); console.log('PASS | ' + name) }
  catch (e) { results.push({ name, ok: false, note: String(e && e.stack || e) }); console.log('FAIL | ' + name + '\n   ' + (e && e.stack || e)) }
}
function eq(a, b, m) { if (a !== b) throw new Error((m || 'eq') + ': ' + JSON.stringify(a) + ' !== ' + JSON.stringify(b)) }
function ok(v, m) { if (!v) throw new Error(m || 'not ok') }

await t('1 担任が自分のクラスの子で始める → viewas Cookie・記録1行（先生のログインはそのまま）', async () => {
  const w = await newWorld()
  const r = await w.startAs(w.teacher, w.kid.id)
  eq(r.status, 200, 'status'); ok(r.json.ok); ok(r.tok, 'viewas cookie')
  ok(!(r.setCookie || []).some((x) => x.startsWith('session=')), 'session は触らない')
  const row = w.db._get('SELECT * FROM view_as_log')
  eq(row.teacher_id, w.teacher.id); eq(row.student_id, w.kid.id); eq(row.class_id, 'cls-1'); eq(row.ended_at, null)
})

await t('2 見ているあいだ /api/auth/me と /api/student/progress は「その子」の本物のデータ', async () => {
  const w = await newWorld()
  const { tok } = await w.startAs(w.teacher, w.kid.id)
  const me = await w.call('GET', '/api/auth/me', { user: w.teacher, cookies: { viewas: tok } })
  eq(me.json.user.id, w.kid.id); eq(me.json.user.role, 'student')
  const p = await w.call('GET', '/api/student/progress', { user: w.teacher, cookies: { viewas: tok } })
  const st = JSON.parse(p.json.progress.stateJson)
  eq(st.coins, 1234, 'その子のコイン'); eq(st.pokedex.length, 30)
  const nt = await w.call('GET', '/api/student/next-try', { user: w.teacher, cookies: { viewas: tok } })
  eq(nt.status, 200, 'next-try')
})

await t('3 【最重要】見ているあいだの保存・提出・コイン・既読・利用記録は1つも書かれない（state_json も全テーブルも1バイトも変わらない）', async () => {
  const w = await newWorld()
  const { tok } = await w.startAs(w.teacher, w.kid.id)
  const before = w.snapshot()
  const C = { user: w.teacher, cookies: { viewas: tok } }
  const writes = [
    ['PUT', '/api/student/progress', { state: { coins: 1, level: 1, pokedex: [1] } }],
    ['PUT', '/api/student/progress', { state: { ...w.big, coins: 999999 } }],
    ['POST', '/api/homework/submit', { title: 'x', body: 'y', dayKey: '2026-10-26' }],
    ['PUT', '/api/homework/submit', { id: 'hw-1', body: 'z' }],
    ['POST', '/api/homework/hw-1/claim', {}],
    ['POST', '/api/student/results', { results: [{ unit: 'm3', isCorrect: 1 }] }],
    ['POST', '/api/student/app-open', {}],
    ['POST', '/api/student/kantan-ref', { weekKey: '2026-W44', self: 'good' }],
    ['POST', '/api/student/weekly-reflection', { weekKey: '2026-W44', good_point: 'がんばった' }],
    ['POST', '/api/student/weekly-plan', { weekKey: '2026-W44', plans: {} }],
    ['POST', '/api/student/next-try', { text: 'つぎ' }],
    ['POST', '/api/student/hanshin-answer', { answer: 'こたえです' }],
    ['POST', '/api/student/message', { body: 'せんせいへ' }],
    ['POST', '/api/student/message/1/read', {}],
    ['POST', '/api/student/announcement/1/read', {}],
    ['POST', '/api/student/contact-note/1/read', {}],
    ['POST', '/api/student/class-mission/1/claim', {}],
    ['POST', '/api/shop/sticker/buy', {}],
    ['POST', '/api/shop/kahoot/buy', {}],
    ['POST', '/api/student/join-class', { code: 'ABCDEF' }],
    ['POST', '/api/student/leave-class', {}],
    ['POST', '/api/battle/create', {}],
    ['POST', '/api/trade/offer', {}],
    ['POST', '/api/defense/entry', {}],
    ['POST', '/api/summer/shiny-found', {}],
    ['POST', '/api/student/secret-question', { question: 'q', answer: 'a' }],
    ['DELETE', '/api/trade/offer', undefined],
    ['POST', '/api/minna/consent', { kind: 'day', mode: 'named' }],
    ['POST', '/api/mi/answer', {}],
  ]
  for (const [m, p, b] of writes) {
    const r = await w.call(m, p, { ...C, body: b })
    eq(r.status, 200, m + ' ' + p); ok(r.json && r.json.viewOnly === true, 'viewOnly ' + m + ' ' + p)
  }
  // GET でも書きこむ道（補填コイン・自動進級など）を通しても書かれない
  await w.call('GET', '/api/student/progress', C)
  await w.call('GET', '/api/auth/me', C)
  await w.call('GET', '/api/student/weekly-plan-status', C)
  await w.call('GET', '/api/student/kantan-ref', C)
  await w.call('GET', '/api/student/my-karte', C)
  const after = w.snapshot()
  eq(after === before, true, '子どものデータが変わった')
  eq(w.db._get("SELECT applied_at FROM makeup_grants WHERE grant_key='mk-1'").applied_at, null, '補填は未適用のまま（本人が開いたときに配られる）')
  const log = w.db._get('SELECT blocked_count FROM view_as_log')
  ok(log.blocked_count >= writes.length, '止めた数が記録される: ' + log.blocked_count)
})

await t('4 見ていないときは、その子のふつうの保存はいつもどおり通る（回帰なし）', async () => {
  const w = await newWorld()
  const r = await w.call('PUT', '/api/student/progress', { user: w.kid, body: { state: { ...w.big, coins: 2000 } } })
  eq(r.status, 200); ok(!r.json.viewOnly)
  eq(JSON.parse(w.db._get('SELECT state_json FROM progress WHERE user_id=?', w.kid.id).state_json).coins, 2000)
})

await t('5 担任はほかのクラスの子に入れない・子どもは使えない・管理者はどの子にも入れる', async () => {
  const w = await newWorld()
  eq((await w.startAs(w.teacher, w.kid2.id)).status, 404, 'ほかのクラス')
  eq((await w.startAs(w.kid, w.kid2.id)).status, 401, '子ども')
  eq((await w.startAs(w.teacher, w.admin.id)).status, 404, '児童でない')
  const a = await w.startAs(w.admin, w.kid2.id)
  eq(a.status, 200, '管理者'); ok(a.tok)
  const ro = await w.call('GET', '/api/teacher/view-as/roster', { user: w.teacher })
  eq(ro.json.classes.length, 1); eq(ro.json.classes[0].members.length, 1); eq(ro.json.classes[0].members[0].id, w.kid.id)
  const ra = await w.call('GET', '/api/teacher/view-as/roster', { user: w.admin })
  eq(ra.json.classes.length, 2)
})

await t('6 Cookie を別の先生が持っても・期限切れでも・署名がちがっても、なりすませない', async () => {
  const w = await newWorld()
  const { tok } = await w.startAs(w.teacher, w.kid.id)
  const me = await w.call('GET', '/api/auth/me', { user: w.other, cookies: { viewas: tok } })
  eq(me.json.user.id, w.other.id, '別の先生はその先生のまま')
  const expired = await sign({ k: 'viewas', t: w.teacher.id, s: w.kid.id, n: 'kid1', l: 'x', exp: Math.floor(Date.now() / 1000) - 5 })
  eq((await w.call('GET', '/api/auth/me', { user: w.teacher, cookies: { viewas: expired } })).json.user.id, w.teacher.id, '期限切れ')
  const forged = tok.slice(0, -3) + 'AAA'
  eq((await w.call('GET', '/api/auth/me', { user: w.teacher, cookies: { viewas: forged } })).json.user.id, w.teacher.id, '署名ちがい')
  // ログインしていない人が viewas だけ持っていても何もできない
  eq((await w.call('GET', '/api/auth/me', { cookies: { viewas: tok } })).json.user, null, 'ログインなし')
  // viewas の中身を session に入れてもログイン扱いにならない
  eq((await w.call('GET', '/api/auth/me', { cookies: { session: tok } })).json.user, null, 'session にすりかえ')
})

await t('7 子どもの画面（/）には見ているときだけ帯と見るだけスクリプトが入る・ふだんの子どもの画面には一切入らない', async () => {
  const w = await newWorld()
  const plain = await w.call('GET', '/', { user: w.kid, raw: true })
  ok(plain.text.indexOf('__VIEWAS__') < 0 && plain.text.indexOf('view-as') < 0 && plain.text.indexOf('viewas') < 0, 'ふだんの画面に痕跡なし')
  const { tok } = await w.startAs(w.teacher, w.kid.id)
  const v = await w.call('GET', '/', { user: w.teacher, cookies: { viewas: tok }, raw: true })
  ok(v.text.indexOf('window.__VIEWAS__=') > 0, '差しこみ')
  ok(v.text.indexOf('テストA') > 0, '名前')
  ok(v.text.indexOf('<head><script data-viewas="1">') > 0, 'head の先頭（ほかのスクリプトより先）')
  ok(v.text.indexOf('こどもの画面') > 0, '元の中身はそのまま')
  eq(v.headers.get('cache-control'), 'no-store')
  // 子ども本人が（なにかの拍子で）viewas Cookie を持っていても入らない
  const k = await w.call('GET', '/', { user: w.kid, cookies: { viewas: tok }, raw: true })
  ok(k.text.indexOf('__VIEWAS__') < 0, '子どもには出ない')
})

await t('8 先生の画面（/teacher）に戻る・終わるボタン・子どもの画面のログアウト → 終わる（先生はログアウトされない）', async () => {
  const w = await newWorld()
  let s = await w.startAs(w.teacher, w.kid.id)
  const back = await w.call('GET', '/teacher', { user: w.teacher, cookies: { viewas: s.tok }, raw: true })
  ok((back.setCookie || []).some((x) => x.startsWith('viewas=;') || /^viewas=.*Max-Age=0/.test(x)), 'Cookie を消す')
  ok(w.db._get('SELECT ended_at FROM view_as_log').ended_at, '終わりの時刻')
  s = await w.startAs(w.teacher, w.kid.id)
  const end = await w.call('POST', '/api/teacher/view-as/end', { user: w.teacher, cookies: { viewas: s.tok } })
  eq(end.status, 200)
  eq(w.db._get('SELECT COUNT(*) AS n FROM view_as_log WHERE ended_at IS NULL').n, 0)
  s = await w.startAs(w.teacher, w.kid.id)
  const lo = await w.call('POST', '/api/auth/logout', { user: w.teacher, cookies: { viewas: s.tok } })
  ok(lo.json.viewOnly && lo.json.ended, 'ログアウトは終わるに置きかえ')
  ok(!(lo.setCookie || []).some((x) => x.startsWith('session=')), '先生の session は消さない')
  s = await w.startAs(w.teacher, w.kid.id)
  const lg = await w.call('GET', '/logout', { user: w.teacher, cookies: { viewas: s.tok } })
  eq(lg.status, 302); eq(lg.headers.get('location'), '/teacher')
})

await t('9 見ているあいだも先生用 API は先生のまま（ほかのタブの先生の画面がこわれない）・状態がわかる', async () => {
  const w = await newWorld()
  const { tok } = await w.startAs(w.teacher, w.kid.id)
  const cls = await w.call('GET', '/api/teacher/class/cls-1/members', { user: w.teacher, cookies: { viewas: tok } })
  eq(cls.status, 200); eq(cls.json.members.length, 1)
  const st = await w.call('GET', '/api/teacher/view-as/status', { user: w.teacher, cookies: { viewas: tok } })
  eq(st.json.active, true); eq(st.json.name, 'テストA')
  const st2 = await w.call('GET', '/api/teacher/view-as/status', { user: w.teacher })
  eq(st2.json.active, false)
})

await t('10 記録：担任は自分と自分のクラスの子の分だけ・管理者は全部・止めた数が出る', async () => {
  const w = await newWorld()
  const s1 = await w.startAs(w.teacher, w.kid.id)
  await w.call('PUT', '/api/student/progress', { user: w.teacher, cookies: { viewas: s1.tok }, body: { state: {} } })
  await w.startAs(w.other, w.kid2.id)
  const lt = await w.call('GET', '/api/teacher/view-as/log', { user: w.teacher })
  eq(lt.json.rows.length, 1); eq(lt.json.rows[0].studentName, 'テストA'); eq(lt.json.rows[0].teacherName, 'せんせいA'); eq(lt.json.rows[0].blockedCount, 1)
  const la = await w.call('GET', '/api/teacher/view-as/log', { user: w.admin })
  eq(la.json.rows.length, 2)
  eq((await w.call('GET', '/api/teacher/view-as/log', { user: w.kid })).status, 401)
})

await t('11 記録のテーブルが無いときは始めない（記録できないなら見せない）', async () => {
  const w = await newWorld({ migrate: false })
  const r = await w.startAs(w.teacher, w.kid.id)
  eq(r.status, 503); ok(!r.tok)
})

await t('12 終わったあと遅れて届いた保存も、先生のアカウントにも子どもにも入らない', async () => {
  const w = await newWorld()
  const { tok } = await w.startAs(w.teacher, w.kid.id)
  await w.call('POST', '/api/teacher/view-as/end', { user: w.teacher, cookies: { viewas: tok } })
  // 期限切れ（＝無効になった）viewas を持ったまま書きこみが来た
  const expired = await sign({ k: 'viewas', t: w.teacher.id, s: w.kid.id, n: 'kid1', l: 'x', exp: Math.floor(Date.now() / 1000) - 1 })
  const before = w.snapshot()
  const r = await w.call('PUT', '/api/student/progress', { user: w.teacher, cookies: { viewas: expired }, body: { state: { coins: 5 } } })
  ok(r.json.viewOnly, '止まる')
  eq(w.snapshot(), before)
})

await t('13 読むだけDB：SELECT だけ通し、書きこみ・DDL・複文は実行しない', async () => {
  const m = await import(VMOD)
  const yes = ['SELECT 1', '  select * from users', '-- c\nSELECT 1', '/* x */ SELECT 1', 'WITH a AS (SELECT 1) SELECT * FROM a', 'SELECT 1;']
  const no = ['INSERT INTO x VALUES (1)', 'UPDATE progress SET state_json=1', 'DELETE FROM x', 'REPLACE INTO x VALUES(1)', 'CREATE TABLE x(a)', 'ALTER TABLE x ADD b', 'DROP TABLE x', 'PRAGMA foreign_keys=OFF', 'SELECT 1; DELETE FROM x', 'WITH a AS (SELECT 1) INSERT INTO x SELECT * FROM a', '', 'VACUUM']
  for (const s of yes) eq(m.viewAsIsReadSql(s), true, s)
  for (const s of no) eq(m.viewAsIsReadSql(s), false, s)
  const db = new FakeD1(); db.db.exec('CREATE TABLE x(a)'); db._run('INSERT INTO x VALUES (1)')
  const ro = m.viewAsReadOnlyDB(db)
  const r = await ro.prepare('INSERT INTO x VALUES (?)').bind(2).run()
  eq(r.meta.changes, 0); await ro.prepare('DELETE FROM x').run(); await ro.exec('DROP TABLE x')
  await ro.batch([ro.prepare('UPDATE x SET a=9'), ro.prepare('SELECT * FROM x')])
  eq(JSON.stringify(db._all('SELECT * FROM x')), '[{"a":1}]')
  eq((await ro.prepare('SELECT a FROM x').first()).a, 1)
})

await t('14 先生の画面の部品：/teacher に読み込みタグ・配る道がある', async () => {
  const src = readFileSync(new URL('../src/index.tsx', import.meta.url), 'utf8')
  ok(src.includes('<script src="/viewas-teacher.js?v=1"></script>'))
  const w = await newWorld()
  const r = await w.call('GET', '/viewas-teacher.js', { raw: true })
  eq(r.status, 200); ok(r.text.includes('VIEWAS_V1'))
})

const pass = results.filter((r) => r.ok).length
console.log(`\n${pass}/${results.length} passed`)
if (pass !== results.length) process.exit(1)
