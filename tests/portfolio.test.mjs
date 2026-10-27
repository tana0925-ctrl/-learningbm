// PORTFOLIO_V1 ＋ AIFLOW_V1 の統合テスト
//   - D1 は node:sqlite（本番DBには一切つながない）。写真専用 D1（PFDB）も別のメモリDB。
//   - 実際のハンドラ（src/index.tsx を esbuild でバンドルしたもの）を app.fetch でそのまま呼ぶ
//   - いちばん大事なこと：写真は先生（自分のクラス）と管理者にしか返らない。子ども・見るだけモード・ログインなしは 403。
//   使い方: node tests/portfolio.test.mjs ./app.after.mjs
import { FakeD1, SCHEMA } from './d1.mjs'
import { readFileSync } from 'node:fs'
import vm from 'node:vm'

const BUNDLE = process.argv[2] || './app.after.mjs'
const SECRET = 'test-session-secret'
const rd = (p) => readFileSync(new URL(p, import.meta.url), 'utf8')
const MIG = ['../migrations/0026_homework_photos.sql', '../migrations/0039_homework_photos2.sql', '../migrations/0046_view_as_log.sql', '../migrations/0050_portfolio.sql'].map(rd)
const MIG_PF = rd('../migrations_pf/0001_pf_blobs.sql')
let _instance = 0, pass = 0, fail = 0

function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }
async function sign(payload) {
  const enc = new TextEncoder()
  const data = b64u(enc.encode(JSON.stringify(payload)))
  const key = await crypto.subtle.importKey('raw', enc.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(data))
  return `v1.${data}.${b64u(new Uint8Array(sig))}`
}
const sessionFor = (u) => sign({ id: u.id, role: u.role, loginId: u.loginId || u.id, isActive: true, iat: Math.floor(Date.now() / 1000) })
function jpeg(n, seed = 1) { const a = new Uint8Array(n); a[0] = 0xFF; a[1] = 0xD8; for (let i = 2; i < n; i++) a[i] = (i * seed) & 0xFF; return a }
function studyDay() { return new Date(Date.now() + 9 * 3600000 - 8.5 * 3600000).toISOString().slice(0, 10) }

async function world({ store = 'd1' } = {}) {
  const db = new FakeD1(); db.db.exec(SCHEMA)
  db.db.exec(`CREATE TABLE IF NOT EXISTS photo_bonus_rewards (user_id TEXT NOT NULL, day_key TEXT NOT NULL, res TEXT, amount INTEGER, created_at TEXT, PRIMARY KEY(user_id, day_key));
              CREATE TABLE IF NOT EXISTS login_attempts (login_id TEXT PRIMARY KEY, fail_count INTEGER, first_fail_at INTEGER, last_fail_at INTEGER, locked_until INTEGER);`)
  for (const m of MIG) db.db.exec(m)
  const pfdb = new FakeD1(); pfdb.db.exec(MIG_PF)
  const r2 = new Map()
  const R2 = { async put(k, v, o) { r2.set(k, { v: new Uint8Array(v), ct: o?.httpMetadata?.contentType }) }, async get(k) { const x = r2.get(k); return x ? { body: x.v, httpMetadata: { contentType: x.ct } } : null }, async delete(k) { r2.delete(k) } }
  const mod = await import(`${BUNDLE}?i=${++_instance}`)
  const app = mod.default
  const env = { DB: db, SESSION_SECRET: SECRET, AI: null, ASSETS: { fetch: async () => new Response('nf', { status: 404 }) } }
  if (store === 'd1') env.PFDB = pfdb
  if (store === 'r2') env.PF = R2
  async function call(method, path, { user, body, form, cookies = {} } = {}) {
    const headers = {}
    const jar = { ...cookies }
    if (user) jar.session = await sessionFor(user)
    const ck = Object.entries(jar).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`).join('; ')
    if (ck) headers.cookie = ck
    let b
    if (form) { b = new FormData(); for (const [k, v] of Object.entries(form)) b.append(k, v) }
    else if (body !== undefined) { headers['content-type'] = 'application/json'; b = JSON.stringify(body) }
    const res = await app.fetch(new Request('https://test.local' + path, { method, headers, body: b }), env, { waitUntil() {}, passThroughOnException() {} })
    let json = null; const buf = new Uint8Array(await res.clone().arrayBuffer())
    try { json = JSON.parse(new TextDecoder().decode(buf)) } catch (_e) {}
    return { status: res.status, json, buf, headers: res.headers }
  }
  const kid = { id: 'stu-1', role: 'student', loginId: 'kid1' }, kid2 = { id: 'stu-2', role: 'student', loginId: 'kid2' }
  const teacher = { id: 'tea-1', role: 'teacher', loginId: 'sensei' }, other = { id: 'tea-2', role: 'teacher', loginId: 'sensei2' }
  const admin = { id: 'adm-1', role: 'admin', loginId: 'admin' }
  db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active, roster_no) VALUES (?,?,?,?,?,?,1,1)", kid.id, 'student', 'kid1', 'テストA', 6, '6-2')
  db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active, roster_no) VALUES (?,?,?,?,?,?,1,1)", kid2.id, 'student', 'kid2', 'テストB', 6, '6-1')
  db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", admin.id, 'admin', 'admin', 'かんり', 0, '-')
  db._run("INSERT INTO classes (id, teacher_id, name) VALUES (?,?,?)", 'cls-1', teacher.id, '6年2組')
  db._run("INSERT INTO classes (id, teacher_id, name) VALUES (?,?,?)", 'cls-2', other.id, '6年1組')
  db._run("INSERT INTO class_members (class_id, user_id) VALUES (?,?)", 'cls-1', kid.id)
  db._run("INSERT INTO class_members (class_id, user_id) VALUES (?,?)", 'cls-2', kid2.id)
  db._run("INSERT INTO progress (user_id, state_json, updated_at) VALUES (?,?,datetime('now'))", kid.id, JSON.stringify({ coins: 0 }))
  return { db, pfdb, r2, env, call, kid, kid2, teacher, other, admin }
}

async function T(name, fn) {
  try { await fn(); pass++; console.log('PASS | ' + name) }
  catch (e) { fail++; console.log('FAIL | ' + name + '\n   ' + (e && e.stack || e)) }
}
function eq(a, b, m) { if (a !== b) throw new Error((m || '') + ' expected ' + JSON.stringify(b) + ' got ' + JSON.stringify(a)) }
function ok(v, m) { if (!v) throw new Error(m || 'not ok') }

async function addPhoto(w, who, userId, extra = {}, size = 3000) {
  return w.call('POST', '/api/teacher/portfolio/upload', { user: who, form: { userId, takenOn: '2026-10-20', subj: '算数', memo: 'わり算', photo: new File([jpeg(size)], 'p.jpg', { type: 'image/jpeg' }), thumb: new File([jpeg(400, 3)], 't.jpg', { type: 'image/jpeg' }), ...extra } })
}

await T('1 先生が写真を追加 → 写真専用D1に入り、本体DBには写真が入らない', async () => {
  const w = await world()
  const r = await addPhoto(w, w.teacher, w.kid.id)
  eq(r.status, 200); ok(r.json.ok)
  eq(w.pfdb._all('SELECT k FROM pf_blobs').length, 2, '本体＋小さい版')
  const it = w.db._get('SELECT * FROM portfolio_items WHERE id=?', r.json.id)
  eq(it.store, 'd1'); eq(it.fy, 2026); eq(it.subj, '算数'); eq(it.class_id, 'cls-1')
  ok(!w.db._all("SELECT name FROM sqlite_master WHERE name='pf_blobs'").length, '本体DBに pf_blobs は無い')
})

await T('2 写真を返すのは先生（自分のクラス）と管理者だけ', async () => {
  const w = await world()
  const id = (await addPhoto(w, w.teacher, w.kid.id)).json.id
  const t = await w.call('GET', '/api/teacher/portfolio/img/' + id, { user: w.teacher })
  eq(t.status, 200); eq(t.buf.length, 3000); eq(t.headers.get('content-type'), 'image/jpeg')
  ok(/private/.test(t.headers.get('cache-control')), 'private キャッシュ')
  eq((await w.call('GET', '/api/teacher/portfolio/img/' + id + '?t=1', { user: w.teacher })).buf.length, 400, '小さい版')
  eq((await w.call('GET', '/api/teacher/portfolio/img/' + id, { user: w.admin })).status, 200, '管理者')
  eq((await w.call('GET', '/api/teacher/portfolio/img/' + id, { user: w.other })).status, 403, 'ほかのクラスの先生')
  eq((await w.call('GET', '/api/teacher/portfolio/img/' + id, { user: w.kid })).status, 403, '本人の子ども')
  eq((await w.call('GET', '/api/teacher/portfolio/img/' + id, {})).status, 403, 'ログインなし')
  eq((await w.call('GET', '/api/teacher/portfolio/items?userId=' + w.kid.id, { user: w.kid })).status, 403, '子どもは目録も×')
  eq((await w.call('GET', '/api/teacher/portfolio/summary', { user: w.kid })).status, 403)
  eq((await w.call('GET', '/api/teacher/portfolio/img/pf_0123456789abcdef0123', { user: w.teacher })).status, 404, 'IDをあてずっぽう')
})

await T('3 見るだけモード（viewas Cookie）の間は先生でも写真を返さない', async () => {
  const w = await world()
  const id = (await addPhoto(w, w.teacher, w.kid.id)).json.id
  const r = await w.call('GET', '/api/teacher/portfolio/img/' + id, { user: w.teacher, cookies: { viewas: 'x' } })
  eq(r.status, 403); eq(r.json.error, 'view_as_active')
  eq((await w.call('GET', '/api/teacher/portfolio/summary', { user: w.teacher, cookies: { viewas: 'x' } })).status, 403)
})

await T('4 家庭学習の写真 /api/photo は子ども本人にも返さない（先生は今までどおり）', async () => {
  const w = await world()
  const dk = studyDay()
  w.db._run('INSERT INTO homework_photos2 (user_id, day_key, idx, mime_type, bytes, byte_size) VALUES (?,?,0,?,?,?)', w.kid.id, dk, 'image/jpeg', jpeg(500), 500)
  eq((await w.call('GET', `/api/photo/${w.kid.id}/${dk}`, { user: w.kid })).status, 403, '本人')
  eq((await w.call('GET', `/api/photo/${w.kid.id}/${dk}`, { user: w.teacher })).status, 200, '担任')
  eq((await w.call('GET', `/api/photo/${w.kid.id}/${dk}`, { user: w.other })).status, 403, 'ほかの先生')
  eq((await w.call('GET', `/api/photo/${w.kid.id}/${dk}`, { user: w.admin })).status, 200, '管理者')
})

await T('5 家庭学習で写真を出すと自動で入る／出しなおしで入れかわる／設定で止められる', async () => {
  const w = await world()
  const dk = studyDay()
  const send = (idx, n) => w.call('POST', '/api/homework/analyze-photo', { user: w.kid, form: { dayKey: dk, idx: String(idx), photo: new File([jpeg(n)], 'p.jpg', { type: 'image/jpeg' }) } })
  eq((await send(0, 9000)).status, 200); eq((await send(1, 9100)).status, 200)
  let rows = w.db._all("SELECT * FROM portfolio_items WHERE src='hw' AND deleted_at IS NULL ORDER BY hw_idx")
  eq(rows.length, 2); eq(rows[0].hw_day_key, dk); eq(rows[0].byte_size, 9000); eq(rows[1].hw_idx, 1)
  eq(w.pfdb._all('SELECT k FROM pf_blobs').length, 2)
  await send(0, 9500)   // 1まい目から出しなおし
  rows = w.db._all("SELECT * FROM portfolio_items WHERE src='hw'")
  eq(rows.length, 1); eq(rows[0].byte_size, 9500); eq(w.pfdb._all('SELECT k FROM pf_blobs').length, 1, '古い写真は置き場からも消える')
  // 設定で止める
  eq((await w.call('POST', '/api/teacher/portfolio/settings', { user: w.teacher, body: { classId: 'cls-1', autoHw: false } })).status, 200)
  await send(1, 9900)
  eq(w.db._all("SELECT * FROM portfolio_items WHERE src='hw'").length, 1, '止めたら入らない')
  eq(w.db._all("SELECT * FROM homework_photos2").length, 2, '家庭学習の写真そのものはいつもどおり保存')
})

await T('6 置き場が無いときは保存しない（家庭学習の提出はいつもどおり成功）', async () => {
  const w = await world({ store: 'none' })
  const r = await addPhoto(w, w.teacher, w.kid.id)
  eq(r.status, 503); eq(r.json.error, 'store_not_ready')
  const s = await w.call('POST', '/api/homework/analyze-photo', { user: w.kid, form: { dayKey: studyDay(), idx: '0', photo: new File([jpeg(9000)], 'p.jpg', { type: 'image/jpeg' }) } })
  eq(s.status, 200); ok(s.json.ok)
  eq(w.db._all('SELECT * FROM portfolio_items').length, 0)
  eq(w.db._all('SELECT * FROM homework_photos2').length, 1)
})

await T('7 R2 があれば R2 に入る', async () => {
  const w = await world({ store: 'r2' })
  const id = (await addPhoto(w, w.teacher, w.kid.id)).json.id
  eq(w.r2.size, 2); eq(w.db._get('SELECT store FROM portfolio_items WHERE id=?', id).store, 'r2')
  eq((await w.call('GET', '/api/teacher/portfolio/img/' + id, { user: w.teacher })).buf.length, 3000)
  eq((await w.call('POST', '/api/teacher/portfolio/delete', { user: w.teacher, body: { ids: [id] } })).json.deleted, 1)
  eq(w.r2.size, 0, '消すと R2 からも消える')
})

await T('8 ほかのクラスの子には追加・変更・削除できない', async () => {
  const w = await world()
  eq((await addPhoto(w, w.teacher, w.kid2.id)).status, 404)
  const id = (await addPhoto(w, w.other, w.kid2.id)).json.id
  eq((await w.call('POST', '/api/teacher/portfolio/update', { user: w.teacher, body: { id, subj: '国語', memo: 'x' } })).status, 403)
  eq((await w.call('POST', '/api/teacher/portfolio/delete', { user: w.teacher, body: { ids: [id] } })).json.deleted, 0)
  eq(w.db._get('SELECT deleted_at FROM portfolio_items WHERE id=?', id).deleted_at, null)
  eq((await addPhoto(w, w.kid, w.kid.id)).status, 403, '子どもは追加できない')
  eq((await addPhoto(w, w.teacher, w.kid.id, {}, 2_000_000)).status, 400, '大きすぎる写真')
  eq((await addPhoto(w, w.teacher, w.kid.id, { photo: new File(['<svg/>'], 'x.svg', { type: 'image/svg+xml' }) })).status, 400, '画像以外')
})

await T('9 一覧・直す・消す（消すと写真は置き場から消え、印だけ残る）', async () => {
  const w = await world()
  const a = (await addPhoto(w, w.teacher, w.kid.id)).json.id
  const b = (await addPhoto(w, w.teacher, w.kid.id, { takenOn: '2026-05-10', subj: '国語' })).json.id
  let it = (await w.call('GET', '/api/teacher/portfolio/items?userId=' + w.kid.id, { user: w.teacher })).json.items
  eq(it.length, 2); eq(it[0].id, a, '新しい順')
  eq((await w.call('POST', '/api/teacher/portfolio/update', { user: w.teacher, body: { id: b, subj: '理科', memo: '観察', takenOn: '2026-06-01' } })).status, 200)
  eq(w.db._get('SELECT subj, taken_on FROM portfolio_items WHERE id=?', b).subj, '理科')
  eq((await w.call('POST', '/api/teacher/portfolio/delete', { user: w.teacher, body: { ids: [a] } })).json.deleted, 1)
  eq(w.pfdb._all('SELECT k FROM pf_blobs').length, 2, 'b の2つだけ')
  it = (await w.call('GET', '/api/teacher/portfolio/items?userId=' + w.kid.id, { user: w.teacher })).json.items
  eq(it.length, 1)
  eq((await w.call('GET', '/api/teacher/portfolio/img/' + a, { user: w.teacher })).status, 404)
  const s = (await w.call('GET', '/api/teacher/portfolio/summary?classId=cls-1', { user: w.teacher })).json
  eq(s.students.length, 1); eq(s.students[0].n, 1); eq(s.total.count, 1); eq(s.settings.keepMode, 'fy_end')
})

await T('10 前からある家庭学習の写真：一覧に出る → とりこむ → 二重に入らない（もとの写真はそのまま）', async () => {
  const w = await world()
  w.db._run('INSERT INTO homework_photos (user_id, day_key, mime_type, bytes, byte_size, created_at) VALUES (?,?,?,?,?,?)', w.kid.id, '2026-05-18', 'image/jpeg', jpeg(800), 800, '2026-05-18 07:00:00')
  w.db._run('INSERT INTO homework_photos2 (user_id, day_key, idx, mime_type, bytes, byte_size) VALUES (?,?,1,?,?,?)', w.kid.id, '2026-09-30', 'image/jpeg', jpeg(700), 700)
  let s = (await w.call('GET', '/api/teacher/portfolio/summary?classId=cls-1', { user: w.teacher })).json
  eq(s.legacy, 2)
  const L = (await w.call('GET', '/api/teacher/portfolio/legacy?classId=cls-1', { user: w.teacher })).json.items
  eq(L.length, 2)
  for (const x of L) {
    const r = await addPhoto(w, w.teacher, x.userId, { src: 'hw', hwDayKey: x.dayKey, hwIdx: String(x.idx) })
    ok(r.json.ok && !r.json.skipped)
  }
  const again = await addPhoto(w, w.teacher, w.kid.id, { src: 'hw', hwDayKey: '2026-05-18', hwIdx: '0' })
  ok(again.json.skipped, '二度目は入れない')
  eq((await addPhoto(w, w.teacher, w.kid.id, { src: 'hw', hwDayKey: '2026-05-19', hwIdx: '0' })).status, 404, '無い日の写真はとりこめない')
  s = (await w.call('GET', '/api/teacher/portfolio/summary?classId=cls-1', { user: w.teacher })).json
  eq(s.legacy, 0)
  eq(w.db._get("SELECT fy FROM portfolio_items WHERE hw_day_key='2026-05-18'").fy, 2026)
  eq(w.db._all('SELECT * FROM homework_photos').length, 1, 'もとの写真は消さない')
  eq((await w.call('GET', '/api/teacher/portfolio/legacy?classId=cls-1', { user: w.other })).status, 404)
})

await T('11 年度末：確認を出す → 「けす」が無いと消さない → 消す（自動では消さない）', async () => {
  const w = await world()
  await addPhoto(w, w.teacher, w.kid.id, { takenOn: '2025-11-01' })   // 前の年度
  await addPhoto(w, w.teacher, w.kid.id, { takenOn: '2026-10-01' })   // 今の年度
  let s = (await w.call('GET', '/api/teacher/portfolio/summary?classId=cls-1', { user: w.teacher })).json
  ok(s.yearEnd, '前の年度が残っていれば確認が出る'); eq(s.yearEnd.count, 1); eq(s.yearEnd.upToFy, s.fy - 1)
  eq((await w.call('POST', '/api/teacher/portfolio/year-end', { user: w.teacher, body: { classId: 'cls-1', upToFy: s.yearEnd.upToFy } })).status, 400, '確認の文字なし')
  eq((await w.call('POST', '/api/teacher/portfolio/year-end', { user: w.other, body: { classId: 'cls-1', upToFy: s.yearEnd.upToFy, confirm: 'けす' } })).status, 404)
  eq(w.db._all('SELECT * FROM portfolio_items WHERE deleted_at IS NULL').length, 2, 'まだ消えていない')
  // あとで
  await w.call('POST', '/api/teacher/portfolio/settings', { user: w.teacher, body: { classId: 'cls-1', snoozeDays: 14 } })
  eq((await w.call('GET', '/api/teacher/portfolio/summary?classId=cls-1', { user: w.teacher })).json.yearEnd, null, 'あとで→出ない')
  // 消さない設定
  w.db._run('UPDATE portfolio_settings SET remind_snooze=NULL')
  await w.call('POST', '/api/teacher/portfolio/settings', { user: w.teacher, body: { classId: 'cls-1', keepMode: 'keep' } })
  eq((await w.call('GET', '/api/teacher/portfolio/summary?classId=cls-1', { user: w.teacher })).json.yearEnd, null, '消さない設定→出ない')
  await w.call('POST', '/api/teacher/portfolio/settings', { user: w.teacher, body: { classId: 'cls-1', keepMode: 'fy_end' } })
  s = (await w.call('GET', '/api/teacher/portfolio/summary?classId=cls-1', { user: w.teacher })).json
  const r = await w.call('POST', '/api/teacher/portfolio/year-end', { user: w.teacher, body: { classId: 'cls-1', upToFy: s.yearEnd.upToFy, confirm: 'けす' } })
  eq(r.json.deleted, 1); eq(r.json.left, 0)
  eq(w.db._all('SELECT * FROM portfolio_items WHERE deleted_at IS NULL').length, 1, '今の年度は残る')
  eq(w.pfdb._all('SELECT k FROM pf_blobs').length, 2)
  eq((await w.call('POST', '/api/teacher/portfolio/year-end', { user: w.teacher, body: { classId: 'cls-1', upToFy: s.fy + 1, confirm: 'けす' } })).status, 400, '先の年度は消せない')
})

await T('12 AIFLOW：FLOW の下書きが入る → 公開 → 流れとして読める（子どもは読めない）', async () => {
  const w = await world()
  w.db._run("INSERT INTO homework_submissions (id, user_id, class_id, day_key) VALUES ('hw-9', ?, 'cls-1', '2026-10-20')", w.kid.id)
  const r = await w.call('POST', '/api/teacher/ai-drafts', { user: w.teacher, body: { classId: 'cls-1', items: [
    { kind: 'FLOW', targetId: w.kid.id, body: '火・木に計算ドリル15分。出した日が1日ふえた。' },
    { kind: 'KARTE', targetId: w.kid.id, body: 'わり算のひっ算、ていねいに書けとったな。' + 'あ'.repeat(200) },
    { kind: 'DAILY', targetId: '', refKey: 'hw-9', body: 'ドリル15分おつかれさま！' },
    { kind: 'FLOW', targetId: w.kid2.id, body: 'ほかのクラス' }] } })
  eq(r.json.saved, 3, 'ほかのクラスの子の分は入らない')
  const ids = w.db._all('SELECT id FROM ai_review_drafts').map((x) => x.id)
  eq((await w.call('POST', '/api/teacher/ai-drafts/mark', { user: w.teacher, body: { ids, status: 'published' } })).json.updated, 3)
  const f = await w.call('GET', '/api/teacher/ai-flow?classId=cls-1', { user: w.teacher })
  eq(f.status, 200)
  const mine = f.json.byUser[w.kid.id]
  eq(mine.length, 3, 'DAILY は提出からその子に結びつく')
  ok(mine.some((x) => x.kind === 'FLOW' && /出した日が1日ふえた/.test(x.text)))
  ok(mine.find((x) => x.kind === 'KARTE').text.length <= 91, '本文は書き出しだけ')
  eq((await w.call('GET', '/api/teacher/ai-flow?classId=cls-1', { user: w.kid })).status, 403)
  eq((await w.call('GET', '/api/teacher/ai-flow?classId=cls-1', { user: w.other })).status, 404)
  // 公開した文に合わせる
  const kid0 = w.db._get("SELECT id FROM ai_review_drafts WHERE kind='KARTE'").id
  eq((await w.call('POST', '/api/teacher/ai-flow/final', { user: w.teacher, body: { items: [{ id: kid0, body: '先生が直した文' }] } })).json.updated, 1)
  eq(w.db._get('SELECT body FROM ai_review_drafts WHERE id=?', kid0).body, '先生が直した文')
  eq((await w.call('POST', '/api/teacher/ai-flow/final', { user: w.other, body: { items: [{ id: kid0, body: 'のっとり' }] } })).json.updated, 0, 'ほかの先生は直せない')
})

await T('13 ai-flow.js：直近4週・名前は伏せる・1人の上限・カルテ全文があるときは書き出しを省く', async () => {
  const src = rd('../public/ai-flow.js')
  const doc = { readyState: 'complete', getElementById: () => null, addEventListener() {} }
  const win = { _qnMask: (t) => String(t).replace(/テストA/g, 'A01') }
  const ctx = vm.createContext({ window: win, document: doc, fetch: async () => ({ json: async () => ({}) }), console })
  vm.runInContext(src, ctx)
  const F = win.AI_FLOW
  F._set({ u1: [
    { kind: 'FLOW', at: '2026-10-21', text: 'テストAは火・木にドリル。' },
    { kind: 'DAILY', at: '2026-10-21', text: 'おつかれさま' },
    { kind: 'KARTE', at: '2026-10-20', text: 'カルテの書き出し' },
    { kind: 'PLAN', at: '2026-10-14', text: 'け'.repeat(400) },
    { kind: 'PLAN', at: '2026-10-07', text: 'こ'.repeat(400) }] })
  const a = F.linesFor('u1', { karte: false }).join('\n')
  ok(/先週までの流れ/.test(a)); ok(/A01は火・木/.test(a), '名前を伏せる'); ok(!/テストA/.test(a))
  ok(/カルテ「カルテの書き出し」/.test(a)); ok(/長いので/.test(a), '上限で切る')
  ok(a.length < 700, '1人ぶんが長くなりすぎない: ' + a.length)
  const b = F.linesFor('u1', { karte: true }).join('\n')
  ok(!/カルテの書き出し/.test(b), 'カルテは別の欄で全文が渡るので省く')
  ok(/はじめての回/.test(F.linesFor('nobody', {}).join('\n')))
  ok(F.ruleLines(true).join('\n').indexOf('くり返しにならないように') >= 0)
  ok(F.ruleLines(true).join('\n').indexOf('[FLOW:') >= 0)
  ok(F.ruleLines(false).join('\n').indexOf('[FLOW:') < 0)
})

await T('14 先生の画面：成果物ボタン・読み込みタグ・配る道。子どもの画面（/）には写真の道が無い', async () => {
  const tsx = rd('../src/index.tsx')
  ok(tsx.indexOf('onclick="PF_OPEN()"') > 0); ok(tsx.indexOf('<script src="/portfolio.js?v=1">') > 0); ok(tsx.indexOf('<script src="/ai-flow.js?v=1">') > 0)
  ok(tsx.indexOf("app.get('/portfolio.js'") > 0); ok(tsx.indexOf("app.get('/ai-flow.js'") > 0)
  const html = rd('../public/index.html')
  ok(html.indexOf('/api/teacher/portfolio') < 0 && html.indexOf('/api/photo/') < 0, '子どもの画面は写真の道を使わない')
  const ta = rd('../public/teacher-ai.js')
  for (const k of ['window.AI_FLOW.prefetch(', 'window.AI_FLOW.linesFor(', "'=== [FLOW:'", 'window.AI_FLOW.saveFinal(', "'FLOW', 'WORK', 'WORKMEMO']"]) ok(ta.indexOf(k) > 0, k)
  // 構文チェック
  new vm.Script(ta); new vm.Script(rd('../public/portfolio.js')); new vm.Script(rd('../public/ai-flow.js'))
})

await T('15 ZIP：この端末で作るZIPが正しい形（CRC・中央ディレクトリ）', async () => {
  const src = rd('../public/portfolio.js')
  const win = {}
  const ctx = vm.createContext({ window: win, document: { getElementById: () => null }, TextEncoder, Blob, Uint8Array, Uint32Array, DataView, ArrayBuffer, Date, setInterval: () => 0, clearInterval() {}, setTimeout: () => 0, fetch: async () => ({ json: async () => ({}) }) })
  vm.runInContext(src, ctx)
  const z = win.__PF_ZIP
  eq(z.crc32(new TextEncoder().encode('123456789')), 0xCBF43926, 'CRC32')
  const blob = z.makeZip([{ name: '001_2026-10-20_算数.jpg', data: jpeg(100) }, { name: '一覧.csv', data: new TextEncoder().encode('a,b') }])
  const u8 = new Uint8Array(await blob.arrayBuffer())
  const dv = new DataView(u8.buffer)
  eq(dv.getUint32(0, true), 0x04034b50)
  const e = u8.length - 22
  eq(dv.getUint32(e, true), 0x06054b50); eq(dv.getUint16(e + 10, true), 2)
  const cdOff = dv.getUint32(e + 16, true)
  eq(dv.getUint32(cdOff, true), 0x02014b50)
  try {
    const { execFileSync } = await import('node:child_process'); const fs = await import('node:fs')
    fs.writeFileSync('/sessions/nifty-amazing-brown/mnt/outputs/tools/_pf_test.zip', u8)
    const out = execFileSync('python3', ['-c', 'import zipfile,sys;z=zipfile.ZipFile("/sessions/nifty-amazing-brown/mnt/outputs/tools/_pf_test.zip");print(z.testzip());print("|".join(z.namelist()))']).toString()
    ok(/^None/.test(out), 'python zipfile で壊れていない: ' + out); ok(out.indexOf('一覧.csv') > 0)
  } catch (err) { if (!/ENOSPC|python3/.test(String(err))) throw err }
})

await T('16 見直し：画像の返し方（nosniff・no-store）／置き場で消せないときは「消した」にしない／転出した子の分も年度末の対象', async () => {
  const w = await world()
  const id = (await addPhoto(w, w.teacher, w.kid.id, { takenOn: '2025-06-01' })).json.id
  const r = await w.call('GET', '/api/teacher/portfolio/img/' + id, { user: w.teacher })
  eq(r.headers.get('x-content-type-options'), 'nosniff'); ok(/no-store/.test(r.headers.get('cache-control'))); ok(/sandbox/.test(r.headers.get('content-security-policy')))
  // 家庭学習の写真：画像でない種類で保存されていても画像として返す
  const dk = studyDay()
  w.db._run('INSERT INTO homework_photos2 (user_id, day_key, idx, mime_type, bytes, byte_size) VALUES (?,?,0,?,?,?)', w.kid.id, dk, 'text/html', jpeg(500), 500)
  const h = await w.call('GET', `/api/photo/${w.kid.id}/${dk}`, { user: w.teacher })
  eq(h.headers.get('content-type'), 'image/jpeg'); eq(h.headers.get('x-content-type-options'), 'nosniff')
  // 置き場が無くなったら消せない → 印を付けない
  const keep = w.env.PFDB; delete w.env.PFDB
  eq((await w.call('POST', '/api/teacher/portfolio/delete', { user: w.teacher, body: { ids: [id] } })).json.deleted, 0)
  eq(w.db._get('SELECT deleted_at FROM portfolio_items WHERE id=?', id).deleted_at, null)
  w.env.PFDB = keep
  // 転出：クラスから外れても、このクラスで入れた写真は年度末の対象
  w.db._run("DELETE FROM class_members WHERE user_id=?", w.kid.id)
  const s = (await w.call('GET', '/api/teacher/portfolio/summary?classId=cls-1', { user: w.teacher })).json
  ok(s.yearEnd && s.yearEnd.count === 1, '転出した子の分も数える')
  const y = await w.call('POST', '/api/teacher/portfolio/year-end', { user: w.teacher, body: { classId: 'cls-1', upToFy: s.yearEnd.upToFy, confirm: 'けす' } })
  eq(y.json.deleted, 1); eq(w.pfdb._all('SELECT k FROM pf_blobs').length, 0)
})

await T('17 🤖 成果物の分析：期間・子ども・教科でしぼった目録（先生だけ・写真は入らない）', async () => {
  const w = await world()
  await addPhoto(w, w.teacher, w.kid.id, { takenOn: '2026-10-01', subj: '算数' })
  await addPhoto(w, w.teacher, w.kid.id, { takenOn: '2026-10-15', subj: '国語' })
  await addPhoto(w, w.teacher, w.kid.id, { takenOn: '2026-08-01', subj: '算数' })
  await addPhoto(w, w.other, w.kid2.id, { takenOn: '2026-10-02' })
  const q = (who, qs) => w.call('GET', '/api/teacher/portfolio/range?' + qs, { user: who })
  let r = await q(w.teacher, 'classId=cls-1&from=2026-09-01&to=2026-10-31')
  eq(r.status, 200); eq(r.json.items.length, 2); eq(r.json.items[0].takenOn, '2026-10-01', '古い順')
  ok(!('bytes' in r.json.items[0]) && !('obj_key' in r.json.items[0]), '写真や置き場の鍵は返さない')
  eq((await q(w.teacher, 'classId=cls-1&from=2026-09-01&to=2026-10-31&subj=' + encodeURIComponent('国語'))).json.items.length, 1)
  eq((await q(w.teacher, 'classId=cls-1&from=2026-01-01&to=2026-12-31&userIds=' + w.kid2.id)).json.items.length, 0, 'ほかのクラスの子は入らない')
  eq((await q(w.teacher, 'classId=cls-2&from=2026-01-01&to=2026-12-31')).status, 404)
  eq((await q(w.kid, 'classId=cls-1&from=2026-01-01&to=2026-12-31')).status, 403)
  eq((await q(w.teacher, 'classId=cls-1&from=x&to=2026-12-31')).status, 400)
})

await T('18 🤖 取り込み→公開：WORK は子どものカルテ（アプリ）に文だけ出る・WORKMEMO は先生だけ・流れに入る', async () => {
  const w = await world()
  const r = await w.call('POST', '/api/teacher/ai-drafts', { user: w.teacher, body: { classId: 'cls-1', items: [
    { kind: 'WORK', targetId: w.kid.id, body: '式のとなりに ことばで考えを書いとったね。次は図も1つ入れてみる？' },
    { kind: 'WORKMEMO', targetId: w.kid.id, body: 'C01：9月より1ページの行数がふえた。式に説明を添えるようになった。' }] } })
  eq(r.json.saved, 2)
  // 公開前は出ない
  await w.call('GET', '/api/student/my-karte', { user: w.kid })   // 表がまだ無ければ作られる
  w.db._run("INSERT INTO student_karte_shared (user_id, class_id, shared_at) VALUES (?, 'cls-1', datetime('now'))", w.kid.id)
  let k = await w.call('GET', '/api/student/my-karte', { user: w.kid })
  eq(k.status, 200); eq(k.json.work, null, '公開前は出ない')
  const ids = w.db._all('SELECT id FROM ai_review_drafts').map((x) => x.id)
  await w.call('POST', '/api/teacher/ai-drafts/mark', { user: w.teacher, body: { ids, status: 'published' } })
  k = await w.call('GET', '/api/student/my-karte', { user: w.kid })
  ok(k.json.work && /図も1つ/.test(k.json.work.text), '子どものカルテに📓')
  ok(JSON.stringify(k.json).indexOf('C01') < 0 && JSON.stringify(k.json).indexOf('行数がふえた') < 0, '先生用メモは出ない')
  ok(JSON.stringify(k.json).indexOf('/api/') < 0 && JSON.stringify(k.json).indexOf('pf_') < 0, '写真の道は出ない')
  const n = await w.call('GET', '/api/teacher/portfolio/work-notes', { user: w.teacher })
  ok(/図も1つ/.test(n.json.byUser[w.kid.id].text))
  eq(Object.keys((await w.call('GET', '/api/teacher/portfolio/work-notes', { user: w.other })).json.byUser).length, 0, 'ほかの先生には出ない')
  eq((await w.call('GET', '/api/teacher/portfolio/work-notes', { user: w.kid })).status, 403)
  const f = await w.call('GET', '/api/teacher/ai-flow?classId=cls-1', { user: w.teacher })
  const kinds = f.json.byUser[w.kid.id].map((x) => x.kind).sort().join(',')
  eq(kinds, 'WORK,WORKMEMO', '次回の流れに入る')
  ok(w.db._all("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_aird_target'").length === 1, '索引')
})

console.log(`\n${pass}/${pass + fail} passed`)
if (fail) process.exit(1)
