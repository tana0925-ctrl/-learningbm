// PORTFOLIO_V1 ＋ AIFLOW_V1 先生の画面のテスト（jsdom）
//   ・public/portfolio.js を読み込み、fetch を本物のハンドラ（バンドル）につないで、開く→子ども→くらべる→大きく を動かす
//   ・public/ai-flow.js が①に「流れ」チェックと「一時チャット」の1行を足すこと
//   使い方: node tests/portfolio_ui.test.mjs ./app.after.mjs   （jsdom が必要: npm i --no-save jsdom）
import { JSDOM } from 'jsdom'
import { readFileSync } from 'node:fs'
import { FakeD1, SCHEMA } from './d1.mjs'

const BUNDLE = process.argv[2] || './app.after.mjs'
const SECRET = 'test-session-secret'
const rd = (p) => readFileSync(new URL(p, import.meta.url), 'utf8')
let pass = 0, fail = 0
async function T(n, f) { try { await f(); pass++; console.log('PASS | ' + n) } catch (e) { fail++; console.log('FAIL | ' + n + '\n   ' + (e && e.stack || e)) } }
function ok(v, m) { if (!v) throw new Error(m || 'not ok') }
function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') }
async function sign(payload) {
  const enc = new TextEncoder(); const data = b64u(enc.encode(JSON.stringify(payload)))
  const key = await crypto.subtle.importKey('raw', enc.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  return `v1.${data}.${b64u(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data))))}`
}
function readBlob(w, b) { return new Promise((res, rej) => { const fr = new w.FileReader(); fr.onload = () => res(new Uint8Array(fr.result)); fr.onerror = rej; fr.readAsArrayBuffer(b) }) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const db = new FakeD1(); db.db.exec(SCHEMA)
for (const m of ['0026_homework_photos.sql', '0039_homework_photos2.sql', '0050_portfolio.sql']) db.db.exec(rd('../migrations/' + m))
const pfdb = new FakeD1(); pfdb.db.exec(rd('../migrations_pf/0001_pf_blobs.sql'))
db._run("INSERT INTO users (id, role, login_id, name, roster_no) VALUES ('stu-1','student','kid1','テストA',1)")
db._run("INSERT INTO classes (id, teacher_id, name) VALUES ('cls-1','tea-1','6年2組')")
db._run("INSERT INTO class_members (class_id, user_id) VALUES ('cls-1','stu-1')")
const app = (await import(BUNDLE)).default
const env = { DB: db, PFDB: pfdb, SESSION_SECRET: SECRET, AI: null }
const cookie = 'session=' + await sign({ id: 'tea-1', role: 'teacher', loginId: 'sensei', isActive: true, iat: Math.floor(Date.now() / 1000) })
async function appFetch(url, init = {}) {
  const h = new Headers(init.headers || {}); h.set('cookie', cookie)
  return app.fetch(new Request(new URL(url, 'https://t.local'), { ...init, headers: h }), env, { waitUntil() {}, passThroughOnException() {} })
}
// 写真を2まい（先生が追加）
for (const [d, s] of [['2026-05-10', '国語'], ['2026-10-20', '国語']]) {
  const fd = new FormData(); fd.append('userId', 'stu-1'); fd.append('takenOn', d); fd.append('subj', s)
  fd.append('photo', new File([new Uint8Array([0xFF, 0xD8, 1, 2, 3])], 'p.jpg', { type: 'image/jpeg' }))
  await appFetch('/api/teacher/portfolio/upload', { method: 'POST', body: fd })
}

await T('1 📸成果物：開く→子ども一覧→子ども→月の見出し→2まいをくらべる→大きく', async () => {
  const dom = new JSDOM('<!doctype html><body><select id="analyticsClassFilter"><option value="cls-1" selected>x</option></select></body>', { runScripts: 'outside-only', url: 'https://t.local/teacher' })
  const w = dom.window
  w.fetch = (u, i) => appFetch(u, i)
  w.confirm = () => true
  w.eval(rd('../public/portfolio.js'))
  await w.PF_OPEN()
  const body = w.document.getElementById('pfBody').innerHTML
  ok(/テストA/.test(body), '子どもが出る'); ok(/2まい/.test(body), '枚数'); ok(/写真を追加/.test(body))
  ok(w.document.getElementById('pfAddFiles').getAttribute('accept') === 'image/*' && w.document.getElementById('pfAddFiles').multiple, 'iPadで撮る/複数')
  await w.PF._stu('stu-1'); await sleep(20)
  const h2 = w.document.getElementById('pfBody').innerHTML
  ok(/10月/.test(h2) && /5月/.test(h2), '月ごと'); ok(/\/api\/teacher\/portfolio\/img\/pf_[0-9a-f]+/.test(h2), '写真の道')
  ok(/ZIPでダウンロード/.test(h2))
  w.PF._cmp()
  const ids = [...h2.matchAll(/PF\._tap\('(pf_[0-9a-f]+)'\)/g)].map((m) => m[1])
  ok(ids.length === 2)
  w.PF._tap(ids[0]); w.PF._tap(ids[1])
  const L = w.document.getElementById('pfLight')
  ok(L.style.display === 'block' && /くらべる/.test(L.innerHTML), 'くらべる画面')
  ok(L.innerHTML.indexOf('5/10') < L.innerHTML.indexOf('10/20'), '左が前')
  w.PF._lc(); w.PF._cmp(); w.PF._tap(ids[0])
  ok(/この写真を消す/.test(L.innerHTML) && /直す/.test(L.innerHTML), '大きく＋直す・消す')
})

await T('2 🧵 ai-flow.js：①に「流れ」チェック（はじめから入）と「一時チャット」のおすすめ', async () => {
  const dom = new JSDOM('<!doctype html><body><div class="row"><label><input type="checkbox" id="taiOptSuggest"> おすすめ計画</label></div><div><button>コピー</button><span id="taiStatus"></span></div></body>', { runScripts: 'outside-only' })
  const w = dom.window
  w.eval(rd('../public/ai-flow.js')); await sleep(50)
  const cb = w.document.getElementById('taiOptFlow')
  ok(cb && cb.checked, 'チェックが入っている')
  ok(/一時チャット/.test(w.document.getElementById('taiFlowTip').textContent))
  ok(w.AI_FLOW.enabled() === true)
  cb.checked = false; ok(w.AI_FLOW.enabled() === false)
})

await T('3 🤖 AIで成果物を分析：①プロンプト（記号・ファイル名・きまり・名前なし）②ZIP（同じ名前）③取り込み（WORK/WORKMEMO・追加）', async () => {
  db._run("UPDATE portfolio_items SET memo='テストAのノート、わり算' WHERE taken_on='2026-10-20'")
  const dom = new JSDOM('<!doctype html><body><select id="analyticsClassFilter"><option value="cls-1" selected>x</option></select><div id="taiDraftList"></div></body>', { runScripts: 'outside-only', url: 'https://t.local/teacher' })
  const w = dom.window
  const posted = []
  w.fetch = async (u, i = {}) => {
    u = String(u)
    if (u.indexOf('/api/teacher/records/parse') === 0) return new Response(JSON.stringify({ ok: true, roster: [{ userId: 'stu-1', loginId: 'kid1', name: 'テストA' }] }))
    if (u === '/api/teacher/ai-drafts' && i.method === 'POST') { const b = JSON.parse(i.body); posted.push(b); return new Response(JSON.stringify({ ok: true, saved: b.items.length })) }
    if (u.indexOf('/api/teacher/ai-drafts') === 0 || u.indexOf('/api/teacher/homework') === 0) return new Response(JSON.stringify({ ok: true, drafts: [], submissions: [] }))
    return appFetch(u, i)
  }
  let clip = ''
  Object.defineProperty(w.navigator, 'clipboard', { value: { writeText: async (t) => { clip = t } }, configurable: true })
  const blobs = []
  w.URL.createObjectURL = (b) => { blobs.push(b); return 'blob:x' }
  w.URL.revokeObjectURL = () => {}
  w.HTMLAnchorElement.prototype.click = function () {}
  w.eval(rd('../public/teacher-ai.js')); w.eval(rd('../public/ai-flow.js')); w.eval(rd('../public/portfolio.js'))
  await w.PF_OPEN()
  const body = w.document.getElementById('pfBody').innerHTML
  ok(/AIで成果物を分析/.test(body)); ok(/名前が写っている写真は外すか、隠してから貼ってね/.test(body), '名前の注意'); ok(/一時チャット/.test(body))
  w.document.getElementById('pfAiFrom').value = '2026-04-01'; w.document.getElementById('pfAiTo').value = '2026-12-31'
  await w.PF._aiCopy()
  ok(/まず|子どもを/.test(w.document.getElementById('pfAiSt').textContent), 'えらばないと止まる')
  w.PF._aiAll(true)
  await w.PF._aiCopy()
  ok(clip.length > 300, 'コピーされた: ' + w.document.getElementById('pfAiSt').textContent)
  const files = [...clip.matchAll(/(C\d\d-\d\d_\d{4}-\d\d-\d\d_[^\s（]+\.jpg)/g)].map((m) => m[1])
  ok(files.length === 2, 'ファイル名2つ: ' + files.join(','))
  ok(files[0] < files[1] && /-01_2026-05-10_国語/.test(files[0]), '古い順・番号_日付_教科')
  ok(clip.indexOf('=== [WORKMEMO:stu-1] ===') >= 0 && clip.indexOf('=== [WORK:stu-1] ===') >= 0, '目印')
  ok(clip.indexOf('テストA') < 0 && clip.indexOf('kid1') < 0, '名前は入らない')
  ok(/（名前）のノート/.test(clip), 'メモの名前は伏せる')
  for (const k of ['書く量の変化', 'ていねいさ', '考え方の書き方', '図や表、式の使い方', '前回の分析メモ', '点数', 'ほかの子と比べない', '1つだけ', '否定的なことば']) ok(clip.indexOf(k) >= 0, k)
  // ② ZIP：プロンプトと同じファイル名
  await w.PF._aiZip()
  const zb = blobs[blobs.length - 1]
  const u8 = await readBlob(w, zb)
  const names = []; const dv = new DataView(u8.buffer)
  for (let p = 0; p + 4 < u8.length; p++) if (dv.getUint32(p, true) === 0x02014b50) { const nl = dv.getUint16(p + 28, true); names.push(new TextDecoder().decode(u8.slice(p + 46, p + 46 + nl))); }
  ok(JSON.stringify(names) === JSON.stringify(files), 'ZIPの名前がプロンプトと同じ: ' + names.join(','))
  ok(names.every((n) => n.indexOf('テスト') < 0), 'ZIPにも名前なし')
  // ③ 取り込み
  w.document.getElementById('pfAiPaste').value = 'はい。\n=== [WORKMEMO:stu-1] ===\nC01：5月より行数がふえた。\n\n=== [WORK:stu-1] ===\nわり算の式のとなりに、ことばで考えを書いとったね。次は図を1つ入れてみる？\n'
  await w.PF._aiImport()
  ok(posted.length === 1, '下書きに送った: ' + w.document.getElementById('pfAiImpSt').textContent)
  ok(posted[0].replace === false, '今日のひと往復の下書きは消さない（追加）')
  const kinds = posted[0].items.map((x) => x.kind + ':' + x.targetId).sort().join(',')
  ok(kinds === 'WORK:stu-1,WORKMEMO:stu-1', kinds)
  ok(w.document.getElementById('pfAiGo').style.display !== 'none', '④へのボタン')
})

await T('4 📓 紙のカルテ：うらの「🎯 来週の めあて」の前に入る／公開した文がない子には出ない', async () => {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only' })
  const w = dom.window
  w.fetch = async () => new Response('{"ok":true,"byUser":{}}')
  w.eval(rd('../public/portfolio.js'))
  const K = w.__PF_KARTE
  K.setWork({ 'stu-1': { text: 'ノートに図をかいて考えとったね。', at: '2026-10-27' } })
  const base = '<html><body><div class="pg last"><div class="sec">✏️</div><div class="sec" style="border-color:#fcd34d"><h2>🎯 来週の わたしの めあて</h2></div><div class="foot">x</div></div></body></html>'
  w._faData = { student: { id: 'stu-1' } }
  const out = K.karteWithWork(base)
  ok(out.indexOf('📓 ノート・作品から') > 0 && out.indexOf('📓') < out.indexOf('🎯'), '🎯の前')
  ok(out.indexOf('<img') < 0, '写真は入らない')
  w._faData = { student: { id: 'stu-9' } }
  ok(K.karteWithWork(base) === base, '無い子には出さない')
  // 包む順番：michi のあとに外側から（michi が入っていないあいだは待つ）
  w._buildKarteHtml = function () { return base }
  ok(K.install(false) === false, 'michi が入るまで待つ')
  const m = function () { return base }; m.__michi = true; w._buildKarteHtml = m
  ok(K.install(false) === true && w._buildKarteHtml.__pfwork && w._buildKarteHtml.__michi, '外側に包む（michi が二重に包まない）')
  w._faData = { student: { id: 'stu-1' } }
  ok(w._buildKarteHtml().indexOf('📓') > 0)
})

await T('5 ②’ PDF：1ファイルに写真を1ページずつ（qpdf で壊れていない）', async () => {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'outside-only' })
  const w = dom.window
  w.fetch = async () => new Response('{}')
  w.eval(rd('../public/portfolio.js'))
  const jpg = (n) => { const a = new Uint8Array(n); a[0] = 0xFF; a[1] = 0xD8; a[n - 2] = 0xFF; a[n - 1] = 0xD9; return a }
  // 本物の JPEG（tools/a.jpg 80x110・b.jpg 110x80）があればそれを使う
  let A = jpg(500), B = jpg(700), ad = [800, 1100], bd = [1100, 800]
  try { A = new Uint8Array(readFileSync(new URL('../../tools/a.jpg', import.meta.url))); B = new Uint8Array(readFileSync(new URL('../../tools/b.jpg', import.meta.url))); ad = [80, 110]; bd = [110, 80] } catch (_e) {}
  const blob = w.__PF_PDF([{ jpg: A, w: ad[0], h: ad[1] }, { jpg: B, w: bd[0], h: bd[1] }])
  const u8 = await readBlob(w, blob)
  ok(new TextDecoder().decode(u8.slice(0, 8)) === '%PDF-1.4')
  const { writeFileSync } = await import('node:fs'); const { execFileSync } = await import('node:child_process')
  const f = new URL('../../tools/_pf_test.pdf', import.meta.url).pathname
  writeFileSync(f, u8)
  let out = ''
  try { out = execFileSync('qpdf', ['--check', f]).toString() } catch (e) { out = String(e.stdout || '') + String(e.stderr || '') }
  ok(/No syntax or stream encoding errors/.test(out), out)
  const pi = execFileSync('pdfinfo', [f]).toString()
  ok(/Pages:\s+2/.test(pi), pi)
})

console.log(`\n${pass}/${pass + fail} passed`)
if (fail) process.exit(1)
