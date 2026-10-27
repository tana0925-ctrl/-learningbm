// AIFLOW_V1 「今日のひと往復」を本物の public/teacher-ai.js ＋ public/ai-flow.js で通すテスト（jsdom）
//   ①コピー：ルール・先週までの流れ・[FLOW:ID] が入る／名前は入らない
//   ③取り込み：[FLOW:ID] が下書きになる
//   ④公開：FLOW も公開ずみになり、公開した文に合わせる（/final）
//   流れのチェックを外すと、今までと同じコピーになる
//   使い方: node tests/aiflow_ui.test.mjs   （jsdom が必要）
import { JSDOM } from 'jsdom'
import { readFileSync } from 'node:fs'
const rd = (p) => readFileSync(new URL(p, import.meta.url), 'utf8')
let pass = 0, fail = 0
async function T(n, f) { try { await f(); pass++; console.log('PASS | ' + n) } catch (e) { fail++; console.log('FAIL | ' + n + '\n   ' + (e && e.stack || e)) } }
function ok(v, m) { if (!v) throw new Error(m || 'not ok') }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const HTML = `<!doctype html><body>
<select id="analyticsClassFilter"><option value="cls-1" selected>6-2</option></select>
<div><label><input type="checkbox" id="taiOptDaily"></label><label><input type="checkbox" id="taiOptKarte" checked></label>
<label><input type="checkbox" id="taiOptClass"></label><label><input type="checkbox" id="taiOptPlan"></label>
<label><input type="checkbox" id="taiOptReflect"></label><label><input type="checkbox" id="taiOptSuggest"></label></div>
<div><button>copy</button><span id="taiStatus"></span></div>
<textarea id="taiPaste"></textarea><div id="taiDraftList"></div><span id="taiPubStatus"></span><span id="taiPubCount"></span>
</body>`

function world() {
  const dom = new JSDOM(HTML, { runScripts: 'outside-only', url: 'https://t.local/teacher' })
  const w = dom.window
  const calls = []
  let drafts = []
  w.fetch = async (url, init = {}) => {
    const u = String(url), body = init.body ? JSON.parse(init.body) : null
    calls.push({ u, body, method: init.method || 'GET' })
    let out = { ok: true }
    if (u.indexOf('/api/teacher/records/parse') === 0) out = { ok: true, roster: [{ userId: 'u1', loginId: 'k1', name: 'テストA' }] }
    else if (u.indexOf('/api/teacher/ai-flow?') === 0) out = { ok: true, byUser: { u1: [{ kind: 'FLOW', at: '2026-10-21', text: 'テストAは火・木にドリル。' }, { kind: 'PLAN', at: '2026-10-14', text: '計画の書き出し' }] } }
    else if (u.indexOf('/api/teacher/student-full-analysis') === 0) out = { ok: false }
    else if (u.indexOf('/api/teacher/ai-drafts?') === 0) out = { ok: true, drafts }
    else if (u === '/api/teacher/ai-drafts' && body) { drafts = body.items.map((x, i) => ({ id: 'd' + i, status: 'draft', ...x })); out = { ok: true, saved: drafts.length } }
    else if (u.indexOf('/api/teacher/karte-materials/pick') === 0) out = { ok: true, byStudent: {} }
    else if (u.indexOf('/api/teacher/student-ai-comments') === 0) out = { ok: true, saved: 1 }
    return { ok: true, status: 200, json: async () => out, text: async () => JSON.stringify(out) }
  }
  let clip = ''
  Object.defineProperty(w.navigator, 'clipboard', { value: { writeText: async (t) => { clip = t }, readText: async () => clip }, configurable: true })
  w.confirm = () => true; w.alert = () => {}
  w._qnMask = (t) => String(t).replace(/テストA/g, '〇〇')
  w.getWeekKeyLocal = () => '2026-W44'
  w.eval(rd('../public/teacher-ai.js'))
  w.eval(rd('../public/ai-flow.js'))
  return { w, calls, clip: () => clip, drafts: () => drafts }
}

await T('1 ①コピー：前の流れのルール・先週までの流れ・[FLOW:ID] が入り、名前は入らない', async () => {
  const W = world(); await sleep(30)
  W.w.sessionStorage.clear()
  await W.w.taiCopyAll(); await sleep(30)
  const t = W.clip()
  ok(t.length > 100, 'コピーされた: ' + W.w.document.getElementById('taiStatus').textContent)
  ok(t.indexOf('【前の流れをふまえる】') >= 0, 'ルール')
  ok(t.indexOf('くり返しにならないように') >= 0)
  ok(t.indexOf('【先週までの流れ') >= 0, '流れ')
  ok(t.indexOf('計画アドバイス「計画の書き出し」') >= 0)
  ok(t.indexOf('=== [FLOW:u1]') >= 0, 'FLOW の目印')
  ok(t.indexOf('=== [KARTE:u1]') >= 0)
  ok(t.indexOf('テストA') < 0, '名前は入らない')
  ok(W.calls.some((c) => c.u.indexOf('/api/teacher/ai-flow?classId=cls-1') === 0), '流れを1回読む')
})

await T('2 流れのチェックを外すと、今までどおり（流れ・FLOW なし）', async () => {
  const W = world(); await sleep(30)
  W.w.sessionStorage.clear()
  W.w.document.getElementById('taiOptFlow').checked = false
  await W.w.taiCopyAll(); await sleep(30)
  const t = W.clip()
  ok(t.length > 100); ok(t.indexOf('先週までの流れ') < 0); ok(t.indexOf('[FLOW:') < 0); ok(t.indexOf('=== [KARTE:u1]') >= 0)
  ok(!W.calls.some((c) => c.u.indexOf('/api/teacher/ai-flow') === 0))
})

await T('3 ③取り込み→④公開：FLOW も公開ずみに・公開した文に合わせる', async () => {
  const W = world(); await sleep(30)
  W.w.sessionStorage.clear()
  await W.w.taiCopyAll(); await sleep(30)
  const al = (W.clip().match(/=== \[KARTE:u1\] (\S+) ===/) || [])[1]
  W.w.document.getElementById('taiPaste').value = `=== [KARTE:u1] ${al} ===\nわり算、ていねいやったな。\n\n=== [FLOW:u1] ${al} ===\n火・木にドリル15分。前の週より1日ふえた。\n`
  await W.w.taiImport(); await sleep(50)
  const d = W.drafts()
  ok(d.length === 2, '2件: ' + JSON.stringify(d.map((x) => x.kind)) + ' ' + W.w.document.getElementById('taiStatus').textContent)
  ok(d.some((x) => x.kind === 'FLOW' && x.targetId === 'u1' && /1日ふえた/.test(x.body)))
  const box = W.w.document.getElementById('taiDraftList').innerHTML
  ok(/流れのメモ/.test(box) && /先生だけ/.test(box), '④に「流れのメモ・先生だけ」')
  W.w.taiCheckAll(true)
  const ta = W.w.document.querySelector('.tai-body[data-id="d1"]') || W.w.document.querySelector('.tai-body[data-id="d0"]')
  ok(ta, '本文の欄'); ta.value = ta.value + '（先生が直した）'
  await W.w.taiPublish(); await sleep(50)
  const mark = W.calls.find((c) => c.u === '/api/teacher/ai-drafts/mark')
  ok(mark && mark.body.ids.length === 2, '2件とも公開ずみに: ' + JSON.stringify(mark && mark.body))
  const fin = W.calls.find((c) => c.u === '/api/teacher/ai-flow/final')
  ok(fin && fin.body.items.some((x) => /先生が直した/.test(x.body)), '公開した文に合わせる')
  ok(/流れのメモ1人/.test(W.w.document.getElementById('taiPubStatus').textContent), W.w.document.getElementById('taiPubStatus').textContent)
})

await T('4 🤖 成果物の分析：WORK（📓・子ども）/WORKMEMO（先生だけ）を④で公開 → カルテを子どもの画面に出す・点数ことばは🟡', async () => {
  const W = world(); await sleep(30)
  // portfolio.js を読むと 点数・比べることば が🟡の対象に足される
  W.w.eval(rd('../public/portfolio.js'))
  await W.w.taiImport({ append: true, classId: 'cls-1', say: () => {}, raw: '=== [WORKMEMO:u1] ===\n行数がふえた。\n\n=== [WORK:u1] ===\n満点めざして、図を1つ入れてみる？\n' })
  await sleep(50)
  const d = W.drafts()
  ok(d.length === 2 && d.some((x) => x.kind === 'WORK') && d.some((x) => x.kind === 'WORKMEMO'), JSON.stringify(d))
  const box = W.w.document.getElementById('taiDraftList').innerHTML
  ok(/成果物へのひとこと/.test(box) && /紙のカルテ（📓）/.test(box), '④に📓')
  ok(/満点/.test(box) && /🟡/.test(box), '点数のことばに🟡')
  W.w.taiCheckAll(true)
  await W.w.taiPublish(); await sleep(50)
  const mark = W.calls.find((c) => c.u === '/api/teacher/ai-drafts/mark')
  ok(mark && mark.body.ids.length === 2)
  const share = W.calls.find((c) => c.u === '/api/teacher/karte-share')
  ok(share && share.body.studentIds[0] === 'u1', 'カルテを子どもの画面に出す')
  ok(/成果物へのひとこと1人/.test(W.w.document.getElementById('taiPubStatus').textContent))
})

await T('5 📒 子どものカルテ（アプリ）：📓 ノート・作品から は文だけ（写真は出さない）', async () => {
  const dom = new JSDOM('<!doctype html><body><div><div id="homeReviewSuggest"></div></div></body>', { runScripts: 'outside-only', url: 'https://t.local/' })
  const w = dom.window
  w.fetch = async (u) => ({ ok: true, json: async () => (String(u).indexOf('/api/student/my-karte') === 0
    ? { ok: true, published: true, week: { days: [], done: 1, minutes: 10, voices: [] }, teacherMessage: '', kantan: {}, work: { text: '図をかいて考えとったね。', at: '2026-10-27' } }
    : { ok: false }) })
  w.eval(rd('../public/student-karte.js'))
  for (let i = 0; i < 40 && !w.document.getElementById('myKarteCard'); i++) await sleep(100)
  await sleep(300)
  const card = w.document.getElementById('myKarteCard')
  ok(card && /📓 ノート・作品から/.test(card.innerHTML) && /図をかいて/.test(card.innerHTML), card ? card.innerHTML.slice(0, 200) : 'カードなし')
  ok(card.innerHTML.indexOf('<img') < 0, '写真なし')
})

console.log(`\n${pass}/${pass + fail} passed`)
if (fail) process.exit(1)
