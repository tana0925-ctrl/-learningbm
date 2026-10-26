// 🔐 HSAUTH_V1 家庭学習の提出で「ログインの有効期限が切れていました」と出た件のテスト
//   ・画面：本物の public/index.html の hsSubmitAndExport と public/hschat.js を jsdom で動かす（hschat.test.mjs と同じやり方）
//   ・サーバ：第1引数に src/index.tsx のバンドルを渡すと、/api/homework/submit の 401／403 の分け方も確かめる
//   使い方: node tests/hsauth.test.mjs [./tests/app.after.mjs]   （jsdom が必要: npm i --no-save jsdom）
import fs from 'fs'
import { JSDOM, VirtualConsole } from 'jsdom'

const ROOT = new URL('..', import.meta.url).pathname
const html = fs.readFileSync(process.env.HSCHAT_HTML || (ROOT + 'public/index.html'), 'utf8').replace(/\r/g, '')
const chatJs = fs.readFileSync(ROOT + 'public/hschat.js', 'utf8')

function slice(from, to) {
  const a = html.indexOf(from); const b = html.indexOf(to, a + 1)
  if (a < 0 || b < 0) throw new Error('index.html に見つからない: ' + from)
  return html.slice(a, b)
}
const HS = [
  slice('function hsEnsureState(){', 'let hsSheetTimer'),
  slice('function hsStartStudy(){', 'function hsComputeUnlockState('),
  slice('async function hsSubmitAndExport(){', '// DBへシートを送信する'),
].join('\n')

const results = []
async function t(name, fn) {
  try { await fn(); results.push({ name, ok: true }) } catch (e) { results.push({ name, ok: false, note: String(e && e.message || e) }) }
}
function eq(a, b, m) { if (a !== b) throw new Error(m + ': ' + JSON.stringify(a) + ' !== ' + JSON.stringify(b)) }
function ok(v, m) { if (!v) throw new Error(m) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))
const EXPIRED = '有効期限'

// reply: 'ok' | 'already' | 'viewOnly' | 401 | 403 | '403teacher'
async function device({ store = null, ls = null, viewAs = false, role = 'student', reply = 'ok' } = {}) {
  const vc = new VirtualConsole()   // jsdom の「navigation は未実装」などは だまらせる
  const dom = new JSDOM('<!doctype html><html><head></head><body>'
    + '<div id="screen-hsweek"><div class="flex"><button id="hwOpenTodayBtn">📝 今日のシートを開く</button></div></div>'
    + '<div id="screen-homestudy"><input id="hsMinutes"><textarea id="hsParentComment"></textarea><div id="hsRewardMsg"></div></div>'
    + '</body></html>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/', virtualConsole: vc })
  const w = dom.window
  if (ls) for (const k of Object.keys(ls)) w.localStorage.setItem(k, ls[k])
  w.__calls = []; w.__reply = reply; w.__alerts = []
  w.__HSAUTH_NO_NAV__ = true
  w.__loggedInRole = role
  w.alert = (m) => { w.__alerts.push(String(m)) }
  if (viewAs) w.__VIEWAS_ON__ = true
  const boot = `
    let _loadingData = false;
    let player = ${JSON.stringify(store || { userId: 'stu-1', coins: 1000, homeStudy: { logs: [] } })};
    function saveData(){ window.__store = JSON.parse(JSON.stringify(player)); }
    async function apiJson(url, opt){
      window.__calls.push({ url, body: JSON.parse(opt.body) });
      const rp = window.__reply;
      const fail = (st, err) => { const e = new Error(err); e.status = st; e.body = { ok: false, error: err }; throw e; };
      if (rp === 401) fail(401, 'login_required');
      if (rp === 403) fail(403, 'forbidden');
      if (rp === '403teacher') fail(403, 'student_only');
      if (rp === 'viewOnly') return { ok: true, viewOnly: true };
      if (rp === 'already') return { ok: true, alreadySubmitted: true, id: 'hw-old' };
      return { ok: true, id: 'hw-' + window.__calls.length };
    }
    function hsRender(){} function hsCheckReturned(){} function hsPhotoClear(){} function ensureSecretState(){ player.secret = player.secret || {}; }
    function grantOcha(){} function logAcquire(){} function updatePlayerDisplay(){} function escapeHtml(s){ return String(s); }
    var _hsPhotoFiles = []; var _hsPhotoAnalysisResult = '';
    function hsPhotosSelected(input){ _hsPhotoFiles.push({}); }
    function hwGetPlanForWeek(){ return {}; }
    async function hsFetchWeeklyMenu(){ return null; }
    window.monSpriteHtml = function(){ return '🐯'; };
    window.fetch = async function(url){ return { ok: true, json: async () => ({}) }; };
    ${HS}
  `
  const s1 = w.document.createElement('script'); s1.textContent = boot; w.document.head.appendChild(s1)
  const s2 = w.document.createElement('script'); s2.textContent = chatJs; w.document.head.appendChild(s2)
  await sleep(1300)
  return {
    w,
    P: () => w.eval('player'),
    sess: () => w.eval('player.homeStudy.sheetSession'),
    log: () => Array.from(w.document.querySelectorAll('#hsChatLog .hc-b')).map((x) => x.textContent),
    chatOpen: () => { const r = w.document.getElementById('hsChat'); return !!(r && r.style.display !== 'none') },
    async click(text) {
      const bs = Array.from(w.document.querySelectorAll('#hsChatFoot button, #hsChatFoot label'))
      const b = bs.find((x) => x.textContent.indexOf(text) >= 0)
      if (!b) throw new Error('ボタンがない: ' + text + ' / ある: ' + bs.map((x) => x.textContent).join(' | '))
      b.click(); await sleep(30)
    },
    pass(min) { const s = w.eval('player.homeStudy.sheetSession'); s.startTs -= min * 60000 },
  }
}
// 対話で 提出の直前（📤 先生に 提出 の画面）まで すすめる
async function toSubmit(d) {
  d.w.HSCHAT.open(); await sleep(50)
  await d.click('アプリの修行'); await d.click('楽しいから'); await d.click('15分')
  d.pass(16); d.w.HSCHAT._t.tick(); await d.click('おわる')
  await d.click('はれ'); await d.click('集中できた'); await d.click('このままでOK')
  await d.click('あとで もらう')
}
// シートで 提出できる下書きを作る
function sheetReady(d) {
  const s = d.w.eval('hsEnsureSessionForToday()')
  s.todo = 'ドリル'; s.why = 'わけ'; s.aim = '10分 がんばる'; d.w.eval('hsStartStudy()')
  const s2 = d.sess(); s2.unlocked = true; s2.endWeather = 'sun'
}

await t('1 提出成功（対話）：いつもの /api/homework/submit に1回・コインは1回・控えは のこらない', async () => {
  const d = await device()
  await toSubmit(d)
  const c0 = d.P().coins
  await d.click('先生に 提出'); await sleep(80)
  eq(d.w.__calls.length, 1, '1回だけ送る'); eq(d.w.__calls[0].url, '/api/homework/submit', 'シートと同じAPI')
  eq(d.P().homeStudy.logs.length, 1, '記録1件')
  const b = d.w.__calls[0].body
  eq(d.P().coins - c0, b.rewardCoins + b.bonusCoins, 'コインは いつもの計算どおり1回')
  ok(d.log().some((x) => x.indexOf('提出できたで！') >= 0), '提出できた')
  eq(d.w.__alerts.filter((a) => a.indexOf(EXPIRED) >= 0).length, 0, 'ログイン切れとは言わない')
  eq(d.w.localStorage.getItem('hsResumeV1'), null, '控えは ない')
})

await t('2 見るだけモード：対話は送らず「👀 見るだけモードなので、提出はされないよ（先生用）」／シートでもサーバの viewOnly を提出あつかいにしない', async () => {
  const v = await device({ viewAs: true })
  await toSubmit(v)
  await v.click('先生に 提出'); await sleep(60)
  eq(v.w.__calls.length, 0, '送らない')
  ok(v.log().some((x) => x === '👀 見るだけモードなので、提出はされないよ（先生用）'), '見るだけモードのひとこと')
  eq(v.w.__alerts.filter((a) => a.indexOf(EXPIRED) >= 0).length, 0, 'ログイン切れとは言わない')
  const s = await device({ reply: 'viewOnly' })
  sheetReady(s); const c0 = s.P().coins
  await s.w.eval('hsSubmitAndExport')(); await sleep(30)
  ok(s.w.__alerts.some((a) => a.indexOf('見るだけモードなので、提出はされないよ（先生用）') >= 0), 'シート：見るだけモードのお知らせ')
  eq(s.P().homeStudy.logs.length, 0, 'シート：記録しない'); eq(s.P().coins, c0, 'シート：コインは動かない')
  ok(s.sess() && s.sess().todo === 'ドリル', 'シート：下書きは のこる')
})

await t('3 先生のアカウント（今回の原因）：対話は送らず先生用のひとこと／シートでサーバが 403 student_only でも ログイン切れと言わず ログイン画面へも送らない', async () => {
  for (const role of ['admin', 'teacher']) {
    const d = await device({ role })
    await toSubmit(d)
    await d.click('先生に 提出'); await sleep(60)
    eq(d.w.__calls.length, 0, role + '：送らない')
    ok(d.log().some((x) => x.indexOf('👀 先生のアカウントで開いているので、提出はされないよ（先生用）') === 0), role + '：先生用のひとこと')
    eq(d.w.__alerts.filter((a) => a.indexOf(EXPIRED) >= 0).length, 0, role + '：ログイン切れとは言わない')
  }
  const s = await device({ role: '', reply: '403teacher' })   // 役割がわからなくても サーバの返事で見分ける
  sheetReady(s)
  await s.w.eval('hsSubmitAndExport')(); await sleep(30)
  ok(s.w.__alerts.some((a) => a.indexOf('先生のアカウントで開いているので、提出はされないよ（先生用）') >= 0), 'シート：先生用のお知らせ')
  eq(s.w.__alerts.filter((a) => a.indexOf(EXPIRED) >= 0).length, 0, 'シート：ログイン切れとは言わない')
  eq(s.w.localStorage.getItem('hsResumeV1'), null, 'シート：控えは作らない')
  eq(s.P().homeStudy.logs.length, 0, '記録しない')
})

await t('4 ほんとうの期限切れ（401）→ 書いたものを控えて ログインへ → ログインしなおすと 対話の提出直前から → もう一度おすと1回だけ提出（コイン1回）', async () => {
  const d = await device({ reply: 401 })
  await toSubmit(d)
  const before = JSON.parse(JSON.stringify(d.sess()))
  await d.click('先生に 提出'); await sleep(80)
  ok(d.w.__alerts.some((a) => a.indexOf(EXPIRED) >= 0), 'ログイン切れのお知らせ')
  eq(d.P().homeStudy.logs.length, 0, '記録しない'); eq(d.P().coins, 1000, 'コインは動かない')
  const raw = d.w.localStorage.getItem('hsResumeV1'); ok(raw, '端末に控える')
  const st = JSON.parse(raw)
  eq(st.uid, 'stu-1', 'だれの控えか'); eq(st.chat, true, '対話から'); eq(st.sess.todo, before.todo, '書いたこと'); eq(st.sess.weatherReason, '集中できた', 'ふりかえり')
  // ログインしなおし：サーバの保存は古い（切れていたので 下書きが とどいていない）＝ sheetSession なし
  const d2 = await device({ ls: { hsResumeV1: raw }, store: { userId: 'stu-1', coins: 1000, homeStudy: { logs: [] } } })
  await sleep(200)
  ok(d2.sess() && d2.sess().todo === before.todo && d2.sess().weatherReason === '集中できた', '下書きが もどる')
  ok(d2.chatOpen(), '対話の画面が ひらく')
  eq(d2.sess()._chat.step, 'photo', '提出の直前')
  ok(d2.log().some((x) => x.indexOf('おかえり！ 書いたことは のこってるで') >= 0), 'おかえり')
  eq(d2.log().filter((x) => x === '先生に 送ってるで…').length, 0, '「送ってるで…」は のこさない')
  // 読みこみで 下書きが また古いものに上書きされても、しばらくは もどす（ひとことは ふやさない）
  d2.w.eval('player.homeStudy.sheetSession = null'); await sleep(1300)
  ok(d2.sess() && d2.sess().todo === before.todo, '上書きされても もどす')
  eq(d2.log().filter((x) => x.indexOf('おかえり！') >= 0).length, 1, 'おかえりは1回')
  await d2.click('先生に 提出'); await sleep(80)
  eq(d2.w.__calls.length, 1, '送るのは1回'); eq(d2.w.__calls[0].body.todo, before.todo, '中身は書いたまま')
  eq(d2.P().homeStudy.logs.length, 1, '記録1件')
  const b = d2.w.__calls[0].body
  eq(d2.P().coins - 1000, b.rewardCoins + b.bonusCoins, 'コインは1回')
  eq(d2.w.localStorage.getItem('hsResumeV1'), null, '控えは消える')
  await d2.w.eval('hsSubmitAndExport')(); await sleep(30)
  eq(d2.w.__calls.length, 1, 'もう一度おしても送らない'); eq(d2.P().coins - 1000, b.rewardCoins + b.bonusCoins, 'コインは二重にならない')
})

await t('5 控えは その子だけ：同じ端末で ほかの子が ログインしても 戻さない・消さない／古い日の控えは 消す', async () => {
  const d = await device({ reply: 401 })
  await toSubmit(d); await d.click('先生に 提出'); await sleep(80)
  const raw = d.w.localStorage.getItem('hsResumeV1')
  const o = await device({ ls: { hsResumeV1: raw }, store: { userId: 'stu-2', coins: 50, homeStudy: { logs: [] } } }); await sleep(200)
  ok(!o.sess() || !o.sess().todo, 'ほかの子には 戻さない'); ok(!o.chatOpen(), '対話も ひらかない')
  ok(o.w.localStorage.getItem('hsResumeV1'), '消さない（その子が あとで ログインする）')
  const old = JSON.parse(raw); old.dayKey = '2000-01-01'
  const x = await device({ ls: { hsResumeV1: JSON.stringify(old) } }); await sleep(200)
  eq(x.w.localStorage.getItem('hsResumeV1'), null, '古い日の控えは 消す'); ok(!x.chatOpen(), 'ひらかない')
})

await t('6 シートで期限切れ（401）→ 控え → ログインしなおすと シートの下書きが もどり、おしらせ（対話は ひらかない）', async () => {
  const d = await device({ reply: 401 })
  sheetReady(d)
  await d.w.eval('hsSubmitAndExport')(); await sleep(30)
  ok(d.w.__alerts.some((a) => a.indexOf(EXPIRED) >= 0), 'ログイン切れのお知らせ')
  const raw = d.w.localStorage.getItem('hsResumeV1'); ok(raw, '控える'); eq(JSON.parse(raw).chat, false, 'シートから')
  const d2 = await device({ ls: { hsResumeV1: raw } }); await sleep(200)
  ok(d2.sess() && d2.sess().todo === 'ドリル' && d2.sess().unlocked, 'シートの下書きが もどる')
  ok(!d2.chatOpen(), '対話は ひらかない'); ok(d2.w.__alerts.some((a) => a.indexOf('おかえり') >= 0), 'おしらせ')
  await d2.w.eval('hsSubmitAndExport')(); await sleep(30)
  eq(d2.w.__calls.length, 1, '1回で出せる'); eq(d2.P().homeStudy.logs.length, 1, '記録1件')
})

await t('7 コインの二重なし：サーバに もう今日の提出があれば（alreadySubmitted）ごほうびは出さない', async () => {
  const d = await device({ reply: 'already' })
  await toSubmit(d)
  await d.click('先生に 提出'); await sleep(80)
  eq(d.w.__calls.length, 1, '1回'); eq(d.P().coins, 1000, 'コインは ふえない')
  eq(d.P().homeStudy.logs.length, 1, '提出ずみとして記録（もう一度は出させない）')
  eq(d.P().homeStudy.logs[0].reward.coins, 0, '記録のごほうびも0')
})

// ── サーバ：/api/homework/submit の 401／403 の分け方（バンドルを渡したときだけ）──
const BUNDLE = process.argv[2]
if (BUNDLE) {
  const { FakeD1, SCHEMA } = await import('./d1.mjs')
  const SECRET = 'test-session-secret'
  const b64u = (buf) => Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  async function makeSession(payload) {
    const enc = new TextEncoder(); const data = b64u(enc.encode(JSON.stringify(payload)))
    const key = await crypto.subtle.importKey('raw', enc.encode(SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
    return `v1.${data}.${b64u(new Uint8Array(await crypto.subtle.sign('HMAC', key, enc.encode(data))))}`
  }
  await t('8 サーバ：ログインなし＝401 login_required／先生・管理者＝403 student_only／子ども＝200（2回目は alreadySubmitted・1日1行）', async () => {
    const db = new FakeD1(); db.db.exec(SCHEMA)
    const cols = ['submitted_at INTEGER', 'todo TEXT', 'why TEXT', 'aim TEXT', 'minutes INTEGER', 'end_weather TEXT', 'weather_reason TEXT', 'next_improve TEXT', 'rest_day INTEGER', 'streak_after INTEGER',
      'reward_kind TEXT', 'reward_coins INTEGER', 'reward_shards INTEGER', 'bonus_coins INTEGER', 'bonus_shards INTEGER', 'self_study_plan TEXT', 'weekly_plan TEXT', 'weekly_reflection TEXT',
      'work_photo_analysis TEXT', 'parent_comment TEXT', 'reward_claimed INTEGER DEFAULT 0', 'reward_claimed_at INTEGER', 'day_key TEXT', 'teacher_id TEXT']
    const have = db._all('PRAGMA table_info(homework_submissions)').map((r) => r.name)
    cols.forEach((c) => { if (have.indexOf(c.split(' ')[0]) < 0) db.db.exec('ALTER TABLE homework_submissions ADD COLUMN ' + c) })
    try { db.db.exec('ALTER TABLE users ADD COLUMN last_login_at TEXT') } catch (_e) {}
    db._run("INSERT INTO users (id, role, login_id, name, grade, class_name, is_active) VALUES (?,?,?,?,?,?,1)", 'stu-1', 'student', 'kid1', 'テスト', 3, '3-1')
    const app = (await import(new URL(BUNDLE, 'file://' + process.cwd() + '/').href)).default
    const env = { DB: db, SESSION_SECRET: SECRET, ADMIN_LOGIN_ID: '', ADMIN_PASSWORD: '', AI: null }
    const body = { dayKey: '2026-10-27', todo: 'ドリル', why: 'わけ', aim: '10分 がんばる', minutes: 10, endWeather: 'sun', rewardCoins: 100, bonusCoins: 0 }
    async function call(user) {
      const headers = { 'content-type': 'application/json' }
      if (user) headers.cookie = 'session=' + (await makeSession({ id: user.id, role: user.role, loginId: user.id, isActive: true, iat: Math.floor(Date.now() / 1000) }))
      const res = await app.fetch(new Request('https://test.local/api/homework/submit', { method: 'POST', headers, body: JSON.stringify(body) }), env, { waitUntil() {}, passThroughOnException() {} })
      let j = null; try { j = await res.json() } catch (_e) {}
      return { status: res.status, json: j }
    }
    const n = await call(null); eq(n.status, 401, 'ログインなしは401'); eq(n.json.error, 'login_required', 'login_required')
    const a = await call({ id: 'adm-1', role: 'admin' }); eq(a.status, 403, '管理者は403'); eq(a.json.error, 'student_only', 'student_only')
    const te = await call({ id: 'tea-1', role: 'teacher' }); eq(te.status, 403, '先生は403'); eq(te.json.error, 'student_only', 'student_only')
    const s1 = await call({ id: 'stu-1', role: 'student' }); eq(s1.status, 200, '子どもは出せる')
    const s2 = await call({ id: 'stu-1', role: 'student' }); eq(s2.json.alreadySubmitted, true, '2回目は alreadySubmitted')
    eq(db._all("SELECT id FROM homework_submissions WHERE user_id='stu-1' AND day_key='2026-10-27'").length, 1, '1日1行')
  })
}

const pass = results.filter((r) => r.ok).length
console.log('\n=== hsauth ===')
for (const r of results) console.log((r.ok ? 'PASS' : 'FAIL') + ' | ' + r.name + (r.note ? ' | ' + r.note : ''))
console.log(`\n${pass}/${results.length} passed`)
process.exit(pass === results.length ? 0 : 1)
