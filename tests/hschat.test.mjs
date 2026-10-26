// 💬 HSCHAT_V1 阪神マンと はじめる家庭学習 — 子ども画面のテスト
//   ・本物の public/index.html から 家庭学習シートの関数（下書き・タイマー・提出）をそのまま切り出して動かす
//   ・public/hschat.js を読み込み、ボタンを押して 最後まで進める
//   ・提出は いつもの hsSubmitAndExport() → /api/homework/submit の中身とコインを確かめる（1回だけ）
//   使い方: node tests/hschat.test.mjs   （jsdom が必要: npm i --no-save jsdom）
//           HSCHAT_HTML=/tmp/served.html node tests/hschat.test.mjs   ← 配信されるHTMLで
import fs from 'fs'
import { JSDOM } from 'jsdom'

const ROOT = new URL('..', import.meta.url).pathname
// HSCHAT_HTML に「配信されたHTML」（src/index.tsx の置きかえ後）を渡すと、そちらで確かめる
const html = fs.readFileSync(process.env.HSCHAT_HTML || (ROOT + 'public/index.html'), 'utf8').replace(/\r/g, '')
const chatJs = fs.readFileSync(ROOT + 'public/hschat.js', 'utf8')
const taiJs = fs.readFileSync(ROOT + 'public/teacher-ai.js', 'utf8')

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

// 1つの「端末」をつくる（store を渡すと、前の端末の保存から続きをはじめる）
async function device({ store = null, ls = null, viewAs = false, submitFail = false } = {}) {
  const dom = new JSDOM('<!doctype html><html><head></head><body>'
    + '<div id="screen-hsweek"><div class="flex"><button id="hwOpenTodayBtn">📝 今日のシートを開く</button></div></div>'
    + '<div id="screen-homestudy"><input id="hsMinutes"><textarea id="hsParentComment"></textarea><div id="hsRewardMsg"></div></div>'
    + '</body></html>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/' })
  const w = dom.window
  if (ls) for (const k of Object.keys(ls)) w.localStorage.setItem(k, ls[k])
  w.__calls = []; w.__saved = 0; w.__submitFail = submitFail
  w.alert = (m) => { w.__alerts = (w.__alerts || []).concat([m]) }
  w.console.warn = () => {}
  if (viewAs) w.__VIEWAS_ON__ = true
  const boot = `
    let player = ${JSON.stringify(store || { userId: 'stu-1', coins: 1000, homeStudy: { logs: [] } })};
    function saveData(){ window.__saved++; window.__store = JSON.parse(JSON.stringify(player)); }
    async function apiJson(url, opt){ window.__calls.push({ url, body: JSON.parse(opt.body) }); if (window.__submitFail) { const e = new Error('net'); throw e; } return { ok: true, id: 'hw-' + window.__calls.length }; }
    function hsRender(){} function hsCheckReturned(){} function hsPhotoClear(){} function ensureSecretState(){ player.secret = player.secret || {}; }
    function grantOcha(){} function logAcquire(){} function updatePlayerDisplay(){} function escapeHtml(s){ return String(s); }
    var _hsPhotoFiles = []; var _hsPhotoAnalysisResult = '';
    function hsPhotosSelected(input){ _hsPhotoFiles.push({}); }
    function hwGetPlanForWeek(){ return { mon:'算数プリント', tue:'算数プリント', wed:'算数プリント', thu:'算数プリント', fri:'算数プリント' }; }
    async function hsFetchWeeklyMenu(){ return { kanjiPage: 'p.20', keisanPage: 'p.12', otherTasks: '' }; }
    window.monSpriteHtml = function(){ return '🐯'; };
    window.fetch = async function(url){
      const body = String(url).indexOf('my-karte') >= 0 ? { ok: true, published: true } : String(url).indexOf('karte-reco') >= 0 ? { ok: true, reco: { a: { name: '分数のかけ算' }, b: { name: '分数のわり算' } } } : {};
      return { ok: true, json: async () => body };
    };
    ${HS}
  `
  const s1 = w.document.createElement('script'); s1.textContent = boot; w.document.head.appendChild(s1)
  const s2 = w.document.createElement('script'); s2.textContent = chatJs; w.document.head.appendChild(s2)
  if (w.__bootErr) throw w.__bootErr
  await sleep(1300)   // 起動（1秒ごと）を1回まわす
  const api = {
    w,
    P: () => w.eval('player'),
    sess: () => w.eval('player.homeStudy.sheetSession'),
    foot: () => w.document.getElementById('hsChatFoot'),
    log: () => Array.from(w.document.querySelectorAll('#hsChatLog .hc-b')).map((x) => x.textContent),
    async click(text) {
      const bs = Array.from(w.document.querySelectorAll('#hsChatFoot button, #hsChatFoot label'))
      const b = bs.find((x) => x.textContent.indexOf(text) >= 0)
      if (!b) throw new Error('ボタンがない: ' + text + ' / ある: ' + bs.map((x) => x.textContent).join(' | '))
      b.click(); await sleep(30)
    },
    async type(v) { const i = w.document.getElementById('hsChatIn'); if (!i) throw new Error('入力欄がない'); i.value = v; w.document.getElementById('hsChatSend').click(); await sleep(30) },
    pass(min) { const s = w.eval('player.homeStudy.sheetSession'); s.startTs -= min * 60000 },   // 開始時刻を前にずらす＝時間がたった
    tick() { w.HSCHAT._t.tick() },
  }
  return api
}

await t('1 はじめる前：今日なにやる→なんで→何分→タイマー開始（いつもの下書きに todo・why・aim が入る）', async () => {
  const d = await device()
  d.w.HSCHAT.open(); await sleep(50)
  ok(d.log().some((x) => x.indexOf('今日は なにやるん？') >= 0), '最初の問い')
  ok(d.foot().textContent.indexOf('分数のかけ算') >= 0, 'カルテの🅰が候補に出る')
  ok(d.foot().textContent.indexOf('計画：算数プリント') >= 0, '今週の計画が候補に出る')
  ok(d.foot().textContent.indexOf('漢字スキル p.20') >= 0, '学校の宿題に先生メニュー')
  await d.click('分数のかけ算')
  await d.click('テストがあるから')
  await d.click('15分')
  const s = d.sess()
  eq(s.started, true, 'タイマー開始'); ok(s.startTs > 0, '開始時刻')
  ok(s.todo.indexOf('分数のかけ算') >= 0, 'todo'); eq(s.why, 'テストがあるから', 'why'); eq(s.aim, '15分 がんばる', 'aim（めあて＝分）')
  ok(d.log().some((x) => x.indexOf('よっしゃ、がんばってな！') >= 0), 'はげまし')
  ok(d.w.document.getElementById('hsChatT'), 'タイマー表示')
})

await t('2 時間になったら 音と画面でお知らせ → もう少し（5分）→ もう一度お知らせ → おわる → 振り返り → いつもの提出（コインは1回だけ）', async () => {
  const d = await device()
  d.w.HSCHAT.open(); await sleep(50)
  await d.click('学校の宿題'); await d.click('苦手をなくしたい'); await d.click('15分')
  d.w.document.getElementById('hsChatX').click()   // 画面を とじても
  d.pass(15); d.tick(); await sleep(20)
  ok(d.w.document.getElementById('hsChat').style.display !== 'none', '時間になったら 画面が ひらく')
  ok(d.log().some((x) => x.indexOf('時間やで！') >= 0), '時間やで！')
  ok(d.w.document.getElementById('hsChat').classList.contains('ring'), '画面で知らせる')
  d.tick(); eq(d.log().filter((x) => x.indexOf('時間やで！') >= 0).length, 1, 'お知らせは1回')
  await d.click('もう少しやる（5分）')
  eq(d.w.HSCHAT._t.targetMs(d.sess()._chat), 20 * 60000, '延長して20分')
  d.pass(5); d.tick(); await sleep(20)
  eq(d.log().filter((x) => x.indexOf('時間やで！') >= 0).length, 2, '延長のあとも知らせる')
  await d.click('おわる')
  eq(d.sess().paused, true, 'おわったら タイマーを止める')
  ok(d.log().some((x) => x.indexOf('今の 気もちは？') >= 0), '気もち')
  await d.click('はれ'); await d.click('集中できた'); await d.click('このままでOK')
  ok(d.log().some((x) => x.indexOf('おうちの人に見せて、サインもらってきてな！') >= 0), 'HSSIGN サインの声かけ（提出の前）')
  await d.click('おうちの人に 見せる'); await sleep(20)
  d.w.document.getElementById('hsSignTa').value = 'よくがんばりました'
  d.w.document.getElementById('hsSignOk').click(); await sleep(30)
  ok(d.log().some((x) => x.indexOf('サインもろたで！ ほな提出しよか') >= 0), 'サインもろたで')
  await d.click('写真を えらぶ')   // label（input はかくれている）
  const pin = d.w.document.getElementById('hsChatPhoto'); d.w.eval('hsPhotosSelected')(pin)
  const coins0 = d.P().coins
  await d.click('先生に 提出'); await sleep(80)
  eq(d.w.__calls.length, 1, '/api/homework/submit は1回')
  const b = d.w.__calls[0].body
  eq(b.why, '苦手をなくしたい', 'why'); eq(b.aim, '15分 がんばる', 'aim'); eq(b.minutes, 20, 'やった時間＝タイマー')
  eq(b.endWeather, 'sun', '天気'); eq(b.weatherReason, '集中できた', '天気の理由'); eq(b.nextImprove, 'このままでOK', '次にするには')
  eq(b.parentComment, '👍 見たよ　よくがんばりました', 'サインは いつもの「サポーターから」に入る')
  ok(b.todo.indexOf('学校の宿題') >= 0 && b.selfStudyPlan === b.todo, 'todo（自主学習の計画も同じ）')
  const got = d.P().coins - coins0
  eq(got, b.rewardCoins + b.bonusCoins, 'コインは いつもの計算どおり')
  eq(d.P().homeStudy.logs.length, 1, 'いつもの記録に1件')
  ok(d.log().some((x) => x.indexOf('提出できたで！') >= 0), '提出できた')
  d.w.HSCHAT.open(); await sleep(30)
  ok(d.log().some((x) => x.indexOf('もう 提出ずみ') >= 0) || d.log().some((x) => x.indexOf('提出できたで！') >= 0), '2回目は出せない')
  await d.w.eval('hsSubmitAndExport')(); await sleep(30)
  eq(d.w.__calls.length, 1, 'シートから押しても2回目は送らない'); eq(d.P().coins - coins0, got, 'コインは二重にならない')
})

await t('3 時間より前に「おわる」→ ほかにやれること さがす → 候補をえらぶと todo に足して つづける／今日はここまで', async () => {
  const d = await device()
  d.w.HSCHAT.open(); await sleep(50)
  await d.click('アプリの修行'); await d.click('楽しいから'); await d.click('20分')
  d.pass(5); await d.click('おわる')
  ok(d.log().some((x) => x.indexOf('もう おわるん？') >= 0), 'もうおわるん？')
  await d.click('さがす')
  ok(d.log().some((x) => x.indexOf('これなんか どうや？') >= 0), '候補')
  ok(d.foot().textContent.indexOf('アプリの修行') < 0, 'えらんだものは候補に出さない')
  await d.click('分数のわり算')
  ok(d.sess().todo.indexOf('アプリの修行＋') === 0 && d.sess().todo.indexOf('分数のわり算') > 0, 'todo に足す')
  eq(d.sess()._chat.step, 'run', 'タイマーは つづく'); eq(d.sess().paused, false, '止めていない')
  await d.click('おわる'); await d.click('今日はここまで')
  eq(d.sess()._chat.step, 'weather', '振り返りへ'); eq(d.sess().minutesManual, '5', 'やった時間は5分')
})

await t('4 一時停止「緊急事態か！？」→ 止まっている間は時間がすすまない → 再開', async () => {
  const d = await device()
  d.w.HSCHAT.open(); await sleep(50)
  await d.click('アプリの修行'); await d.click('楽しいから'); await d.click('10分')
  d.pass(3)
  await d.click('一時停止')
  ok(d.log().some((x) => x.indexOf('緊急事態か！？') >= 0), '緊急事態か')
  const e1 = d.w.eval('hsGetElapsedMs(player.homeStudy.sheetSession)')
  await sleep(1100)
  eq(d.w.eval('hsGetElapsedMs(player.homeStudy.sheetSession)'), e1, '止まっている')
  d.tick(); eq(d.sess()._chat.step, 'run', '止まっている間は お知らせしない')
  await d.click('再開')
  eq(d.sess().paused, false, '再開'); ok(d.log().some((x) => x.indexOf('おかえり') >= 0), 'おかえり')
})

await t('5 とちゅうでアプリを閉じても 続きから（開始時刻で計算するので 時間がずれない）', async () => {
  const d = await device()
  d.w.HSCHAT.open(); await sleep(50)
  await d.click('アプリの修行'); await d.click('楽しいから'); await d.click('15分')
  const store = d.w.__store
  ok(store && store.homeStudy.sheetSession._chat, '保存に会話の続きがのる')
  store.homeStudy.sheetSession.startTs -= 16 * 60000   // 閉じている間に16分たった
  const d2 = await device({ store })
  d2.tick(); await sleep(20)
  ok(d2.w.document.getElementById('hsChat') && d2.w.document.getElementById('hsChat').style.display !== 'none', '時間になっていたら 対話の画面が ひらく')
  ok(d2.log().some((x) => x.indexOf('時間やで！') >= 0), '開いたら すぐ お知らせ')
  ok(d2.log().some((x) => x.indexOf('よっしゃ、がんばってな！') >= 0), '前の会話も のこる')
  ok(Math.floor(d2.w.eval('hsGetElapsedMs(player.homeStudy.sheetSession)') / 60000) >= 16, '時間はずれない')
})

await t('6 シートの「スタート」で先に始めていたら、タイマーは やり直さずに そのまま使う', async () => {
  const d = await device()
  const s = d.w.eval('hsEnsureSessionForToday()')
  s.todo = 'ドリル'; s.why = 'わけ'; s.aim = 'めあて'; d.w.eval('hsStartStudy()')
  d.pass(7); const st = d.sess().startTs
  d.w.HSCHAT.open(); await sleep(50)
  eq(d.sess()._chat.step, 'run', 'タイマーの画面から'); eq(d.sess().startTs, st, '開始時刻は そのまま')
  ok(d.log().some((x) => x.indexOf('シートで もう はじめてる') >= 0), 'ひとこと')
})

await t('7 その他（自分で書く）・何分（その他）・送れなかったときは もう一度', async () => {
  const d = await device({ submitFail: true })
  d.w.HSCHAT.open(); await sleep(50)
  await d.click('その他（自分で書く）'); await d.type('リコーダーの練習')
  await d.click('その他（自分で書く）'); await d.type('発表会があるから')
  await d.click('その他'); await d.type('500')
  ok(d.log().some((x) => x.indexOf('1〜180') >= 0), 'はんい外は もう一度')
  await d.type('25')
  eq(d.sess().aim, '25分 がんばる', '25分'); eq(d.sess().todo, 'リコーダーの練習', 'todo'); eq(d.sess().why, '発表会があるから', 'why')
  d.pass(25); d.tick(); await d.click('おわる')
  await d.click('あめ'); await d.click('その他'); await d.type('ゆびが いたかった')
  await d.click('その他'); await d.type('ゆっくり 練習する')
  await d.click('あとで もらう')
  await d.click('先生に 提出'); await sleep(80)
  eq(d.P().homeStudy.logs.length, 0, '送れなかったら 記録しない')
  ok(d.log().some((x) => x.indexOf('もう一度 おしてみてな') >= 0), 'もう一度')
  d.w.__submitFail = false
  await d.click('先生に 提出'); await sleep(80)
  const b = d.w.__calls[d.w.__calls.length - 1].body
  eq(b.endWeather, 'rain', '天気'); eq(b.weatherReason, 'ゆびが いたかった', '理由'); eq(b.nextImprove, 'ゆっくり 練習する', '次'); eq(b.minutes, 25, '時間')
  eq(d.P().homeStudy.logs.length, 1, '2回目で記録')
})

await t('8 お知らせ：その子に1回だけ（端末に記録）・「はじめる」で対話へ・見るだけモードでは出さない／記録しない', async () => {
  const d = await device(); await sleep(3800)
  const box = d.w.document.getElementById('hsChatIntro')
  ok(box, 'お知らせが出る')
  ok(box.textContent.indexOf('家庭学習を阪神マンと対話しながらできるようになったで！') >= 0, '先生の文言')
  ok(box.textContent.indexOf('💬 阪神マンとはじめる') >= 0 && box.textContent.indexOf('あとで') >= 0, 'ボタン2つ')
  eq(d.w.localStorage.getItem('hsChatIntroV1:stu-1'), '1', '端末に記録')
  d.w.document.getElementById('hsChatIntroGo').click(); await sleep(30)
  ok(d.w.document.getElementById('hsChat').style.display !== 'none', '対話の画面へ')
  const d2 = await device({ ls: { 'hsChatIntroV1:stu-1': '1' } }); await sleep(3800)
  ok(!d2.w.document.getElementById('hsChatIntro'), '2回目は出さない')
  const d3 = await device({ viewAs: true }); await sleep(3800)
  ok(!d3.w.document.getElementById('hsChatIntro'), '見るだけモードでは出さない')
  eq(d3.w.localStorage.getItem('hsChatIntroV1:stu-1'), null, '見るだけモードでは記録しない')
  const d4 = await device({ store: { userId: 'stu-2', coins: 0, homeStudy: { logs: [] } }, ls: { 'hsChatIntroV1:stu-1': '1' } }); await sleep(3800)
  ok(d4.w.document.getElementById('hsChatIntro'), 'ほかの子には その子の1回')
})

await t('9 入口ボタン：週の画面と 今日のシートの上に「💬 阪神マンとはじめる」・提出した日は かくす・いつものシートはそのまま', async () => {
  const d = await device(); await sleep(1600)
  const a = d.w.document.getElementById('hsChatEntryW'), b = d.w.document.getElementById('hsChatEntryS')
  ok(a && b, '2か所'); eq(a.textContent, '💬 阪神マンとはじめる', '文言')
  ok(d.w.document.getElementById('hwOpenTodayBtn'), 'いつものシートのボタンは のこる')
  d.P().homeStudy.logs.unshift({ dayKey: d.w.eval('hsGetDayKey830(new Date())'), kind: 'sheet' })
  await sleep(1600)
  eq(a.style.display, 'none', '提出した日は かくす')
})

await t('10 阪神マンのことば・ボタンに NG語（責める・否定的なことば）が入っていない', async () => {
  const m = taiJs.match(/var TAI_NG_WORDS = (\[[\s\S]*?\]);/)
  ok(m, 'NG語の一覧'); const NG = (0, eval)(m[1])
  const d = await device(); const T = d.w.HSCHAT._t
  const texts = [].concat(Object.values(T.SAY), T.TODO_FIXED.map((x) => x.label), T.WHYS.map((x) => x.label), T.NEXTS, Object.values(T.REASONS).flat(), T.WEATHERS.map((x) => x.label))
  const hits = []
  texts.forEach((s) => { NG.forEach((w) => { if (String(s).indexOf(w) >= 0) hits.push(w + '←' + s) }); if (/まだ[^。、！？!?\n]{0,14}(ない|ません|へん|てない)/.test(s)) hits.push('まだ〜ない←' + s) })
  eq(hits.length, 0, 'NG語: ' + hits.join(' / '))
})

await t('11 すぐ おわっても（0分）シートの「0分のままだよ」確認は出さずに 対話から出せる・見るだけモードでは提出しない', async () => {
  const d = await device()
  d.w.confirm = () => { d.w.__confirmed = 1; return true }
  d.w.HSCHAT.open(); await sleep(50)
  await d.click('アプリの修行'); await d.click('楽しいから'); await d.click('10分')
  await d.click('おわる'); await d.click('今日はここまで')
  await d.click('くもり'); await d.click('半分くらいわかった'); await d.click('時間を変える')
  await d.click('あとで もらう')
  await d.click('先生に 提出'); await sleep(80)
  eq(d.w.__confirmed, undefined, '確認は出さない'); eq(d.w.__calls.length, 1, '出せた'); eq(d.w.__calls[0].body.minutes, 0, 'タイマーの時間のまま')
  eq(d.w.__calls[0].body.nextImprove, '時間を変える', '次'); eq(d.w.__calls[0].body.endWeather, 'cloud', 'くもり')
  const v = await device({ viewAs: true })
  v.w.HSCHAT.open(); await sleep(50)
  await v.click('アプリの修行'); await v.click('楽しいから'); await v.click('10分'); await v.click('おわる'); await v.click('今日はここまで')
  await v.click('はれ'); await v.click('わかった'); await v.click('このままでOK'); await v.click('あとで もらう'); await v.click('先生に 提出'); await sleep(50)
  eq(v.w.__calls.length, 0, '見るだけモードでは送らない'); ok(v.log().some((x) => x.indexOf('見るだけモード') >= 0), 'ひとこと')
})

// ── ✍️ HSSIGN_V1 サポーター（おうちの人）のサイン ──
function hookFetch(d, reply) {
  const base = d.w.fetch
  d.w.__signCalls = []
  d.w.fetch = async function (url, opt) {
    if (String(url).indexOf('/api/homework/parent-sign') >= 0) {
      const body = JSON.parse(opt.body); d.w.__signCalls.push(body)
      const j = reply ? reply(body) : { ok: true, signed: true, parentComment: body.text }
      return { ok: true, json: async () => j }
    }
    return base(url, opt)
  }
}
async function toSign(d, w = 'はれ', r = '集中できた', n = 'このままでOK') {
  d.w.HSCHAT.open(); await sleep(50)
  await d.click('アプリの修行'); await d.click('楽しいから'); await d.click('15分')
  d.pass(16); d.tick(); await d.click('おわる')
  await d.click(w); await d.click(r); await d.click(n)
}

await t('12 HSSIGN 提出の前：おうちの方むけの画面（大きい文字・今日やったこと・時間・天気の要約）→ 👍見たよ（ひとことなし）→ 提出（コインはいつもどおり1回）', async () => {
  const d = await device()
  await toSign(d)
  eq(d.sess()._chat.step, 'sign', 'サインの段')
  await d.click('おうちの人に 見せる'); await sleep(20)
  const box = d.w.document.getElementById('hsSign')
  ok(box, 'おうちの方むけの画面'); const tx = box.textContent
  ok(tx.indexOf('おうちの方へ') >= 0 && tx.indexOf('お子さんの今日の取り組みです') >= 0, '見出し')
  ok(tx.indexOf('アプリの修行') >= 0, '今日やったこと'); ok(tx.indexOf('16分') >= 0 && tx.indexOf('15分 がんばる') >= 0, '時間とめあて'); ok(tx.indexOf('☀️ はれ') >= 0 && tx.indexOf('集中できた') >= 0, '天気とわけ'); ok(tx.indexOf('このままでOK') >= 0, '次は')
  ok(/font-size:30px/.test(d.w.document.getElementById('hsChatCss').textContent), '大きめの文字')
  await d.click('おうちの人に 見せる'); await sleep(20)
  eq(d.w.document.querySelectorAll('#hsSign').length, 1, '2回おしても画面は1つ')
  d.w.document.getElementById('hsSignOk').click(); await sleep(30)
  eq(d.sess().parentComment, '👍 見たよ', 'ひとことなしは「👍 見たよ」')
  eq(d.w.document.getElementById('hsParentComment').value, '👍 見たよ', 'シートの「サポーターから」欄にも同じ文')
  const coins0 = d.P().coins
  await d.click('先生に 提出'); await sleep(80)
  eq(d.w.__calls.length, 1, '提出は1回'); eq(d.w.__calls[0].body.parentComment, '👍 見たよ', 'parentComment')
  const b = d.w.__calls[0].body
  eq(d.P().coins - coins0, b.rewardCoins + b.bonusCoins, 'コインは いつもの計算のまま（サインで増えない）')
  eq(d.P().homeStudy.logs[0].parentComment, '👍 見たよ', '端末の記録にも')
  ok(!d.foot().textContent.includes('サインを もらう'), 'サイン済みなら あとからボタンは出さない')
})

await t('13 HSSIGN「あとでもらう」で先に提出 → その日のうちに「サインをもらう」→ 同じ日の提出の「サポーターから」に足す（コインは変わらない）', async () => {
  const d = await device(); hookFetch(d)
  await toSign(d, 'くもり', '半分くらいわかった', '量を変える')
  await d.click('あとで もらう')
  ok(d.log().some((x) => x.indexOf('サインは 提出したあとでも もらえるで') >= 0), 'あとでも もらえる')
  await d.click('先生に 提出'); await sleep(80)
  eq(d.w.__calls[0].body.parentComment, '', 'サインなしで提出できる')
  const coins1 = d.P().coins
  ok(d.foot().textContent.indexOf('おうちの人の サインを もらう') >= 0, '提出のあと 対話の画面にボタン')
  await sleep(1600)
  const sb = d.w.document.getElementById('hsSignLaterS')
  ok(sb && sb.style.display !== 'none', '今日のシートの上にも「サインをもらう」')
  ok(d.w.document.getElementById('hsChatEntryS').style.display === 'none', '「はじめる」は かくれたまま')
  await d.click('おうちの人の サインを もらう'); await sleep(20)
  const tx = d.w.document.getElementById('hsSign').textContent
  ok(tx.indexOf('アプリの修行') >= 0 && tx.indexOf('☁️ くもり') >= 0 && tx.indexOf('量を変える') >= 0, '提出した内容の要約')
  d.w.document.getElementById('hsSignTa').value = '明日もがんばろうね'
  d.w.document.getElementById('hsSignOk').click(); await sleep(60)
  eq(d.w.__signCalls.length, 1, '1回だけ送る')
  eq(d.w.__signCalls[0].dayKey, d.w.eval('hsGetDayKey830(new Date())'), '今日の提出')
  eq(d.w.__signCalls[0].text, '👍 見たよ　明日もがんばろうね', '「サポーターから」の文')
  eq(d.P().homeStudy.logs[0].parentComment, '👍 見たよ　明日もがんばろうね', '端末の記録にも入る')
  eq(d.w.document.getElementById('hsParentComment').value, '👍 見たよ　明日もがんばろうね', 'シートの欄にも')
  ok(d.log().some((x) => x.indexOf('サインもろたで！ 先生にも とどけたで') >= 0), 'ひとこと')
  eq(d.P().coins, coins1, 'コインは変わらない'); eq(d.w.__calls.length, 1, '提出は1回のまま')
  await sleep(1600)
  eq(sb.style.display, 'none', 'サインが入ったら ボタンは かくす')
})

await t('14 HSSIGN シートで先に「サポーターから」を書いてもらっていたら サインの段はとばす／送れなかったら記録しない／見るだけモードは送らない', async () => {
  const d = await device()
  d.w.HSCHAT.open(); await sleep(50)
  await d.click('アプリの修行'); await d.click('楽しいから'); await d.click('10分')
  const s = d.sess(); s.parentComment = 'シートに書きました'; d.w.eval('hsSetSession')(s)
  d.pass(10); d.tick(); await d.click('おわる'); await d.click('はれ'); await d.click('わかった'); await d.click('このままでOK')
  eq(d.sess()._chat.step, 'photo', 'サインの段はとばす')
  await d.click('先生に 提出'); await sleep(80)
  eq(d.w.__calls[0].body.parentComment, 'シートに書きました', 'シートの文のまま')
  ok(!d.w.document.getElementById('hsSignLaterS') || d.w.document.getElementById('hsSignLaterS').style.display === 'none', 'あとからボタンも出さない')
  const e = await device(); hookFetch(e, () => null)
  await toSign(e); await e.click('あとで もらう'); await e.click('先生に 提出'); await sleep(80)
  await e.click('おうちの人の サインを もらう'); e.w.document.getElementById('hsSignOk').click(); await sleep(60)
  eq(e.P().homeStudy.logs[0].parentComment, '', '送れなかったら 端末にも入れない')
  ok(e.log().some((x) => x.indexOf('また あとで おしてみてな') >= 0), 'もう一度')
  const v = await device({ viewAs: true, store: { userId: 'stu-1', coins: 0, homeStudy: { logs: [{ dayKey: 'X', kind: 'sheet', todo: 'ドリル', minutes: 5, parentComment: '' }] } } }); hookFetch(v)
  v.P().homeStudy.logs[0].dayKey = v.w.eval('hsGetDayKey830(new Date())')
  v.w.HSCHAT.open(); await sleep(30)
  await v.click('おうちの人の サインを もらう'); v.w.document.getElementById('hsSignOk').click(); await sleep(40)
  eq(v.w.__signCalls.length, 0, '見るだけモードでは送らない')
})

const pass = results.filter((r) => r.ok).length
console.log('\n=== hschat ===')
for (const r of results) console.log((r.ok ? 'PASS' : 'FAIL') + ' | ' + r.name + (r.note ? ' | ' + r.note : ''))
console.log(`\n${pass}/${results.length} passed`)
process.exit(pass === results.length ? 0 : 1)
