// 💬 HSWEEKCHAT_V1 阪神マンと ふりかえる（週の振り返りを 対話で）— 子ども画面のテスト
//   ・本物の public/index.html から 週の振り返りの「出す」（hwSubmitReflection）をそのまま切り出して動かす
//   ・public/kantanref.js（👆かんたんふりかえり）・public/weekref2.js（🤝📊🏫💭）・public/hsweekchat.js を読み込む
//   ・対話で出したときと、いまの画面のボタンで出したときで、サーバに送る中身が同じことを確かめる
//   使い方: node tests/hsweekchat.test.mjs   （jsdom が必要: npm i --no-save jsdom）
//           HSCHAT_HTML=/tmp/served.html node tests/hsweekchat.test.mjs   ← 配信されるHTMLで
import fs from 'fs'
import { JSDOM } from 'jsdom'

const ROOT = new URL('..', import.meta.url).pathname
const html = fs.readFileSync(process.env.HSCHAT_HTML || (ROOT + 'public/index.html'), 'utf8').replace(/\r/g, '')
const kantanJs = fs.readFileSync(ROOT + 'public/kantanref.js', 'utf8')
const wr2Js = fs.readFileSync(ROOT + 'public/weekref2.js', 'utf8')
const chatJs = fs.readFileSync(ROOT + 'public/hsweekchat.js', 'utf8')
const taiJs = fs.readFileSync(ROOT + 'public/teacher-ai.js', 'utf8')

function slice(from, to) {
  const a = html.indexOf(from); const b = html.indexOf(to, a + 1)
  if (a < 0 || b < 0) throw new Error('index.html に見つからない: ' + from)
  return html.slice(a, b)
}
const SUBMIT = slice('function hwSubmitReflection(){', 'function hwSavePlans(){')

const results = []
async function t(name, fn) {
  try { await fn(); results.push({ name, ok: true }) } catch (e) { results.push({ name, ok: false, note: String(e && e.message || e) }) }
}
function eq(a, b, m) { if (a !== b) throw new Error(m + ': ' + JSON.stringify(a) + ' !== ' + JSON.stringify(b)) }
function ok(v, m) { if (!v) throw new Error(m) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const WK = '2026-W44'
function serverData(o = {}) {
  return {
    kantan: { ok: true, week: { best: { unit: 'u-hi', c: 9 }, hwDays: 3, openDays: 4, questions: 24, recentUnit: 'u-hi' }, hard: [], reco: { b: { id: 'u-hi2' } }, status: { wrote: !!o.wrote, rewarded: !!o.rewarded }, reward: 20, taps: null, oneTap: !!o.oneTap, prev: null },
    wr2: o.noWr2 ? null : {
      ok: true, promise: o.noPromise ? null : { text: '毎日 10分 計算を やる' }, plan: [{ day: '月', text: '計算ドリル' }, { day: '水', text: '比の問題' }],
      facts: { openDays: 4, units: [{ unit: 'u-hi', c: 9, prevC: 6, n: 10 }], planDays: 3, doneDays: 2, hwDays: 3 },
      topics: [{ subj: '算数', theme: '比の利用' }], subjects: ['国語', '算数', '理科', '社会'],
      question: { id: 'q01', q: 'どの やり方が よかった？', choices: ['くりかえし といた', 'まちがいを 見なおした', '図や 絵に かいた', '声に 出して 読んだ'] }, mine: null
    },
    posts: o.noSample ? [] : [{ mine: false, kind: 'week', body: '計算を毎日5分つづけたら、はやくなった。来週は文章題もやってみる。', name: '' }, { mine: true, kind: 'week', body: '自分の', name: '' }],
  }
}

async function device({ viewAs = false, data = serverData(), fri = false } = {}) {
  const dom = new JSDOM('<!doctype html><html><head></head><body>'
    + '<div id="hwPlanArea" class="hidden"><div id="hwPlanInputs"></div></div>'
    + '<div id="hwReflectionArea"><div class="wrap"><textarea id="hwReflectionInput"></textarea></div><div id="hwReflectionMsg"></div></div>'
    + '</body></html>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/' })
  const w = dom.window
  w.__posts = []; w.__st = { ok: true, student: true, wrote: !!data.kantan.status.wrote, rewarded: !!data.kantan.status.rewarded, reward: 20 }
  w.console.warn = () => {}
  if (viewAs) w.__VIEWAS_ON__ = true
  if (fri) { const RD = w.Date; const fixed = new RD('2026-10-30T01:00:00Z').getTime(); w.Date = class extends RD { constructor(...a) { if (a.length) super(...a); else super(fixed) } static now() { return fixed } } }
  w.__data = data
  const boot = `
    let player = { userId: 'stu-1', coins: 1000 };
    var CURRICULUM = { math: { grades: { 6: { units: [{ id: 'u-hi', name: '比' }, { id: 'u-hi2', name: '比の利用' }] } } } };
    var _hwWeekOffset = 0;
    var _hwDayKeys830 = ['mon','tue','wed','thu','fri'];
    var __plan = { mon: '計算ドリル', fri: { free: '', reflection: '' } };
    function hsGetDayKey830(){ return '2026-10-30'; }
    function hsGetWeekDayKey830(){ return '2026-10-30'; }
    function hsGetWeekKey(){ return '${WK}'; }
    function hwGetPlanForWeek(){ return JSON.parse(JSON.stringify(__plan)); }
    function hwSavePlanForWeek(wk, p){ __plan = p; }
    window.monSpriteHtml = function(){ return '🐯'; };
    window.fetch = async function(url, opt){
      url = String(url); const m = (opt && opt.method) || 'GET'; const D = window.__data;
      let body = {};
      if (m === 'POST') { const b = JSON.parse(opt.body); window.__posts.push({ url: url.split('?')[0], body: b });
        if (url.indexOf('/api/student/weekly-reflection') >= 0 && !window.__VIEWAS_ON__) { if (String(b.freeText||'').length >= 5) { window.__st.wrote = true; window.__st.rewarded = true; } }
        body = { ok: true }; }
      else if (url.indexOf('/api/student/kantan-ref') >= 0) body = D.kantan;
      else if (url.indexOf('/api/student/week-ref2') >= 0) body = D.wr2 || { ok: false };
      else if (url.indexOf('/api/student/minna/posts') >= 0) body = { ok: true, posts: D.posts };
      else if (url.indexOf('/api/student/week-ref-status') >= 0) body = Object.assign({}, window.__st);
      else if (url.indexOf('/api/student/next-try') >= 0) body = { ok: true, nextTry: null };
      else body = { ok: true };
      return { ok: true, status: 200, json: async () => JSON.parse(JSON.stringify(body)) };
    };
    ${SUBMIT}
    window.hwSubmitReflection = hwSubmitReflection;
  `
  for (const src of [boot, kantanJs, wr2Js, chatJs]) { const s = w.document.createElement('script'); s.textContent = src; w.document.head.appendChild(s) }
  await sleep(50)
  const api = {
    w,
    foot: () => w.document.getElementById('hsWChatFoot'),
    log: () => Array.from(w.document.querySelectorAll('#hsWChatLog .hc-b')).map((x) => x.textContent),
    posts: (u) => w.__posts.filter((p) => p.url.indexOf(u) >= 0),
    async click(text) {
      const bs = Array.from(w.document.querySelectorAll('#hsWChatFoot button'))
      const b = bs.find((x) => x.textContent.indexOf(text) >= 0)
      if (!b) throw new Error('ボタンがない: ' + text + ' / ある: ' + bs.map((x) => x.textContent).join(' | '))
      b.click(); await sleep(20)
    },
    async type(v) { const i = w.document.getElementById('hsWChatIn'); if (!i) throw new Error('入力欄がない'); i.value = v; w.document.getElementById('hsWChatSend').click(); await sleep(20) },
    async openChat() { w.HSWEEKCHAT.open(); await sleep(80) },
  }
  return api
}
function lastIdx(arr, f) { for (let i = arr.length - 1; i >= 0; i--) if (f(arr[i])) return i; return -1 }

// いまの画面（👆かんたんふりかえり＋WEEKREF2）のボタンで 同じものを えらんで出す
async function screenSend(d) {
  await sleep(1700)   // かんたんふりかえりの欄が出る（1.5秒ごと）
  const q = (sel) => d.w.document.querySelector(sel)
  const clickV = async (k, v) => { const b = q('#kantanRef [data-key="' + k + '"][data-v="' + v + '"]'); if (!b) throw new Error('画面にない ' + k + '=' + v); b.click(); await sleep(20) }
  const clickW = async (k, v) => { const b = q('#kantanRef [data-w2="' + k + '"][data-v="' + v + '"]'); if (!b) throw new Error('画面にない w2 ' + k + '=' + v); b.click(); await sleep(20) }
  await sleep(80)
  await clickW('pr', 'some'); await clickW('reason', 'time')
  await clickV('self', 'good'); await clickV('reason', 'best:u-hi'); await clickV('next', 'change'); await clickV('how', 'time')
  q('#kantanAdd').value = '夜ごはんの前に やる'
  await clickV('mood', 'sun')
  await clickW('topic', '0'); await clickW('learned', 'know'); await clickW('more', '0'); await clickW('qc', '1')
  await sleep(20)
  q('#kantanSend').click(); await sleep(60)
}
// 対話で 同じものを えらんで出す
async function chatSend(d) {
  await d.openChat()
  await d.click('ちょっと'); await d.click('時間が なかった')
  await d.click('見た！')
  await d.click('よくできた'); await d.click('で 9問 せいかい'); await d.click('やり方を 変える'); await d.click('時間')
  await d.type('夜ごはんの前に やる')
  await d.click('はれ')
  await d.click('算数：比の利用'); await d.click('「比の利用」の ことが わかった'); await d.click('家で もう一度 ためしたい'); await d.click('まちがいを 見なおした')
}

await t('1 入口「💬 阪神マンとふりかえる」が 週の振り返りの らん（かんたんふりかえりの上）に出る・いまの画面はそのまま', async () => {
  const d = await device(); await sleep(1700)
  const kb = d.w.document.getElementById('kantanRef'), e = d.w.document.getElementById('hsWChatEntry')
  ok(kb && kb.textContent.indexOf('かんたんふりかえり') >= 0, 'いまの画面（かんたんふりかえり）は そのまま')
  ok(e && e.style.display !== 'none', '入口が出る'); eq(e.textContent, '💬 阪神マンとふりかえる', '文言'); eq(e.nextSibling, kb, 'かんたんふりかえりの すぐ上')
  d.w.document.getElementById('hwReflectionArea').classList.add('hidden'); await sleep(1600)
  eq(e.style.display, 'none', '振り返りの らんが かくれているときは 出さない')
})

await t('2 質問の順番：見本（こんなふうに書いた人がおるで）→ 先週決めたこと → 今週の記録の紹介 → ◎○△ → なんで → 次どうする → 気もち → 学校での学び → 考える問い → まとめ', async () => {
  const d = await device()
  await chatSend(d)
  const L = d.log()
  const idx = (s) => L.findIndex((x) => x.indexOf(s) >= 0)
  const order = ['いっしょに ふりかえろか', 'こんなふうに 書いた人が おるで', '先週 決めたこと、どうだった？', '今週の きろく、見てみよか', '今週の 自分の 学びは', 'なんで そう思う？', '次は どうする？', 'なにを 変えてみる？', 'ひとこと あったら', '今週の 気もちは？', '学校での 学びも', 'わかったこと・できるように', 'もっと 知りたい', '今週の 考える問い', 'まとめると']
  order.forEach((s) => ok(idx(s) >= 0, 'ない: ' + s))
  for (let i = 1; i < order.length; i++) ok(idx(order[i - 1]) < idx(order[i]), '順番: ' + order[i - 1] + ' → ' + order[i])
  ok(L[idx('こんなふうに')].indexOf('計算を毎日5分つづけたら') >= 0, '採用された 見本の文'); ok(L.join('').indexOf('自分の') < 0 || L[idx('こんなふうに')].indexOf('「自分の」') < 0, '自分の分は 見本にしない')
  ok(L[idx('先週 決めたこと')].indexOf('毎日 10分 計算を やる') >= 0, '先週の あなた')
  const f = L[idx('今週の きろく')]
  ok(f.indexOf('ひらいた日：4日') >= 0 && f.indexOf('「比」せいかい：先週 6問 → 今週 9問') >= 0 && f.indexOf('3日のうち 2日') >= 0, '記録は 事実だけ')
  ok(!/%|位|点/.test(f), '比較・順位・点・パーセントは出さない')
  ok(L[idx('今週の 考える問い')].indexOf('どの やり方が よかった？') >= 0, '問い')
  ok(d.foot().textContent.indexOf('これで 出す（🪙20コイン）') >= 0, 'まとめのあと「これで出す」')
})

await t('3 対話で出す → いまの画面と 同じ提出（weekly-reflection の自由欄・◎・なんで・次／week-ref2／kantan-ref）がサーバに届く', async () => {
  const a = await device(); await screenSend(a)
  const b = await device(); await chatSend(b); await b.click('これで 出す'); await sleep(80)
  for (const u of ['/api/student/weekly-reflection', '/api/student/week-ref2', '/api/student/kantan-ref']) {
    eq(a.posts(u).length, 1, '画面: ' + u); eq(b.posts(u).length, 1, '対話: ' + u)
    const x = a.posts(u)[0].body, y = b.posts(u)[0].body
    delete x.addedChars; delete y.addedChars
    eq(JSON.stringify(y), JSON.stringify(x), '同じ中身: ' + u)
  }
  const r = b.posts('/api/student/weekly-reflection')[0].body
  eq(r.weekKey, WK, '今週'); ok(r.goodPoint.indexOf('◎ よくできた ／ なんで：') === 0, '項目欄 good_point'); ok(r.nextAction.indexOf('次：やり方を 変える（時間）') === 0, '項目欄 next_action')
  ok(r.freeText.indexOf('今週の 自分の 学びは ◎よくできた。') === 0, '自由欄の文（いつもの形）')
  ok(r.freeText.indexOf('先週 決めたことは ちょっと できた（時間が なかった）') >= 0 && r.freeText.indexOf('学校では 算数の「比の利用」') >= 0, '先週決めたこと・学校での学びも 文に')
  eq(b.posts('/api/student/weekly-plan').length, 1, '週の計画（金曜の振り返り）にも いつもどおり')
})

await t('4 出したあと：🪙20コイン（サーバの返事どおり・1回）→ もう一度 出しても 2回目のコインの言葉は出ない', async () => {
  const d = await device(); await chatSend(d)
  await d.click('これで 出す'); await sleep(2400)
  ok(d.log().some((x) => x.indexOf('🪙20コイン ゲット！') >= 0), '20コイン')
  await d.click('とじる'); await d.openChat()
  ok(d.log().some((x) => x.indexOf('もう 出してあるで。出しなおしても ええで') >= 0), '出しなおしOK')
  await chatSend2(d)
  ok(d.foot().textContent.indexOf('🪙') < 0, '2回目は コインの表示なし')
  await d.click('これで 出す'); await sleep(2400)
  ok(!d.log().some((x) => x.indexOf('🪙20コイン ゲット！') >= 0), 'コインの言葉は出ない'); ok(d.log().some((x) => x.indexOf('出したで！') >= 0), '出した')
  eq(d.posts('/api/student/weekly-reflection').length, 2, '提出は いつもの道で2回（コインはサーバの台帳で1回）')
})
async function chatSend2(d) {   // 見本なし・学校と問いは とばす・じぶんの ことば
  await d.click('できた'); await d.click('見た！'); await d.click('まあまあ'); await d.type('かけ算が はやく なった')
  await d.click('このまま つづける'); await d.click('なし'); await d.click('えらばない'); await d.click('とばす'); await d.click('とばす')
}

await t('5 じぶんの ことばだけ でも出せる（なんで・ひとこと・問い）・先週の約束が無い週は とばす・見本が無ければ出さない', async () => {
  const d = await device({ data: serverData({ noPromise: true, noSample: true }) })
  await d.openChat()
  ok(!d.log().some((x) => x.indexOf('こんなふうに') >= 0), '見本なし')
  ok(d.log().some((x) => x.indexOf('今週の 計画、どうだった？') >= 0), '約束が無ければ 今週の計画')
  await d.click('とばす'); await d.click('見た！'); await d.click('もう少し')
  await d.type('時間が つくりにくかった')
  await d.click('このまま つづける'); await d.type('朝に やる'); await d.click('くもり')
  await d.click('国語'); await d.type('音読が すらすら できた'); await d.type('ほかの 物語も 読みたい')
  await d.type('声に 出すと おぼえやすい')
  await d.click('これで 出す'); await sleep(60)
  const r = d.posts('/api/student/weekly-reflection')[0].body
  ok(r.goodPoint.indexOf('△ もう少し ／ なんで：時間が つくりにくかった') === 0, 'なんで（じぶんの ことば）')
  ok(r.nextAction.indexOf('次：このまま つづける　朝に やる') === 0, 'ひとこと')
  const w2 = d.posts('/api/student/week-ref2')[0].body
  eq(w2.school.subj, '国語'); eq(w2.school.learned, '音読が すらすら できた'); eq(w2.school.more, 'ほかの 物語も 読みたい'); eq(w2.q.text, '声に 出すと おぼえやすい'); eq(w2.q.choice, -1)
  eq(w2.promise.result, '', '先週の約束は とばした')
})

await t('6 金曜に開いたとき（まだ出していない子）：いつもの金曜の声かけの箱が「一緒にふりかえろか！」になる（1つだけ・1日1回）→ 対話へ', async () => {
  const d = await device({ fri: true }); d.w.localStorage.clear()
  ok(d.w.HSWEEKCHAT._t.isFri(), '金曜')
  const r = d.w.kantanRefNudge({ ok: true, wrote: false, rewarded: false, reward: 20 }, () => { d.w.__fallback = 1 })
  eq(r, true, '声かけを引き受ける'); await sleep(30)
  const el = d.w.document.querySelectorAll('#weekRefNudge')
  eq(el.length, 1, '箱は1つ'); ok(el[0].textContent.indexOf('一緒に ふりかえろか！') >= 0, '一緒にふりかえろか！')
  ok(el[0].textContent.indexOf('自分で 書く') >= 0, 'いつもの画面にも 行ける'); eq(d.w.__fallback, undefined, 'いつもの声かけは 重ねて出さない')
  eq(d.w.localStorage.getItem('weekRefNudgeV1'), '2026-10-30', '今日はもう声をかけた（weekref.js と同じ印）')
  d.w.kantanRefNudge({ ok: true }, () => {}); eq(d.w.document.querySelectorAll('#weekRefNudge').length, 1, '重ならない')
  d.w.document.getElementById('weekRefNudgeGo').click(); await sleep(80)
  ok(d.w.document.getElementById('hsWChat').style.display !== 'none', '対話が ひらく')
  const e = await device()   // 金曜いがい（木曜）は いつもの声かけ（かんたんふりかえり側）
  const RD = e.w.Date; const thu = new RD('2026-10-29T01:00:00Z').getTime(); e.w.Date = class extends RD { constructor(...a) { if (a.length) super(...a); else super(thu) } static now() { return thu } }
  e.w.kantanRefNudge({ ok: true }, () => { e.w.__fallback = 1 }); await sleep(40)
  ok(!e.w.document.getElementById('weekRefNudge') || e.w.document.getElementById('weekRefNudge').textContent.indexOf('一緒に ふりかえろか') < 0, '金曜いがいは いつもどおり')
})

await t('7 見るだけモードでは出さない・NG語（責める・否定的なことば）が入っていない', async () => {
  const v = await device({ viewAs: true }); await chatSend(v); await v.click('これで 出す'); await sleep(40)
  eq(v.posts('/api/student/weekly-reflection').length, 0, '見るだけモードでは送らない'); ok(v.log().some((x) => x.indexOf('見るだけモード') >= 0), 'ひとこと')
  const m = taiJs.match(/var TAI_NG_WORDS = (\[[\s\S]*?\]);/)
  ok(m, 'NG語の一覧'); const NG = (0, eval)(m[1])
  const T = v.w.HSWEEKCHAT._t
  // 「✅できた／🌗ちょっと／🌱できなかった」は 子どもが えらぶ ことばで、いまの画面（weekref2.js）と同じ選択肢なので 対象外（阪神マンの ことばと ボタンの残りを見る）
  const texts = [].concat(Object.values(T.SAY), T.PR.filter((x) => x.k !== 'not').map((x) => x.label), T.RS.map((x) => x.label), T.MORES, T.learnedList('比').map((x) => x.s), T.learnedList('').map((x) => x.s))
  const hits = []
  texts.forEach((s) => { NG.forEach((w) => { if (String(s).indexOf(w) >= 0) hits.push(w + '←' + s) }); if (/まだ[^。、！？!?\n]{0,14}(ない|ません|へん|てない)/.test(s)) hits.push('まだ〜ない←' + s) })
  eq(hits.length, 0, 'NG語: ' + hits.join(' / '))
})

await t('8 とじても つづきから・「さいしょから」で やり直せる・読めないときは いつもの らんを案内', async () => {
  const d = await device(); await d.openChat()
  await d.click('できた'); await d.click('見た！')
  d.w.document.getElementById('hsWChatX').click(); await d.openChat()
  ok(d.foot().textContent.indexOf('よくできた') >= 0, '◎○△の問いから つづき')
  await d.click('よくできた'); await d.click('で 9問 せいかい'); await d.click('このまま つづける'); await d.click('なし'); await d.click('えらばない'); await d.click('とばす'); await d.click('とばす')
  await d.click('さいしょから'); await sleep(80)
  ok(d.foot().textContent.indexOf('できた') >= 0 && d.log().filter((x) => x.indexOf('いっしょに ふりかえろか') >= 0).length === 1, 'さいしょから')
  const e = await device({ data: Object.assign(serverData(), { kantan: { ok: false, status: {} } }) }); await e.openChat()
  ok(e.log().some((x) => x.indexOf('いつもの ふりかえりの らんも 使えるで') >= 0), '読めないとき')
})

const pass = results.filter((r) => r.ok).length
console.log('\n=== hsweekchat ===')
for (const r of results) console.log((r.ok ? 'PASS' : 'FAIL') + ' | ' + r.name + (r.note ? ' | ' + r.note : ''))
console.log(`\n${pass}/${results.length} passed`)
process.exit(pass === results.length ? 0 : 1)
