// 📊 WORKREC_V1 成果物の評価も 📸成果物 で — 取り出し・行き先・保存のテスト
//   使い方: node tests/workrec.test.mjs   （jsdom が必要: npm i --no-save jsdom）
import fs from 'fs'
import { JSDOM } from 'jsdom'

const ROOT = new URL('..', import.meta.url).pathname
const pfJs = fs.readFileSync(ROOT + 'public/portfolio.js', 'utf8')
const tsx = fs.readFileSync(ROOT + 'src/index.tsx', 'utf8')
const results = []
async function t(name, fn) { try { await fn(); results.push({ name, ok: true }) } catch (e) { results.push({ name, ok: false, note: String(e && e.message || e) }) } }
function eq(a, b, m) { if (a !== b) throw new Error(m + ': ' + JSON.stringify(a) + ' !== ' + JSON.stringify(b)) }
function ok(v, m) { if (!v) throw new Error(m) }

function boot() {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/teacher' })
  const w = dom.window
  w.__calls = []
  w.fetch = async (url, opt) => { w.__calls.push({ url, body: opt && opt.body ? JSON.parse(opt.body) : null }); return { ok: true, json: async () => ({ ok: true, saved: (opt && opt.body ? JSON.parse(opt.body).rows.length : 0) }) } }
  w.console.warn = () => {}
  const s = w.document.createElement('script'); s.textContent = pfJs; w.document.body.appendChild(s)
  return w
}

const REPLY = [
  'まえおき（読みとばされる）',
  '=== [WORKMEMO:u1] ===',
  '式を図で説明する量がふえた。',
  '=== [WORK:u1] ===',
  '図をつかって 考えを 書いてたね。',
  '=== [WORKREC:u1:C03-01] ===',
  '題: 分数のわり算の説明',
  '教科: 算数',
  '単元: 分数のわり算',
  '本文:',
  '3/4÷1/2 を 図にかいて 考えた。',
  '1/2 が いくつ分かを 数えた。',
  '振り返り: なし',
  '先生の印: ○',
  '評価コメント:',
  '知識・技能：B',
  '　「計算の手順を正しく書いている」',
  '思考・判断・表現：A',
  '　「図と言葉の両方で、なぜその答えになるかを説明している」',
  '主体的に学習に取り組む態度：この成果物からは分かりません',
  '=== [WORKREC:u2:C07-01] ===',
  '題: 江戸の文化のまとめ',
  '教科: 社会',
  '本文: 浮世絵がゴッホにえいきょうしたことを書いた',
  '振り返り: もっと調べたい',
  '先生の印:',
  '評価コメント:',
  '知識・技能：この成果物からは分かりません',
  '思考・判断・表現：この成果物からは分かりません',
  '主体的に学習に取り組む態度：この成果物からは分かりません',
  '=== [WORK:u2] ===',
  '浮世絵のこと、よく調べてたね。',
].join('\n')

await t('1 AIの返事から WORKREC を取り出す（ほかの欄は ひと往復へ のこす）', async () => {
  const w = boot(); const R = w.PF._rec
  const sp = R.splitRec(REPLY)
  eq(sp.rows.length, 2, '2件')
  const a = sp.rows[0]
  eq(a.userId, 'u1', '子ども'); eq(a.no, 'C03-01', '写真の番号'); eq(a.title, '分数のわり算の説明', '題'); eq(a.subject, '算数', '教科'); eq(a.unit, '分数のわり算', '単元')
  ok(a.body.indexOf('図にかいて') >= 0 && a.body.indexOf('いくつ分') >= 0, '本文は複数行'); eq(a.reflection, '', '「なし」は空'); eq(a.evalRank, '○', '先生の印')
  ok(a.evalComment.indexOf('思考・判断・表現：A') >= 0 && a.evalComment.indexOf('「図と言葉') >= 0, '評価コメントは根拠ごと')
  ok(sp.rest.indexOf('[WORKMEMO:u1]') >= 0 && sp.rest.indexOf('[WORK:u1]') >= 0 && sp.rest.indexOf('[WORK:u2]') >= 0, 'ほかの欄は のこる')
  ok(sp.rest.indexOf('WORKREC') < 0 && sp.rest.indexOf('知識・技能') < 0, '評価は ひと往復（子どもへの道）に まぎれない')
  ok(sp.rest.indexOf('浮世絵のこと、よく調べてたね') >= 0, 'WORKREC のあとの WORK も のこる')
})

await t('2 行き先：A・B・C があれば「成績」、なければ「記録」（分析タブの取り込みと同じ決まり）', async () => {
  const w = boot(); const R = w.PF._rec
  const sp = R.splitRec(REPLY)
  eq(R.recDest(sp.rows[0]), 'score', 'ABCあり→成績'); eq(sp.rows[0].k, 'B'); eq(sp.rows[0].t, 'A'); eq(sp.rows[0].a, '', '分からない観点は空')
  eq(R.recDest(sp.rows[1]), 'record', 'ABCなし→記録')
  eq(R.kanten('知識・技能：Ａ').k, 'A', '全角のＡも読む')
})

await t('3 保存：成績は 成果物（題・日・教科）ごとに test-scores、記録は records', async () => {
  const w = boot(); const R = w.PF._rec
  const sp = R.splitRec(REPLY)
  sp.rows.forEach((r) => { r.day = '2026-10-22' })
  const o = await R.saveRec(sp.rows)
  const sc = w.__calls.filter((c) => c.url === '/api/teacher/test-scores/save'), rc = w.__calls.filter((c) => c.url === '/api/teacher/records/save')
  eq(sc.length, 1, '成績は1回'); eq(rc.length, 1, '記録は1回')
  eq(sc[0].body.testName, '分数のわり算の説明'); eq(sc[0].body.subject, '算数'); eq(sc[0].body.testDate, '2026-10-22')
  const r0 = sc[0].body.rows[0]
  eq(r0.userId, 'u1'); eq(r0.evalKnowledge, 'B'); eq(r0.evalThinking, 'A'); eq(r0.evalAttitude, ''); eq(r0.score, null, '点数は入れない'); eq(r0.evalRank, '○')
  eq(rc[0].body.rows[0].userId, 'u2'); eq(rc[0].body.rows[0].reflection, 'もっと調べたい'); eq(rc[0].body.rows[0].title, '江戸の文化のまとめ')
  eq(o.score, 1); eq(o.record, 1)
})

await t('4 写真の日付・教科で うめる／題が無ければ本文の1行目', async () => {
  const w = boot(); const R = w.PF._rec
  const rows = [{ userId: 'u1', no: 'C01-01', title: '', day: '', subject: '', unit: '', body: 'ノートの1行目\n2行目', reflection: '', evalRank: '', evalComment: '' }]
  R.fillFromPhoto(rows)
  eq(rows[0].title, 'ノートの1行目', '題'); eq(rows[0].day, '', '写真が分からなければ空のまま')
})

await t('5 プロンプト：WORKREC の欄・3観点・B が標準・WORK には評価を書かない', async () => {
  const w = boot(); const R = w.PF._rec
  const L = R.recPromptLines({ grade: '' }).join('\n')
  ok(L.indexOf('WORKREC') >= 0 && L.indexOf('知識・技能') >= 0 && L.indexOf('B が標準') >= 0 && L.indexOf('この成果物からは分かりません') >= 0, 'きまり')
  ok(L.indexOf('子どもには出ません') >= 0, '先生だけ')
  ok(pfJs.indexOf("'・WORK と WORKMEMO の欄には、評価・点数・◎○△・ABC") >= 0, 'WORK・WORKMEMO には 評価を書かない')
  ok(pfJs.indexOf("=== [WORKREC:' + u + ':' + e.no + '] ===") >= 0, '写真1まいごとの目印')
  // 学年の評価規準（_ekTable があれば入る）
  w._ekTable = () => ({ '6': { 算数: { kt: '分数の計算ができる', sh: '図や式で説明できる', st: '粘り強く考える' } } })
  const L2 = R.recPromptLines({ grade: '6' }).join('\n')
  ok(L2.indexOf('6年の評価規準') >= 0 && L2.indexOf('分数の計算ができる') >= 0, '評価規準')
})

await t('6 分析タブ：成果物・振り返りの入口は 📸成果物 へ（テストは そのまま）・二重保存の防止', async () => {
  ok(tsx.indexOf('📥 取り込み（テスト）') >= 0, '見出し'); ok(tsx.indexOf('📸 成果物をひらく') >= 0, '案内のボタン')
  ok(tsx.indexOf('>📋 成果物・振り返りを読ませるプロンプト</button>') < 0, '前のプロンプトのボタンは外した')
  ok(tsx.indexOf('function copyRecordPrompt(){') >= 0 && tsx.indexOf('function parseRecords(){') >= 0, '前の形の読み取りは のこす')
  ok(tsx.indexOf('WORKREC_V1 同じ返事を2回取り込んでも') >= 0 && tsx.indexOf('WORKREC_V1 同じ返事を2回保存しても') >= 0, '記録・成績とも 二重にしない')
})

const pass = results.filter((r) => r.ok).length
console.log('\n=== workrec ===')
for (const r of results) console.log((r.ok ? 'PASS' : 'FAIL') + ' | ' + r.name + (r.note ? ' | ' + r.note : ''))
console.log(`\n${pass}/${results.length} passed`)
process.exit(pass === results.length ? 0 : 1)
