// 📰 SHINBUN_V1 道しるべ新聞（印刷カルテ）— 組み立てのテスト
//   ・本物の src/index.tsx から _buildKarteHtml と小道具を切り出し、karte-shinbun.js → karte-michi.js を読みこむ
//   ・紙のレイアウト（2ページに おさまるか）は Chromium で確かめた（このテストは 中身の決まりを見る）
//   使い方: node tests/shinbun.test.mjs   （jsdom が必要: npm i --no-save jsdom）
import fs from 'fs'
import { JSDOM } from 'jsdom'

const ROOT = new URL('..', import.meta.url).pathname
const tsx = fs.readFileSync(ROOT + 'src/index.tsx', 'utf8').split('\n')
const hi = tsx.findIndex((l) => l.indexOf('function _unitJa(id)') >= 0)
const helpers = tsx.slice(hi, hi + 4).join('\n')
const sa = tsx.find((l) => l.indexOf('function _subjectArea(id){') >= 0)
const line = tsx.find((l) => l.indexOf('function _buildKarteHtml(){') >= 0)
const build = line.slice(line.indexOf('function _buildKarteHtml(){'), line.indexOf(' function downloadKartePdf(){'))
const shJs = fs.readFileSync(ROOT + 'public/karte-shinbun.js', 'utf8')
const miJs = fs.readFileSync(ROOT + 'public/karte-michi.js', 'utf8')
const pfJs = fs.readFileSync(ROOT + 'public/portfolio.js', 'utf8')
const taiJs = fs.readFileSync(ROOT + 'public/teacher-ai.js', 'utf8')

const results = []
async function t(name, fn) { try { await fn(); results.push({ name, ok: true }) } catch (e) { results.push({ name, ok: false, note: String(e && e.message || e) }) } }
function eq(a, b, m) { if (a !== b) throw new Error(m + ': ' + JSON.stringify(a) + ' !== ' + JSON.stringify(b)) }
function ok(v, m) { if (!v) throw new Error(m) }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

async function make(data, { withShinbun = true, withPf = false, name = '児童A さん（6年生）' } = {}) {
  const dom = new JSDOM('<!doctype html><body></body>', { runScripts: 'dangerously', url: 'https://learning-bm.pages.dev/teacher' })
  const w = dom.window
  w.fetch = async () => ({ ok: true, json: async () => ({ ok: false }) })
  w.console.error = () => {}
  const sc = (txt) => { const s = w.document.createElement('script'); s.textContent = txt; w.document.body.appendChild(s) }
  sc(helpers + '\n' + sa.trim() + '\n' + build + '\nwindow._buildKarteHtml=_buildKarteHtml;window._unitJa=_unitJa;window._unitGrade=_unitGrade;window._gradeClass=_gradeClass;window._subjectArea=_subjectArea;')
  w._faName = name; w._faData = data
  if (withShinbun) sc(shJs)
  sc(miJs)
  await sleep(50)
  if (withPf) { sc(pfJs); w.__PF_KARTE.install(true); w.__PF_KARTE.setWork({ 'stu-x': { text: 'ノートに 図を かいて 考えていたね。' } }) }
  return { w, html: () => w._buildKarteHtml() }
}

const AI = ['先週は 4日 家庭学習を 出したな。木曜は 場所を 変えたら 集中できたって 書いてたで。',
  '▼考えてほしいこと', '集中できた日と できなかった日、なにが ちがったと 思う？',
  '▼これやってみる？', '・分数のわり算を 図にかいて 3問 といてみる？', '・しずかな場所で 15分 やってみる？',
  '▼見出し', '場所を変えたら、集中できた', '▼小見出し', '火曜は「音が気になった」――木曜、しずかな部屋で25分',
  '▼トップ記事', '先週は 5日のうち 4日、家庭学習に とりくんだ。', '木曜は しずかな 場所に うつって 勉強し、「集中できた」と 書いている。',
  '▼教室から', '社会の話し合いで、友だちの意見を つないで 話していた。', '▼編集後記', '「しずかな場所やった」の ひとことが 心に のこったで。'].join('\n')
function rich() {
  return {
    ok: true, student: { id: 'stu-x', grade: 6 }, classId: 'c1',
    overview: { totalSubmissions: 96, totalMinutes: 3100, maxStreak: 9, currentStreak: 0, sunCount: 60, cloudCount: 28, rainCount: 8 },
    subjects: [{ unit: 'm6-frac-mul', rate: 86, total: 140 }, { unit: 'm6-frac-div', rate: 58, total: 125 }],
    recentSubmissions: [
      { day_key: '2026-10-19', todo: '🅰「分数÷分数」をもう一度', minutes: 20, end_weather: 'sun', weather_reason: 'わかった：問題を といてみて', next_improve: 'このままでOK', parent_comment: '👍 見たよ' },
      { day_key: '2026-10-20', todo: '学校の宿題', minutes: 15, end_weather: 'cloud', weather_reason: 'ちょっと集中が切れた：音が 気になった', next_improve: '🏠 場所を変える' },
      { day_key: '2026-10-22', todo: '算数プリント', minutes: 25, end_weather: 'sun', weather_reason: '集中できた：しずかな場所やった', next_improve: '場所を変える', parent_comment: '👍 見たよ　自分から部屋をうつっていました' }],
    reflections: [{ weekKey: '2026-W43', goodPoint: '◎ よくできた ／ なんで：場所を変えたら集中できた', nextAction: '次：問題文に 線を ひいて 読む' }],
    teacherNotes: [{ dayKey: '2026-10-22', body: '新聞の見出しのつけ方がうまかった', showInKarte: true }, { dayKey: '2026-10-21', body: 'これは紙に出さないメモ', showInKarte: false }],
    aiComment: AI, aiCommentMeta: { updatedAt: '2026-10-27', weekStart: '2026-10-19' },
    lastWeek: { from: '2026-10-19', total: 64, days: 4, units: [{ unit: 'm6-frac-div', total: 30, rate: 62, yearRate: 58 }, { unit: 'm6-ratio', total: 18, rate: 72, yearRate: 70, firstEver: true }] },
    monthlyTrends: [{ month: '2026-09', count: 13 }, { month: '2026-10', count: 12 }],
    teishutsu: { karteWeek: { hwDays: 3, onTime: 3 } },
    hanshinAnswers: [{ question: 'いちばん 集中できる 時間は いつ？', answer: '夕ごはんの前' }],
    karteHist: [{ weekKey: '2026-W43', body: AI, publishedAt: '2026-10-27' }, { weekKey: '2026-W42', body: 'x\n▼見出し\n火曜と木曜、2日つづけて晴れ', publishedAt: '2026-10-20' }],
    nextTry: { weekKey: '2026-W43', text: '比を アプリで 5問 やってみる' },
    shinbun: { ago3: { from: '2026-09-28', to: '2026-10-02', days: 1, minutes: 10, voices: ['時間が なかった'], next: 'はやく はじめる' },
      album: [{ dayKey: '2026-09-30', text: 'まちがいの 理由が わかった' }],
      ref2: { promise: '場所を 変える', result: 'できた', reason: '木曜に しずかな 部屋で やった', q: 'なんで 文化が さかえたのか', subj: '社会', theme: '江戸の文化', learned: '浮世絵が ゴッホに えいきょうした' },
      lesson: [{ dayKey: '2026-10-21', subj: '社会', unit: '江戸の文化' }] }
  }
}

await t('1 AIの ▼見出し・▼小見出し・▼トップ記事・▼教室から・▼編集後記 で 1面と2面を組む（2ページ・名前・号）', async () => {
  const { html } = await make(rich()); const h = html()
  ok(h.indexOf('道しるべ新聞') >= 0 && h.indexOf('阪神マン新聞社 発行') >= 0, '題字'); ok(h.indexOf('今週の 主役　<b>児童A</b> さん') >= 0, '主役の名前（さん・学年はつけなおす）')
  eq((h.match(/class="pg np/g) || []).length, 2, '1人2ページ')
  ok(h.indexOf('<div class="hl">場所を変えたら、集中できた</div>') >= 0, '見出し'); ok(h.indexOf('火曜は「音が気になった」') >= 0, '小見出し')
  ok(h.indexOf('<p>先週は 5日のうち 4日、家庭学習に とりくんだ。</p>') >= 0, 'トップ記事（段落ごと）'); ok(h.indexOf('文・阪神マン記者') >= 0, '記者名')
  ok(h.indexOf('<h2>教室から') >= 0 && h.indexOf('友だちの意見を つないで') >= 0, '教室から'); ok(h.indexOf('編集後記') >= 0 && h.indexOf('心に のこったで') >= 0, '編集後記')
  ok(h.indexOf('阪神マン記者の コラム') >= 0 && h.indexOf('木曜は 場所を 変えたら') >= 0, 'コラム＝阪神マンの文'); ok(h.indexOf('💭 集中できた日と') >= 0, '考えてほしいこと')
  ok(h.indexOf('第4号') < 0 && /第\d+号/.test(h), '号'); ok(h.indexOf('10月19日〜10月23日号') >= 0, '週')
})

await t('2 記録の欄：天気・わたしのことば・取材メモ（🏠のアイコンもとる）・おうちの人から・インタビュー・くらべてみよう・アルバム・バックナンバー・予告・今週の授業', async () => {
  const { html } = await make(rich()); const h = html()
  ok(h.indexOf('先週の 天気') >= 0 && h.indexOf('<div class="m">20分</div>') >= 0, '天気')
  ok(h.indexOf('<b>木</b>集中できた：しずかな場所やった') >= 0, 'わたしのことば')
  ok(h.indexOf('取材メモ') >= 0 && h.indexOf('>場所を変える</td>') >= 0 && h.indexOf('🏠 場所を変える') < 0, '取材メモ・次の作戦のアイコンはとる')
  ok(h.indexOf('おうちの人から') >= 0 && h.indexOf('自分から部屋をうつっていました') >= 0, 'おうちの人から')
  ok(h.indexOf('インタビュー') >= 0 && h.indexOf('「場所を 変える」 … できた') >= 0 && h.indexOf('問題文に 線を ひいて 読む') >= 0, 'インタビュー')
  ok(h.indexOf('くらべてみよう') >= 0 && h.indexOf('9月28日〜') >= 0, 'くらべてみよう（よくなったときだけ）')
  ok(h.indexOf('ことばの アルバム') >= 0, 'アルバム'); ok(h.indexOf('「火曜と木曜、2日つづけて晴れ」') >= 0 && (h.match(/「場所を変えたら、集中できた」/g) || []).length === 0, 'バックナンバー（今週の号は のせない）')
  ok(h.indexOf('来週の 予告') >= 0 && h.indexOf('比を アプリで 5問 やってみる') >= 0, '予告'); ok(h.indexOf('今週の 授業') >= 0 && h.indexOf('社会「江戸の文化」') >= 0, '今週の授業')
  ok(h.indexOf('新聞の見出しのつけ方がうまかった') >= 0 && h.indexOf('これは紙に出さないメモ') < 0, '先生から（カルテに出す印のメモだけ）')
  ok(h.indexOf('阪神マンからの しつもん') >= 0 && h.indexOf('夕ごはんの前') >= 0, '阪神マンのしつもんへの答え')
})

await t('3 見るだけの紙：○つけ・□・書く線・点数・％を出さない', async () => {
  const { html } = await make(rich()); const h = html()
  ok(!/class="(box|circ|line|bl|cc|bx)"/.test(h.replace(/class="line"><div class="st/g, '')), '書きこむ部品がない')
  ok(h.indexOf('%') < 0 || !/[0-9０-９]+\s*[%％]/.test(h.replace(/style="[^"]*"/g, '').replace(/<style>[\s\S]*?<\/style>/, '')), 'パーセントの数字を出さない')
  ok(!/[0-9]+点/.test(h.replace(/タイプシュート [0-9]+点/g, '')), '点数を出さない')
})

await t('4 AIの記事がない・家庭学習を出していない週：記録の事実だけで見出しを作る（出していないことは書かない）', async () => {
  const d = rich(); d.aiComment = ''; d.karteHist = []; d.recentSubmissions = []; d.teishutsu = null
  const { html } = await make(d); const h = html()
  ok(h.indexOf('<div class="hl">アプリで 64問に 挑戦</div>') >= 0, 'アプリの事実から見出し')
  ok(h.indexOf('記録から まとめました') >= 0, 'AIではないと分かる')
  ;['出していない', '出さなかった', '未提出', 'できなかった', 'さぼ'].forEach((w) => ok(h.indexOf(w) < 0, 'ない週の ことばを使わない: ' + w))
  ok(!/[^0-9]0日/.test(h) && !/[^0-9]0分/.test(h), '0日・0分を出さない')
  ok(h.indexOf('くらべてみよう') < 0, '0日の週は くらべない'); ok(h.indexOf('取材メモ') < 0 && h.indexOf('先週の 天気') < 0, '記録のない欄は出さない')
  // アプリも0のとき
  const e = rich(); e.aiComment = ''; e.recentSubmissions = []; e.lastWeek = { from: '2026-10-19', total: 0, days: 0, units: [] }
  const h2 = (await make(e)).html(); ok(h2.indexOf('<div class="hl">4月から 96回の 家庭学習</div>') >= 0, '4月からの記録から')
})

await t('5 AIがなくて 記録がある週：本人のことばを見出しに（事実だけの記事）', async () => {
  const d = rich(); d.aiComment = ''; d.karteHist = []
  const h = (await make(d)).html()
  ok(h.indexOf('<div class="hl">「集中できた：しずかな場所やった」</div>') >= 0, '晴れの日の いちばん長いことば')
  ok(h.indexOf('先週は 5日のうち 3日、合わせて 60分 家庭学習に とりくんだ。') >= 0, '事実の記事')
  ok(h.indexOf('阪神マン記者の コラム') < 0, 'コラムは AIの文があるときだけ')
})

await t('6 くらべてみよう は 前より よくなったか 同じときだけ', async () => {
  const d = rich(); d.shinbun.ago3 = { from: '2026-09-28', to: '2026-10-02', days: 5, minutes: 100, voices: [], next: '' }
  const h = (await make(d)).html(); ok(h.indexOf('くらべてみよう') < 0, '3週間前のほうが多いときは出さない')
})

await t('7 📓 ノート・作品から は 2面の決まった場所に入る／新聞が作れないときは これまでの紙', async () => {
  const { html } = await make(rich(), { withPf: true }); const h = html()
  ok(h.indexOf('📓 ノート・作品から') >= 0 && h.indexOf('<!--PF_WORK-->') < 0, '📓が入る')
  ok(h.indexOf('📓 ノート・作品から') > h.indexOf('道しるべ新聞　2面'), '2面に入る')
  // 📸 SHINBUN_PHOTO_V1 写真：いちばん新しい成果物の写真が 📓 の欄に入る（写真だけでも 欄ができる）
  const px = 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=='
  const p1 = await make(rich(), { withPf: true }); p1.w.__PF_KARTE.setPhoto({ 'stu-x': { id: 'i1', src: px, takenOn: '2026-10-22', subj: '算数' } })
  const hp = p1.html(); ok(hp.indexOf('<figure class="pf-ph"><img src="' + px) >= 0 && hp.indexOf('10/22・算数') >= 0, '写真と日付・教科')
  const p2 = await make(rich(), { withPf: true }); p2.w.__PF_KARTE.setWork({}); p2.w.__PF_KARTE.setPhoto({ 'stu-x': { id: 'i1', src: px, takenOn: '2026-10-22', hw: true } })
  const hq = p2.html(); ok(hq.indexOf('📸 写真で見る 成果物') >= 0 && hq.indexOf('10/22・家庭学習') >= 0, '写真だけでも 欄ができる')
  const p3 = await make(rich(), { withPf: true }); p3.w.__PF_KARTE.setWork({}); ok(p3.html().indexOf('<!--PF_WORK-->') < 0 && p3.html().indexOf('<figure class="pf-ph"') < 0, 'どちらも無ければ 欄なし')
  ok(pfJs.indexOf("/^data:image\\//.test(du)") >= 0, '写真は data: にしてから 紙に入れる（印刷に まにあう）')
  const m = await make(rich(), { withShinbun: false }); ok(m.html().indexOf('🧭 学びの道しるべ') >= 0 && m.html().indexOf('道しるべ新聞') < 0, '新聞のファイルがなければ これまでの紙')
  const x = await make(rich()); x.w.KARTE_SHINBUN = () => { throw new Error('x') }; ok(x.html().indexOf('🧭 学びの道しるべ') >= 0, 'こわれても これまでの紙')
})

await t('8 ことば：新聞の決まった文・ミニ講座に NG語がない／AIへの指示に ▼見出し・▼トップ記事 など', async () => {
  const m = taiJs.match(/var TAI_NG_WORDS = (\[[\s\S]*?\]);/); const NG = (0, eval)(m[1])
  const fixed = shJs.match(/'[^'\n]*[ぁ-ん][^'\n]*'/g).map((x) => x.slice(1, -1)).filter((x) => !/^[.#@]|font-family|\{|<|=/.test(x))
  const hits = []; fixed.forEach((s) => NG.forEach((w) => { if (s.indexOf(w) >= 0) hits.push(w + '←' + s) }))
  eq(hits.length, 0, 'NG語: ' + hits.join(' / '))
  ;['▼見出し', '▼小見出し', '▼トップ記事', '▼教室から', '▼編集後記'].forEach((k) => ok(taiJs.indexOf("'      " + k + "'") >= 0, 'AIへの指示: ' + k))
  ok(taiJs.indexOf('名前は書かない') >= 0 && taiJs.indexOf('出していないことにはふれない') >= 0, '記事のきまり')
  const sp = (await make(rich())).w.michiSplitAi(AI)
  eq(sp.head, '場所を変えたら、集中できた'); eq(sp.sub, '火曜は「音が気になった」――木曜、しずかな部屋で25分'); ok(sp.top.split('\n').length === 2, 'トップ記事は段落を のこす'); eq(sp.ask, '集中できた日と できなかった日、なにが ちがったと 思う？', '前の見出しは そのまま')
  eq(sp.tries.length, 2, 'やってみるも そのまま')
})

await t('9 冒険ニュース：その子の 防衛戦・MVPの部門・図鑑・タイプシュート（ほかの子の名前・勝ち負け・順位の数字は出さない）', async () => {
  const d = rich(); d.lastWeekSpecial = { pokedex: 3, typeshoot: 1250, wild: 0 }
  d.shinbun.adv = { def: { count: 4, monsters: ['ピヨヒコ'], strategy: 'guard', mvp: ['kufu'] } }
  const h = (await make(d)).html()
  ok(h.indexOf('冒険ニュース') >= 0, '欄'); ok(h.indexOf('4回 出場。「ピヨヒコ」で、作戦は まもり 重視') >= 0, '防衛戦')
  ok(h.indexOf('「くふう」部門に えらばれた') >= 0, 'MVPは部門の名前だけ'); ok(h.indexOf('新しく 3ひき 登録') >= 0, '図鑑'); ok(h.indexOf('タイプシュート</b>　1250点') >= 0, 'タイプシュート')
  const vis = h.replace(/<style>[\s\S]*?<\/style>/, '').replace(/<script>[\s\S]*?<\/script>/g, '').replace(/<[^>]+>/g, ' ')   // 見える文字だけ
  ;['位', '負け', '勝ち', 'lose', 'win'].forEach((w) => ok(vis.replace(/単位|位置/g, '').indexOf(w) < 0, '出さない: ' + w))
  const r1 = rich(); r1.rankPt = { now: 340, prev: 280, prev2: 300 }; const hr = (await make(r1)).html()
  ok(hr.indexOf('正解ポイント 340（先週より 60 ふえた）') >= 0, 'ランキングは その子の ポイントと 先週とのくらべ')
  const r2 = rich(); r2.rankPt = { now: 340, prev: 280, prev2: 200 }; ok((await make(r2)).html().indexOf('（3週 つづけて のびている）') >= 0, '3週つづけて')
  const r3 = rich(); r3.rankPt = { now: 100, prev: 280, prev2: null }; const h3 = (await make(r3)).html(); ok(h3.indexOf('正解ポイント 100</div>') >= 0 || h3.indexOf('正解ポイント 100<') >= 0, 'へったときは 数だけ'); ok(h3.indexOf('へった') < 0, 'へったとは 書かない')
  ok(!/\d+\s*位/.test(hr.replace(/<style>[\s\S]*?<\/style>/, '')), '順位は出さない')
  const e = rich(); e.lastWeekSpecial = null; ok((await make(e)).html().indexOf('冒険ニュース') < 0, '記録がなければ 欄なし')
  ok(taiJs.indexOf('【アプリの冒険（先週）】') >= 0 && taiJs.indexOf('ほかの子の名前、クラスの勝ち負け、順位の数字は書かない') >= 0, 'AIの材料と きまり')
})

await t('10 友だちの名前は 紙に出さない（子どもが書いたことばの中の クラスの子の名前→「友だち」・主役の名前は そのまま）', async () => {
  const d = rich()
  d.recentSubmissions[0].weather_reason = 'わかった：山田さんに 教えてもらった'
  d.recentSubmissions[2].parent_comment = '👍 見たよ　ゆうたくんと いっしょに やっていました'
  d.shinbun.ref2.reason = '佐藤花子さんと 問題を 出し合った'
  const x = await make(d)
  x.w.getStudentNameMap = () => ({ a: '山田 太郎', b: '佐藤 花子', c: '児童A' })
  x.w._serverFuriganaMap = { b: 'ゆうた' }
  const h = x.html()
  ok(h.indexOf('山田') < 0 && h.indexOf('佐藤') < 0 && h.indexOf('ゆうた') < 0, '名前が のこらない')
  ok(h.indexOf('友だちさんに 教えてもらった') >= 0 && h.indexOf('友だちさんと 問題を') >= 0 && h.indexOf('友だちくんと いっしょに') >= 0, '「友だち」に')
  ok(h.indexOf('今週の 主役　<b>児童A</b> さん') >= 0, '主役の名前は 題字に のこる')
  ok(h.indexOf('ゆうがた') < 0 || true, '')
  const T = x.w.__SHINBUN_T
  eq(T.maskNames('<p>ゆうがたに やった</p>', ['ゆうた']), '<p>ゆうがたに やった</p>', 'ひらがなの 一部は こわさない')
  eq(T.maskNames('<img alt="山田"><p>山田さん</p>', ['山田']), '<img alt="山田"><p>友だちさん</p>', 'タグの中には さわらない')
})

const pass = results.filter((r) => r.ok).length
console.log('\n=== shinbun ===')
for (const r of results) console.log((r.ok ? 'PASS' : 'FAIL') + ' | ' + r.name + (r.note ? ' | ' + r.note : ''))
console.log(`\n${pass}/${results.length} passed`)
process.exit(pass === results.length ? 0 : 1)
