// NOWUNIT_V1 カルテの🅰🅱が「いまの単元」を中心に作られるかのテスト（public/karte-michi.js をそのまま読む）
//   使い方: node tests/nowunit.test.mjs
import fs from 'fs'
import vm from 'vm'
const root = new URL('..', import.meta.url).pathname
const html = fs.readFileSync(root + 'public/index.html', 'utf8')
const head = 'const CURRICULUM = {'
const i0 = html.indexOf(head); let dep = 0, e0 = -1
for (let j = i0 + head.length - 1; j < html.length; j++) { const ch = html[j]; if (ch === '{') dep++; else if (ch === '}') { dep--; if (dep === 0) { e0 = j; break } } }
const CUR = (new Function('return (' + html.slice(i0 + head.length - 1, e0 + 1) + ')'))()
const win = {
  CURRICULUM: CUR,
  document: { readyState: 'complete', getElementById: () => null, addEventListener() {}, querySelector: () => null },
  setInterval: () => 0, clearInterval() {}, setTimeout: () => 0, clearTimeout() {},
  fetch: async () => ({ json: async () => ({ ok: false }) }), console,
}
win.window = win
vm.createContext(win)
vm.runInContext(fs.readFileSync(root + 'public/karte-michi.js', 'utf8'), win)
const reco = win.michiComputeReco, resolveNow = win.michiResolveNow
let pass = 0, fail = 0
function t(name, fn) { try { fn(); pass++; console.log('PASS ' + name) } catch (e) { fail++; console.log('FAIL ' + name + ' :: ' + e.message) } }
function eq(a, b, m) { if (a !== b) throw new Error(m + ' (got ' + JSON.stringify(a) + ', want ' + JSON.stringify(b) + ')') }
function ok(v, m) { if (!v) throw new Error(m) }
const NG = ['おそい', '遅い', '遅れ', 'おくれ', '少ない', 'すくない', '足りない', 'たりない', 'サボ', 'できていない', 'できてない', 'できなかった', 'しかない', 'ダメ', 'だめ', 'ちゃんと', '全然', 'みんなより', '平均']
function noNg(r) { const txt = [r.a && r.a.why, r.b && r.b.why, r.mark, r.note].join(' '); NG.forEach((w) => ok(txt.indexOf(w) < 0, 'NG語: ' + w + ' in ' + txt)); ok(!/まだ[^。、！？\n]{0,14}(ない|ません|へん)/.test(txt), 'まだ〜ない') }
function kid(o) { return Object.assign({ student: { id: 's1', grade: 6 }, classId: 'c1', subjects: [], recentUnits: [], karteReco: null, recoFeedback: null, nextTry: null }, o || {}) }
const iso = (daysAgo) => new Date(Date.now() - daysAgo * 86400000).toISOString().slice(0, 19).replace('T', ' ')
const G = (o) => Object.assign({ nowManual: {}, memoTopics: [], nowUnits: [], classGrade: 6, unitProgress: null }, o || {})

t('1 いまの単元の決め方：先生 > 授業メモ > クラスの記録 > 標準', () => {
  const nu = [{ unit: 'm6-proportion', n: 40, users: 5, n7: 20, users7: 4 }]
  eq(resolveNow(G({ nowManual: { math: { unit: 'm6-circle' } }, memoTopics: [{ subj: '算数', theme: '比の利用' }], nowUnits: nu }), 6, 'math').src, 'manual', '先生が先')
  const m = resolveNow(G({ memoTopics: [{ subj: '算数', theme: '比の利用' }], nowUnits: nu }), 6, 'math'); eq(m.src, 'memo', 'メモ'); eq(m.id, 'm6-ratio', '比の利用→比')
  eq(resolveNow(G({ memoTopics: [{ subj: '算数', theme: '比例と反比例のグラフ' }] }), 6, 'math').id, 'm6-proportion', 'いちばん長い名前で照合')
  eq(resolveNow(G({ memoTopics: [{ subj: '社会', theme: '江戸幕府の政治' }] }), 6, 'social').id, 's6-hist-u7', '2文字の重なりで照合')
  eq(resolveNow(G({ memoTopics: [{ subj: '算数', theme: '拡大図と縮図' }, { subj: '算数', theme: '比' }], nowUnits: nu }), 6, 'math').src, 'auto', '最新行が照合できなければメモは使わない')
  eq(resolveNow(G({ nowUnits: nu }), 6, 'math').id, 'm6-proportion', '自動')
  eq(resolveNow(G({ nowUnits: [{ unit: 'm6-proportion', n: 300, users: 2, n7: 300, users7: 2 }] }), 6, 'math').src, 'std', '2人だけは自動にしない')
  eq(resolveNow(G({ nowUnits: [{ unit: 'm7-seifu', n: 300, users: 9, n7: 300, users7: 9 }] }), 6, 'math').src, 'std', '中学の単元は使わない')
  eq(resolveNow(G({ nowManual: { math: { unit: 'm5-speed' } } }), 6, 'math').src, 'std', '学年外は手で選んでも使わない')
  eq(resolveNow(G(), 6, 'social'), null, '社会は標準なし')
})

t('2 記録が少ない子：🅱＝いまの単元・🅰＝その1つ前・💡わけに「いま授業で」', () => {
  const r = reco(kid(), G({ nowManual: { math: { unit: 'm6-circle' } } }))
  eq(r.b.id, 'm6-circle', '🅱'); eq(r.a.id, 'm6-ratio', '🅰'); eq(r.now.src, 'manual', 'now')
  ok(r.b.why.indexOf('いま 授業で やっている') >= 0, r.b.why); ok(r.a.why.indexOf('いま 授業で やっている「円の面積」') >= 0, r.a.why)
  ok(r.mark.indexOf('📍') === 0, r.mark); noNg(r)
})

t('3 記録が少ない子・社会を先生が選んだ（算数はおまかせ）→ 社会のいまの単元から', () => {
  const r = reco(kid(), G({ nowManual: { social: { unit: 's6-hist-u8' } } }))
  eq(r.subj, 'social', '教科'); eq(r.b.id, 's6-hist-u8', '🅱'); eq(r.a.id, 's6-hist-u7', '🅰'); noNg(r)
})

t('4 いまの単元がよくできている子：🅱＝その次・🅰＝まちがいが多いほう', () => {
  const d = kid({ subjects: [{ unit: 'm6-circle', total: 30, rate: 95 }, { unit: 'm6-ratio', total: 20, rate: 60 }], recentUnits: [{ unit: 'm6-circle', n: 20, c: 19, firstAt: iso(5), lastAt: iso(1) }, { unit: 'm6-ratio', n: 10, c: 5, firstAt: iso(9), lastAt: iso(8) }] })
  const r = reco(d, G({ nowManual: { math: { unit: 'm6-circle' } } }))
  eq(r.b.id, 'm6-proportion', '🅱 つぎ'); eq(r.a.id, 'm6-ratio', '🅰 まちがいが多い比'); ok(r.b.why.indexOf('よく できている') >= 0, r.b.why); noNg(r)
})

t('5 いまの単元で つまずき中：🅰＝いまの単元・🅱＝その次', () => {
  const d = kid({ subjects: [{ unit: 'm6-circle', total: 12, rate: 50 }], recentUnits: [{ unit: 'm6-circle', n: 12, c: 6, firstAt: iso(5), lastAt: iso(1) }] })
  const r = reco(d, G({ nowManual: { math: { unit: 'm6-circle' } } }))
  eq(r.a.id, 'm6-circle', '🅰'); eq(r.b.id, 'm6-proportion', '🅱'); ok(r.a.why.indexOf('かためよう') >= 0, r.a.why); noNg(r)
})

t('6 同じ単元が続かない：先週（自動）の🅰と同じなら、もう1つの候補へ', () => {
  const g = G({ nowManual: { math: { unit: 'm6-circle' } } })
  const d = kid({ karteReco: { weekKey: '2020-W01', source: 'auto', reco: { a: { id: 'm6-ratio' } }, updatedAt: iso(7) } })
  const r = reco(d, g)
  ok(r.a.id !== 'm6-ratio', '🅰が先週と同じ: ' + r.a.id); ok(r.a.id !== r.b.id, '🅰と🅱が同じ'); noNg(r)
})

t('7 学年外・中学の単元は出さない（記録が5年・中1ばかりの子）', () => {
  const d = kid({ subjects: [{ unit: 'm5-speed', total: 100, rate: 90 }, { unit: 'm7-seifu', total: 40, rate: 70 }], recentUnits: [{ unit: 'm5-speed', n: 100, c: 90, firstAt: iso(10), lastAt: iso(2) }, { unit: 'm7-seifu', n: 40, c: 28, firstAt: iso(3), lastAt: iso(1) }] })
  for (const g of [G(), G({ nowUnits: [{ unit: 'j6-classic', n: 140, users: 4, n7: 140, users7: 4 }] })]) {
    const r = reco(d, g)
    ok(win.michiResolveNow && r, 'できる')
    for (const x of [r.a, r.b]) if (x) { const sg = /小6/.test(x.entry); ok(sg, '学年外: ' + x.entry) }
  }
})

t('8 記録が多い教科（国語）でクラスがまとめて取り組んでいる単元 → それを中心に', () => {
  const d = kid({ subjects: [{ unit: 'j6-bunpo', total: 68, rate: 74 }], recentUnits: [{ unit: 'j6-bunpo', n: 68, c: 50, firstAt: iso(6), lastAt: iso(6) }] })
  const r = reco(d, G({ nowUnits: [{ unit: 'j6-classic', n: 184, users: 4, n7: 142, users7: 4 }] }))
  eq(r.subj, 'japanese', '教科'); eq(r.now.id, 'j6-classic', 'いま'); eq(r.now.src, 'auto', '自動'); eq(r.b.id, 'j6-classic', '🅱'); eq(r.a.id, 'j6-bunpo', '🅰'); noNg(r)
})

t('9 先生の差しかえ・本人の「来週やってみたいこと」・どう思う？ は今まで通り先', () => {
  const g = G({ nowManual: { math: { unit: 'm6-circle' } } })
  const o = reco(kid({ karteReco: { source: 'teacher', reco: { anchor: 'm6-frac-div' }, updatedAt: iso(1) } }), g)
  eq(o.a.id, 'm6-frac-div', '差しかえ'); ok(o.override, 'override'); eq(o.now, null, 'nowは使わない')
  const p = reco(kid({ nextTry: { unit: 's6-politics', text: 'やってみる', weekKey: '2020-W01' } }), g)
  eq(p.pick, 's6-politics', '本人'); eq(p.subj, 'social', '本人の教科')
  const f = reco(kid({ subjects: [{ unit: 'm6-ratio', total: 30, rate: 90 }], recentUnits: [{ unit: 'm6-ratio', n: 30, c: 27, firstAt: iso(5), lastAt: iso(2) }], recoFeedback: { unit: 'm6-ratio', subj: 'math', choice: 'easy', createdAt: iso(3) } }), g)
  ok(f.note.indexOf('かんたんすぎ') >= 0, f.note)
})

t('10 6年2組の今週（10/26）のような材料：記録0の子11人分が同じでも いまの単元と その前', () => {
  const g = G({ nowUnits: [{ unit: 'm6-ratio', n: 31, users: 4, n7: 26, users7: 3 }, { unit: 'm6-circle', n: 16, users: 2, n7: 16, users7: 2 }] })
  const r = reco(kid(), g)
  eq(r.now.id, 'm6-ratio', 'クラスの記録から 比'); eq(r.b.id, 'm6-ratio', '🅱'); eq(r.a.id, 'm6-frac-dec', '🅰 1つ前（アプリの並び）'); noNg(r)
})

t('11 自動の推定：攻略モードで「まだ」の単元は使わない・人数が同じなら先の単元／先に進む単元が無ければ いまの授業の単元へ', () => {
  const nu = [{ unit: 'j6-classic', n: 184, users: 4, n7: 142, users7: 4 }, { unit: 'j6-bunpo', n: 290, users: 5, n7: 124, users7: 4 }, { unit: 'j6-kanji', n: 300, users: 4, n7: 200, users7: 4 }]
  eq(resolveNow(G({ nowUnits: nu, unitProgress: { units: { 'j6-classic': false } } }), 6, 'japanese').id, 'j6-bunpo', 'まだ の古典はのぞく・同じ人数なら先の文法')
  eq(resolveNow(G({ nowUnits: nu }), 6, 'japanese').id, 'j6-classic', '設定が無ければ古典')
  const r = reco(kid({ nextTry: { unit: 's6-politics', text: 'やってみる', weekKey: '2020-W01' }, subjects: [{ unit: 's6-politics', total: 360, rate: 99 }], recentUnits: [{ unit: 's6-politics', n: 360, c: 359, firstAt: iso(10), lastAt: iso(1) }] }), G({ nowManual: { social: { unit: 's6-hist-u7' } }, unitProgress: { units: { 's6-world': false } } }))
  eq(r.a.id, 's6-politics', '本人の単元'); eq(r.b.id, 's6-hist-u7', '🅱は授業の単元（はじめにもどらない）')
})

console.log(`\n${pass}/${pass + fail} passed`)
if (fail) process.exit(1)
