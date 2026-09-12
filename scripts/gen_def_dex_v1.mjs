// __DEF_DEX_V1__ src/def_dex.ts を 本番の 図鑑から つくり直す。手で 書かない。
//   ぼうえいせんの ものさし（window.defNorm）は その子の 進みぐあいを 1つも 見ていない。
//   レベル50・星と つかれは なし・上限つき。つまり モンスターの番号だけで つよさが きまる。
//   だから「番号 → つよさ」の 表に できる。サーバは 図鑑を 持てないので この表を つかう。
//   もとは public/index.html（図鑑）と public/defstage_monsters.js（げんていキャラ）と
//   src/index.tsx（ものさし・番号の つけかえ）。この4つから 毎回 作り直して 突き合わせる。
import fs from 'node:fs'

const NL = String.fromCharCode(10)
const pub = fs.readFileSync('public/index.html', 'utf8')
const dm = fs.readFileSync('public/defstage_monsters.js', 'utf8')
const idx = fs.readFileSync('src/index.tsx', 'utf8')

const MON = []
const win = { MONSTERS: MON, addEventListener() {}, location: { href: '' }, localStorage: { getItem: () => null, setItem() {} } }
const doc = {
  getElementById: () => null, addEventListener() {}, querySelector: () => null, querySelectorAll: () => [],
  createElement: () => ({ style: {}, appendChild() {}, setAttribute() {} }), body: { appendChild() {} }, head: { appendChild() {} }
}
const blocks = [...pub.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/gi)].map(m => m[1]).filter(b => b.indexOf('MONSTERS.push') >= 0)
let skipped = 0
for (const b of blocks) {
  try {
    (new Function('MONSTERS', 'window', 'document', 'console', 'alert', 'setTimeout', 'setInterval', 'fetch', b))(
      MON, win, doc, { log() {}, warn() {}, error() {} }, () => {}, () => 0, () => 0, () => Promise.resolve()
    )
  } catch (e) { skipped++ }
}
try {
  (new Function('window', 'MON', dm.replace(/window\.MONSTERS/g, 'MON').replace(/MONSTERS/g, 'MON')))({}, MON)
} catch (e) { skipped++ }

const a = idx.indexOf('window.defNorm=function(b){')
const b2 = idx.indexOf('return s;};', a) + 11
if (a < 0 || b2 <= a) { console.log('NG: ものさしが 見つからない'); process.exit(1) }
const W = {}
;(new Function('window', idx.slice(a, b2)))(W)
if (typeof W.defNorm !== 'function') { console.log('NG: ものさしが 動かない'); process.exit(1) }

const byId = {}
const shadow = []
for (const m of MON) {
  if (!m || m.id == null) continue
  if (byId[m.id] == null) byId[m.id] = m
  else shadow.push(m.id + String.fromCharCode(58) + m.name)
}

// __DEF_DEX_ALIAS_V1__ つなぎが 配信のときに 番号を つけかえている 子たち。
//   もとの ファイルでは 先に いる 別の子に 番号を とられていて、そのままでは 見えない。
//   本番と 同じ番号で 表に 入れ直す。つなぎに その つけかえが 本当に あるかも 見る。
const ALIAS = [[1511, 'ソンケイ'], [1512, 'ソンケーン'], [1513, 'ソンケーア'], [1514, 'ネンリキ'], [1515, 'まるやまード']]
let aliased = 0
for (const pair of ALIAS) {
  const nid = pair[0]
  const nm = pair[1]
  const hit = MON.filter(m => m && m.name === nm)
  if (hit.length !== 1) { console.log('NG: ' + nm + ' が ' + hit.length + ' 体（1体でないので中止）'); process.exit(1) }
  if (idx.indexOf(' ' + nid + ';') < 0 && idx.indexOf('id: ' + nid + ',') < 0) { console.log('NG: つなぎに ' + nid + ' への つけかえが ない'); process.exit(1) }
  if (byId[nid] != null) { console.log('NG: ' + nid + ' は すでに ふさがっている'); process.exit(1) }
  const cp = {}
  for (const k in hit[0]) cp[k] = hit[0][k]
  cp.id = nid
  byId[nid] = cp
  aliased++
}
console.log('つけかえ ' + aliased + ' 体 / かさなり ' + shadow.length + ' 件 ' + shadow.join(' '))
if (aliased !== 5) { console.log('NG: つけかえの 数が ちがう'); process.exit(1) }
if (shadow.length !== 7) { console.log('NG: かさなりの数が かわった（つけかえの 表を 見直すこと）'); process.exit(1) }

const keys = Object.keys(byId).map(Number).sort((x, y) => x - y)
console.log('図鑑 ' + keys.length + ' 体 / 読みとばした かたまり ' + skipped)
if (keys.length < 400) { console.log('NG: 図鑑が 少なすぎる'); process.exit(1) }

const lines = []
let dropped = 0
for (const id of keys) {
  const base = byId[id]
  const s = W.defNorm(base)
  const el = Array.isArray(base.elementType) ? base.elementType[0] : (base.elementType || 'normal')
  const sk = (Array.isArray(base.skills) ? base.skills : []).map(x => {
    const o = { n: String(x.name || ''), t: String(x.type || 'normal'), p: Number(x.pow || 0), a: (x.acc == null ? 0.95 : Number(x.acc)) }
    if (x.element) o.e = String(x.element)
    return o
  })
  const row = {
    n: String(base.name || ''), s: String(base.sprite || ''),
    hp: Number(s.hp), a: Number(s.atk), d: Number(s.def), p: Number(s.spd),
    b: String(base.buff || 'lucky'), e: String(el), k: sk
  }
  let ok = Number.isFinite(row.hp) && row.hp > 0 && Number.isFinite(row.a) && Number.isFinite(row.d) && Number.isFinite(row.p) && row.p > 0 && sk.length > 0
  if (ok) {
    let pow = false
    for (const x of sk) { if (Number.isFinite(x.p) && x.p > 0 && Number.isFinite(x.a) && x.a > 0) pow = true }
    ok = pow
  }
  if (!ok) { dropped++; continue }
  lines.push(JSON.stringify(String(id)) + ':' + JSON.stringify(row))
}
console.log('つかえる ' + lines.length + ' 体 / 出せない ' + dropped + ' 体')

const json = '{' + lines.join(',') + '}'
let h = 2166136261 >>> 0
for (let i = 0; i < json.length; i++) { h ^= json.charCodeAt(i); h = Math.imul(h, 16777619) }
const sig = (h >>> 0).toString(16)

const head = [
  '// __DEF_DEX_V1__ 自動生成ファイル（scripts/gen_def_dex_v1.mjs）。手で編集しないこと。',
  '// ぼうえいせんの ものさしは モンスターの番号だけで きまる（レベル50・星と つかれ なし・上限つき）。',
  '// だから この表で、アプリを 開いていない子の 手持ちの先頭も サーバだけで 出せる。',
  '// n=なまえ s=すがた hp a=こうげき d=まもり p=はやさ b=タイプ e=ぞくせい k=わざ',
  '// @ts-nocheck',
  '/* eslint-disable */',
  '',
  'export const DEF_DEX_COUNT = ' + lines.length,
  "export const DEF_DEX_SIG = '" + sig + "'",
  '',
  'const DEF_DEX = {'
].join(NL)

const tail = [
  '}',
  '',
  '// 番号から ぼうえいせん用の 1体を かえす。表に 無い番号は null。',
  'export function defDexEntry(id) {',
  '  const k = Math.floor(Number(id))',
  '  if (!Number.isFinite(k)) return null',
  '  const m = DEF_DEX[String(k)]',
  '  if (!m) return null',
  '  const sk = []',
  '  for (const x of m.k) {',
  '    const o = { name: x.n, type: x.t, pow: x.p, acc: x.a }',
  '    if (x.e) o.element = x.e',
  '    sk.push(o)',
  '  }',
  '  return {',
  '    id: k, name: m.n, sprite: m.s, level: 50, dn: 1,',
  '    hp: m.hp, atk: m.a, def: m.d, spd: m.p,',
  '    buff: m.b, elementType: m.e, skillPow: 10, skills: sk',
  '  }',
  '}',
  ''
].join(NL)

const out = head + NL + lines.join(',' + NL) + NL + tail
fs.writeFileSync('src/def_dex.ts', out)
console.log('DEX SIG ' + sig + ' / ' + out.length + ' 文字')
