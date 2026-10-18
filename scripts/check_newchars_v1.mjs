// NEWCHARS_V1 の確認。児童ページ（/）の「配信されるHTML」（src/index.tsx の .replace() をかけたあと）を
// dist/_worker.js から作り、中のJSを node の vm で動かして、次をたしかめる。
//   ・1701〜1707 が MONSTERS に1回ずつだけある（IDのかぶりがない）
//   ・九九（kuku）の野生テーブルに 1701,1702,1704,1705,1706,1707 が入り、1703 は入っていない
//   ・ミッニ(1702) は Lv18 でミッキ(1703) に進化する
//   ・図鑑の入手方法の自動表示が「算数（2年）「九九バトルフィールド」の野生バトル…」/「進化（…）」になる
//   ・public/mon/list.js に 1701〜1707 があり、public/mon/<id>.png が 192x192 である
// どれか1つでも合わなければ exit 1。
import fs from 'fs';
import vm from 'vm';

const mod = await import(process.cwd() + '/dist/_worker.js');
const env = { ASSETS: { fetch: async (req) => {
  const u = new URL(typeof req === 'string' ? req : req.url);
  const p = (!u.pathname || u.pathname === '/') ? '/index.html' : u.pathname;
  try { return new Response(fs.readFileSync(process.cwd() + '/public' + p), { status: 200, headers: { 'content-type': 'text/html; charset=utf-8' } }); }
  catch (e) { return new Response('', { status: 404 }); }
} } };
const res = await mod.default.fetch(new Request('http://localhost/'), env, { waitUntil() {} });
const html = await res.text();
const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
const scripts = []; let m; while ((m = re.exec(html))) scripts.push(m[1]);
const P = new Proxy(function(){}, { get: (t, k) => k === Symbol.toPrimitive ? (() => '') : (k === 'length' ? 0 : P), apply: () => P, construct: () => P, set: () => true });
const sb = { console: { log(){}, warn(){}, error(){}, info(){} }, setTimeout: () => 0, setInterval: () => 0, clearTimeout(){}, clearInterval(){},
  document: P, navigator: { userAgent: '' }, location: { href: '', search: '', hostname: 'x', pathname: '/' },
  localStorage: { getItem: () => null, setItem(){}, removeItem(){} }, sessionStorage: { getItem: () => null, setItem(){} },
  fetch: () => new Promise(() => {}), requestAnimationFrame: () => 0, addEventListener(){}, removeEventListener(){},
  Audio: P, Image: P, matchMedia: () => ({ matches: false, addListener(){} }), getComputedStyle: () => P, alert(){}, confirm: () => false,
  performance: { now: () => 0 }, screen: {}, innerWidth: 1024, innerHeight: 768, HTMLElement: function(){}, Element: function(){}, Node: function(){},
  MutationObserver: function(){ return { observe(){} }; }, ResizeObserver: function(){ return { observe(){} }; }, IntersectionObserver: function(){ return { observe(){} }; },
  CustomEvent: function(){}, Event: function(){}, URLSearchParams, URL, TextEncoder, TextDecoder,
  btoa: s => Buffer.from(s, 'binary').toString('base64'), atob: s => Buffer.from(s, 'base64').toString('binary') };
sb.window = sb; sb.self = sb; sb.globalThis = sb;
const ctx = vm.createContext(sb);
scripts.forEach(s => { try { vm.runInContext(s, ctx, { timeout: 5000 }); } catch (e) {} });
// getObtainMethod と PVE_AREAS は initGame() の中にあり（ログイン後に動く）、ここでは呼べない。
// そこで配信HTMLから2つの本文をそのまま切り出し、同じ組み合わせで外に置いて動かす（確認用。配信物は変えない）。
function cutBalanced(src, head, open, close) {
  const st = src.indexOf(head);
  if (st < 0 || src.indexOf(head, st + 1) >= 0) return null;
  let i = src.indexOf(open, st + head.length - 1), depth = 0, q = null;
  for (; i < src.length; i++) {
    const c = src[i], n = src[i + 1];
    if (q) { if (c === '\\') { i++; continue; } if (c === q) q = null; continue; }
    if (c === '/' && n === '/') { i = src.indexOf('\n', i); continue; }
    if (c === '/' && n === '*') { i = src.indexOf('*/', i) + 1; continue; }
    if (c === "'" || c === '"' || c === '`') { q = c; continue; }
    if (c === open) depth++;
    else if (c === close) { depth--; if (depth === 0) return src.slice(st, i + 1); }
  }
  return null;
}
const gomSrc = cutBalanced(html, 'function getObtainMethod(m){', '{', '}');
const pveSrc = cutBalanced(html, 'const PVE_AREAS = [', '[', ']');
if (!gomSrc || !pveSrc) { console.log('### 中止: 配信HTMLから getObtainMethod / PVE_AREAS を1件ずつ切り出せない'); process.exit(1); }
vm.runInContext('globalThis.__gom = (function(){ ' + pveSrc + ';\n' + gomSrc + '\n return getObtainMethod; })();', ctx);
const out = JSON.parse(vm.runInContext(`JSON.stringify((function(){
  var ids=[1701,1702,1703,1704,1705,1706,1707], r={};
  r.count = ids.map(function(i){ return MONSTERS.filter(function(x){return Number(x.id)===i;}).length; });
  r.names = ids.map(function(i){ var x=MONSTERS.find(function(y){return Number(y.id)===i;}); return x? x.name : null; });
  r.obtain = ids.map(function(i){ var x=MONSTERS.find(function(y){return Number(y.id)===i;}); return x? __gom(x) : null; });
  r.kuku = WILD_AREA_POOLS.kuku;
  var a=MONSTERS.find(function(y){return Number(y.id)===1702;}); r.evo = a ? [a.nextId, a.evoLevel] : null;
  var all={}; MONSTERS.forEach(function(x){ all[x.id]=(all[x.id]||0)+1; }); r.total = Object.keys(all).length;
  return r; })())`, ctx));
let bad = 0; const ng = (s) => { bad++; console.log('NG: ' + s); };
console.log(JSON.stringify(out, null, 1));
out.count.forEach((c, k) => { if (c !== 1) ng('id ' + (1701 + k) + ' の登録数が ' + c); });
const flat = (d) => (out.kuku && out.kuku[d]) || [];
[[1,1701],[1,1702],[2,1704],[2,1705],[3,1706],[3,1707]].forEach(([d, id]) => { if (flat(d).indexOf(id) < 0) ng('kuku 深さ' + d + ' に ' + id + ' が無い'); });
[1,2,3].forEach(d => { if (flat(d).indexOf(1703) >= 0) ng('kuku に 1703 が入っている'); });
if (!out.evo || out.evo[0] !== 1703 || out.evo[1] !== 18) ng('ミッニの進化が 1703/Lv18 でない: ' + JSON.stringify(out.evo));
[0,1,3,4,5,6].forEach(k => { if (!/九九バトルフィールド/.test(out.obtain[k] || '')) ng((1701 + k) + ' の入手方法: ' + out.obtain[k]); });
if (!/進化（ミッニがLv18で進化）/.test(out.obtain[2] || '')) ng('1703 の入手方法: ' + out.obtain[2]);
const list = fs.readFileSync('public/mon/list.js', 'utf8');
for (let i = 1701; i <= 1707; i++) {
  if (!new RegExp('[\\[,]' + i + '[,\\]]').test(list)) ng('list.js に ' + i + ' が無い');
  const f = 'public/mon/' + i + '.png';
  if (!fs.existsSync(f)) { ng(f + ' が無い'); continue; }
  const b = fs.readFileSync(f);
  const w = b.readUInt32BE(16), h = b.readUInt32BE(20);
  if (w !== 192 || h !== 192) ng(f + ' が ' + w + 'x' + h);
}
if (bad) { console.log('### 中止: ' + bad + ' 件'); process.exit(1); }
console.log('OK: 新キャラ7体の登録・九九の出現・進化・入手方法の表示・絵の受け皿 すべて合格');
