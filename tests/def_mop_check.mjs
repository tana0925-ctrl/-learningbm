// __DEFMOP_CHECK_V1__ 防衛戦の「掃討」まわりのオフライン検証。
//   node tests/def_mop_check.mjs html   <before.html> <after.html>
//       …配信される HTML 2 つから戦闘エンジンを抜き出して比べる。
//         (1) mopTicks を渡さないとき 40 シードぶん 出力がバイト単位で同一
//             ＝ ためしうち・友達バトルは 1 ビットも変わらない
//         (2) after に mopTicks=120 を渡すと 12 シードすべてで reason==='base'
//   node tests/def_mop_check.mjs engine <src/def_engine.ts>
//       …サーバ側エンジンに mopTicks=120 を渡すと reason==='base' になること。
// 落ちたら exit 1。
import fs from 'fs';

const NAMES = ['autoBattleRT', '_abRng', '_abFighter', '_abAdv', '_abPickSkill', '_abDmg',
  '_pbRun', '_pbBehavior', '_pbIsTree', '_pbCond', 'getTypeMultiplier', 'getElementTypeMultiplier'];

function scanBlock(H, start) {
  let i = H.indexOf('{', start); if (i < 0) throw new Error('no {');
  let d = 0, j = i, inS = null, inC = null; const n = H.length;
  while (j < n) {
    const c = H[j], p = j > 0 ? H[j - 1] : '';
    if (inC) { if (inC === '//' && c === '\n') inC = null; else if (inC === '/*' && c === '/' && p === '*') inC = null; j++; continue; }
    if (inS) { if (c === '\\') { j += 2; continue; } if (c === inS) inS = null; j++; continue; }
    if (c === '/' && H[j + 1] === '/') { inC = '//'; j++; continue; }
    if (c === '/' && H[j + 1] === '*') { inC = '/*'; j += 2; continue; }
    if (c === '"' || c === "'" || c === '`') { inS = c; j++; continue; }
    if (c === '{') d++; else if (c === '}') { d--; if (d === 0) return H.slice(start, j + 1); }
    j++;
  }
  throw new Error('ran off end');
}

function compile(body) {
  const src = "function getMonster(id){ if(typeof id==='number'&&isFinite(id)) throw new Error('DB'); return null }\n"
    + "function getStats(){ throw new Error('GS') }\n" + body + "\nmodule.exports={autoBattleRT};";
  const m = { exports: {} };
  new Function('module', 'exports', src)(m, m.exports);
  return m.exports.autoBattleRT;
}

function fromHtml(html) {
  const tc = [...html.matchAll(/const\s+TYPE_CHART\s*=/g)];
  if (tc.length !== 1) throw new Error('TYPE_CHART x' + tc.length);
  let body = scanBlock(html, tc[0].index) + ';\n';
  for (const n of NAMES) {
    const m = [...html.matchAll(new RegExp('function\\s+' + n + '\\s*\\(', 'g'))];
    if (m.length !== 1) throw new Error(n + ' x' + m.length);
    body += scanBlock(html, m[0].index) + '\n';
  }
  return compile(body);
}

function fromEngineTs(ts) {
  const s = ts.replace(/^export /gm, '') + '\nmodule.exports={defAutoBattleRT};';
  const m = { exports: {} };
  new Function('module', 'exports', s)(m, m.exports);
  return m.exports.defAutoBattleRT;
}

function roster(seed, nA, nB) {
  let x = (seed >>> 0) || 1;
  const r = () => { x ^= x << 13; x >>>= 0; x ^= x >> 17; x ^= x << 5; x >>>= 0; return x / 4294967296 };
  const els = ['normal', 'fire', 'water', 'grass', 'electric', 'flying', 'rock', 'psychic', 'ice', 'bug', 'steel', 'dragon', 'dark', 'ground', 'fighting', 'ghost', 'poison', 'fairy'];
  const buffs = ['attack', 'guard', 'speed', 'lucky'], strats = ['balance', 'attack', 'guard'];
  const mk = (i, side) => {
    const lvl = 1 + Math.floor(r() * 80), nsk = 1 + Math.floor(r() * 3), skills = [];
    for (let k = 0; k < nsk; k++) skills.push({ name: 's' + k, type: 'attack', pow: 10 + Math.floor(r() * 40), acc: 0.7 + r() * 0.3, desc: '', effect: null, element: els[Math.floor(r() * els.length)], stunMs: 0, target: 'enemy' });
    return { level: lvl, strategy: strats[Math.floor(r() * 3)], lane: null, role: 'mid', raw: { name: side + i, sprite: '', hp: 100 + Math.floor(r() * 900), atk: 10 + Math.floor(r() * 120), def: 5 + Math.floor(r() * 90), spd: 5 + Math.floor(r() * 60), buff: buffs[Math.floor(r() * 4)], skillPow: 12, elementType: els[Math.floor(r() * els.length)], skills } };
  };
  const A = [], B = [], programsA = [];
  for (let i = 0; i < nA; i++) { A.push(mk(i, 'A')); programsA.push([{ c: 'always', a: 'attackBase' }]) }
  for (let j = 0; j < nB; j++) B.push(mk(j, 'B'));
  return { A, B, programsA, programB: [{ c: 'always', a: 'attackBase' }] };
}

const opts = (s, r, mop) => {
  const o = { bases: true, lanes: true, laneCount: 3, seed: s, program: true, programsA: r.programsA, programB: r.programB, forts: false, tactics: true, contact: true, foeLaneMix: true };
  if (mop) o.mopTicks = mop;
  return o;
};
const cp = (v) => JSON.parse(JSON.stringify(v));

function reasonTally(fn, mop, n) {
  const t = {};
  for (let s = 1; s <= n; s++) {
    const r = roster(s, 22, 8);
    const rep = fn(cp(r.A), cp(r.B), opts(s, r, mop));
    t[rep.reason] = (t[rep.reason] || 0) + 1;
  }
  return t;
}

const mode = process.argv[2];
let ng = false;

if (mode === 'html') {
  const before = fromHtml(fs.readFileSync(process.argv[3], 'utf8'));
  const after = fromHtml(fs.readFileSync(process.argv[4], 'utf8'));
  let same = true;
  for (let s = 1; s <= 40; s++) {
    const r = roster(s, 22, 8);
    const a = before(cp(r.A), cp(r.B), opts(s, r));
    const b = after(cp(r.A), cp(r.B), opts(s, r));
    if (JSON.stringify(a) !== JSON.stringify(b)) { same = false; console.log('DIFF at seed ' + s); break; }
  }
  console.log('mopTicks なしで 40 シード 同一:', same);
  if (!same) ng = true;
  const t = reasonTally(after, 120, 12);
  console.log('mopTicks=120 の reason:', JSON.stringify(t));
  if (t.base !== 12) ng = true;
} else if (mode === 'engine') {
  const fn = fromEngineTs(fs.readFileSync(process.argv[3], 'utf8'));
  const t0 = reasonTally(fn, 0, 12);
  const t1 = reasonTally(fn, 120, 12);
  console.log('mopTicks なし  の reason:', JSON.stringify(t0));
  console.log('mopTicks=120 の reason:', JSON.stringify(t1));
  if (t1.base !== 12) ng = true;
} else {
  console.log('usage: def_mop_check.mjs html <before> <after> | engine <def_engine.ts>');
  process.exit(2);
}

if (ng) { console.log('NG'); process.exit(1) }
console.log('検証 OK');
