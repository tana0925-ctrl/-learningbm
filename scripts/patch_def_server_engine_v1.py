#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __DEF_SERVER_ENGINE_V1__
# 本番（デプロイ済み）の HTML から戦闘エンジン（TYPE_CHART + 12関数）を抜き出し、
# src/def_engine.ts として保存する。src/index.tsx には import 1行と GET 1本だけ足す。
#   - .replace() のチェーンは 72 件のまま（増やさない・減らさない）
#   - public/index.html は一切さわらない
#   - DB / DDL には一切さわらない
# fail-closed: 事前チェックに1つでも失敗したらファイルに一切触れずに exit 1
import sys, io, os, re, json, hashlib, urllib.request

SRC  = 'src/index.tsx'
PUB  = 'public/index.html'
OUT  = 'src/def_engine.ts'
SENT = '__DEF_SERVER_ENGINE_V1__'   # 冪等性の番兵（検証条件とは別物）
PROD = 'https://learning-bm.pages.dev/'

BS = "app.get('/', async (c) => {"
BE = "app.get('/logout'"
EXPECT_CHAIN = 72

NAMES = ['autoBattleRT', '_abRng', '_abFighter', '_abAdv', '_abPickSkill', '_abDmg',
         '_pbRun', '_pbBehavior', '_pbIsTree', '_pbCond',
         'getTypeMultiplier', 'getElementTypeMultiplier']

# 本番の replace チェーンで書き換わることが実測で分かっている関数。
# ここ以外が repo と本番でズレていたら中止する（チェーンが別の関数に触り始めた合図）。
EXPECT_DIFF = set(['_abFighter', 'autoBattleRT'])

# 本番側 _abFighter に必ず入っているはずの印（__AB_RAW_ELEM_SKILLS_V1__ が効いている証拠）
RAW_MARK = "elementType:(R.elementType!=null?R.elementType:'normal')"

GUARD = ['__DEF_SNAP_SPDSKILLS_V1__', '__DEF_RESOLVE_VERIFY_V1__', '__AB_RAW_ELEM_SKILLS_V1__',
         'defAutoAdvanceV1', 'defense_standing', 'defense_carry_lock',
         'const DEFENSE_BASE_HP = 380']

IMP_ANCHOR = "import { registerMi } from './mi'"
IMP_NEW = ("import { registerMi } from './mi'\n"
           "import { defAutoBattleRT, defTestRoster, DEF_ENGINE_SIG, DEF_ENGINE_BYTES } from './def_engine'")

ROUTE_ANCHOR = "app.post('/api/defense/resolve', async (c) => {"

ROUTE_NEW = """// __DEF_SERVER_ENGINE_V1__ サーバ側エンジンの突き合わせ用（GET・計算のみ・DB には一切さわらない）
app.get('/api/defense/_engine_check', (c) => {
  const seed = (Number(c.req.query('seed') || 1) >>> 0) || 1
  const nA = Math.max(1, Math.min(40, Number(c.req.query('a') || 22) || 22))
  const nB = Math.max(1, Math.min(40, Number(c.req.query('b') || 8) || 8))
  const reps = Math.max(1, Math.min(24, Number(c.req.query('reps') || 1) || 1))
  const withRoster = c.req.query('roster') !== '0'
  const roster: any = defTestRoster(seed, nA, nB)
  const mkOpts = () => ({
    bases: true, lanes: true, laneCount: 3, seed: seed, program: true,
    programsA: roster.programsA, programB: roster.programB,
    forts: false, tactics: true, contact: true
  })
  let rep: any = null
  for (let i = 0; i < reps; i++) {
    rep = defAutoBattleRT(JSON.parse(JSON.stringify(roster.A)), JSON.parse(JSON.stringify(roster.B)), mkOpts())
  }
  return c.json({
    ok: true, sig: DEF_ENGINE_SIG, bytes: DEF_ENGINE_BYTES,
    seed: seed, a: nA, b: nB, reps: reps,
    roster: withRoster ? roster : null, rep: rep
  })
})

"""


def die(msg):
    print('ABORT: ' + msg)
    sys.exit(1)


def scan_block(H, start, where):
    """start から最初の { を探し、対応する } までを（} を含めて）返す。文字列 / コメントは飛ばす。"""
    i = H.find('{', start)
    if i < 0:
        die('%s: opening brace not found' % where)
    d = 0
    j = i
    inS = None
    inC = None
    n = len(H)
    while j < n:
        c = H[j]
        p = H[j - 1] if j > 0 else ''
        if inC:
            if inC == '//' and c == '\n':
                inC = None
            elif inC == '/*' and c == '/' and p == '*':
                inC = None
            j += 1
            continue
        if inS:
            if c == '\\':
                j += 2
                continue
            if c == inS:
                inS = None
            j += 1
            continue
        if c == '/' and j + 1 < n and H[j + 1] == '/':
            inC = '//'
            j += 1
            continue
        if c == '/' and j + 1 < n and H[j + 1] == '*':
            inC = '/*'
            j += 2
            continue
        if c == '"' or c == "'" or c == '\u0060':
            inS = c
            j += 1
            continue
        if c == '{':
            d += 1
        elif c == '}':
            d -= 1
            if d == 0:
                return H[start:j + 1]
        j += 1
    die('%s: brace scan ran off the end' % where)


def grab_fn(H, name, where):
    m = list(re.finditer(r'function\s+' + re.escape(name) + r'\s*\(', H))
    if len(m) != 1:
        die('%s: "function %s(" は %d 件（1件でないと危険）' % (where, name, len(m)))
    src = scan_block(H, m[0].start(), '%s:%s' % (where, name))
    if not src.startswith('function'):
        die('%s:%s 先頭が function ではない' % (where, name))
    if not src.endswith('}'):
        die('%s:%s 末尾が } ではない' % (where, name))
    return src


def grab_tc(H, where):
    m = list(re.finditer(r'const\s+TYPE_CHART\s*=', H))
    if len(m) != 1:
        die('%s: TYPE_CHART の定義が %d 件（1件でないと危険）' % (where, len(m)))
    return scan_block(H, m[0].start(), '%s:TYPE_CHART' % where)


# ---------------- 読み込み ----------------
if not os.path.exists(SRC):
    die('%s が無い' % SRC)
if not os.path.exists(PUB):
    die('%s が無い' % PUB)

src = io.open(SRC, encoding='utf-8').read()
pub = io.open(PUB, encoding='utf-8').read()

if SENT in src and os.path.exists(OUT):
    print('ALREADY APPLIED (sentinel present) - no file touched')
    sys.exit(0)
if SENT in src or os.path.exists(OUT):
    die('中途半端に適用されている（番兵と %s が食い違う）' % OUT)

# ---------------- 事前チェック（1つでも落ちたら書かない） ----------------
if src.count(BS) != 1:
    die("app.get('/', async (c) => {  が %d 件（1件でないと危険）" % src.count(BS))
if src.count(BE) != 1:
    die("app.get('/logout' が %d 件" % src.count(BE))
st = src.find(BS)
en = src.find(BE)
if not (0 <= st < en):
    die('チェーン範囲が取れない')
chain = src[st:en].count('.replace(')
print('chain before = %d' % chain)
if chain != EXPECT_CHAIN:
    die('chain %d != %d' % (chain, EXPECT_CHAIN))

if src.count(IMP_ANCHOR) != 1:
    die('import アンカーが %d 件' % src.count(IMP_ANCHOR))
if src.count(ROUTE_ANCHOR) != 1:
    die('route アンカーが %d 件' % src.count(ROUTE_ANCHOR))
if src.count("'/api/defense/_engine_check'") != 0:
    die('_engine_check がすでにある')
for g in GUARD:
    if g not in src:
        die('guard missing before: ' + g)
if src.count('ensureDefenseTables') != 1:
    die('ensureDefenseTables の出現が %d 件（呼び出しは0件のままであること）' % src.count('ensureDefenseTables'))

# ---------------- 本番 HTML を GET（読み取りのみ） ----------------
print('GET %s' % PROD)
req = urllib.request.Request(PROD, headers={'User-Agent': 'def-server-engine-v1'})
resp = urllib.request.urlopen(req, timeout=120)
if resp.getcode() != 200:
    die('本番 GET が %d' % resp.getcode())
prod = resp.read().decode('utf-8')
print('prod html = %d chars' % len(prod))
if len(prod) < 3000000:
    die('本番 HTML が短すぎる（%d 文字）' % len(prod))

# ---------------- 抜き出し ----------------
tc_prod = grab_tc(prod, 'prod')
tc_pub = grab_tc(pub, 'repo')
if tc_prod != tc_pub:
    die('TYPE_CHART が repo と本番でズレている')

fn_prod = {}
fn_pub = {}
diff = set()
for n in NAMES:
    fn_prod[n] = grab_fn(prod, n, 'prod')
    fn_pub[n] = grab_fn(pub, n, 'repo')
    if fn_prod[n] != fn_pub[n]:
        diff.add(n)

print('repo と本番で差がある関数: %s' % sorted(diff))
if diff != EXPECT_DIFF:
    die('差のある関数が想定と違う（想定 %s / 実際 %s）。チェーンが別の関数に触り始めた可能性'
        % (sorted(EXPECT_DIFF), sorted(diff)))

if RAW_MARK not in fn_prod['_abFighter']:
    die('本番の _abFighter に __AB_RAW_ELEM_SKILLS_V1__ の印が無い')
if 'getMonster(' not in fn_prod['_abFighter']:
    die('_abFighter の形が想定と違う')

engine_body = tc_prod + ';\n' + '\n'.join([fn_prod[n] for n in NAMES])
engine_bytes = len(engine_body.encode('utf-8'))
sig = hashlib.sha256(engine_body.encode('utf-8')).hexdigest()
print('engine = %d bytes, sha256 = %s' % (engine_bytes, sig))
if not (20000 <= engine_bytes <= 60000):
    die('engine のサイズが想定外（%d bytes）' % engine_bytes)

# ---------------- src/def_engine.ts を書く ----------------
ts = []
ts.append('// ' + SENT + ' 自動生成ファイル（scripts/patch_def_server_engine_v1.py）。手で編集しないこと。')
ts.append('// 本番 HTML（replace チェーン適用後）から抜き出した戦闘エンジンそのもの。')
ts.append('// DOM / player / モンスター図鑑には依存しない。raw 経路だけを使う。')
ts.append('// @ts-nocheck')
ts.append('/* eslint-disable */')
ts.append('')
ts.append("export const DEF_ENGINE_SIG = '" + sig + "'")
ts.append('export const DEF_ENGINE_BYTES = ' + str(engine_bytes))
ts.append('')
ts.append('const __DEF_ENGINE = (function () {')
ts.append('  // 図鑑はサーバに無い。raw 経路では結果が捨てられるだけなので null を返す。')
ts.append('  // 万一 {id, level} 経路に入ったら、黙って弱いステータスで戦わずに落とす。')
ts.append('  function getMonster(__id) {')
ts.append("    if (typeof __id === 'number' && isFinite(__id)) throw new Error('DEF_ENGINE_MONSTER_DB_REQUIRED')")
ts.append('    return null')
ts.append('  }')
ts.append('  function getStats() {')
ts.append("    throw new Error('DEF_ENGINE_GETSTATS_REQUIRED')")
ts.append('  }')
ts.append('')
ts.append(engine_body)
ts.append('')
ts.append('  return { autoBattleRT: autoBattleRT }')
ts.append('})()')
ts.append('')
ts.append('export function defAutoBattleRT(specsA, specsB, opts) {')
ts.append('  return __DEF_ENGINE.autoBattleRT(specsA, specsB, opts)')
ts.append('}')
ts.append('')
ts.append('// 突き合わせ用の決定論的なテスト編成。作った編成そのものを返して、')
ts.append('// ブラウザ側の本物のエンジンに同じものを食わせて比べる。')
ts.append('export function defTestRoster(seed, nA, nB) {')
ts.append('  var x = (seed >>> 0) || 1')
ts.append('  function r() { x ^= x << 13; x >>>= 0; x ^= x >> 17; x ^= x << 5; x >>>= 0; return x / 4294967296 }')
ts.append("  var els = ['normal','fire','water','grass','electric','flying','rock','psychic','ice','bug','steel','dragon','dark','ground','fighting','ghost','poison','fairy']")
ts.append("  var buffs = ['attack','guard','speed','lucky']")
ts.append("  var strats = ['balance','attack','guard']")
ts.append('  function mk(i, side) {')
ts.append('    var lvl = 1 + Math.floor(r() * 80)')
ts.append('    var nsk = 1 + Math.floor(r() * 3)')
ts.append('    var skills = []')
ts.append('    for (var k = 0; k < nsk; k++) {')
ts.append("      skills.push({ name: 's' + k, type: 'attack', pow: 10 + Math.floor(r() * 40), acc: 0.7 + r() * 0.3, desc: '', effect: null, element: els[Math.floor(r() * els.length)], stunMs: 0, target: 'enemy' })")
ts.append('    }')
ts.append('    return {')
ts.append("      level: lvl, strategy: strats[Math.floor(r() * 3)], lane: null, role: 'mid',")
ts.append('      raw: {')
ts.append("        name: side + i, sprite: '', hp: 100 + Math.floor(r() * 900),")
ts.append('        atk: 10 + Math.floor(r() * 120), def: 5 + Math.floor(r() * 90), spd: 5 + Math.floor(r() * 60),')
ts.append('        buff: buffs[Math.floor(r() * 4)], skillPow: 12,')
ts.append('        elementType: els[Math.floor(r() * els.length)], skills: skills')
ts.append('      }')
ts.append('    }')
ts.append('  }')
ts.append('  var A = [], B = [], programsA = []')
ts.append("  for (var i = 0; i < nA; i++) { A.push(mk(i, 'A')); programsA.push([{ c: 'always', a: 'attackBase' }]) }")
ts.append("  for (var j = 0; j < nB; j++) { B.push(mk(j, 'B')) }")
ts.append("  return { A: A, B: B, programsA: programsA, programB: [{ c: 'always', a: 'attackBase' }] }")
ts.append('}')
ts.append('')
out_ts = '\n'.join(ts)

# ---------------- src/index.tsx を書き換える ----------------
out_src = src.replace(IMP_ANCHOR, IMP_NEW, 1)
out_src = out_src.replace(ROUTE_ANCHOR, ROUTE_NEW + ROUTE_ANCHOR, 1)

# ---------------- 適用後チェック（番兵とは別の条件で見る） ----------------
st2 = out_src.find(BS)
en2 = out_src.find(BE)
chain2 = out_src[st2:en2].count('.replace(')
print('chain after  = %d' % chain2)
if chain2 != EXPECT_CHAIN:
    die('chain が変わった: %d != %d' % (chain2, EXPECT_CHAIN))
if out_src.count("'/api/defense/_engine_check'") != 1:
    die('_engine_check が 1 件になっていない')
if out_src.count("from './def_engine'") != 1:
    die('import が 1 件になっていない')
if out_src.count(ROUTE_ANCHOR) != 1:
    die('resolve のアンカーが壊れた')
if out_src.count('ensureDefenseTables') != 1:
    die('ensureDefenseTables が変わった')
for g in GUARD:
    if g not in out_src:
        die('guard missing after: ' + g)
if out_src.count(SENT) != 1:
    die('番兵が 1 件でない')
if out_ts.count('function autoBattleRT(') != 1:
    die('生成した def_engine.ts の autoBattleRT が 1 件でない')
for n in NAMES:
    if out_ts.count('function ' + n + '(') != 1:
        die('生成した def_engine.ts の %s が 1 件でない' % n)
if out_ts.count('const TYPE_CHART =') != 1:
    die('生成した def_engine.ts の TYPE_CHART が 1 件でない')

io.open(OUT, 'w', encoding='utf-8').write(out_ts)
io.open(SRC, 'w', encoding='utf-8').write(out_src)
print('OK: applied (chain stays %d, engine %d bytes)' % (chain2, engine_bytes))
