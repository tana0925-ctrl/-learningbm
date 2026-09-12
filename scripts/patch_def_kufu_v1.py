# -*- coding: utf-8 -*-
# DEF_KUFU_V1（防衛戦・くふう賞）
#   1) サーバの戦闘計算の前に、うごきの めいれいへ 前から順に 番号をふる。
#      出陣のときに _id が 落とされるため、サーバ側で ふりなおす。
#      番号をふっても 勝敗・tick・基地HP・events は かわらない（同じ種で実測ずみ）。
#   2) その戦いで ほんとうに うごいた めいれいの しゅるい数を かぞえる。
#      posA[i].n（そのとき うごいていた めいれいの番号）を あつめるだけ。
#   3) しゅるい数が 同じときは、書いた めいれいが 少ない子（むだの ない子）を 上にする。
#   4) 部門が成り立つ日だけ 台帳に行を作る。しゅるい数が みんな同じ日は 出さない。
#   5) 見た目は public/defense2.js に 足す（くふう の ベスト3 と 自分の きろく）。
# 枚数も 資格も サーバ側の定数だけで決める（1位40／2位30／3位20）。
# 表のつくりかたは ここでは流さない。
# アンカーが一致しなければ 何も書かずに止まる（fail-closed）。
import io
import sys

CHAIN_EXPECT = 82


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def apply_to(path, guard, steps):
    s = io.open(path, encoding='utf-8').read()
    if guard in s:
        print('すでに適用ずみ: %s' % path)
        return s, False
    for label, a, b in steps:
        n = s.count(a)
        if n != 1:
            print('NG: %s のアンカー %s が %d 件（期待 1）' % (path, label, n))
            sys.exit(1)
    for label, a, b in steps:
        s = s.replace(a, b, 1)
    return s, True


RES_PATH = "src/def_resolve.ts"

RES_A_CATS = """  { key: 'mamori', label: 'たえた わりあい' }
]
"""
RES_B_CATS = """  { key: 'mamori', label: 'たえた わりあい' },
  { key: 'kufu',   label: 'くふう' }
]
"""

RES_A_FN = """function defMvpAwards(rep, ents) {
"""
RES_B_FN = """// __DEF_KUFU_V1__ くふう ＝ その戦いで ほんとうに うごいた めいれいの しゅるい数。
//   モンスターの つよさでは なく、書いた めいれいが その場面で はたらいたかを 見る。
//   ブロックを つみ上げるだけでは ふえない（うごかなければ かぞえない）。
//   とどかない ルールは 0かいなので 点に ならない。
//   同じ しゅるい数のときは、書いた めいれいが 少ない子（むだの ない子）を 上にする。
//   value は しゅるい数 * 100 + 書いた かず（下2けた）。0 は きろく なし。
// 出陣のときに _id が 落とされるので、サーバ側で 前から順に ふりなおす。
// もとの めいれいは 1文字も かえない（控えを作って、その控えで 戦わせる）。
function defKufuTag(prog) {
  let seq = 0
  const walk = function (arr) {
    if (!Array.isArray(arr)) return []
    const out = []
    for (const nd of arr) {
      if (!nd || typeof nd !== 'object') { out.push(nd); continue }
      const o = {}
      for (const p in nd) o[p] = nd[p]
      if (Array.isArray(nd.body)) o.body = walk(nd.body)
      if (Array.isArray(nd.els)) o.els = walk(nd.els)
      if ((!nd.t || nd.t === 'a') && nd.a != null) { o._id = seq; seq++ }
      out.push(o)
    }
    return out
  }
  const p = walk(prog)
  return { prog: p, total: seq }
}

function defKufuVals(evs, n, wrote) {
  const seen = [], k = [], val = [], rank = []
  for (let i = 0; i < n; i++) seen.push({})
  for (const e of (evs || [])) {
    if (!e || !Array.isArray(e.posA)) continue
    for (let i = 0; i < n && i < e.posA.length; i++) {
      const p = e.posA[i]
      const id = Math.floor(Number(p && p.n))
      if (Number.isFinite(id) && id >= 0) seen[i][id] = 1
    }
  }
  for (let i = 0; i < n; i++) {
    const kk = Object.keys(seen[i]).length
    const w = Math.max(0, Math.min(99, Math.floor(Number(wrote && wrote[i]) || 0)))
    k.push(kk)
    val.push(kk > 0 ? (kk * 100 + w) : 0)
    rank.push(kk > 0 ? (kk * 1000 + (99 - w)) : 0)
  }
  return { k: k, val: val, rank: rank }
}

function defMvpAwards(rep, ents, kwrote) {
"""

RES_A_FEW = """    const few = (n < DEF_MVP_MIN_ENTRIES)
"""
RES_B_FEW = """    // __DEF_KUFU_V1__ うごいた めいれいの しゅるい数。events の posA から かぞえる。
    const _kf = defKufuVals(evs, n, kwrote)
    vals.kufu = _kf.val
    const few = (n < DEF_MVP_MIN_ENTRIES)
"""

RES_A_LOOP = """      const v = vals[cat.key]
      const places = few ? null : defMvpRank(v)
"""
RES_B_LOOP = """      const v = vals[cat.key]
      // __DEF_KUFU_V1__ くふうは 見せる数と 順位づけの数が ちがう。
      //   しゅるい数が みんな同じ日は 部門ごと 出さない（うその表彰は しない）。
      let places = few ? null : defMvpRank(v)
      if (cat.key === 'kufu') {
        let _kn = 0
        const _ku = []
        for (const _x of _kf.k) { if (_x > 0) _kn++; if (_ku.indexOf(_x) < 0) _ku.push(_x) }
        places = (few || _kn < DEF_MVP_MIN_ENTRIES || _ku.length < 2) ? null : defMvpRank(_kf.rank)
      }
"""

RES_A_PROG = """    const programsA = ents.map(function (e) {
      return (Array.isArray(e.m.prog) && e.m.prog.length) ? e.m.prog : DEF_DEFAULT_PROG
    })
"""
RES_B_PROG = """    // __DEF_KUFU_V1__ 番号をふった控えで戦わせる（勝敗・tick・基地HP は かわらない）。
    const _kfTag = ents.map(function (e) {
      return defKufuTag((Array.isArray(e.m.prog) && e.m.prog.length) ? e.m.prog : DEF_DEFAULT_PROG)
    })
    const _kfWrote = _kfTag.map(function (x) { return x.total })
    const programsA = _kfTag.map(function (x) { return x.prog })
"""

RES_A_CALL = "    try { _mv = defMvpAwards(rep, ents) } catch (_e) { _mv = null }"
RES_B_CALL = "    try { _mv = defMvpAwards(rep, ents, _kfWrote) } catch (_e) { _mv = null }"

RES_STEPS = [
    ("cats", RES_A_CATS, RES_B_CATS),
    ("fn", RES_A_FN, RES_B_FN),
    ("few", RES_A_FEW, RES_B_FEW),
    ("loop", RES_A_LOOP, RES_B_LOOP),
    ("prog", RES_A_PROG, RES_B_PROG),
    ("call", RES_A_CALL, RES_B_CALL),
]

D2_PATH = "public/defense2.js"

D2_A_VAL = """  function def2MvpValText(key, v){
    var n = Number(v) || 0;
"""
D2_B_VAL = """  /* __DEF_KUFU_V1__ くふう：その日 ほんとうに うごいた めいれいの しゅるい数 */
  DEF2_MVP_LABEL.kufu = 'くふう';
  DEF2_MVP_ICON.kufu = '💡';
  function def2MvpValText(key, v){
    var n = Number(v) || 0;
    if (key === 'kufu'){
      var _kk = Math.floor(n / 100), _kw = Math.round(n % 100);
      if (_kk <= 0) return 'きろく なし';
      return _kk + 'しゅるい うごいた' + ((_kw > _kk) ? '（かいた ' + _kw + '）' : '');
    }
"""

D2_A_ORDER = "        var order = ['seme','nebari','mamori'];"
D2_B_ORDER = "        var order = ['seme','nebari','mamori','kufu'];"

D2_STEPS = [
    ("val", D2_A_VAL, D2_B_VAL),
    ("order", D2_A_ORDER, D2_B_ORDER),
]

IDX_PATH = "src/index.tsx"
IDX_STEPS = [
    ("ver", '<script src="/defense2.js?v=15"></script>', '<script src="/defense2.js?v=16"></script>'),
]

# 冪等の番兵は、あとの検証でかぞえる印（__DEF_KUFU_V1__）とは べつの文字列にしてある。
RES_GUARD = 'function defKufuTag('
D2_GUARD = 'DEF2_MVP_ICON.kufu ='
IDX_GUARD = '/defense2.js?v=16'

idx0 = io.open(IDX_PATH, encoding='utf-8').read()
n0 = chain_count(idx0)
print('chain before =', n0)
if n0 != CHAIN_EXPECT:
    print('NG: 流す前のチェーンが %d 件でない' % CHAIN_EXPECT)
    sys.exit(1)

res, res_ch = apply_to(RES_PATH, RES_GUARD, RES_STEPS)
idx, idx_ch = apply_to(IDX_PATH, IDX_GUARD, IDX_STEPS)
d2, d2_ch = apply_to(D2_PATH, D2_GUARD, D2_STEPS)

n1 = chain_count(idx)
print('chain after =', n1)
if n1 != CHAIN_EXPECT:
    print('NG: 流したあとのチェーンが %d 件でない' % CHAIN_EXPECT)
    sys.exit(1)

if res_ch:
    io.open(RES_PATH, 'w', encoding='utf-8').write(res)
if idx_ch:
    io.open(IDX_PATH, 'w', encoding='utf-8').write(idx)
if d2_ch:
    io.open(D2_PATH, 'w', encoding='utf-8').write(d2)
print('適用 OK  res=%s idx=%s d2=%s' % (res_ch, idx_ch, d2_ch))
