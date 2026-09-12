# -*- coding: utf-8 -*-
# DEF_LOG_FIT_V1 : 1戦ぶんの きろくが 大きすぎると 'null' が のこって、
#   そのクラス全員が リプレイを 見られなくなる。それを ふせぐ。
#   上限を こえたときだけ、きろくの コマを まびいて 入る大きさに する。
#   1コマは それだけで その瞬間の ぜんぶ（HP・いち・きち）を もっているので、
#   まびいても のこった コマだけで 絵が つながる（さしぶんでは ないため）。
#   かちまけ・きちHP・ひょうしょう は ここへ来る前に もう きまっているので さわらない。
#
# 1回流しても 2回流しても 同じ形（番兵 __DEF_LOG_FIT_V1__）。
# 一致しないときは 何も書かずに 失敗で終わる（fail-closed）。

import io
import sys

NL = chr(10)

RES_PATH = 'src/def_resolve.ts'
INDEX_PATH = 'src/index.tsx'

SENTINEL = '__DEF_LOG_FIT_V1__'

OLD_FN = 'export async function defServerResolve(env, st, classId, enemies) {'
OLD_MK = '    const logJson = JSON.stringify(log)'
NEW_MK = '    const logJson = defLogFit(log)'
OLD_CM = '    // 切り詰めると壊れた JSON を保存してしまうので、大きすぎたら諦めて今まで通りに流す'
NEW_CM = '    // 入らないときは コマを まびいて 入る形に する。こわれた JSON は のこさない。'
OLD_IF = '    if (!logJson || logJson.length > 900000) return null'
NEW_IF = '    if (!logJson || logJson.length > DEF_LOG_LIMIT) return null'

OLD_IMP = "import { defServerResolve, defEntryOk } from './def_resolve'"
NEW_IMP = "import { defServerResolve, defEntryOk, defLogFit } from './def_resolve'"

OLD_CLI = "  const logJson = (_lnFull && _lnFull.length <= 900000) ? _lnFull : 'null'"
NEW_CLI = ('  // ' + SENTINEL + " 入らないときは コマを まびいて 入れる（'null' に しない）" + NL
           + "  const logJson = (_lnFull && _lnFull.length <= 900000) ? _lnFull : (defLogFit(body.log) || 'null')")

BLOCK = """// __DEF_LOG_FIT_V1__ きろくが 大きすぎると 'null' が のこって、クラス全員が リプレイを 見られなくなる。
// そうならないように、上限を こえたときだけ コマを まびいて 入る大きさに する。
// 1コマは それだけで その瞬間の ぜんぶ（HP・いち・きち）を もっている（さしぶんでは ない）ので、
// まびいても のこった コマだけで 絵が つながる。
// かちまけ・きちHP・ひょうしょう は ここへ来る前に もう きまっている。ここでは さわらない。
const DEF_LOG_LIMIT = 900000
const DEF_LOG_TARGET = 860000

// もとの きろくは 書きかえない。うわべだけ 写して コマを さしかえた 入れものを 返す。
function defLogSwap(log, kept, allN) {
  const rep = log.replay
  const r2 = {}
  for (const p in rep) r2[p] = rep[p]
  r2.events = kept
  if (allN != null) r2.thin = { v: 1, kept: kept.length, all: allN }
  const l2 = {}
  for (const q in log) l2[q] = log[q]
  l2.replay = r2
  return l2
}

// のこす コマを えらぶ。たおれた コマと さいごの コマは かならず のこす。
// あとは はじめから おわりまで 等間かくで ひろう（前だけ のこると 絵が とちゅうで 止まるため）。
function defLogPick(evs, keepN) {
  const n = evs.length
  if (keepN >= n) return evs
  const mark = new Array(n)
  let used = 0
  let i = 0
  const deads = []
  for (i = 0; i < n; i++) if (evs[i] && evs[i].dead) deads.push(i)
  if (deads.length <= Math.floor(keepN / 2)) {
    for (i = 0; i < deads.length; i++) if (!mark[deads[i]]) { mark[deads[i]] = 1; used++ }
  }
  if (!mark[n - 1]) { mark[n - 1] = 1; used++ }
  const rest = keepN - used
  if (rest > 0) {
    const step = n / rest
    for (i = 0; i < rest; i++) {
      let p = Math.floor(i * step)
      if (p >= n) p = n - 1
      let q = p
      let guard = 0
      while (q < n && mark[q] && guard++ < n) q++
      if (q >= n) { q = p; while (q >= 0 && mark[q]) q-- }
      if (q >= 0 && q < n && !mark[q]) { mark[q] = 1; used++ }
    }
  }
  const out = []
  for (i = 0; i < n; i++) if (mark[i]) out.push(evs[i])
  return out
}

// 入る大きさの きろくを 返す。どうしても 入らないときだけ null。
// こわれた JSON は ぜったいに 返さない（切り詰めは しない。コマごと まびく）。
export function defLogFit(log) {
  let json = null
  try { json = JSON.stringify(log) } catch (_e) { return null }
  if (!json) return null
  if (json.length <= DEF_LOG_LIMIT) return json
  const rep = log && log.replay
  const evs = (rep && Array.isArray(rep.events)) ? rep.events : null
  if (!evs || evs.length < 2) return null
  let head = 0
  try { head = JSON.stringify(defLogSwap(log, [], null)).length } catch (_e) { return null }
  const budget = DEF_LOG_TARGET - head
  if (budget < 1000) return null
  const avg = Math.max(1, (json.length - head) / evs.length)
  let keepN = Math.floor(budget / avg)
  for (let pass = 0; pass < 6; pass++) {
    if (keepN < 1) keepN = 1
    const kept = defLogPick(evs, keepN)
    let out = null
    try { out = JSON.stringify(defLogSwap(log, kept, evs.length)) } catch (_e) { return null }
    if (out && out.length <= DEF_LOG_LIMIT) return out
    keepN = Math.floor(keepN * 0.75)
    if (keepN < 1) break
  }
  return null
}

"""


def read(path):
    return io.open(path, encoding='utf-8').read()


def write(path, text):
    io.open(path, 'w', encoding='utf-8', newline='').write(text)


def need_one(text, anchor, label):
    n = text.count(anchor)
    if n != 1:
        print('NG: %s のアンカーが %d 件（1 件でないので中止）' % (label, n))
        sys.exit(1)


def chain_count(text):
    i = text.index("app.get('/', async (c) => {")
    j = text.index("app.get('/logout'", i)
    return text[i:j].count('.replace(')


def main():
    v = read(RES_PATH)
    s = read(INDEX_PATH)

    hits = [SENTINEL in v, SENTINEL in s]
    if all(hits):
        print('すでに入っています（番兵 %s）。何もしません。' % SENTINEL)
        return
    if any(hits):
        print('NG: 片方だけ入っている状態です。手で見てください。')
        sys.exit(1)

    for nm in ('defLogFit', 'defLogPick', 'defLogSwap', 'DEF_LOG_LIMIT', 'DEF_LOG_TARGET'):
        if v.count(nm) != 0 or s.count(nm) != 0:
            print('NG: %s という名前が すでにある' % nm)
            sys.exit(1)

    need_one(v, OLD_FN, 'サーバの 入り口')
    need_one(v, OLD_MK, 'きろくの 文字れつ化')
    need_one(v, OLD_CM, 'きろくの おぼえがき')
    need_one(v, OLD_IF, 'きろくの 上限しらべ')
    need_one(s, OLD_IMP, 'とりこみ')
    need_one(s, OLD_CLI, 'ブラウザ経路の 上限しらべ')

    chain_before = chain_count(s)

    v2 = v.replace(OLD_FN, BLOCK + OLD_FN).replace(OLD_MK, NEW_MK).replace(OLD_CM, NEW_CM).replace(OLD_IF, NEW_IF)
    s2 = s.replace(OLD_IMP, NEW_IMP).replace(OLD_CLI, NEW_CLI)

    checks = [
        ('サーバの 番兵', v2.count(SENTINEL), 1),
        ('つなぎの 番兵', s2.count(SENTINEL), 1),
        ('新しい かんすう', v2.count('export function defLogFit(log) {'), 1),
        ('かんすうの よびだし', v2.count('defLogFit(log)'), 2),
        ('えらび かんすう', v2.count('function defLogPick(evs, keepN) {'), 1),
        ('写し かんすう', v2.count('function defLogSwap(log, kept, allN) {'), 1),
        ('上限の なまえ', v2.count('DEF_LOG_LIMIT'), 4),
        ('めやすの なまえ', v2.count('DEF_LOG_TARGET'), 2),
        ('じかに 文字れつ化', v2.count('const logJson = JSON.stringify(log)'), 0),
        ('サーバの 数字 900000', v2.count('900000'), 1),
        ('つなぎの とりこみ', s2.count('defLogFit'), 2),
        ('ブラウザ経路の 古いしっぽ', s2.count("? _lnFull : 'null'"), 0),
        ('ブラウザ経路の 新しいしっぽ', s2.count("(defLogFit(body.log) || 'null')"), 1),
    ]
    bad = 0
    for label, got, want in checks:
        if got != want:
            print('NG: %s が %d 件（%d 件の予定）' % (label, got, want))
            bad += 1
    if bad:
        sys.exit(1)

    chain_after = chain_count(s2)
    if chain_after != chain_before:
        print('NG: つなぎの数が %d から %d（ふえない予定）' % (chain_before, chain_after))
        sys.exit(1)

    write(RES_PATH, v2)
    write(INDEX_PATH, s2)
    print('OK: 入れました。つなぎの数は %d のまま。' % chain_after)


main()
