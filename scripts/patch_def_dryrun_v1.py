#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __DEF_DRYRUN_V1__ : 防衛戦の「空打ちの確認口」を足す（教師だけ・GET・書き込みなし）
#
#  - defServerResolve() を書き込みなしで呼び、番人が通るか／サーバが何と判定するかを返す。
#  - DB には SELECT しか出さない。INSERT / UPDATE / DELETE は1つも書かない。
#  - defenseSettings() は defAutoAdvanceV1 が admin_settings を書くことがあるので呼ばない。
#    （admin_settings を直接 SELECT して読むだけにする）
#  - src/def_resolve.ts は defEntryOk を export するだけ（番人のロジックは1文字も変えない）。
#
# fail-closed: 事前チェックに1つでも失敗したら、どのファイルにも触れずに exit 1
import sys, io

SRC = 'src/index.tsx'
RES = 'src/def_resolve.ts'
SENT = '__DEF_DRYRUN_V1__'   # 冪等性の番兵（検証条件とは別物）
BS = "app.get('/', async (c) => {"
BE = "app.get('/logout'"
EXPECT_CHAIN = 72            # この改修では .replace() を1本も足さない

IMP_OLD = "import { defServerResolve } from './def_resolve'"
IMP_NEW = "import { defServerResolve, defEntryOk } from './def_resolve'"

RES_OLD = "function defEntryOk(m) {"
RES_NEW = "export function defEntryOk(m) {"

ANCHOR = "app.post('/api/defense/resolve', async (c) => {"

BLOCK = """// """ + SENT + """ 防衛戦の空打ち（教師だけ・GET・DB には SELECT しか出さない）
// 目的：次の開催の前に「番人が通るか」「サーバが何と判定するか」を、書き込まずに確かめる。
// ここでは INSERT / UPDATE / DELETE を一切実行しない。報酬付与も走らせない。
// defenseSettings() は呼ばない（defAutoAdvanceV1 が admin_settings を書くことがあるため）。
app.get('/api/teacher/defense/dry-run', async (c) => {
  const _drU = requireTeacher(c)
  if (!_drU) return jsonError(c, 401, 'unauthorized')
  const _drRows = await c.env.DB.prepare("SELECT key, value FROM admin_settings WHERE key IN ('defense_active','defense_decision_at','defense_event_key') LIMIT 8").all<any>()
  const _drKv: any = {}
  for (const _drR of ((_drRows && _drRows.results) || [])) _drKv[String(_drR.key)] = String(_drR.value == null ? '' : _drR.value)
  const _drDecisionAt = String(_drKv.defense_decision_at || '')
  const _drSt = {
    active: _drKv.defense_active === '1',
    decisionAt: _drDecisionAt,
    eventKey: String(c.req.query('event_key') || _drKv.defense_event_key || _drDecisionAt || '')
  }
  const _drOut: any = {
    ok: true, dry_run: true, wrote: false,
    engine_sig: DEF_ENGINE_SIG,
    active: _drSt.active, decision_at: _drSt.decisionAt, event_key: _drSt.eventKey,
    classes: [], class_id: null, already: null, entries: null, gate: null, server: null
  }
  if (!_drSt.eventKey) { _drOut.note = 'event_key が未設定です'; return c.json(_drOut) }
  const _drCls = await c.env.DB.prepare("SELECT class_id AS cid, COUNT(*) AS n FROM defense_entries WHERE event_key=? GROUP BY class_id ORDER BY class_id ASC LIMIT 50").bind(_drSt.eventKey).all<any>()
  _drOut.classes = ((_drCls && _drCls.results) || []).map((r: any) => ({ class_id: String(r.cid == null ? '' : r.cid), entries: Number(r.n || 0) }))
  const _drCid = String(c.req.query('class_id') || (_drOut.classes.length === 1 ? _drOut.classes[0].class_id : ''))
  if (!_drCid) { _drOut.note = 'class_id を付けてください（classes から選ぶ）'; return c.json(_drOut) }
  _drOut.class_id = _drCid
  const _drDone = await c.env.DB.prepare("SELECT 1 AS x FROM defense_results WHERE event_key=? AND class_id=? LIMIT 1").bind(_drSt.eventKey, _drCid).first<any>()
  _drOut.already = !!_drDone
  const _drEs = await c.env.DB.prepare("SELECT de.monster_json AS mj, u.name AS nm FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? ORDER BY de.created_at ASC, de.user_id ASC LIMIT 200").bind(_drSt.eventKey, _drCid).all<any>()
  const _drList = ((_drEs && _drEs.results) || [])
  const _drDetail: any[] = []
  let _drPass = 0
  for (const _drE of _drList) {
    let _drM: any = null
    let _drParsed = true
    try { _drM = JSON.parse(String(_drE.mj)) } catch (_e) { _drParsed = false }
    const _drOkE = _drParsed && defEntryOk(_drM)
    if (_drOkE) _drPass++
    _drDetail.push({
      name: String(_drE.nm || ''),
      parsed: _drParsed,
      spd: (_drM && _drM.spd != null) ? Number(_drM.spd) : null,
      skills: (_drM && Array.isArray(_drM.skills)) ? _drM.skills.length : null,
      hp: (_drM && _drM.hp != null) ? Number(_drM.hp) : null,
      atk: (_drM && _drM.atk != null) ? Number(_drM.atk) : null,
      def: (_drM && _drM.def != null) ? Number(_drM.def) : null,
      elementType: (_drM && _drM.elementType != null) ? String(_drM.elementType) : null,
      ok: _drOkE
    })
  }
  _drOut.entries = { total: _drList.length, ok: _drPass, ng: _drList.length - _drPass, detail: _drDetail }
  _drOut.gate = { open: (_drList.length > 0 && _drPass === _drList.length) }
  const _drRes = await defServerResolve(c.env, _drSt, _drCid, DEFENSE_ENEMIES)
  _drOut.server = _drRes
    ? { would_resolve: true, result: _drRes.result, base_hp_end: _drRes.baseHpEnd, seed: _drRes.seed, entries: _drRes.entries, log_bytes: String(_drRes.logJson || '').length }
    : { would_resolve: false }
  return c.json(_drOut)
})

"""

GUARD = ['__DEF_SNAP_SPDSKILLS_V1__', '__DEF_RESOLVE_VERIFY_V1__', '__DEF_SERVER_RESOLVE_V1__',
         'defAutoAdvanceV1', 'defense_standing', 'defense_carry_lock',
         'const DEFENSE_BASE_HP = 380', 'function requireTeacher(c: any) {', 'function jsonError']


def die(msg):
    print('NG: ' + msg)
    sys.exit(1)


src = io.open(SRC, encoding='utf-8').read()
res = io.open(RES, encoding='utf-8').read()

# ---- 冪等性の番兵（検証条件とは別物） ----
if SENT in src:
    print('ALREADY APPLIED (sentinel present) - no file touched')
    sys.exit(0)

# ---- アンカーの一意性 ----
if src.count(BS) != 1: die("app.get('/', async (c) => { が一意でない: %d" % src.count(BS))
if src.count(BE) != 1: die("app.get('/logout' が一意でない: %d" % src.count(BE))
st = src.find(BS); en = src.find(BE)
if en <= st: die('block bounds inverted')
chain = src[st:en].count('.replace(')
print('chain before = %d' % chain)
if chain != EXPECT_CHAIN: die('chain %d != %d' % (chain, EXPECT_CHAIN))

if src.count(ANCHOR) != 1: die('挿入アンカーが一意でない: %d' % src.count(ANCHOR))
if src.count(IMP_OLD) != 1: die('import 行が一意でない: %d' % src.count(IMP_OLD))
if src.count(IMP_NEW) != 0: die('import はすでに書き換わっている')
if res.count(RES_OLD) != 1: die('def_resolve.ts の defEntryOk 定義が一意でない: %d' % res.count(RES_OLD))
if res.count(RES_NEW) != 0: die('def_resolve.ts はすでに export 済み')
if res.count('export async function defServerResolve(') != 1: die('defServerResolve が見つからない')
if res.count('logJson.length > 900000') != 1: die('def_resolve.ts のログ上限チェックが無い')

for g in GUARD:
    if g not in src: die('guard missing before: ' + g)
if src.count('ensureDefenseTables') != 1:
    die('ensureDefenseTables の出現が 1 件でない（呼び出しは0件のまま）')

# ---- 適用 ----
out = src.replace(IMP_OLD, IMP_NEW, 1)
out = out.replace(ANCHOR, BLOCK + ANCHOR, 1)
res_out = res.replace(RES_OLD, RES_NEW, 1)

# ---- 適用後の自己チェック（ここで落ちたら書かない） ----
st2 = out.find(BS); en2 = out.find(BE)
chain2 = out[st2:en2].count('.replace(')
if chain2 != EXPECT_CHAIN: die('chain after %d != %d（.replace() を足していないはず）' % (chain2, EXPECT_CHAIN))
if out.count(SENT) != 1: die('番兵が1件でない: %d' % out.count(SENT))
if out.count("app.get('/api/teacher/defense/dry-run'") != 1: die('確認口が1件でない')
if out.count(IMP_NEW) != 1: die('import の書き換えに失敗')
if out.count('ensureDefenseTables') != 1: die('ensureDefenseTables が増減した')
if res_out.count(RES_NEW) != 1: die('def_resolve.ts の export に失敗')

# 追加ブロックに書き込み系が混ざっていないこと（ここが今回いちばん大事）
b0 = out.find(SENT)
b1 = out.find(ANCHOR, b0)
if b1 <= b0: die('追加ブロックの範囲が取れない')
blk = out[b0:b1]
for bad in ['INSERT', 'UPDATE ', 'DELETE', 'CREATE ', 'DROP ', 'ALTER ',
            'ensureDefenseTables', 'defenseSettings(', '.run()', '.batch(']:
    if bad in blk: die('確認口に書き込み系が入っている: ' + bad)
if 'SELECT' not in blk: die('確認口が DB を読んでいない')

io.open(SRC, 'w', encoding='utf-8').write(out)
io.open(RES, 'w', encoding='utf-8').write(res_out)
print('APPLIED: chain=%d（変わらず）, 確認口 GET /api/teacher/defense/dry-run' % chain2)
