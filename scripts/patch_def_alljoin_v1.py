# -*- coding: utf-8 -*-
# DEF_ALLJOIN_V1 : クラス全員が ぼうえいせんに 出る。
#   1) まだ 出していない子は「手持ちの先頭」で 自動さんか（めいれいは 既定）。
#      すがた・つよさは src/def_dex.ts の 表から とる。ぼうえいせんの ものさしは
#      その子の 進みぐあいを 1つも 見ないので、モンスターの番号だけで きまる。
#   2) 勝ったら クラス全員に 20枚。自分で 出した子は さらに +10（あわせて 30枚）。
#   3) 表彰（せめ・まもり・ねばり・くふう）と MVP は 自分で 出した子だけ。
#   読みとりは クラスで 最初の1人が 通るときの 1回だけ（すでに ある 錠の かたまりの 中）。
#
# 1回流しても 2回流しても 同じ形（番兵 __DEF_ALLJOIN_V1__）。
# 一致しないときは 何も書かずに 失敗で終わる（fail-closed）。

import io
import sys

NL = chr(10)
Q1 = chr(39)

INDEX_PATH = 'src/index.tsx'
RES_PATH = 'src/def_resolve.ts'

SENTINEL = '__DEF_ALLJOIN_V1__'

AJ_INS = ('INS' + 'ERT INTO defense_entries (event_key, user_id, class_id, monster_json, strategy, created_at)'
          + ' VALUES (?,?,?,?,?,datetime(' + Q1 + 'now' + Q1 + ')) ON CONFLICT(event_key, user_id) DO NOTHING')
RW_INS = ('INS' + 'ERT OR IGNORE INTO defense_rewards (event_key, class_id, user_id, coins, seen, created_at)'
          + ' VALUES (?,?,?,?,0,datetime(' + Q1 + 'now' + Q1 + '))')
AJ_SEL = ("SELECT cm.user_id AS uid, json_extract(p.state_json, " + Q1 + "$.party[0]" + Q1 + ") AS pid"
          + " FROM class_members cm LEFT JOIN progress p ON p.user_id = cm.user_id"
          + " WHERE cm.class_id=? AND cm.user_id NOT IN (SELECT user_id FROM defense_entries WHERE event_key=? AND class_id=?)"
          + " LIMIT 200")

S_IMP_OLD = "import { defServerResolve, defEntryOk, defLogFit } from './def_resolve'"
S_IMP_NEW = S_IMP_OLD + NL + "import { defDexEntry } from './def_dex'"

S_ANCHOR = NL.join([
    "              await c.env.DB.batch(_dsRows.map((r: any) => _dsIns.bind(st.eventKey, String(r.uid), classId, String(r.mj), String(r.strat || 'balance'))))",
    '            }',
])
S_JOIN = NL.join([
    '            // ' + SENTINEL + ' クラス全員が 出る。まだ 出していない子は 手持ちの先頭で 自動さんか。',
    '            //   ここは クラスで 最初の1人だけが 通る（すぐ上の 錠と 同じ かたまり）。1日に 1回だけ。',
    '            //   つよさは src/def_dex.ts の 表。ぼうえいせんの ものさしは モンスターの番号だけで',
    '            //   きまるので、図鑑が サーバに 無くても 同じ すがた・つよさに なる。',
    '            //   読みとりは クラス名簿ぶんの 1回だけ。state_json は まるごと 取らない。',
    '            try {',
    '              const _ajAll = await c.env.DB.prepare("' + AJ_SEL + '").bind(classId, st.eventKey, classId).all<any>()',
    '              const _ajRows: any[] = []',
    '              for (const _ajR of ((_ajAll && _ajAll.results) || [])) {',
    '                const _ajM: any = defDexEntry(_ajR && _ajR.pid)',
    '                if (!_ajM || !defEntryOk(_ajM)) continue',
    '                _ajM.auto = 1',
    '                const _ajU = String((_ajR && _ajR.uid) || ' + Q1 + Q1 + ')',
    '                if (!_ajU) continue',
    '                _ajRows.push({ uid: _ajU, mj: JSON.stringify(_ajM) })',
    '              }',
    '              if (_ajRows.length) {',
    '                const _ajIns = c.env.DB.prepare("' + AJ_INS + '")',
    "                await c.env.DB.batch(_ajRows.map((r: any) => _ajIns.bind(st.eventKey, r.uid, classId, r.mj, 'balance')))",
    '              }',
    '            } catch (_e) {}',
])

S_COIN_OLD = 'const DEFENSE_WIN_COINS = 20'
S_COIN_NEW = NL.join([
    S_COIN_OLD,
    '// ' + SENTINEL + ' 自分で 出した子の うわのせ。勝利コイン 20 とは べつの 数。',
    'const DEFENSE_ENTRY_BONUS_COINS = 10',
])

S_RW_OLD = NL.join([
    '        const _srvEs = await c.env.DB.prepare("SELECT user_id FROM defense_entries WHERE event_key=? AND class_id=?").bind(st.eventKey, classId).all<any>()',
    '        for (const _srvR of ((_srvEs && _srvEs.results) || [])) {',
    '          await c.env.DB.prepare("' + RW_INS + '").bind(st.eventKey, classId, String(_srvR.user_id), DEFENSE_WIN_COINS).run()',
    '        }',
])
S_RW_NEW = NL.join([
    '        // ' + SENTINEL + ' 勝ったら クラス全員に 20枚。自分で 出した子は さらに +10（あわせて 30枚）。',
    '        const _srvEs = await c.env.DB.prepare("SELECT user_id, json_extract(monster_json, ' + Q1 + '$.auto' + Q1 + ') AS au FROM defense_entries WHERE event_key=? AND class_id=?").bind(st.eventKey, classId).all<any>()',
    '        const _srvRw = c.env.DB.prepare("' + RW_INS + '")',
    '        const _srvList = ((_srvEs && _srvEs.results) || []).map((r: any) => _srvRw.bind(st.eventKey, classId, String(r.user_id), (Number(r.au) === 1 ? DEFENSE_WIN_COINS : DEFENSE_WIN_COINS + DEFENSE_ENTRY_BONUS_COINS)))',
    '        if (_srvList.length) await c.env.DB.batch(_srvList)',
])

C_RW_OLD = NL.join([
    '      const es = await c.env.DB.prepare("SELECT user_id FROM defense_entries WHERE event_key=? AND class_id=?").bind(st.eventKey, classId).all<any>()',
    '      for (const r of ((es && es.results) || [])) {',
    '        await c.env.DB.prepare("' + RW_INS + '").bind(st.eventKey, classId, String(r.user_id), DEFENSE_WIN_COINS).run()',
    '      }',
])
C_RW_NEW = NL.join([
    '      // ' + SENTINEL + ' こちらの みちすじも 同じ（クラス全員に 20枚、自分で 出した子は 30枚）。',
    '      const es = await c.env.DB.prepare("SELECT user_id, json_extract(monster_json, ' + Q1 + '$.auto' + Q1 + ') AS au FROM defense_entries WHERE event_key=? AND class_id=?").bind(st.eventKey, classId).all<any>()',
    '      const _cbRw = c.env.DB.prepare("' + RW_INS + '")',
    '      const _cbList = ((es && es.results) || []).map((r: any) => _cbRw.bind(st.eventKey, classId, String(r.user_id), (Number(r.au) === 1 ? DEFENSE_WIN_COINS : DEFENSE_WIN_COINS + DEFENSE_ENTRY_BONUS_COINS)))',
    '      if (_cbList.length) await c.env.DB.batch(_cbList)',
])

V_ENT_OLD = "      ents.push({ m: m, nm: String(r.nm || ''), sg: String(r.sg || ''), uid: String(r.uid || '') })"
V_ENT_NEW = "      ents.push({ m: m, nm: String(r.nm || ''), sg: String(r.sg || ''), uid: String(r.uid || ''), auto: (Number(m.auto) === 1) })"

V_FEW_OLD = '    const few = (n < DEF_MVP_MIN_ENTRIES)'
V_FEW_NEW = NL.join([
    '    // ' + SENTINEL + ' 表彰は 自分で 出した子だけ。自動で 出た子は 数にも 入れない。',
    '    let _ajSelf = 0',
    '    for (let i = 0; i < n; i++) if (!(ents[i] && ents[i].auto)) _ajSelf++',
    '    const few = (_ajSelf < DEF_MVP_MIN_ENTRIES)',
])

V_KUFU_OLD = '    vals.kufu = _kf.val'
V_KUFU_NEW = NL.join([
    V_KUFU_OLD,
    '    // ' + SENTINEL + ' 自動で 出た子の きろくは 0 に する（順位に 入らない）。',
    '    for (let i = 0; i < n; i++) {',
    '      if (!(ents[i] && ents[i].auto)) continue',
    '      vals.seme[i] = 0',
    '      vals.mamori[i] = 0',
    '      vals.nebari[i] = 0',
    '      vals.kufu[i] = 0',
    '      _kf.k[i] = 0',
    '      _kf.rank[i] = 0',
    '    }',
])

V_LED_OLD = NL.join([
    '      for (let i = 0; i < n; i++) {',
    '        const place = places ? places[i] : 0',
])
V_LED_NEW = NL.join([
    '      for (let i = 0; i < n; i++) {',
    '        if (ents[i] && ents[i].auto) continue',
    '        const place = places ? places[i] : 0',
])

V_CON_OLD = '          dealt: Math.round(dealt || 0), alive: live'
V_CON_NEW = '          dealt: Math.round(dealt || 0), alive: live, auto: (Number(e.m && e.m.auto) === 1)'

V_MVP_OLD = NL.join([
    '    let mvp = null',
    '    try { mvp = computeMVP(_mvRep, ents.map(function (e) { return { name: e.nm } })) } catch (_e) { mvp = null }',
])
V_MVP_NEW = NL.join([
    '    let mvp = null',
    '    // ' + SENTINEL + ' MVP も 自分で 出した子から えらぶ。',
    '    try {',
    '      const _ajIdx = []',
    '      for (let i = 0; i < ents.length; i++) if (!ents[i].auto) _ajIdx.push(i)',
    '      if (_ajIdx.length) {',
    '        const _ajA0 = (_mvRep && _mvRep.teams && _mvRep.teams.A) ? _mvRep.teams.A : []',
    '        const _ajA = _ajIdx.map(function (i) { return _ajA0[i] }).filter(function (x) { return !!x })',
    '        if (_ajA.length === _ajIdx.length) {',
    '          mvp = computeMVP({ teams: { A: _ajA } }, _ajIdx.map(function (i) { return { name: ents[i].nm } }))',
    '        }',
    '      }',
    '    } catch (_e) { mvp = null }',
])


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
    s = read(INDEX_PATH)
    v = read(RES_PATH)

    hits = [SENTINEL in s, SENTINEL in v]
    if all(hits):
        print('すでに入っています（番兵 %s）。何もしません。' % SENTINEL)
        return
    if any(hits):
        print('NG: 片方だけ入っている状態です。手で見てください。')
        sys.exit(1)

    for nm in ('defDexEntry', '_ajRows', 'DEFENSE_ENTRY_BONUS_COINS'):
        if s.count(nm) != 0:
            print('NG: %s という名前が すでにある' % nm)
            sys.exit(1)

    need_one(s, S_IMP_OLD, 'とりこみ')
    need_one(s, S_ANCHOR, '持ち越しの まとめ書き')
    need_one(s, S_COIN_OLD, '勝利コイン')
    need_one(s, S_RW_OLD, 'サーバみちすじの ごほうび')
    need_one(s, C_RW_OLD, 'ブラウザみちすじの ごほうび')
    need_one(v, V_ENT_OLD, '出た子の ならび')
    need_one(v, V_FEW_OLD, '人数が 少ないときの しきい')
    need_one(v, V_KUFU_OLD, 'くふうの 数')
    need_one(v, V_LED_OLD, '台帳の くりかえし')
    need_one(v, V_CON_OLD, 'はたらきの ひとつ')
    need_one(v, V_MVP_OLD, 'MVP えらび')

    chain_before = chain_count(s)

    s2 = (s.replace(S_IMP_OLD, S_IMP_NEW)
           .replace(S_ANCHOR, S_ANCHOR + NL + S_JOIN)
           .replace(S_COIN_OLD, S_COIN_NEW)
           .replace(S_RW_OLD, S_RW_NEW)
           .replace(C_RW_OLD, C_RW_NEW))
    v2 = (v.replace(V_ENT_OLD, V_ENT_NEW)
           .replace(V_FEW_OLD, V_FEW_NEW)
           .replace(V_KUFU_OLD, V_KUFU_NEW)
           .replace(V_LED_OLD, V_LED_NEW)
           .replace(V_CON_OLD, V_CON_NEW)
           .replace(V_MVP_OLD, V_MVP_NEW))

    checks = [
        ('つなぎの番兵', s2.count(SENTINEL), 4),
        ('サーバの番兵', v2.count(SENTINEL), 3),
        ('表のとりこみ', s2.count("import { defDexEntry } from './def_dex'"), 1),
        ('表のよびだし', s2.count('defDexEntry(_ajR && _ajR.pid)'), 1),
        ('自動さんかの まとめ書き', s2.count('_ajIns.bind(st.eventKey, r.uid, classId, r.mj, ' + Q1 + 'balance' + Q1 + ')'), 1),
        ('うわのせの 数', s2.count('const DEFENSE_ENTRY_BONUS_COINS = 10'), 1),
        ('勝利コイン 20', s2.count(S_COIN_OLD), 1),
        ('ごほうびの まとめ書き', s2.count('await c.env.DB.batch(_srvList)') + s2.count('await c.env.DB.batch(_cbList)'), 2),
        ('1件ずつの 書き込みが 消えた', s2.count('String(_srvR.user_id), DEFENSE_WIN_COINS'), 0),
        ('1件ずつの 書き込みが 消えた2', s2.count('String(r.user_id), DEFENSE_WIN_COINS'), 0),
        ('自動の しるし', v2.count('auto: (Number(m.auto) === 1)'), 1),
        ('表彰の 数え方', v2.count('const few = (_ajSelf < DEF_MVP_MIN_ENTRIES)'), 1),
        ('きろくを 0 に', v2.count('_kf.rank[i] = 0'), 1),
        ('台帳の とばし', v2.count('if (ents[i] && ents[i].auto) continue'), 1),
        ('MVP の えらび', v2.count('_ajIdx.map(function (i) { return { name: ents[i].nm } })'), 1),
        ('①が のこっている', s2.count('__DEF_LOG_FIT_V1__'), 1),
        ('③aが のこっている', s2.count('__DEFSTAGE_30_V1__'), 1),
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

    write(INDEX_PATH, s2)
    write(RES_PATH, v2)
    print('OK: 入れました。つなぎの数は %d のまま。' % chain_after)


main()
