# -*- coding: utf-8 -*-
# DEF_STAGE_V4 : 難易度を出陣人数でわりつける。
#   段の u を [0,.24,.27,.30,.33,.37,.42,.47,.53,.60] にして、(n/8)^0.6 をかける。
#   n が読めないときは 8 とみなす（8人ぶんの強さ＝これまでと同じ並び）。
#   てきの体数は 8 のまま。増やさない。
#
# 1回流しても 2回流しても 同じ形になる（番兵 __DEFSTAGE_N_V1__）。
# 一致しないときは 何も書かずに 失敗で終わる（fail-closed）。

import io
import sys

NL = chr(10)

STAGE_PATH = 'src/def_stage.ts'
INDEX_PATH = 'src/index.tsx'

SENTINEL = '__DEFSTAGE_N_V1__'


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


DS_OLD_SIG = 'export function defStageEnemies(base, stage) {'
DS_NEW_SIG = 'export function defStageEnemies(base, stage, n) {'

DS_OLD_U = '  const u = Math.pow(k / (DEF_STAGE_MAX - 1), 2.2)'
DS_NEW_U = NL.join([
    '  // DEF_STAGE_V4 ' + SENTINEL + ' 段の強さに 出陣人数 n をかけ合わせる。',
    '  //   段の u は 1段 1.12 倍きざみ。n は 8 人を 1.0 とする (n/8)^0.6。',
    '  //   n が読めないときは 8（これまでと同じ強さ）。体数は 8 のまま。',
    '  const _dsUt = [0, 0.24, 0.27, 0.30, 0.33, 0.37, 0.42, 0.47, 0.53, 0.60]',
    '  const _dsN = Math.floor(Number(n))',
    '  const _dsNn = (Number.isFinite(_dsN) && _dsN >= 1) ? Math.min(200, _dsN) : 8',
    '  const u = _dsUt[k] * Math.pow(_dsNn / 8, 0.6)',
])

IX_ANCHOR_DECL = 'const DEFENSE_ENEMIES = ['
IX_HELPER = NL.join([
    '// DEF_STAGE_V4 ' + SENTINEL + ' 出陣している人数を かぞえるだけの助け。',
    '// 読むだけで、ここからは 何も書きこまない。かぞえられなければ 8 を返す。',
    'async function defEntryCount(env: any, eventKey: any, classId: any): Promise<number> {',
    '  try {',
    '    const r: any = await env.DB.prepare("SELECT COUNT(*) AS c FROM defense_entries de JOIN users u ON u.id=de.user_id WHERE de.event_key=? AND de.class_id=? LIMIT 1").bind(String(eventKey), String(classId)).first()',
    '    const n = Number(r && r.c)',
    '    if (!Number.isFinite(n) || n < 1) return 8',
    '    return Math.min(200, Math.floor(n))',
    '  } catch (_e) { return 8 }',
    '}',
    '',
])

IX_OLD_STATUS = '  out.enemy_squad = defStageEnemies(DEFENSE_ENEMIES, out.stage)'
IX_NEW_STATUS = '  out.enemy_squad = defStageEnemies(DEFENSE_ENEMIES, out.stage, await defEntryCount(c.env, st.eventKey, classId))'

IX_OLD_DRY = '  const _drEnemies = defStageEnemies(DEFENSE_ENEMIES, _drStage)'
IX_NEW_DRY = '  const _drEnemies = defStageEnemies(DEFENSE_ENEMIES, _drStage, _drList.length)'

IX_OLD_RES = 'defServerResolve(c.env, st, classId, defStageEnemies(DEFENSE_ENEMIES, _dsStage))'
IX_NEW_RES = 'defServerResolve(c.env, st, classId, defStageEnemies(DEFENSE_ENEMIES, _dsStage, await defEntryCount(c.env, st.eventKey, classId)))'


def main():
    g = read(STAGE_PATH)
    s = read(INDEX_PATH)

    if SENTINEL in g and SENTINEL in s:
        print('すでに入っています（番兵 %s）。何もしません。' % SENTINEL)
        return

    if (SENTINEL in g) != (SENTINEL in s):
        print('NG: 片方だけ入っている状態です。手で見てください。')
        sys.exit(1)

    need_one(g, DS_OLD_SIG, 'def_stage のみだし')
    need_one(g, DS_OLD_U, 'def_stage の u')
    need_one(s, IX_ANCHOR_DECL, 'てきの定数')
    need_one(s, IX_OLD_STATUS, 'status のよびだし')
    need_one(s, IX_OLD_DRY, 'から実行のよびだし')
    need_one(s, IX_OLD_RES, 'けっか確定のよびだし')
    if s.count('defEntryCount') != 0:
        print('NG: defEntryCount がすでにある')
        sys.exit(1)

    chain_before = chain_count(s)

    g2 = g.replace(DS_OLD_SIG, DS_NEW_SIG).replace(DS_OLD_U, DS_NEW_U)
    s2 = s.replace(IX_ANCHOR_DECL, IX_HELPER + IX_ANCHOR_DECL)
    s2 = s2.replace(IX_OLD_STATUS, IX_NEW_STATUS)
    s2 = s2.replace(IX_OLD_DRY, IX_NEW_DRY)
    s2 = s2.replace(IX_OLD_RES, IX_NEW_RES)

    if SENTINEL not in g2 or SENTINEL not in s2:
        print('NG: 番兵が入らなかった')
        sys.exit(1)
    if g2.count(DS_NEW_SIG) != 1 or g2.count('base.map(') != 1:
        print('NG: def_stage の形がおかしい')
        sys.exit(1)
    if s2.count('defStageEnemies(DEFENSE_ENEMIES') != 3:
        print('NG: よびだしが 3 件でない')
        sys.exit(1)
    if s2.count('DEFENSE_ENEMIES') != 5:
        print('NG: てきの定数の参照が 5 件でない')
        sys.exit(1)
    if s2.count('defEntryCount') != 3:
        print('NG: defEntryCount が 3 件でない')
        sys.exit(1)

    chain_after = chain_count(s2)
    if chain_after != chain_before:
        print('NG: つなぎの数が %d から %d に変わった（変えない予定）' % (chain_before, chain_after))
        sys.exit(1)

    write(STAGE_PATH, g2)
    write(INDEX_PATH, s2)
    print('OK: 入れました。つなぎの数は %d のまま。' % chain_after)


main()
