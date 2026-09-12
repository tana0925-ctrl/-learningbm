# -*- coding: utf-8 -*-
# DEFSTAGE_30_V1 : 段の強さを 段だけで きめる。表を やめて 式に して、上を 30 段まで のばす。
#   1) 人数わりつけ (n/8)^0.6 を やめる。クラス全員が 出るので 人数は ほぼ 一定で、
#      人数で わりつけると 友だちを さそうほど てきが 強くなり、逆に なるため。
#   2) u の ベタ書き表を 1.12 倍の 式に する。段を いくつに ふやしても つづく。
#   3) てきの はやさ を 段で 少しずつ 上げる。いまは はやさが 渡っておらず 10 のままで、
#      よこの道の てきが 基地に とどかないので「1つの道に あつめるだけ」が いつも 最善に なる。
#   4) ごほうびの 頭打ちも 10 段から 30 段に そろえる。
#   ステージ1 は 1つも かわらない（素のまま・はやさ 10）。
#
# 1回流しても 2回流しても 同じ形（番兵 __DEFSTAGE_30_V1__）。
# 一致しないときは 何も書かずに 失敗で終わる（fail-closed）。

import io
import sys

NL = chr(10)

STG_PATH = 'src/def_stage.ts'
RES_PATH = 'src/def_resolve.ts'
INDEX_PATH = 'src/index.tsx'
D2_PATH = 'public/defense2.js'

SENTINEL = '__DEFSTAGE_30_V1__'

G_MAX_OLD = 'export const DEF_STAGE_MAX = 10'
G_MAX_NEW = 'export const DEF_STAGE_MAX = 30'

G_CMT_OLD = NL.join([
    '  // DEF_STAGE_V4 __DEFSTAGE_N_V1__ 段の強さに 出陣人数 n をかけ合わせる。',
    '  //   段の u は 1段 1.12 倍きざみ。n は 8 人を 1.0 とする (n/8)^0.6。',
    '  //   n が読めないときは 8（これまでと同じ強さ）。体数は 8 のまま。',
])
G_CMT_NEW = NL.join([
    '  // DEF_STAGE_V5 __DEFSTAGE_30_V1__ __DEFSTAGE_N_V1__ 段の強さは 段だけで きまる。',
    '  //   クラス全員が 出るので 人数は ほぼ 一定。人数で わりつけると 友だちを さそうほど',
    '  //   てきが 強くなり「みんなで やれば 勝てる」と 逆に なる。n は 受け取るが つかわない。',
])

G_BLK_OLD = NL.join([
    '  const _dsUt = [0, 0.24, 0.27, 0.30, 0.33, 0.37, 0.42, 0.47, 0.53, 0.60]',
    '  const _dsN = Math.floor(Number(n))',
    '  const _dsNn = (Number.isFinite(_dsN) && _dsN >= 1) ? Math.min(200, _dsN) : 8',
    '  const u = _dsUt[k] * Math.pow(_dsNn / 8, 0.6)',
])
G_BLK_NEW = NL.join([
    '  //   u は 1段 1.12 倍きざみ。表を やめて 式に したので 段を いくつ ふやしても つづく。',
    '  //   ステージ1 は u = 0（素のまま）。2 で 0.24、10 で 約0.59、30 で 約5.73。',
    '  //   てきの はやさ も 段で 少しずつ 上げる（1 は 10 のまま、2 で 40、8 いこう 70）。',
    '  //   はやさが 10 のままだと よこの道の てきが 基地に とどかず、',
    '  //   みんなを 1つの道に あつめるだけが いつも 最善に なってしまう。',
    '  const _dsSpd = (k <= 0) ? 10 : Math.min(70, 35 + 5 * k)',
    '  const u = (k <= 0) ? 0 : 0.24 * Math.pow(1.12, k - 1)',
])

G_SPD_OLD = '    if (k > 0) o.spd = Math.round(10 + 230 * u)'
G_SPD_NEW = '    o.spd = _dsSpd'

V_OLD = 'raw: { name: en.name, sprite: en.sprite, hp: en.hp, atk: en.atk, def: en.def, buff: en.buff, skillPow: en.skillPow, elementType: en.elementType, skills: en.skills }'
V_NEW = 'raw: { name: en.name, sprite: en.sprite, hp: en.hp, atk: en.atk, def: en.def, spd: en.spd, buff: en.buff, skillPow: en.skillPow, elementType: en.elementType, skills: en.skills }'

D_OLD = '{raw:{name:en.name,sprite:en.sprite,hp:en.hp,atk:en.atk,def:en.def,buff:en.buff,skillPow:en.skillPow,elementType:en.elementType,skills:en.skills}, strategy:' + chr(39) + 'attack' + chr(39) + '}'
D_NEW = '{raw:{name:en.name,sprite:en.sprite,hp:en.hp,atk:en.atk,def:en.def,spd:en.spd,buff:en.buff,skillPow:en.skillPow,elementType:en.elementType,skills:en.skills}, strategy:' + chr(39) + 'attack' + chr(39) + '}'

S_C1_OLD = '// 敵の強さが 10 で頭打ちなのに合わせて、ボーナスの計算も 10 で頭打ちにする'
S_C1_NEW = '// ' + SENTINEL + ' 敵の強さが 30 で頭打ちなのに合わせて、ボーナスの計算も 30 で頭打ちにする'
S_C2_OLD = '// （11回目以降のクリアで台帳が増え続けないようにするため）。'
S_C2_NEW = '// （31回目以降のクリアで台帳が増え続けないようにするため）。'
S_MAX_OLD = 'const DEFSTAGE_BONUS_MAX_STAGE = 10'
S_MAX_NEW = 'const DEFSTAGE_BONUS_MAX_STAGE = 30'
S_V_OLD = '/defense2.js?v=20'
S_V_NEW = '/defense2.js?v=21'


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
    g = read(STG_PATH)
    v = read(RES_PATH)
    s = read(INDEX_PATH)
    d = read(D2_PATH)

    hits = [SENTINEL in g, SENTINEL in s]
    if all(hits):
        print('すでに入っています（番兵 %s）。何もしません。' % SENTINEL)
        return
    if any(hits):
        print('NG: 片方だけ入っている状態です。手で見てください。')
        sys.exit(1)

    need_one(g, G_MAX_OLD, '段の上限')
    need_one(g, G_CMT_OLD, '段の おぼえがき')
    need_one(g, G_BLK_OLD, '段の 強さの 式')
    need_one(g, G_SPD_OLD, 'てきの はやさ')
    need_one(v, V_OLD, 'サーバの てきの わたし方')
    need_one(d, D_OLD, 'ブラウザの てきの わたし方')
    need_one(s, S_C1_OLD, 'ごほうびの おぼえがき1')
    need_one(s, S_C2_OLD, 'ごほうびの おぼえがき2')
    need_one(s, S_MAX_OLD, 'ごほうびの 頭打ち')
    need_one(s, S_V_OLD, 'defense2 の ばんごう')

    chain_before = chain_count(s)

    g2 = g.replace(G_MAX_OLD, G_MAX_NEW).replace(G_CMT_OLD, G_CMT_NEW).replace(G_BLK_OLD, G_BLK_NEW).replace(G_SPD_OLD, G_SPD_NEW)
    v2 = v.replace(V_OLD, V_NEW)
    d2 = d.replace(D_OLD, D_NEW)
    s2 = s.replace(S_C1_OLD, S_C1_NEW).replace(S_C2_OLD, S_C2_NEW).replace(S_MAX_OLD, S_MAX_NEW).replace(S_V_OLD, S_V_NEW)

    checks = [
        ('段の番兵', g2.count(SENTINEL), 1),
        ('つなぎの番兵', s2.count(SENTINEL), 1),
        ('段の上限30', g2.count(G_MAX_NEW), 1),
        ('古い表', g2.count('_dsUt'), 0),
        ('古い人数', g2.count('_dsNn'), 0),
        ('古い人数2', g2.count('_dsN'), 0),
        ('新しい式', g2.count('Math.pow(1.12, k - 1)'), 1),
        ('はやさの式', g2.count('const _dsSpd = (k <= 0) ? 10 : Math.min(70, 35 + 5 * k)'), 1),
        ('はやさの代入', g2.count('o.spd = _dsSpd'), 1),
        ('体数を増やしていない', g2.count('base.map('), 1),
        ('3引数の形', g2.count('export function defStageEnemies(base, stage, n) {'), 1),
        ('段の番兵N', g2.count('__DEFSTAGE_N_V1__'), 1),
        ('サーバの はやさ', v2.count('spd: en.spd'), 1),
        ('ブラウザの はやさ', d2.count('spd:en.spd'), 1),
        ('ごほうびの頭打ち30', s2.count(S_MAX_NEW), 1),
        ('ばんごう21', s2.count(S_V_NEW), 1),
        ('ばんごう20', s2.count(S_V_OLD), 0),
        ('①が のこっている', s2.count('__DEF_LOG_FIT_V1__'), 1),
        ('①の かんすう', s2.count('defLogFit'), 2),
        ('①の かんすう（サーバ）', v2.count('defLogFit'), 2),
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

    write(STG_PATH, g2)
    write(RES_PATH, v2)
    write(INDEX_PATH, s2)
    write(D2_PATH, d2)
    print('OK: 入れました。つなぎの数は %d のまま。' % chain_after)


main()
