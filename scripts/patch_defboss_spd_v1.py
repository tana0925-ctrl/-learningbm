# -*- coding: utf-8 -*-
# DEFBOSS_SPD_V1  ぼうえいせんの ボス4体（段12/15/18/21）の はやさ を 1.15倍に する。
#
#   さわるのは src/index.tsx の DEFBOSS_FACE と defBossApply だけ。
#   HP の 1.3倍は そのまま。atk / def / skillPow は 1文字も かえない。
#   てきの spd 上限 70（src/def_stage.ts）にも さわらない。
#
#   .replace( チェーンは 1件も ふえない（チェーンの 外にある サーバ側の 関数だから）。
#   アンカーが 1件で なければ 何も 書かずに とまる（fail-closed）。
import io
import sys

SRC = 'src/index.tsx'
STG = 'src/def_stage.ts'
SENTINEL = '__DEFBOSS_SPD_V1__'
CHAIN_BEFORE = 102
CHAIN_AFTER = 102
SPD_MUL = '1.15'

# 他の便の しるし。1つでも 消えたら 止める。
KEEP = [
    '__DEFBOSS_V1__',
    '__DEFSTAGE_V2_SENTINEL__',
    '__DEF_SERVER_ENGINE_V1__',
    '__DEF_DRYRUN_V1__',
    '__DEF_ALLJOIN_V1__',
    '__DEF_MVP_V1__',
    '__DEFLANE_MIX_V1__',
    '__DEFSTAGE_30_V1__',
    '__ZWAR_CASTLE_STAND_V1__',
    '__ZWAR_BOSS_SKILL3_V1__',
]


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def need(label, text, s, want):
    got = s.count(text)
    if got != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, got, want))
        sys.exit(1)


# --- 1) ボスの表に spdMul を足す -----------------------------------------
A_FACE = (
    "const DEFBOSS_FACE: any = {\n"
    "  '12': { name: 'モンヤブリ', sprite: '\u{1FA93}', hpMul: 1.3 },\n"
    "  '15': { name: 'カゲハヤテ', sprite: '\u{1F32A}\u{FE0F}', hpMul: 1.3 },\n"
    "  '18': { name: 'イワヨロイ', sprite: '\u{1F5FF}', hpMul: 1.3 },\n"
    "  '21': { name: 'ヨルオウガ', sprite: '\u{1F311}', hpMul: 1 }\n"
    "}\n"
)

N_FACE = (
    "// ⚡ __DEFBOSS_SPD_V1__ ボスの はやさ は 段の spd の 1.15倍。\n"
    "//    spd は「何回 うごけるか」そのもの（cdMax = 20*120/spd）なので、\n"
    "//    atk を 3倍に しても 勝率は 1ptも うごかないのに、spd は すぐ 効く。\n"
    "//    1.15 は「書き方で 勝敗が きまる 段」を つくるための 値。1.4 いじょうは 段21 が 0% に なる。\n"
    "//    HP の 1.3倍は すえおき。atk / def / skillPow は さわらない。\n"
    "const DEFBOSS_FACE: any = {\n"
    "  '12': { name: 'モンヤブリ', sprite: '\u{1FA93}', hpMul: 1.3, spdMul: " + SPD_MUL + " },\n"
    "  '15': { name: 'カゲハヤテ', sprite: '\u{1F32A}\u{FE0F}', hpMul: 1.3, spdMul: " + SPD_MUL + " },\n"
    "  '18': { name: 'イワヨロイ', sprite: '\u{1F5FF}', hpMul: 1.3, spdMul: " + SPD_MUL + " },\n"
    "  '21': { name: 'ヨルオウガ', sprite: '\u{1F311}', hpMul: 1, spdMul: " + SPD_MUL + " }\n"
    "}\n"
)

# --- 2) defBossApply で spd を かける ------------------------------------
A_APPLY = (
    "    const mul = Number(b.hpMul) || 1\n"
    "    const hp = Math.round(Number(last.hp || 0) * mul)\n"
    "    o.hp = (Number.isFinite(hp) && hp > 0) ? hp : Math.floor(Number(last.hp || 0))\n"
    "    o.boss = true\n"
)

N_APPLY = (
    "    const mul = Number(b.hpMul) || 1\n"
    "    const hp = Math.round(Number(last.hp || 0) * mul)\n"
    "    o.hp = (Number.isFinite(hp) && hp > 0) ? hp : Math.floor(Number(last.hp || 0))\n"
    "    // ⚡ __DEFBOSS_SPD_V1__ spdMul が ある ボスだけ はやさ を かける。\n"
    "    //    こわれた 値の ときは 何も かけない（段の spd の まま）。ここで 例外は 出さない。\n"
    "    const smul = Number(b.spdMul)\n"
    "    if (Number.isFinite(smul) && smul > 0) {\n"
    "      const spd = Math.round(Number(last.spd || 0) * smul)\n"
    "      if (Number.isFinite(spd) && spd > 0) o.spd = spd\n"
    "    }\n"
    "    o.boss = true\n"
)

# ------------------------------------------------------------------
s = io.open(SRC, encoding='utf-8').read()
before = chain_count(s)

if SENTINEL in s:
    print('すでに適用済み（番兵あり）。何も書かない。chain =', before)
    if before != CHAIN_AFTER:
        print('NG: 適用済みなのにチェーンが %d 件（期待 %d）' % (before, CHAIN_AFTER))
        sys.exit(1)
    sys.exit(0)

if before != CHAIN_BEFORE:
    print('NG: 流す前のチェーンが %d 件（期待 %d）' % (before, CHAIN_BEFORE))
    sys.exit(1)

need('ボスの表', A_FACE, s, 1)
need('defBossApply の HP ブロック', A_APPLY, s, 1)
need('spdMul がまだ無いこと', 'spdMul', s, 0)
need('defBossApply', 'function defBossApply(squad: any, stage: any): any {', s, 1)
need('defBossApply の よびだし', 'defBossApply(', s, 4)

for k in KEEP:
    if k not in s:
        print('NG: しるし %s が 見あたらない' % k)
        sys.exit(1)

# てきの spd 上限 70 に さわっていないこと（別ファイル・読むだけ）
g = io.open(STG, encoding='utf-8').read()
if g.count('Math.min(70, 35 + 5 * k)') != 1:
    print('NG: def_stage.ts の spd 上限 70 が 見あたらない')
    sys.exit(1)

old = s
s = s.replace(A_FACE, N_FACE, 1)
s = s.replace(A_APPLY, N_APPLY, 1)

after = chain_count(s)
ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


chk('チェーン', after, CHAIN_AFTER)
chk('チェーンの増減', after - before, 0)
chk('番兵', s.count(SENTINEL), 2)
chk('spdMul: ' + SPD_MUL, s.count('spdMul: ' + SPD_MUL), 4)
chk('spdMul を読む行', s.count('const smul = Number(b.spdMul)'), 1)
chk('spd を入れる行', s.count('if (Number.isFinite(spd) && spd > 0) o.spd = spd'), 1)
# HP の 1.3倍は すえおき（段21 だけ 1.0 の まま）
chk('hpMul 1.3', s.count('hpMul: 1.3'), 3)
chk('hpMul 1（段21）', s.count("hpMul: 1, spdMul:"), 1)
# atk / def / skillPow は defBossApply の 中に 出てこない
_i = s.index('function defBossApply(')
_j = s.index('const DEFENSE_WIN_COINS', _i)
_body = s[_i:_j]
for bad in ['o.atk', 'o.def', 'o.skillPow']:
    chk('defBossApply が %s に さわっていない' % bad, _body.count(bad), 0)

# しるしの数が かわっていない
for k in KEEP:
    chk('しるし ' + k, s.count(k), old.count(k))

# 足したブロック以外は 1文字も かわっていない
_rebuilt = s.replace(N_FACE, A_FACE, 1).replace(N_APPLY, A_APPLY, 1)
if _rebuilt != old:
    print('NG: 足したブロック以外が かわっている')
    ok[0] = False
else:
    print('OK: 足したブロック以外は かわっていない')

if not ok[0]:
    print('書かずに 中止する')
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('OK: DEFBOSS_SPD_V1 を 適用した。chain %d -> %d（増減 0）' % (before, after))
print('    ボス4体（段12/15/18/21）の spd = 段の spd(70) x %s = 81' % SPD_MUL)
