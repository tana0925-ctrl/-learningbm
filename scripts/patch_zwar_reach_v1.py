# -*- coding: utf-8 -*-
# ZWAR_REACH_FIX_V1（攻略モード／ゾンビ襲来：画面のはばがせまいと 戦闘が はじまらない不具合）
#
#   public/index.html の nearestEngagement で、
#     止まる距離   ＝ (じぶんの半分 ＋ あいての半分) ÷ 画面のはば × 100 ＋ 0.2 ［％］
#     ねらえる距離 ＝ 6 ［％・固定］
#   という具合に ものさしが そろっていない。止まる距離は 画面のはばで 変わるので、
#   793px より せまいと 止まる距離のほうが 遠くなり、味方も敵も いつまでも かみ合わない。
#   ボスは 絵が大きい（60px）ので 914px より せまいと ボスだけ 戦えない。
#   iPad の たて向きは 768px で、ちょうど この「だれも攻撃しない」帯に入る。
#
#   なおし方：ねらえる距離を 止まる距離と まったく同じ式で出し、そこから 0.2 だけ遠くする。
#             Math.max(6, ...) で 下ささえをするので、914px 以上の画面では 6 のまま＝これまでと同じ。
#
#   さわるのは src/index.tsx の .replace チェーンだけ。public/index.html は 手で編集しない。
#   配信されるコードは throw せず、アンカーが無いときは console.error して skip する。
#   「敵が 自分では ねらいを決めない」別の不具合には さわらない（players のループのまま）。
#   アンカーが 一意でなければ 1文字も書かずに exit 1（fail-closed）。
import io
import sys

SRC = 'src/index.tsx'
HTML = 'public/index.html'
SENTINEL = '__ZWAR_REACH_FIX_V1__'
CHAIN_BEFORE = 102
CHAIN_AFTER = 103


def chain_count(s):
    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    return s[i:j].count('.replace(')


def need(label, text, s, want):
    got = s.count(text)
    if got != want:
        print('NG: アンカー %s が %d 件（期待 %d）' % (label, got, want))
        sys.exit(1)


# 直前のチェーン（__ZWAR_BOSS_SKILL3_V1__）の1行と、キャッシュに入れる1行のあいだに さしこむ
ZBS_LINE = r'''    if (t.indexOf(_zbs1) !== -1) { t = t.replace(_zbs1, _zbs2) } else { console.error('[__ZWAR_BOSS_SKILL3_V1__] anchor not found') }
'''
CACHE_LINE = '    _rootHtmlCache = t\n'

NEW_BLOCK = r'''    // 🎯 __ZWAR_REACH_FIX_V1__ : せまい画面だと 攻略モード／ゾンビ襲来の 戦闘が はじまらない不具合。
    //   止まる距離 ＝ (じぶんの半分 ＋ あいての半分) ÷ 画面のはば × 100 ＋ 0.2 ［％］で、画面のはばで変わる。
    //   なのに ねらえる距離だけ 6［％］の固定だったので、793px より せまいと
    //   止まる距離のほうが 遠くなって、味方も敵も いつまでも かみ合わなかった（iPad たては 768px）。
    //   ボスは 絵が大きい（60px）ので 914px より せまいと ボスだけ 戦えなかった。
    //   ねらえる距離を 止まる距離と まったく同じ式で出して、そこから 0.2 だけ 遠くする。
    //   914px 以上では Math.max(6, ...) が 6 を返すので、広い画面は これまでと 1つも変わらない。
    //   敵が 自分では ねらいを決めない 別の不具合には さわらない（players のループのまま）。
    const _zwr1 = "      if(cand && best < 6){ pu.target=cand; cand.target=pu; }"
    const _zwr2 = "      /* __ZWAR_REACH_FIX_V1__ ねらえる距離を 止まる距離と 同じものさし（画面のはばに対する％）で 出す。 */\n      if(cand){\n        var _zwBW = 600;\n        try{ _zwBW = Math.max(1, Number(warState && warState._battleW) || 600); }catch(e){ _zwBW = 600; }\n        var _zwHalfPct = function(un){ return ((((un && un.isBoss) ? 60 : 46) / 2) / _zwBW) * 100; };\n        var _zwStop = _zwHalfPct(pu) + _zwHalfPct(cand) + 0.2;\n        var _zwReach = Math.max(6, _zwStop + 0.2);\n        if(best < _zwReach){ pu.target=cand; cand.target=pu; }\n      }"
    if (t.indexOf(_zwr1) !== -1) { t = t.replace(_zwr1, _zwr2) } else { console.error('[__ZWAR_REACH_FIX_V1__] anchor not found') }
'''

A_SRC = ZBS_LINE + CACHE_LINE
N_SRC = ZBS_LINE + NEW_BLOCK + CACHE_LINE

# ------------------------------------------------------------------
s = io.open(SRC, encoding='utf-8').read()
h = io.open(HTML, encoding='utf-8').read()
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

# --- さしこむ場所（src/index.tsx）---
need('チェーンのさしこみ口', A_SRC, s, 1)
need('root ハンドラ', "app.get('/', async (c) => {", s, 1)
need('logout ハンドラ', "app.get('/logout'", s, 1)

# --- 書きかえる先（public/index.html）が 一意であること ---
need('nearestEngagement（html）', 'function nearestEngagement(){', h, 1)
need('ねらえる距離 6（html）', '      if(cand && best < 6){ pu.target=cand; cand.target=pu; }', h, 1)
need('止まる距離 halfPct（html）', '      const wpx = unit && unit.isBoss ? 60 : 46;', h, 1)
need('止まる距離 ＋0.2（html）', 'const gap = myHalf + halfPct(nearest) + 0.2;', h, 2)

# --- チェーンの ほかの行が 同じ場所を さわっていないこと ---
_ci = s.index("app.get('/', async (c) => {")
_cj = s.index("app.get('/logout'", _ci)
_chain = s[_ci:_cj]
for _w in ('nearestEngagement', 'best < 6', 'for(const pu of players)', 'halfPct'):
    if _w in _chain:
        print('NG: チェーンの中に すでに %s が出てくる。手で見てから流し直す。' % _w)
        sys.exit(1)

s = s.replace(A_SRC, N_SRC, 1)
after = chain_count(s)

ok = [True]


def chk(label, got, want):
    if got != want:
        print('NG: %s が %s 件（期待 %s）' % (label, got, want))
        ok[0] = False


# --- 増えたのは 自分の1件だけ ---
chk('チェーン', after, CHAIN_AFTER)
chk('増えた件数', after - before, 1)
chk('番兵', s.count(SENTINEL), 3)
chk('_zwr1', s.count('_zwr1'), 3)
chk('_zwr2', s.count('_zwr2'), 2)
chk('ねらえる距離のもとの1行', s.count('if(cand && best < 6){ pu.target=cand; cand.target=pu; }'), 1)
chk('新しい ねらえる距離', s.count('var _zwReach = Math.max(6, _zwStop + 0.2);'), 1)
chk('止まる距離と同じ式', s.count('var _zwStop = _zwHalfPct(pu) + _zwHalfPct(cand) + 0.2;'), 1)
chk('ボス60/通常46', s.count('(un && un.isBoss) ? 60 : 46'), 1)
chk('anchor not found の logging', s.count("console.error('[__ZWAR_REACH_FIX_V1__] anchor not found')"), 1)
chk('indexOf ガード', s.count('if (t.indexOf(_zwr1) !== -1)'), 1)

# --- 配信されるコードで throw しない（チェーン全件が 黙って捨てられるのを ふせぐ）---
_bi = s.index('const _zwr1 = ')
_bj = s.index(CACHE_LINE, _bi)
_blk = s[_bi:_bj]
for _w in ('throw', 'Error('):
    if _w in _blk:
        print('NG: さしこんだ行に %s が入っている（配信コードは throw しない）' % _w)
        ok[0] = False
if 'console.error' not in _blk:
    print('NG: アンカー不一致のときの console.error が無い')
    ok[0] = False

# --- 敵が自分でねらいを決める別の不具合には さわっていない ---
#     さしこんだ行は ループを1つも足さない（敵側のねらい決めを 新しく作らない）
if 'for(' in _blk or 'players' in _blk or 'enemies' in _blk:
    print('NG: さしこんだ行が ループや players/enemies に さわっている')
    ok[0] = False

# --- 壊してはいけないもの ---
chk('__DEFSTAGE_BONUS_V1__', s.count('__DEFSTAGE_BONUS_V1__'), 7)
chk('__DEFSTAGE_SENTINEL_V1__', s.count('__DEFSTAGE_SENTINEL_V1__'), 1)
chk('__DEFSTAGE_CHARS_V1__', s.count('__DEFSTAGE_CHARS_V1__'), 1)
chk('__DEF_SNAP_SPDSKILLS_V1__', s.count('__DEF_SNAP_SPDSKILLS_V1__'), 1)
chk('__DEF_RESOLVE_VERIFY_V1__', s.count('__DEF_RESOLVE_VERIFY_V1__'), 1)
chk('__ZWAR_BOSS_SKILL3_V1__', s.count('__ZWAR_BOSS_SKILL3_V1__'), 4)
chk('__ZWAR_CASTLE_STAND_V1__', s.count('__ZWAR_CASTLE_STAND_V1__'), 6)
chk('基地HP 380', s.count('DEFENSE_BASE_HP = 380'), 1)
chk('勝利コイン 20', s.count('DEFENSE_WIN_COINS = 20'), 1)
chk('defStageEnemies の呼び出し', s.count('defStageEnemies('), 3)
chk('ステージ前進の UPDATE', s.count('UPDATE defense_stage SET stage = stage + 1'), 2)
chk('降格の書き込み', s.count('UPDATE defense_stage SET stage - 1'), 0)

if not ok[0]:
    print('検証に落ちたので 何も書かない')
    sys.exit(1)

io.open(SRC, 'w', encoding='utf-8').write(s)
print('OK: 適用した。chain =', before, '->', after)
