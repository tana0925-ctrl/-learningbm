#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# __ZWAR_SELF_V1__ 便1：ゾンビ襲来で「児童の出撃ユニットのわざ3」が発動するようにする。
#
# 2026-10-05 に本番の配信HTML（https://learning-bm.pages.dev/ の / 実物）で確かめたこと
#  ・ゾンビ襲来の効果処理 warMaybeProcSkill3 は すでに完成している。
#  ・ところが入口が mon.moves[2] だけ。moves を持つキャラは MONSTERS 中16体
#    （ゾンビ報酬 id1201〜1216）だけで、児童のキャラは skills しか持たない。
#    → 児童のユニットは わざ3 が ずっと無反応だった。
#  ・県ボスは別便 __ZWAR_BOSS_SKILL3_V1__（src/index.tsx のチェーン）で
#    すでに skills フォールバック済み。ボスだけ効果が出ていて 不公平だった。
#
# この便がすること（児童側だけ）
#  1. getWarUnitStatsFromMonster の2か所で、moves が無いときだけ skills を見る。
#     （moves は消さない。両方読む）
#  2. 効果キーのゆれをそろえる __zwarNormEffect を足す。
#     *_self（93個）→ buff_atk / buff_def / buff_spd、buff_speed → buff_spd。
#  3. 勝ち確定になる技は わざと受けつけない（instant_kill / revive / stun /
#     counter / reflect / evade / shield は空にして捨てる）。先生の指示。
#  4. みんな回復（heal_party）は 陣営ごとに10秒に1回までにする（重ねがけ防止）。
#
# この便がしないこと
#  ・敵（ざこ・ボスの spawn）には さわらない（便2であつかう）。
#  ・防衛戦には 1バイトも さわらない。
#  ・src/index.tsx には さわらない（チェーンの数は変わらない）。
#  ・public/index.html は この script 経由でしか さわらない（LF改行のまま）。
#
# 一致しなければ 何も書かずに 異常終了する（フェイルクローズ）。2回流しても安全。

import io
import re
import sys

PATH = 'public/index.html'
SENTINEL = '__ZWAR_SELF_V1__'

FN_HEAD = 'function getWarUnitStatsFromMonster(mon, id){'
PROC_HEAD = 'function warMaybeProcSkill3(att, target){'
HEAL_HEAD = "if(e==='heal_party'){"

# わざ3を取り出す3行のかたまり。字下げは site ごとに違うので後方参照で合わせる。
ANCHOR_RE = re.compile(
    r"(?P<ind>[ \t]*)const m3 = \(mon && Array\.isArray\(mon\.moves\) && mon\.moves\[2\]\) \? mon\.moves\[2\] : null;\n"
    r"(?P=ind)const skill3Name = m3 \? \(m3\.name\|\|''\) : '';\n"
    r"(?P=ind)const skill3Effect = m3 \? \(m3\.effect\|\|''\) : '';\n"
)

# この便で 1件も 数が変わってはいけない目印（他の便のチェーンのアンカーを含む）
KEEP = [
    "const atkInterval = clamp(1100 - (mon.spd||30)*6, 420, 1100);",
    "const atkInterval = clamp(1000 - spd*4, 380, 1000);",
    "const move = 9 + clamp(spd,5,200)/10;",
    "const move = 5 + clamp(spd,5,200)/14;  // ゆっくり行軍（にゃんこ風の「間」）",
    "const cost = clamp(Math.round((hp*0.55 + atk*4 + def*0.8 + spd*0.5)/6), 30, 160);",
    PROC_HEAD,
    HEAL_HEAD,
    "warTeamUnits(att.team).forEach(u=>warHeal(u, u.hpMax*__ratio));",
    "function warMaybeProcSkill3",
    "spawnUnit('enemy', {",
]

NORM_BLOCK = (
    "// " + SENTINEL + " わざの効果キーの ゆれ を ゾンビ襲来の言い方に そろえる。\n"
    "// ・*_self（自分を強くする技・93個）は buff_atk / buff_def / buff_spd で受ける。\n"
    "// ・buff_speed と buff_spd の表記ゆれは buff_spd に そろえる。\n"
    "// ・勝ち確定になる技は わざと 受けつけない（空にして捨てる）。先生の指示。\n"
    "//   instant_kill / revive / stun / counter / reflect / evade / shield\n"
    "// ・ここに無いキーは そのまま返す。warMaybeProcSkill3 が知らないキーは何もしない。\n"
    "function __zwarNormEffect(e){\n"
    "  var s = String(e == null ? '' : e);\n"
    "  var has = function(o, k){ return Object.prototype.hasOwnProperty.call(o, k); };\n"
    "  var ng = { instant_kill:1, revive:1, stun:1, counter:1, reflect:1, evade:1, shield:1 };\n"
    "  if (has(ng, s)) return '';\n"
    "  var conv = {\n"
    "    buff_atk_self: 'buff_atk',\n"
    "    buff_def_self: 'buff_def',\n"
    "    buff_spd_self: 'buff_spd',\n"
    "    buff_speed_self: 'buff_spd',\n"
    "    buff_speed: 'buff_spd',\n"
    "    speed: 'buff_spd',\n"
    "    attack: 'buff_atk',\n"
    "    guard: 'buff_def'\n"
    "  };\n"
    "  return has(conv, s) ? conv[s] : s;\n"
    "}\n"
    "try{ window.__zwarNormEffect = __zwarNormEffect; }catch(e){}\n"
)

HEAL_CAP = (
    "\n"
    "      // " + SENTINEL + " みんな回復は 陣営ごとに 10秒に1回まで（重ねがけで固くなりすぎるのを防ぐ）。\n"
    "      try{\n"
    "        if(!window.__zwarHealPartyUntil) window.__zwarHealPartyUntil = {};\n"
    "        var __hk = (att && att.team) ? String(att.team) : 'player';\n"
    "        if(window.__zwarHealPartyUntil[__hk] && now < window.__zwarHealPartyUntil[__hk]) return;\n"
    "        window.__zwarHealPartyUntil[__hk] = now + 10000;\n"
    "      }catch(__he){}"
)


def site_block(ind):
    i = ind
    return (
        i + "// " + SENTINEL + " 児童のキャラは moves を持たず skills を持っている。moves が無いときだけ skills を見る。\n"
        + i + "const m3 = (function(){\n"
        + i + "  try{\n"
        + i + "    var _mv = (mon && Array.isArray(mon.moves) && mon.moves.length) ? mon.moves : null;\n"
        + i + "    var _sk = (!_mv && mon && Array.isArray(mon.skills) && mon.skills.length) ? mon.skills : null;\n"
        + i + "    var _a = _mv || _sk;\n"
        + i + "    return (_a && _a[2]) ? _a[2] : null;\n"
        + i + "  }catch(e){ return null; }\n"
        + i + "})();\n"
        + i + "const skill3Name = m3 ? (m3.name||'') : '';\n"
        + i + "const skill3Effect = m3 ? ((typeof __zwarNormEffect === 'function') ? __zwarNormEffect(m3.effect) : '') : '';\n"
    )


def ng(msg):
    print('NG: ' + msg)
    sys.exit(1)


def main():
    src = io.open(PATH, encoding='utf-8', newline='').read()

    if '\r' in src:
        ng('CRLF が混ざっている（このファイルは LF）')

    if SENTINEL in src:
        print('すでに適用済み（何もしない）: ' + SENTINEL)
        return

    before = dict((k, src.count(k)) for k in KEEP)

    if src.count(FN_HEAD) != 1:
        ng('getWarUnitStatsFromMonster が %d 件（期待 1）' % src.count(FN_HEAD))
    if src.count(PROC_HEAD) != 1:
        ng('warMaybeProcSkill3 が %d 件（期待 1）' % src.count(PROC_HEAD))
    if src.count(HEAL_HEAD) != 1:
        ng("if(e==='heal_party'){ が %d 件（期待 1）" % src.count(HEAL_HEAD))

    f0 = src.index(FN_HEAD)
    f1 = src.index('\nfunction ', f0 + len(FN_HEAD))

    all_m = list(ANCHOR_RE.finditer(src))
    if len(all_m) != 3:
        ng('わざ3の3行かたまりが %d 件（期待 3 ＝ 児童2 ・ 敵ボスspawn1）' % len(all_m))

    inside = [m for m in all_m if f0 < m.start() < f1]
    outside = [m for m in all_m if not (f0 < m.start() < f1)]
    if len(inside) != 2 or len(outside) != 1:
        ng('児童側 %d 件 / 外 %d 件（期待 2 / 1）' % (len(inside), len(outside)))
    for m in inside:
        if m.group('ind') != '    ':
            ng('児童側の字下げが想定外: %r' % m.group('ind'))
    if outside[0].group('ind') != '  ':
        ng('敵ボスspawn側の字下げが想定外: %r' % outside[0].group('ind'))

    added_lines = 0
    out = src
    # 後ろから置きかえる（前の置きかえで位置がずれないように）
    for m in reversed(inside):
        blk = site_block(m.group('ind'))
        added_lines += blk.count('\n') - m.group(0).count('\n')
        out = out[:m.start()] + blk + out[m.end():]

    out = out.replace(PROC_HEAD, NORM_BLOCK + PROC_HEAD, 1)
    added_lines += NORM_BLOCK.count('\n')
    out = out.replace(HEAL_HEAD, HEAL_HEAD + HEAL_CAP, 1)
    added_lines += HEAL_CAP.count('\n')

    # --- 書く前の自己点検。1つでも外れたら 書かずに 止める ---
    if len(list(ANCHOR_RE.finditer(out))) != 1:
        ng('置きかえ後の3行かたまりが %d 件（期待 1 ＝ 敵ボスspawnだけ残る）'
           % len(list(ANCHOR_RE.finditer(out))))
    if out.count('Array.isArray(mon.skills)') != 2:
        ng('skills フォールバックが %d 件（期待 2）' % out.count('Array.isArray(mon.skills)'))
    if out.count('function __zwarNormEffect(e){') != 1:
        ng('__zwarNormEffect が %d 件（期待 1）' % out.count('function __zwarNormEffect(e){'))
    if out.count('__zwarNormEffect(m3.effect)') != 2:
        ng('正規化の呼び出しが %d 件（期待 2）' % out.count('__zwarNormEffect(m3.effect)'))
    if out.count('window.__zwarHealPartyUntil') != 5:
        ng('みんな回復の上限が %d 件（期待 5）' % out.count('window.__zwarHealPartyUntil'))
    if out.count(SENTINEL) != 4:
        ng('目印が %d 件（期待 4）' % out.count(SENTINEL))
    if '\r' in out:
        ng('CRLF を作ってしまった')
    for k in KEEP:
        if out.count(k) != before[k]:
            ng('さわってはいけない目印の数が変わった: %r %d -> %d' % (k, before[k], out.count(k)))
    if out.count('\n') != src.count('\n') + added_lines:
        ng('行数の増え方が合わない（%d -> %d, 期待 +%d）'
           % (src.count('\n'), out.count('\n'), added_lines))
    if len(out) <= len(src):
        ng('ファイルが増えていない')

    io.open(PATH, 'w', encoding='utf-8', newline='').write(out)
    print('OK: %s を更新（+%d 行、%d -> %d バイト）'
          % (PATH, added_lines, len(src), len(out)))
    print('  児童の出撃ユニット 2か所に skills フォールバック')
    print('  __zwarNormEffect（*_self 93個 と buff_speed/buff_spd の表記ゆれ、勝ち確定技は捨てる）')
    print('  heal_party は 陣営ごとに 10秒に1回まで')


if __name__ == '__main__':
    main()
