# -*- coding: utf-8 -*-
# DEF2_LV50_SAME_V1 --- ためしバトルを 本ばんと おなじ ものさしに し、
#                      子どもに 一言で つたえる。
#
#   1) ためしバトルの じぶんの モンスターを、出陣の ひかえ（レベル50・上限つき）で うごかす
#   2) みんなの けっせんの 下見でも spd を ひかえから 読む（サーバの けいさんと そろう）
#   3) 出陣の 画面と けっかの 画面に「みんな おなじ レベル50」と 出す
#
# さわるのは public/defense2.js と src/index.tsx。
# .replace チェーンは 84 から 85（出陣画面の おしらせ 1本）。
# よみこみ番号は v17 から v18。
# public/index.html は 読むだけ。手では さわらない。
# 一つでも あてはまらなければ 何も 書かずに 止まる（fail-closed）。

import io
import sys

D2 = 'public/defense2.js'
TSX = 'src/index.tsx'
HTML = 'public/index.html'

MARK = 'DEF2_LV50_SAME_V1'
ALREADY = 'raw:pick.raw'

CHAIN_BEFORE = 84
CHAIN_AFTER = 85

NL = chr(10)
BT = chr(96)


def die(msg):
    print(u'NG: ' + msg)
    sys.exit(1)


d2 = io.open(D2, encoding='utf-8').read()
tsx = io.open(TSX, encoding='utf-8').read()
html = io.open(HTML, encoding='utf-8').read()

if ALREADY in d2:
    print(u'すでに 適用ずみ。何も しない。')
    sys.exit(0)

if MARK in d2 or MARK in tsx:
    die(u'番兵だけ のこっている。人の目で 見てほしい。')

if 'window._defSnapshot=function(id){return _defSnapshot(id);};' not in tsx:
    die(u'さきに DEF_LV50_V1 を 流してから。')

E1_OLD = u'    return {id:id, level:lvl, strategy:strat};'

E1_NEW = (u'    /* DEF2_LV50_SAME_V1' + NL
          + u'       ためしバトルも 本ばんと おなじ ものさしで うごかす。' + NL
          + u'       レベル50・星と つかれは なし・atk/def/spd は 300 まで・合計 5000 まで。' + NL
          + u'       練習と 本ばんが ちがうと、じぶんの プログラムの よしあしが 見えない。 */' + NL
          + u'    var _sn = null;' + NL
          + u"    try{ if(typeof window._defSnapshot === 'function') _sn = window._defSnapshot(id); }catch(e){ _sn = null; }" + NL
          + u'    if(_sn){ return {id:id, level:50, strategy:strat, raw:{name:_sn.name, sprite:_sn.sprite, hp:_sn.hp, atk:_sn.atk, def:_sn.def, spd:_sn.spd, buff:_sn.buff, skillPow:_sn.skillPow, elementType:_sn.elementType, skills:_sn.skills}}; }' + NL
          + u'    return {id:id, level:lvl, strategy:strat};')

E2_OLD = u'      for(i=0;i<TB.allies;i++){ A.push({id:pick.id, level:pick.level, strategy:pick.strategy}); pa.push(prog); }'
E2_NEW = u'      for(i=0;i<TB.allies;i++){ A.push({id:pick.id, level:pick.level, strategy:pick.strategy, raw:pick.raw}); pa.push(prog); }'

E3_OLD = u'                   spd: Number(neutral.spd || 10) };'
E3_NEW = (u'                   /* DEF2_LV50_SAME_V1 spd も ひかえから 読む（サーバの けいさんと そろえる） */' + NL
          + u'                   spd: Number((m && m.spd) || neutral.spd || 10) };')

E4_OLD = u"""      if(_rsn){ hero += '<div style="margin-top:8px;display:inline-block;background:rgba(255,255,255,.20);border-radius:999px;padding:5px 14px;font-size:13px;font-weight:800;">'+esc(_rsn)+'</div>'; }"""

E4_NEW = (E4_OLD + NL
          + u'      /* DEF2_LV50_SAME_V1 どうして かちまけが きまったのかを、さきに つたえる */' + NL
          + u"""      hero += '<div style="margin-top:8px;font-size:11px;opacity:.85;line-height:1.5;">ぼうえいせんでは みんな おなじ レベル50 で たたかうよ。<br>かちまけは プログラムの くふうで きまるんだ。</div>';""")

EDITS = ((u'ためしバトルの ひかえ', E1_OLD, E1_NEW),
         (u'ためしバトルの なかま', E2_OLD, E2_NEW),
         (u'下見の spd', E3_OLD, E3_NEW),
         (u'けっか画面の ひとこと', E4_OLD, E4_NEW))

for label, old, new in EDITS:
    if d2.count(old) != 1:
        die(u'%s の あて先が %d 件（1件で ないと 流さない）' % (label, d2.count(old)))
    if new in d2:
        die(u'%s の 新しい 中みが すでに ある' % label)

INS = u'      t = t.replace("return {id:Number(id),name:base.name,sprite:base.sprite,level:lvl,", "return {id:Number(id),name:base.name,sprite:base.sprite,level:lvl,dn:1,")'
if tsx.count(INS) != 1:
    die(u'差しこみ口が %d 件（1件で ないと 流さない）' % tsx.count(INS))

O5 = u"""var enemyHtml='<div style="font-weight:900;margin:6px 0;">👾 敵軍団（"""
N5 = u"""var enemyHtml='<div style="background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:8px 10px;margin-bottom:8px;color:#1e40af;font-size:12px;font-weight:700;line-height:1.6;">みんな おなじ レベル50 で たたかうよ。かちまけは プログラムの くふうで きまるんだ。</div><div style="font-weight:900;margin:6px 0;">👾 敵軍団（"""

if html.count(O5) != 1:
    die(u'出陣画面の あて先が %d 件（1件で ないと 流さない）' % html.count(O5))
if N5 in html:
    die(u'出陣画面の 新しい 中みが すでに ある')

V_OLD = '/defense2.js' + '?v' + '=17'
V_NEW = '/defense2.js' + '?v' + '=18'
if tsx.count(V_OLD) != 1:
    die(u'よみこみ番号 v17 が %d 件' % tsx.count(V_OLD))
if tsx.count(V_NEW) != 0:
    die(u'よみこみ番号 v18 が すでに ある')

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
before = tsx[i:j].count('.replace(')
if before != CHAIN_BEFORE:
    die(u'チェーンが %d 件（%d 件の はず）' % (before, CHAIN_BEFORE))

for label, old, new in EDITS:
    d2 = d2.replace(old, new, 1)

ADD = (u'      // DEF2_LV50_SAME_V1 出陣の 画面で、みんな おなじ ものさしだと つたえる' + NL
       + u'      t = t.replace(' + BT + O5 + BT + u', ' + BT + N5 + BT + u')')

tsx = tsx.replace(INS, INS + NL + ADD, 1)
tsx = tsx.replace(V_OLD, V_NEW, 1)

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
after = tsx[i:j].count('.replace(')
if after != CHAIN_AFTER:
    die(u'チェーンが %d 件（%d 件の はず）' % (after, CHAIN_AFTER))

if d2.count(MARK) != 3:
    die(u'番兵が defense2.js に %d 件（3件の はず）' % d2.count(MARK))
if tsx.count(MARK) != 1:
    die(u'番兵が index.tsx に %d 件（1件の はず）' % tsx.count(MARK))

io.open(D2, 'w', encoding='utf-8').write(d2)
io.open(TSX, 'w', encoding='utf-8').write(tsx)
print(u'OK: チェーン %d から %d、よみこみ番号 v17 から v18' % (before, after))
