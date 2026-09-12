# -*- coding: utf-8 -*-
# DEF_LV50_V1 --- ぼうえいせん だけ、みんな おなじ ものさしで たたかう。
#
#   1) レベルは みんな 50。レベルの さは のこらない
#   2) 星の ばいりつ と その日の つかれは つかわない（ぼうえいせん だけ）
#   3) atk / def / spd は 300 まで。そのあと 合計 5000 まで
#      （こえた分だけ おなじ わりあいで へらす。かたちは のこる）
#
# しゅるいごとの つよさ（base の hp / atk / def / spd / stage）は そのまま のこる。
# しゅぎょう・野生バトル・図鑑は _defSnapshot を とおらないので さわらない。
#
# さわるのは src/index.tsx だけ。.replace チェーンに 2本 足す（82 から 84）。
# public/index.html は 読むだけ。手では さわらない。
# 一つでも あてはまらなければ 何も 書かずに 止まる（fail-closed）。

import io
import sys

TSX = 'src/index.tsx'
HTML = 'public/index.html'

MARK = '__DEF_LV50_V1__'
ALREADY = 'window.defNorm=function(b)'

CHAIN_BEFORE = 82
CHAIN_AFTER = 84

Q = chr(34)
AP = chr(39)


def die(msg):
    print(u'NG: ' + msg)
    sys.exit(1)


tsx = io.open(TSX, encoding='utf-8').read()
html = io.open(HTML, encoding='utf-8').read()

if ALREADY in tsx:
    print(u'すでに 適用ずみ。何も しない。')
    sys.exit(0)

if MARK in tsx:
    die(u'番兵だけ のこっている。人の目で 見てほしい。')

INS = (u'      t = t.replace(' + Q
       + u'buff:base.buff||' + AP + u'lucky' + AP + u',elementType:el,skillPow:10}' + Q + u', ' + Q
       + u'buff:base.buff||' + AP + u'lucky' + AP + u',elementType:el,skillPow:10,spd:Number((s&&s.spd)||10),'
       + u'skills:(Array.isArray(base.skills)?base.skills.map(function(_sk){return Object.assign({},_sk)}):[])}'
       + Q + u')')

A1_OLD = (u'function _defSnapshot(id){ try{ var base=getMonster(Number(id)); if(!base) return null; '
          u'var inst=(player.monsters&&(player.monsters[id]||player.monsters[String(id)]))||{level:1}; '
          u'var lvl=Math.max(1,Number(inst.level||1)); var s=getStats(base,lvl);')

A1_NEW = (u'/*__DEF_LV50_V1__ ぼうえいせんの ものさし。レベル50・星と つかれは なし・atk/def/spd は 300 まで・合計 5000 まで。'
          u'しゅるいごとの つよさは のこる*/'
          u'window.defNorm=function(b){'
          u'var L=50,sm=Number((b&&b.stage)||1),id=Number(b&&b.id),s;'
          u'if(id===152){s={hp:5000,atk:300,def:300,spd:300};}'
          u'else if(id===153){s={hp:8000,atk:500,def:500,spd:500};}'
          u'else if(id===154){s={hp:9999,atk:777,def:777,spd:777};}'
          u'else if(id===999){s={hp:Math.floor(8500+35*(L-1)),atk:Math.floor(Number(b.atk||10)+L*1.5+L*sm*0.5),'
          u'def:Math.floor(Number(b.def||5)+L*1.2+L*sm*0.4),spd:Math.floor(Number(b.spd||5)+L*1.1+L*sm*0.3)};}'
          u'else{s={hp:Math.floor(Number(b.hp||100)*3+L*30+L*sm*5),atk:Math.floor(Number(b.atk||10)+L*1.5+L*sm*0.5),'
          u'def:Math.floor(Number(b.def||5)+L*1.2+L*sm*0.4),spd:Math.floor(Number(b.spd||5)+L*1.2+L*sm*0.4)};}'
          u's.atk=Math.min(s.atk,300);s.def=Math.min(s.def,300);s.spd=Math.min(s.spd,300);'
          u'var tot=s.hp+s.atk+s.def+s.spd;'
          u'if(tot>5000){var k=5000/tot;s={hp:Math.floor(s.hp*k),atk:Math.floor(s.atk*k),def:Math.floor(s.def*k),spd:Math.floor(s.spd*k)};}'
          u's.hp=Math.max(1,s.hp);s.atk=Math.max(1,s.atk);s.def=Math.max(1,s.def);s.spd=Math.max(1,s.spd);s.maxHp=s.hp;return s;};'
          u'window._defSnapshot=function(id){return _defSnapshot(id);};'
          u'function _defSnapshot(id){ try{ var base=getMonster(Number(id)); if(!base) return null; '
          u'var inst=(player.monsters&&(player.monsters[id]||player.monsters[String(id)]))||{level:1}; '
          u'var lvl=50; var s=window.defNorm(base);')

A2_OLD = u'return {id:Number(id),name:base.name,sprite:base.sprite,level:lvl,'
A2_NEW = u'return {id:Number(id),name:base.name,sprite:base.sprite,level:lvl,dn:1,'

if tsx.count(INS) != 1:
    die(u'差しこみ口が %d 件（1件で ないと 流さない）' % tsx.count(INS))

for label, a in ((u'ものさしの あて先', A1_OLD), (u'しるしの あて先', A2_OLD)):
    if html.count(a) != 1:
        die(u'%s が %d 件（1件で ないと 流さない）' % (label, html.count(a)))

for label, a in ((u'ものさしの 新しい 中み', A1_NEW), (u'しるしの 新しい 中み', A2_NEW)):
    if a in html:
        die(u'%s が すでに ある' % label)

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
before = tsx[i:j].count('.replace(')
if before != CHAIN_BEFORE:
    die(u'チェーンが %d 件（%d 件の はず）' % (before, CHAIN_BEFORE))

ADD = (u'      // __DEF_LV50_V1__ ぼうえいせんの ものさしを そろえる（レベル50・星と つかれ なし・上限つき）と、その しるし'
       + chr(10)
       + u'      t = t.replace(' + Q + A1_OLD + Q + u', ' + Q + A1_NEW + Q + u')'
       + chr(10)
       + u'      t = t.replace(' + Q + A2_OLD + Q + u', ' + Q + A2_NEW + Q + u')')

tsx = tsx.replace(INS, INS + chr(10) + ADD, 1)

i = tsx.index("app.get('/', async (c) => {")
j = tsx.index("app.get('/logout'", i)
after = tsx[i:j].count('.replace(')
if after != CHAIN_AFTER:
    die(u'チェーンが %d 件（%d 件の はず）' % (after, CHAIN_AFTER))

if tsx.count(MARK) != 2:
    die(u'番兵が %d 件（2件の はず）' % tsx.count(MARK))

io.open(TSX, 'w', encoding='utf-8').write(tsx)
print(u'OK: チェーン %d から %d' % (before, after))
