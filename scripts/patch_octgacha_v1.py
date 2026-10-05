#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
OCTGACHA_V1  期間限定ガチャの「器」＋10月の12体。

  ・毎月の差し替えは LIMITED_GACHA_PLAN の1か所だけ。11月は1行足すだけ。
  ・期間外は if を1つ抜けるだけ。いまとまったく同じ動きになる。
  ・キャラが0体のときは「期間中」とみなさない。見出しもバナーも出ない。
  ・激レアの確率（ふつう0.25% / ラッキー2%）は1つも変えない。
    激レアが当たったときの中身を、半分の確率で限定キャラに振り替えるだけ。
  ・デバフ技の「威力」表示を '-' にする（ダメージが出ないのに数字が出ていた）。

  ⚠️ public/index.html は1バイトも触らない。配信チェーンの t.replace() でだけ扱う。
  ⚠️ チェーンは 8 本増える。増分が違えば1バイトも書かずに止まる。
  ⚠️ 絵（public/mon/1220〜1231.png）は別途アップロード。
     このスクリプトは list.js に id を足すだけなので、PNG が無いと絵文字のままになる
     （受け皿 monSpriteHtml が onerror で絵文字に戻すので、壊れない）。
"""
import io
import os
import sys

SRC = 'src/index.tsx'
LIST = 'public/mon/list.js'
CHAIN_DELTA = 8
NEW_IDS = [1220, 1221, 1222, 1223, 1224, 1225, 1226, 1227, 1228, 1229, 1230, 1231]


def die(msg):
    print('::error::' + msg)
    sys.exit(1)


def chain_count(text):
    a = text.index("app.get('/'")
    b = text.index("app.get('/logout'")
    return text[a:b].count('.replace(')


# ---------------------------------------------------------------- 0. 事前確認
src = io.open(SRC, encoding='utf-8').read()

want = os.environ.get('CHAIN_BEFORE', '').strip()
if not want:
    die('CHAIN_BEFORE が渡されていません。')
now = chain_count(src)
if str(now) != want:
    die('チェーン数が合いません。実測 %d / 指定 %s。他の便が流れた可能性があります。'
        '1バイトも書かずに止めました。' % (now, want))
print('チェーン数 %d を確認。' % now)


# ------------------------------------------------- 1. 差し込む JS（1行ずつ）
# 書き方のきまり（9/26 の事故をくり返さないため）:
#   ・シングルクォートだけ使う。ダブルクォート・バックスラッシュ・バッククォート・
#     ${ は1文字も入れない。HTML を組むときは innerHTML を使わず DOM で作る。

def mon(i, name, sprite, hp, atk, dfn, spd, buff, elem, s1, s2, s3, desc):
    return (
        "{id:%d,name:'%s',sprite:'%s',hp:%d,atk:%d,def:%d,spd:%d,buff:'%s',"
        "elementType:'%s',rarity:6,stage:1,gacha:true,evoLevel:null,nextId:null,"
        "skills:[%s,%s,%s],desc:'%s'}" % (i, name, sprite, hp, atk, dfn, spd, buff, elem, s1, s2, s3, desc)
    )


def nrm(name, pow_, acc, elem):
    return "{name:'%s',type:'normal',pow:%d,acc:%s,element:'%s',desc:''}" % (name, pow_, acc, elem)


def hvy(name, pow_, acc, elem):
    return "{name:'%s',type:'heavy',pow:%d,acc:%s,element:'%s',desc:''}" % (name, pow_, acc, elem)


def uniq(name, pow_, acc, eff, desc):
    return ("{name:'%s',type:'unique',pow:%d,acc:%s,effect:'%s',desc:'%s'}"
            % (name, pow_, acc, eff, desc))


MONS = [
    mon(1220, 'フジイッポン', '🗻', 480, 75, 95, 50, 'guard', 'rock',
        nrm('せおいなげ', 15, '0.96', 'fighting'),
        hvy('フジおろし', 40, '0.78', 'rock'),
        uniq('どっしり', 0, '1.0', 'buff_def', '自分の ぼうぎょを 上げる'),
        '日本の 柔道の キャラ。山のように どっしり かまえて、動かない。'),
    mon(1221, 'パンピン', '🐼', 360, 80, 60, 95, 'speed', 'normal',
        nrm('ドライブ', 15, '0.96', 'normal'),
        hvy('スマッシュ大回転', 38, '0.78', 'normal'),
        uniq('よみきり', 12, '0.95', 'debuff_acc', '相手の めいちゅうを 下げる'),
        '中国の 卓球の キャラ。相手の つぎの 一手を 先に よんでしまう。'),
    mon(1222, 'ゾウダッシュ', '🐘', 400, 85, 65, 95, 'speed', 'ground',
        nrm('ふみこみ', 15, '0.96', 'ground'),
        hvy('きゅうはっしん', 40, '0.78', 'ground'),
        uniq('おいかぜ', 0, '1.0', 'buff_speed', '自分の すばやさを 上げる'),
        'タイの 陸上100mの キャラ。大きいのに とても はやい。'),
    mon(1223, 'トゥクシャトル', '🛺', 340, 80, 55, 100, 'speed', 'steel',
        nrm('ショートサーブ', 15, '0.96', 'steel'),
        hvy('スマッシュ三輪', 38, '0.78', 'steel'),
        uniq('クラクション', 16, '0.90', 'aoe', '相手 ぜんたいに 音の こうげき'),
        'タイの バドミントンの キャラ。三輪車で コートを かけまわる。'),
    mon(1224, 'クジャクバディ', '🦚', 450, 70, 90, 70, 'guard', 'flying',
        nrm('タッチ', 15, '0.96', 'flying'),
        hvy('カバディカバディ', 40, '0.78', 'flying'),
        uniq('はねひろげ', 0, '1.0', 'buff_def', '自分の ぼうぎょを 上げる'),
        'インドの カバディの キャラ。羽を 広げると だれも 通れない。'),
    mon(1225, 'ウータンキック', '🦧', 390, 85, 65, 90, 'speed', 'grass',
        nrm('トーキック', 15, '0.96', 'fighting'),
        hvy('ローリングキック', 40, '0.78', 'fighting'),
        uniq('ジャングルの風', 0, '1.0', 'buff_speed', '自分の すばやさを 上げる'),
        'マレーシアの セパタクローの キャラ。足だけで ボールを あつかう。'),
    mon(1226, 'トラユミ', '🐯', 380, 95, 60, 85, 'attack', 'fighting',
        nrm('ねらいうち', 16, '0.96', 'fighting'),
        hvy('とらのいちげき', 40, '0.78', 'fighting'),
        uniq('しずかな目', 0, '1.0', 'buff_lucky', 'ねらいが さえて、当たりやすく・会心が 出やすくなる'),
        '韓国の アーチェリーの キャラ。しずかに 息を ととのえて、まんなかを ねらう。'),
    mon(1227, 'ペルシャヅキ', '🧶', 400, 90, 70, 75, 'attack', 'normal',
        nrm('せいけんづき', 15, '0.96', 'fighting'),
        hvy('まわしげり', 40, '0.78', 'fighting'),
        uniq('まきこみ', 14, '0.95', 'debuff_atk', '相手の こうげきを 下げる'),
        'イランの 空手の キャラ。じゅうたんで 相手を まきこんでしまう。'),
    mon(1228, 'パゴダパッド', '🛕', 420, 80, 75, 80, 'lucky', 'psychic',
        nrm('ワンボタン', 15, '0.96', 'psychic'),
        hvy('コンボ入力', 38, '0.80', 'psychic'),
        uniq('しゅうちゅう', 0, '1.0', 'buff_lucky', 'あつまった 気もちで、当たりやすく・会心が 出やすくなる'),
        'ミャンマーの eスポーツの キャラ。金の 仏塔の 形の コントローラーを もつ。'),
    mon(1229, 'バンリザブン', '🧱', 520, 75, 95, 55, 'guard', 'rock',
        nrm('ばたあし', 15, '0.96', 'water'),
        hvy('かべごえターン', 40, '0.78', 'rock'),
        uniq('ながいながい息', 0, '1.0', 'heal_self', 'つかうと 自分の たいりょくが かいふくする'),
        '中国の 競泳の キャラ。どこまでも つづく かべのように、ずっと 泳げる。'),
    mon(1230, 'チョウチンリン', '🏮', 370, 75, 70, 95, 'lucky', 'fire',
        nrm('ゆか', 15, '0.96', 'fire'),
        hvy('ちゅうがえり三回', 38, '0.80', 'fire'),
        uniq('ちゃくち', 0, '1.0', 'buff_def_party', 'みかた ぜんたいの ぼうぎょを 上げる'),
        '中国の 体操の キャラ。くるくる まわって、ぴたりと 止まる。'),
    mon(1231, 'タケタイキョク', '🎋', 460, 70, 90, 65, 'guard', 'grass',
        nrm('まわし手', 14, '0.98', 'grass'),
        hvy('雲のかまえ', 38, '0.80', 'grass'),
        uniq('ゆっくり呼吸', 0, '1.0', 'heal_party', 'みかた ぜんたいの たいりょくが かいふくする'),
        '中国の 太極拳の キャラ。竹のように しなやかで、おれない。'),
]

# ---- A: 期間表・12体・判定関数・バナー描画 ------------------------------------
PLAN = (
    "window.LIMITED_GACHA_PLAN=["
    "{key:'2026-10',label:'10月限定',emoji:'🏅',start:'2026-10-05',end:'2026-10-31',"
    "ids:[1220,1221,1222,1223,1224,1225,1226,1227,1228,1229,1230,1231]}"
    "];"
)

PAYLOAD_A = (
    "/* OCTGACHA_V1 ここだけ差し替えれば毎月できる。期間とidの表。 */"
    + PLAN
    + "try{[" + ','.join(MONS) + "].forEach(function(m){"
      "if(!window.MONSTERS.some(function(x){return Number(x.id)===Number(m.id);}))window.MONSTERS.push(m);"
      "});}catch(e){}"
    # 日付ユーティリティ（夏フェスと同じ 年-月-日 の文字列方式）
    "window.limitedGachaDateStr=function(d){d=d||new Date();"
    "return d.getFullYear()+'-'+String(d.getMonth()+1).padStart(2,'0')+'-'+String(d.getDate()).padStart(2,'0');};"
    "window.limitedGachaJa=function(s){var a=String(s||'').split('-');"
    "return a.length===3?(Number(a[1])+'月'+Number(a[2])+'日'):String(s||'');};"
    "window.limitedGachaDaysLeft=function(p,d){try{var now=d||new Date();var a=String(p.end).split('-');"
    "var e=new Date(Number(a[0]),Number(a[1])-1,Number(a[2]),23,59,59);"
    "return Math.max(0,Math.ceil((e-now)/86400000));}catch(err){return 0;}};"
    # いま期間中の限定枠。キャラが0体なら null（＝期間中とみなさない）
    "window.getLimitedGachaNow=function(d){try{var t=window.limitedGachaDateStr(d);"
    "var P=window.LIMITED_GACHA_PLAN||[];"
    "for(var i=0;i<P.length;i++){var p=P[i];if(!p||!p.start||!p.end)continue;"
    "if(t<p.start||t>p.end)continue;"
    "var ids=(p.ids||[]).map(Number).filter(function(x){try{return !!getMonster(x);}catch(e){return false;}});"
    "if(!ids.length)continue;"
    "return {key:p.key,label:p.label,emoji:p.emoji,start:p.start,end:p.end,ids:ids};}"
    "}catch(e){}return null;};"
    "window.getLimitedGachaFor=function(id){try{id=Number(id);var P=window.LIMITED_GACHA_PLAN||[];"
    "for(var i=0;i<P.length;i++){var p=P[i];if(p&&(p.ids||[]).map(Number).indexOf(id)>=0)return p;}"
    "}catch(e){}return null;};"
    # ガチャ画面のバナー（いつまでか・何体か）
    "window.renderLimitedGachaBanner=function(){try{"
    "var el=document.getElementById('limitedGachaBanner');if(!el)return;"
    "var p=window.getLimitedGachaNow();"
    "if(!p){el.className='hidden';el.textContent='';return;}"
    "var left=window.limitedGachaDaysLeft(p);"
    "el.className='mb-2 rounded-xl border border-amber-300 bg-amber-50 px-3 py-2 text-center';"
    "el.textContent='';"
    "var a=document.createElement('div');a.className='text-sm font-black text-amber-800';"
    "a.textContent=(p.emoji||'🏅')+' '+p.label+'キャラが ガチャに とうじょう中！';"
    "var b=document.createElement('div');b.className='text-xs font-bold text-amber-700 mt-0.5';"
    "b.textContent=window.limitedGachaJa(p.end)+'まで（'+(left<=1?'きょうが さいご':'あと'+left+'日')"
    "+'） ／ ぜんぶで'+p.ids.length+'たい';"
    "var c=document.createElement('div');c.className='text-[10px] text-amber-600 mt-1 leading-snug';"
    "c.textContent='げきレアが あたったとき、はんぶんの かくりつで この子たちが でるよ。コインの ねだんは いつもと おなじ。';"
    "el.appendChild(a);el.appendChild(b);el.appendChild(c);}catch(e){}};"
)

# ---- 差し替えの一覧（アンカー, 追記する中身） --------------------------------
EDITS = [
    # A 定義。MONSTERS が組み上がったあと、中間層モンスターの直前に置く。
    ('        // === 中間層モンスター（イベント・クエスト報酬系, ATK50〜80） ===',
     'after_script', PAYLOAD_A),

    # B 図鑑の「通常」枠から限定キャラを外す（gachaSet は除外用のSet）
    ('            const eggSet = new Set();', 'before_script',
     "try{(window.LIMITED_GACHA_PLAN||[]).forEach(function(p){"
     "(p.ids||[]).forEach(function(x){gachaSet.add(Number(x));});});}catch(e){}"),

    # C 図鑑に限定セクションを作る。0体なら見出しも出さない。
    ('            // ===== ラボ（かけらで復活） =====', 'before_script',
     "try{(window.LIMITED_GACHA_PLAN||[]).forEach(function(p){"
     "var ids=(p.ids||[]).map(Number).filter(function(x){return !!getMonster(x);});"
     "if(!ids.length)return;"
     "var sp=document.createElement('div');"
     "sp.className='border-t border-dashed border-gray-300 my-6';container.appendChild(sp);"
     "var ti=document.createElement('div');"
     "ti.className='flex items-center justify-center gap-2 my-4 text-lg font-black text-gray-800';"
     "var e1=document.createElement('span');e1.className='text-base';e1.textContent=p.emoji||'🏅';"
     "var e2=document.createElement('span');e2.textContent=(p.label||'限定')+'ガチャ';"
     "var e3=document.createElement('span');e3.className='text-xs font-bold text-gray-500';"
     "e3.textContent='('+window.limitedGachaJa(p.start)+'〜'+window.limitedGachaJa(p.end)+')';"
     "ti.appendChild(e1);ti.appendChild(e2);ti.appendChild(e3);container.appendChild(ti);"
     "var gr=document.createElement('div');"
     "gr.className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2';container.appendChild(gr);"
     "ids.forEach(function(x){renderEvoLine([x],gr);});});}catch(e){}"),

    # D 激レア枠(stage4)のピックアップ。確率そのものは1つも変えない。
    ('        function getRandomMonster(stage, level) {', 'after_script',
     "/* OCTGACHA_V1 期間外は if を抜けるだけ。いまと同じ動きになる。 */"
     "if(stage===4){try{var _lg=window.getLimitedGachaNow&&window.getLimitedGachaNow();"
     "if(_lg&&_lg.ids.length&&Math.random()<0.5){"
     "var _li=_lg.ids[Math.floor(Math.random()*_lg.ids.length)];var _lm=getMonster(_li);"
     "if(_lm)return {type:'monster',data:_lm,level:level};}}catch(e){}}"),

    # E1 バナーの入れ物。HTMLなので属性はシングルクォート。
    # （アンカーにダブルクォートを入れないため、見出しの末尾だけを目印にする）
    ('<span>🎰</span> ガチャ</h3>',
     'after_html', "<div id='limitedGachaBanner' class='hidden'></div>"),

    # E2 バナーを描くタイミング。コイン表示の更新に相乗りする。
    ('        function updatePlayerDisplay() {', 'after_script',
     "try{if(window.renderLimitedGachaBanner)window.renderLimitedGachaBanner();}catch(e){}"),

    # F 図鑑の「入手方法」。実際の出方どおりに書く。
    ("          if(m.gacha===true) return 'ガチャ';", 'before_script',
     "try{var _lp=window.getLimitedGachaFor&&window.getLimitedGachaFor(id);"
     "if(_lp)return _lp.label+'ガチャ（ふつう／ラッキー）で、げきレアが あたったときに 出る。'"
      "+window.limitedGachaJa(_lp.start)+'〜'+window.limitedGachaJa(_lp.end)+'だけ';}catch(e){}"),
]


def esc_ts(s):
    """TS の二重引用符つき文字列に入れる。バックスラッシュとダブルクォートは使わない設計。"""
    for bad, label in ((chr(92), 'バックスラッシュ'), ('"', 'ダブルクォート'),
                       ('`', 'バッククォート'), ('${', 'ドル波かっこ'), ('\n', '改行')):
        if bad in s:
            die('差し込む中身に %s が入っています。配信JSが壊れるので中止します。' % label)
    return '"' + s + '"'


# ---------------------------------------------------------------- 2. 書き換え
a = src.index("app.get('/'")
b = src.index("app.get('/logout'")
head, chain, tail = src[:a], src[a:b], src[b:]

# アンカーは「配信される児立ページ」= public/index.html の中にある。
# src/index.tsx ではなく、こちらで一意性を数える。
html = io.open('public/index.html', encoding='utf-8').read()

added = 0
for anchor, kind, payload in EDITS:
    if html.count(anchor) != 1:
        die('アンカーが %d 件見つかりました（1件つないと危険）: %s' % (html.count(anchor), anchor[:60]))
    if kind.endswith('html'):
        new = anchor + payload
    elif kind.startswith('after'):
        new = anchor + payload
    else:
        new = payload + anchor
    chain = chain.replace(
        '      let t = await a.text()\n',
        '      let t = await a.text()\n      t = t.replace(%s, %s)\n' % (esc_ts(anchor), esc_ts(new)),
        1)
    added += 1

# 技の「威力」表示。デバフ技はダメージが出ないので '-' にする（数字は嘘になる）。
A_POW = "let powText = '-';\n                        if (skill.pow > 0) {"
B_POW = ("let powText = '-';\n                        "
         "if (skill.pow > 0 && String(skill.effect||'').indexOf('debuff') !== 0) {")
if html.count(A_POW) != 1:
    die('威力表示のアンカーが見つかりません。')
chain = chain.replace(
    '      let t = await a.text()\n',
    '      let t = await a.text()\n      t = t.replace(%s, %s)\n'
    % ('"' + A_POW.replace(chr(92), '').replace('\n', chr(92) + 'n') + '"',
       '"' + B_POW.replace('\n', chr(92) + 'n') + '"'),
    1)
added += 1

out = head + chain + tail

after = chain_count(out)
if after - now != CHAIN_DELTA:
    die('チェーンの增分が %d です（%d のはず）。中止します。' % (after - now, CHAIN_DELTA))
if added != CHAIN_DELTA:
    die('差し替えた数が %d です（%d のはず）。' % (added, CHAIN_DELTA))

io.open(SRC, 'w', encoding='utf-8').write(out)
print('%s を書き換えました。チェーン %d -> %d' % (SRC, now, after))


# ------------------------------------------------- 3. list.js に id を足す
lst = io.open(LIST, encoding='utf-8').read()
if 'window.MON_IMG_IDS=[' not in lst:
    die('list.js の形が思っていたものと違います。')
pre, rest = lst.split('window.MON_IMG_IDS=[', 1)
body, post = rest.split(']', 1)
ids = [int(x) for x in body.replace(' ', '').split(',') if x.strip()]
before_n = len(ids)
for i in NEW_IDS:
    if i not in ids:
        ids.append(i)
ids = sorted(set(ids))
io.open(LIST, 'w', encoding='utf-8').write(
    pre + 'window.MON_IMG_IDS=[' + ','.join(str(x) for x in ids) + ']' + post)
print('list.js: %d 件 -> %d 件' % (before_n, len(ids)))

missing = [i for i in NEW_IDS if not os.path.exists('public/mon/%d.png' % i)]
if missing:
    print('※ 絵がまだ無い id: %s' % missing)
    print('※ 絵が無くても受け皿が���文字に戻すので画面は壊れない。'
          'PNG を置いた時点で自動的に絵に変わる。')
