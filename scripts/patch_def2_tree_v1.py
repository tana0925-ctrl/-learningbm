# -*- coding: utf-8 -*-
"""DEF2TREE_V1  防衛戦の プログラムを ツリー（くりかえし・ぶんき）にする

先生のことば:
  「防衛戦のプログラミングわかりにくいのかなー。プログラミングの学習にしたいのに」

いままで
  ジムチャレンジ … じょうけん17・うごき26・くりかえし／ぶんき あり・お手本あり
  防衛戦         … じょうけん4 ・うごき5 ・くりかえし も ぶんき も なし
  小学校の プログラミングは じゅんじ・じょうけんぶんき・くりかえし を あつかう。

これから
  防衛戦でも ジムと おなじ ブロックで 組めるようにする。
  ジムチャレンジ側の コードは 1文字も 書きかえない。
  index.html の 絵をかく しくみを かりるための さしこみ口を 足すだけ。
  さしこみ口は だれも つかっていなければ 何も しない。

さわるのは 2つだけ:
  public/defense2.js   … 本体（scripts/def2tree_block_v1.js を さしこむ）
  src/index.tsx        … かりるための さしこみ口 4つ と よみこみ v10 -> v11

public/index.html には 1文字も 書かない。
めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。
"""

import io
import sys

D = 'public/defense2.js'
S = 'src/index.tsx'
H = 'public/index.html'
B = 'scripts/def2tree_block_v1.js'

# 冪等性の番兵（もう 流したかを 見るだけ。たしかめる 条件とは べつもの）
MARK_D = 'DEF2TREE_V1_MARK'
MARK_S = 'DEF2TREE_V1_WIRED'

D_A1      = "  function optionsHtml(list,cur){ return list.map(function(o){ return '<option value=\"'+o.v+'\"'+(o.v===cur?' selected':'')+'>'+esc(o.label)+'</option>'; }).join(''); }"
D_A2_OLD  = "  function renderEditor(){\n    var box=document.getElementById('def2ProgBox'); if(!box) return; ensureRules();"
D_A2_NEW  = "  function renderEditor(){\n    var box=document.getElementById('def2ProgBox'); if(!box) return;\n    if(d2tActive() && d2tPaint(box)) return; /* DEF2TREE_V1 ツリーが つかえるなら そちらで かく */\n    ensureRules();"
D_A3_OLD  = "  function progFromRules(){ return ensureRules().map(function(r){ var o={c:r.c,a:r.a}; var cd=COND.filter(function(x){return x.v===r.c;})[0]; if(cd&&cd.num){ o.cn=Number(r.cn!=null?r.cn:(cd.dflt||0)); } return o; }); }"
D_A3_NEW  = "  function progFromRules(){\n    /* DEF2TREE_V1 ツリーが つかえる ときは ツリーを そのまま わたす */\n    if(d2tActive()){ var _t=d2tProg(); if(_t && _t.length) return _t; }\n    return ensureRules().map(function(r){ var o={c:r.c,a:r.a}; var cd=COND.filter(function(x){return x.v===r.c;})[0]; if(cd&&cd.num){ o.cn=Number(r.cn!=null?r.cn:(cd.dflt||0)); } return o; });\n  }"
D_A5_OLD  = "      p.defProgram = JSON.parse(JSON.stringify(ensureRules()));"
D_A5_NEW  = "      /* DEF2TREE_V1 ツリーの ときは ツリーを ほぞん。ツリーを ひょうで 上書きしない。 */\n      if(d2tActive()){ p.defProgram = JSON.parse(JSON.stringify(d2tProg())); }\n      else if(!(window._pbIsTree && window._pbIsTree(p.defProgram))){ p.defProgram = JSON.parse(JSON.stringify(ensureRules())); }"
D_A6_OLD  = "  function tbNumberRules(prog){\n    var out=[], i, r, o;"
D_A6_NEW  = "  function tbNumberRules(prog){\n    /* DEF2TREE_V1 ツリーは もともと _id を もっているので そのまま つかう */\n    if(window._pbIsTree && window._pbIsTree(prog)) return prog;\n    var out=[], i, r, o;"
D_A7_OLD  = "    var evs=(rep&&rep.events)||[], rules=prog||[], i, k, pa, p;"
D_A7_NEW  = "    var evs=(rep&&rep.events)||[], rules=d2tTallyRules(prog), i, k, pa, p; /* DEF2TREE_V1 */"
D_A8_OLD  = "      +'<div style=\"font-size:11px;color:#64748b;margin-bottom:5px;\">上から じゅんに 見て、さいしょに あてはまった 1つだけ うごくよ。</div>';"
D_A8_NEW  = "      +'<div style=\"font-size:11px;color:#64748b;margin-bottom:5px;\">'+((window._pbIsTree&&window._pbIsTree(prog))?'ブロックを 上から じゅんに 実行して、いちばん下まで いったら また 上に もどるよ。':'上から じゅんに 見て、さいしょに あてはまった 1つだけ うごくよ。')+'</div>';"
D_A9_OLD  = "        +'<div style=\"flex:1;color:'+(on?'#334155':'#9a3412')+';font-weight:'+(on?'400':'900')+';\">'+esc(tbRuleLine(rules[i]))"
D_A9_NEW  = "        +'<div style=\"flex:1;color:'+(on?'#334155':'#9a3412')+';font-weight:'+(on?'400':'900')+';\">'+esc(rules[i].line!=null?rules[i].line:tbRuleLine(rules[i]))"
D_A10_OLD = "        +'じょうけんが あてはまらなかったのかも。上の ほうに 「いつも」が あると、そこで とまるよ。▲▼で じゅんばんを かえて、もういちど ためしてみよう。</div>';"
D_A10_NEW = "        +((window._pbIsTree&&window._pbIsTree(prog))?'じょうけんが あてはまらなかったのかも。じょうけんの すうじを かえたり、↑↓で ブロックの じゅんばんを かえて、もういちど ためしてみよう。':'じょうけんが あてはまらなかったのかも。上の ほうに 「いつも」が あると、そこで とまるよ。▲▼で じゅんばんを かえて、もういちど ためしてみよう。')+'</div>';"
D_A11_OLD = "    tryMountEditor(); tryMountTryBattle();"
D_A11_NEW = "    d2tInstallHook(); tryMountEditor(); tryMountTryBattle();"

S_ANCHOR  = "      t = t.replace('</body>', '<script src=\"/def_join_nudge.js?v=1\"></script></body>')"
S_ADD     = "\n      // 🧩 DEF2TREE_V1_WIRED 防衛戦の プログラムを くりかえし・ぶんき が つかえる ブロックにする。\n      //    ジムチャレンジの 絵をかく しくみを 防衛戦から かりるための さしこみ口を 足すだけ。\n      //    だれも さしこみ口を つかっていなければ、ジム側の うごきは これまでと まったく かわらない。\n      //    中身は public/defense2.js。public/index.html は 手で 書きかえない。\n      t = t.replace(`window._pbApplyTpl=_pbApplyTpl;`, `window._pbApplyTpl=_pbApplyTpl; /* DEF2TREE_V1_EXPOSE */ window.__pbHooksV1=true; window._pbCatalog=_pbCatalog; window._pbRenderNode=_pbRenderNode; window._pbAddPal=_pbAddPal; window._pbInjectCss=_pbInjectCss; window._pbEnsureIds=_pbEnsureIds; window._pbCur=_pbCur; window._pbIsTree=_pbIsTree; window._pbPersist=_pbPersist;`)\n      t = t.replace(`function _gcRenderPrep(){ _gcStopMover();`, `function _gcRenderPrep(){ /* DEF2TREE_V1_PREPHOOK */ if(typeof window._pbPrepHook===\"function\"){ try{ if(window._pbPrepHook()) return; }catch(e){} } _gcStopMover();`)\n      t = t.replace(`function _pbCatalog(){ return {`, `function _pbCatalog(){ /* DEF2TREE_V1_CATHOOK */ if(typeof window._pbCatalogHook===\"function\"){ try{ var _pbHk=window._pbCatalogHook(_pbCatalogRaw()); if(_pbHk&&_pbHk.conds&&_pbHk.conds.length&&_pbHk.acts&&_pbHk.acts.length) return _pbHk; }catch(e){} } return _pbCatalogRaw(); } function _pbCatalogRaw(){ return {`)\n      t = t.replace(`var b=function(kind,txt,bg){ return '<button class=\"pb-palbtn\"`, `var b=function(kind,txt,bg){ /* DEF2TREE_V1_BLKHOOK */ if(typeof window._pbBlocksHook===\"function\"){ try{ if(!window._pbBlocksHook(kind)) return ''; }catch(e){} } return '<button class=\"pb-palbtn\"`)"
S_V_OLD   = '/defense2.js' + '?v' + '=10'
S_V_NEW   = '/defense2.js' + '?v' + '=11'

H_ANCHORS = [
    ('さらけだし口', "window._pbApplyTpl=_pbApplyTpl;"),
    ('かきなおし口', "function _gcRenderPrep(){ _gcStopMover();"),
    ('ひょうの口', "function _pbCatalog(){ return {"),
    ('ぶひん箱の口', "var b=function(kind,txt,bg){ return '<button class=\"pb-palbtn\""),
]


def need_one(name, text, hay):
    n = hay.count(text)
    if n != 1:
        print('NG: めじるし %s が %d 件（1件で ないので 止めます）' % (name, n))
        return False
    return True


def main():
    d = io.open(D, encoding='utf-8', newline='').read()
    s = io.open(S, encoding='utf-8', newline='').read()
    h = io.open(H, encoding='utf-8', newline='').read()
    block = io.open(B, encoding='utf-8', newline='').read()

    done_d = MARK_D in d
    done_s = MARK_S in s
    if done_d and done_s:
        print('すでに 入っています。なにも しません。')
        return 0
    if done_d != done_s:
        print('NG: かたほうだけ 入っています（d=%s s=%s）。手で 見てください。' % (done_d, done_s))
        return 1
    if MARK_D not in block:
        print('NG: %s に 番兵が ありません' % B)
        return 1

    ok = True
    for name, text in H_ANCHORS:
        ok = need_one(name, text, h) and ok

    for name, text in (
        ('えらびリスト', D_A1),
        ('絵をかく ところ', D_A2_OLD),
        ('めいれいを 取り出す ところ', D_A3_OLD),
        ('ほぞんする ところ', D_A5_OLD),
        ('ばんごうづけ', D_A6_OLD),
        ('ひょうの もと', D_A7_OLD),
        ('ひょうの せつめい', D_A8_OLD),
        ('ひょうの 1行', D_A9_OLD),
        ('ひょうの ちゅうい', D_A10_OLD),
        ('とりつけ', D_A11_OLD),
    ):
        ok = need_one(name, text, d) and ok

    ok = need_one('よみこみ v10', S_V_OLD, s) and ok
    ok = need_one('つなぎ先', S_ANCHOR, s) and ok

    if s.count(S_V_NEW) != 0:
        print('NG: よみこみ v11 が もう あります'); ok = False
    if 'd2tPrepHook' in d or 'D2T_KEY' in d:
        print('NG: ツリーの ぶひんが もう 入っています'); ok = False
    if '_pbCatalogRaw' in s or '_pbPrepHook' in s:
        print('NG: さしこみ口が もう 入っています'); ok = False
    if '_pbCatalogRaw' in h:
        print('NG: index.html が すでに 書きかえられています'); ok = False

    i = s.index("app.get('/', async (c) => {")
    j = s.index("app.get('/logout'", i)
    chain = s[i:j].count('.replace(')
    if chain != 78:
        print('NG: チェーンが %d 件（流す前は 78 件の はず）' % chain); ok = False

    if not ok:
        print('中止しました。ファイルには 1文字も 書いていません。')
        return 1

    d2 = d.replace(D_A1, block.rstrip('\n') + '\n\n' + D_A1, 1)
    d2 = d2.replace(D_A2_OLD, D_A2_NEW, 1)
    d2 = d2.replace(D_A3_OLD, D_A3_NEW, 1)
    d2 = d2.replace(D_A5_OLD, D_A5_NEW, 1)
    d2 = d2.replace(D_A6_OLD, D_A6_NEW, 1)
    d2 = d2.replace(D_A7_OLD, D_A7_NEW, 1)
    d2 = d2.replace(D_A8_OLD, D_A8_NEW, 1)
    d2 = d2.replace(D_A9_OLD, D_A9_NEW, 1)
    d2 = d2.replace(D_A10_OLD, D_A10_NEW, 1)
    d2 = d2.replace(D_A11_OLD, D_A11_NEW, 1)

    s2 = s.replace(S_ANCHOR, S_ANCHOR + S_ADD, 1)
    s2 = s2.replace(S_V_OLD, S_V_NEW, 1)

    i = s2.index("app.get('/', async (c) => {")
    j = s2.index("app.get('/logout'", i)
    chain2 = s2[i:j].count('.replace(')
    if chain2 != 82:
        print('NG: 流したあとの チェーンが %d 件（78 + 4 = 82 の はず）' % chain2)
        return 1
    if d2 == d or s2 == s:
        print('NG: なにも かわりませんでした')
        return 1

    io.open(D, 'w', encoding='utf-8', newline='').write(d2)
    io.open(S, 'w', encoding='utf-8', newline='').write(s2)
    print('OK: 入れました。チェーン 78 -> %d' % chain2)
    return 0


if __name__ == '__main__':
    sys.exit(main())
