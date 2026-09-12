# -*- coding: utf-8 -*-
"""DEF2SEND_GUARD_V1

防衛戦の 出陣（POST /api/defense/entry）で おくる プログラムの 安全べん。

サーバは monster を 4000文字で 切る。切られると JSON が とちゅうで
きれて まるごと 読めなくなり、その子の プログラムが だまって 消える。
子どもには 何が おきたか わからない。それを ふせぐ。

やることは 2つだけ:
  1. おくる ぶんから _id を とりのぞく（画面の中の ばんごうなので サーバには いらない。
     JSON が 約25% 小さくなる）
  2. ブロックが 60 を こえたら うちどめ。へらしたら かならず 子どもに しらせる。

へんしゅう画面と ためしバトルの プログラムには 1文字も さわらない。
（発火回数表が _id に たよっているので、そちらでは のこしたまま）

さわるのは 2つだけ:
  public/defense2.js … 安全べんを 足して、おくる ところに つなぐ
  src/index.tsx     … よみこみの v を 1つ 上げる（チェーンの数は 変えない）

めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。
"""

import io
import sys

D2 = 'public/defense2.js'
IDX = 'src/index.tsx'

# 冪等性の番兵（すでに流したかを 見るだけの しるし。検証条件には つかわない）
MARK = 'DEF2SEND_GUARD_V1_MARK'

A_MAKESUBMIT = 'function makeSubmit(orig){'
A_SEND_OLD = 'b.monster.prog=prog; opt.body=JSON.stringify(b);'
A_SEND_NEW = 'b.monster.prog=d2SendProg(prog, b.monster); opt.body=JSON.stringify(b);'

V_OLD = '/defense2.js' + '?v' + '=9'
V_NEW = '/defense2.js' + '?v' + '=10'

BLOCK_JS = (
"""/* ===== DEF2SEND_GUARD_V1_MARK : 出陣で おくる プログラムの 安全べん =====
     出陣の おくり先は monster を 4000文字で 切ってしまう。
     切られると JSON が とちゅうで きれて まるごと 読めなくなり、
     その子の プログラムが だまって 消える。それを ふせぐ ところ。

     ・ここで さわるのは「おくる ぶん」だけ。
       へんしゅう画面と ためしバトルの プログラムには 1文字も さわらない
       （_id は 画面の中の ばんごうなので、そちらでは のこしたまま）
     ・おくる ぶんは コピーして _id を とりのぞく（JSON が 約25% 小さくなる）
     ・ブロックが 60 を こえたら ここで うちどめ
     ・さいごに monster が 4000文字 未満に おさまるまで うしろから へらす
     ・へらしたときは かならず 子どもに 見える かたちで しらせる（だまって 消さない）
     ==================================================================== */
  var D2_SEND_MAX_NODES = 60;
  var D2_SEND_MAX_CHARS = 4000;

  function d2CountNodes(n){
    var i, k, c;
    if(n === null || typeof n !== 'object') return 0;
    if(Array.isArray(n)){ c = 0; for(i = 0; i < n.length; i++){ c += d2CountNodes(n[i]); } return c; }
    c = 1;
    for(k in n){ if(Object.prototype.hasOwnProperty.call(n, k)){ c += d2CountNodes(n[k]); } }
    return c;
  }

  function d2StripIds(n){
    var i, k, out;
    if(n === null || typeof n !== 'object') return n;
    if(Array.isArray(n)){ out = []; for(i = 0; i < n.length; i++){ out.push(d2StripIds(n[i])); } return out; }
    out = {};
    for(k in n){
      if(!Object.prototype.hasOwnProperty.call(n, k)) continue;
      if(k === '_id') continue;
      out[k] = d2StripIds(n[k]);
    }
    return out;
  }

  function d2MonsterChars(monster, prog){
    var k, probe = {};
    try{
      if(monster && typeof monster === 'object'){
        for(k in monster){ if(Object.prototype.hasOwnProperty.call(monster, k)){ probe[k] = monster[k]; } }
      }
      probe.prog = prog;
      return JSON.stringify(probe).length;
    }catch(e){ return 0; }
  }

  function d2SendNotice(kept, dropped, why){
    var box, btn;
    try{
      box = document.getElementById('def2SendNotice');
      if(!box){
        box = document.createElement('div');
        box.id = 'def2SendNotice';
        box.style.cssText = 'position:fixed;left:10px;right:10px;bottom:10px;z-index:100001;max-width:560px;margin:0 auto;background:#fff7ed;border:2px solid #fdba74;border-radius:12px;padding:12px 14px;box-shadow:0 8px 24px rgba(0,0,0,.25);font-size:13px;color:#7c2d12;line-height:1.7;';
        document.body.appendChild(box);
      }
      box.innerHTML = '<div style="font-weight:900;font-size:14px;margin-bottom:4px;">📏 プログラムが ながいので、ここまでを もっていきます</div>'
        + '<div>' + esc(why) + '</div>'
        + '<div style="margin-top:4px;">上から <b>' + kept + 'こ</b> を 出陣に もっていったよ。のこりの <b>' + dropped + 'こ</b> は おいてきています。</div>'
        + '<div style="margin-top:4px;">ブロックを すこし へらすと、ぜんぶ もっていけるよ。まちがいでは ないから だいじょうぶ。</div>'
        + '<div style="text-align:right;margin-top:8px;"><button id="def2SendNoticeX" style="border:0;background:#fdba74;color:#7c2d12;border-radius:8px;padding:6px 14px;font-weight:900;cursor:pointer;">わかった</button></div>';
      btn = document.getElementById('def2SendNoticeX');
      if(btn){ btn.addEventListener('click', function(){ try{ box.parentNode.removeChild(box); }catch(e){} }); }
    }catch(e){
      try{ window.alert('プログラムが ながいので、上から ' + kept + 'こ だけ 出陣に もっていったよ。'); }catch(e2){}
    }
  }

  function d2SendProg(prog, monster){
    var sent, before, dropped, why;
    try{
      if(!Array.isArray(prog) || !prog.length) return prog;
      sent = d2StripIds(prog);
      before = sent.length;
      why = '';
      while(sent.length > 1 && d2CountNodes(sent) > D2_SEND_MAX_NODES){ sent.pop(); }
      if(sent.length < before){ why = 'ブロックは ぜんぶで ' + D2_SEND_MAX_NODES + 'こ までだよ。'; }
      while(sent.length > 1 && d2MonsterChars(monster, sent) >= D2_SEND_MAX_CHARS){ sent.pop(); }
      if(sent.length < before && !why){ why = 'おくれる ながさを こえたよ。'; }
      if(d2CountNodes(sent) > D2_SEND_MAX_NODES || d2MonsterChars(monster, sent) >= D2_SEND_MAX_CHARS){
        sent = d2StripIds(DEFAULT_PROG);
        why = 'ひとつの ブロックの 中が とても 大きいので、いちばん かんたんな うごきに もどしたよ。';
      }
      dropped = Math.max(0, before - sent.length);
      if(dropped > 0 || why){ d2SendNotice(sent.length, dropped, why); }
      return sent;
    }catch(e){
      try{ console.error('def2 send guard', e); }catch(e2){}
      return prog;
    }
  }

  window.__DEF2_SEND_GUARD_V1 = { MAX_NODES: D2_SEND_MAX_NODES, MAX_CHARS: D2_SEND_MAX_CHARS, count: d2CountNodes, strip: d2StripIds, chars: d2MonsterChars, fit: d2SendProg };
"""
)

BLOCK = BLOCK_JS + "\n  "


def read(p):
    return io.open(p, encoding='utf-8', newline='').read()


def write(p, t):
    io.open(p, 'w', encoding='utf-8', newline='').write(t)


def main():
    d = read(D2)
    s = read(IDX)

    if MARK in d:
        print('すでに 入っています。なにも しません。')
        return 0

    for label, text, t in (
        ('おくる ところ（makeSubmit）', A_MAKESUBMIT, d),
        ('prog を つめる 1行', A_SEND_OLD, d),
        ('よみこみの v', V_OLD, s),
        ('ためしバトルの _id づけ', 'o={c:r.c,a:r.a,_id:(i+1)}', d),
        ('エントリーの あて先', '/api/defense/entry', d),
        ('きほんの プログラム', "var DEFAULT_PROG = [{c:'always',a:'attackBase'}];", d),
    ):
        c = t.count(text)
        if c != 1:
            print('NG: めじるし %s が %d 件（1件で ないので 止めます）' % (label, c))
            return 1

    if V_NEW in s:
        print('NG: あたらしい v が すでに あります')
        return 1
    for name in ('d2SendProg', 'd2StripIds', 'd2CountNodes', 'd2MonsterChars',
                 'd2SendNotice', 'D2_SEND_MAX_NODES', '__DEF2_SEND_GUARD_V1'):
        if name in d:
            print('NG: 名まえ %s が ぶつかります' % name)
            return 1
    if MARK not in BLOCK:
        print('NG: しるしが 入っていません')
        return 1

    d2 = d.replace(A_MAKESUBMIT, BLOCK + A_MAKESUBMIT, 1)
    d2 = d2.replace(A_SEND_OLD, A_SEND_NEW, 1)
    s2 = s.replace(V_OLD, V_NEW, 1)

    if d2 == d or s2 == s:
        print('NG: 書きかえが おきませんでした')
        return 1
    if d2.count(MARK) != 1:
        print('NG: しるしの数が おかしい')
        return 1
    if d2.count(A_SEND_NEW) != 1:
        print('NG: おくる ところに つながっていない')
        return 1
    if A_SEND_OLD in d2:
        print('NG: ふるい おくり方が のこっている')
        return 1
    if d2.count('function makeSubmit(orig){') != 1:
        print('NG: makeSubmit の数が おかしい')
        return 1
    if d2.count('o={c:r.c,a:r.a,_id:(i+1)}') != 1:
        print('NG: ためしバトルの _id づけを こわしています')
        return 1
    if d2.count('/api/defense/entry') != 1 or d2.count('/api/defense/resolve') != 1:
        print('NG: あて先の数が おかしい')
        return 1
    if d2.count('D2_SEND_MAX_NODES = 60') != 1:
        print('NG: 上限 60 が 入っていない')
        return 1
    if d2.count('D2_SEND_MAX_CHARS = 4000') != 1:
        print('NG: 4000文字の 見はりが 入っていない')
        return 1
    if s2.count(V_NEW) != 1 or V_OLD in s2:
        print('NG: よみこみの v が おかしい')
        return 1

    write(D2, d2)
    write(IDX, s2)
    print('OK: 出陣で おくる プログラムに 安全べんを つけました')
    return 0


if __name__ == '__main__':
    sys.exit(main())
