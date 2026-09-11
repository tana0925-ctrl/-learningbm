# -*- coding: utf-8 -*-
"""DEF2TRY_RULETALLY_V1

ためしバトルの あとに、じぶんが 書いた めいれい 1本ずつの
「何かい うごいたか」を 出す。0かいの めいれいを めだたせる。

しくみ:
  たたかいの まいコマには、そのとき うごいた ルールの ばんごうが
  もともと のこっている（どれにも あてはまらなかった ときは -1）。
  ところが 防衛戦の めいれい表には ばんごうが ついていなかったので
  ずっと -1 のままだった。ためしバトルの ときだけ ばんごうを つけて かぞえる。
  ばんごうを つけても たたかいの けっかは 1ミリも 変わらない（実測ずみ）。

さわるのは 2つだけ:
  public/defense2.js  … ばんごうづけ と、けっかの ひょう
  src/index.tsx       … よみこみの v を 1つ 上げる（チェーンの数は 変えない）

まえからある わりあいバーは、この ひょうに まとめた。
（にた ひょうを 2つ ならべると 子どもが まようため）

めじるしが きっちり 1件 見つからなければ、ファイルには 1文字も 書かずに 止まる。
"""

import io
import sys

D2 = 'public/defense2.js'
IDX = 'src/index.tsx'

# 冪等性の番兵（すでに流したかを 見るだけの しるし）
MARK = 'DEF2TRY_RULETALLY_V1_MARK'

A_TALLY = '  function tbTallyHtml(rep, prog){'
A_INFO = '  function tbInfoHtml(rep, prog){'
A_PROG = "      var prog=progFromRules(); if(!prog || !prog.length) prog=DEFAULT_PROG;"
A_PROG_NEW = A_PROG + "\n      prog=tbNumberRules(prog);"

V_OLD = '/defense2.js' + '?v' + '=8'
V_NEW = '/defense2.js' + '?v' + '=9'

BLOCK = """  /* DEF2TRY_RULETALLY_V1_MARK
     じぶんが 書いた ルール 1本ずつに 見えない ばんごうを つける。
     たたかいの まいコマには、そのとき うごいた ルールの ばんごうが
     もともと のこっているので、それを かぞえるだけで
     「どの めいれいが 何かい うごいたか」が わかる。
     0かいの めいれいを めだたせるのが ねらい。
     まえの わりあいバーは、この ひょうに まとめた。 */
  function tbNumberRules(prog){
    var out=[], i, r, o;
    for(i=0;i<(prog||[]).length;i++){
      r=prog[i]||{}; o={c:r.c,a:r.a,_id:(i+1)};
      if(r.cn!=null) o.cn=r.cn;
      out.push(o);
    }
    return out;
  }

  function tbCondLabel(r){
    var i, cd=null;
    for(i=0;i<COND.length;i++){ if(COND[i].v===r.c){ cd=COND[i]; break; } }
    if(!cd) return String(r.c||'');
    if(cd.num) return cd.label+' '+(r.cn!=null?r.cn:(cd.dflt||0))+'%';
    return cd.label;
  }

  function tbRuleLine(r){ return 'もし '+tbCondLabel(r)+' なら → '+tbActLabel(r.a); }

  function tbTallyHtml(rep, prog){
    var evs=(rep&&rep.events)||[], rules=prog||[], i, k, pa, p;
    var cnt={}, none=0, total=0, mx=1, zero=0, n, pct, on, out;
    for(i=0;i<evs.length;i++){
      pa=evs[i].posA; if(!pa) continue;
      for(k=0;k<pa.length;k++){
        p=pa[k]; if(!p||!p.act) continue;
        total++;
        if(p.n!=null&&p.n>0){ cnt[p.n]=(cnt[p.n]||0)+1; } else { none++; }
      }
    }
    if(!total||!rules.length) return '';
    for(i=0;i<rules.length;i++){ n=cnt[rules[i]._id]||0; if(n>mx) mx=n; }
    out='<div style="font-weight:900;font-size:13px;color:#334155;margin:10px 0 2px;">🧭 じぶんの めいれいは 何かい うごいた？</div>'
      +'<div style="font-size:11px;color:#64748b;margin-bottom:5px;">上から じゅんに 見て、さいしょに あてはまった 1つだけ うごくよ。</div>';
    for(i=0;i<rules.length;i++){
      n=cnt[rules[i]._id]||0; on=(n>0); pct=Math.round(n*100/mx); if(!on) zero++;
      out+='<div style="display:flex;align-items:center;gap:6px;margin:4px 0;font-size:12px;'
        +(on?'':'background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;padding:4px 6px;')+'">'
        +'<div style="flex:0 0 20px;height:20px;line-height:20px;text-align:center;border-radius:999px;font-weight:900;color:#fff;background:'+(on?'#0d9488':'#f97316')+';">'+(i+1)+'</div>'
        +'<div style="flex:1;color:'+(on?'#334155':'#9a3412')+';font-weight:'+(on?'400':'900')+';">'+esc(tbRuleLine(rules[i]))
        +(on?'':'<br><span style="font-size:11px;font-weight:400;">1かいも うごかなかった</span>')+'</div>'
        +'<div style="flex:0 0 56px;background:#e2e8f0;border-radius:999px;height:9px;overflow:hidden;"><div style="width:'+pct+'%;height:100%;background:'+(on?'#0d9488':'#fdba74')+';"></div></div>'
        +'<div style="flex:0 0 58px;text-align:right;font-weight:900;color:'+(on?'#0f766e':'#9a3412')+';">'+n+'かい</div>'
        +'</div>';
    }
    if(none>0){
      out+='<div style="display:flex;align-items:center;gap:6px;margin:4px 0;font-size:12px;color:#64748b;">'
        +'<div style="flex:0 0 20px;text-align:center;">－</div>'
        +'<div style="flex:1;">どの めいれいにも あてはまらなかった とき</div>'
        +'<div style="flex:0 0 56px;"></div>'
        +'<div style="flex:0 0 58px;text-align:right;font-weight:900;">'+none+'かい</div></div>';
    }
    if(zero>0){
      out+='<div style="background:#fff7ed;border:1px solid #fed7aa;border-radius:10px;padding:8px;font-size:12px;color:#9a3412;margin-top:6px;line-height:1.6;">'
        +'⚠ '+zero+'本の めいれいが 1かいも うごかなかったよ。<br>'
        +'じょうけんが あてはまらなかったのかも。上の ほうに 「いつも」が あると、そこで とまるよ。▲▼で じゅんばんを かえて、もういちど ためしてみよう。</div>';
    }
    return out;
  }

"""


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
        ('けっかの ひょう', A_TALLY, d),
        ('そのつぎの 関数', A_INFO, d),
        ('めいれいを 取り出す ところ', A_PROG, d),
        ('よみこみの v', V_OLD, s),
    ):
        c = t.count(text)
        if c != 1:
            print('NG: めじるし %s が %d 件（1件で ないので 止めます）' % (label, c))
            return 1

    if V_NEW in s:
        print('NG: あたらしい v が すでに あります')
        return 1
    if 'tbNumberRules' in d:
        print('NG: 名まえが ぶつかります')
        return 1

    k1 = d.index(A_TALLY)
    k2 = d.index(A_INFO, k1)
    if k2 <= k1:
        print('NG: じゅんばんが おかしい')
        return 1
    old = d[k1:k2]
    if old.count('  function ') != 1:
        print('NG: 入れかえる はんいが 広すぎます')
        return 1

    d2 = d[:k1] + BLOCK + d[k2:]
    d2 = d2.replace(A_PROG, A_PROG_NEW, 1)
    s2 = s.replace(V_OLD, V_NEW, 1)

    if d2 == d or s2 == s:
        print('NG: 書きかえが おきませんでした')
        return 1
    if d2.count(MARK) != 1:
        print('NG: しるしの数が おかしい')
        return 1
    if d2.count('function tbTallyHtml(rep, prog){') != 1:
        print('NG: ひょうの 関数が おかしい')
        return 1
    if d2.count('tbNumberRules') != 2:
        print('NG: ばんごうづけの 数が おかしい')
        return 1
    if d2.count('#def2TryAnim .gc-now{') != 1 or d2.count('#def2Anim .gc-now{') != 1:
        print('NG: みための きまりを こわしています')
        return 1
    if s2.count(V_NEW) != 1 or V_OLD in s2:
        print('NG: よみこみの v が おかしい')
        return 1

    write(D2, d2)
    write(IDX, s2)
    print('OK: めいれいごとの 「何かい うごいた」ひょうを 足しました')
    return 0


if __name__ == '__main__':
    sys.exit(main())
